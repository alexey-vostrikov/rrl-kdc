//! The concrete GSS acceptor: the realm's own `HDB` is the keytab.
//!
//! [`super::gss_preauth`] owns the mechanism and leaves accepting a token to a
//! [`GssAcceptor`](super::gss_preauth::GssAcceptor). This is that acceptor, and it exists so that a
//! realm does not have to write one: the KDC already holds the keys a GSS context needs, and the
//! service it accepts *for* is its own `krbtgt` principal.
//!
//! **The credential is `krbtgt/REALM@REALM`, and that is the whole security argument.** Heimdal
//! acquires its acceptor credential for exactly that name (`pa_gss_acquire_acceptor_cred`), and the
//! reason is that only the KDC holds that key: a client's TGT is a ticket for this service, so the
//! token it sends is its own TGT, and no third party can build one. Accepting for any other service
//! would let whoever holds that service's key log in as any client.
//!
//! **A token must be bound to the request it answers.** The `KDC-REQ-BODY` is passed to the acceptor
//! as the GSS channel binding's `application_data` (`cb.application_data` in Heimdal's
//! `kdc/gss_preauth.c`), so a token captured from one AS-REQ cannot authenticate another. The
//! underlying acceptor accepts an initiator that sends no bindings at all — that is MIT's rule for
//! services in general — which is why `gss-require-bound-request` exists and defaults to on: for
//! pre-authentication a token bound to nothing is a token that can be replayed.
//!
//! **What is not here.** This is one round: an AP-REQ in, an AP-REP out. The Kerberos mechanism has
//! no second round, so no context state is exported into the cookie, and the `state` argument is
//! ignored rather than carried. A mechanism that needs rounds — a token-based one, say — would have
//! to export its context, which the client crate this is built on does not yet offer.

use std::sync::Arc;

use crate::crypto::{Enctype, Key};
use crate::error::{Error, Result};
use crate::hdb::{Hdb, HdbEntry};
use crate::name::Principal;

use super::gss_preauth::{GssAcceptor, GssError, GssStep};

/// Kerberos 5's GSS-API mechanism OID (RFC 4121 §3): `1.2.840.113554.1.2.2`.
pub const MECH_KRB5: &str = "1.2.840.113554.1.2.2";

/// The OID Microsoft shipped before RFC 4121 assigned one, still sent by its clients and accepted
/// by MIT: `1.2.840.48018.1.2.2`.
pub const MECH_KRB5_OLD: &str = "1.2.840.48018.1.2.2";

/// `GSS_C_ANON_FLAG` (RFC 2744 §3.12): the initiator asked for an anonymous context.
///
/// Read out of the authenticator's RFC 4121 §4.1.1 checksum, where the flags are a 32-bit
/// little-endian word. Defined here because the acceptor crate names the flags this KDC reads
/// except this one.
pub const GSS_C_ANON_FLAG: u32 = 0x0000_0040;

/// `GSS_C_CHANNEL_BOUND_FLAG` (RFC 4121 §3): the acceptor's bindings matched.
const GSS_C_CHANNEL_BOUND_FLAG: u32 = 0x0000_0800;

/// The acceptor: an `HDB`, the realm, and the policy about bindings.
pub struct HdbGssAcceptor {
    hdb: Arc<dyn Hdb>,
    realm: String,
    /// `krbtgt/REALM@REALM`, resolved once: every token this accepts is for this service.
    service: Principal,
    /// Its name without the realm, which is what a ticket's `sname` is compared as.
    service_name: String,
    max_skew_secs: i64,
    require_bound_request: bool,
}

impl std::fmt::Debug for HdbGssAcceptor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HdbGssAcceptor")
            .field("service", &self.service.to_string())
            .field("max_skew_secs", &self.max_skew_secs)
            .field("require_bound_request", &self.require_bound_request)
            .finish_non_exhaustive()
    }
}

impl HdbGssAcceptor {
    /// The acceptor for `realm`, reading keys from `hdb`.
    pub fn new(hdb: Arc<dyn Hdb>, realm: &str) -> Result<HdbGssAcceptor> {
        let service_name = format!("krbtgt/{realm}");
        let service = Principal::parse(&format!("{service_name}@{realm}")).map_err(Error::from)?;
        Ok(HdbGssAcceptor {
            hdb,
            realm: realm.to_owned(),
            service,
            service_name,
            max_skew_secs: 300,
            require_bound_request: true,
        })
    }

    /// The clock-skew tolerance for the authenticator's timestamp.
    pub fn with_clock_skew(mut self, max_skew_secs: i64) -> Self {
        self.max_skew_secs = max_skew_secs;
        self
    }

    /// Whether a token that carries no channel bindings is refused.
    ///
    /// On by default: without bindings the token answers no particular request, and a captured one
    /// can be replayed into an AS-REQ of the attacker's choosing. A realm turns this off only to
    /// interoperate with a client that cannot bind, and that is a decision, not a default.
    pub fn with_require_bound_request(mut self, require: bool) -> Self {
        self.require_bound_request = require;
        self
    }

    /// The service every token has to be for.
    pub fn service(&self) -> &Principal {
        &self.service
    }

    /// The `krbtgt` entry, as the keys of the exchange.
    fn keys(&self) -> Result<Option<HdbEntry>> {
        self.hdb.fetch_for_service(&self.service)
    }
}

impl GssAcceptor for HdbGssAcceptor {
    fn step(
        &self,
        mechanism: Option<&str>,
        token: &[u8],
        _state: &[u8],
        bindings: &[u8],
    ) -> std::result::Result<GssStep, GssError> {
        // Only the two Kerberos OIDs. A token framed for another mechanism is refused by name:
        // accepting it would mean accepting whatever that mechanism proved about a name, and the
        // realm's `gss-mechanisms-allowed` list is written in these terms.
        if let Some(mechanism) = mechanism
            && mechanism != MECH_KRB5
            && mechanism != MECH_KRB5_OLD
        {
            return Err(GssError::MechanismNotAllowed(mechanism.to_owned()));
        }

        // The realm's own state, before the token is judged: a KDC with no key for its own
        // `krbtgt` cannot accept anything, and reporting that as a bad token would send the client
        // looking for a bug in its own end of the exchange.
        match self.keys() {
            Ok(Some(entry)) if !entry.keys.is_empty() => {}
            Ok(_) => {
                return Err(GssError::Unavailable(format!(
                    "the realm has no key for {}, so there is nothing to accept a token with",
                    self.service
                )));
            }
            Err(e) => {
                return Err(GssError::Unavailable(format!(
                    "the realm's own entry could not be read: {e}"
                )));
            }
        }

        let source = HdbKeytab {
            hdb: Arc::clone(&self.hdb),
            service: self.service.clone(),
            service_name: self.service_name.clone(),
            realm: self.realm.clone(),
        };
        // `AcceptOptions` is `non_exhaustive`, so it is written field by field: a literal would
        // stop compiling when the acceptor crate grows an option, which is the point of the
        // attribute and not an obstacle to route around.
        let mut options = rrl_krb5::acceptor::AcceptOptions::default();
        options.max_skew_secs = self.max_skew_secs;
        // The request body, and nothing else: this is what Heimdal binds, and a client that puts
        // more in its bindings than the KDC did is a client whose bindings do not match.
        options.channel_bindings = Some(rrl_krb5::ChannelBindings::new(bindings));
        let (context, reply) =
            match rrl_krb5::KerberosContext::accept_token_with_source(&source, token, &options) {
                Ok(accepted) => accepted,
                // Every failure past the check above is the token's: a bad envelope, an expired
                // ticket, an authenticator that does not verify, a replay.
                Err(e) => return Err(GssError::Refused(e.to_string())),
            };

        // Defence in depth: `find` below already refuses any other service, so a context for
        // something else means the keytab source was bypassed.
        if context.service_principal != self.service.to_string() {
            return Err(GssError::Refused(format!(
                "the token is for {}, and this acceptor answers only for {}",
                context.service_principal, self.service
            )));
        }
        if self.require_bound_request && context.gss_flags & GSS_C_CHANNEL_BOUND_FLAG == 0 {
            return Err(GssError::Refused(
                "the token carries no channel binding, so it answers no particular request \
                 (gss-require-bound-request)"
                    .to_owned(),
            ));
        }

        // The reply key is the ticket's session key: the client has it (it sealed the ticket),
        // and it is the one key both ends of this exchange already share. A second key would have
        // to come from a long-term key, which a GSS login has not presented.
        let enctype = Enctype::from_i32(context.enctype as i32).map_err(|_| {
            GssError::Refused(format!(
                "the accepted ticket's enctype {} has no implementation here",
                context.enctype as i32
            ))
        })?;
        let session_key = Key::new(enctype, context.session_key.clone())
            .map_err(|e| GssError::Refused(format!("the accepted session key: {e}")))?;

        Ok(GssStep::Done {
            output: reply,
            session_key,
            initiator: Some(context.client_principal.clone()),
            anonymous: context.gss_flags & GSS_C_ANON_FLAG != 0,
            // The acceptor crate reports no lifetime for the context it established, and the
            // ticket's own times stand. Named rather than guessed: an invented lifetime would
            // silently shorten every ticket this realm issues over GSS.
            lifetime: None,
            mechanism: MECH_KRB5.to_owned(),
            body_checksum: None,
        })
    }
}

/// The realm's `HDB` seen as a keytab, for the acceptor.
///
/// Two names only — `krbtgt/REALM` and `krbtgt/REALM@REALM` — because that is the scope of the
/// credential. A ticket for any other service finds no key and the exchange fails, which is what
/// Heimdal gets from acquiring a credential for the `krbtgt` name.
struct HdbKeytab {
    hdb: Arc<dyn Hdb>,
    service: Principal,
    service_name: String,
    realm: String,
}

impl rrl_krb5::keytab::KeytabSource for HdbKeytab {
    fn name(&self) -> String {
        format!("HDB:{}/{}", self.realm, self.service_name)
    }

    fn keys(&self) -> Vec<rrl_krb5::ServiceKey> {
        match self.hdb.fetch_for_service(&self.service) {
            Ok(Some(entry)) => convert(&entry, &self.realm),
            _ => Vec::new(),
        }
    }

    fn find(
        &self,
        principal: &str,
        enctype: rrl_krb5::EncType,
        kvno: Option<u32>,
    ) -> Option<rrl_krb5::ServiceKey> {
        // The name a ticket carries is the service's, with or without the realm.
        if principal != self.service_name
            && principal != format!("{}@{}", self.service_name, self.realm)
        {
            return None;
        }
        let entry = self.hdb.fetch_for_service(&self.service).ok().flatten()?;
        let keys = convert(&entry, &self.realm);
        select(&keys, enctype, kvno)
    }
}

/// The key of `enctype` (version `kvno`, when one matches), out of `keys`.
///
/// The same order of preference the acceptor crate uses for a keytab: an exact `kvno` when asked
/// for one and present, otherwise the first key of that enctype. A miss on the version is not a
/// miss: an entry mid-rotation holds the older version, and the enctype plus the HMAC decide.
fn select(
    keys: &[rrl_krb5::ServiceKey],
    enctype: rrl_krb5::EncType,
    kvno: Option<u32>,
) -> Option<rrl_krb5::ServiceKey> {
    let matching: Vec<&rrl_krb5::ServiceKey> =
        keys.iter().filter(|k| k.enctype == enctype).collect();
    if let Some(kvno) = kvno
        && let Some(exact) = matching.iter().find(|k| k.kvno == kvno)
    {
        return Some((*exact).clone());
    }
    matching.first().map(|k| (*k).clone())
}

/// An `HDB` entry's keys as a keytab's entries.
fn convert(entry: &HdbEntry, realm: &str) -> Vec<rrl_krb5::ServiceKey> {
    entry
        .keys
        .iter()
        .filter_map(|key| {
            // The acceptor crate implements the AES enctypes and nothing else, so a key in a
            // retired enctype is left out rather than converted into something it is not.
            let enctype = rrl_krb5::EncType::from_i32(key.key.enctype().id())?;
            Some(rrl_krb5::ServiceKey::new(
                entry.principal.components.join("/"),
                realm,
                key.kvno,
                enctype,
                key.key.bytes().to_vec(),
            ))
        })
        .collect()
}
