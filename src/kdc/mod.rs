//! The protocol engine: one request in, one reply out, no socket in sight.
//!
//! ```no_run
//! use std::sync::Arc;
//! use rrl_kdc::crypto::OwnCipher;
//! use rrl_kdc::hdb::MemoryHdb;
//! use rrl_kdc::kdc::{Kdc, KdcConfig};
//!
//! # fn main() -> rrl_kdc::Result<()> {
//! let kdc = Kdc::new(
//!     KdcConfig::new("EXAMPLE.COM")?,
//!     Arc::new(MemoryHdb::new()),
//!     Arc::new(OwnCipher),
//! );
//! let reply = kdc.handle(&[], 1_700_000_000); // a request's octets, this KDC's time
//! # let _ = reply;
//! # Ok(())
//! # }
//! ```
//!
//! The time is a parameter and not a call to the system clock: a KDC whose
//! behaviour cannot be pinned to an instant cannot be tested, and every check in
//! here — ticket lifetimes, clock skew, expiry — is about an instant.

pub mod config;

mod as_exchange;
pub mod cookie;
pub mod preauth;
mod tgs_exchange;

pub mod fast;
/// The change-password service (RFC 3244): protocol constants, the reply a
/// caller frames, and the `kadmin/changepw` entry a realm needs.
pub mod kpasswd;
pub mod logon_info;
pub mod otp;
pub mod pac;
pub mod pkinit;
/// `PA-REQ-ENC-PA-REP` (RFC 6806 §11): the checksum that ties a reply to its request.
pub mod req_enc_pa_rep;
/// S4U2Self (MS-SFU): a service asking for a ticket in somebody else's name.
pub mod s4u;
#[cfg(feature = "spake")]
pub mod spake;

/// The `till` a request asks for, with RFC 4120 §5.4.1's zero read as "as long as you allow".
///
/// Heimdal's `_kdc_fix_time` (`kdc/kerberos5.c`) does the same, with the comment "fix for old
/// clients": a literal zero is the epoch, so `min(0, now + max_life)` is a ticket that ends
/// before it starts. The KDC then refuses it as `KDC_ERR_NEVER_VALID` — telling a client whose
/// `kinit` just succeeded that its brand-new TGT is expired, which is exactly as useful as it
/// sounds, and it is what the ad-join stand reported.
///
/// `i64::MAX` rather than a computed bound: the caller's `min` with the configured lifetime is
/// what decides the end, and this function's only job is to stop zero being taken literally.
pub(super) fn till_of(body: &crate::msg::KdcReqBody) -> i64 {
    if body.till == 0 { i64::MAX } else { body.till }
}

pub use kpasswd::{VERSION_CHANGE, VERSION_SET, changepw_entry, result_payload};

use std::sync::Arc;

use std::net::IpAddr;

use crate::address;
use crate::crypto::Cipher;
use crate::error::{Error, codes};
use crate::hdb::Hdb;
use crate::msg::KdcReq;
use crate::name::Principal;

pub use as_exchange::Purpose;
pub use as_exchange::{endtime, renew_till, starttime, ticket_flags, usable_enctypes};
pub use config::KdcConfig;

/// Who may change whose password (RFC 3244 §2: the service is told, not told
/// what to decide).
///
/// It is a trait rather than a file because the decision is an authorization
/// question, and this crate does not own authorization: the process that embeds
/// the KDC almost always has a directory, a group membership and a policy of its
/// own, and a KDC that read `/var/heimdal/kadmind.acl` would be inventing a
/// second answer to a question already answered. [`SelfOnly`] is the default,
/// because it needs no configuration and cannot grant too much.
pub trait ChangePolicy: std::fmt::Debug + Send + Sync {
    /// Whether `actor` may set the password of `target`.
    fn may_change(&self, actor: &Principal, target: &Principal) -> bool;
}

/// Everyone changes only their own password.
#[derive(Debug, Clone, Copy, Default)]
pub struct SelfOnly;

impl ChangePolicy for SelfOnly {
    fn may_change(&self, actor: &Principal, target: &Principal) -> bool {
        actor == target
    }
}

/// The engine: a configuration, a database, a cipher, who may change whose
/// password, and — when the realm issues PACs — where an account's identity comes
/// from.
pub struct Kdc {
    config: KdcConfig,
    hdb: Arc<dyn Hdb>,
    cipher: Arc<dyn Cipher>,
    policy: Arc<dyn ChangePolicy>,
    identities: Option<Arc<dyn logon_info::PacIdentities>>,
    /// The realm's certificate and trust anchors, when PKINIT is configured.
    ///
    /// `None` means the realm authenticates with passwords only, and a `PA-PK-AS-REQ` is
    /// refused rather than half-answered: a KDC that accepted a certificate it cannot chain
    /// would be worse than one that does not offer the feature.
    #[cfg(feature = "pkinit")]
    pkinit: Option<Arc<pkinit::reply::State>>,
    /// The realm key `PA-FX-COOKIE` is sealed under (RFC 6113 §5.4.2.3).
    ///
    /// `None` means this realm does not offer the cookie, and then it must not advertise one:
    /// a client offered a cookie it never receives would wait for a round that never comes.
    /// The key is deliberately separate from every other realm secret, so that a cookie can
    /// never be mistaken for a ticket or an armor key.
    cookie_key: Option<crate::crypto::Key>,
    /// The multi-round pre-authentication this realm offers. Empty by default: a realm
    /// that configured none must not advertise one (see [`preauth`]).
    preauth: preauth::Registry,
}

impl std::fmt::Debug for Kdc {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Kdc")
            .field("config", &self.config)
            .field("policy", &self.policy)
            .field("issues_pac", &self.identities.is_some())
            .field("pkinit", &self.offers_pkinit())
            .field("cookie", &self.cookie_key.is_some())
            .field("preauth", &self.preauth)
            .finish()
    }
}

impl Kdc {
    /// A KDC for `config`, reading principals from `hdb`.
    pub fn new(config: KdcConfig, hdb: Arc<dyn Hdb>, cipher: Arc<dyn Cipher>) -> Self {
        Kdc {
            config,
            hdb,
            cipher,
            policy: Arc::new(SelfOnly),
            identities: None,
            #[cfg(feature = "pkinit")]
            pkinit: None,
            cookie_key: None,
            preauth: preauth::Registry::new(),
        }
    }

    /// The same KDC offering `mechanism` as multi-round pre-authentication.
    ///
    /// A realm with mechanisms still answers a client that names none, so this only adds a
    /// way in; it never closes the ones that already exist.
    pub fn with_mechanism(mut self, mechanism: Arc<dyn preauth::Mechanism>) -> Self {
        self.preauth = std::mem::take(&mut self.preauth).with(mechanism);
        self
    }

    /// The same KDC offering `PA-FX-COOKIE`, sealed under `key`.
    ///
    /// Multi-round pre-authentication needs somewhere to keep its state between rounds, and
    /// the cookie is that place. A realm that has not configured a key does not offer the
    /// mechanism at all — see [`cookie`].
    pub fn with_cookie_key(mut self, key: crate::crypto::Key) -> Self {
        self.cookie_key = Some(key);
        self
    }

    /// The same KDC answering PKINIT, with the realm's certificate and its trust anchors.
    #[cfg(feature = "pkinit")]
    pub fn with_pkinit(mut self, state: Arc<pkinit::reply::State>) -> Self {
        self.pkinit = Some(state);
        self
    }

    /// Whether this realm accepts certificate logins.
    pub fn offers_pkinit(&self) -> bool {
        #[cfg(feature = "pkinit")]
        {
            self.pkinit.is_some()
        }
        #[cfg(not(feature = "pkinit"))]
        {
            false
        }
    }

    /// The PKINIT state, when the realm has one.
    #[cfg(feature = "pkinit")]
    pub(super) fn pkinit(&self) -> Option<&pkinit::reply::State> {
        self.pkinit.as_deref()
    }

    /// The same KDC issuing PACs, with `identities` answering who an account is.
    ///
    /// A KDC without this issues plain Kerberos tickets, which is correct for a
    /// realm with no Windows clients: a PAC that states an identity invented here
    /// would be worse than no PAC at all.
    pub fn with_pac(mut self, identities: Arc<dyn logon_info::PacIdentities>) -> Self {
        self.identities = Some(identities);
        self
    }

    /// Whether tickets carry a PAC.
    pub fn issues_pac(&self) -> bool {
        self.identities.is_some()
    }

    /// The `AuthorizationData` a ticket for `client` carries, or `None` when this
    /// realm does not issue PACs or the directory does not know the account.
    ///
    /// The signature type follows `server_key`, because a PAC signature is keyed by
    /// the ticket's service key — and the `krbtgt` key that countersigns it must be
    /// of the same enctype, so that one signature type describes both checksums.
    pub(crate) fn pac_authorization_data(
        &self,
        client: &Principal,
        server_key: &crate::crypto::Key,
        now: i64,
    ) -> crate::Result<Option<Vec<u8>>> {
        let Some(identities) = &self.identities else {
            return Ok(None);
        };
        let Some(identity) = identities.identity(client)? else {
            return Ok(None);
        };
        let signature =
            pac::SignatureType::for_enctype(server_key.enctype()).ok_or_else(|| Error::Kdc {
                code: codes::KDC_ERR_ETYPE_NOSUPP,
                text: format!(
                    "{:?} has no PAC signature type, so a PAC signed with it could not be \
                     verified by anything",
                    server_key.enctype()
                ),
            })?;
        let krbtgt = self
            .hdb()
            .fetch(&Principal::krbtgt(self.config.realm()))?
            .ok_or_else(|| Error::Hdb("the realm has no krbtgt entry".into()))?;
        let kdc_key = krbtgt
            .key_for(signature.enctype().ok_or_else(|| Error::Kdc {
                code: codes::KDC_ERR_ETYPE_NOSUPP,
                text: "the PAC signature names no enctype".into(),
            })?)
            .ok_or_else(|| Error::Kdc {
                code: codes::KDC_ERR_ETYPE_NOSUPP,
                text: format!(
                    "the krbtgt entry has no {:?} key for the PAC signature",
                    signature.enctype()
                ),
            })?;

        let logon = identity.logon_info(client.to_string(), now);
        let mut blob = pac::pac(&[
            pac::Buffer::new(pac::PAC_LOGON_INFO, logon_info::encode(&logon)?),
            pac::client_info(&logon.effective_name, now)?,
            pac::Buffer::new(
                pac::PAC_SERVER_CHECKSUM,
                vec![0u8; signature.signature_len() + 4],
            ),
            pac::Buffer::new(
                pac::PAC_PRIVSVR_CHECKSUM,
                vec![0u8; signature.signature_len() + 4],
            ),
        ]);
        pac::seal(&mut blob, server_key, &kdc_key.key, signature)?;
        Ok(Some(pac::authorization_data(&blob)))
    }

    /// The same KDC with `policy` deciding who may change whose password.
    pub fn with_change_policy(mut self, policy: Arc<dyn ChangePolicy>) -> Self {
        self.policy = policy;
        self
    }

    /// The policy in force.
    pub fn change_policy(&self) -> &dyn ChangePolicy {
        self.policy.as_ref()
    }

    /// Shorthand for the change-password paths, which ask one question.
    pub(super) fn policy(&self) -> &dyn ChangePolicy {
        self.policy.as_ref()
    }

    /// The configuration in force.
    pub fn config(&self) -> &KdcConfig {
        &self.config
    }

    /// The database.
    pub fn hdb(&self) -> &dyn Hdb {
        self.hdb.as_ref()
    }

    /// The cipher.
    pub fn cipher(&self) -> &dyn Cipher {
        self.cipher.as_ref()
    }

    /// The database as a shared handle, for a front end that needs to own one —
    /// `kadmind` builds an `Admin` over the same database the KDC serves from, so
    /// that a principal it creates and a ticket the KDC issues cannot disagree.
    #[cfg(feature = "kadmin")]
    pub(crate) fn hdb_arc(&self) -> Arc<dyn Hdb> {
        Arc::clone(&self.hdb)
    }

    /// The crypto backend as a shared handle.
    #[cfg(feature = "kadmin")]
    pub(crate) fn cipher_arc(&self) -> Arc<dyn Cipher> {
        Arc::clone(&self.cipher)
    }

    /// Answers one request whose peer address is not known.
    ///
    /// Address checks behave as Heimdal's do when the source is unknown: a
    /// request that names addresses is refused, because a check that cannot be
    /// answered must not pass. A transport that knows the peer should call
    /// [`Kdc::handle_from`] instead.
    pub fn handle(&self, request: &[u8], now: i64) -> Vec<u8> {
        self.handle_from(request, now, None)
    }

    /// Answers one request that arrived from `peer`: the reply's octets, always
    /// a reply.
    ///
    /// Every failure becomes a `KRB-ERROR` rather than a Rust error, because a
    /// KDC that says nothing leaves the client waiting for a timeout and
    /// guessing. The Rust error is what the caller logs.
    pub fn handle_from(&self, request: &[u8], now: i64, peer: Option<IpAddr>) -> Vec<u8> {
        let req = match KdcReq::decode(request) {
            Ok(req) => req,
            Err(err) => return self.error(None, &Error::from(err), now),
        };
        let outcome = match address::check(
            self.config.address_policy(),
            req.body.addresses.as_deref(),
            peer,
        ) {
            Err(err) => Err(err),
            Ok(verdict) if verdict.is_allowed() => {
                if req.msg_type == crate::msg::TGS_REQ {
                    self.handle_tgs(&req, now, request)
                } else {
                    // The exact octets: PKINIT's KDF binds the AS-REQ the client sent into
                    // its context, and a re-encoding would produce a different key.
                    self.handle_as(&req, now, request)
                }
            }
            Ok(_verdict) => {
                // `warn-ticket-addresses`: the mismatch is logged and the
                // request is served anyway, which is what an operator migrating
                // to address checks needs to see before enforcing them.
                Err(address::refused())
            }
        };
        match outcome {
            Ok(reply) => reply,
            Err(err) => self.error(Some(&req), &err, now),
        }
    }

    /// The armor key of an armored request, or `None` when its armor cannot be opened.
    ///
    /// Errors are swallowed here on purpose: this runs on the error path, and an error
    /// whose armor will not open must still reach the client as a plain error rather
    /// than be replaced by a second failure explaining the first.
    fn armor_key_of(&self, req: &KdcReq, now: i64) -> Option<crate::crypto::Key> {
        let bytes = match req.padata(fast::PA_FX_FAST) {
            Some(bytes) => bytes,
            None => {
                if std::env::var_os("KDC_ARMOR_DIAG").is_some() {
                    eprintln!("armor-diag: no PA-FX-FAST on the error path");
                }
                return None;
            }
        };
        let armored = fast::ArmoredRequest::decode(bytes).ok()?;
        if armored.armor.is_some() {
            return self.armor_key_for_error(&armored, now).ok();
        }
        // Implicit armor, RFC 6113 §5.4.2.6: a `TGS-REQ` carries no `armor` field at all,
        // because the ticket already travelled in `PA-TGS-REQ` and the key is derived from
        // that request's subkey and the TGT's session key.
        //
        // This branch is what makes a refusal readable. Without it every error of an
        // armored TGS request went out in the clear — `armor_key_inner` demands an `armor`
        // field, found none, and the `?` above swallowed the failure — so a client that had
        // armored looked inside the armor, found no `PA-FX-ERROR`, and reported "the FAST
        // response is missing FX-FAST" instead of the service the KDC could not find.
        // TEMP-DIAG
        if std::env::var_os("KDC_ARMOR_DIAG").is_some() {
            let armored_shape = fast::ArmoredRequest::decode(bytes)
                .map(|a| a.armor.is_some())
                .unwrap_or(false);
            eprintln!(
                "armor-diag: padata={:?} explicit_armor={armored_shape}",
                req.padata.iter().map(|(k, _)| *k).collect::<Vec<_>>()
            );
        }
        let shown = match self.check_evidence(req, now) {
            Ok(shown) => shown,
            Err(err) => {
                if std::env::var_os("KDC_ARMOR_DIAG").is_some() {
                    eprintln!("armor-diag: check_evidence failed: {err}");
                }
                return None;
            }
        };
        let subkey = match shown.subkey.as_ref() {
            Some(subkey) => subkey,
            None => {
                if std::env::var_os("KDC_ARMOR_DIAG").is_some() {
                    eprintln!("armor-diag: no subkey in the authenticator");
                }
                return None;
            }
        };
        fast::implicit_armor_key(subkey, &shown.tgt.session_key).ok()
    }

    /// Renders `err` as the reply, attaching `METHOD-DATA` where the code needs
    /// it.
    fn error(&self, req: Option<&KdcReq>, err: &Error, now: i64) -> Vec<u8> {
        let (code, mut method_data) = match err {
            Error::Preauth {
                code, method_data, ..
            } => (*code, Some(method_data.clone())),
            other => (other.kdc_code(), None),
        };
        let text = err.is_client_facing().then(|| err.to_string());
        let (realm, sname, crealm, cname) = match req {
            Some(r) => (
                r.body.realm.clone(),
                r.body
                    .sname
                    .clone()
                    .unwrap_or_else(|| crate::name::Principal::krbtgt(self.config.realm())),
                r.body.cname.as_ref().map(|c| c.realm.clone()),
                r.body.cname.clone(),
            ),
            None => (
                self.config.realm().to_owned(),
                crate::name::Principal::krbtgt(self.config.realm()),
                None,
                None,
            ),
        };
        // RFC 6113 §5.4.2.3: the cookie rides in the error's METHOD-DATA, and it is what lets a
        // client that cannot armor by ticket keep a multi-round exchange going. It goes in
        // before the armor wrapper below, so that an armored client finds it inside the armor
        // too — the same METHOD-DATA, not a second copy of it.
        // A mechanism that answered "more" has already computed the state the next round
        // needs; anything else has none, and the cookie then carries what the client brought.
        let next_state: &[u8] = match err {
            Error::Preauth { state, .. } => state,
            _ => &[],
        };
        if let Some(cookie) =
            req.and_then(|r| self.cookie_for(r, code, now, &realm, cname.as_ref(), next_state))
        {
            // `Error::Preauth` carries METHOD-DATA already encoded, so the cookie is added to the
            // decoded list and the list is encoded again. Appending octets to the DER would only
            // work while the length fits in one octet, and that is the kind of limit nobody
            // notices until the offer grows.
            // `decode_pa_data` takes the *content* of the SEQUENCE, and the field holds the
            // whole thing; handing it the SEQUENCE reads zero elements, and a cookie that
            // replaced the offer instead of joining it is how the third-party client found this.
            //
            // An error with no METHOD-DATA at all is the case that produced a real defect:
            // `Error::Kdc` carries none, so a cookie computed for it was dropped on the floor —
            // a mechanism that refused a round lost the state already paid for, and the client
            // had to start over after every mistake. An empty list is the right start here,
            // because the cookie is the *first* element of the METHOD-DATA this reply carries.
            let mut items = match method_data.as_deref() {
                None => Some(Vec::new()),
                // A METHOD-DATA that does not parse is not repaired: dropping the cookie leaves
                // the reply exactly as it was, which is the failure a client can still use.
                Some(der) => crate::msg::method_data_of(der).ok(),
            };
            if let Some(items) = &mut items {
                items.push(cookie);
                method_data = Some(crate::msg::encode_pa_data(items));
            }
        }

        // RFC 6113 §5.4.2.5: an error caused by an armored request has to come back
        // inside the armor. A client that armored looks for `PA-FX-ERROR` in the armored
        // container and, finding none, falls back to the *outer* error — which carries
        // no pre-authentication types by design — and concludes the KDC offered it
        // nothing. The reported error is then "no usable key", not the one that was
        // actually sent, which is how a missing wrapper turns into a mystery.
        //
        // The container goes in `e-data`, as `METHOD-DATA`, rather than in the error's
        // `padata`: MIT's client reads an error's PA-DATA from `e-data` only, and a
        // reply it cannot open is indistinguishable from no reply at all.
        let armored = req.and_then(|r| {
            r.padata(fast::PA_FX_FAST)?;
            let key = self.armor_key_of(r, now)?;
            let inner = crate::msg::KrbError {
                ctime: None,
                cusec: None,
                stime: now,
                susec: 0,
                code,
                crealm: crealm.clone(),
                cname: cname.clone(),
                realm: realm.clone(),
                sname: sname.clone(),
                e_text: text.clone(),
                e_data: method_data.clone(),
                padata: Vec::new(),
            }
            .encode();
            // The methods also appear beside `PA-FX-ERROR` inside the container: MIT
            // reads them from there, not out of the error it just unwrapped.
            let mut container = method_data
                .as_deref()
                .and_then(|m| {
                    let mut rd = crate::der::Reader::new(m);
                    let seq = rd.next_tlv("METHOD-DATA").ok()?;
                    crate::msg::decode_pa_data("METHOD-DATA", seq.content).ok()
                })
                .unwrap_or_default();
            container.push((fast::PA_FX_ERROR, inner));
            let wrapped =
                fast::wrap_reply(&key, &container, None, None, r.body.nonce, self.cipher()).ok()?;
            Some(crate::msg::encode_pa_data(&[(
                fast::PA_FX_FAST_REPLY,
                wrapped,
            )]))
        });

        crate::msg::KrbError {
            ctime: None,
            cusec: None,
            stime: now,
            susec: 0,
            code,
            crealm,
            cname,
            realm,
            sname,
            e_text: text,
            // The real `METHOD-DATA` travels inside the armor when there is one; a
            // second copy in the clear would be unsigned data beside signed data.
            e_data: armored.or(method_data),
            padata: Vec::new(),
        }
        .encode()
    }
}

impl Kdc {
    /// The `PA-FX-COOKIE` to put in an error, when this exchange is one that can carry one.
    ///
    /// The state comes from the cookie the client sent, when that cookie is ours, unexpired and
    /// issued to this client; otherwise the exchange starts empty. A cookie that does not pass
    /// is *dropped silently*: reporting it would let anyone who can rewrite a request make the
    /// KDC refuse a legitimate login.
    ///
    /// Only the two pre-authentication errors carry it — those are the points at which a
    /// multi-round exchange has something to remember. Every other refusal ends the exchange,
    /// and a cookie on it would invite a retry that cannot help.
    fn cookie_for(
        &self,
        req: &KdcReq,
        code: i32,
        now: i64,
        realm: &str,
        cname: Option<&crate::name::Principal>,
        next_state: &[u8],
    ) -> Option<(i32, Vec<u8>)> {
        let key = self.cookie_key.as_ref()?;
        // `MORE_PREAUTH_DATA` is the code whose whole purpose is a next round, so it is the
        // one that most needs a cookie. The two pre-authentication errors keep it for a
        // different reason: a client retrying with a better salt should not lose the round
        // it has already paid for.
        if code != codes::KDC_ERR_PREAUTH_REQUIRED
            && code != codes::KDC_ERR_PREAUTH_FAILED
            && code != codes::KDC_ERR_MORE_PREAUTH_DATA_REQUIRED
        {
            return None;
        }
        // A mechanism's fresh state wins over whatever the client brought: the round just
        // ran, and what it decided is newer than what it started from.
        let state = if next_state.is_empty() {
            req.padata(fast::PA_FX_COOKIE)
                .and_then(|value| cookie::Cookie::decode(&*self.cipher, key, value).ok())
                .filter(|c| c.accept(now, realm, cname).is_ok())
                .map(|c| c.state)
                .unwrap_or_default()
        } else {
            next_state.to_vec()
        };
        let cookie = cookie::Cookie::new(realm, cname.cloned(), state, now);
        let octets = cookie.encode(&*self.cipher, key).ok()?;
        Some((fast::PA_FX_COOKIE, octets))
    }
}

impl Kdc {
    /// The mechanisms this realm offers.
    pub(super) fn preauth(&self) -> &preauth::Registry {
        &self.preauth
    }

    /// What the incoming cookie says this exchange has already done, or nothing.
    ///
    /// A cookie that is expired, foreign, addressed to somebody else or simply will not
    /// open gives an empty state: the mechanism then restarts its first round. Refusing
    /// instead would let anyone able to rewrite a request make the KDC reject a legitimate
    /// login, which is a denial of service wearing a diagnostic's clothes.
    pub(super) fn resume_state(
        &self,
        padata: &[(i32, Vec<u8>)],
        now: i64,
        realm: &str,
        cname: Option<&crate::name::Principal>,
    ) -> Vec<u8> {
        let Some(key) = self.cookie_key.as_ref() else {
            return Vec::new();
        };
        padata
            .iter()
            .find(|(ty, _)| *ty == fast::PA_FX_COOKIE)
            .and_then(|(_, value)| cookie::Cookie::decode(&*self.cipher, key, value).ok())
            .filter(|c| c.accept(now, realm, cname).is_ok())
            .map(|c| c.state)
            .unwrap_or_default()
    }
}

/// The error a realm that is not ours gets. Naming the realm we do serve tells
/// the operator what went wrong without telling the client anything it did not
/// already send.
pub(super) fn wrong_realm(requested: &str, ours: &str) -> Error {
    Error::Kdc {
        code: codes::KDC_ERR_WRONG_REALM,
        text: format!("this KDC serves {ours}, not {requested}"),
    }
}
