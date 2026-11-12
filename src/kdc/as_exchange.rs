//! The AS exchange: `AS-REQ` in, `AS-REP` or `KRB-ERROR` out.
//!
//! The order of the checks is Heimdal's `_kdc_as_rep` (`kdc/kerberos5.c`),
//! because the order *is* the protocol: a client must not learn anything about
//! a principal from a reply that refused it for the wrong reason, and a KDC that
//! checks pre-authentication before it checks whether the principal exists is a
//! principal-enumeration oracle.
//!
//! 1. the request is an `AS-REQ` and its realm is ours;
//! 2. the client exists, and is not locked, disabled or expired;
//! 3. the service is `krbtgt/REALM` — this stage issues TGTs only;
//! 4. some enctype is acceptable to the client, to this KDC *and* to the entry;
//! 5. pre-authentication, if the policy or the entry wants it;
//! 6. the flags and the times, bounded by both entries' limits;
//! 7. the ticket, the encrypted part, and the reply.

use crate::crypto::{Enctype, Key, usage};
use crate::error::{Error, Result, codes};
use crate::hdb::{HdbEntry, flags as entry_flags};
use crate::msg::{
    AS_REP, EncKdcRepPart, EncTicketPart, EncryptedData, EtypeInfo2Entry, KdcRep, KdcReq,
    KdcReqBody, PA_ENC_TIMESTAMP, PA_ETYPE_INFO2, Ticket, decode_enc_ts_enc, encode_etype_info2,
    encode_pa_data, kdc_options, tkt_flags,
};
use crate::name::Principal;

use super::{Kdc, KdcConfig};

/// What the enctype is being chosen for.
///
/// Heimdal distinguishes the two because `hdb_entry.etypes` restricts what a
/// principal may be *issued*, not how it proves who it is: a client whose entry
/// declares only AES-128 still pre-authenticates in AES-256 if that is the key it
/// has, because refusing would break the login of every such account without
/// protecting anything. `_kdc_find_etype` takes the same distinction as
/// `is_preauth`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Purpose {
    /// Verifying a client's pre-authentication.
    Preauth,
    /// Sealing a ticket for a principal.
    Ticket,
}

/// The enctypes a request may be answered in.
///
/// The intersection of what the client asked for, what this KDC issues, and what
/// the entry has a key for — an enctype the principal has no key for cannot
/// verify its pre-authentication or encrypt its reply. Strongest first, because
/// the first one becomes the session key.
///
/// For a [`Purpose::Ticket`] there is a fourth filter: the entry's own `etypes`
/// restriction, if it declares one. That is the exchange's declaration of what
/// it can read, and honouring it is the difference between a realm where an
/// operator can turn off AES-128 for one service and a realm where the setting
/// exists but does nothing.
pub fn usable_enctypes(
    config: &KdcConfig,
    requested: &[i32],
    entry: &HdbEntry,
    purpose: Purpose,
) -> Vec<Enctype> {
    config
        .allowed_enctypes()
        .iter()
        .copied()
        .filter(|e| requested.contains(&e.id()) && entry.key_for(*e).is_some())
        .filter(|e| match (purpose, &entry.etypes) {
            (Purpose::Ticket, Some(declared)) => declared.contains(e),
            _ => true,
        })
        .collect()
}

/// Whose order decides which of the usable enctypes is first.
///
/// Heimdal's `_kdc_find_etype` has exactly two branches, and neither is "strongest" in any
/// absolute sense: one walks this KDC's own list (its first acceptable entry wins), the other
/// walks the client's `etype` list (its first acceptable entry wins). Which branch runs is what
/// `*-use-strongest-session-key` and `use-strongest-server-key` choose.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnctypeOrder {
    /// The client's list decides: RFC 4120 §3.1.3 as it reads, and Heimdal's default.
    ClientPreferred,
    /// This KDC's `allowed_enctypes` order decides: Heimdal's `*-use-strongest-*`.
    KdcPreferred,
}

/// `usable`, reordered as `order` says.
///
/// The set is the same either way — the intersection of what the client asked for, what this KDC
/// issues and what the entry has a key for — so the two orders can never disagree about *whether*
/// an enctype is possible, only about which one comes first. An enctype the client did not list
/// has no place in the client's order and is kept at the end rather than dropped, which is the
/// difference between "the client's list ran out" and "there is nothing at all".
pub fn order_enctypes(
    usable: Vec<Enctype>,
    requested: &[i32],
    order: EnctypeOrder,
) -> Vec<Enctype> {
    match order {
        EnctypeOrder::KdcPreferred => usable,
        EnctypeOrder::ClientPreferred => {
            let mut out = usable;
            out.sort_by_key(|e| {
                requested
                    .iter()
                    .position(|r| *r == e.id())
                    .unwrap_or(usize::MAX)
            });
            out
        }
    }
}

/// Whether `p` is this realm's own ticket-granting ticket, `krbtgt/REALM@REALM`.
///
/// The distinction matters twice: a PAC is written into the root TGT whatever the service's
/// `no-auth-data-reqd` says (nothing could revoke a TGT that never had one), and a cross-realm
/// `krbtgt/OTHER@HERE` is the one `krbtgt` a PAC is *not* written into when its entry says so.
pub(crate) fn is_root_tgt(p: &Principal) -> bool {
    p.is_krbtgt() && p.components.get(1) == Some(&p.realm)
}

/// Whether the request names the well-known anonymous principal (RFC 6111, RFC 8062 §3).
///
/// The identity is the name type and the components: `WELLKNOWN/ANONYMOUS` under any other
/// type is a different principal, which is why the type is checked rather than the spelling.
fn is_anonymous(name: &Principal) -> bool {
    name.name_type == crate::name::NT_WELLKNOWN
        && name.components.len() == 2
        && name.components[0] == "WELLKNOWN"
        && name.components[1] == "ANONYMOUS"
}

/// Resolves an `NT-ENTERPRISE` client name to the principal it names (RFC 6806 §6).
///
/// A name that is not enterprise passes through untouched — the option permits a rename, it
/// does not perform one. An enterprise name is one component of the form `user@realm`, and
/// the result is the `NT-PRINCIPAL` name in that realm.
///
/// Refusing without the option is the point of the whole mechanism: resolving it would make
/// the reply name a principal the client never sent, and a client that did not ask for
/// `canonicalize` is entitled to reject exactly that.
fn canonical_client_name(cname: &Principal, options: u32, realm: &str) -> Result<Principal> {
    if cname.name_type != crate::name::NT_ENTERPRISE {
        return Ok(cname.clone());
    }
    let refuse = |text: String| Error::Kdc {
        code: codes::KDC_ERR_C_PRINCIPAL_UNKNOWN,
        text,
    };
    if options & kdc_options::CANONICALIZE == 0 {
        return Err(refuse(format!(
            "{cname} is an enterprise name (NT-ENTERPRISE) and the request did not set \
             the canonicalize option: resolving it would answer with a name the client \
             did not send, which is what that option authorises"
        )));
    }
    // `NT-ENTERPRISE ::= SEQUENCE { name-string }` with exactly one component.
    let [component] = cname.components.as_slice() else {
        return Err(refuse(format!(
            "{cname} is an enterprise name with {} components; the type carries exactly one, \
             of the form user@realm",
            cname.components.len()
        )));
    };
    // The realm comes from the name, not from the request: `user@OTHER.REALM` names an
    // account in another realm, and this KDC serves one.
    let Some((principal, named_realm)) = component.rsplit_once('@') else {
        return Err(refuse(format!(
            "{cname} is an enterprise name without a realm: the component must be \
             user@realm, and {component:?} has no @"
        )));
    };
    if !super::same_realm(named_realm, realm) {
        return Err(super::wrong_realm(named_realm, realm));
    }
    if principal.is_empty() {
        return Err(refuse(format!("{cname} names no user before the realm")));
    }
    // The name is issued in **our** spelling of the realm: the client's case comes from a DNS name,
    // and every lookup that follows compares against the configured realm.
    Ok(Principal::new(
        crate::name::NT_PRINCIPAL,
        [principal],
        realm,
    ))
}

/// The value of `pa_type` in a `PA-DATA` list.
///
/// `KdcReq::padata` does this for a whole request; the AS exchange needs it over a list
/// that may have come from inside a FAST wrapper instead.
fn padata_value(padata: &[(i32, Vec<u8>)], pa_type: i32) -> Option<&[u8]> {
    padata
        .iter()
        .find(|(t, _)| *t == pa_type)
        .map(|(_, v)| v.as_slice())
}

/// `may-postdate`: may this ticket be postdated, and is it?
///
/// Heimdal writes `may_postdate` only when the client asked for `allow-postdate` **and** both
/// entries allow postdating, and refuses the request with `KDC_ERR_POLICY` when it was asked for
/// and not allowed — a client told "yes" by a flag and "no" by the ticket would have no way to
/// notice. The ticket itself is marked `invalid` and `postdated` when the client asked for a
/// postdated one and said when it starts; `starttime` answers that part.
pub fn may_postdate(body: &KdcReqBody, client: &HdbEntry, server: &HdbEntry) -> Result<bool> {
    if body.kdc_options & kdc_options::ALLOW_POSTDATE == 0 {
        return Ok(false);
    }
    if client.has(entry_flags::POSTDATE) && server.has(entry_flags::POSTDATE) {
        Ok(true)
    } else {
        Err(Error::Kdc {
            code: codes::KDC_ERR_POLICY,
            text: "the ticket may not be postdated".into(),
        })
    }
}

/// `from`, when the request asks for a postdated ticket and the client is
/// allowed one. A `from` on a request that did not ask for `postdated` is
/// ignored, as MIT ignores it.
pub fn starttime(body: &KdcReqBody, client: &HdbEntry) -> Option<i64> {
    let asked = body.kdc_options & kdc_options::POSTDATED != 0;
    if asked && client.has(entry_flags::POSTDATE) {
        body.from
    } else {
        None
    }
}

/// When the ticket ends: the requested `till`, bounded by this KDC's `max_life`
/// and by both entries' `max_life`, counted from the start.
pub fn endtime(
    config: &KdcConfig,
    body: &KdcReqBody,
    client: &HdbEntry,
    server: &HdbEntry,
    start: i64,
) -> i64 {
    let mut end = super::till_of(body).min(start.saturating_add(config.max_life()));
    if let Some(max) = client.max_life {
        end = end.min(start.saturating_add(max));
    }
    if let Some(max) = server.max_life {
        end = end.min(start.saturating_add(max));
    }
    end
}

/// `renew-till`, when the request asks for a renewable ticket: bounded by
/// `max_renewable_life` and by both entries' `max_renew`, counted from the
/// start.
///
/// A `rtime` of zero means "as long as you allow" (RFC 4120 §5.4.1), which is
/// the configuration's bound here.
pub fn renew_till(
    config: &KdcConfig,
    body: &KdcReqBody,
    client: &HdbEntry,
    server: &HdbEntry,
    start: i64,
) -> Option<i64> {
    if body.kdc_options & kdc_options::RENEWABLE == 0 {
        return None;
    }
    let asked = match body.rtime {
        None | Some(0) => start.saturating_add(config.max_renewable_life()),
        Some(rtime) => rtime,
    };
    let mut till = asked.min(start.saturating_add(config.max_renewable_life()));
    if let Some(max) = client.max_renew {
        till = till.min(start.saturating_add(max));
    }
    if let Some(max) = server.max_renew {
        till = till.min(start.saturating_add(max));
    }
    Some(till)
}

/// `TicketFlags` for a ticket granted to `client` for `server`.
///
/// `forwardable` and `proxiable` need three consents each: the client asked,
/// the client's entry allows it, and the service's entry allows it (Heimdal:
/// `client->flags.forwardable && server->flags.forwardable`).
pub fn ticket_flags(
    body: &KdcReqBody,
    client: &HdbEntry,
    server: &HdbEntry,
    preauthenticated: bool,
    renewable: bool,
    may_postdate: bool,
    postdated_start: Option<i64>,
) -> u32 {
    let mut flags = tkt_flags::INITIAL;
    if may_postdate {
        flags |= tkt_flags::MAY_POSTDATE;
    }
    if postdated_start.is_some() {
        // RFC 4120 §2.4: a postdated ticket is not usable until `starttime`, and `invalid` is
        // what makes an acceptor refuse it before then. `VALIDATE` clears the flag.
        flags |= tkt_flags::POSTDATED | tkt_flags::INVALID;
    }
    if preauthenticated {
        flags |= tkt_flags::PRE_AUTHENT;
    }
    if body.kdc_options & kdc_options::FORWARDABLE != 0
        && client.has(entry_flags::FORWARDABLE)
        && server.has(entry_flags::FORWARDABLE)
    {
        flags |= tkt_flags::FORWARDABLE;
    }
    if body.kdc_options & kdc_options::PROXIABLE != 0
        && client.has(entry_flags::PROXIABLE)
        && server.has(entry_flags::PROXIABLE)
    {
        flags |= tkt_flags::PROXIABLE;
    }
    if renewable {
        flags |= tkt_flags::RENEWABLE;
    }
    if server.has(entry_flags::OK_AS_DELEGATE) {
        flags |= tkt_flags::OK_AS_DELEGATE;
    }
    flags
}

/// One `PA-DATA` element of `METHOD-DATA`: the pre-authentication type this
/// stage announces, and the etype information that goes with it.
fn method_data(entries: &[EtypeInfo2Entry], extra: &[(i32, Vec<u8>)]) -> Vec<u8> {
    let mut items = vec![
        (PA_ENC_TIMESTAMP, Vec::new()),
        // Advertised unconditionally, as MIT's KDC does: a client that armors replaces
        // the timestamp with this, a client that does not ignores it. Offering it only
        // to clients that already armored would be circular — the first armored request
        // is exactly the one that needs to learn it exists.
        (super::fast::PA_ENCRYPTED_CHALLENGE, Vec::new()),
        // RFC 6806 §11: the client sends `(149, empty)` back only if it sees this, and until it
        // does, it has no way to learn that this KDC answers with a request checksum — or, from
        // that, that it supports FAST and therefore S4U.
        (super::req_enc_pa_rep::PA_REQ_ENC_PA_REP, Vec::new()),
        (PA_ETYPE_INFO2, encode_etype_info2(entries)),
    ];
    // The multi-round mechanisms the realm offers, after the single-round ones: a client
    // reads this list to decide how to authenticate, and a mechanism missing from it is a
    // mechanism it will never try.
    items.extend_from_slice(extra);
    encode_pa_data(&items)
}

/// The `ETYPE-INFO2` entries for `entry`: one per usable enctype, each with the
/// salt that key was made with.
///
/// The salt comes from the entry, not from the principal's name: a principal
/// whose name changed has a salt its name no longer produces, and a client told
/// the wrong salt derives a key that does not exist.
fn etype_info2(entry: &HdbEntry, usable: &[Enctype]) -> Vec<EtypeInfo2Entry> {
    usable
        .iter()
        .filter_map(|e| {
            entry.key_for(*e).map(|k| EtypeInfo2Entry {
                etype: *e,
                salt: k.salt.clone(),
                s2kparams: None,
            })
        })
        .collect()
}

/// `KDC_ERR_PREAUTH_REQUIRED` with the method data attached.
fn preauth_required(
    cname: &Principal,
    entries: &[EtypeInfo2Entry],
    announced: &[(i32, Vec<u8>)],
    state: Vec<u8>,
) -> Error {
    Error::Preauth {
        code: codes::KDC_ERR_PREAUTH_REQUIRED,
        text: format!("{cname} must pre-authenticate"),
        method_data: method_data(entries, announced),
        state,
    }
}

/// `KDC_ERR_PREAUTH_FAILED` with the method data attached, which is how a client
/// learns the salt it should have used.
fn preauth_failed(cname: &Principal, entries: &[EtypeInfo2Entry], why: &str) -> Error {
    Error::Preauth {
        code: codes::KDC_ERR_PREAUTH_FAILED,
        text: format!("{cname}: {why}"),
        method_data: method_data(entries, &[]),
        state: Vec::new(),
    }
}

impl Kdc {
    /// Handles an `AS-REQ`.
    pub(super) fn handle_as(&self, req: &KdcReq, now: i64, raw: &[u8]) -> Result<Vec<u8>> {
        // FAST first: if the client armored the exchange, the request that matters is
        // the one inside the armor, and the reply has to be armored back.
        let Some(armored_bytes) = req.padata(super::fast::PA_FX_FAST) else {
            return self.answer_as(&req.body, &req.padata, now, None, false, raw, &req.raw_body);
        };
        let armored = super::fast::ArmoredRequest::decode(armored_bytes)?;
        let armor_key = self.armor_key(&armored, now)?;
        let inner = super::fast::unwrap(&armored, &armor_key, &req.raw_body, self.cipher())?;
        let mut r = crate::der::Reader::new(&inner.req_body);
        let content = r.expect_in("KrbFastReq req-body", crate::der::SEQUENCE)?;
        let body = KdcReqBody::decode(content)?;

        // `hide-client-names` decides how much of the outer body means anything: with it
        // set, RFC 6113 §5.4.4.2 says the client identity in the outer body is to be
        // **ignored**, so comparing realms would refuse a request that hid its names on
        // purpose. Without it, the two bodies are one request sent twice and must agree.
        let options = inner.options();
        if let Some(bad) = super::fast::unsupported_critical(options) {
            return Err(Error::Kdc {
                code: codes::KDC_ERR_UNKNOWN_CRITICAL_FAST_OPTIONS,
                text: format!(
                    "PA-FX-FAST: unsupported critical fast-options {bad:#010x}; this KDC \
                     implements hide-client-names only"
                ),
            });
        }
        let hide = options & super::fast::HIDE_CLIENT_NAMES != 0;
        if !hide && body.realm != req.body.realm {
            // The armored body is the one answered, but the outer body is what was
            // signed; a pair that disagrees about the realm is not a request this KDC
            // can make sense of.
            return Err(Error::Protocol(
                "PA-FX-FAST: the armored body names a different realm than the request".into(),
            ));
        }
        self.answer_as(
            &body,
            &inner.padata,
            now,
            Some(&armor_key),
            hide,
            raw,
            &inner.req_body,
        )
    }

    /// The key an armored request is encrypted under: the session key of the ticket its
    /// armor presents.
    ///
    /// The armor ticket must be a `krbtgt` of this realm — a client armors with its own
    /// TGT, and a ticket for anything else would let any service's key open a login it
    /// has nothing to do with.
    pub(super) fn armor_key(&self, armored: &super::fast::ArmoredRequest, now: i64) -> Result<Key> {
        self.armor_key_inner(armored, now, true)
    }

    /// The same derivation without the freshness check.
    ///
    /// The error path needs the armor key to wrap a refusal, and it runs after the request
    /// was accepted far enough to be refused. Re-checking the clock there would turn a clear
    /// refusal into an unreadable one — the error would fail to wrap because the error path
    /// itself insisted on a condition the request had already failed.
    pub(super) fn armor_key_for_error(
        &self,
        armored: &super::fast::ArmoredRequest,
        now: i64,
    ) -> Result<Key> {
        self.armor_key_inner(armored, now, false)
    }

    fn armor_key_inner(
        &self,
        armored: &super::fast::ArmoredRequest,
        now: i64,
        validate: bool,
    ) -> Result<Key> {
        let armor = armored.armor.as_ref().ok_or_else(|| Error::Kdc {
            code: codes::KDC_ERR_PREAUTH_FAILED,
            text: "PA-FX-FAST without armor".into(),
        })?;
        if armor.armor_type != 1 {
            return Err(Error::Kdc {
                code: codes::KDC_ERR_PREAUTH_FAILED,
                text: format!(
                    "PA-FX-FAST armor type {}: only 1 (an AP-REQ) is defined",
                    armor.armor_type
                ),
            });
        }
        let ap_req = crate::msg::ApReq::decode(&armor.armor_value)?;
        let ticket = ap_req.ticket()?;
        let krbtgt = Principal::krbtgt(self.config().realm());
        if ticket.sname != krbtgt {
            return Err(Error::Kdc {
                code: codes::KRB_AP_ERR_MODIFIED,
                text: format!(
                    "PA-FX-FAST armor presents a ticket for {}, not {krbtgt}; only a TGT \
                     of this realm may armor an AS exchange",
                    ticket.sname
                ),
            });
        }
        let entry = self
            .hdb()
            .fetch(&krbtgt)?
            .ok_or_else(|| Error::Hdb("the krbtgt entry is missing from the database".into()))?;
        let part = self.decrypt_ticket(&ticket, &entry)?;
        if now > part.endtime {
            return Err(Error::Kdc {
                code: codes::KRB_AP_ERR_TKT_EXPIRED,
                text: format!("the armor TGT expired at {}", part.endtime),
            });
        }

        // The armor key is **not** the ticket's session key when the client put a subkey
        // in the authenticator — which every client does, MIT's included, because a
        // subkey can be discarded afterwards and the TGT's session key cannot. RFC 6113
        // §5.4.1: `cf2(subkey, "subkeyarmor", session key, "ticketarmor")`. Using the
        // session key directly here produces a checksum mismatch against every real
        // client while agreeing perfectly with a client of one's own.
        let authenticator = crate::msg::Authenticator::decode(
            &self
                .cipher()
                .decrypt(
                    &part.session_key,
                    super::fast::usage::AP_REQ_AUTH,
                    &ap_req.authenticator.cipher,
                )
                .map_err(|_| Error::Kdc {
                    code: codes::KRB_AP_ERR_BAD_INTEGRITY,
                    text: "PA-FX-FAST: the armor authenticator does not open with the \
                           ticket's session key"
                        .into(),
                })?,
        )?;
        // RFC 4120 §3.2.3: an authenticator outside the clock skew is either a replay from
        // long ago or a client with a broken clock, and both must fail before anything is
        // derived from it. Heimdal reaches the same place through `krb5_verify_ap_req2`;
        // skipping it made this path accept an authenticator of any age.
        let skew = now.saturating_sub(authenticator.ctime);
        if validate && skew.abs() > self.config().clockskew() {
            return Err(Error::Kdc {
                code: codes::KRB_AP_ERR_SKEW,
                text: format!(
                    "PA-FX-FAST: the armor authenticator is {skew} seconds from this KDC's \
                     clock, and the allowed skew is {}",
                    self.config().clockskew()
                ),
            });
        }
        // No replay cache here, on purpose, and the live client is why.
        //
        // RFC 4120 §3.2.3 obliges a *server* to refuse an authenticator it has seen, and
        // the obvious reading is that a KDC is such a server. It is not: the armor AP-REQ
        // is not the credential — it names a key, and the authentication is the
        // `PA-ENCRYPTED-CHALLENGE` inside. Recorded evidence: `krb5` 1.0 builds its armor
        // once per login (`if armored && armor.is_none()`), then re-sends the *same*
        // `AP-REQ` after `PREAUTH_REQUIRED` to send the challenge — so a cache keyed on
        // (client, ctime, cusec) refused an honest login with `KRB_AP_ERR_REPEAT`, and that
        // client is tested against a live MIT KDC, which means MIT's KDC does not
        // replay-check armor either.
        //
        // Replaying an armored request gains an attacker nothing: the reply is sealed in a
        // reply key strengthened by a random value that travels only inside the armor. The
        // freshness check above is still worth having — a stale authenticator is a client
        // fighting the clock — but treating the armor as a single-use token is not.

        let Some(subkey) = authenticator.subkey else {
            return Ok(part.session_key);
        };
        let mixed = crate::crypto::kdf::cf2(
            subkey.bytes(),
            "subkeyarmor",
            part.session_key.enctype(),
            part.session_key.bytes(),
            "ticketarmor",
        )?;
        Ok(Key::new(part.session_key.enctype(), mixed)?)
    }

    /// The AS exchange proper, over a request that has already been unwrapped.
    ///
    /// `armor` is `Some` when the request arrived inside `PA-FX-FAST`; the reply is then
    /// sealed in a strengthened key and its `padata` travels inside
    /// `PA-FX-FAST-REPLY`.
    /// `hide` is RFC 6113's `hide-client-names`: the reply names
    /// `WELLKNOWN/ANONYMOUS` instead of the client, and the real name survives only inside
    /// the ticket, which is sealed with a service key.
    ///
    /// The argument list is long because each parameter is a distinct protocol input that
    /// the two callers (armored and plain) supply differently, and grouping them into a
    /// struct would name the grouping after the call sites rather than after the exchange.
    #[allow(clippy::too_many_arguments)]
    fn answer_as(
        &self,
        body: &KdcReqBody,
        padata: &[(i32, Vec<u8>)],
        now: i64,
        armor: Option<&Key>,
        hide: bool,
        raw: &[u8],
        body_der: &[u8],
    ) -> Result<Vec<u8>> {
        let config = self.config();
        if !super::same_realm(&body.realm, config.realm()) {
            return Err(super::wrong_realm(&body.realm, config.realm()));
        }

        // 2. The client. An AS-REQ without a client name cannot be answered:
        // there is nobody to encrypt the reply for.
        let mut cname = body
            .cname
            .clone()
            .ok_or_else(|| Error::Protocol("AS-REQ without a client name".into()))?;
        // The client's spelling of the realm is folded into ours before anything looks the name up:
        // a lookup compares the realm of the principal against this KDC's, and a client that took
        // its realm from a DNS name would otherwise be told its own account does not exist.
        //
        // A `NT-PRINCIPAL` name carries no realm of its own - the realm is the request's, in the
        // body - so the empty one is filled from there first.
        if cname.realm.is_empty() {
            cname.realm = body.realm.clone();
        }
        super::fold_realm(&mut cname, config.realm());
        // RFC 6806 §6: an enterprise name is resolved to the principal it names, and the
        // reply carries that canonical name — which is only legal because the client asked
        // for it with `canonicalize`.
        let cname = canonical_client_name(&cname, body.kdc_options, config.realm())?;

        // RFC 8062 §4.1: an anonymous client is answered before the directory is
        // consulted. There is no account behind `WELLKNOWN/ANONYMOUS`, and inventing one
        // would defeat the mode: the whole point is that the KDC learns nothing about who
        // asked, which it cannot do while looking the asker up.
        if is_anonymous(&cname) {
            // PKINIT is what makes an anonymous ticket possible at all: without a KDC key
            // pair there is nothing to derive a reply key from (RFC 8062 §4.1). A build
            // without the feature therefore refuses the name, rather than answering as
            // though the anonymous path did not exist.
            #[cfg(feature = "pkinit")]
            {
                return self.answer_anonymous_as(body, padata, now, raw, body_der, &cname);
            }
            #[cfg(not(feature = "pkinit"))]
            {
                let _ = (padata, raw, body_der);
                return Err(Error::Kdc {
                    code: codes::KDC_ERR_NULL_KEY,
                    text: "anonymous PKINIT is not compiled into this build: the `pkinit` \
                           feature carries the certificate handling it needs"
                        .into(),
                });
            }
        }
        if !super::name_type_ok(config, &cname) {
            return Err(Error::UnknownPrincipal(cname.to_string()));
        }
        let client = self
            .hdb()
            .fetch(&cname)?
            .ok_or_else(|| Error::UnknownPrincipal(cname.to_string()))?;
        if !client.is_valid_at(now) {
            return Err(Error::Kdc {
                code: codes::KDC_ERR_CLIENT_REVOKED,
                text: format!("{cname} is locked, disabled or expired"),
            });
        }
        if !client.has(entry_flags::CLIENT) {
            return Err(Error::Kdc {
                code: codes::KDC_ERR_POLICY,
                text: format!("{cname} is not a client principal"),
            });
        }

        // 3. The service. Only the ticket-granting service is issued here.
        let mut sname = body
            .sname
            .clone()
            .ok_or_else(|| Error::Protocol("AS-REQ without a service name".into()))?;
        // The same folding as the client: a client that spelled the realm from a DNS name asks for
        // `krbtgt/EXAMPLE.COM@example.com`, and that name is not in the database.
        super::fold_realm(&mut sname, config.realm());
        let server = self
            .hdb()
            .fetch(&sname)?
            .ok_or_else(|| Error::UnknownPrincipal(sname.to_string()))?;
        // Any service may be asked for here — that is what an "initial ticket" is,
        // and Heimdal allows it (`kdc/kerberos5.c` restricts an AS request only by
        // the entry's own flags). The opposite restriction lives in the TGS: an
        // entry with `initial` may *only* be reached this way, which is how
        // `kpasswd` keeps `kadmin/changepw` out of reach of a stolen TGT.
        if !server.has(entry_flags::SERVER) {
            return Err(Error::UnknownPrincipal(sname.to_string()));
        }

        // 4. Enctypes.
        //
        // Two orders over one set: the enctype the client is asked to pre-authenticate with and
        // the enctype of the session key it is granted are chosen by separate options in Heimdal,
        // because a realm may want the first to be strong while leaving the second to the client.
        let usable = usable_enctypes(config, &body.etypes, &client, Purpose::Preauth);
        if usable.is_empty() {
            return Err(Error::UnsupportedEnctype(
                body.etypes.first().copied().unwrap_or(0),
            ));
        }
        let preauth_usable = order_enctypes(
            usable.clone(),
            &body.etypes,
            if config.preauth_use_strongest_session_key() {
                EnctypeOrder::KdcPreferred
            } else {
                EnctypeOrder::ClientPreferred
            },
        );
        let session_usable = order_enctypes(
            usable.clone(),
            &body.etypes,
            if config.svc_use_strongest_session_key() {
                EnctypeOrder::KdcPreferred
            } else {
                EnctypeOrder::ClientPreferred
            },
        );
        let entries = etype_info2(&client, &preauth_usable);

        // 4b. Multi-round pre-authentication (SPAKE, OTP).
        //
        // Run before the single-round methods because a mechanism decides the reply key
        // itself: under SPAKE it is derived from the exchange, not from the long-term key,
        // so the timestamp path could not compute it even in principle.
        let longterm: Vec<Key> = preauth_usable
            .iter()
            .filter_map(|e| client.key_for(*e).map(|k| k.key.clone()))
            .collect();
        let context = super::preauth::Request {
            cname: &cname,
            realm: config.realm(),
            body: body_der,
            longterm: &longterm,
            armor,
            now,
            cipher: self.cipher(),
        };
        let (announced, announced_state) = self.preauth().announce_all(&context)?;
        let mut mechanism_key: Option<Key> = None;
        let mut mechanism_padata: Option<Vec<u8>> = None;
        // A mechanism that knows how long its authentication lasts bounds the ticket by it.
        let mut mechanism_bound: Option<i64> = None;
        if let Some((mechanism, value)) = self.preauth().requested(padata) {
            let resumed = self.resume_state(padata, now, config.realm(), Some(&cname));
            match mechanism.round(&context, &resumed, &value) {
                Ok(super::preauth::Step::More { padata, state }) => {
                    // Not a refusal: the client answers with another request and the cookie
                    // carries what this round learned. Returning PREAUTH_FAILED here would
                    // make every multi-round mechanism look like a wrong password.
                    return Err(Error::Preauth {
                        code: super::preauth::MORE_PREAUTH_DATA_REQUIRED,
                        text: format!("{cname}: {} needs another round", mechanism.name()),
                        method_data: encode_pa_data(&[(mechanism.pa_type(), padata)]),
                        state,
                    });
                }
                Ok(super::preauth::Step::Done {
                    reply_key,
                    padata,
                    endtime_bound,
                }) => {
                    mechanism_key = Some(reply_key);
                    mechanism_padata = padata;
                    mechanism_bound = endtime_bound;
                }
                Ok(super::preauth::Step::Failed { code, text }) => {
                    return Err(Error::Kdc {
                        code,
                        text: format!("{cname}: {}: {text}", mechanism.name()),
                    });
                }
                Err(err) => {
                    return Err(Error::Kdc {
                        code: codes::KDC_ERR_PREAUTH_FAILED,
                        text: format!("{cname}: {}: {err}", mechanism.name()),
                    });
                }
            }
        }

        // 5. Pre-authentication.
        //
        // PKINIT first, when the realm offers it and the client asked for it: the reply key
        // comes from a Diffie-Hellman exchange rather than from anything in the request, and
        // the `PA-PK-AS-REP` that lets the client derive it is built here because it has to
        // travel in the same reply.
        #[cfg(feature = "pkinit")]
        let pkinit_answer = match (
            padata_value(padata, super::pkinit::PA_PK_AS_REQ),
            self.pkinit(),
        ) {
            (Some(value), Some(state)) => {
                // A source that could not produce an identity is an outage, not a realm without
                // the feature, and it is reported as one: `KDC_ERR_NULL_KEY` would tell the client
                // to try a mechanism this realm does not offer at all.
                let state = match state {
                    Ok(state) => state,
                    Err(e) => {
                        return Err(Error::Kdc {
                            code: codes::KDC_ERR_PREAUTH_FAILED,
                            text: format!("PKINIT: the realm has no usable identity: {e}"),
                        });
                    }
                };
                let server_key_enctype = session_usable[0];
                // The private exponent comes from the same source as the session keys. A
                // failure there is a broken RNG and must not degrade into a predictable
                // key, so it is a refusal rather than a retry.
                let entropy = self.cipher().random(Enctype::Aes256Sha1)?.bytes().to_vec();
                let answer = super::pkinit::reply::answer(
                    &state,
                    value,
                    body_der,
                    raw,
                    &cname,
                    &Principal::krbtgt(config.realm()),
                    server_key_enctype,
                    now,
                    &|n| {
                        let mut bytes = entropy.clone();
                        bytes.resize(n, 0);
                        bytes.truncate(n);
                        bytes
                    },
                );
                match answer {
                    Ok(a) => Some(a),
                    Err(super::pkinit::PkinitError::GroupTooWeak { have, want }) => {
                        // The one PKINIT refusal with a next step (RFC 4556 §3.2.4): the groups
                        // this realm accepts go back as `TD-DH-PARAMETERS`, and a client that has
                        // a stronger one retries. A generic failure would end a login that has a
                        // remedy, and raising `pkinit_dh_min_bits` would silently break every
                        // PKINIT client rather than move it up a group.
                        let accepted: Vec<super::pkinit::dh::Group> = [2048u32, 4096]
                            .into_iter()
                            .filter(|bits| *bits >= want)
                            .map(super::pkinit::dh::Group::at_least)
                            .collect();
                        return Err(Error::Preauth {
                            code: codes::KDC_ERR_DH_KEY_PARAMETERS_NOT_ACCEPTED,
                            text: format!(
                                "the client's Diffie-Hellman group is {have} bits, and this \
                                 realm requires at least {want}"
                            ),
                            method_data: super::pkinit::td_dh_parameters(&accepted),
                            // No state: the next round restarts the exchange with a stronger
                            // group, and there is nothing from this one to carry into it.
                            state: Vec::new(),
                        });
                    }
                    Err(e) => {
                        return Err(Error::Kdc {
                            code: codes::KDC_ERR_PREAUTH_FAILED,
                            text: format!("PKINIT: {e}"),
                        });
                    }
                }
            }
            (Some(_), None) => {
                return Err(Error::Kdc {
                    code: codes::KDC_ERR_PREAUTH_FAILED,
                    text: "PA-PK-AS-REQ: this realm does not accept certificate logins".into(),
                });
            }
            (None, _) => None,
        };

        // Two other methods; which one is acceptable depends on the armor, not on the
        // client's preference. Inside FAST the plain timestamp is refused: a `PA-ENC-TIMESTAMP`
        // sealed directly in the long-term key is the offline oracle the armor exists to
        // close, so accepting it there would leave the hole open behind a lock.
        let timestamp = padata_value(padata, PA_ENC_TIMESTAMP);
        let challenge = padata_value(padata, super::fast::PA_ENCRYPTED_CHALLENGE);
        let preauthenticated =
            mechanism_key.is_some() || timestamp.is_some() || challenge.is_some() || {
                #[cfg(feature = "pkinit")]
                {
                    pkinit_answer.is_some()
                }
                #[cfg(not(feature = "pkinit"))]
                {
                    false
                }
            };
        #[cfg(feature = "pkinit")]
        let pkinit_key = pkinit_answer.as_ref().map(|a| a.reply_key.clone());
        #[cfg(not(feature = "pkinit"))]
        let pkinit_key: Option<Key> = None;

        let reply_key = if let Some(key) = mechanism_key {
            key
        } else if let Some(key) = pkinit_key {
            key
        } else if let Some(value) = challenge {
            // A challenge cannot be answered without the armor: its key is
            // `cf2(armor, …, long-term, …)`, so a client that sends one unarmored is
            // asking this KDC to invent a secret it does not have.
            let Some(armor_key) = armor else {
                return Err(preauth_failed(
                    &cname,
                    &entries,
                    "PA-ENCRYPTED-CHALLENGE requires FAST armor",
                ));
            };
            match self.verify_enc_challenge(&client, &usable, value, armor_key, now) {
                Ok(key) => key,
                Err(err) => return Err(with_salts(err, &cname, &entries)),
            }
        } else if let Some(value) = timestamp {
            if armor.is_some() {
                return Err(preauth_failed(
                    &cname,
                    &entries,
                    "PA-ENC-TIMESTAMP is not accepted inside FAST: \
                     use PA-ENCRYPTED-CHALLENGE",
                ));
            }
            match self.verify_enc_timestamp(&client, &usable, value, now) {
                Ok(key) => key,
                Err(err) => return Err(with_salts(err, &cname, &entries)),
            }
        } else if config.require_preauth() || client.has(entry_flags::REQUIRE_PREAUTH) {
            return Err(preauth_required(
                &cname,
                &entries,
                &announced,
                announced_state,
            ));
        } else {
            client
                .key_for(session_usable[0])
                .map(|k| k.key.clone())
                .ok_or_else(|| preauth_failed(&cname, &entries, "no key for the session enctype"))?
        };

        // 6. Flags and times.
        let may_postdate = may_postdate(body, &client, &server)?;
        let start = starttime(body, &client);
        let effective_start = start.unwrap_or(now);
        let endtime = endtime(config, body, &client, &server, effective_start);
        // A mechanism's own bound (`Step::Done::endtime_bound`): GSS pre-authentication caps a
        // ticket at the lifetime of the context that authenticated it. Like the PKINIT bound
        // below, it only ever shortens — a mechanism cannot buy a longer ticket than the policy
        // allows.
        let endtime = match mechanism_bound {
            Some(bound) if bound > 0 => endtime.min(effective_start.saturating_add(bound)),
            _ => endtime,
        };
        // `pkinit_max_life_bound`: Heimdal lets a realm cap what a certificate login buys, and it
        // is a cap on this exchange only — a password login is bounded by the policy above. The
        // bound never extends a lifetime, only shortens one.
        //
        // Shadowed rather than mutated, so that a build without the feature compiles without a
        // `mut` that nothing there needs.
        #[cfg(feature = "pkinit")]
        let endtime = match (pkinit_answer.is_some(), config.pkinit_policy().max_life) {
            (true, Some(bound)) => endtime.min(effective_start.saturating_add(bound)),
            _ => endtime,
        };
        if endtime <= effective_start {
            return Err(Error::Kdc {
                code: codes::KDC_ERR_NEVER_VALID,
                text: "the requested lifetime ends before it starts".into(),
            });
        }
        // `renewable-ok`: the client said "a renewable one is better than a short one". Heimdal
        // reads it as: if the granted lifetime stops short of what was asked for, hand back a
        // renewable ticket whose renew-till reaches the original request. Only then — a client that
        // got the lifetime it asked for did not ask for renewability, and giving it anyway would
        // make the flag mean "always renewable" (RFC 4120 §5.4.1).
        let mut renewable = body.kdc_options & kdc_options::RENEWABLE != 0;
        let mut renew_till = renew_till(config, body, &client, &server, effective_start);
        if !renewable
            && body.kdc_options & crate::msg::kdc_options::RENEWABLE_OK != 0
            && endtime < super::till_of(body)
        {
            renewable = true;
            renew_till = Some({
                let asked = super::till_of(body);
                let mut till =
                    asked.min(effective_start.saturating_add(config.max_renewable_life()));
                if let Some(max) = client.max_renew {
                    till = till.min(effective_start.saturating_add(max));
                }
                if let Some(max) = server.max_renew {
                    till = till.min(effective_start.saturating_add(max));
                }
                till
            });
        }
        // RFC 6806 §11: the flag and the checksum move together — a client reads the flag to
        // decide whether to look for the checksum, so one without the other is a reply it
        // rejects as modified.
        let wants_enc_pa_rep = super::req_enc_pa_rep::requested(padata);
        let mut flags = ticket_flags(
            body,
            &client,
            &server,
            preauthenticated,
            renewable && renew_till.is_some(),
            may_postdate,
            start,
        );
        if wants_enc_pa_rep {
            flags |= tkt_flags::ENC_PA_REP;
        }

        // 7. One session key, written into both the ticket and the reply: two
        // keys would mean the client holds one the ticket does not accept.
        let session_key = self.cipher().random(session_usable[0])?;
        // The ticket is sealed in a key of an enctype the client asked for and this
        // KDC allows — not in the strongest key the entry happens to hold.
        //
        // `enctypes()` answers "which keys does this entry have", strongest first;
        // `usable` answers "which may be issued here", and those are different
        // questions. Picking from the first ignores `allowed_enctypes` completely, so
        // a realm configured for AES-SHA1 only issued tickets sealed in AES-SHA384 —
        // the operator's restriction silently not applied. impacket found it: it asked
        // for AES-SHA1 and got a ticket it could not even name the enctype of.
        let server_key = usable
            .iter()
            .find_map(|e| server.key_for(*e))
            .ok_or_else(|| {
                Error::Hdb("the krbtgt entry has no key for any usable enctype".into())
            })?;

        let ticket_part = EncTicketPart {
            flags,
            session_key: session_key.clone(),
            crealm: client.principal.realm.clone(),
            cname: client.principal.clone(),
            // No realm has been traversed: this ticket was issued by the realm
            // that names it (RFC 4120 §3.3.3.2).
            transited_type: 0,
            transited: Vec::new(),
            authtime: now,
            starttime: start,
            endtime,
            renew_till,
            // Good from where the client said it would be.
            caddr: body.addresses.clone(),
            // A PAC, when this realm issues them: the client's identity from the
            // directory, signed with this ticket's service key and countersigned with
            // `krbtgt`'s.
            authorization_data: if self.include_pac(
                &server,
                is_root_tgt(&server.principal),
                super::pac_attributes(padata),
            ) {
                self.pac_authorization_data(&client.principal, &server_key.key, now)?
            } else {
                None
            },
        };
        let ticket = Ticket {
            realm: config.realm().to_owned(),
            sname: server.principal.clone(),
            enc: EncryptedData::seal(
                self.cipher(),
                &server_key.key,
                usage::KDC_REP_TICKET,
                Some(server_key.kvno),
                &ticket_part.encode(),
            )?,
        };
        // The encoded ticket, before the reply is assembled: `finished` checksums the
        // ticket as the client will receive it, so it has to be the same octets.
        let ticket_der = ticket.encode();

        let mut rep_part = EncKdcRepPart {
            session_key,
            // Heimdal always sends at least one `last_req`: MIT's ASN.1 cannot
            // tell a zero-length SEQUENCE OF from an indefinite length, and
            // refuses the reply without it.
            last_req: vec![(0, client.pw_end.unwrap_or(0))],
            nonce: body.nonce,
            key_expiration: client.pw_end,
            flags,
            authtime: now,
            starttime: start,
            endtime,
            renew_till,
            srealm: server.principal.realm.clone(),
            sname: server.principal.clone(),
            caddr: body.addresses.clone(),
            padata: Vec::new(),
        };
        // Under PKINIT the reply key came from a Diffie-Hellman exchange, so there is no
        // long-term key for an attacker to guess at and nothing to strengthen: the key
        // exists only on the two machines that took part.
        #[cfg(feature = "pkinit")]
        let pkinit_reply = pkinit_answer.is_some();
        #[cfg(not(feature = "pkinit"))]
        let pkinit_reply = false;

        // With FAST the reply key is strengthened by a random secret that only the
        // armor carries, so a recorded reply cannot be attacked offline. Without FAST
        // it stays the client's long-term key, which is what every client expects.
        let (strengthen_key, sealed_with) = match (armor, pkinit_reply) {
            (_, true) => (None, reply_key.clone()),
            (Some(_), false) => {
                let (strength, strengthened) = super::fast::strengthen(self.cipher(), &reply_key)?;
                (Some(strength), strengthened)
            }
            (None, false) => (None, reply_key.clone()),
        };

        // RFC 6806 §11: the checksum is over the request *as received*, keyed with the key the
        // client will reconstruct. Under FAST that is the strengthened key — the same one that
        // opens this part — which is why it cannot be computed before the strengthening.
        if wants_enc_pa_rep {
            rep_part.padata = vec![(
                super::req_enc_pa_rep::PA_REQ_ENC_PA_REP,
                super::req_enc_pa_rep::checksum(
                    self.cipher(),
                    &sealed_with,
                    super::req_enc_pa_rep::KU_AS_REQ,
                    raw,
                )?,
            )];
            // Heimdal's `add_enc_pa_rep` adds this beside the checksum, and it carries more than
            // the checksum does: MIT's client reads "FAST is available" from the presence of
            // PA-FX-FAST here, and from *that* concludes the KDC supports S4U. A KDC that sent
            // only the checksum would be a KDC with protocol transition nobody ever tries.
            rep_part.padata.push((super::fast::PA_FX_FAST, Vec::new()));
        }

        let enc_part = EncryptedData::seal(
            self.cipher(),
            &sealed_with,
            usage::AS_REP_ENCPART,
            Some(client.kvno()),
            &rep_part.encode(crate::msg::ENC_AS_REP_PART),
        )?;

        // Heimdal repeats the etype information in the reply, so a client that read the
        // salt from the error still sees it here. Inside FAST it travels in the armor,
        // because a salt in the clear is one more thing to attack.
        let mut padata_out = vec![(PA_ETYPE_INFO2, encode_etype_info2(&entries))];
        // Whatever the mechanism wants the client to see in the reply — SPAKE's `encdata`
        // is what lets the client finish the exchange, so a reply without it is a reply
        // the client cannot check.
        if let Some(value) = mechanism_padata
            && let Some((mechanism, _)) = self.preauth().requested(padata)
        {
            padata_out.push((mechanism.pa_type(), value));
        }
        #[cfg(feature = "pkinit")]
        if let Some(answer) = &pkinit_answer {
            // The client needs this to derive the reply key; without it the `enc-part` it
            // receives is unreadable, and the failure looks like a broken KDC.
            padata_out.push((super::pkinit::PA_PK_AS_REP, answer.pa_pk_as_rep.clone()));
        }
        if let Some(key) = armor {
            // The KDC's own challenge: the client asked for "prove you hold my
            // long-term key", and a KDC that cannot answer is indistinguishable from an
            // impostor that relays the armor. The reply key is the long-term one — that
            // is what was verified — so it is the key this proof is built on.
            padata_out.push((
                super::fast::PA_ENCRYPTED_CHALLENGE,
                super::fast::kdc_challenge(
                    self.cipher(),
                    key,
                    &reply_key,
                    now,
                    (now.rem_euclid(1_000_000)) as u32,
                )?,
            ));
            let finish = super::fast::finished(
                self.cipher(),
                key,
                &ticket_der,
                &client.principal,
                now,
                (now.rem_euclid(1_000_000)) as u32,
            )?;
            padata_out = vec![(
                super::fast::PA_FX_FAST_REPLY,
                super::fast::wrap_reply(
                    key,
                    &padata_out,
                    strengthen_key.as_ref(),
                    Some(finish),
                    body.nonce,
                    self.cipher(),
                )?,
            )];
        }

        // `hide-client-names`: the outer reply is the one an observer reads, so under this
        // option it names the anonymous principal. The ticket keeps the real client —
        // it is encrypted under the service key, and the client is the only one who needs
        // to know whom the ticket is about.
        let (crealm, cname) = if hide {
            let anonymous = super::fast::anonymous_principal();
            (anonymous.realm.clone(), anonymous)
        } else {
            (client.principal.realm.clone(), client.principal.clone())
        };

        Ok(KdcRep {
            msg_type: AS_REP,
            padata: padata_out,
            crealm,
            cname,
            ticket,
            enc_part,
        }
        .encode())
    }

    /// Verifies `PA-ENCRYPTED-CHALLENGE` (RFC 6113 §5.4.6) and returns the long-term
    /// key it proves.
    ///
    /// The challenge opens with
    /// `cf2(armor, "clientchallengearmor", long-term, "challengelongterm")`, so it proves
    /// two things at once and neither alone: possession of the armor ticket *and*
    /// knowledge of the password. That is why the plain timestamp is refused inside FAST
    /// rather than merely deprecated — accepting it would let anyone holding a TGT
    /// (a stolen laptop, a compromised host) log in without the password.
    fn verify_enc_challenge(
        &self,
        client: &HdbEntry,
        usable: &[Enctype],
        value: &[u8],
        armor_key: &Key,
        now: i64,
    ) -> Result<Key> {
        let ed = EncryptedData::decode("PA-ENCRYPTED-CHALLENGE", value)?;
        if !usable.contains(&ed.etype) {
            return Err(Error::PreauthFailed(format!(
                "PA-ENCRYPTED-CHALLENGE is {}, which was not offered",
                ed.etype.name()
            )));
        }
        let long_term = client
            .key_for(ed.etype)
            .ok_or_else(|| Error::PreauthFailed(format!("no {} key", ed.etype.name())))?;
        let key = super::fast::client_challenge_key(armor_key, &long_term.key)?;
        let plain = self
            .cipher()
            .decrypt(&key, super::fast::usage::ENC_CHALLENGE_CLIENT, &ed.cipher)
            .map_err(|_| {
                Error::PreauthFailed(
                    "PA-ENCRYPTED-CHALLENGE did not open: wrong password, or an armor \
                     this client did not use"
                        .into(),
                )
            })?;
        let (timestamp, _usec) = decode_enc_ts_enc(&plain)?;
        let skew = now.saturating_sub(timestamp);
        if skew.abs() > self.config().clockskew() {
            return Err(Error::Skew {
                skew,
                allowed: self.config().clockskew(),
            });
        }
        Ok(long_term.key.clone())
    }

    /// Verifies `PA-ENC-TIMESTAMP` against the entry's keys and returns the key
    /// that worked.
    fn verify_enc_timestamp(
        &self,
        client: &HdbEntry,
        usable: &[Enctype],
        value: &[u8],
        now: i64,
    ) -> Result<Key> {
        let ed = EncryptedData::decode("PA-ENC-TIMESTAMP", value)?;
        if !usable.contains(&ed.etype) {
            return Err(Error::PreauthFailed(format!(
                "PA-ENC-TIMESTAMP is {}, which was not offered",
                ed.etype.name()
            )));
        }
        let key = client
            .key_for(ed.etype)
            .ok_or_else(|| Error::PreauthFailed(format!("no {} key", ed.etype.name())))?;
        let plain = self
            .cipher()
            .decrypt(&key.key, usage::AS_REQ_PA_ENC_TS, &ed.cipher)
            .map_err(|_| Error::PreauthFailed("PA-ENC-TIMESTAMP did not decrypt".into()))?;
        let (timestamp, _usec) = decode_enc_ts_enc(&plain)?;
        // The timestamp is the whole proof: encrypted in the client's long-term
        // key, so only the real client could produce it, and inside the clock
        // skew, so it is not a recording. Checking only the decryption would
        // accept a replay forever.
        let skew = now.saturating_sub(timestamp);
        if skew.abs() > self.config().clockskew() {
            return Err(Error::Skew {
                skew,
                allowed: self.config().clockskew(),
            });
        }
        Ok(key.key.clone())
    }

    /// Answers an anonymous `AS-REQ` (RFC 8062 §4.1).
    ///
    /// Kept apart from the password path on purpose: an anonymous login has no account, no
    /// long-term key, no `etype-info`, no PAC and no pre-authentication list, so threading it
    /// through the ordinary flow would fill that flow with branches about a case it is not.
    #[cfg(feature = "pkinit")]
    fn answer_anonymous_as(
        &self,
        body: &KdcReqBody,
        padata: &[(i32, Vec<u8>)],
        now: i64,
        raw: &[u8],
        body_der: &[u8],
        cname: &Principal,
    ) -> Result<Vec<u8>> {
        let config = self.config();
        let anonymous = super::fast::anonymous_principal();

        // §4.1: "If the client in the AS request is anonymous, the anonymous KDC option MUST
        // be set"; without it the refusal is a named code, not a guess at intent.
        if body.kdc_options & crate::msg::kdc_options::ANONYMOUS == 0 {
            return Err(Error::Kdc {
                code: codes::KDC_ERR_BADOPTION,
                text: "the anonymous principal needs the `anonymous` kdc-option (RFC 8062 \
                       §4.1); without it this is a request to log in as a name that exists \
                       nowhere"
                    .into(),
            });
        }

        // An anonymous ticket is an opening into the realm. A realm that did not open it
        // says so, with its own code rather than a failure the client would retry.
        if !config.anonymous_pkinit() {
            return Err(Error::Kdc {
                code: codes::KDC_ERR_POLICY,
                text: "anonymous PKINIT is not enabled for this realm; an anonymous ticket \
                       is issued only where an administrator asked for one"
                    .into(),
            });
        }

        let Some(state) = self.pkinit() else {
            // RFC 8062 §4.1: with no key to encrypt the reply the KDC returns NULL_KEY.
            return Err(Error::Kdc {
                code: codes::KDC_ERR_NULL_KEY,
                text: "anonymous PKINIT needs a KDC certificate, and this KDC has none \
                       configured"
                    .into(),
            });
        };
        let state = state.map_err(|e| Error::Kdc {
            code: codes::KDC_ERR_NULL_KEY,
            text: format!("anonymous PKINIT: the realm's identity is unusable: {e}"),
        })?;

        let value =
            padata_value(padata, super::pkinit::PA_PK_AS_REQ).ok_or_else(|| Error::Kdc {
                code: codes::KDC_ERR_PREAUTH_FAILED,
                text: "anonymous PKINIT carries an unsigned PA-PK-AS-REQ (RFC 8062 §4.1); \
                   without one there is nothing to derive a reply key from"
                    .into(),
            })?;

        // The reply key's enctype comes from what the client asked for and this realm
        // allows — there is no entry whose keys could answer the question instead.
        let enctype = config
            .allowed_enctypes()
            .iter()
            .copied()
            .find(|e| body.etypes.contains(&e.id()))
            .ok_or_else(|| Error::UnsupportedEnctype(body.etypes.first().copied().unwrap_or(0)))?;

        let server = Principal::krbtgt(config.realm());
        let entry = self
            .hdb()
            .fetch(&server)?
            .ok_or_else(|| Error::Hdb("the krbtgt entry is missing from the database".into()))?;
        let server_key = usable_enctypes(config, &body.etypes, &entry, Purpose::Ticket)
            .into_iter()
            .find_map(|e| entry.key_for(e))
            .ok_or_else(|| {
                Error::Hdb("the krbtgt entry has no key for any usable enctype".into())
            })?;

        // The private exponent comes from the same source as every other secret here. A
        // broken RNG must fail loudly rather than produce a predictable key.
        let entropy = self.cipher().random(Enctype::Aes256Sha1)?.bytes().to_vec();
        let answer = super::pkinit::reply::answer_anonymous(
            &state,
            value,
            body_der,
            raw,
            cname,
            &server,
            enctype,
            &|n| entropy.iter().copied().cycle().take(n).collect(),
        )
        .map_err(|e| match e {
            super::pkinit::PkinitError::Unsupported(ref why) => Error::Kdc {
                code: if why.contains("public value") {
                    codes::KDC_ERR_PUBLIC_KEY_ENCRYPTION_NOT_SUPPORTED
                } else {
                    codes::KDC_ERR_PREAUTH_FAILED
                },
                text: format!("anonymous PKINIT: {e}"),
            },
            other => Error::Kdc {
                code: codes::KDC_ERR_PREAUTH_FAILED,
                text: format!("anonymous PKINIT: {other}"),
            },
        })?;
        let session_key = answer.session_key.clone().ok_or_else(|| Error::Kdc {
            code: codes::KDC_ERR_PREAUTH_FAILED,
            text: "anonymous PKINIT produced no session key".into(),
        })?;

        // Short-lived by policy: this ticket proves "somebody" and is meant to be replaced
        // by a real one as soon as the client can obtain it. It never outlives what the
        // client asked for.
        let endtime = body.till.min(now + 3600);
        if endtime <= now {
            return Err(Error::Kdc {
                code: codes::KDC_ERR_NEVER_VALID,
                text: "the requested lifetime ends before it starts".into(),
            });
        }
        let flags = tkt_flags::INITIAL | tkt_flags::PRE_AUTHENT | tkt_flags::ANONYMOUS;

        let ticket_part = EncTicketPart {
            flags,
            session_key: session_key.clone(),
            // §4.1: the reply's client realm is the anonymous realm, and the ticket's
            // client must match the reply's — a ticket and a reply that disagree are
            // unusable by any client.
            crealm: anonymous.realm.clone(),
            cname: anonymous.clone(),
            transited_type: 0,
            transited: Vec::new(),
            authtime: now,
            starttime: None,
            endtime,
            renew_till: None,
            caddr: body.addresses.clone(),
            // §4.1: no authorization data. A PAC here would name the account, which is the
            // one thing an anonymous ticket must not carry.
            authorization_data: None,
        };
        let ticket = Ticket {
            realm: config.realm().to_owned(),
            sname: server.clone(),
            enc: EncryptedData::seal(
                self.cipher(),
                &server_key.key,
                usage::KDC_REP_TICKET,
                Some(server_key.kvno),
                &ticket_part.encode(),
            )?,
        };

        let rep_part = EncKdcRepPart {
            session_key,
            last_req: vec![(0, 0)],
            nonce: body.nonce,
            key_expiration: None,
            flags,
            authtime: now,
            starttime: None,
            endtime,
            renew_till: None,
            srealm: server.realm.clone(),
            sname: server.clone(),
            caddr: body.addresses.clone(),
            // Anonymous PKINIT authenticates nobody and the client cannot have asked for a
            // request checksum before it had a key to check one with.
            padata: Vec::new(),
        };
        let enc_part = EncryptedData::seal(
            self.cipher(),
            &answer.reply_key,
            usage::AS_REP_ENCPART,
            None,
            &rep_part.encode(crate::msg::ENC_AS_REP_PART),
        )?;

        let mut padata_out = vec![(super::pkinit::PA_PK_AS_REP, answer.pa_pk_as_rep.clone())];
        if let Some(kx) = &answer.pa_pkinit_kx {
            // §7: the KDC's contribution to the session key. Without it the client cannot
            // recompute the key and — correctly — refuses the reply.
            padata_out.push((super::pkinit::PA_PKINIT_KX, kx.clone()));
        }

        Ok(KdcRep {
            msg_type: AS_REP,
            padata: padata_out,
            crealm: anonymous.realm.clone(),
            cname: anonymous,
            ticket,
            enc_part,
        }
        .encode())
    }
}

/// A pre-authentication failure carries the salts, so the client can see which
/// salt this KDC expects instead of guessing.
fn with_salts(err: Error, cname: &Principal, entries: &[EtypeInfo2Entry]) -> Error {
    match err {
        Error::PreauthFailed(why) => preauth_failed(cname, entries, &why),
        // A clock skew is not a wrong password: telling the client which salt
        // to use would suggest the credentials were the problem.
        other => other,
    }
}
