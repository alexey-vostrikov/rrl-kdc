//! The TGS exchange: `TGS-REQ` in, `TGS-REP` out.
//!
//! The request proves nothing by itself: it carries a `PA-TGS-REQ` — an
//! `AP-REQ` presenting a ticket — and everything this exchange decides rests on
//! that ticket and its authenticator. Heimdal's `_kdc_tgs_rep`
//! (`kdc/krb5tgs.c`) is the order followed here:
//!
//! 1. the realm is ours, and a `PA-TGS-REQ` is present;
//! 2. the ticket decrypts under `krbtgt/REALM` and has not expired — checked
//!    **before** the authenticator, because an expired ticket makes the
//!    authenticator irrelevant;
//! 3. the authenticator decrypts under the ticket's session key, names the same
//!    client, and its checksum covers the exact octets of `KDC-REQ-BODY`;
//! 4. the authenticator's clock is inside the skew;
//! 5. the service exists and may be a service;
//! 6. the ticket is issued, never longer-lived than the TGT it came from.
//!
//! `PA-FX-FAST` is accepted in the **implicit** form of RFC 6113 §5.4.2.6: the key comes
//! from the `PA-TGS-REQ` authenticator's subkey and the TGT's session key, the request
//! checksum covers the `AP-REQ`, and both the reply and any error travel back inside the
//! armor. An explicit armor ticket is refused by name rather than silently ignored.
//!
//! What is deliberately absent at this stage: referrals, S4U, `transited` across realms.
//! A request that needs one of them is answered with a code that says so, not with a
//! ticket that claims to be something it is not.

use crate::crypto::{Key, usage};
use crate::error::{Error, Result, codes};
use crate::hdb::{HdbEntry, flags as entry_flags};
use crate::msg::KdcReqBody;
use crate::msg::{
    self, ApReq, Authenticator, EncKdcRepPart, EncTicketPart, EncryptedData, KdcRep, KdcReq,
    PA_TGS_REQ, TGS_REP, Ticket, kdc_options, tkt_flags,
};
use crate::name::Principal;

use super::Kdc;
use super::as_exchange::Purpose;
use super::config::TransitedPolicy;
use super::transited;

/// A `TGS-REQ` whose evidence has been checked: the client it proves, and the
/// TGT it came with.
#[derive(Debug)]
/// The request as it arrived: the PA-DATA a reply may answer and the octets a checksum covers.
///
/// One value rather than two arguments because they are the same fact — this is what the client
/// sent — and because `tgs_answer` already takes the body, the proof, the armor and the hiding
/// flag, none of which travel with them.
#[derive(Clone, Copy)]
struct Received<'a> {
    /// `PA-DATA` of the request that was answered (the inner one under FAST).
    padata: &'a [(i32, Vec<u8>)],
    /// The octets as they arrived, which is what RFC 6806 §11 checksums.
    raw: &'a [u8],
}

/// The armour a TGS request arrived in, and what the reply must do about it.
///
/// Three facts that always travel together and are read in one place each: whether there is an
/// armor key at all (which decides whether the reply is strengthened and wrapped), whether the
/// client presented an armor *ticket* rather than relying on the implicit key, and whether
/// `hide-client-names` asks the reply to name nobody. They were three parameters of `tgs_answer`
/// until the count reached the point clippy objects to; as a struct they are one thing, which is
/// also how the code reads them.
struct Armor<'a> {
    /// The reply key, when the exchange is armored (RFC 6113 §5.4.1). `None` for a plain request.
    key: Option<&'a Key>,
    /// Whether the armor was explicit: an `armor` AP-REQ presenting a TGT of this realm, rather
    /// than the implicit key derived from `PA-TGS-REQ`'s subkey.
    explicit: bool,
    /// `hide-client-names`: the reply names `WELLKNOWN/ANONYMOUS` instead of the client.
    hide: bool,
}

impl Armor<'_> {
    /// No armour: the request arrived as it was written.
    fn none() -> Self {
        Armor {
            key: None,
            explicit: false,
            hide: false,
        }
    }
}

/// What a constrained delegation decided.
///
/// The client comes from the evidence ticket, and so does `authtime`: the user authenticated
/// then, and this ticket exists because the service was trusted to remember it.
struct Proxy {
    user: Principal,
    authtime: i64,
}

/// What a protocol transition decided.
///
/// One struct rather than three return values: the identity, whether the ticket may be
/// forwardable, and the `PA-DATA` that has to come back are one decision, and separating them
/// invites a caller to use two of the three.
struct Transition {
    /// The user the service acts for.
    user: Principal,
    /// Whether `forwardable` survives into the ticket (MS-SFU §3.1.4).
    may_delegate: bool,
    /// `PA-S4U-X509-USER` for the reply, when the client sent one.
    reply: Option<(i32, Vec<u8>)>,
}

pub(super) struct Proven {
    /// The TGT's own part. A renewal and a validation are defined as edits to
    /// it, so it is carried whole rather than field by field.
    pub(super) tgt: EncTicketPart,
    /// The key the reply is encrypted in: the authenticator's subkey when it
    /// carried one, otherwise the TGT's session key.
    reply_key: Key,
    /// The usage that reply key pairs with (RFC 4120 §7.5.1): 9 for a subkey,
    /// 8 for the session key.
    reply_usage: u32,
    /// The authenticator's subkey, when it carried one. RFC 6113 §5.4.2.6 builds the
    /// implicit FAST armor key from this and the TGT's session key, so it has to survive
    /// the check rather than being folded into `reply_key`.
    pub(super) subkey: Option<Key>,
    /// The realm that issued the presented TGT — the `realm` field of the `Ticket`.
    ///
    /// It is what decides whether a realm is a *transit* realm: RFC 4120 §3.3.3.2 says the
    /// issuer "will be added to the transited field of the ticket to be issued", and Heimdal
    /// compares exactly this against the client's and the server's realms (`tgt_realm` in
    /// `kdc/krb5tgs.c`, taken from the `krbtgt/X@ISSUER` entry it decrypted with). The
    /// second component of `krbtgt/X` is *our* realm, not the issuer, and using it here would
    /// add the realm doing the work instead of the one before it — a three-realm hop would
    /// then reach the last KDC with an empty path.
    pub(super) tgt_issuer: String,
}

/// The extra ticket flags `forwarded` and `proxy` ask for (RFC 4120 §3.3.3), or a refusal.
///
/// Neither is a permission: `forwardable` and `proxiable` in the TGT permit a *future*
/// delegation, and these two ask for it now. A TGT issued without the flag is how an
/// operator says "this credential stays where it is", so the absence is refused rather than
/// worked around.
///
/// `passthrough` — the older name Kerberos uses for what a proxy ticket claims — is a
/// distinct protocol addition and is not set here; a ticket that claims it without the
/// address restrictions it implies would be read by a service as a delegated credential.
fn forwarding_plan(body: &KdcReqBody, tgt: &EncTicketPart, sname: &Principal) -> Result<u32> {
    let forwarded = body.kdc_options & kdc_options::FORWARDED != 0;
    let proxy = body.kdc_options & kdc_options::PROXY != 0;
    if !forwarded && !proxy {
        return Ok(0);
    }
    if forwarded && proxy {
        return Err(badoption(
            "a ticket cannot be both forwarded and proxied: the first is used by this \
             client from another address, the second is handed to somebody else, and a \
             ticket claiming both tells a service nothing about which it received",
        ));
    }
    if forwarded {
        if tgt.flags & tkt_flags::FORWARDABLE == 0 {
            return Err(badoption(
                "the forwarded option needs a forwardable TGT, and this one is not: the \
                 realm did not permit this credential to be used from another address",
            ));
        }
        return Ok(tkt_flags::FORWARDED);
    }
    // The proxy branch.
    if tgt.flags & tkt_flags::PROXIABLE == 0 {
        return Err(badoption(
            "the proxy option needs a proxiable TGT, and this one is not: the realm did not \
             permit this credential to be delegated",
        ));
    }
    if sname.is_krbtgt() {
        // §3.3.3: "The PROXY option will not be honored on requests for additional TGTs."
        return Err(badoption(
            "a TGT cannot be proxied: a ticket-granting ticket handed to another party is \
             that party's own access, not a delegation (RFC 4120 §3.3.3)",
        ));
    }
    if body.addresses.as_ref().is_none_or(|a| a.is_empty()) {
        return Err(badoption(
            "a proxy ticket must name the address it is to be used from, or ask for any: \
             without one there is nothing to check when it is presented",
        ));
    }
    Ok(tkt_flags::PROXY)
}

/// The ticket's own fields, decided once out of three rules: a service ticket,
/// a renewal, a validation.
#[derive(Debug)]
struct TicketPlan {
    flags: u32,
    authtime: i64,
    starttime: Option<i64>,
    endtime: i64,
    renew_till: Option<i64>,
}

/// `KDC_ERR_BADOPTION`: the request asked for something that does not apply.
fn badoption(why: &str) -> Error {
    Error::Kdc {
        code: codes::KDC_ERR_BADOPTION,
        text: why.into(),
    }
}

/// The realm itself and then its ancestors, longest first: `DEV.EXAMPLE.COM` gives
/// `DEV.EXAMPLE.COM`, `EXAMPLE.COM`, `COM`.
///
/// This is the candidate order for a referral (RFC 6806 §8) and nothing more: the realm named by
/// the request is the best hop when a direct trust exists, and each ancestor is one step closer to
/// the top of the hierarchy the two realms share.
fn hierarchy_of(realm: &str) -> Vec<String> {
    let labels: Vec<&str> = realm.split('.').collect();
    (0..labels.len()).map(|i| labels[i..].join(".")).collect()
}

/// The `transited` field of the presented TGT, before its contents are read.
///
/// RFC 4120 §3.3.3: "If the transited field needs to be updated, but the transited type is not
/// supported, the `KDC_ERR_TRTYPE_NOSUPP` error is returned". Type 0 is admitted only when it is
/// empty — that is what Microsoft's TGTs carry, and Heimdal's `fix_transited_encoding` makes the
/// same exception (`kdc/krb5tgs.c`). Anything else is refused by name rather than parsed with a
/// reader that would produce a path nobody wrote.
fn check_transited_type(tgt: &EncTicketPart) -> Result<()> {
    match tgt.transited_type {
        transited::DOMAIN_X500_COMPRESS => Ok(()),
        0 if tgt.transited.is_empty() => Ok(()),
        other => Err(Error::Kdc {
            code: codes::KDC_ERR_TRTYPE_NOSUPP,
            text: format!(
                "the presented ticket carries transited type {other}, and this KDC reads only \
                 DOMAIN-X500-COMPRESS (1), or type 0 with an empty field"
            ),
        }),
    }
}

/// A service ticket: bounded by the KDC's `max_life`, the service's `max_life`
/// and, above all, by the TGT's own endtime.
fn service_plan(
    config: &super::KdcConfig,
    body: &msg::KdcReqBody,
    server: &HdbEntry,
    tgt_flags: u32,
    tgt_endtime: i64,
    now: i64,
) -> Result<TicketPlan> {
    let mut endtime = super::till_of(body).min(now.saturating_add(config.max_life()));
    if let Some(max) = server.max_life {
        endtime = endtime.min(now.saturating_add(max));
    }
    // The TGT is the client's proof of identity: a ticket outliving it would let
    // a revoked client keep working.
    endtime = endtime.min(tgt_endtime);
    if endtime <= now {
        return Err(Error::Kdc {
            code: codes::KDC_ERR_NEVER_VALID,
            text: "the TGT expires before the ticket would start".into(),
        });
    }
    // `renewable-ok`: the client would rather have a renewable ticket than a short one. Heimdal
    // honours it here only when the TGT is renewable — a request that could not be renewed is not
    // made renewable by asking, since the client would be handed a flag its TGT does not support.
    let renewable_ok = body.kdc_options & crate::msg::kdc_options::RENEWABLE_OK != 0
        && tgt_flags & tkt_flags::RENEWABLE != 0
        && endtime < super::till_of(body);
    let renewable = body.kdc_options & kdc_options::RENEWABLE != 0 || renewable_ok;
    let renew_till = renewable.then(|| {
        let asked = match body.rtime {
            // With `renewable-ok` no `rtime` was sent: the client asked for the lifetime it wanted
            // in `till`, and that is what the renewable ticket has to reach.
            None | Some(0) if renewable_ok => super::till_of(body),
            None | Some(0) => now.saturating_add(config.max_renewable_life()),
            Some(rtime) => rtime,
        };
        let mut till = asked.min(now.saturating_add(config.max_renewable_life()));
        if let Some(max) = server.max_renew {
            till = till.min(now.saturating_add(max));
        }
        till.min(tgt_endtime)
    });

    // Flags carry over from the TGT, not from what the client asks: a client
    // cannot grant itself a forwardable ticket from a TGT that was not
    // forwardable (RFC 4120 §3.3.3).
    let mut flags = 0u32;
    if tgt_flags & tkt_flags::FORWARDABLE != 0 && body.kdc_options & kdc_options::FORWARDABLE != 0 {
        flags |= tkt_flags::FORWARDABLE;
    }
    if tgt_flags & tkt_flags::PROXIABLE != 0 && body.kdc_options & kdc_options::PROXIABLE != 0 {
        flags |= tkt_flags::PROXIABLE;
    }
    if tgt_flags & tkt_flags::PRE_AUTHENT != 0 {
        flags |= tkt_flags::PRE_AUTHENT;
    }
    if tgt_flags & tkt_flags::RENEWABLE != 0 && renew_till.is_some() {
        flags |= tkt_flags::RENEWABLE;
    }
    if server.has(entry_flags::OK_AS_DELEGATE) {
        flags |= tkt_flags::OK_AS_DELEGATE;
    }
    Ok(TicketPlan {
        flags,
        authtime: now,
        starttime: None,
        endtime,
        renew_till,
    })
}

/// A validation: clear `INVALID` and change nothing else, because a validation
/// is not an authentication and must not extend anything.
fn validate_plan(tgt: &EncTicketPart, now: i64) -> Result<TicketPlan> {
    if tgt.flags & tkt_flags::INVALID == 0 {
        return Err(badoption(
            "the ticket is not invalid, so there is nothing to validate",
        ));
    }
    let start = tgt
        .starttime
        .ok_or_else(|| badoption("a postdated ticket without a start time cannot be validated"))?;
    if start > now {
        return Err(Error::Kdc {
            code: codes::KRB_AP_ERR_TKT_NYV,
            text: format!("the ticket is not valid before {start}"),
        });
    }
    Ok(TicketPlan {
        flags: tgt.flags & !tkt_flags::INVALID,
        authtime: tgt.authtime,
        starttime: Some(start),
        endtime: tgt.endtime,
        renew_till: tgt.renew_till,
    })
}

/// A renewal: the old lifetime counted from now, capped by `renew-till`.
///
/// The requested `till` is deliberately ignored. A renewal exists so a client
/// does not have to keep its long-term key around; taking the lifetime from the
/// request would turn renewal into a way to grow a ticket without
/// re-authenticating, which is the opposite of the point.
fn renew_plan(tgt: &EncTicketPart, now: i64) -> Result<TicketPlan> {
    if tgt.flags & tkt_flags::RENEWABLE == 0 {
        return Err(badoption("the ticket is not renewable"));
    }
    let renew_till = tgt
        .renew_till
        .ok_or_else(|| badoption("the ticket is renewable but carries no renew-till"))?;
    let started = tgt.starttime.unwrap_or(tgt.authtime);
    let old_life = tgt.endtime.saturating_sub(started);
    let endtime = now.saturating_add(old_life).min(renew_till);
    if endtime <= now {
        return Err(Error::Kdc {
            code: codes::KDC_ERR_NEVER_VALID,
            text: format!("renew-till {renew_till} has passed, so there is nothing to extend"),
        });
    }
    Ok(TicketPlan {
        // A renewal is not an authentication either: the flags come from the
        // ticket being renewed, unchanged.
        flags: tgt.flags,
        authtime: tgt.authtime,
        starttime: tgt.starttime,
        endtime,
        renew_till: Some(renew_till),
    })
}

impl Kdc {
    /// Handles a `TGS-REQ`.
    pub(super) fn handle_tgs(&self, req: &KdcReq, now: i64, raw: &[u8]) -> Result<Vec<u8>> {
        // RFC 6113 §5.4.2.6: a TGS request can be armored **implicitly** — there is no
        // `armor` field, because the armor already travelled: the `AP-REQ` in `PA-TGS-REQ`
        // presents the client's TGT and carries its subkey, and the armor key is derived
        // from both. That is why a client that armors its AS exchange can armor its TGS
        // requests without holding a second ticket.
        let Some(fast_bytes) = req.padata(super::fast::PA_FX_FAST) else {
            // `check_evidence` looks the `AP-REQ` up itself; the unarmored path does not
            // need it here.
            let proven = self.check_evidence(req, now)?;
            let received = Received {
                padata: &req.padata,
                raw,
            };
            return self.tgs_answer(&req.body, proven, now, Armor::none(), received);
        };

        let armored = super::fast::ArmoredRequest::decode(fast_bytes)?;
        let ap_req_bytes = req.padata(PA_TGS_REQ).ok_or_else(|| Error::Kdc {
            code: codes::KRB_AP_ERR_MODIFIED,
            text: "PA-FX-FAST in a TGS-REQ without PA-TGS-REQ: there is nothing to \
                   derive the implicit armor key from"
                .into(),
        })?;

        // The evidence is checked first because the armor key does not exist until the
        // authenticator's subkey is known — and the subkey is only trustworthy after the
        // ticket and the authenticator have been verified.
        let proven = self.check_evidence(req, now)?;

        // Two ways a TGS request arrives armored, and the armor key is derived differently
        // in each. Getting this wrong is invisible: the reply is well-formed and the client
        // says only that the FAST response was missing.
        //
        // * Implicit (RFC 6113 §5.4.2.6): no `armor` field. The ticket travelled in
        //   PA-TGS-REQ, and the key is `cf2(subkey, "subkeyarmor", session key,
        //   "ticketarmor")` from that request's authenticator subkey and the TGT's session
        //   key. A client that armored its AS exchange armors its TGS requests this way.
        // * Explicit: an `armor` AP-REQ presenting a TGT of this realm — the same shape the
        //   AS exchange takes. MIT krb5 sends this form for a service ticket when its
        //   credential cache records an armor for the TGT, and Samba reaches it through
        //   `gss_init_sec_context` for a `cifs/` ticket. Refusing it left the join at
        //   "FAST fast response is missing FX-FAST", which names the armor rather than the
        //   service the KDC could not issue.
        let explicit_armor = armored.armor.is_some();
        let (armor_key, inner) = if explicit_armor {
            let armor_key = self.armor_key(&armored, now)?;
            let inner = super::fast::unwrap(&armored, &armor_key, ap_req_bytes, self.cipher())?;
            (armor_key, inner)
        } else {
            let Some(subkey) = &proven.subkey else {
                return Err(Error::Kdc {
                    code: codes::KRB_AP_ERR_MODIFIED,
                    text: "PA-FX-FAST in a TGS-REQ whose authenticator has no subkey: the \
                           implicit armor key is cf2(subkey, \"subkeyarmor\", session key, \
                           \"ticketarmor\") and cannot be derived without one"
                        .into(),
                });
            };
            let armor_key = super::fast::implicit_armor_key(subkey, &proven.tgt.session_key)?;
            let inner =
                super::fast::unwrap_implicit(&armored, &armor_key, ap_req_bytes, self.cipher())?;
            (armor_key, inner)
        };

        let options = inner.options();
        if let Some(bad) = super::fast::unsupported_critical(options) {
            return Err(Error::Kdc {
                code: codes::KDC_ERR_UNKNOWN_CRITICAL_FAST_OPTIONS,
                text: format!("PA-FX-FAST: unsupported critical fast-options {bad:#010x}"),
            });
        }
        let hide = options & super::fast::HIDE_CLIENT_NAMES != 0;

        let mut r = crate::der::Reader::new(&inner.req_body);
        let content = r.expect_in("KrbFastReq req-body", crate::der::SEQUENCE)?;
        let body = KdcReqBody::decode(content)?;

        let received = Received {
            padata: &inner.padata,
            raw,
        };
        self.tgs_answer(
            &body,
            proven,
            now,
            Armor {
                key: Some(&armor_key),
                explicit: explicit_armor,
                hide,
            },
            received,
        )
    }

    /// The exchange itself, over a body that has already been recovered from wherever it
    /// travelled — the outer request, or inside an armor.
    fn tgs_answer(
        &self,
        body: &KdcReqBody,
        proven: Proven,
        now: i64,
        armor: Armor<'_>,
        received: Received<'_>,
    ) -> Result<Vec<u8>> {
        // The PA-DATA a reply may answer: the inner one under FAST, the outer one otherwise.
        let padata = received.padata;
        let config = self.config();
        // The realm in a TGS request is the *server's* realm, not this KDC's (RFC 4120 §5.4.1,
        // field [2]: "the realm part of the server's principal identifier"). A client asking a KDC
        // for a service in another realm puts that realm here, which is how RFC 6806 §8 referrals
        // begin — "C: TGS-REQ sname=http/foo.dev.example.com +NC to ADMIN.EXAMPLE.COM" — so a
        // realm that is not ours is a name to resolve, not a request to refuse. Refusing here would
        // answer the first hop of every referral chain with `KDC_ERR_WRONG_REALM` and leave the
        // mechanism unreachable however well the rest of it is written.
        //
        // The AS exchange keeps its own check (`as_exchange.rs`): there the realm is the client's,
        // and a client from another realm has no business asking this one for a TGT.

        // The `transited` field of the evidence is read before anything is issued on it: an
        // encoding this KDC does not know would otherwise be copied into the reply, and a refusal
        // for the real reason is cheaper than a path nobody can verify.
        check_transited_type(&proven.tgt)?;

        // The service the client asked for.
        let mut sname = body
            .sname
            .clone()
            .ok_or_else(|| Error::Protocol("TGS-REQ without a service name".into()))?;

        // 5: the service.
        //
        // `fetch_for_service`, not `fetch`: a directory may hold the account under one
        // name and publish another. `HOST$@REALM` carries `cifs/host.example.com` in
        // `servicePrincipalName`, and a client asks for the latter — the ticket is
        // then sealed with `HOST$`'s key while naming `cifs/host` (that is what
        // [MS-ADTS] does, and what Samba needs to join).
        //
        // A name this realm does not hold is not always a refusal: RFC 6806 §8 lets a KDC answer
        // with a cross-realm TGT toward the realm that may, and the client walks the chain itself.
        // That answer is a ticket to `krbtgt/HOP@OURREALM`, so it is a rewrite of the name the
        // rest of this exchange works with rather than a separate reply path.
        if !super::name_type_ok(config, &sname) {
            return Err(Error::Kdc {
                code: codes::KDC_ERR_S_PRINCIPAL_UNKNOWN,
                text: format!("{sname} is not a service in this realm"),
            });
        }
        let server = match self.hdb().fetch_for_service(&sname)? {
            Some(server) => server,
            None => match self.referral(&sname, &proven, body)? {
                Some((hop, entry)) => {
                    sname = hop;
                    entry
                }
                None => {
                    return Err(Error::Kdc {
                        code: codes::KDC_ERR_S_PRINCIPAL_UNKNOWN,
                        text: format!("{sname} is not a service in this realm"),
                    });
                }
            },
        };
        if !server.has(entry_flags::SERVER) {
            return Err(Error::Kdc {
                code: codes::KDC_ERR_S_PRINCIPAL_UNKNOWN,
                text: format!("{sname} may not be issued a ticket"),
            });
        }
        // RFC 6806 §6: a TGS reply must not change the name the client asked for, so
        // `canonicalize` does not. Heimdal makes one exception, for deployments that depend on the
        // old behaviour: a service whose entry carries `force-canonicalize` gets the entry's own
        // name back, which is how a directory that publishes `servicePrincipalName`s asks to be
        // answered with the account it actually stores.
        //
        // This is also where an alias stops being an alias: `fetch_for_service` finds an entry by
        // any of its names and hands back the entry as stored, so a ticket names the alias unless
        // the flag says otherwise. A hard alias in Heimdal rewrites the fetched entry's principal
        // to the alias instead; spelling the rule here keeps the stored entry immutable and gives
        // the same ticket for everything but that combination.
        if server.has(entry_flags::FORCE_CANONICALIZE) {
            sname = server.principal.clone();
        }

        // Heimdal's `hdb` flag `initial`: a ticket for this service must come
        // from an AS-REQ. `kadmin/changepw` is the reason it exists — a password
        // that could be changed with any stolen TGT is a password an attacker
        // rotates to lock the owner out.
        if server.has(entry_flags::INITIAL) {
            return Err(Error::Kdc {
                code: codes::KDC_ERR_POLICY,
                text: format!("{sname} requires an initial ticket"),
            });
        }

        // S4U2Self, MS-SFU §3.1: a service asking for a ticket in somebody else's name.
        //
        // Before the plan, because the plan's flags depend on it: a ticket issued this way is
        // forwardable only when the service is trusted for delegation *and* the user is, and
        // the impersonated user's identity is what the ticket, the PAC and the reply all name.
        let transition = self.protocol_transition(padata, &proven, &sname, &server, now)?;
        let proxy = self.constrained_delegation(body, &proven, &sname, &server, now)?;

        if transition.is_some() && proxy.is_some() {
            // Heimdal applies the transition first and then the proxy, which leaves the
            // evidence ticket verified against the *impersonated* user's key — a request
            // nobody writes, and one whose two halves would have to be read in a particular
            // order to mean anything. Refusing says so instead of picking an order.
            return Err(badoption(
                "a request carries both S4U2Self and S4U2Proxy; they are two exchanges, and \
                 a KDC that applied both would have to choose which one owns the client",
            ));
        }

        // 6: the ticket.
        //
        // The set is the same either way; the order is the option's choice, and Heimdal's default
        // is the client's list (`tgt-use-strongest-session-key` off).
        let usable = super::order_enctypes(
            super::usable_enctypes(config, &body.etypes, &server, Purpose::Ticket),
            &body.etypes,
            if config.tgt_use_strongest_session_key() {
                super::EnctypeOrder::KdcPreferred
            } else {
                super::EnctypeOrder::ClientPreferred
            },
        );
        let session_enctype = usable.first().copied().ok_or_else(|| {
            // The three-way intersection is empty, and which side caused it is the first thing
            // an operator needs: the enctype the client asked for, the enctypes this KDC
            // implements, and the ones `server`'s own entry allows.
            let allowed: Vec<_> = match &server.etypes {
                Some(declared) => declared.clone(),
                None => server.enctypes(),
            };
            if allowed.is_empty() || !allowed.iter().any(|e| body.etypes.contains(&e.id())) {
                Error::NoUsableEnctype {
                    principal: server.principal.clone(),
                    allowed,
                    asked: body.etypes.clone(),
                }
            } else {
                Error::UnsupportedEnctype(body.etypes.first().copied().unwrap_or(0))
            }
        })?;

        // `require-pac`: a TGT without a PAC is one this realm would not have issued, and a
        // realm that requires PACs treats it as revoked (Heimdal's `KRB5KDC_ERR_TGT_REVOKED`).
        // Checked before anything is granted from it, including a renewal: the point of the
        // setting is that such a ticket is not a credential here, and a renewal would be the
        // cheapest way to launder one into a ticket that has a PAC.
        if config.require_pac()
            && !proven
                .tgt
                .authorization_data
                .as_deref()
                .is_some_and(super::pac::carries_pac)
        {
            return Err(Error::Kdc {
                code: codes::KDC_ERR_TGT_REVOKED,
                text: format!(
                    "{}'s ticket-granting ticket for {} carries no authorization data, and \
                     this realm requires a PAC",
                    proven.tgt.crealm, proven.tgt.cname
                ),
            });
        }

        let validate = body.kdc_options & kdc_options::VALIDATE != 0;
        let renew = body.kdc_options & kdc_options::RENEW != 0;

        // A postdated ticket is unusable until it is validated, and validation
        // is the only thing that may touch an INVALID ticket (RFC 4120
        // §3.3.3).
        if !validate && proven.tgt.flags & tkt_flags::INVALID != 0 {
            return Err(Error::Kdc {
                code: codes::KRB_AP_ERR_TKT_INVALID,
                text: "the TGT is postdated and has not been validated".into(),
            });
        }
        if (renew || validate) && !sname.is_krbtgt() {
            // Renewal and validation ask for the TGT again; a request that aims
            // them at a service is asking for something the protocol has no
            // meaning for.
            return Err(badoption(
                "renew and validate apply to the ticket-granting ticket only",
            ));
        }

        // RFC 4120 §3.3.3: `forwarded` and `proxy` are operations, and each is gated by a
        // flag the TGT must already carry. Both take their addresses from the request.
        let forwarding = forwarding_plan(body, &proven.tgt, &sname)?;

        let plan = if validate {
            validate_plan(&proven.tgt, now)?
        } else if renew {
            renew_plan(&proven.tgt, now)?
        } else {
            service_plan(
                config,
                body,
                &server,
                proven.tgt.flags,
                proven.tgt.endtime,
                now,
            )?
        };
        let TicketPlan {
            flags,
            authtime: plan_authtime,
            starttime,
            endtime,
            renew_till,
        } = plan;
        // MS-SFU §3.1.5.2: a proxy ticket inherits the evidence ticket's `authtime`, because
        // that is when the user actually authenticated — the whole point of delegation is that
        // the user did not authenticate now.
        let authtime = proxy.as_ref().map_or(plan_authtime, |p| p.authtime);
        let mut flags = flags | forwarding;

        // RFC 6806 §11, the same contract as in the AS exchange: `PA-REQ-ENC-PA-REP` present in
        // the request means the reply carries a checksum over the request and sets the flag.
        let wants_enc_pa_rep = super::req_enc_pa_rep::requested(padata);
        if wants_enc_pa_rep {
            flags |= tkt_flags::ENC_PA_REP;
        }

        // The identity the ticket and the PAC name: the service's own, unless this was a
        // protocol transition.
        let (client, crealm) = match (&transition, &proxy) {
            (Some(t), _) => (t.user.clone(), t.user.realm.clone()),
            (None, Some(p)) => (p.user.clone(), p.user.realm.clone()),
            (None, None) => (proven.tgt.cname.clone(), proven.tgt.crealm.clone()),
        };
        if let Some(t) = &transition {
            // MS-SFU §3.1.4: a ticket obtained by protocol transition is forwardable only if
            // the service is trusted for delegation and the user's own account is. Otherwise
            // the flag is cleared — leaving it set would hand the service a credential it
            // could present as S4U2Proxy evidence for a user it was never allowed to delegate.
            if !t.may_delegate {
                flags &= !tkt_flags::FORWARDABLE;
            }
        }

        let session_key = self.cipher().random(session_enctype)?;
        // A user-to-user ticket is sealed in the session key of the additional
        // ticket, not in any long-term key: the server holds no keytab, and the
        // TGT it sent is the only key material the two sides share (RFC 4120
        // §2.9.2). Everything up to here is the same for both kinds of ticket.
        let ticket_key = match self.user_to_user_key(body, &sname)? {
            Some((key, kvno)) => (key, kvno),
            None => {
                // Same rule as the AS: the ticket is sealed in an enctype this KDC is allowed to
                // issue and the service holds a key for, not in whichever key happens to be
                // strongest.
                let key = super::sealing_key(config, &server, &usable)
                    .ok_or_else(|| Error::Hdb(format!("{sname} has no usable key")))?;
                (key.key.clone(), Some(key.kvno))
            }
        };

        // The realms this ticket has passed through. Heimdal's rule, from
        // `fix_transited_encoding`: the issuer of the presented TGT is a transit realm only when it
        // is neither the client's nor the server's, so an ordinary ticket in this realm carries an
        // empty path and a ticket from A to B through C carries `C`.
        //
        // The type of the field was checked when the request came in, before any name was resolved.
        let path = transited::path_with_transit(
            &proven.tgt.transited,
            &crealm,
            &sname.realm,
            &proven.tgt_issuer,
        )?;

        // Whether the path is checked at all is the realm's policy (Heimdal's `transited-policy`),
        // and a client may waive the check only when the policy says its request is honoured. A
        // ticket issued without the check says so by leaving `TRANSITED-POLICY-CHECKED` clear, and
        // the service then checks the path itself (RFC 4120 §2.7) — refusing the request instead
        // would let a client break its own logon by setting a bit.
        let check = match config.transited_policy() {
            TransitedPolicy::AlwaysCheck | TransitedPolicy::AllowPerPrincipal => true,
            TransitedPolicy::AlwaysHonourRequest => {
                body.kdc_options & kdc_options::DISABLE_TRANSITED_CHECK == 0
            }
        };
        if check {
            transited::accept(&path, &crealm, &sname.realm, config.transited_realms())?;
            flags |= tkt_flags::TRANSITED_POLICY_CHECKED;
        }

        let transited = transited::encode(&path);
        let (transited_type, transited) = if transited.is_empty() {
            (0, Vec::new())
        } else {
            (transited::DOMAIN_X500_COMPRESS, transited)
        };

        let ticket_part = EncTicketPart {
            flags,
            session_key: session_key.clone(),
            crealm: crealm.clone(),
            cname: client.clone(),
            transited_type,
            transited,
            authtime,
            starttime,
            endtime,
            renew_till,
            caddr: body.addresses.clone(),
            // The PAC is rebuilt for this ticket rather than copied from the TGT: its
            // service checksum is keyed by *this* service's key, and the KDC signature
            // is over the whole buffer, so a copied one would not verify. Whether there is
            // one at all is the realm's and the entries' decision.
            authorization_data: if self.include_pac(
                &server,
                super::is_root_tgt(&server.principal),
                super::pac_attributes(padata),
            ) {
                self.pac_authorization_data(&client, &ticket_key.0, authtime)?
            } else {
                None
            },
        };
        let ticket = Ticket {
            realm: config.realm().to_owned(),
            // What the client asked for, which may not be the entry's own name: the
            // service is addressed by the name it published, and a ticket naming
            // `HOST$` instead of `cifs/host` would be accepted by nobody.
            sname: sname.clone(),
            enc: EncryptedData::seal(
                self.cipher(),
                &ticket_key.0,
                usage::KDC_REP_TICKET,
                ticket_key.1,
                &ticket_part.encode(),
            )?,
        };

        let rep_part = EncKdcRepPart {
            session_key,
            last_req: vec![(0, 0)],
            nonce: body.nonce,
            key_expiration: None,
            flags,
            authtime,
            starttime,
            endtime,
            renew_till,
            srealm: server.principal.realm.clone(),
            // The name the client asked for, as in the ticket: the reply's encrypted
            // part states which service the ticket is for, and a client compares it
            // with the name it asked for before accepting the answer
            // (`KRB5_KDCREP_MODIFIED` otherwise). The entry's own name — `HOST$` — is
            // not what was asked for.
            sname: sname.clone(),
            caddr: body.addresses.clone(),
            // Keyed with the reply key — the TGT's session key or the authenticator's subkey —
            // and over the request as it arrived, which is what `krb5`'s client verifies.
            padata: if wants_enc_pa_rep {
                vec![(
                    super::req_enc_pa_rep::PA_REQ_ENC_PA_REP,
                    super::req_enc_pa_rep::checksum(
                        self.cipher(),
                        &proven.reply_key,
                        super::req_enc_pa_rep::KU_TGS_REQ,
                        received.raw,
                    )?,
                )]
            } else {
                Vec::new()
            },
        };
        // The reply is encrypted in the TGT's session key (usage 8) or in the
        // authenticator's subkey (usage 9). Using the wrong usage produces a
        // reply the client cannot read, which reads as a broken KDC rather than
        // as a wrong number.
        //
        // An armored exchange strengthens that key with a random secret, and the secret travels
        // only inside the armor (RFC 6113 §5.4.4.2). Strengthening is not optional company for the
        // armor: a client that armored its request reconstructs the reply key from the `strengthen`
        // value it is handed, and a reply sealed in the unstrengthened key is one it cannot open -
        // measured as `Failed to decode encpart in ticket` from Samba's client, which armors where
        // MIT's `kvno` does not, so the same KDC answered MIT and not Samba.
        // Only when the reply is sealed in the TGT's session key - that is, when the client sent no
        // subkey. Heimdal's own rule, from `get_cred.c`: with a subkey the reply is opened with it
        // directly under usage 9; without one, the session key is first run through
        // `fast_tgs_strengthen_key` and usage 8. Strengthening a subkey seals the reply in a key the
        // client never derives, and it reports that as `Failed to decode encpart in ticket` - a
        // message about a ticket, for a reply it could not open.
        // Both conditions, and Heimdal needs both: `fast_tgs_strengthen_key` is a no-op when there
        // is no FAST state, so an unarmored exchange is never strengthened; and the subkey branch
        // opens the reply with the subkey directly, so an armored one that sent a subkey is not
        // strengthened either.
        let strengthen = armor.key.is_some();
        let (strengthen_key, sealed_with) = if strengthen {
            let (strength, strengthened) =
                super::fast::strengthen(self.cipher(), &proven.reply_key)?;
            (Some(strength), strengthened)
        } else {
            (None, proven.reply_key.clone())
        };
        let mut plaintext = rep_part.encode(msg::ENC_TGS_REP_PART);
        // CONTROL: Heimdal's own krb5.asn1 declares no EXPLICIT TAGS, so its decoder reads
        // `[APPLICATION 26]` as implicit - the sequence's *contents* behind the tag, with no
        // inner SEQUENCE. RFC 4120's module says EXPLICIT, which is what `encode` writes.
        if std::env::var_os("KDC_TGS_IMPLICIT").is_some()
            && let Some(stripped) = Self::strip_inner_sequence(&plaintext)
        {
            plaintext = stripped;
        }
        if std::env::var_os("KDC_TGS_DIAG").is_some() {
            eprintln!(
                "tgs-diag: sname={sname} armor={} subkey={:?} reply_usage={} strengthened={} \
                 sealed_key={:?} plaintext={}",
                if armor.explicit {
                    "explicit"
                } else {
                    "implicit"
                },
                proven.subkey.as_ref().map(|k| k.enctype()),
                proven.reply_usage,
                strengthen,
                sealed_with.enctype(),
                plaintext.len()
            );
        }
        // TEMP-DIAG: the plaintext the client has to parse once it has opened the reply.
        if std::env::var_os("KDC_DUMP").is_some() {
            let _ = std::fs::write("/tmp/kdc-enctgsrep.der", &plaintext);
        }
        let enc_part = EncryptedData::seal(
            self.cipher(),
            &sealed_with,
            proven.reply_usage,
            None,
            &plaintext,
        )?;

        // RFC 6113 §5.4.2.6: an armored TGS request is answered inside the armor, with a
        // `finished` checksum over the ticket so the client can tell it is the answer to
        // this request and not a substituted one.
        let (crealm, cname) = if armor.hide {
            let anonymous = super::fast::anonymous_principal();
            (anonymous.realm.clone(), anonymous)
        } else {
            (crealm, client.clone())
        };
        let mut padata_out: Vec<(i32, Vec<u8>)> = transition
            .as_ref()
            .and_then(|t| t.reply.clone())
            .into_iter()
            .collect();
        let rep = KdcRep {
            msg_type: TGS_REP,
            padata: Vec::new(),
            crealm,
            cname,
            ticket,
            enc_part,
        };
        // CONTROL: answer without the FAST wrapper, to tell whether the wrapper or the
        // EncTGSRepPart inside it is what the client refuses.
        let armor_key = if std::env::var_os("KDC_NO_ARMOR").is_some() {
            None
        } else {
            armor.key
        };
        if let Some(key) = armor_key {
            let finish = super::fast::finished(
                self.cipher(),
                key,
                &rep.ticket.encode(),
                &proven.tgt.cname,
                now,
                now.rem_euclid(1_000_000) as u32,
            )?;
            padata_out.push((
                super::fast::PA_FX_FAST_REPLY,
                super::fast::wrap_reply(
                    key,
                    &[],
                    strengthen_key.as_ref(),
                    Some(finish),
                    body.nonce,
                    self.cipher(),
                )?,
            ));
        }
        Ok(KdcRep {
            padata: padata_out,
            ..rep
        }
        .encode())
    }

    /// Rewrites `tag len 30 len2 fields` as `tag len2 fields`.
    ///
    /// Only for the experiment: it is the difference between an ASN.1 module that says EXPLICIT
    /// TAGS and one that leaves the default, IMPLICIT.
    fn strip_inner_sequence(der: &[u8]) -> Option<Vec<u8>> {
        fn tlv(b: &[u8], o: usize) -> Option<(u8, usize, usize)> {
            let tag = *b.get(o)?;
            let first = *b.get(o + 1)?;
            if first & 0x80 == 0 {
                Some((tag, o + 2, first as usize))
            } else {
                let n = (first & 0x7f) as usize;
                let len = b.get(o + 2..o + 2 + n)?;
                Some((
                    tag,
                    o + 2 + n,
                    len.iter().fold(0usize, |a, b| a * 256 + *b as usize),
                ))
            }
        }
        fn header(len: usize) -> Vec<u8> {
            if len < 0x80 {
                vec![len as u8]
            } else if len < 0x100 {
                vec![0x81, len as u8]
            } else {
                vec![0x82, (len >> 8) as u8, len as u8]
            }
        }
        let (tag, body, _len) = tlv(der, 0)?;
        let (inner, i_body, i_len) = tlv(der, body)?;
        if inner != 0x30 {
            return None;
        }
        let fields = der.get(i_body..i_body + i_len)?;
        let mut out = vec![tag];
        out.extend(header(fields.len()));
        out.extend_from_slice(fields);
        Some(out)
    }

    /// Evaluates a protocol transition (S4U2Self), MS-SFU §3.1.
    ///
    /// Returns `None` when the request carries neither S4U `PA-DATA`, which is every ordinary
    /// request. When it carries one or both, the claim is verified and the identity is
    /// returned for the ticket, the PAC and the reply — the three places that must agree, and
    /// the reason this runs before the ticket is built rather than after.
    fn protocol_transition(
        &self,
        padata: &[(i32, Vec<u8>)],
        proven: &Proven,
        sname: &Principal,
        server: &HdbEntry,
        now: i64,
    ) -> Result<Option<Transition>> {
        let for_user = padata
            .iter()
            .find(|(t, _)| *t == super::s4u::PA_FOR_USER)
            .map(|(_, v)| super::s4u::ForUser::decode(v))
            .transpose()?;
        let x509 = padata
            .iter()
            .find(|(t, _)| *t == super::s4u::PA_S4U_X509_USER)
            .map(|(_, v)| super::s4u::X509User::decode(v))
            .transpose()?;
        if for_user.is_none() && x509.is_none() {
            return Ok(None);
        }

        // MS-SFU §3.1.2: the service may only ask for a ticket *to itself*. Anything else
        // would let any service with a TGT mint tickets for any other service in the realm,
        // which is the whole of Kerberos's authorization model in one request.
        if proven.tgt.cname != *sname {
            return Err(badoption(&format!(
                "S4U2Self: {} asked for a ticket to {sname}; a protocol transition is only \
                 allowed to the service's own name",
                proven.tgt.cname
            )));
        }

        // The checksums, each under the key its specification names: PA-FOR-USER under the
        // TGT's session key, PA-S4U-X509-USER under the authenticator's subkey.
        if let Some(f) = &for_user {
            f.verify(&proven.tgt.session_key)?;
        }
        let subkey = proven.subkey.as_ref();
        if let Some(x) = &x509 {
            let Some(subkey) = subkey else {
                return Err(Error::Kdc {
                    code: codes::KRB_AP_ERR_MODIFIED,
                    text: "PA-S4U-X509-USER: the authenticator carries no subkey, and the \
                           checksum is keyed with it; without one there is nothing to verify"
                        .into(),
                });
            };
            x.verify(self.cipher(), subkey)?;
        }

        // Both halves are one claim. A request carrying two that disagree is a client that
        // cannot make up its mind, and picking either would be picking for it.
        let user = match (&for_user, &x509) {
            (Some(f), Some(x)) => {
                if x.cname.as_ref() != Some(&f.user) {
                    return Err(Error::Kdc {
                        code: codes::KDC_ERR_BADOPTION,
                        text: format!(
                            "S4U2Self: PA-FOR-USER names {} and PA-S4U-X509-USER names {}; \
                             one request, one user",
                            f.user,
                            x.cname
                                .as_ref()
                                .map_or_else(|| "(nobody)".to_string(), ToString::to_string)
                        ),
                    });
                }
                f.user.clone()
            }
            (Some(f), None) => f.user.clone(),
            (None, Some(x)) => x.user().cloned().ok_or_else(|| Error::Kdc {
                code: codes::KDC_ERR_BADOPTION,
                text: "PA-S4U-X509-USER names no user; there is nobody to act for".into(),
            })?,
            (None, None) => unreachable!("checked above"),
        };

        // The user has to exist and be loggable in *this* realm: impersonating an account
        // that does not exist would mint a ticket nobody can check, and looking the name up
        // is also what decides the PAC's groups.
        let entry = self.hdb().fetch(&user)?.ok_or_else(|| Error::Kdc {
            code: codes::KDC_ERR_C_PRINCIPAL_UNKNOWN,
            text: format!("S4U2Self: {user} is not an account of this realm"),
        })?;
        if !entry.is_valid_at(now) {
            return Err(Error::Kdc {
                code: codes::KDC_ERR_CLIENT_REVOKED,
                text: format!("S4U2Self: {user} is locked, disabled or expired"),
            });
        }
        if !entry.has(entry_flags::CLIENT) {
            return Err(Error::Kdc {
                code: codes::KDC_ERR_POLICY,
                text: format!("S4U2Self: {user} is not a client principal"),
            });
        }

        // MS-SFU §3.1.4: forwardable only when the service is trusted for delegation and the
        // user's account is forwardable. Neither alone is enough, and the flag is what an
        // S4U2Proxy request will later demand as evidence.
        let may_delegate =
            server.has(entry_flags::TRUSTED_FOR_DELEGATION) && entry.has(entry_flags::FORWARDABLE);

        let reply = match (&x509, subkey) {
            (Some(x), Some(subkey)) => Some((
                super::s4u::PA_S4U_X509_USER,
                x.reply(self.cipher(), subkey)?,
            )),
            _ => None,
        };

        Ok(Some(Transition {
            user,
            may_delegate,
            reply,
        }))
    }

    /// Evaluates a constrained delegation (S4U2Proxy), MS-SFU §3.1.5.
    ///
    /// The delegating service holds a ticket for itself; the user's ticket — obtained by
    /// S4U2Self, or sent by a user who authenticated to the service — travels in
    /// `additional-tickets`; and the service asks for a ticket to *another* service in the
    /// user's name. The evidence is what makes it delegation rather than impersonation: no
    /// user ticket, no delegation.
    ///
    /// Every refusal here is a rule from Heimdal's `validate_constrained_delegation`
    /// (`kdc/mssfu.c`), and the most important one is that the evidence is decrypted with the
    /// **delegating service's** key: the service has to prove it received that ticket, not
    /// merely that it can name a user.
    fn constrained_delegation(
        &self,
        body: &KdcReqBody,
        proven: &Proven,
        sname: &Principal,
        server: &HdbEntry,
        now: i64,
    ) -> Result<Option<Proxy>> {
        // §3.1.5.1: the option says the client comes from the additional ticket. Without it
        // this is an ordinary request that happens to carry a ticket (user-to-user does), and
        // `enc-tkt-in-skey` means the ticket travels encrypted in a session key, which is a
        // different mechanism with its own handling.
        if body.kdc_options & kdc_options::CNAME_IN_ADDL_TKT == 0 {
            return Ok(None);
        }
        if body.kdc_options & kdc_options::ENC_TKT_IN_SKEY != 0 {
            return Err(badoption(
                "cname-in-addl-tkt with enc-tkt-in-skey: the evidence ticket cannot be both \
                 the source of the client and sealed in a session key",
            ));
        }

        let raw = body.additional_tickets.as_deref().ok_or_else(|| {
            badoption(
                "cname-in-addl-tkt without additional-tickets: there is no evidence ticket, \
                 and a delegation nobody can prove is impersonation",
            )
        })?;
        // `first_ticket` is the user-to-user path's reader; it returns the ticket's own
        // TLV, which is exactly what `Ticket::decode` wants.
        let evidence = Ticket::decode(&first_ticket(raw)?)?;

        // The delegator is the client of the TGT — the service making the request. Its own key
        // opens the evidence, which is what proves the service received it.
        let delegator = self
            .hdb()
            .fetch(&proven.tgt.cname)?
            .ok_or_else(|| Error::Kdc {
                code: codes::KDC_ERR_C_PRINCIPAL_UNKNOWN,
                text: format!("S4U2Proxy: {} is not in this realm", proven.tgt.cname),
            })?;
        let part = self
            .decrypt_ticket(&evidence, &delegator)
            .map_err(|e| Error::Kdc {
                code: codes::KRB_AP_ERR_BAD_INTEGRITY,
                text: format!(
                    "S4U2Proxy: the evidence ticket does not open with {}'s key: {e}",
                    proven.tgt.cname
                ),
            })?;

        // §3.1.5.2: the evidence has to be usable. Not forwardable means the user (or the KDC,
        // for an S4U2Self ticket) said it may not travel further, and expired means there is
        // nothing to delegate.
        if part.flags & tkt_flags::FORWARDABLE == 0 {
            return Err(badoption(
                "S4U2Proxy: the evidence ticket is not forwardable, so it may not be \
                 presented for another service",
            ));
        }
        if now > part.endtime {
            return Err(Error::Kdc {
                code: codes::KRB_AP_ERR_TKT_EXPIRED,
                text: "S4U2Proxy: the evidence ticket has expired".into(),
            });
        }
        if part.crealm != self.config().realm() {
            return Err(badoption(&format!(
                "S4U2Proxy: the evidence ticket is for {}, not this realm; constrained \
                 delegation does not cross realms",
                part.crealm
            )));
        }

        // §3.1.4: delegation is allowed when the service delegates to itself, or when the
        // requested service is one the service's administrator listed. `None` and an empty list
        // both mean "nobody but itself": the absence of a list is not a permission.
        let to_itself = proven.tgt.cname == *sname || delegator.principal == *sname;
        let listed = delegator
            .constrained_delegation
            .as_ref()
            .is_some_and(|acl| {
                acl.iter()
                    .any(|p| p == sname || p.components == server.principal.components)
            });
        if !to_itself && !listed {
            return Err(badoption(&format!(
                "S4U2Proxy: {} may not delegate to {sname}; a service delegates to itself and \
                 to the names its entry lists, and this one lists {}",
                proven.tgt.cname,
                match &delegator.constrained_delegation {
                    None => "nothing".to_string(),
                    Some(acl) if acl.is_empty() => "nobody".to_string(),
                    Some(acl) => acl.len().to_string() + " other name(s)",
                }
            )));
        }

        Ok(Some(Proxy {
            user: part.cname.clone(),
            authtime: part.authtime,
        }))
    }

    /// The realm to send a client to when this KDC cannot answer for the name it asked for.
    ///
    /// RFC 6806 §8: "If the canonicalize flag in the KDC options is set and the KDC doesn't find
    /// the principal locally ... the KDC MAY return a cross-realm ticket-granting ticket to the
    /// next hop on the trust path towards a realm that may be able to resolve the principal name."
    /// The client then walks the chain itself, and what this KDC issues is an ordinary
    /// cross-realm TGT — `krbtgt/HOP@OURREALM`, sealed in the key the two realms share — so the
    /// referral is a rewrite of the name the rest of the exchange works with, not a second reply
    /// path.
    ///
    /// The hop comes from the DNS hierarchy, because this crate is a library: it has no
    /// `[domain_realm]` to resolve a host name and no `[capaths]` to override one, and the
    /// embedder owns that configuration. The candidates are the realm the request names and then
    /// its ancestors, longest first; the first one this database holds as `krbtgt/X@OURREALM` wins.
    /// Naming the target itself is what lets a realm with a direct trust answer in one hop, and
    /// naming an ancestor is what lets a realm in the middle of a hierarchy hand the client on.
    ///
    /// No referral is issued when the client did not set `canonicalize` (RFC 6806 §3 requires it,
    /// because the reply then names a principal other than the one asked for), when the target is
    /// this realm (there is nothing to refer to), or when the hop would go back to where the
    /// evidence came from — the client's realm, the issuer of its TGT, or a realm already on the
    /// transited path. A KDC that answers A→B with a ticket back to A hands the client a loop it can
    /// only leave by giving up.
    fn referral(
        &self,
        sname: &Principal,
        proven: &Proven,
        body: &KdcReqBody,
    ) -> Result<Option<(Principal, HdbEntry)>> {
        if body.kdc_options & kdc_options::CANONICALIZE == 0 {
            return Ok(None);
        }
        // `krbtgt/X@OURREALM` names X in its second component; a service names its realm in
        // `realm`. The two spellings of "where this name lives" differ, and reading the wrong one
        // would send the client to the realm it is already in.
        let target = if sname.is_krbtgt() {
            match sname.components.get(1) {
                Some(realm) => realm.clone(),
                None => return Ok(None),
            }
        } else {
            sname.realm.clone()
        };
        let our_realm = self.config().realm();
        if target.is_empty() || target == our_realm {
            return Ok(None);
        }

        let already = transited::decode(&proven.tgt.transited, &proven.tgt.crealm, &target)
            .unwrap_or_default();
        for hop in hierarchy_of(&target) {
            if hop == our_realm
                || hop == proven.tgt.crealm
                || hop == proven.tgt_issuer
                || already.contains(&hop)
            {
                continue;
            }
            let name = Principal {
                name_type: crate::name::NT_SRV_INST,
                components: vec!["krbtgt".to_owned(), hop],
                realm: our_realm.to_owned(),
            };
            if let Some(entry) = self.hdb().fetch(&name)? {
                return Ok(Some((name, entry)));
            }
        }
        Ok(None)
    }

    /// The key a user-to-user ticket is sealed in, when the request asked for
    /// one: the session key of the ticket in `additional-tickets`.
    ///
    /// The rules are Heimdal's (`krb5tgs.c`, `b->kdc_options.enc_tkt_in_skey`):
    /// there must be an additional ticket, it must be a ticket-granting ticket,
    /// it must decrypt under this realm's `krbtgt` key, and the service asked for
    /// must be the client that ticket names. The last one is what makes this
    /// safe: without it, anybody could get a ticket for anybody sealed in a key
    /// they chose, which is a ticket they could read.
    fn user_to_user_key(
        &self,
        body: &crate::msg::KdcReqBody,
        sname: &Principal,
    ) -> Result<Option<(Key, Option<u32>)>> {
        if body.kdc_options & kdc_options::ENC_TKT_IN_SKEY == 0 {
            return Ok(None);
        }
        let encoded = body
            .additional_tickets
            .as_deref()
            .ok_or_else(|| Error::Kdc {
                code: codes::KDC_ERR_BADOPTION,
                text: "enc-tkt-in-skey without additional-tickets".into(),
            })?;
        let ticket = Ticket::decode(&first_ticket(encoded)?)?;
        if !ticket.sname.is_krbtgt() {
            return Err(Error::Kdc {
                code: codes::KDC_ERR_POLICY,
                text: format!(
                    "the additional ticket is for {}, not a ticket-granting ticket",
                    ticket.sname
                ),
            });
        }
        let krbtgt = Principal::krbtgt(self.config().realm());
        if ticket.sname != krbtgt {
            return Err(Error::Kdc {
                code: codes::KDC_ERR_POLICY,
                text: format!(
                    "user-to-user across realms is not supported: {}",
                    ticket.sname
                ),
            });
        }
        let entry = self
            .hdb()
            .fetch(&krbtgt)?
            .ok_or_else(|| Error::Hdb("the krbtgt entry is missing from the database".into()))?;
        let part = self.decrypt_ticket(&ticket, &entry)?;
        if part.cname != *sname {
            return Err(Error::Kdc {
                code: codes::KDC_ERR_MUST_USE_USER2USER,
                text: format!(
                    "the additional ticket names {} but the ticket was asked for {sname}",
                    part.cname
                ),
            });
        }
        Ok(Some((part.session_key, None)))
    }

    /// Steps 1–4: decode `PA-TGS-REQ`, decrypt the ticket, then the
    /// authenticator, then check the checksum over the request body.
    /// Visible in `kdc` because the error path of `Kdc::error` needs the same evidence to
    /// derive an implicit armor key; a refusal that cannot be wrapped is a refusal the
    /// client cannot read.
    pub(super) fn check_evidence(&self, req: &KdcReq, now: i64) -> Result<Proven> {
        let config = self.config();
        let ap_req_bytes = req.padata(PA_TGS_REQ).ok_or_else(|| {
            Error::Protocol(
                "TGS-REQ without PA-TGS-REQ: a TGS request must present a ticket".into(),
            )
        })?;
        let ap_req = ApReq::decode(ap_req_bytes)?;
        let ticket = ap_req.ticket()?;

        // 2. The ticket must be ours and must decrypt under krbtgt's key.
        //
        // "Ours" means its second component is our realm, not that we issued it: a cross-realm
        // TGT `krbtgt/B@A` was issued by A and is addressed to us, and refusing it here is why a
        // client from another realm could not get a service ticket. What decides the key is the
        // issuing realm — the one in the ticket's `realm` — because that is the realm whose
        // `krbtgt` we share.
        let krbtgt = Principal::krbtgt(config.realm());
        let tgt_realm = ticket
            .sname
            .components
            .get(1)
            .filter(|_| ticket.sname.is_krbtgt())
            .ok_or_else(|| Error::Kdc {
                code: codes::KRB_AP_ERR_MODIFIED,
                text: format!(
                    "PA-TGS-REQ presents a ticket for {}, which is not a ticket-granting ticket",
                    ticket.sname
                ),
            })?
            .clone();
        if !super::same_realm(&tgt_realm, config.realm()) {
            return Err(Error::Kdc {
                code: codes::KRB_AP_ERR_MODIFIED,
                text: format!(
                    "PA-TGS-REQ presents a ticket for {}, and this KDC serves {}",
                    ticket.sname,
                    config.realm()
                ),
            });
        }
        // A ticket issued by this realm is sealed in our own `krbtgt`; one issued by another is
        // sealed in the shared key, which we hold under the mirror image of its name.
        let key_entry = if ticket.realm == config.realm() {
            krbtgt.clone()
        } else {
            Principal {
                name_type: crate::name::NT_SRV_INST,
                components: vec!["krbtgt".to_owned(), ticket.realm.clone()],
                realm: config.realm().to_owned(),
            }
        };
        let krbtgt_entry = self.hdb().fetch(&key_entry)?.ok_or_else(|| {
            Error::Hdb(format!(
                "the {key_entry} entry is missing from the database"
            ))
        })?;
        let ticket_part = self.decrypt_ticket(&ticket, &krbtgt_entry)?;

        // Expiry before anything else: an expired TGT makes the authenticator
        // irrelevant, and answering "bad authenticator" for a ticket that is
        // simply old sends the client looking for the wrong problem.
        if now > ticket_part.endtime {
            return Err(Error::Kdc {
                code: codes::KRB_AP_ERR_TKT_EXPIRED,
                text: format!("the TGT expired at {}", ticket_part.endtime),
            });
        }
        if let Some(start) = ticket_part.starttime
            && now < start
        {
            return Err(Error::Kdc {
                code: codes::KRB_AP_ERR_TKT_NYV,
                text: format!("the TGT is not valid before {start}"),
            });
        }

        // 3. The authenticator, in the ticket's session key.
        let authenticator = self.decrypt_authenticator(&ap_req, &ticket_part)?;
        if authenticator.crealm != ticket_part.crealm || authenticator.cname != ticket_part.cname {
            return Err(Error::Kdc {
                code: codes::KRB_AP_ERR_BADMATCH,
                text: format!(
                    "the authenticator names {}@{} but the ticket names {}",
                    authenticator.cname, authenticator.crealm, ticket_part.cname
                ),
            });
        }

        // The checksum covers the exact octets of KDC-REQ-BODY as they arrived. That is
        // true under FAST as well, and not by accident: a TGS request sends its body both
        // outside the armor and inside it (RFC 6113 §5.4.2.6 keeps `PA-TGS-REQ` outer and
        // mirrors the body), so the client checksums the same octets either way. What FAST
        // changes is the *other* checksum — the `req-checksum` over the `AP-REQ`, which
        // `fast::unwrap` verifies. Re-encoding a decoded body would produce equal-looking
        // DER that is not byte-identical, and the client's own checksum is over what it
        // sent.
        let (cksum_type, cksum) = authenticator.cksum.as_ref().ok_or_else(|| Error::Kdc {
            code: codes::KRB_AP_ERR_INAPP_CKSUM,
            text: "the authenticator has no checksum over the request".into(),
        })?;
        if *cksum_type != ticket_part.session_key.enctype().checksum_type() {
            return Err(Error::Kdc {
                code: codes::KRB_AP_ERR_INAPP_CKSUM,
                text: format!(
                    "the checksum type {} does not belong to the session key's {}",
                    cksum_type,
                    ticket_part.session_key.enctype().name()
                ),
            });
        }
        self.cipher()
            .verify_checksum(
                &ticket_part.session_key,
                usage::TGS_REQ_AUTH_CKSUM,
                &req.raw_body,
                cksum,
            )
            .map_err(|_| Error::Kdc {
                code: codes::KRB_AP_ERR_MODIFIED,
                text: "the checksum does not cover this request body".into(),
            })?;

        // 4. The authenticator's clock.
        let skew = now.saturating_sub(authenticator.ctime);
        if skew.abs() > config.clockskew() {
            return Err(Error::Skew {
                skew,
                allowed: config.clockskew(),
            });
        }

        // The reply key: the subkey if the client offered one, else the TGT's
        // session key.
        let (reply_key, reply_usage) = match &authenticator.subkey {
            Some(subkey) => (subkey.clone(), usage::TGS_REP_ENCPART_SUBKEY),
            None => (
                ticket_part.session_key.clone(),
                usage::TGS_REP_ENCPART_SESSKEY,
            ),
        };

        Ok(Proven {
            tgt: ticket_part,
            reply_key,
            reply_usage,
            subkey: authenticator.subkey.clone(),
            // The issuer, not `tgt_realm`: that one is the component validated above, which is
            // this KDC's own realm by construction.
            tgt_issuer: ticket.realm.clone(),
        })
    }

    /// Decrypts a ticket with the key it says it was encrypted in, falling back
    /// to the entry's other keys.
    ///
    /// The ticket names its enctype, so that one is tried first: flailing
    /// through every key on a wrong guess turns a clear "this ticket is not
    /// mine" into a slow, indistinguishable failure.
    pub(super) fn decrypt_ticket(
        &self,
        ticket: &Ticket,
        entry: &HdbEntry,
    ) -> Result<EncTicketPart> {
        let mut candidates = vec![ticket.enc.etype];
        candidates.extend(
            entry
                .enctypes()
                .into_iter()
                .filter(|e| *e != ticket.enc.etype),
        );
        for enctype in candidates {
            let Some(key) = entry.key_for(enctype) else {
                continue;
            };
            if let Ok(plain) =
                self.cipher()
                    .decrypt(&key.key, usage::KDC_REP_TICKET, &ticket.enc.cipher)
            {
                return EncTicketPart::decode(&plain).map_err(Error::from);
            }
        }
        Err(Error::Kdc {
            code: codes::KRB_AP_ERR_BAD_INTEGRITY,
            text: "the ticket does not decrypt under any key this KDC holds".into(),
        })
    }

    /// Decrypts the authenticator in the ticket's session key.
    fn decrypt_authenticator(
        &self,
        ap_req: &ApReq,
        ticket: &EncTicketPart,
    ) -> Result<Authenticator> {
        if ap_req.authenticator.etype != ticket.session_key.enctype() {
            return Err(Error::Kdc {
                code: codes::KRB_AP_ERR_BAD_INTEGRITY,
                text: format!(
                    "the authenticator is {}, the session key is {}",
                    ap_req.authenticator.etype.name(),
                    ticket.session_key.enctype().name()
                ),
            });
        }
        let plain = self
            .cipher()
            .decrypt(
                &ticket.session_key,
                usage::TGS_REQ_AUTH,
                &ap_req.authenticator.cipher,
            )
            .map_err(|_| Error::Kdc {
                code: codes::KRB_AP_ERR_BAD_INTEGRITY,
                text: "the authenticator does not decrypt under the ticket's session key".into(),
            })?;
        Authenticator::decode(&plain).map_err(Error::from)
    }
}

/// The first `Ticket` in the `additional-tickets` SEQUENCE, as DER.
///
/// The field arrives as the content of `[11]`, which is the `SEQUENCE OF`
/// wrapper; its first element is the server's TGT.
fn first_ticket(encoded: &[u8]) -> Result<Vec<u8>> {
    let mut r = crate::der::Reader::new(encoded);
    let content = r.expect_in("additional-tickets", crate::der::SEQUENCE)?;
    let mut s = crate::der::Reader::new(content);
    let tlv = s.next_tlv("additional-tickets")?;
    if tlv.tag != crate::der::app(crate::msg::TICKET) {
        return Err(Error::Kdc {
            code: codes::KDC_ERR_BADOPTION,
            text: format!(
                "additional-tickets holds tag {:#04x}, not a Ticket",
                tlv.tag
            ),
        });
    }
    // The reader hands back the tag and the content separately; `Ticket::decode`
    // wants the whole application-tagged value, so the header is rebuilt.
    let mut out = Vec::with_capacity(tlv.content.len() + 6);
    out.push(tlv.tag);
    crate::der::encode_len(&mut out, tlv.content.len());
    out.extend_from_slice(tlv.content);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The candidate order for a referral: the realm named by the request, then its ancestors.
    /// A KDC that offered the ancestors first would send a client to the top of the tree and back
    /// down for a service it could have reached in one hop.
    #[test]
    fn the_referral_candidates_run_from_the_realm_upwards() {
        assert_eq!(
            hierarchy_of("DEV.EXAMPLE.COM"),
            vec!["DEV.EXAMPLE.COM", "EXAMPLE.COM", "COM"]
        );
        assert_eq!(hierarchy_of("EXAMPLE.COM"), vec!["EXAMPLE.COM", "COM"]);
        assert_eq!(hierarchy_of("REALM"), vec!["REALM"]);
    }
}
