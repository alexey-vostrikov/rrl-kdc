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
    let mut end = body.till.min(start.saturating_add(config.max_life()));
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
) -> u32 {
    let mut flags = tkt_flags::INITIAL;
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
fn method_data(entries: &[EtypeInfo2Entry]) -> Vec<u8> {
    encode_pa_data(&[
        (PA_ENC_TIMESTAMP, Vec::new()),
        // Advertised unconditionally, as MIT's KDC does: a client that armors replaces
        // the timestamp with this, a client that does not ignores it. Offering it only
        // to clients that already armored would be circular — the first armored request
        // is exactly the one that needs to learn it exists.
        (super::fast::PA_ENCRYPTED_CHALLENGE, Vec::new()),
        (PA_ETYPE_INFO2, encode_etype_info2(entries)),
    ])
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
fn preauth_required(cname: &Principal, entries: &[EtypeInfo2Entry]) -> Error {
    Error::Preauth {
        code: codes::KDC_ERR_PREAUTH_REQUIRED,
        text: format!("{cname} must pre-authenticate"),
        method_data: method_data(entries),
    }
}

/// `KDC_ERR_PREAUTH_FAILED` with the method data attached, which is how a client
/// learns the salt it should have used.
fn preauth_failed(cname: &Principal, entries: &[EtypeInfo2Entry], why: &str) -> Error {
    Error::Preauth {
        code: codes::KDC_ERR_PREAUTH_FAILED,
        text: format!("{cname}: {why}"),
        method_data: method_data(entries),
    }
}

impl Kdc {
    /// Handles an `AS-REQ`.
    pub(super) fn handle_as(&self, req: &KdcReq, now: i64) -> Result<Vec<u8>> {
        // FAST first: if the client armored the exchange, the request that matters is
        // the one inside the armor, and the reply has to be armored back.
        let Some(armored_bytes) = req.padata(super::fast::PA_FX_FAST) else {
            return self.answer_as(&req.body, &req.padata, now, None, false);
        };
        let armored = super::fast::ArmoredRequest::decode(armored_bytes)?;
        let armor_key = self.armor_key(&armored, now)?;
        let inner = super::fast::unwrap(&armored, &armor_key, &req.raw_body, self.cipher())?;
        let mut r = crate::der::Reader::new(&inner.req_body);
        let content = r.expect("KrbFastReq req-body", crate::der::SEQUENCE)?;
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
        self.answer_as(&body, &inner.padata, now, Some(&armor_key), hide)
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
        Key::new(part.session_key.enctype(), mixed)
    }

    /// The AS exchange proper, over a request that has already been unwrapped.
    ///
    /// `armor` is `Some` when the request arrived inside `PA-FX-FAST`; the reply is then
    /// sealed in a strengthened key and its `padata` travels inside
    /// `PA-FX-FAST-REPLY`.
    /// `hide` is RFC 6113's `hide-client-names`: the reply names
    /// `WELLKNOWN/ANONYMOUS` instead of the client, and the real name survives only inside
    /// the ticket, which is sealed with a service key.
    fn answer_as(
        &self,
        body: &KdcReqBody,
        padata: &[(i32, Vec<u8>)],
        now: i64,
        armor: Option<&Key>,
        hide: bool,
    ) -> Result<Vec<u8>> {
        let config = self.config();
        if body.realm != config.realm() {
            return Err(super::wrong_realm(&body.realm, config.realm()));
        }

        // 2. The client. An AS-REQ without a client name cannot be answered:
        // there is nobody to encrypt the reply for.
        let cname = body
            .cname
            .clone()
            .ok_or_else(|| Error::Protocol("AS-REQ without a client name".into()))?;
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
        let sname = body
            .sname
            .clone()
            .ok_or_else(|| Error::Protocol("AS-REQ without a service name".into()))?;
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
        let usable = usable_enctypes(config, &body.etypes, &client, Purpose::Preauth);
        if usable.is_empty() {
            return Err(Error::UnsupportedEnctype(
                body.etypes.first().copied().unwrap_or(0),
            ));
        }
        let entries = etype_info2(&client, &usable);

        // 5. Pre-authentication.
        //
        // Two methods; which one is acceptable depends on the armor, not on the client's
        // preference. Inside FAST the plain timestamp is refused: a `PA-ENC-TIMESTAMP`
        // sealed directly in the long-term key is the offline oracle the armor exists to
        // close, so accepting it there would leave the hole open behind a lock.
        let timestamp = padata_value(padata, PA_ENC_TIMESTAMP);
        let challenge = padata_value(padata, super::fast::PA_ENCRYPTED_CHALLENGE);
        let preauthenticated = timestamp.is_some() || challenge.is_some();
        let reply_key = if let Some(value) = challenge {
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
            return Err(preauth_required(&cname, &entries));
        } else {
            client
                .key_for(usable[0])
                .map(|k| k.key.clone())
                .ok_or_else(|| preauth_failed(&cname, &entries, "no key for the session enctype"))?
        };

        // 6. Flags and times.
        let start = starttime(body, &client);
        let effective_start = start.unwrap_or(now);
        let endtime = endtime(config, body, &client, &server, effective_start);
        if endtime <= effective_start {
            return Err(Error::Kdc {
                code: codes::KDC_ERR_NEVER_VALID,
                text: "the requested lifetime ends before it starts".into(),
            });
        }
        let renew_till = renew_till(config, body, &client, &server, effective_start);
        let flags = ticket_flags(
            body,
            &client,
            &server,
            preauthenticated,
            renew_till.is_some(),
        );

        // 7. One session key, written into both the ticket and the reply: two
        // keys would mean the client holds one the ticket does not accept.
        let session_key = self.cipher().random(usable[0])?;
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
            authorization_data: self.pac_authorization_data(
                &client.principal,
                &server_key.key,
                now,
            )?,
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

        let rep_part = EncKdcRepPart {
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
        };
        // With FAST the reply key is strengthened by a random secret that only the
        // armor carries, so a recorded reply cannot be attacked offline. Without FAST
        // it stays the client's long-term key, which is what every client expects.
        let (strengthen_key, sealed_with) = match armor {
            Some(_) => {
                let (strength, strengthened) = super::fast::strengthen(self.cipher(), &reply_key)?;
                (Some(strength), strengthened)
            }
            None => (None, reply_key.clone()),
        };
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
