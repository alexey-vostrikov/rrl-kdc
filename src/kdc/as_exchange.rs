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
        let body = &req.body;
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
        let preauthenticated = req.padata(PA_ENC_TIMESTAMP).is_some();
        let reply_key = match req.padata(PA_ENC_TIMESTAMP) {
            Some(value) => match self.verify_enc_timestamp(&client, &usable, value, now) {
                Ok(key) => key,
                Err(err) => return Err(with_salts(err, &cname, &entries)),
            },
            None if config.require_preauth() || client.has(entry_flags::REQUIRE_PREAUTH) => {
                return Err(preauth_required(&cname, &entries));
            }
            None => client
                .key_for(usable[0])
                .map(|k| k.key.clone())
                .ok_or_else(|| {
                    preauth_failed(&cname, &entries, "no key for the session enctype")
                })?,
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
        let server_key = server
            .key_for(server.enctypes().first().copied().unwrap_or(usable[0]))
            .ok_or_else(|| Error::Hdb("the krbtgt entry has no usable key".into()))?;

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
        let enc_part = EncryptedData::seal(
            self.cipher(),
            &reply_key,
            usage::AS_REP_ENCPART,
            Some(client.kvno()),
            &rep_part.encode(crate::msg::ENC_AS_REP_PART),
        )?;

        Ok(KdcRep {
            msg_type: AS_REP,
            // Heimdal repeats the etype information in the reply, so a client
            // that read the salt from the error still sees it here.
            padata: vec![(PA_ETYPE_INFO2, encode_etype_info2(&entries))],
            crealm: client.principal.realm.clone(),
            cname: client.principal.clone(),
            ticket,
            enc_part,
        }
        .encode())
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
