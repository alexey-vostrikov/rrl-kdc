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
//! What is deliberately absent at this stage: referrals, S4U, PAC, FAST,
//! `transited` across realms. A request that needs one of them is answered with
//! a code that says so, not with a ticket that claims to be something it is not.

use crate::crypto::{Key, usage};
use crate::error::{Error, Result, codes};
use crate::hdb::{HdbEntry, flags as entry_flags};
use crate::msg::{
    self, ApReq, Authenticator, EncKdcRepPart, EncTicketPart, EncryptedData, KdcRep, KdcReq,
    PA_TGS_REQ, TGS_REP, Ticket, kdc_options, tkt_flags,
};
use crate::name::Principal;

use super::{Kdc, wrong_realm};

/// A `TGS-REQ` whose evidence has been checked: the client it proves, and the
/// TGT it came with.
#[derive(Debug)]
struct Proven {
    /// The client named by the ticket and confirmed by the authenticator.
    client: Principal,
    /// The TGT's ticket flags, which bound what the new ticket may claim.
    tgt_flags: u32,
    /// The TGT's `endtime`: a service ticket cannot outlive it.
    tgt_endtime: i64,
    /// The key the reply is encrypted in: the authenticator's subkey when it
    /// carried one, otherwise the TGT's session key.
    reply_key: Key,
    /// The usage that reply key pairs with (RFC 4120 §7.5.1): 9 for a subkey,
    /// 8 for the session key.
    reply_usage: u32,
}

impl Kdc {
    /// Handles a `TGS-REQ`.
    pub(super) fn handle_tgs(&self, req: &KdcReq, now: i64) -> Result<Vec<u8>> {
        let body = &req.body;
        let config = self.config();
        if body.realm != config.realm() {
            return Err(wrong_realm(&body.realm, config.realm()));
        }

        // The service the client asked for.
        let sname = body
            .sname
            .clone()
            .ok_or_else(|| Error::Protocol("TGS-REQ without a service name".into()))?;

        // 1–4: the evidence.
        let proven = self.check_evidence(req, now)?;

        // 5: the service.
        let server = self.hdb().fetch(&sname)?.ok_or_else(|| Error::Kdc {
            code: codes::KDC_ERR_S_PRINCIPAL_UNKNOWN,
            text: format!("{sname} is not a service in this realm"),
        })?;
        if !server.has(entry_flags::SERVER) {
            return Err(Error::Kdc {
                code: codes::KDC_ERR_S_PRINCIPAL_UNKNOWN,
                text: format!("{sname} may not be issued a ticket"),
            });
        }

        // 6: the ticket.
        let usable = super::usable_enctypes(config, &body.etypes, &server);
        let session_enctype = usable
            .first()
            .copied()
            .ok_or_else(|| Error::UnsupportedEnctype(body.etypes.first().copied().unwrap_or(0)))?;

        // A service ticket never outlives the TGT it came from: the TGT is the
        // client's proof of identity, and a ticket that outlived it would let a
        // revoked client keep working.
        let start = now;
        // Bounded by this KDC's `max_life` and the service's `max_life` — the
        // client's entry does not bound a service ticket, its TGT does.
        let mut endtime = body.till.min(start.saturating_add(config.max_life()));
        if let Some(max) = server.max_life {
            endtime = endtime.min(start.saturating_add(max));
        }
        endtime = endtime.min(proven.tgt_endtime);
        if endtime <= start {
            return Err(Error::Kdc {
                code: codes::KDC_ERR_NEVER_VALID,
                text: "the TGT expires before the ticket would start".into(),
            });
        }
        let renew_till = (body.kdc_options & kdc_options::RENEWABLE != 0).then(|| {
            let asked = match body.rtime {
                None | Some(0) => start.saturating_add(config.max_renewable_life()),
                Some(rtime) => rtime,
            };
            let mut till = asked.min(start.saturating_add(config.max_renewable_life()));
            if let Some(max) = server.max_renew {
                till = till.min(start.saturating_add(max));
            }
            till.min(proven.tgt_endtime)
        });

        // Flags carry over from the TGT, not from what the client asks: a
        // client cannot grant itself a forwardable ticket from a TGT that was
        // not forwardable (RFC 4120 §3.3.3).
        let mut flags = 0u32; // a service ticket starts with no flags of its own
        if proven.tgt_flags & tkt_flags::FORWARDABLE != 0
            && body.kdc_options & kdc_options::FORWARDABLE != 0
        {
            flags |= tkt_flags::FORWARDABLE;
        }
        if proven.tgt_flags & tkt_flags::PROXIABLE != 0
            && body.kdc_options & kdc_options::PROXIABLE != 0
        {
            flags |= tkt_flags::PROXIABLE;
        }
        if proven.tgt_flags & tkt_flags::PRE_AUTHENT != 0 {
            flags |= tkt_flags::PRE_AUTHENT;
        }
        if proven.tgt_flags & tkt_flags::RENEWABLE != 0 && renew_till.is_some() {
            flags |= tkt_flags::RENEWABLE;
        }
        if server.has(entry_flags::OK_AS_DELEGATE) {
            flags |= tkt_flags::OK_AS_DELEGATE;
        }

        let session_key = self.cipher().random(session_enctype)?;
        let server_enctype = server
            .enctypes()
            .first()
            .copied()
            .unwrap_or(session_enctype);
        let server_key = server
            .key_for(server_enctype)
            .ok_or_else(|| Error::Hdb(format!("{sname} has no usable key")))?;

        let ticket_part = EncTicketPart {
            flags,
            session_key: session_key.clone(),
            crealm: proven.client.realm.clone(),
            cname: proven.client.clone(),
            // No realm has been traversed: the ticket came from the realm that
            // names it. Cross-realm `transited` is step 3.
            transited_type: 0,
            transited: Vec::new(),
            authtime: now,
            starttime: None,
            endtime,
            renew_till,
            caddr: body.addresses.clone(),
            authorization_data: None,
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
            last_req: vec![(0, 0)],
            nonce: body.nonce,
            key_expiration: None,
            flags,
            authtime: now,
            starttime: None,
            endtime,
            renew_till,
            srealm: server.principal.realm.clone(),
            sname: server.principal.clone(),
            caddr: body.addresses.clone(),
        };
        // The reply is encrypted in the TGT's session key (usage 8) or in the
        // authenticator's subkey (usage 9). Using the wrong usage produces a
        // reply the client cannot read, which reads as a broken KDC rather than
        // as a wrong number.
        let enc_part = EncryptedData::seal(
            self.cipher(),
            &proven.reply_key,
            proven.reply_usage,
            None,
            &rep_part.encode(msg::ENC_TGS_REP_PART),
        )?;

        Ok(KdcRep {
            msg_type: TGS_REP,
            // No PA-DATA in a TGS-REP at this stage: RFC 6806's
            // PA-REQ-ENC-PA-REP belongs with FAST, which is step 4.
            padata: Vec::new(),
            crealm: proven.client.realm.clone(),
            cname: proven.client.clone(),
            ticket,
            enc_part,
        }
        .encode())
    }

    /// Steps 1–4: decode `PA-TGS-REQ`, decrypt the ticket, then the
    /// authenticator, then check the checksum over the request body.
    fn check_evidence(&self, req: &KdcReq, now: i64) -> Result<Proven> {
        let config = self.config();
        let ap_req_bytes = req.padata(PA_TGS_REQ).ok_or_else(|| {
            Error::Protocol(
                "TGS-REQ without PA-TGS-REQ: a TGS request must present a ticket".into(),
            )
        })?;
        let ap_req = ApReq::decode(ap_req_bytes)?;
        let ticket = ap_req.ticket()?;

        // 2. The ticket must be ours and must decrypt under krbtgt's key.
        let krbtgt = Principal::krbtgt(config.realm());
        if ticket.sname != krbtgt {
            return Err(Error::Kdc {
                code: codes::KRB_AP_ERR_MODIFIED,
                text: format!(
                    "PA-TGS-REQ presents a ticket for {}, not {krbtgt}",
                    ticket.sname
                ),
            });
        }
        let krbtgt_entry = self
            .hdb()
            .fetch(&krbtgt)?
            .ok_or_else(|| Error::Hdb("the krbtgt entry is missing from the database".into()))?;
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

        // The checksum covers the exact octets of KDC-REQ-BODY as they arrived.
        // Re-encoding a decoded body would produce equal-looking DER that is not
        // byte-identical, and the client's own checksum is over what it sent.
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
            client: ticket_part.cname.clone(),
            tgt_flags: ticket_part.flags,
            tgt_endtime: ticket_part.endtime,
            reply_key,
            reply_usage,
        })
    }

    /// Decrypts a ticket with the key it says it was encrypted in, falling back
    /// to the entry's other keys.
    ///
    /// The ticket names its enctype, so that one is tried first: flailing
    /// through every key on a wrong guess turns a clear "this ticket is not
    /// mine" into a slow, indistinguishable failure.
    fn decrypt_ticket(&self, ticket: &Ticket, entry: &HdbEntry) -> Result<EncTicketPart> {
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
                return EncTicketPart::decode(&plain);
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
        Authenticator::decode(&plain)
    }
}
