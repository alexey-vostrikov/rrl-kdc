//! Accepting an AP-REQ from a service's client — the step every port of this KDC repeats.
//!
//! kpasswd, kx509, kadmin and hprop all begin the same way: a client presents a ticket for *this*
//! service, sealed in that service's key, together with an authenticator it sealed in the ticket's
//! session key. Four hand-written copies of that sequence is four chances to forget the clock, the
//! client name, or the ticket's expiry — so it lives here and the four callers differ only in what
//! they require of the *name*.
//!
//! **What is checked, and why each check is not optional:**
//!
//! * the ticket is for a service this realm issued (`sname`, first component, plus the realm): a
//!   ticket for `host/other` proves nothing about this service;
//! * the service's key exists and matches the ticket's enctype: without it the ticket does not
//!   decrypt, and an implementation that fell back to another key would be guessing;
//! * the ticket has not expired;
//! * the authenticator opens in the ticket's session key, names the same client as the ticket, and
//!   its `ctime` is within the clock skew — that timestamp is the whole of the freshness argument,
//!   and a server that skipped it would accept a replayed authenticator forever.
//!
//! What is *not* here is replay detection: a replay cache is per-service state with its own
//! lifetime, and each port has its own answer (kadmin keeps one per context, kpasswd's exchange is
//! one-shot). Returning the authenticator lets a caller that needs it use `ctime` and `seq-number`.

use crate::crypto::{Cipher, Key, usage};
use crate::error::codes;
use crate::hdb::Hdb;
use crate::msg::{ApReq, Authenticator, EncTicketPart};
use crate::name::Principal;

/// What accepting an AP-REQ tells the caller.
#[derive(Debug, Clone)]
pub struct Accepted {
    /// The ticket's session key: what the client will seal its requests in.
    pub session_key: Key,
    /// The client the ticket was issued to — the fact the ticket proves.
    pub client: Principal,
    /// The client's realm, which for a cross-realm ticket is not ours.
    pub client_realm: String,
    /// The decoded authenticator, for a caller that needs its subkey, sequence number or
    /// authorization data.
    pub authenticator: Authenticator,
    /// The ticket's contents.
    pub ticket: EncTicketPart,
    /// The AP options the client set (RFC 4120 §5.5.1): `MUTUAL-REQUIRED` decides whether an
    /// `AP-REP` has to be sent, and a server that skipped it would leave the client blocking.
    pub ap_options: u32,
}

/// Why an AP-REQ was refused: an RFC 4120 code and a sentence for the log.
pub type Refusal = (i32, String);

/// Accepts an AP-REQ for the service whose first name component is `service`, in `realm`.
///
/// `now` is passed rather than read so that a test can decide what time it is; `skew` is the
/// tolerance on the authenticator's timestamp.
pub fn accept(
    cipher: &dyn Cipher,
    hdb: &dyn Hdb,
    ap_req_bytes: &[u8],
    service: &str,
    realm: &str,
    now: i64,
    skew: i64,
) -> std::result::Result<Accepted, Refusal> {
    let ap_req = ApReq::decode(ap_req_bytes)
        .map_err(|e| (codes::KRB_AP_ERR_MODIFIED, format!("the AP-REQ: {e}")))?;
    let ticket = ap_req
        .ticket()
        .map_err(|e| (codes::KRB_AP_ERR_MODIFIED, format!("the ticket: {e}")))?;

    // The name, before the key: a ticket for another service is the wrong request, not a bad one,
    // and saying so is what makes the refusal diagnosable from the client's side.
    if ticket.sname.components.first().map(|c| c.as_str()) != Some(service) {
        return Err((
            codes::KRB_AP_ERR_MODIFIED,
            format!(
                "the ticket is for {}, and a {service} ticket must be for {service}/…",
                ticket.sname
            ),
        ));
    }
    if ticket.sname.realm != realm {
        return Err((
            codes::KRB_AP_ERR_MODIFIED,
            format!(
                "the {service} ticket is for {} and this realm is {realm}",
                ticket.sname.realm
            ),
        ));
    }

    let entry = hdb
        .fetch_for_service(&ticket.sname)
        .map_err(|e| (codes::KRB_AP_ERR_MODIFIED, format!("{e}")))?
        .ok_or_else(|| {
            (
                codes::KDC_ERR_S_PRINCIPAL_UNKNOWN,
                format!("{} is not in the database", ticket.sname),
            )
        })?;
    let key = entry
        .key_for(ticket.enc.etype)
        .ok_or_else(|| {
            (
                codes::KRB_AP_ERR_BAD_INTEGRITY,
                format!(
                    "{} has no key of the ticket's enctype {}",
                    entry.principal,
                    ticket.enc.etype.name()
                ),
            )
        })?
        .key
        .clone();

    let part = cipher
        .decrypt(&key, usage::KDC_REP_TICKET, &ticket.enc.cipher)
        .map_err(|_| {
            (
                codes::KRB_AP_ERR_BAD_INTEGRITY,
                format!("the ticket for {} does not decrypt", ticket.sname),
            )
        })
        .and_then(|plain| {
            EncTicketPart::decode(&plain)
                .map_err(|e| (codes::KRB_AP_ERR_MODIFIED, format!("the ticket: {e}")))
        })?;

    if now > part.endtime {
        return Err((
            codes::KRB_AP_ERR_TKT_EXPIRED,
            format!(
                "the ticket for {} expired {}s ago",
                ticket.sname,
                now - part.endtime
            ),
        ));
    }

    let authenticator = cipher
        .decrypt(
            &part.session_key,
            usage::AP_REQ_AUTH,
            &ap_req.authenticator.cipher,
        )
        .map_err(|_| {
            (
                codes::KRB_AP_ERR_BAD_INTEGRITY,
                "the authenticator does not decrypt in the ticket's session key".into(),
            )
        })
        .and_then(|plain| {
            Authenticator::decode(&plain).map_err(|e| {
                (
                    codes::KRB_AP_ERR_MODIFIED,
                    format!("the authenticator: {e}"),
                )
            })
        })?;

    if authenticator.cname != part.cname || authenticator.crealm != part.crealm {
        return Err((
            codes::KRB_AP_ERR_MODIFIED,
            format!(
                "the authenticator names {}@{}, and the ticket {}@{}",
                authenticator.cname, authenticator.crealm, part.cname, part.crealm
            ),
        ));
    }
    let skew_seen = now.saturating_sub(authenticator.ctime);
    if skew_seen.abs() > skew {
        return Err((
            codes::KRB_AP_ERR_SKEW,
            format!(
                "the authenticator is {skew_seen}s from this server's clock, and the skew is {skew}s"
            ),
        ));
    }

    Ok(Accepted {
        ap_options: ap_req.ap_options,
        session_key: part.session_key.clone(),
        client: part.cname.clone(),
        client_realm: part.crealm.clone(),
        authenticator,
        ticket: part,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{Enctype, OwnCipher};
    use crate::hdb::{HdbEntry, MemoryHdb};
    use crate::msg::{EncTicketPart, EncryptedData, Ticket};

    const REALM: &str = "EXAMPLE.COM";
    const NOW: i64 = 1_700_000_000;

    fn p(name: &str) -> Principal {
        Principal::parse(name).expect("a principal")
    }

    /// A realm with a service whose key the test holds.
    fn realm() -> (MemoryHdb, Key) {
        let key = OwnCipher.random(Enctype::Aes256Sha1).expect("a key");
        let mut entry = HdbEntry::service(p(&format!("hprop/kdc.example.com@{REALM}")));
        entry.add_key(key.clone(), 1, None);
        let db = MemoryHdb::new();
        db.store(entry).expect("stored");
        (db, key)
    }

    /// An AP-REQ for the service, sealed in its key, with the authenticator at `ctime`.
    fn ap_req(
        service_key: &Key,
        client: &str,
        ctime: i64,
        ticket_endtime: i64,
        sname: &str,
        realm: &str,
    ) -> Vec<u8> {
        let cipher = OwnCipher;
        let session = cipher.random(Enctype::Aes256Sha1).expect("a session key");
        let part = EncTicketPart {
            flags: 0,
            session_key: session.clone(),
            crealm: REALM.to_owned(),
            cname: p(client),
            transited_type: 0,
            transited: Vec::new(),
            authtime: NOW - 60,
            starttime: None,
            endtime: ticket_endtime,
            renew_till: None,
            caddr: None,
            authorization_data: None,
        };
        let enc = EncryptedData::seal(
            &cipher,
            service_key,
            usage::KDC_REP_TICKET,
            None,
            &part.encode(),
        )
        .expect("the ticket seals");
        let ticket = Ticket {
            realm: realm.to_owned(),
            sname: p(sname),
            enc,
        };
        let authenticator = Authenticator {
            crealm: REALM.to_owned(),
            cname: p(client),
            cksum: None,
            cusec: 0,
            ctime,
            subkey: None,
            seq_number: None,
            authorization_data: None,
        };
        let authenticator = EncryptedData::seal(
            &cipher,
            &session,
            usage::AP_REQ_AUTH,
            None,
            &authenticator.encode(),
        )
        .expect("the authenticator seals");
        ApReq {
            ap_options: 0,
            ticket: ticket.encode(),
            authenticator,
        }
        .encode()
    }

    fn service_name() -> String {
        format!("hprop/kdc.example.com@{REALM}")
    }

    #[test]
    fn a_good_request_is_accepted_and_says_who_asked() {
        let (db, key) = realm();
        let ap = ap_req(
            &key,
            &format!("kadmin/hprop@{REALM}"),
            NOW,
            NOW + 3600,
            &service_name(),
            REALM,
        );
        let accepted = accept(&OwnCipher, &db, &ap, "hprop", REALM, NOW, 300).expect("accepted");
        assert_eq!(accepted.client.to_string(), format!("kadmin/hprop@{REALM}"));
        assert_eq!(accepted.client_realm, REALM);
        assert_eq!(accepted.session_key.enctype(), Enctype::Aes256Sha1);
        assert_eq!(accepted.authenticator.ctime, NOW);
    }

    /// A ticket for another service is refused by name: the refusal has to say what was wrong with
    /// the *request*, or the client is left guessing.
    #[test]
    fn a_ticket_for_another_service_is_refused_by_name() {
        let (db, key) = realm();
        let ap = ap_req(
            &key,
            &format!("kadmin/hprop@{REALM}"),
            NOW,
            NOW + 3600,
            &format!("host/other@{REALM}"),
            REALM,
        );
        let (code, text) =
            accept(&OwnCipher, &db, &ap, "hprop", REALM, NOW, 300).expect_err("refused");
        assert_eq!(code, codes::KRB_AP_ERR_MODIFIED);
        assert!(text.contains("hprop/"), "{text}");
        assert!(text.contains("host/other"), "{text}");
    }

    /// The realm is part of the name: a `hprop/…` ticket from another realm is not this service's.
    #[test]
    fn a_ticket_for_another_realm_is_refused() {
        let (db, key) = realm();
        let ap = ap_req(
            &key,
            &format!("kadmin/hprop@{REALM}"),
            NOW,
            NOW + 3600,
            &format!("hprop/kdc.example.com@{REALM}"),
            "OTHER.COM",
        );
        let (code, text) =
            accept(&OwnCipher, &db, &ap, "hprop", REALM, NOW, 300).expect_err("refused");
        assert_eq!(code, codes::KRB_AP_ERR_MODIFIED);
        assert!(text.contains("OTHER.COM"), "{text}");
    }

    /// An expired ticket is refused with its own code, so a client can tell "renew" from "wrong key".
    #[test]
    fn an_expired_ticket_is_refused() {
        let (db, key) = realm();
        let ap = ap_req(
            &key,
            &format!("kadmin/hprop@{REALM}"),
            NOW,
            NOW - 1,
            &service_name(),
            REALM,
        );
        let (code, _) =
            accept(&OwnCipher, &db, &ap, "hprop", REALM, NOW, 300).expect_err("refused");
        assert_eq!(code, codes::KRB_AP_ERR_TKT_EXPIRED);
    }

    /// An authenticator outside the skew is a replay or a broken clock, and both are refusals.
    #[test]
    fn an_authenticator_outside_the_skew_is_refused() {
        let (db, key) = realm();
        for ctime in [NOW - 301, NOW + 301] {
            let ap = ap_req(
                &key,
                &format!("kadmin/hprop@{REALM}"),
                ctime,
                NOW + 3600,
                &service_name(),
                REALM,
            );
            let (code, text) =
                accept(&OwnCipher, &db, &ap, "hprop", REALM, NOW, 300).expect_err("refused");
            assert_eq!(code, codes::KRB_AP_ERR_SKEW, "{text}");
        }
        // And one inside it is not.
        let ap = ap_req(
            &key,
            &format!("kadmin/hprop@{REALM}"),
            NOW - 300,
            NOW + 3600,
            &service_name(),
            REALM,
        );
        assert!(accept(&OwnCipher, &db, &ap, "hprop", REALM, NOW, 300).is_ok());
    }

    /// A service the database does not know is a different refusal from a bad token: the realm is
    /// misconfigured, and the code says so.
    #[test]
    fn an_unknown_service_is_refused_by_code() {
        let key = OwnCipher.random(Enctype::Aes256Sha1).expect("a key");
        let db = MemoryHdb::new();
        let ap = ap_req(
            &key,
            &format!("kadmin/hprop@{REALM}"),
            NOW,
            NOW + 3600,
            &service_name(),
            REALM,
        );
        let (code, text) =
            accept(&OwnCipher, &db, &ap, "hprop", REALM, NOW, 300).expect_err("refused");
        assert_eq!(code, codes::KDC_ERR_S_PRINCIPAL_UNKNOWN);
        assert!(text.contains("not in the database"), "{text}");
    }

    /// An authenticator naming a different client than its ticket is refused: the ticket says who,
    /// and an authenticator that disagrees is either broken or an attempt to be somebody else.
    #[test]
    fn an_authenticator_for_another_client_is_refused() {
        let (db, key) = realm();
        // Sealed correctly, then rewritten to name somebody else: the test builds both halves so
        // that the mismatch is real rather than a decryption failure.
        let cipher = OwnCipher;
        let session = cipher.random(Enctype::Aes256Sha1).expect("a session key");
        let part = EncTicketPart {
            flags: 0,
            session_key: session.clone(),
            crealm: REALM.to_owned(),
            cname: p(&format!("kadmin/hprop@{REALM}")),
            transited_type: 0,
            transited: Vec::new(),
            authtime: NOW - 60,
            starttime: None,
            endtime: NOW + 3600,
            renew_till: None,
            caddr: None,
            authorization_data: None,
        };
        let enc = EncryptedData::seal(&cipher, &key, usage::KDC_REP_TICKET, None, &part.encode())
            .expect("the ticket seals");
        let ticket = Ticket {
            realm: REALM.to_owned(),
            sname: p(&service_name()),
            enc,
        };
        let authenticator = Authenticator {
            crealm: REALM.to_owned(),
            cname: p(&format!("alice@{REALM}")),
            cksum: None,
            cusec: 0,
            ctime: NOW,
            subkey: None,
            seq_number: None,
            authorization_data: None,
        };
        let authenticator = EncryptedData::seal(
            &cipher,
            &session,
            usage::AP_REQ_AUTH,
            None,
            &authenticator.encode(),
        )
        .expect("the authenticator seals");
        let ap = ApReq {
            ap_options: 0,
            ticket: ticket.encode(),
            authenticator,
        }
        .encode();

        let (code, text) =
            accept(&OwnCipher, &db, &ap, "hprop", REALM, NOW, 300).expect_err("refused");
        assert_eq!(code, codes::KRB_AP_ERR_MODIFIED);
        assert!(text.contains("alice"), "{text}");
        assert!(text.contains("kadmin/hprop"), "{text}");
    }

    /// A ticket whose enctype the service has no key for is refused by enctype, not by "bad
    /// integrity": the two are different problems for whoever has to fix it.
    #[test]
    fn a_ticket_with_an_enctype_the_service_lacks_is_refused() {
        let (db, key) = realm();
        // A ticket sealed in a key of another enctype, which the entry does not hold.
        let other = OwnCipher.random(Enctype::Aes128Sha1).expect("a key");
        let ap = ap_req(
            &other,
            &format!("kadmin/hprop@{REALM}"),
            NOW,
            NOW + 3600,
            &service_name(),
            REALM,
        );
        let (code, text) =
            accept(&OwnCipher, &db, &ap, "hprop", REALM, NOW, 300).expect_err("refused");
        assert_eq!(code, codes::KRB_AP_ERR_BAD_INTEGRITY);
        assert!(text.contains("no key of the ticket's enctype"), "{text}");
        // The same request with the right key is accepted, so the refusal above was about the key.
        let ap = ap_req(
            &key,
            &format!("kadmin/hprop@{REALM}"),
            NOW,
            NOW + 3600,
            &service_name(),
            REALM,
        );
        assert!(accept(&OwnCipher, &db, &ap, "hprop", REALM, NOW, 300).is_ok());
    }

    /// A ticket sealed in the wrong key does not open, and the refusal says the ticket, not the
    /// authenticator: telling the client which half failed is what makes this diagnosable.
    #[test]
    fn a_ticket_sealed_in_another_key_is_refused() {
        let (db, key) = realm();
        let _ = key;
        let stranger = OwnCipher.random(Enctype::Aes256Sha1).expect("a key");
        // The database holds `key`, the ticket is sealed in `stranger` of the same enctype.
        let ap = ap_req(
            &stranger,
            &format!("kadmin/hprop@{REALM}"),
            NOW,
            NOW + 3600,
            &service_name(),
            REALM,
        );
        let (code, text) =
            accept(&OwnCipher, &db, &ap, "hprop", REALM, NOW, 300).expect_err("refused");
        assert_eq!(code, codes::KRB_AP_ERR_BAD_INTEGRITY);
        assert!(text.contains("does not decrypt"), "{text}");
    }
}
