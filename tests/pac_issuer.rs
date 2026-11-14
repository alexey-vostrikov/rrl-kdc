//! The PAC issuer seam: what the KDC hands over, and what it does with the answer.
//!
//! `tests/pac_ticket.rs` checks the PAC the crate builds itself. This file checks the split MIT
//! makes between `kdc_authdata.c` and a kdb module's `issue_pac`: that the KDC asks an issuer, that
//! it passes the facts a directory cannot obtain any other way — both keys, the signature type, the
//! PAC an incoming ticket carried — and that it puts the answer in the ticket rather than rebuilding
//! one of its own.
//!
//! The issuer here is a test double. That is the point: a seam proved with the implementation it
//! ships with is a seam nobody has crossed.

use std::sync::{Arc, Mutex};

use rrl_kdc::crypto::{Cipher, Enctype, Key, OwnCipher, usage};
use rrl_kdc::der;
use rrl_kdc::hdb::{HdbEntry, MemoryHdb};
use rrl_kdc::kdc::pac::{PacIssuer, PacRequest, SignatureType};
use rrl_kdc::kdc::{Kdc, KdcConfig};
use rrl_kdc::msg::{
    self, ApReq, Authenticator, EncTicketPart, EncryptedData, Ticket, encode_pa_data, kdc_options,
    tkt_flags,
};
use rrl_kdc::name::Principal;

const REALM: &str = "EXAMPLE.COM";
const SERVICE: &str = "host/server.example.com";
const NOW: i64 = 1_700_000_000;

fn alice() -> Principal {
    Principal::parse(&format!("alice@{REALM}")).unwrap()
}

fn service() -> Principal {
    Principal::parse(&format!("{SERVICE}@{REALM}")).unwrap()
}

/// What one call to [`Recorder`] saw.
#[derive(Debug, Clone)]
struct Seen {
    client: Principal,
    server: Principal,
    authtime: i64,
    signature: SignatureType,
    server_key: Key,
    kdc_key: Key,
    old_pac: Option<Vec<u8>>,
}

/// An issuer that records its arguments and answers with whatever the test told it to.
struct Recorder {
    /// Everything the KDC passed, one entry per call.
    seen: Mutex<Vec<Seen>>,
    /// What to answer: `Ok(Some(bytes))`, `Ok(None)`, or an error.
    answer: Answer,
}

enum Answer {
    /// Return this `AuthorizationData`.
    Pac(Vec<u8>),
    /// Decline: a ticket without a PAC.
    None,
    /// Fail, which a KDC must report rather than swallow.
    Fail,
}

impl std::fmt::Debug for Recorder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Recorder")
            .field("calls", &self.seen.lock().map(|s| s.len()).unwrap_or(0))
            .finish_non_exhaustive()
    }
}

impl Recorder {
    fn pac(answer: Answer) -> Arc<Recorder> {
        Arc::new(Recorder {
            seen: Mutex::new(Vec::new()),
            answer,
        })
    }

    fn calls(&self) -> Vec<Seen> {
        self.seen.lock().expect("the recorder's lock").clone()
    }

    fn only_call(&self) -> Seen {
        let calls = self.calls();
        assert_eq!(calls.len(), 1, "the issuer is asked once per ticket");
        calls.into_iter().next().unwrap()
    }
}

impl PacIssuer for Recorder {
    fn issue(&self, request: &PacRequest<'_>) -> rrl_kdc::Result<Option<Vec<u8>>> {
        self.seen.lock().expect("the recorder's lock").push(Seen {
            client: request.client.clone(),
            server: request.server.clone(),
            authtime: request.authtime,
            signature: request.signature,
            server_key: request.server_key.clone(),
            kdc_key: request.kdc_key.clone(),
            old_pac: request.old_pac.map(<[u8]>::to_vec),
        });
        match &self.answer {
            Answer::Pac(bytes) => Ok(Some(bytes.clone())),
            Answer::None => Ok(None),
            Answer::Fail => Err(rrl_kdc::Error::Hdb("the directory is gone".into())),
        }
    }
}

/// The realm, with the `krbtgt` and the service keys this file asserts on.
fn realm() -> (MemoryHdb, Key, Key) {
    let cipher = OwnCipher;
    let db = MemoryHdb::new();
    let mut krbtgt = HdbEntry::krbtgt(REALM);
    krbtgt
        .add_password_key(&cipher, Enctype::Aes256Sha1, b"master", 1)
        .unwrap();
    let krbtgt_key = krbtgt.key_for(Enctype::Aes256Sha1).unwrap().key.clone();
    db.insert(krbtgt).unwrap();

    let mut alice_entry = HdbEntry::user(alice());
    alice_entry
        .add_password_key(&cipher, Enctype::Aes256Sha1, b"pw", 1)
        .unwrap();
    db.insert(alice_entry).unwrap();

    let mut service_entry = HdbEntry::service(service());
    service_entry
        .add_password_key(&cipher, Enctype::Aes256Sha1, b"svc", 1)
        .unwrap();
    let service_key = service_entry
        .key_for(Enctype::Aes256Sha1)
        .unwrap()
        .key
        .clone();
    db.insert(service_entry).unwrap();
    (db, krbtgt_key, service_key)
}

fn kdc(issuer: Option<Arc<Recorder>>) -> (Kdc, Key, Key) {
    let (db, krbtgt_key, service_key) = realm();
    let mut kdc = Kdc::new(
        KdcConfig::new(REALM).unwrap(),
        Arc::new(db),
        Arc::new(OwnCipher),
    );
    if let Some(issuer) = issuer {
        kdc = kdc.with_pac_issuer(issuer);
    }
    (kdc, krbtgt_key, service_key)
}

/// A TGT as the AS exchange would have issued it, with whatever `authorization_data` the test wants.
fn tgt(krbtgt_key: &Key, authorization_data: Option<Vec<u8>>) -> (Vec<u8>, Key) {
    let cipher = OwnCipher;
    let session_key = cipher.random(Enctype::Aes256Sha1).unwrap();
    let part = EncTicketPart {
        flags: tkt_flags::INITIAL | tkt_flags::PRE_AUTHENT | tkt_flags::FORWARDABLE,
        session_key: session_key.clone(),
        crealm: REALM.into(),
        cname: alice(),
        transited_type: 0,
        transited: Vec::new(),
        authtime: NOW - 60,
        starttime: None,
        endtime: NOW + 3600,
        renew_till: None,
        caddr: None,
        authorization_data,
    };
    let ticket = Ticket {
        realm: REALM.into(),
        sname: Principal::krbtgt(REALM),
        enc: EncryptedData::seal(
            &cipher,
            krbtgt_key,
            usage::KDC_REP_TICKET,
            Some(1),
            &part.encode(),
        )
        .unwrap(),
    };
    (ticket.encode(), session_key)
}

/// A `TGS-REQ` presenting that TGT.
fn tgs_req(ticket: &[u8], session_key: &Key) -> Vec<u8> {
    let cipher = OwnCipher;
    let body = der::seq(&[
        der::field(0, der::flags32(kdc_options::FORWARDABLE)),
        der::field(2, der::general_string(REALM)),
        der::field(3, service().encode_name()),
        der::field(5, der::time(NOW + 3600)),
        der::field(7, der::int(0x4343)),
        der::field(8, der::seq(&[der::int(18)])),
    ]);
    let cksum = cipher
        .checksum(session_key, usage::TGS_REQ_AUTH_CKSUM, &body)
        .unwrap();
    let auth = Authenticator {
        crealm: REALM.into(),
        cname: alice(),
        cksum: Some((Enctype::Aes256Sha1.checksum_type(), cksum)),
        cusec: 0,
        ctime: NOW,
        subkey: None,
        seq_number: None,
        authorization_data: None,
    };
    let ap_req = ApReq {
        ap_options: 0,
        ticket: ticket.to_vec(),
        authenticator: EncryptedData::seal(
            &cipher,
            session_key,
            usage::TGS_REQ_AUTH,
            None,
            &auth.encode(),
        )
        .unwrap(),
    };
    let parts = vec![
        der::field(1, der::int(5)),
        der::field(2, der::int(12)),
        der::field(3, encode_pa_data(&[(msg::PA_TGS_REQ, ap_req.encode())])),
        der::field(4, body),
    ];
    der::cons(der::app(12), &[der::seq(&parts)])
}

/// The ticket from a reply, decrypted with the key that sealed it.
fn issued(reply: &[u8], key: &Key) -> EncTicketPart {
    let fields = der::Fields::parse_app("KDC-REP", 13, reply).expect("a KDC-REP");
    let ticket = Ticket::decode(fields.bytes(5, "KDC-REP").expect("the ticket")).expect("a Ticket");
    let plain = OwnCipher
        .decrypt(key, usage::KDC_REP_TICKET, &ticket.enc.cipher)
        .expect("the ticket opens with the service key");
    EncTicketPart::decode(&plain).expect("an EncTicketPart")
}

/// The `AuthorizationData` the ticket from a reply carries.
fn authorization_data(reply: &[u8], key: &Key) -> Option<Vec<u8>> {
    issued(reply, key).authorization_data
}

/// A `TGS-REQ` against a fresh TGT, answered. Every case here is a service ticket, because that is
/// where the two keys differ: in an `AS-REP` the server *is* `krbtgt`, so a seam signed with one key
/// twice would look correct.
fn service_reply(kdc: &Kdc, krbtgt_key: &Key) -> Vec<u8> {
    let (ticket, session) = tgt(krbtgt_key, None);
    kdc.handle_from(&tgs_req(&ticket, &session), NOW, None)
}

/// The issuer is asked, and its answer is what the ticket carries.
///
/// Not "a PAC appeared": the octets here are recognisable and are not what `IdentityIssuer` would
/// have produced with any identity, so a KDC that quietly built its own PAC would fail this.
#[test]
fn the_issuers_answer_is_what_the_ticket_carries() {
    let answer = rrl_kdc::kdc::pac::authorization_data(b"the issuer's own pac");
    let issuer = Recorder::pac(Answer::Pac(answer.clone()));
    let (kdc, krbtgt_key, _) = kdc(Some(Arc::clone(&issuer)));

    let (ticket, session) = tgt(&krbtgt_key, None);
    let reply = kdc.handle_from(&tgs_req(&ticket, &session), NOW, None);
    assert!(
        msg::KrbError::decode(&reply).is_err(),
        "a ticket was expected: {:?}",
        msg::KrbError::decode(&reply).map(|e| (e.code, e.e_text))
    );
    let (_, _, service_key) = realm();
    let carried = authorization_data(&reply, &service_key).expect("the ticket carries a PAC");
    assert_eq!(
        carried, answer,
        "the ticket carries the issuer's octets, untouched"
    );
    assert_eq!(issuer.only_call().client, alice());
}

/// A realm that installed no issuer issues plain Kerberos tickets.
#[test]
fn a_realm_without_an_issuer_issues_no_pac() {
    let (kdc, krbtgt_key, service_key) = kdc(None);
    let reply = service_reply(&kdc, &krbtgt_key);
    assert!(
        msg::KrbError::decode(&reply).is_err(),
        "the ticket itself must still be issued"
    );
    assert_eq!(
        authorization_data(&reply, &service_key),
        None,
        "no issuer, no PAC — the same answer MIT gives a kdb module with no issue_pac"
    );
}

/// An issuer that declines leaves the ticket without a PAC, and that is not an error.
#[test]
fn an_issuer_that_declines_leaves_no_pac() {
    let issuer = Recorder::pac(Answer::None);
    let (kdc, krbtgt_key, service_key) = kdc(Some(issuer));
    let reply = service_reply(&kdc, &krbtgt_key);
    assert!(
        msg::KrbError::decode(&reply).is_err(),
        "declining a PAC is not declining a login: {:?}",
        msg::KrbError::decode(&reply).map(|e| (e.code, e.e_text))
    );
    assert_eq!(authorization_data(&reply, &service_key), None);
}

/// A failure inside the issuer is reported, not swallowed into a ticket without a PAC.
///
/// A realm that asked for PACs and silently stopped issuing them looks like a Windows client that
/// cannot log on; the fault has to surface where it happened.
#[test]
fn an_error_from_the_issuer_is_not_swallowed() {
    let issuer = Recorder::pac(Answer::Fail);
    let (kdc, krbtgt_key, _) = kdc(Some(issuer));
    let reply = service_reply(&kdc, &krbtgt_key);
    let err = msg::KrbError::decode(&reply).expect("a broken directory must not produce a ticket");
    // The code, not the text: an internal failure is `SVC_UNAVAILABLE` and its message stays in the
    // realm's own log, because a client told "the directory is gone" learns something about the
    // deployment, and a client told "wrong password" would be told a lie.
    assert_eq!(
        err.code,
        rrl_kdc::error::codes::KDC_ERR_SVC_UNAVAILABLE,
        "a directory that cannot answer is a realm fault: {:?}",
        (err.code, err.e_text)
    );
}

/// A service ticket's PAC is signed with two different keys, and the issuer is given both.
///
/// This is the check that a seam signed with one key fails: in a `TGS-REP` the server checksum is
/// keyed by the service's key and the privsvr checksum by `krbtgt`'s, so an issuer handed one key
/// twice would produce a PAC that verifies here and at no service. An `AS-REP` cannot show this —
/// there the server *is* `krbtgt`, and the two keys are equal by construction.
#[test]
fn the_issuer_is_given_the_service_key_and_the_krbtgt_key() {
    let issuer = Recorder::pac(Answer::Pac(rrl_kdc::kdc::pac::authorization_data(b"a pac")));
    let (kdc, krbtgt_key, service_key) = kdc(Some(Arc::clone(&issuer)));

    let (ticket, session) = tgt(&krbtgt_key, None);
    let reply = kdc.handle_from(&tgs_req(&ticket, &session), NOW, None);
    assert!(
        msg::KrbError::decode(&reply).is_err(),
        "{:?}",
        msg::KrbError::decode(&reply).map(|e| (e.code, e.e_text))
    );

    let seen = issuer.only_call();
    assert_eq!(seen.server, service(), "the issuer is told which service");
    assert_eq!(
        seen.server_key.bytes(),
        service_key.bytes(),
        "the server checksum's key is the service's"
    );
    assert_eq!(
        seen.kdc_key.bytes(),
        krbtgt_key.bytes(),
        "the privsvr checksum's key is the realm's krbtgt"
    );
    assert_ne!(
        seen.server_key.bytes(),
        seen.kdc_key.bytes(),
        "and they are two keys: one key twice is a PAC no service can verify"
    );
    assert_eq!(
        seen.signature,
        SignatureType::for_enctype(Enctype::Aes256Sha1).unwrap(),
        "one signature type describes both checksums"
    );
    // The value a logon's expiry is measured from has to be the one written into the ticket beside
    // it, whichever the KDC decides: an issuer given another instant would state a logon window the
    // service computes differently.
    assert_eq!(
        seen.authtime,
        issued(&reply, &service_key).authtime,
        "the issuer is given the authtime the ticket carries"
    );
}

/// The PAC an incoming ticket carried reaches the issuer of the next one.
///
/// A service hop is where a PAC is either kept or replaced, and the decision is the directory's: an
/// issuer that could not see the incoming PAC could not keep it.
#[test]
fn the_pac_an_incoming_ticket_carried_reaches_the_issuer() {
    let incoming = rrl_kdc::kdc::pac::authorization_data(b"the pac from the tgt");
    let issuer = Recorder::pac(Answer::Pac(rrl_kdc::kdc::pac::authorization_data(
        b"the new pac",
    )));
    let (kdc, krbtgt_key, _) = kdc(Some(Arc::clone(&issuer)));

    let (ticket, session) = tgt(&krbtgt_key, Some(incoming));
    let reply = kdc.handle_from(&tgs_req(&ticket, &session), NOW, None);
    assert!(
        msg::KrbError::decode(&reply).is_err(),
        "{:?}",
        msg::KrbError::decode(&reply).map(|e| (e.code, e.e_text))
    );

    let seen = issuer.only_call();
    assert_eq!(
        seen.old_pac.as_deref(),
        Some(&b"the pac from the tgt"[..]),
        "the PAC itself, not the AuthorizationData around it"
    );
}

/// A `TGS-REQ` whose TGT carried no PAC gives the issuer no old PAC rather than an empty one.
#[test]
fn a_tgt_without_a_pac_gives_the_issuer_nothing_to_keep() {
    let issuer = Recorder::pac(Answer::None);
    let (kdc, krbtgt_key, _) = kdc(Some(Arc::clone(&issuer)));
    let (ticket, session) = tgt(&krbtgt_key, None);
    let _ = kdc.handle_from(&tgs_req(&ticket, &session), NOW, None);
    assert_eq!(issuer.only_call().old_pac, None);
}
