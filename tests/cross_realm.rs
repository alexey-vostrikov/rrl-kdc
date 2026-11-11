//! Cross-realm: a ticket addressed to this realm but issued by another.
//!
//! A Kerberos trust between two realms is one shared key stored under two names — `krbtgt/B@A` in
//! A, `krbtgt/A@B` in B. A client in A asks its own KDC for `krbtgt/B@A`, then presents that to B,
//! which issues the service ticket. The second half is what this file tests, because it is the
//! half that was missing: the ticket's issuing realm is A, its service realm is B, and B has to
//! accept it and find the key in a database entry that does not carry its own name.
//!
//! The `transited` path across a third realm is not here: it needs two KDCs in a row, and lives in
//! `cross_realm_chain.rs`, which walks it over sockets. What this file holds is the accepting half
//! — a ticket another realm issued, and what this one does with it.

mod common;

use std::sync::Arc;

use common::NOW;
use rrl_kdc::crypto::{Cipher, Enctype, Key, OwnCipher, usage};
use rrl_kdc::der;
use rrl_kdc::hdb::{HdbEntry, MemoryHdb};
use rrl_kdc::kdc::{Kdc, KdcConfig};
use rrl_kdc::msg::{
    self, ApReq, Authenticator, EncTicketPart, EncryptedData, Ticket, encode_pa_data, tkt_flags,
};
use rrl_kdc::name::Principal;

const A: &str = "REALM.A";
const B: &str = "REALM.B";

/// The key the two realms share; A stores it as `krbtgt/B@A`, B as `krbtgt/A@B`.
fn shared(cipher: &dyn Cipher) -> Key {
    cipher
        .s2k(
            Enctype::Aes256Sha1,
            b"trust",
            b"shared between A and B",
            None,
        )
        .unwrap()
}

fn service_in_b() -> Principal {
    Principal::parse(&format!("cifs/files@{B}")).unwrap()
}

/// Realm B: its own `krbtgt`, the mirror trust entry, and a service.
fn realm_b() -> (MemoryHdb, Key) {
    let cipher = OwnCipher;
    let db = MemoryHdb::new();

    let mut own = HdbEntry::krbtgt(B);
    own.add_password_key(&cipher, Enctype::Aes256Sha1, b"master", 1)
        .unwrap();
    db.insert(own).unwrap();

    let mut trust = HdbEntry::service(Principal {
        name_type: rrl_kdc::name::NT_SRV_INST,
        components: vec!["krbtgt".to_owned(), A.to_owned()],
        realm: B.to_owned(),
    });
    trust.add_key(shared(&cipher), 1, None);
    db.insert(trust).unwrap();

    let mut svc = HdbEntry::service(service_in_b());
    svc.add_password_key(&cipher, Enctype::Aes256Sha1, b"svc", 1)
        .unwrap();
    db.insert(svc).unwrap();

    (db, shared(&cipher))
}

fn kdc_b(db: MemoryHdb) -> Kdc {
    Kdc::new(
        KdcConfig::new(B).unwrap(),
        Arc::new(db),
        Arc::new(OwnCipher),
    )
}

/// A TGT as realm A would have issued it for B: `krbtgt/B@A`, sealed in the shared key.
fn tgt_from_a(cname: &Principal, shared: &Key) -> (Vec<u8>, Key) {
    let cipher = OwnCipher;
    let session_key = cipher.random(Enctype::Aes256Sha1).unwrap();
    let part = EncTicketPart {
        flags: tkt_flags::FORWARDABLE | tkt_flags::PRE_AUTHENT,
        session_key: session_key.clone(),
        crealm: A.to_owned(),
        cname: cname.clone(),
        transited_type: 0,
        transited: Vec::new(),
        authtime: NOW - 60,
        starttime: None,
        endtime: NOW + 3600,
        renew_till: None,
        caddr: None,
        authorization_data: None,
    };
    let ticket = Ticket {
        // Issued by A: this field is where B learns whose `krbtgt` key to look for.
        realm: A.to_owned(),
        sname: Principal::krbtgt(B),
        enc: EncryptedData::seal(
            &cipher,
            shared,
            usage::KDC_REP_TICKET,
            Some(1),
            &part.encode(),
        )
        .unwrap(),
    };
    (ticket.encode(), session_key)
}

/// A TGS-REQ for `target` in realm B, presenting `ticket` with `session_key`.
fn tgs_req(ticket: &[u8], session_key: &Key, target: &Principal, cname: &Principal) -> Vec<u8> {
    let cipher = OwnCipher;
    let body = der::seq(&[
        der::field(0, der::flags32(0)),
        der::field(2, der::general_string(&target.realm)),
        der::field(3, target.encode_name()),
        der::field(5, der::time(NOW + 3600)),
        der::field(7, der::int(0x4242)),
        der::field(8, der::seq(&[der::int(18)])),
    ]);
    let cksum = cipher
        .checksum(session_key, usage::TGS_REQ_AUTH_CKSUM, &body)
        .unwrap();
    let authenticator = Authenticator {
        crealm: A.to_owned(),
        cname: cname.clone(),
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
            &authenticator.encode(),
        )
        .unwrap(),
    };
    let padata = encode_pa_data(&[(msg::PA_TGS_REQ, ap_req.encode())]);
    der::cons(
        der::app(12),
        &[der::seq(&[
            der::field(1, der::int(5)),
            der::field(2, der::int(12)),
            der::field(3, padata),
            der::field(4, body),
        ])],
    )
}

/// Whether the reply is a success rather than a `KRB-ERROR`.
fn succeeded(reply: &[u8]) -> bool {
    msg::KrbError::decode(reply).is_err()
}

/// The feature: B answers a request that presents a ticket A issued addresses to B.
#[test]
fn a_ticket_issued_by_another_realm_reaches_a_service() {
    let (db, shared) = realm_b();
    let kdc = kdc_b(db);
    let user = Principal::parse(&format!("alice@{A}")).unwrap();
    let (ticket, session_key) = tgt_from_a(&user, &shared);

    let reply = kdc.handle_from(
        &tgs_req(&ticket, &session_key, &service_in_b(), &user),
        NOW,
        None,
    );
    assert!(succeeded(&reply), "B must answer, not refuse");

    let part = common::read_reply(&reply, &session_key, usage::TGS_REP_ENCPART_SESSKEY);
    assert_eq!(
        part.sname,
        service_in_b(),
        "the ticket is for the service asked for"
    );
    assert_eq!(part.srealm, B);
    // The client's own name is in the reply's clear part; the encrypted part carries the
    // service. What proves the cross-realm path is that `srealm` is B while the ticket came
    // from A.
}

/// The reply is sealed in the cross-realm ticket's session key, which is the proof B decrypted it:
/// that key exists nowhere in B's database.
#[test]
fn the_reply_is_sealed_in_the_session_key_it_could_only_have_from_the_ticket() {
    let (db, shared) = realm_b();
    let kdc = kdc_b(db);
    let user = Principal::parse(&format!("alice@{A}")).unwrap();
    let (ticket, session_key) = tgt_from_a(&user, &shared);

    let reply = kdc.handle_from(
        &tgs_req(&ticket, &session_key, &service_in_b(), &user),
        NOW,
        None,
    );

    // The reply opens under the ticket's session key...
    let part = common::read_reply(&reply, &session_key, usage::TGS_REP_ENCPART_SESSKEY);
    assert_eq!(part.srealm, B);

    // ...and the same reply read with an unrelated key is not the same encrypted part, which is
    // what a client holding the wrong key would see: a decrypt failure, not a ticket.
    let wrong = OwnCipher.random(Enctype::Aes256Sha1).unwrap();
    let f = der::Fields::parse_app("TGS-REP", 13, &reply).expect("a TGS-REP");
    let mut r = der::Reader::new(f.bytes(6, "TGS-REP").expect("enc-part"));
    let content = r.expect_in("enc-part", der::SEQUENCE).expect("the part");
    let enc = EncryptedData::decode_content("enc-part", content).expect("EncryptedData");
    assert!(
        OwnCipher
            .decrypt(&wrong, usage::TGS_REP_ENCPART_SESSKEY, &enc.cipher)
            .is_err(),
        "the reply must not open under an unrelated key"
    );
}

/// A ticket addressed to a third realm is refused: B only honours `krbtgt/B`.
#[test]
fn a_ticket_addressed_to_a_third_realm_is_refused() {
    let (db, shared) = realm_b();
    let kdc = kdc_b(db);
    let user = Principal::parse(&format!("alice@{A}")).unwrap();
    let (ticket, session_key) = tgt_from_a(&user, &shared);

    let mut parsed = Ticket::decode(&ticket).unwrap();
    parsed.sname = Principal::krbtgt("REALM.C");
    let reply = kdc.handle_from(
        &tgs_req(&parsed.encode(), &session_key, &service_in_b(), &user),
        NOW,
        None,
    );

    assert!(
        !succeeded(&reply),
        "a ticket for C must not be answered by B"
    );
}

/// A ticket addressed to B but sealed in a key B does not hold is refused — the trust is the key,
/// not the name.
#[test]
fn a_ticket_sealed_in_an_unknown_key_is_refused() {
    let (db, _shared) = realm_b();
    let kdc = kdc_b(db);
    let user = Principal::parse(&format!("alice@{A}")).unwrap();
    // Sealed in A's own idea of a key, which is not the one B holds under `krbtgt/A@B`.
    let impostor = OwnCipher
        .s2k(Enctype::Aes256Sha1, b"trust", b"not the shared salt", None)
        .unwrap();
    let (ticket, session_key) = tgt_from_a(&user, &impostor);

    let reply = kdc.handle_from(
        &tgs_req(&ticket, &session_key, &service_in_b(), &user),
        NOW,
        None,
    );
    assert!(
        !succeeded(&reply),
        "a ticket B cannot decrypt must be refused, not answered"
    );
}

/// A realm this KDC cannot reach gets no ticket and no referral: the body names where the server
/// lives (RFC 4120 §5.4.1 field [2]), and a name this realm neither holds nor can hand on is a
/// refusal, not an answer for somebody else's realm.
#[test]
fn a_name_in_a_realm_this_kdc_cannot_reach_is_refused() {
    let (db, shared) = realm_b();
    let kdc = kdc_b(db);
    let user = Principal::parse(&format!("alice@{A}")).unwrap();
    let (ticket, session_key) = tgt_from_a(&user, &shared);

    let elsewhere = Principal::parse("cifs/files@FOREIGN.REALM").unwrap();
    let reply = kdc.handle_from(
        &tgs_req(&ticket, &session_key, &elsewhere, &user),
        NOW,
        None,
    );
    let err = msg::KrbError::decode(&reply).expect("a refusal is a KRB-ERROR");
    assert_eq!(
        err.code,
        rrl_kdc::error::codes::KDC_ERR_S_PRINCIPAL_UNKNOWN,
        "no trust, no hierarchy, no referral — and the code says which"
    );
}

/// A body rewritten in flight fails its checksum before any name is looked at: the checksum is
/// over the octets as sent, and a KDC that decoded and re-encoded the body would verify its own
/// re-encoding and accept the tampering.
#[test]
fn a_body_rewritten_in_flight_fails_the_checksum() {
    let (db, shared) = realm_b();
    let kdc = kdc_b(db);
    let user = Principal::parse(&format!("alice@{A}")).unwrap();
    let (ticket, session_key) = tgt_from_a(&user, &shared);

    let mut req = tgs_req(&ticket, &session_key, &service_in_b(), &user);
    // The same length, so the DER stays valid; only the octets the client signed change.
    let at = req
        .windows(B.len())
        .position(|w| w == B.as_bytes())
        .expect("the body carries the realm");
    req[at..at + A.len()].copy_from_slice(A.as_bytes());

    let reply = kdc.handle_from(&req, NOW, None);
    let err = msg::KrbError::decode(&reply).expect("a refusal");
    assert_eq!(err.code, rrl_kdc::error::codes::KRB_AP_ERR_MODIFIED);
}
