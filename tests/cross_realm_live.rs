//! Cross-realm, end to end: two KDCs and a client that goes through both.
//!
//! The three exchanges a client makes between two realms, each over the wire:
//!
//! 1. to **A**: an AS-REQ for `alice`, which returns a TGT for A;
//! 2. to **A**: a TGS-REQ for `krbtgt/B@A`, which returns a ticket addressed to B and sealed in
//!    the key the two realms share;
//! 3. to **B**: a TGS-REQ presenting that ticket for `cifs/files@B`, which returns the service
//!    ticket.
//!
//! Step 2 is A's half of a trust and step 3 is B's, and this file is what makes the feature
//! observable rather than argued: the client here is the test, so every octet is on the wire and
//! nothing is short-circuited by calling the engine directly.
//!
//! What the assertions are about:
//!
//! * the service ticket decrypts under B's service key — the key exists only in B's database;
//! * it names `alice@A`, so the ticket B issued carries the client from the other realm;
//! * its `transited` is empty and of type 0, which is what a direct A→B hop is: no realm in
//!   between, in the same form Microsoft's TGTs use.

mod common;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;

use rrl_kdc::crypto::{Cipher, Enctype, Key, OwnCipher, usage};
use rrl_kdc::der;
use rrl_kdc::hdb::{HdbEntry, MemoryHdb};
use rrl_kdc::kdc::{Kdc, KdcConfig};
use rrl_kdc::msg::{
    self, ApReq, Authenticator, EncTicketPart, EncryptedData, Ticket, encode_pa_data, kdc_options,
    tkt_flags,
};
use rrl_kdc::name::Principal;
use rrl_kdc::transport::{RunningKdc, serve_loopback};

const A: &str = "REALM.A";
const B: &str = "REALM.B";
const PASSWORD: &str = "correct horse battery staple";

/// The key A keeps as `krbtgt/B@A` and B keeps as `krbtgt/A@B` — the whole of the trust.
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

fn service_in_b(cipher: &dyn Cipher) -> (Principal, Key) {
    let principal = Principal::parse(&format!("cifs/files@{B}")).unwrap();
    let key = cipher
        .s2k(
            Enctype::Aes256Sha1,
            b"service",
            principal.default_salt().as_slice(),
            None,
        )
        .unwrap();
    (principal, key)
}

/// Realm A: its own `krbtgt`, `alice`, and the trust entry addressed at B.
fn realm_a() -> MemoryHdb {
    let cipher = OwnCipher;
    let db = MemoryHdb::new();

    let mut krbtgt = HdbEntry::krbtgt(A);
    krbtgt
        .add_password_key(&cipher, Enctype::Aes256Sha1, b"master key of A", 1)
        .unwrap();
    db.insert(krbtgt).unwrap();

    let mut alice = HdbEntry::user(Principal::parse(&format!("alice@{A}")).unwrap());
    alice
        .add_password_key(&cipher, Enctype::Aes256Sha1, PASSWORD.as_bytes(), 1)
        .unwrap();
    db.insert(alice).unwrap();

    // `krbtgt/B@A`: the same principal name B uses for itself, but stored in realm A and keyed
    // with the shared key. It is what makes A able to issue a ticket B will accept.
    let mut towards_b = HdbEntry::service(Principal {
        name_type: rrl_kdc::name::NT_SRV_INST,
        components: vec!["krbtgt".to_owned(), B.to_owned()],
        realm: A.to_owned(),
    });
    towards_b.add_key(shared(&cipher), 1, None);
    db.insert(towards_b).unwrap();

    db
}

/// Realm B: its own `krbtgt`, the mirror trust entry, and one service.
fn realm_b() -> MemoryHdb {
    let cipher = OwnCipher;
    let db = MemoryHdb::new();

    let mut krbtgt = HdbEntry::krbtgt(B);
    krbtgt
        .add_password_key(&cipher, Enctype::Aes256Sha1, b"master key of B", 1)
        .unwrap();
    db.insert(krbtgt).unwrap();

    let mut from_a = HdbEntry::service(Principal {
        name_type: rrl_kdc::name::NT_SRV_INST,
        components: vec!["krbtgt".to_owned(), A.to_owned()],
        realm: B.to_owned(),
    });
    from_a.add_key(shared(&cipher), 1, None);
    db.insert(from_a).unwrap();

    let (principal, key) = service_in_b(&cipher);
    let mut svc = HdbEntry::service(principal);
    svc.add_key(key, 1, None);
    db.insert(svc).unwrap();

    db
}

fn start(realm: &str, db: MemoryHdb) -> RunningKdc {
    serve_loopback(Kdc::new(
        KdcConfig::new(realm).unwrap(),
        Arc::new(db),
        Arc::new(OwnCipher),
    ))
}

/// A TCP exchange with a four-octet length in front, which is how this KDC's transport frames.
fn ask(addr: &str, request: &[u8]) -> Vec<u8> {
    let mut stream = TcpStream::connect(addr).expect("the KDC listens");
    let mut framed = (request.len() as u32).to_be_bytes().to_vec();
    framed.extend_from_slice(request);
    stream.write_all(&framed).expect("the request goes out");

    let mut header = [0u8; 4];
    stream.read_exact(&mut header).expect("a reply arrives");
    let len = u32::from_be_bytes(header) as usize;
    let mut reply = vec![0u8; len];
    stream.read_exact(&mut reply).expect("the reply is whole");
    reply
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

/// An AS-REQ for `client` in `realm`, asking for that realm's own TGT, with a timestamp.
fn as_req(client: &Principal, password: &[u8], timestamp: i64) -> Vec<u8> {
    let cipher = OwnCipher;
    let realm = client.realm.as_str();
    let ts_key = cipher
        .s2k(Enctype::Aes256Sha1, password, &client.default_salt(), None)
        .unwrap();
    let stamped = msg::encode_enc_ts_enc(timestamp, None);
    let padata_value =
        EncryptedData::seal(&cipher, &ts_key, usage::AS_REQ_PA_ENC_TS, None, &stamped)
            .unwrap()
            .encode();

    let body = der::seq(&[
        der::field(0, der::flags32(kdc_options::FORWARDABLE)),
        der::field(1, client.encode_name()),
        der::field(2, der::general_string(realm)),
        der::field(3, Principal::krbtgt(realm).encode_name()),
        der::field(5, der::time(timestamp + 3600)),
        der::field(7, der::int(0x1111_2222)),
        der::field(8, der::seq(&[der::int(18)])),
    ]);
    der::cons(
        der::app(10),
        &[der::seq(&[
            der::field(1, der::int(5)),
            der::field(2, der::int(10)),
            der::field(3, encode_pa_data(&[(msg::PA_ENC_TIMESTAMP, padata_value)])),
            der::field(4, body),
        ])],
    )
}

/// A TGS-REQ presenting `ticket` with `session_key`, for `target`, to the KDC of `realm`.
fn tgs_req(
    realm: &str,
    ticket: &[u8],
    session_key: &Key,
    target: &Principal,
    client: &Principal,
    timestamp: i64,
    options: u32,
) -> Vec<u8> {
    let cipher = OwnCipher;
    let body = der::seq(&[
        der::field(0, der::flags32(options)),
        der::field(2, der::general_string(realm)),
        der::field(3, target.encode_name()),
        der::field(5, der::time(timestamp + 3600)),
        der::field(7, der::int(0x3333_4444)),
        der::field(8, der::seq(&[der::int(18)])),
    ]);
    let cksum = cipher
        .checksum(session_key, usage::TGS_REQ_AUTH_CKSUM, &body)
        .unwrap();
    let authenticator = Authenticator {
        crealm: client.realm.clone(),
        cname: client.clone(),
        cksum: Some((Enctype::Aes256Sha1.checksum_type(), cksum)),
        cusec: 0,
        ctime: timestamp,
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
    der::cons(
        der::app(12),
        &[der::seq(&[
            der::field(1, der::int(5)),
            der::field(2, der::int(12)),
            der::field(3, encode_pa_data(&[(msg::PA_TGS_REQ, ap_req.encode())])),
            der::field(4, body),
        ])],
    )
}

/// The `enc-part` of a `KDC-REP`, decoded and decrypted with `key`.
fn open_rep(reply: &[u8], app_tag: u8, key: &Key, use_: u32) -> Vec<u8> {
    let what = if app_tag == 11 { "AS-REP" } else { "TGS-REP" };
    let f = der::Fields::parse_app(what, app_tag, reply).unwrap_or_else(|e| {
        panic!(
            "{what} expected, and the reply was: {:?} ({e})",
            msg::KrbError::decode(reply).map(|k| (k.code, k.e_text))
        )
    });
    let mut r = der::Reader::new(f.bytes(6, what).expect("enc-part"));
    let content = r.expect_in(what, der::SEQUENCE).expect("the part");
    let enc = EncryptedData::decode_content(what, content).expect("EncryptedData");
    OwnCipher
        .decrypt(key, use_, &enc.cipher)
        .expect("the encrypted part must open under the key the exchange says it used")
}

/// The `Ticket` of a `KDC-REP`: field `[5]`, a whole `[APPLICATION 1]`.
fn ticket_of(reply: &[u8], app_tag: u8) -> Ticket {
    let what = if app_tag == 11 { "AS-REP" } else { "TGS-REP" };
    let f = der::Fields::parse_app(what, app_tag, reply).expect("a KDC-REP");
    Ticket::decode(f.bytes(5, what).expect("ticket")).expect("the ticket decodes")
}

/// The whole path, and what B's service ticket says.
#[test]
fn a_client_from_a_reaches_a_service_in_b_through_both_kdcs() {
    let cipher = OwnCipher;
    let a = start(A, realm_a());
    let b = start(B, realm_b());
    let now = now();

    let alice = Principal::parse(&format!("alice@{A}")).unwrap();

    // 1. To A: an ordinary login, which gives a TGT for A.
    let as_reply = ask(&a.addr(), &as_req(&alice, PASSWORD.as_bytes(), now));
    let alice_key = cipher
        .s2k(
            Enctype::Aes256Sha1,
            PASSWORD.as_bytes(),
            &alice.default_salt(),
            None,
        )
        .unwrap();
    let as_part =
        msg::EncKdcRepPart::decode(&open_rep(&as_reply, 11, &alice_key, usage::AS_REP_ENCPART))
            .expect("an EncASRepPart");
    let tgt_a = ticket_of(&as_reply, 11);

    // 2. To A: a ticket addressed to B. This is A's half of the trust.
    let towards_b = Principal {
        name_type: rrl_kdc::name::NT_SRV_INST,
        components: vec!["krbtgt".to_owned(), B.to_owned()],
        realm: A.to_owned(),
    };
    let cross_reply = ask(
        &a.addr(),
        &tgs_req(
            A,
            &tgt_a.encode(),
            &as_part.session_key,
            &towards_b,
            &alice,
            now,
            kdc_options::FORWARDABLE,
        ),
    );
    let cross_part = msg::EncKdcRepPart::decode(&open_rep(
        &cross_reply,
        13,
        &as_part.session_key,
        usage::TGS_REP_ENCPART_SESSKEY,
    ))
    .expect("an EncTGSRepPart");
    let cross_ticket = ticket_of(&cross_reply, 13);
    assert_eq!(
        cross_ticket.realm, A,
        "A issues it: the realm field names the issuer, which is how B picks the key"
    );
    assert_eq!(cross_ticket.sname, towards_b, "addressed to B");

    // 3. To B: the service ticket, presenting what A issued.
    let (service_principal, service_key) = service_in_b(&cipher);
    let service_reply = ask(
        &b.addr(),
        &tgs_req(
            B,
            &cross_ticket.encode(),
            &cross_part.session_key,
            &service_principal,
            &alice,
            now,
            kdc_options::FORWARDABLE,
        ),
    );
    let service_part = msg::EncKdcRepPart::decode(&open_rep(
        &service_reply,
        13,
        &cross_part.session_key,
        usage::TGS_REP_ENCPART_SESSKEY,
    ))
    .expect("an EncTGSRepPart");

    assert_eq!(service_part.sname, service_principal);
    assert_eq!(service_part.srealm, B);

    // The ticket B issued, opened with B's service key — a key that exists nowhere in A.
    let service_ticket = ticket_of(&service_reply, 13);
    let plain = OwnCipher
        .decrypt(
            &service_key,
            usage::KDC_REP_TICKET,
            &service_ticket.enc.cipher,
        )
        .expect("the service ticket must open under the service's own key");
    let part = EncTicketPart::decode(&plain).expect("an EncTicketPart");

    assert_eq!(
        part.cname, alice,
        "the ticket names the client from the other realm"
    );
    assert_eq!(part.crealm, A, "and keeps her realm, which is not B's");
    assert_eq!(
        part.transited_type, 0,
        "a direct A to B hop has no transit realm"
    );
    assert!(part.transited.is_empty(), "so the path is empty");
    assert!(
        part.flags & tkt_flags::FORWARDABLE != 0,
        "forwardable was asked for, and a cross-realm ticket is where it matters most"
    );

    a.stop();
    b.stop();
}

/// The negative that makes the positive mean something: without the mirror entry in B, the same
/// three exchanges fail at step 3 — the trust is a key, not a name.
#[test]
fn without_the_mirror_entry_b_refuses_the_ticket_a_issued() {
    let cipher = OwnCipher;
    let a = start(A, realm_a());

    // B without `krbtgt/A@B`.
    let db = MemoryHdb::new();
    let mut krbtgt = HdbEntry::krbtgt(B);
    krbtgt
        .add_password_key(&cipher, Enctype::Aes256Sha1, b"master key of B", 1)
        .unwrap();
    db.insert(krbtgt).unwrap();
    let (principal, key) = service_in_b(&cipher);
    let mut svc = HdbEntry::service(principal);
    svc.add_key(key, 1, None);
    db.insert(svc).unwrap();
    let b = start(B, db);

    let now = now();
    let alice = Principal::parse(&format!("alice@{A}")).unwrap();
    let as_reply = ask(&a.addr(), &as_req(&alice, PASSWORD.as_bytes(), now));
    let alice_key = cipher
        .s2k(
            Enctype::Aes256Sha1,
            PASSWORD.as_bytes(),
            &alice.default_salt(),
            None,
        )
        .unwrap();
    let as_part =
        msg::EncKdcRepPart::decode(&open_rep(&as_reply, 11, &alice_key, usage::AS_REP_ENCPART))
            .unwrap();
    let tgt_a = ticket_of(&as_reply, 11);

    let towards_b = Principal {
        name_type: rrl_kdc::name::NT_SRV_INST,
        components: vec!["krbtgt".to_owned(), B.to_owned()],
        realm: A.to_owned(),
    };
    let cross_reply = ask(
        &a.addr(),
        &tgs_req(
            A,
            &tgt_a.encode(),
            &as_part.session_key,
            &towards_b,
            &alice,
            now,
            kdc_options::FORWARDABLE,
        ),
    );
    let cross_part = msg::EncKdcRepPart::decode(&open_rep(
        &cross_reply,
        13,
        &as_part.session_key,
        usage::TGS_REP_ENCPART_SESSKEY,
    ))
    .unwrap();
    let cross_ticket = ticket_of(&cross_reply, 13);

    let service_reply = ask(
        &b.addr(),
        &tgs_req(
            B,
            &cross_ticket.encode(),
            &cross_part.session_key,
            &service_in_b(&cipher).0,
            &alice,
            now,
            0,
        ),
    );

    let err = msg::KrbError::decode(&service_reply)
        .expect("B must refuse, and a refusal is a KRB-ERROR, not silence");
    // The property is that B produces a refusal rather than a service ticket: without the
    // shared entry there is no key to open the cross-realm ticket with, and a ticket that cannot
    // be decrypted must not be answered. Which code it answers with is B's choice; that it
    // answers with an error is the contract.
    assert!(
        err.code != 0,
        "a refusal must carry a code, got {:?} with {:?}",
        err.code,
        err.e_text
    );

    a.stop();
    b.stop();
}
