//! The CVE regressions MIT keeps in `src/tests`, ported to this engine.
//!
//! Three of the five are a KDC that dereferences a pointer it never initialised: `t_cve-2013-1416`
//! (a service name with an empty component), `t_cve-2013-1417` (a service name with one component and
//! no instance), `t_cve-2021-36222` (`PA-ENCRYPTED-CHALLENGE` with an empty value and no armor). Two
//! are malformed packets that sent a 1.10 KDC through an uninitialised pointer, `t_cve-2012-1014` and
//! `t_cve-2012-1015`.
//!
//! None of those is a memory-safety bug in Rust, and pretending otherwise would be a test that cannot
//! fail. What transfers is the property each one was really about: **a request a client controls
//! reaches the deepest path it can and comes back as a `KRB-ERROR`** — never as an unwind, never as
//! silence. In a KDC an unwind is a denial of service: one malformed packet from anybody who can
//! reach port 88, and the realm stops issuing tickets.
//!
//! The shapes are rebuilt here rather than replayed as bytes, with one exception: `t_cve-2012-1014`
//! and `-1015` carry captured packets, and those are replayed with the realm replaced — `KRBTEST.COM`
//! and `EXAMPLE.COM` are both eleven octets, so the substitution shifts nothing.

use std::sync::Arc;

use rrl_kdc::crypto::{Cipher, Enctype, Key, OwnCipher, usage};
use rrl_kdc::der;
use rrl_kdc::error::codes;
use rrl_kdc::hdb::{HdbEntry, MemoryHdb};
use rrl_kdc::kdc::{Kdc, KdcConfig};
use rrl_kdc::msg::{
    self, ApReq, Authenticator, EncKdcRepPart, EncTicketPart, EncryptedData, Ticket,
    encode_pa_data, kdc_options, tkt_flags,
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

/// `PA-ENCRYPTED-CHALLENGE`, RFC 6113 §5.4.1: the type whose handling CVE-2021-36222 broke.
const PA_ENCRYPTED_CHALLENGE: i32 = 138;
/// `AS-REQ`, `AS-REP`, `TGS-REQ` and `TGS-REP`, as both the message types and the application tags
/// (RFC 4120 §7.2 — the numbers are the same, which is why one constant serves both).
const AS_REQ: u8 = 10;
const TGS_REQ: u8 = 12;
const TGS_REP: u8 = 13;

fn realm() -> (MemoryHdb, Key) {
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
        .add_password_key(
            &cipher,
            Enctype::Aes256Sha1,
            b"correct horse battery staple",
            1,
        )
        .unwrap();
    db.insert(alice_entry).unwrap();

    let mut service_entry = HdbEntry::service(service());
    service_entry
        .add_password_key(&cipher, Enctype::Aes256Sha1, b"svc", 1)
        .unwrap();
    db.insert(service_entry).unwrap();
    (db, krbtgt_key)
}

/// An engine and the `krbtgt` key of the database it answers from.
///
/// Both from the same `realm()`: a ticket sealed with another store's key is one this KDC cannot
/// open, which would make every case below fail for a reason that has nothing to do with the CVE.
fn engine() -> (Kdc, Key) {
    let (db, key) = realm();
    (
        Kdc::new(
            KdcConfig::new(REALM).unwrap(),
            Arc::new(db),
            Arc::new(OwnCipher),
        ),
        key,
    )
}

/// A TGT, built the way the AS exchange would have issued it.
fn tgt(krbtgt_key: &Key) -> (Vec<u8>, Key) {
    let cipher = OwnCipher;
    let session_key = cipher.random(Enctype::Aes256Sha1).unwrap();
    let part = EncTicketPart {
        flags: tkt_flags::INITIAL | tkt_flags::PRE_AUTHENT,
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
        authorization_data: None,
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

/// A `TGS-REQ` for `target`, presenting `ticket`.
fn tgs_req(ticket: &[u8], session_key: &Key, target: &Principal) -> Vec<u8> {
    let cipher = OwnCipher;
    let body = der::seq(&[
        der::field(0, der::flags32(kdc_options::FORWARDABLE)),
        der::field(2, der::general_string(REALM)),
        der::field(3, target.encode_name()),
        der::field(5, der::time(NOW + 3600)),
        der::field(7, der::int(0x4242)),
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
    let parts = [
        der::field(1, der::int(5)),
        der::field(2, der::int(i64::from(TGS_REQ))),
        der::field(3, encode_pa_data(&[(msg::PA_TGS_REQ, ap_req.encode())])),
        der::field(4, body),
    ];
    der::cons(der::app(TGS_REQ), &[der::seq(&parts)])
}

/// An `AS-REQ` carrying exactly `padata` and no `PA-FX-FAST`.
fn as_req(padata: &[(i32, Vec<u8>)]) -> Vec<u8> {
    let body = der::seq(&[
        der::field(0, der::flags32(kdc_options::FORWARDABLE)),
        der::field(1, alice().encode_name()),
        der::field(2, der::general_string(REALM)),
        der::field(3, Principal::krbtgt(REALM).encode_name()),
        der::field(5, der::time(NOW + 3600)),
        der::field(7, der::int(0x1234_5678)),
        der::field(8, der::seq(&[der::int(18), der::int(17)])),
    ]);
    let mut parts = vec![
        der::field(1, der::int(5)),
        der::field(2, der::int(i64::from(AS_REQ))),
    ];
    parts.push(der::field(3, encode_pa_data(padata)));
    parts.push(der::field(4, body));
    der::cons(der::app(AS_REQ), &[der::seq(&parts)])
}

/// The code of the reply, which must be a `KRB-ERROR` and not an answer.
fn code_of(reply: &[u8]) -> i32 {
    match msg::KrbError::decode(reply) {
        Ok(err) => err.code,
        Err(err) => panic!("expected a KRB-ERROR; the engine answered something else: {err}"),
    }
}

/// After a malformed packet, the engine still answers a correct one.
///
/// This is the half of every MIT test in this family that says the most: their scripts call `kinit`
/// again at the end, because the bug was a crash and a crash takes the whole KDC with it. Here the
/// same statement is made directly — a good request still gets a ticket.
fn still_serving(kdc: &Kdc, krbtgt_key: &Key) {
    let (ticket, session_key) = tgt(krbtgt_key);
    let reply = kdc.handle(&tgs_req(&ticket, &session_key, &service()), NOW);
    assert!(
        msg::KrbError::decode(&reply).is_err(),
        "the engine stopped answering valid requests after a malformed one: {:02x?}",
        msg::KrbError::decode(&reply)
    );
    let f = der::Fields::parse_app("TGS-REP", TGS_REP, &reply)
        .expect("a TGS-REP for a request that must succeed");
    let mut r = der::Reader::new(f.bytes(6, "TGS-REP").unwrap());
    let content = r.expect_in("enc-part", der::SEQUENCE).unwrap();
    let enc = EncryptedData::decode_content("enc-part", content).unwrap();
    let plain = OwnCipher
        .decrypt(&session_key, usage::TGS_REP_ENCPART_SESSKEY, &enc.cipher)
        .expect("the reply decrypts in the TGT's session key");
    EncKdcRepPart::decode(&plain).expect("the encrypted part is an EncTGSRepPart");
}

/// CVE-2021-36222: `PA-ENCRYPTED-CHALLENGE` with an empty value and no FAST armor.
///
/// The bug was that the MIT KDC followed the pre-authentication type into a path that only exists
/// inside FAST, and dereferenced the armor it had never been given. This engine refuses earlier, and
/// the refusal is what the test holds: a challenge cannot be answered without the armor, because its
/// key is derived from one.
#[test]
fn an_empty_pa_encrypted_challenge_without_armor_is_refused() {
    let (kdc, key) = engine();
    let reply = kdc.handle(&as_req(&[(PA_ENCRYPTED_CHALLENGE, Vec::new())]), NOW);
    assert_eq!(
        code_of(&reply),
        codes::KDC_ERR_PREAUTH_FAILED,
        "a challenge the KDC cannot verify is a failed pre-authentication"
    );
    still_serving(&kdc, &key);
}

/// The same packet with a value that is not `EncryptedData` at all.
#[test]
fn a_challenge_that_is_not_encrypted_data_is_refused() {
    let (kdc, key) = engine();
    let reply = kdc.handle(&as_req(&[(PA_ENCRYPTED_CHALLENGE, vec![0xde, 0xad])]), NOW);
    assert_eq!(code_of(&reply), codes::KDC_ERR_PREAUTH_FAILED);
    still_serving(&kdc, &key);
}

/// CVE-2013-1416: a service name with an empty component — `kvno /test`, `test/`, `/`.
///
/// MIT's KDC split the name and walked the components without checking that there was one; the crash
/// came from the empty one. Here the name is decoded as a principal whose component is the empty
/// string, no such service exists, and the answer says so.
#[test]
fn a_service_name_with_an_empty_component_is_refused() {
    let (kdc, key) = engine();
    let (ticket, session_key) = tgt(&key);

    for components in [
        vec![String::new()],
        vec!["test".to_string(), String::new()],
        vec![String::new(), "test".to_string()],
        vec![String::new(), String::new()],
    ] {
        let target = Principal {
            name_type: 1,
            components: components.clone(),
            realm: REALM.to_string(),
        };
        let reply = kdc.handle(&tgs_req(&ticket, &session_key, &target), NOW);
        assert_eq!(
            code_of(&reply),
            codes::KDC_ERR_S_PRINCIPAL_UNKNOWN,
            "a name with an empty component ({components:?}) names no service here"
        );
    }
    still_serving(&kdc, &key);
}

/// CVE-2013-1417: a service name with one component and no instance — `kvno -S host example.com`.
///
/// A one-component service name is legal in the protocol and this realm has no such principal, so the
/// answer is the same one an unknown two-part name gets.
#[test]
fn a_service_name_with_one_component_is_refused() {
    let (kdc, key) = engine();
    let (ticket, session_key) = tgt(&key);
    let target = Principal {
        name_type: 1,
        components: vec!["host".to_string()],
        realm: REALM.to_string(),
    };
    let reply = kdc.handle(&tgs_req(&ticket, &session_key, &target), NOW);
    assert_eq!(code_of(&reply), codes::KDC_ERR_S_PRINCIPAL_UNKNOWN);
    still_serving(&kdc, &key);
}

/// CVE-2012-1014 and CVE-2012-1015: the packets MIT captured, replayed.
///
/// These were uninitialised-pointer bugs in a C encoder, so what they can prove here is narrower than
/// what they prove there — but not nothing: they are AS-REQs whose `PA-DATA` list is one octet away
/// from valid in every position, which is exactly the input a decoder on port 88 must survive.
///
/// The realm octets are replaced (`KRBTEST.COM` → `EXAMPLE.COM`, both eleven octets) so the packets
/// get past the realm check and into the handlers rather than being refused at the door — which would
/// make the test green for the wrong reason.
#[test]
fn the_captured_malformed_requests_are_refused_and_the_kdc_keeps_serving() {
    let (kdc, key) = engine();

    // `t_cve-2012-1014`: the first request with one octet spliced in at every position.
    let x1 = hex("6A5E305BA103020105A2030201");
    let x2 = hex(concat!(
        "A44F304DA007030500FEDCBA90A10E30",
        "0CA003020101A10530031B0141A2031B",
        "0141A30E300CA003020101A10530031B",
        "0141A511180F31393934303631303036",
        "303331375AA70302012AA80530030201",
        "01"
    ));

    // `t_cve-2012-1015`: a checksum that cannot be made, at every position in its last field.
    let y1 = hex(concat!(
        "6A81A030819DA103020105A20302010A",
        "A30E300C300AA10402020095A2020400",
        "A48180307EA00703050000000000A120",
        "301EA003020101A11730151B066B7262",
        "7467741B0B4B5242544553542E434F4D",
        "A20D1B0B4B5242544553542E434F4D",
        "A320301EA003020101A11730151B066B72",
        "627467741B0B4B5242544553542E434F",
        "4DA511180F3139393430363130303630",
        "3331375AA7030201"
    ));
    let y2 = hex("A8083006020106020112");

    let mut refused = 0;
    for octet in 0_u8..=255 {
        for request in [
            to_our_realm([x1.clone(), vec![octet], x2.clone()].concat()),
            to_our_realm([y1.clone(), vec![octet], y2.clone()].concat()),
        ] {
            // Every one of these must produce a reply, and a reply that decodes: a `KRB-ERROR` is
            // the contract, and anything else is an answer to a request that was not understood.
            let reply = kdc.handle(&request, NOW);
            let code = code_of(&reply);
            // Not `KDC_ERR_WRONG_REALM`: that would mean the realm swap missed and the packet was
            // turned away at the door, which is a green test proving nothing about the handlers.
            assert_ne!(
                code,
                codes::KDC_ERR_WRONG_REALM,
                "octet {octet:#04x}: the packet never reached a handler"
            );
            refused += 1;
        }
    }
    assert_eq!(refused, 512, "both packets, every spliced octet");
    still_serving(&kdc, &key);
}

/// A request that is nothing but a tag, truncated at every length.
///
/// The same property as above, from the other end: MIT's two crash bugs were both "the request was
/// shorter than the parser assumed". Walking every prefix of a valid request covers every such
/// assumption at once, and it is cheap enough to keep in the plain test run.
#[test]
fn every_prefix_of_a_request_is_refused_without_taking_the_kdc_down() {
    let (kdc, key) = engine();
    let (ticket, session_key) = tgt(&key);
    let valid = tgs_req(&ticket, &session_key, &service());
    for len in 0..valid.len() {
        let reply = kdc.handle(&valid[..len], NOW);
        msg::KrbError::decode(&reply).unwrap_or_else(|err| {
            panic!(
                "a request cut to {len} of {} octets was not answered: {err}",
                valid.len()
            )
        });
    }
    still_serving(&kdc, &key);
}

/// The captured packets with their realm swapped for this one.
///
/// `KRBTEST.COM` and `EXAMPLE.COM` are both eleven octets, so the substitution changes no length and
/// no offset. Without it the packets fail the realm check at the door, and a test that proves the
/// door works while claiming to test the handlers is worse than no test.
fn to_our_realm(packet: Vec<u8>) -> Vec<u8> {
    let from = b"KRBTEST.COM";
    let to = REALM.as_bytes();
    assert_eq!(from.len(), to.len(), "the swap must not shift anything");
    let mut out = packet;
    let mut at = 0;
    while let Some(found) = out[at..]
        .windows(from.len())
        .position(|window| window == from)
    {
        let start = at + found;
        out[start..start + to.len()].copy_from_slice(to);
        at = start + to.len();
    }
    out
}

fn hex(text: &str) -> Vec<u8> {
    let text: Vec<u8> = text.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    text.chunks(2)
        .map(|pair| {
            let digit = |b: u8| (b as char).to_digit(16).expect("hex digits") as u8;
            digit(pair[0]) << 4 | digit(pair[1])
        })
        .collect()
}
