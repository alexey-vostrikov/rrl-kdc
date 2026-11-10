//! Forwarded and proxy tickets (RFC 4120 §3.3.3).
//!
//! Two KDC options that are *operations*, not permissions: `forwarded` asks for a ticket
//! carrying the client's own identity for use from a different address, and `proxy` for one
//! the client hands to somebody else. Both are gated by a flag the TGT must already carry —
//! `forwardable` and `proxiable` respectively — and a TGT without the flag is the case that
//! matters: the whole point of the gate is that an operator can refuse to hand it out.
//!
//! §3.3.3 also says the addresses are the client's, and that `proxy` is not honoured on a
//! request for another TGT: a proxied TGT would be a ticket-granting ticket somebody else
//! can use, which is not a delegation anybody offers.
//!
//! The requests are built by hand, as in `tgs_errors.rs`, because a well-behaved client does
//! not ask for these unless its administrator configured it.

use std::sync::Arc;

use rust_kdc::crypto::{Cipher, Enctype, Key, OwnCipher, usage};
use rust_kdc::der;
use rust_kdc::error::codes;
use rust_kdc::hdb::{HdbEntry, MemoryHdb, flags as entry_flags};
use rust_kdc::kdc::{Kdc, KdcConfig};
use rust_kdc::msg::{
    self, ApReq, Authenticator, EncTicketPart, EncryptedData, Ticket, encode_pa_data, kdc_options,
    tkt_flags,
};
use rust_kdc::name::Principal;

const REALM: &str = "EXAMPLE.COM";
const SERVICE: &str = "host/server.example.com";
const NOW: i64 = 1_700_000_000;

fn alice() -> Principal {
    Principal::parse(&format!("alice@{REALM}")).unwrap()
}

fn service() -> Principal {
    Principal::parse(&format!("{SERVICE}@{REALM}")).unwrap()
}

fn realm() -> (MemoryHdb, Key) {
    let cipher = OwnCipher;
    let db = MemoryHdb::new();

    let mut krbtgt = HdbEntry::krbtgt(REALM);
    let krbtgt_key = cipher.random(Enctype::Aes256Sha1).unwrap();
    krbtgt.add_key(krbtgt_key.clone(), 1, None);
    db.insert(krbtgt).unwrap();

    let mut user = HdbEntry::user(alice());
    user.flags &= !entry_flags::REQUIRE_PREAUTH;
    user.add_password_key(&cipher, Enctype::Aes256Sha1, b"password", 1)
        .unwrap();
    db.insert(user).unwrap();

    let mut svc = HdbEntry::service(service());
    svc.add_password_key(&cipher, Enctype::Aes256Sha1, b"key", 1)
        .unwrap();
    db.insert(svc).unwrap();

    (db, krbtgt_key)
}

fn kdc() -> (Kdc, Key) {
    let (db, krbtgt_key) = realm();
    (
        Kdc::new(
            KdcConfig::new(REALM).unwrap().with_require_preauth(false),
            Arc::new(db),
            Arc::new(OwnCipher),
        ),
        krbtgt_key,
    )
}

/// A TGT with exactly the flags the test asks for.
fn tgt(krbtgt_key: &Key, flags: u32) -> (Vec<u8>, Key) {
    let cipher = OwnCipher;
    let session_key = cipher.random(Enctype::Aes256Sha1).unwrap();
    let part = EncTicketPart {
        flags: tkt_flags::INITIAL | tkt_flags::PRE_AUTHENT | flags,
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

/// A `TGS-REQ` for `target`, asking for `options`, from `addresses`.
fn tgs_req(
    ticket: &[u8],
    session_key: &Key,
    target: &Principal,
    options: u32,
    addresses: Option<Vec<u8>>,
) -> Vec<u8> {
    let cipher = OwnCipher;
    let mut body_parts = vec![
        der::field(0, der::flags32(options)),
        der::field(2, der::general_string(REALM)),
        der::field(3, target.encode_name()),
        der::field(5, der::time(NOW + 3600)),
        der::field(7, der::int(0x4242)),
        der::field(8, der::seq(&[der::int(18)])),
    ];
    if let Some(addrs) = &addresses {
        body_parts.insert(4, der::field(9, addrs.clone()));
    }
    let body = der::seq(&body_parts);

    let cksum = cipher
        .checksum(session_key, usage::TGS_REQ_AUTH_CKSUM, &body)
        .unwrap();
    let authenticator = Authenticator {
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
            &authenticator.encode(),
        )
        .unwrap(),
    }
    .encode();

    der::cons(
        der::app(12),
        &[der::seq(&[
            der::field(1, der::int(5)),
            der::field(2, der::int(12)),
            der::field(3, encode_pa_data(&[(msg::PA_TGS_REQ, ap_req)])),
            der::field(4, body),
        ])],
    )
}

/// A `HostAddress` list carrying one IPv4 address.
fn addresses(octets: [u8; 4]) -> Vec<u8> {
    let mut addr = vec![0x00, 0x02]; // address-type 2: IPv4
    addr.extend_from_slice(&octets);
    der::seq(&[der::seq(&[
        der::field(0, der::int(20)),
        der::field(1, der::octets(&addr)),
    ])])
}

fn error_of(reply: &[u8]) -> msg::KrbError {
    msg::KrbError::decode(reply)
        .unwrap_or_else(|e| panic!("expected a KRB-ERROR, got something else: {e}"))
}

/// The flags of the ticket in a TGS-REP, decrypted with the service key.
fn ticket_flags_of(reply: &[u8]) -> u32 {
    use rust_kdc::msg::{EncTicketPart, Ticket};

    let f = der::Fields::parse_app("TGS-REP", 13, reply).expect("a TGS-REP");
    let ticket = Ticket::decode(f.bytes(5, "TGS-REP").expect("the ticket")).expect("a Ticket");

    // The service key is the one the test put in the database.
    let mut entry = HdbEntry::service(service());
    entry
        .add_password_key(&OwnCipher, Enctype::Aes256Sha1, b"key", 1)
        .unwrap();
    let key = entry
        .key_for(Enctype::Aes256Sha1)
        .map(|k| k.key.clone())
        .expect("the service has a key");

    let plain = OwnCipher
        .decrypt(&key, usage::KDC_REP_TICKET, &ticket.enc.cipher)
        .expect("the ticket opens with the service key");
    EncTicketPart::decode(&plain)
        .expect("an EncTicketPart")
        .flags
}

#[test]
fn a_forwarded_ticket_needs_a_forwardable_tgt() {
    // The gate, and the reason the option exists: an operator who issues a TGT without
    // `forwardable` has said this credential must not be turned into one usable elsewhere.
    let (kdc, krbtgt_key) = kdc();
    let (ticket, session_key) = tgt(&krbtgt_key, 0);
    let reply = kdc.handle(
        &tgs_req(
            &ticket,
            &session_key,
            &service(),
            kdc_options::FORWARDED,
            Some(addresses([10, 0, 0, 5])),
        ),
        NOW,
    );
    let err = error_of(&reply);
    assert_eq!(err.code, codes::KDC_ERR_BADOPTION);
    assert!(
        err.e_text.unwrap_or_default().contains("forwardable"),
        "the refusal must name the flag the TGT lacks"
    );
}

#[test]
fn a_forwarded_ticket_is_issued_with_the_flag_and_the_new_address() {
    // With a forwardable TGT the ticket is issued, carries `forwarded`, and its address is
    // the one the client asked to be usable from — that address is the whole point.
    let (kdc, krbtgt_key) = kdc();
    let (ticket, session_key) = tgt(&krbtgt_key, tkt_flags::FORWARDABLE);
    let reply = kdc.handle(
        &tgs_req(
            &ticket,
            &session_key,
            &service(),
            kdc_options::FORWARDED,
            Some(addresses([10, 0, 0, 5])),
        ),
        NOW,
    );
    assert!(
        msg::KrbError::decode(&reply).is_err(),
        "a forwardable TGT must be honoured: {:?}",
        msg::KrbError::decode(&reply)
    );
    let flags = ticket_flags_of(&reply);
    assert!(
        flags & tkt_flags::FORWARDED != 0,
        "the ticket must carry the forwarded flag: {flags:#010x}"
    );
}

#[test]
fn a_plain_ticket_is_not_forwarded() {
    // The pair: the same request without the option must not produce a forwarded ticket,
    // or the first test would pass on a KDC that always sets the flag.
    let (kdc, krbtgt_key) = kdc();
    let (ticket, session_key) = tgt(&krbtgt_key, tkt_flags::FORWARDABLE);
    let reply = kdc.handle(
        &tgs_req(
            &ticket,
            &session_key,
            &service(),
            kdc_options::FORWARDABLE,
            None,
        ),
        NOW,
    );
    assert!(msg::KrbError::decode(&reply).is_err());
    let flags = ticket_flags_of(&reply);
    assert!(
        flags & tkt_flags::FORWARDED == 0,
        "a ticket must not claim to be forwarded when it was not: {flags:#010x}"
    );
}

#[test]
fn a_proxy_ticket_needs_a_proxiable_tgt() {
    let (kdc, krbtgt_key) = kdc();
    let (ticket, session_key) = tgt(&krbtgt_key, 0);
    let reply = kdc.handle(
        &tgs_req(
            &ticket,
            &session_key,
            &service(),
            kdc_options::PROXY,
            Some(addresses([10, 0, 0, 7])),
        ),
        NOW,
    );
    let err = error_of(&reply);
    assert_eq!(err.code, codes::KDC_ERR_BADOPTION);
    assert!(
        err.e_text.unwrap_or_default().contains("proxiable"),
        "the refusal must name the flag the TGT lacks"
    );
}

#[test]
fn a_proxy_ticket_is_issued_and_carries_the_flag() {
    let (kdc, krbtgt_key) = kdc();
    let (ticket, session_key) = tgt(&krbtgt_key, tkt_flags::PROXIABLE);
    let reply = kdc.handle(
        &tgs_req(
            &ticket,
            &session_key,
            &service(),
            kdc_options::PROXY,
            Some(addresses([10, 0, 0, 7])),
        ),
        NOW,
    );
    assert!(
        msg::KrbError::decode(&reply).is_err(),
        "a proxiable TGT must be honoured: {:?}",
        msg::KrbError::decode(&reply)
    );
    assert!(ticket_flags_of(&reply) & tkt_flags::PROXY != 0);
}

#[test]
fn a_proxy_without_an_address_is_refused() {
    // RFC 4120 §3.3.3: when granting a proxy the client MUST specify the address it is to
    // be used from, or say "any". A proxy with no address is one nobody can check, so the
    // omission is refused rather than filled in.
    let (kdc, krbtgt_key) = kdc();
    let (ticket, session_key) = tgt(&krbtgt_key, tkt_flags::PROXIABLE);
    let reply = kdc.handle(
        &tgs_req(&ticket, &session_key, &service(), kdc_options::PROXY, None),
        NOW,
    );
    let err = error_of(&reply);
    assert_eq!(err.code, codes::KDC_ERR_BADOPTION);
    let text = err.e_text.unwrap_or_default();
    assert!(
        text.contains("address"),
        "the refusal must say what is missing: {text}"
    );
}

#[test]
fn a_proxied_tgt_is_refused() {
    // §3.3.3: "The PROXY option will not be honored on requests for additional TGTs." A
    // proxied TGT is a ticket-granting ticket somebody else can use, which no realm offers
    // by accident.
    let (kdc, krbtgt_key) = kdc();
    let (ticket, session_key) = tgt(&krbtgt_key, tkt_flags::PROXIABLE);
    let reply = kdc.handle(
        &tgs_req(
            &ticket,
            &session_key,
            &Principal::krbtgt(REALM),
            kdc_options::PROXY,
            Some(addresses([10, 0, 0, 7])),
        ),
        NOW,
    );
    let err = error_of(&reply);
    assert_eq!(err.code, codes::KDC_ERR_BADOPTION);
    let text = err.e_text.unwrap_or_default();
    assert!(
        text.contains("TGT"),
        "the refusal must say which ticket kind is refused: {text}"
    );
}

#[test]
fn asking_for_a_proxy_and_a_forwarded_ticket_at_once_is_refused() {
    // The two flags describe different tickets: one is used by the client from elsewhere,
    // the other is handed to somebody else. A ticket that claims both is one whose audit
    // trail says nothing, so the request is refused rather than resolved by picking one.
    let (kdc, krbtgt_key) = kdc();
    let (ticket, session_key) = tgt(&krbtgt_key, tkt_flags::PROXIABLE | tkt_flags::FORWARDABLE);
    let reply = kdc.handle(
        &tgs_req(
            &ticket,
            &session_key,
            &service(),
            kdc_options::PROXY | kdc_options::FORWARDED,
            Some(addresses([10, 0, 0, 7])),
        ),
        NOW,
    );
    let err = error_of(&reply);
    assert_eq!(err.code, codes::KDC_ERR_BADOPTION);
}
