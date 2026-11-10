//! `PA-FX-COOKIE`, RFC 6113 §5.4.2.3.
//!
//! The cookie is not armor and carries no key: it is **opaque KDC state** that a client it has
//! never met hands back on the next round. Its whole job is to let a multi-round
//! pre-authentication (SPAKE, OTP, anything that needs three messages) remember what happened
//! in the previous one without the KDC keeping a table of half-finished exchanges.
//!
//! Two properties hold it together, and both are tested here rather than asserted in prose:
//! a client cannot read or alter it, because it travels encrypted under a key the client never
//! sees; and the KDC cannot be made to continue somebody else's exchange, because the cookie
//! names the realm and the client it was issued to and is refused when either differs.
//!
//! # What this is not
//!
//! There is no third-party acceptance for this, and there cannot be one yet: the cookie only
//! exists to serve a multi-round mechanism, and this crate has none — SPAKE and OTP are
//! `RRL-3.24`. A client that has no second round to remember still gets a cookie in its
//! `PREAUTH_REQUIRED`, hands it back, and sees the KDC continue with the same state; that
//! round trip is the acceptance. Calling it interop would be dressing up a self-test.

use std::sync::Arc;

use rrl_kdc::crypto::usage;
use rrl_kdc::crypto::{Cipher, Enctype, Key, OwnCipher};
use rrl_kdc::der;
use rrl_kdc::error::codes;
use rrl_kdc::hdb::{HdbEntry, MemoryHdb};
use rrl_kdc::kdc::cookie::Cookie;
use rrl_kdc::kdc::{Kdc, KdcConfig};
use rrl_kdc::msg::{self, EncryptedData, encode_enc_ts_enc, encode_pa_data, kdc_options};
use rrl_kdc::name::Principal;

const REALM: &str = "EXAMPLE.COM";
const PASSWORD: &str = "correct horse battery staple";
const NOW: i64 = 1_700_000_000;

fn principal(name: &str) -> Principal {
    Principal::parse(&format!("{name}@{REALM}")).unwrap()
}

fn db() -> MemoryHdb {
    let cipher = OwnCipher;
    let db = MemoryHdb::new();

    let mut krbtgt = HdbEntry::krbtgt(REALM);
    krbtgt
        .add_password_key(&cipher, Enctype::Aes256Sha1, b"master", 1)
        .unwrap();
    db.insert(krbtgt).unwrap();

    let mut alice = HdbEntry::user(principal("alice"));
    for e in [Enctype::Aes256Sha1, Enctype::Aes128Sha1] {
        alice
            .add_password_key(&cipher, e, PASSWORD.as_bytes(), 1)
            .unwrap();
    }
    db.insert(alice).unwrap();

    let mut bob = HdbEntry::user(principal("bob"));
    bob.add_password_key(&cipher, Enctype::Aes256Sha1, b"bob", 1)
        .unwrap();
    db.insert(bob).unwrap();
    db
}

/// An AS-REQ, built the way a client builds one.
fn as_req(name: &str, realm: &str, etypes: &[i32], padata: Vec<(i32, Vec<u8>)>) -> Vec<u8> {
    let client = Principal::parse(&format!("{name}@{realm}")).unwrap();
    let body = der::seq(&[
        der::field(0, der::flags32(kdc_options::FORWARDABLE)),
        der::field(1, client.encode_name()),
        der::field(2, der::general_string(realm)),
        der::field(3, Principal::krbtgt(realm).encode_name()),
        der::field(5, der::time(NOW + 3600)),
        der::field(7, der::int(0x1234_5678)),
        der::field(
            8,
            der::seq(
                &etypes
                    .iter()
                    .map(|e| der::int(*e as i64))
                    .collect::<Vec<_>>(),
            ),
        ),
    ]);
    let mut parts = vec![der::field(1, der::int(5)), der::field(2, der::int(10))];
    if !padata.is_empty() {
        parts.push(der::field(3, encode_pa_data(&padata)));
    }
    parts.push(der::field(4, body));
    der::cons(der::app(10), &[der::seq(&parts)])
}

/// A `PA-ENC-TIMESTAMP` value for `password`, at `timestamp`.
fn enc_timestamp(password: &[u8], enctype: Enctype, timestamp: i64) -> Vec<u8> {
    let cipher = OwnCipher;
    let key = cipher
        .s2k(enctype, password, b"EXAMPLE.COMalice", None)
        .unwrap();
    let plain = encode_enc_ts_enc(timestamp, None);
    EncryptedData::seal(&cipher, &key, usage::AS_REQ_PA_ENC_TS, None, &plain)
        .unwrap()
        .encode()
}

/// `METHOD-DATA` from a reply, when it carries one.
fn method_data(reply: &[u8]) -> Option<Vec<(i32, Vec<u8>)>> {
    let err = msg::KrbError::decode(reply).expect("the reply is a KRB-ERROR");
    err.method_data().ok()
}

/// The realm's cookie key — the one secret a client never holds.
fn cookie_key() -> Key {
    let cipher = OwnCipher;
    cipher
        .s2k(Enctype::Aes256Sha1, b"cookie-secret", b"cookie", None)
        .unwrap()
}

fn kdc_with_cookie() -> Kdc {
    Kdc::new(
        KdcConfig::new(REALM).unwrap(),
        Arc::new(db()),
        Arc::new(OwnCipher),
    )
    .with_cookie_key(cookie_key())
}

fn kdc_without_cookie() -> Kdc {
    Kdc::new(
        KdcConfig::new(REALM).unwrap(),
        Arc::new(db()),
        Arc::new(OwnCipher),
    )
}

/// The cookie from a reply's `METHOD-DATA`, decoded with the realm's key.
fn cookie_of(reply: &[u8]) -> Cookie {
    let method = method_data(reply).expect("the reply offers pre-authentication");
    let value = method
        .iter()
        .find(|(t, _)| *t == rrl_kdc::kdc::fast::PA_FX_COOKIE)
        .map(|(_, v)| v.clone())
        .expect("a PA-FX-COOKIE among the offered methods");
    Cookie::decode(&OwnCipher, &cookie_key(), &value).expect("the realm's own cookie decodes")
}

#[test]
fn a_preauth_required_error_carries_a_cookie_that_names_the_client() {
    // RFC 6113 §5.4.2.3: the cookie travels in the error's METHOD-DATA. Without one a client
    // that cannot armor by ticket has no way to keep the exchange going.
    let reply = kdc_with_cookie().handle(&as_req("alice", REALM, &[18], vec![]), NOW);
    let (code, _) = (msg::KrbError::decode(&reply).unwrap().code, ());
    assert_eq!(code, codes::KDC_ERR_PREAUTH_REQUIRED);

    let cookie = cookie_of(&reply);
    assert_eq!(cookie.realm, REALM);
    assert_eq!(
        cookie.client.as_ref().map(|c| c.components.clone()),
        Some(vec!["alice".to_string()]),
        "the cookie says whose exchange it belongs to"
    );
    assert_eq!(cookie.issued, NOW);
    assert!(
        cookie.expiration > NOW,
        "a cookie that is already expired is not a cookie"
    );
}

#[test]
fn adding_a_cookie_does_not_displace_the_other_offers() {
    // The defect the third-party client found first: the cookie was appended to a METHOD-DATA
    // that had been decoded as empty, so the reply offered `PA-FX-COOKIE` and no enctypes — and
    // every client in the world fails on that with "no usable key", which says nothing about
    // what went wrong here. A cookie is an addition to the offer, never a replacement for it.
    let reply = kdc_with_cookie().handle(&as_req("alice", REALM, &[18], vec![]), NOW);
    let method = method_data(&reply).expect("the reply offers pre-authentication");
    assert!(
        method
            .iter()
            .any(|(t, _)| *t == msg::PA_ENC_TIMESTAMP || *t == msg::PA_ETYPE_INFO2),
        "the way to log in must survive the cookie: {:?}",
        method.iter().map(|(t, _)| *t).collect::<Vec<_>>()
    );
    assert!(
        method
            .iter()
            .any(|(t, _)| *t == rrl_kdc::kdc::fast::PA_FX_COOKIE),
        "and the cookie is there beside it"
    );
}

#[test]
fn a_client_that_does_not_hold_the_key_cannot_read_the_cookie() {
    // The property that makes the cookie safe to hand to an unauthenticated client: it is an
    // EncryptedData under a realm secret. If the client's name appeared in the clear, the
    // cookie would leak who is trying to log in to anyone on the path.
    let reply = kdc_with_cookie().handle(&as_req("alice", REALM, &[18], vec![]), NOW);
    let method = method_data(&reply).unwrap();
    let raw = method
        .iter()
        .find(|(t, _)| *t == rrl_kdc::kdc::fast::PA_FX_COOKIE)
        .map(|(_, v)| v.clone())
        .unwrap();

    let haystack = String::from_utf8_lossy(&raw);
    assert!(
        !haystack.contains("alice") && !haystack.contains(REALM),
        "the cookie must not carry the client's name in the clear"
    );

    // And a key that is not the realm's produces nothing usable.
    let wrong = OwnCipher
        .s2k(
            Enctype::Aes256Sha1,
            b"not-the-cookie-secret",
            b"cookie",
            None,
        )
        .unwrap();
    assert!(
        Cookie::decode(&OwnCipher, &wrong, &raw).is_err(),
        "a client-invented key must not open a realm cookie"
    );
}

#[test]
fn the_state_a_cookie_carries_survives_into_the_next_round() {
    // This is what the cookie is *for*: a multi-round mechanism writes its state here and reads
    // it back a round later. The KDC adds nothing of its own, so what comes out of the second
    // cookie is what went into the first — which is exactly the property SPAKE will rely on.
    let kdc = kdc_with_cookie();
    let first = cookie_of(&kdc.handle(&as_req("alice", REALM, &[18], vec![]), NOW));

    let mut carried = first.clone();
    carried.state = b"round-one-state".to_vec();
    let value = carried.encode(&OwnCipher, &cookie_key()).unwrap();
    // A second round: the client already sent a timestamp and failed, so the error is
    // PREAUTH_FAILED — the cookie has to come back on that one too, or a client cannot retry.
    let reply = kdc.handle(
        &as_req(
            "alice",
            REALM,
            &[18],
            vec![
                (rrl_kdc::kdc::fast::PA_FX_COOKIE, value),
                (
                    msg::PA_ENC_TIMESTAMP,
                    enc_timestamp(b"wrong password", Enctype::Aes256Sha1, NOW),
                ),
            ],
        ),
        NOW,
    );
    let code = msg::KrbError::decode(&reply).unwrap().code;
    assert_eq!(code, codes::KDC_ERR_PREAUTH_FAILED);

    let second = cookie_of(&reply);
    assert_eq!(
        second.state, b"round-one-state",
        "the state a client carried must come back, or a multi-round mechanism restarts forever"
    );
}

#[test]
fn a_cookie_issued_to_one_client_is_not_honoured_for_another() {
    // Without this, one client's half-finished exchange could be picked up by another — and in
    // a multi-round mechanism that means one account finishing another's authentication.
    let kdc = kdc_with_cookie();
    let mut stolen = cookie_of(&kdc.handle(&as_req("alice", REALM, &[18], vec![]), NOW));
    stolen.state = b"alice-was-here".to_vec();
    let value = stolen.encode(&OwnCipher, &cookie_key()).unwrap();

    let reply = kdc.handle(
        &as_req(
            "bob",
            REALM,
            &[18],
            vec![(rrl_kdc::kdc::fast::PA_FX_COOKIE, value)],
        ),
        NOW,
    );
    let carried = cookie_of(&reply);
    assert!(
        carried.state.is_empty(),
        "a cookie naming alice must not seed bob's exchange: {:?}",
        carried.state
    );
    assert_eq!(
        carried.client.as_ref().map(|c| c.components.clone()),
        Some(vec!["bob".to_string()])
    );
}

#[test]
fn an_expired_cookie_is_ignored_rather_than_honoured() {
    // A cookie is state, and stale state is worse than no state: a mechanism that resumed from
    // an expired round would accept a proof computed for a challenge nobody remembers issuing.
    let kdc = kdc_with_cookie();
    let mut old = cookie_of(&kdc.handle(&as_req("alice", REALM, &[18], vec![]), NOW));
    old.issued = NOW - 4000;
    old.expiration = NOW - 3000;
    old.state = b"stale".to_vec();
    let value = old.encode(&OwnCipher, &cookie_key()).unwrap();

    let reply = kdc.handle(
        &as_req(
            "alice",
            REALM,
            &[18],
            vec![(rrl_kdc::kdc::fast::PA_FX_COOKIE, value)],
        ),
        NOW,
    );
    assert!(
        cookie_of(&reply).state.is_empty(),
        "an expired cookie must be dropped, not continued"
    );
}

#[test]
fn a_cookie_from_another_realm_is_ignored() {
    // Two realms on one host share a client population but not their state. A cookie from the
    // other realm is not a proof of anything here.
    let kdc = kdc_with_cookie();
    let mut foreign = cookie_of(&kdc.handle(&as_req("alice", REALM, &[18], vec![]), NOW));
    foreign.realm = "OTHER.EXAMPLE".into();
    foreign.state = b"other-realm".to_vec();
    let value = foreign.encode(&OwnCipher, &cookie_key()).unwrap();

    let reply = kdc.handle(
        &as_req(
            "alice",
            REALM,
            &[18],
            vec![(rrl_kdc::kdc::fast::PA_FX_COOKIE, value)],
        ),
        NOW,
    );
    assert!(cookie_of(&reply).state.is_empty());
}

#[test]
fn an_altered_cookie_is_ignored_and_the_exchange_continues() {
    // A cookie that cannot be opened is not an error to report to the client — an attacker
    // could then use it to make the KDC refuse a legitimate login. It is ignored, and the
    // exchange starts again.
    let kdc = kdc_with_cookie();
    let mut raw = cookie_of(&kdc.handle(&as_req("alice", REALM, &[18], vec![]), NOW))
        .encode(&OwnCipher, &cookie_key())
        .unwrap();
    let last = raw.len() - 1;
    raw[last] ^= 0xff;

    let reply = kdc.handle(
        &as_req(
            "alice",
            REALM,
            &[18],
            vec![(rrl_kdc::kdc::fast::PA_FX_COOKIE, raw)],
        ),
        NOW,
    );
    assert_eq!(
        msg::KrbError::decode(&reply).unwrap().code,
        codes::KDC_ERR_PREAUTH_REQUIRED,
        "the exchange restarts rather than failing"
    );
    assert!(cookie_of(&reply).state.is_empty());
}

#[test]
fn a_realm_without_a_cookie_key_offers_no_cookie() {
    // The feature is opt-in because it needs a realm secret that nothing else uses. A realm
    // that has not configured one must not advertise a mechanism it cannot honour.
    let reply = kdc_without_cookie().handle(&as_req("alice", REALM, &[18], vec![]), NOW);
    let method = method_data(&reply).unwrap();
    assert!(
        !method
            .iter()
            .any(|(t, _)| *t == rrl_kdc::kdc::fast::PA_FX_COOKIE),
        "no key, no cookie: {method:?}"
    );
}

#[test]
fn the_debug_view_says_whether_the_cookie_is_offered() {
    // `Debug` on `Kdc` is what an operator reads when the answer is not what was expected, and
    // "is the cookie on" is the first thing to check when a multi-round client gets nowhere. A
    // `Debug` that printed the same thing either way would be worse than none: it would look
    // like an answer.
    let on = format!("{:?}", kdc_with_cookie());
    assert!(on.contains("cookie: true"), "{on}");
    let off = format!("{:?}", kdc_without_cookie());
    assert!(off.contains("cookie: false"), "{off}");
}
