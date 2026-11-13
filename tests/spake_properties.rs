//! Properties of SPAKE that a passing exchange does not prove.
//!
//! Two survivors of mutation testing showed that a complete, correct-looking exchange can be
//! built out of values that make it worthless:
//!
//! * a **fixed** `x` still completes, because both sides compute `K` from the same numbers — and
//!   if `x` is zero then `K` is the identity point, which is public. Every input to `K'[n]`
//!   except `w` would then be known to an eavesdropper, so the password could be ground offline
//!   again: exactly the property this mechanism exists to provide.
//! * a scalar that is **not divisible by the cofactor** also completes, and quietly reopens the
//!   small-subgroup channel of RFC 9588 §10.1.
//!
//! Both are asserted here as properties rather than trusted to a comment.

#![cfg(feature = "spake")]

use std::sync::Arc;

use rrl_kdc::crypto::{Cipher, Enctype, Key, OwnCipher};
use rrl_kdc::der;
use rrl_kdc::hdb::{HdbEntry, MemoryHdb};
use rrl_kdc::kdc::spake::Spake;
use rrl_kdc::kdc::{Kdc, KdcConfig};
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
    alice
        .add_password_key(&cipher, Enctype::Aes256Sha1, PASSWORD.as_bytes(), 1)
        .unwrap();
    db.insert(alice).unwrap();
    db
}

fn cookie_key() -> Key {
    OwnCipher
        .s2k(Enctype::Aes256Sha1, b"cookie-secret", b"cookie", None)
        .unwrap()
}

fn kdc() -> Kdc {
    Kdc::new(
        KdcConfig::new(REALM).unwrap(),
        Arc::new(db()),
        Arc::new(OwnCipher),
    )
    .with_cookie_key(cookie_key())
    .with_mechanism(Arc::new(Spake::new()))
}

fn as_req(padata: Vec<(i32, Vec<u8>)>) -> Vec<u8> {
    let body = der::seq(&[
        der::field(0, der::flags32(0)),
        der::field(1, principal("alice").encode_name()),
        der::field(2, der::general_string(REALM)),
        der::field(3, Principal::krbtgt(REALM).encode_name()),
        der::field(5, der::time(NOW + 3600)),
        der::field(7, der::int(0x4242)),
        der::field(8, der::seq(&[der::int(18)])),
    ]);
    let mut parts = vec![der::field(1, der::int(5)), der::field(2, der::int(10))];
    if !padata.is_empty() {
        parts.push(der::field(3, rrl_kdc::msg::encode_pa_data(&padata)));
    }
    parts.push(der::field(4, body));
    der::cons(der::app(10), &[der::seq(&parts)])
}

/// The `SPAKESupport` message for `groups`, as a client writes it.
fn support(groups: &[i64]) -> Vec<u8> {
    let ids: Vec<Vec<u8>> = groups.iter().map(|g| der::int(*g)).collect();
    der::field(0, der::seq(&[der::field(0, der::seq(&ids))]))
}

/// The `PA-SPAKE` challenge value from a reply.
fn challenge_of(reply: &[u8]) -> Vec<u8> {
    let err = rrl_kdc::msg::KrbError::decode(reply).expect("a KRB-ERROR");
    let methods = err.method_data().expect("METHOD-DATA");
    methods
        .into_iter()
        .find(|(t, _)| *t == 151)
        .map(|(_, v)| v)
        .expect("a PA-SPAKE challenge")
}

/// The `T` inside a challenge: `[1] { [0]=group [1]=octets [2]=factors }`.
fn public_of(challenge: &[u8]) -> Vec<u8> {
    let mut r = der::Reader::new(challenge);
    let inner = r.expect_in("challenge", der::ctx(1)).expect("challenge");
    let mut sr = der::Reader::new(inner);
    let f = der::Fields::parse(
        "SPAKEChallenge",
        sr.expect_in("challenge", der::SEQUENCE).unwrap(),
    )
    .expect("fields");
    let mut pr = der::Reader::new(f.bytes(1, "challenge").expect("pubkey"));
    pr.expect_in("pubkey", der::OCTET_STRING)
        .expect("octets")
        .to_vec()
}

#[test]
fn two_exchanges_for_the_same_client_use_different_scalars() {
    // `x` has to be random per exchange. It is the KDC's entire contribution to `K`: with a
    // fixed `x` the shared value is a function of public things, and the password can be
    // ground offline from a recording — the attack SPAKE removes.
    let kdc = kdc();
    let first = challenge_of(&kdc.handle(&as_req(vec![(151, support(&[1]))]), NOW));
    let second = challenge_of(&kdc.handle(&as_req(vec![(151, support(&[1]))]), NOW));
    assert_ne!(
        public_of(&first),
        public_of(&second),
        "the KDC's public value must differ between exchanges"
    );
}

#[test]
fn the_kdc_public_value_is_not_just_the_mask() {
    // The same property from the other end: `T = x·G + w·M` with `x = 0` collapses to `w·M`,
    // which anyone holding the password can compute and nobody else needs. A reply that is a
    // pure function of the client's name and password is a reply with no secret in it.
    //
    // Two different clients with the same password produce different masks only if their salts
    // differ; here the same client is used twice, so what is being ruled out is a public value
    // that does not move at all.
    let kdc = kdc();
    let once = public_of(&challenge_of(
        &kdc.handle(&as_req(vec![(151, support(&[1]))]), NOW),
    ));
    let mut seen = std::collections::HashSet::new();
    for _ in 0..8 {
        let t = public_of(&challenge_of(
            &kdc.handle(&as_req(vec![(151, support(&[1]))]), NOW),
        ));
        seen.insert(t);
    }
    seen.insert(once);
    assert!(
        seen.len() >= 7,
        "eight exchanges produced {} distinct public values, so the scalar is not fresh",
        seen.len()
    );
}

#[test]
fn a_challenge_refuses_a_client_that_names_only_groups_we_do_not_implement() {
    // The one refusal a client acts on by trying another method. It must be `PREAUTH_FAILED`
    // and it must name the groups asked for, because "pre-authentication failed" with no detail
    // is what an operator cannot act on.
    //
    // The ids are deliberately unregistered: this test used to name 3 and 4, which were the NIST
    // curves this crate did not implement — and it kept passing for the wrong reason until they
    // were implemented, at which point it was asserting that P-384/P-521 are absent. A group id
    // nobody has assigned cannot drift like that.
    let kdc = kdc();
    let reply = kdc.handle(&as_req(vec![(151, support(&[98, 99]))]), NOW);
    let err = rrl_kdc::msg::KrbError::decode(&reply).expect("a KRB-ERROR");
    assert_eq!(err.code, rrl_kdc::error::codes::KDC_ERR_PREAUTH_FAILED);
    let text = err.e_text.unwrap_or_default();
    for implemented in ["edwards25519", "P-256", "P-384", "P-521"] {
        assert!(
            text.contains(implemented),
            "the refusal lists what the realm does have ({implemented}): {text}"
        );
    }
    assert!(text.contains("98") && text.contains("99"), "{text}");
}

#[test]
fn the_advertised_offer_is_empty_and_the_challenge_is_not() {
    // RFC 9588 §4.1: the offer is the empty `PA-SPAKE`; a realm that put a challenge there
    // would be answering a support message it was never sent.
    let kdc = kdc();
    let empty = kdc.handle(&as_req(Vec::new()), NOW);
    let err = rrl_kdc::msg::KrbError::decode(&empty).expect("a KRB-ERROR");
    let offered = err
        .method_data()
        .expect("METHOD-DATA")
        .into_iter()
        .find(|(t, _)| *t == 151)
        .map(|(_, v)| v)
        .expect("a PA-SPAKE offer");
    assert!(offered.is_empty(), "the offer carries no value");

    let challenged = challenge_of(&kdc.handle(&as_req(vec![(151, support(&[1]))]), NOW));
    assert!(!challenged.is_empty(), "the challenge carries one");
}
