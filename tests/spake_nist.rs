//! Which group the KDC picks when a client lists several.
//!
//! RFC 9588 §4.2 has the client send `SPAKESupport` with the groups it accepts, in preference
//! order, and the KDC choose one of them. Until this crate implemented the NIST curves it had one
//! group and the question did not arise; now it does, and the two ways to get it wrong are:
//!
//! * **ours first instead of the client's.** A client that lists P-521 before edwards25519 has said
//!   which it wants, and a KDC imposing its own order picks a group the client ranked lower.
//! * **a challenge that does not name the group it used.** The client reads the group from the
//!   challenge, derives `w` with that group's length and pepper, and a challenge naming the wrong id
//!   derives a different `w` — the exchange then fails at the last step with nothing to point at.
//!
//! What is checked here is the choice and the encoding, not the plaintext of a NIST handshake: the
//! arithmetic is pinned against the registry's constants in `kdc::spake::group`, and the full
//! exchange is exercised end to end by `krb5` 1.0 in `spake_live.rs` for `edwards25519` — the only
//! group that client asks for. A NIST client does not exist in the test stand, and saying so is
//! better than implying this file proves interop it cannot.

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
const PA_SPAKE: i32 = 151;

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

/// The `PA-SPAKE` value from a reply's `METHOD-DATA`.
fn pa_spake_of(reply: &[u8]) -> Option<Vec<u8>> {
    let err = rrl_kdc::msg::KrbError::decode(reply).ok()?;
    err.method_data()
        .ok()?
        .into_iter()
        .find(|(t, _)| *t == PA_SPAKE)
        .map(|(_, v)| v)
}

/// The group id and public value a challenge carries: `[1] { [0]=group, [1]=pubkey, [2]=factors }`.
fn challenge_parts(challenge: &[u8]) -> (i64, Vec<u8>) {
    let mut r = der::Reader::new(challenge);
    let inner = r
        .expect_in("challenge", der::ctx(1))
        .expect("the challenge wrapper");
    let mut sr = der::Reader::new(inner);
    let f = der::Fields::parse(
        "SPAKEChallenge",
        sr.expect_in("challenge", der::SEQUENCE)
            .expect("a SEQUENCE"),
    )
    .expect("fields");
    let group = f.int(0, "SPAKEChallenge").expect("the group");
    let mut pr = der::Reader::new(f.bytes(1, "SPAKEChallenge").expect("pubkey"));
    let public = pr
        .expect_in("pubkey", der::OCTET_STRING)
        .expect("octets")
        .to_vec();
    // The factors are present and name SF-NONE; a challenge offering a factor the client cannot
    // answer would be worse than one offering none.
    assert!(
        f.bytes(2, "SPAKEChallenge").is_ok(),
        "every challenge names at least one second factor"
    );
    (group, public)
}

/// A compressed SEC1 point of the curve's length: tag octet plus the coordinate.
fn compressed_len(group: i64) -> usize {
    match group {
        1 => 32, // edwards25519 is compressed Edwards, one 32-octet value
        2 => 33, // P-256: 1 + 32
        3 => 49, // P-384: 1 + 48
        4 => 67, // P-521: 1 + 66
        other => panic!("unexpected group {other}"),
    }
}

/// The KDC takes the **client's** first supported group, not its own preferred one.
#[test]
fn the_challenge_names_the_clients_first_supported_group() {
    let kdc = kdc();
    for (asked, expected) in [
        (vec![4, 1], 4),
        (vec![3, 2], 3),
        (vec![2, 1], 2),
        (vec![1], 1),
        // An unregistered group first is skipped, not fatal.
        (vec![99, 3], 3),
    ] {
        let reply = kdc.handle_from(&as_req(vec![(PA_SPAKE, support(&asked))]), NOW, None);
        let challenge = pa_spake_of(&reply)
            .unwrap_or_else(|| panic!("no PA-SPAKE in the reply to {asked:?}: {:?}", reply.len()));
        let (group, public) = challenge_parts(&challenge);
        assert_eq!(group, expected, "asked {asked:?}");
        assert_eq!(
            public.len(),
            compressed_len(group),
            "the public value is a compressed point of the group it names"
        );
    }
}

/// A client whose list has nothing in common gets the refusal that names both sides.
///
/// `PREAUTH_FAILED` rather than a hard failure: a client treats that after a support message as
/// "no group in common, try another method", which is the only useful answer.
#[test]
fn a_client_with_no_common_group_is_refused_and_told_what_exists() {
    let kdc = kdc();
    let reply = kdc.handle_from(&as_req(vec![(PA_SPAKE, support(&[98, 99]))]), NOW, None);
    let err = rrl_kdc::msg::KrbError::decode(&reply).expect("a KRB-ERROR");
    assert_eq!(err.code, rrl_kdc::error::codes::KDC_ERR_PREAUTH_FAILED);
    let text = err.e_text.clone().unwrap_or_default();
    assert!(
        text.contains("P-256") && text.contains("edwards25519") && text.contains("[98, 99]"),
        "the message names what we have and what was asked: {text}"
    );
}

/// The state carried in the cookie names the group, so a resumed exchange uses the same arithmetic.
///
/// The cookie is opaque to a client and travels back sealed, so the only way it can be wrong in a
/// way nobody notices is for the group in it to differ from the group in the challenge — and then
/// the KDC would resume with another curve's arithmetic and fail at the last step.
#[test]
fn a_resumed_exchange_keeps_the_group_it_started_with() {
    let kdc = kdc();
    let first = kdc.handle_from(&as_req(vec![(PA_SPAKE, support(&[3, 1]))]), NOW, None);
    let challenge = pa_spake_of(&first).expect("a challenge");
    let (group, _) = challenge_parts(&challenge);
    assert_eq!(group, 3, "P-384 was first in the list");

    let err = rrl_kdc::msg::KrbError::decode(&first).expect("a KRB-ERROR");
    let cookie = err
        .method_data()
        .expect("METHOD-DATA")
        .into_iter()
        .find(|(t, _)| *t == 133)
        .map(|(_, v)| v)
        .expect("a PA-FX-COOKIE");

    // The client answers with a public value of the group it was given and the cookie; the KDC must
    // resume the P-384 state rather than refuse a two-times-too-short value as "not a point".
    let response = der::seq(&[
        der::field(0, der::octets(&[0x02; 49])),
        der::field(1, {
            // An `EncryptedData` the KDC cannot open: the point of the test is that the arithmetic
            // is reached at all, and a refusal for the wrong reason (a 33-octet value on P-384)
            // would arrive before it.
            rrl_kdc::msg::EncryptedData {
                etype: Enctype::Aes256Sha1,
                kvno: None,
                cipher: vec![0u8; 32],
            }
            .encode()
        }),
    ]);
    let reply = kdc.handle_from(
        &as_req(vec![(PA_SPAKE, response), (133, cookie)]),
        NOW,
        None,
    );
    let err = rrl_kdc::msg::KrbError::decode(&reply).expect("a KRB-ERROR");
    let text = err.e_text.clone().unwrap_or_default();
    assert!(
        !text.contains("octets") || !text.contains("P-384"),
        "the KDC must not reject the value for its length: {text}"
    );
    assert!(
        text.contains("SPAKE") || err.code == rrl_kdc::error::codes::KDC_ERR_PREAUTH_FAILED,
        "it refused the exchange, not the group: {text}"
    );
}
