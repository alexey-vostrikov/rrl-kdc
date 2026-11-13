//! The order of `METHOD-DATA`: a mechanism must not come after the password.
//!
//! A KDC that announces SPAKE and lists it after `PA-ENC-TIMESTAMP` has a mechanism no client will
//! use. MIT's `kinit` walks the list and takes the first type its modules can answer, which was
//! measured against this KDC: with `PA-ENC-TIMESTAMP` first it produced an encrypted timestamp,
//! never ran its SPAKE module, and the login **succeeded** — so every test that checks only "the
//! login worked" agreed with a defect that removed exactly the property SPAKE exists for.
//!
//! The order is pinned here because it is invisible in every other test: the reply is valid either
//! way, the exchange completes either way, and only a client that honours the KDC's preference
//! shows the difference.

#![cfg(feature = "spake")]

mod common;

use std::sync::Arc;

use common::{NOW, REALM};
use rrl_kdc::crypto::{Cipher, Enctype, OwnCipher};
use rrl_kdc::der;
use rrl_kdc::hdb::{Hdb, HdbEntry, MemoryHdb};
use rrl_kdc::kdc::spake::Spake;
use rrl_kdc::kdc::{Kdc, KdcConfig};
use rrl_kdc::msg;
use rrl_kdc::name::Principal;

const PA_SPAKE: i32 = 151;

fn realm() -> Arc<dyn Hdb> {
    let cipher = OwnCipher;
    let db = MemoryHdb::new();
    let mut krbtgt = HdbEntry::krbtgt(REALM);
    krbtgt
        .add_password_key(&cipher, Enctype::Aes256Sha1, b"master", 1)
        .unwrap();
    db.insert(krbtgt).unwrap();
    let mut alice = HdbEntry::user(Principal::parse(&format!("alice@{REALM}")).unwrap());
    alice
        .add_password_key(&cipher, Enctype::Aes256Sha1, b"pw", 1)
        .unwrap();
    db.insert(alice).unwrap();
    Arc::new(db)
}

fn kdc() -> Kdc {
    let cipher = OwnCipher;
    let cookie = cipher
        .s2k(Enctype::Aes256Sha1, b"cookie-secret", b"cookie", None)
        .unwrap();
    Kdc::new(KdcConfig::new(REALM).unwrap(), realm(), Arc::new(cipher))
        .with_cookie_key(cookie)
        .with_mechanism(Arc::new(Spake::new()))
}

/// A bare `AS-REQ` for `alice`, so the KDC answers with `PREAUTH_REQUIRED` and its `METHOD-DATA`.
fn as_req() -> Vec<u8> {
    let body = der::seq(&[
        der::field(0, der::flags32(0)),
        der::field(
            1,
            Principal::parse(&format!("alice@{REALM}"))
                .unwrap()
                .encode_name(),
        ),
        der::field(2, der::general_string(REALM)),
        der::field(3, Principal::krbtgt(REALM).encode_name()),
        der::field(5, der::time(NOW + 3600)),
        der::field(7, der::int(0x1111)),
        der::field(8, der::seq(&[der::int(18)])),
    ]);
    der::cons(
        der::app(10),
        &[der::seq(&[
            der::field(1, der::int(5)),
            der::field(2, der::int(10)),
            der::field(4, body),
        ])],
    )
}

/// The `METHOD-DATA` types of the refusal, in the order the KDC wrote them.
fn method_types(reply: &[u8]) -> Vec<i32> {
    let err = msg::KrbError::decode(reply).expect("a KRB-ERROR");
    err.method_data()
        .expect("METHOD-DATA")
        .into_iter()
        .map(|(t, _)| t)
        .collect()
}

/// `PA-ENC-TIMESTAMP` is the last thing offered, not the first.
#[test]
fn the_password_method_comes_after_the_mechanisms() {
    let types = method_types(&kdc().handle_from(&as_req(), NOW, None));
    let spake = types
        .iter()
        .position(|t| *t == PA_SPAKE)
        .unwrap_or_else(|| panic!("SPAKE is not offered at all: {types:?}"));
    let timestamp = types
        .iter()
        .position(|t| *t == msg::PA_ENC_TIMESTAMP)
        .expect("the password method is still offered");
    assert!(
        spake < timestamp,
        "SPAKE at {spake}, PA-ENC-TIMESTAMP at {timestamp} in {types:?}: a client that takes the \
         first type it can answer takes the password, and the offline oracle SPAKE removes stays"
    );
}

/// FAST's challenge stays ahead of the mechanisms: an armored client must find it, and MIT's own
/// KDC lists it first as well.
#[test]
fn the_armored_challenge_is_offered_before_the_mechanisms() {
    let types = method_types(&kdc().handle_from(&as_req(), NOW, None));
    let challenge = types
        .iter()
        .position(|t| *t == rrl_kdc::kdc::fast::PA_ENCRYPTED_CHALLENGE)
        .unwrap_or_else(|| panic!("PA-ENCRYPTED-CHALLENGE is missing: {types:?}"));
    let spake = types.iter().position(|t| *t == PA_SPAKE).expect("SPAKE");
    assert!(challenge < spake, "{types:?}");
}

/// A realm with no mechanisms still offers the password method — the reordering must not have
/// removed it, and a realm that configured nothing must stay usable.
#[test]
fn a_realm_without_mechanisms_still_offers_the_password() {
    let kdc = Kdc::new(KdcConfig::new(REALM).unwrap(), realm(), Arc::new(OwnCipher));
    let types = method_types(&kdc.handle_from(&as_req(), NOW, None));
    assert!(
        types.contains(&msg::PA_ENC_TIMESTAMP),
        "the only method such a realm has: {types:?}"
    );
    assert!(types.contains(&msg::PA_ETYPE_INFO2), "{types:?}");
    assert!(
        !types.contains(&PA_SPAKE),
        "and it does not advertise what it does not have: {types:?}"
    );
}
