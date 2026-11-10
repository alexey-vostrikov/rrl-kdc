//! OTP accepted by the third-party client, over a socket.
//!
//! The client is `krb5` 1.0 with `login_with_otp` and a FAST armor TGT — the `kinit -T armor`
//! flow, where the armor is a ticket the user already holds and the one-time value goes inside
//! it. RFC 6560 §3.2 puts the challenge in `enc-fast-rep`, so a KDC that offers OTP to an
//! unarmored request is offering something it cannot complete; `tests/otp.rs` pins that at the
//! mechanism, and this file pins the exchange that works.

#![cfg(feature = "otp")]

use std::sync::Arc;

use rust_kdc::crypto::{Cipher, Enctype, OwnCipher};
use rust_kdc::hdb::{HdbEntry, MemoryHdb};
use rust_kdc::kdc::otp::{Otp, Verifier};
use rust_kdc::kdc::{Kdc, KdcConfig};
use rust_kdc::name::Principal;
use rust_kdc::transport::RunningKdc;

const REALM: &str = "EXAMPLE.COM";
const PASSWORD: &str = "correct horse battery staple";
const OTP: &str = "942617";

/// A verifier that knows exactly one value, which is what a test needs and what a RADIUS
/// server is in production: the KDC has no token store of its own.
struct Fixed;

impl Verifier for Fixed {
    fn verify(&self, _client: &Principal, value: &str) -> rust_kdc::Result<bool> {
        Ok(value == OTP)
    }
}

fn realm() -> Arc<dyn rust_kdc::hdb::Hdb> {
    let cipher = OwnCipher;
    let db = MemoryHdb::new();

    let mut krbtgt = HdbEntry::krbtgt(REALM);
    for e in [Enctype::Aes256Sha1, Enctype::Aes128Sha1] {
        krbtgt
            .add_password_key(&cipher, e, b"master-key-of-the-realm", 1)
            .unwrap();
    }
    db.insert(krbtgt).unwrap();

    for (name, password) in [("alice", PASSWORD), ("armor", PASSWORD)] {
        let mut entry = HdbEntry::user(Principal::parse(&format!("{name}@{REALM}")).unwrap());
        for e in [Enctype::Aes256Sha1, Enctype::Aes128Sha1] {
            entry
                .add_password_key(&cipher, e, password.as_bytes(), 1)
                .unwrap();
        }
        db.insert(entry).unwrap();
    }
    Arc::new(db)
}

fn start() -> RunningKdc {
    let cipher = OwnCipher;
    let key = cipher
        .s2k(Enctype::Aes256Sha1, b"cookie-secret", b"cookie", None)
        .unwrap();
    let kdc = Kdc::new(KdcConfig::new(REALM).unwrap(), realm(), Arc::new(cipher))
        .with_cookie_key(key)
        .with_mechanism(Arc::new(Otp::new(Arc::new(Fixed))));
    rust_kdc::transport::serve_loopback(kdc)
}

/// A TGT to armor with: a ticket the user holds before the OTP login, obtained the ordinary way.
fn armor(stand: &RunningKdc) -> krb5::Credentials {
    let client = krb5::KdcClient::new(REALM, [stand.addr().as_str()]);
    let armor = krb5::Principal::parse(&format!("armor@{REALM}")).unwrap();
    client
        .login_with_password(&armor, PASSWORD)
        .unwrap_or_else(|e| panic!("the armor login failed, so OTP cannot be tested: {e}"))
}

#[test]
fn a_client_logs_in_with_a_one_time_password() {
    let stand = start();
    let client =
        krb5::KdcClient::new(REALM, [stand.addr().as_str()]).with_fast_armor(armor(&stand));
    let alice = krb5::Principal::parse(&format!("alice@{REALM}")).unwrap();
    let creds = client
        .login_with_otp(&alice, OTP)
        .unwrap_or_else(|e| panic!("OTP login failed: {e}"));

    assert_eq!(creds.client.to_string(), format!("alice@{REALM}"));
    assert_eq!(creds.server.to_string(), format!("krbtgt/{REALM}@{REALM}"));
    assert_ne!(
        creds.flags & rust_kdc::msg::tkt_flags::PRE_AUTHENT,
        0,
        "an OTP login is pre-authentication: flags were {:#010x}",
        creds.flags
    );
}

#[test]
fn a_wrong_one_time_value_is_refused() {
    // The property the mechanism exists for. The client derives the reply key from the armor, so
    // it would happily read a reply sealed that way; what must not happen is that a reply is
    // produced at all when the value is wrong.
    let stand = start();
    let client =
        krb5::KdcClient::new(REALM, [stand.addr().as_str()]).with_fast_armor(armor(&stand));
    let alice = krb5::Principal::parse(&format!("alice@{REALM}")).unwrap();
    let err = client
        .login_with_otp(&alice, "000000")
        .expect_err("a wrong one-time value must not produce a ticket");

    let text = format!("{err}");
    assert!(
        text.contains("KDC_ERR_PREAUTH_FAILED"),
        "the refusal is a pre-authentication failure: {text}"
    );
    assert!(
        text.contains("one-time value"),
        "and it names the token check rather than something else: {text}"
    );
}

#[test]
fn the_armor_is_required_and_its_absence_is_not_a_silent_fallback() {
    // RFC 6560 §3.2 carries the challenge inside the armor. A client that asks for OTP without
    // one must be told, rather than falling back to a password login — a fallback would let an
    // attacker who can strip the armor downgrade the login to something weaker.
    let stand = start();
    let client = krb5::KdcClient::new(REALM, [stand.addr().as_str()]);
    let alice = krb5::Principal::parse(&format!("alice@{REALM}")).unwrap();
    let err = client
        .login_with_otp(&alice, OTP)
        .expect_err("OTP without armor cannot be completed");
    let text = format!("{err}");
    assert!(
        text.to_lowercase().contains("armor"),
        "the client is told the armor is what is missing: {text}"
    );
}
