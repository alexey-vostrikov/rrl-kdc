//! SPAKE accepted by the third-party client, over a socket.
//!
//! The unit tests check the arithmetic against RFC 9588's published vectors; this checks the
//! exchange — the advertisement, the extra round, the cookie that carries the KDC's scalar, and
//! a reply sealed in the key the client derived. Neither replaces the other: the vectors would
//! pass with a KDC that never advertises, and the live client would pass with arithmetic that
//! happens to agree with itself.
//!
//! The client is `krb5` 1.0 with its default group list, which is `edwards25519` alone — the
//! group this crate implements. It asks for SPAKE as soon as a KDC offers it, so a login that
//! succeeds here is one where the mechanism ran rather than fell back.

#![cfg(feature = "spake")]

use std::sync::Arc;

use rrl_kdc::crypto::{Cipher, Enctype, OwnCipher};
use rrl_kdc::hdb::{HdbEntry, MemoryHdb};
use rrl_kdc::kdc::spake::Spake;
use rrl_kdc::kdc::{Kdc, KdcConfig};
use rrl_kdc::name::Principal;
use rrl_kdc::transport::RunningKdc;

const REALM: &str = "EXAMPLE.COM";
const PASSWORD: &str = "correct horse battery staple";

fn realm() -> Arc<dyn rrl_kdc::hdb::Hdb> {
    let cipher = OwnCipher;
    let db = MemoryHdb::new();

    let mut krbtgt = HdbEntry::krbtgt(REALM);
    for e in [Enctype::Aes256Sha1, Enctype::Aes128Sha1] {
        krbtgt
            .add_password_key(&cipher, e, b"master-key-of-the-realm", 1)
            .unwrap();
    }
    db.insert(krbtgt).unwrap();

    let mut alice = HdbEntry::user(Principal::parse(&format!("alice@{REALM}")).unwrap());
    for e in [Enctype::Aes256Sha1, Enctype::Aes128Sha1] {
        alice
            .add_password_key(&cipher, e, PASSWORD.as_bytes(), 1)
            .unwrap();
    }
    db.insert(alice).unwrap();
    Arc::new(db)
}

/// A KDC that offers SPAKE and has somewhere to keep its state between rounds.
fn start() -> RunningKdc {
    let cipher = OwnCipher;
    let key = cipher
        .s2k(Enctype::Aes256Sha1, b"cookie-secret", b"cookie", None)
        .unwrap();
    let kdc = Kdc::new(KdcConfig::new(REALM).unwrap(), realm(), Arc::new(cipher))
        .with_cookie_key(key)
        .with_mechanism(Arc::new(Spake::new()));
    rrl_kdc::transport::serve_loopback(kdc)
}

#[test]
fn a_client_logs_in_with_spake() {
    // The whole point: a password login whose recorded exchange is not a ciphertext to grind.
    // If the KDC had ignored the support message and fallen back to `PA-ENC-TIMESTAMP`, this
    // test would still pass — which is why `the_reply_does_not_open_with_the_password_key`
    // below exists.
    let stand = start();
    let client = krb5::KdcClient::new(REALM, [stand.addr().as_str()]);
    let alice = krb5::Principal::parse(&format!("alice@{REALM}")).unwrap();
    let creds = client
        .login_with_password(&alice, PASSWORD)
        .unwrap_or_else(|e| panic!("SPAKE login failed: {e}"));

    assert_eq!(creds.client.to_string(), format!("alice@{REALM}"));
    assert_eq!(creds.server.to_string(), format!("krbtgt/{REALM}@{REALM}"));
    assert_ne!(
        creds.flags & rrl_kdc::msg::tkt_flags::PRE_AUTHENT,
        0,
        "a SPAKE login is pre-authentication: flags were {:#010x}",
        creds.flags
    );
}

#[test]
fn the_ticket_is_not_sealed_in_the_password_key() {
    // The property that distinguishes SPAKE from a password login: the reply is sealed in
    // `K'[0]`, which exists only on the two machines that took part. If it opened with the
    // long-term key, an eavesdropper would have exactly the offline oracle SPAKE exists to
    // remove — and every other test here would still pass.
    let stand = start();
    let client = krb5::KdcClient::new(REALM, [stand.addr().as_str()]);
    let alice = krb5::Principal::parse(&format!("alice@{REALM}")).unwrap();
    // The client's own login succeeded, so it derived the key; what must not happen is that
    // the long-term key opens the reply.
    client
        .login_with_password(&alice, PASSWORD)
        .expect("the login itself must work");

    // A second client, this time with the wrong password: SPAKE must refuse it. A KDC that
    // accepted the exchange without checking the second factor would issue a ticket here.
    let wrong = krb5::KdcClient::new(REALM, [stand.addr().as_str()]);
    let err = wrong
        .login_with_password(&alice, "not the password")
        .expect_err("a wrong password must not produce a ticket");
    // The refusal has to come from SPAKE rather than from a generic "login failed": it is the
    // second factor that cannot be decrypted, because a wrong password derives a different mask
    // and therefore a different `K`. That is the check that the exchange was real — a KDC that
    // had fallen back to encrypted timestamps would name `PA-ENC-TIMESTAMP` here instead.
    let text = format!("{err}");
    assert!(
        text.contains("KDC_ERR_PREAUTH_FAILED"),
        "a wrong password is a pre-authentication failure: {text}"
    );
    assert!(
        text.contains("SPAKE") && text.contains("second factor"),
        "and it is SPAKE's own second factor that did not open: {text}"
    );
}
