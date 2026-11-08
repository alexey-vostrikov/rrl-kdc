//! The acceptance test: a real Kerberos client gets a TGT from this KDC.
//!
//! The client is `krb5` — a third-party implementation, written by someone
//! else and tested against a live MIT KDC. That is the point: a KDC which
//! agrees only with itself agrees with nothing, and a self-round-trip is not
//! evidence of a wire format.
//!
//! What the client does here is what `kinit alice` does: AS-REQ without
//! pre-authentication, `PREAUTH_REQUIRED` with `ETYPE-INFO2` in answer,
//! `PA-ENC-TIMESTAMP`, `AS-REP`. Every step is a check the KDC has to pass,
//! because the client will not accept a reply that MIT's client would not.

use std::sync::Arc;

use rust_heimdal_kdc::crypto::{Enctype, OwnCipher};
use rust_heimdal_kdc::hdb::{Hdb, HdbEntry, MemoryHdb};
use rust_heimdal_kdc::kdc::KdcConfig;
use rust_heimdal_kdc::msg::tkt_flags;
use rust_heimdal_kdc::name::Principal;
use rust_heimdal_kdc::transport::RunningKdc;

const REALM: &str = "EXAMPLE.COM";
const PASSWORD: &str = "correct horse battery staple";

/// A realm with `krbtgt/REALM` and one user, both keyed with `PASSWORD`.
fn realm() -> Arc<dyn Hdb> {
    let cipher = OwnCipher;
    let db = MemoryHdb::new();

    let mut krbtgt = HdbEntry::krbtgt(REALM);
    krbtgt
        .add_password_key(&cipher, Enctype::Aes256Sha1, b"master-key-of-the-realm", 1)
        .unwrap();
    krbtgt
        .add_password_key(&cipher, Enctype::Aes128Sha1, b"master-key-of-the-realm", 1)
        .unwrap();
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

/// The KDC on a loopback port, answering until the test ends.
fn start() -> RunningKdc {
    let cipher = OwnCipher;
    let config = KdcConfig::new(REALM).unwrap();
    let kdc = rust_heimdal_kdc::kdc::Kdc::new(config, realm(), Arc::new(cipher));
    rust_heimdal_kdc::transport::serve_loopback(kdc)
}

#[test]
fn a_client_gets_a_tgt_with_a_password() {
    let stand = start();
    let client = krb5::KdcClient::new(REALM, [stand.addr().as_str()]);
    let alice = krb5::Principal::parse(&format!("alice@{REALM}")).unwrap();
    let creds = client
        .login_with_password(&alice, PASSWORD)
        .unwrap_or_else(|e| panic!("kinit failed against this KDC: {e}"));

    assert_eq!(
        creds.server.to_string(),
        format!("krbtgt/{REALM}@{REALM}"),
        "the ticket must be for krbtgt, which is what makes it a TGT"
    );
    assert_eq!(creds.client.to_string(), format!("alice@{REALM}"));
    assert_ne!(
        creds.flags & tkt_flags::INITIAL,
        0,
        "an AS-REP grants an initial ticket; flags were {:#010x}",
        creds.flags
    );
    assert_ne!(
        creds.flags & tkt_flags::PRE_AUTHENT,
        0,
        "the client authenticated, so the ticket must say so; flags were {:#010x}",
        creds.flags
    );
    assert!(
        creds.endtime > creds.authtime,
        "the ticket must have a positive lifetime: authtime {}, endtime {}",
        creds.authtime,
        creds.endtime
    );
    assert!(
        creds.renew_till.is_none_or(|t| t >= creds.endtime),
        "a renewable ticket cannot expire before it ends"
    );
    assert_eq!(
        creds.session_key.enctype(),
        18,
        "the strongest enctype both sides have must win"
    );
}

#[test]
fn the_same_client_gets_the_same_ticket_twice() {
    // A KDC that produces a different principal, realm or key type on a second
    // identical request is a KDC whose reply depends on something it was not
    // asked about.
    let stand = start();
    let client = krb5::KdcClient::new(REALM, [stand.addr().as_str()]);
    let alice = krb5::Principal::parse(&format!("alice@{REALM}")).unwrap();
    let a = client.login_with_password(&alice, PASSWORD).unwrap();
    let b = client.login_with_password(&alice, PASSWORD).unwrap();
    assert_eq!(a.server, b.server);
    assert_eq!(a.flags, b.flags);
    assert_ne!(
        a.session_key.bytes(),
        b.session_key.bytes(),
        "two tickets must not share a session key"
    );
}
