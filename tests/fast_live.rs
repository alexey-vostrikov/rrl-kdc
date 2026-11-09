//! FAST accepted by a client that is not ours.
//!
//! `tests/fast_armor.rs` proves the property locally: the reply does not open with the
//! password key. This file proves the other half — that a third-party client which
//! implements FAST (the `krb5` crate, tested by its author against a live MIT KDC) can
//! armor a login against this KDC and get a ticket it accepts.
//!
//! Both halves are needed. The property without interop is a private dialect; interop
//! without the property is FAST in name only, because a client that stays connected to a
//! KDC whose reply opens with the password key has gained nothing.

use std::sync::Arc;

use rust_kdc::crypto::{Enctype, OwnCipher};
use rust_kdc::hdb::{Hdb, HdbEntry, MemoryHdb};
use rust_kdc::kdc::KdcConfig;
use rust_kdc::name::Principal;
use rust_kdc::transport::RunningKdc;

const REALM: &str = "EXAMPLE.COM";
const PASSWORD: &str = "correct horse battery staple";
/// The service a ticket is asked for, which is what Samba does right after its AS exchange.
const SERVICE: &str = "cifs/files.example.com";

fn realm() -> Arc<dyn Hdb> {
    let cipher = OwnCipher;
    let db = MemoryHdb::new();

    let mut krbtgt = HdbEntry::krbtgt(REALM);
    for e in [Enctype::Aes256Sha1, Enctype::Aes128Sha1] {
        krbtgt
            .add_password_key(&cipher, e, b"master-key-of-the-realm", 1)
            .unwrap();
    }
    db.insert(krbtgt).unwrap();

    let mut service = HdbEntry::service(Principal::parse(&format!("{SERVICE}@{REALM}")).unwrap());
    for e in [Enctype::Aes256Sha1, Enctype::Aes128Sha1] {
        service
            .add_password_key(&cipher, e, b"service-key", 1)
            .unwrap();
    }
    db.insert(service).unwrap();

    let mut alice = HdbEntry::user(Principal::parse(&format!("alice@{REALM}")).unwrap());
    for e in [Enctype::Aes256Sha1, Enctype::Aes128Sha1] {
        alice
            .add_password_key(&cipher, e, PASSWORD.as_bytes(), 1)
            .unwrap();
    }
    db.insert(alice).unwrap();

    Arc::new(db)
}

fn start() -> RunningKdc {
    let config = KdcConfig::new(REALM).unwrap();
    let kdc = rust_kdc::kdc::Kdc::new(config, realm(), Arc::new(OwnCipher));
    rust_kdc::transport::serve_loopback(kdc)
}

fn alice() -> krb5::Principal {
    krb5::Principal::parse(&format!("alice@{REALM}")).unwrap()
}

#[test]
fn a_third_party_client_gets_a_tgt_inside_fast() {
    let stand = start();
    let plain = krb5::KdcClient::new(REALM, [stand.addr().as_str()]);

    // The armor is a TGT obtained the ordinary way: RFC 6113 armors the *next* login
    // with a ticket the client already holds.
    let armor = plain
        .login_with_password(&alice(), PASSWORD)
        .unwrap_or_else(|e| panic!("the unarmored login failed, so FAST cannot be tested: {e}"));

    let armored = krb5::KdcClient::new(REALM, [stand.addr().as_str()]).with_fast_armor(armor);
    let creds = armored
        .login_with_password(&alice(), PASSWORD)
        .unwrap_or_else(|e| panic!("a FAST login was refused: {e}"));

    assert_eq!(
        creds.server.to_string(),
        format!("krbtgt/{REALM}@{REALM}"),
        "the armored login must still yield a TGT"
    );
    assert!(
        !creds.ticket.is_empty(),
        "the ticket must carry an encrypted part"
    );
}

#[test]
fn fast_does_not_turn_a_wrong_password_into_a_right_one() {
    // The armor proves possession of a TGT, not of the password: the `PA-ENC-TIMESTAMP`
    // inside it is still sealed in the key derived from the password and still has to
    // open.
    let stand = start();
    let plain = krb5::KdcClient::new(REALM, [stand.addr().as_str()]);
    let armor = plain.login_with_password(&alice(), PASSWORD).unwrap();

    let armored = krb5::KdcClient::new(REALM, [stand.addr().as_str()]).with_fast_armor(armor);
    assert!(
        armored
            .login_with_password(&alice(), "not the password")
            .is_err(),
        "a wrong password was accepted inside FAST"
    );
}

#[test]
fn an_armored_tgs_request_gets_an_armored_reply() {
    // RRL-2.21. After the AS exchange a service or a joining machine armors its *TGS* request
    // with the TGT it just received — the implicit armor of RFC 6113 §5.4.2.6, whose key comes
    // from the `PA-TGS-REQ` subkey. A reply that does not come back inside the armor makes a
    // third-party client report "FAST fast response is missing FX-FAST" and gives up, which is
    // what the ad-join stand saw.
    //
    // This is the half no unit test can prove: the request and the reply are built and read by
    // somebody else's code.
    let stand = start();
    let plain = krb5::KdcClient::new(REALM, [stand.addr().as_str()]);
    let tgt = plain
        .login_with_password(&alice(), PASSWORD)
        .unwrap_or_else(|e| panic!("the unarmored login failed: {e}"));

    let armored = krb5::KdcClient::new(REALM, [stand.addr().as_str()]).with_fast_armor(tgt.clone());
    let service = krb5::Principal::parse(&format!("{SERVICE}@{REALM}")).unwrap();
    let creds = armored
        .service_ticket(&tgt, &service)
        .unwrap_or_else(|e| panic!("an armored TGS request was refused: {e}"));

    assert_eq!(
        creds.server.to_string(),
        format!("{SERVICE}@{REALM}"),
        "the ticket must name the service that was asked for"
    );
    assert!(
        !creds.ticket.is_empty(),
        "and carry an encrypted part the service could open"
    );
}
