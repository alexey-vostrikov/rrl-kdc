//! FAST in the TGS exchange, judged by the primary client.
//!
//! RFC 6113 §5.4.2.6 armors a TGS request **implicitly**: there is no `armor` field,
//! because the ticket already travelled in `PA-TGS-REQ` and its subkey is enough to derive
//! the armor key. The client here is `krb5` 1.0, which sends that form whenever a
//! `fast_armor` is configured — so a KDC that ignores `PA-FX-FAST` in a TGS request answers
//! in cleartext a client that asked for armor, and a KDC that gets the key derivation wrong
//! cannot read the request at all.
//!
//! Two things are checked here that no unit test can: that the client's own derivation
//! agrees with ours, and that the reply it accepts is the one we wrapped.

use std::sync::Arc;

use rust_kdc::crypto::{Enctype, OwnCipher};
use rust_kdc::hdb::{Hdb, HdbEntry, MemoryHdb};
use rust_kdc::kdc::{Kdc, KdcConfig};
use rust_kdc::name::Principal;
use rust_kdc::transport::{RunningKdc, serve_loopback};

const REALM: &str = "EXAMPLE.COM";
const PASSWORD: &str = "correct horse battery staple";
const SERVICE: &str = "host/server.example.com";

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

    let mut alice = HdbEntry::user(Principal::parse(&format!("alice@{REALM}")).unwrap());
    for e in [Enctype::Aes256Sha1, Enctype::Aes128Sha1] {
        alice
            .add_password_key(&cipher, e, PASSWORD.as_bytes(), 1)
            .unwrap();
    }
    db.insert(alice).unwrap();

    let mut service = HdbEntry::service(Principal::parse(&format!("{SERVICE}@{REALM}")).unwrap());
    for e in [Enctype::Aes256Sha1, Enctype::Aes128Sha1] {
        service
            .add_password_key(&cipher, e, b"the-service-key-which-nobody-knows", 1)
            .unwrap();
    }
    db.insert(service).unwrap();

    Arc::new(db)
}

fn start() -> RunningKdc {
    let kdc = Kdc::new(KdcConfig::new(REALM).unwrap(), realm(), Arc::new(OwnCipher));
    serve_loopback(kdc)
}

fn alice() -> krb5::Principal {
    krb5::Principal::parse(&format!("alice@{REALM}")).unwrap()
}

#[test]
fn a_client_gets_a_service_ticket_inside_the_armor() {
    let stand = start();
    let plain = krb5::KdcClient::new(REALM, [stand.addr().as_str()]);
    let tgt = plain
        .login_with_password(&alice(), PASSWORD)
        .unwrap_or_else(|e| panic!("kinit failed: {e}"));

    // With an armor configured, this client sends `PA-FX-FAST` in the TGS request and a
    // subkey in the authenticator — the implicit form. Nothing else about the call
    // changes, which is the point: armor is transparent to a client that has a TGT.
    let armored = krb5::KdcClient::new(REALM, [stand.addr().as_str()]).with_fast_armor(tgt.clone());
    let service = krb5::Principal::parse(&format!("{SERVICE}@{REALM}")).unwrap();
    let ticket = armored
        .service_ticket(&tgt, &service)
        .unwrap_or_else(|e| panic!("an armored TGS exchange was refused: {e}"));

    assert_eq!(
        ticket.server.to_string(),
        format!("{SERVICE}@{REALM}"),
        "the armored reply must still name the service that was asked for"
    );
    assert_eq!(
        ticket.client.to_string(),
        format!("alice@{REALM}"),
        "and the client the TGT proved"
    );
    assert!(
        ticket.endtime <= tgt.endtime,
        "a service ticket cannot outlive its TGT: {} > {}",
        ticket.endtime,
        tgt.endtime
    );
}

#[test]
fn the_armored_and_unarmored_paths_agree() {
    // The same request twice, once inside the armor and once without: if the armored path
    // had a different idea of the ticket — a different lifetime, a different service name —
    // this is where it would show. A single test that only ran the armored path could not
    // tell "the armor works" from "the armor quietly changed the answer".
    let stand = start();
    let plain = krb5::KdcClient::new(REALM, [stand.addr().as_str()]);
    let tgt = plain.login_with_password(&alice(), PASSWORD).unwrap();
    let service = krb5::Principal::parse(&format!("{SERVICE}@{REALM}")).unwrap();

    let unarmored = plain
        .service_ticket(&tgt, &service)
        .unwrap_or_else(|e| panic!("the plain TGS exchange failed: {e}"));
    let armored = krb5::KdcClient::new(REALM, [stand.addr().as_str()])
        .with_fast_armor(tgt.clone())
        .service_ticket(&tgt, &service)
        .unwrap_or_else(|e| panic!("the armored TGS exchange failed: {e}"));

    assert_eq!(armored.server, unarmored.server);
    assert_eq!(armored.client, unarmored.client);
    assert_eq!(
        armored.endtime - unarmored.endtime,
        0,
        "the armor must not change the ticket's lifetime"
    );
}
