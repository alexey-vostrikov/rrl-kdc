//! A KDC whose principals live in a file.
//!
//! The unit tests prove the backend stores and fetches what it was given. This
//! proves the *engine* works on top of it: a TGT issued from a database, the
//! process forgotten, a new one opened from the same file, and a second TGT
//! issued — which is the only thing "persistence" can mean for a KDC.
#![cfg(feature = "hdb-redb")]

use std::sync::Arc;

use rust_heimdal_kdc::crypto::{Enctype, OwnCipher};
use rust_heimdal_kdc::hdb::{Hdb, HdbEntry, RedbHdb};
use rust_heimdal_kdc::kdc::{Kdc, KdcConfig};
use rust_heimdal_kdc::name::Principal;
use rust_heimdal_kdc::transport::serve_loopback;

const REALM: &str = "EXAMPLE.COM";
const PASSWORD: &str = "correct horse battery staple";

/// A directory removed when the test ends.
struct Dir(std::path::PathBuf);

impl Dir {
    fn new(tag: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "rhk-kdc-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&path).unwrap();
        Dir(path)
    }

    fn file(&self) -> std::path::PathBuf {
        self.0.join("hdb.redb")
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Fills a database the way an operator would: `krbtgt`, then accounts.
fn provision(path: &std::path::Path) -> RedbHdb {
    let cipher = OwnCipher;
    let hdb = RedbHdb::open(path).unwrap();

    let mut krbtgt = HdbEntry::krbtgt(REALM);
    for e in [Enctype::Aes256Sha1, Enctype::Aes128Sha1] {
        krbtgt
            .add_password_key(&cipher, e, b"master-key-of-the-realm", 1)
            .unwrap();
    }
    hdb.store(krbtgt).unwrap();

    let mut alice = HdbEntry::user(Principal::parse(&format!("alice@{REALM}")).unwrap());
    for e in [Enctype::Aes256Sha1, Enctype::Aes128Sha1] {
        alice
            .add_password_key(&cipher, e, PASSWORD.as_bytes(), 1)
            .unwrap();
    }
    hdb.store(alice).unwrap();

    let mut service = HdbEntry::service(Principal::parse(&format!("host/h@{REALM}")).unwrap());
    service
        .add_password_key(&cipher, Enctype::Aes256Sha1, b"service-key", 1)
        .unwrap();
    hdb.store(service).unwrap();
    hdb
}

#[test]
fn a_tgt_is_issued_from_a_database_file_and_after_a_reopen() {
    let dir = Dir::new("persist");

    // First process: provision, serve, take a TGT.
    let first = {
        let hdb = provision(&dir.file());
        let stand = serve_loopback(Kdc::new(
            KdcConfig::new(REALM).unwrap(),
            Arc::new(hdb),
            Arc::new(OwnCipher),
        ));
        let client = krb5::KdcClient::new(REALM, [stand.addr().as_str()]);
        let alice = krb5::Principal::parse(&format!("alice@{REALM}")).unwrap();
        client
            .login_with_password(&alice, PASSWORD)
            .expect("the first TGT must be issued from the database")
    };

    // Second process: nothing in memory, a fresh handle on the same file.
    let second = {
        let hdb = RedbHdb::open(dir.file()).expect("the database must still open");
        assert_eq!(
            hdb.fetch(&Principal::krbtgt(REALM))
                .unwrap()
                .unwrap()
                .keys
                .len(),
            2,
            "the krbtgt entry must have survived the process that wrote it"
        );
        let stand = serve_loopback(Kdc::new(
            KdcConfig::new(REALM).unwrap(),
            Arc::new(hdb),
            Arc::new(OwnCipher),
        ));
        let client = krb5::KdcClient::new(REALM, [stand.addr().as_str()]);
        let alice = krb5::Principal::parse(&format!("alice@{REALM}")).unwrap();
        client
            .login_with_password(&alice, PASSWORD)
            .expect("a TGT must still be issued after reopening the database")
    };

    assert_eq!(
        first.server, second.server,
        "both must be TGTs for the realm"
    );
    assert_eq!(first.client, second.client);
    assert_ne!(
        first.session_key.bytes(),
        second.session_key.bytes(),
        "two TGTs must not share a session key"
    );
}

#[test]
fn a_service_ticket_works_from_a_database_file() {
    let dir = Dir::new("service");
    let hdb = provision(&dir.file());
    let stand = serve_loopback(Kdc::new(
        KdcConfig::new(REALM).unwrap(),
        Arc::new(hdb),
        Arc::new(OwnCipher),
    ));
    let client = krb5::KdcClient::new(REALM, [stand.addr().as_str()]);
    let alice = krb5::Principal::parse(&format!("alice@{REALM}")).unwrap();
    let tgt = client.login_with_password(&alice, PASSWORD).unwrap();
    let service = krb5::Principal::parse(&format!("host/h@{REALM}")).unwrap();
    let ticket = client
        .service_ticket(&tgt, &service)
        .expect("the TGS exchange must read the service from the database");
    assert_eq!(ticket.server.to_string(), format!("host/h@{REALM}"));
}

#[test]
fn an_account_removed_from_the_file_cannot_log_in() {
    // Removing a principal is the operation an operator does when somebody
    // leaves, so it has to take effect for the next authentication, not for the
    // next restart.
    let dir = Dir::new("removed");
    let hdb = provision(&dir.file());
    hdb.remove(&Principal::parse(&format!("alice@{REALM}")).unwrap())
        .unwrap();
    let stand = serve_loopback(Kdc::new(
        KdcConfig::new(REALM).unwrap(),
        Arc::new(hdb),
        Arc::new(OwnCipher),
    ));
    let client = krb5::KdcClient::new(REALM, [stand.addr().as_str()]);
    let alice = krb5::Principal::parse(&format!("alice@{REALM}")).unwrap();
    let err = client
        .login_with_password(&alice, PASSWORD)
        .expect_err("a removed principal must not get a ticket");
    let text = err.to_string();
    assert!(
        text.contains("6") || text.to_lowercase().contains("principal unknown"),
        "the client must be told the principal is unknown, got: {text}"
    );
}
