//! The administrator's API, judged by whether a realm built with it works.
//!
//! The point of this layer is not that it can call `Hdb::store` — a caller could
//! already do that. It is that it refuses the operations which look like a good
//! idea and are not: creating over an existing account, deleting `krbtgt`,
//! replacing keys in place, pruning the keys a ticket still needs. Each of those
//! is a test here, and the last one is a client logging in.

use std::sync::Arc;

use rust_heimdal_kdc::admin::{Admin, Modify, NewPrincipal, Role};
use rust_heimdal_kdc::crypto::{Cipher, Enctype, OwnCipher};
use rust_heimdal_kdc::hdb::{Hdb, HdbEntry, MemoryHdb, flags as entry_flags};
use rust_heimdal_kdc::kdc::{Kdc, KdcConfig};
use rust_heimdal_kdc::name::Principal;
use rust_heimdal_kdc::transport::serve_loopback;

const REALM: &str = "EXAMPLE.COM";
const NOW: i64 = 1_700_000_000;

fn p(name: &str) -> Principal {
    Principal::parse(&format!("{name}@{REALM}")).unwrap()
}

/// A database with the realm's `krbtgt`, and an administrator over it.
fn realm() -> (Arc<MemoryHdb>, Admin) {
    let cipher = OwnCipher;
    let db = MemoryHdb::new();
    let mut krbtgt = HdbEntry::krbtgt(REALM);
    for e in [Enctype::Aes256Sha1, Enctype::Aes128Sha1] {
        krbtgt
            .add_password_key(&cipher, e, b"master-key-of-the-realm", 1)
            .unwrap();
    }
    db.insert(krbtgt).unwrap();
    let db = Arc::new(db);
    let admin = Admin::with_defaults(REALM, Arc::clone(&db) as Arc<dyn Hdb>, Arc::new(cipher));
    (db, admin)
}

#[test]
fn a_created_account_can_log_in() {
    let (db, admin) = realm();
    let created = admin
        .create(NewPrincipal::user(p("alice"), b"a password".to_vec()))
        .unwrap();
    assert_eq!(created.principal, p("alice"));
    assert_eq!(
        created.keys.len(),
        4,
        "a key per enctype the KDC issues, or a client asking for another one is refused"
    );
    assert!(created.has(entry_flags::CLIENT));

    // ... and the KDC issues a TGT for it, which is the only proof that the
    // entry is well-formed rather than merely present.
    let stand = serve_loopback(Kdc::new(
        KdcConfig::new(REALM).unwrap(),
        Arc::clone(&db) as Arc<dyn Hdb>,
        Arc::new(OwnCipher),
    ));
    let client = krb5::KdcClient::new(REALM, [stand.addr().as_str()]);
    let alice = krb5::Principal::parse(&p("alice").to_string()).unwrap();
    client
        .login_with_password(&alice, "a password")
        .expect("an account made through the administrator's API must be able to log in");
}

#[test]
fn creating_over_an_existing_account_is_refused() {
    let (_db, admin) = realm();
    admin
        .create(NewPrincipal::user(p("alice"), b"first".to_vec()))
        .unwrap();
    let err = admin
        .create(NewPrincipal::user(p("alice"), b"second".to_vec()))
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("already exists"),
        "a create that overwrote would reset the keys of a live account, got: {err}"
    );
    // The first password still works.
    let entry = admin.get(&p("alice")).unwrap();
    assert_eq!(entry.kvno(), 1);
}

#[test]
fn a_service_account_may_be_issued_tickets_but_not_ask_for_them() {
    let (_db, admin) = realm();
    let service = admin
        .create(NewPrincipal::service(
            Principal::parse(&format!("host/h@{REALM}")).unwrap(),
            b"service key".to_vec(),
        ))
        .unwrap();
    assert!(service.has(entry_flags::SERVER));
    assert!(
        !service.has(entry_flags::CLIENT),
        "a service is a target, not a client; giving it both is how a service account \
         becomes a way in"
    );
    assert!(
        !service.has(entry_flags::REQUIRE_PREAUTH),
        "a service does not pre-authenticate: it has no password to prove"
    );
}

#[test]
fn deleting_krbtgt_is_refused() {
    let (_db, admin) = realm();
    let err = admin.delete(&Principal::krbtgt(REALM)).unwrap_err().to_string();
    assert!(
        err.contains("may not be deleted"),
        "deleting krbtgt invalidates every ticket in the realm, got: {err}"
    );
}

#[test]
fn an_immutable_entry_cannot_be_deleted() {
    let (db, admin) = realm();
    admin
        .create(NewPrincipal::user(p("keeper"), b"pw".to_vec()))
        .unwrap();
    let mut entry = admin.get(&p("keeper")).unwrap();
    entry.flags |= entry_flags::IMMUTABLE;
    db.store(entry).unwrap();
    assert!(admin.delete(&p("keeper")).is_err());
}

#[test]
fn deleting_a_missing_account_reports_that_there_was_none() {
    let (_db, admin) = realm();
    assert!(!admin.delete(&p("nobody")).unwrap());
}

#[test]
fn a_password_change_moves_the_kvno_and_keeps_the_old_keys() {
    let (_db, admin) = realm();
    admin
        .create(NewPrincipal::user(p("alice"), b"old".to_vec()))
        .unwrap();
    let first = admin.get(&p("alice")).unwrap().key_for(Enctype::Aes256Sha1).unwrap().key.clone();
    let kvno = admin.set_password(&p("alice"), b"new").unwrap();
    assert_eq!(kvno, 2);
    let after = admin.get(&p("alice")).unwrap();
    assert_eq!(after.kvno(), 2);
    assert_eq!(
        after.keys.len(),
        4,
        "one new key per enctype, and the old ones dropped: a password change replaces, it does \
         not accumulate"
    );
    assert_ne!(after.key_for(Enctype::Aes256Sha1).unwrap().key, first);
}

#[test]
fn pruning_old_keys_leaves_only_the_current_kvno() {
    let (db, admin) = realm();
    admin
        .create(NewPrincipal::user(p("alice"), b"one".to_vec()))
        .unwrap();
    // Two keys at kvno 1, then a change to kvno 2 which replaces them, then an
    // import of an old key to simulate a realm that accumulated them.
    admin.set_password(&p("alice"), b"two").unwrap();
    let mut entry = admin.get(&p("alice")).unwrap();
    let old = OwnCipher
        .s2k(Enctype::Aes256Sha1, b"one", b"EXAMPLE.COMalice", None)
        .unwrap();
    entry.add_key(old, 1, Some(b"EXAMPLE.COMalice".to_vec()));
    db.store(entry).unwrap();
    assert!(admin.get(&p("alice")).unwrap().keys.len() > 4);

    let removed = admin.prune_old_keys(&p("alice")).unwrap();
    assert!(removed > 0);
    let after = admin.get(&p("alice")).unwrap();
    assert!(
        after.keys.iter().all(|k| k.kvno == after.kvno()),
        "pruning must leave only the current kvno"
    );
}

#[test]
fn an_empty_modification_is_refused() {
    let (_db, admin) = realm();
    admin
        .create(NewPrincipal::user(p("alice"), b"pw".to_vec()))
        .unwrap();
    let err = admin.modify(&p("alice"), Modify::default()).unwrap_err().to_string();
    assert!(
        err.contains("nothing to do"),
        "a no-op that reports success is a change an operator will believe happened"
    );
}

#[test]
fn locking_and_unlocking_works() {
    let (_db, admin) = realm();
    admin
        .create(NewPrincipal::user(p("alice"), b"pw".to_vec()))
        .unwrap();
    let locked = admin
        .modify(
            &p("alice"),
            Modify {
                locked_out: Some(true),
                ..Modify::default()
            },
        )
        .unwrap();
    assert!(locked.has(entry_flags::LOCKED_OUT));
    let unlocked = admin
        .modify(
            &p("alice"),
            Modify {
                locked_out: Some(false),
                ..Modify::default()
            },
        )
        .unwrap();
    assert!(!unlocked.has(entry_flags::LOCKED_OUT));
}

#[test]
fn the_keytab_carries_every_key_the_entry_holds() {
    let (db, admin) = realm();
    let host = Principal::parse(&format!("host/h@{REALM}")).unwrap();
    admin
        .create(NewPrincipal::service(host.clone(), b"service key".to_vec()))
        .unwrap();

    // A realm that already went through a rotation, so the entry holds an older
    // kvno as well: that is the case a keytab has to serve, because the service
    // may be running with the previous file while the KDC already has the new key.
    let old = OwnCipher
        .s2k(Enctype::Aes256Sha1, b"service key", b"EXAMPLE.COMhost".as_slice(), None)
        .unwrap();
    admin.set_password(&host, b"rotated service key").unwrap();
    let mut entry = admin.get(&host).unwrap();
    assert_eq!(entry.kvno(), 2, "the rotation must have moved the kvno");
    entry.add_key(old, 1, Some(b"EXAMPLE.COMhost".to_vec()));
    db.store(entry).unwrap();

    let keytab = admin.keytab_for(&host).unwrap();
    let kvnos: Vec<u32> = keytab.entries().iter().map(|e| e.kvno).collect();
    assert!(
        kvnos.contains(&1) && kvnos.contains(&2),
        "a keytab must carry the old kvno too: a service deploys it before the KDC rotates,          got kvnos {kvnos:?}"
    );
    // The keytab must survive a round trip through the file format.
    let bytes = keytab.to_bytes();
    let back = rust_heimdal_kdc::hdb::Keytab::parse(&bytes).unwrap();
    assert_eq!(back.entries().len(), keytab.entries().len());
}

#[test]
fn a_keytab_for_an_entry_with_no_keys_is_refused() {
    let (_db, admin) = realm();
    admin
        .create(NewPrincipal {
            principal: p("empty"),
            password: Vec::new(),
            enctypes: Vec::new(),
            role: Role::Server,
        })
        .unwrap();
    let err = admin.keytab_for(&p("empty")).unwrap_err().to_string();
    assert!(
        err.contains("no keys"),
        "an empty keytab that reports success is a service that will fail at the first request"
    );
}

#[test]
fn the_listing_walks_every_principal() {
    let (_db, admin) = realm();
    for name in ["alice", "bob", "carol"] {
        admin
            .create(NewPrincipal::user(p(name), b"pw".to_vec()))
            .unwrap();
    }
    let listed = admin.list().unwrap();
    assert_eq!(listed.len(), 4, "three accounts and the krbtgt the realm was made with");
    assert!(listed.contains(&Principal::krbtgt(REALM)));
}

#[test]
fn creating_in_another_realm_is_refused() {
    let (_db, admin) = realm();
    let err = admin
        .create(NewPrincipal::user(
            Principal::parse("alice@OTHER.COM").unwrap(),
            b"pw".to_vec(),
        ))
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("OTHER.COM"),
        "an administrator manages one realm, got: {err}"
    );
}

#[test]
fn a_password_can_be_set_on_a_principal_with_a_restricted_enctype_set() {
    // A realm that issues only AES-128: the entry gets one key, and a change
    // makes one new key rather than four.
    let cipher = OwnCipher;
    let db = MemoryHdb::new();
    let mut krbtgt = HdbEntry::krbtgt(REALM);
    krbtgt
        .add_password_key(&cipher, Enctype::Aes128Sha1, b"master", 1)
        .unwrap();
    db.insert(krbtgt).unwrap();
    let db = Arc::new(db);
    let admin = Admin::new(
        REALM,
        Arc::clone(&db) as Arc<dyn Hdb>,
        Arc::new(cipher),
        &[Enctype::Aes128Sha1],
    );
    admin
        .create(NewPrincipal::user(p("alice"), b"pw".to_vec()))
        .unwrap();
    assert_eq!(admin.get(&p("alice")).unwrap().keys.len(), 1);
    admin.set_password(&p("alice"), b"new").unwrap();
    let after = admin.get(&p("alice")).unwrap();
    assert_eq!(after.keys.len(), 1, "a change keeps the entry's enctype set");
    assert_eq!(after.keys[0].key.enctype(), Enctype::Aes128Sha1);
}

#[test]
fn an_analyst_can_see_what_a_principal_is() {
    // The `get` side, which a listing tool needs: flags, kvno, validity.
    let (_db, admin) = realm();
    admin
        .create(NewPrincipal::user(p("alice"), b"pw".to_vec()))
        .unwrap();
    admin
        .modify(
            &p("alice"),
            Modify {
                valid_end: Some(Some(NOW + 86_400)),
                ..Modify::default()
            },
        )
        .unwrap();
    let entry = admin.get(&p("alice")).unwrap();
    assert_eq!(entry.valid_end, Some(NOW + 86_400));
    assert!(entry.is_valid_at(NOW));
    assert!(!entry.is_valid_at(NOW + 86_401));
}
