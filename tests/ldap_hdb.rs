//! A KDC whose database is a directory, judged by a client logging in.
//!
//! The mapping is worth nothing if the engine cannot serve from it, so these
//! tests put a `LdapHdb` under a real `Kdc`, feed the `Directory` a stale
//! attributes map (as a directory would hold), and then have the `krb5` client
//! ask for a ticket the way `kinit` does.
//!
//! The fake directory is deliberately dumb: a map from principal to attributes,
//! with no LDAP anywhere. That is the point of the module's design — the KDC asks
//! four questions of a trait, and a directory that answers them is a directory
//! this KDC can serve from, whether it is in-process, over LDAP, or a file.
#![cfg(feature = "hdb-ldap")]

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use rust_heimdal_kdc::crypto::{Enctype, OwnCipher};
use rust_heimdal_kdc::error::Error;
use rust_heimdal_kdc::hdb::ldap::{
    Attributes, Directory, LdapHdb, attrs, dn_for, from_attributes, to_attributes, uac,
};
use rust_heimdal_kdc::hdb::{Hdb, HdbEntry, flags};
use rust_heimdal_kdc::kdc::{Kdc, KdcConfig};
use rust_heimdal_kdc::kdc::{Purpose, usable_enctypes};
use rust_heimdal_kdc::name::Principal;
use rust_heimdal_kdc::transport::serve_loopback;

const REALM: &str = "EXAMPLE.COM";
const PASSWORD: &str = "correct horse battery staple";

fn p(name: &str) -> Principal {
    Principal::parse(&format!("{name}@{REALM}")).unwrap()
}

/// A directory that keeps attributes and nothing else.
#[derive(Debug, Default)]
struct FakeDirectory {
    entries: Mutex<BTreeMap<String, Attributes>>,
    /// Set to make `get` answer for the wrong principal, which is what a
    /// directory with a broken index does.
    misindex: Mutex<Option<Principal>>,
}

impl FakeDirectory {
    fn new() -> Self {
        FakeDirectory::default()
    }

    fn insert(&self, entry: &HdbEntry) {
        self.entries
            .lock()
            .unwrap()
            .insert(entry.principal.to_string(), to_attributes(entry));
    }
}

impl Directory for FakeDirectory {
    fn get(&self, principal: &Principal) -> Result<Option<Attributes>, Error> {
        if let Some(wrong) = self.misindex.lock().unwrap().clone() {
            return Ok(self
                .entries
                .lock()
                .unwrap()
                .get(&wrong.to_string())
                .cloned());
        }
        Ok(self
            .entries
            .lock()
            .unwrap()
            .get(&principal.to_string())
            .cloned())
    }

    fn put(&self, principal: &Principal, attributes: &Attributes) -> Result<(), Error> {
        self.entries
            .lock()
            .unwrap()
            .insert(principal.to_string(), attributes.clone());
        Ok(())
    }

    fn delete(&self, principal: &Principal) -> Result<bool, Error> {
        Ok(self
            .entries
            .lock()
            .unwrap()
            .remove(&principal.to_string())
            .is_some())
    }

    fn list(&self) -> Result<Vec<Principal>, Error> {
        Ok(self
            .entries
            .lock()
            .unwrap()
            .keys()
            .map(|name| Principal::parse(name).unwrap())
            .collect())
    }
}

/// The directory as the trait the KDC asks.
fn shared(directory: &Arc<FakeDirectory>) -> Arc<dyn Directory> {
    // The same object, so a test can change the directory under a running KDC —
    // which is the whole point of not caching the realm.
    Arc::clone(directory) as Arc<dyn Directory>
}

/// `alice` and the realm's `krbtgt`, in attributes.
fn realm(directory: &FakeDirectory) {
    let cipher = OwnCipher;

    let mut krbtgt = HdbEntry::krbtgt(REALM);
    for e in [Enctype::Aes256Sha1, Enctype::Aes128Sha1] {
        krbtgt
            .add_password_key(&cipher, e, b"master-key-of-the-realm", 1)
            .unwrap();
    }
    krbtgt.flags |= flags::SERVER | flags::REQUIRE_PREAUTH;
    directory.insert(&krbtgt);

    let mut alice = HdbEntry::user(p("alice"));
    for e in [Enctype::Aes256Sha1, Enctype::Aes128Sha1] {
        alice
            .add_password_key(&cipher, e, PASSWORD.as_bytes(), 1)
            .unwrap();
    }
    directory.insert(&alice);
}

fn kdc_over(directory: Arc<dyn Directory>) -> Kdc {
    Kdc::new(
        KdcConfig::new(REALM).unwrap(),
        Arc::new(LdapHdb::new(directory)) as Arc<dyn Hdb>,
        Arc::new(OwnCipher),
    )
}

#[test]
fn a_client_logs_in_against_a_kdc_whose_database_is_attributes() {
    // The whole chain: attributes → HdbEntry → the engine → a ticket, and a
    // third-party client that will not accept a reply MIT would refuse.
    let directory = Arc::new(FakeDirectory::new());
    realm(&directory);
    let stand = serve_loopback(kdc_over(shared(&directory)));

    let client = krb5::KdcClient::new(REALM, [stand.addr().as_str()]);
    let alice = krb5::Principal::parse(&p("alice").to_string()).unwrap();
    let ctx = client
        .login_with_password(&alice, PASSWORD)
        .expect("a principal stored as LDAP attributes must be able to log in");
    // The context is the proof: the client validated the reply's encrypted part in
    // the key it derived from the password it was given.
    let _ = ctx;
}

#[test]
fn a_deleted_entry_stops_working_without_a_restart() {
    // A KDC that cached the realm would keep issuing tickets for an account that
    // was removed an hour ago.
    let directory = Arc::new(FakeDirectory::new());
    realm(&directory);
    let stand = serve_loopback(kdc_over(shared(&directory)));
    let client = krb5::KdcClient::new(REALM, [stand.addr().as_str()]);
    let alice = krb5::Principal::parse(&p("alice").to_string()).unwrap();
    client
        .login_with_password(&alice, PASSWORD)
        .expect("first login must work");

    directory
        .entries
        .lock()
        .unwrap()
        .remove(&p("alice").to_string());

    assert!(
        client.login_with_password(&alice, PASSWORD).is_err(),
        "an account removed from the directory must stop getting tickets"
    );
}

#[test]
fn a_password_changed_through_the_hdb_is_the_one_that_works() {
    // The write direction: a new password stored as attributes, then used.
    let directory = Arc::new(FakeDirectory::new());
    realm(&directory);
    let hdb = LdapHdb::new(shared(&directory));
    let mut alice = hdb.fetch(&p("alice")).unwrap().unwrap();
    let updated = alice.rekey(&OwnCipher, b"a new password").unwrap();
    hdb.store(updated).unwrap();
    alice = hdb.fetch(&p("alice")).unwrap().unwrap();
    assert_eq!(
        alice.kvno(),
        2,
        "the version must have moved and survived the round trip"
    );

    let stand = serve_loopback(kdc_over(shared(&directory)));
    let client = krb5::KdcClient::new(REALM, [stand.addr().as_str()]);
    let who = krb5::Principal::parse(&p("alice").to_string()).unwrap();
    client
        .login_with_password(&who, "a new password")
        .expect("the new password must work");
    assert!(
        client.login_with_password(&who, PASSWORD).is_err(),
        "and the old one must not"
    );
}

#[test]
fn the_kvno_and_the_keys_are_written_both_ways() {
    // Microsoft's attributes are copies; a client that reads them must see the
    // same number the KDC does.
    let directory = Arc::new(FakeDirectory::new());
    realm(&directory);
    let attributes = directory
        .entries
        .lock()
        .unwrap()
        .get(&p("alice").to_string())
        .cloned()
        .unwrap();
    assert_eq!(attributes.first(attrs::KEY_VERSION_NUMBER), Some(&b"1"[..]));
    assert_eq!(
        attributes.first(attrs::AD_KEY_VERSION_NUMBER),
        Some(&b"1"[..])
    );
    assert_eq!(attributes.get(attrs::KEY).len(), 2, "one value per key");
    assert!(
        attributes.has("objectClass"),
        "an entry a directory accepts has to name its classes"
    );
}

#[test]
fn an_etypes_restriction_narrows_what_the_kdc_issues() {
    // Heimdal's `etypes` and Microsoft's `msDS-SupportedEncryptionTypes` say the
    // same thing: this principal may be issued only these. A setting that exists
    // and does nothing is worse than no setting.
    let cipher = OwnCipher;
    let mut service = HdbEntry::service(Principal::parse(&format!("host/h@{REALM}")).unwrap());
    for e in [Enctype::Aes256Sha1, Enctype::Aes128Sha1] {
        service
            .add_password_key(&cipher, e, b"service key", 1)
            .unwrap();
    }
    service.etypes = Some(vec![Enctype::Aes128Sha1]);

    let config = KdcConfig::new(REALM).unwrap();
    let requested = [18, 17];
    assert_eq!(
        usable_enctypes(&config, &requested, &service, Purpose::Ticket),
        vec![Enctype::Aes128Sha1],
        "the declared set must exclude AES-256 even though a key for it exists"
    );
    assert_eq!(
        usable_enctypes(&config, &requested, &service, Purpose::Preauth),
        vec![Enctype::Aes256Sha1, Enctype::Aes128Sha1],
        "pre-authentication is not a ticket: Heimdal does not apply the restriction there, and \
         refusing would lock out the account instead of protecting anything"
    );
}

#[test]
fn an_etypes_restriction_survives_the_directory() {
    let directory = Arc::new(FakeDirectory::new());
    realm(&directory);
    let hdb = LdapHdb::new(shared(&directory));
    let mut krbtgt = hdb.fetch(&Principal::krbtgt(REALM)).unwrap().unwrap();
    krbtgt.etypes = Some(vec![Enctype::Aes128Sha1]);
    hdb.store(krbtgt).unwrap();
    let back = hdb.fetch(&Principal::krbtgt(REALM)).unwrap().unwrap();
    assert_eq!(back.etypes, Some(vec![Enctype::Aes128Sha1]));
}

#[test]
fn a_directory_that_answers_for_the_wrong_principal_is_refused() {
    // An index bug in the directory must not become tickets for the wrong person.
    let directory = Arc::new(FakeDirectory::new());
    realm(&directory);
    *directory.misindex.lock().unwrap() = Some(p("alice"));
    let hdb = LdapHdb::new(shared(&directory));
    let err = hdb
        .fetch(&Principal::krbtgt(REALM))
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("returned the entry for"),
        "the message must name the mismatch: {err}"
    );
}

#[test]
fn the_walk_is_ordered_and_visits_every_principal_once() {
    let directory = Arc::new(FakeDirectory::new());
    realm(&directory);
    for name in ["bob", "carol", "dave"] {
        let mut entry = HdbEntry::user(p(name));
        entry
            .add_password_key(&OwnCipher, Enctype::Aes256Sha1, b"pw", 1)
            .unwrap();
        directory.insert(&entry);
    }
    let hdb = LdapHdb::new(shared(&directory));

    let mut seen = Vec::new();
    let mut next = hdb.first().unwrap();
    while let Some(principal) = next {
        next = hdb.next(&principal).unwrap();
        seen.push(principal.to_string());
    }
    // The realm's `krbtgt` and `alice`, plus the three added here.
    assert_eq!(seen.len(), 5);
    let mut sorted = seen.clone();
    sorted.sort();
    assert_eq!(
        seen, sorted,
        "a walk must be in one order, whatever the directory returns"
    );
    assert_eq!(
        seen.iter().collect::<std::collections::BTreeSet<_>>().len(),
        seen.len(),
        "every principal exactly once"
    );
}

#[test]
fn next_is_a_function_of_the_principal_and_not_of_the_directories_mood() {
    // The directory returns its entries in insertion order, which is not sorted.
    // `next` must not depend on that, or two walks disagree.
    let directory = Arc::new(FakeDirectory::new());
    for name in ["zulu", "alpha", "mike"] {
        let mut entry = HdbEntry::user(p(name));
        entry
            .add_password_key(&OwnCipher, Enctype::Aes256Sha1, b"pw", 1)
            .unwrap();
        directory.insert(&entry);
    }
    let hdb = LdapHdb::new(shared(&directory));
    assert_eq!(
        hdb.next(&p("alpha")).unwrap(),
        Some(p("mike")),
        "the successor of alpha is mike, not whatever came next in the map"
    );
}

#[test]
fn renaming_writes_the_new_name_before_removing_the_old() {
    let directory = Arc::new(FakeDirectory::new());
    realm(&directory);
    let hdb = LdapHdb::new(shared(&directory));
    hdb.rename(&p("alice"), &p("alice2")).unwrap();

    assert!(
        hdb.fetch(&p("alice")).unwrap().is_none(),
        "the old name must be gone"
    );
    let moved = hdb.fetch(&p("alice2")).unwrap().unwrap();
    assert_eq!(moved.principal, p("alice2"));
    assert_eq!(moved.keys.len(), 2, "the keys travel with the name");
    // The salt is the principal's history and must not be recomputed: a client
    // that derived its key with the old salt has to keep working.
    assert_eq!(
        moved.keys[0].salt.as_deref(),
        Some(b"EXAMPLE.COMalice".as_slice()),
        "the salt must survive the rename"
    );
}

#[test]
fn renaming_onto_an_existing_principal_is_refused() {
    let directory = Arc::new(FakeDirectory::new());
    realm(&directory);
    let hdb = LdapHdb::new(shared(&directory));
    let err = hdb
        .rename(&p("alice"), &Principal::krbtgt(REALM))
        .unwrap_err();
    assert!(matches!(err, Error::Exists(_)), "{err}");
    assert!(
        hdb.fetch(&p("alice")).unwrap().is_some(),
        "a refused rename must leave both entries alone"
    );
}

#[test]
fn an_entry_disabled_in_the_directory_cannot_log_in() {
    // The end of the `userAccountControl` chain: an administrator disables an
    // account in the directory, and the KDC refuses it without a restart.
    let directory = Arc::new(FakeDirectory::new());
    realm(&directory);

    let mut alice = HdbEntry::user(p("alice"));
    alice
        .add_password_key(&OwnCipher, Enctype::Aes256Sha1, PASSWORD.as_bytes(), 1)
        .unwrap();
    alice.flags |= flags::INVALID;
    directory.insert(&alice);

    // The directory spells the same fact twice, consistently: an entry that said
    // it in only one place would be a contradiction the mapping refuses, which
    // `from_attributes` is tested for elsewhere.
    let mut attributes = directory
        .entries
        .lock()
        .unwrap()
        .get(&p("alice").to_string())
        .cloned()
        .unwrap();
    let uac_value: u32 =
        std::str::from_utf8(attributes.first(attrs::AD_USER_ACCOUNT_CONTROL).unwrap())
            .unwrap()
            .parse()
            .unwrap();
    attributes.set(
        attrs::AD_USER_ACCOUNT_CONTROL,
        (uac_value | uac::ACCOUNTDISABLE).to_string(),
    );
    assert_eq!(
        from_attributes(&attributes).unwrap().flags & flags::INVALID,
        flags::INVALID,
        "reading the directory must see the account as disabled"
    );

    let stand = serve_loopback(kdc_over(shared(&directory)));
    let client = krb5::KdcClient::new(REALM, [stand.addr().as_str()]);
    let who = krb5::Principal::parse(&p("alice").to_string()).unwrap();
    assert!(
        client.login_with_password(&who, PASSWORD).is_err(),
        "an account the directory marks disabled must not get a ticket"
    );
}

#[test]
fn a_dn_names_the_principal_and_the_realm() {
    let dn = dn_for(&p("alice"), "cn=Kerberos,dc=example,dc=com");
    assert_eq!(
        dn,
        "krb5PrincipalName=alice@EXAMPLE.COM,krb5RealmName=EXAMPLE.COM,cn=Kerberos,dc=example,dc=com"
    );
    let service = Principal::parse(&format!("host/web.example.com@{REALM}")).unwrap();
    assert_eq!(
        dn_for(&service, ""),
        "krb5PrincipalName=host/web.example.com@EXAMPLE.COM,krb5RealmName=EXAMPLE.COM"
    );
}
