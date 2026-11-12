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

use rrl_kdc::crypto::{Cipher, Enctype, Key, OwnCipher, usage};
use rrl_kdc::der;
use rrl_kdc::error::Error;
use rrl_kdc::hdb::ldap::{
    Attributes, Directory, LdapHdb, attrs, dn_for, from_attributes, to_attributes, uac,
};
use rrl_kdc::hdb::{Hdb, HdbEntry, flags};
use rrl_kdc::kdc::{Kdc, KdcConfig};
use rrl_kdc::kdc::{Purpose, usable_enctypes};
use rrl_kdc::msg::{
    self, ApReq, Authenticator, EncTicketPart, EncryptedData, Ticket, encode_pa_data, kdc_options,
    tkt_flags,
};
use rrl_kdc::name::Principal;
use rrl_kdc::transport::serve_loopback;

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

    fn get_by_spn(&self, spn: &str) -> Result<Option<Attributes>, Error> {
        // An equality search on `servicePrincipalName`, which is what an LDAP server
        // does with the index it keeps for that attribute.
        Ok(self
            .entries
            .lock()
            .unwrap()
            .values()
            .find(|attributes| {
                attributes
                    .get(attrs::AD_SERVICE_PRINCIPAL_NAME)
                    .iter()
                    .filter_map(|value| std::str::from_utf8(value).ok())
                    .any(|value| value.eq_ignore_ascii_case(spn))
            })
            .cloned())
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

/// A sealed LDAP backend: what the directory holds has no key in the clear, and it reads back.
///
/// The end-to-end shape matters more here than for a file: `krb5Key` is a *directory attribute*, and a
/// read-only account with that attribute in its ACL holds every key it can see. Sealing it means such a
/// copy is worthless without the master keytab, which is exactly what Heimdal's LDAP backend does when
/// it has a master key.
#[test]
fn a_sealed_directory_holds_no_plaintext_key() {
    use rrl_kdc::crypto::{Cipher, Enctype, OwnCipher};
    use rrl_kdc::hdb::mkey::MasterKeys;

    let directory = Arc::new(FakeDirectory::new());
    realm(&directory);
    let master = OwnCipher.random(Enctype::Aes256Sha1).unwrap();
    let keys = MasterKeys::single(master, 1);

    let mut alice = HdbEntry::user(p("alice"));
    alice
        .add_password_key(&OwnCipher, Enctype::Aes256Sha1, PASSWORD.as_bytes(), 1)
        .unwrap();
    let plain = alice.keys[0].key.bytes().to_vec();

    // Written through a sealed backend: the directory gets sealed values.
    let sealed = LdapHdb::new(Arc::clone(&directory) as Arc<dyn Directory>)
        .with_master_keys(keys.clone(), Arc::new(OwnCipher))
        .expect("a sealed backend");
    assert!(sealed.is_sealed());
    sealed.store(alice).expect("stored");

    // What the directory actually holds.
    let stored = directory
        .get(&p("alice"))
        .expect("a lookup")
        .expect("alice");
    for value in stored.get(attrs::KEY) {
        assert!(
            !value.windows(plain.len()).any(|w| w == plain.as_slice()),
            "a key was written to the directory in the clear"
        );
    }

    // The same backend reads it back, and a backend without the key refuses by name.
    let back = sealed.fetch(&p("alice")).expect("a fetch").expect("alice");
    assert_eq!(back.keys[0].key.bytes(), plain.as_slice());

    let unsealed = LdapHdb::new(Arc::clone(&directory) as Arc<dyn Directory>);
    let err = unsealed
        .fetch(&p("alice"))
        .expect_err("a sealed attribute needs the master key");
    assert!(
        err.to_string().contains("sealed under a master key"),
        "{err}"
    );

    // An empty key set is refused at construction: sealing with nothing is not a mode.
    let err = LdapHdb::new(Arc::clone(&directory) as Arc<dyn Directory>)
        .with_master_keys(MasterKeys::none(), Arc::new(OwnCipher))
        .expect_err("no master key");
    assert!(err.to_string().contains("no master key"), "{err}");
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
fn the_ad_key_blob_is_a_projection_and_krb5key_wins() {
    // The projection is for tools that look for an Active Directory's shape. It is
    // generated from `krb5Key` and must not become a second source of truth: an
    // entry whose blob was edited by hand still gets its keys from `krb5Key`.
    let directory = FakeDirectory::new();
    realm(&directory);
    let attributes = directory
        .entries
        .lock()
        .unwrap()
        .get(&p("alice").to_string())
        .cloned()
        .unwrap();
    let blob = attributes
        .first(attrs::AD_SUPPLEMENTAL_CREDENTIALS)
        .expect("an entry with keys must carry the projection");
    assert!(blob.len() >= 111, "a USER_PROPERTIES structure");

    // Replace it with garbage: the entry must still read, because the keys are in
    // `krb5Key` and the blob is not consulted while they are.
    let mut edited = attributes.clone();
    edited.set(attrs::AD_SUPPLEMENTAL_CREDENTIALS, b"not a blob".to_vec());
    let entry = from_attributes(&edited).expect("the blob must not be authoritative");
    assert_eq!(entry.keys.len(), 2, "the keys come from krb5Key");

    // And an entry with no keys carries no blob: absent means "not filled in",
    // while an empty one would claim the account has no credentials.
    let mut keyless = HdbEntry::user(p("fresh"));
    keyless.etypes = None;
    let written = to_attributes(&keyless);
    assert!(!written.has(attrs::AD_SUPPLEMENTAL_CREDENTIALS));
}

#[test]
fn the_projection_is_read_when_krb5key_is_absent() {
    // An account written by an AD-shaped tool has its keys in
    // `supplementalCredentials` and nowhere else. Refusing to read it would mean
    // this KDC can only serve directories it wrote itself.
    let directory = FakeDirectory::new();
    realm(&directory);
    let attributes = directory
        .entries
        .lock()
        .unwrap()
        .get(&p("alice").to_string())
        .cloned()
        .unwrap();
    let expected: Vec<(Enctype, Vec<u8>)> = from_attributes(&attributes)
        .unwrap()
        .keys
        .iter()
        .map(|k| (k.key.enctype(), k.key.bytes().to_vec()))
        .collect();

    let mut ad_shaped = attributes.clone();
    assert!(ad_shaped.remove(attrs::KEY), "krb5Key is what we take away");
    let entry = from_attributes(&ad_shaped).expect("the projection is the only source left");
    assert_eq!(
        entry.keys.len(),
        expected.len(),
        "every key in the blob comes back"
    );
    // Order is not a fact either direction keeps: `krb5Key` comes back in the
    // order the directory stored it and the blob is sorted by enctype, so the
    // comparison is by enctype rather than by position.
    let mut read: Vec<(Enctype, Vec<u8>)> = entry
        .keys
        .iter()
        .map(|k| (k.key.enctype(), k.key.bytes().to_vec()))
        .collect();
    let mut expected = expected;
    read.sort_by_key(|(enctype, _)| enctype.id());
    expected.sort_by_key(|(enctype, _)| enctype.id());
    assert_eq!(read, expected, "byte for byte, per enctype");
    for key in &entry.keys {
        assert_eq!(
            key.kvno, entry.kvno,
            "the blob has no version, so the version comes from the attribute"
        );
    }
    assert_eq!(
        entry.kvno, 1,
        "msDS-KeyVersionNumber still says what it said"
    );
}

#[test]
fn a_projection_that_cannot_be_read_is_refused_rather_than_guessed() {
    // With `krb5Key` gone there is nothing to fall back to, and an account with
    // invented or missing keys cannot log in. The refusal names the attribute, so
    // the operator sees which half of the entry is broken.
    let directory = FakeDirectory::new();
    realm(&directory);
    let mut attributes = directory
        .entries
        .lock()
        .unwrap()
        .get(&p("alice").to_string())
        .cloned()
        .unwrap();
    attributes.remove(attrs::KEY);
    attributes.set(attrs::AD_SUPPLEMENTAL_CREDENTIALS, b"not a blob".to_vec());
    match from_attributes(&attributes) {
        Err(Error::Hdb(text)) => assert!(
            text.contains(attrs::AD_SUPPLEMENTAL_CREDENTIALS),
            "the message must name the attribute, not just fail: {text}"
        ),
        other => panic!("expected a refusal naming the attribute, got {other:?}"),
    }
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

/// A machine account as a Windows directory holds it: the principal is `HOST$`, and
/// the name clients ask for lives in `servicePrincipalName`.
fn machine(directory: &FakeDirectory) -> Principal {
    let principal = Principal::parse(&format!("HOST$@{REALM}")).unwrap();
    let mut entry = HdbEntry::service(principal.clone());
    for e in [Enctype::Aes256Sha1, Enctype::Aes128Sha1] {
        entry
            .add_password_key(&OwnCipher, e, b"machine-password", 1)
            .unwrap();
    }
    directory.insert(&entry);
    // `to_attributes` derives `servicePrincipalName` from `host/NAME` for a service
    // principal; the stand needs `cifs/…` as well, which is the name Samba asks for.
    let mut attributes = to_attributes(&entry);
    attributes.add(
        attrs::AD_SERVICE_PRINCIPAL_NAME,
        format!("cifs/{}", HOST).into_bytes(),
    );
    directory.put(&principal, &attributes).unwrap();
    principal
}

const HOST: &str = "host.ad.example.com";

#[test]
fn a_ticket_is_issued_for_a_name_the_account_publishes() {
    // The defect this pins: a client asks for `cifs/host.ad.example.com`, the
    // directory holds `HOST$` and publishes that name, and a lookup by principal
    // found nothing — `net ads join` stopped at the first SMB ticket.
    let directory = Arc::new(FakeDirectory::new());
    realm(&directory);
    let machine_principal = machine(&directory);

    let asked = Principal::parse(&format!("cifs/{HOST}@{REALM}")).unwrap();
    let entry = LdapHdb::new(shared(&directory))
        .fetch_for_service(&asked)
        .expect("the lookup must not fail")
        .expect("the published name must be found");
    assert_eq!(
        entry.principal, machine_principal,
        "the keys come from the machine account"
    );
}

#[test]
fn a_name_the_account_does_not_publish_is_not_found() {
    // The other half: resolving by SPN must not turn into "any service will do".
    let directory = Arc::new(FakeDirectory::new());
    realm(&directory);
    machine(&directory);
    let asked = Principal::parse(&format!("http/nowhere@{REALM}")).unwrap();
    assert!(
        LdapHdb::new(shared(&directory))
            .fetch_for_service(&asked)
            .unwrap()
            .is_none(),
        "an unregistered name must not resolve"
    );
}

#[test]
fn a_directory_that_answers_with_the_wrong_entry_is_refused() {
    // A directory with a broken SPN index must not produce a ticket for whichever
    // account it happened to return: the entry has to publish the name asked for.
    let directory = Arc::new(FakeDirectory::new());
    realm(&directory);
    machine(&directory);
    #[derive(Debug)]
    struct Liar(Arc<FakeDirectory>);
    impl Directory for Liar {
        fn get(&self, principal: &Principal) -> Result<Option<Attributes>, Error> {
            self.0.get(principal)
        }
        fn get_by_spn(&self, _spn: &str) -> Result<Option<Attributes>, Error> {
            // Answers every name with the machine's entry.
            Ok(self.0.get(&p("HOST$")).unwrap())
        }
        fn put(&self, principal: &Principal, attributes: &Attributes) -> Result<(), Error> {
            self.0.put(principal, attributes)
        }
        fn delete(&self, principal: &Principal) -> Result<bool, Error> {
            self.0.delete(principal)
        }
        fn list(&self) -> Result<Vec<Principal>, Error> {
            self.0.list()
        }
    }
    let asked = Principal::parse(&format!("http/nowhere@{REALM}")).unwrap();
    let err = LdapHdb::new(Arc::new(Liar(Arc::clone(&directory))))
        .fetch_for_service(&asked)
        .expect_err("an entry that does not publish the name must be refused");
    let text = format!("{err}");
    assert!(text.contains("service principal name"), "{text}");
}

#[test]
fn a_live_client_gets_a_ticket_for_the_name_it_asked_for() {
    // The end-to-end half of the SPN lookup, through a third-party client: it asks for
    // `cifs/host.ad.example.com`, the directory holds `HOST$`, and the answer must be
    // a ticket naming what the client asked for and sealed in `HOST$`'s key.
    //
    // Naming `HOST$` in the reply would be the subtle failure: the client would hold a
    // ticket it believes belongs to another service, and an SMB server comparing
    // `sname` against its own name would refuse it.
    let directory = Arc::new(FakeDirectory::new());
    realm(&directory);
    let machine_principal = machine(&directory);
    let stand = serve_loopback(kdc_over(shared(&directory)));

    let client = krb5::KdcClient::new(REALM, [stand.addr().as_str()]);
    let alice = krb5::Principal::parse(&p("alice").to_string()).unwrap();
    let ctx = client
        .login_with_password(&alice, PASSWORD)
        .expect("alice logs in");

    let asked = krb5::Principal::parse(&format!("cifs/{HOST}@{REALM}")).unwrap();
    let ticket = client
        .service_ticket(&ctx, &asked)
        .expect("a service ticket for a published name must be issued");

    // The proof is that the client could open the ticket at all: its `enc-part` is
    // sealed in the key of the entry the lookup found, and the client checks the
    // reply's checksum against it. A ticket sealed in a different account's key would
    // fail here rather than at the SMB server.
    assert_eq!(
        ticket.ticket_server().map(|p| p.to_string()),
        Some(asked.to_string()),
        "the ticket names the service the client asked for, not the account that holds it"
    );
    assert_ne!(
        asked.to_string(),
        machine_principal.to_string(),
        "the two names really differ, or this test proves nothing"
    );
}

// ---- S4U2Proxy over a directory (RRL-3.27) -------------------------------------------

/// A service account in the directory, with a key and an optional delegation list.
fn service_entry(directory: &FakeDirectory, name: &str, delegate_to: Option<Vec<Principal>>) {
    let cipher = OwnCipher;
    let mut entry = HdbEntry::service(p(name));
    for e in [Enctype::Aes256Sha1, Enctype::Aes128Sha1] {
        entry
            .add_password_key(&cipher, e, b"service-key", 1)
            .unwrap();
    }
    entry.constrained_delegation = delegate_to;
    directory.insert(&entry);
}

/// The realm's `krbtgt` key, derived the way the test's directory derived it.
fn krbtgt_key() -> Key {
    let mut entry = HdbEntry::krbtgt(REALM);
    entry
        .add_password_key(
            &OwnCipher,
            Enctype::Aes256Sha1,
            b"master-key-of-the-realm",
            1,
        )
        .unwrap();
    entry
        .key_for(Enctype::Aes256Sha1)
        .map(|k| k.key.clone())
        .unwrap()
}

/// A service key, derived the way [`service_entry`] derived it.
fn service_key() -> Key {
    let mut entry = HdbEntry::service(p("svc/delegator.example.com"));
    entry
        .add_password_key(&OwnCipher, Enctype::Aes256Sha1, b"service-key", 1)
        .unwrap();
    entry
        .key_for(Enctype::Aes256Sha1)
        .map(|k| k.key.clone())
        .unwrap()
}

/// A TGT for `client` and its session key.
fn tgt_for(client: &Principal, krbtgt: &Key, now: i64) -> (Vec<u8>, Key) {
    let cipher = OwnCipher;
    let session = cipher.random(Enctype::Aes256Sha1).unwrap();
    let part = EncTicketPart {
        flags: tkt_flags::INITIAL | tkt_flags::PRE_AUTHENT | tkt_flags::FORWARDABLE,
        session_key: session.clone(),
        crealm: REALM.into(),
        cname: client.clone(),
        transited_type: 0,
        transited: Vec::new(),
        authtime: now - 60,
        starttime: None,
        endtime: now + 3600,
        renew_till: None,
        caddr: None,
        authorization_data: None,
    };
    let ticket = Ticket {
        realm: REALM.into(),
        sname: Principal::krbtgt(REALM),
        enc: EncryptedData::seal(
            &cipher,
            krbtgt,
            usage::KDC_REP_TICKET,
            Some(1),
            &part.encode(),
        )
        .unwrap(),
    };
    (ticket.encode(), session)
}

/// An evidence ticket in `alice`'s name, sealed in `key` — the delegating service's key.
fn evidence(key: &Key, now: i64) -> Vec<u8> {
    let cipher = OwnCipher;
    let part = EncTicketPart {
        flags: tkt_flags::INITIAL | tkt_flags::FORWARDABLE,
        session_key: cipher.random(Enctype::Aes256Sha1).unwrap(),
        crealm: REALM.into(),
        cname: p("alice"),
        transited_type: 0,
        transited: Vec::new(),
        authtime: now - 300,
        starttime: None,
        endtime: now + 3600,
        renew_till: None,
        caddr: None,
        authorization_data: None,
    };
    Ticket {
        realm: REALM.into(),
        sname: p("svc/delegator.example.com"),
        enc: EncryptedData::seal(&cipher, key, usage::KDC_REP_TICKET, Some(1), &part.encode())
            .unwrap(),
    }
    .encode()
}

/// A `TGS-REQ` for `target`, with `cname-in-addl-tkt` and the evidence ticket.
fn proxy_req(tgt: &[u8], session: &Key, target: &Principal, evidence: &[u8], now: i64) -> Vec<u8> {
    let cipher = OwnCipher;
    let body = der::seq(&[
        der::field(0, der::flags32(kdc_options::CNAME_IN_ADDL_TKT)),
        der::field(2, der::general_string(REALM)),
        der::field(3, target.encode_name()),
        der::field(5, der::time(now + 3600)),
        der::field(7, der::int(0x4242)),
        der::field(8, der::seq(&[der::int(18)])),
        der::field(11, der::seq(&[evidence.to_vec()])),
    ]);
    let cksum = cipher
        .checksum(session, usage::TGS_REQ_AUTH_CKSUM, &body)
        .unwrap();
    let authenticator = Authenticator {
        crealm: REALM.into(),
        cname: p("svc/delegator.example.com"),
        cksum: Some((Enctype::Aes256Sha1.checksum_type(), cksum)),
        cusec: 0,
        ctime: now,
        subkey: None,
        seq_number: None,
        authorization_data: None,
    };
    let ap_req = ApReq {
        ap_options: 0,
        ticket: tgt.to_vec(),
        authenticator: EncryptedData::seal(
            &cipher,
            session,
            usage::TGS_REQ_AUTH,
            None,
            &authenticator.encode(),
        )
        .unwrap(),
    }
    .encode();
    der::cons(
        der::app(12),
        &[der::seq(&[
            der::field(1, der::int(5)),
            der::field(2, der::int(12)),
            der::field(3, encode_pa_data(&[(msg::PA_TGS_REQ, ap_req)])),
            der::field(4, body),
        ])],
    )
}

const NOW: i64 = 1_700_000_000;

#[test]
fn a_delegation_list_in_the_directory_decides_who_may_delegate() {
    // The end of the chain RRL-3.27 is about: an administrator writes
    // `msDS-AllowedToDelegateTo` in the directory, and the KDC honours it. Without this the
    // attribute is decoded and nothing reads it, which is the shape of bug that looks like a
    // working feature until somebody tries to use it.
    let directory = Arc::new(FakeDirectory::new());
    realm(&directory);
    service_entry(
        &directory,
        "svc/delegator.example.com",
        Some(vec![p("cifs/files.example.com")]),
    );
    service_entry(&directory, "cifs/files.example.com", None);
    let kdc = kdc_over(shared(&directory));

    let (tgt, session) = tgt_for(&p("svc/delegator.example.com"), &krbtgt_key(), NOW);
    let request = proxy_req(
        &tgt,
        &session,
        &p("cifs/files.example.com"),
        &evidence(&service_key(), NOW),
        NOW,
    );
    let reply = kdc.handle(&request, NOW);
    assert!(
        msg::KrbError::decode(&reply).is_err(),
        "a listed delegation must be granted: {:?}",
        msg::KrbError::decode(&reply)
    );

    // And the ticket is the user's, sealed in the target service's key.
    let f = der::Fields::parse_app("TGS-REP", 13, &reply).unwrap();
    let mut r = der::Reader::new(f.bytes(4, "TGS-REP").expect("cname"));
    let seq = r.next_tlv("cname").unwrap();
    assert_eq!(
        Principal::decode("cname", seq.content, REALM)
            .unwrap()
            .components,
        vec!["alice"],
        "the delegated ticket names the user, not the service"
    );
}

#[test]
fn the_same_request_is_refused_when_the_directory_lists_nobody() {
    // The pair: the granting above must come from the attribute, not from the service being
    // trusted-for-delegation alone. A service with no list may delegate only to itself.
    let directory = Arc::new(FakeDirectory::new());
    realm(&directory);
    service_entry(&directory, "svc/delegator.example.com", None);
    service_entry(&directory, "cifs/files.example.com", None);
    let kdc = kdc_over(shared(&directory));

    let (tgt, session) = tgt_for(&p("svc/delegator.example.com"), &krbtgt_key(), NOW);
    let request = proxy_req(
        &tgt,
        &session,
        &p("cifs/files.example.com"),
        &evidence(&service_key(), NOW),
        NOW,
    );
    let reply = kdc.handle(&request, NOW);
    let err = msg::KrbError::decode(&reply).expect("a refusal");
    assert_eq!(err.code, rrl_kdc::error::codes::KDC_ERR_BADOPTION);
    assert!(
        err.e_text.unwrap_or_default().contains("may not delegate"),
        "the refusal names the rule"
    );
}
