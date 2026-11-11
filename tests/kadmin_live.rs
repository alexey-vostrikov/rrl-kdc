//! `kadmind`, judged by a stock `kadmin` client.
//!
//! The client here is not this crate's: it is `krb5` 1.0's `kadmin` module, which
//! speaks ONC RPC with RPCSEC_GSS privacy and RFC 4121 per-message tokens against
//! MIT's `kadmind`. If it connects, handshakes, and reads a principal back, then
//! the wire format is right in a way no amount of self-testing could show — the
//! GSS layer in particular round-trips perfectly against itself while being wrong
//! in every usage number.
#![cfg(feature = "kadmin")]

use std::sync::Arc;

use rrl_kdc::admin::wire::{Grants, Policy, Rights};
use rrl_kdc::crypto::{Cipher, Enctype, OwnCipher};
use rrl_kdc::hdb::{Hdb, HdbEntry, MemoryHdb, flags};
use rrl_kdc::kadmin::{Kadmin, admin_entry, serve_kadmin_loopback};
use rrl_kdc::kdc::{Kdc, KdcConfig};
use rrl_kdc::name::Principal;
use rrl_kdc::transport::serve_loopback;

const REALM: &str = "EXAMPLE.COM";
const ADMIN_PASSWORD: &str = "the administrators password";
const ALICE_PASSWORD: &str = "alices password";

fn p(name: &str) -> Principal {
    Principal::parse(&format!("{name}@{REALM}")).unwrap()
}

/// The same principal in the client's type — the two crates do not share one, and
/// that is deliberate: the boundary between them is the wire.
fn kp(name: &str) -> krb5::Principal {
    krb5::Principal::parse(&p(name).to_string()).unwrap()
}

/// A realm with a `krbtgt`, `alice`, and `kadmin/admin`.
fn realm() -> Arc<MemoryHdb> {
    let cipher = OwnCipher;
    let db = MemoryHdb::new();

    let mut krbtgt = HdbEntry::krbtgt(REALM);
    for e in [Enctype::Aes256Sha1, Enctype::Aes128Sha1] {
        krbtgt
            .add_password_key(&cipher, e, b"master-key-of-the-realm", 1)
            .unwrap();
    }
    db.insert(krbtgt).unwrap();

    let mut admin = admin_entry(REALM, &cipher, ADMIN_PASSWORD.as_bytes()).unwrap();
    admin.flags |= flags::CLIENT | flags::REQUIRE_PREAUTH;
    db.insert(admin).unwrap();

    let mut alice = HdbEntry::user(p("alice"));
    for e in [Enctype::Aes256Sha1, Enctype::Aes128Sha1] {
        alice
            .add_password_key(&cipher, e, ALICE_PASSWORD.as_bytes(), 1)
            .unwrap();
    }
    db.insert(alice).unwrap();
    Arc::new(db)
}

/// A `kadmin` client connected to a fresh stand, plus the stand's handles.
struct Stand {
    client: krb5::kadmin::AdminClient,
    kdc: krb5::KdcClient,
    /// The database the KDC and the admin server share, so a test can ask what was actually
    /// stored rather than what the protocol said.
    db: Arc<MemoryHdb>,
    /// Held, not read: dropping it stops the KDC the client logs in against.
    #[allow(dead_code)]
    kdc_stand: rrl_kdc::transport::RunningKdc,
    kadmin_stand: rrl_kdc::kadmin::RunningKadmin,
}

fn stand_with(policy: Arc<dyn Policy>) -> Stand {
    let db = realm();
    let cipher: Arc<dyn Cipher> = Arc::new(OwnCipher);
    let kdc = Kdc::new(
        KdcConfig::new(REALM).unwrap(),
        Arc::clone(&db) as Arc<dyn Hdb>,
        Arc::clone(&cipher),
    );
    let kadmin = Kadmin::new(
        Kdc::new(
            KdcConfig::new(REALM).unwrap(),
            Arc::clone(&db) as Arc<dyn Hdb>,
            Arc::clone(&cipher),
        ),
        policy,
    )
    .unwrap();
    let kdc_stand = serve_loopback(kdc);
    let kadmin_stand = serve_kadmin_loopback(kadmin).unwrap();

    // The client's own KDC client: it asks for an initial ticket for
    // kadmin/admin and then talks to the admin port, exactly as `kadmin -p` does.
    let client_kdc = krb5::KdcClient::new(REALM, [kdc_stand.addr()]);
    let admin = krb5::Principal::parse(&p("kadmin/admin").to_string()).unwrap();
    let client = krb5::kadmin::AdminClient::connect_with_password(
        &client_kdc,
        &admin,
        ADMIN_PASSWORD,
        kadmin_stand.addr(),
    )
    .expect("a stock kadmin client must be able to connect");

    Stand {
        client,
        kdc: client_kdc,
        db,
        kdc_stand,
        kadmin_stand,
    }
}

/// Every right, for the administrator.
fn owner() -> Arc<dyn Policy> {
    Arc::new(Grants::new().grant(&p("kadmin/admin"), Rights::ALL))
}

#[test]
fn a_stock_kadmin_client_connects_and_asks_for_its_privileges() {
    // The handshake is the hard part: a NULLPROC carrying the AP-REQ, a MIC over
    // the sequence window, and then every call sealed.
    let mut stand = stand_with(owner());
    let privileges = stand.client.privileges().expect("get_privs must answer");
    assert!(
        privileges.get() && privileges.add() && privileges.delete() && privileges.modify(),
        "an administrator with every right must be told so"
    );
    stand.kadmin_stand.stop();
}

#[test]
fn a_stock_kadmin_client_reads_a_principal_back() {
    let mut stand = stand_with(owner());
    let entry = stand
        .client
        .get_principal(&kp("alice"))
        .expect("get_principal must answer");
    assert_eq!(entry.principal.realm, REALM);
    assert_eq!(entry.kvno, 1);
    stand.kadmin_stand.stop();
}

#[test]
fn a_stock_kadmin_client_lists_the_realm() {
    let mut stand = stand_with(owner());
    let listed = stand
        .client
        .list_principals("*")
        .expect("get_principals must answer");
    let names: Vec<String> = listed.iter().map(ToString::to_string).collect();
    assert!(
        names.iter().any(|n| n == &p("alice").to_string()),
        "{names:?}"
    );
    assert!(
        names
            .iter()
            .any(|n| n == &Principal::krbtgt(REALM).to_string()),
        "the walk must reach every principal: {names:?}"
    );
    stand.kadmin_stand.stop();
}

#[test]
fn a_stock_kadmin_client_creates_and_deletes_a_principal() {
    // The end of the write path: a principal made over the admin protocol must be
    // one the KDC will issue a ticket for, so this logs in as it afterwards.
    let mut stand = stand_with(owner());
    let bob = p("bob");
    stand
        .client
        .create_principal(
            &kp("bob"),
            &krb5::kadmin::PrincipalChanges::default(),
            Some("bobs password"),
        )
        .expect("create_principal must answer");

    let created = stand
        .client
        .get_principal(&kp("bob"))
        .expect("get after create");
    assert_eq!(created.kvno, 1);

    // The KDC issues a ticket for it: the proof that the entry is well-formed
    // rather than merely present.
    let bob_principal = krb5::Principal::parse(&bob.to_string()).unwrap();
    stand
        .kdc
        .login_with_password(&bob_principal, "bobs password")
        .expect("a principal created by kadmin must be able to log in");

    stand
        .client
        .delete_principal(&kp("bob"))
        .expect("delete_principal must answer");
    assert!(
        stand.client.get_principal(&kp("bob")).is_err(),
        "a deleted principal must be gone"
    );
    stand.kadmin_stand.stop();
}

/// `modprinc` over the wire, from the client that writes it.
///
/// The fields go through the record, the mask and the attribute word — three chances to be
/// positional in the wrong place — so what is checked is that the entry the KDC then uses has what
/// the client asked for.
#[test]
fn a_stock_kadmin_client_modifies_a_principal() {
    let mut stand = stand_with(owner());
    let before = stand.client.get_principal(&kp("alice")).expect("get");

    // `modprinc -maxlife 10h -maxrenewlife 7d -expire 0`: a lifetime, a renewable lifetime, and an
    // expiry of zero, which MIT spells "never" rather than the epoch.
    // The struct is `non_exhaustive`, so it is filled in field by field: that is also what a
    // caller outside the crate has to do.
    let mut changes = krb5::kadmin::PrincipalChanges::default();
    changes.max_life = Some(36_000);
    changes.max_renewable_life = Some(604_800);
    changes.princ_expire_time = Some(0);
    // And one attribute on, one off, as `modprinc +requires_preauth -forwardable` words it.
    changes = changes.with_attributes(
        &before,
        krb5::kadmin::attributes::REQUIRES_PRE_AUTH,
        krb5::kadmin::attributes::DISALLOW_FORWARDABLE,
    );
    stand
        .client
        .modify_principal(&kp("alice"), &changes)
        .expect("modify_principal must answer");

    let after = stand.client.get_principal(&kp("alice")).expect("get");
    assert_eq!(after.max_life, 36_000);
    assert_eq!(after.max_renewable_life, 604_800);
    assert_eq!(after.princ_expire_time, 0, "an expiry of zero is \"never\"");
    assert_ne!(
        after.attributes & krb5::kadmin::attributes::REQUIRES_PRE_AUTH,
        0
    );
    assert_eq!(
        after.attributes & krb5::kadmin::attributes::DISALLOW_FORWARDABLE,
        0,
        "the bit was cleared, and a cleared DISALLOW bit means forwardable is allowed"
    );

    // The other direction, so the word is shown to be reversible rather than merely writable: set
    // the bit, and it comes back.
    // Both edits in one call: `with_attributes` computes the whole word from the entry it is
    // given, so two calls would have the second one undo the first.
    let reverse = krb5::kadmin::PrincipalChanges::default().with_attributes(
        &after,
        krb5::kadmin::attributes::DISALLOW_FORWARDABLE,
        krb5::kadmin::attributes::REQUIRES_PRE_AUTH,
    );
    stand
        .client
        .modify_principal(&kp("alice"), &reverse)
        .expect("a second modify");
    let reversed = stand.client.get_principal(&kp("alice")).expect("get");
    assert_ne!(
        reversed.attributes & krb5::kadmin::attributes::DISALLOW_FORWARDABLE,
        0,
        "setting the bit must forbid forwardable tickets"
    );
    assert_eq!(
        reversed.attributes & krb5::kadmin::attributes::REQUIRES_PRE_AUTH,
        0,
        "and clearing the other must take pre-authentication off"
    );
    stand.kadmin_stand.stop();
}

/// `ktadd -norandkey`: the keys the admin server hands out are the keys the KDC will accept.
///
/// The point of the test is not that the reply parsed — it is that a ticket obtained with the
/// extracted keytab is issued: keys that look right and open nothing are the failure this catches.
#[test]
fn a_stock_kadmin_client_extracts_the_keys_a_keytab_needs() {
    let mut stand = stand_with(owner());
    let stored = stand.db.fetch(&p("alice")).unwrap().unwrap();

    let extracted = stand
        .client
        .extract_keys(&kp("alice"), None)
        .expect("extract_keys");
    assert_eq!(
        extracted.len(),
        stored.keys.len(),
        "one record per key, not one per enctype or per kvno"
    );
    for (kvno, key) in &extracted {
        let record = stored
            .keys
            .iter()
            .find(|k| k.kvno == *kvno && k.key.enctype().id() == key.enctype())
            .unwrap_or_else(|| {
                panic!("kvno {kvno}, enctype {} is not in the entry", key.enctype())
            });
        assert_eq!(
            key.bytes(),
            record.key.bytes(),
            "the bytes must be the stored ones"
        );
    }

    // And the keytab built from them authenticates: a wrong key would fail every exchange after
    // the initial ticket was handed out, which is exactly what a service operator would report.
    let path = std::env::temp_dir()
        .join(format!("rrl-kadmin-{}-alice.keytab", std::process::id()))
        .to_string_lossy()
        .into_owned();
    let _ = std::fs::remove_file(&path);
    stand
        .client
        .ktadd(&kp("alice"), &path, false)
        .expect("ktadd -norandkey");
    let keytab = krb5::Keytab::load(&path).expect("the keytab must be readable");
    stand
        .kdc
        .login_with_keytab(
            &krb5::Principal::parse(&p("alice").to_string()).unwrap(),
            &keytab,
        )
        .expect("the extracted keys must be the ones the KDC knows");

    // A kvno the entry does not have is a refusal, not an empty keytab.
    let absent = stand.client.extract_keys(&kp("alice"), Some(9));
    assert!(absent.is_err(), "kvno 9 is not in the entry: {absent:?}");
    let _ = std::fs::remove_file(&path);
    stand.kadmin_stand.stop();
}

/// Extracting keys is its own right: reading an entry's metadata must not be enough to walk away
/// with the keys themselves.
#[test]
fn extracting_keys_needs_the_extract_right() {
    // The administrator may read and list, and nothing more.
    let reader = Arc::new(Grants::new().grant(&p("kadmin/admin"), Rights::READ | Rights::LIST));
    let mut stand = stand_with(reader);
    let refused = stand.client.extract_keys(&kp("alice"), None);
    assert!(
        matches!(refused, Err(krb5::kadmin::Error::Kadm5(_))),
        "a reader must be refused with a kadm5 status, not a key list: {refused:?}"
    );
    // And what it may do still works, so the refusal is about the right and not the connection.
    stand.client.get_principal(&kp("alice")).expect("get");
    stand.kadmin_stand.stop();
}

/// `setstr` / `getstr` / `delstr` over the wire, from the client that writes them.
#[test]
fn a_stock_kadmin_client_sets_and_reads_string_attributes() {
    let mut stand = stand_with(owner());
    assert!(
        stand
            .client
            .get_strings(&kp("alice"))
            .expect("getstr")
            .is_empty(),
        "a fresh principal has no string attributes"
    );

    stand
        .client
        .set_string(&kp("alice"), "kpasswd_server", Some("kpasswd.example.com"))
        .expect("setstr must answer");
    stand
        .client
        .set_string(&kp("alice"), "kadmin_keytab", Some("/etc/krb5.keytab"))
        .expect("setstr must answer");

    let strings = stand.client.get_strings(&kp("alice")).expect("getstr");
    assert_eq!(
        strings,
        vec![
            (
                "kpasswd_server".to_string(),
                "kpasswd.example.com".to_string()
            ),
            ("kadmin_keytab".to_string(), "/etc/krb5.keytab".to_string()),
        ],
        "the pairs come back in the order they were set"
    );

    // `delstr`: the value absent is a deletion, and the other attribute stays.
    stand
        .client
        .set_string(&kp("alice"), "kpasswd_server", None)
        .expect("delstr must answer");
    assert_eq!(
        stand.client.get_strings(&kp("alice")).expect("getstr"),
        vec![("kadmin_keytab".to_string(), "/etc/krb5.keytab".to_string())]
    );
    stand.kadmin_stand.stop();
}

/// The strings live in the entry, so they survive the round trip through the HDB the KDC serves
/// from — not only in the admin server's memory.
#[test]
fn string_attributes_reach_the_database_the_kdc_uses() {
    let mut stand = stand_with(owner());
    stand
        .client
        .set_string(&kp("alice"), "note", Some("written by kadmin"))
        .expect("setstr");
    let stored = stand
        .db
        .fetch(&p("alice"))
        .expect("the database answers")
        .expect("alice is there");
    assert_eq!(
        stored.strings,
        vec![("note".to_string(), "written by kadmin".to_string())]
    );
    stand.kadmin_stand.stop();
}

/// `renprinc` over the wire: the client asks, and the principal the KDC then knows is the new one,
/// with the same password.
#[test]
fn a_stock_kadmin_client_renames_a_principal() {
    let mut stand = stand_with(owner());
    stand
        .client
        .rename_principal(&kp("alice"), &kp("alicia"))
        .expect("rename_principal must answer");

    assert!(
        stand.client.get_principal(&kp("alice")).is_err(),
        "the old name must be gone"
    );
    let renamed = stand
        .client
        .get_principal(&kp("alicia"))
        .expect("get the new name");
    assert_eq!(renamed.kvno, 1, "the keys came with the name");

    // And the KDC logs the principal in under the new name with the old password: a rename that
    // moved the name but not the keys would answer every exchange afterwards.
    let alicia = krb5::Principal::parse(&p("alicia").to_string()).unwrap();
    stand
        .kdc
        .login_with_password(&alicia, ALICE_PASSWORD)
        .expect("the renamed principal must still log in");
    stand.kadmin_stand.stop();
}

#[test]
fn a_stock_kadmin_client_changes_a_password() {
    let mut stand = stand_with(owner());
    stand
        .client
        .change_password(&kp("alice"), "a new password")
        .expect("chpass_principal must answer");

    let after = stand.client.get_principal(&kp("alice")).expect("get");
    assert_eq!(after.kvno, 2, "a password change must move the kvno");

    let alice = krb5::Principal::parse(&p("alice").to_string()).unwrap();
    stand
        .kdc
        .login_with_password(&alice, "a new password")
        .expect("the new password must work");
    stand.kadmin_stand.stop();
}

#[test]
fn a_client_without_rights_is_refused_with_a_kadm5_status() {
    // The authorization is the same `Policy` the JSON front end uses, so a
    // `kadmin` user with no rights gets MIT's AUTH_* code rather than data.
    let mut stand = stand_with(Arc::new(Grants::new()));
    let error = stand
        .client
        .get_principal(&kp("alice"))
        .expect_err("a client with no rights must be refused");
    let text = format!("{error}");
    assert!(
        text.to_lowercase().contains("privilege") || text.contains("AUTH"),
        "the refusal must name the missing privilege, got: {text}"
    );
    stand.kadmin_stand.stop();
}

#[test]
fn a_password_set_over_the_admin_protocol_is_the_one_the_kdc_accepts() {
    // The whole chain in one test: kadmind writes the keys, the KDC reads them,
    // and a third-party client logs in with the password that was set.
    let mut stand = stand_with(owner());
    stand
        .client
        .create_principal(
            &kp("carol"),
            &krb5::kadmin::PrincipalChanges::default(),
            Some("carols first password"),
        )
        .expect("create");
    stand
        .client
        .change_password(&kp("carol"), "carols second password")
        .expect("chpass");

    let carol = krb5::Principal::parse(&p("carol").to_string()).unwrap();
    stand
        .kdc
        .login_with_password(&carol, "carols second password")
        .expect("the second password must work");
    assert!(
        stand
            .kdc
            .login_with_password(&carol, "carols first password")
            .is_err(),
        "the first password must not"
    );
    stand.kadmin_stand.stop();
}

#[test]
fn a_stock_kadmin_client_randomises_keys() {
    // `cpw -randkey`: the keys are replaced with ones nobody knows, which is how a
    // service account is provisioned. The reply carries the new keys, and the kvno
    // must have moved.
    let mut stand = stand_with(owner());
    let before = stand.client.get_principal(&kp("alice")).expect("get");
    let (kvno, keys) = stand
        .client
        .randomize_keys(&kp("alice"))
        .expect("chrand_principal3 must answer");
    assert_eq!(kvno, before.kvno + 1, "new keys are a new version");
    assert!(!keys.is_empty(), "the reply must carry the keys it made");
    stand.kadmin_stand.stop();
}

#[test]
fn a_principal_created_without_a_password_gets_none_and_cannot_log_in() {
    // `addprinc -randkey` without one: the entry exists with no keys. The client
    // must be able to make it, and the KDC must refuse to issue it a ticket —
    // which is the difference between "no keys yet" and "a key of nothing".
    let mut stand = stand_with(owner());
    stand
        .client
        .create_principal(&kp("svc"), &krb5::kadmin::PrincipalChanges::default(), None)
        .expect("create without a password must answer");
    let entry = stand.client.get_principal(&kp("svc")).expect("get");
    assert_eq!(entry.kvno, 0, "no keys, no version");

    let svc = krb5::Principal::parse(&p("svc").to_string()).unwrap();
    assert!(
        stand.kdc.login_with_password(&svc, "").is_err(),
        "a keyless principal must not get a ticket"
    );
    stand.kadmin_stand.stop();
}
