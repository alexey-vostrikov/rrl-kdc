//! The change-password rules, from the storage's point of view.
//!
//! The policy tests in `src/acl.rs` prove the decision. These prove the thing
//! that made "storage" worth asking for: a grant survives the process that made
//! it, lives in the same file as the principals, and a revocation takes effect
//! for the very next change rather than for the next restart.
#![cfg(feature = "hdb-redb")]

use std::sync::Arc;

use rrl_kdc::acl::{AclStore, StoredAclPolicy, Targets};
use rrl_kdc::crypto::{Cipher, Enctype, OwnCipher};
use rrl_kdc::hdb::{Hdb, HdbEntry, RedbHdb};
use rrl_kdc::kdc::{ChangePolicy, Kdc, KdcConfig, changepw_entry, kpasswd};
use rrl_kdc::name::Principal;

const REALM: &str = "EXAMPLE.COM";
const NOW: i64 = 1_700_000_000;

fn p(s: &str) -> Principal {
    Principal::parse(&format!("{s}@{REALM}")).unwrap()
}

/// A directory removed when the test ends.
struct Dir(std::path::PathBuf);

impl Dir {
    fn new(tag: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "rhk-acl-{tag}-{}-{}",
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

#[test]
fn a_grant_survives_the_process_that_made_it() {
    let dir = Dir::new("persist");
    {
        let store = RedbHdb::open(dir.file()).unwrap();
        store.grant(&p("admin"), Targets::Any).unwrap();
    }
    {
        let store = RedbHdb::open(dir.file()).unwrap();
        let rules = store.rules().unwrap();
        assert_eq!(rules.len(), 1, "the rule must outlive its writer");
        assert_eq!(rules[0].actor, p("admin"));
        assert_eq!(rules[0].targets, Targets::Any);
    }
}

#[test]
fn rules_and_principals_share_one_handle() {
    // A backup that carries the principals and not the rules restores a realm
    // where nobody may change a password, so they live in one file — and redb
    // allows one handle on it, so they live behind one object.
    let dir = Dir::new("shared");
    {
        let store = RedbHdb::open(dir.file()).unwrap();
        let mut alice = HdbEntry::user(p("alice"));
        alice
            .add_password_key(&OwnCipher, Enctype::Aes256Sha1, b"pw", 1)
            .unwrap();
        store.store(alice).unwrap();
        store.grant(&p("admin"), Targets::Only(p("alice"))).unwrap();
    }
    // Read back through one handle, as a KDC does.
    let store = RedbHdb::open(dir.file()).unwrap();
    assert!(
        store.fetch(&p("alice")).unwrap().is_some(),
        "the principal must still be there"
    );
    assert_eq!(store.rules().unwrap().len(), 1, "and so must the rule");
}

#[test]
fn a_second_handle_on_the_file_is_refused() {
    // Documentation, not a wish: redb locks the file, so a KDC must not try to
    // open the same database twice — the error is what tells an operator that
    // two processes are pointed at one database.
    let dir = Dir::new("locked");
    let _first = RedbHdb::open(dir.file()).unwrap();
    let second = RedbHdb::open(dir.file());
    assert!(
        second.is_err(),
        "a second handle on a locked database must fail, not silently share it"
    );
}

#[test]
fn a_revocation_takes_effect_for_the_next_change() {
    let dir = Dir::new("revoke");
    let acl = Arc::new(RedbHdb::open(dir.file()).unwrap());
    acl.grant(&p("admin"), Targets::Any).unwrap();
    let policy = StoredAclPolicy::new(acl.clone() as Arc<dyn AclStore>);
    let _ = &acl;
    assert!(
        policy.may_change(&p("admin"), &p("bob")),
        "the grant must work before it is withdrawn"
    );
    policy.store().revoke(&p("admin"), &Targets::Any).unwrap();
    assert!(
        !policy.may_change(&p("admin"), &p("bob")),
        "a policy that keeps a revoked rule lets somebody in after they were removed"
    );
}

#[test]
fn a_rule_from_the_file_lets_an_administrator_change_a_password_over_the_wire() {
    // The end of the chain: a rule in the database, a policy reading it, and a
    // client whose change the KDC accepts.
    let dir = Dir::new("wire");
    let store = Arc::new(RedbHdb::open(dir.file()).unwrap());
    let hdb = Arc::clone(&store);
    let cipher = OwnCipher;

    let mut krbtgt = HdbEntry::krbtgt(REALM);
    for e in [Enctype::Aes256Sha1, Enctype::Aes128Sha1] {
        krbtgt
            .add_password_key(&cipher, e, b"master-key-of-the-realm", 1)
            .unwrap();
    }
    hdb.store(krbtgt).unwrap();
    hdb.store(changepw_entry(REALM, &cipher, b"the-changepw-service-key").unwrap())
        .unwrap();
    for (name, password) in [("admin", "admins password"), ("bob", "bobs password")] {
        let mut entry = HdbEntry::user(p(name));
        entry
            .add_password_key(&cipher, Enctype::Aes256Sha1, password.as_bytes(), 1)
            .unwrap();
        hdb.store(entry).unwrap();
    }

    store.grant(&p("admin"), Targets::Any).unwrap();

    let kdc = Kdc::new(
        KdcConfig::new(REALM).unwrap(),
        Arc::clone(&store) as Arc<dyn Hdb>,
        Arc::new(cipher),
    )
    .with_change_policy(StoredAclPolicy::new(Arc::clone(&store) as Arc<dyn AclStore>).policy());

    // A change-password ticket for admin, minted by hand, since the point here is
    // the authorization rather than the exchange.
    let (reply, subkey) = exchange(&kdc, "admin", "bobs password becomes this");
    let status = status_of(&reply, &subkey);
    assert_eq!(
        status,
        kpasswd::STATUS_SUCCESS,
        "the administrator's change must be accepted"
    );
}

#[test]
fn a_client_with_no_rule_is_refused_over_the_wire() {
    let dir = Dir::new("nobody");
    let store = Arc::new(RedbHdb::open(dir.file()).unwrap());
    let hdb = Arc::clone(&store);
    let cipher = OwnCipher;
    let mut krbtgt = HdbEntry::krbtgt(REALM);
    krbtgt
        .add_password_key(&cipher, Enctype::Aes256Sha1, b"master", 1)
        .unwrap();
    hdb.store(krbtgt).unwrap();
    hdb.store(changepw_entry(REALM, &cipher, b"the-changepw-service-key").unwrap())
        .unwrap();
    for name in ["alice", "bob"] {
        let mut entry = HdbEntry::user(p(name));
        entry
            .add_password_key(&cipher, Enctype::Aes256Sha1, b"pw", 1)
            .unwrap();
        hdb.store(entry).unwrap();
    }
    // No rules at all.
    let kdc = Kdc::new(
        KdcConfig::new(REALM).unwrap(),
        Arc::clone(&store) as Arc<dyn Hdb>,
        Arc::new(cipher),
    )
    .with_change_policy(StoredAclPolicy::new(Arc::clone(&store) as Arc<dyn AclStore>).policy());

    let (reply, subkey) = exchange(&kdc, "alice", "bobs password becomes this");
    assert_eq!(status_of(&reply, &subkey), kpasswd::STATUS_ACCESSDENIED);
}

/// One change-password exchange for `bob`, built by hand.
fn exchange(
    kdc: &Kdc,
    actor: &str,
    new_password: &str,
) -> (kpasswd::ChangeReply, rrl_kdc::crypto::Key) {
    use rrl_kdc::crypto::usage;
    use rrl_kdc::msg::kpasswd::{ChangePasswdData, seal_krb_priv};
    use rrl_kdc::msg::{ApReq, Authenticator, EncTicketPart, EncryptedData, Ticket, tkt_flags};

    let cipher = OwnCipher;
    let session = cipher.random(Enctype::Aes256Sha1).unwrap();
    let service_key = cipher
        .s2k(
            Enctype::Aes256Sha1,
            b"the-changepw-service-key",
            format!("{REALM}kadminchangepw").as_bytes(),
            None,
        )
        .unwrap();
    let part = EncTicketPart {
        flags: tkt_flags::INITIAL | tkt_flags::PRE_AUTHENT,
        session_key: session.clone(),
        crealm: REALM.into(),
        cname: p(actor),
        transited_type: 0,
        transited: Vec::new(),
        authtime: NOW - 60,
        starttime: None,
        endtime: NOW + 3600,
        renew_till: None,
        caddr: None,
        authorization_data: None,
    };
    let ticket = Ticket {
        realm: REALM.into(),
        sname: Principal::parse(&format!("kadmin/changepw@{REALM}")).unwrap(),
        enc: EncryptedData::seal(
            &cipher,
            &service_key,
            usage::KDC_REP_TICKET,
            Some(1),
            &part.encode(),
        )
        .unwrap(),
    };
    let subkey = cipher.random(Enctype::Aes256Sha1).unwrap();
    let auth = Authenticator {
        crealm: REALM.into(),
        cname: p(actor),
        cksum: None,
        cusec: 0,
        ctime: NOW,
        subkey: Some(subkey.clone()),
        seq_number: Some(1),
        authorization_data: None,
    };
    let ap_req = ApReq {
        ap_options: 0,
        ticket: ticket.encode(),
        authenticator: EncryptedData::seal(
            &cipher,
            &session,
            usage::AP_REQ_AUTH,
            None,
            &auth.encode(),
        )
        .unwrap(),
    };
    let data = ChangePasswdData {
        new_password: new_password.as_bytes().to_vec(),
        target: Some(p("bob")),
    };
    let request = seal_krb_priv(&cipher, &subkey, &data.encode(), Some(1), NOW).unwrap();
    let reply = kdc
        .handle_kpasswd(&ap_req.encode(), &request, kpasswd::VERSION_SET, NOW)
        .unwrap_or_else(|e| panic!("the exchange must be answered: {e}"));
    (reply, subkey)
}

fn status_of(reply: &kpasswd::ChangeReply, subkey: &rrl_kdc::crypto::Key) -> u16 {
    let (payload, _) =
        rrl_kdc::msg::kpasswd::open_krb_priv(&OwnCipher, subkey, &reply.priv_message)
            .expect("the reply must decrypt in the client's subkey");
    u16::from_be_bytes([payload[0], payload[1]])
}
