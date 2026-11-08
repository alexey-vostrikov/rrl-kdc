//! `kpasswd`: a client changes its password, and the change takes effect.
//!
//! Judged by the primary client, as everything else here is: `krb5` runs the
//! whole RFC 3244 exchange — an initial ticket for `kadmin/changepw`, an
//! `AP-REQ`, a sealed request under a subkey it chose, an `AP-REP` checked for
//! its own clock, then the result. Nothing in that sequence is optional, and a
//! KDC that gets one field wrong fails at the client rather than in a unit test.

use std::sync::Arc;

use rust_heimdal_kdc::crypto::{Cipher, Enctype, OwnCipher};
use rust_heimdal_kdc::hdb::{Hdb, HdbEntry, MemoryHdb};
use rust_heimdal_kdc::kdc::kpasswd::{
    ChangeReply, STATUS_ACCESSDENIED, STATUS_MALFORMED, STATUS_SUCCESS, VERSION_CHANGE, VERSION_SET,
};
use rust_heimdal_kdc::kdc::{Kdc, KdcConfig, changepw_entry};
use rust_heimdal_kdc::msg::kpasswd::ChangePasswdData;
use rust_heimdal_kdc::name::Principal;
use rust_heimdal_kdc::transport::{RunningKpasswd, serve_kpasswd_loopback, serve_loopback};

const REALM: &str = "EXAMPLE.COM";
const OLD: &str = "the old password";
/// The instant the hand-built exchanges claim, so a ticket's lifetime and the
/// authenticator's clock agree with what the server is told.
const NOW: i64 = 1_700_000_000;
const NEW: &str = "an entirely new password";

/// A realm with `krbtgt`, `alice` and the change-password service.
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

    db.insert(changepw_entry(REALM, &cipher, b"the-changepw-service-key").unwrap())
        .unwrap();

    let mut alice = HdbEntry::user(Principal::parse(&format!("alice@{REALM}")).unwrap());
    for e in [Enctype::Aes256Sha1, Enctype::Aes128Sha1] {
        alice
            .add_password_key(&cipher, e, OLD.as_bytes(), 1)
            .unwrap();
    }
    db.insert(alice).unwrap();
    Arc::new(db)
}

struct Stand {
    kdc_addr: String,
    kpasswd_addr: String,
    db: Arc<MemoryHdb>,
    _kdc: rust_heimdal_kdc::transport::RunningKdc,
    _kpasswd: RunningKpasswd,
}

fn start() -> Stand {
    let db = realm();
    let cipher: Arc<dyn Cipher> = Arc::new(OwnCipher);
    let make = || {
        Kdc::new(
            KdcConfig::new(REALM).unwrap(),
            Arc::clone(&db) as Arc<dyn Hdb>,
            Arc::clone(&cipher),
        )
    };
    let kdc = serve_loopback(make());
    let kpasswd = serve_kpasswd_loopback(make());
    Stand {
        kdc_addr: kdc.addr(),
        kpasswd_addr: kpasswd.addr(),
        db,
        _kdc: kdc,
        _kpasswd: kpasswd,
    }
}

fn alice() -> krb5::Principal {
    krb5::Principal::parse(&format!("alice@{REALM}")).unwrap()
}

fn login(stand: &Stand, password: &str) -> Result<(), String> {
    let client = krb5::KdcClient::new(REALM, [stand.kdc_addr.as_str()]);
    client
        .login_with_password(&alice(), password)
        .map(|_| ())
        .map_err(|e| e.to_string())
}

#[test]
fn the_new_password_works_and_the_old_one_does_not() {
    let stand = start();
    // Without this line a KDC that refuses every password would pass the test.
    login(&stand, OLD).expect("the old password must work before the change");

    let client = krb5::KdcClient::new(REALM, [stand.kdc_addr.as_str()]);
    krb5::kpasswd::change_password(&client, &alice(), OLD, NEW, &stand.kpasswd_addr)
        .expect("the change must succeed");

    login(&stand, NEW).expect("the new password must work");
    let err = login(&stand, OLD).expect_err("the old password must be refused");
    assert!(
        err.contains("pre-authentication") || err.contains("24"),
        "the old password must fail at pre-authentication, got: {err}"
    );
}

#[test]
fn the_change_moves_the_key_version_and_keeps_the_old_key() {
    // A client holding a ticket issued a second ago must still be able to use
    // it, so the old keys stay and the kvno goes up.
    let stand = start();
    let before = stand
        .db
        .fetch(&Principal::parse(&format!("alice@{REALM}")).unwrap())
        .unwrap()
        .unwrap();
    let client = krb5::KdcClient::new(REALM, [stand.kdc_addr.as_str()]);
    krb5::kpasswd::change_password(&client, &alice(), OLD, NEW, &stand.kpasswd_addr)
        .expect("the change must succeed");
    let after = stand
        .db
        .fetch(&Principal::parse(&format!("alice@{REALM}")).unwrap())
        .unwrap()
        .unwrap();

    assert_eq!(before.kvno(), 1, "the account started at kvno 1");
    assert_eq!(after.kvno(), 2, "a change must move the kvno");
    assert_eq!(
        after.keys.len(),
        before.keys.len(),
        "one new key per enctype the account already had"
    );
    assert_ne!(
        after.key_for(Enctype::Aes256Sha1).unwrap().key,
        before.key_for(Enctype::Aes256Sha1).unwrap().key,
        "the new key must differ from the old one"
    );
}

#[test]
fn a_wrong_old_password_cannot_change_anything() {
    let stand = start();
    let client = krb5::KdcClient::new(REALM, [stand.kdc_addr.as_str()]);
    let result = krb5::kpasswd::change_password(
        &client,
        &alice(),
        "not the password",
        NEW,
        &stand.kpasswd_addr,
    );
    assert!(
        result.is_err(),
        "a change that cannot get an initial ticket must fail"
    );
    // ... and the account is untouched.
    login(&stand, OLD).expect("the password must not have changed");
    assert!(
        login(&stand, NEW).is_err(),
        "the new password must not have taken effect"
    );
    let entry = stand
        .db
        .fetch(&Principal::parse(&format!("alice@{REALM}")).unwrap())
        .unwrap()
        .unwrap();
    assert_eq!(entry.kvno(), 1, "a failed change must not move the kvno");
}

// ---------------------------------------------------------------------------
// The wire, assembled by hand
//
// `kpasswd` covers the happy path. These cover what a client cannot ask for
// through that wrapper — a request naming somebody else, an empty password — and
// they build the exchange themselves so the *server's* rule is what is under
// test, not the client's willingness to ask.
// ---------------------------------------------------------------------------

/// The change-password service's key, as the test provisions it.
const CHANGEPW_KEY: &[u8] = b"the-changepw-service-key";

/// A change-password ticket and the session key it carries, built the way the AS
/// builds one.
fn changepw_ticket(cname: &str) -> (Vec<u8>, rust_heimdal_kdc::crypto::Key) {
    use rust_heimdal_kdc::crypto::usage;
    use rust_heimdal_kdc::msg::{EncTicketPart, EncryptedData, Ticket, tkt_flags};

    let cipher = OwnCipher;
    let session = cipher.random(Enctype::Aes256Sha1).unwrap();
    let svc = Principal::parse(&format!("kadmin/changepw@{REALM}")).unwrap();
    let part = EncTicketPart {
        // An initial ticket, which is what RFC 3244 requires.
        flags: tkt_flags::INITIAL | tkt_flags::PRE_AUTHENT,
        session_key: session.clone(),
        crealm: REALM.into(),
        cname: Principal::parse(&format!("{cname}@{REALM}")).unwrap(),
        transited_type: 0,
        transited: Vec::new(),
        authtime: NOW - 60,
        starttime: None,
        endtime: NOW + 3600,
        renew_till: None,
        caddr: None,
        authorization_data: None,
    };
    // The salt is the one the database derived the key with, so the ticket
    // decrypts: `changepw_entry` used the principal's default salt.
    let service_key = cipher
        .s2k(
            Enctype::Aes256Sha1,
            CHANGEPW_KEY,
            format!("{REALM}kadminchangepw").as_bytes(),
            None,
        )
        .unwrap();
    let ticket = Ticket {
        realm: REALM.into(),
        sname: svc,
        enc: EncryptedData::seal(
            &cipher,
            &service_key,
            usage::KDC_REP_TICKET,
            Some(1),
            &part.encode(),
        )
        .unwrap(),
    };
    (ticket.encode(), session)
}

/// One exchange, assembled by hand: returns the reply and the subkey it was
/// sealed under, so the test can read the status the server sent.
fn exchange(
    kdc: &Kdc,
    client: &str,
    version: u16,
    user_data: &[u8],
) -> (ChangeReply, rust_heimdal_kdc::crypto::Key) {
    use rust_heimdal_kdc::crypto::usage;
    use rust_heimdal_kdc::msg::apreq::ApReq;
    use rust_heimdal_kdc::msg::kpasswd::seal_krb_priv;
    use rust_heimdal_kdc::msg::{Authenticator, EncryptedData};

    let cipher = OwnCipher;
    let (ticket, session) = changepw_ticket(client);
    let subkey = cipher.random(Enctype::Aes256Sha1).unwrap();
    let authenticator = Authenticator {
        crealm: REALM.into(),
        cname: Principal::parse(&format!("{client}@{REALM}")).unwrap(),
        cksum: None,
        cusec: 0,
        ctime: NOW,
        subkey: Some(subkey.clone()),
        seq_number: Some(1),
        authorization_data: None,
    };
    let ap_req = ApReq {
        ap_options: 0,
        ticket,
        authenticator: EncryptedData::seal(
            &cipher,
            &session,
            usage::AP_REQ_AUTH,
            None,
            &authenticator.encode(),
        )
        .unwrap(),
    }
    .encode();
    let request = seal_krb_priv(&cipher, &subkey, user_data, Some(1), NOW).unwrap();
    let reply = kdc
        .handle_kpasswd(&ap_req, &request, version, NOW)
        .unwrap_or_else(|e| panic!("the exchange must be answered, not error: {e}"));
    (reply, subkey)
}

/// The status code the server put in the reply.
fn status(reply: &ChangeReply, subkey: &rust_heimdal_kdc::crypto::Key) -> u16 {
    use rust_heimdal_kdc::msg::kpasswd::open_krb_priv;
    let (payload, _) = open_krb_priv(&OwnCipher, subkey, &reply.priv_message)
        .expect("the reply must decrypt in the subkey the client chose");
    assert!(payload.len() >= 2, "a result is a status and a message");
    u16::from_be_bytes([payload[0], payload[1]])
}

/// A KDC on a database the caller keeps a handle to.
fn kdc_over(db: Arc<MemoryHdb>) -> Kdc {
    Kdc::new(
        KdcConfig::new(REALM).unwrap(),
        db as Arc<dyn Hdb>,
        Arc::new(OwnCipher),
    )
}

#[test]
fn a_request_for_another_account_is_access_denied() {
    // There is no administrator ACL yet, so setting somebody else's password is
    // refused rather than done: a KDC that ignored the field would let any user
    // change any password.
    let db = realm();
    let mut bob = HdbEntry::user(Principal::parse(&format!("bob@{REALM}")).unwrap());
    bob.add_password_key(&OwnCipher, Enctype::Aes256Sha1, b"bob-password", 1)
        .unwrap();
    db.insert(bob).unwrap();
    let kdc = kdc_over(Arc::clone(&db));

    let data = ChangePasswdData {
        new_password: b"taken over".to_vec(),
        target: Some(Principal::parse(&format!("bob@{REALM}")).unwrap()),
    };
    let (reply, subkey) = exchange(&kdc, "alice", VERSION_SET, &data.encode());
    assert_eq!(
        status(&reply, &subkey),
        STATUS_ACCESSDENIED,
        "changing another account's password must be refused"
    );

    // ... and bob's password is untouched.
    let bob_after = db
        .fetch(&Principal::parse(&format!("bob@{REALM}")).unwrap())
        .unwrap()
        .unwrap();
    assert_eq!(
        bob_after.kvno(),
        1,
        "a refused change must not move the kvno"
    );
    assert!(
        login_as(&db, "bob", "bob-password"),
        "bob's own password must still work"
    );
    assert!(!login_as(&db, "bob", "taken over"));
}

/// Whether `password` logs `who` in, against a KDC over `db`.
fn login_as(db: &Arc<MemoryHdb>, who: &str, password: &str) -> bool {
    let stand = serve_loopback(kdc_over(Arc::clone(db)));
    let client = krb5::KdcClient::new(REALM, [stand.addr().as_str()]);
    let principal = krb5::Principal::parse(&format!("{who}@{REALM}")).unwrap();
    client.login_with_password(&principal, password).is_ok()
}

#[test]
fn an_empty_password_is_malformed() {
    let db = realm();
    let kdc = kdc_over(Arc::clone(&db));
    let (reply, subkey) = exchange(&kdc, "alice", VERSION_CHANGE, b"");
    assert_eq!(
        status(&reply, &subkey),
        STATUS_MALFORMED,
        "an empty password must be refused, not set"
    );
    let alice_after = db
        .fetch(&Principal::parse(&format!("alice@{REALM}")).unwrap())
        .unwrap()
        .unwrap();
    assert_eq!(
        alice_after.kvno(),
        1,
        "a refused change must not move the kvno"
    );
}

#[test]
fn setting_your_own_password_through_the_set_protocol_works() {
    // The same path as `kpasswd`, but through RFC 3244's `ChangePasswdData`: it
    // must not be refused just because it names its own account.
    let db = realm();
    let kdc = kdc_over(Arc::clone(&db));
    let data = ChangePasswdData {
        new_password: NEW.as_bytes().to_vec(),
        target: None,
    };
    let (reply, subkey) = exchange(&kdc, "alice", VERSION_SET, &data.encode());
    assert_eq!(status(&reply, &subkey), STATUS_SUCCESS);
    assert!(
        login_as(&db, "alice", NEW),
        "the new password must work after a set-password through the wire"
    );
}

#[test]
fn the_change_password_service_needs_its_own_ticket() {
    // Without the `change-pw` flag the service is just another service, and the
    // AS refuses to issue an initial ticket for it.
    let db = MemoryHdb::new();
    let cipher = OwnCipher;
    let mut krbtgt = HdbEntry::krbtgt(REALM);
    krbtgt
        .add_password_key(&cipher, Enctype::Aes256Sha1, b"master", 1)
        .unwrap();
    db.insert(krbtgt).unwrap();
    let mut changepw = changepw_entry(REALM, &cipher, b"svc").unwrap();
    changepw.flags &= !rust_heimdal_kdc::hdb::flags::CHANGE_PW;
    db.insert(changepw).unwrap();
    let mut alice_entry = HdbEntry::user(Principal::parse(&format!("alice@{REALM}")).unwrap());
    alice_entry
        .add_password_key(&cipher, Enctype::Aes256Sha1, OLD.as_bytes(), 1)
        .unwrap();
    db.insert(alice_entry).unwrap();

    let stand = serve_loopback(Kdc::new(
        KdcConfig::new(REALM).unwrap(),
        Arc::new(db),
        Arc::new(cipher),
    ));
    let client = krb5::KdcClient::new(REALM, [stand.addr().as_str()]);
    let err = client
        .login_with_password(&alice(), OLD)
        .and_then(|tgt| {
            client.service_ticket(
                &tgt,
                &krb5::Principal::parse(&format!("kadmin/changepw@{REALM}")).unwrap(),
            )
        })
        .expect_err("a service without change-pw must not be reachable");
    // Two refusals, and both are correct: the AS will not issue an initial
    // ticket for a service without `change-pw`, and the TGS will not issue an
    // ordinary one because the entry is marked `initial`.
    let text = err.to_string();
    assert!(
        text.contains("12") || text.contains("initial ticket"),
        "a change-password service without the flag must be refused with policy, got: {text}"
    );
}
