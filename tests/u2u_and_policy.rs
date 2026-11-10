//! User-to-user tickets (RFC 4120 §2.9.2) and the change-password policy.
//!
//! Two things that are easy to get wrong and cheap to check:
//!
//! * A user-to-user ticket is sealed in the **session key of the server's own
//!   TGT**, which the server sent along in `additional-tickets`. The server holds
//!   no keytab — that is the whole point — so a KDC that sealed the ticket in the
//!   service's long-term key would produce a ticket that nobody can read.
//! * A request may only ask for a user-to-user ticket *for the client of that
//!   TGT*. Without that rule anybody could get a ticket for anybody sealed in a
//!   key they chose, and read it.
//!
//! The change-password half is the policy question: the default allows exactly
//! self-service, and an embedder that has a directory says who else may.

use std::sync::Arc;

use rrl_kdc::crypto::{Cipher, Enctype, Key, OwnCipher, usage};
use rrl_kdc::der;
use rrl_kdc::error::codes;
use rrl_kdc::hdb::{Hdb, HdbEntry, MemoryHdb};
use rrl_kdc::kdc::{
    ChangePolicy, Kdc, KdcConfig, SelfOnly, kpasswd::ChangeReply, kpasswd::STATUS_SUCCESS,
    kpasswd::changepw_entry,
};
use rrl_kdc::msg::{EncTicketPart, EncryptedData, Ticket, kdc_options, tkt_flags};
use rrl_kdc::name::Principal;

const REALM: &str = "EXAMPLE.COM";
const PASSWORD: &str = "correct horse battery staple";
const SERVICE: &str = "host/server.example.com";
const NOW: i64 = 1_700_000_000;

fn alice() -> Principal {
    Principal::parse(&format!("alice@{REALM}")).unwrap()
}

fn service() -> Principal {
    Principal::parse(&format!("{SERVICE}@{REALM}")).unwrap()
}

/// The realm, plus the `krbtgt` key the test needs to mint a server's TGT.
fn realm() -> (Arc<MemoryHdb>, Key) {
    let cipher = OwnCipher;
    let db = MemoryHdb::new();

    let mut krbtgt = HdbEntry::krbtgt(REALM);
    for e in [Enctype::Aes256Sha1, Enctype::Aes128Sha1] {
        krbtgt
            .add_password_key(&cipher, e, b"master-key-of-the-realm", 1)
            .unwrap();
    }
    let krbtgt_key = krbtgt.key_for(Enctype::Aes256Sha1).unwrap().key.clone();
    db.insert(krbtgt).unwrap();

    let mut alice_entry = HdbEntry::user(alice());
    for e in [Enctype::Aes256Sha1, Enctype::Aes128Sha1] {
        alice_entry
            .add_password_key(&cipher, e, PASSWORD.as_bytes(), 1)
            .unwrap();
    }
    db.insert(alice_entry).unwrap();

    let mut svc = HdbEntry::service(service());
    for e in [Enctype::Aes256Sha1, Enctype::Aes128Sha1] {
        svc.add_password_key(&cipher, e, b"the-service-key", 1)
            .unwrap();
    }
    db.insert(svc).unwrap();

    (Arc::new(db), krbtgt_key)
}

fn kdc_over(db: Arc<MemoryHdb>) -> Kdc {
    Kdc::new(
        KdcConfig::new(REALM).unwrap(),
        db as Arc<dyn Hdb>,
        Arc::new(OwnCipher),
    )
}

/// The TGT a *server* would hold: its own, for the realm, sealed with `krbtgt`.
fn server_tgt(krbtgt_key: &Key, who: &Principal) -> (Vec<u8>, Key) {
    let cipher = OwnCipher;
    let session = cipher.random(Enctype::Aes256Sha1).unwrap();
    let part = EncTicketPart {
        flags: tkt_flags::INITIAL | tkt_flags::PRE_AUTHENT,
        session_key: session.clone(),
        crealm: REALM.into(),
        cname: who.clone(),
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
        sname: Principal::krbtgt(REALM),
        enc: EncryptedData::seal(
            &cipher,
            krbtgt_key,
            usage::KDC_REP_TICKET,
            Some(1),
            &part.encode(),
        )
        .unwrap(),
    };
    (ticket.encode(), session)
}

/// A TGS request with `enc-tkt-in-skey` and `additional`, using `tgt` as the
/// evidence — built by hand, because the point is what the *server* does with a
/// request the client library would refuse to send.
fn u2u_request(tgt: &(Vec<u8>, Key), additional: &[u8], target: &Principal) -> Vec<u8> {
    let cipher = OwnCipher;
    let body = der::seq(&[
        der::field(0, der::flags32(kdc_options::ENC_TKT_IN_SKEY)),
        der::field(2, der::general_string(REALM)),
        der::field(3, target.encode_name()),
        der::field(5, der::time(NOW + 3600)),
        der::field(7, der::int(0x4242)),
        der::field(8, der::seq(&[der::int(18)])),
        der::field(11, der::seq(&[additional.to_vec()])),
    ]);
    let cksum = cipher
        .checksum(&tgt.1, usage::TGS_REQ_AUTH_CKSUM, &body)
        .unwrap();
    let auth = rrl_kdc::msg::Authenticator {
        crealm: REALM.into(),
        cname: alice(),
        cksum: Some((Enctype::Aes256Sha1.checksum_type(), cksum)),
        cusec: 0,
        ctime: NOW,
        subkey: None,
        seq_number: None,
        authorization_data: None,
    };
    let ap_req = rrl_kdc::msg::ApReq {
        ap_options: 0,
        ticket: tgt.0.clone(),
        authenticator: EncryptedData::seal(
            &cipher,
            &tgt.1,
            usage::TGS_REQ_AUTH,
            None,
            &auth.encode(),
        )
        .unwrap(),
    };
    der::cons(
        der::app(12),
        &[der::seq(&[
            der::field(1, der::int(5)),
            der::field(2, der::int(12)),
            der::field(
                3,
                rrl_kdc::msg::encode_pa_data(&[(rrl_kdc::msg::PA_TGS_REQ, ap_req.encode())]),
            ),
            der::field(4, body),
        ])],
    )
}

// ---------------------------------------------------------------------------
// U2U (RFC 4120 §2.9.2)
// ---------------------------------------------------------------------------

#[test]
fn a_user_to_user_ticket_is_sealed_in_the_servers_session_key() {
    let (db, krbtgt_key) = realm();
    let kdc = kdc_over(db);
    // The server's own TGT, which it would send to the client.
    let server_side = server_tgt(&krbtgt_key, &service());
    // The client's own TGT, which is the evidence for the request.
    let client_side = {
        let session = OwnCipher.random(Enctype::Aes256Sha1).unwrap();
        let part = EncTicketPart {
            flags: tkt_flags::INITIAL | tkt_flags::PRE_AUTHENT,
            session_key: session.clone(),
            crealm: REALM.into(),
            cname: alice(),
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
            sname: Principal::krbtgt(REALM),
            enc: EncryptedData::seal(
                &OwnCipher,
                &krbtgt_key,
                usage::KDC_REP_TICKET,
                Some(1),
                &part.encode(),
            )
            .unwrap(),
        };
        (ticket.encode(), session)
    };

    let request = u2u_request(&client_side, &server_side.0, &service());
    let reply = kdc.handle(&request, NOW);
    assert!(
        rrl_kdc::msg::KrbError::decode(&reply).is_err(),
        "a user-to-user request must be answered with a ticket"
    );

    // The ticket must open in the *server's* session key, not in any long-term
    // key: that is the whole meaning of user-to-user.
    let f = der::Fields::parse_app("TGS-REP", 13, &reply).unwrap();
    let ticket = Ticket::decode(f.bytes(5, "TGS-REP").unwrap()).unwrap();
    assert_eq!(ticket.sname, service());
    let plain = OwnCipher
        .decrypt(&server_side.1, usage::KDC_REP_TICKET, &ticket.enc.cipher)
        .expect("the ticket must decrypt in the session key of the server's TGT");
    let part = EncTicketPart::decode(&plain).unwrap();
    assert_eq!(
        part.cname,
        alice(),
        "the ticket names the client that asked for it"
    );
}

#[test]
fn a_user_to_user_ticket_does_not_open_in_the_service_key() {
    // The negative half of the one above: with the service's long-term key the
    // ticket must not decrypt, or the KDC sealed it in the wrong key and every
    // user-to-user service would still work by accident.
    let (db, krbtgt_key) = realm();
    let service_key = db
        .fetch(&service())
        .unwrap()
        .unwrap()
        .key_for(Enctype::Aes256Sha1)
        .unwrap()
        .key
        .clone();
    let kdc = kdc_over(db);
    let server_side = server_tgt(&krbtgt_key, &service());
    let client_side = server_tgt(&krbtgt_key, &alice());
    let request = u2u_request(&client_side, &server_side.0, &service());
    let reply = kdc.handle(&request, NOW);
    assert!(rrl_kdc::msg::KrbError::decode(&reply).is_err());
    let f = der::Fields::parse_app("TGS-REP", 13, &reply).unwrap();
    let ticket = Ticket::decode(f.bytes(5, "TGS-REP").unwrap()).unwrap();
    assert!(
        OwnCipher
            .decrypt(&service_key, usage::KDC_REP_TICKET, &ticket.enc.cipher)
            .is_err(),
        "a user-to-user ticket must not be readable with the service's own key"
    );
}

#[test]
fn user_to_user_for_the_wrong_principal_is_refused() {
    // The additional ticket names alice, but the ticket was asked for the
    // service: without this rule anybody could get a ticket for anybody sealed
    // in a key they chose.
    let (db, krbtgt_key) = realm();
    let kdc = kdc_over(db);
    let alices_tgt = server_tgt(&krbtgt_key, &alice());
    let client_side = server_tgt(&krbtgt_key, &alice());
    let request = u2u_request(&client_side, &alices_tgt.0, &service());
    let reply = kdc.handle(&request, NOW);
    let err = rrl_kdc::msg::KrbError::decode(&reply)
        .expect("a mismatched user-to-user request must be refused");
    assert_eq!(err.code, codes::KDC_ERR_MUST_USE_USER2USER);
}

#[test]
fn user_to_user_without_an_additional_ticket_is_badoption() {
    let (db, krbtgt_key) = realm();
    let kdc = kdc_over(db);
    let client_side = server_tgt(&krbtgt_key, &alice());
    // The same request with enc-tkt-in-skey but no [11].
    let body = der::seq(&[
        der::field(0, der::flags32(kdc_options::ENC_TKT_IN_SKEY)),
        der::field(2, der::general_string(REALM)),
        der::field(3, service().encode_name()),
        der::field(5, der::time(NOW + 3600)),
        der::field(7, der::int(1)),
        der::field(8, der::seq(&[der::int(18)])),
    ]);
    let cksum = OwnCipher
        .checksum(&client_side.1, usage::TGS_REQ_AUTH_CKSUM, &body)
        .unwrap();
    let auth = rrl_kdc::msg::Authenticator {
        crealm: REALM.into(),
        cname: alice(),
        cksum: Some((Enctype::Aes256Sha1.checksum_type(), cksum)),
        cusec: 0,
        ctime: NOW,
        subkey: None,
        seq_number: None,
        authorization_data: None,
    };
    let ap_req = rrl_kdc::msg::ApReq {
        ap_options: 0,
        ticket: client_side.0.clone(),
        authenticator: EncryptedData::seal(
            &OwnCipher,
            &client_side.1,
            usage::TGS_REQ_AUTH,
            None,
            &auth.encode(),
        )
        .unwrap(),
    };
    let request = der::cons(
        der::app(12),
        &[der::seq(&[
            der::field(1, der::int(5)),
            der::field(2, der::int(12)),
            der::field(
                3,
                rrl_kdc::msg::encode_pa_data(&[(rrl_kdc::msg::PA_TGS_REQ, ap_req.encode())]),
            ),
            der::field(4, body),
        ])],
    );
    let reply = kdc.handle(&request, NOW);
    let err = rrl_kdc::msg::KrbError::decode(&reply)
        .expect("a user-to-user request without a ticket must be refused");
    assert_eq!(err.code, codes::KDC_ERR_BADOPTION);
}

// ---------------------------------------------------------------------------
// The change-password policy
// ---------------------------------------------------------------------------

/// A policy an embedder would write: administrators may change anybody's, and
/// everybody else only their own.
#[derive(Debug)]
struct Administrators(Vec<Principal>);

impl ChangePolicy for Administrators {
    fn may_change(&self, actor: &Principal, target: &Principal) -> bool {
        actor == target || self.0.contains(actor)
    }
}

/// A realm with the change-password service, `alice`, `bob`, and `admin`.
fn realm_with_accounts() -> Arc<MemoryHdb> {
    let (db, _) = realm();
    let db = Arc::try_unwrap(db).expect("the only handle");
    for (name, password) in [("bob", "bobs password"), ("admin", "admins password")] {
        let mut entry = HdbEntry::user(Principal::parse(&format!("{name}@{REALM}")).unwrap());
        entry
            .add_password_key(&OwnCipher, Enctype::Aes256Sha1, password.as_bytes(), 1)
            .unwrap();
        db.insert(entry).unwrap();
    }
    db.insert(changepw_entry(REALM, &OwnCipher, b"the-changepw-service-key").unwrap())
        .unwrap();
    Arc::new(db)
}

#[test]
fn the_default_policy_is_self_service_only() {
    let policy = SelfOnly;
    assert!(policy.may_change(&alice(), &alice()));
    assert!(!policy.may_change(
        &alice(),
        &Principal::parse(&format!("bob@{REALM}")).unwrap()
    ));
}

#[test]
fn an_administrator_may_change_another_password() {
    // The whole point of the policy: an embedder that has a directory says who
    // the administrators are, and this crate just asks.
    let db = realm_with_accounts();
    let admin = Principal::parse(&format!("admin@{REALM}")).unwrap();
    let kdc =
        kdc_over(Arc::clone(&db)).with_change_policy(Arc::new(Administrators(vec![admin.clone()])));

    let data = rrl_kdc::msg::kpasswd::ChangePasswdData {
        new_password: b"a password an admin set".to_vec(),
        target: Some(Principal::parse(&format!("bob@{REALM}")).unwrap()),
    };
    let reply = change_through_wire(&kdc, "admin", 0xff80, &data.encode());
    assert_eq!(status_of(&reply.0, &reply.1), STATUS_SUCCESS);

    let bob = db
        .fetch(&Principal::parse(&format!("bob@{REALM}")).unwrap())
        .unwrap()
        .unwrap();
    assert_eq!(bob.kvno(), 2, "bob's key must have moved to the next kvno");
}

#[test]
fn a_non_administrator_still_may_not() {
    let db = realm_with_accounts();
    let admin = Principal::parse(&format!("admin@{REALM}")).unwrap();
    let kdc = kdc_over(Arc::clone(&db)).with_change_policy(Arc::new(Administrators(vec![admin])));
    let data = rrl_kdc::msg::kpasswd::ChangePasswdData {
        new_password: b"alice tries it".to_vec(),
        target: Some(Principal::parse(&format!("bob@{REALM}")).unwrap()),
    };
    let reply = change_through_wire(&kdc, "alice", 0xff80, &data.encode());
    assert_eq!(
        status_of(&reply.0, &reply.1),
        rrl_kdc::kdc::kpasswd::STATUS_ACCESSDENIED
    );
    let bob = db
        .fetch(&Principal::parse(&format!("bob@{REALM}")).unwrap())
        .unwrap()
        .unwrap();
    assert_eq!(bob.kvno(), 1, "a refused change must not move the kvno");
}

/// One change-password exchange assembled by hand, returning the reply and the
/// subkey it was sealed under.
fn change_through_wire(
    kdc: &Kdc,
    actor: &str,
    version: u16,
    user_data: &[u8],
) -> (ChangeReply, Key) {
    let cipher = OwnCipher;
    let session = cipher.random(Enctype::Aes256Sha1).unwrap();
    let svc = Principal::parse(&format!("kadmin/changepw@{REALM}")).unwrap();
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
        cname: Principal::parse(&format!("{actor}@{REALM}")).unwrap(),
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
    let subkey = cipher.random(Enctype::Aes256Sha1).unwrap();
    let auth = rrl_kdc::msg::Authenticator {
        crealm: REALM.into(),
        cname: Principal::parse(&format!("{actor}@{REALM}")).unwrap(),
        cksum: None,
        cusec: 0,
        ctime: NOW,
        subkey: Some(subkey.clone()),
        seq_number: Some(1),
        authorization_data: None,
    };
    let ap_req = rrl_kdc::msg::ApReq {
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
    let request =
        rrl_kdc::msg::kpasswd::seal_krb_priv(&cipher, &subkey, user_data, Some(1), NOW).unwrap();
    let reply = kdc
        .handle_kpasswd(&ap_req.encode(), &request, version, NOW)
        .unwrap_or_else(|e| panic!("the exchange must be answered: {e}"));
    (reply, subkey)
}

/// The status in a change-password reply.
fn status_of(reply: &ChangeReply, subkey: &Key) -> u16 {
    let (payload, _) =
        rrl_kdc::msg::kpasswd::open_krb_priv(&OwnCipher, subkey, &reply.priv_message)
            .expect("the reply must decrypt in the client's subkey");
    u16::from_be_bytes([payload[0], payload[1]])
}
