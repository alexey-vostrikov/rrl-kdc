//! S4U2Self (MS-SFU §3.1): a service asking for a ticket in somebody else's name.
//!
//! The exchange is built by hand, as in `forward_proxy.rs`: a stock client does not ask for a
//! protocol transition unless its administrator configured it, and the cases that matter here
//! are the refusals — a service asking for a ticket to *another* service, a checksum that does
//! not verify, a user that does not exist. Each is a rule that, if it were missing, would let
//! any service with a TGT mint tickets for the whole realm.
//!
//! The ticket is decrypted with the service's own key and its client compared, because a KDC
//! that answered with the right `crealm` and the wrong `cname` would look correct in the reply
//! and be useless to the service.

use std::sync::Arc;

use rust_kdc::crypto::{Cipher, Enctype, Key, OwnCipher, usage};
use rust_kdc::der;
use rust_kdc::error::codes;
use rust_kdc::hdb::{HdbEntry, MemoryHdb, flags as entry_flags};
use rust_kdc::kdc::s4u;
use rust_kdc::kdc::{Kdc, KdcConfig};
use rust_kdc::msg::{
    self, ApReq, Authenticator, EncKdcRepPart, EncTicketPart, EncryptedData, Ticket,
    encode_pa_data, kdc_options, tkt_flags,
};
use rust_kdc::name::Principal;

const REALM: &str = "EXAMPLE.COM";
const SERVICE: &str = "svc/host.example.com";
const NOW: i64 = 1_700_000_000;

fn alice() -> Principal {
    Principal::parse(&format!("alice@{REALM}")).unwrap()
}

fn bob() -> Principal {
    Principal::parse(&format!("bob@{REALM}")).unwrap()
}

fn service() -> Principal {
    Principal::parse(&format!("{SERVICE}@{REALM}")).unwrap()
}

/// What the test can vary about the realm it builds.
#[derive(Default)]
struct Knobs {
    /// Mark the service `trusted-for-delegation`.
    trusted: bool,
    /// Mark the impersonated user `forwardable`.
    user_forwardable: bool,
    /// Leave `bob` out of the database.
    no_bob: bool,
}

fn realm(knobs: Knobs) -> (MemoryHdb, Key, Key) {
    let cipher = OwnCipher;
    let db = MemoryHdb::new();

    let mut krbtgt = HdbEntry::krbtgt(REALM);
    let krbtgt_key = cipher.random(Enctype::Aes256Sha1).unwrap();
    krbtgt.add_key(krbtgt_key.clone(), 1, None);
    db.insert(krbtgt).unwrap();

    let mut user = HdbEntry::user(alice());
    user.add_password_key(&cipher, Enctype::Aes256Sha1, b"password", 1)
        .unwrap();
    if knobs.user_forwardable {
        user.flags |= entry_flags::FORWARDABLE;
    }
    db.insert(user).unwrap();

    if !knobs.no_bob {
        let mut second = HdbEntry::user(bob());
        second
            .add_password_key(&cipher, Enctype::Aes256Sha1, b"password", 1)
            .unwrap();
        db.insert(second).unwrap();
    }

    // A second service that exists: the refusal in `a_service_cannot_ask...` has to come from
    // the S4U rule, not from a name this realm does not hold.
    let mut elsewhere =
        HdbEntry::service(Principal::parse(&format!("host/elsewhere@{REALM}")).unwrap());
    elsewhere
        .add_password_key(&cipher, Enctype::Aes256Sha1, b"key", 1)
        .unwrap();
    db.insert(elsewhere).unwrap();

    let mut svc = HdbEntry::service(service());
    let svc_key = cipher.random(Enctype::Aes256Sha1).unwrap();
    svc.add_key(svc_key.clone(), 1, None);
    if knobs.trusted {
        svc.flags |= entry_flags::TRUSTED_FOR_DELEGATION;
    }
    db.insert(svc).unwrap();

    (db, krbtgt_key, svc_key)
}

fn kdc(knobs: Knobs) -> (Kdc, Key, Key) {
    let (db, krbtgt_key, svc_key) = realm(knobs);
    (
        Kdc::new(
            KdcConfig::new(REALM).unwrap().with_require_preauth(false),
            Arc::new(db),
            Arc::new(OwnCipher),
        ),
        krbtgt_key,
        svc_key,
    )
}

/// A TGT belonging to the *service*, which is who may ask for a protocol transition.
fn service_tgt(krbtgt_key: &Key) -> (Vec<u8>, Key) {
    let cipher = OwnCipher;
    let session_key = cipher.random(Enctype::Aes256Sha1).unwrap();
    let part = EncTicketPart {
        flags: tkt_flags::INITIAL | tkt_flags::PRE_AUTHENT | tkt_flags::FORWARDABLE,
        session_key: session_key.clone(),
        crealm: REALM.into(),
        cname: service(),
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
    (ticket.encode(), session_key)
}

/// `PA-FOR-USER` naming `user`, checksummed the way a client does.
fn for_user(user: &Principal, tgt_session_key: &Key) -> Vec<u8> {
    let probe = s4u::ForUser {
        user: user.clone(),
        auth: "Kerberos".into(),
        checksum: Vec::new(),
    };
    let sum = s4u::hmac_md5_checksum(tgt_session_key.bytes(), 17, &probe.checksummed());
    der::seq(&[
        der::field(0, user.encode_name()),
        der::field(1, der::general_string(&user.realm)),
        der::field(
            2,
            der::seq(&[
                der::field(0, der::int(-138)),
                der::field(1, der::octets(&sum)),
            ]),
        ),
        der::field(3, der::general_string("Kerberos")),
    ])
}

/// `PA-S4U-X509-USER` for `user`, checksummed with the authenticator's subkey at usage 26.
fn x509_user(user: &Principal, nonce: u32, subkey: &Key, ask_reply_usage: bool) -> Vec<u8> {
    let options = if ask_reply_usage { 0x2000_0000u32 } else { 0 };
    let id = der::seq(&[
        der::field(0, der::int(nonce as i64)),
        der::field(1, user.encode_name()),
        der::field(2, der::general_string(&user.realm)),
        der::field(4, der::flags32(options)),
    ]);
    let sum = OwnCipher.checksum(subkey, 26, &id).unwrap();
    let checksum = der::seq(&[
        der::field(0, der::int(Enctype::Aes256Sha1.checksum_type() as i64)),
        der::field(1, der::octets(&sum)),
    ]);
    der::seq(&[der::field(0, id), der::field(1, checksum)])
}

/// A `TGS-REQ` for `target`, carrying `padata` alongside the `PA-TGS-REQ`.
fn tgs_req(
    ticket: &[u8],
    session_key: &Key,
    target: &Principal,
    options: u32,
    extra: &[(i32, Vec<u8>)],
) -> Vec<u8> {
    tgs_req_with_subkey(ticket, session_key, target, options, None, extra)
}

/// The same, with a subkey in the authenticator — which is what an S4U client sends, because
/// `PA-S4U-X509-USER` is checksummed with it.
fn tgs_req_with_subkey(
    ticket: &[u8],
    session_key: &Key,
    target: &Principal,
    options: u32,
    subkey: Option<&Key>,
    extra: &[(i32, Vec<u8>)],
) -> Vec<u8> {
    let cipher = OwnCipher;
    let body = der::seq(&[
        der::field(0, der::flags32(options)),
        der::field(2, der::general_string(REALM)),
        der::field(3, target.encode_name()),
        der::field(5, der::time(NOW + 3600)),
        der::field(7, der::int(0x4242)),
        der::field(8, der::seq(&[der::int(18)])),
    ]);

    let cksum = cipher
        .checksum(session_key, usage::TGS_REQ_AUTH_CKSUM, &body)
        .unwrap();
    let authenticator = Authenticator {
        crealm: REALM.into(),
        cname: service(),
        cksum: Some((Enctype::Aes256Sha1.checksum_type(), cksum)),
        cusec: 0,
        ctime: NOW,
        subkey: subkey.cloned(),
        seq_number: None,
        authorization_data: None,
    };
    let ap_req = ApReq {
        ap_options: 0,
        ticket: ticket.to_vec(),
        authenticator: EncryptedData::seal(
            &cipher,
            session_key,
            usage::TGS_REQ_AUTH,
            None,
            &authenticator.encode(),
        )
        .unwrap(),
    }
    .encode();

    let mut padata = vec![(msg::PA_TGS_REQ, ap_req)];
    padata.extend_from_slice(extra);
    der::cons(
        der::app(12),
        &[der::seq(&[
            der::field(1, der::int(5)),
            der::field(2, der::int(12)),
            der::field(3, encode_pa_data(&padata)),
            der::field(4, body),
        ])],
    )
}

/// The `EncTicketPart` of the ticket in a `TGS-REP`, opened with `key`.
fn ticket_part(reply: &[u8], key: &Key) -> EncTicketPart {
    let f = der::Fields::parse_app("TGS-REP", 13, reply).expect("a TGS-REP");
    let ticket = Ticket::decode(f.get(5, "TGS-REP").expect("the ticket")).expect("a Ticket");
    let plain = OwnCipher
        .decrypt(key, usage::KDC_REP_TICKET, &ticket.enc.cipher)
        .expect("the ticket opens with the service key");
    EncTicketPart::decode(&plain).expect("an EncTicketPart")
}

fn reply_padata(reply: &[u8]) -> Vec<(i32, Vec<u8>)> {
    let f = der::Fields::parse_app("TGS-REP", 13, reply).expect("a TGS-REP");
    match f.opt(2) {
        None => Vec::new(),
        Some(raw) => {
            let mut r = der::Reader::new(raw);
            let seq = r.next("PA-DATA").expect("a SEQUENCE");
            msg::decode_pa_data("TGS-REP", seq.content).expect("PA-DATA")
        }
    }
}

#[test]
fn a_service_can_ask_for_a_ticket_in_a_users_name() {
    // The whole point: the service holds a TGT for itself, names `alice`, and receives a
    // ticket whose client is `alice` and whose PAC is hers.
    let (kdc, krbtgt_key, svc_key) = kdc(Knobs::default());
    let (tgt, session) = service_tgt(&krbtgt_key);
    let request = tgs_req(
        &tgt,
        &session,
        &service(),
        0,
        &[(s4u::PA_FOR_USER, for_user(&alice(), &session))],
    );
    let reply = kdc.handle(&request, NOW);
    assert!(
        msg::KrbError::decode(&reply).is_err(),
        "a well-formed transition must be answered: {:?}",
        msg::KrbError::decode(&reply)
    );

    let part = ticket_part(&reply, &svc_key);
    assert_eq!(
        part.cname.components,
        vec!["alice"],
        "the ticket names the user"
    );
    assert_eq!(part.crealm, REALM);

    // And the reply states the same name in the clear, which is what a client compares.
    let f = der::Fields::parse_app("TGS-REP", 13, &reply).unwrap();
    let mut r = der::Reader::new(f.get(4, "TGS-REP").expect("cname"));
    let seq = r.next("cname").unwrap();
    let named = Principal::decode("cname", seq.content, REALM).unwrap();
    assert_eq!(named.components, vec!["alice"]);
}

#[test]
fn a_service_that_is_not_trusted_for_delegation_gets_no_forwardable_ticket() {
    // MS-SFU §3.1.4. Without this, every service with a TGT could hand the ticket on as
    // S4U2Proxy evidence for a user it was never allowed to delegate.
    let (kdc, krbtgt_key, svc_key) = kdc(Knobs {
        user_forwardable: true,
        ..Default::default()
    });
    let (tgt, session) = service_tgt(&krbtgt_key);
    // `forwardable` is asked for, and cleared: the request may want it, the KDC decides.
    let request = tgs_req(
        &tgt,
        &session,
        &service(),
        kdc_options::FORWARDABLE,
        &[(s4u::PA_FOR_USER, for_user(&alice(), &session))],
    );
    let reply = kdc.handle(&request, NOW);
    assert!(msg::KrbError::decode(&reply).is_err());

    let part = ticket_part(&reply, &svc_key);
    assert!(
        part.flags & tkt_flags::FORWARDABLE == 0,
        "a service that is not trusted for delegation must not receive a forwardable ticket: \
         {:#010x}",
        part.flags
    );
}

#[test]
fn a_trusted_service_with_a_forwardable_user_gets_a_forwardable_ticket() {
    // The pair to the test above: the flag survives when both halves allow it, so the
    // clearing is a decision rather than "S4U tickets are never forwardable".
    let (kdc, krbtgt_key, svc_key) = kdc(Knobs {
        trusted: true,
        user_forwardable: true,
        ..Default::default()
    });
    let (tgt, session) = service_tgt(&krbtgt_key);
    let request = tgs_req(
        &tgt,
        &session,
        &service(),
        kdc_options::FORWARDABLE,
        &[(s4u::PA_FOR_USER, for_user(&alice(), &session))],
    );
    let reply = kdc.handle(&request, NOW);
    assert!(msg::KrbError::decode(&reply).is_err());

    let part = ticket_part(&reply, &svc_key);
    assert!(
        part.flags & tkt_flags::FORWARDABLE != 0,
        "trusted service and forwardable user: {:#010x}",
        part.flags
    );
}

#[test]
fn a_service_cannot_ask_for_a_ticket_in_a_users_name_to_another_service() {
    // Without this rule any service could mint tickets for any other service in the realm,
    // which is the whole of Kerberos's authorization in one request.
    let (kdc, krbtgt_key, _) = kdc(Knobs::default());
    let (tgt, session) = service_tgt(&krbtgt_key);
    let target = Principal::parse(&format!("host/elsewhere@{REALM}")).unwrap();
    let request = tgs_req(
        &tgt,
        &session,
        &target,
        0,
        &[(s4u::PA_FOR_USER, for_user(&alice(), &session))],
    );
    let reply = kdc.handle(&request, NOW);
    let err = msg::KrbError::decode(&reply).expect("a refusal");
    assert_eq!(err.code, codes::KDC_ERR_BADOPTION);
    let text = err.e_text.unwrap_or_default();
    assert!(
        text.contains("own name"),
        "the refusal must say the ticket has to be to the service itself: {text}"
    );
}

#[test]
fn a_checksum_from_another_key_is_refused() {
    // The claim is only worth what its key proves. A service that copied a checksum out of
    // another exchange, or guessed one, must not get a ticket.
    let (kdc, krbtgt_key, _) = kdc(Knobs::default());
    let (tgt, session) = service_tgt(&krbtgt_key);
    let other = OwnCipher.random(Enctype::Aes256Sha1).unwrap();
    let request = tgs_req(
        &tgt,
        &session,
        &service(),
        0,
        &[(s4u::PA_FOR_USER, for_user(&alice(), &other))],
    );
    let reply = kdc.handle(&request, NOW);
    let err = msg::KrbError::decode(&reply).expect("a refusal");
    assert_eq!(err.code, codes::KRB_AP_ERR_BAD_INTEGRITY);
}

#[test]
fn a_user_that_is_not_in_this_realm_is_refused_by_name() {
    // Impersonating an account that does not exist would mint a ticket nobody can check, and
    // the PAC would have no groups to put in it.
    let (kdc, krbtgt_key, _) = kdc(Knobs {
        no_bob: true,
        ..Default::default()
    });
    let (tgt, session) = service_tgt(&krbtgt_key);
    let request = tgs_req(
        &tgt,
        &session,
        &service(),
        0,
        &[(s4u::PA_FOR_USER, for_user(&bob(), &session))],
    );
    let reply = kdc.handle(&request, NOW);
    let err = msg::KrbError::decode(&reply).expect("a refusal");
    assert_eq!(err.code, codes::KDC_ERR_C_PRINCIPAL_UNKNOWN);
}

#[test]
fn an_ordinary_request_carries_no_s4u_padata_back() {
    // The refusal to answer is not enough: an ordinary request must also not receive
    // PA-S4U-X509-USER, or a client would read a claim nobody made.
    let (kdc, krbtgt_key, svc_key) = kdc(Knobs::default());
    let (tgt, session) = service_tgt(&krbtgt_key);
    let request = tgs_req(&tgt, &session, &service(), 0, &[]);
    let reply = kdc.handle(&request, NOW);
    assert!(msg::KrbError::decode(&reply).is_err());

    assert!(
        !reply_padata(&reply)
            .iter()
            .any(|(t, _)| *t == s4u::PA_S4U_X509_USER),
        "an ordinary request must not be answered with an S4U claim"
    );
    // And the ticket is the service's own, as before.
    let part = ticket_part(&reply, &svc_key);
    assert_eq!(part.cname.components, vec!["svc", "host.example.com"]);
}

#[test]
fn the_reply_enc_part_names_the_impersonated_user() {
    // A client compares the reply's `cname` with the one it asked to act for; a reply naming
    // the service would be refused as modified even though the ticket were correct.
    let (kdc, krbtgt_key, _) = kdc(Knobs::default());
    let (tgt, session) = service_tgt(&krbtgt_key);
    let request = tgs_req(
        &tgt,
        &session,
        &service(),
        0,
        &[(s4u::PA_FOR_USER, for_user(&alice(), &session))],
    );
    let reply = kdc.handle(&request, NOW);
    assert!(msg::KrbError::decode(&reply).is_err());

    let f = der::Fields::parse_app("TGS-REP", 13, &reply).unwrap();
    let enc = EncryptedData::decode("enc-part", f.get(6, "TGS-REP").expect("enc-part")).unwrap();
    // The reply part is sealed in the TGT session key, which the test holds.
    let plain = OwnCipher
        .decrypt(&session, usage::TGS_REP_ENCPART_SESSKEY, &enc.cipher)
        .expect("the reply opens with the TGT's session key");
    let rep = EncKdcRepPart::decode(&plain).expect("an EncTGSRepPart");
    assert_eq!(
        rep.sname.components,
        vec!["svc", "host.example.com"],
        "the service is the one asked for"
    );
}

#[test]
fn the_reply_echos_the_s4u_user_id_checksummed_with_the_subkey() {
    // MIT's client verifies this checksum and refuses a correct ticket as modified without it.
    // It also reads the usage from the `options` bit: asking for usage 27 and receiving 26 is
    // exactly the mistake that makes that client report KRB5_KDCREP_MODIFIED.
    let (kdc, krbtgt_key, svc_key) = kdc(Knobs::default());
    let (tgt, session) = service_tgt(&krbtgt_key);
    let subkey = OwnCipher.random(Enctype::Aes256Sha1).unwrap();
    let request = tgs_req_with_subkey(
        &tgt,
        &session,
        &service(),
        0,
        Some(&subkey),
        &[
            (s4u::PA_FOR_USER, for_user(&alice(), &session)),
            (
                s4u::PA_S4U_X509_USER,
                x509_user(&alice(), 0x4242, &subkey, true),
            ),
        ],
    );
    let reply = kdc.handle(&request, NOW);
    assert!(
        msg::KrbError::decode(&reply).is_err(),
        "the two halves name the same user and must be answered: {:?}",
        msg::KrbError::decode(&reply)
    );

    let value = reply_padata(&reply)
        .into_iter()
        .find(|(t, _)| *t == s4u::PA_S4U_X509_USER)
        .map(|(_, v)| v)
        .expect("the reply must carry PA-S4U-X509-USER");

    let echoed = s4u::X509User::decode(&value).expect("a PA-S4U-X509-USER");
    assert_eq!(echoed.nonce, 0x4242, "the nonce is the client's");
    assert_eq!(
        echoed.cname.as_ref().map(|p| p.components.clone()),
        Some(vec!["alice".to_string()])
    );
    // And the checksum is the KDC's: usage 27 over the id, under the subkey.
    let mut r = der::Reader::new(&value);
    let seq = r.expect("PA-S4U-X509-USER", der::SEQUENCE).unwrap();
    let f = der::Fields::parse("PA-S4U-X509-USER", seq).unwrap();
    let id = f.get(0, "user-id").unwrap().to_vec();
    let expected = OwnCipher.checksum(&subkey, 27, &id).unwrap();
    let mut cr = der::Reader::new(f.get(1, "checksum").unwrap());
    let cseq = cr.expect("Checksum", der::SEQUENCE).unwrap();
    let cf = der::Fields::parse("Checksum", cseq).unwrap();
    assert_eq!(
        cf.octets(1, "Checksum").unwrap(),
        expected.as_slice(),
        "the reply's checksum is usage 27 over the client's own bytes"
    );

    // The ticket is the user's, so the claim and the ticket agree.
    assert_eq!(
        ticket_part(&reply, &svc_key).cname.components,
        vec!["alice"]
    );
}

#[test]
fn two_halves_naming_different_users_are_refused() {
    // One request, one user: a KDC that picked either half would be choosing for the client.
    let (kdc, krbtgt_key, _) = kdc(Knobs::default());
    let (tgt, session) = service_tgt(&krbtgt_key);
    let subkey = OwnCipher.random(Enctype::Aes256Sha1).unwrap();
    let request = tgs_req_with_subkey(
        &tgt,
        &session,
        &service(),
        0,
        Some(&subkey),
        &[
            (s4u::PA_FOR_USER, for_user(&alice(), &session)),
            (
                s4u::PA_S4U_X509_USER,
                x509_user(&bob(), 0x4242, &subkey, true),
            ),
        ],
    );
    let reply = kdc.handle(&request, NOW);
    let err = msg::KrbError::decode(&reply).expect("a refusal");
    assert_eq!(err.code, codes::KDC_ERR_BADOPTION);
    let text = err.e_text.unwrap_or_default();
    assert!(text.contains("one request, one user"), "{text}");
}
