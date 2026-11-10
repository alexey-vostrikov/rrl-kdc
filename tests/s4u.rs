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

use rrl_kdc::crypto::{Cipher, Enctype, Key, OwnCipher, usage};
use rrl_kdc::der;
use rrl_kdc::error::codes;
use rrl_kdc::hdb::{HdbEntry, MemoryHdb, flags as entry_flags};
use rrl_kdc::kdc::s4u;
use rrl_kdc::kdc::{Kdc, KdcConfig};
use rrl_kdc::msg::{
    self, ApReq, Authenticator, EncKdcRepPart, EncTicketPart, EncryptedData, Ticket,
    encode_pa_data, kdc_options, tkt_flags,
};
use rrl_kdc::name::Principal;

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
    tgs_req_proxy(ticket, session_key, target, options, subkey, extra, None)
}

/// The same, with an evidence ticket in `additional-tickets [10]`.
fn tgs_req_proxy(
    ticket: &[u8],
    session_key: &Key,
    target: &Principal,
    options: u32,
    subkey: Option<&Key>,
    extra: &[(i32, Vec<u8>)],
    additional: Option<&[u8]>,
) -> Vec<u8> {
    let cipher = OwnCipher;
    let mut parts = vec![
        der::field(0, der::flags32(options)),
        der::field(2, der::general_string(REALM)),
        der::field(3, target.encode_name()),
        der::field(5, der::time(NOW + 3600)),
        der::field(7, der::int(0x4242)),
        der::field(8, der::seq(&[der::int(18)])),
    ];
    if let Some(evidence) = additional {
        // `additional-tickets [11]`: [10] is `enc-authorization-data`.
        parts.push(der::field(11, der::seq(&[evidence.to_vec()])));
    }
    let body = der::seq(&parts);

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
    let ticket = Ticket::decode(f.bytes(5, "TGS-REP").expect("the ticket")).expect("a Ticket");
    let plain = OwnCipher
        .decrypt(key, usage::KDC_REP_TICKET, &ticket.enc.cipher)
        .expect("the ticket opens with the service key");
    EncTicketPart::decode(&plain).expect("an EncTicketPart")
}

fn reply_padata(reply: &[u8]) -> Vec<(i32, Vec<u8>)> {
    let f = der::Fields::parse_app("TGS-REP", 13, reply).expect("a TGS-REP");
    match f.opt_bytes(2) {
        None => Vec::new(),
        Some(raw) => {
            let mut r = der::Reader::new(raw);
            let seq = r.next_tlv("PA-DATA").expect("a SEQUENCE");
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
    let mut r = der::Reader::new(f.bytes(4, "TGS-REP").expect("cname"));
    let seq = r.next_tlv("cname").unwrap();
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
    let enc = EncryptedData::decode("enc-part", f.bytes(6, "TGS-REP").expect("enc-part")).unwrap();
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
    let seq = r.expect_in("PA-S4U-X509-USER", der::SEQUENCE).unwrap();
    let f = der::Fields::parse("PA-S4U-X509-USER", seq).unwrap();
    let id = f.bytes(0, "user-id").unwrap().to_vec();
    let expected = OwnCipher.checksum(&subkey, 27, &id).unwrap();
    let mut cr = der::Reader::new(f.bytes(1, "checksum").unwrap());
    let cseq = cr.expect_in("Checksum", der::SEQUENCE).unwrap();
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

// ---- S4U2Proxy (constrained delegation, MS-SFU §3.1.5) --------------------------------

/// An evidence ticket for `user`, sealed in `key` — the delegating service's key, which is what
/// proves the service received it.
fn evidence_ticket(user: &Principal, key: &Key, flags: u32, authtime: i64) -> Vec<u8> {
    let cipher = OwnCipher;
    let part = EncTicketPart {
        flags: tkt_flags::FORWARDABLE | flags,
        session_key: cipher.random(Enctype::Aes256Sha1).unwrap(),
        crealm: user.realm.clone(),
        cname: user.clone(),
        transited_type: 0,
        transited: Vec::new(),
        authtime,
        starttime: None,
        endtime: NOW + 3600,
        renew_till: None,
        caddr: None,
        authorization_data: None,
    };
    Ticket {
        realm: REALM.into(),
        sname: service(),
        enc: EncryptedData::seal(&cipher, key, usage::KDC_REP_TICKET, Some(1), &part.encode())
            .unwrap(),
    }
    .encode()
}

/// A realm where the delegating service may delegate to `target`.
fn realm_with_delegation(acl: Option<Vec<Principal>>) -> (Kdc, Key, Key, Key) {
    let cipher = OwnCipher;
    let db = MemoryHdb::new();

    let mut krbtgt = HdbEntry::krbtgt(REALM);
    let krbtgt_key = cipher.random(Enctype::Aes256Sha1).unwrap();
    krbtgt.add_key(krbtgt_key.clone(), 1, None);
    db.insert(krbtgt).unwrap();

    let mut user = HdbEntry::user(alice());
    user.add_password_key(&cipher, Enctype::Aes256Sha1, b"password", 1)
        .unwrap();
    db.insert(user).unwrap();

    let mut svc = HdbEntry::service(service());
    let svc_key = cipher.random(Enctype::Aes256Sha1).unwrap();
    svc.add_key(svc_key.clone(), 1, None);
    svc.flags |= entry_flags::TRUSTED_FOR_DELEGATION;
    svc.constrained_delegation = acl;
    db.insert(svc).unwrap();

    let mut files = HdbEntry::service(Principal::parse(&format!("cifs/files@{REALM}")).unwrap());
    let files_key = cipher.random(Enctype::Aes256Sha1).unwrap();
    files.add_key(files_key.clone(), 1, None);
    db.insert(files).unwrap();

    (
        Kdc::new(
            KdcConfig::new(REALM).unwrap().with_require_preauth(false),
            Arc::new(db),
            Arc::new(OwnCipher),
        ),
        krbtgt_key,
        svc_key,
        files_key,
    )
}

fn files() -> Principal {
    Principal::parse(&format!("cifs/files@{REALM}")).unwrap()
}

#[test]
fn a_listed_service_receives_a_ticket_in_the_users_name() {
    // The whole of S4U2Proxy: the service proves it holds the user's ticket, is allowed to
    // delegate there, and receives a ticket the other service can actually open.
    let (kdc, krbtgt_key, svc_key, files_key) = realm_with_delegation(Some(vec![files()]));
    let (tgt, session) = service_tgt(&krbtgt_key);
    let evidence = evidence_ticket(&alice(), &svc_key, 0, NOW - 300);
    let request = tgs_req_proxy(
        &tgt,
        &session,
        &files(),
        kdc_options::CNAME_IN_ADDL_TKT,
        None,
        &[],
        Some(&evidence),
    );
    let reply = kdc.handle(&request, NOW);
    assert!(
        msg::KrbError::decode(&reply).is_err(),
        "a listed delegation must be answered: {:?}",
        msg::KrbError::decode(&reply)
    );

    // The ticket is sealed in `cifs/files`'s key and names the user — the two things the
    // receiving service checks before it believes anything the delegating service says.
    let part = ticket_part(&reply, &files_key);
    assert_eq!(part.cname.components, vec!["alice"]);
    assert_eq!(part.cname.realm, REALM);
}

#[test]
fn the_proxy_ticket_names_the_user_and_keeps_the_evidence_authtime() {
    // Both halves of §3.1.5.2 that are easy to lose: the client must be the user (not the
    // service), and `authtime` must be when the *user* authenticated, not now.
    let (kdc, krbtgt_key, svc_key, _files_key) = realm_with_delegation(Some(vec![files()]));
    let (tgt, session) = service_tgt(&krbtgt_key);
    let authtime = NOW - 3000;
    let evidence = evidence_ticket(&alice(), &svc_key, 0, authtime);
    let request = tgs_req_proxy(
        &tgt,
        &session,
        &files(),
        kdc_options::CNAME_IN_ADDL_TKT,
        None,
        &[],
        Some(&evidence),
    );
    let reply = kdc.handle(&request, NOW);
    assert!(msg::KrbError::decode(&reply).is_err());

    // The reply's cleartext client is the user.
    let f = der::Fields::parse_app("TGS-REP", 13, &reply).unwrap();
    let mut r = der::Reader::new(f.bytes(4, "TGS-REP").expect("cname"));
    let seq = r.next_tlv("cname").unwrap();
    let named = Principal::decode("cname", seq.content, REALM).unwrap();
    assert_eq!(named.components, vec!["alice"], "the ticket is the user's");

    // And the reply part, sealed in the TGT's session key, carries the evidence's authtime.
    let enc = EncryptedData::decode("enc-part", f.bytes(6, "TGS-REP").expect("enc-part")).unwrap();
    let plain = OwnCipher
        .decrypt(&session, usage::TGS_REP_ENCPART_SESSKEY, &enc.cipher)
        .expect("the reply opens with the TGT's session key");
    let rep = EncKdcRepPart::decode(&plain).expect("an EncTGSRepPart");
    assert_eq!(
        rep.authtime, authtime,
        "the user authenticated then; this ticket exists because the service remembered it"
    );
}

#[test]
fn a_service_not_in_the_acl_may_not_delegate() {
    // The absence of a list is not a permission: a service with no ACL delegates only to
    // itself, and the refusal says so.
    let (kdc, krbtgt_key, svc_key, _files_key) = realm_with_delegation(None);
    let (tgt, session) = service_tgt(&krbtgt_key);
    let evidence = evidence_ticket(&alice(), &svc_key, 0, NOW - 300);
    let request = tgs_req_proxy(
        &tgt,
        &session,
        &files(),
        kdc_options::CNAME_IN_ADDL_TKT,
        None,
        &[],
        Some(&evidence),
    );
    let reply = kdc.handle(&request, NOW);
    let err = msg::KrbError::decode(&reply).expect("a refusal");
    assert_eq!(err.code, codes::KDC_ERR_BADOPTION);
    let text = err.e_text.unwrap_or_default();
    assert!(
        text.contains("may not delegate") && text.contains("nothing"),
        "the refusal must say there is no list: {text}"
    );
}

#[test]
fn an_empty_acl_is_a_decision_not_a_permission() {
    // `Some([])` is an administrator saying "to nobody". Treating it as "no restriction" would
    // turn a deliberate denial into a grant.
    let (kdc, krbtgt_key, svc_key, _files_key) = realm_with_delegation(Some(Vec::new()));
    let (tgt, session) = service_tgt(&krbtgt_key);
    let evidence = evidence_ticket(&alice(), &svc_key, 0, NOW - 300);
    let request = tgs_req_proxy(
        &tgt,
        &session,
        &files(),
        kdc_options::CNAME_IN_ADDL_TKT,
        None,
        &[],
        Some(&evidence),
    );
    let reply = kdc.handle(&request, NOW);
    let err = msg::KrbError::decode(&reply).expect("a refusal");
    assert_eq!(err.code, codes::KDC_ERR_BADOPTION);
    assert!(
        err.e_text.unwrap_or_default().contains("nobody"),
        "an empty list reads as `nobody`, and the refusal says it"
    );
}

#[test]
fn an_evidence_ticket_that_is_not_forwardable_cannot_be_delegated() {
    // The flag is what a user says about their ticket: without it, the service may use it and
    // may not hand it on.
    let (kdc, krbtgt_key, svc_key, _files_key) = realm_with_delegation(Some(vec![files()]));
    let (tgt, session) = service_tgt(&krbtgt_key);
    let cipher = OwnCipher;
    let part = EncTicketPart {
        flags: tkt_flags::INITIAL,
        session_key: cipher.random(Enctype::Aes256Sha1).unwrap(),
        crealm: REALM.into(),
        cname: alice(),
        transited_type: 0,
        transited: Vec::new(),
        authtime: NOW - 300,
        starttime: None,
        endtime: NOW + 3600,
        renew_till: None,
        caddr: None,
        authorization_data: None,
    };
    let evidence = Ticket {
        realm: REALM.into(),
        sname: service(),
        enc: EncryptedData::seal(
            &cipher,
            &svc_key,
            usage::KDC_REP_TICKET,
            Some(1),
            &part.encode(),
        )
        .unwrap(),
    }
    .encode();
    let request = tgs_req_proxy(
        &tgt,
        &session,
        &files(),
        kdc_options::CNAME_IN_ADDL_TKT,
        None,
        &[],
        Some(&evidence),
    );
    let reply = kdc.handle(&request, NOW);
    let err = msg::KrbError::decode(&reply).expect("a refusal");
    assert_eq!(err.code, codes::KDC_ERR_BADOPTION);
    assert!(
        err.e_text.unwrap_or_default().contains("not forwardable"),
        "the refusal names the missing flag"
    );
}

#[test]
fn an_evidence_ticket_from_another_key_proves_nothing() {
    // The service has to have received the ticket. A ticket sealed in somebody else's key is
    // one the service never held, and honouring it would let any service delegate any user.
    let (kdc, krbtgt_key, _, _) = realm_with_delegation(Some(vec![files()]));
    let (tgt, session) = service_tgt(&krbtgt_key);
    let other = OwnCipher.random(Enctype::Aes256Sha1).unwrap();
    let evidence = evidence_ticket(&alice(), &other, 0, NOW - 300);
    let request = tgs_req_proxy(
        &tgt,
        &session,
        &files(),
        kdc_options::CNAME_IN_ADDL_TKT,
        None,
        &[],
        Some(&evidence),
    );
    let reply = kdc.handle(&request, NOW);
    let err = msg::KrbError::decode(&reply).expect("a refusal");
    assert_eq!(err.code, codes::KRB_AP_ERR_BAD_INTEGRITY);
}

#[test]
fn cname_in_addl_tkt_without_a_ticket_is_refused_by_name() {
    let (kdc, krbtgt_key, _, _) = realm_with_delegation(Some(vec![files()]));
    let (tgt, session) = service_tgt(&krbtgt_key);
    let request = tgs_req_proxy(
        &tgt,
        &session,
        &files(),
        kdc_options::CNAME_IN_ADDL_TKT,
        None,
        &[],
        None,
    );
    let reply = kdc.handle(&request, NOW);
    let err = msg::KrbError::decode(&reply).expect("a refusal");
    assert_eq!(err.code, codes::KDC_ERR_BADOPTION);
    assert!(
        err.e_text.unwrap_or_default().contains("evidence ticket"),
        "the refusal names what is missing"
    );
}

#[test]
fn both_s4u_requests_at_once_are_refused() {
    // Heimdal applies the transition and then the proxy, which verifies the evidence against
    // the impersonated user's key — an order nobody's client relies on. Refusing is honest.
    let (kdc, krbtgt_key, svc_key, _files_key) = realm_with_delegation(Some(vec![files()]));
    let (tgt, session) = service_tgt(&krbtgt_key);
    let evidence = evidence_ticket(&alice(), &svc_key, 0, NOW - 300);
    let request = tgs_req_proxy(
        &tgt,
        &session,
        &service(),
        kdc_options::CNAME_IN_ADDL_TKT,
        None,
        &[(s4u::PA_FOR_USER, for_user(&alice(), &session))],
        Some(&evidence),
    );
    let reply = kdc.handle(&request, NOW);
    let err = msg::KrbError::decode(&reply).expect("a refusal");
    assert_eq!(err.code, codes::KDC_ERR_BADOPTION);
    assert!(
        err.e_text.unwrap_or_default().contains("two exchanges"),
        "the refusal explains why"
    );
}
#[test]
fn an_expired_evidence_ticket_cannot_be_delegated() {
    // An evidence ticket is a credential the user issued once. Past its lifetime there is
    // nothing to delegate, and a KDC that honoured it would extend the user's authority for
    // as long as the service kept the octets.
    let (kdc, krbtgt_key, svc_key, _) = realm_with_delegation(Some(vec![files()]));
    let (tgt, session) = service_tgt(&krbtgt_key);
    let cipher = OwnCipher;
    let part = EncTicketPart {
        flags: tkt_flags::FORWARDABLE,
        session_key: cipher.random(Enctype::Aes256Sha1).unwrap(),
        crealm: REALM.into(),
        cname: alice(),
        transited_type: 0,
        transited: Vec::new(),
        authtime: NOW - 7200,
        starttime: None,
        // Expired an hour ago: `now` is what the KDC is told, and the evidence is older.
        endtime: NOW - 3600,
        renew_till: None,
        caddr: None,
        authorization_data: None,
    };
    let evidence = Ticket {
        realm: REALM.into(),
        sname: service(),
        enc: EncryptedData::seal(
            &cipher,
            &svc_key,
            usage::KDC_REP_TICKET,
            Some(1),
            &part.encode(),
        )
        .unwrap(),
    }
    .encode();
    let request = tgs_req_proxy(
        &tgt,
        &session,
        &files(),
        kdc_options::CNAME_IN_ADDL_TKT,
        None,
        &[],
        Some(&evidence),
    );
    let reply = kdc.handle(&request, NOW);
    let err = msg::KrbError::decode(&reply).expect("a refusal");
    assert_eq!(err.code, codes::KRB_AP_ERR_TKT_EXPIRED);
    assert!(err.e_text.unwrap_or_default().contains("expired"));
}

#[test]
fn evidence_from_another_realm_cannot_be_delegated() {
    // Constrained delegation is a statement this realm makes about its own services. An
    // evidence ticket from elsewhere would ask it to extend a foreign realm's authority.
    let (kdc, krbtgt_key, svc_key, _) = realm_with_delegation(Some(vec![files()]));
    let (tgt, session) = service_tgt(&krbtgt_key);
    let cipher = OwnCipher;
    let part = EncTicketPart {
        flags: tkt_flags::FORWARDABLE,
        session_key: cipher.random(Enctype::Aes256Sha1).unwrap(),
        crealm: "OTHER.EXAMPLE".into(),
        cname: Principal::parse("alice@OTHER.EXAMPLE").unwrap(),
        transited_type: 0,
        transited: Vec::new(),
        authtime: NOW - 300,
        starttime: None,
        endtime: NOW + 3600,
        renew_till: None,
        caddr: None,
        authorization_data: None,
    };
    let evidence = Ticket {
        realm: "OTHER.EXAMPLE".into(),
        sname: service(),
        enc: EncryptedData::seal(
            &cipher,
            &svc_key,
            usage::KDC_REP_TICKET,
            Some(1),
            &part.encode(),
        )
        .unwrap(),
    }
    .encode();
    let request = tgs_req_proxy(
        &tgt,
        &session,
        &files(),
        kdc_options::CNAME_IN_ADDL_TKT,
        None,
        &[],
        Some(&evidence),
    );
    let reply = kdc.handle(&request, NOW);
    let err = msg::KrbError::decode(&reply).expect("a refusal");
    assert_eq!(err.code, codes::KDC_ERR_BADOPTION);
    assert!(
        err.e_text
            .unwrap_or_default()
            .contains("does not cross realms"),
        "the refusal says which rule it broke"
    );
}

#[test]
fn a_request_with_only_the_x509_half_is_answered_for_that_user() {
    // Heimdal accepts either half; MIT's client sends both. A KDC that required PA-FOR-USER
    // would refuse a client that sent only the modern one, and the client would read that as
    // a KDC without S4U rather than as a policy.
    let (kdc, krbtgt_key, svc_key) = kdc(Knobs::default());
    let (tgt, session) = service_tgt(&krbtgt_key);
    let subkey = OwnCipher.random(Enctype::Aes256Sha1).unwrap();
    let request = tgs_req_with_subkey(
        &tgt,
        &session,
        &service(),
        0,
        Some(&subkey),
        &[(
            s4u::PA_S4U_X509_USER,
            x509_user(&alice(), 0x99, &subkey, true),
        )],
    );
    let reply = kdc.handle(&request, NOW);
    assert!(
        msg::KrbError::decode(&reply).is_err(),
        "the X509 half alone is a complete claim: {:?}",
        msg::KrbError::decode(&reply)
    );
    assert_eq!(
        ticket_part(&reply, &svc_key).cname.components,
        vec!["alice"]
    );
}

#[test]
fn an_x509_half_with_a_foreign_checksum_is_refused() {
    // The modern half is not decoration: a client that sends it is signing the id it wants a
    // ticket for, and a checksum over other bytes proves nothing.
    let (kdc, krbtgt_key, _) = kdc(Knobs::default());
    let (tgt, session) = service_tgt(&krbtgt_key);
    let subkey = OwnCipher.random(Enctype::Aes256Sha1).unwrap();
    let other = OwnCipher.random(Enctype::Aes256Sha1).unwrap();
    let request = tgs_req_with_subkey(
        &tgt,
        &session,
        &service(),
        0,
        Some(&subkey),
        // Checksummed with a key the request does not carry.
        &[(
            s4u::PA_S4U_X509_USER,
            x509_user(&alice(), 0x99, &other, true),
        )],
    );
    let reply = kdc.handle(&request, NOW);
    let err = msg::KrbError::decode(&reply).expect("a refusal");
    assert_eq!(err.code, codes::KRB_AP_ERR_BAD_INTEGRITY);
}
