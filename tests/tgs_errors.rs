//! Every way a `TGS-REQ` can be wrong, each answered with the code that names
//! it.
//!
//! The TGT here is built by the test rather than obtained from the AS exchange,
//! because each case needs a *different* TGT — expired, not yet valid, naming
//! somebody else — and building it directly is the only way to hold those
//! knobs. The AS exchange has its own tests; this file is about what the TGS
//! engine does with the evidence it is handed.

use std::sync::Arc;

use rust_kdc::crypto::{Cipher, Enctype, Key, OwnCipher, usage};
use rust_kdc::der;
use rust_kdc::error::codes;
use rust_kdc::hdb::{HdbEntry, MemoryHdb};
use rust_kdc::kdc::{Kdc, KdcConfig};
use rust_kdc::msg::{
    self, ApReq, Authenticator, EncKdcRepPart, EncTicketPart, EncryptedData, KdcReq, Ticket,
    encode_pa_data, kdc_options, tkt_flags,
};
use rust_kdc::name::Principal;

const REALM: &str = "EXAMPLE.COM";
const SERVICE: &str = "host/server.example.com";
const NOW: i64 = 1_700_000_000;

fn alice() -> Principal {
    Principal::parse(&format!("alice@{REALM}")).unwrap()
}

fn service() -> Principal {
    Principal::parse(&format!("{SERVICE}@{REALM}")).unwrap()
}

/// The realm, and the `krbtgt` key the test TGTs are sealed with.
fn realm() -> (MemoryHdb, Key) {
    let cipher = OwnCipher;
    let db = MemoryHdb::new();
    let mut krbtgt = HdbEntry::krbtgt(REALM);
    krbtgt
        .add_password_key(&cipher, Enctype::Aes256Sha1, b"master", 1)
        .unwrap();
    let krbtgt_key = krbtgt.key_for(Enctype::Aes256Sha1).unwrap().key.clone();
    db.insert(krbtgt).unwrap();

    let mut alice_entry = HdbEntry::user(alice());
    alice_entry
        .add_password_key(&cipher, Enctype::Aes256Sha1, b"pw", 1)
        .unwrap();
    db.insert(alice_entry).unwrap();

    let mut service_entry = HdbEntry::service(service());
    service_entry
        .add_password_key(&cipher, Enctype::Aes256Sha1, b"svc", 1)
        .unwrap();
    db.insert(service_entry).unwrap();
    (db, krbtgt_key)
}

fn kdc() -> Kdc {
    let (db, _) = realm();
    Kdc::new(
        KdcConfig::new(REALM).unwrap(),
        Arc::new(db),
        Arc::new(OwnCipher),
    )
}

/// A TGT as the AS exchange would have issued it, with the knobs this file
/// needs.
struct Tgt {
    ticket: Vec<u8>,
    session_key: Key,
}

fn tgt(
    krbtgt_key: &Key,
    cname: &Principal,
    endtime: i64,
    starttime: Option<i64>,
    flags: u32,
) -> Tgt {
    let cipher = OwnCipher;
    let session_key = cipher.random(Enctype::Aes256Sha1).unwrap();
    let part = EncTicketPart {
        flags,
        session_key: session_key.clone(),
        crealm: cname.realm.clone(),
        cname: cname.clone(),
        transited_type: 0,
        transited: Vec::new(),
        authtime: NOW - 60,
        starttime,
        endtime,
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
    Tgt {
        ticket: ticket.encode(),
        session_key,
    }
}

/// What the test can corrupt about the request it builds.
struct Knobs {
    /// The name in the authenticator, when it should differ from the ticket's.
    authenticator_cname: Option<Principal>,
    /// The `ctime` in the authenticator.
    authenticator_ctime: i64,
    /// Corrupt the checksum after the body is built.
    break_checksum: bool,
    /// Omit `PA-TGS-REQ` entirely.
    no_evidence: bool,
    /// Ask for a service other than [`service`].
    target: Option<Principal>,
}

impl Default for Knobs {
    fn default() -> Self {
        Knobs {
            authenticator_cname: None,
            authenticator_ctime: NOW,
            break_checksum: false,
            no_evidence: false,
            target: None,
        }
    }
}

/// A `TGS-REQ` presenting `tgt`, built as a client builds one.
fn tgs_req(tgt: &Tgt, knobs: Knobs) -> Vec<u8> {
    let cipher = OwnCipher;
    let target = knobs.target.clone().unwrap_or_else(service);
    let body = der::seq(&[
        der::field(0, der::flags32(kdc_options::FORWARDABLE)),
        der::field(2, der::general_string(REALM)),
        der::field(3, target.encode_name()),
        der::field(5, der::time(NOW + 3600)),
        der::field(7, der::int(0x4242)),
        der::field(8, der::seq(&[der::int(18)])),
    ]);
    let mut padata = Vec::new();
    if !knobs.no_evidence {
        // The checksum is over the body's exact octets, tag included — which is
        // what the KDC verifies and why the body is built before the
        // authenticator here.
        let mut cksum = cipher
            .checksum(&tgt.session_key, usage::TGS_REQ_AUTH_CKSUM, &body)
            .unwrap();
        if knobs.break_checksum {
            cksum[0] ^= 0xff;
        }
        let auth = Authenticator {
            crealm: REALM.into(),
            cname: knobs.authenticator_cname.clone().unwrap_or_else(alice),
            cksum: Some((Enctype::Aes256Sha1.checksum_type(), cksum)),
            cusec: 0,
            ctime: knobs.authenticator_ctime,
            subkey: None,
            seq_number: None,
            authorization_data: None,
        };
        let ap_req = ApReq {
            ap_options: 0,
            ticket: tgt.ticket.clone(),
            authenticator: EncryptedData::seal(
                &cipher,
                &tgt.session_key,
                usage::TGS_REQ_AUTH,
                None,
                &auth.encode(),
            )
            .unwrap(),
        };
        padata.push((msg::PA_TGS_REQ, ap_req.encode()));
    }
    let mut parts = vec![der::field(1, der::int(5)), der::field(2, der::int(12))];
    if !padata.is_empty() {
        parts.push(der::field(3, encode_pa_data(&padata)));
    }
    parts.push(der::field(4, body));
    der::cons(der::app(12), &[der::seq(&parts)])
}

fn code_of(reply: &[u8]) -> i32 {
    msg::KrbError::decode(reply)
        .unwrap_or_else(|e| panic!("expected KRB-ERROR, got something else: {e}"))
        .code
}

#[test]
fn a_valid_request_is_answered_with_a_ticket() {
    // The baseline: everything below is a deviation from this.
    let (_, krbtgt_key) = realm();
    let t = tgt(
        &krbtgt_key,
        &alice(),
        NOW + 3600,
        None,
        tkt_flags::INITIAL | tkt_flags::PRE_AUTHENT | tkt_flags::FORWARDABLE,
    );
    let reply = kdc().handle(&tgs_req(&t, Knobs::default()), NOW);
    assert!(
        msg::KrbError::decode(&reply).is_err(),
        "the baseline request must succeed, or every test below proves nothing"
    );
}

#[test]
fn an_expired_tgt_is_tkt_expired() {
    let (_, krbtgt_key) = realm();
    let t = tgt(&krbtgt_key, &alice(), NOW - 1, None, tkt_flags::INITIAL);
    assert_eq!(
        code_of(&kdc().handle(&tgs_req(&t, Knobs::default()), NOW)),
        codes::KRB_AP_ERR_TKT_EXPIRED
    );
}

#[test]
fn a_tgt_that_is_not_valid_yet_is_tkt_nyv() {
    let (_, krbtgt_key) = realm();
    let t = tgt(
        &krbtgt_key,
        &alice(),
        NOW + 7200,
        Some(NOW + 3600),
        tkt_flags::INITIAL,
    );
    assert_eq!(
        code_of(&kdc().handle(&tgs_req(&t, Knobs::default()), NOW)),
        codes::KRB_AP_ERR_TKT_NYV
    );
}

#[test]
fn an_unknown_service_is_s_principal_unknown() {
    let (_, krbtgt_key) = realm();
    let t = tgt(&krbtgt_key, &alice(), NOW + 3600, None, tkt_flags::INITIAL);
    let knobs = Knobs {
        target: Some(Principal::parse(&format!("nfs/nowhere@{REALM}")).unwrap()),
        ..Knobs::default()
    };
    assert_eq!(
        code_of(&kdc().handle(&tgs_req(&t, knobs), NOW)),
        codes::KDC_ERR_S_PRINCIPAL_UNKNOWN
    );
}

/// A principal that exists but is not a service gets the *same* answer as one
/// that does not exist, and that is the behaviour to keep.
///
/// Heimdal looks the target up with `HDB_F_GET_SERVER`, so "there, but not a
/// service" and "not there" collapse into one answer before the KDC ever sees
/// them; this backend returns the entry and the flag check decides. Answering
/// `KDC_ERR_POLICY` here would claim something else — that the principal *is*
/// a service and is being refused — and would send a client looking for a
/// policy to change instead of for a service that exists. The flag check is
/// the boundary, so it is what this test holds in place.
#[test]
fn a_principal_that_is_not_a_service_is_s_principal_unknown_too() {
    let (_, krbtgt_key) = realm();
    let t = tgt(&krbtgt_key, &alice(), NOW + 3600, None, tkt_flags::INITIAL);
    // `alice` is in the database, with a password key and the client flags a
    // user entry carries — it is present and is not a service.
    let knobs = Knobs {
        target: Some(alice()),
        ..Knobs::default()
    };
    assert_eq!(
        code_of(&kdc().handle(&tgs_req(&t, knobs), NOW)),
        codes::KDC_ERR_S_PRINCIPAL_UNKNOWN
    );
}

#[test]
fn a_checksum_that_does_not_cover_the_body_is_modified() {
    let (_, krbtgt_key) = realm();
    let t = tgt(&krbtgt_key, &alice(), NOW + 3600, None, tkt_flags::INITIAL);
    let knobs = Knobs {
        break_checksum: true,
        ..Knobs::default()
    };
    assert_eq!(
        code_of(&kdc().handle(&tgs_req(&t, knobs), NOW)),
        codes::KRB_AP_ERR_MODIFIED
    );
}

#[test]
fn an_authenticator_naming_another_client_is_badmatch() {
    let (_, krbtgt_key) = realm();
    let t = tgt(&krbtgt_key, &alice(), NOW + 3600, None, tkt_flags::INITIAL);
    let knobs = Knobs {
        authenticator_cname: Some(Principal::parse(&format!("bob@{REALM}")).unwrap()),
        ..Knobs::default()
    };
    assert_eq!(
        code_of(&kdc().handle(&tgs_req(&t, knobs), NOW)),
        codes::KRB_AP_ERR_BADMATCH
    );
}

#[test]
fn a_stale_authenticator_is_skew() {
    let (_, krbtgt_key) = realm();
    let t = tgt(&krbtgt_key, &alice(), NOW + 3600, None, tkt_flags::INITIAL);
    let knobs = Knobs {
        authenticator_ctime: NOW - 86_400,
        ..Knobs::default()
    };
    assert_eq!(
        code_of(&kdc().handle(&tgs_req(&t, knobs), NOW)),
        codes::KRB_AP_ERR_SKEW
    );
}

#[test]
fn a_request_without_evidence_is_refused() {
    let (_, krbtgt_key) = realm();
    let t = tgt(&krbtgt_key, &alice(), NOW + 3600, None, tkt_flags::INITIAL);
    let knobs = Knobs {
        no_evidence: true,
        ..Knobs::default()
    };
    assert_eq!(
        code_of(&kdc().handle(&tgs_req(&t, knobs), NOW)),
        codes::KRB_AP_ERR_MODIFIED
    );
}

/// A ticket for something other than `krbtgt` cannot be evidence for a TGS
/// request: presenting a service ticket to get another service ticket is how a
/// client would launder a stolen ticket.
#[test]
fn a_ticket_that_is_not_a_tgt_is_refused() {
    let (_, krbtgt_key) = realm();
    let cipher = OwnCipher;
    let session_key = cipher.random(Enctype::Aes256Sha1).unwrap();
    let part = EncTicketPart {
        flags: tkt_flags::INITIAL,
        session_key: session_key.clone(),
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
    let forged = Ticket {
        realm: REALM.into(),
        // A service ticket, sealed with a key the test happens to know.
        sname: service(),
        enc: EncryptedData::seal(
            &cipher,
            &krbtgt_key,
            usage::KDC_REP_TICKET,
            Some(1),
            &part.encode(),
        )
        .unwrap(),
    };
    let t = Tgt {
        ticket: forged.encode(),
        session_key,
    };
    assert_eq!(
        code_of(&kdc().handle(&tgs_req(&t, Knobs::default()), NOW)),
        codes::KRB_AP_ERR_MODIFIED
    );
}

/// The flags of a service ticket come from the TGT, not from the request: a
/// client that asks for `forwardable` without holding a forwardable TGT does not
/// get one.
#[test]
fn a_service_ticket_cannot_be_more_forwardable_than_its_tgt() {
    let (_, krbtgt_key) = realm();
    let t = tgt(&krbtgt_key, &alice(), NOW + 3600, None, tkt_flags::INITIAL);
    let reply = kdc().handle(&tgs_req(&t, Knobs::default()), NOW);
    let part = read_reply(&reply, &t.session_key);
    assert_eq!(
        part.flags & tkt_flags::FORWARDABLE,
        0,
        "the TGT was not forwardable, so neither is the ticket"
    );
}

#[test]
fn a_forwardable_tgt_yields_a_forwardable_ticket() {
    let (_, krbtgt_key) = realm();
    let t = tgt(
        &krbtgt_key,
        &alice(),
        NOW + 3600,
        None,
        tkt_flags::INITIAL | tkt_flags::FORWARDABLE,
    );
    let reply = kdc().handle(&tgs_req(&t, Knobs::default()), NOW);
    let part = read_reply(&reply, &t.session_key);
    assert_ne!(
        part.flags & tkt_flags::FORWARDABLE,
        0,
        "the TGT was forwardable and the client asked, so the ticket must be too"
    );
}

/// A service ticket cannot outlive the TGT it came from.
#[test]
fn a_service_ticket_does_not_outlive_its_tgt() {
    let (_, krbtgt_key) = realm();
    // A TGT with a short life, and a request that asks for an hour.
    let t = tgt(&krbtgt_key, &alice(), NOW + 600, None, tkt_flags::INITIAL);
    let reply = kdc().handle(&tgs_req(&t, Knobs::default()), NOW);
    let part = read_reply(&reply, &t.session_key);
    assert!(
        part.endtime <= NOW + 600,
        "the ticket ends at {} but its TGT ends at {}",
        part.endtime,
        NOW + 600
    );
    assert!(part.endtime > NOW, "the ticket must still be usable");
}

/// Reads the `EncTGSRepPart` out of a `TGS-REP`, decrypting with the TGT's
/// session key — what a client does.
fn read_reply(reply: &[u8], session_key: &Key) -> EncKdcRepPart {
    let f = rust_kdc::der::Fields::parse_app("TGS-REP", 13, reply)
        .expect("a TGS request that should have succeeded was answered with an error");
    let mut r = rust_kdc::der::Reader::new(f.bytes(6, "TGS-REP").unwrap());
    let content = r.expect_in("enc-part", der::SEQUENCE).unwrap();
    let enc = EncryptedData::decode_content("enc-part", content).unwrap();
    let plain = OwnCipher
        .decrypt(session_key, usage::TGS_REP_ENCPART_SESSKEY, &enc.cipher)
        .expect("the reply must decrypt in the TGT's session key, usage 8");
    EncKdcRepPart::decode(&plain).expect("the encrypted part must be an EncTGSRepPart")
}

/// The decoded request is available for diagnostics and for the tests above that
/// want to see what was actually sent.
#[allow(dead_code)]
fn decode(bytes: &[u8]) -> KdcReq {
    KdcReq::decode(bytes).unwrap()
}
