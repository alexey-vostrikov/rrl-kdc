//! Ticket lifetimes: what a `till` of zero means, and what the TGT bounds.
//!
//! A `KDC-REQ-BODY` may say `till = 0`, and RFC 4120 §5.4.1 reads that as "as long as you
//! allow" — Heimdal's `_kdc_fix_time` says the same in one line, with the comment "fix for old
//! clients". Treating it literally gives a ticket that ends at the epoch, which the KDC then
//! refuses as `KDC_ERR_NEVER_VALID`: a client that asked for "whatever you allow" is told its
//! ticket would expire before it started, and an operator has nothing to act on.
//!
//! The other half is the bound: a service ticket may never outlive the TGT it came from,
//! because the TGT is the client's proof of identity and a ticket outliving it would let a
//! revoked client keep working.
//!
//! These are the two failures from the ad-join stand, and they alternate with how the client
//! authenticated — which is why they are pinned here as functions of the request, not of a
//! stand.

use std::sync::Arc;

use rust_kdc::crypto::{Cipher, Enctype, Key, OwnCipher, usage};
use rust_kdc::der;
use rust_kdc::error::codes;
use rust_kdc::hdb::{Hdb, HdbEntry, MemoryHdb, flags as entry_flags};
use rust_kdc::kdc::{Kdc, KdcConfig};
use rust_kdc::msg::{
    self, ApReq, Authenticator, EncKdcRepPart, EncTicketPart, EncryptedData, Ticket,
    encode_pa_data, kdc_options, tkt_flags,
};
use rust_kdc::name::Principal;

const REALM: &str = "EXAMPLE.COM";
const SERVICE: &str = "cifs/files.example.com";
const NOW: i64 = 1_700_000_000;
/// The configuration's own bound, read rather than guessed: a constant here would pin the test
/// to today's default and silently disagree with the KDC the day it changes.
fn max_life() -> i64 {
    KdcConfig::new(REALM).unwrap().max_life()
}

fn alice() -> Principal {
    Principal::parse(&format!("alice@{REALM}")).unwrap()
}

fn service() -> Principal {
    Principal::parse(&format!("{SERVICE}@{REALM}")).unwrap()
}

fn realm(tgt_endtime: i64) -> (MemoryHdb, Key) {
    let cipher = OwnCipher;
    let db = MemoryHdb::new();

    let mut krbtgt = HdbEntry::krbtgt(REALM);
    let krbtgt_key = cipher.random(Enctype::Aes256Sha1).unwrap();
    krbtgt.add_key(krbtgt_key.clone(), 1, None);
    db.insert(krbtgt).unwrap();

    let mut user = HdbEntry::user(alice());
    user.flags &= !entry_flags::REQUIRE_PREAUTH;
    user.add_password_key(&cipher, Enctype::Aes256Sha1, b"password", 1)
        .unwrap();
    db.insert(user).unwrap();

    let mut svc = HdbEntry::service(service());
    svc.add_password_key(&cipher, Enctype::Aes256Sha1, b"key", 1)
        .unwrap();
    let _ = tgt_endtime;
    db.insert(svc).unwrap();

    (db, krbtgt_key)
}

fn kdc(tgt_endtime: i64) -> (Kdc, Key, Key) {
    let (db, krbtgt_key) = realm(tgt_endtime);
    let svc_key = OwnCipher.random(Enctype::Aes256Sha1).unwrap();
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

/// A TGT for `alice`, valid until `endtime`.
fn tgt(krbtgt_key: &Key, endtime: i64) -> (Vec<u8>, Key) {
    let cipher = OwnCipher;
    let session_key = cipher.random(Enctype::Aes256Sha1).unwrap();
    let part = EncTicketPart {
        flags: tkt_flags::INITIAL | tkt_flags::PRE_AUTHENT | tkt_flags::FORWARDABLE,
        session_key: session_key.clone(),
        crealm: REALM.into(),
        cname: alice(),
        transited_type: 0,
        transited: Vec::new(),
        authtime: NOW - 60,
        starttime: None,
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
    (ticket.encode(), session_key)
}

/// A `TGS-REQ` for `service()` whose body says `till`.
fn tgs_req(ticket: &[u8], session_key: &Key, till: i64) -> Vec<u8> {
    let cipher = OwnCipher;
    let body = der::seq(&[
        der::field(0, der::flags32(kdc_options::FORWARDABLE)),
        der::field(2, der::general_string(REALM)),
        der::field(3, service().encode_name()),
        der::field(5, der::time(till)),
        der::field(7, der::int(0x4242)),
        der::field(8, der::seq(&[der::int(18)])),
    ]);

    let cksum = cipher
        .checksum(session_key, usage::TGS_REQ_AUTH_CKSUM, &body)
        .unwrap();
    let authenticator = Authenticator {
        crealm: REALM.into(),
        cname: alice(),
        cksum: Some((Enctype::Aes256Sha1.checksum_type(), cksum)),
        cusec: 0,
        ctime: NOW,
        subkey: None,
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

/// The `EncTGSRepPart` of a reply, opened with the TGT's session key.
fn rep_part(reply: &[u8], session_key: &Key) -> EncKdcRepPart {
    let f = der::Fields::parse_app("TGS-REP", 13, reply).expect("a TGS-REP");
    let enc = EncryptedData::decode("enc-part", f.get(6, "TGS-REP").expect("enc-part"))
        .expect("an EncryptedData");
    let plain = OwnCipher
        .decrypt(session_key, usage::TGS_REP_ENCPART_SESSKEY, &enc.cipher)
        .expect("the reply opens with the TGT's session key");
    EncKdcRepPart::decode(&plain).expect("an EncTGSRepPart")
}

#[test]
fn a_till_of_zero_means_as_long_as_the_kdc_allows() {
    // RFC 4120 §5.4.1, and Heimdal's `_kdc_fix_time`: zero is not the epoch, it is "whatever
    // you allow". A literal reading produced `KDC_ERR_NEVER_VALID` — the error the ad-join
    // stand reported after a successful `kinit`, which reads to an operator as "the KDC thinks
    // my brand-new TGT is expired".
    let (kdc, krbtgt_key, _) = kdc(NOW + 2 * max_life());
    let (ticket, session) = tgt(&krbtgt_key, NOW + 2 * max_life());
    let reply = kdc.handle(&tgs_req(&ticket, &session, 0), NOW);
    assert!(
        msg::KrbError::decode(&reply).is_err(),
        "a till of zero must be granted, not refused: {:?}",
        msg::KrbError::decode(&reply)
    );

    let rep = rep_part(&reply, &session);
    assert_eq!(
        rep.endtime,
        NOW + max_life(),
        "the configuration's bound, counted from now"
    );
}

#[test]
fn a_service_ticket_never_outlives_its_tgt() {
    // The TGT is the client's proof of identity: a ticket that outlived it would let a revoked
    // client keep working until the service ticket ran out.
    let tgt_end = NOW + 600;
    let (kdc, krbtgt_key, _) = kdc(tgt_end);
    let (ticket, session) = tgt(&krbtgt_key, tgt_end);
    // The client asks for a day, which nothing allows.
    let reply = kdc.handle(&tgs_req(&ticket, &session, NOW + 86_400), NOW);
    assert!(msg::KrbError::decode(&reply).is_err());

    let rep = rep_part(&reply, &session);
    assert_eq!(
        rep.endtime, tgt_end,
        "clamped to the TGT, not to the request"
    );
}

#[test]
fn a_till_that_is_already_past_is_still_refused() {
    // The pair that keeps the test above from passing for the wrong reason: a client asking
    // for a ticket that has already expired is not asking for "whatever you allow", and
    // granting it would hand out a ticket nobody can use.
    let (kdc, krbtgt_key, _) = kdc(NOW + 7200);
    let (ticket, session) = tgt(&krbtgt_key, NOW + 7200);
    let reply = kdc.handle(&tgs_req(&ticket, &session, NOW - 3600), NOW);
    let err = msg::KrbError::decode(&reply).expect("a refusal");
    assert_eq!(err.code, codes::KDC_ERR_NEVER_VALID);
}

#[test]
fn an_expired_tgt_is_refused_before_the_plan_is_reached() {
    // The other refusal that can produce a lifetime complaint, and a different code: an
    // expired TGT is `TKT_EXPIRED`, not `NEVER_VALID`, and an operator triaging by code has to
    // be able to tell the two apart.
    let (kdc, krbtgt_key, _) = kdc(NOW + 7200);
    let (ticket, session) = tgt(&krbtgt_key, NOW - 60);
    let reply = kdc.handle(&tgs_req(&ticket, &session, NOW + 3600), NOW);
    let err = msg::KrbError::decode(&reply).expect("a refusal");
    assert_eq!(err.code, codes::KRB_AP_ERR_TKT_EXPIRED);
}
/// An AS-REQ for `alice`, no pre-authentication, whose body says `till`.
fn as_req(till: i64) -> Vec<u8> {
    let body = der::seq(&[
        der::field(0, der::flags32(kdc_options::FORWARDABLE)),
        der::field(1, alice().encode_name()),
        der::field(2, der::general_string(REALM)),
        der::field(3, Principal::krbtgt(REALM).encode_name()),
        der::field(5, der::time(till)),
        der::field(7, der::int(0x1234_5678)),
        der::field(8, der::seq(&[der::int(18)])),
    ]);
    der::cons(
        der::app(10),
        &[der::seq(&[
            der::field(1, der::int(5)),
            der::field(2, der::int(10)),
            der::field(4, body),
        ])],
    )
}

/// The `EncASRepPart` of an AS-REP, opened with `key`.
fn as_rep_part(reply: &[u8], key: &Key) -> EncKdcRepPart {
    let f = der::Fields::parse_app("AS-REP", 11, reply).expect("an AS-REP");
    let enc = EncryptedData::decode("enc-part", f.get(6, "AS-REP").expect("enc-part"))
        .expect("an EncryptedData");
    let plain = OwnCipher
        .decrypt(key, usage::AS_REP_ENCPART, &enc.cipher)
        .expect("the reply opens with alice's key");
    EncKdcRepPart::decode(&plain).expect("an EncASRepPart")
}

#[test]
fn an_as_request_with_a_till_of_zero_gets_the_configured_lifetime() {
    // The same normalisation on the AS side, and it matters for the same reason: a client that
    // asks "as long as you allow" must not be told its ticket would expire before it starts —
    // that refusal happens before a TGT exists at all, so there is nothing for the client to
    // retry with.
    let (kdc, _, _) = kdc(NOW + 7200);
    let reply = kdc.handle(&as_req(0), NOW);
    assert!(
        msg::KrbError::decode(&reply).is_err(),
        "an AS-REQ with till 0 must be granted: {:?}",
        msg::KrbError::decode(&reply)
    );

    // The reply key is alice's long-term key, derived by the same `add_password_key` the test
    // realm used — deriving it by hand would test a second implementation of string-to-key.
    let mut probe = HdbEntry::user(alice());
    probe
        .add_password_key(&OwnCipher, Enctype::Aes256Sha1, b"password", 1)
        .unwrap();
    let key = probe
        .key_for(Enctype::Aes256Sha1)
        .map(|k| k.key.clone())
        .expect("alice has a key");
    let rep = as_rep_part(&reply, &key);
    assert_eq!(rep.endtime, NOW + max_life());
}
#[test]
fn a_service_ticket_inherits_its_flags_from_the_tgt_not_from_the_request() {
    // RFC 4120 §3.3.3: a client cannot grant itself a forwardable ticket from a TGT that is not
    // forwardable. The mirror rule matters as much — a client that asks for nothing still gets
    // `forwardable` when its TGT has it, because every real client relies on that and a KDC
    // that ignored the TGT would issue tickets nobody can delegate.
    //
    // Four cases, because the guard has two conditions on each flag: one side alone must not be
    // enough, and both sides together must be.
    let cipher = OwnCipher;
    for (tgt_forwardable, asked_forwardable, expect) in [
        (true, true, true),
        (true, false, false),
        (false, true, false),
        (false, false, false),
    ] {
        let (kdc, krbtgt_key, _) = kdc(NOW + 7200);
        let (ticket, session) = tgt_with_flags(
            &krbtgt_key,
            NOW + 7200,
            if tgt_forwardable {
                tkt_flags::FORWARDABLE
            } else {
                0
            },
        );
        let options = if asked_forwardable {
            kdc_options::FORWARDABLE
        } else {
            0
        };
        let reply = kdc.handle(
            &tgs_req_with_options(&ticket, &session, NOW + 3600, options),
            NOW,
        );
        assert!(
            msg::KrbError::decode(&reply).is_err(),
            "tgt={tgt_forwardable} asked={asked_forwardable}: {:?}",
            msg::KrbError::decode(&reply)
        );
        let rep = rep_part(&reply, &session);
        assert_eq!(
            rep.flags & tkt_flags::FORWARDABLE != 0,
            expect,
            "tgt={tgt_forwardable} asked={asked_forwardable}: the TGT decides, and both must \
             agree before the flag is granted: {:#010x}",
            rep.flags
        );
        let _ = cipher;
    }
}

#[test]
fn pre_authentication_carries_over_from_the_tgt() {
    // `pre-authent` on a service ticket says the user proved something to the KDC. A ticket
    // without it is one a service may refuse; a ticket with it that the TGT did not earn would
    // be a lie about how the user authenticated.
    let (kdc, krbtgt_key, _) = kdc(NOW + 7200);

    let (ticket, session) = tgt_with_flags(&krbtgt_key, NOW + 7200, tkt_flags::PRE_AUTHENT);
    let reply = kdc.handle(&tgs_req(&ticket, &session, NOW + 3600), NOW);
    assert!(msg::KrbError::decode(&reply).is_err());
    assert!(
        rep_part(&reply, &session).flags & tkt_flags::PRE_AUTHENT != 0,
        "a ticket from a pre-authenticated TGT is pre-authenticated"
    );

    let (ticket, session) = tgt_with_flags(&krbtgt_key, NOW + 7200, 0);
    let reply = kdc.handle(&tgs_req(&ticket, &session, NOW + 3600), NOW);
    assert!(msg::KrbError::decode(&reply).is_err());
    assert_eq!(
        rep_part(&reply, &session).flags & tkt_flags::PRE_AUTHENT,
        0,
        "and one from a TGT that never proved anything is not"
    );
}

/// A TGT for `alice` carrying exactly `extra` on top of `INITIAL`.
fn tgt_with_flags(krbtgt_key: &Key, endtime: i64, extra: u32) -> (Vec<u8>, Key) {
    let cipher = OwnCipher;
    let session_key = cipher.random(Enctype::Aes256Sha1).unwrap();
    let part = EncTicketPart {
        flags: tkt_flags::INITIAL | extra,
        session_key: session_key.clone(),
        crealm: REALM.into(),
        cname: alice(),
        transited_type: 0,
        transited: Vec::new(),
        authtime: NOW - 60,
        starttime: None,
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
    (ticket.encode(), session_key)
}

/// A `TGS-REQ` asking for `options`, with a real `till`.
fn tgs_req_with_options(ticket: &[u8], session_key: &Key, till: i64, options: u32) -> Vec<u8> {
    let cipher = OwnCipher;
    let body = der::seq(&[
        der::field(0, der::flags32(options)),
        der::field(2, der::general_string(REALM)),
        der::field(3, service().encode_name()),
        der::field(5, der::time(till)),
        der::field(7, der::int(0x4242)),
        der::field(8, der::seq(&[der::int(18)])),
    ]);
    let cksum = cipher
        .checksum(session_key, usage::TGS_REQ_AUTH_CKSUM, &body)
        .unwrap();
    let authenticator = Authenticator {
        crealm: REALM.into(),
        cname: alice(),
        cksum: Some((Enctype::Aes256Sha1.checksum_type(), cksum)),
        cusec: 0,
        ctime: NOW,
        subkey: None,
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

#[test]
fn an_account_that_allows_no_requested_enctype_is_refused_by_name() {
    // RRL-2.26 point 3: the refusal has to say whose restriction it is. "enctype 23 is not one
    // this KDC implements" sends an operator to look at the KDC's configuration; the truth here
    // is that the *service* declares a narrower set, and the answer should say so.
    let (db, krbtgt_key) = realm(NOW + 7200);
    let mut svc = db.fetch(&service()).unwrap().unwrap();
    svc.etypes = Some(vec![Enctype::Aes128Sha1]);
    db.insert(svc).unwrap();
    let kdc = Kdc::new(
        KdcConfig::new(REALM).unwrap().with_require_preauth(false),
        Arc::new(db),
        Arc::new(OwnCipher),
    );

    let (ticket, session) = tgt(&krbtgt_key, NOW + 7200);
    // The test's `tgs_req` asks for AES256 only, which this service may not be issued.
    let reply = kdc.handle(&tgs_req(&ticket, &session, NOW + 3600), NOW);
    let err = msg::KrbError::decode(&reply).expect("a refusal");
    assert_eq!(err.code, codes::KDC_ERR_ETYPE_NOSUPP);
    let text = err.e_text.unwrap_or_default();
    assert!(
        text.contains("cifs/files.example.com") && text.contains("may be issued"),
        "the refusal must name the account and its declaration: {text}"
    );
    assert!(
        text.contains("Aes128Sha1"),
        "and say what it allows: {text}"
    );
}
