//! `PA-REQ-ENC-PA-REP` (RFC 6806 §11): the KDC's checksum over the request it answered.
//!
//! Two things ride on this value, and both are about a client deciding whether to trust the
//! exchange it is in:
//!
//! * the **ticket flag** `enc-pa-rep` (bit 15) says the reply was produced from *this* request,
//!   and the checksum in the encrypted part is over the exact octets the client sent. An
//!   attacker who alters an unprotected AS-REQ cannot recompute it, because it is keyed with
//!   the reply key — which is why MIT's client treats a missing or wrong checksum as
//!   `KRB5_KDCREP_MODIFIED` rather than as a nicety;
//! * the presence of `PA-FX-FAST` in that same encrypted PA-DATA is how the client learns the
//!   KDC supports FAST, which in turn is how it learns the KDC supports S4U. A KDC that never
//!   sends this value is, to that client, a KDC that does not do protocol transition at all.
//!
//! The shape is pinned by `krb5` 1.0's `verify_enc_pa_rep`, which is the client this crate is
//! judged by: a `Checksum` (type, value) in `EncKDCRepPart.padata [12]`, keyed with the reply
//! key at usage 56, over the request as received.

use std::sync::Arc;

use rust_kdc::crypto::{Cipher, Enctype, Key, OwnCipher, usage};
use rust_kdc::der;
use rust_kdc::error::codes;
use rust_kdc::hdb::{HdbEntry, MemoryHdb, flags as entry_flags};
use rust_kdc::kdc::{Kdc, KdcConfig};
use rust_kdc::msg::{
    self, ApReq, Authenticator, EncKdcRepPart, EncTicketPart, EncryptedData, Ticket,
    encode_pa_data, kdc_options, tkt_flags,
};
use rust_kdc::name::Principal;

const REALM: &str = "EXAMPLE.COM";
const SERVICE: &str = "cifs/files.example.com";
const PASSWORD: &[u8] = b"correct horse battery staple";
const NOW: i64 = 1_700_000_000;

/// `KRB5_KU_AS_REQ` — Heimdal's `lib/krb5/krb5.h`, and what `krb5` 1.0 verifies with.
const KU_AS_REQ: u32 = 56;
/// `KRB5_KU_TGS_REQ` — the same table, one past it.
const KU_TGS_REQ: u32 = 57;
/// `PA-REQ-ENC-PA-REP`.
const PA_REQ_ENC_PA_REP: i32 = 149;
/// TicketFlags `enc-pa-rep`: RFC numbering bit 15.
const ENC_PA_REP: u32 = 0x0001_0000;

fn alice() -> Principal {
    Principal::parse(&format!("alice@{REALM}")).unwrap()
}

fn service() -> Principal {
    Principal::parse(&format!("{SERVICE}@{REALM}")).unwrap()
}

fn db() -> MemoryHdb {
    let cipher = OwnCipher;
    let db = MemoryHdb::new();

    let mut krbtgt = HdbEntry::krbtgt(REALM);
    krbtgt
        .add_password_key(&cipher, Enctype::Aes256Sha1, b"master-key", 1)
        .unwrap();
    db.insert(krbtgt).unwrap();

    let mut user = HdbEntry::user(alice());
    // `HdbEntry::user` sets `require-preauth`, and these tests are about the reply, not about
    // the pre-authentication the client did.
    user.flags &= !entry_flags::REQUIRE_PREAUTH;
    user.add_password_key(&cipher, Enctype::Aes256Sha1, PASSWORD, 1)
        .unwrap();
    db.insert(user).unwrap();

    let mut svc = HdbEntry::service(service());
    svc.add_password_key(&cipher, Enctype::Aes256Sha1, b"service-key", 1)
        .unwrap();
    db.insert(svc).unwrap();

    db
}

fn kdc(require_preauth: bool) -> Kdc {
    Kdc::new(
        KdcConfig::new(REALM)
            .unwrap()
            .with_require_preauth(require_preauth),
        Arc::new(db()),
        Arc::new(OwnCipher),
    )
}

/// Alice's long-term key, which is the reply key when no pre-authentication replaced it.
fn alice_key() -> Key {
    let mut probe = HdbEntry::user(alice());
    probe
        .add_password_key(&OwnCipher, Enctype::Aes256Sha1, PASSWORD, 1)
        .unwrap();
    probe
        .key_for(Enctype::Aes256Sha1)
        .map(|k| k.key.clone())
        .expect("alice has a key")
}

/// An AS-REQ for alice's TGT, carrying `padata`.
fn as_req(padata: &[(i32, Vec<u8>)]) -> Vec<u8> {
    let body = der::seq(&[
        der::field(0, der::flags32(kdc_options::FORWARDABLE)),
        der::field(1, alice().encode_name()),
        der::field(2, der::general_string(REALM)),
        der::field(3, Principal::krbtgt(REALM).encode_name()),
        der::field(5, der::time(NOW + 3600)),
        der::field(7, der::int(0x4242)),
        der::field(8, der::seq(&[der::int(18)])),
    ]);
    let mut parts = vec![der::field(1, der::int(5)), der::field(2, der::int(10))];
    if !padata.is_empty() {
        parts.push(der::field(3, encode_pa_data(padata)));
    }
    parts.push(der::field(4, body));
    der::cons(der::app(10), &[der::seq(&parts)])
}

/// The `EncKDCRepPart` of an AS-REP, opened with the reply key.
fn as_rep_part(reply: &[u8], key: &Key) -> EncKdcRepPart {
    let f = der::Fields::parse_app("AS-REP", 11, reply).expect("an AS-REP");
    let enc = EncryptedData::decode("enc-part", f.bytes(6, "AS-REP").expect("enc-part"))
        .expect("an EncryptedData");
    let plain = OwnCipher
        .decrypt(key, usage::AS_REP_ENCPART, &enc.cipher)
        .expect("the reply opens with the reply key");
    EncKdcRepPart::decode(&plain).expect("an EncASRepPart")
}

/// The checksum out of `PA-REQ-ENC-PA-REP`: `(type, value)`.
fn request_checksum(rep: &EncKdcRepPart) -> Option<(i32, Vec<u8>)> {
    let value = rep
        .padata
        .iter()
        .find(|(t, _)| *t == PA_REQ_ENC_PA_REP)
        .map(|(_, v)| v)?;
    let mut r = der::Reader::new(value);
    let seq = r.expect_in("Checksum", der::SEQUENCE).ok()?;
    let f = der::Fields::parse("Checksum", seq).ok()?;
    Some((
        f.int(0, "Checksum").ok()? as i32,
        f.octets(1, "Checksum").ok()?.to_vec(),
    ))
}

#[test]
fn the_preauth_required_error_advertises_the_request_checksum() {
    // MIT's client sends `(149, empty)` only when it knows the KDC understands it; Heimdal and
    // MIT both list it in `METHOD-DATA`. Without the advertisement the client never asks, never
    // receives the checksum, and concludes the KDC has no FAST — hence no S4U.
    let reply = kdc(true).handle(&as_req(&[]), NOW);
    let err = msg::KrbError::decode(&reply).expect("a PREAUTH_REQUIRED");
    assert_eq!(err.code, codes::KDC_ERR_PREAUTH_REQUIRED);

    let data = err.e_data.expect("METHOD-DATA");
    let mut r = der::Reader::new(&data);
    let seq = r.expect_in("METHOD-DATA", der::SEQUENCE).unwrap();
    let padata = msg::decode_pa_data("METHOD-DATA", seq).unwrap();
    assert!(
        padata.iter().any(|(t, _)| *t == PA_REQ_ENC_PA_REP),
        "the error must offer PA-REQ-ENC-PA-REP: {:?}",
        padata.iter().map(|(t, _)| *t).collect::<Vec<_>>()
    );
}

#[test]
fn the_reply_carries_a_checksum_over_the_request_it_answered() {
    let request = as_req(&[(PA_REQ_ENC_PA_REP, Vec::new())]);
    let reply = kdc(false).handle(&request, NOW);
    assert!(
        msg::KrbError::decode(&reply).is_err(),
        "an AS-REQ asking for the checksum must be answered: {:?}",
        msg::KrbError::decode(&reply)
    );

    let key = alice_key();
    let rep = as_rep_part(&reply, &key);
    assert!(
        rep.flags & ENC_PA_REP != 0,
        "the `enc-pa-rep` flag must be set when the checksum is there: {:#010x}",
        rep.flags
    );

    let (ty, sum) = request_checksum(&rep).expect("PA-REQ-ENC-PA-REP in the encrypted part");
    assert_eq!(
        ty,
        Enctype::Aes256Sha1.checksum_type(),
        "the checksum type must be the reply key's, or a client rejects it as foreign"
    );
    // The client's side: verify with the reply key over the octets it sent.
    OwnCipher
        .verify_checksum(&key, KU_AS_REQ, &request, &sum)
        .expect("the checksum must verify over the request as sent");
}

#[test]
fn a_checksum_over_another_request_does_not_verify() {
    // The pair that makes the test above mean something: if the checksum were over anything
    // else — a re-encoding, a fixed value, the body only — this would pass too.
    let request = as_req(&[(PA_REQ_ENC_PA_REP, Vec::new())]);
    let reply = kdc(false).handle(&request, NOW);
    assert!(msg::KrbError::decode(&reply).is_err());

    let key = alice_key();
    let rep = as_rep_part(&reply, &key);
    let (_, sum) = request_checksum(&rep).expect("a checksum");

    let mut other = request.clone();
    let last = other.len() - 1;
    other[last] ^= 0x01;
    assert!(
        OwnCipher
            .verify_checksum(&key, KU_AS_REQ, &other, &sum)
            .is_err(),
        "a checksum that verified over altered bytes would be decoration"
    );
}

#[test]
fn a_request_that_did_not_ask_gets_no_checksum_and_no_flag() {
    // MIT's client decides whether to verify by the flag, so the two must move together: a flag
    // without a checksum makes the client reject a correct reply as modified.
    let reply = kdc(false).handle(&as_req(&[]), NOW);
    assert!(msg::KrbError::decode(&reply).is_err());

    let rep = as_rep_part(&reply, &alice_key());
    assert_eq!(
        rep.flags & ENC_PA_REP,
        0,
        "no request, no flag: the client would look for a checksum and find none"
    );
    assert!(request_checksum(&rep).is_none(), "and no checksum either");
}

/// A TGT for `service()` — no, for alice — plus its session key, so a TGS request can be built.
fn tgt(krbtgt_key: &Key) -> (Vec<u8>, Key) {
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

fn krbtgt_key() -> Key {
    // The key the test put in the database for `krbtgt/REALM`.
    let mut entry = HdbEntry::krbtgt(REALM);
    entry
        .add_password_key(&OwnCipher, Enctype::Aes256Sha1, b"master-key", 1)
        .unwrap();
    entry
        .key_for(Enctype::Aes256Sha1)
        .map(|k| k.key.clone())
        .unwrap()
}

fn tgs_req(ticket: &[u8], session_key: &Key, padata: &[(i32, Vec<u8>)]) -> Vec<u8> {
    let cipher = OwnCipher;
    let body = der::seq(&[
        der::field(0, der::flags32(0)),
        der::field(2, der::general_string(REALM)),
        der::field(3, service().encode_name()),
        der::field(5, der::time(NOW + 3600)),
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

    let mut all = vec![(msg::PA_TGS_REQ, ap_req)];
    all.extend_from_slice(padata);
    der::cons(
        der::app(12),
        &[der::seq(&[
            der::field(1, der::int(5)),
            der::field(2, der::int(12)),
            der::field(3, encode_pa_data(&all)),
            der::field(4, body),
        ])],
    )
}

#[test]
fn a_tgs_reply_carries_a_checksum_over_the_tgs_request() {
    // The same contract one exchange later, with usage 57 and the TGT's session key as the
    // reply key. A KDC that only did this for AS would leave every S4U2Proxy request unverifiable
    // — and those are TGS requests.
    let key = krbtgt_key();
    let (ticket, session) = tgt(&key);
    let request = tgs_req(&ticket, &session, &[(PA_REQ_ENC_PA_REP, Vec::new())]);
    let reply = kdc(false).handle(&request, NOW);
    assert!(
        msg::KrbError::decode(&reply).is_err(),
        "a TGS-REQ asking for the checksum must be answered: {:?}",
        msg::KrbError::decode(&reply)
    );

    let f = der::Fields::parse_app("TGS-REP", 13, &reply).unwrap();
    let enc = EncryptedData::decode("enc-part", f.bytes(6, "TGS-REP").expect("enc-part")).unwrap();
    let plain = OwnCipher
        .decrypt(&session, usage::TGS_REP_ENCPART_SESSKEY, &enc.cipher)
        .expect("the reply opens with the TGT's session key");
    let rep = EncKdcRepPart::decode(&plain).expect("an EncTGSRepPart");

    assert!(rep.flags & ENC_PA_REP != 0, "{:#010x}", rep.flags);
    let (ty, sum) = request_checksum(&rep).expect("PA-REQ-ENC-PA-REP");
    assert_eq!(ty, Enctype::Aes256Sha1.checksum_type());
    OwnCipher
        .verify_checksum(&session, KU_TGS_REQ, &request, &sum)
        .expect("the checksum verifies over the TGS request as sent");
}

#[test]
fn the_encrypted_pa_data_also_announces_fast() {
    // MIT's client reads FAST support from the presence of `PA-FX-FAST` *inside this encrypted
    // PA-DATA*, and reads S4U support from FAST. A KDC that sent the checksum alone would be
    // told apart from one that supports protocol transition by nothing, and the client would
    // never try S4U — which is the whole reason this value exists here.
    let request = as_req(&[(PA_REQ_ENC_PA_REP, Vec::new())]);
    let reply = kdc(false).handle(&request, NOW);
    assert!(msg::KrbError::decode(&reply).is_err());

    let rep = as_rep_part(&reply, &alice_key());
    assert!(
        rep.padata
            .iter()
            .any(|(t, _)| *t == rust_kdc::kdc::fast::PA_FX_FAST),
        "PA-FX-FAST must be in the encrypted PA-DATA: {:?}",
        rep.padata.iter().map(|(t, _)| *t).collect::<Vec<_>>()
    );
}
