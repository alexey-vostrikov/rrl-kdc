//! Every refusal a KDC makes is a different code, and the difference is the
//! whole point: a client that cannot tell "no such principal" from "wrong
//! password" from "your clock is wrong" guesses, and a client that is told the
//! realm it asked for is not served here goes looking for the right KDC.
//!
//! These tests speak to the engine directly, not over a socket: the request's
//! octets go in and the reply's octets come out, so a refusal is checked at the
//! level it is decided and a thousand of them cost nothing.

use std::sync::Arc;

use rust_heimdal_kdc::crypto::{Cipher, Enctype, Key, OwnCipher, usage};
use rust_heimdal_kdc::der;
use rust_heimdal_kdc::error::codes;
use rust_heimdal_kdc::hdb::{HdbEntry, MemoryHdb, flags as entry_flags};
use rust_heimdal_kdc::kdc::{Kdc, KdcConfig};
use rust_heimdal_kdc::msg::{
    self, EncryptedData, PA_ENC_TIMESTAMP, encode_enc_ts_enc, encode_etype_info2, encode_pa_data,
    kdc_options,
};
use rust_heimdal_kdc::name::Principal;

const REALM: &str = "EXAMPLE.COM";
const PASSWORD: &str = "correct horse battery staple";
const NOW: i64 = 1_700_000_000;

fn principal(name: &str) -> Principal {
    Principal::parse(&format!("{name}@{REALM}")).unwrap()
}

/// A realm with `krbtgt`, `alice` and nothing else.
fn db() -> MemoryHdb {
    let cipher = OwnCipher;
    let db = MemoryHdb::new();

    let mut krbtgt = HdbEntry::krbtgt(REALM);
    krbtgt
        .add_password_key(&cipher, Enctype::Aes256Sha1, b"master", 1)
        .unwrap();
    db.insert(krbtgt).unwrap();

    let mut alice = HdbEntry::user(principal("alice"));
    for e in [Enctype::Aes256Sha1, Enctype::Aes128Sha1] {
        alice
            .add_password_key(&cipher, e, PASSWORD.as_bytes(), 1)
            .unwrap();
    }
    db.insert(alice).unwrap();
    db
}

fn kdc() -> Kdc {
    Kdc::new(
        KdcConfig::new(REALM).unwrap(),
        Arc::new(db()),
        Arc::new(OwnCipher),
    )
}

/// An AS-REQ, built the way a client builds one.
fn as_req(name: &str, realm: &str, etypes: &[i32], padata: Vec<(i32, Vec<u8>)>) -> Vec<u8> {
    let client = Principal::parse(&format!("{name}@{realm}")).unwrap();
    let body = der::seq(&[
        der::field(0, der::flags32(kdc_options::FORWARDABLE)),
        der::field(1, client.encode_name()),
        der::field(2, der::general_string(realm)),
        der::field(3, Principal::krbtgt(realm).encode_name()),
        der::field(5, der::time(NOW + 3600)),
        der::field(7, der::int(0x1234_5678)),
        der::field(
            8,
            der::seq(
                &etypes
                    .iter()
                    .map(|e| der::int(*e as i64))
                    .collect::<Vec<_>>(),
            ),
        ),
    ]);
    let mut parts = vec![der::field(1, der::int(5)), der::field(2, der::int(10))];
    if !padata.is_empty() {
        parts.push(der::field(3, encode_pa_data(&padata)));
    }
    parts.push(der::field(4, body));
    der::cons(der::app(10), &[der::seq(&parts)])
}

/// A `PA-ENC-TIMESTAMP` value for `password`, at `timestamp`.
fn enc_timestamp(password: &[u8], enctype: Enctype, timestamp: i64) -> Vec<u8> {
    let cipher = OwnCipher;
    let key = cipher
        .s2k(enctype, password, b"EXAMPLE.COMalice", None)
        .unwrap();
    let plain = encode_enc_ts_enc(timestamp, None);
    EncryptedData::seal(&cipher, &key, usage::AS_REQ_PA_ENC_TS, None, &plain)
        .unwrap()
        .encode()
}

/// `METHOD-DATA`: the `PA-DATA` elements of an error's `e-data`.
type MethodData = Vec<(i32, Vec<u8>)>;

/// The code in a reply, and its `METHOD-DATA` when it has one.
fn reply_code(reply: &[u8]) -> (i32, Option<MethodData>) {
    let err = msg::KrbError::decode(reply)
        .unwrap_or_else(|e| panic!("the reply is not a KRB-ERROR: {e}"));
    (err.code, err.method_data().ok())
}

#[test]
fn an_unknown_principal_is_client_unknown() {
    let reply = kdc().handle(&as_req("nobody", REALM, &[18], Vec::new()), NOW);
    assert_eq!(reply_code(&reply).0, codes::KDC_ERR_C_PRINCIPAL_UNKNOWN);
}

#[test]
fn a_foreign_realm_is_wrong_realm() {
    // The realm is not ours; the client must be told so, not told that some
    // principal is missing from a realm we do not serve.
    let reply = kdc().handle(&as_req("alice", "OTHER.COM", &[18], Vec::new()), NOW);
    assert_eq!(reply_code(&reply).0, codes::KDC_ERR_WRONG_REALM);
}

#[test]
fn require_preauth_answers_with_the_method_data() {
    let reply = kdc().handle(&as_req("alice", REALM, &[18], Vec::new()), NOW);
    let (code, methods) = reply_code(&reply);
    assert_eq!(code, codes::KDC_ERR_PREAUTH_REQUIRED);
    let methods = methods.expect("PREAUTH_REQUIRED must carry METHOD-DATA");
    let etype_info2 = methods
        .iter()
        .find(|(t, _)| *t == msg::PA_ETYPE_INFO2)
        .map(|(_, v)| v.clone())
        .expect("METHOD-DATA must offer ETYPE-INFO2, or the client cannot compute a key");
    let entries = msg::decode_etype_info2(&etype_info2).unwrap();
    let entry = entries
        .iter()
        .find(|e| e.etype == Enctype::Aes256Sha1)
        .expect("the strongest enctype the client asked for must be offered");
    // The salt is the one the entry's key was made with, which is what the
    // client needs to derive the same key.
    assert_eq!(entry.salt.as_deref(), Some(&b"EXAMPLE.COMalice"[..]));
}

#[test]
fn a_wrong_password_is_preauth_failed_with_the_salts() {
    let padata = vec![(
        PA_ENC_TIMESTAMP,
        enc_timestamp(b"not my password", Enctype::Aes256Sha1, NOW),
    )];
    let reply = kdc().handle(&as_req("alice", REALM, &[18], padata), NOW);
    let (code, methods) = reply_code(&reply);
    assert_eq!(code, codes::KDC_ERR_PREAUTH_FAILED);
    assert!(
        methods.is_some(),
        "a failed pre-authentication must still carry the salts, or the client cannot tell \
         a wrong password from a wrong salt"
    );
}

#[test]
fn a_stale_timestamp_is_skew_and_not_a_wrong_password() {
    // A replay from a day ago: the credentials are right, the clock is not.
    // Answering PREAUTH_FAILED here sends the operator looking for a password.
    let padata = vec![(
        PA_ENC_TIMESTAMP,
        enc_timestamp(PASSWORD.as_bytes(), Enctype::Aes256Sha1, NOW - 86_400),
    )];
    let reply = kdc().handle(&as_req("alice", REALM, &[18], padata), NOW);
    assert_eq!(reply_code(&reply).0, codes::KRB_AP_ERR_SKEW);
}

#[test]
fn a_timestamp_in_the_future_is_skew_too() {
    let padata = vec![(
        PA_ENC_TIMESTAMP,
        enc_timestamp(PASSWORD.as_bytes(), Enctype::Aes256Sha1, NOW + 86_400),
    )];
    let reply = kdc().handle(&as_req("alice", REALM, &[18], padata), NOW);
    assert_eq!(reply_code(&reply).0, codes::KRB_AP_ERR_SKEW);
}

#[test]
fn a_preauth_just_inside_the_skew_is_accepted() {
    // The boundary that matters: five minutes is the default allowance, and a
    // client exactly at it is not late.
    let padata = vec![(
        PA_ENC_TIMESTAMP,
        enc_timestamp(PASSWORD.as_bytes(), Enctype::Aes256Sha1, NOW - 300),
    )];
    let reply = kdc().handle(&as_req("alice", REALM, &[18], padata), NOW);
    match msg::KrbError::decode(&reply) {
        Err(_) => {} // an AS-REP, which is what acceptance looks like
        Ok(err) => panic!(
            "a timestamp exactly at the allowance must be accepted, but the reply was \
             KRB-ERROR {} ({})",
            err.code,
            err.e_text.unwrap_or_default()
        ),
    }
}

#[test]
fn an_enctype_nobody_has_is_etype_nosupp() {
    // 23 is RC4, which this KDC does not implement; 1 is DES.
    let reply = kdc().handle(&as_req("alice", REALM, &[23, 1], Vec::new()), NOW);
    assert_eq!(reply_code(&reply).0, codes::KDC_ERR_ETYPE_NOSUPP);
}

#[test]
fn a_locked_account_is_client_revoked() {
    let cipher = OwnCipher;
    let db = MemoryHdb::new();
    let mut krbtgt = HdbEntry::krbtgt(REALM);
    krbtgt
        .add_password_key(&cipher, Enctype::Aes256Sha1, b"master", 1)
        .unwrap();
    db.insert(krbtgt).unwrap();
    let mut alice = HdbEntry::user(principal("alice"));
    alice
        .add_password_key(&cipher, Enctype::Aes256Sha1, PASSWORD.as_bytes(), 1)
        .unwrap();
    alice.flags |= entry_flags::LOCKED_OUT;
    db.insert(alice).unwrap();
    let kdc = Kdc::new(
        KdcConfig::new(REALM).unwrap(),
        Arc::new(db),
        Arc::new(cipher),
    );
    let padata = vec![(
        PA_ENC_TIMESTAMP,
        enc_timestamp(PASSWORD.as_bytes(), Enctype::Aes256Sha1, NOW),
    )];
    let reply = kdc.handle(&as_req("alice", REALM, &[18], padata), NOW);
    assert_eq!(reply_code(&reply).0, codes::KDC_ERR_CLIENT_REVOKED);
}

#[test]
fn a_tgs_request_is_answered_not_ignored() {
    // A TGS request sent with no evidence must be answered — the code is
    // checked in `tgs_errors`; what matters here is that it is not silence.
    let client = principal("alice");
    let body = der::seq(&[
        der::field(0, der::flags32(0)),
        der::field(2, der::general_string(REALM)),
        der::field(3, Principal::krbtgt(REALM).encode_name()),
        der::field(5, der::time(NOW + 3600)),
        der::field(7, der::int(1)),
        der::field(8, der::seq(&[der::int(18)])),
    ]);
    let req = der::cons(
        der::app(12),
        &[der::seq(&[
            der::field(1, der::int(5)),
            der::field(2, der::int(12)),
            der::field(4, body),
        ])],
    );
    let reply = kdc().handle(&req, NOW);
    let (code, _) = reply_code(&reply);
    assert_ne!(
        code, 0,
        "a request that cannot be served still gets an error code"
    );
    let _ = client;
}

#[test]
fn garbage_is_an_error_and_not_a_crash() {
    let kdc = kdc();
    for bad in [
        vec![],
        vec![0x6a],
        vec![0x6a, 0x02, 0x30, 0x00],
        vec![0xff; 64],
        as_req("alice", REALM, &[18], Vec::new())[..20].to_vec(),
    ] {
        let reply = kdc.handle(&bad, NOW);
        let err = msg::KrbError::decode(&reply)
            .expect("every malformed request must be answered with a KRB-ERROR");
        assert_ne!(err.code, 0, "an error must carry a code");
    }
}

/// An enctype the client asked for and this KDC issues, but the entry has no
/// key for, must not become the session key: the client cannot use a key type
/// it holds no long-term key for, and the KDC cannot check its pre-authentication
/// with one.
#[test]
fn an_enctype_the_entry_has_no_key_for_is_not_chosen() {
    let cipher = OwnCipher;
    let reply = kdc().handle(
        &as_req(
            "alice",
            REALM,
            // 20 is aes256-cts-hmac-sha384-192: allowed here, requested by the
            // client, and absent from alice's entry.
            &[20, 18],
            vec![(
                PA_ENC_TIMESTAMP,
                enc_timestamp(PASSWORD.as_bytes(), Enctype::Aes256Sha1, NOW),
            )],
        ),
        NOW,
    );
    assert!(
        msg::KrbError::decode(&reply).is_err(),
        "the request is valid and must be answered with an AS-REP, not an error"
    );

    // Read the session key out of the reply's encrypted part, which is the only
    // place that says which enctype the KDC settled on.
    let rep = read_as_rep(&reply);
    let key = cipher
        .s2k(
            Enctype::Aes256Sha1,
            PASSWORD.as_bytes(),
            b"EXAMPLE.COMalice",
            None,
        )
        .unwrap();
    assert_eq!(
        rep.enc_part.etype,
        Enctype::Aes256Sha1,
        "the reply is encrypted in the client's key, which is AES-256-SHA1 here"
    );
    let plain = cipher
        .decrypt(&key, usage::AS_REP_ENCPART, &rep.enc_part.cipher)
        .expect("the client must be able to decrypt its own reply");
    let part = msg::EncKdcRepPart::decode(&plain).unwrap();
    assert_eq!(
        part.session_key.enctype(),
        Enctype::Aes256Sha1,
        "session key enctype must be one the entry has a long-term key for; \
         aes256-cts-hmac-sha384-192 is not"
    );
}

/// The outer `KDC-REP`, decoded from what the engine produced.
fn read_as_rep(reply: &[u8]) -> AsRepView {
    let f = rust_heimdal_kdc::der::Fields::parse_app("KDC-REP", 11, reply).unwrap();
    // The client and realm are checked by the acceptance test against a real
    // client; here only the encrypted part matters.
    let _crealm = f.string(3, "KDC-REP").unwrap();
    let mut r = rust_heimdal_kdc::der::Reader::new(f.get(6, "KDC-REP").unwrap());
    let enc_part = EncryptedData::decode(
        "enc-part",
        &rust_heimdal_kdc::der::tlv(
            rust_heimdal_kdc::der::SEQUENCE,
            r.expect("enc-part", rust_heimdal_kdc::der::SEQUENCE)
                .unwrap(),
        ),
    )
    .unwrap();
    AsRepView { enc_part }
}

struct AsRepView {
    enc_part: EncryptedData,
}

/// The salt in `METHOD-DATA` must be the one the entry's key was made with,
/// even when it is not the principal's default salt.
#[test]
fn the_advertised_salt_is_the_one_the_key_was_made_with() {
    let cipher = OwnCipher;
    let db = MemoryHdb::new();
    let mut krbtgt = HdbEntry::krbtgt(REALM);
    krbtgt
        .add_password_key(&cipher, Enctype::Aes256Sha1, b"master", 1)
        .unwrap();
    db.insert(krbtgt).unwrap();
    let mut alice = HdbEntry::user(principal("alice"));
    let key = cipher
        .s2k(
            Enctype::Aes256Sha1,
            PASSWORD.as_bytes(),
            b"a salt from before the rename",
            None,
        )
        .unwrap();
    alice.add_key(key, 1, Some(b"a salt from before the rename".to_vec()));
    db.insert(alice).unwrap();

    let kdc = Kdc::new(
        KdcConfig::new(REALM).unwrap(),
        Arc::new(db),
        Arc::new(cipher),
    );
    let reply = kdc.handle(&as_req("alice", REALM, &[18], Vec::new()), NOW);
    let (_, methods) = reply_code(&reply);
    let entries = msg::decode_etype_info2(
        &methods
            .unwrap()
            .into_iter()
            .find(|(t, _)| *t == msg::PA_ETYPE_INFO2)
            .unwrap()
            .1,
    )
    .unwrap();
    assert_eq!(
        entries[0].salt.as_deref(),
        Some(&b"a salt from before the rename"[..]),
        "recomputing the salt from the principal's name would break every key made \
         before the name changed"
    );
    let _ = (
        Key::new(Enctype::Aes128Sha1, vec![0u8; 16]),
        encode_etype_info2(&[]),
    );
}
