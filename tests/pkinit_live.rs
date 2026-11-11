//! PKINIT wired into the AS exchange: a certificate login produces a TGT.
//!
//! The format of the reply is judged by OpenSSL (`scripts/verify-pkinit-reply.sh`); what
//! this file judges is the wiring — that a `PA-PK-AS-REQ` reaching `handle_as` produces an
//! AS-REP whose `enc-part` opens with the key the client can derive, which is the whole
//! point of the exchange and the one thing a format check cannot see.
//!
//! The client side is built here rather than by `openssl cms -sign`, because the client's
//! Diffie-Hellman private exponent has to stay in the test for it to derive the same key —
//! and because the signature's format is already covered elsewhere. The signature is made
//! with the `rsa` crate directly, not through `reply::Identity::signed_data`, so a mistake
//! in that function cannot make this test pass.

#![cfg(feature = "pkinit")]

use std::sync::Arc;

use num_bigint::BigUint;
use rrl_kdc::crypto::{Cipher, Enctype, Key, OwnCipher, usage};
use rrl_kdc::der;
use rrl_kdc::hdb::{HdbEntry, MemoryHdb};
use rrl_kdc::kdc::pkinit::{self, dh, reply};
use rrl_kdc::kdc::{Kdc, KdcConfig};
use rrl_kdc::name::Principal;

const REALM: &str = "EXAMPLE.COM";
const NOW: i64 = 1_800_000_000;

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!(
        "{}/tests/pkinit/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap_or_else(|e| panic!("read {name}: {e}"))
}

fn pem_to_der(pem: &[u8]) -> Vec<u8> {
    use base64::Engine;
    let text = String::from_utf8_lossy(pem);
    let body: String = text
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect::<Vec<_>>()
        .join("");
    base64::engine::general_purpose::STANDARD
        .decode(body.trim())
        .expect("PEM body is base64")
}

fn alice() -> Principal {
    Principal::parse(&format!("alice@{REALM}")).unwrap()
}

/// The realm, with `krbtgt`, `alice`, and PKINIT configured from the fixtures.
fn kdc() -> Kdc {
    let cipher = OwnCipher;
    let db = MemoryHdb::new();

    let mut krbtgt = HdbEntry::krbtgt(REALM);
    for e in [Enctype::Aes256Sha1, Enctype::Aes128Sha1] {
        krbtgt
            .add_password_key(&cipher, e, b"master-key-of-the-realm", 1)
            .unwrap();
    }
    db.insert(krbtgt).unwrap();

    let mut user = HdbEntry::user(alice());
    for e in [Enctype::Aes256Sha1, Enctype::Aes128Sha1] {
        user.add_password_key(&cipher, e, b"password-of-alice", 1)
            .unwrap();
    }
    db.insert(user).unwrap();

    let mut anchors = pkinit::TrustAnchors::new();
    anchors.add(&pem_to_der(&fixture("ca.pem"))).unwrap();

    let state = reply::State {
        policy: Default::default(),
        identity: reply::Identity::from_der(
            &pem_to_der(&fixture("kdc.pem")),
            &pem_to_der(&fixture("kdc-key.pem")),
        )
        .expect("the KDC identity"),
        anchors,
    };

    Kdc::new(
        KdcConfig::new(REALM).unwrap(),
        Arc::new(db),
        Arc::new(OwnCipher),
    )
    .with_pkinit(Arc::new(state))
}

/// The `AS-REQ` a PKINIT client sends, built and signed by the fixture example.
///
/// The signature is OpenSSL's and the client's Diffie-Hellman exponent comes back with the
/// request, because only the client can derive the reply key: a test that signed with this
/// crate's own code would agree with a mistake in it, and one that did not hold the exponent
/// could not check that the reply opens at all.
fn pkinit_as_req() -> (Vec<u8>, BigUint) {
    let request = fixture("pkinit-as-req.der");
    let exponent = fixture("pkinit-client-exponent.bin");
    (request, BigUint::from_bytes_be(&exponent))
}

/// The `PA-DATA` of an AS-REP.
fn rep_padata(reply: &[u8]) -> Vec<(i32, Vec<u8>)> {
    let f = der::Fields::parse_app("AS-REP", 11, reply).expect("an AS-REP");
    match f.opt_bytes(2) {
        None => Vec::new(),
        Some(raw) => {
            let mut r = der::Reader::new(raw);
            let seq = r.next_tlv("PA-DATA").expect("a SEQUENCE");
            rrl_kdc::msg::decode_pa_data("AS-REP", seq.content).expect("PA-DATA")
        }
    }
}

#[test]
fn a_certificate_login_produces_a_tgt_the_client_can_read() {
    // The whole exchange, end to end: the client's certificate authenticates it, the DH
    // values agree, and the reply's `enc-part` opens with the key both sides derived.
    let kdc = kdc();
    let (request, private) = pkinit_as_req();

    let reply = kdc.handle(&request, NOW);
    assert!(
        rrl_kdc::msg::KrbError::decode(&reply).is_err(),
        "a valid certificate login must produce a ticket: {:?}",
        rrl_kdc::msg::KrbError::decode(&reply)
    );

    // The reply must carry `PA-PK-AS-REP`, or the client cannot derive the key at all.
    let padata = rep_padata(&reply);
    let pa_pk_as_rep = padata
        .iter()
        .find(|(t, _)| *t == pkinit::PA_PK_AS_REP)
        .map(|(_, v)| v.clone())
        .expect("an AS-REP to a PKINIT request must carry PA-PK-AS-REP");

    // The client's half: open `DHRepInfo`, take the KDC's public value out of the signed
    // `KDCDHKeyInfo`, and agree. The signature is not checked here — OpenSSL does that in
    // `scripts/verify-pkinit-reply.sh`, and re-checking it with our own verifier would make
    // the test agree with a mistake.
    let kdc_public = kdc_public_value(&pa_pk_as_rep);
    let group = dh::Group::at_least(2048);
    let ours = dh::KeyPair::from_private(group, private);
    let z = ours
        .agree(&kdc_public)
        .expect("the KDC's value is in the group");

    // `enc-part`'s enctype tells which enctype the client should derive for.
    let f = der::Fields::parse_app("AS-REP", 11, &reply).expect("an AS-REP");
    let enc_part =
        rrl_kdc::msg::EncryptedData::decode("enc-part", f.bytes(6, "AS-REP").expect("enc-part"))
            .expect("an EncryptedData");

    // Derive as the client does. The KDF is the one this KDC prefers among those the request
    // offered — but the request offered none, so this is the legacy `octetstring2key`.
    let key_bytes = reply::reply_key(
        &z,
        None,
        &alice(),
        &Principal::krbtgt(REALM),
        enc_part.etype,
        &request,
        &pa_pk_as_rep,
    )
    .expect("the legacy KDF");
    let key = Key::new(enc_part.etype, key_bytes).expect("a key");

    let plain = OwnCipher
        .decrypt(&key, usage::AS_REP_ENCPART, &enc_part.cipher)
        .expect("the reply must open with the key the client derived");
    assert!(
        !plain.is_empty(),
        "the decrypted EncASRepPart must not be empty"
    );

    // And the ticket is a real one: it decrypts under `krbtgt`'s key.
    assert!(
        f.opt_bytes(5).is_some(),
        "the reply must carry a ticket, not only a key"
    );
}

/// The KDC's DH public value out of a `PA-PK-AS-REP`.
fn kdc_public_value(pa_value: &[u8]) -> Vec<u8> {
    let mut r = der::Reader::new(pa_value);
    let dh_info = r.next_tlv("PA-PK-AS-REP").expect("the choice");
    assert_eq!(dh_info.tag, der::ctx(0), "dhInfo [0]");
    let mut ir = der::Reader::new(dh_info.content);
    let seq = ir.next_tlv("DHRepInfo").expect("a SEQUENCE");
    let mut sr = der::Reader::new(seq.content);
    let signed_tlv = sr.next_tlv("dhSignedData").expect("dhSignedData");
    let mut dr = der::Reader::new(signed_tlv.content);
    let octets = dr.next_tlv("OCTET STRING").expect("an OCTET STRING");

    // Walk the CMS envelope to its content: `ContentInfo { OID, [0] SignedData }`, and the
    // `KDCDHKeyInfo` inside `EncapsulatedContentInfo`.
    let mut cr = der::Reader::new(octets.content);
    let ci = cr.next_tlv("ContentInfo").expect("a ContentInfo");
    let mut cir = der::Reader::new(ci.content);
    cir.next_tlv("contentType").expect("the OID");
    let wrapped = cir.next_tlv("content").expect("the content");
    let mut wr = der::Reader::new(wrapped.content);
    let sd = wr.next_tlv("SignedData").expect("a SignedData");
    let mut sdr = der::Reader::new(sd.content);
    sdr.next_tlv("version").unwrap();
    sdr.next_tlv("digestAlgorithms").unwrap();
    let encap = sdr.next_tlv("EncapsulatedContentInfo").unwrap();
    let mut er = der::Reader::new(encap.content);
    er.next_tlv("eContentType").unwrap();
    let econtent = er.next_tlv("eContent").unwrap();
    let mut ecr = der::Reader::new(econtent.content);
    let info_octets = ecr
        .next_tlv("OCTET STRING")
        .expect("the KDCDHKeyInfo octets");

    // `KDCDHKeyInfo ::= SEQUENCE { [0] BIT STRING, [1] INTEGER }`
    let mut kr = der::Reader::new(info_octets.content);
    let info = kr.next_tlv("KDCDHKeyInfo").expect("a SEQUENCE");
    let mut krr = der::Reader::new(info.content);
    let key_tlv = krr.next_tlv("subjectPublicKey").expect("the key");
    let mut br = der::Reader::new(key_tlv.content);
    let bits = br.next_tlv("BIT STRING").expect("a BIT STRING");
    bits.content[1..].to_vec()
}

#[test]
fn a_realm_without_pkinit_refuses_a_certificate_login() {
    // The pair that keeps the test above from passing for the wrong reason: a KDC that
    // silently ignored `PA-PK-AS-REQ` would fall through to the password path and answer
    // with `PREAUTH_REQUIRED`, which looks like a working realm that simply wants a
    // password — and leaves the client guessing.
    let cipher = OwnCipher;
    let db = MemoryHdb::new();
    let mut krbtgt = HdbEntry::krbtgt(REALM);
    for e in [Enctype::Aes256Sha1, Enctype::Aes128Sha1] {
        krbtgt
            .add_password_key(&cipher, e, b"master-key-of-the-realm", 1)
            .unwrap();
    }
    db.insert(krbtgt).unwrap();
    let mut user = HdbEntry::user(alice());
    user.add_password_key(&cipher, Enctype::Aes256Sha1, b"password-of-alice", 1)
        .unwrap();
    db.insert(user).unwrap();
    let plain = Kdc::new(
        KdcConfig::new(REALM).unwrap(),
        Arc::new(db),
        Arc::new(OwnCipher),
    );

    let (request, _) = pkinit_as_req();
    let reply = plain.handle(&request, NOW);
    let err = rrl_kdc::msg::KrbError::decode(&reply)
        .expect("a realm without PKINIT must refuse, not fall through");
    assert_eq!(err.code, rrl_kdc::error::codes::KDC_ERR_PREAUTH_FAILED);
    assert!(
        err.e_text
            .unwrap_or_default()
            .contains("certificate logins"),
        "the refusal must say that the realm does not accept them"
    );
}
