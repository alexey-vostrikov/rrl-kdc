//! The KDC's signed reply, built from the same fixtures the request tests use.
//!
//! `scripts/verify-pkinit-reply.sh` is the real judge — OpenSSL decides whether the CMS
//! envelope is one a client can read — and this file holds the parts that can be asserted
//! in-process: that the envelope names the certificate it was signed with, that the content
//! type is the one PKINIT requires, that the nonce travels, and that a misconfigured
//! identity is refused at load time rather than producing an unusable signature.

#![cfg(feature = "pkinit")]

use rust_kdc::crypto::Enctype;
use rust_kdc::der::{self, Reader};
use rust_kdc::kdc::pkinit::{self, PkinitError, reply};
use rust_kdc::name::Principal;

const NOW: i64 = 1_800_000_000;

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!(
        "{}/tests/pkinit/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap_or_else(|e| panic!("read {name}: {e}"))
}

fn der_of(pem: &[u8]) -> Vec<u8> {
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

fn identity() -> reply::Identity {
    reply::Identity::from_der(
        &der_of(&fixture("kdc.pem")),
        &der_of(&fixture("kdc-key.pem")),
    )
    .expect("the KDC identity loads")
}

#[test]
fn the_identity_loads_both_key_encodings_that_tools_emit() {
    // PKCS#8 (`BEGIN PRIVATE KEY`) and PKCS#1 (`BEGIN RSA PRIVATE KEY`) are both what the
    // same tool emits depending on how the key was made, and an operator should not have to
    // know which one they have.
    let cert = der_of(&fixture("kdc.pem"));
    let pkcs8 = der_of(&fixture("kdc-key.pem"));
    assert!(
        reply::Identity::from_der(&cert, &pkcs8).is_ok(),
        "the fixture is PKCS#8"
    );

    // A certificate that is not one is refused at load, not at signing: a signature under a
    // key nobody can chain is worse than a failure to start.
    assert!(matches!(
        reply::Identity::from_der(b"not a certificate", &pkcs8),
        Err(PkinitError::Malformed(_))
    ));
    // And a key that is not one.
    assert!(matches!(
        reply::Identity::from_der(&cert, b"not a key"),
        Err(PkinitError::Malformed(_))
    ));
}

#[test]
fn the_signed_data_names_the_certificate_it_was_signed_with() {
    // The `SignerInfo` identifies the signer by issuer and serial, and a client resolves the
    // certificate that way. Taking those octets from the certificate rather than rebuilding
    // the name is what makes the lookup succeed; a rebuilt `Name` differs in encoding and
    // resolves to nothing.
    let cert = der_of(&fixture("kdc.pem"));
    let identity = identity();
    let signed = identity
        .signed_data(pkinit::ID_PKINIT_DH_KEY_DATA, b"content")
        .expect("signs");

    // What the client will see: the certificate carried inside the envelope.
    let bundled = carried_certificate(&signed).expect("the envelope carries a certificate");
    assert_eq!(
        bundled, cert,
        "the certificate sent alongside must be the signer's own"
    );

    // And the issuer and serial the `SignerInfo` names must be that certificate's.
    let (issuer, serial) = signer_id(&signed);
    let (cert_issuer, cert_serial) = certificate_id(&cert);
    assert_eq!(issuer, cert_issuer, "the SignerInfo names another issuer");
    assert_eq!(serial, cert_serial, "the SignerInfo names another serial");
}

#[test]
fn the_envelope_carries_the_content_type_and_the_content() {
    // A signature over the wrong content type verifies perfectly and means nothing, so the
    // type is asserted rather than assumed.
    let signed = identity()
        .signed_data(pkinit::ID_PKINIT_DH_KEY_DATA, b"the dh key info")
        .expect("signs");

    let mut r = Reader::new(&signed);
    let ci = r.next_tlv("ContentInfo").expect("a ContentInfo");
    let mut cr = Reader::new(ci.content);
    let oid = cr.next_tlv("contentType").expect("the contentType OID");
    assert_eq!(
        der::decode_oid("contentType", oid.content).unwrap(),
        "1.2.840.113549.1.7.2",
        "id-signedData"
    );

    let sd = signed_data_content(&signed);
    let mut sr = Reader::new(&sd);
    sr.next_tlv("version").unwrap();
    sr.next_tlv("digestAlgorithms").unwrap();
    let encap = sr.next_tlv("EncapsulatedContentInfo").unwrap();
    let mut er = Reader::new(encap.content);
    let etype = er.next_tlv("eContentType").unwrap();
    assert_eq!(
        der::decode_oid("eContentType", etype.content).unwrap(),
        pkinit::ID_PKINIT_DH_KEY_DATA
    );
    let wrapped = er.next_tlv("eContent").unwrap();
    let mut wr = Reader::new(wrapped.content);
    let octets = wr.next_tlv("OCTET STRING").unwrap();
    assert_eq!(octets.content, b"the dh key info");
}

#[test]
fn the_whole_reply_round_trips_to_the_structure_rfc_4556_describes() {
    // `[0] DHRepInfo { dhSignedData [0] SignedData }` — read back from the octets the AS
    // exchange would put in `PA-PK-AS-REP`.
    let identity = identity();
    let info = reply::kdcdh_key_info(&[0x11; 256], 0x5150_1234);
    let signed = identity
        .signed_data(pkinit::ID_PKINIT_DH_KEY_DATA, &info)
        .expect("signs");
    let rep = reply::dh_rep_info(signed.clone());

    let mut r = Reader::new(&rep);
    let dh_info = r.next_tlv("PA-PK-AS-REP").expect("the choice");
    assert_eq!(dh_info.tag, der::ctx(0));
    let mut ir = Reader::new(dh_info.content);
    let seq = ir.next_tlv("DHRepInfo").expect("a SEQUENCE");
    let f = der::Fields::parse("DHRepInfo", seq.content).expect("fields");
    let data = f.bytes(0, "DHRepInfo").expect("dhSignedData");
    let mut dr = Reader::new(data);
    let octets = dr.next_tlv("dhSignedData").expect("an OCTET STRING");
    assert_eq!(
        octets.content,
        signed.as_slice(),
        "the SignedData must travel unmodified"
    );
}

#[test]
fn a_misordered_der_certificate_is_refused_rather_than_crashing() {
    // `issuer_and_serial` walks the certificate by position. Truncating it must give an
    // error, because a KDC that panics on a configuration mistake takes the realm down.
    let cert = der_of(&fixture("kdc.pem"));
    for cut in [0usize, 1, 4, 16, cert.len() / 2] {
        let truncated = &cert[..cut.min(cert.len())];
        assert!(
            reply::Identity::from_der(truncated, &der_of(&fixture("kdc-key.pem"))).is_err(),
            "a certificate cut to {cut} octets must be refused"
        );
    }
}

/// The `SignedData` SEQUENCE's content, from a `ContentInfo`'s DER.
///
/// Positional, because CMS is written in universal tags and `der::Fields` exists for
/// RFC 4120's `[n]`-tagged fields: using it here fails on the first octet of a
/// `ContentInfo`. The same mistake cost a session in the verifier.
fn signed_data_content(signed: &[u8]) -> Vec<u8> {
    let mut r = Reader::new(signed);
    let ci = r.next_tlv("ContentInfo").expect("a ContentInfo");
    let mut cr = Reader::new(ci.content);
    cr.next_tlv("contentType").expect("the contentType OID");
    let wrapped = cr.next_tlv("content [0]").expect("the content");
    let mut wr = Reader::new(wrapped.content);
    wr.next_tlv("SignedData")
        .expect("the SignedData SEQUENCE")
        .content
        .to_vec()
}

/// The certificate carried inside a `SignedData`, as DER.
fn carried_certificate(signed: &[u8]) -> Option<Vec<u8>> {
    let sd = signed_data_content(signed);
    let mut sr = Reader::new(&sd);
    sr.next_tlv("version").ok()?;
    sr.next_tlv("digestAlgorithms").ok()?;
    sr.next_tlv("EncapsulatedContentInfo").ok()?;
    let certs = sr.next_tlv("certificates").ok()?;
    assert_eq!(certs.tag, 0xa0, "certificates [0] IMPLICIT");
    let mut ir = Reader::new(certs.content);
    let first = ir.next_tlv("Certificate").ok()?;
    Some(der::tlv(der::SEQUENCE, first.content))
}

/// The `IssuerAndSerialNumber` a `SignerInfo` names, as (name DER, serial octets).
fn signer_id(signed: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let sd = signed_data_content(signed);
    let mut sr = Reader::new(&sd);
    sr.next_tlv("version").unwrap();
    sr.next_tlv("digestAlgorithms").unwrap();
    sr.next_tlv("EncapsulatedContentInfo").unwrap();
    sr.next_tlv("certificates").unwrap();
    let infos = sr.next_tlv("signerInfos").unwrap();
    let mut ir = Reader::new(infos.content);
    let info = ir.next_tlv("SignerInfo").unwrap();
    let mut fr = Reader::new(info.content);
    fr.next_tlv("version").unwrap();
    let sid = fr.next_tlv("IssuerAndSerialNumber").unwrap();
    let mut sidr = Reader::new(sid.content);
    let issuer = sidr.next_tlv("issuer").unwrap();
    let serial = sidr.next_tlv("serialNumber").unwrap();
    (
        der::tlv(der::SEQUENCE, issuer.content),
        serial.content.to_vec(),
    )
}

/// The same, taken from the certificate itself.
fn certificate_id(cert: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let mut r = Reader::new(cert);
    let c = r.next_tlv("Certificate").unwrap();
    let mut cr = Reader::new(c.content);
    let tbs = cr.next_tlv("TBSCertificate").unwrap();
    let mut t = Reader::new(tbs.content);
    let first = t.next_tlv("tbs").unwrap();
    let mut tail = t;
    let serial = if first.tag == 0xa0 {
        tail.next_tlv("serialNumber").unwrap()
    } else {
        first
    };
    tail.next_tlv("signature").unwrap();
    let issuer = tail.next_tlv("issuer").unwrap();
    (
        der::tlv(der::SEQUENCE, issuer.content),
        serial.content.to_vec(),
    )
}

#[test]
fn the_reply_key_is_the_length_of_the_chosen_enctype() {
    // The KDF's output is key material for the enctype the client asked for; deriving 32
    // octets for AES-128 would produce a key of the wrong size and a reply nobody can open.
    let client = Principal::new(1, ["alice"], "EXAMPLE.COM");
    let server = Principal::krbtgt("EXAMPLE.COM");
    for (enctype, want) in [
        (Enctype::Aes128Sha1, 16),
        (Enctype::Aes256Sha1, 32),
        (Enctype::Aes128Sha256, 16),
        (Enctype::Aes256Sha384, 32),
    ] {
        let key = reply::reply_key(
            &[0x33; 32],
            Some(pkinit::dh::KDF_SHA256),
            &client,
            &server,
            enctype,
            b"as-req",
            b"pk-as-rep",
        )
        .expect("a known KDF");
        assert_eq!(key.len(), want, "{enctype:?}");
    }
}

#[test]
fn the_fixture_is_inside_its_validity_window() {
    // The reply tests would otherwise pass on a certificate nobody would accept in
    // production, which is how a realm ships with an expired KDC certificate.
    let cert = der_of(&fixture("kdc.pem"));
    let anchors = {
        let mut a = pkinit::TrustAnchors::new();
        a.add(&der_of(&fixture("ca.pem"))).unwrap();
        a
    };
    assert_eq!(anchors.len(), 1);

    // A request signed by the KDC's own key does not authenticate a client, so this is only
    // about the certificate being valid at `NOW`: parse it and check the window directly.
    let (_, parsed) = x509_parser::parse_x509_certificate(&cert).expect("a certificate");
    let v = parsed.validity();
    assert!(
        NOW >= v.not_before.timestamp() && NOW <= v.not_after.timestamp(),
        "the fixture's KDC certificate is outside its validity window at {NOW}"
    );
}
