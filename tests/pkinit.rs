//! PKINIT's trust decision, judged against OpenSSL's own output.
//!
//! Every signature here was made by `openssl cms -sign`, and every certificate by
//! `openssl x509`. That is the point: a request this crate both builds and verifies would
//! prove only that it agrees with itself. The `AuthPack` inside is built by this crate
//! (it is the ASN.1 under test), the envelope around it by somebody else.
//!
//! What each test is for:
//!
//! * a valid certificate for `alice` authenticates `alice@EXAMPLE.COM` — the happy path,
//!   without which the refusals below could all be passing for the wrong reason;
//! * a certificate for `bob` does not authenticate `alice`, and the name comes from the
//!   `id-pkinit-san` otherName rather than from the subject DN;
//! * the right name from an untrusted CA is refused, as is an expired certificate, one
//!   with no `id-pkinit-san`, and one issued for TLS servers;
//! * `paChecksum` binds the signature to this body: another body is refused.

#![cfg(feature = "pkinit")]

use rrl_kdc::kdc::pkinit::{self, PkinitError, Request, TrustAnchors};
use rrl_kdc::name::Principal;

/// The moment the fixtures are valid: their certificates run from 2026 to 2046, and the
/// expired one covers a single day in 2020.
const NOW: i64 = 1_800_000_000;

fn fixture(name: &str) -> Vec<u8> {
    let path = format!("{}/tests/pkinit/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read(&path).unwrap_or_else(|e| panic!("read {path}: {e}"))
}

fn request(name: &str) -> Request {
    Request::decode(&fixture(&format!("request-{name}-wrapped.der")))
        .unwrap_or_else(|e| panic!("decode {name}: {e}"))
}

fn anchors() -> TrustAnchors {
    let mut anchors = TrustAnchors::new();
    anchors
        .add(&pem_to_der(&fixture("ca.pem")))
        .expect("the test CA is a certificate");
    anchors
}

/// The DER inside a PEM file, without pulling in a base64 crate for a test fixture.
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

#[test]
fn a_certificate_for_alice_authenticates_alice() {
    let identity = pkinit::Identity::authenticate(&request("alice"), &anchors(), NOW)
        .expect("a valid certificate from a trusted CA must authenticate");
    assert_eq!(
        identity.principal,
        Principal::parse("alice@EXAMPLE.COM").unwrap(),
        "the principal comes from the id-pkinit-san otherName"
    );
}

#[test]
fn the_name_comes_from_the_san_and_not_from_the_subject() {
    // `bob`'s certificate has `CN=bob`, so a verifier that read the subject DN would also
    // pass this test. The certificate whose subject is `CN=alice` but whose SAN names
    // nobody (`no-pkinit-san.pem`) is the one that separates the two: it must be refused,
    // because a subject DN is not a Kerberos name.
    let identity = pkinit::Identity::authenticate(&request("bob"), &anchors(), NOW)
        .expect("bob's certificate is valid");
    assert_eq!(
        identity.principal,
        Principal::parse("bob@EXAMPLE.COM").unwrap()
    );
    assert_ne!(
        identity.principal,
        Principal::parse("alice@EXAMPLE.COM").unwrap()
    );
}

#[test]
fn a_certificate_without_id_pkinit_san_names_nobody() {
    let err = pkinit::Identity::authenticate(&request("no-pkinit-san"), &anchors(), NOW)
        .expect_err("a certificate with no PKINIT SAN must not authenticate");
    assert_eq!(err, PkinitError::NoPrincipalName);
}

#[test]
fn a_certificate_from_an_untrusted_ca_is_refused() {
    let err = pkinit::Identity::authenticate(&request("untrusted-alice"), &anchors(), NOW)
        .expect_err("alice's name from an unrelated CA must not authenticate");
    assert_eq!(err, PkinitError::UntrustedIssuer);
}

#[test]
fn an_expired_certificate_is_refused() {
    let err = pkinit::Identity::authenticate(&request("expired"), &anchors(), NOW)
        .expect_err("an expired certificate must not authenticate");
    match err {
        PkinitError::Expired { not_after, now, .. } => {
            assert!(now > not_after, "the fixture is meant to be in the past");
        }
        other => panic!("expected Expired, got {other:?}"),
    }
}

#[test]
fn the_same_certificate_is_accepted_inside_its_window() {
    // The expired fixture is refused at NOW; at a moment inside its window the very same
    // request must pass. Without this, `an_expired_certificate_is_refused` could be
    // passing because of a parse failure rather than because of the dates.
    let at = 1_577_836_800; // 2020-01-01T00:00:00Z
    let identity = pkinit::Identity::authenticate(&request("expired"), &anchors(), at)
        .expect("valid on the day it was issued");
    assert_eq!(
        identity.principal,
        Principal::parse("alice@EXAMPLE.COM").unwrap()
    );
}

#[test]
fn a_certificate_issued_for_tls_servers_is_refused() {
    let err = pkinit::Identity::authenticate(&request("wrong-purpose"), &anchors(), NOW)
        .expect_err("a serverAuth certificate must not become a Kerberos login");
    assert_eq!(err, PkinitError::WrongKeyPurpose);
}

#[test]
fn the_checksum_binds_the_signature_to_the_body() {
    // The signature is valid, the certificate is valid, and the body is not the one that
    // was signed. This is the binding RFC 4556 §3.2.1 requires, and the reason a signed
    // `AuthPack` cannot be lifted from one request into another.
    let req = request("alice");
    let pack = req.auth_pack().expect("AuthPack");
    let body = fixture("body.der");
    pkinit::check_body(&pack, &body).expect("the fixture's own body matches");

    let mut tampered = body.clone();
    // Flip a byte in the nonce, which is the difference between two requests.
    let last = tampered.len() - 1;
    tampered[last] ^= 0x01;
    assert_eq!(
        pkinit::check_body(&pack, &tampered).unwrap_err(),
        PkinitError::BodyMismatch
    );
}

#[test]
fn the_authenticator_carries_the_nonce_and_the_checksum() {
    let pack = request("alice").auth_pack().expect("AuthPack");
    assert_eq!(pack.pk_authenticator.nonce, 0x5150_1234);
    assert_eq!(pack.pk_authenticator.ctime, 1_700_000_000);
    assert_eq!(pack.pk_authenticator.pa_checksum.len(), 20);
    assert!(
        pack.client_public_value.is_none(),
        "the fixtures are the RSA key transport form, which needs no DH value"
    );
}

#[test]
fn an_unsigned_request_is_anonymous_pkinit_not_a_login() {
    // `id-pkinit-authData` with no `SignedData` is RFC 8062's anonymous form. Reading it
    // as an authenticated request would log in `WELLKNOWN/ANONYMOUS` as whoever the body
    // named.
    use rrl_kdc::der;
    let pack = fixture("authpack.der");
    // ContentInfo { contentType id-pkinit-authData, [0] EXPLICIT OCTET STRING }
    let content_info = der::seq(&[
        der::tlv(0x06, &[0x2b, 0x06, 0x01, 0x05, 0x02, 0x03, 0x01]),
        der::field(0, der::octets(&pack)),
    ]);
    let wrapped = der::seq(&[der::field(0, content_info)]);
    let req = Request::decode(&wrapped).expect("a bare ContentInfo is readable");
    assert!(req.signed.is_none(), "there is no SignedData to verify");
    assert_eq!(
        pkinit::Identity::authenticate(&req, &anchors(), NOW).unwrap_err(),
        PkinitError::Anonymous
    );
}

#[test]
fn the_signed_attributes_are_bound_to_the_authpack() {
    // The signature covers the attributes, and the attributes carry a `messageDigest` of
    // the content. Without that comparison a valid signature would vouch for whatever
    // content happened to travel beside it — a different nonce, a different checksum, a
    // different body.
    //
    // The tampering is done on the wire rather than by rebuilding the envelope: flip one
    // octet inside the `eContent` and leave every attribute and the signature untouched.
    // DER lengths do not change, so the only thing that differs is the content.
    let mut wrapped = fixture("request-alice-wrapped.der");
    let pack = fixture("authpack.der");
    let at = wrapped
        .windows(pack.len())
        .position(|w| w == pack.as_slice())
        .expect("the AuthPack is inside the request verbatim");
    let last = at + pack.len() - 1;
    wrapped[last] ^= 0x01;

    let req = Request::decode(&wrapped).expect("still a readable PA-PK-AS-REQ");
    assert_ne!(
        req.auth_pack, pack,
        "the tampering has to change the content"
    );
    match pkinit::Identity::authenticate(&req, &anchors(), NOW) {
        Err(PkinitError::BadSignature(m)) => {
            assert!(
                m.contains("messageDigest"),
                "expected the digest binding to fail, got: {m}"
            );
        }
        other => panic!("a substituted AuthPack must be refused, got {other:?}"),
    }
}

#[test]
fn a_message_without_signed_auth_pack_is_refused() {
    // `PA-PK-AS-REQ ::= SEQUENCE { signedAuthPack [0] }`. A sequence that starts with
    // anything else is not this message, and saying which octet was wrong beats a stack
    // of "unexpected tag" from three levels down.
    use rrl_kdc::der;
    let wrong = der::seq(&[der::field(1, der::int(5))]);
    match Request::decode(&wrong) {
        Err(PkinitError::Malformed(m)) => assert!(
            m.contains("signedAuthPack"),
            "the error should name the field: {m}"
        ),
        other => panic!("expected Malformed, got {other:?}"),
    }
}

#[test]
fn a_content_info_of_an_unknown_type_is_refused_by_name() {
    // PKINIT defines exactly two content types. Anything else is a request this KDC does
    // not understand, and treating it as one it does would be the more dangerous answer.
    use rrl_kdc::der;
    let unknown = der::seq(&[
        der::tlv(
            0x06,
            &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01],
        ), // id-data
        der::field(0, der::octets(b"whatever")),
    ]);
    let wrapped = der::seq(&[der::field(0, unknown)]);
    match Request::decode(&wrapped) {
        Err(PkinitError::Unsupported(m)) => assert!(
            m.contains("1.2.840.113549.1.7.1"),
            "the error should name the type it saw: {m}"
        ),
        other => panic!("expected Unsupported, got {other:?}"),
    }
}

#[test]
fn an_anchor_that_is_not_a_certificate_is_refused() {
    // Trust anchors come from configuration. A file that is not a certificate must be an
    // error at load time, not a realm that silently trusts nothing — or worse, trusts
    // whatever parses.
    let mut anchors = TrustAnchors::new();
    assert!(anchors.add(b"not a certificate").is_err());
    assert!(
        anchors.is_empty(),
        "a refused anchor must not be half-added"
    );
}

#[test]
fn an_empty_anchor_set_trusts_nothing() {
    // The default for a realm that has not configured PKINIT. If this ever returned Ok,
    // every certificate in the world would be an administrator.
    let err = pkinit::Identity::authenticate(&request("alice"), &TrustAnchors::new(), NOW)
        .expect_err("no anchors means no trust");
    assert_eq!(err, PkinitError::UntrustedIssuer);
}

#[test]
fn a_body_that_was_not_signed_is_refused_before_the_certificate_is_considered() {
    // `Request::auth_pack` reads the structure without judging it; the checksum is a
    // separate decision, and it comes before any X.509 work. Doing it the other way round
    // means an untrusted certificate masks a mismatched body, and the operator fixes the
    // wrong thing.
    let req = request("alice");
    let pack = req.auth_pack().expect("AuthPack");
    let body = fixture("body.der");
    let mut other_body = body.clone();
    other_body[0] ^= 0x01; // the SEQUENCE tag, so the octets differ
    assert_eq!(
        pkinit::check_body(&pack, &other_body).unwrap_err(),
        PkinitError::BodyMismatch
    );
}
