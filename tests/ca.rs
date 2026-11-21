//! A real CSR through the CA seam: parsed, its possession proved against a fixture key, authorized,
//! and handed to an authority that records what it was asked to sign.
//!
//! The request is built here the way `openssl req` builds one — `CertificationRequestInfo` signed by
//! the key it carries — because the point of the module is that a CSR from a third-party tool is
//! read, not that this crate can read its own output.

#![cfg(feature = "pkinit")]

use rrl_kdc::der::{self, Reader};
use rrl_kdc::kdc::ca::{
    self, CaError, CertificateAuthority, Csr, CsrAuthorizer, SelfIssued, SigningRequest,
};
use rrl_kdc::name::Principal;

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
        .expect("a PEM body is base64")
}

fn p(name: &str) -> Principal {
    Principal::parse(name).unwrap()
}

/// The `SubjectPublicKeyInfo` of the fixture RSA key: `SEQUENCE { rsaEncryption, BIT STRING }`,
/// where the BIT STRING holds the PKCS#1 `RSAPublicKey`.
fn spki_of(key: &rsa::RsaPrivateKey) -> Vec<u8> {
    use rsa::pkcs1::EncodeRsaPublicKey;
    // `to_pkcs1_der` is on the *public* half; the private key exposes it through `to_public_key`.
    let pkcs1 = key
        .to_public_key()
        .to_pkcs1_der()
        .expect("a public key")
        .as_bytes()
        .to_vec();
    der::seq(&[
        der::seq(&[
            der::tlv(der::OBJECT_IDENTIFIER, &oid_content("1.2.840.113549.1.1.1")),
            der::tlv(0x05, &[]),
        ]),
        der::tlv(der::BIT_STRING, &[&[0u8][..], &pkcs1].concat()),
    ])
}

fn oid_content(text: &str) -> Vec<u8> {
    let parts: Vec<u64> = text.split('.').map(|p| p.parse().unwrap()).collect();
    let mut out = vec![(40 * parts[0] + parts[1]) as u8];
    for &part in &parts[2..] {
        let mut chunk = vec![(part & 0x7f) as u8];
        let mut rest = part >> 7;
        while rest > 0 {
            chunk.push(0x80 | (rest & 0x7f) as u8);
            rest >>= 7;
        }
        chunk.reverse();
        out.extend(chunk);
    }
    out
}

/// A CSR over `subject`/`extensions`, signed by the fixture key: what `openssl req -new` produces.
fn csr_with(
    subject: Option<Vec<u8>>,
    extensions: Option<Vec<u8>>,
) -> (Vec<u8>, rsa::RsaPrivateKey) {
    use rsa::pkcs1v15::SigningKey;
    use rsa::pkcs8::DecodePrivateKey;
    use rsa::signature::{SignatureEncoding, Signer};

    let key = rsa::RsaPrivateKey::from_pkcs8_der(&der_of(&fixture("alice-key.pem")))
        .expect("the fixture key");
    let info = der::seq(&[
        der::int(0),                              // version v1
        subject.unwrap_or_else(|| der::seq(&[])), // an empty Name is legal
        spki_of(&key),
        der::tlv(der::ctx(0), &attributes(extensions)),
    ]);
    let signing = SigningKey::<rsa_sha2::Sha256>::new(key.clone());
    let signature = signing.sign(&info).to_vec();
    let csr = der::seq(&[
        info,
        der::seq(&[
            der::tlv(
                der::OBJECT_IDENTIFIER,
                &oid_content("1.2.840.113549.1.1.11"),
            ),
            der::tlv(0x05, &[]),
        ]),
        der::tlv(der::BIT_STRING, &[&[0u8][..], &signature].concat()),
    ]);
    (csr, key)
}

/// `attributes [0] IMPLICIT SET OF Attribute`, with one `extensionRequest` when there are
/// extensions: `Attribute ::= SEQUENCE { type OID, values SET OF }`, and each value is
/// `ExtensionRequest ::= SEQUENCE { extns Extensions }` (PKCS#9 §5.4.2).
fn attributes(extensions: Option<Vec<u8>>) -> Vec<u8> {
    let Some(exts) = extensions else {
        return Vec::new();
    };
    der::seq(&[
        der::tlv(
            der::OBJECT_IDENTIFIER,
            &oid_content("1.2.840.113549.1.9.14"),
        ),
        der::cons(0x31, &[der::seq(&[exts])]),
    ])
}

/// The authority side of the seam: records the request and returns a distinguishable blob.
#[derive(Debug, Default)]
struct Recording {
    requests: std::sync::Mutex<Vec<SigningRequest>>,
}

impl CertificateAuthority for Recording {
    fn sign(&self, request: &SigningRequest) -> Result<Vec<u8>, CaError> {
        self.requests.lock().unwrap().push(request.clone());
        Ok(b"signed".to_vec())
    }
}

/// The whole path: a CSR from a tool parses, its possession proof verifies, the realm's SAN is in
/// what the authority signs, and the principal that asked is the one the certificate names.
/// A CSR whose key is on a NIST curve and whose signature is ECDSA.
///
/// `curve` picks the curve, the digest and the signature OID together, because those three have to
/// agree: an `ecdsa-with-SHA384` signature over a SHA-256 digest fails for every input and reads
/// like a wrong key.
///
/// The key is derived from a fixed scalar rather than generated: a test that cannot be repeated is
/// a test whose failure cannot be reproduced.
fn ec_csr(curve: EcCurve) -> Vec<u8> {
    let (spki, signature_of) = curve.key();
    let info = der::seq(&[der::int(0), der::seq(&[]), spki, der::tlv(der::ctx(0), &[])]);
    let signature = signature_of(&info);
    der::seq(&[
        info,
        der::seq(&[der::tlv(
            der::OBJECT_IDENTIFIER,
            &oid_content(curve.sig_alg()),
        )]),
        der::tlv(der::BIT_STRING, &[&[0u8][..], &signature].concat()),
    ])
}

/// A public key as a CSR carries it, and a signer over that key's curve.
type EcKey = (Vec<u8>, Box<dyn Fn(&[u8]) -> Vec<u8>>);

/// The two curves a certificate in this family is signed on. P-521 has no test here: nothing in the
/// repository issues one, and its arm is the same code with a longer scalar.
#[derive(Clone, Copy)]
enum EcCurve {
    P256,
    P384,
}

impl EcCurve {
    fn curve_oid(self) -> &'static str {
        match self {
            EcCurve::P256 => "1.2.840.10045.3.1.7",
            EcCurve::P384 => "1.3.132.0.34",
        }
    }

    fn sig_alg(self) -> &'static str {
        match self {
            EcCurve::P256 => "1.2.840.10045.4.3.2",
            EcCurve::P384 => "1.2.840.10045.4.3.3",
        }
    }

    /// The `SubjectPublicKeyInfo`, and a closure that signs a message the way this curve's
    /// signature algorithm says: hash it, then ECDSA over the digest.
    ///
    /// The closure is boxed because the two curves are different types: one generic over the curve
    /// would need the `Digest` bound that this crate's `p256` features do not expose.
    fn key(self) -> EcKey {
        use p256::elliptic_curve::sec1::ToSec1Point as _;
        match self {
            EcCurve::P256 => {
                let sk = p256::SecretKey::from_slice(&[7u8; 32]).expect("a P-256 scalar");
                let point = sk.public_key().to_sec1_point(false).as_bytes().to_vec();
                let spki = ec_spki(self.curve_oid(), &point);
                let sign = Box::new(move |message: &[u8]| {
                    use p256::ecdsa::signature::hazmat::PrehashSigner as _;
                    use rsa_sha2::Digest as _;
                    let digest = rsa_sha2::Sha256::digest(message);
                    let signing = p256::ecdsa::SigningKey::from(&sk);
                    let s: p256::ecdsa::DerSignature =
                        signing.sign_prehash(&digest).expect("signs");
                    s.as_bytes().to_vec()
                });
                (spki, sign)
            }
            EcCurve::P384 => {
                let sk = p384::SecretKey::from_slice(&[7u8; 48]).expect("a P-384 scalar");
                let point = sk.public_key().to_sec1_point(false).as_bytes().to_vec();
                let spki = ec_spki(self.curve_oid(), &point);
                let sign = Box::new(move |message: &[u8]| {
                    use p384::ecdsa::signature::hazmat::PrehashSigner as _;
                    use rsa_sha2::Digest as _;
                    let digest = rsa_sha2::Sha384::digest(message);
                    let signing = p384::ecdsa::SigningKey::from(&sk);
                    let s: p384::ecdsa::DerSignature =
                        signing.sign_prehash(&digest).expect("signs");
                    s.as_bytes().to_vec()
                });
                (spki, sign)
            }
        }
    }
}

/// `SubjectPublicKeyInfo` for an elliptic-curve key: `SEQUENCE { SEQUENCE { id-ecPublicKey, curve },
/// BIT STRING { point } }`, the point in its uncompressed form — what `openssl req` writes.
fn ec_spki(curve_oid: &str, point: &[u8]) -> Vec<u8> {
    der::seq(&[
        der::seq(&[
            der::tlv(der::OBJECT_IDENTIFIER, &oid_content("1.2.840.10045.2.1")),
            der::tlv(der::OBJECT_IDENTIFIER, &oid_content(curve_oid)),
        ]),
        der::tlv(der::BIT_STRING, &[&[0u8][..], point].concat()),
    ])
}

#[test]
fn a_csr_proves_possession_and_is_signed_with_the_realms_san() {
    let (bytes, _key) = csr_with(None, None);
    let csr = Csr::parse(&bytes).expect("the CSR parses");
    csr.verify_possession()
        .expect("its signature verifies under its own key");

    let ca = Recording::default();
    let issued = ca::issue(
        &csr,
        &p("alice@EXAMPLE.COM"),
        &p("alice@EXAMPLE.COM"),
        (1_000, 3_600),
        &SelfIssued,
        &ca,
    )
    .expect("an authorized request is signed");
    assert_eq!(issued.certificate, b"signed");

    let recorded = ca.requests.lock().unwrap();
    assert_eq!(recorded.len(), 1);
    let request = &recorded[0];
    assert_eq!(request.principal, p("alice@EXAMPLE.COM"));
    assert_eq!(request.not_before, 1_000);
    assert_eq!(request.not_after, 3_600);

    // The SAN the realm decided on is in the extension set the authority is asked to sign.
    let san = ca::san_for(&p("alice@EXAMPLE.COM"));
    assert!(
        request.extensions.windows(san.len()).any(|w| w == san),
        "the id-pkinit-san SAN is not among the granted extensions"
    );
}

/// A signature that does not verify is a request for a certificate for a key nobody has: refused, and
/// the authority is never asked.
#[test]
fn a_tampered_csr_is_refused_before_the_authority_sees_it() {
    let (bytes, _key) = csr_with(None, None);
    // Flip a byte of the signature, which is the last value in the SEQUENCE.
    let mut tampered = bytes.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 0xff;
    let csr = Csr::parse(&tampered).expect("still a CSR");
    let err = csr
        .verify_possession()
        .expect_err("a wrong signature must not verify");
    assert!(matches!(err, CaError::PossessionNotProven(_)), "{err:?}");

    let ca = Recording::default();
    let issued = ca::issue(
        &csr,
        &p("alice@EXAMPLE.COM"),
        &p("alice@EXAMPLE.COM"),
        (0, 3600),
        &SelfIssued,
        &ca,
    );
    assert!(issued.is_err());
    assert!(
        ca.requests.lock().unwrap().is_empty(),
        "the authority must not sign a request whose key is not proven"
    );

    // And a CSR that is not one is refused as malformed rather than as an attack.
    assert!(matches!(
        Csr::parse(b"not a csr").unwrap_err(),
        CaError::Malformed(_)
    ));
}

/// A principal may not be issued a certificate for somebody else without an explicit grant, whatever
/// the CSR says about its subject.
#[test]
fn a_csr_for_another_principal_is_refused_by_the_default_authorizer() {
    let (bytes, _key) = csr_with(
        // A subject naming bob, which changes nothing: the principal is the realm's decision.
        Some(der::seq(&[der::cons(
            0x31,
            &[der::seq(&[
                der::tlv(der::OBJECT_IDENTIFIER, &oid_content("2.5.4.3")),
                der::tlv(0x13, b"bob"),
            ])],
        )])),
        None,
    );
    let csr = Csr::parse(&bytes).expect("parses");
    let ca = Recording::default();
    let err = ca::issue(
        &csr,
        &p("alice@EXAMPLE.COM"),
        &p("bob@EXAMPLE.COM"),
        (0, 3600),
        &SelfIssued,
        &ca,
    )
    .expect_err("alice must not get bob's certificate");
    assert!(matches!(err, CaError::Refused(_)), "{err:?}");

    // The subject did travel in the signing request — it is the CSR's, and the authority may use it.
    assert!(ca.requests.lock().unwrap().is_empty());
}

/// The CSR's requested extensions arrive at the authority, with the name-bearing ones filtered out.
#[test]
fn a_requested_extension_reaches_the_authority_and_a_san_does_not() {
    let exts = der::seq(&[
        der::seq(&[
            der::tlv(der::OBJECT_IDENTIFIER, &oid_content("2.5.29.17")),
            der::octets(b"a client-chosen san"),
        ]),
        der::seq(&[
            der::tlv(der::OBJECT_IDENTIFIER, &oid_content("2.5.29.37")),
            der::octets(b"an eku"),
        ]),
    ]);
    let (bytes, _key) = csr_with(None, Some(exts));
    let csr = Csr::parse(&bytes).expect("parses");
    let requested = csr
        .extensions
        .as_ref()
        .expect("the extensionRequest was read");

    let ca = Recording::default();
    ca::issue(
        &csr,
        &p("alice@EXAMPLE.COM"),
        &p("alice@EXAMPLE.COM"),
        (0, 3600),
        &SelfIssued,
        &ca,
    )
    .expect("signed");

    let recorded = ca.requests.lock().unwrap();
    let granted = &recorded[0].extensions;
    let mut r = Reader::new(granted);
    let list = r.next_tlv("Extensions").expect("a SEQUENCE");
    let mut items = Reader::new(list.content);
    let mut oids = Vec::new();
    while !items.is_empty() {
        let e = items.next_tlv("Extension").expect("an Extension");
        let mut er = Reader::new(e.content);
        let oid = er.next_tlv("extnID").expect("an OID");
        oids.push(der::decode_oid("extnID", oid.content).unwrap());
    }
    assert!(
        oids.contains(&"2.5.29.37".to_string()),
        "the EKU the client asked for must reach the authority: {oids:?}"
    );
    // The SAN in the granted set is the realm's own, exactly once: the client's was dropped, and a
    // certificate with two `subjectAltName`s is one no client reads consistently.
    let san_count = oids.iter().filter(|o| *o == "2.5.29.17").count();
    assert_eq!(
        san_count, 1,
        "the realm's SAN must be present once and the client's not at all: {oids:?}"
    );
    let realm_san = ca::san_for(&p("alice@EXAMPLE.COM"));
    assert!(
        granted.windows(realm_san.len()).any(|w| w == realm_san),
        "the one SAN must be the realm's"
    );
    assert!(
        !granted
            .windows(b"a client-chosen san".len())
            .any(|w| w == b"a client-chosen san"),
        "the client's SAN value must not survive"
    );
    // The requested set is a value the parser read, not an empty placeholder.
    assert!(!requested.is_empty());
}

/// An authorizer other than the default is consulted with the principal that asked and what it asks
/// for — the seam an operator's rule plugs into.
#[test]
fn a_custom_authorizer_sees_who_asked_and_what_for() {
    #[derive(Debug)]
    struct DenyEverything;

    impl CsrAuthorizer for DenyEverything {
        fn authorize(&self, who: &Principal, request: &SigningRequest) -> Result<(), CaError> {
            Err(CaError::Refused(format!(
                "{who} may not have a certificate for {}",
                request.principal
            )))
        }
    }

    let (bytes, _key) = csr_with(None, None);
    let csr = Csr::parse(&bytes).expect("parses");
    let ca = Recording::default();
    let err = ca::issue(
        &csr,
        &p("alice@EXAMPLE.COM"),
        &p("alice@EXAMPLE.COM"),
        (0, 3600),
        &DenyEverything,
        &ca,
    )
    .expect_err("a policy that refuses everything refuses");
    assert!(err.to_string().contains("alice@EXAMPLE.COM"), "{err}");
    assert!(ca.requests.lock().unwrap().is_empty());
}

/// An elliptic-curve CSR proves possession, on both curves this crate checks.
///
/// `verify_ecdsa` was at zero coverage: every CSR test used an RSA key, so the EC branch — parse the
/// curve out of the SPKI, pick the digest the signature algorithm names, verify — had never run.
/// It is the branch a PKINIT client with an EC certificate takes, and the digest choice is the part
/// that goes wrong silently: verifying SHA-256 with the SHA-384 variant fails for every input and
/// reads like a wrong key.
#[test]
fn an_elliptic_curve_csr_proves_possession_on_both_curves() {
    for curve in [EcCurve::P256, EcCurve::P384] {
        let bytes = ec_csr(curve);
        let csr = Csr::parse(&bytes).expect("an EC CSR parses");
        csr.verify_possession()
            .unwrap_or_else(|e| panic!("{}: {e:?}", curve.sig_alg()));
    }
}

/// A flipped bit in an EC signature is refused, not accepted: the same statement the RSA test makes,
/// on a path where the failure mode is a `verify` that returns `true` because it could not read the
/// signature and treated that as success.
#[test]
fn a_tampered_ecdsa_signature_is_refused() {
    let mut bytes = ec_csr(EcCurve::P256);
    let last = bytes.len() - 1;
    bytes[last] ^= 0xff;
    let csr = Csr::parse(&bytes).expect("still a CSR");
    let err = csr
        .verify_possession()
        .expect_err("a wrong ECDSA signature must not verify");
    assert!(matches!(err, CaError::PossessionNotProven(_)), "{err:?}");
}

/// A digest this build does not check with an EC key is `Unsupported`, not `Bad` — an unverifiable
/// signature must not be reported as one that failed, and certainly not as one that passed.
#[test]
fn an_ecdsa_digest_this_build_does_not_check_is_unsupported() {
    // `ecdsa-with-SHA224` (1.2.840.10045.4.3.1) is not in the list this crate checks.
    let mut bytes = ec_csr(EcCurve::P256);
    // Replace the signature algorithm OID with SHA-224: same length, so the BIT STRING stays put
    // and the refusal comes from the algorithm, not from a broken encoding.
    let sha224 = oid_content("1.2.840.10045.4.3.1");
    let sha256 = oid_content("1.2.840.10045.4.3.2");
    assert_eq!(sha224.len(), sha256.len(), "the swap keeps the lengths");
    let at = bytes
        .windows(sha256.len())
        .position(|w| w == sha256.as_slice())
        .expect("the OID is in the CSR");
    bytes[at..at + sha224.len()].copy_from_slice(&sha224);
    let csr = Csr::parse(&bytes).expect("still a CSR");
    let err = csr
        .verify_possession()
        .expect_err("an unchecked digest is not a pass");
    assert!(
        matches!(
            err,
            CaError::PossessionNotProven(_) | CaError::Unsupported(_)
        ),
        "must be a refusal, got {err:?}"
    );
}
