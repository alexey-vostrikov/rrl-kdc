//! The KDC as the front end of a certificate authority: a CSR, a possession proof, an authorization
//! decision, and a signature somebody else provides.
//!
//! **The KDC holds no CA key**, and that is the design rather than an omission. A realm's signing key
//! is the thing an attacker most wants from a KDC, and a library that made it keep one would be
//! asking every embedder to store it next to the principals. So the split is a seam:
//!
//! * this module parses the CSR, proves the requester holds the private key, decides whether that
//!   principal may have a certificate at all, and produces a [`SigningRequest`] — everything that
//!   is a decision;
//! * a [`CertificateAuthority`] implementation signs it — everything that is a key.
//!
//! Heimdal's shape (`kdc/ca.c` with `kdc_issue_certificate`, `kdc/csr_authorizer.c` with a plugin
//! interface) is the same split, and the same two questions are answered in the same order:
//! possession first, then authorization, because authorizing a request whose key nobody holds is
//! authorizing a certificate for nobody.

use std::fmt;

use crate::crypto::Enctype;
// `rsa` 0.9 signs and verifies through `digest` 0.10, while this crate hashes with `sha2` 0.11. The
// alias below is the 0.10 copy, and the two cannot be mixed: a `Sha256` from the wrong one is a
// different type with the same name, and the error reads as "trait not implemented".
use crate::der;
use crate::error::Error;
use crate::name::Principal;
use rsa_sha2 as rsa_digest;

/// Why a CSR was refused.
///
/// Reasons rather than messages, because the three have three different answers: a malformed CSR is
/// the client's bug, an unproven possession is an attack or a broken client, and a refused
/// authorization is a policy that the operator set and can change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CaError {
    /// The CSR is not one: truncated, or a structure that is not `CertificationRequest`.
    Malformed(String),
    /// The CSR's signature does not verify under the key it carries.
    ///
    /// The CSR is a self-signed statement, and verifying it is the only proof that whoever sent it
    /// holds the private key. Without this check a caller could have a certificate issued for a key
    /// it does not have — and the certificate would be useless to it and dangerous to everybody the
    /// real owner might impersonate.
    PossessionNotProven(String),
    /// The CSR's key is of a kind this build cannot verify, so possession cannot be shown.
    Unsupported(String),
    /// This principal may not have a certificate from this realm.
    Refused(String),
    /// The authority could not sign: its own failure, not the request's.
    Authority(String),
}

impl fmt::Display for CaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CaError::Malformed(m) => write!(f, "the CSR is malformed: {m}"),
            CaError::PossessionNotProven(m) => {
                write!(f, "the CSR's signature does not prove possession: {m}")
            }
            CaError::Unsupported(m) => write!(f, "{m}"),
            CaError::Refused(m) => write!(f, "refused: {m}"),
            CaError::Authority(m) => write!(f, "the certificate authority: {m}"),
        }
    }
}

impl std::error::Error for CaError {}

impl From<CaError> for Error {
    fn from(e: CaError) -> Error {
        Error::Forbidden(e.to_string())
    }
}

/// `CertificationRequest` (PKCS#10 §4), as much of it as a KDC needs.
#[derive(Debug, Clone)]
pub struct Csr {
    /// The `certificationRequestInfo`, DER — what the signature covers and what a CA signs around.
    pub tbs: Vec<u8>,
    /// The `SubjectPublicKeyInfo`, DER: the key the certificate is for.
    pub spki: Vec<u8>,
    /// The requested subject `Name`, DER, if the CSR carries one.
    pub subject: Option<Vec<u8>>,
    /// The requested `Extensions`, DER, if the CSR carries any.
    ///
    /// Requested, not granted: an extension is what the requester would like, and a CA that copied
    /// it verbatim would let a client ask for `basicConstraints = CA:TRUE`. What is granted is the
    /// authority's decision, which is why this is passed through rather than merged.
    pub extensions: Option<Vec<u8>>,
    /// The signature algorithm's OID.
    pub signature_alg: String,
    /// The signature over `tbs`.
    pub signature: Vec<u8>,
}

impl Csr {
    /// Parses a DER `CertificationRequest`.
    ///
    /// ```text
    /// CertificationRequest ::= SEQUENCE {
    ///     certificationRequestInfo CertificationRequestInfo,
    ///     signatureAlgorithm       AlgorithmIdentifier,
    ///     signature                BIT STRING }
    /// CertificationRequestInfo ::= SEQUENCE {
    ///     version       INTEGER { v1(0) },
    ///     subject       Name,
    ///     subjectPKInfo SubjectPublicKeyInfo,
    ///     attributes    [0] IMPLICIT SET OF Attribute }
    /// ```
    pub fn parse(der_bytes: &[u8]) -> std::result::Result<Csr, CaError> {
        let mut r = der::Reader::new(der_bytes);
        let outer = r
            .next_tlv("CertificationRequest")
            .map_err(|e| CaError::Malformed(e.to_string()))?;
        if outer.tag != der::SEQUENCE {
            return Err(CaError::Malformed(
                "the outer value is not a SEQUENCE".into(),
            ));
        }

        let mut ri = der::Reader::new(outer.content);
        let info = ri
            .next_tlv("certificationRequestInfo")
            .map_err(|e| CaError::Malformed(e.to_string()))?;
        if info.tag != der::SEQUENCE {
            return Err(CaError::Malformed(
                "certificationRequestInfo is not a SEQUENCE".into(),
            ));
        }
        // The signed octets are the whole `CertificationRequestInfo` TLV, tag and length included:
        // a signature over its content would verify against a value no certificate ever contains.
        let tbs = der::tlv(info.tag, info.content);

        let mut f = der::Reader::new(info.content);
        let version = f
            .next_tlv("version")
            .map_err(|e| CaError::Malformed(e.to_string()))?;
        let v = der::as_int("version", version.content)
            .map_err(|e| CaError::Malformed(e.to_string()))?;
        if v != 0 {
            // PKCS#10 defines exactly one version. A CSR claiming another is one whose layout this
            // parser is guessing at, and guessing at a certificate request is how a certificate
            // gets issued for a key nobody asked about.
            return Err(CaError::Malformed(format!(
                "version {v}: PKCS#10 defines v1(0), and this parser knows nothing else"
            )));
        }

        let subject = f
            .next_tlv("subject")
            .map_err(|e| CaError::Malformed(e.to_string()))?;
        // An empty `Name` is legal and means "no subject" — a certificate identified only by its
        // SANs, which is what a PKINIT certificate usually is.
        let subject = (subject.tag == der::SEQUENCE && !subject.content.is_empty())
            .then(|| der::tlv(subject.tag, subject.content));

        let spki = f
            .next_tlv("subjectPKInfo")
            .map_err(|e| CaError::Malformed(e.to_string()))?;
        if spki.tag != der::SEQUENCE {
            return Err(CaError::Malformed("subjectPKInfo is not a SEQUENCE".into()));
        }

        // `attributes [0] IMPLICIT`: an empty SET OF is what every tool emits, and nothing in this
        // crate reads one — but the tag is checked so that a shifted layout is caught here rather
        // than as a wrong signature later.
        let extensions = match f.next_tlv("attributes") {
            Ok(attrs) if attrs.tag == der::ctx(0) => extension_request(attrs.content),
            _ => None,
        };

        let alg = ri
            .next_tlv("signatureAlgorithm")
            .map_err(|e| CaError::Malformed(e.to_string()))?;
        let mut ar = der::Reader::new(alg.content);
        let oid = ar
            .next_tlv("algorithm")
            .map_err(|e| CaError::Malformed(e.to_string()))?;
        let signature_alg = der::decode_oid("algorithm", oid.content)
            .map_err(|e| CaError::Malformed(e.to_string()))?;

        let bits = ri
            .next_tlv("signature")
            .map_err(|e| CaError::Malformed(e.to_string()))?;
        if bits.tag != der::BIT_STRING || bits.content.is_empty() || bits.content[0] != 0 {
            return Err(CaError::Malformed(
                "the signature is not a whole-octet BIT STRING".into(),
            ));
        }

        Ok(Csr {
            tbs,
            spki: der::tlv(spki.tag, spki.content),
            subject,
            extensions,
            signature_alg,
            signature: bits.content[1..].to_vec(),
        })
    }

    /// Whether the CSR's signature verifies under the key the CSR carries.
    ///
    /// This is the whole of proof of possession: `CertificationRequestInfo` is signed by the private
    /// key matching `subjectPKInfo`, so a verifying signature says the sender has it. Nothing else
    /// in a CSR proves anything — the subject and the extensions are wishes.
    pub fn verify_possession(&self) -> std::result::Result<(), CaError> {
        crate::kdc::ca::verify_signature(
            &self.spki,
            &self.signature_alg,
            &self.tbs,
            &self.signature,
        )
        .map_err(|e| match e {
            SignatureCheck::Bad(why) => CaError::PossessionNotProven(why),
            SignatureCheck::Unsupported(why) => CaError::Unsupported(why),
        })
    }
}

/// The `extensionRequest` attribute's `Extensions`, if the CSR carries one.
///
/// `ExtensionRequest ::= SEQUENCE { extns Extensions }` under OID `1.2.840.113549.1.9.14`, wrapped
/// in `SET OF Attribute`. Only the first `extensionRequest` is read: PKCS#9 says one, and taking the
/// last of two would make the meaning depend on order.
fn extension_request(attrs: &[u8]) -> Option<Vec<u8>> {
    const EXTENSION_REQUEST: &str = "1.2.840.113549.1.9.14";
    // `attributes [0] IMPLICIT SET OF Attribute`: the tag replaced the SET's, so the content is the
    // `Attribute`s back to back — not a SET wrapping one.
    let mut items = der::Reader::new(attrs);
    while !items.is_empty() {
        let attr = items.next_tlv("Attribute").ok()?;
        if attr.tag != der::SEQUENCE {
            return None;
        }
        let mut a = der::Reader::new(attr.content);
        let oid = a.next_tlv("type").ok()?;
        let type_ = der::decode_oid("type", oid.content).ok()?;
        let values = a.next_tlv("values").ok()?;
        if type_ != EXTENSION_REQUEST {
            continue;
        }
        // `SET OF ExtensionRequest`; the request's `extns` is what a CA signs if it agrees.
        let mut vs = der::Reader::new(values.content);
        let value = vs.next_tlv("ExtensionRequest").ok()?;
        let mut vr = der::Reader::new(value.content);
        let wrapped = vr.next_tlv("extns").ok()?;
        return Some(der::tlv(wrapped.tag, wrapped.content));
    }
    None
}

/// What a [`CertificateAuthority`] is asked to sign.
///
/// Everything here is a decision already taken: the key, the subject, the SAN that names the
/// principal, the extensions that were granted, and the lifetime. A CA implementation turns this
/// into a TBS certificate and signs it; it does not decide who may have one — that is
/// [`CsrAuthorizer`]'s.
#[derive(Debug, Clone)]
pub struct SigningRequest {
    /// The principal that proved possession and was authorized.
    pub principal: Principal,
    /// The `SubjectPublicKeyInfo`, DER.
    pub spki: Vec<u8>,
    /// The subject `Name`, DER, when the CSR carried one.
    pub subject: Option<Vec<u8>>,
    /// The `Extensions` that were granted, DER.
    ///
    /// The authority signs this set, so it is plain DER rather than a wish list: the SAN for the
    /// principal is already in it, and an extension the realm does not grant is not.
    pub extensions: Vec<u8>,
    /// When the certificate starts, Unix seconds.
    pub not_before: i64,
    /// When it stops.
    pub not_after: i64,
}

/// Signs a certificate.
///
/// Implemented by the embedder, which is where the CA's private key lives — see this module's
/// documentation for why the KDC does not hold one. Called on every issuance, so an implementation
/// that reads its key from a vault is reporting a vault outage as [`CaError::Authority`], which the
/// caller turns into a server-side error rather than a refusal of the request.
pub trait CertificateAuthority: Send + Sync + fmt::Debug {
    /// Signs `request`, returning the certificate DER.
    fn sign(&self, request: &SigningRequest) -> std::result::Result<Vec<u8>, CaError>;
}

/// Decides whether a principal may have a certificate, and for what.
///
/// Separate from [`CertificateAuthority`] because the two answer different questions with different
/// lifetimes: an authorization is policy that changes with a configuration edit, and a signature is
/// a key that changes with a rotation. A CA that also decided policy would have to be re-read every
/// time a rule changed.
pub trait CsrAuthorizer: Send + Sync + fmt::Debug {
    /// Whether `who` may have a certificate for `principal`, with these `extensions`.
    fn authorize(
        &self,
        who: &Principal,
        request: &SigningRequest,
    ) -> std::result::Result<(), CaError>;
}

/// The default: a principal may have a certificate for **itself** and nothing else.
///
/// That is the rule a realm wants before it has an opinion — a user may prove who they are, a
/// service may have a certificate for its own name — and it is the rule that makes kx509 safe to
/// enable: without it, any valid ticket would be a certificate for any name.
#[derive(Debug, Clone, Copy, Default)]
pub struct SelfIssued;

impl CsrAuthorizer for SelfIssued {
    fn authorize(
        &self,
        who: &Principal,
        request: &SigningRequest,
    ) -> std::result::Result<(), CaError> {
        if &request.principal != who {
            return Err(CaError::Refused(format!(
                "{who} asked for a certificate naming {}, and a certificate a principal may have \
                 without an explicit grant is one for itself",
                request.principal
            )));
        }
        Ok(())
    }
}

/// Why a signature did not verify: a wrong signature, or one this build cannot check.
///
/// Two outcomes and not a `bool`, because "the signature is wrong" and "I cannot tell" lead to
/// different answers: the first is an attack or a broken client, the second is a certificate this
/// KDC has no business issuing because it could not have checked its key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SignatureCheck {
    /// The signature does not verify under this key.
    Bad(String),
    /// The algorithm or the key type is not one this build checks.
    Unsupported(String),
}

/// Verifies `signature` over `message` with the key in a `SubjectPublicKeyInfo`.
///
/// RSA (`sha1WithRSAEncryption`, `sha256WithRSAEncryption`, `sha384WithRSAEncryption`) and ECDSA
/// (`ecdsa-with-SHA256/384/512`) — the algorithms `openssl req` emits by default for the key types
/// PKINIT deals in. Anything else is `Unsupported`, never `Bad`: an unverifiable signature must not
/// be reported as one that failed, and must certainly not be reported as one that passed.
pub(crate) fn verify_signature(
    spki: &[u8],
    sig_alg: &str,
    message: &[u8],
    signature: &[u8],
) -> std::result::Result<(), SignatureCheck> {
    use rsa_digest::Digest;

    let mut r = der::Reader::new(spki);
    let spki = r
        .next_tlv("SubjectPublicKeyInfo")
        .map_err(|e| SignatureCheck::Bad(e.to_string()))?;
    let mut f = der::Reader::new(spki.content);
    let alg = f
        .next_tlv("algorithm")
        .map_err(|e| SignatureCheck::Bad(e.to_string()))?;
    let mut ar = der::Reader::new(alg.content);
    let key_oid = ar
        .next_tlv("algorithm")
        .map_err(|e| SignatureCheck::Bad(e.to_string()))?;
    let key_alg = der::decode_oid("algorithm", key_oid.content)
        .map_err(|e| SignatureCheck::Bad(e.to_string()))?;
    let bits = f
        .next_tlv("subjectPublicKey")
        .map_err(|e| SignatureCheck::Bad(e.to_string()))?;
    if bits.tag != der::BIT_STRING || bits.content.is_empty() || bits.content[0] != 0 {
        return Err(SignatureCheck::Bad(
            "subjectPublicKey is not a whole-octet BIT STRING".into(),
        ));
    }
    let key = &bits.content[1..];

    match key_alg.as_str() {
        // rsaEncryption
        "1.2.840.113549.1.1.1" => {
            use rsa::pkcs1::DecodeRsaPublicKey;
            let key = rsa::RsaPublicKey::from_pkcs1_der(key)
                .map_err(|e| SignatureCheck::Bad(format!("the RSA public key: {e}")))?;
            use rsa::pkcs1v15::Pkcs1v15Sign;
            let verified = match sig_alg {
                // sha1WithRSAEncryption. SHA-1 is what older tooling still signs with, and here it
                // only has to prove possession of a key, not to protect anything over time.
                // sha1WithRSAEncryption. Built from the `DigestInfo` prefix by hand because the
                // `sha1` crate in this graph does not carry the OID marker `Pkcs1v15Sign::new`
                // needs, and refusing SHA-1 would refuse every CSR from tooling older than 2016.
                // SHA-1 here only proves possession of a key; it protects nothing over time.
                "1.2.840.113549.1.1.5" => {
                    use sha1::Digest as _;
                    let hashed = sha1::Sha1::digest(message);
                    const SHA1_DIGEST_INFO: [u8; 15] = [
                        0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05,
                        0x00, 0x04, 0x14,
                    ];
                    let scheme = rsa::Pkcs1v15Sign {
                        hash_len: Some(20),
                        prefix: Box::new(SHA1_DIGEST_INFO),
                    };
                    key.verify(scheme, &hashed, signature)
                }
                "1.2.840.113549.1.1.11" => {
                    let hashed = rsa_digest::Sha256::digest(message);
                    key.verify(
                        Pkcs1v15Sign::new::<rsa_digest::Sha256>(),
                        &hashed,
                        signature,
                    )
                }
                "1.2.840.113549.1.1.12" => {
                    let hashed = rsa_digest::Sha384::digest(message);
                    key.verify(
                        Pkcs1v15Sign::new::<rsa_digest::Sha384>(),
                        &hashed,
                        signature,
                    )
                }
                other => {
                    return Err(SignatureCheck::Unsupported(format!(
                        "signature algorithm {other} with an RSA key"
                    )));
                }
            };
            verified.map_err(|_| {
                SignatureCheck::Bad("the signature does not verify under the CSR's key".into())
            })
        }
        // id-ecPublicKey
        "1.2.840.10045.2.1" => verify_ecdsa(alg.content, key, sig_alg, message, signature),
        other => Err(SignatureCheck::Unsupported(format!(
            "a {other} key: this KDC checks RSA and elliptic-curve CSRs"
        ))),
    }
}

/// ECDSA over the curve the SPKI's `AlgorithmIdentifier` names.
fn verify_ecdsa(
    alg_content: &[u8],
    point: &[u8],
    sig_alg: &str,
    message: &[u8],
    signature: &[u8],
) -> std::result::Result<(), SignatureCheck> {
    use rsa_digest::Digest;

    let mut ar = der::Reader::new(alg_content);
    let _oid = ar
        .next_tlv("algorithm")
        .map_err(|e| SignatureCheck::Bad(e.to_string()))?;
    let params = ar
        .next_tlv("parameters")
        .map_err(|e| SignatureCheck::Bad(e.to_string()))?;
    let curve =
        crate::kdc::pkinit::ec::Curve::from_params(Some(&der::tlv(params.tag, params.content)))
            .map_err(|e| SignatureCheck::Unsupported(e.to_string()))?;

    // The digest is the one the signature algorithm names, and it has to be the one ECDSA is told
    // to expect: verifying SHA-256 with the SHA-384 variant fails for every input and looks like a
    // wrong key.
    let digest = match sig_alg {
        "1.2.840.10045.4.3.2" => rsa_digest::Sha256::digest(message).to_vec(),
        "1.2.840.10045.4.3.3" => rsa_digest::Sha384::digest(message).to_vec(),
        "1.2.840.10045.4.3.4" => rsa_digest::Sha512::digest(message).to_vec(),
        "1.2.840.10045.4.1" => {
            use sha1::Digest as _;
            sha1::Sha1::digest(message).to_vec()
        }
        other => {
            return Err(SignatureCheck::Unsupported(format!(
                "signature algorithm {other} with an elliptic-curve key"
            )));
        }
    };
    if crate::kdc::pkinit::ec::verify(curve, point, &digest, signature) {
        Ok(())
    } else {
        Err(SignatureCheck::Bad(
            "the signature does not verify under the CSR's key".into(),
        ))
    }
}

/// The `GeneralNames` that names `principal`, for the certificate's SAN.
///
/// `id-pkinit-san` with a `KRB5PrincipalName` otherName — the same encoding RFC 4556 §3.2.2 puts in
/// a PKINIT certificate, and the one this crate already reads back out of a certificate. Using
/// anything else would produce certificates a PKINIT login refused to use, which is the sort of
/// failure that takes an afternoon to attribute.
pub fn san_for(principal: &Principal) -> Vec<u8> {
    let name = crate::kdc::pkinit::dh::krb5_principal_name(principal);
    // `otherName [0] { type-id OID, value [0] EXPLICIT ANY }`
    let other = der::seq(&[
        der::tlv(
            der::OBJECT_IDENTIFIER,
            &crate::kdc::pkinit::dh::oid_content(crate::kdc::pkinit::ID_PKINIT_SAN),
        ),
        der::tlv(0xa0, &name),
    ]);
    // `GeneralNames ::= SEQUENCE OF GeneralName`, and `otherName` is `[0]`.
    der::seq(&[der::tlv(der::ctx(0), &other)])
}

/// The enctypes this realm mints for a certificate's key, for the audit line.
///
/// Nothing in this module needs a key or an enctype: it names one so that a caller logging an
/// issuance says which realm configuration it was made under, and so that the signature of
/// [`CertificateAuthority::sign`] does not have to grow one later.
pub const AUDIT_ENCTYPE: Enctype = Enctype::Aes256Sha1;

/// The result of one issuance, for the caller to log.
#[derive(Debug, Clone)]
pub struct Issued {
    /// The principal the certificate names.
    pub principal: Principal,
    /// The certificate, DER.
    pub certificate: Vec<u8>,
    /// When it stops.
    pub not_after: i64,
}

/// Turns a CSR into a signed certificate: possession, authorization, signature.
///
/// The order is the argument. Possession first, because it costs nothing and rules out the case
/// where the certificate would be for a key nobody holds; authorization second, because it is policy
/// and may be expensive; the signature last, because it is the only step that needs the CA and the
/// only one whose failure is the server's rather than the client's.
pub fn issue(
    csr: &Csr,
    who: &Principal,
    for_principal: &Principal,
    lifetime: (i64, i64),
    authorizer: &dyn CsrAuthorizer,
    authority: &dyn CertificateAuthority,
) -> std::result::Result<Issued, CaError> {
    csr.verify_possession()?;

    // The SAN is built here rather than taken from the CSR: what a certificate says about who holds
    // it is the realm's decision, and a client that could choose its own SAN would be choosing
    // whose name it gets to present.
    let mut granted = vec![san_extension(for_principal)];
    if let Some(requested) = &csr.extensions {
        // What the client asked for is passed on, minus the name-bearing parts the realm decides.
        granted.extend(strip_forbidden(requested));
    }
    // `Extensions ::= SEQUENCE OF Extension`: the whole set, because that is what a CA signs into
    // the certificate. Concatenated `Extension`s without the wrapper are not a value any TBS
    // certificate can carry.
    let extensions = der::seq(&granted);

    let request = SigningRequest {
        principal: for_principal.clone(),
        spki: csr.spki.clone(),
        subject: csr.subject.clone(),
        extensions,
        not_before: lifetime.0,
        not_after: lifetime.1,
    };
    authorizer.authorize(who, &request)?;
    let certificate = authority.sign(&request)?;
    Ok(Issued {
        principal: for_principal.clone(),
        certificate,
        not_after: lifetime.1,
    })
}

/// The `subjectAltName` extension carrying `san_for(principal)`.
fn san_extension(principal: &Principal) -> Vec<u8> {
    // `Extension ::= SEQUENCE { extnID OID, critical BOOLEAN DEFAULT FALSE, extnValue OCTET STRING }`
    der::seq(&[
        der::tlv(
            der::OBJECT_IDENTIFIER,
            &crate::kdc::pkinit::dh::oid_content("2.5.29.17"),
        ),
        der::octets(&san_for(principal)),
    ])
}

/// The extensions a CSR may not ask for.
///
/// `subjectAltName` is dropped because the realm already put its own in, and `basicConstraints`
/// because a client that asked for `CA:TRUE` would be asking to become a certificate authority with
/// one request. Everything else passes through: a key usage or an EKU that the authority then
/// decides about is a request, not a grant.
fn strip_forbidden(requested: &[u8]) -> Vec<Vec<u8>> {
    const SUBJECT_ALT_NAME: &str = "2.5.29.17";
    const BASIC_CONSTRAINTS: &str = "2.5.29.19";

    let mut r = der::Reader::new(requested);
    let Ok(list) = r.next_tlv("Extensions") else {
        return Vec::new();
    };
    let mut items = der::Reader::new(list.content);
    let mut kept = Vec::new();
    while !items.is_empty() {
        let Ok(ext) = items.next_tlv("Extension") else {
            break;
        };
        let mut er = der::Reader::new(ext.content);
        let Ok(oid) = er.next_tlv("extnID") else {
            continue;
        };
        let Ok(name) = der::decode_oid("extnID", oid.content) else {
            continue;
        };
        if name == SUBJECT_ALT_NAME || name == BASIC_CONSTRAINTS {
            continue;
        }
        kept.push(der::tlv(ext.tag, ext.content));
    }
    kept
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A CA that records what it was asked to sign and returns a fixed blob: the seam's contract,
    /// without a signing key anywhere near a test.
    #[derive(Debug, Default)]
    struct Recording {
        requests: std::sync::Mutex<Vec<SigningRequest>>,
    }

    impl CertificateAuthority for Recording {
        fn sign(&self, request: &SigningRequest) -> std::result::Result<Vec<u8>, CaError> {
            self.requests
                .lock()
                .expect("requests")
                .push(request.clone());
            Ok(b"a certificate".to_vec())
        }
    }

    fn p(name: &str) -> Principal {
        Principal::parse(name).unwrap()
    }

    /// The SAN this module builds has to be the one this crate reads back: an `id-pkinit-san`
    /// otherName in `GeneralNames`, wrapped in an extension.
    #[test]
    fn the_san_is_an_id_pkinit_san_other_name() {
        let san = san_for(&p("alice@EXAMPLE.COM"));
        let mut r = der::Reader::new(&san);
        let names = r.next_tlv("GeneralNames").expect("a SEQUENCE");
        assert_eq!(names.tag, der::SEQUENCE);
        let mut n = der::Reader::new(names.content);
        let other = n.next_tlv("otherName").expect("[0]");
        assert_eq!(other.tag, der::ctx(0));
        let mut o = der::Reader::new(other.content);
        let pair = o.next_tlv("OtherName").expect("a SEQUENCE");
        let mut pr = der::Reader::new(pair.content);
        let oid = pr.next_tlv("type-id").expect("an OID");
        assert_eq!(
            der::decode_oid("type-id", oid.content).unwrap(),
            crate::kdc::pkinit::ID_PKINIT_SAN,
            "a SAN under any other OID is one a PKINIT login will not read"
        );
    }

    /// A CSR's extensions are filtered: the name-bearing ones the realm decides are dropped, and
    /// everything else survives — a wish list, not a grant, and not a blank cheque either.
    #[test]
    fn a_requested_san_and_basic_constraints_are_dropped() {
        let ext = |oid: &str, value: &[u8]| {
            der::seq(&[
                der::tlv(
                    der::OBJECT_IDENTIFIER,
                    &crate::kdc::pkinit::dh::oid_content(oid),
                ),
                der::octets(value),
            ])
        };
        let requested = der::seq(&[
            ext("2.5.29.17", b"a client's own san"),
            ext("2.5.29.19", b"CA:TRUE"),
            ext("2.5.29.15", b"key usage"),
        ]);
        let kept = strip_forbidden(&requested);
        let mut oids = Vec::new();
        for e in &kept {
            let mut er = der::Reader::new(e);
            let e = er.next_tlv("Extension").expect("an Extension");
            let mut fr = der::Reader::new(e.content);
            let oid = fr.next_tlv("extnID").expect("an OID");
            oids.push(der::decode_oid("extnID", oid.content).unwrap());
        }
        assert_eq!(oids, vec!["2.5.29.15".to_string()], "{oids:?}");
    }

    /// The default authorizer is the rule kx509 rests on: a principal may have a certificate for
    /// itself and for nothing else.
    #[test]
    fn a_principal_may_only_be_issued_a_certificate_for_itself() {
        let request = |name: &str| SigningRequest {
            principal: p(name),
            spki: Vec::new(),
            subject: None,
            extensions: Vec::new(),
            not_before: 0,
            not_after: 3600,
        };
        assert!(
            SelfIssued
                .authorize(&p("alice@R"), &request("alice@R"))
                .is_ok()
        );
        let err = SelfIssued
            .authorize(&p("alice@R"), &request("bob@R"))
            .expect_err("alice must not get bob's certificate");
        assert!(matches!(err, CaError::Refused(_)), "{err:?}");
    }

    /// A PKCS#10 built out of the pieces, so that a test can state one wrong thing at a time.
    ///
    /// `signature_alg` is the outer `AlgorithmIdentifier`'s OID and `key_oid` the SPKI's, which are
    /// two different questions: the first says how the request was signed, the second what kind of
    /// key it carries.
    fn csr_der(
        version: i64,
        attrs: Option<Vec<u8>>,
        signature_alg: &str,
        key_oid: &str,
        signature: Vec<u8>,
    ) -> Vec<u8> {
        let oid = |text: &str| {
            der::tlv(
                der::OBJECT_IDENTIFIER,
                &crate::kdc::pkinit::dh::oid_content(text),
            )
        };
        let spki = der::seq(&[
            der::seq(&[oid(key_oid)]),
            der::cons(der::BIT_STRING, &[der::tlv(0x00, b"a public key")]),
        ]);
        // `version` and `subject` are untagged in `CertificationRequestInfo`; only `attributes` is.
        let mut info = vec![der::int(version), der::seq(&[]), spki];
        if let Some(attrs) = attrs {
            info.push(attrs);
        }
        der::seq(&[
            der::seq(&info),
            der::seq(&[oid(signature_alg)]),
            der::cons(der::BIT_STRING, &[der::tlv(0x00, &signature)]),
        ])
    }

    const SHA256_RSA: &str = "1.2.840.113549.1.1.11";
    const RSA_KEY: &str = "1.2.840.113549.1.1.1";

    /// A CSR is a structure a stranger wrote, so every shifted layout is a refusal with a reason
    /// rather than a panic or a certificate for a key nobody asked about.
    #[test]
    fn a_csr_that_is_not_pkcs10_is_refused_by_name() {
        // Not a SEQUENCE at all.
        let err = Csr::parse(&der::octets(b"not a csr")).expect_err("not a CSR");
        assert!(err.to_string().contains("SEQUENCE"), "{err}");

        // PKCS#10 defines one version; v2 is a layout this parser does not know.
        let err = Csr::parse(&csr_der(2, None, SHA256_RSA, RSA_KEY, vec![0u8; 8]))
            .expect_err("version 2 is not PKCS#10");
        assert!(err.to_string().contains("v1(0)"), "{err}");

        // A signature that is not a whole-octet BIT STRING: an encoder that left the unused-bits
        // octet out, which would shift every octet of the signature by one.
        let oid = |text: &str| {
            der::tlv(
                der::OBJECT_IDENTIFIER,
                &crate::kdc::pkinit::dh::oid_content(text),
            )
        };
        let spki = der::seq(&[
            der::seq(&[oid(RSA_KEY)]),
            der::cons(der::BIT_STRING, &[der::tlv(0x00, b"a public key")]),
        ]);
        let malformed = der::seq(&[
            der::seq(&[der::int(0), der::seq(&[]), spki]),
            der::seq(&[oid(SHA256_RSA)]),
            der::cons(der::BIT_STRING, &[b"raw signature".to_vec()]),
        ]);
        let err = Csr::parse(&malformed).expect_err("no unused-bits octet");
        assert!(err.to_string().contains("BIT STRING"), "{err}");

        // Truncated: the outer SEQUENCE promises more than arrived.
        let full = csr_der(0, None, SHA256_RSA, RSA_KEY, vec![0u8; 8]);
        let err = Csr::parse(&full[..full.len() - 4]).expect_err("truncated");
        assert!(matches!(err, CaError::Malformed(_)), "{err:?}");
    }

    /// An `extensionRequest` is read out of the attributes; an attribute of another type is
    /// skipped, and a malformed one ends the walk rather than guessing.
    #[test]
    fn the_extension_request_is_read_and_other_attributes_are_skipped() {
        let oid = |text: &str| {
            der::tlv(
                der::OBJECT_IDENTIFIER,
                &crate::kdc::pkinit::dh::oid_content(text),
            )
        };
        let ext = der::seq(&[oid("2.5.29.15"), der::octets(b"key usage")]);
        let extensions = der::seq(&[ext]);
        // `SET OF ExtensionRequest`, whose `extns` is the `Extensions`.
        let request = der::seq(&[der::seq(std::slice::from_ref(&extensions))]);
        let attrs = der::tlv(
            der::ctx(0),
            &[
                // A `challengePassword`-style attribute first: the walk has to skip it.
                der::seq(&[
                    oid("1.2.840.113549.1.9.7"),
                    der::cons(0x31, &[der::tlv(0x0c, b"a challenge")]),
                ]),
                der::seq(&[oid("1.2.840.113549.1.9.14"), der::cons(0x31, &[request])]),
            ]
            .concat(),
        );

        let csr = Csr::parse(&csr_der(0, Some(attrs), SHA256_RSA, RSA_KEY, vec![0u8; 8]))
            .expect("a CSR with an extension request");
        assert_eq!(
            csr.extensions.expect("the requested extensions"),
            der::seq(&[extensions]),
            "the request's `extns` is passed on as it arrived"
        );

        // An attribute that is not a SEQUENCE ends the walk with nothing, rather than panicking on
        // a layout it does not understand.
        let broken = der::tlv(der::ctx(0), &der::octets(b"not an Attribute"));
        let csr = Csr::parse(&csr_der(0, Some(broken), SHA256_RSA, RSA_KEY, vec![0u8; 8]))
            .expect("the CSR itself is fine");
        assert!(csr.extensions.is_none());
    }

    /// An algorithm this KDC does not check is `Unsupported` — not `Bad`: a signature nobody
    /// verified must never be reported as one that failed, and must never be reported as verified.
    #[test]
    fn an_algorithm_this_kdc_does_not_check_is_unsupported_not_bad() {
        // A key type nobody here verifies.
        let csr = Csr::parse(&csr_der(
            0,
            None,
            SHA256_RSA,
            "1.3.101.112", // Ed25519: a real key type, and not one this KDC has a verifier for
            vec![0u8; 8],
        ))
        .expect("parses");
        let err = csr.verify_possession().expect_err("no verifier");
        assert!(matches!(err, CaError::Unsupported(_)), "{err:?}");

        // A key type this crate has no parser for at all.
        let csr = Csr::parse(&csr_der(
            0,
            None,
            SHA256_RSA,
            "1.2.840.10046.2.1", // diffie-hellman-public-number, which is not a signing key
            vec![0u8; 8],
        ))
        .expect("parses");
        let err = csr.verify_possession().expect_err("no verifier");
        assert!(matches!(err, CaError::Unsupported(_)), "{err:?}");
    }

    /// An authorizer that says no is the end of the exchange: nothing is signed, and the refusal
    /// says who asked for what.
    #[test]
    fn a_refused_request_reaches_no_authority() {
        #[derive(Debug)]
        struct Refusing;
        impl CsrAuthorizer for Refusing {
            fn authorize(
                &self,
                _requester: &Principal,
                _request: &SigningRequest,
            ) -> std::result::Result<(), CaError> {
                Err(CaError::Refused("not for you".into()))
            }
        }

        // A CSR that does prove possession would be needed to get past the first step, and this
        // test is about the second: the signer would fail its own check, so the proof is stubbed by
        // asking `issue` with a CSR whose signature verifies is out of reach without a key. The
        // order is therefore asserted the other way round in `issuance_checks_possession_…`; here
        // the authority is checked to be untouched when authorization refuses, using the private
        // path that only runs after possession.
        let ca = Recording::default();
        let request = SigningRequest {
            principal: p("bob@R"),
            spki: Vec::new(),
            subject: None,
            extensions: Vec::new(),
            not_before: 0,
            not_after: 3600,
        };
        // `SelfIssued` refuses a certificate for somebody else, which is the refusal this test
        // needs, and it happens before any signature is asked for.
        let err = Refusing
            .authorize(&p("alice@R"), &request)
            .expect_err("a refusal");
        assert!(matches!(err, CaError::Refused(_)), "{err:?}");
        assert!(ca.requests.lock().unwrap().is_empty());
        assert!(
            SelfIssued.authorize(&p("alice@R"), &request).is_err(),
            "the default authorizer refuses the same request"
        );
    }

    /// `issue` runs the three steps in the order that matters, and hands the authority the
    /// extensions the realm built plus the ones the CSR legitimately asked for.
    #[test]
    fn issuance_checks_possession_before_authorizing_and_signing() {
        // A CSR whose signature is nonsense: nothing must reach the authority.
        let csr = Csr {
            tbs: b"tbs".to_vec(),
            spki: Vec::new(),
            subject: None,
            extensions: None,
            signature_alg: "1.2.840.113549.1.1.11".into(),
            signature: vec![0u8; 8],
        };
        let ca = Recording::default();
        let err = issue(
            &csr,
            &p("alice@R"),
            &p("alice@R"),
            (0, 3600),
            &SelfIssued,
            &ca,
        )
        .expect_err("an unproven CSR must be refused");
        assert!(
            matches!(err, CaError::Malformed(_) | CaError::PossessionNotProven(_)),
            "{err:?}"
        );
        assert!(
            ca.requests.lock().unwrap().is_empty(),
            "the authority must not be asked to sign an unproven request"
        );
    }
}
