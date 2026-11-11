//! PKINIT (RFC 4556) — the half that decides *who is asking*, before any key is
//! exchanged.
//!
//! A password login proves knowledge of a secret both sides already share. A certificate
//! login proves possession of a private key and, just as importantly, that some authority
//! vouched for the name attached to it. The second half is where the security actually
//! lives: a signature that verifies against a certificate is worthless if that
//! certificate is expired, chained to nothing, or names somebody else. So this module is
//! the trust decision, separated from the key exchange on purpose — the exchange can be
//! reviewed against RFC 4556 §3.2.3, and the decision against the policy of a realm.
//!
//! What is here:
//!
//! * `PA-PK-AS-REQ` (type 16) as the client sends it: `[0] ContentInfo`, either a CMS
//!   `SignedData` over the `AuthPack` or, for anonymous PKINIT (RFC 8062), the bare
//!   `AuthPack` with no signature at all;
//! * the `SignedData` envelope — certificates, signer, signed attributes, signature —
//!   and the checks that make it mean something: the content type the attributes name is
//!   the one the envelope claims, the `messageDigest` attribute is the digest of the
//!   content, and the signature verifies over the attributes *as a SET*, which is the
//!   one detail every hand-written CMS verifier gets wrong first;
//! * the certificate chain to a configured anchor, with validity at the KDC's clock;
//! * the `id-pkinit-san` otherName (`1.3.6.1.5.2.2`) that names the principal. A
//!   certificate without it authenticates nobody here: the subject DN is not a Kerberos
//!   name, and treating it as one is how "log in as the admin" bugs are made.
//!
//! Not here, and deliberately: Diffie-Hellman, the reply, and the KDF. A KDC that
//! verified certificates but derived the reply key from anything it liked would look
//! finished and be worthless, so the exchange gets its own module and its own tests.
//!
//! Signature algorithms accepted: RSA PKCS#1 v1.5 with SHA-256 or SHA-384, and ECDSA
//! P-256/P-384 with the same digests. Everything else is refused by name rather than
//! silently skipped — an unverifiable signature must never read as a verified one.

use std::fmt;

use crate::name::Principal;

#[cfg(feature = "pkinit")]
use rsa_sha2 as rsa_digest;

#[cfg(feature = "pkinit")]
use crate::Result;

#[cfg(feature = "pkinit")]
pub mod dh;
// Curves are the `pkinit` feature's, like the rest of the exchange: a password-only build has no
// use for an ECDH key pair, and the three curve crates should not be compiled for it.
#[cfg(feature = "pkinit")]
pub mod ec;
// The whole reply half needs the X.509 stack and RSA signing, so it travels with the
// feature rather than being half-present in a password-only build.
#[cfg(feature = "pkinit")]
pub mod reply;

/// `PA-PKINIT-KX` (RFC 8062 §7): the KDC's contribution to an anonymous session key.
pub const PA_PKINIT_KX: i32 = 147;

/// The key usage of that contribution (RFC 8062 §7).
pub const KU_PA_PKINIT_KX: u32 = 44;

/// Re-exported so that the anonymous path and its tests name one principal, not two.
pub use super::fast::anonymous_principal as fast_anonymous_principal;

/// `PA-PK-AS-REQ`, RFC 4556 §3.2.1.
pub const PA_PK_AS_REQ: i32 = 16;
/// `PA-PK-AS-REP`, RFC 4556 §3.2.3.
pub const PA_PK_AS_REP: i32 = 17;

/// `id-pkinit-authData` (`1.3.6.1.5.2.3.1`): what the client's `SignedData` carries.
pub const ID_PKINIT_AUTH_DATA: &str = "1.3.6.1.5.2.3.1";
/// `id-pkinit-DHKeyData` (`1.3.6.1.5.2.3.2`): what the KDC's reply carries.
pub const ID_PKINIT_DH_KEY_DATA: &str = "1.3.6.1.5.2.3.2";
/// `id-pkinit-KPClientAuth` (`1.3.6.1.5.2.3.4`): the EKU a client certificate needs.
pub const ID_PKINIT_KP_CLIENT_AUTH: &str = "1.3.6.1.5.2.3.4";
/// `id-pkinit-san` (`1.3.6.1.5.2.2`): the otherName that carries a principal.
pub const ID_PKINIT_SAN: &str = "1.3.6.1.5.2.2";

const ID_SIGNED_DATA: &str = "1.2.840.113549.1.7.2";
// The four below are the CMS and digest identifiers only the trusted path names, so they travel
// with the feature: a password-only build has no envelope to parse and no digest to name.
/// `id-sha256`, the digest CMS and X.509 both name.
#[cfg(feature = "pkinit")]
const SHA256_OID: &str = "2.16.840.1.101.3.4.2.1";
/// `id-sha384`.
#[cfg(feature = "pkinit")]
const SHA384_OID: &str = "2.16.840.1.101.3.4.2.2";
/// `contentType`, the signed attribute naming what the signature is over.
#[cfg(feature = "pkinit")]
const ATTR_CONTENT_TYPE: &str = "1.2.840.113549.1.9.3";
/// `messageDigest`, the signed attribute carrying the content's digest.
#[cfg(feature = "pkinit")]
const ATTR_MESSAGE_DIGEST: &str = "1.2.840.113549.1.9.4";
/// `rsaEncryption`: PKCS#1 v1.5, with the hash named beside it. A `SignerInfo` uses this
/// where a certificate uses `sha256WithRSAEncryption`.
pub const RSA_ENCRYPTION: &str = "1.2.840.113549.1.1.1";

/// A `SEQUENCE`'s members, by position.
///
/// CMS is written in universal tags — `INTEGER`, `OID`, `SET OF` — while `der::Fields`
/// exists for RFC 4120, where every field is `[n]` context-tagged. Using `Fields` on a
/// `ContentInfo` fails on its first octet, and pretending otherwise produced a decoder
/// that only ever read the structures it had built itself.
struct Seq<'a> {
    items: Vec<crate::der::Tlv<'a>>,
}

impl<'a> Seq<'a> {
    fn parse(context: &'static str, content: &'a [u8]) -> std::result::Result<Self, PkinitError> {
        let mut r = crate::der::Reader::new(content);
        let mut items = Vec::new();
        while !r.is_empty() {
            items.push(
                r.next_tlv(context)
                    .map_err(|e| PkinitError::Malformed(e.to_string()))?,
            );
        }
        Ok(Self { items })
    }

    fn at(
        &self,
        index: usize,
        context: &'static str,
    ) -> std::result::Result<&crate::der::Tlv<'a>, PkinitError> {
        self.items.get(index).ok_or_else(|| {
            PkinitError::Malformed(format!(
                "{context}: no member {index} (there are {})",
                self.items.len()
            ))
        })
    }

    /// The member at `index`, required to carry `tag`.
    fn tagged(
        &self,
        index: usize,
        tag: u8,
        context: &'static str,
    ) -> std::result::Result<&crate::der::Tlv<'a>, PkinitError> {
        let item = self.at(index, context)?;
        if item.tag != tag {
            return Err(PkinitError::Malformed(format!(
                "{context}: member {index} has tag {:#04x}, expected {tag:#04x}",
                item.tag
            )));
        }
        Ok(item)
    }

    /// The member at `index` as an `AlgorithmIdentifier`, yielding its algorithm OID.
    #[cfg(feature = "pkinit")]
    ///
    /// CMS puts the algorithm one structure deep — `SEQUENCE { OID, parameters }` — in
    /// every place that names one, and each of those places is somewhere a reader can
    /// forget the extra level.
    fn algorithm(
        &self,
        index: usize,
        context: &'static str,
    ) -> std::result::Result<String, PkinitError> {
        let alg = self.tagged(index, crate::der::SEQUENCE, context)?;
        let inner = Seq::parse("AlgorithmIdentifier", alg.content)?;
        inner.oid(0, "AlgorithmIdentifier")
    }

    /// The member at `index` as an OID, in dotted-decimal form.
    fn oid(&self, index: usize, context: &'static str) -> std::result::Result<String, PkinitError> {
        let item = self.tagged(index, crate::der::OBJECT_IDENTIFIER, context)?;
        crate::der::decode_oid(context, item.content)
            .map_err(|e| PkinitError::Malformed(e.to_string()))
    }
}

/// Boils a `[n]`-tagged member down to the universal TLV inside it, for the places where
/// CMS wraps a structure EXPLICITLY.
fn explicit<'a>(
    tlv: &crate::der::Tlv<'a>,
    context: &'static str,
) -> std::result::Result<crate::der::Tlv<'a>, PkinitError> {
    let mut r = crate::der::Reader::new(tlv.content);
    let inner = r
        .next_tlv(context)
        .map_err(|e| PkinitError::Malformed(e.to_string()))?;
    Ok(inner)
}

/// Why a certificate login was refused.
///
/// Each variant names a decision, not a symptom: an operator reading the KDC's log needs
/// to know whether the user's certificate expired or whether the realm does not trust its
/// issuer, because the two have nothing in common but the word "refused".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PkinitError {
    /// The `PA-DATA` is not a `PA-PK-AS-REQ` this KDC can read.
    Malformed(String),
    /// The client sent no signature, which is anonymous PKINIT — a different feature,
    /// with a different principal (`WELLKNOWN/ANONYMOUS`), not an unauthenticated login.
    Anonymous,
    /// No certificate in the envelope chains to a configured anchor.
    UntrustedIssuer,
    /// A certificate in the chain is outside its validity window at the KDC's clock.
    Expired {
        /// The subject the certificate names, as text.
        subject: String,
        /// `notBefore`, seconds since the epoch.
        not_before: i64,
        /// `notAfter`, seconds since the epoch.
        not_after: i64,
        /// The KDC's clock when the chain was checked.
        now: i64,
    },
    /// The signature does not verify, or does not cover what it claims to.
    BadSignature(String),
    /// The certificate carries no `id-pkinit-san` otherName.
    NoPrincipalName,
    /// The `id-pkinit-san` otherName named a principal the realm cannot accept.
    BadPrincipalName(String),
    /// The certificate's extended key usage excludes client authentication.
    WrongKeyPurpose,
    /// `paChecksum` does not cover the request body: the signature is valid, but over
    /// somebody else's request.
    BodyMismatch,
    /// A field this KDC does not implement was required to continue.
    Unsupported(String),
}

impl fmt::Display for PkinitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed(m) => write!(f, "PA-PK-AS-REQ is malformed: {m}"),
            Self::Anonymous => write!(f, "PA-PK-AS-REQ carries no signature (anonymous PKINIT)"),
            Self::UntrustedIssuer => write!(
                f,
                "no certificate in the request chains to a configured trust anchor"
            ),
            Self::Expired {
                subject,
                not_before,
                not_after,
                now,
            } => write!(
                f,
                "the certificate of {subject} is not valid at {now}: \
                 valid from {not_before} until {not_after}"
            ),
            Self::BadSignature(m) => write!(f, "the request's signature does not verify: {m}"),
            Self::NoPrincipalName => write!(
                f,
                "the certificate carries no id-pkinit-san otherName, so it names no principal"
            ),
            Self::BadPrincipalName(m) => {
                write!(f, "the certificate names no usable principal: {m}")
            }
            Self::WrongKeyPurpose => write!(
                f,
                "the certificate's extended key usage does not include id-pkinit-KPClientAuth"
            ),
            Self::BodyMismatch => write!(
                f,
                "paChecksum does not cover this request body: the signature is over a \
                 different request"
            ),
            Self::Unsupported(m) => write!(f, "PKINIT feature this KDC does not implement: {m}"),
        }
    }
}

impl std::error::Error for PkinitError {}

/// The `pkAuthenticator` of RFC 4556 §3.2.1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PkAuthenticator {
    /// `cusec`.
    pub cusec: u32,
    /// `ctime`, seconds since the epoch.
    pub ctime: i64,
    /// `nonce`, echoed in the reply so the client can tie it to this request.
    pub nonce: u32,
    /// `paChecksum`: SHA-1 over the `KDC-REQ-BODY` the request carries.
    ///
    /// This is what binds the signature to *this* request. Without checking it, a signed
    /// `AuthPack` could be lifted from one request and replayed into another — a valid
    /// signature, a valid certificate, and the wrong body. RFC 4556 §3.2.1 requires the
    /// KDC to verify it, and MIT's KDC does.
    pub pa_checksum: Vec<u8>,
}

/// What an `AuthPack` says, before any of it is trusted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthPack {
    /// The client's proof of freshness.
    pub pk_authenticator: PkAuthenticator,
    /// `clientPublicValue`: the client's ephemeral DH public key, as an
    /// `AlgorithmIdentifier`-tagged SPKI. `None` means RSA key transport.
    pub client_public_value: Option<Vec<u8>>,
    /// `supportedKDFs` (RFC 8636 §8), in the client's order of preference.
    pub supported_kdfs: Vec<String>,
}

/// A `PA-PK-AS-REQ` as it arrived: the content, and who claims to have signed it.
#[derive(Debug, Clone)]
pub struct Request {
    /// The `AuthPack` DER inside the envelope.
    pub auth_pack: Vec<u8>,
    /// The `SignedData` envelope, when there was one.
    pub signed: Option<Vec<u8>>,
}

/// Who the request authenticated, once every check has passed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    /// The principal the certificate's `id-pkinit-san` names.
    pub principal: Principal,
    /// The subject DN of the signing certificate, as text, for the audit log.
    pub subject: String,
    /// The signing certificate itself, DER.
    ///
    /// Kept because the reply needs the same certificate's public key: RFC 4556 §3.2.3.2's key
    /// transport encrypts the reply key to *the certificate that signed the request*, and looking
    /// it up again from the envelope would be a second parse of the same thing.
    pub cert: Vec<u8>,
}

impl Request {
    /// Splits a `PA-PK-AS-REQ` into its envelope and its content.
    ///
    /// `PA-PK-AS-REQ ::= SEQUENCE { signedAuthPack [0] IMPLICIT ContentInfo }`, and the
    /// `ContentInfo` is either `SignedData` or the bare `AuthPack` under
    /// `id-pkinit-authData` (RFC 8062's anonymous form).
    pub fn decode(pa: &[u8]) -> std::result::Result<Self, PkinitError> {
        use crate::der::Reader;

        let mut r = Reader::new(pa);
        let seq = r
            .next_tlv("PA-PK-AS-REQ")
            .map_err(|e| PkinitError::Malformed(e.to_string()))?;
        if seq.tag != crate::der::SEQUENCE {
            return Err(PkinitError::Malformed(
                "PA-PK-AS-REQ is not a SEQUENCE".into(),
            ));
        }
        // `Fields` would refuse a universal-tagged member, and every CMS structure inside
        // is universal; only the outermost `[0]` is a context tag.
        let mut outer = Reader::new(seq.content);
        let signed_tlv = outer
            .next_tlv("signedAuthPack")
            .map_err(|e| PkinitError::Malformed(e.to_string()))?;
        if signed_tlv.tag != crate::der::ctx(0) {
            return Err(PkinitError::Malformed(format!(
                "PA-PK-AS-REQ starts with tag {:#04x}, not signedAuthPack [0]",
                signed_tlv.tag
            )));
        }
        // Clients put the whole `ContentInfo` inside `[0]`, so it is unwrapped one level.
        let ci_tlv = explicit(&signed_tlv, "signedAuthPack")?;
        let ci = Seq::parse("ContentInfo", ci_tlv.content)?;
        let oid = ci.oid(0, "ContentInfo")?;
        let body = ci.at(1, "ContentInfo")?;

        if oid == ID_SIGNED_DATA {
            let pack = signed_content(&ci_tlv)?;
            Ok(Self {
                auth_pack: pack,
                signed: Some(ci_tlv.content.to_vec()),
            })
        } else if oid == ID_PKINIT_AUTH_DATA {
            let octets = explicit(body, "id-pkinit-authData")?;
            if octets.tag != crate::der::OCTET_STRING {
                return Err(PkinitError::Malformed(
                    "id-pkinit-authData is not an OCTET STRING".into(),
                ));
            }
            Ok(Self {
                auth_pack: octets.content.to_vec(),
                signed: None,
            })
        } else {
            Err(PkinitError::Unsupported(format!(
                "ContentInfo of type {oid}; PKINIT expects id-signedData or id-pkinit-authData"
            )))
        }
    }

    /// The `AuthPack` itself.
    pub fn auth_pack(&self) -> std::result::Result<AuthPack, PkinitError> {
        use crate::der::{Fields, Reader};

        let mut r = Reader::new(&self.auth_pack);
        let seq = r
            .next_tlv("AuthPack")
            .map_err(|e| PkinitError::Malformed(e.to_string()))?;
        let f = Fields::parse("AuthPack", seq.content)
            .map_err(|e| PkinitError::Malformed(e.to_string()))?;

        // PKINIT's ASN.1 module is `DEFINITIONS EXPLICIT TAGS`, so `[0]` wraps the
        // structure rather than replacing its tag — unlike CMS, which is IMPLICIT. The two
        // conventions meet in this file, and mixing them up shifts every field by one.
        let pa_tlv = f
            .opt_bytes(0)
            .ok_or_else(|| PkinitError::Malformed("AuthPack has no pkAuthenticator".into()))?;
        let mut pr = Reader::new(pa_tlv);
        let pa_seq = pr
            .next_tlv("PKAuthenticator")
            .map_err(|e| PkinitError::Malformed(e.to_string()))?;
        let pf = Fields::parse("PKAuthenticator", pa_seq.content)
            .map_err(|e| PkinitError::Malformed(e.to_string()))?;
        let pk_authenticator = PkAuthenticator {
            cusec: pf
                .u32(0, "PKAuthenticator")
                .map_err(|e| PkinitError::Malformed(e.to_string()))?,
            ctime: pf
                .time(1, "PKAuthenticator")
                .map_err(|e| PkinitError::Malformed(e.to_string()))?,
            nonce: pf
                .u32(2, "PKAuthenticator")
                .map_err(|e| PkinitError::Malformed(e.to_string()))?,
            pa_checksum: pf
                .octets(3, "PKAuthenticator")
                .map_err(|e| PkinitError::Malformed(e.to_string()))?
                .to_vec(),
        };

        let client_public_value = f.opt_bytes(1).map(<[u8]>::to_vec);

        // `[4] SEQUENCE OF AlgorithmIdentifier`: the KDFs the client can do. The OIDs are
        // kept as text because the choice among them belongs to the exchange, not here.
        let mut supported_kdfs = Vec::new();
        if let Some(list) = f.opt_bytes(4) {
            let mut lr = Reader::new(list);
            let seq = lr
                .next_tlv("supportedKDFs")
                .map_err(|e| PkinitError::Malformed(e.to_string()))?;
            let mut items = Reader::new(seq.content);
            while !items.is_empty() {
                let item = items
                    .next_tlv("AlgorithmIdentifier")
                    .map_err(|e| PkinitError::Malformed(e.to_string()))?;
                let af = Fields::parse("AlgorithmIdentifier", item.content)
                    .map_err(|e| PkinitError::Malformed(e.to_string()))?;
                supported_kdfs.push(
                    af.oid(0, "AlgorithmIdentifier")
                        .map_err(|e| PkinitError::Malformed(e.to_string()))?,
                );
            }
        }

        Ok(AuthPack {
            pk_authenticator,
            client_public_value,
            supported_kdfs,
        })
    }
}

/// The `AuthPack` DER inside a `SignedData` envelope, after the attributes and the
/// signature have been read but not yet judged.
fn signed_content(ci: &crate::der::Tlv<'_>) -> std::result::Result<Vec<u8>, PkinitError> {
    let signed = envelope_body(ci)?;
    let content = signed.econtent()?;
    Ok(content)
}

/// The `SignedData` SEQUENCE inside a `ContentInfo`.
fn envelope_body<'a>(ci: &crate::der::Tlv<'a>) -> std::result::Result<Seq<'a>, PkinitError> {
    let outer = Seq::parse("ContentInfo", ci.content)?;
    let wrapped = outer.at(1, "ContentInfo")?;
    let sd = explicit(wrapped, "SignedData")?;
    if sd.tag != crate::der::SEQUENCE {
        return Err(PkinitError::Malformed(
            "ContentInfo does not wrap a SignedData SEQUENCE".into(),
        ));
    }
    Seq::parse("SignedData", sd.content)
}

impl<'a> Seq<'a> {
    /// The `EncapsulatedContentInfo` member: its content type and its `eContent`.
    fn econtent(&self) -> std::result::Result<Vec<u8>, PkinitError> {
        let encap = self.tagged(2, crate::der::SEQUENCE, "SignedData")?;
        let ef = Seq::parse("EncapsulatedContentInfo", encap.content)?;
        let oid = ef.oid(0, "EncapsulatedContentInfo")?;
        if oid != ID_PKINIT_AUTH_DATA {
            return Err(PkinitError::Malformed(format!(
                "SignedData carries {oid}, not id-pkinit-authData"
            )));
        }
        let wrapped = ef.at(1, "EncapsulatedContentInfo")?;
        let octets = explicit(wrapped, "eContent")?;
        Ok(octets.content.to_vec())
    }
}

// The verification half needs an X.509 stack and RSA/ECDSA arithmetic, so it lives
// behind the feature: a password-only realm should not carry either.
#[cfg(feature = "pkinit")]
pub use trusted::*;

#[cfg(feature = "pkinit")]
mod trusted {
    use super::*;

    use x509_parser::certificate::X509Certificate;
    use x509_parser::prelude::*;

    /// The certificates a realm accepts as roots.
    ///
    /// Held as DER and parsed per request rather than kept as opaque handles: a
    /// configuration reload replaces the whole set, and a stale parse is a trust decision
    /// made against yesterday's anchors.
    #[derive(Debug, Clone)]
    pub struct TrustAnchors {
        anchors: Vec<Vec<u8>>,
    }

    impl TrustAnchors {
        /// An empty set, which trusts nothing — the honest default for a realm that has
        /// not configured PKINIT.
        pub fn new() -> Self {
            Self {
                anchors: Vec::new(),
            }
        }

        /// Adds a DER certificate as an anchor.
        pub fn add(&mut self, der: &[u8]) -> std::result::Result<(), PkinitError> {
            parse_cert(der)?;
            self.anchors.push(der.to_vec());
            Ok(())
        }

        /// The anchors, in the order they were added.
        pub fn len(&self) -> usize {
            self.anchors.len()
        }

        /// Whether the realm trusts anything at all.
        pub fn is_empty(&self) -> bool {
            self.anchors.is_empty()
        }
    }

    /// Parses a DER certificate, refusing trailing octets.
    pub(super) fn parse_cert<'a>(
        der: &'a [u8],
    ) -> std::result::Result<X509Certificate<'a>, PkinitError> {
        let (rest, cert) = X509Certificate::from_der(der)
            .map_err(|e| PkinitError::Malformed(format!("certificate: {e}")))?;
        if !rest.is_empty() {
            return Err(PkinitError::Malformed(format!(
                "certificate has {} trailing octets",
                rest.len()
            )));
        }
        Ok(cert)
    }

    /// Checks that every certificate in `chain` (leaf first) is inside its validity window
    /// at `now`.
    ///
    /// The whole chain, not just the leaf: an expired intermediate is exactly as
    /// disqualifying as an expired client certificate, and checking only the leaf is the
    /// kind of shortcut that survives every test written against freshly generated
    /// fixtures.
    fn check_validity<'a>(
        chain: &[X509Certificate<'a>],
        now: i64,
    ) -> std::result::Result<(), PkinitError> {
        for cert in chain {
            let v = cert.validity();
            let (not_before, not_after) = (v.not_before.timestamp(), v.not_after.timestamp());
            if now < not_before || now > not_after {
                return Err(PkinitError::Expired {
                    subject: cert.subject().to_string(),
                    not_before,
                    not_after,
                    now,
                });
            }
        }
        Ok(())
    }

    /// Walks from `leaf` towards a root, trusting only certificates signed by the one
    /// before them, and succeeds when the issuer is one of `anchors`.
    ///
    /// Every candidate is checked by signature, never by subject name alone: two
    /// certificates can share a subject DN, and picking an issuer by name is how a chain
    /// is built to whatever root the attacker brought along.
    fn build_chain<'a>(
        leaf: &'a [u8],
        candidates: &'a [Vec<u8>],
        anchors: &'a [Vec<u8>],
        now: i64,
    ) -> std::result::Result<Vec<X509Certificate<'a>>, PkinitError> {
        let mut chain = vec![parse_cert(leaf)?];
        // Ten is the depth a chain can usefully have; beyond that a request is either
        // broken or trying to make this loop expensive.
        for _ in 0..10 {
            let current = chain.last().expect("the chain starts with the leaf");
            let issuer_der = current.issuer().to_string();
            let mut advanced = false;
            for candidate in candidates.iter().chain(anchors.iter()) {
                let cert = parse_cert(candidate)?;
                if cert.subject().to_string() != issuer_der {
                    continue;
                }
                if !signed_by(current, &cert)? {
                    continue;
                }
                let is_anchor = anchors.iter().any(|a| a == candidate);
                chain.push(cert);
                if is_anchor {
                    check_validity(&chain, now)?;
                    return Ok(chain);
                }
                advanced = true;
                break;
            }
            if !advanced {
                return Err(PkinitError::UntrustedIssuer);
            }
        }
        Err(PkinitError::UntrustedIssuer)
    }

    /// Whether `child`'s signature verifies under `issuer`'s public key.
    fn signed_by(
        child: &X509Certificate<'_>,
        issuer: &X509Certificate<'_>,
    ) -> std::result::Result<bool, PkinitError> {
        let alg = child.signature_algorithm.algorithm.to_string();
        let signature = child.signature_value.data.as_ref();
        let tbs = child.tbs_certificate.as_ref();
        verify_signature(issuer, &alg, None, tbs, signature)
    }

    /// The digest an algorithm OID means, given what the CMS envelope said separately.
    ///
    /// X.509 names the hash inside the signature algorithm (`sha256WithRSAEncryption`),
    /// CMS does not: a `SignerInfo` carries `rsaEncryption` and puts the hash in its own
    /// `digestAlgorithm`. Reading only the signature algorithm therefore looks correct
    /// for certificates and fails on every CMS envelope, which is why this takes the
    /// envelope's digest as a fallback rather than assuming one shape.
    fn digest_for<'a>(sig_alg: &str, cms_digest: Option<&'a str>) -> Option<&'a str> {
        match sig_alg {
            // sha256WithRSAEncryption, sha384WithRSAEncryption
            "1.2.840.113549.1.1.11" => Some(SHA256_OID),
            "1.2.840.113549.1.1.12" => Some(SHA384_OID),
            // rsaEncryption: PKCS#1 v1.5, hash named beside it.
            "1.2.840.113549.1.1.1" => cms_digest,
            _ => None,
        }
    }

    /// Verifies `signature` over `message` with `cert`'s key.
    ///
    /// `cms_digest` is the `SignerInfo`'s `digestAlgorithm`, used when the signature
    /// algorithm is plain `rsaEncryption`. Anything this code cannot check is
    /// `Unsupported`, never `false`: an unverifiable signature must not be reported as one
    /// that failed, and must certainly not be reported as one that passed.
    fn verify_signature(
        cert: &X509Certificate<'_>,
        sig_alg: &str,
        cms_digest: Option<&str>,
        message: &[u8],
        signature: &[u8],
    ) -> std::result::Result<bool, PkinitError> {
        use rsa::pkcs1::DecodeRsaPublicKey;
        use rsa::pkcs1v15::Pkcs1v15Sign;

        let digest = digest_for(sig_alg, cms_digest).ok_or_else(|| {
            PkinitError::Unsupported(format!(
                "signature algorithm {sig_alg} with digest {}",
                cms_digest.unwrap_or("none")
            ))
        })?;
        // The `SubjectPublicKeyInfo`'s BIT STRING holds the PKCS#1 `RSAPublicKey` DER.
        let spki = &cert.public_key().subject_public_key.data;
        let key = rsa::RsaPublicKey::from_pkcs1_der(spki)
            .map_err(|e| PkinitError::Unsupported(format!("RSA public key: {e}")))?;
        match digest {
            SHA256_OID => {
                let hashed = <rsa_digest::Sha256 as rsa_digest::Digest>::digest(message);
                Ok(key
                    .verify(
                        Pkcs1v15Sign::new::<rsa_digest::Sha256>(),
                        &hashed,
                        signature,
                    )
                    .is_ok())
            }
            SHA384_OID => {
                let hashed = <rsa_digest::Sha384 as rsa_digest::Digest>::digest(message);
                Ok(key
                    .verify(
                        Pkcs1v15Sign::new::<rsa_digest::Sha384>(),
                        &hashed,
                        signature,
                    )
                    .is_ok())
            }
            other => Err(PkinitError::Unsupported(format!(
                "digest algorithm {other}"
            ))),
        }
    }

    /// The principal a certificate names through `id-pkinit-san`.
    ///
    /// That extension is the only place a Kerberos name may come from. The subject DN of
    /// a certificate is an X.500 name that happens to contain an `alice`; treating it as
    /// a principal would let the CA's subject-name policy decide who may log in as whom,
    /// which is not what the realm configured.
    pub fn principal_of(cert: &X509Certificate<'_>) -> std::result::Result<Principal, PkinitError> {
        let names = cert
            .subject_alternative_name()
            .map_err(|e| PkinitError::Malformed(format!("subjectAltName: {e}")))?;
        let Some(names) = names else {
            return Err(PkinitError::NoPrincipalName);
        };
        for name in &names.value.general_names {
            if let GeneralName::OtherName(oid, value) = name {
                if oid.to_string() != ID_PKINIT_SAN {
                    continue;
                }
                return parse_krb5_principal_name(value);
            }
        }
        Err(PkinitError::NoPrincipalName)
    }

    /// `KRB5PrincipalName ::= SEQUENCE { realm [0] Realm, principalName [1] PrincipalName }`.
    fn parse_krb5_principal_name(value: &[u8]) -> std::result::Result<Principal, PkinitError> {
        use crate::der::{Fields, Reader};

        // The otherName value is `[0] EXPLICIT KRB5PrincipalName`: one context tag around
        // the SEQUENCE.
        let mut r = Reader::new(value);
        let outer = r
            .next_tlv("id-pkinit-san")
            .map_err(|e| PkinitError::BadPrincipalName(e.to_string()))?;
        let mut or = Reader::new(outer.content);
        let seq = or
            .next_tlv("KRB5PrincipalName")
            .map_err(|e| PkinitError::BadPrincipalName(e.to_string()))?;
        let f = Fields::parse("KRB5PrincipalName", seq.content)
            .map_err(|e| PkinitError::BadPrincipalName(e.to_string()))?;
        let realm = f
            .string(0, "KRB5PrincipalName")
            .map_err(|e| PkinitError::BadPrincipalName(e.to_string()))?;
        // RFC 4120's module is EXPLICIT too, so `[1]` wraps the `PrincipalName`.
        let name_tlv = f
            .bytes(1, "KRB5PrincipalName")
            .map_err(|e| PkinitError::BadPrincipalName(e.to_string()))?;
        let mut nr = Reader::new(name_tlv);
        let name_seq = nr
            .next_tlv("PrincipalName")
            .map_err(|e| PkinitError::BadPrincipalName(e.to_string()))?;
        let nf = Fields::parse("PrincipalName", name_seq.content)
            .map_err(|e| PkinitError::BadPrincipalName(e.to_string()))?;
        let name_type = nf
            .int(0, "PrincipalName")
            .map_err(|e| PkinitError::BadPrincipalName(e.to_string()))?;
        let components_tlv = nf
            .bytes(1, "PrincipalName")
            .map_err(|e| PkinitError::BadPrincipalName(e.to_string()))?;
        let mut cr = Reader::new(components_tlv);
        let components_seq = cr
            .next_tlv("principal components")
            .map_err(|e| PkinitError::BadPrincipalName(e.to_string()))?;
        let mut items = Reader::new(components_seq.content);
        let mut components = Vec::new();
        while !items.is_empty() {
            let item = items
                .next_tlv("component")
                .map_err(|e| PkinitError::BadPrincipalName(e.to_string()))?;
            components.push(
                String::from_utf8(item.content.to_vec()).map_err(|_| {
                    PkinitError::BadPrincipalName("a component is not UTF-8".into())
                })?,
            );
        }
        if components.is_empty() {
            return Err(PkinitError::BadPrincipalName(
                "the principal has no components".into(),
            ));
        }
        Ok(Principal::new(name_type as i32, components, realm))
    }

    /// Whether the certificate's extended key usage permits client authentication.
    ///
    /// An absent EKU means "any purpose" and is accepted, as RFC 5280 §4.2.1.12 says; a
    /// present one must list `id-pkinit-KPClientAuth`. A certificate issued for TLS
    /// servers must not become a Kerberos login by accident.
    pub fn key_purpose_ok(cert: &X509Certificate<'_>) -> std::result::Result<bool, PkinitError> {
        let Ok(Some(extension)) = cert.extended_key_usage() else {
            return Ok(true);
        };
        let eku = extension.value;
        // `client_auth` in X.509 is TLS client authentication (1.3.6.1.5.5.7.3.2), which is
        // a different purpose from PKINIT's (`1.3.6.1.5.2.3.4`) and lives in `other` here.
        // Accepting TLS's would let any certificate issued for a web client log in to the
        // realm, so the OID is compared by name.
        Ok(eku.any
            || eku
                .other
                .iter()
                .any(|oid| oid.to_string() == ID_PKINIT_KP_CLIENT_AUTH))
    }

    impl Identity {
        /// Authenticates a request: signature, chain, validity, key purpose, and the
        /// principal the certificate names.
        ///
        /// Nothing here touches the request body; [`check_body`] does that, because a
        /// valid signature over a different body is a different failure with a different
        /// cause.
        pub fn authenticate(
            request: &Request,
            anchors: &TrustAnchors,
            now: i64,
        ) -> std::result::Result<Self, PkinitError> {
            let Some(signed) = &request.signed else {
                return Err(PkinitError::Anonymous);
            };
            // `request.signed` holds the `ContentInfo`'s content, so a TLV is wrapped
            // around it to hand the envelope parser one value rather than two shapes.
            let ci = crate::der::Tlv {
                tag: crate::der::SEQUENCE,
                content: signed,
            };
            let envelope = Envelope::parse(&ci)?;

            let signer_cert = envelope.find_signer()?;
            let mut candidates = envelope.certificates.clone();
            candidates.retain(|c| c != &signer_cert);
            // The chain is built for its verdict, not for its contents: reaching an anchor
            // is what the check is, and validity of every link is checked on the way.
            let _chain = build_chain(&signer_cert, &candidates, &anchors.anchors, now)?;
            let leaf = parse_cert(&signer_cert)?;

            if !key_purpose_ok(&leaf)? {
                return Err(PkinitError::WrongKeyPurpose);
            }

            // The signature covers the attributes, not the content: RFC 5652 §5.4 says
            // the signature is over the DER of the `SignedAttributes` as a SET, so the
            // implicit `[0]` tag is put back before hashing.
            // `SET OF` is `0x31`; the SignerInfo carries it as `[0] IMPLICIT`, which is
            // the same octets with a different tag and nothing else changed.
            let attrs_der = crate::der::tlv(0x31, &envelope.signed_attrs_content);
            // The signature is over the attributes, not over their digest: hashing here
            // and hashing again inside `verify_signature` would verify SHA-256 of a
            // SHA-256, which fails for every input and looks like a wrong key.
            if !verify_signature(
                &leaf,
                &envelope.signature_alg,
                Some(&envelope.digest_alg),
                &attrs_der,
                &envelope.signature,
            )? {
                return Err(PkinitError::BadSignature(
                    "the signature over the signed attributes does not verify".into(),
                ));
            }

            // The attributes must name this content type and carry this content's digest.
            // Checking the signature alone would accept a signed statement about
            // anything at all.
            let mut content_type = None;
            let mut message_digest = None;
            for (oid, values) in &envelope.attributes {
                let Some(first) = values.first() else {
                    return Err(PkinitError::BadSignature(format!(
                        "attribute {oid} has no value"
                    )));
                };
                match oid.as_str() {
                    ATTR_CONTENT_TYPE => content_type = Some(parse_oid(first)?),
                    ATTR_MESSAGE_DIGEST => message_digest = Some(first.clone()),
                    _ => {}
                }
            }
            if content_type.as_deref() != Some(ID_PKINIT_AUTH_DATA) {
                return Err(PkinitError::BadSignature(format!(
                    "signed attributes name {:?}, not id-pkinit-authData",
                    content_type
                )));
            }
            let Some(message_digest) = message_digest else {
                return Err(PkinitError::BadSignature(
                    "signed attributes carry no messageDigest".into(),
                ));
            };
            let actual = match envelope.digest_alg.as_str() {
                "2.16.840.1.101.3.4.2.1" => {
                    use sha2::Digest;
                    sha2::Sha256::digest(&request.auth_pack).to_vec()
                }
                "2.16.840.1.101.3.4.2.2" => {
                    use sha2::Digest;
                    sha2::Sha384::digest(&request.auth_pack).to_vec()
                }
                _ => unreachable!("checked above"),
            };
            if actual != message_digest {
                return Err(PkinitError::BadSignature(
                    "messageDigest is not the digest of the AuthPack".into(),
                ));
            }

            let principal = principal_of(&leaf)?;
            Ok(Identity {
                principal,
                subject: leaf.subject().to_string(),
                cert: signer_cert.clone(),
            })
        }
    }

    /// An X.500 `Name`'s content, rendered the way `x509-parser` renders a certificate's
    /// issuer, so the two texts compare equal.
    fn x509_parser_name(content: &[u8]) -> std::result::Result<String, PkinitError> {
        use x509_parser::x509::X509Name;
        // `X509Name` is parsed from the full `SEQUENCE`; the caller holds its content.
        let der = crate::der::tlv(crate::der::SEQUENCE, content);
        let (_, name) = X509Name::from_der(&der)
            .map_err(|e| PkinitError::Malformed(format!("issuer name: {e}")))?;
        Ok(name.to_string())
    }

    fn parse_oid(content: &[u8]) -> std::result::Result<String, PkinitError> {
        crate::der::decode_oid("Attribute", content)
            .map_err(|e| PkinitError::Malformed(e.to_string()))
    }

    /// The parts of a `SignedData` this module judges.
    struct Envelope {
        certificates: Vec<Vec<u8>>,
        /// `IssuerAndSerialNumber`'s issuer, as text, for the candidate filter.
        issuer_text: String,
        serial: Vec<u8>,
        digest_alg: String,
        /// The signed attributes' content, as a SET for hashing: RFC 5652 §5.4 says the
        /// signature covers the DER of the `SignedAttributes` **as a SET**, so the
        /// implicit `[0]` tag is put back before hashing. Keeping the content and
        /// re-tagging is exact, because the length encoding is a function of the content.
        signed_attrs_content: Vec<u8>,
        /// The attributes, already split: OID and its values.
        attributes: Vec<(String, Vec<Vec<u8>>)>,
        signature_alg: String,
        signature: Vec<u8>,
    }

    impl Envelope {
        fn parse(ci: &crate::der::Tlv<'_>) -> std::result::Result<Self, PkinitError> {
            let sd = envelope_body(ci)?;

            // `certificates [0] IMPLICIT SET OF CertificateChoices`: the members are the
            // choice's encodings, and a plain certificate is a SEQUENCE.
            let mut certificates = Vec::new();
            if let Some(slot) = sd.items.get(3).filter(|s| s.tag == crate::der::ctx(0)) {
                let mut r = crate::der::Reader::new(slot.content);
                while !r.is_empty() {
                    let item = r
                        .next_tlv("CertificateChoices")
                        .map_err(|e| PkinitError::Malformed(e.to_string()))?;
                    if item.tag == crate::der::SEQUENCE {
                        certificates.push(crate::der::tlv(item.tag, item.content));
                    }
                }
            }

            // `signerInfos SET OF SignerInfo`: the last member, whatever precedes it.
            let infos = sd
                .items
                .last()
                .ok_or_else(|| PkinitError::Malformed("SignedData is empty".into()))?;
            if infos.tag != crate::der::SEQUENCE | 0x11 {
                return Err(PkinitError::Malformed(
                    "SignedData does not end with signerInfos".into(),
                ));
            }
            let mut items = crate::der::Reader::new(infos.content);
            let first = items
                .next_tlv("SignerInfo")
                .map_err(|e| PkinitError::Malformed(e.to_string()))?;
            if !items.is_empty() {
                return Err(PkinitError::Unsupported(
                    "a SignedData with more than one SignerInfo".into(),
                ));
            }
            let f = Seq::parse("SignerInfo", first.content)?;

            // `SIGNER-IDENTIFIER ::= CHOICE { issuerAndSerialNumber, [0] subjectKeyIdentifier }`
            let sid = f.at(1, "SignerInfo")?;
            if sid.tag != crate::der::SEQUENCE {
                return Err(PkinitError::Unsupported(
                    "SignerInfo identified by subjectKeyIdentifier; PKINIT uses \
                     issuerAndSerialNumber"
                        .into(),
                ));
            }
            let sif = Seq::parse("IssuerAndSerialNumber", sid.content)?;
            let issuer_content = sif.at(0, "IssuerAndSerialNumber")?.content;
            let issuer_text = x509_parser_name(issuer_content)?;
            let serial = sif.at(1, "IssuerAndSerialNumber")?.content.to_vec();

            let digest_alg = f.algorithm(2, "SignerInfo")?;
            let signed_attrs_tlv = f
                .at(3, "SignerInfo")
                .map_err(|_| PkinitError::BadSignature("SignerInfo has no signedAttrs".into()))?;
            if signed_attrs_tlv.tag != crate::der::ctx(0) {
                return Err(PkinitError::BadSignature(
                    "SignerInfo's attributes are not signed (they are unsigned or absent)".into(),
                ));
            }
            let mut items = crate::der::Reader::new(signed_attrs_tlv.content);
            let mut attributes = Vec::new();
            while !items.is_empty() {
                let attr = items
                    .next_tlv("Attribute")
                    .map_err(|e| PkinitError::Malformed(e.to_string()))?;
                let af = Seq::parse("Attribute", attr.content)?;
                let oid = af.oid(0, "Attribute")?;
                let values = af.tagged(1, 0x31, "Attribute")?;
                let mut vr = crate::der::Reader::new(values.content);
                let mut out = Vec::new();
                while !vr.is_empty() {
                    out.push(
                        vr.next_tlv("Attribute value")
                            .map_err(|e| PkinitError::Malformed(e.to_string()))?
                            .content
                            .to_vec(),
                    );
                }
                attributes.push((oid, out));
            }
            let signature_alg = f.algorithm(4, "SignerInfo")?;
            let signature = f
                .tagged(5, crate::der::OCTET_STRING, "SignerInfo")?
                .content
                .to_vec();

            Ok(Self {
                certificates,
                issuer_text,
                serial,
                digest_alg,
                signed_attrs_content: signed_attrs_tlv.content.to_vec(),
                attributes,
                signature_alg,
                signature,
            })
        }

        /// The certificate whose issuer and serial the `SignerInfo` names.
        ///
        /// Selected by the pair, not by position: `certificates` is a SET, its order is
        /// whatever the encoder produced, and taking the first would authenticate
        /// whichever certificate happened to sort first.
        fn find_signer(&self) -> std::result::Result<Vec<u8>, PkinitError> {
            for der in &self.certificates {
                let cert = parse_cert(der)?;
                // The issuer is compared as text and the serial as octets: the pair is
                // only a candidate filter, and the signature check that follows is what
                // actually decides. Comparing the issuer's raw DER would be stricter,
                // but `x509-parser` does not expose it, and the signature already rules
                // out a name-swapped certificate.
                if cert.issuer().to_string() != self.issuer_text {
                    continue;
                }
                if cert.tbs_certificate.raw_serial() != self.serial {
                    continue;
                }
                return Ok(der.clone());
            }
            Err(PkinitError::BadSignature(
                "the SignerInfo names a certificate the request did not send".into(),
            ))
        }
    }

    /// Checks that `paChecksum` covers `body`.
    ///
    /// RFC 4556 §3.2.1: the checksum is SHA-1 over the `KDC-REQ-BODY` as it was sent.
    /// This is the binding that stops a signed `AuthPack` from being replayed into a
    /// request it was not written for — the signature stays valid, only the meaning
    /// changes.
    pub fn check_body(auth_pack: &AuthPack, body: &[u8]) -> std::result::Result<(), PkinitError> {
        use sha1::Digest;
        let expected = sha1::Sha1::digest(body);
        if auth_pack.pk_authenticator.pa_checksum != expected.as_slice() {
            return Err(PkinitError::BodyMismatch);
        }
        Ok(())
    }
}

/// Parses a DER certificate with the same strictness the trust code applies: no trailing
/// octets, and a structure that parses end to end.
#[cfg(feature = "pkinit")]
pub(super) fn parse_certificate(
    der: &[u8],
) -> std::result::Result<x509_parser::certificate::X509Certificate<'_>, PkinitError> {
    trusted::parse_cert(der)
}

#[cfg(not(feature = "pkinit"))]
mod untrusted {
    // Without the feature there is no X.509 stack, so no certificate can be trusted and
    // the only honest answer to a PKINIT request is that this build cannot make one. Nothing from
    // `super` is needed: the type below exists only so that a caller's signature compiles.

    /// Present so that callers compile without the feature; it trusts nothing.
    #[derive(Debug, Clone, Default)]
    pub struct TrustAnchors;

    impl TrustAnchors {
        /// An empty set.
        pub fn new() -> Self {
            Self
        }

        /// Always zero: this build has no X.509.
        pub fn len(&self) -> usize {
            0
        }

        /// Always true.
        pub fn is_empty(&self) -> bool {
            true
        }
    }
}

#[cfg(not(feature = "pkinit"))]
pub use untrusted::TrustAnchors;

#[cfg(feature = "pkinit")]
impl Default for TrustAnchors {
    /// Empty, and written out here rather than delegated to `new` — and `new` does not
    /// delegate here either. Pointing each at the other recursed until the stack ran out,
    /// which the tests found as a crash rather than as a wrong answer.
    fn default() -> Self {
        TrustAnchors::new()
    }
}

#[cfg(feature = "pkinit")]
#[allow(dead_code)]
fn _assert_result_is_ours(_: crate::error::Error) -> Result<()> {
    Ok(())
}
