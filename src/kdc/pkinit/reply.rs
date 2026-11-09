//! The KDC's half of PKINIT: `PA-PK-AS-REP` and the reply key.
//!
//! The client proves who it is in `PA-PK-AS-REQ` and offers a Diffie-Hellman public value.
//! The KDC answers with its own, signs it so the client can tell a real KDC from a relay,
//! and derives the reply key from the shared secret. Two things make this half worth
//! writing carefully:
//!
//! * the signature travels in CMS `SignedData`, so this module is the *signing* counterpart
//!   of the verification in the parent module — same attributes, same "signature covers the
//!   attributes as a SET" rule, opposite direction;
//! * the reply key `enc-part` is sealed with does not exist on either side until the
//!   exchange completes, which is what makes PKINIT immune to the offline password search
//!   FAST also closes.
//!
//! The KDC's contribution is a fresh pair per request. Caching key pairs would mean
//! `dhKeyExpiration` and the `serverDHNonce` that must accompany it; a fresh pair needs
//! neither, and a KDC that answers once per login can afford the exponentiation.
//!
//! What is here: `KDCDHKeyInfo`, the `SignedData` around it, `DHRepInfo`, and the reply-key
//! derivation of RFC 8636. What is not: RSA key transport (`encKeyPack`, `[1]`), which MIT's
//! own client refuses, and elliptic-curve ECDH.

use super::PkinitError;
#[cfg(feature = "pkinit")]
use super::rsa_digest;
use crate::crypto::Enctype;
use crate::der;
use crate::name::Principal;

/// `id-pkinit-rkeyData` (`1.3.6.1.5.2.3.3`): the content type of a `ReplyKeyPack`, used by
/// the key-transport form this module does not implement. Declared so that a request that
/// asks for it is refused by name rather than misread.
pub const ID_PKINIT_RKEY_DATA: &str = "1.3.6.1.5.2.3.3";

/// The KDC's certificate and private key, as the realm was configured with them.
///
/// DER, not PEM: a PEM parser is a file-format concern, and this crate deliberately has no
/// opinion about where a key comes from. An embedder that reads a PEM file decodes it and
/// hands the octets here.
#[cfg(feature = "pkinit")]
pub struct Identity {
    /// The certificate sent alongside the signature, DER.
    pub cert: Vec<u8>,
    /// The RSA key that signs.
    pub key: rsa::RsaPrivateKey,
}

#[cfg(feature = "pkinit")]
impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The key must not reach a log line, and a derived `Debug` would print it.
        f.debug_struct("pkinit::Identity")
            .field("cert_octets", &self.cert.len())
            .field("key", &"<private key>")
            .finish()
    }
}

#[cfg(feature = "pkinit")]
impl Identity {
    /// The identity from a DER certificate and a DER-encoded RSA private key.
    ///
    /// Both PKCS#8 (`BEGIN PRIVATE KEY`) and PKCS#1 (`BEGIN RSA PRIVATE KEY`) are accepted,
    /// because both are what a tool emits depending on how the key was made.
    pub fn from_der(cert: &[u8], key: &[u8]) -> Result<Self, PkinitError> {
        use rsa::pkcs1::DecodeRsaPrivateKey;
        use rsa::pkcs8::DecodePrivateKey;

        // The certificate is parsed rather than stored blind: a wrong file would otherwise
        // produce a signature under a key nobody can chain, and the client's report would
        // be "the KDC is not trustworthy" rather than "the KDC is misconfigured".
        super::parse_certificate(cert)?;
        let key = rsa::RsaPrivateKey::from_pkcs8_der(key)
            .or_else(|_| rsa::RsaPrivateKey::from_pkcs1_der(key))
            .map_err(|e| PkinitError::Malformed(format!("the KDC's private key: {e}")))?;
        Ok(Self {
            cert: cert.to_vec(),
            key,
        })
    }

    /// Signs `content` as CMS `SignedData` of `content_type`.
    ///
    /// The shape is the one the verifier reads, and the details are the ones that decide
    /// whether a third-party client accepts it: `[0]`-implicit `signedAttrs` whose DER is
    /// re-tagged as a SET before hashing, `digestAlgorithm` naming the hash separately from
    /// `rsaEncryption`, and the certificate carried inside the envelope so the client need
    /// not have it out of band.
    pub fn signed_data(&self, content_type: &str, content: &[u8]) -> Result<Vec<u8>, PkinitError> {
        use rsa::pkcs1v15::Pkcs1v15Sign;
        use rsa_digest::Digest;

        let digest_alg = der::seq(&[
            der::tlv(der::OBJECT_IDENTIFIER, &encode_oid(super::SHA256_OID)),
            der::tlv(0x05, &[]), // NULL parameters, as OpenSSL emits them
        ]);

        // The two attributes RFC 5652 requires for a detached-capable signature, both
        // present here because the verifier refuses a signature that does not say what it
        // is over.
        let attrs_content = [
            der::seq(&[
                der::tlv(
                    der::OBJECT_IDENTIFIER,
                    &encode_oid(super::ATTR_CONTENT_TYPE),
                ),
                der::cons(
                    0x31,
                    &[der::tlv(der::OBJECT_IDENTIFIER, &encode_oid(content_type))],
                ),
            ]),
            der::seq(&[
                der::tlv(
                    der::OBJECT_IDENTIFIER,
                    &encode_oid(super::ATTR_MESSAGE_DIGEST),
                ),
                der::cons(0x31, &[der::octets(&rsa_digest::Sha256::digest(content))]),
            ]),
        ]
        .concat();

        // Signed over the attributes **as a SET**: the SignerInfo carries them as `[0]
        // IMPLICIT SET`, so the tag is put back before hashing.
        let attrs_der = der::tlv(0x31, &attrs_content);
        let digest = rsa_digest::Sha256::digest(&attrs_der);
        let signature = self
            .key
            .sign(Pkcs1v15Sign::new::<rsa_digest::Sha256>(), &digest)
            .map_err(|e| PkinitError::BadSignature(format!("the KDC cannot sign: {e}")))?;

        let (issuer, serial) = issuer_and_serial(&self.cert)?;

        let signer_info = der::seq(&[
            der::int(1), // version
            // `IssuerAndSerialNumber`, which is what the client looks the certificate up by.
            der::seq(&[issuer, der::tlv(der::INTEGER, &serial)]),
            digest_alg.clone(),
            der::tlv(0xa0, &attrs_content), // signedAttrs [0] IMPLICIT
            der::seq(&[
                der::tlv(der::OBJECT_IDENTIFIER, &encode_oid(super::RSA_ENCRYPTION)),
                der::tlv(0x05, &[]),
            ]),
            der::octets(&signature),
        ]);
        let signed_data = der::seq(&[
            der::int(3), // version: 3 whenever certificates of type other than X.509 v1 appear
            der::cons(0x31, &[digest_alg]), // digestAlgorithms
            // EncapsulatedContentInfo: the content travels inside, `-nodetach` in OpenSSL's
            // terms, which is the form RFC 4556 describes.
            der::seq(&[
                der::tlv(der::OBJECT_IDENTIFIER, &encode_oid(content_type)),
                der::tlv(0xa0, &der::octets(content)),
            ]),
            // certificates [0] IMPLICIT: the signer's own, so the client can chain it.
            der::tlv(0xa0, &self.cert),
            der::cons(0x31, &[signer_info]), // signerInfos
        ]);

        Ok(der::seq(&[
            der::tlv(der::OBJECT_IDENTIFIER, &encode_oid(super::ID_SIGNED_DATA)),
            der::tlv(0xa0, &signed_data),
        ]))
    }
}

/// The issuer `Name` and serial number of a certificate, as octets.
///
/// Walked out of the DER rather than rebuilt from a parsed structure: a `Name` re-encoded
/// from its RDNs is byte-identical only if the encoder sorts and formats exactly as the
/// issuer did, and a signature that names a *nearly* identical issuer is one no client can
/// resolve. Taking the octets that are already there cannot disagree with them.
fn issuer_and_serial(cert_der: &[u8]) -> Result<(Vec<u8>, Vec<u8>), PkinitError> {
    let mut r = der::Reader::new(cert_der);
    let cert = r
        .next("Certificate")
        .map_err(|e| PkinitError::Malformed(e.to_string()))?;
    if cert.tag != der::SEQUENCE {
        return Err(PkinitError::Malformed(
            "the certificate is not a SEQUENCE".into(),
        ));
    }
    let mut cr = der::Reader::new(cert.content);
    let tbs = cr
        .next("TBSCertificate")
        .map_err(|e| PkinitError::Malformed(e.to_string()))?;
    let mut t = der::Reader::new(tbs.content);
    // `version [0] EXPLICIT` is optional; its presence shifts every field by one.
    let first = t
        .next("TBSCertificate")
        .map_err(|e| PkinitError::Malformed(e.to_string()))?;
    let mut tail = t;
    let serial = if first.tag == 0xa0 {
        tail.next("serialNumber")
            .map_err(|e| PkinitError::Malformed(e.to_string()))?
    } else {
        first
    };
    // serialNumber, then the signature algorithm, then the issuer.
    tail.next("signature")
        .map_err(|e| PkinitError::Malformed(e.to_string()))?;
    let issuer = tail
        .next("issuer")
        .map_err(|e| PkinitError::Malformed(e.to_string()))?;
    Ok((
        der::tlv(der::SEQUENCE, issuer.content),
        serial.content.to_vec(),
    ))
}

/// `KDCDHKeyInfo ::= SEQUENCE { subjectPublicKey [0] BIT STRING, nonce [1] INTEGER,
/// dhKeyExpiration [2] OPTIONAL }` (RFC 4556 §3.2.3).
///
/// The nonce is the client's, echoed: it is what ties the KDC's public value to this
/// request, and a KDC that answered with a key from another exchange would be caught by it.
/// `dhKeyExpiration` is absent because a fresh pair is generated per request — an expiring
/// key that is never reused needs no expiry.
pub fn kdcdh_key_info(public: &[u8], nonce: u32) -> Vec<u8> {
    let mut bits = vec![0u8]; // unused-bit count
    bits.extend_from_slice(public);
    der::seq(&[
        der::field(0, der::tlv(0x03, &bits)),
        der::field(1, der::int(i64::from(nonce))),
    ])
}

/// `PA-PK-AS-REP` in its Diffie-Hellman form: `[0] DHRepInfo { dhSignedData [0], ... }`.
///
/// `signed_data` is the `SignedData` over [`kdcdh_key_info`], which the caller produces
/// because it owns the KDC's identity.
pub fn dh_rep_info(signed_data: Vec<u8>) -> Vec<u8> {
    // `dhSignedData [0] IMPLICIT OCTET STRING` holds the ContentInfo, and the whole is
    // wrapped in `dhInfo [0]`.
    let rep = der::seq(&[der::field(0, der::octets(&signed_data))]);
    der::tlv(der::ctx(0), &rep)
}

/// The reply key from the shared secret: RFC 8636's KDF when the client offered one, else
/// RFC 4556's `octetstring2key`.
///
/// The returned octets are key material, not a `Key`: random-to-key is the identity for
/// AES, but keeping the conversion at the call site makes it obvious that no enctype with a
/// real random-to-key could be smuggled through here.
pub fn reply_key(
    z: &[u8],
    kdf: Option<&str>,
    client: &Principal,
    server: &Principal,
    enctype: Enctype,
    as_req: &[u8],
    pk_as_rep: &[u8],
) -> Result<Vec<u8>, PkinitError> {
    let len = super::dh::key_len(enctype);
    match kdf {
        None => Ok(super::dh::octetstring2key(z, len)),
        Some(oid) => {
            let info = super::dh::other_info(oid, client, server, enctype, as_req, pk_as_rep);
            super::dh::sp800_56a(oid, z, &info, len).ok_or_else(|| {
                PkinitError::Unsupported(format!(
                    "the client offered KDF {oid}, which this KDC does not implement"
                ))
            })
        }
    }
}

/// The KDF this KDC prefers out of those a client offered.
///
/// Strongest first, as MIT does, and the client's order is not consulted: a client that
/// offers SHA-256 and SHA-1 wants the KDC to choose well, not to take whatever comes first
/// in a list an attacker on the wire could reorder.
pub fn choose_kdf(offered: &[String]) -> Option<&'static str> {
    super::dh::OFFERED
        .iter()
        .copied()
        .find(|kdf| offered.iter().any(|o| o == kdf))
}

/// Everything the reply half needs from the realm's configuration.
#[cfg(feature = "pkinit")]
pub struct State {
    /// The KDC's certificate and signing key.
    pub identity: Identity,
    /// The roots a client's certificate may chain to.
    pub anchors: super::TrustAnchors,
}

/// What the exchange produced: the key the reply's `enc-part` is sealed in, and the
/// `PA-PK-AS-REP` that lets the client derive the same key.
#[cfg(feature = "pkinit")]
pub struct Answer {
    /// The AS reply key, from the shared secret.
    pub reply_key: crate::crypto::Key,
    /// The `PA-PK-AS-REP` value.
    pub pa_pk_as_rep: Vec<u8>,
    /// The client's DH public value, for a log line — not for a decision.
    pub client_group_bits: u32,
}

/// Runs the KDC's half of PKINIT over a `PA-PK-AS-REQ`.
///
/// The order is the protocol: authenticate the client's signature and certificate first,
/// because everything after it is a key handed to whoever asked; then bind the signature to
/// *this* request through `paChecksum`; then read the client's DH value; then agree, sign,
/// and derive.
///
/// `rng` supplies the private exponent. It is a parameter rather than a call to
/// `getrandom` so that a test can make an exchange reproducible — and so that an embedder
/// with its own entropy source is not forced through ours.
#[cfg(feature = "pkinit")]
#[allow(clippy::too_many_arguments)]
pub fn answer(
    state: &State,
    pa_value: &[u8],
    body_der: &[u8],
    as_req_der: &[u8],
    client: &Principal,
    server: &Principal,
    enctype: Enctype,
    now: i64,
    rng: &dyn Fn(usize) -> Vec<u8>,
) -> Result<Answer, PkinitError> {
    // 1. Who is asking.
    let request = super::Request::decode(pa_value)?;
    let identity = super::Identity::authenticate(&request, &state.anchors, now)?;
    if &identity.principal != client {
        // The certificate names someone else. Answering would issue a ticket to the
        // certificate's owner while the request claims to be another — a mix-up nobody
        // benefits from except an attacker who holds one and asks for the other.
        return Err(PkinitError::BadPrincipalName(format!(
            "the certificate names {} but the request asks for {client}",
            identity.principal
        )));
    }

    // 2. That the signature covers this request. `paChecksum` is over the
    //    `KDC-REQ-BODY` (RFC 4556 §3.2.1) — not over the whole AS-REQ, which is what the
    //    KDF binds in later and is a different input.
    let pack = request.auth_pack()?;
    super::check_body(&pack, body_der)?;

    // 3. The client's public value, and the group it is in.
    let value = pack.client_public_value.as_deref().ok_or_else(|| {
        PkinitError::Unsupported(
            "the request carries no clientPublicValue: RSA key transport is not implemented".into(),
        )
    })?;
    let (group, peer) = parse_client_public_value(value)?;

    // 4. Our own value, and the shared secret.
    let ours = super::dh::KeyPair::generate(group, rng)?;
    let z = ours.agree(&peer)?;

    // 5. The reply key. Unknown KDFs are refused, not replaced by the legacy one: a client
    //    that named a KDF is going to derive with it, and a silent fallback would produce a
    //    reply it cannot open.
    let kdf = match pack.supported_kdfs.is_empty() {
        true => None,
        false => Some(choose_kdf(&pack.supported_kdfs).ok_or_else(|| {
            PkinitError::Unsupported(format!(
                "the client offers KDFs this KDC does not implement: {:?}",
                pack.supported_kdfs
            ))
        })?),
    };

    // The signature covers the `KDCDHKeyInfo`, so it is built before the reply key: the
    // KDF binds `pk-as-rep` into its context, and that has to be the octets the client will
    // see rather than a placeholder.
    let info = kdcdh_key_info(&ours.public_bytes(), pack.pk_authenticator.nonce);
    let signed = state
        .identity
        .signed_data(super::ID_PKINIT_DH_KEY_DATA, &info)?;
    let pa_pk_as_rep = dh_rep_info(signed.clone());

    let key_bytes = reply_key(&z, kdf, client, server, enctype, as_req_der, &pa_pk_as_rep)?;
    let reply_key = crate::crypto::Key::new(enctype, key_bytes)
        .map_err(|e| PkinitError::Malformed(format!("the reply key: {e}")))?;

    Ok(Answer {
        reply_key,
        pa_pk_as_rep,
        client_group_bits: group.bits(),
    })
}

/// The group and the public value out of `clientPublicValue`.
///
/// `SubjectPublicKeyInfo ::= SEQUENCE { algorithm AlgorithmIdentifier, subjectPublicKey
/// BIT STRING }`, where the algorithm is `dhpublicnumber` with the domain parameters as its
/// parameters, and the bit string holds the DH value big-endian.
#[cfg(feature = "pkinit")]
fn parse_client_public_value(value: &[u8]) -> Result<(super::dh::Group, Vec<u8>), PkinitError> {
    let mut r = der::Reader::new(value);
    let spki = r
        .next("clientPublicValue")
        .map_err(|e| PkinitError::Malformed(e.to_string()))?;
    if spki.tag != der::SEQUENCE {
        return Err(PkinitError::Malformed(
            "clientPublicValue is not a SubjectPublicKeyInfo".into(),
        ));
    }
    let mut sr = der::Reader::new(spki.content);
    let alg = sr
        .next("algorithm")
        .map_err(|e| PkinitError::Malformed(e.to_string()))?;
    let bits = sr
        .next("subjectPublicKey")
        .map_err(|e| PkinitError::Malformed(e.to_string()))?;
    if bits.tag != 0x03 {
        return Err(PkinitError::Malformed(
            "subjectPublicKey is not a BIT STRING".into(),
        ));
    }

    // The algorithm must be `dhpublicnumber`; an ECDH or RSA key here would be a mode this
    // KDC does not implement, and guessing would derive a key nobody else computes.
    let mut ar = der::Reader::new(alg.content);
    let oid = ar
        .next("algorithm")
        .map_err(|e| PkinitError::Malformed(e.to_string()))?;
    let name = der::decode_oid("algorithm", oid.content)
        .map_err(|e| PkinitError::Malformed(e.to_string()))?;
    if name != super::dh::DH_PUBLIC_NUMBER {
        return Err(PkinitError::Unsupported(format!(
            "clientPublicValue uses {name}; this KDC implements finite-field DH \
             (dhpublicnumber) only"
        )));
    }
    let params = ar.next("DomainParameters").map_err(|_| {
        PkinitError::Malformed(
            "dhpublicnumber without domain parameters: the group cannot be inferred".into(),
        )
    })?;
    let group = super::dh::Group::from_domain_parameters(&der::tlv(der::SEQUENCE, params.content))?;

    if bits.content.is_empty() {
        return Err(PkinitError::Malformed("subjectPublicKey is empty".into()));
    }
    // The first octet is the unused-bit count, which must be zero for a DH value: a
    // non-zero count means the client sent something that is not whole octets.
    if bits.content[0] != 0 {
        return Err(PkinitError::Malformed(format!(
            "subjectPublicKey has {} unused bits",
            bits.content[0]
        )));
    }
    Ok((group, bits.content[1..].to_vec()))
}

/// An OID's content octets, the inverse of `der::decode_oid`.
fn encode_oid(text: &str) -> Vec<u8> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::der::Reader;

    #[test]
    fn the_kdcdh_key_info_carries_the_public_value_and_echoes_the_nonce() {
        let info = kdcdh_key_info(&[0xde, 0xad, 0xbe, 0xef], 0x1234_5678);
        let mut r = Reader::new(&info);
        let seq = r.next("KDCDHKeyInfo").unwrap();
        assert_eq!(seq.tag, der::SEQUENCE);

        let mut inner = Reader::new(seq.content);
        let key_tlv = inner.next("subjectPublicKey").unwrap();
        assert_eq!(key_tlv.tag, 0xa0, "subjectPublicKey [0]");
        let mut kr = Reader::new(key_tlv.content);
        let bits = kr.next("BIT STRING").unwrap();
        assert_eq!(bits.tag, 0x03);
        assert_eq!(bits.content[0], 0, "no unused bits");
        assert_eq!(&bits.content[1..], &[0xde, 0xad, 0xbe, 0xef]);

        let nonce_tlv = inner.next("nonce").unwrap();
        assert_eq!(nonce_tlv.tag, 0xa1);
        let mut nr = Reader::new(nonce_tlv.content);
        let nonce = nr.next("INTEGER").unwrap();
        assert_eq!(
            crate::der::as_int("nonce", nonce.content).unwrap(),
            0x1234_5678
        );
    }

    #[test]
    fn the_dh_rep_info_wraps_the_signed_data_as_rfc_4556_describes() {
        // `PA-PK-AS-REP ::= CHOICE { dhInfo [0] DHRepInfo }`
        // `DHRepInfo ::= SEQUENCE { dhSignedData [0] IMPLICIT OCTET STRING }`
        let rep = dh_rep_info(vec![0x30, 0x00]);
        assert_eq!(rep[0], der::ctx(0), "dhInfo [0] is the outermost tag");

        let mut r = Reader::new(&rep);
        let outer = r.next("PA-PK-AS-REP").unwrap();
        let mut or = Reader::new(outer.content);
        let seq = or.next("DHRepInfo").unwrap();
        assert_eq!(seq.tag, der::SEQUENCE);

        let mut sr = Reader::new(seq.content);
        let field = sr.next("dhSignedData").unwrap();
        assert_eq!(field.tag, 0xa0);
        let mut fr = Reader::new(field.content);
        let octets = fr.next("OCTET STRING").unwrap();
        assert_eq!(octets.tag, 0x04);
        assert_eq!(octets.content, &[0x30, 0x00]);
    }

    #[test]
    fn the_kdf_choice_prefers_the_strongest_offered() {
        use super::super::dh::{KDF_SHA1, KDF_SHA256, KDF_SHA512};

        // A client offering all three gets SHA-256, this KDC's first choice — not SHA-512,
        // which it also implements, and not SHA-1, which is merely tolerated for older
        // clients.
        let offered = vec![
            KDF_SHA1.to_string(),
            KDF_SHA512.to_string(),
            KDF_SHA256.to_string(),
        ];
        assert_eq!(choose_kdf(&offered), Some(KDF_SHA256));

        // A client that offers only SHA-1 still gets an answer: refusing it would break
        // every client built before RFC 8636.
        assert_eq!(choose_kdf(&[KDF_SHA1.to_string()]), Some(KDF_SHA1));

        // One that offers nothing this KDC knows is refused rather than given a fallback it
        // did not ask for.
        assert_eq!(choose_kdf(&["1.2.3".to_string()]), None);

        // And a client that offers no KDF at all gets the legacy derivation, which the
        // caller signals with `None` and not with an empty list.
        assert_eq!(choose_kdf(&[]), None);
    }

    #[test]
    fn the_reply_key_depends_on_the_exchange_and_not_only_on_the_secret() {
        use crate::crypto::Enctype;
        let client = Principal::new(1, ["alice"], "EXAMPLE.COM");
        let server = Principal::krbtgt("EXAMPLE.COM");
        let z = [0x42u8; 32];

        let base = reply_key(
            &z,
            Some(super::super::dh::KDF_SHA256),
            &client,
            &server,
            Enctype::Aes256Sha1,
            b"as-req",
            b"pk-as-rep",
        )
        .unwrap();
        assert_eq!(base.len(), 32);

        // The same secret in a different exchange is a different key: an attacker who
        // captured one exchange cannot make its key open another.
        let other_client = Principal::new(1, ["bob"], "EXAMPLE.COM");
        assert_ne!(
            base,
            reply_key(
                &z,
                Some(super::super::dh::KDF_SHA256),
                &other_client,
                &server,
                Enctype::Aes256Sha1,
                b"as-req",
                b"pk-as-rep"
            )
            .unwrap()
        );
        assert_ne!(
            base,
            reply_key(
                &z,
                Some(super::super::dh::KDF_SHA256),
                &client,
                &server,
                Enctype::Aes256Sha1,
                b"another request",
                b"pk-as-rep"
            )
            .unwrap()
        );

        // No KDF offered means the legacy derivation, which is a different function
        // entirely — one octet counter from zero instead of four from one.
        let legacy = reply_key(
            &z,
            None,
            &client,
            &server,
            Enctype::Aes256Sha1,
            b"as-req",
            b"pk-as-rep",
        )
        .unwrap();
        assert_ne!(legacy, base);
        assert_eq!(legacy.len(), 32);
    }

    #[test]
    fn an_unknown_kdf_is_refused_rather_than_substituted() {
        let client = Principal::new(1, ["alice"], "EXAMPLE.COM");
        let err = reply_key(
            &[0x42; 32],
            Some("1.2.3"),
            &client,
            &Principal::krbtgt("EXAMPLE.COM"),
            crate::crypto::Enctype::Aes256Sha1,
            b"a",
            b"b",
        )
        .unwrap_err();
        match err {
            PkinitError::Unsupported(m) => assert!(m.contains("1.2.3"), "{m}"),
            other => panic!("expected Unsupported, got {other:?}"),
        }
    }
}
