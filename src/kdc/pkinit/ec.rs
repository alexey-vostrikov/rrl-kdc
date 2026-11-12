//! Elliptic-curve Diffie-Hellman for PKINIT (RFC 5349).
//!
//! The client offers an `id-ecPublicKey` `SubjectPublicKeyInfo` where RFC 4556 clients offer
//! `dhpublicnumber`, and the rest of the exchange is unchanged: the KDC answers with a
//! `KDCDHKeyInfo` whose `subjectPublicKey` holds **its own point**, the same `SignedData` wraps it,
//! and the shared secret goes through the same KDF. What differs is everything about the arithmetic,
//! which is why it lives here and not in [`super::dh`].
//!
//! Three curves, because three are what every client offers: P-256, P-384 and P-521. The curve is
//! named by the client's `AlgorithmIdentifier` and has to be used as named — a KDC that substituted
//! one would produce a secret nobody else computes, and the failure would look like a corrupt
//! ticket rather than a protocol error.

use crate::der;
use crate::kdc::pkinit::PkinitError;
// The SEC1 point encoding is a trait in `elliptic-curve` 0.14, and every curve crate re-exports the
// same one; naming it once here keeps the three arms below identical.
use p256::elliptic_curve::sec1::ToSec1Point;

/// `id-ecPublicKey` (RFC 5480 §2.1.1).
pub const ID_EC_PUBLIC_KEY: &str = "1.2.840.10045.2.1";

/// A NIST curve, as a client may name one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Curve {
    /// `prime256v1` / `secp256r1`.
    P256,
    /// `secp384r1`.
    P384,
    /// `secp521r1`.
    P521,
}

impl Curve {
    /// The curve a `namedCurve` OID names, if it is one of the three.
    ///
    /// Explicitly parameterised curves are refused rather than supported: RFC 5480 §2.1.1 allows a
    /// client to spell out the field and the generator, every implementation emits `namedCurve`
    /// instead, and accepting the explicit form means validating parameters whose one bad case is a
    /// curve with a known discrete log.
    pub fn from_oid(oid: &str) -> Option<Curve> {
        match oid {
            "1.2.840.10045.3.1.7" => Some(Curve::P256),
            "1.3.132.0.34" => Some(Curve::P384),
            "1.3.132.0.35" => Some(Curve::P521),
            _ => None,
        }
    }

    /// The curve's OID, as a client names it.
    pub fn oid(self) -> &'static str {
        match self {
            Curve::P256 => "1.2.840.10045.3.1.7",
            Curve::P384 => "1.3.132.0.34",
            Curve::P521 => "1.3.132.0.35",
        }
    }

    /// The curve's field size in bits.
    pub fn bits(self) -> u32 {
        match self {
            Curve::P256 => 256,
            Curve::P384 => 384,
            Curve::P521 => 521,
        }
    }

    /// Octets in a field element — and so in one coordinate of a point.
    pub fn field_len(self) -> usize {
        match self {
            Curve::P256 => 32,
            Curve::P384 => 48,
            Curve::P521 => 66,
        }
    }

    /// The curve named by an `AlgorithmIdentifier`'s parameters (`namedCurve`).
    pub fn from_params(params: Option<&[u8]>) -> Result<Curve, PkinitError> {
        let params = params.ok_or_else(|| {
            PkinitError::Malformed("an elliptic-curve key without a named curve".into())
        })?;
        let mut r = der::Reader::new(params);
        let oid = r
            .next_tlv("namedCurve")
            .map_err(|e| PkinitError::Malformed(e.to_string()))?;
        let name = der::decode_oid("namedCurve", oid.content)
            .map_err(|e| PkinitError::Malformed(e.to_string()))?;
        Curve::from_oid(&name).ok_or_else(|| {
            // Not `Malformed`: the request is well-formed and names a curve this KDC does not
            // have. Reporting it as malformed would send the operator to the wrong place.
            PkinitError::Unsupported(format!(
                "elliptic curve {name}; this KDC implements P-256, P-384 and P-521"
            ))
        })
    }
}

/// An ephemeral key pair, with the point the client is told to use.
pub struct KeyPair {
    curve: Curve,
    secret: Secret,
    point: Vec<u8>,
}

enum Secret {
    P256(p256::SecretKey),
    P384(p384::SecretKey),
    P521(p521::SecretKey),
}

impl std::fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The scalar must not reach a log line; the curve and the public point are safe.
        f.debug_struct("pkinit::ec::KeyPair")
            .field("curve", &self.curve)
            .field("point_octets", &self.point.len())
            .finish()
    }
}

impl KeyPair {
    /// A fresh pair on `curve`.
    ///
    /// The scalar comes from `rng` rather than from the OS, for the same reason it does in
    /// [`super::dh`]: a test has to be able to make an exchange reproducible, and an embedder with
    /// its own entropy source should not be forced through somebody else's. The octets are
    /// rejection-sampled until they name a scalar in `[1, n)`, which is what `from_slice` decides.
    pub fn generate(curve: Curve, rng: &dyn Fn(usize) -> Vec<u8>) -> Result<KeyPair, PkinitError> {
        for _ in 0..64 {
            let candidate = scalar_bytes(curve, rng)?;
            match curve {
                Curve::P256 => {
                    if let Ok(sk) = p256::SecretKey::from_slice(&candidate) {
                        let point = sk.public_key().to_sec1_point(false).as_bytes().to_vec();
                        return Ok(KeyPair {
                            curve,
                            secret: Secret::P256(sk),
                            point,
                        });
                    }
                }
                Curve::P384 => {
                    if let Ok(sk) = p384::SecretKey::from_slice(&candidate) {
                        let point = sk.public_key().to_sec1_point(false).as_bytes().to_vec();
                        return Ok(KeyPair {
                            curve,
                            secret: Secret::P384(sk),
                            point,
                        });
                    }
                }
                Curve::P521 => {
                    if let Ok(sk) = p521::SecretKey::from_slice(&candidate) {
                        let point = sk.public_key().to_sec1_point(false).as_bytes().to_vec();
                        return Ok(KeyPair {
                            curve,
                            secret: Secret::P521(sk),
                            point,
                        });
                    }
                }
            }
        }
        // Sixty-four rejected candidates is not bad luck, it is a generator that is not random —
        // and an exchange that continued would be one with a guessable scalar.
        Err(PkinitError::Malformed(
            "the entropy source produced no usable elliptic-curve scalar in 64 attempts".into(),
        ))
    }

    /// The curve this pair is on.
    pub fn curve(&self) -> Curve {
        self.curve
    }

    /// The public point, SEC1 uncompressed: `04 || X || Y`.
    ///
    /// This is what a PKINIT reply carries, byte for byte — **not** a `SubjectPublicKeyInfo`:
    /// RFC 5349 §2.2 puts the point in `KDCDHKeyInfo.subjectPublicKey`, and the curve is already
    /// known from the request. A client that found an SPKI there would fail to parse it.
    pub fn point(&self) -> &[u8] {
        &self.point
    }

    /// The shared secret with the client's point: the X coordinate, field-length octets.
    pub fn agree(&self, peer: &[u8]) -> Result<Vec<u8>, PkinitError> {
        let bad_peer =
            |what: &str| PkinitError::Malformed(format!("the client's EC point: {what}"));
        match &self.secret {
            Secret::P256(sk) => {
                let peer =
                    p256::PublicKey::from_sec1_bytes(peer).map_err(|_| bad_peer("not on P-256"))?;
                let z = p256::ecdh::diffie_hellman(sk.to_nonzero_scalar(), peer.as_affine());
                Ok(z.raw_secret_bytes().to_vec())
            }
            Secret::P384(sk) => {
                let peer =
                    p384::PublicKey::from_sec1_bytes(peer).map_err(|_| bad_peer("not on P-384"))?;
                let z = p384::ecdh::diffie_hellman(sk.to_nonzero_scalar(), peer.as_affine());
                Ok(z.raw_secret_bytes().to_vec())
            }
            Secret::P521(sk) => {
                let peer =
                    p521::PublicKey::from_sec1_bytes(peer).map_err(|_| bad_peer("not on P-521"))?;
                let z = p521::ecdh::diffie_hellman(sk.to_nonzero_scalar(), peer.as_affine());
                Ok(z.raw_secret_bytes().to_vec())
            }
        }
    }
}

/// Verifies an ECDSA signature over an already-computed digest.
///
/// `digest` is the hash, not the message: ECDSA signs a digest, and hashing here would verify a
/// hash of a hash, which fails for every input and reads like a wrong key. `signature` is the DER
/// `ECDSA-Sig-Value` (`SEQUENCE { r INTEGER, s INTEGER }`) that every CSR and certificate carries.
///
/// A point that is not on `curve` is a `false`, not an error: the caller is asking whether this
/// signature verifies under this key, and a key that is not a key does not verify anything.
pub fn verify(curve: Curve, point: &[u8], digest: &[u8], signature: &[u8]) -> bool {
    macro_rules! attempt {
        ($m:ident) => {{
            let Ok(key) = $m::ecdsa::VerifyingKey::from_sec1_bytes(point) else {
                return false;
            };
            let Ok(sig) = $m::ecdsa::DerSignature::from_bytes(signature) else {
                return false;
            };
            use $m::ecdsa::signature::hazmat::PrehashVerifier;
            key.verify_prehash(digest, &sig).is_ok()
        }};
    }
    match curve {
        Curve::P256 => attempt!(p256),
        Curve::P384 => attempt!(p384),
        Curve::P521 => attempt!(p521),
    }
}

/// `field_len` octets from `rng`, with P-521's top bits cleared.
///
/// A P-521 scalar is 521 bits, so the first octet has seven bits at most; the other two curves have
/// field sizes that are whole octets and need no trimming. Trimming here rather than inside the
/// curve crate keeps the rejection sampling from throwing away three quarters of the candidates.
fn scalar_bytes(curve: Curve, rng: &dyn Fn(usize) -> Vec<u8>) -> Result<Vec<u8>, PkinitError> {
    let mut bytes = rng(curve.field_len());
    if bytes.len() < curve.field_len() {
        return Err(PkinitError::Malformed(format!(
            "the entropy source returned {} octets for a {} field",
            bytes.len(),
            curve.field_len()
        )));
    }
    bytes.truncate(curve.field_len());
    if curve == Curve::P521 {
        bytes[0] &= 0x01;
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// OID content octets, so a test can name a curve without a parser for the text form.
    fn oid_bytes(text: &str) -> Vec<u8> {
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

    /// Deterministic bytes: the exchange is reproducible, and the generator is stateful because
    /// rejection sampling calls it more than once.
    fn rng() -> impl Fn(usize) -> Vec<u8> {
        let state = std::cell::Cell::new(0x1234_5678u32);
        move |len| {
            (0..len)
                .map(|_| {
                    let mut x = state.get();
                    x ^= x << 13;
                    x ^= x >> 17;
                    x ^= x << 5;
                    state.set(x);
                    (x >> 24) as u8
                })
                .collect()
        }
    }

    /// Both sides compute the same secret, on every curve — which is the whole point, and the one
    /// property a hand-written ECDH can get wrong while every test still passes.
    #[test]
    fn both_sides_agree_on_every_curve() {
        for curve in [Curve::P256, Curve::P384, Curve::P521] {
            let kdc = KeyPair::generate(curve, &rng()).expect("a kdc pair");
            let client = KeyPair::generate(curve, &rng()).expect("a client pair");
            let a = kdc.agree(client.point()).expect("the kdc agrees");
            let b = client.agree(kdc.point()).expect("the client agrees");
            assert_eq!(a, b, "{curve:?}: the two halves of the exchange disagree");
            assert_eq!(
                a.len(),
                curve.field_len(),
                "{curve:?}: the secret is one field element"
            );
            // A secret of zeros would be a broken curve, not a valid exchange.
            assert!(a.iter().any(|b| *b != 0), "{curve:?}: an all-zero secret");
        }
    }

    /// The point a reply carries is SEC1 uncompressed on the named curve: `04` and two coordinates.
    #[test]
    fn the_point_is_sec1_uncompressed() {
        for curve in [Curve::P256, Curve::P384, Curve::P521] {
            let pair = KeyPair::generate(curve, &rng()).expect("a pair");
            let point = pair.point();
            assert_eq!(point[0], 0x04, "{curve:?}: not the uncompressed form");
            assert_eq!(
                point.len(),
                1 + 2 * curve.field_len(),
                "{curve:?}: not two coordinates of the field width"
            );
            // And it is a point the peer accepts, on the same curve.
            let peer = KeyPair::generate(curve, &rng()).expect("a peer");
            assert!(
                peer.agree(point).is_ok(),
                "{curve:?}: the point is not on the curve"
            );
        }
    }

    /// A point from another curve is refused rather than coerced: the shared secret would be
    /// computed from a value the client never sent.
    #[test]
    fn a_point_from_another_curve_is_refused() {
        let p256 = KeyPair::generate(Curve::P256, &rng()).expect("a pair");
        let p384 = KeyPair::generate(Curve::P384, &rng()).expect("a pair");
        assert!(
            p256.agree(p384.point()).is_err(),
            "a P-384 point must not be agreed on P-256"
        );
        // And a value that is not a point at all.
        assert!(p256.agree(&[0x04; 65]).is_err(), "garbage is not a point");
    }

    /// A signature over a digest verifies, and a different digest does not — the property the CSR
    /// possession check rests on, on every curve.
    #[test]
    fn a_signature_verifies_over_the_digest_it_covers() {
        for curve in [Curve::P256, Curve::P384, Curve::P521] {
            let pair = KeyPair::generate(curve, &rng()).expect("a pair");
            let digest = [
                0x11u8, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
                0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
                0xcc, 0xdd, 0xee, 0xff, 0x00,
            ];
            let sig: Vec<u8> = match &pair.secret {
                Secret::P256(sk) => {
                    use p256::ecdsa::signature::hazmat::PrehashSigner as _;
                    let signing =
                        p256::ecdsa::SigningKey::from_slice(&sk.to_bytes()).expect("a key");
                    let s: p256::ecdsa::DerSignature =
                        signing.sign_prehash(&digest).expect("signs");
                    s.as_bytes().to_vec()
                }
                Secret::P384(sk) => {
                    use p384::ecdsa::signature::hazmat::PrehashSigner as _;
                    let signing =
                        p384::ecdsa::SigningKey::from_slice(&sk.to_bytes()).expect("a key");
                    let s: p384::ecdsa::DerSignature =
                        signing.sign_prehash(&digest).expect("signs");
                    s.as_bytes().to_vec()
                }
                Secret::P521(sk) => {
                    use p521::ecdsa::signature::hazmat::PrehashSigner as _;
                    let signing =
                        p521::ecdsa::SigningKey::from_slice(&sk.to_bytes()).expect("a key");
                    let s: p521::ecdsa::DerSignature =
                        signing.sign_prehash(&digest).expect("signs");
                    s.as_bytes().to_vec()
                }
            };
            assert!(
                verify(curve, pair.point(), &digest, &sig),
                "{curve:?}: a signature over this digest must verify"
            );
            let mut other = digest;
            other[0] ^= 0xff;
            assert!(
                !verify(curve, pair.point(), &other, &sig),
                "{curve:?}: a signature must not verify over another digest"
            );
            // And a point from another curve does not verify anything.
            let elsewhere = KeyPair::generate(Curve::P256, &rng()).expect("a pair");
            if curve != Curve::P256 {
                assert!(!verify(Curve::P256, pair.point(), &digest, &sig));
                assert!(!verify(curve, elsewhere.point(), &digest, &sig));
            }
        }
    }

    /// `namedCurve` is what a client sends; an explicitly parameterised curve is refused, because
    /// accepting one means validating parameters whose bad case is a curve with a known log.
    #[test]
    fn a_named_curve_is_read_and_anything_else_is_refused() {
        let named = der::tlv(der::OBJECT_IDENTIFIER, &oid_bytes(Curve::P384.oid()));
        assert_eq!(Curve::from_params(Some(&named)).unwrap(), Curve::P384);

        // An OID that is not one of the three.
        let other = der::tlv(der::OBJECT_IDENTIFIER, &oid_bytes("1.2.840.10045.3.1.1"));
        let err = Curve::from_params(Some(&other)).unwrap_err();
        assert!(matches!(err, PkinitError::Unsupported(_)), "got {err:?}");

        // No parameters at all.
        assert!(matches!(
            Curve::from_params(None).unwrap_err(),
            PkinitError::Malformed(_)
        ));
    }
}
