//! The SPAKE groups (RFC 9588 §12.2) and the arithmetic the exchange does in them.
//!
//! Four groups, registry ids 1 to 4: edwards25519 and the three NIST curves. Everything
//! group-specific lives here — the mask constants, how a multiplier octet string becomes a scalar,
//! how a point is serialized, and which hash the transcript uses — so that `super` is written once
//! over [`Group`] and changing the group is a matter of selecting a different value.
//!
//! # Why the arithmetic is not ours
//!
//! The constants, the serialization choices and the lengths are transcribed from the registry and
//! pinned by tests. The curve arithmetic is `curve25519-dalek` and the `p*` crates, for the reason
//! `super` gives: field and group arithmetic written by hand fails subtly rather than loudly, and
//! this crate's own-bytes principle is about the RFC 3961 profiles, not about elliptic curves.
//!
//! # Why the NIST code mirrors the client's
//!
//! `rrl-krb5`'s `client::spake::nist` is the other half of this exchange and runs against the same
//! three crates. The reduction rule below is that module's — Horner's rule in the scalar field — and
//! not the crates' own `Reduce`, which subtracts the order once and is therefore too little for
//! P-521's multiplier. Two sides that reduced the same octets differently would compute different
//! keys, and the failure would arrive as "the password is wrong".
//!
//! # The other differences that matter
//!
//! * **Cofactor.** edwards25519 has cofactor 8 and RFC 9588 §10.1 requires clearing it; the NIST
//!   curves have cofactor 1, so the step does not exist there.
//! * **Hash length.** The transcript hash is the group's own — SHA-256, SHA-384, SHA-512 — and its
//!   length reaches `K'[n]`, so a wrong choice is a different key rather than a formatting error.
//! * **Multiplier length.** The registry's 32 or 48 octets are the *input* length, not the scalar
//!   width: P-521 takes 48 octets and reduces them into a 66-octet scalar.

use p256::elliptic_curve::PrimeField as _;
use p256::elliptic_curve::sec1::{FromSec1Point as _, ToSec1Point as _};

use super::Mask;
use crate::crypto::{Cipher, Enctype};
use crate::error::{Error, Result};

/// Registry id of edwards25519 (RFC 9588 §12.2.2.1).
pub const EDWARDS25519: i32 = 1;
/// Registry id of P-256 (§12.2.2.2).
pub const P256: i32 = 2;
/// Registry id of P-384 (§12.2.2.3).
pub const P384: i32 = 3;
/// Registry id of P-521 (§12.2.2.4).
pub const P521: i32 = 4;

/// The groups this crate implements, in the order RFC 9588 registers them.
pub const ALL: [i32; 4] = [EDWARDS25519, P256, P384, P521];

/// The registry name of `id`, for a log line or an error.
pub fn name(id: i32) -> Option<&'static str> {
    match id {
        EDWARDS25519 => Some("edwards25519"),
        P256 => Some("P-256"),
        P384 => Some("P-384"),
        P521 => Some("P-521"),
        _ => None,
    }
}

/// The group `id` names, or `None` for a group this crate does not implement.
///
/// `None` rather than a refusal with a code: a client offering a group the KDC does not have is
/// answered by choosing another from its list, and an unregistered id is a different thing from one
/// this build omits.
pub fn by_id(id: i32) -> Option<Box<dyn Group>> {
    match id {
        EDWARDS25519 => Some(Box::new(Ed25519)),
        P256 => Some(Box::new(Nist(Curve::P256))),
        P384 => Some(Box::new(Nist(Curve::P384))),
        P521 => Some(Box::new(Nist(Curve::P521))),
        _ => None,
    }
}

/// The choice a KDC makes when it answers a client's group list.
///
/// The client's order, first we implement — RFC 9588 §4.2 has the client list its preferences and
/// the KDC pick from them, and a KDC imposing its own order picks a group the client ranked last,
/// for a reason of its own. `None` when nothing in the list is ours.
pub fn first_supported(groups: &[i32]) -> Option<i32> {
    groups.iter().copied().find(|id| by_id(*id).is_some())
}

/// One SPAKE group.
///
/// Every method that touches a secret takes and returns octets: a curve crate's scalar type is not
/// nameable across four curves, and a trait with an associated type would push that type into
/// `super` for no gain. Keeping the secret as octets means the reduction rules stay inside the
/// implementation that knows them, which is where RFC 9588 puts them.
pub(crate) trait Group {
    /// The registry id.
    fn id(&self) -> i32;

    /// The length of the multiplier octet string, from the registry: 32 or 48, **not** the scalar
    /// size.
    fn multiplier_len(&self) -> usize;

    /// `w` as a scalar, from the octets `PRF+` produced: the integer they denote, reduced modulo
    /// the group order (SEC1 §2.3.8, RFC 8032 §3.1).
    fn multiplier(&self, w: &[u8]) -> Result<Vec<u8>>;

    /// A random secret scalar, uniformly in `[0, n)`.
    fn random_multiplier(&self, cipher: &dyn Cipher) -> Result<Vec<u8>>;

    /// `x·G + w·M`, serialized — the value a party sends as its public key.
    fn public_value(&self, private: &[u8], w: &[u8], mask: Mask) -> Result<Vec<u8>>;

    /// `x·(peer − w·N)`, serialized — the shared value both sides end up with.
    fn shared_value(&self, private: &[u8], w: &[u8], peer: &[u8], mask: Mask) -> Result<Vec<u8>>;

    /// The transcript hash over the concatenation of `parts`.
    fn hash(&self, parts: &[&[u8]]) -> Vec<u8>;
}

/// The serialized mask constant `mask`.
fn mask_bytes(mask: Mask, m: &'static [u8], n: &'static [u8]) -> &'static [u8] {
    match mask {
        Mask::M => m,
        Mask::N => n,
    }
}

// --------------------------------------------------------------------------------------------
// edwards25519: cofactor 8, SHA-256, 32-octet multiplier, compressed Edwards points.
// --------------------------------------------------------------------------------------------

/// The registry's M, compressed (RFC 9588 §12.2.2.1).
const ED_M: &[u8] = &[
    0xd0, 0x48, 0x03, 0x2c, 0x6e, 0xa0, 0xb6, 0xd6, 0x97, 0xdd, 0xc2, 0xe8, 0x6b, 0xda, 0x85, 0xa3,
    0x3a, 0xda, 0xc9, 0x20, 0xf1, 0xbf, 0x18, 0xe1, 0xb0, 0xc6, 0xd1, 0x66, 0xa5, 0xce, 0xcd, 0xaf,
];
/// The registry's N, compressed.
const ED_N: &[u8] = &[
    0xd3, 0xbf, 0xb5, 0x18, 0xf4, 0x4f, 0x34, 0x30, 0xf2, 0x9d, 0x0c, 0x92, 0xaf, 0x50, 0x38, 0x65,
    0xa1, 0xed, 0x32, 0x81, 0xdc, 0x69, 0xb3, 0x5d, 0xd8, 0x68, 0xba, 0x85, 0xf8, 0x86, 0xc4, 0xab,
];

fn array32(bytes: &[u8], what: &str) -> Result<[u8; 32]> {
    bytes
        .try_into()
        .map_err(|_| Error::Protocol(format!("an edwards25519 {what} is 32 octets")))
}

/// A compressed Edwards point, refused when it is not on the curve.
///
/// A value off the curve is what an invalid-curve attack is made of (RFC 9588 §10.1), so it is
/// refused here rather than fed to the arithmetic.
fn ed_point(bytes: &[u8]) -> Result<curve25519_dalek::edwards::EdwardsPoint> {
    curve25519_dalek::edwards::CompressedEdwardsY(array32(bytes, "point")?)
        .decompress()
        .ok_or_else(|| Error::Protocol("a SPAKE public value is not a curve point".into()))
}

fn ed_scalar(bytes: &[u8]) -> Result<curve25519_dalek::scalar::Scalar> {
    Ok(curve25519_dalek::scalar::Scalar::from_bytes_mod_order(
        array32(bytes, "scalar")?,
    ))
}

/// edwards25519 (RFC 9588 §12.2.2.1).
#[derive(Debug, Clone, Copy)]
pub(crate) struct Ed25519;

impl Group for Ed25519 {
    fn id(&self) -> i32 {
        EDWARDS25519
    }

    fn multiplier_len(&self) -> usize {
        32
    }

    fn multiplier(&self, w: &[u8]) -> Result<Vec<u8>> {
        Ok(ed_scalar(w)?.to_bytes().to_vec())
    }

    fn random_multiplier(&self, cipher: &dyn Cipher) -> Result<Vec<u8>> {
        let bytes = cipher.random(Enctype::Aes256Sha1)?;
        Ok(
            curve25519_dalek::scalar::Scalar::from_bytes_mod_order(array32(bytes.bytes(), "seed")?)
                .to_bytes()
                .to_vec(),
        )
    }

    fn public_value(&self, private: &[u8], w: &[u8], mask: Mask) -> Result<Vec<u8>> {
        use curve25519_dalek::edwards::EdwardsPoint;
        // The cofactor is applied to the point, not to the scalar: a `Scalar` is a value modulo the
        // group order, so multiplying one by eight reduces again — and the order is odd, so the
        // product would no longer be a multiple of eight in integer terms, which is exactly the
        // property §10.1 wants. Scaling the point gives `8r·G` with no reduction anywhere.
        let masked = ed_point(mask_bytes(mask, ED_M, ED_N))? * ed_scalar(w)?;
        Ok(
            (EdwardsPoint::mul_base(&ed_scalar(private)?).mul_by_cofactor() + masked)
                .compress()
                .to_bytes()
                .to_vec(),
        )
    }

    fn shared_value(&self, private: &[u8], w: &[u8], peer: &[u8], mask: Mask) -> Result<Vec<u8>> {
        let unmasked = ed_point(peer)? - ed_point(mask_bytes(mask, ED_M, ED_N))? * ed_scalar(w)?;
        Ok((unmasked * ed_scalar(private)?)
            .mul_by_cofactor()
            .compress()
            .to_bytes()
            .to_vec())
    }

    fn hash(&self, parts: &[&[u8]]) -> Vec<u8> {
        use sha2::Digest;
        let mut d = sha2::Sha256::new();
        for part in parts {
            d.update(part);
        }
        d.finalize().to_vec()
    }
}

// --------------------------------------------------------------------------------------------
// The NIST curves: cofactor 1, SEC1-compressed points, their own hash.
// --------------------------------------------------------------------------------------------

/// Which NIST curve, so that one implementation covers all three.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Curve {
    P256,
    P384,
    P521,
}

/// `bytes` (big-endian, any length) mod the group order, in constant time: Horner's rule in the
/// scalar field.
///
/// The curve crates' own `Reduce` subtracts the order once, which is too little for P-521's 48-octet
/// multiplier against a 66-octet order. `rrl-krb5`'s client reduces exactly this way, and two sides
/// that reduced differently would derive different keys and report it as a wrong password.
macro_rules! reduce {
    ($m:ident, $bytes:expr) => {{
        let b256 = $m::Scalar::from(256u64);
        $bytes.iter().fold($m::Scalar::ZERO, |acc, &b| {
            acc * b256 + $m::Scalar::from(u64::from(b))
        })
    }};
}

/// Picks the crate for the curve, so one body covers all three.
macro_rules! per_curve {
    ($which:expr, $m:ident => $body:expr) => {
        match $which {
            Curve::P256 => {
                use p256 as $m;
                $body
            }
            Curve::P384 => {
                use p384 as $m;
                $body
            }
            Curve::P521 => {
                use p521 as $m;
                $body
            }
        }
    };
}

/// The registry's constants, transcribed (§12.2.2.2-§12.2.2.4) and pinned by the tests.
const P256_M: &[u8] = &[
    0x02, 0x88, 0x6e, 0x2f, 0x97, 0xac, 0xe4, 0x6e, 0x55, 0xba, 0x9d, 0xd7, 0x24, 0x25, 0x79, 0xf2,
    0x99, 0x3b, 0x64, 0xe1, 0x6e, 0xf3, 0xdc, 0xab, 0x95, 0xaf, 0xd4, 0x97, 0x33, 0x3d, 0x8f, 0xa1,
    0x2f,
];
const P256_N: &[u8] = &[
    0x03, 0xd8, 0xbb, 0xd6, 0xc6, 0x39, 0xc6, 0x29, 0x37, 0xb0, 0x4d, 0x99, 0x7f, 0x38, 0xc3, 0x77,
    0x07, 0x19, 0xc6, 0x29, 0xd7, 0x01, 0x4d, 0x49, 0xa2, 0x4b, 0x4f, 0x98, 0xba, 0xa1, 0x29, 0x2b,
    0x49,
];
const P384_M: &[u8] = &[
    0x03, 0x0f, 0xf0, 0x89, 0x5a, 0xe5, 0xeb, 0xf6, 0x18, 0x70, 0x80, 0xa8, 0x2d, 0x82, 0xb4, 0x2e,
    0x27, 0x65, 0xe3, 0xb2, 0xf8, 0x74, 0x9c, 0x7e, 0x05, 0xeb, 0xa3, 0x66, 0x43, 0x4b, 0x36, 0x3d,
    0x3d, 0xc3, 0x6f, 0x15, 0x31, 0x47, 0x39, 0x07, 0x4d, 0x2e, 0xb8, 0x61, 0x3f, 0xce, 0xec, 0x28,
    0x53,
];
const P384_N: &[u8] = &[
    0x02, 0xc7, 0x2c, 0xf2, 0xe3, 0x90, 0x85, 0x3a, 0x1c, 0x1c, 0x4a, 0xd8, 0x16, 0xa6, 0x2f, 0xd1,
    0x58, 0x24, 0xf5, 0x60, 0x78, 0x91, 0x8f, 0x43, 0xf9, 0x22, 0xca, 0x21, 0x51, 0x8f, 0x9c, 0x54,
    0x3b, 0xb2, 0x52, 0xc5, 0x49, 0x02, 0x14, 0xcf, 0x9a, 0xa3, 0xf0, 0xba, 0xab, 0x4b, 0x66, 0x5c,
    0x10,
];
const P521_M: &[u8] = &[
    0x02, 0x00, 0x3f, 0x06, 0xf3, 0x81, 0x31, 0xb2, 0xba, 0x26, 0x00, 0x79, 0x1e, 0x82, 0x48, 0x8e,
    0x8d, 0x20, 0xab, 0x88, 0x9a, 0xf7, 0x53, 0xa4, 0x18, 0x06, 0xc5, 0xdb, 0x18, 0xd3, 0x7d, 0x85,
    0x60, 0x8c, 0xfa, 0xe0, 0x6b, 0x82, 0xe4, 0xa7, 0x2c, 0xd7, 0x44, 0xc7, 0x19, 0x19, 0x35, 0x62,
    0xa6, 0x53, 0xea, 0x1f, 0x11, 0x9e, 0xef, 0x93, 0x56, 0x90, 0x7e, 0xdc, 0x9b, 0x56, 0x97, 0x99,
    0x62, 0xd7, 0xaa,
];
const P521_N: &[u8] = &[
    0x02, 0x00, 0xc7, 0x92, 0x4b, 0x9e, 0xc0, 0x17, 0xf3, 0x09, 0x45, 0x62, 0x89, 0x43, 0x36, 0xa5,
    0x3c, 0x50, 0x16, 0x7b, 0xa8, 0xc5, 0x96, 0x38, 0x76, 0x88, 0x05, 0x42, 0xbc, 0x66, 0x9e, 0x49,
    0x4b, 0x25, 0x32, 0xd7, 0x6c, 0x5b, 0x53, 0xdf, 0xb3, 0x49, 0xfd, 0xf6, 0x91, 0x54, 0xb9, 0xe0,
    0x04, 0x8c, 0x58, 0xa4, 0x2e, 0x8e, 0xd0, 0x4c, 0xef, 0x05, 0x2a, 0x3b, 0xc3, 0x49, 0xd9, 0x55,
    0x75, 0xcd, 0x25,
];

/// A NIST curve (RFC 9588 §12.2.2.2-§12.2.2.4).
#[derive(Debug, Clone, Copy)]
pub(crate) struct Nist(Curve);

impl Nist {
    fn id_of(self) -> i32 {
        match self.0 {
            Curve::P256 => P256,
            Curve::P384 => P384,
            Curve::P521 => P521,
        }
    }

    fn label(self) -> &'static str {
        name(self.id_of()).expect("every Curve has a name")
    }

    fn constants(self) -> (&'static [u8], &'static [u8]) {
        match self.0 {
            Curve::P256 => (P256_M, P256_N),
            Curve::P384 => (P384_M, P384_N),
            Curve::P521 => (P521_M, P521_N),
        }
    }
}

impl Group for Nist {
    fn id(&self) -> i32 {
        self.id_of()
    }

    fn multiplier_len(&self) -> usize {
        // edwards25519 and P-256 take 32; P-384 and P-521 take 48. The registry is explicit, and
        // P-521's 48 is shorter than its 66-octet scalar.
        match self.0 {
            Curve::P256 => 32,
            Curve::P384 | Curve::P521 => 48,
        }
    }

    fn multiplier(&self, w: &[u8]) -> Result<Vec<u8>> {
        let len = self.multiplier_len();
        if w.len() != len {
            return Err(Error::Protocol(format!(
                "a {} SPAKE multiplier is {len} octets, this one is {}",
                self.label(),
                w.len()
            )));
        }
        let curve = self.0;
        per_curve!(curve, m => Ok(reduce!(m, w).to_bytes().to_vec()))
    }

    fn random_multiplier(&self, cipher: &dyn Cipher) -> Result<Vec<u8>> {
        let curve = self.0;
        let label = self.label();
        per_curve!(curve, m => {
            // Uniform in `[0, n)` by rejection, as OpenSSL's `BN_rand_range` and the client both do:
            // an unconditional reduction would favour the low values, which is what §10.2 warns
            // about. P-521's top octet is masked so the draw is under the field width rather than
            // uniformly rejected.
            for _ in 0..64 {
                let mut repr = m::FieldBytes::default();
                let mut filled = 0;
                while filled < repr.len() {
                    let bytes = cipher.random(Enctype::Aes256Sha1)?.bytes().to_vec();
                    let take = (repr.len() - filled).min(bytes.len());
                    repr[filled..filled + take].copy_from_slice(&bytes[..take]);
                    filled += take;
                }
                if curve == Curve::P521 {
                    repr[0] &= 0x01;
                }
                if bool::from(m::Scalar::from_repr(repr).is_some()) {
                    return Ok(repr.to_vec());
                }
            }
            Err(Error::Protocol(format!(
                "no random value below the {label} group order in 64 draws: the RNG is broken"
            )))
        })
    }

    fn public_value(&self, private: &[u8], w: &[u8], mask: Mask) -> Result<Vec<u8>> {
        let curve = self.0;
        let (mc, nc) = self.constants();
        let label = self.label();
        per_curve!(curve, m => {
            let x = reduce!(m, private);
            let w = reduce!(m, w);
            let c = m::AffinePoint::from_sec1_bytes(mask_bytes(mask, mc, nc))
                .map_err(|_| Error::Protocol(format!("{label}: a mask constant is not a point")))?;
            // No cofactor: the NIST curves have cofactor 1, so the scalar is applied as it is.
            let p = m::ProjectivePoint::GENERATOR * x + m::ProjectivePoint::from(c) * w;
            Ok(p.to_affine().to_sec1_point(true).as_bytes().to_vec())
        })
    }

    fn shared_value(&self, private: &[u8], w: &[u8], peer: &[u8], mask: Mask) -> Result<Vec<u8>> {
        let curve = self.0;
        let (mc, nc) = self.constants();
        let label = self.label();
        per_curve!(curve, m => {
            let q = m::AffinePoint::from_sec1_bytes(peer).map_err(|_| {
                Error::Protocol(format!(
                    "{label}: a SPAKE public value is not a point on this curve"
                ))
            })?;
            let x = reduce!(m, private);
            let w = reduce!(m, w);
            let c = m::AffinePoint::from_sec1_bytes(mask_bytes(mask, mc, nc))
                .map_err(|_| Error::Protocol(format!("{label}: a mask constant is not a point")))?;
            let k = (m::ProjectivePoint::from(q) - m::ProjectivePoint::from(c) * w) * x;
            let out = k.to_affine().to_sec1_point(true).as_bytes().to_vec();
            // A compressed point is one tag octet plus the coordinate; the identity has no
            // compressed form, so a different length means the peer steered the shared value there.
            if out.len() != m::FieldBytes::default().len() + 1 {
                // The identity has no compressed form; a peer that steered the shared value there
                // is doing something the RFC forbids, and returning an empty or short value would
                // make both sides derive a "key" from it.
                return Err(Error::Protocol(format!(
                    "{label}: the shared value is the point at infinity"
                )));
            }
            Ok(out)
        })
    }

    fn hash(&self, parts: &[&[u8]]) -> Vec<u8> {
        use sha2::Digest;
        match self.0 {
            Curve::P256 => {
                let mut d = sha2::Sha256::new();
                for part in parts {
                    d.update(part);
                }
                d.finalize().to_vec()
            }
            Curve::P384 => {
                let mut d = sha2::Sha384::new();
                for part in parts {
                    d.update(part);
                }
                d.finalize().to_vec()
            }
            Curve::P521 => {
                let mut d = sha2::Sha512::new();
                for part in parts {
                    d.update(part);
                }
                d.finalize().to_vec()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::OwnCipher;

    /// The registry's lengths, including the two a careless copy gets wrong: P-384's multiplier is
    /// 48, and P-521's is 48 while its hash is 64.
    #[test]
    fn the_registry_lengths_are_what_the_constants_say() {
        for (id, expected, multiplier, hash) in [
            (EDWARDS25519, "edwards25519", 32, 32),
            (P256, "P-256", 32, 32),
            (P384, "P-384", 48, 48),
            (P521, "P-521", 48, 64),
        ] {
            assert_eq!(name(id), Some(expected));
            let group = by_id(id).expect("implemented");
            assert_eq!(group.id(), id);
            assert_eq!(group.multiplier_len(), multiplier, "{expected} multiplier");
            assert_eq!(
                group.hash(&[b"a", b"b"]).len(),
                hash,
                "{expected} transcript hash length"
            );
        }
        assert_eq!(name(5), None, "an unregistered id has no name");
        assert!(by_id(5).is_none(), "and no group");
    }

    /// The mask constants decode as points on their own curves: the one property a transcribed hex
    /// must have, and the one a typo breaks.
    #[test]
    fn every_mask_constant_is_a_point_on_its_curve() {
        for id in ALL {
            let group = by_id(id).expect("implemented");
            let w = vec![7u8; group.multiplier_len()];
            for mask in [Mask::M, Mask::N] {
                let x = group.random_multiplier(&OwnCipher).expect("a scalar");
                group
                    .public_value(&x, &w, mask)
                    .unwrap_or_else(|e| panic!("{} {mask:?}: {e}", name(id).unwrap()));
            }
        }
    }

    /// Both sides compute the same shared value in every group — the property the exchange rests on.
    ///
    /// A self-round-trip proves the two sides agree with each other, not with the RFC. The RFC's
    /// values are pinned by `the_published_vectors_reproduce` in `super` (edwards25519) and by the
    /// mask constants above, each of which only decodes if it is the registered point on the
    /// registered curve; what is left is the arithmetic between them, which is what this checks.
    #[test]
    fn both_sides_compute_the_same_shared_value_in_every_group() {
        for id in ALL {
            let group = by_id(id).expect("implemented");
            let label = name(id).unwrap();
            let w = vec![0x5au8; group.multiplier_len()];
            let x = group.random_multiplier(&OwnCipher).expect("a scalar");
            let y = group.random_multiplier(&OwnCipher).expect("a scalar");

            // The two masks are not interchangeable: the KDC masks with M and the client with N,
            // and each side unmasks with the other's. Using M on both sides makes the two halves
            // agree with themselves and disagree with each other — which is exactly what this
            // assertion caught when it was written that way.
            let kdc_public = group.public_value(&x, &w, Mask::M).expect("T");
            let client_public = group.public_value(&y, &w, Mask::N).expect("S");
            let kdc_shared = group
                .shared_value(&x, &w, &client_public, Mask::N)
                .expect("K");
            let client_shared = group.shared_value(&y, &w, &kdc_public, Mask::M).expect("K");
            assert_eq!(kdc_shared, client_shared, "{label}: the two sides agree");
        }
    }

    /// A value that is not a point on the curve is refused rather than fed to the arithmetic: that
    /// is what an invalid-curve attack is made of (RFC 9588 §10.1).
    #[test]
    fn a_public_value_that_is_not_a_point_is_refused() {
        for id in ALL {
            let group = by_id(id).expect("implemented");
            let label = name(id).unwrap();
            let w = vec![1u8; group.multiplier_len()];
            let x = group.random_multiplier(&OwnCipher).unwrap();
            let len = group.public_value(&x, &w, Mask::M).unwrap().len();
            // Not every value is off the curve — on edwards25519 most are *on* it, all-bits-set
            // included — so the two cases name a value known to be bad rather than assuming any
            // wrong-looking octets will do. For edwards25519 it is `0x02` repeated, which has no
            // square root for its y; for the NIST curves the first octet is the SEC1 tag, and
            // `0x00` is not one.
            let bogus = match id {
                EDWARDS25519 => vec![0x02u8; len],
                _ => {
                    let mut b = vec![0xffu8; len];
                    b[0] = 0x00;
                    b
                }
            };
            assert!(
                group.shared_value(&x, &w, &bogus, Mask::N).is_err(),
                "{label}: an off-curve value must be refused"
            );
        }
    }

    /// A multiplier of the wrong length is refused by name rather than padded silently.
    #[test]
    fn a_multiplier_of_the_wrong_length_is_refused() {
        for id in ALL {
            let group = by_id(id).expect("implemented");
            let short = vec![0u8; group.multiplier_len() - 1];
            let err = group
                .multiplier(&short)
                .expect_err("a short multiplier is refused")
                .to_string();
            assert!(
                err.contains(name(id).unwrap()),
                "the message names the group: {err}"
            );
        }
    }

    /// A KDC picks from the client's list in the client's order, and skips what it does not have.
    #[test]
    fn selection_follows_the_clients_order() {
        assert_eq!(first_supported(&[P521, EDWARDS25519]), Some(P521));
        assert_eq!(first_supported(&[99, P384]), Some(P384));
        assert_eq!(first_supported(&[99, 100]), None, "nothing in common");
        assert_eq!(first_supported(&[]), None);
    }
}
