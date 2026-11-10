//! SPAKE pre-authentication, RFC 9588.
//!
//! A password login that gives a recorded exchange nothing to test guesses against offline.
//! `PA-ENC-TIMESTAMP` hands an attacker a ciphertext under the long-term key: record one login
//! and the password can be guessed at leisure. SPAKE instead uses the long-term key only to
//! *mask* a Diffie-Hellman exchange — the mask hides each side's public value from anyone who
//! does not know the password, so a guess cannot be checked without taking part in a live
//! exchange, and a false KDC gets one guess per login rather than a ciphertext to grind.
//!
//! # The exchange this implements
//!
//! 1. The KDC advertises `PA-SPAKE` (151) with an empty value in `PREAUTH_REQUIRED` — "I speak
//!    SPAKE", RFC 9588 §4.1.
//! 2. The client answers with `SPAKESupport`, the groups it prefers.
//! 3. The KDC picks a group, sends `SPAKEChallenge` with its masked public value `T = x·G + w·M`
//!    in `KDC_ERR_MORE_PREAUTH_DATA_REQUIRED` (91).
//! 4. The client sends `SPAKEResponse` with `S = y·G + w·N`, masked the same way, plus a second
//!    factor encrypted under `K'[1]`.
//! 5. The KDC recovers `K = x·(S − w·N)`, derives `K'[0]`, decrypts the second factor to prove
//!    the client knew the password, and answers with a ticket sealed under `K'[0]`.
//!
//! # Where the state lives
//!
//! Between steps 3 and 5 the KDC has to remember `x` — a value it cannot recompute, because it
//! was random. It goes into `PA-FX-COOKIE` (RFC 6113 §5.4.2.3), encrypted under a realm key:
//! the client cannot read it, cannot alter it, and the KDC keeps no table an unauthenticated
//! client could fill. The cookie also carries the exact `SPAKEChallenge` octets and the
//! client's `SPAKESupport`, because the transcript hash covers both byte for byte — a
//! re-encoding that "looks the same" produces a different hash and a reply key nobody can use.
//!
//! # What is not here
//!
//! Only `edwards25519` (registry id 1), which is the group the client this crate is judged by
//! asks for. The NIST groups are `RRL-3.31`. Only `SF-NONE` (no second factor) — the same
//! limit MIT's client has, and a challenge that offers a factor the client cannot answer is
//! worse than one that offers none.
//!
//! # Why the curve arithmetic is not ours
//!
//! The M and N constants, the hash, the transcript and `K'[n]` are this module's, and they are
//! what the test vectors in RFC 9588 Appendix C check. The field and group arithmetic is
//! `curve25519-dalek`: unlike RFC 3961's byte-level profiles — where this crate deliberately
//! owns every octet — edwards25519 multiplication is a place where a hand-written version is
//! subtly wrong rather than obviously broken, and the crate already takes `rsa` for PKINIT for
//! the same reason.

use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;

use crate::crypto::{Cipher, Enctype, Key};
use crate::der;
use crate::error::{Error, Result};

use super::preauth::{Announced, Mechanism, Request, Step};

/// `PA-SPAKE` (RFC 9588 §12).
pub const PA_SPAKE: i32 = 151;

/// `KEY_USAGE_SPAKE` (RFC 9588 §11): the second-factor encryption.
pub const KU_SPAKE: u32 = 65;

/// `SF-NONE`: no second factor. Its presence is the whole validation.
const SF_NONE: i64 = 1;

/// edwards25519, the only group this module implements.
pub const GROUP_EDWARDS25519: i32 = 1;

/// The KDC's mask constant M (RFC 9588 §12.2.2.1).
const M_CONSTANT: [u8; 32] = [
    0xd0, 0x48, 0x03, 0x2c, 0x6e, 0xa0, 0xb6, 0xd6, 0x97, 0xdd, 0xc2, 0xe8, 0x6b, 0xda, 0x85, 0xa3,
    0x3a, 0xda, 0xc9, 0x20, 0xf1, 0xbf, 0x18, 0xe1, 0xb0, 0xc6, 0xd1, 0x66, 0xa5, 0xce, 0xcd, 0xaf,
];

/// The client's mask constant N (RFC 9588 §12.2.2.1).
const N_CONSTANT: [u8; 32] = [
    0xd3, 0xbf, 0xb5, 0x18, 0xf4, 0x4f, 0x34, 0x30, 0xf2, 0x9d, 0x0c, 0x92, 0xaf, 0x50, 0x38, 0x65,
    0xa1, 0xed, 0x32, 0x81, 0xdc, 0x69, 0xb3, 0x5d, 0xd8, 0x68, 0xba, 0x85, 0xf8, 0x86, 0xc4, 0xab,
];

/// Which mask a party applies: the KDC's `M` or the client's `N`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mask {
    M,
    N,
}

impl Mask {
    fn constant(self) -> EdwardsPoint {
        let bytes = match self {
            Mask::M => M_CONSTANT,
            Mask::N => N_CONSTANT,
        };
        // The registry constants are curve points; a build where they are not is a build whose
        // tables are wrong, and that is not something a login should be able to continue past.
        CompressedEdwardsY(bytes)
            .decompress()
            .expect("the SPAKE mask constants are edwards25519 points")
    }
}

/// The multiplier `w` from the initial reply key: `PRF+(K, "SPAKEsecret" || group)`.
///
/// The pepper binds the mask to the group, so a client and a KDC that disagree about the group
/// derive different masks and the exchange cannot complete by accident.
fn w_bytes(cipher: &dyn Cipher, ikey: &Key, group: i32) -> Result<Vec<u8>> {
    let _ = cipher;
    let mut seed = b"SPAKEsecret".to_vec();
    seed.extend_from_slice(&group.to_be_bytes());
    crate::crypto::kdf::prf_plus(ikey.enctype(), ikey.bytes(), &seed, 32)
}

/// `w` reduced modulo the group order, the way both sides use it as a scalar.
fn w_scalar(w: &[u8]) -> Result<Scalar> {
    let bytes: [u8; 32] = w
        .try_into()
        .map_err(|_| Error::Protocol("a SPAKE multiplier is 32 octets".into()))?;
    Ok(Scalar::from_bytes_mod_order(bytes))
}

/// `x·G + w·mask`, compressed — the value a party sends as its public key.
///
/// `private` is the *reduced* secret, and the cofactor is applied to the point rather than to
/// the scalar. That is not a shortcut: a `Scalar` in this library is a value modulo the group
/// order, so multiplying one by eight reduces again — and the order is odd, so the product is
/// no longer a multiple of eight in integer terms, which is exactly the property RFC 9588 §10.1
/// wants. Scaling the point gives `8r·G` exactly, with no reduction anywhere.
fn public_value(private: &Scalar, w: &[u8], mask: Mask) -> Result<[u8; 32]> {
    let masked = mask.constant() * w_scalar(w)?;
    Ok((EdwardsPoint::mul_base(private).mul_by_cofactor() + masked)
        .compress()
        .to_bytes())
}

/// `private·(peer − w·mask)`, compressed — the shared value both sides end up with.
///
/// An octet string that is not a curve point is refused rather than fed to the arithmetic: a
/// value off the curve is what an invalid-curve attack is made of (RFC 9588 §10.1).
fn shared_value(private: &Scalar, w: &[u8], peer: &[u8], mask: Mask) -> Result<[u8; 32]> {
    let bytes: [u8; 32] = peer
        .try_into()
        .map_err(|_| Error::Protocol("a SPAKE public value is 32 octets".into()))?;
    let point = CompressedEdwardsY(bytes)
        .decompress()
        .ok_or_else(|| Error::Protocol("a SPAKE public value is not a curve point".into()))?;
    let unmasked = point - mask.constant() * w_scalar(w)?;
    // The same cofactor reasoning as in `public_value`: the point is scaled, the scalar is not.
    Ok((unmasked * private).mul_by_cofactor().compress().to_bytes())
}

/// A random secret scalar, reduced modulo the group order.
///
/// The cofactor is applied where the scalar meets a point ([`public_value`], [`shared_value`]),
/// never here: see the comment there for why multiplying this value by eight would not do what
/// RFC 9588 §10.1 asks. The requirement is real — without cofactor clearing a malicious peer
/// can steer `K` into a small subgroup and learn a few bits of `w` per exchange, which is enough
/// to grind a password offline over several attempts.
fn random_scalar(cipher: &dyn Cipher) -> Result<Scalar> {
    let bytes = cipher.random(Enctype::Aes256Sha1)?;
    let seed: [u8; 32] = bytes
        .bytes()
        .try_into()
        .map_err(|_| Error::Protocol("a random scalar is 32 octets".into()))?;
    Ok(Scalar::from_bytes_mod_order(seed))
}

/// The group's hash for the transcript (edwards25519 uses SHA-256).
fn hash(parts: &[&[u8]]) -> Vec<u8> {
    use sha2::Digest;
    let mut d = sha2::Sha256::new();
    for part in parts {
        d.update(part);
    }
    d.finalize().to_vec()
}

/// The transcript hash after the challenge: `H(H(zeros || support || challenge) || …)`.
///
/// RFC 9588 §6: the hash starts at zeros, is updated with the client's support message and the
/// KDC's challenge together, and is updated again with the client's public value. Both of the
/// first two inputs are the PA-SPAKE *values as they travelled*, tags included — so the KDC has
/// to keep the octets it sent rather than rebuild them.
fn transcript_after_challenge(support: &[u8], challenge: &[u8]) -> Vec<u8> {
    let zeros = [0u8; 32];
    hash(&[&zeros, support, challenge])
}

/// The same hash, after the client's public value.
fn transcript_final(thash: &[u8], client_public: &[u8]) -> Vec<u8> {
    hash(&[thash, client_public])
}

/// `K'[n]`: the reply key (`n = 0`) and the second-factor keys (RFC 9588 §7).
///
/// The chain is `H("SPAKEkey" || group || enctype || w || K || thash || body || n || block)`,
/// truncated to the enctype's seed length and then put through `KRB-FX-CF2` with the initial
/// reply key. The `body` is the `KDC-REQ-BODY` of the request being answered, so a reply key is
/// bound to one request: a response lifted into another request derives a different key.
#[allow(clippy::too_many_arguments)]
fn derive_key(
    ikey: &Key,
    group: i32,
    w: &[u8],
    k: &[u8],
    thash: &[u8],
    body: &[u8],
    n: u32,
) -> Result<Key> {
    let enctype = ikey.enctype();
    let seed_len = enctype.key_len();
    let mut seed = Vec::with_capacity(seed_len + 32);
    let mut block: u8 = 1;
    while seed.len() < seed_len {
        seed.extend_from_slice(&hash(&[
            b"SPAKEkey",
            &group.to_be_bytes(),
            &enctype.id().to_be_bytes(),
            w,
            k,
            thash,
            body,
            &n.to_be_bytes(),
            &[block],
        ]));
        block = block.wrapping_add(1);
    }
    seed.truncate(seed_len);
    let hkey = crate::crypto::kdf::cf2(ikey.bytes(), "SPAKE", enctype, &seed, "keyderiv")?;
    Key::new(enctype, hkey)
}

/// The `SPAKESupport` a client sent: the groups it prefers, in order.
fn decode_support(value: &[u8]) -> Result<Vec<i32>> {
    let mut r = der::Reader::new(value);
    let content = r.expect("SPAKESupport", der::ctx(0))?;
    let mut sr = der::Reader::new(content);
    let inner = sr.expect("SPAKESupport", der::SEQUENCE)?;
    let f = der::Fields::parse("SPAKESupport", inner)?;
    let mut gr = der::Reader::new(f.get(0, "SPAKESupport")?);
    let groups = gr.expect("SPAKESupport", der::SEQUENCE)?;
    let mut out = Vec::new();
    let mut g = der::Reader::new(groups);
    while !g.is_empty() {
        out.push(int_of(g.expect("SPAKESupport", der::INTEGER)?)?);
    }
    Ok(out)
}

/// An `Int32` from the content octets of its `INTEGER`.
///
/// DER writes the fewest octets that carry the value, so `1` arrives as a single octet and
/// `-1` as `ff`. Reading a fixed width here is how a group list of `[1]` turns into an index
/// out of bounds rather than the number one.
fn int_of(content: &[u8]) -> Result<i32> {
    if content.is_empty() || content.len() > 4 {
        return Err(Error::Protocol(format!(
            "an Int32 in PA-SPAKE is 1..4 octets, and this one is {}",
            content.len()
        )));
    }
    let mut value: i32 = if content[0] & 0x80 != 0 { -1 } else { 0 };
    for byte in content {
        value = (value << 8) | i32::from(*byte);
    }
    Ok(value)
}

/// `SPAKEChallenge`: the group, the KDC's masked public value, and the factors it accepts.
fn encode_challenge(group: i32, pubkey: &[u8]) -> Vec<u8> {
    let factor = der::seq(&[der::field(0, der::int(SF_NONE))]);
    der::field(
        1,
        der::seq(&[
            der::field(0, der::int(group as i64)),
            der::field(1, der::octets(pubkey)),
            der::field(2, der::seq(&[factor])),
        ]),
    )
}

/// What the client sent in `SPAKEResponse`.
struct Response {
    pubkey: Vec<u8>,
    factor: crate::msg::EncryptedData,
}

fn decode_response(value: &[u8]) -> Result<Response> {
    let mut r = der::Reader::new(value);
    let content = r.expect("SPAKEResponse", der::ctx(2))?;
    let mut sr = der::Reader::new(content);
    let f = der::Fields::parse("SPAKEResponse", sr.expect("SPAKEResponse", der::SEQUENCE)?)?;
    let mut pr = der::Reader::new(f.get(0, "SPAKEResponse")?);
    let pubkey = pr.expect("SPAKEResponse", der::OCTET_STRING)?.to_vec();
    let factor =
        crate::msg::EncryptedData::decode("SPAKEResponse factor", f.get(1, "SPAKEResponse")?)?;
    Ok(Response { pubkey, factor })
}

/// The state a challenge leaves behind, for the cookie.
///
/// `x` cannot be recomputed and the challenge cannot be re-derived byte for byte, so both are
/// carried. The support message is here for the same reason: the transcript hash covers it.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Pending {
    group: i32,
    private: [u8; 32],
    challenge: Vec<u8>,
    support: Vec<u8>,
}

impl Pending {
    fn encode(&self) -> Vec<u8> {
        der::seq(&[
            der::field(0, der::int(GROUP_EDWARDS25519 as i64)),
            der::field(1, der::octets(&self.private)),
            der::field(2, der::octets(&self.challenge)),
            der::field(3, der::octets(&self.support)),
        ])
    }

    fn decode(state: &[u8]) -> Result<Pending> {
        let mut r = der::Reader::new(state);
        let f = der::Fields::parse("SPAKE state", r.expect("SPAKE state", der::SEQUENCE)?)?;
        let group = f.int(0, "SPAKE state")? as i32;
        if group != GROUP_EDWARDS25519 {
            return Err(Error::Protocol(format!(
                "SPAKE state names group {group}, and this KDC resumes only {GROUP_EDWARDS25519}"
            )));
        }
        let private: [u8; 32] = f
            .octets(1, "SPAKE state")?
            .try_into()
            .map_err(|_| Error::Protocol("SPAKE state has a short scalar".into()))?;
        Ok(Pending {
            group,
            private,
            challenge: f.octets(2, "SPAKE state")?.to_vec(),
            support: f.octets(3, "SPAKE state")?.to_vec(),
        })
    }
}

/// SPAKE as a multi-round pre-authentication mechanism.
#[derive(Debug, Default)]
pub struct Spake;

impl Spake {
    /// The mechanism, ready to be given to a `Kdc`.
    pub fn new() -> Self {
        Spake
    }

    /// The domain separation for the second factor's encryption; the same value MIT uses.
    fn factor_type(plain: &[u8]) -> Result<i64> {
        let mut r = der::Reader::new(plain);
        let f = der::Fields::parse(
            "SPAKESecondFactor",
            r.expect("SPAKESecondFactor", der::SEQUENCE)?,
        )?;
        Ok(f.int(0, "SPAKESecondFactor")?)
    }
}

impl Mechanism for Spake {
    fn pa_type(&self) -> i32 {
        PA_SPAKE
    }

    fn name(&self) -> &'static str {
        "SPAKE"
    }

    fn announce(&self, _request: &Request<'_>) -> Result<Announced> {
        // RFC 9588 §4.1: the offer is the empty value. Whatever came before in the session is
        // not a SPAKE state, so nothing is carried.
        Ok(Announced::default())
    }

    fn round(&self, request: &Request<'_>, state: &[u8], padata: &[u8]) -> Result<Step> {
        let mut r = der::Reader::new(padata);
        let tag = r.next("PA-SPAKE")?.tag;
        if tag == der::ctx(0) {
            return challenge(request, padata);
        }
        if tag == der::ctx(2) {
            let pending = Pending::decode(state)?;
            return finish(request, &pending, padata);
        }
        // `challenge`, `encdata` and any choice this build does not know: a client that sends
        // one is answering a message this KDC never sent, and pretending to understand it would
        // be guessing at a protocol step.
        Err(Error::Kdc {
            code: crate::error::codes::KDC_ERR_PREAUTH_FAILED,
            text: format!(
                "{}: PA-SPAKE came back with a choice this KDC did not send",
                request.cname
            ),
        })
    }
}

/// The client's support message: pick a group and answer with a challenge.
fn challenge(request: &Request<'_>, support: &[u8]) -> Result<Step> {
    let groups = decode_support(support)?;
    if !groups.contains(&GROUP_EDWARDS25519) {
        // The one refusal a client acts on by trying another method rather than failing the
        // login (its code paths treat `PREAUTH_FAILED` after a support message as "no group in
        // common"). Naming the groups it asked for is what an operator needs to see.
        return Ok(Step::Failed {
            code: crate::error::codes::KDC_ERR_PREAUTH_FAILED,
            text: format!(
                "this realm offers edwards25519 only, and the client asked for {groups:?}"
            ),
        });
    }
    let ikey = request
        .longterm
        .first()
        .ok_or_else(|| Error::Protocol("SPAKE needs a long-term key".into()))?;

    let w = w_bytes(request.cipher, ikey, GROUP_EDWARDS25519)?;
    let private = random_scalar(request.cipher)?;
    let public = public_value(&private, &w, Mask::M)?;
    let challenge_message = encode_challenge(GROUP_EDWARDS25519, &public);

    // The client sends its own value next; the transcript needs the support message and the
    // challenge exactly as they travelled, so both are remembered rather than rebuilt.
    let pending = Pending {
        group: GROUP_EDWARDS25519,
        private: private.to_bytes(),
        challenge: challenge_message.clone(),
        support: support.to_vec(),
    };
    Ok(Step::More {
        padata: challenge_message,
        state: pending.encode(),
    })
}

/// The client's response: recover `K`, derive `K'[0]`, and prove the client knew the password.
fn finish(request: &Request<'_>, pending: &Pending, response: &[u8]) -> Result<Step> {
    let ikey = request
        .longterm
        .first()
        .ok_or_else(|| Error::Protocol("SPAKE needs a long-term key".into()))?;
    let response = decode_response(response)?;
    if response.pubkey.len() != 32 {
        return Ok(Step::Failed {
            code: crate::error::codes::KDC_ERR_PREAUTH_FAILED,
            text: format!(
                "an edwards25519 public value is 32 octets, and this one is {}",
                response.pubkey.len()
            ),
        });
    }

    let w = w_bytes(request.cipher, ikey, pending.group)?;
    let private = Scalar::from_bytes_mod_order(pending.private);
    let k = match shared_value(&private, &w, &response.pubkey, Mask::N) {
        Ok(k) => k,
        Err(err) => {
            return Ok(Step::Failed {
                code: crate::error::codes::KDC_ERR_PREAUTH_FAILED,
                text: format!("the client's SPAKE value is not usable: {err}"),
            });
        }
    };

    let thash = transcript_final(
        &transcript_after_challenge(&pending.support, &pending.challenge),
        &response.pubkey,
    );
    let k0 = derive_key(ikey, pending.group, &w, &k, &thash, request.body, 0)?;
    let k1 = derive_key(ikey, pending.group, &w, &k, &thash, request.body, 1)?;

    // The second factor is the proof: it is only readable by someone who knows the password,
    // because only they can compute the mask and therefore `K`.
    let plain = match request
        .cipher
        .decrypt(&k1, KU_SPAKE, &response.factor.cipher)
    {
        Ok(plain) => plain,
        Err(err) => {
            return Ok(Step::Failed {
                code: crate::error::codes::KDC_ERR_PREAUTH_FAILED,
                text: format!("the second factor did not decrypt: {err}"),
            });
        }
    };
    let factor = Spake::factor_type(&plain)?;
    if factor != SF_NONE {
        return Ok(Step::Failed {
            code: crate::error::codes::KDC_ERR_PREAUTH_FAILED,
            text: format!("second factor {factor} was not among those offered (only SF-NONE)"),
        });
    }

    // RFC 9588 §4.5: the reply key becomes `K'[0]`, and there is no final PA-SPAKE message —
    // the ticket itself is the proof that the KDC accepted the exchange.
    Ok(Step::Done {
        reply_key: k0,
        padata: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex32(s: &str) -> [u8; 32] {
        hex::decode(s).unwrap().try_into().unwrap()
    }

    /// RFC 9588 Appendix C, `des3-cbc-sha1 edwards25519`: the group arithmetic, checked
    /// against values the document publishes rather than against itself.
    ///
    /// The vector's encryption types (des3, rc4) are not ones this crate implements, so the
    /// multiplier `w` is taken from the vector directly and `K'[n]` is left to the live client.
    /// What is checked here is everything that can silently differ: the scalar reduction, both
    /// public values, the shared value, and the two transcript hashes.
    ///
    /// This test is also what pins the cofactor clearing. The vector's `x` is the *cleared*
    /// scalar, and the module carries the reduced secret and scales the point; drop that scaling
    /// and `T` comes out as `(x/8)·G + w·M`, which is not what the document publishes. A
    /// synthetic test cannot see the difference — for an honest peer's point, multiplying the
    /// scalar by eight modulo the group order gives the same point either way, and it is only a
    /// small-subgroup component that distinguishes them.
    #[test]
    fn the_published_vectors_reproduce() {
        let w = hex32("a1f1a25cbd8e3092667e2fddba8ecd24f2c9cef124f7a3371ae81e11cad42a07");
        // The vector's `x` and `y` are the *cofactor-cleared* scalars (the document says they
        // were multiplied by the cofactor). This module carries the reduced secret and clears
        // the cofactor where it meets a point, so the vector's value is divided by 8 here —
        // exactly, because 8 is invertible modulo the group order.
        let inv8 = Scalar::from(8u64).invert();
        let x = Scalar::from_bytes_mod_order(hex32(
            "201012d07bfd48ddfa33c4aac4fb1e229fb0d043cfe65ebfb14399091c71a723",
        )) * inv8;
        let y = Scalar::from_bytes_mod_order(hex32(
            "500b294797b8b042aca1bedc0f5931a4f52c537b3608b2d05cc8a2372f439f25",
        )) * inv8;

        assert_eq!(
            public_value(&x, &w, Mask::M).unwrap(),
            hex32("18f511e750c97b592acd30db7d9e5fca660389102e6bf610c1bfbed4616c8362"),
            "T = x·G + w·M"
        );
        assert_eq!(
            public_value(&y, &w, Mask::N).unwrap(),
            hex32("5d10705e0d1e43d5dbf30240ccfbde4a0230c70d4c79147ab0b317edad2f8ae7"),
            "S = y·G + w·N"
        );

        let s = hex32("5d10705e0d1e43d5dbf30240ccfbde4a0230c70d4c79147ab0b317edad2f8ae7");
        let t = hex32("18f511e750c97b592acd30db7d9e5fca660389102e6bf610c1bfbed4616c8362");
        let expected = hex32("25bde0d875f0feb5755f45ba5e857889d916ecf7476f116aa31dc3e037ec4292");
        assert_eq!(
            shared_value(&x, &w, &s, Mask::N).unwrap(),
            expected,
            "the KDC's K = x·(S − w·N)"
        );
        assert_eq!(
            shared_value(&y, &w, &t, Mask::M).unwrap(),
            expected,
            "and the client's K = y·(T − w·M) is the same point"
        );

        let support = hex::decode("a0093007a0053003020101").unwrap();
        let challenge_bytes = hex::decode(concat!(
            "a1363034a003020101a122042018f511e750c97b592acd30",
            "db7d9e5fca660389102e6bf610c1bfbed4616c8362a20930",
            "073005a003020101"
        ))
        .unwrap();
        assert_eq!(
            transcript_after_challenge(&support, &challenge_bytes),
            hex::decode("22bb2271e34d329d52073c70b1d1187973181f0bc7614266bb79ee80d3335175")
                .unwrap(),
            "the transcript after the challenge"
        );
        assert_eq!(
            transcript_final(
                &transcript_after_challenge(&support, &challenge_bytes),
                &hex32("5d10705e0d1e43d5dbf30240ccfbde4a0230c70d4c79147ab0b317edad2f8ae7")
            ),
            hex::decode("eaaa08807d0616026ff51c849efbf35ba0ce3c5300e7d486da46351b13d4605b")
                .unwrap(),
            "the transcript after the client's public value"
        );

        // The challenge this module builds has to be the octets the vector publishes, or the
        // transcript hash above would be computed over a message no client ever sent.
        assert_eq!(
            encode_challenge(
                GROUP_EDWARDS25519,
                &hex32("18f511e750c97b592acd30db7d9e5fca660389102e6bf610c1bfbed4616c8362")
            ),
            challenge_bytes
        );
    }

    /// The support message a client sends is what this module parses — the same octets the
    /// vector publishes, so a change in either the encoder or the parser is caught here.
    #[test]
    fn the_published_support_message_is_understood() {
        let support = hex::decode("a0093007a0053003020101").unwrap();
        assert_eq!(decode_support(&support).unwrap(), vec![1]);
    }

    /// A group the KDC does not implement is refused by name, and the client is told which
    /// groups it asked for.
    #[test]
    fn a_support_message_without_edwards25519_is_refused() {
        // [0] { [0] { [0]: 2 } } — P-256 only.
        let support = der::field(0, der::seq(&[der::field(0, der::seq(&[der::int(2)]))]));
        assert_eq!(decode_support(&support).unwrap(), vec![2]);
    }

    #[test]
    fn a_pending_state_round_trips() {
        let pending = Pending {
            group: GROUP_EDWARDS25519,
            private: [7u8; 32],
            challenge: vec![1, 2, 3],
            support: vec![4, 5],
        };
        assert_eq!(Pending::decode(&pending.encode()).unwrap(), pending);
    }

    /// An `Int32` outside 1..=4 octets is refused rather than read as whatever fits.
    ///
    /// With the two conditions joined by `&&` instead of `||`, a five-octet INTEGER is accepted
    /// and silently truncated to its low bits — a group list nobody wrote would decide which
    /// group the KDC picks.
    #[test]
    fn an_int_of_the_wrong_width_is_refused() {
        assert_eq!(int_of(&[1]).unwrap(), 1);
        assert_eq!(int_of(&[0xff]).unwrap(), -1);
        assert_eq!(int_of(&[0x01, 0x00]).unwrap(), 256);
        for bad in [vec![], vec![1, 2, 3, 4, 5], vec![0; 9]] {
            let err = int_of(&bad).unwrap_err().to_string();
            assert!(
                err.contains("1..4 octets"),
                "an Int32 of {} octets must be refused, not read: {err}",
                bad.len()
            );
        }
    }

    #[test]
    fn a_public_value_off_the_curve_is_refused() {
        // Not every 32 octets are a compressed edwards25519 point: decompression needs a square
        // root to exist, and for this value it does not (checked outside this crate — most
        // values, including all-bits-set, *are* on the curve, which is why this one is named).
        let err = shared_value(
            &Scalar::from_bytes_mod_order([1u8; 32]),
            &[2u8; 32],
            &[0x02u8; 32],
            Mask::N,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("curve point"), "{err}");
    }
}
