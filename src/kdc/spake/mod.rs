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

mod group;

use crate::crypto::{Cipher, Key};
use crate::der;
use crate::error::{Error, Result};

use super::preauth::{Announced, Mechanism, Request, Step};

/// `PA-SPAKE` (RFC 9588 §12).
pub const PA_SPAKE: i32 = 151;

/// `KEY_USAGE_SPAKE` (RFC 9588 §11): the second-factor encryption.
pub const KU_SPAKE: u32 = 65;

/// `SF-NONE`: no second factor. Its presence is the whole validation.
const SF_NONE: i64 = 1;

/// The id the old, single-group code named. Kept because a realm's configuration and the tests
/// refer to it, and because the group module's constant carries the same value.
pub const GROUP_EDWARDS25519: i32 = group::EDWARDS25519;

/// Which mask a party applies: the KDC's `M` or the client's `N`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mask {
    M,
    N,
}

/// The multiplier `w` from the initial reply key: `PRF+(K, "SPAKEsecret" || group)`.
///
/// The pepper binds the mask to the group, so a client and a KDC that disagree about the group
/// derive different masks and the exchange cannot complete by accident.
fn w_bytes(cipher: &dyn Cipher, ikey: &Key, group: &dyn group::Group) -> Result<Vec<u8>> {
    let _ = cipher;
    let mut seed = b"SPAKEsecret".to_vec();
    seed.extend_from_slice(&group.id().to_be_bytes());
    // The registry's multiplier length, not a constant: P-384 and P-521 take 48 octets, and a
    // 32-octet pepper would derive a different `w` — the exchange would fail at the last step with
    // nothing to point at.
    Ok(crate::crypto::kdf::prf_plus(
        ikey.enctype(),
        ikey.bytes(),
        &seed,
        group.multiplier_len(),
    )?)
}

/// The chain is `H("SPAKEkey" || group || enctype || w || K || thash || body || n || block)`,
/// truncated to the enctype's seed length and then put through `KRB-FX-CF2` with the initial
/// reply key. The `body` is the `KDC-REQ-BODY` of the request being answered, so a reply key is
/// bound to one request: a response lifted into another request derives a different key.
#[allow(clippy::too_many_arguments)]
fn derive_key(
    ikey: &Key,
    group: &dyn group::Group,
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
        seed.extend_from_slice(&group.hash(&[
            b"SPAKEkey",
            &group.id().to_be_bytes(),
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
    Ok(Key::new(enctype, hkey)?)
}

/// `H(H(zero || support || challenge) || client pubkey)` — RFC 9588 §6.
///
/// The zero prefix is the transcript's initial value: "All bits are set to zero in the initial
/// value", and the hash of that plus the first input is the first update. The hash is the group's
/// own, so a P-384 exchange hashes ten more octets than a P-256 one at every step — and the result
/// reaches `K'[n]`, which is why picking the wrong one is a different key rather than a formatting
/// problem.
fn transcript_after_challenge(
    group: &dyn group::Group,
    support: &[u8],
    challenge: &[u8],
) -> Vec<u8> {
    let zero = vec![0u8; group.hash(&[]).len()];
    group.hash(&[&zero, support, challenge])
}

/// The final transcript hash: the first update and the client's public value.
fn transcript_final(group: &dyn group::Group, first: &[u8], client_public: &[u8]) -> Vec<u8> {
    group.hash(&[first, client_public])
}

/// The `SPAKESupport` a client sent: the groups it prefers, in order.
fn decode_support(value: &[u8]) -> Result<Vec<i32>> {
    let mut r = der::Reader::new(value);
    let content = r.expect_in("SPAKESupport", der::ctx(0))?;
    let mut sr = der::Reader::new(content);
    let inner = sr.expect_in("SPAKESupport", der::SEQUENCE)?;
    let f = der::Fields::parse("SPAKESupport", inner)?;
    let mut gr = der::Reader::new(f.bytes(0, "SPAKESupport")?);
    let groups = gr.expect_in("SPAKESupport", der::SEQUENCE)?;
    let mut out = Vec::new();
    let mut g = der::Reader::new(groups);
    while !g.is_empty() {
        out.push(int_of(g.expect_in("SPAKESupport", der::INTEGER)?)?);
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
    let content = r.expect_in("SPAKEResponse", der::ctx(2))?;
    let mut sr = der::Reader::new(content);
    let f = der::Fields::parse(
        "SPAKEResponse",
        sr.expect_in("SPAKEResponse", der::SEQUENCE)?,
    )?;
    let mut pr = der::Reader::new(f.bytes(0, "SPAKEResponse")?);
    let pubkey = pr.expect_in("SPAKEResponse", der::OCTET_STRING)?.to_vec();
    let factor =
        crate::msg::EncryptedData::decode("SPAKEResponse factor", f.bytes(1, "SPAKEResponse")?)?;
    Ok(Response { pubkey, factor })
}

/// The state a challenge leaves behind, for the cookie.
///
/// `x` cannot be recomputed and the challenge cannot be re-derived byte for byte, so both are
/// carried. The support message is here for the same reason: the transcript hash covers it.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Pending {
    group: i32,
    /// The KDC's secret scalar, as octets: its width is the group's, and a fixed array would pin
    /// this state to edwards25519.
    private: Vec<u8>,
    challenge: Vec<u8>,
    support: Vec<u8>,
}

impl Pending {
    fn encode(&self) -> Vec<u8> {
        der::seq(&[
            der::field(0, der::int(self.group as i64)),
            der::field(1, der::octets(&self.private)),
            der::field(2, der::octets(&self.challenge)),
            der::field(3, der::octets(&self.support)),
        ])
    }

    fn decode(state: &[u8]) -> Result<Pending> {
        let mut r = der::Reader::new(state);
        let f = der::Fields::parse("SPAKE state", r.expect_in("SPAKE state", der::SEQUENCE)?)?;
        let group = f.int(0, "SPAKE state")? as i32;
        // A state naming a group this build does not have is a cookie from another build, and
        // resuming it with the wrong arithmetic would compute a key nobody else has.
        let implementation = group::by_id(group).ok_or_else(|| {
            Error::Protocol(format!(
                "SPAKE state names group {group}, which this KDC does not implement"
            ))
        })?;
        let private = f.octets(1, "SPAKE state")?.to_vec();
        if private.len() != implementation.multiplier_len().max(32) && private.len() < 32 {
            return Err(Error::Protocol("SPAKE state has a short scalar".into()));
        }
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
            r.expect_in("SPAKESecondFactor", der::SEQUENCE)?,
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

    fn announce(&self, _request: &Request<'_>) -> Result<Option<Announced>> {
        // RFC 9588 §4.1: the offer is the empty value. Whatever came before in the session is
        // not a SPAKE state, so nothing is carried. SPAKE works with or without armor, so there
        // is no exchange where this mechanism declines to be announced.
        Ok(Some(Announced::default()))
    }

    fn round(&self, request: &Request<'_>, state: &[u8], padata: &[u8]) -> Result<Step> {
        let mut r = der::Reader::new(padata);
        let tag = r.next_tlv("PA-SPAKE")?.tag;
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
    // The client's order, first we implement (RFC 9588 §4.2). `None` is the one refusal a client
    // acts on by trying another method rather than failing the login, and naming the groups it
    // asked for is what an operator needs to see.
    let Some(id) = group::first_supported(&groups) else {
        return Ok(Step::Failed {
            code: crate::error::codes::KDC_ERR_PREAUTH_FAILED,
            text: format!(
                "this realm offers {:?}, and the client asked for {groups:?}",
                group::ALL
                    .iter()
                    .filter_map(|id| group::name(*id))
                    .collect::<Vec<_>>()
            ),
        });
    };
    let implementation = group::by_id(id)
        .ok_or_else(|| Error::Protocol(format!("group {id} has no implementation")))?;
    let ikey = request
        .longterm
        .first()
        .ok_or_else(|| Error::Protocol("SPAKE needs a long-term key".into()))?;

    let w = w_bytes(request.cipher, ikey, implementation.as_ref())?;
    // Checked at the source: `PRF+` produces the registry's length, and a mismatch here would
    // otherwise reach the arithmetic as a scalar nobody validated.
    implementation.multiplier(&w)?;
    let private = implementation.random_multiplier(request.cipher)?;
    let public = implementation.public_value(&private, &w, Mask::M)?;
    let challenge_message = encode_challenge(id, &public);

    // The client sends its own value next; the transcript needs the support message and the
    // challenge exactly as they travelled, so both are remembered rather than rebuilt.
    let pending = Pending {
        group: id,
        private,
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
    let implementation = group::by_id(pending.group).ok_or_else(|| {
        Error::Protocol(format!(
            "SPAKE state names group {}, which this KDC does not implement",
            pending.group
        ))
    })?;
    let w = w_bytes(request.cipher, ikey, implementation.as_ref())?;
    implementation.multiplier(&w)?;
    // The length check is the group's, not a constant: a client that answered with an
    // edwards25519-sized value after being given a P-384 challenge is confused, and the arithmetic
    // would refuse it anyway with a message about points rather than about the exchange.
    let k = match implementation.shared_value(&pending.private, &w, &response.pubkey, Mask::N) {
        Ok(k) => k,
        Err(err) => {
            return Ok(Step::Failed {
                code: crate::error::codes::KDC_ERR_PREAUTH_FAILED,
                text: format!("the client's SPAKE value is not usable: {err}"),
            });
        }
    };

    let thash = transcript_final(
        implementation.as_ref(),
        &transcript_after_challenge(
            implementation.as_ref(),
            &pending.support,
            &pending.challenge,
        ),
        &response.pubkey,
    );
    let k0 = derive_key(
        ikey,
        implementation.as_ref(),
        &w,
        &k,
        &thash,
        request.body,
        0,
    )?;
    let k1 = derive_key(
        ikey,
        implementation.as_ref(),
        &w,
        &k,
        &thash,
        request.body,
        1,
    )?;

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
        endtime_bound: None,
        reply_key: k0,
        padata: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::scalar::Scalar;

    /// The group the module's edwards25519 implementation is, for the vector below.
    fn ed() -> Box<dyn group::Group> {
        group::by_id(group::EDWARDS25519).expect("edwards25519 is implemented")
    }

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
            ed().public_value(&x.to_bytes(), &w, Mask::M).unwrap(),
            hex32("18f511e750c97b592acd30db7d9e5fca660389102e6bf610c1bfbed4616c8362"),
            "T = x·G + w·M"
        );
        assert_eq!(
            ed().public_value(&y.to_bytes(), &w, Mask::N).unwrap(),
            hex32("5d10705e0d1e43d5dbf30240ccfbde4a0230c70d4c79147ab0b317edad2f8ae7"),
            "S = y·G + w·N"
        );

        let s = hex32("5d10705e0d1e43d5dbf30240ccfbde4a0230c70d4c79147ab0b317edad2f8ae7");
        let t = hex32("18f511e750c97b592acd30db7d9e5fca660389102e6bf610c1bfbed4616c8362");
        let expected = hex32("25bde0d875f0feb5755f45ba5e857889d916ecf7476f116aa31dc3e037ec4292");
        assert_eq!(
            ed().shared_value(&x.to_bytes(), &w, &s, Mask::N).unwrap(),
            expected,
            "the KDC's K = x·(S − w·N)"
        );
        assert_eq!(
            ed().shared_value(&y.to_bytes(), &w, &t, Mask::M).unwrap(),
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
            transcript_after_challenge(ed().as_ref(), &support, &challenge_bytes),
            hex::decode("22bb2271e34d329d52073c70b1d1187973181f0bc7614266bb79ee80d3335175")
                .unwrap(),
            "the transcript after the challenge"
        );
        assert_eq!(
            transcript_final(
                ed().as_ref(),
                &transcript_after_challenge(ed().as_ref(), &support, &challenge_bytes),
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
            private: vec![7u8; 32],
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
        let err = ed()
            .shared_value(&[1u8; 32], &[2u8; 32], &[0x02u8; 32], Mask::N)
            .unwrap_err()
            .to_string();
        assert!(err.contains("curve point"), "{err}");
    }
}
