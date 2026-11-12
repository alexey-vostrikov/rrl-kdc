//! OTP pre-authentication, RFC 6560, as MIT's `kinit -T armor` drives it.
//!
//! A one-time value from a token instead of a password. The KDC says which tokens it will take
//! in a `PA-OTP-CHALLENGE` (141); the client answers with `PA-OTP-REQUEST` (142) carrying the
//! value and the challenge's nonce back. Both travel inside FAST armor (RFC 6560 §3.2 puts the
//! challenge in `enc-fast-rep`), which is what keeps the one-time value off the wire.
//!
//! # Which variant this implements, and why
//!
//! RFC 6560 §3.3 splits on the `must-encrypt-nonce` flag:
//!
//! * flag **set**: the OTP value never travels; it generates the client and reply keys, and the
//!   KDC must know the value in advance;
//! * flag **clear**: the value travels in `otp-value` (inside the armor), and the reply key is
//!   the armor key.
//!
//! Only the second is implemented. It is the one that fits a KDC which asks somebody else — a
//! RADIUS server, a token vault — whether a value is correct, which is how FreeIPA does
//! two-factor login and what MIT's KDC does when the value is not in its own database. The first
//! needs the KDC to hold every token's current value, and this crate has no such store; a
//! half-implementation of it would derive keys the KDC cannot compute.
//!
//! The flag is therefore **not** set in the challenge, and that is the signal: a client reading
//! a clear flag puts the value in `otp-value` and derives the reply key from the armor, exactly
//! as this side expects.
//!
//! # Where the value is judged
//!
//! [`Verifier`] is the seam. The crate does not know what a valid one-time value is, and must
//! not: it lives in a RADIUS server, a token vault or a test double. A refusal from the verifier
//! is `KDC_ERR_PREAUTH_FAILED` and nothing else — an OTP has no "wrong password" nuance worth
//! distinguishing, and telling a client that its token is simply unknown is a hint an attacker
//! can use.
//!
//! # What makes a captured request useless
//!
//! The nonce. It is random, as long as the armor key, and it goes into the cookie between the
//! challenge and the response; a `PA-OTP-REQUEST` replayed without it — or with one issued to
//! another exchange — is refused. Without that check, anyone who recorded one login could
//! replay it while the token's value is still current.

use std::sync::Arc;

use crate::der;
use crate::error::{Error, Result};
use crate::msg::EncryptedData;
use crate::name::Principal;

use super::preauth::{Announced, Mechanism, Request, Step};

/// `PA-OTP-CHALLENGE` (RFC 6560 §4).
pub const PA_OTP_CHALLENGE: i32 = 141;

/// `PA-OTP-REQUEST` (RFC 6560 §4).
pub const PA_OTP_REQUEST: i32 = 142;

/// The usage the client encrypts the nonce under (MIT's `KU_PA_OTP_REQUEST`).
pub const KU_PA_OTP_REQUEST: u32 = 45;

/// `must-encrypt-nonce`: the variant this crate does not implement (see the module comment).
pub const OTP_FLAG_MUST_ENCRYPT_NONCE: u32 = 0x0400_0000;

/// `collect-pin`: the client should put a PIN before the value.
pub const OTP_FLAG_COLLECT_PIN: u32 = 0x1000_0000;

/// Who judges a one-time value.
///
/// Implemented by the caller: this crate has no token store and should not grow one. `value` is
/// the string the client sent, already decrypted from the armor; whatever the deployment
/// considers a valid answer is its business.
pub trait Verifier: Send + Sync {
    /// Whether `value` is the one-time value for `client` at this moment.
    ///
    /// An `Err` is a failure of the check itself (a RADIUS server that did not answer), and is
    /// reported as such rather than as a wrong token: the two are different operational events.
    fn verify(&self, client: &Principal, value: &str) -> Result<bool>;
}

/// OTP as a multi-round pre-authentication mechanism.
pub struct Otp<V: Verifier> {
    verifier: Arc<V>,
    /// What the client is told the token is for, if anything. Shown by `kinit`, so it is worth
    /// naming when a user has more than one token.
    service: Option<String>,
}

impl<V: Verifier> std::fmt::Debug for Otp<V> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Otp")
            .field("service", &self.service)
            .finish_non_exhaustive()
    }
}

impl<V: Verifier> Otp<V> {
    /// OTP for a realm whose values `verifier` judges.
    pub fn new(verifier: Arc<V>) -> Self {
        Otp {
            verifier,
            service: None,
        }
    }

    /// The same, naming the service the token is for in the challenge.
    pub fn with_service(mut self, service: impl Into<String>) -> Self {
        self.service = Some(service.into());
        self
    }
}

/// The challenge's nonce, and nothing else: that is all the KDC has to remember.
///
/// The token list is fixed by this mechanism — one token, no PIN, no format — so remembering it
/// would be remembering a constant.
fn encode_state(nonce: &[u8]) -> Vec<u8> {
    der::seq(&[
        der::field(0, der::int(1)),
        der::field(1, der::octets(nonce)),
    ])
}

fn decode_state(state: &[u8]) -> Result<Vec<u8>> {
    let mut r = der::Reader::new(state);
    let f = der::Fields::parse("OTP state", r.expect_in("OTP state", der::SEQUENCE)?)?;
    let version = f.int(0, "OTP state")?;
    if version != 1 {
        return Err(Error::Protocol(format!(
            "OTP state of version {version}, and this KDC writes 1"
        )));
    }
    Ok(f.octets(1, "OTP state")?.to_vec())
}

/// One `OTP-TOKENINFO`: a token that takes a value and nothing else.
///
/// Every field is OPTIONAL in RFC 6560's ASN.1, and leaving them out says what this mechanism
/// needs: no PIN (`collect-pin` clear), no fixed length, no particular format, and — the point —
/// `must-encrypt-nonce` clear, so the client sends the value and derives the reply key from the
/// armor. A client that reads this challenge can answer it; one that reads a token asking for a
/// hashed value would drop it and report that the KDC offers nothing usable.
fn encode_token_info(flags: u32) -> Vec<u8> {
    // `[0] OTPFlags` is an IMPLICIT BIT STRING: its content is the unused-bit count and then the
    // bits, which is what `der::flags32` builds — the same shape the client parses back.
    let flags = der::flags32(flags);
    der::seq(&[der::tlv(0x80, &flags[2..])])
}

/// `PA-OTP-CHALLENGE ::= SEQUENCE { nonce [0], otp-service [1], otp-tokenInfo [2] }`.
///
/// The tags are IMPLICIT (RFC 6560's module says so), unlike RFC 4120's: `[0]` carries the nonce
/// octets directly, and `[2]` carries the concatenated `OTP-TOKENINFO` sequences, not a nested
/// SEQUENCE OF.
fn encode_challenge(nonce: &[u8], service: Option<&str>) -> Vec<u8> {
    let mut fields = vec![der::tlv(0x80, nonce)];
    if let Some(service) = service {
        fields.push(der::tlv(0x81, service.as_bytes()));
    }
    fields.push(der::tlv(0xa2, &encode_token_info(0)));
    der::seq(&fields)
}

/// The fields of a `PA-OTP-REQUEST` this mechanism reads.
struct Request2 {
    nonce_cipher: EncryptedData,
    value: String,
}

/// Parses `PA-OTP-REQUEST`, refusing what cannot be answered.
fn decode_request(value: &[u8]) -> Result<Request2> {
    let mut r = der::Reader::new(value);
    let f = der::Fields::parse(
        "PA-OTP-REQUEST",
        r.expect_in("PA-OTP-REQUEST", der::SEQUENCE)?,
    )?;
    let enc = f.bytes(2, "PA-OTP-REQUEST")?;
    // `[2]` is an IMPLICIT `EncryptedData`: the tag replaced its SEQUENCE, so what is left is
    // that SEQUENCE's content.
    let nonce_cipher = EncryptedData::decode_content("PA-OTP-REQUEST nonce", enc)?;
    let raw = f.bytes(5, "PA-OTP-REQUEST")?;
    let value = String::from_utf8(raw.to_vec())
        .map_err(|_| Error::Protocol("the OTP value is not UTF-8".into()))?;
    Ok(Request2 {
        nonce_cipher,
        value,
    })
}

/// Equality that does not stop at the first difference.
///
/// The nonce is a secret the KDC issued; comparing it byte by byte with early exit leaks how much
/// of a guess was right, and a nonce is short enough to walk one octet at a time.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

impl<V: Verifier> Mechanism for Otp<V> {
    fn pa_type(&self) -> i32 {
        PA_OTP_REQUEST
    }

    fn announce_type(&self) -> i32 {
        PA_OTP_CHALLENGE
    }

    fn name(&self) -> &'static str {
        "OTP"
    }

    fn announce(&self, request: &Request<'_>) -> Result<Option<Announced>> {
        // RFC 6560 §3.2: the challenge belongs inside `enc-fast-rep`. An unarmored request
        // cannot carry it, and a client that saw the offer would send a request this side could
        // not verify — so the mechanism says nothing rather than offering a method that cannot
        // complete.
        let Some(armor) = request.armor else {
            return Ok(None);
        };
        // Long enough to be unguessable, per §3.2: "at least as long as the Armor Key length".
        let nonce = request.cipher.random(armor.enctype())?.bytes().to_vec();
        Ok(Some(Announced {
            padata: encode_challenge(&nonce, self.service.as_deref()),
            state: encode_state(&nonce),
        }))
    }

    fn round(&self, request: &Request<'_>, state: &[u8], padata: &[u8]) -> Result<Step> {
        let Some(armor) = request.armor else {
            // A `PA-OTP-REQUEST` outside FAST armor would mean the one-time value travelled in
            // the clear. RFC 6560 §3.2 does not allow it, and neither does this KDC.
            return Ok(Step::Failed {
                code: crate::error::codes::KDC_ERR_PREAUTH_FAILED,
                text: "PA-OTP-REQUEST arrived without FAST armor, and the value is not \
                       accepted unarmored"
                    .into(),
            });
        };
        if state.is_empty() {
            // No cookie, so no nonce, so no way to tell this request from a replay. Starting a
            // fresh challenge instead of guessing is what keeps a recorded exchange useless.
            return Ok(Step::Failed {
                code: crate::error::codes::KDC_ERR_MORE_PREAUTH_DATA_REQUIRED,
                text: "no challenge is outstanding for this client; ask again".into(),
            });
        }

        let expected = decode_state(state)?;
        let parsed = match decode_request(padata) {
            Ok(parsed) => parsed,
            Err(err) => {
                return Ok(Step::Failed {
                    code: crate::error::codes::KDC_ERR_PREAUTH_FAILED,
                    text: format!("PA-OTP-REQUEST did not parse: {err}"),
                });
            }
        };

        // The nonce is the whole replay defence: it was issued to this client, in this exchange,
        // and only the holder of the armor key can send it back.
        let nonce =
            match request
                .cipher
                .decrypt(armor, KU_PA_OTP_REQUEST, &parsed.nonce_cipher.cipher)
            {
                Ok(plain) => plain,
                Err(err) => {
                    return Ok(Step::Failed {
                        code: crate::error::codes::KDC_ERR_PREAUTH_FAILED,
                        text: format!("the challenge nonce did not decrypt: {err}"),
                    });
                }
            };
        let got = {
            let mut r = der::Reader::new(&nonce);
            let f = der::Fields::parse(
                "PA-OTP-ENC-REQUEST",
                r.expect_in("PA-OTP-ENC-REQUEST", der::SEQUENCE)?,
            )?;
            f.bytes(0, "PA-OTP-ENC-REQUEST")?.to_vec()
        };
        if !constant_time_eq(&got, &expected) {
            return Ok(Step::Failed {
                code: crate::error::codes::KDC_ERR_PREAUTH_FAILED,
                text: "the nonce is not the one this exchange was issued".into(),
            });
        }

        match self.verifier.verify(request.cname, &parsed.value) {
            Ok(true) => {}
            Ok(false) => {
                return Ok(Step::Failed {
                    code: crate::error::codes::KDC_ERR_PREAUTH_FAILED,
                    text: "the one-time value was not accepted".into(),
                });
            }
            Err(err) => {
                // A verifier that could not answer is an operational failure, not a wrong token.
                // Reporting it as `PREAUTH_FAILED` would send the user to retype a value that
                // was never judged.
                return Err(Error::Kdc {
                    code: crate::error::codes::KDC_ERR_SVC_UNAVAILABLE,
                    text: format!("the OTP verifier did not answer: {err}"),
                });
            }
        }

        // RFC 6560 §3.3: with `must-encrypt-nonce` clear, the reply key is the armor key. The
        // AS path then strengthens it, because the request is armored — which is the "strengthened
        // if the KDC says so" the client's own documentation mentions.
        Ok(Step::Done {
            endtime_bound: None,
            reply_key: armor.clone(),
            padata: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Always(bool);

    impl Verifier for Always {
        fn verify(&self, _client: &Principal, _value: &str) -> Result<bool> {
            Ok(self.0)
        }
    }

    #[test]
    fn the_challenge_has_the_shape_the_client_reads() {
        let nonce = vec![7u8; 32];
        let challenge = encode_challenge(&nonce, Some("cifs/host"));
        let mut r = der::Reader::new(&challenge);
        let f = der::Fields::parse(
            "challenge",
            r.expect_in("challenge", der::SEQUENCE).unwrap(),
        )
        .expect("fields");
        assert_eq!(
            f.bytes(0, "challenge").unwrap(),
            &nonce[..],
            "the nonce is [0]"
        );
        assert_eq!(
            f.bytes(1, "challenge").unwrap(),
            b"cifs/host",
            "the service is [1]"
        );
        // `[2]` is the concatenated token infos, and each one is a real SEQUENCE.
        let mut tokens = der::Reader::new(f.bytes(2, "challenge").unwrap());
        let token = der::Fields::parse(
            "OTP-TOKENINFO",
            tokens.expect_in("token", der::SEQUENCE).unwrap(),
        )
        .expect("token fields");
        assert!(tokens.is_empty(), "exactly one token");
        // The flags say "no PIN", which is what makes the client send a value instead of asking
        // for one: `collect-pin` is the bit that would change its behaviour.
        let flags = token.bytes(0, "OTP-TOKENINFO").unwrap();
        let value = u32::from_be_bytes([flags[1], flags[2], flags[3], flags[4]]);
        assert_eq!(value & OTP_FLAG_COLLECT_PIN, 0);
        assert_eq!(
            value & OTP_FLAG_MUST_ENCRYPT_NONCE,
            0,
            "the flag this implementation depends on"
        );
    }

    /// A mechanism that names a service has to say so in the challenge.
    ///
    /// RFC 6560 §3.2 makes `otp-service` optional "to assist the client in locating the OTP
    /// token" — a user with several tokens needs it, and a challenge that silently drops it looks
    /// like the mechanism was configured without one.
    #[test]
    fn a_named_service_reaches_the_client() {
        use crate::crypto::{Cipher, OwnCipher};
        let cipher = OwnCipher;
        let armor = cipher
            .s2k(crate::crypto::Enctype::Aes256Sha1, b"armor", b"armor", None)
            .unwrap();
        let cname = crate::name::Principal::parse("alice@EXAMPLE.COM").unwrap();
        let request = Request {
            cname: &cname,
            realm: "EXAMPLE.COM",
            body: &[],
            longterm: &[],
            armor: Some(&armor),
            now: 0,
            cipher: &cipher,
        };
        let otp = Otp::new(Arc::new(Always(true))).with_service("cifs/files.example.com");
        let announced = otp.announce(&request).unwrap().expect("armored");

        let mut r = der::Reader::new(&announced.padata);
        let f = der::Fields::parse(
            "challenge",
            r.expect_in("challenge", der::SEQUENCE).unwrap(),
        )
        .expect("fields");
        assert_eq!(
            f.bytes(1, "challenge").unwrap(),
            b"cifs/files.example.com",
            "the service the token is for is [1]"
        );
    }

    /// `name` is what an operator reads when a login is refused, so it is pinned rather than
    /// derived from the type name: "otp" and "OTP" are the same to a computer and different to
    /// whoever is reading the log.
    #[test]
    fn the_mechanism_names_itself() {
        let otp = Otp::new(Arc::new(Always(true)));
        assert_eq!(otp.name(), "OTP");
    }

    /// `Debug` is read when the answer is not what was expected, and "which mechanism, with
    /// which service" is the first question. A `Debug` that printed nothing would look like an
    /// answer.
    #[test]
    fn the_debug_view_says_which_mechanism_and_service() {
        let plain = format!("{:?}", Otp::new(Arc::new(Always(true))));
        assert!(plain.contains("Otp"), "{plain}");
        assert!(plain.contains("service"), "{plain}");

        let named = format!(
            "{:?}",
            Otp::new(Arc::new(Always(true))).with_service("cifs/host")
        );
        assert!(
            named.contains("cifs/host"),
            "the service is what distinguishes two OTP realms: {named}"
        );
    }

    #[test]
    fn the_state_carries_the_nonce_and_nothing_else() {
        let nonce = vec![9u8; 32];
        assert_eq!(decode_state(&encode_state(&nonce)).unwrap(), nonce);
    }

    #[test]
    fn a_state_of_another_version_is_refused() {
        let wrong = der::seq(&[
            der::field(0, der::int(2)),
            der::field(1, der::octets(&[1, 2])),
        ]);
        let err = decode_state(&wrong).unwrap_err().to_string();
        assert!(err.contains("version"), "{err}");
    }

    #[test]
    fn the_nonce_comparison_is_not_length_blind() {
        assert!(constant_time_eq(&[1, 2, 3], &[1, 2, 3]));
        assert!(!constant_time_eq(&[1, 2, 3], &[1, 2]));
        assert!(!constant_time_eq(&[1, 2, 3], &[1, 2, 4]));
        assert!(!constant_time_eq(&[], &[0]));
    }

    #[test]
    fn the_mechanism_answers_under_the_request_type_and_offers_the_challenge_type() {
        // The two differ, and the framework has to know it: advertising the request type would
        // offer a client nothing it treats as a challenge.
        let otp = Otp::new(Arc::new(Always(true)));
        assert_eq!(otp.pa_type(), PA_OTP_REQUEST);
        assert_eq!(otp.announce_type(), PA_OTP_CHALLENGE);
        assert_eq!(PA_OTP_CHALLENGE, 141);
        assert_eq!(PA_OTP_REQUEST, 142);
    }
}
