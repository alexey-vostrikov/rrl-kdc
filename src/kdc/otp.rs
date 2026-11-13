//! OTP pre-authentication, RFC 6560, as MIT's `kinit -T armor` drives it.
//!
//! A one-time value from a token instead of a password. The KDC says which tokens it will take
//! in a `PA-OTP-CHALLENGE` (141); the client answers with `PA-OTP-REQUEST` (142) carrying the
//! challenge's nonce back — and, depending on the variant described below, the value with it or
//! not at all. Both messages travel inside FAST armor (RFC 6560 §3.2 puts the challenge in
//! `enc-fast-rep`), which is what keeps the one-time value off the wire.
//!
//! # Which variant this implements, and why
//!
//! RFC 6560 §3.3 splits on the `must-encrypt-nonce` flag:
//!
//! * flag **set**: the OTP value never travels; it generates the client and reply keys instead
//!   (RFC 6560 §3.6), and the KDC must know the value — [`OtpSource`] is that seam;
//! * flag **clear**: the value travels in `otp-value` inside the armor, and the reply key is the
//!   armor key — [`Verifier`] judges it, which fits a KDC that asks a RADIUS server or a token
//!   vault.
//!
//! **Both are implemented, and which one a realm gets is decided by what it installed.** A realm
//! with an [`OtpSource`] gets the encrypted-nonce variant: it holds the values, so the value never
//! needs to travel; a realm with only a [`Verifier`] gets the other. The challenge's flag says
//! which, so a client is never asked for a value the KDC would ignore, nor trusted to withhold one
//! it needs.
//!
//! §3.6's derivation, in full, because it is the whole difference:
//!
//! ```text
//! K2         = string-to-key(enctype(ArmorKey), Base64(OTP) || "Krb-preAuth")
//! ClientKey  = KRB-FX-CF2(ArmorKey, K2, "OTPComb1", "OTPComb2")
//! ReplyKey   = KRB-FX-CF2(ArmorKey, K2, "OTPComb3", "OTPComb4")
//! ```
//!
//! The salt is the principal's default salt: §3.6 lets the KDC send one in the challenge and says
//! to use the enctype's defaults when it does not, and for the AES enctypes RFC 3962 §4 defines
//! that default as realm || principal — which is `Principal::default_salt`.
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

use crate::crypto::{Cipher, Key};
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

/// `BOOLEAN` (universal tag 1): the flag octet's type in the state, and in `otp-tokenInfo`.
const BOOLEAN: u8 = 0x01;

/// `must-encrypt-nonce`: the value is withheld and the keys come from it instead (§3.3).
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

/// Where a token's current value lives.
///
/// The seam for the `must-encrypt-nonce` variant: with the flag set the value never travels, so the
/// KDC has to have it. Unlike [`Verifier`], which judges a value it is shown, this *supplies* one —
/// and that is the difference between a KDC that can be told a token is valid and one that can
/// derive the same keys the token did.
///
/// `None` means this account has no token value to give, which is a refusal and not an error: a
/// user without a token cannot use this mechanism, and saying so is `PREAUTH_FAILED` with a plain
/// reason.
pub trait OtpSource: std::fmt::Debug + Send + Sync {
    /// The value the account's token is showing now, as the text the token displays.
    fn value(&self, client: &Principal) -> Option<String>;
}

/// OTP as a multi-round pre-authentication mechanism.
pub struct Otp<V: Verifier> {
    verifier: Arc<V>,
    /// Set when the realm holds its tokens' values, which selects the `must-encrypt-nonce` variant.
    source: Option<Arc<dyn OtpSource>>,
    /// What the client is told the token is for, if anything. Shown by `kinit`, so it is worth
    /// naming when a user has more than one token.
    service: Option<String>,
}

impl<V: Verifier> std::fmt::Debug for Otp<V> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Otp")
            .field("service", &self.service)
            .field("holds_values", &self.source.is_some())
            .finish_non_exhaustive()
    }
}

impl<V: Verifier> Otp<V> {
    /// OTP for a realm whose values `verifier` judges.
    pub fn new(verifier: Arc<V>) -> Self {
        Otp {
            verifier,
            source: None,
            service: None,
        }
    }

    /// The same, naming the service the token is for in the challenge.
    pub fn with_service(mut self, service: impl Into<String>) -> Self {
        self.service = Some(service.into());
        self
    }

    /// The same, with the realm's token values in `source`.
    ///
    /// This selects the `must-encrypt-nonce` variant (RFC 6560 §3.3): the challenge sets the flag,
    /// the client withholds the value, and both keys are derived from the armor key and the value
    /// (§3.6). A realm that also installed a [`Verifier`] does not use it in this mode — the value
    /// is not shown to the KDC, it is known to it.
    pub fn with_source(mut self, source: Arc<dyn OtpSource>) -> Self {
        self.source = Some(source);
        self
    }
}

/// The challenge's nonce, and nothing else: that is all the KDC has to remember.
///
/// The token list is fixed by this mechanism — one token, no PIN, no format — so remembering it
/// would be remembering a constant.
fn encode_state(nonce: &[u8], must_encrypt: bool) -> Vec<u8> {
    let mut fields = vec![
        der::field(0, der::int(1)),
        der::field(1, der::octets(nonce)),
    ];
    // `[2]` only when set: a cookie issued by a realm that holds no token values has to keep
    // parsing, and an absent boolean is the RFC's default for the flag.
    if must_encrypt {
        fields.push(der::field(2, der::tlv(BOOLEAN, &[0xff])));
    }
    der::seq(&fields)
}

fn decode_state(state: &[u8]) -> Result<(Vec<u8>, bool)> {
    let mut r = der::Reader::new(state);
    let f = der::Fields::parse("OTP state", r.expect_in("OTP state", der::SEQUENCE)?)?;
    let version = f.int(0, "OTP state")?;
    if version != 1 {
        return Err(Error::Protocol(format!(
            "OTP state of version {version}, and this KDC writes 1"
        )));
    }
    // `opt_bytes` returns the field's content, which here is the whole `BOOLEAN` TLV — tag and
    // length included. Reading its first octet reads the tag (0x01), which would call every state
    // clear; the value is one level in. DER's `true` is 0xff.
    let must_encrypt = match f.opt_bytes(2) {
        Some(bytes) => {
            let mut r = der::Reader::new(bytes);
            matches!(r.expect_in("OTP state [2]", BOOLEAN)?, [0xff])
        }
        None => false,
    };
    Ok((f.octets(1, "OTP state")?.to_vec(), must_encrypt))
}

/// One `OTP-TOKENINFO`: a token that takes a value and nothing else.
///
/// Only `flags` is sent. Every other field of RFC 6560's ASN.1 is OPTIONAL and leaving them out
/// says what this mechanism needs: no PIN, no fixed length, no particular format, no challenge, no
/// hash algorithms to choose from. The flags say the one thing that differs between realms —
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
fn encode_challenge(nonce: &[u8], service: Option<&str>, must_encrypt: bool) -> Vec<u8> {
    let mut fields = vec![der::tlv(0x80, nonce)];
    if let Some(service) = service {
        fields.push(der::tlv(0x81, service.as_bytes()));
    }
    fields.push(der::tlv(
        0xa2,
        &encode_token_info(if must_encrypt {
            OTP_FLAG_MUST_ENCRYPT_NONCE
        } else {
            0
        }),
    ));
    der::seq(&fields)
}

/// A `PA-OTP-CHALLENGE`, read back.
///
/// The counterpart of [`encode_challenge`], and it is here because a structure this crate writes
/// with no reader of its own can only be checked by a client that is not in the stand. RFC 6560's
/// module is `IMPLICIT TAGS`, so `otp-tokenInfo [2]` replaces the `SEQUENCE OF`'s own tag and its
/// content is the token `SEQUENCE`s one after another with nothing around them — one nesting less
/// than a reader who assumes `[2] { SEQUENCE OF }` gets, and the kind of mistake that turns a
/// challenge into "the KDC offers nothing" without any error anywhere.
///
/// It parses what the RFC allows rather than what the encoder emits: a challenge may carry several
/// tokens (§3.2), and a token may carry fields this realm never sends. Unknown fields are ignored,
/// as `Fields` keeps them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Challenge {
    /// The nonce the client must return sealed in its Client Key.
    pub nonce: Vec<u8>,
    /// What the token is for, when the realm names it: the hint a user with several tokens needs
    /// to pick the right one.
    pub service: Option<String>,
    /// One entry per token the KDC would accept, at least one (§3.2: `SIZE(1..MAX)`).
    pub tokens: Vec<TokenInfo>,
}

/// One `OTP-TOKENINFO` of a [`Challenge`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenInfo {
    /// `OTPFlags ::= KerberosFlags`: bit 0 is the most significant, as everywhere in Kerberos, so
    /// `must-encrypt-nonce` — bit 5 — is `0x0400_0000`.
    pub flags: u32,
}

impl TokenInfo {
    /// Whether the value is withheld and both keys come from it (§3.3, §3.6).
    pub fn must_encrypt(&self) -> bool {
        self.flags & OTP_FLAG_MUST_ENCRYPT_NONCE != 0
    }

    /// Whether the client should collect a PIN and put it before the value.
    pub fn collect_pin(&self) -> bool {
        self.flags & OTP_FLAG_COLLECT_PIN != 0
    }
}

impl Challenge {
    /// Parses `PA-OTP-CHALLENGE`, refusing what cannot be answered.
    pub fn decode(value: &[u8]) -> Result<Self> {
        let mut r = der::Reader::new(value);
        let f = der::Fields::parse(
            "PA-OTP-CHALLENGE",
            r.expect_in("PA-OTP-CHALLENGE", der::SEQUENCE)?,
        )?;

        // `[0] nonce OCTET STRING` is IMPLICIT, so the field's content is the nonce itself.
        let nonce = f.bytes(0, "PA-OTP-CHALLENGE")?.to_vec();
        if nonce.is_empty() {
            return Err(Error::Protocol(
                "PA-OTP-CHALLENGE: the nonce is empty, which would make every reply the same"
                    .into(),
            ));
        }

        // `[1] otp-service UTF8String`, also IMPLICIT.
        let service = match f.opt_bytes(1) {
            Some(bytes) => Some(String::from_utf8(bytes.to_vec()).map_err(|_| {
                Error::Protocol("PA-OTP-CHALLENGE: otp-service is not UTF-8".into())
            })?),
            None => None,
        };

        // `[2] otp-tokenInfo`: IMPLICIT over `SEQUENCE (SIZE(1..MAX)) OF OTP-TOKENINFO`, so the
        // content is the token SEQUENCEs concatenated — not one SEQUENCE wrapping them.
        let mut tokens = Vec::new();
        let mut list = der::Reader::new(f.bytes(2, "PA-OTP-CHALLENGE")?);
        while !list.is_empty() {
            let content = list.expect_in("otp-tokenInfo", der::SEQUENCE)?;
            let t = der::Fields::parse("OTP-TOKENINFO", content)?;
            // `flags [0] OTPFlags` is IMPLICIT over a BIT STRING, so the content is the BIT
            // STRING's: an unused-bit count and then the bits. `as_flags32` reads it, and reads a
            // trimmed encoding as well — Kerberos implementations send a fixed four octets where
            // DER would allow dropping trailing zero ones, and both have to work.
            let flags = der::as_flags32("OTP-TOKENINFO flags", t.bytes(0, "OTP-TOKENINFO")?)?;
            tokens.push(TokenInfo { flags });
        }
        if tokens.is_empty() {
            return Err(Error::Protocol(
                "PA-OTP-CHALLENGE: otp-tokenInfo is SEQUENCE SIZE(1..MAX) and this one is empty"
                    .into(),
            ));
        }

        Ok(Self {
            nonce,
            service,
            tokens,
        })
    }

    /// Whether any offered token withholds the value.
    ///
    /// "Any" and not "all": §3.2 says the client may generate its value according to the
    /// information in *one* of the tokens, so a set where one entry withholds the value is still a
    /// set the client can answer — it picks the token whose terms it can meet.
    pub fn must_encrypt(&self) -> bool {
        self.tokens.iter().any(TokenInfo::must_encrypt)
    }
}

/// The client and reply keys when the value does not travel (RFC 6560 §3.6).
///
/// `K2` is string-to-key over the **base64** of the value with `"Krb-preAuth"` appended, and the two
/// keys are `KRB-FX-CF2` of the armor key and `K2` under the four `OTPComb` peppers. The base64 is
/// not decoration: the same value with a different encoding derives different keys, and the failure
/// is indistinguishable from a wrong token.
///
/// The salt is the principal's default: §3.6 lets the KDC send one in the challenge and falls back
/// to "the default values defined for the particular enctype", which RFC 3962 §4 makes
/// realm || principal — exactly [`Principal::default_salt`].
fn keys_from_value(
    armor: &Key,
    value: &str,
    principal: &Principal,
    cipher: &dyn Cipher,
) -> Result<(Key, Key)> {
    use base64::Engine as _;

    let enctype = armor.enctype();
    let mut secret = base64::engine::general_purpose::STANDARD
        .encode(value.as_bytes())
        .into_bytes();
    secret.extend_from_slice(b"Krb-preAuth");
    let k2 = cipher.s2k(enctype, &secret, &principal.default_salt(), None)?;

    let client =
        crate::crypto::kdf::cf2(armor.bytes(), "OTPComb1", enctype, k2.bytes(), "OTPComb2")?;
    let reply =
        crate::crypto::kdf::cf2(armor.bytes(), "OTPComb3", enctype, k2.bytes(), "OTPComb4")?;
    Ok((Key::new(enctype, client)?, Key::new(enctype, reply)?))
}

/// The fields of a `PA-OTP-REQUEST` this mechanism reads.
struct Request2 {
    nonce_cipher: EncryptedData,
    /// The value, when the client sent one.
    ///
    /// RFC 6560 §3.3 makes it absent whenever the challenge set `must-encrypt-nonce`, so "is there
    /// a value" is a fact about which variant the exchange is running, not a property of this
    /// mechanism. Requiring it unconditionally — which this reader did — makes the withheld variant
    /// unable to parse its own request.
    value: Option<String>,
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
    // `[5] otp-value OCTET STRING` is IMPLICIT and OPTIONAL: absent means the value did not
    // travel, which is what a `must-encrypt-nonce` challenge asks for.
    let value = match f.opt_bytes(5) {
        Some(raw) => Some(
            String::from_utf8(raw.to_vec())
                .map_err(|_| Error::Protocol("the OTP value is not UTF-8".into()))?,
        ),
        None => None,
    };
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
        // A realm that holds its tokens' values asks the client to withhold the value (§3.3); one
        // that does not has to be shown it. The flag is the only thing that tells a client which.
        let must_encrypt = self.source.is_some();
        Ok(Some(Announced {
            padata: encode_challenge(&nonce, self.service.as_deref(), must_encrypt),
            state: encode_state(&nonce, must_encrypt),
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

        let (expected, must_encrypt) = decode_state(state)?;
        let parsed = match decode_request(padata) {
            Ok(parsed) => parsed,
            Err(err) => {
                return Ok(Step::Failed {
                    code: crate::error::codes::KDC_ERR_PREAUTH_FAILED,
                    text: format!("PA-OTP-REQUEST did not parse: {err}"),
                });
            }
        };

        // Which key the nonce is sealed in depends on the variant, and getting it wrong is a
        // refusal that looks like a wrong token. With the value withheld (§3.3) the client seals it
        // in the Client Key, which is derived from the value this realm is supposed to hold.
        let (nonce_key, reply_key, clear_value) = if must_encrypt {
            // §3.3 is a MUST NOT for the client: with the flag set the value must not appear. A
            // realm that asked for that and then quietly accepted a value would have logged it in
            // the same breath — the value travelled, and accepting it does not untravel it.
            if parsed.value.is_some() {
                return Ok(Step::Failed {
                    code: crate::error::codes::KDC_ERR_PREAUTH_FAILED,
                    text: "the challenge withheld the value, and the request carried it anyway"
                        .into(),
                });
            }
            let Some(value) = self
                .source
                .as_ref()
                .and_then(|source| source.value(request.cname))
            else {
                return Ok(Step::Failed {
                    code: crate::error::codes::KDC_ERR_PREAUTH_FAILED,
                    text: format!(
                        "{} has no one-time value on record, and this realm's tokens do not \
                         send theirs",
                        request.cname
                    ),
                });
            };
            let (client_key, reply_key) =
                match keys_from_value(armor, &value, request.cname, request.cipher) {
                    Ok(keys) => keys,
                    Err(err) => {
                        return Ok(Step::Failed {
                            code: crate::error::codes::KDC_ERR_PREAUTH_FAILED,
                            text: format!("the one-time keys could not be derived: {err}"),
                        });
                    }
                };
            (client_key, reply_key, None)
        } else {
            // The other variant has no key of its own to check the nonce with, so the value is the
            // only evidence there is — and a request without it is a request that proves nothing.
            let Some(value) = parsed.value else {
                return Ok(Step::Failed {
                    code: crate::error::codes::KDC_ERR_PREAUTH_FAILED,
                    text: "the challenge asked for the value and the request carries none".into(),
                });
            };
            (armor.clone(), armor.clone(), Some(value))
        };

        // The nonce is the whole replay defence: it was issued to this client, in this exchange,
        // and only the holder of the right key can send it back.
        let nonce =
            match request
                .cipher
                .decrypt(&nonce_key, KU_PA_OTP_REQUEST, &parsed.nonce_cipher.cipher)
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

        // With the value withheld there is nothing for a verifier to judge: the proof was the
        // nonce, which only the holder of the value's keys could seal. Asking a `Verifier` for an
        // empty value would turn a realm's own tokens into "not accepted".
        if must_encrypt {
            return Ok(Step::Done {
                endtime_bound: None,
                reply_key,
                padata: None,
            });
        }

        let Some(value) = clear_value else {
            // Both branches above set one of the two; reaching here would mean `must_encrypt` was
            // read two different ways in the same round, which is this function's problem and not
            // the client's.
            return Err(Error::Protocol(
                "OTP: the nonce was checked under one variant and the value read under the other"
                    .into(),
            ));
        };
        match self.verifier.verify(request.cname, &value) {
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
        let challenge = encode_challenge(&nonce, Some("cifs/host"), false);
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
        assert_eq!(
            decode_state(&encode_state(&nonce, false)).unwrap(),
            (nonce, false)
        );
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
    /// A realm that holds its tokens' values selects the `must-encrypt-nonce` variant.
    #[derive(Debug)]
    struct Tokens;

    impl OtpSource for Tokens {
        fn value(&self, client: &Principal) -> Option<String> {
            (client.name() == "alice").then(|| "123456".to_owned())
        }
    }

    impl Verifier for Tokens {
        fn verify(&self, _client: &Principal, _value: &str) -> Result<bool> {
            panic!("a realm that holds its values must not be asked to verify one")
        }
    }

    #[test]
    fn a_realm_with_values_sets_the_flag_and_a_realm_without_does_not() {
        let with = encode_challenge(&[1u8; 16], None, true);
        let without = encode_challenge(&[1u8; 16], None, false);
        assert_ne!(with, without, "the flag changes the challenge");
        // The flag is bit 6 of the token flags octet: 0x0400_0000 in `OTPFlags`, which is the third
        // octet from the end of a 32-bit BIT STRING.
        assert!(
            with.windows(2).any(|w| w == [0x04, 0x00]),
            "the must-encrypt-nonce bit is set"
        );
        assert!(
            !without.windows(2).any(|w| w == [0x04, 0x00]),
            "and clear in the other"
        );
    }

    /// The state carries the flag, and a state written without it still parses as a clear flag.
    #[test]
    fn the_state_remembers_which_variant_it_started() {
        let nonce = vec![9u8; 16];
        let (back, must) = decode_state(&encode_state(&nonce, true)).unwrap();
        assert_eq!(back, nonce);
        assert!(must, "the flag survives the cookie");
        let (back, must) = decode_state(&encode_state(&nonce, false)).unwrap();
        assert_eq!(back, nonce);
        assert!(!must, "and an absent flag is the RFC's default");
    }

    /// §3.6's derivation, computed here from the formula rather than asked of the code under test.
    ///
    /// This is what makes the test worth having: if both sides called the same helper, a wrong
    /// pepper or a missing base64 would agree with itself and every exchange would still pass.
    #[test]
    fn the_derived_keys_are_what_the_formula_says() {
        use base64::Engine as _;
        let cipher = crate::crypto::OwnCipher;
        let armor = cipher.random(crate::crypto::Enctype::Aes256Sha1).unwrap();
        let principal = Principal::parse("alice@EXAMPLE.COM").unwrap();
        let value = "123456";

        // Written out again, deliberately, from RFC 6560 §3.6.
        let mut secret = base64::engine::general_purpose::STANDARD
            .encode(value.as_bytes())
            .into_bytes();
        assert_eq!(
            String::from_utf8(secret.clone()).unwrap(),
            "MTIzNDU2",
            "the base64 of 123456, which the derivation feeds to string-to-key"
        );
        secret.extend_from_slice(b"Krb-preAuth");
        let k2 = cipher
            .s2k(
                crate::crypto::Enctype::Aes256Sha1,
                &secret,
                &principal.default_salt(),
                None,
            )
            .unwrap();
        let expected_client = crate::crypto::kdf::cf2(
            armor.bytes(),
            "OTPComb1",
            crate::crypto::Enctype::Aes256Sha1,
            k2.bytes(),
            "OTPComb2",
        )
        .unwrap();
        let expected_reply = crate::crypto::kdf::cf2(
            armor.bytes(),
            "OTPComb3",
            crate::crypto::Enctype::Aes256Sha1,
            k2.bytes(),
            "OTPComb4",
        )
        .unwrap();

        let (client, reply) = keys_from_value(&armor, value, &principal, &cipher).unwrap();
        assert_eq!(client.bytes(), expected_client, "the Client Key");
        assert_eq!(reply.bytes(), expected_reply, "the Reply Key");
        assert_ne!(
            client.bytes(),
            reply.bytes(),
            "the two keys are different, or the client key would decrypt the reply"
        );
    }

    /// A value that differs by one digit derives keys that differ everywhere.
    #[test]
    fn a_wrong_value_derives_different_keys() {
        let cipher = crate::crypto::OwnCipher;
        let armor = cipher.random(crate::crypto::Enctype::Aes256Sha1).unwrap();
        let principal = Principal::parse("alice@EXAMPLE.COM").unwrap();
        let (ok_client, ok_reply) = keys_from_value(&armor, "123456", &principal, &cipher).unwrap();
        let (bad_client, bad_reply) =
            keys_from_value(&armor, "123457", &principal, &cipher).unwrap();
        assert_ne!(ok_client.bytes(), bad_client.bytes());
        assert_ne!(ok_reply.bytes(), bad_reply.bytes());
    }

    /// The mechanism offers itself only inside FAST, and offers the flag when it holds values.
    #[test]
    fn the_mechanism_announces_only_inside_armor() {
        let cipher = crate::crypto::OwnCipher;
        let armor = cipher.random(crate::crypto::Enctype::Aes256Sha1).unwrap();
        let alice = Principal::parse("alice@EXAMPLE.COM").unwrap();
        let longterm = vec![armor.clone()];
        let body = vec![0u8; 4];

        let otp = Otp::new(Arc::new(Tokens)).with_source(Arc::new(Tokens));
        let unarmored = Request {
            cname: &alice,
            realm: "EXAMPLE.COM",
            body: &body,
            longterm: &longterm,
            armor: None,
            now: 1_700_000_000,
            cipher: &cipher,
        };
        assert!(
            otp.announce(&unarmored).unwrap().is_none(),
            "without armor there is nowhere to put the challenge, so nothing is offered"
        );

        let armored = Request {
            armor: Some(&armor),
            ..unarmored
        };
        let announced = otp.announce(&armored).unwrap().expect("a challenge");
        assert!(!announced.padata.is_empty());
        assert!(
            !announced.state.is_empty(),
            "the nonce travels in the cookie"
        );
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// The wire shape of the challenge, pinned octet by octet.
    ///
    /// A round trip through this module's own encoder and decoder would pass for an encoding that
    /// no client can read — both sides would share the mistake. The literal below is the check that
    /// comes from outside: `[2]` carries the token `SEQUENCE` *directly*, `nonce` carries the bytes
    /// *directly*, and the flag is bit 5 of a `KerberosFlags` word.
    #[test]
    fn the_challenge_on_the_wire_is_what_a_client_expects() {
        // 30 15                       SEQUENCE, 21 octets
        //   80 02 01 02                [0] nonce, IMPLICIT: the bytes, no OCTET STRING inside
        //   81 04 63 69 66 73          [1] otp-service "cifs", IMPLICIT
        //   a2 09                      [2] otp-tokenInfo, IMPLICIT over SEQUENCE OF
        //     30 07                    the one OTP-TOKENINFO
        //       80 05 00 04 00 00 00     [0] OTPFlags: unused=0, 0x0400_0000
        assert_eq!(
            hex(&encode_challenge(&[1, 2], Some("cifs"), true)),
            "301580020102810463696673a209300780050004000000"
        );
        // And with no service and no flag: three octets of zeros, one nesting level less than a
        // reader who assumes `[2] { SEQUENCE OF }` would look for.
        assert_eq!(
            hex(&encode_challenge(&[1, 2], None, false)),
            "300f80020102a209300780050000000000"
        );
    }

    /// Both variants read back the way they were written.
    #[test]
    fn a_challenge_round_trips_through_its_own_reader() {
        let without = Challenge::decode(&encode_challenge(&[7u8; 16], None, false)).unwrap();
        assert_eq!(without.nonce, vec![7u8; 16]);
        assert_eq!(without.service, None);
        assert_eq!(without.tokens, vec![TokenInfo { flags: 0 }]);
        assert!(!without.must_encrypt());

        let with =
            Challenge::decode(&encode_challenge(&[8u8; 16], Some("cifs/host"), true)).unwrap();
        assert_eq!(with.nonce, vec![8u8; 16]);
        assert_eq!(with.service.as_deref(), Some("cifs/host"));
        assert_eq!(with.tokens.len(), 1);
        assert!(
            with.must_encrypt(),
            "the flag survives the round trip; without it the client would send the value"
        );
        assert!(!with.tokens[0].collect_pin(), "and no PIN is asked for");
    }

    /// A token set with more than one entry, which the encoder does not emit and the reader must
    /// still read: §3.2 allows several, and a client that reads only the first would ignore the
    /// token the user actually holds.
    #[test]
    fn every_token_of_a_set_is_read() {
        let mut tokens = encode_token_info(OTP_FLAG_COLLECT_PIN);
        tokens.extend(encode_token_info(OTP_FLAG_MUST_ENCRYPT_NONCE));
        let challenge = der::seq(&[der::tlv(0x80, &[1u8; 16]), der::tlv(0xa2, &tokens)]);

        let decoded = Challenge::decode(&challenge).unwrap();
        assert_eq!(
            decoded.tokens,
            vec![
                TokenInfo {
                    flags: OTP_FLAG_COLLECT_PIN
                },
                TokenInfo {
                    flags: OTP_FLAG_MUST_ENCRYPT_NONCE
                },
            ],
            "both tokens, in the order sent"
        );
        assert!(
            decoded.must_encrypt(),
            "one usable token is enough to withhold the value"
        );
    }

    /// A challenge with no token, an empty nonce, or a token without flags is refused rather than
    /// half-read: each of those leaves the client with nothing to answer.
    #[test]
    fn an_unanswerable_challenge_is_refused() {
        let no_tokens = der::seq(&[der::tlv(0x80, &[1u8; 16]), der::tlv(0xa2, &[])]);
        assert!(Challenge::decode(&no_tokens).is_err(), "SIZE(1..MAX)");

        let empty_nonce = der::seq(&[der::tlv(0x80, &[]), der::tlv(0xa2, &encode_token_info(0))]);
        assert!(Challenge::decode(&empty_nonce).is_err(), "an empty nonce");

        // `flags [0] OTPFlags` has no OPTIONAL in the module, so its absence is not "no flags".
        let no_flags = der::seq(&[der::tlv(0x80, &[1u8; 16]), der::tlv(0xa2, &der::seq(&[]))]);
        assert!(Challenge::decode(&no_flags).is_err(), "flags are required");
    }
}
