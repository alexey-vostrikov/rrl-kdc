//! FAST: the pre-authentication framework of RFC 6113.
//!
//! # The problem it solves, in one sentence
//!
//! Without FAST, an AS exchange hands an attacker everything needed for an offline
//! password search: `PA-ENC-TIMESTAMP` is sealed directly in the client's
//! long-term key, so a recorded exchange — or a stolen ticket — can be attacked at
//! leisure, with no further contact with the KDC.
//!
//! FAST puts the whole exchange inside an encryption whose key the client derived
//! from something it can throw away: the session key of an armoring ticket. What
//! travels outside is a wrapper that reveals nothing about the password. Getting
//! the password wrong then costs one guess per interaction with the KDC instead of
//! billions per second on a stolen file.
//!
//! # The shape of the exchange
//!
//! ```text
//! AS-REQ                                    PA-FX-FAST = [0] {
//!   PA-FX-FAST (136)                          armor        [0] KrbFastArmor {
//!                                                 armor-type  [0] 1
//!                                                 armor-value [1] <AP-REQ of a TGT>
//!                                               }
//!                                             req-checksum [1] Checksum(outer body)
//!                                             enc-fast-req [2] EncryptedData(armor key,
//!                                                              usage 51) {
//!                                               fast-options [0] BIT STRING
//!                                               padata       [1] METHOD-DATA
//!                                               req-body     [2] KDC-REQ-BODY
//!                                             }
//!                                           }
//!
//! AS-REP                                    PA-FX-FAST-REPLY (137) = [0] {
//!                                             enc-fast-rep [0] EncryptedData(armor key,
//!                                                              usage 52) {
//!                                               padata      [0] METHOD-DATA
//!                                               strengthen-key [1] OPTIONAL
//!                                               finished    [2] OPTIONAL
//!                                               nonce       [3] UInt32
//!                                             }
//!                                           }
//! ```
//!
//! # Wiring status
//!
//! This module is the layer, not the exchange: `unwrap` and `wrap_reply` are tested
//! against each other and against tampering, and **the engine does not call them
//! yet**. `handle_as` still answers an unarmored request, and a client that sends
//! `PA-FX-FAST` today gets a reply that ignores it.
//!
//! That gap is deliberate and stated rather than papered over: a half-wired FAST that
//! wrapped the request but left the reply's `enc-part` under the password-derived key
//! would claim a property it does not have, and the claim is the whole point of the
//! protocol. The remaining work for `TASQ-3.9` is the AS path — armor `AP-REQ`
//! validation, running the inner request, and putting `PA-FX-FAST-REPLY` into the
//! reply — plus a client that can drive it.
//!
//! # What is implemented, and what is not
//!
//! Armor by **explicit ticket** (`armor-type` 1, an `AP-REQ` for a TGT) — the case
//! that carries the security property, and the one a client uses after it already
//! holds a ticket.
//!
//! Armor by **cookie alone** (`PA-FX-COOKIE`, RFC 6113 §5.4.2.3) is *not*
//! implemented: a request that asks for it is refused with a clear code rather than
//! answered as if the exchange were armored. That mode is how a client with no
//! ticket at all bootstraps — it needs the cookie machinery and its own replay
//! rules, and pretending to support it would be worse than saying it is missing.
//!
//! `strengthen-key` and the `finished` verifier are not written either: the first
//! narrows a negotiated key the client already chose, and the second is a
//! confirmation a client may check. Neither is required for the property above, and
//! both are listed in `docs/ub-log.md` so nothing reads as supported that is not.

use crate::crypto::{Cipher, Enctype, Key};
use crate::der::{self, Fields, Reader};
use crate::error::{Error, Result};
use crate::msg::EncryptedData;

/// `PA-FX-FAST`: the client's armored request.
pub const PA_FX_FAST: i32 = 136;
/// The real `KRB-ERROR` inside an armored reply (RFC 6113 §5.4.2.5). Without this
/// the client sees an empty outer error and cannot learn how to pre-authenticate.
pub const PA_FX_ERROR: i32 = 137;

/// `PA-FX-FAST-REPLY`: the KDC's armored answer.
///
/// **136, the same number as the request.** RFC 6113 gives the request and the reply
/// one `PA-DATA` type because the direction decides which is meant; 137 is `PA-FX-ERROR`,
/// the real error *inside* an armored reply. Getting this wrong is invisible to a test
/// that reuses the constant on both sides — the armor round-trips perfectly and no
/// client that actually implements FAST will read it. A third-party client found it.
pub const PA_FX_FAST_REPLY: i32 = 136;

/// `PA-ENCRYPTED-CHALLENGE`: the pre-authentication of an armored exchange
/// (RFC 6113 §5.4.6). Inside FAST a `PA-ENC-TIMESTAMP` would be sealed in the
/// long-term key with nothing around it, which is the oracle FAST exists to remove —
/// so the challenge replaces it rather than accompanying it.
pub const PA_ENCRYPTED_CHALLENGE: i32 = 138;

/// `hide-client-names`, RFC 6113 §5.4.4.2: bit 1, which in `KerberosFlags` numbering is
/// the second-highest bit of the first octet.
pub const HIDE_CLIENT_NAMES: u32 = 0x4000_0000;

/// Bit 0, reserved for expansion.
const RESERVED_BIT: u32 = 0x8000_0000;

/// Bits 1 through 15 are the critical options; bit 16 and above are non-critical and must
/// be ignored by a conforming KDC.
const CRITICAL_MASK: u32 = 0x7fff_0000;

/// The critical `fast-options` bits this KDC implements: only `hide-client-names`.
const IMPLEMENTED: u32 = HIDE_CLIENT_NAMES;

/// The critical options in `bits` that this KDC does not implement, if any.
///
/// RFC 6113 §5.4.4.2 requires failing such a request with
/// `KDC_ERR_UNKNOWN_CRITICAL_FAST_OPTIONS`: the client asked for behaviour it will not
/// get, and answering anyway hands it a reply whose guarantees it will misread.
pub fn unsupported_critical(bits: u32) -> Option<u32> {
    let bad = bits & CRITICAL_MASK & !IMPLEMENTED;
    if bad != 0 {
        return Some(bad);
    }
    // The reserved bit is not in the critical range, and RFC 6113 neither requires failing
    // nor allows ignoring it explicitly. A client that sets it speaks a later version of
    // the framework, so the honest answer is a refusal rather than a reply it may not
    // understand.
    if bits & RESERVED_BIT != 0 {
        return Some(RESERVED_BIT);
    }
    None
}

/// A `fast-options` `BIT STRING` *content* for `options`, the inverse of
/// [`FastRequest::options`].
///
/// RFC 4120 declares `KerberosFlags ::= BIT STRING (SIZE (32..))`, so the encoding is
/// always four value octets with an unused count of zero — never the shortest form. A
/// client that trims trailing zero octets sends a bit string this KDC reads as a smaller
/// number, which for `hide-client-names` means "not requested".
pub fn options_bits(options: u32) -> Vec<u8> {
    let mut content = vec![0u8];
    content.extend_from_slice(&options.to_be_bytes());
    content
}

/// The principal a reply names under `hide-client-names` (RFC 6113 §5.4.4.2, RFC 6112).
///
/// `WELLKNOWN/ANONYMOUS@WELLKNOWN:ANONYMOUS` — the realm is not the client's, because the
/// whole point is that the reply no longer says which realm the client belongs to.
pub fn anonymous_principal() -> crate::name::Principal {
    crate::name::Principal::new(1, ["WELLKNOWN", "ANONYMOUS"], "WELLKNOWN:ANONYMOUS")
}

/// `PA-FX-COOKIE`: the stateless pre-authentication state a KDC hands back.
pub const PA_FX_COOKIE: i32 = 133;

/// Key usages of RFC 6113 §5.4.2 — separate from every other use of the armor key,
/// which is what keeps an armored request from being replayed as something else.
pub mod usage {
    /// The checksum over the outer request body.
    pub const FAST_REQ_CHKSUM: u32 = 50;
    /// The encryption of `KrbFastReq`.
    pub const FAST_ENC: u32 = 51;
    /// The encryption of `KrbFastResponse`.
    pub const FAST_REP: u32 = 52;
    /// The `finished` verifier's checksum.
    pub const FAST_FINISHED: u32 = 53;
    /// The AP-REQ authenticator — RFC 4120, not 6113, but the armor path needs it to
    /// read the subkey out of the armor's own AP-REQ.
    pub const AP_REQ_AUTH: u32 = 11;
    /// The client's encrypted challenge (RFC 6113 §7.5.1).
    pub const ENC_CHALLENGE_CLIENT: u32 = 54;
    /// The KDC's answer to it.
    pub const ENC_CHALLENGE_KDC: u32 = 55;
}

/// `KrbFastArmor`: how the armor key is established.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Armor {
    /// `armor-type [0]`. Only 1 — an `AP-REQ` — is defined by the specification.
    pub armor_type: i32,
    /// `armor-value [1]`: the `AP-REQ` itself when the type is 1.
    pub armor_value: Vec<u8>,
}

/// `KrbFastArmoredReq` inside `PA-FX-FAST-REQUEST`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArmoredRequest {
    /// Absent when the client relies on a cookie instead of a ticket.
    pub armor: Option<Armor>,
    /// `req-checksum [1]`: `(type, octets)` over the *outer* request body.
    pub req_checksum: (i32, Vec<u8>),
    /// `enc-fast-req [2]`.
    pub enc_fast_req: Vec<u8>,
}

impl ArmoredRequest {
    /// Decodes `PA-FX-FAST`'s value.
    ///
    /// `PA-FX-FAST-REQUEST ::= CHOICE { armored-data [0] KrbFastArmoredReq, ... }`:
    /// the value here is the content of the `[0]`, because `PA-DATA`'s `padata-value`
    /// is an `OCTET STRING` holding the whole encoded choice.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        let choice = r.next("PA-FX-FAST-REQUEST")?;
        if choice.tag != 0xa0 {
            return Err(Error::Protocol(format!(
                "PA-FX-FAST-REQUEST is {:#04x}, and only armored-data [0] is defined",
                choice.tag
            )));
        }
        // The CHOICE's content is the `KrbFastArmoredReq` SEQUENCE itself, so its own
        // tag and length come before the fields.
        let mut inside = Reader::new(choice.content);
        let sequence = inside.next("KrbFastArmoredReq")?;
        if sequence.tag != der::SEQUENCE {
            return Err(Error::Protocol(format!(
                "KrbFastArmoredReq is {:#04x}, not a SEQUENCE",
                sequence.tag
            )));
        }
        let f = Fields::parse("KrbFastArmoredReq", sequence.content)?;
        // `armor` is OPTIONAL and absent means "the client is relying on a cookie",
        // which `unwrap` refuses by name. A present-but-malformed armor is a
        // different matter and is refused here: a client that sent something is not
        // a client that sent nothing.
        let armor = match f.opt(0) {
            None => None,
            Some(raw) => {
                let inner = Fields::parse("KrbFastArmor", inner_sequence("KrbFastArmor", raw)?)?;
                Some(Armor {
                    armor_type: inner.int(0, "KrbFastArmor")? as i32,
                    armor_value: inner_octets("armor-value", inner.get(1, "KrbFastArmor")?)?
                        .to_vec(),
                })
            }
        };
        let checksum = Fields::parse(
            "Checksum",
            inner_sequence(
                "Checksum",
                f.opt(1)
                    .ok_or_else(|| Error::Protocol("PA-FX-FAST without req-checksum".into()))?,
            )?,
        )?;
        Ok(ArmoredRequest {
            armor,
            req_checksum: (
                checksum.int(0, "Checksum")? as i32,
                inner_octets("Checksum.checksum", checksum.get(1, "Checksum")?)?.to_vec(),
            ),
            enc_fast_req: f.get(2, "enc-fast-req")?.to_vec(),
        })
    }

    /// The DER of `PA-FX-FAST`'s value.
    pub fn encode(&self) -> Vec<u8> {
        let mut parts = Vec::new();
        if let Some(armor) = &self.armor {
            parts.push(der::field(
                0,
                der::seq(&[
                    der::field(0, der::int(armor.armor_type as i64)),
                    der::field(1, der::octets(&armor.armor_value)),
                ]),
            ));
        }
        parts.push(der::field(
            1,
            der::seq(&[
                der::field(0, der::int(self.req_checksum.0 as i64)),
                der::field(1, der::octets(&self.req_checksum.1)),
            ]),
        ));
        parts.push(der::field(2, self.enc_fast_req.clone()));
        der::cons(0xa0, &[der::seq(&parts)])
    }
}

/// The content of a `SEQUENCE` that a context-tagged field wraps.
///
/// `der::field(n, tlv)` puts the whole TLV as the field's content, so a reader that
/// takes the field gets the tag and length before the members. Every nested structure
/// in this module needs the same unwrapping, and doing it in one place keeps the
/// alternative — assuming the content starts at the first member — from creeping back
/// in one call site at a time.
/// The octets of an `OCTET STRING` that a context-tagged field wraps — the same
/// unwrapping as [`inner_sequence`], for the types that are not `SEQUENCE`s. A field
/// holding an `OCTET STRING` carries its tag and length before the value, and taking
/// the field's content as the value is off by two octets in every case here.
fn inner_octets<'a>(context: &'static str, raw: &'a [u8]) -> Result<&'a [u8]> {
    let mut r = Reader::new(raw);
    let octets = r.next(context)?;
    if octets.tag != der::OCTET_STRING {
        return Err(Error::Protocol(format!(
            "{context} is {:#04x}, not an OCTET STRING",
            octets.tag
        )));
    }
    Ok(octets.content)
}

fn inner_sequence<'a>(context: &'static str, raw: &'a [u8]) -> Result<&'a [u8]> {
    let mut r = Reader::new(raw);
    let sequence = r.next(context)?;
    if sequence.tag != der::SEQUENCE {
        return Err(Error::Protocol(format!(
            "{context} is {:#04x}, not a SEQUENCE",
            sequence.tag
        )));
    }
    Ok(sequence.content)
}

/// `KrbFastReq`: what the client actually asked for, once the wrapper is off.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FastRequest {
    /// `fast-options [0]`, as the raw `BIT STRING` content.
    pub fast_options: Vec<u8>,
    /// `padata [1]`: the real pre-authentication data, `PA-ENC-TIMESTAMP` included.
    pub padata: Vec<(i32, Vec<u8>)>,
    /// `req-body [2]`, kept as the exact `KDC-REQ-BODY` TLV: the inner body is what
    /// the AS exchange must act on, and its octets are what a checksum would cover.
    pub req_body: Vec<u8>,
}

impl FastRequest {
    /// Decodes a decrypted `KrbFastReq`.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        let seq = r.next("KrbFastReq")?;
        if seq.tag != der::SEQUENCE {
            return Err(Error::Protocol("KrbFastReq is not a SEQUENCE".into()));
        }
        let f = Fields::parse("KrbFastReq", seq.content)?;
        let mut p = Reader::new(f.get(1, "KrbFastReq")?);
        let padata =
            crate::msg::decode_pa_data("KrbFastReq", p.expect("KrbFastReq", der::SEQUENCE)?)?;
        // `[0]` wraps a `BIT STRING`, whose content is the unused-bit count followed by
        // the octets; the tag is unwrapped here so `options()` sees only the content.
        let fast_options = match f.opt(0) {
            None => Vec::new(),
            Some(raw) => {
                let mut r = Reader::new(raw);
                let bits = r.next("fast-options")?;
                if bits.tag != 0x03 {
                    return Err(Error::Protocol(format!(
                        "fast-options is {:#04x}, not a BIT STRING",
                        bits.tag
                    )));
                }
                bits.content.to_vec()
            }
        };
        Ok(FastRequest {
            fast_options,
            padata,
            req_body: f.get(2, "KrbFastReq")?.to_vec(),
        })
    }

    /// The DER of `KrbFastReq`.
    pub fn encode(&self) -> Vec<u8> {
        der::seq(&[
            der::field(0, der::cons(0x03, std::slice::from_ref(&self.fast_options))),
            der::field(1, crate::msg::encode_pa_data(&self.padata)),
            der::field(2, self.req_body.clone()),
        ])
    }

    /// The fast-options bits, as a number, **bit 0 the most significant**.
    ///
    /// `KerberosFlags` numbers its bits from the top, so bit 1 — RFC 6113's
    /// `hide-client-names` — is `0x4000_0000`, not `0x0000_0002`. Reading it the other way
    /// finds no option set in any real request and looks like "clients do not use this".
    pub fn options(&self) -> u32 {
        // Decoded by the same function the rest of the crate uses for `KerberosFlags`, so
        // that a bit constant means one thing everywhere. The first version of this looped
        // over the octets and shifted by the bit's position instead, producing a *logical
        // bit number* — flag 1 came out as `0x2` while every other flag constant in this
        // crate spells it `0x4000_0000`. Nothing ever matched, which is why the option was
        // read, parsed and then silently never applied.
        crate::der::as_flags32("fast-options", &self.fast_options).unwrap_or(0)
    }
}

/// Removes the wrapper: verifies the request checksum and decrypts the body.
///
/// `outer_body` is the exact `KDC-REQ-BODY` of the request that arrived — for an
/// AS-REQ the checksum covers it, which is what binds the wrapper to the request it
/// wraps and stops one armored body from being attached to another.
pub fn unwrap(
    armored: &ArmoredRequest,
    armor_key: &Key,
    outer_body: &[u8],
    cipher: &dyn Cipher,
) -> Result<FastRequest> {
    if armored.armor.is_none() {
        // Cookie-only armor is a different bootstrap with its own replay rules; see
        // the module documentation. Refusing is the honest answer.
        return Err(Error::Kdc {
            code: crate::error::codes::KDC_ERR_PREAUTH_FAILED,
            text: "PA-FX-FAST without armor: this KDC implements armoring by ticket, \
                   not the cookie bootstrap of RFC 6113 §5.4.2.3"
                .into(),
        });
    }
    cipher.verify_checksum(
        armor_key,
        usage::FAST_REQ_CHKSUM,
        outer_body,
        &armored.req_checksum.1,
    )?;
    let enc = EncryptedData::decode("enc-fast-req", &armored.enc_fast_req)?;
    let plain = cipher.decrypt(armor_key, usage::FAST_ENC, &enc.cipher)?;
    FastRequest::decode(&plain)
}

/// Wraps a reply: the `PA-FX-FAST-REPLY` value, or `None` when the request was not
/// armored and the reply travels in the clear as ordinary Kerberos.
///
/// `nonce` is echoed so that the client can tie the armored answer to the armored
/// request it sent.
pub fn wrap_reply(
    armor_key: &Key,
    padata: &[(i32, Vec<u8>)],
    strengthen_key: Option<&Key>,
    finished: Option<Vec<u8>>,
    nonce: u32,
    cipher: &dyn Cipher,
) -> Result<Vec<u8>> {
    let mut parts = vec![der::field(0, crate::msg::encode_pa_data(padata))];
    if let Some(sk) = strengthen_key {
        // `[1] EncryptionKey`: the client needs it to reconstruct the reply key, and
        // it travels only inside the armor, which is what keeps it from an attacker.
        parts.push(der::field(1, crate::msg::encode_key(sk)));
    }
    if let Some(fin) = finished {
        parts.push(der::field(2, fin));
    }
    parts.push(der::field(3, der::int(nonce as i64)));
    let response = der::seq(&parts);
    let enc = EncryptedData::seal(cipher, armor_key, usage::FAST_REP, None, &response)?;
    Ok(der::cons(0xa0, &[der::seq(&[der::field(0, enc.encode())])]))
}

/// The key the client sealed its `PA-ENCRYPTED-CHALLENGE` with (RFC 6113 §5.4.6).
///
/// `cf2(armor, "clientchallengearmor", long_term, "challengelongterm")`. Two secrets go
/// in: the armor key, which proves the client holds its TGT, and the long-term key,
/// which proves it knows the password. Either alone leaves the challenge replayable by
/// whoever holds that one — and a challenge replayable by the armor alone would make
/// every TGT a skeleton key.
pub fn client_challenge_key(armor_key: &Key, long_term: &Key) -> Result<Key> {
    let mixed = crate::crypto::kdf::cf2(
        armor_key.bytes(),
        "clientchallengearmor",
        long_term.enctype(),
        long_term.bytes(),
        "challengelongterm",
    )?;
    Key::new(long_term.enctype(), mixed)
}

/// The key the KDC answers the challenge with: the same construction under
/// `"kdcchallengearmor"`.
///
/// A different pepper, not a different secret: the point is that a client seeing this
/// decrypt can tell it is talking to a KDC that holds the long-term key, so a server
/// that merely relays the armor cannot impersonate one.
pub fn kdc_challenge_key(armor_key: &Key, long_term: &Key) -> Result<Key> {
    let mixed = crate::crypto::kdf::cf2(
        armor_key.bytes(),
        "kdcchallengearmor",
        long_term.enctype(),
        long_term.bytes(),
        "challengelongterm",
    )?;
    Key::new(long_term.enctype(), mixed)
}

/// The KDC's half of the encrypted challenge: a timestamp sealed in the KDC challenge
/// key, as `PA-ENCRYPTED-CHALLENGE` sends it.
pub fn kdc_challenge(
    cipher: &dyn Cipher,
    armor_key: &Key,
    long_term: &Key,
    time: i64,
    usec: u32,
) -> Result<Vec<u8>> {
    let key = kdc_challenge_key(armor_key, long_term)?;
    let ts = der::seq(&[
        der::field(0, der::time(time)),
        der::field(1, der::int(i64::from(usec))),
    ]);
    EncryptedData::seal(cipher, &key, usage::ENC_CHALLENGE_KDC, None, &ts).map(|e| e.encode())
}

/// `KrbFastFinished` (RFC 6113 §5.4.2.4): what makes an armored reply provably the
/// answer to *this* ticket.
///
/// The checksum covers the ticket in usage 53, so a KDC — or anything on the path —
/// cannot swap the ticket for another and keep the rest of the reply. MIT's client
/// refuses a reply without it, which is how this got implemented: the property is
/// "the ticket is the one the KDC issued", and a reply that merely decrypts does not
/// establish it.
pub fn finished(
    cipher: &dyn Cipher,
    armor_key: &Key,
    ticket: &[u8],
    client: &crate::name::Principal,
    time: i64,
    usec: u32,
) -> Result<Vec<u8>> {
    let checksum = cipher.checksum(armor_key, usage::FAST_FINISHED, ticket)?;
    Ok(der::seq(&[
        der::field(0, der::time(time)),
        der::field(1, der::int(i64::from(usec))),
        der::field(2, der::general_string(&client.realm)),
        der::field(3, client.encode_name()),
        der::field(
            4,
            der::seq(&[
                der::field(0, der::int(i64::from(armor_key.enctype().checksum_type()))),
                der::field(1, der::octets(&checksum)),
            ]),
        ),
    ]))
}

/// A `strengthen_key` and the reply key it produces (RFC 6113 §5.4.2.2).
///
/// The AS-REP's `enc-part` is sealed in the client's long-term key, and that is an
/// oracle: an attacker who recorded the exchange can try passwords against it. FAST
/// closes it by mixing a random per-exchange secret into the reply key —
/// `cf2(strengthen, "strengthenkey", reply, "replykey")` — and delivering that secret
/// only inside the armor. A guess cannot be checked without it, so the oracle is gone.
///
/// Doing without this would leave the *request* protected and the *reply* attackable,
/// which is the half-measure this module refuses to be.
pub fn strengthen(cipher: &dyn Cipher, reply_key: &Key) -> Result<(Key, Key)> {
    let strength = cipher.random(reply_key.enctype())?;
    let strengthened = crate::crypto::kdf::cf2(
        strength.bytes(),
        "strengthenkey",
        reply_key.enctype(),
        reply_key.bytes(),
        "replykey",
    )?;
    let key = Key::new(reply_key.enctype(), strengthened)?;
    Ok((strength, key))
}

/// The key an armored request is encrypted under: the session key of the ticket its
/// `AP-REQ` presents.
///
/// The caller validates the `AP-REQ` itself — that is the TGS exchange's job, and it
/// already does it for `PA-TGS-REQ` — and passes the session key here.
pub fn armor_supported(enctype: Enctype) -> bool {
    // Every enctype this crate implements can armor: the armor key is an ordinary
    // session key and needs no special handling.
    Enctype::from_id(enctype.id()).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::OwnCipher;

    fn key() -> Key {
        Key::new(Enctype::Aes256Sha1, vec![0x11u8; 32]).unwrap()
    }

    fn request() -> FastRequest {
        FastRequest {
            fast_options: vec![0, 0x40],
            padata: vec![(crate::msg::PA_ENC_TIMESTAMP, b"sealed-timestamp".to_vec())],
            req_body: der::seq(&[
                der::field(0, der::flags32(0x4081_0000)),
                der::field(2, der::general_string("EXAMPLE.COM")),
                der::field(7, der::int(0x1234)),
            ]),
        }
    }

    fn armored(inner: &FastRequest, outer_body: &[u8]) -> ArmoredRequest {
        let cipher = OwnCipher;
        let plain = inner.encode();
        let enc = EncryptedData::seal(&cipher, &key(), usage::FAST_ENC, None, &plain).unwrap();
        ArmoredRequest {
            armor: Some(Armor {
                armor_type: 1,
                armor_value: b"an-ap-req".to_vec(),
            }),
            req_checksum: (
                Enctype::Aes256Sha1.checksum_type(),
                cipher
                    .checksum(&key(), usage::FAST_REQ_CHKSUM, outer_body)
                    .unwrap(),
            ),
            enc_fast_req: enc.encode(),
        }
    }

    #[test]
    fn the_armored_request_round_trips_through_der() {
        let inner = request();
        let outer = der::seq(&[der::field(7, der::int(1))]);
        let request = armored(&inner, &outer);
        let decoded = ArmoredRequest::decode(&request.encode()).unwrap();
        assert_eq!(decoded, request);
        assert_eq!(decoded.armor.unwrap().armor_type, 1);
    }

    #[test]
    fn the_wrapper_yields_the_request_that_was_wrapped() {
        let inner = request();
        let outer = der::seq(&[der::field(7, der::int(1))]);
        let request = armored(&inner, &outer);
        let decoded = unwrap(&request, &key(), &outer, &OwnCipher).unwrap();
        assert_eq!(decoded, inner, "the inner request survives byte for byte");
    }

    #[test]
    fn a_body_that_is_not_the_one_checksummed_is_refused() {
        // The checksum binds the wrapper to the request it arrived in. Without this,
        // an armored body could be replayed inside somebody else's request — which is
        // the whole attack FAST exists to stop, in its cheapest form.
        let inner = request();
        let outer = der::seq(&[der::field(7, der::int(1))]);
        let request = armored(&inner, &outer);
        let other = der::seq(&[der::field(7, der::int(2))]);
        assert!(unwrap(&request, &key(), &other, &OwnCipher).is_err());
    }

    #[test]
    fn a_wrong_armor_key_does_not_open_the_body() {
        let inner = request();
        let outer = der::seq(&[der::field(7, der::int(1))]);
        let request = armored(&inner, &outer);
        let wrong = Key::new(Enctype::Aes256Sha1, vec![0x22u8; 32]).unwrap();
        assert!(unwrap(&request, &wrong, &outer, &OwnCipher).is_err());
    }

    #[test]
    fn a_request_without_armor_is_refused_by_name() {
        let inner = request();
        let outer = der::seq(&[der::field(7, der::int(1))]);
        let mut request = armored(&inner, &outer);
        request.armor = None;
        match unwrap(&request, &key(), &outer, &OwnCipher) {
            Err(Error::Kdc { text, .. }) => {
                assert!(
                    text.contains("cookie"),
                    "the refusal must say what is missing: {text}"
                );
            }
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    #[test]
    fn the_reply_round_trips_and_names_the_nonce() {
        let wrapped = wrap_reply(
            &key(),
            &[(crate::msg::PA_ETYPE_INFO2, b"salts".to_vec())],
            None,
            None,
            0x4242,
            &OwnCipher,
        )
        .unwrap();
        let mut r = Reader::new(&wrapped);
        let choice = r.next("PA-FX-FAST-REPLY").unwrap();
        assert_eq!(choice.tag, 0xa0);
        let mut inside = Reader::new(choice.content);
        let sequence = inside.next("KrbFastArmoredRep").unwrap();
        assert_eq!(sequence.tag, der::SEQUENCE);
        let f = Fields::parse("KrbFastArmoredRep", sequence.content).unwrap();
        let enc = EncryptedData::decode("enc-fast-rep", f.get(0, "enc-fast-rep").unwrap()).unwrap();
        let plain = OwnCipher
            .decrypt(&key(), usage::FAST_REP, &enc.cipher)
            .unwrap();
        let response = Fields::parse("KrbFastResponse", {
            let mut rr = Reader::new(&plain);
            let seq = rr.next("KrbFastResponse").unwrap();
            assert_eq!(seq.tag, der::SEQUENCE);
            seq.content
        })
        .unwrap();
        assert_eq!(response.int(3, "nonce").unwrap(), 0x4242);
    }

    #[test]
    fn the_fast_options_are_read_as_bits() {
        // The bit numbering is `KerberosFlags`': bit 0 is the most significant, so flag 1
        // is `0x4000_0000` — the same spelling `kdc_options::FORWARDABLE` uses for flag 1
        // of a different field. A test that pinned "flag 1 is 0x2" is what let the option
        // be parsed and then never matched against anything.
        let mut hide = request();
        hide.fast_options = options_bits(HIDE_CLIENT_NAMES);
        assert_eq!(hide.options(), 0x4000_0000, "hide-client-names is flag 1");

        let mut none = request();
        none.fast_options = options_bits(0);
        assert_eq!(none.options(), 0);

        let mut mixed = request();
        mixed.fast_options = options_bits(0x4000_8000);
        assert_eq!(
            mixed.options(),
            0x4000_8000,
            "flag 1 plus a non-critical flag 16"
        );

        // The reserved bit is flag 0, `0x8000_0000`.
        let mut reserved = request();
        reserved.fast_options = options_bits(0x8000_0000);
        assert_eq!(reserved.options(), 0x8000_0000);
    }

    #[test]
    fn the_option_encoding_keeps_the_full_width() {
        // `KerberosFlags ::= BIT STRING (SIZE (32..))`: four octets and an unused count of
        // zero. Trimming to the shortest form would make the same option read as a
        // smaller number on the other side.
        assert_eq!(options_bits(0), vec![0, 0, 0, 0, 0]);
        assert_eq!(options_bits(HIDE_CLIENT_NAMES), vec![0, 0x40, 0, 0, 0]);
    }

    #[test]
    fn only_the_implemented_critical_options_pass_the_check() {
        // Bit 1 is implemented; bits 2..=15 are critical and unknown; bit 16 onwards are
        // non-critical and must be ignored; bit 0 is reserved.
        assert_eq!(unsupported_critical(0), None);
        assert_eq!(unsupported_critical(HIDE_CLIENT_NAMES), None);
        assert_eq!(
            unsupported_critical(0x0000_8000),
            None,
            "flag 16 is non-critical"
        );
        assert_eq!(
            unsupported_critical(0x2000_0000),
            Some(0x2000_0000),
            "flag 2 is critical and undefined"
        );
        // Flag 15 is `1 << (31 - 15)` = `0x0001_0000`, the last critical one; flag 16 is
        // `0x0000_8000`, the first non-critical. One shift apart, opposite rules.
        assert_eq!(
            unsupported_critical(HIDE_CLIENT_NAMES | 0x0001_0000),
            Some(0x0001_0000),
            "flag 15 is critical"
        );
        assert_eq!(unsupported_critical(0x0000_8000), None, "flag 16 is not");
        assert_eq!(
            unsupported_critical(0x8000_0000),
            Some(0x8000_0000),
            "the reserved bit is refused rather than ignored"
        );
    }

    #[test]
    fn a_choice_that_is_not_armored_data_is_refused() {
        // `PA-FX-FAST-REQUEST` is a CHOICE, and only `[0]` is defined; anything else
        // is an extension this KDC does not know, and guessing would be worse than
        // saying so.
        let mut bytes = vec![0xa1, 0x00];
        assert!(ArmoredRequest::decode(&bytes).is_err());
        bytes[0] = 0x30;
        assert!(ArmoredRequest::decode(&bytes).is_err());
    }
}
