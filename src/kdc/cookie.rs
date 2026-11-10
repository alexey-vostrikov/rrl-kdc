//! `PA-FX-COOKIE`: opaque KDC state a client hands back, RFC 6113 §5.4.2.3.
//!
//! A multi-round pre-authentication — SPAKE, OTP, anything that needs more than one message —
//! has to remember what happened in the previous round. There are two ways to do that: keep a
//! table of half-finished exchanges, or put the state in the client's hands encrypted. The
//! cookie is the second, and RFC 6113 prefers it because a KDC with a table is a KDC with a
//! memory limit an unauthenticated client can reach.
//!
//! Two properties carry the whole design:
//!
//! * **The client cannot read or alter it.** It is an `EncryptedData` under a realm key that
//!   nothing else uses. Reading it would tell an eavesdropper who is logging in; altering it
//!   would let one client finish another's exchange.
//! * **The KDC cannot be steered by it.** The cookie names the realm and the client it was
//!   issued to, and a cookie for somebody else — or an expired one, or one that does not open —
//!   is *ignored*, not refused. Refusing would let anyone who can rewrite a request make the
//!   KDC reject a legitimate login, which is a denial of service with a friendly error message.
//!
//! # What is not here
//!
//! Nothing in this crate produces two rounds yet: SPAKE and OTP are `RRL-3.24`. So the cookie
//! is written, issued in `PREAUTH_REQUIRED` and `PREAUTH_FAILED`, accepted, and its state
//! travels back — and that round trip is all it does today. The design is finished and the
//! state has nowhere to go until a mechanism writes into it; saying so is better than implying
//! the feature is complete because it compiles.

use crate::crypto::{Cipher, Key};
use crate::der;
use crate::error::{Error, Result};
use crate::name::Principal;

/// The domain separation for a cookie's key use.
///
/// Heimdal uses `KRB5_KU_H5L_COOKIE`, which is `-25` — outside the range RFC 3961 assigns, and
/// not representable as the `u32` this crate's crypto takes. 63 is unassigned by RFC 3961 and
/// RFC 4121, so it is free for a value that only this crate ever encrypts and decrypts. The
/// number is local by construction: a cookie never crosses a KDC boundary, so no other
/// implementation needs to agree with it.
pub const KU_COOKIE: u32 = 63;

/// The format version. A cookie that says another number is from a KDC this one cannot resume
/// from, and is dropped — the client simply starts again.
const VERSION: i64 = 1;

/// How long a cookie stays usable.
///
/// Short, because it is a claim about an exchange in progress: five minutes is longer than a
/// client retry and shorter than anything an attacker could usefully hold. Heimdal uses a
/// `FAST_EXPIRATION_TIME` of the same order.
pub const LIFETIME: i64 = 300;

/// The state a client carries between rounds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cookie {
    /// When the KDC issued this cookie.
    pub issued: i64,
    /// When it stops being usable.
    pub expiration: i64,
    /// The realm that issued it. A cookie from another realm proves nothing here.
    pub realm: String,
    /// Whose exchange this is. `None` only for a request that named no client, which a KDC
    /// answering `PREAUTH_REQUIRED` never sees.
    pub client: Option<Principal>,
    /// What a multi-round mechanism wants to remember. Opaque here by construction: the KDC
    /// copies it from one round to the next and never looks inside.
    pub state: Vec<u8>,
}

impl Cookie {
    /// A fresh cookie for `client` in `realm`, issued at `now`.
    pub fn new(realm: &str, client: Option<Principal>, state: Vec<u8>, now: i64) -> Self {
        Cookie {
            issued: now,
            expiration: now + LIFETIME,
            realm: realm.to_owned(),
            client,
            state,
        }
    }

    /// The octets that travel as the `PA-FX-COOKIE` value.
    ///
    /// An `EncryptedData`, because that is the smallest thing that gives both confidentiality
    /// and integrity with the primitives this crate already has — a separate MAC beside a
    /// ciphertext is one more thing to get wrong about ordering.
    pub fn encode(&self, cipher: &dyn Cipher, key: &Key) -> Result<Vec<u8>> {
        let plain = self.plaintext();
        let sealed = crate::msg::EncryptedData::seal(cipher, key, KU_COOKIE, None, &plain)?;
        Ok(sealed.encode())
    }

    /// The DER this cookie encrypts to: `SEQUENCE { version, issued, expiration, realm,
    /// client, state }`.
    fn plaintext(&self) -> Vec<u8> {
        let mut parts = vec![
            der::field(0, der::int(VERSION)),
            der::field(1, der::time(self.issued)),
            der::field(2, der::time(self.expiration)),
            der::field(3, der::general_string(&self.realm)),
        ];
        if let Some(client) = &self.client {
            parts.push(der::field(4, client.encode_name()));
        }
        parts.push(der::field(5, der::octets(&self.state)));
        der::seq(&parts)
    }

    /// Opens a cookie, without deciding whether it may be used: expiry and ownership are
    /// [`Cookie::accept`]'s business, because they depend on the request being answered.
    pub fn decode(cipher: &dyn Cipher, key: &Key, octets: &[u8]) -> Result<Cookie> {
        let sealed = crate::msg::EncryptedData::decode("PA-FX-COOKIE", octets)?;
        let plain = cipher.decrypt(key, KU_COOKIE, &sealed.cipher)?;
        // `plaintext` is a whole SEQUENCE: the field tags live inside it, one level down.
        let mut r = der::Reader::new(&plain);
        let content = r.expect_in("PA-FX-COOKIE", der::SEQUENCE)?;
        let f = der::Fields::parse("PA-FX-COOKIE", content)?;
        let version = f.int(0, "PA-FX-COOKIE")?;
        if version != VERSION {
            return Err(Error::Kdc {
                code: crate::error::codes::KDC_ERR_POLICY,
                text: format!("a cookie of version {version}, and this KDC writes {VERSION}"),
            });
        }
        let realm = f.string(3, "PA-FX-COOKIE")?;
        let client = f
            .opt_bytes(4)
            .map(|_| {
                // The name is stored as a whole `Principal` SEQUENCE inside the field, and
                // `Principal::decode` takes the content of that SEQUENCE.
                let mut nr = der::Reader::new(f.bytes(4, "PA-FX-COOKIE")?);
                let inner = nr.expect_in("PA-FX-COOKIE", der::SEQUENCE)?;
                Principal::decode("PA-FX-COOKIE", inner, &realm)
                    .map_err(Error::from)
            })
            .transpose()?;
        Ok(Cookie {
            issued: f.time(1, "PA-FX-COOKIE")?,
            expiration: f.time(2, "PA-FX-COOKIE")?,
            realm,
            client,
            state: f.octets(5, "PA-FX-COOKIE")?.to_vec(),
        })
    }

    /// Whether this cookie may be resumed for `client` in `realm` at `now`.
    ///
    /// A refusal here is not an error to send: the caller ignores the cookie and starts the
    /// exchange over. See the module comment for why that is not an error.
    pub fn accept(&self, now: i64, realm: &str, client: Option<&Principal>) -> Result<()> {
        if self.expiration < now {
            return Err(Error::Kdc {
                code: crate::error::codes::KDC_ERR_POLICY,
                text: format!("this cookie expired {} seconds ago", now - self.expiration),
            });
        }
        if !self.realm.eq_ignore_ascii_case(realm) {
            return Err(Error::Kdc {
                code: crate::error::codes::KDC_ERR_POLICY,
                text: format!("this cookie was issued by {}, not {realm}", self.realm),
            });
        }
        match (&self.client, client) {
            // `Principal`'s equality is realm and components, which is the identity a cookie
            // has to hold: the name type is not who the client is (RFC 6806 §6).
            (Some(mine), Some(theirs)) if mine != theirs => Err(Error::Kdc {
                code: crate::error::codes::KDC_ERR_POLICY,
                text: format!("this cookie belongs to {mine}, not {theirs}"),
            }),
            (Some(mine), None) => Err(Error::Kdc {
                code: crate::error::codes::KDC_ERR_POLICY,
                text: format!("this cookie belongs to {mine}, and the request names nobody"),
            }),
            _ => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Enctype;
    use crate::crypto::OwnCipher;

    fn key() -> Key {
        OwnCipher
            .s2k(Enctype::Aes256Sha1, b"cookie-secret", b"cookie", None)
            .unwrap()
    }

    #[test]
    fn a_cookie_round_trips_through_its_own_encoding() {
        let cipher = OwnCipher;
        let cookie = Cookie::new(
            "EXAMPLE.COM",
            Some(Principal::parse("alice@EXAMPLE.COM").unwrap()),
            b"state".to_vec(),
            1_700_000_000,
        );
        let octets = cookie.encode(&cipher, &key()).unwrap();
        let back = Cookie::decode(&cipher, &key(), &octets).unwrap();
        assert_eq!(back, cookie);
    }
}
