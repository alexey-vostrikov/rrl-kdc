//! The four AES enctypes and the Kerberos encryption profile over them,
//! behind a backend trait so two independent implementations can be checked
//! against the same vectors.
//!
//! Enctypes 17/18 are RFC 3962 (§5.3's "simplified profile": MAC over the
//! plaintext); 19/20 are RFC 8009 (§5: encrypt-then-MAC over `IV | C`, so the
//! receiver can check integrity *before* decrypting). They are written out
//! separately on purpose: a single routine parameterised by hash and key size
//! cannot serve both, because the octets that go under the MAC differ.
//!
//! # Two backends
//!
//! [`OwnCipher`] is this crate's implementation. The `crypto-rskrb5` feature
//! adds a second one over `rskrb5::crypto`, a third-party implementation of the
//! same RFCs. Every known-answer vector in `tests/` runs against both, so a
//! disagreement is caught by `cargo test` rather than by a client that cannot
//! log in.

pub mod aes_cts;
pub mod kdf;
pub mod nfold;

#[cfg(feature = "crypto-rskrb5")]
pub mod rskrb5_backend;

use std::sync::Arc;

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{Error, Result};
pub use kdf::{KeyUse, Sha2Kind, dk, dr, kdf_hmac_sha2, s2k, usage, usage_constant};

/// The AES block size, and the length of every Kerberos confounder.
pub const AES_BLOCK: usize = 16;

/// `aes{128,256}-cts-hmac-{sha1-96,sha256-128,sha384-192}`.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, PartialOrd, Ord)]
/// The four AES enctypes this crate implements.
pub enum Enctype {
    /// `aes128-cts-hmac-sha1-96` (RFC 3962).
    Aes128Sha1 = 17,
    /// `aes256-cts-hmac-sha1-96` (RFC 3962).
    Aes256Sha1 = 18,
    /// `aes128-cts-hmac-sha256-128` (RFC 8009).
    Aes128Sha256 = 19,
    /// `aes256-cts-hmac-sha384-192` (RFC 8009).
    Aes256Sha384 = 20,
}

#[cfg(feature = "serde")]
impl serde::Serialize for Enctype {
    /// The RFC 3961 number, as it appears on the wire and in every `krb5.conf`.
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_i32(self.id())
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Enctype {
    /// Refuses a number this KDC does not implement, rather than defaulting to
    /// one: a request asking for an enctype the caller could not have meant is a
    /// mistake worth reporting.
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        let id = i32::deserialize(deserializer)?;
        Enctype::from_id(id).ok_or_else(|| {
            serde::de::Error::custom(format!("enctype {id} is not one this KDC implements"))
        })
    }
}

impl Enctype {
    /// Strongest first: the order a KDC offers them in, and the order an
    /// `allowed_enctypes` list is matched in.
    pub const ALL: [Enctype; 4] = [
        Enctype::Aes256Sha384,
        Enctype::Aes256Sha1,
        Enctype::Aes128Sha256,
        Enctype::Aes128Sha1,
    ];

    /// The enctype with this RFC 3961 number, if it is one of the four.
    pub fn from_id(id: i32) -> Option<Self> {
        match id {
            17 => Some(Enctype::Aes128Sha1),
            18 => Some(Enctype::Aes256Sha1),
            19 => Some(Enctype::Aes128Sha256),
            20 => Some(Enctype::Aes256Sha384),
            _ => None,
        }
    }

    /// The name Heimdal and MIT print, and the one `krb5.conf` lists.
    pub fn from_name(name: &str) -> Option<Self> {
        match name.trim().to_ascii_lowercase().replace('_', "-").as_str() {
            "aes128-cts-hmac-sha1-96" | "aes128-sha1" | "aes-128" => Some(Enctype::Aes128Sha1),
            "aes256-cts-hmac-sha1-96" | "aes256-sha1" | "aes-256" => Some(Enctype::Aes256Sha1),
            "aes128-cts-hmac-sha256-128" | "aes128-sha2" => Some(Enctype::Aes128Sha256),
            "aes256-cts-hmac-sha384-192" | "aes256-sha2" => Some(Enctype::Aes256Sha384),
            _ => None,
        }
    }

    /// The RFC 3961 enctype number, as it appears on the wire.
    pub fn id(self) -> i32 {
        self as i32
    }

    /// The name Heimdal, MIT and `krb5.conf` use.
    pub fn name(self) -> &'static str {
        match self {
            Enctype::Aes128Sha1 => "aes128-cts-hmac-sha1-96",
            Enctype::Aes256Sha1 => "aes256-cts-hmac-sha1-96",
            Enctype::Aes128Sha256 => "aes128-cts-hmac-sha256-128",
            Enctype::Aes256Sha384 => "aes256-cts-hmac-sha384-192",
        }
    }

    /// The length of the protocol key `Ke`.
    pub fn key_len(self) -> usize {
        match self {
            Enctype::Aes128Sha1 | Enctype::Aes128Sha256 => 16,
            Enctype::Aes256Sha1 | Enctype::Aes256Sha384 => 32,
        }
    }

    /// The confounder is one cipher block for every enctype (RFC 3961 §5.3,
    /// RFC 8009 §5).
    /// The confounder length: one cipher block for every enctype.
    pub fn confounder_len(self) -> usize {
        AES_BLOCK
    }

    /// Truncated MAC length (RFC 3962 §6, RFC 8009 §6).
    pub fn mac_len(self) -> usize {
        match self {
            Enctype::Aes128Sha1 | Enctype::Aes256Sha1 => 12,
            Enctype::Aes128Sha256 => 16,
            Enctype::Aes256Sha384 => 24,
        }
    }

    /// The size of the derived integrity key `Ki`.
    ///
    /// RFC 3962 §5.3 sizes it exactly like the protocol key. RFC 8009 §5 gives
    /// `aes256-cts-hmac-sha384-192` a **192-bit** `Ki` and `Kc` against a
    /// 256-bit `Ke`, so for that enctype the integrity key is 24 octets, not
    /// 32. Deriving 32 and truncating the MAC instead produces a tag no peer
    /// agrees with — MIT's `crypto_tests` catches exactly this.
    pub fn integrity_key_len(self) -> usize {
        match self {
            Enctype::Aes256Sha384 => 24,
            other => other.key_len(),
        }
    }

    /// The size of the derived checksum key `Kc` (RFC 3962 §5.3, RFC 8009 §5).
    pub fn checksum_key_len(self) -> usize {
        self.integrity_key_len()
    }

    /// The keyed checksum type that goes with this enctype.
    pub fn checksum_type(self) -> i32 {
        match self {
            Enctype::Aes128Sha1 => 15,   // hmac-sha1-96-aes128
            Enctype::Aes256Sha1 => 16,   // hmac-sha1-96-aes256
            Enctype::Aes128Sha256 => 19, // hmac-sha256-128-aes128
            Enctype::Aes256Sha384 => 20, // hmac-sha384-192-aes256
        }
    }

    /// `None` for RFC 3962 (SHA-1), the hash family for RFC 8009.
    pub fn sha2_kind(self) -> Option<Sha2Kind> {
        match self {
            Enctype::Aes128Sha1 | Enctype::Aes256Sha1 => None,
            Enctype::Aes128Sha256 => Some(Sha2Kind::Sha256),
            Enctype::Aes256Sha384 => Some(Sha2Kind::Sha384),
        }
    }

    /// The default `s2kparams` iteration count (RFC 3962 §A.2, RFC 8009 §4).
    pub fn default_iterations(self) -> u32 {
        match self.sha2_kind() {
            None => kdf::DEFAULT_ITERATIONS_SHA1,
            Some(_) => kdf::DEFAULT_ITERATIONS_SHA2,
        }
    }

    /// Parses an `allowed_enctypes`-style list. Unknown names are refused: a
    /// configuration that names `rc4-hmac` and is silently given AES instead
    /// is worse than one that fails at startup.
    pub fn parse_list(names: &[&str]) -> Result<Vec<Enctype>> {
        let mut out = Vec::with_capacity(names.len());
        for n in names {
            // A name first, as `krb5.conf` writes it, then a number: the RFC 3961
            // number appears in `klist -e` output and in documentation, and an
            // operator pasting `18` should get the enctype rather than a message
            // claiming 18 is not implemented.
            let parsed = Enctype::from_name(n)
                .or_else(|| n.trim().parse::<i32>().ok().and_then(Enctype::from_id));
            match parsed {
                Some(e) if !out.contains(&e) => out.push(e),
                Some(_) => {}
                None => {
                    return Err(Error::Config(format!(
                        "enctype {n:?} is not one this KDC implements; it issues {} (RFC 3962 and RFC 8009 only)",
                        Enctype::ALL
                            .iter()
                            .map(|e| e.name())
                            .collect::<Vec<_>>()
                            .join(", ")
                    )));
                }
            }
        }
        Ok(out)
    }
}

/// A Kerberos key of a known enctype.
///
/// Bytes are zeroized on drop: a KDC holds the `krbtgt` key, and that key is
/// the realm.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
/// A Kerberos key of a known enctype.
pub struct Key {
    #[zeroize(skip)]
    enctype: Enctype,
    bytes: Vec<u8>,
}

impl std::fmt::Debug for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print key material: this type ends up in logs the moment a
        // struct containing it derives Debug.
        write!(
            f,
            "Key({}, {} octets)",
            self.enctype.name(),
            self.bytes.len()
        )
    }
}

impl Key {
    /// A key from its raw octets, which must be exactly the enctype's size.
    pub fn new(enctype: Enctype, bytes: impl Into<Vec<u8>>) -> Result<Self> {
        let bytes = bytes.into();
        if bytes.len() != enctype.key_len() {
            return Err(Error::KeyLength {
                enctype,
                want: enctype.key_len(),
                got: bytes.len(),
            });
        }
        Ok(Key { enctype, bytes })
    }

    /// The enctype these octets are a key for.
    pub fn enctype(&self) -> Enctype {
        self.enctype
    }

    /// The key material.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The key length in octets.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Always false: a zero-length key is refused by [`Key::new`].
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

/// The cryptographic operations a KDC performs, as a replaceable backend.
///
/// Every method takes the raw key rather than a backend-specific type, so
/// implementations share nothing but octets — which is the point: a
/// disagreement is then a disagreement about the wire, not about an API.
pub trait Cipher: std::fmt::Debug + Send + Sync {
    /// Which implementation this is, for logs and test names.
    fn name(&self) -> &'static str;

    /// A fresh random key, from the OS.
    fn random(&self, enctype: Enctype) -> Result<Key>;

    /// RFC 3962 §A / RFC 8009 §4 string-to-key.
    ///
    /// `params` is the `s2kparams` octet string from `ETYPE-INFO2`: four
    /// big-endian octets of iteration count, or `None` for the enctype default.
    fn s2k(
        &self,
        enctype: Enctype,
        password: &[u8],
        salt: &[u8],
        params: Option<&[u8]>,
    ) -> Result<Key>;

    /// The usage-specific key (DR/DK for 17/18, KDF-HMAC-SHA2 for 19/20).
    fn derive_key(
        &self,
        enctype: Enctype,
        base: &[u8],
        usage: u32,
        use_: KeyUse,
    ) -> Result<Vec<u8>>;

    /// Encrypt with a fresh random confounder.
    fn encrypt(&self, key: &Key, usage: u32, plaintext: &[u8]) -> Result<Vec<u8>>;

    /// Encrypt with a caller-supplied confounder — for known-answer vectors
    /// and deterministic tests. Never use it in production code: a repeated
    /// confounder under the same key breaks the profile's security.
    fn encrypt_with_confounder(
        &self,
        key: &Key,
        usage: u32,
        plaintext: &[u8],
        confounder: &[u8],
    ) -> Result<Vec<u8>>;

    /// Decrypt and verify in one call; nothing is returned unless the tag
    /// checks out.
    fn decrypt(&self, key: &Key, usage: u32, ciphertext: &[u8]) -> Result<Vec<u8>>;

    /// Keyed checksum (RFC 3961 §5.3, RFC 8009 §6).
    fn checksum(&self, key: &Key, usage: u32, data: &[u8]) -> Result<Vec<u8>>;

    /// Check a keyed checksum in constant time.
    fn verify_checksum(&self, key: &Key, usage: u32, data: &[u8], tag: &[u8]) -> Result<()> {
        let expected = self.checksum(key, usage, data)?;
        if ct_eq(&expected, tag) {
            Ok(())
        } else {
            Err(Error::Crypto("checksum mismatch".into()))
        }
    }
}

/// This crate's implementation of [`Cipher`].
#[derive(Debug, Clone, Copy, Default)]
pub struct OwnCipher;

impl OwnCipher {
    /// The backend, boxed for handing to a KDC.
    pub fn backend() -> Arc<dyn Cipher> {
        Arc::new(OwnCipher)
    }
}

impl Cipher for OwnCipher {
    fn name(&self) -> &'static str {
        "own"
    }

    fn random(&self, enctype: Enctype) -> Result<Key> {
        let mut bytes = vec![0u8; enctype.key_len()];
        getrandom::fill(&mut bytes).map_err(|e| Error::Crypto(format!("getrandom: {e}")))?;
        Key::new(enctype, bytes)
    }

    fn s2k(
        &self,
        enctype: Enctype,
        password: &[u8],
        salt: &[u8],
        params: Option<&[u8]>,
    ) -> Result<Key> {
        Key::new(enctype, kdf::s2k(enctype, password, salt, params)?)
    }

    fn derive_key(
        &self,
        enctype: Enctype,
        base: &[u8],
        usage: u32,
        use_: KeyUse,
    ) -> Result<Vec<u8>> {
        kdf::derive_key(enctype, base, usage, use_)
    }

    fn encrypt(&self, key: &Key, usage: u32, plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut confounder = vec![0u8; key.enctype().confounder_len()];
        getrandom::fill(&mut confounder).map_err(|e| Error::Crypto(format!("getrandom: {e}")))?;
        self.encrypt_with_confounder(key, usage, plaintext, &confounder)
    }

    fn encrypt_with_confounder(
        &self,
        key: &Key,
        usage: u32,
        plaintext: &[u8],
        confounder: &[u8],
    ) -> Result<Vec<u8>> {
        let e = key.enctype();
        if confounder.len() != e.confounder_len() {
            return Err(Error::Crypto(format!(
                "confounder is {} octets, {} needs {}",
                confounder.len(),
                e.name(),
                e.confounder_len()
            )));
        }
        let mut plain = Vec::with_capacity(confounder.len() + plaintext.len());
        plain.extend_from_slice(confounder);
        plain.extend_from_slice(plaintext);

        let ke = kdf::derive_key(e, key.bytes(), usage, KeyUse::Encrypt)?;
        let ki = kdf::derive_key(e, key.bytes(), usage, KeyUse::Integrity)?;
        let zero_iv = [0u8; AES_BLOCK];

        match e.sha2_kind() {
            // RFC 3961 §5.3: the MAC covers the plaintext and follows it.
            None => {
                let mut out = aes_cts::encrypt(&ke, &zero_iv, &plain)?;
                let tag = hmac_by(e, &ki, &plain)?;
                out.extend_from_slice(&tag[..e.mac_len()]);
                Ok(out)
            }
            // RFC 8009 §5: the MAC covers `IV | C`, so it can be checked
            // before decrypting.
            Some(_) => {
                let cipher = aes_cts::encrypt(&ke, &zero_iv, &plain)?;
                let mut macced = Vec::with_capacity(AES_BLOCK + cipher.len());
                macced.extend_from_slice(&zero_iv);
                macced.extend_from_slice(&cipher);
                let tag = hmac_by(e, &ki, &macced)?;
                let mut out = cipher;
                out.extend_from_slice(&tag[..e.mac_len()]);
                Ok(out)
            }
        }
    }

    fn decrypt(&self, key: &Key, usage: u32, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let e = key.enctype();
        let mac_len = e.mac_len();
        if ciphertext.len() < AES_BLOCK + mac_len {
            return Err(Error::Crypto(format!(
                "ciphertext is {} octets; {} needs at least {}",
                ciphertext.len(),
                e.name(),
                AES_BLOCK + mac_len
            )));
        }
        let (cipher, tag) = ciphertext.split_at(ciphertext.len() - mac_len);
        let ke = kdf::derive_key(e, key.bytes(), usage, KeyUse::Encrypt)?;
        let ki = kdf::derive_key(e, key.bytes(), usage, KeyUse::Integrity)?;
        let zero_iv = [0u8; AES_BLOCK];

        let plain = match e.sha2_kind() {
            None => {
                let plain = aes_cts::decrypt(&ke, &zero_iv, cipher)?;
                let expect = hmac_by(e, &ki, &plain)?;
                if !ct_eq(&expect[..mac_len], tag) {
                    return Err(Error::Crypto("integrity check failed".into()));
                }
                plain
            }
            Some(_) => {
                let mut macced = Vec::with_capacity(AES_BLOCK + cipher.len());
                macced.extend_from_slice(&zero_iv);
                macced.extend_from_slice(cipher);
                let expect = hmac_by(e, &ki, &macced)?;
                if !ct_eq(&expect[..mac_len], tag) {
                    return Err(Error::Crypto("integrity check failed".into()));
                }
                aes_cts::decrypt(&ke, &zero_iv, cipher)?
            }
        };

        if plain.len() < e.confounder_len() {
            return Err(Error::Crypto(
                "decrypted plaintext is shorter than the confounder".into(),
            ));
        }
        Ok(plain[e.confounder_len()..].to_vec())
    }

    fn checksum(&self, key: &Key, usage: u32, data: &[u8]) -> Result<Vec<u8>> {
        let kc = kdf::derive_key(key.enctype(), key.bytes(), usage, KeyUse::Checksum)?;
        let tag = hmac_by(key.enctype(), &kc, data)?;
        Ok(tag[..key.enctype().mac_len()].to_vec())
    }
}

fn hmac_by(enctype: Enctype, key: &[u8], msg: &[u8]) -> Result<Vec<u8>> {
    use hmac::{Hmac, KeyInit, Mac};
    use sha1::Sha1;
    use sha2::{Sha256, Sha384};
    Ok(match enctype.sha2_kind() {
        None => {
            let mut m = <Hmac<Sha1> as KeyInit>::new_from_slice(key)
                .map_err(|_| Error::Crypto("HMAC-SHA1 key".into()))?;
            m.update(msg);
            m.finalize().into_bytes().to_vec()
        }
        Some(Sha2Kind::Sha256) => {
            let mut m = <Hmac<Sha256> as KeyInit>::new_from_slice(key)
                .map_err(|_| Error::Crypto("HMAC-SHA256 key".into()))?;
            m.update(msg);
            m.finalize().into_bytes().to_vec()
        }
        Some(Sha2Kind::Sha384) => {
            let mut m = <Hmac<Sha384> as KeyInit>::new_from_slice(key)
                .map_err(|_| Error::Crypto("HMAC-SHA384 key".into()))?;
            m.update(msg);
            m.finalize().into_bytes().to_vec()
        }
    })
}

/// Constant-time equality for tags and keys.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enctype_table_is_self_consistent() {
        for e in Enctype::ALL {
            assert_eq!(Enctype::from_id(e.id()), Some(e));
            assert_eq!(Enctype::from_name(e.name()), Some(e));
            assert_eq!(e.key_len(), if e.id() % 2 == 0 { 32 } else { 16 });
            assert!(e.mac_len() >= 12);
        }
        assert_eq!(
            Enctype::from_id(23),
            None,
            "RC4 is not implemented on purpose"
        );
    }

    #[test]
    fn enctype_list_refuses_what_it_cannot_issue() {
        assert_eq!(
            Enctype::parse_list(&["aes256-cts-hmac-sha1-96", "aes128-cts-hmac-sha1-96"]).unwrap(),
            vec![Enctype::Aes256Sha1, Enctype::Aes128Sha1]
        );
        // Duplicates collapse; unknown names are refused, not ignored.
        assert_eq!(
            Enctype::parse_list(&["aes-256", "aes256-sha1"]).unwrap(),
            vec![Enctype::Aes256Sha1]
        );
        assert!(Enctype::parse_list(&["rc4-hmac"]).is_err());
        assert!(Enctype::parse_list(&["des3-cbc-sha1"]).is_err());
    }

    fn cipher() -> OwnCipher {
        OwnCipher
    }

    #[test]
    fn round_trip_all_enctypes() {
        let c = cipher();
        for e in Enctype::ALL {
            let key = c.random(e).unwrap();
            let ct = c
                .encrypt(&key, usage::AS_REP_ENCPART, b"hello ticket")
                .unwrap();
            let pt = c.decrypt(&key, usage::AS_REP_ENCPART, &ct).unwrap();
            assert_eq!(pt, b"hello ticket", "{}", e.name());
        }
    }

    #[test]
    fn wrong_usage_fails_the_integrity_check() {
        let c = cipher();
        for e in Enctype::ALL {
            let key = c.random(e).unwrap();
            let ct = c
                .encrypt(&key, usage::AS_REP_ENCPART, b"encrypted part")
                .unwrap();
            assert!(
                c.decrypt(&key, usage::KDC_REP_TICKET, &ct).is_err(),
                "{} accepted a foreign usage",
                e.name()
            );
        }
    }

    #[test]
    fn a_flipped_bit_is_refused() {
        let c = cipher();
        for e in Enctype::ALL {
            let key = c.random(e).unwrap();
            let mut ct = c
                .encrypt(&key, usage::KDC_REP_TICKET, b"ticket body")
                .unwrap();
            let last = ct.len() - 1;
            ct[last] ^= 1;
            assert!(
                c.decrypt(&key, usage::KDC_REP_TICKET, &ct).is_err(),
                "{}",
                e.name()
            );
        }
    }

    #[test]
    fn checksums_round_trip_and_refuse_a_foreign_usage() {
        let c = cipher();
        for e in Enctype::ALL {
            let key = c.random(e).unwrap();
            let tag = c
                .checksum(&key, usage::TGS_REQ_AUTH_CKSUM, b"req-body")
                .unwrap();
            assert_eq!(tag.len(), e.mac_len());
            c.verify_checksum(&key, usage::TGS_REQ_AUTH_CKSUM, b"req-body", &tag)
                .unwrap();
            assert!(
                c.verify_checksum(&key, usage::AP_REQ_AUTH_CKSUM, b"req-body", &tag)
                    .is_err()
            );
        }
    }

    #[test]
    fn key_length_is_enforced() {
        assert!(Key::new(Enctype::Aes256Sha1, vec![0u8; 16]).is_err());
        assert!(Key::new(Enctype::Aes128Sha1, vec![0u8; 32]).is_err());
    }

    #[test]
    fn debug_does_not_leak_key_material() {
        let key = Key::new(Enctype::Aes128Sha1, vec![0x41u8; 16]).unwrap();
        let printed = format!("{key:?}");
        assert!(!printed.contains("41"), "{printed}");
        assert!(printed.contains("16 octets"), "{printed}");
    }

    #[test]
    fn a_short_confounder_is_refused() {
        let c = cipher();
        let key = c.random(Enctype::Aes128Sha1).unwrap();
        assert!(c.encrypt_with_confounder(&key, 3, b"x", &[0u8; 8]).is_err());
    }
}
