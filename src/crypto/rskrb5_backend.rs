//! A second [`Cipher`] over `rskrb5::crypto`.
//!
//! This backend exists to disagree with ours, loudly, if either is wrong. It is
//! not a dependency of the protocol engine: the KDC never requires it, and
//! `cargo test --features crypto-rskrb5` runs every known-answer vector against
//! both implementations.
//!
//! Three differences between the two APIs are absorbed here, and each is a
//! place where an adapter can silently lose correctness:
//!
//! * `s2kparams` is a **hex string** of eight characters in `rskrb5`, not four
//!   octets. Passing the decimal rendering would yield a wrong-but-plausible
//!   key, so the conversion is done once, here, with a test.
//! * `rskrb5` names its own enctypes; the mapping is by number, and an enctype
//!   it does not have is an error rather than a guess.
//! * `AesSha2Etype::derive_key` takes a **label**, while the RFC 3961 path
//!   takes a 5-octet constant — both are "the thing being derived", so the
//!   call sites are shaped the same but the bytes are computed by that crate.

use rskrb5::crypto::KerberosEtype;

use super::{Cipher, Enctype, Key, KeyUse, Sha2Kind, ct_eq};
use crate::error::{Error, Result};

/// `rskrb5`'s crypto behind this crate's [`Cipher`] trait.
#[derive(Debug, Clone, Copy, Default)]
pub struct Rskrb5Cipher;

impl Rskrb5Cipher {
    /// The backend, boxed for handing to a KDC or to a test harness.
    pub fn backend() -> std::sync::Arc<dyn Cipher> {
        std::sync::Arc::new(Rskrb5Cipher)
    }
}

fn map(enctype: Enctype) -> Result<KerberosEtype> {
    KerberosEtype::from_etype_id(enctype.id())
        .ok_or_else(|| Error::Crypto(format!("rskrb5 has no enctype {}", enctype.id())))
}

fn crypto_error(e: impl std::fmt::Display) -> Error {
    Error::Crypto(format!("rskrb5: {e}"))
}

/// The four-octet iteration count rendered the way `rskrb5` wants it: eight
/// hex characters. `None` means "the enctype's default", which for `rskrb5` is
/// the only s2kparams string it accepts implicitly.
fn s2kparams_hex(params: Option<&[u8]>) -> Result<String> {
    match params {
        None | Some([]) => Ok(String::new()),
        Some(p) if p.len() >= 4 => Ok(format!("{:02x}{:02x}{:02x}{:02x}", p[0], p[1], p[2], p[3])),
        Some(p) => Err(Error::Crypto(format!(
            "s2kparams is {} octets, expected 4",
            p.len()
        ))),
    }
}

impl Cipher for Rskrb5Cipher {
    fn name(&self) -> &'static str {
        "rskrb5"
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
        let hex_params = s2kparams_hex(params)?;
        let key = match map(enctype)? {
            KerberosEtype::Sha1(e) => e.string_to_key(password, salt, &hex_params),
            KerberosEtype::Sha2(e) => e.string_to_key(password, salt, &hex_params),
            other => {
                return Err(Error::Crypto(format!(
                    "rskrb5 backend does not serve {other:?}; this KDC issues AES only"
                )));
            }
        }
        .map_err(crypto_error)?;
        Key::new(enctype, key)
    }

    fn derive_key(
        &self,
        enctype: Enctype,
        base: &[u8],
        usage: u32,
        use_: KeyUse,
    ) -> Result<Vec<u8>> {
        let constant = super::usage_constant(usage, use_);
        match map(enctype)? {
            KerberosEtype::Sha1(e) => e.derive_key(base, &constant),
            KerberosEtype::Sha2(e) => e.derive_key(base, &constant),
            other => {
                return Err(Error::Crypto(format!(
                    "rskrb5 backend does not serve {other:?}"
                )));
            }
        }
        .map_err(crypto_error)
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
        if confounder.len() != key.enctype().confounder_len() {
            return Err(Error::Crypto(format!(
                "confounder is {} octets, {} needs {}",
                confounder.len(),
                key.enctype().name(),
                key.enctype().confounder_len()
            )));
        }
        match map(key.enctype())? {
            KerberosEtype::Sha1(e) => {
                e.encrypt_message_with_confounder(key.bytes(), plaintext, usage, confounder)
            }
            KerberosEtype::Sha2(e) => {
                e.encrypt_message_with_confounder(key.bytes(), plaintext, usage, confounder)
            }
            other => {
                return Err(Error::Crypto(format!(
                    "rskrb5 backend does not serve {other:?}"
                )));
            }
        }
        .map_err(crypto_error)
    }

    fn decrypt(&self, key: &Key, usage: u32, ciphertext: &[u8]) -> Result<Vec<u8>> {
        match map(key.enctype())? {
            KerberosEtype::Sha1(e) => e.decrypt_message(key.bytes(), ciphertext, usage),
            KerberosEtype::Sha2(e) => e.decrypt_message(key.bytes(), ciphertext, usage),
            other => {
                return Err(Error::Crypto(format!(
                    "rskrb5 backend does not serve {other:?}"
                )));
            }
        }
        .map_err(crypto_error)
    }

    fn checksum(&self, key: &Key, usage: u32, data: &[u8]) -> Result<Vec<u8>> {
        match map(key.enctype())? {
            KerberosEtype::Sha1(e) => e.checksum(key.bytes(), data, usage),
            KerberosEtype::Sha2(e) => e.checksum(key.bytes(), data, usage),
            other => {
                return Err(Error::Crypto(format!(
                    "rskrb5 backend does not serve {other:?}"
                )));
            }
        }
        .map_err(crypto_error)
    }

    fn verify_checksum(&self, key: &Key, usage: u32, data: &[u8], tag: &[u8]) -> Result<()> {
        let expected = self.checksum(key, usage, data)?;
        if ct_eq(&expected, tag) {
            Ok(())
        } else {
            Err(Error::Crypto("checksum mismatch".into()))
        }
    }
}

/// `Sha2Kind` is used only to keep the import list honest in this module: the
/// mapping to `rskrb5`'s enctypes is by number, not by hash family, so a future
/// enctype that swaps the hash cannot be silently mis-mapped here.
#[allow(dead_code)]
fn _assert_sha2_mapping(enctype: Enctype) -> Option<Sha2Kind> {
    enctype.sha2_kind()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn s2kparams_become_eight_hex_characters() {
        assert_eq!(
            s2kparams_hex(Some(&4096u32.to_be_bytes())).unwrap(),
            "00001000"
        );
        assert_eq!(
            s2kparams_hex(Some(&32768u32.to_be_bytes())).unwrap(),
            "00008000"
        );
        assert_eq!(s2kparams_hex(None).unwrap(), "");
        assert!(s2kparams_hex(Some(&[0, 1])).is_err());
    }

    #[test]
    fn every_enctype_this_crate_issues_has_a_backend() {
        for e in Enctype::ALL {
            assert!(map(e).is_ok(), "{} is not mapped", e.name());
        }
        // The backend would happily serve RC4; this crate must not ask it to.
        assert!(map(Enctype::Aes128Sha1).is_ok());
    }
}
