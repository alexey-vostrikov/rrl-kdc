//! The realm's master key: the key an entry's keys are stored under.
//!
//! A KDC's database holds one key per principal, and those keys are the realm: whoever reads them can
//! forge a ticket for any principal. Storing them in the clear makes the database file as valuable as
//! the KDC itself. So Heimdal stores each key **encrypted under the master key**, which lives in its
//! own file (`kstash`'s output) and is the one secret an operator guards.
//!
//! **The construction is one `krb5_encrypt`** with a usage of its own:
//!
//! ```text
//! sealed = encrypt(master_key, usage 0x484442, key_bytes)
//! ```
//!
//! `HDB_KU_MKEY` is `0x484442` in `lib/hdb/hdb.h` — deliberately not a small RFC 4120 usage number,
//! because this is not a protocol message: it is a realm's private storage decision, and giving it a
//! number the protocol also uses would let a captured ciphertext be replayed across the two.
//!
//! For AES-256-SHA1 that makes a sealed key 16 (confounder) + 32 (key) + 12 (tag) = **60 octets**,
//! which is the number an operator sees when a sealed database reaches a KDC that cannot open it.
//!
//! **Where the master key comes from: a keytab.** `kstash` writes `hdb_write_master_key`, which is
//! `krb5_kt_add_entry` for a principal `K/M@REALM` — so Heimdal's own stash file *is* a keytab, and
//! this crate's [`Keytab`](super::keytab::Keytab) reads it without a second format. Older formats
//! (`read_master_mit`, a bare `int16` enctype and a length-prefixed key; `read_master_encryptionkey`,
//! an `EncryptionKey` DER) are read by Heimdal and are not read here: a realm on a release from this
//! century uses the keytab, and a reader for a retired format is a place for a bug to live.
//!
//! **Several master keys at once is normal.** Rolling the master key adds a new one and leaves the
//! old one until every entry has been re-sealed; `Key.mkvno` says which sealed each entry, and the
//! set is searched by it. A set that does not contain the number an entry names is a refusal:
//! guessing another key would fail the tag check and report a corrupt database rather than a missing
//! key.

use crate::crypto::{Cipher, Enctype, Key};
use crate::error::{Error, Result};
use crate::name::Principal;

use super::keytab::Keytab;

/// `HDB_KU_MKEY` (`lib/hdb/hdb.h`): the usage a stored key is sealed under.
pub const HDB_KU_MKEY: u32 = 0x484442;

/// The principal a master keytab carries.
pub const MASTER_PRINCIPAL: &str = "K/M";

/// One master key, with the version number that names it.
#[derive(Debug, Clone)]
pub struct MasterKey {
    /// The key itself.
    pub key: Key,
    /// `kvno`: the version, which every sealed key records as `mkvno`.
    pub kvno: u32,
}

/// The master keys a realm has: one per version, newest first.
#[derive(Debug, Clone, Default)]
pub struct MasterKeys {
    keys: Vec<MasterKey>,
}

impl MasterKeys {
    /// An empty set: a realm that stores its keys in the clear.
    pub fn none() -> MasterKeys {
        MasterKeys::default()
    }

    /// A set with one key.
    pub fn single(key: Key, kvno: u32) -> MasterKeys {
        MasterKeys {
            keys: vec![MasterKey { key, kvno }],
        }
    }

    /// Reads the master keytab at `path`.
    ///
    /// Every entry for `K/M` (any realm) is a master key; the version is the entry's `kvno`, which is
    /// what `kstash` writes and what a sealed key's `mkvno` refers to.
    pub fn from_keytab(path: impl AsRef<std::path::Path>) -> Result<MasterKeys> {
        let path = path.as_ref();
        let keytab = Keytab::load(path)?;
        let mut keys: Vec<MasterKey> = keytab
            .entries()
            .iter()
            .filter(|entry| {
                entry.principal.components.len() == 1
                    && entry.principal.components[0] == "M"
                    && entry.principal.name_type != 0
            })
            .map(|entry| MasterKey {
                key: entry.key.clone(),
                kvno: entry.kvno,
            })
            .collect();
        // `K/M` with the name type the keytab records; a keytab may also name it with two components
        // in a realm of its own, so both shapes are accepted and the filter above is by name.
        if keys.is_empty() {
            keys = keytab
                .entries()
                .iter()
                .filter(|entry| entry.principal.components.join("/") == MASTER_PRINCIPAL)
                .map(|entry| MasterKey {
                    key: entry.key.clone(),
                    kvno: entry.kvno,
                })
                .collect();
        }
        if keys.is_empty() {
            return Err(Error::Hdb(format!(
                "{}: no {} principal in it, so it does not hold a master key",
                path.display(),
                MASTER_PRINCIPAL
            )));
        }
        keys.sort_by_key(|k| std::cmp::Reverse(k.kvno));
        Ok(MasterKeys { keys })
    }

    /// Builds a set from pairs, for a caller that has the key material already.
    pub fn from_keys(keys: impl IntoIterator<Item = (Key, u32)>) -> MasterKeys {
        let mut keys: Vec<MasterKey> = keys
            .into_iter()
            .map(|(key, kvno)| MasterKey { key, kvno })
            .collect();
        keys.sort_by_key(|k| std::cmp::Reverse(k.kvno));
        MasterKeys { keys }
    }

    /// Whether the set holds anything.
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// Every key, newest first.
    pub fn keys(&self) -> &[MasterKey] {
        &self.keys
    }

    /// The key numbered `kvno`, or the newest when the caller does not know the number.
    ///
    /// `None` and not a fallback: a `kvno` that names nothing means the set is missing a key the
    /// database needs, and sealing or opening with a different one produces a tag failure that reads
    /// as corruption.
    pub fn get(&self, kvno: Option<u32>) -> Option<&MasterKey> {
        match kvno {
            Some(kvno) => self.keys.iter().find(|k| k.kvno == kvno),
            None => self.keys.first(),
        }
    }

    /// Seals `key_bytes` under the newest master key, returning the ciphertext and the `mkvno` it was
    /// sealed with.
    pub fn seal(&self, cipher: &dyn Cipher, key_bytes: &[u8]) -> Result<(Vec<u8>, u32)> {
        let mkey = self
            .get(None)
            .ok_or_else(|| Error::Hdb("no master key to seal a key under".into()))?;
        let sealed = seal_key(cipher, &mkey.key, key_bytes)?;
        Ok((sealed, mkey.kvno))
    }

    /// Opens `sealed`, which a database says was sealed under `mkvno`.
    ///
    /// **`mkvno` is used when it is present and the set has that version.** An entry sealed before a
    /// master-key roll names the old key, and opening it with the new one fails the tag; an entry
    /// that names a version this set does not have is refused by name rather than tried against the
    /// others, because a tag failure on a wrong key is indistinguishable from a corrupt record.
    pub fn unseal(
        &self,
        cipher: &dyn Cipher,
        sealed: &[u8],
        mkvno: Option<u32>,
        enctype: Enctype,
    ) -> Result<Vec<u8>> {
        self.open(cipher, sealed, mkvno, &|open: &[u8]| {
            if open.len() != enctype.key_len() {
                return Err(Error::Hdb(format!(
                    "a key sealed as {} opened to {} octets, and that enctype takes {}",
                    enctype.name(),
                    open.len(),
                    enctype.key_len()
                )));
            }
            Ok(())
        })
    }

    /// Opens `sealed` and checks that the result is `expected_len` octets.
    ///
    /// For material that is sealed like a key but is not a key of any enctype: an account's NT hash
    /// is sixteen octets and there is no enctype to name it by. The length check is not decoration —
    /// a value that opens to another length means the record is about something else, and a caller
    /// that took it would act on the wrong bytes.
    pub fn unseal_bytes(
        &self,
        cipher: &dyn Cipher,
        sealed: &[u8],
        mkvno: Option<u32>,
        expected_len: usize,
        what: &str,
    ) -> Result<Vec<u8>> {
        self.open(cipher, sealed, mkvno, &|open: &[u8]| {
            if open.len() != expected_len {
                return Err(Error::Hdb(format!(
                    "a sealed {what} opened to {} octets, and a {what} is {expected_len}",
                    open.len()
                )));
            }
            Ok(())
        })
    }

    /// The one place that chooses the master key and opens; `check` says what the result must be.
    fn open(
        &self,
        cipher: &dyn Cipher,
        sealed: &[u8],
        mkvno: Option<u32>,
        check: &dyn Fn(&[u8]) -> Result<()>,
    ) -> Result<Vec<u8>> {
        match mkvno {
            Some(kvno) => {
                let mkey = self.get(Some(kvno)).ok_or_else(|| {
                    Error::Hdb(format!(
                        "a key was sealed under master key {kvno}, and this realm has {}",
                        match self.keys.iter().map(|k| k.kvno).collect::<Vec<_>>() {
                            versions if versions.is_empty() => "none".to_owned(),
                            versions => format!("{versions:?}"),
                        }
                    ))
                })?;
                let open = open_sealed(cipher, &mkey.key, sealed)?;
                check(&open)?;
                Ok(open)
            }
            // A database written before the master key was introduced says nothing about the
            // version. Every key in the set is tried, and a set that opens none of them reports that
            // rather than a corrupt key.
            None => {
                let mut last = None;
                for mkey in &self.keys {
                    match open_sealed(cipher, &mkey.key, sealed) {
                        Ok(open) => {
                            check(&open)?;
                            return Ok(open);
                        }
                        Err(e) => last = Some(e),
                    }
                }
                Err(last.unwrap_or_else(|| {
                    Error::Hdb("a key is sealed and this realm has no master key".into())
                }))
            }
        }
    }
}

/// `encrypt(master_key, HDB_KU_MKEY, key_bytes)`.
pub fn seal_key(cipher: &dyn Cipher, master: &Key, key_bytes: &[u8]) -> Result<Vec<u8>> {
    cipher
        .encrypt(master, HDB_KU_MKEY, key_bytes)
        .map_err(|e| Error::Hdb(format!("sealing a key under the master key: {e}")))
}

/// `decrypt(master_key, HDB_KU_MKEY, sealed)`, with the one message a caller can act on: a tag that
/// does not verify means the wrong master key or a corrupt record, and telling them apart is not
/// possible from here.
fn open_sealed(cipher: &dyn Cipher, master: &Key, sealed: &[u8]) -> Result<Vec<u8>> {
    cipher.decrypt(master, HDB_KU_MKEY, sealed).map_err(|_| {
        Error::Hdb(
            "a sealed key does not open under this master key: the tag does not verify, so the \
                 master key is the wrong one or the record is corrupt"
                .into(),
        )
    })
}

/// The inverse, which refuses unless the tag verifies.
pub fn unseal_key(
    cipher: &dyn Cipher,
    master: &Key,
    sealed: &[u8],
    enctype: Enctype,
) -> Result<Vec<u8>> {
    let open = open_sealed(cipher, master, sealed)?;
    if open.len() != enctype.key_len() {
        return Err(Error::Hdb(format!(
            "a key sealed as {} opened to {} octets, and that enctype takes {}",
            enctype.name(),
            open.len(),
            enctype.key_len()
        )));
    }
    Ok(open)
}

/// Whether `bytes` can be a plain key of `enctype`.
///
/// The test is the length and nothing else, deliberately. A sealed key is `confounder + key + tag`,
/// and **the overhead is the master key's, not the sealed key's**: a 32-octet `aes256-cts-hmac-sha384`
/// key sealed under an `aes256-cts-hmac-sha1` master key is 32 + 16 + 12 = 60 octets, where that
/// enctype's own overhead is 40. Computing the expected sealed length from the *key's* enctype — which
/// is what this function first did — therefore misjudges every key whose enctype differs from the
/// master's, and a live stand caught it: a sha384 key was reported as a 60-octet anomaly.
///
/// So the rule is the inverse and it does not need to know which key sealed what: a key whose length
/// is not its enctype's cannot be plaintext, so it is sealed and needs the master key to open. Whether
/// it opens at all is decided by the tag.
pub fn is_plain_key(bytes: &[u8], enctype: Enctype) -> bool {
    bytes.len() == enctype.key_len()
}

/// Writes a master keytab at `path`, which is what `kstash` produces: one `K/M` entry per key.
///
/// A realm that provisions its own master key needs this: `kstash` prompts on a terminal, and a
/// container has none. The file is a plain keytab, so the ordinary protections apply — it is the one
/// file whose loss is the realm's loss.
pub fn write_keytab(
    path: impl AsRef<std::path::Path>,
    realm: &str,
    keys: &[(Key, u32)],
) -> Result<()> {
    let mut keytab = Keytab::new();
    let principal = Principal::parse(&format!("{MASTER_PRINCIPAL}@{realm}"))?;
    for (key, kvno) in keys {
        keytab.add(super::keytab::KeytabEntry {
            principal: principal.clone(),
            key: key.clone(),
            kvno: *kvno,
            timestamp: 0,
        });
    }
    keytab.save(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::OwnCipher;

    fn master() -> Key {
        OwnCipher.random(Enctype::Aes256Sha1).expect("a key")
    }

    /// A sealed key is the enctype's overhead longer than the key itself — 60 octets for AES-256 —
    /// which is the number an operator sees in the error a sealed database produces.
    #[test]
    fn a_sealed_aes256_key_is_sixty_octets() {
        let master = master();
        let plain = vec![0x5au8; 32];
        let sealed = seal_key(&OwnCipher, &master, &plain).expect("sealed");
        assert_eq!(
            sealed.len(),
            60,
            "16 confounder + 32 key + 12 tag: what Heimdal's hprop sends"
        );
        assert!(!is_plain_key(&sealed, Enctype::Aes256Sha1));
        assert!(is_plain_key(&plain, Enctype::Aes256Sha1));
        assert_eq!(
            unseal_key(&OwnCipher, &master, &sealed, Enctype::Aes256Sha1).expect("opened"),
            plain
        );
    }

    /// A key whose enctype differs from the master's seals and opens, and the length of the result is
    /// the **master's** overhead plus the key's size — not the sealed key's own overhead.
    ///
    /// This is the shape that broke a live stand: `aes256-cts-hmac-sha384` has a 40-octet overhead and
    /// `aes256-cts-hmac-sha1` a 28-octet one, so a sha384 key sealed under a sha1 master is 60 octets,
    /// which that enctype's own arithmetic calls impossible.
    #[test]
    fn a_key_of_another_enctype_seals_under_the_master() {
        let master = OwnCipher.random(Enctype::Aes256Sha1).expect("a key");
        let keys = MasterKeys::single(master.clone(), 1);
        for (enctype, len) in [
            (Enctype::Aes256Sha384, 32),
            (Enctype::Aes256Sha1, 32),
            (Enctype::Aes128Sha256, 16),
            (Enctype::Aes128Sha1, 16),
        ] {
            let plain = vec![0x42u8; len];
            let (sealed, kvno) = keys.seal(&OwnCipher, &plain).expect("sealed");
            assert_eq!(
                sealed.len(),
                len + Enctype::Aes256Sha1.overhead(),
                "{enctype:?}: the overhead is the master key's"
            );
            assert!(
                !is_plain_key(&sealed, enctype),
                "{enctype:?}: a sealed key is never its own length"
            );
            assert_eq!(
                keys.unseal(&OwnCipher, &sealed, Some(kvno), enctype)
                    .expect("opened"),
                plain,
                "{enctype:?}"
            );
        }
    }

    /// The usage is Heimdal's `HDB_KU_MKEY`. A different one produces a ciphertext that opens to
    /// nothing, which is why the constant is asserted rather than trusted.
    #[test]
    fn the_usage_is_hdb_ku_mkey() {
        assert_eq!(HDB_KU_MKEY, 0x484442);
        assert_eq!(HDB_KU_MKEY, 4_736_066);
        let master = master();
        let sealed = seal_key(&OwnCipher, &master, &[0x11; 32]).expect("sealed");
        // Sealed under a neighbouring usage, the same octets do not open.
        let wrong = OwnCipher
            .encrypt(&master, HDB_KU_MKEY + 1, &[0x11; 32])
            .expect("sealed");
        assert_ne!(sealed, wrong);
        assert!(unseal_key(&OwnCipher, &master, &wrong, Enctype::Aes256Sha1).is_err());
    }

    /// A wrong master key is a refusal that says so. Reporting a corrupt record instead would send an
    /// operator to look at a database that is intact.
    #[test]
    fn the_wrong_master_key_is_refused_by_name() {
        let sealed = seal_key(&OwnCipher, &master(), &[0x5a; 32]).expect("sealed");
        let other = master();
        let err = unseal_key(&OwnCipher, &other, &sealed, Enctype::Aes256Sha1)
            .expect_err("the wrong key");
        assert!(err.to_string().contains("does not open"), "{err}");
        assert!(err.to_string().contains("master key"), "{err}");
    }

    /// A set of several versions opens an entry sealed under whichever one it names — that is what a
    /// rolled master key looks like — and refuses one that names a version it does not have.
    #[test]
    fn a_set_opens_the_version_an_entry_names() {
        let old = master();
        let new = master();
        let keys = MasterKeys::from_keys([(old.clone(), 1), (new.clone(), 2)]);
        assert_eq!(keys.get(None).map(|k| k.kvno), Some(2), "the newest");

        let sealed_old = seal_key(&OwnCipher, &old, &[0x01; 32]).expect("sealed");
        let sealed_new = seal_key(&OwnCipher, &new, &[0x02; 32]).expect("sealed");

        assert_eq!(
            keys.unseal(&OwnCipher, &sealed_old, Some(1), Enctype::Aes256Sha1)
                .expect("the old key opens it"),
            vec![0x01u8; 32]
        );
        assert_eq!(
            keys.unseal(&OwnCipher, &sealed_new, Some(2), Enctype::Aes256Sha1)
                .expect("the new key opens it"),
            vec![0x02u8; 32]
        );

        let err = keys
            .unseal(&OwnCipher, &sealed_old, Some(3), Enctype::Aes256Sha1)
            .expect_err("version 3 is not here");
        assert!(err.to_string().contains("master key 3"), "{err}");
        assert!(
            err.to_string().contains("[2, 1]"),
            "the versions are listed newest first: {err}"
        );
    }

    /// An entry that says nothing about the version is tried against every key in the set, because a
    /// database written before the master key existed carries no `mkvno`.
    #[test]
    fn an_entry_without_a_version_is_tried_against_every_key() {
        let old = master();
        let new = master();
        let keys = MasterKeys::from_keys([(old.clone(), 1), (new, 2)]);
        let sealed = seal_key(&OwnCipher, &old, &[0x07; 32]).expect("sealed");
        assert_eq!(
            keys.unseal(&OwnCipher, &sealed, None, Enctype::Aes256Sha1)
                .expect("one of them opens it"),
            vec![0x07u8; 32]
        );
    }

    /// Sealing picks the newest key and reports its version, so that what is written can be opened
    /// after a roll.
    #[test]
    fn sealing_uses_the_newest_key_and_says_which() {
        let keys = MasterKeys::from_keys([(master(), 1), (master(), 4)]);
        let (sealed, kvno) = keys.seal(&OwnCipher, &[0x33; 32]).expect("sealed");
        assert_eq!(kvno, 4);
        assert_eq!(
            keys.unseal(&OwnCipher, &sealed, Some(4), Enctype::Aes256Sha1)
                .expect("opened"),
            vec![0x33u8; 32]
        );
    }

    /// An empty set cannot seal and says so: a KDC with no master key that silently stored plaintext
    /// would be a KDC whose operator believes the database is protected.
    #[test]
    fn an_empty_set_refuses_to_seal() {
        let err = MasterKeys::none()
            .seal(&OwnCipher, &[0x5a; 32])
            .expect_err("no master key");
        assert!(err.to_string().contains("no master key"), "{err}");
    }

    /// A keytab is what `kstash` writes, so a master key round-trips through one — and a keytab
    /// without `K/M` is refused by name rather than read as an empty set.
    #[test]
    fn a_master_key_round_trips_through_a_keytab() {
        let dir = std::env::temp_dir().join(format!(
            "rrl-mkey-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&dir).expect("a directory");
        let path = dir.join("stash");
        let first = master();
        write_keytab(&path, "EXAMPLE.COM", &[(first.clone(), 1)]).expect("written");

        let keys = MasterKeys::from_keytab(&path).expect("read");
        assert_eq!(keys.keys().len(), 1);
        assert_eq!(keys.keys()[0].kvno, 1);
        assert_eq!(keys.keys()[0].key.bytes(), first.bytes());

        // A keytab of some other service is not a master key file.
        let mut other = Keytab::new();
        other.add(super::super::keytab::KeytabEntry {
            principal: Principal::parse("host/s.example.com@EXAMPLE.COM").expect("a name"),
            key: master(),
            kvno: 1,
            timestamp: 0,
        });
        let other_path = dir.join("not-a-stash");
        other.save(&other_path).expect("written");
        let err = MasterKeys::from_keytab(&other_path).expect_err("no K/M");
        assert!(err.to_string().contains("K/M"), "{err}");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
