//! The principal database, shaped after Heimdal's `lib/hdb/hdb.asn1`.
//!
//! Heimdal's `HDB` is an interface (`lib/hdb/hdb.h`) with several backends —
//! LDAP, mdb, sqlite, MIT's dump format, a keytab, db3 — and one record type,
//! `hdb_entry`. This module keeps the record and the interface; the backends
//! come one at a time, starting with memory and a keytab.
//!
//! The record is deliberately Heimdal's, not something invented: an entry has a
//! principal, a **keyset** (each key with its own kvno and salt), validity
//! times, and a flags word whose bit meanings are the ones in `hdb.asn1`. A
//! later `redb` backend then stores exactly this, and an import from a Heimdal
//! dump or from an LDAP `krbPrincipalKey` has somewhere to land.

use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};

use crate::crypto::{Cipher, Enctype, Key};
use crate::error::{Error, Result};
use crate::name::Principal;

pub mod keytab;
pub mod record;
#[cfg(feature = "hdb-redb")]
pub mod redb_store;

pub use keytab::Keytab;
#[cfg(feature = "hdb-redb")]
pub use redb_store::RedbHdb;

/// `HDBFlags` (Heimdal `lib/hdb/hdb.asn1`), in BIT STRING order: bit *n* is
/// `1 << (31 - n)`, exactly as the ASN.1 names them.
pub mod flags {
    /// `initial` — this principal may get a ticket without asking for a
    /// service first.
    pub const INITIAL: u32 = 0x8000_0000;
    /// `forwardable`.
    pub const FORWARDABLE: u32 = 0x4000_0000;
    /// `proxiable`.
    pub const PROXIABLE: u32 = 0x2000_0000;
    /// `renewable`.
    pub const RENEWABLE: u32 = 0x1000_0000;
    /// `postdate`.
    pub const POSTDATE: u32 = 0x0800_0000;
    /// `server` — a ticket may be issued *for* this principal.
    pub const SERVER: u32 = 0x0400_0000;
    /// `client` — this principal may ask for tickets.
    pub const CLIENT: u32 = 0x0200_0000;
    /// `invalid` — the entry exists but is refused.
    pub const INVALID: u32 = 0x0100_0000;
    /// `require-preauth`.
    pub const REQUIRE_PREAUTH: u32 = 0x0080_0000;
    /// `change-pw` — the `kadmin/changepw` service.
    pub const CHANGE_PW: u32 = 0x0040_0000;
    /// `require-hwauth`.
    pub const REQUIRE_HWAUTH: u32 = 0x0020_0000;
    /// `ok-as-delegate`.
    pub const OK_AS_DELEGATE: u32 = 0x0010_0000;
    /// `user-to-user`.
    pub const USER_TO_USER: u32 = 0x0008_0000;
    /// `immutable` — may not be deleted.
    pub const IMMUTABLE: u32 = 0x0004_0000;
    /// `trusted-for-delegation`.
    pub const TRUSTED_FOR_DELEGATION: u32 = 0x0002_0000;
    /// `allow-kerberos4`.
    pub const ALLOW_KERBEROS4: u32 = 0x0001_0000;
    /// `allow-digest`.
    pub const ALLOW_DIGEST: u32 = 0x0000_8000;
    /// `locked-out` — authentication is denied.
    pub const LOCKED_OUT: u32 = 0x0000_4000;
    /// `require-pwchange`.
    pub const REQUIRE_PWCHANGE: u32 = 0x0000_2000;
}

/// One key of an entry: the material, the kvno it belongs to, and the salt it
/// was made with.
///
/// Heimdal keeps the salt in the entry rather than recomputing it, because a
/// principal's salt is a property of the principal's *history*: changing the
/// salt invalidates every key, and an entry that has to guess gets it wrong for
/// any principal whose name changed.
#[derive(Clone, Debug)]
pub struct HdbKey {
    /// `mkvno` is not modelled yet: nothing here is encrypted under a master
    /// key, so no key records which one it used.
    pub kvno: u32,
    /// The key.
    pub key: Key,
    /// The salt `s2k` used, as it must be sent in `ETYPE-INFO2`.
    pub salt: Option<Vec<u8>>,
}

/// `hdb_entry`: one principal.
#[derive(Clone, Debug)]
pub struct HdbEntry {
    /// The principal this entry is for.
    pub principal: Principal,
    /// The keys, at most one per (kvno, enctype).
    pub keys: Vec<HdbKey>,
    /// `HDBFlags`.
    pub flags: u32,
    /// `valid_start`.
    pub valid_start: Option<i64>,
    /// `valid_end`.
    pub valid_end: Option<i64>,
    /// When the password stops working.
    pub pw_end: Option<i64>,
    /// `max_life` for tickets issued to this principal as a service.
    pub max_life: Option<i64>,
    /// `max_renew` for the same.
    pub max_renew: Option<i64>,
    /// `modified`.
    pub modified: i64,
}

impl HdbEntry {
    /// A user principal: `client`, `initial`, `forwardable`, `proxiable`,
    /// `renewable`, `require-preauth` — Heimdal's `default_principal_flags`
    /// for a normal account.
    pub fn user(principal: Principal) -> Self {
        HdbEntry {
            principal,
            keys: Vec::new(),
            flags: flags::CLIENT
                | flags::INITIAL
                | flags::FORWARDABLE
                | flags::PROXIABLE
                | flags::RENEWABLE
                | flags::REQUIRE_PREAUTH,
            valid_start: None,
            valid_end: None,
            pw_end: None,
            max_life: None,
            max_renew: None,
            modified: 0,
        }
    }

    /// A service principal: `server`, and by default not a client.
    pub fn service(principal: Principal) -> Self {
        HdbEntry {
            principal,
            keys: Vec::new(),
            flags: flags::SERVER,
            valid_start: None,
            valid_end: None,
            pw_end: None,
            max_life: None,
            max_renew: None,
            modified: 0,
        }
    }

    /// The `krbtgt/REALM` entry: a service, and the one ticket that must be
    /// forwardable for a realm to be worth anything.
    pub fn krbtgt(realm: &str) -> Self {
        HdbEntry {
            principal: Principal::krbtgt(realm),
            keys: Vec::new(),
            flags: flags::SERVER | flags::FORWARDABLE | flags::PROXIABLE | flags::RENEWABLE,
            valid_start: None,
            valid_end: None,
            pw_end: None,
            max_life: None,
            max_renew: None,
            modified: 0,
        }
    }

    /// Whether `flag` is set.
    pub fn has(&self, flag: u32) -> bool {
        self.flags & flag != 0
    }

    /// The highest-kvno key of `enctype`, if the entry has one.
    pub fn key_for(&self, enctype: Enctype) -> Option<&HdbKey> {
        self.keys
            .iter()
            .filter(|k| k.key.enctype() == enctype)
            .max_by_key(|k| k.kvno)
    }

    /// The enctypes this entry has keys for, strongest first.
    pub fn enctypes(&self) -> Vec<Enctype> {
        Enctype::ALL
            .into_iter()
            .filter(|e| self.key_for(*e).is_some())
            .collect()
    }

    /// The highest kvno any key is at.
    pub fn kvno(&self) -> u32 {
        self.keys.iter().map(|k| k.kvno).max().unwrap_or(0)
    }

    /// Whether the entry may authenticate at `now`.
    pub fn is_valid_at(&self, now: i64) -> bool {
        if self.has(flags::INVALID) || self.has(flags::LOCKED_OUT) {
            return false;
        }
        let before_validity = self.valid_start.is_some_and(|start| now < start);
        let after_validity = self.valid_end.is_some_and(|end| now > end);
        let password_expired = self.pw_end.is_some_and(|end| now > end);
        !(before_validity || after_validity || password_expired)
    }

    /// Adds a key derived from `password` with the entry's salt (or the
    /// principal's default salt) at `kvno`.
    ///
    /// This is the KDC side of `kadmin addprinc -pw`: `s2k` runs here, and the
    /// salt is recorded so the client is told the same one in `ETYPE-INFO2`.
    pub fn add_password_key(
        &mut self,
        cipher: &dyn Cipher,
        enctype: Enctype,
        password: &[u8],
        kvno: u32,
    ) -> Result<()> {
        let salt = self
            .keys
            .iter()
            .filter(|k| k.kvno == kvno)
            .find_map(|k| k.salt.clone())
            .unwrap_or_else(|| self.principal.default_salt());
        // `None` lets the cipher use the enctype's default iteration count —
        // the same default the client applies when `ETYPE-INFO2` carries no
        // `s2kparams`, which is how both sides agree without being told.
        let key = cipher.s2k(enctype, password, &salt, None)?;
        self.keys.push(HdbKey {
            kvno,
            key,
            salt: Some(salt),
        });
        Ok(())
    }

    /// Adds a raw key at `kvno` — what a keytab import does.
    pub fn add_key(&mut self, key: Key, kvno: u32, salt: Option<Vec<u8>>) {
        self.keys.push(HdbKey { kvno, key, salt });
    }
}

/// What a KDC needs from a database (Heimdal's `hdb_open`, `hdb_fetch_kvno`,
/// `hdb_store`, `hdb_remove`, `hdb_firstkey`, `hdb_nextkey`, `hdb_rename`).
///
/// Every method is `&self`: a KDC serves requests concurrently, so a backend
/// that needs to mutate takes its own lock. The trait is synchronous on
/// purpose — a KDC's critical section is a hash lookup, and making every
/// backend `async` would buy nothing and complicate every caller.
pub trait Hdb: Send + Sync + std::fmt::Debug {
    /// The entry for `principal`, or `None` if there is none.
    fn fetch(&self, principal: &Principal) -> Result<Option<HdbEntry>>;

    /// Inserts or replaces an entry.
    fn store(&self, entry: HdbEntry) -> Result<()>;

    /// Removes an entry; returns whether there was one.
    fn remove(&self, principal: &Principal) -> Result<bool>;

    /// Renames an entry.
    fn rename(&self, from: &Principal, to: &Principal) -> Result<()>;

    /// The first principal, in the backend's order.
    fn first(&self) -> Result<Option<Principal>>;

    /// The principal after `after`, in the backend's order.
    fn next(&self, after: &Principal) -> Result<Option<Principal>>;
}

/// A database in memory: what the tests use, and what an in-process KDC can
/// start from before it has storage of its own.
#[derive(Debug, Default)]
pub struct MemoryHdb {
    entries: RwLock<BTreeMap<Principal, HdbEntry>>,
}

impl MemoryHdb {
    /// An empty database.
    pub fn new() -> Self {
        MemoryHdb::default()
    }

    /// A database shared the way a KDC holds one.
    pub fn shared(self) -> Arc<dyn Hdb> {
        Arc::new(self)
    }

    /// An entry, added in one call.
    pub fn insert(&self, entry: HdbEntry) -> Result<()> {
        self.store(entry)
    }

    /// How many principals are stored — for tests and diagnostics.
    pub fn len(&self) -> usize {
        self.entries.read().expect("hdb lock").len()
    }

    /// Whether the database is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Hdb for MemoryHdb {
    fn fetch(&self, principal: &Principal) -> Result<Option<HdbEntry>> {
        Ok(self
            .entries
            .read()
            .map_err(|_| Error::Hdb("lock poisoned".into()))?
            .get(principal)
            .cloned())
    }

    fn store(&self, entry: HdbEntry) -> Result<()> {
        let mut guard = self
            .entries
            .write()
            .map_err(|_| Error::Hdb("lock poisoned".into()))?;
        guard.insert(entry.principal.clone(), entry);
        Ok(())
    }

    fn remove(&self, principal: &Principal) -> Result<bool> {
        Ok(self
            .entries
            .write()
            .map_err(|_| Error::Hdb("lock poisoned".into()))?
            .remove(principal)
            .is_some())
    }

    fn rename(&self, from: &Principal, to: &Principal) -> Result<()> {
        let mut guard = self
            .entries
            .write()
            .map_err(|_| Error::Hdb("lock poisoned".into()))?;
        let mut entry = guard
            .remove(from)
            .ok_or_else(|| Error::Hdb(format!("cannot rename {from}: no such principal")))?;
        entry.principal = to.clone();
        guard.insert(to.clone(), entry);
        Ok(())
    }

    fn first(&self) -> Result<Option<Principal>> {
        Ok(self
            .entries
            .read()
            .map_err(|_| Error::Hdb("lock poisoned".into()))?
            .keys()
            .next()
            .cloned())
    }

    fn next(&self, after: &Principal) -> Result<Option<Principal>> {
        Ok(self
            .entries
            .read()
            .map_err(|_| Error::Hdb("lock poisoned".into()))?
            .range(after.clone()..)
            .skip_while(|(p, _)| *p == after)
            .map(|(p, _)| p.clone())
            .next())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::OwnCipher;

    fn realm_db() -> MemoryHdb {
        let db = MemoryHdb::new();
        let cipher = OwnCipher;
        let mut krbtgt = HdbEntry::krbtgt("R");
        krbtgt
            .add_password_key(&cipher, Enctype::Aes256Sha1, b"master", 1)
            .unwrap();
        db.insert(krbtgt).unwrap();
        db
    }

    #[test]
    fn keys_are_found_by_enctype_at_the_highest_kvno() {
        let cipher = OwnCipher;
        let mut e = HdbEntry::user(Principal::parse("alice@R").unwrap());
        e.add_password_key(&cipher, Enctype::Aes256Sha1, b"old", 1)
            .unwrap();
        e.add_password_key(&cipher, Enctype::Aes128Sha1, b"old", 1)
            .unwrap();
        e.add_password_key(&cipher, Enctype::Aes256Sha1, b"new", 2)
            .unwrap();
        let k = e.key_for(Enctype::Aes256Sha1).unwrap();
        assert_eq!(k.kvno, 2);
        assert_eq!(e.kvno(), 2);
        assert_eq!(e.enctypes(), vec![Enctype::Aes256Sha1, Enctype::Aes128Sha1]);
        assert!(e.key_for(Enctype::Aes256Sha384).is_none());
    }

    #[test]
    fn a_password_key_records_the_default_salt() {
        let cipher = OwnCipher;
        let mut e = HdbEntry::user(Principal::parse("alice@R").unwrap());
        e.add_password_key(&cipher, Enctype::Aes256Sha1, b"pw", 1)
            .unwrap();
        assert_eq!(e.keys[0].salt.as_deref(), Some(&b"Ralice"[..]));
        // The key must be the one a client would derive from the same salt.
        let expected = cipher
            .s2k(Enctype::Aes256Sha1, b"pw", b"Ralice", None)
            .unwrap();
        assert_eq!(e.keys[0].key, expected);
    }

    #[test]
    fn store_fetch_and_iterate() {
        let db = realm_db();
        assert!(db.fetch(&Principal::krbtgt("R")).unwrap().is_some());
        assert!(
            db.fetch(&Principal::parse("nobody@R").unwrap())
                .unwrap()
                .is_none()
        );
        db.insert(HdbEntry::user(Principal::parse("alice@R").unwrap()))
            .unwrap();
        db.insert(HdbEntry::user(Principal::parse("bob@R").unwrap()))
            .unwrap();
        let mut seen = Vec::new();
        let mut cur = db.first().unwrap();
        while let Some(p) = cur {
            seen.push(p.to_string());
            cur = db.next(&p).unwrap();
        }
        assert_eq!(seen, ["alice@R", "bob@R", "krbtgt/R@R"]);
        assert!(db.remove(&Principal::parse("bob@R").unwrap()).unwrap());
        assert!(!db.remove(&Principal::parse("bob@R").unwrap()).unwrap());
    }

    #[test]
    fn rename_moves_the_keys_with_the_name() {
        let db = realm_db();
        let mut e = HdbEntry::user(Principal::parse("alice@R").unwrap());
        e.add_password_key(&OwnCipher, Enctype::Aes128Sha1, b"pw", 1)
            .unwrap();
        db.insert(e).unwrap();
        db.rename(
            &Principal::parse("alice@R").unwrap(),
            &Principal::parse("carol@R").unwrap(),
        )
        .unwrap();
        assert!(
            db.fetch(&Principal::parse("alice@R").unwrap())
                .unwrap()
                .is_none()
        );
        let carol = db
            .fetch(&Principal::parse("carol@R").unwrap())
            .unwrap()
            .unwrap();
        assert_eq!(carol.principal.to_string(), "carol@R");
        assert_eq!(carol.keys.len(), 1);
        assert!(
            db.rename(
                &Principal::parse("nobody@R").unwrap(),
                &Principal::parse("x@R").unwrap()
            )
            .is_err()
        );
    }

    #[test]
    fn invalid_and_locked_entries_are_not_valid() {
        let now = 1_700_000_000;
        let mut e = HdbEntry::user(Principal::parse("alice@R").unwrap());
        assert!(e.is_valid_at(now));
        e.flags |= flags::INVALID;
        assert!(!e.is_valid_at(now));
        e.flags = flags::CLIENT;
        e.flags |= flags::LOCKED_OUT;
        assert!(!e.is_valid_at(now));
        e.flags = flags::CLIENT;
        e.valid_end = Some(now - 1);
        assert!(!e.is_valid_at(now));
    }

    #[test]
    fn the_name_type_does_not_hide_an_entry() {
        let db = realm_db();
        let mut alice = Principal::parse("alice@R").unwrap();
        db.insert(HdbEntry::user(alice.clone())).unwrap();
        // A client may send NT-UNKNOWN; the entry must still be found.
        alice.name_type = crate::name::NT_UNKNOWN;
        assert!(db.fetch(&alice).unwrap().is_some());
    }
}
