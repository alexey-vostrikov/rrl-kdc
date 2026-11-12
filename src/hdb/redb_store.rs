//! The redb backend: one file, one table, one process at a time.
//!
//! redb is a pure-Rust embedded store with a single writer and MVCC readers,
//! which is exactly the shape a KDC needs: reads happen constantly and are never
//! blocked by the rare write, and there is no server to run or port to open.
//!
//! The version is the one the in-process consumer (`rust-rest-ldap`) already
//! builds against, so a KDC embedded in it shares a store rather than adding a
//! second copy of redb to the graph.
//!
//! # What this backend does not do
//!
//! It does not lock across processes. redb takes its own file lock, so a second
//! `RedbHdb` on the same file fails to open — which is the right outcome: two
//! KDCs writing one database without replication is data loss waiting to be
//! noticed. A stand with several KDCs wants replication, and that is `hprop`, not
//! a second writer.

use std::path::{Path, PathBuf};

use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};

use crate::crypto::{Cipher, OwnCipher};
use crate::error::{Error, Result};
use crate::hdb::mkey::MasterKeys;
use crate::name::Principal;

use crate::acl::{AclRule, AclStore, Targets};

use super::policy::Policy;
use super::record;
use super::{Hdb, HdbEntry};

/// `key` → the entry, DER-encoded by [`super::record`].
const ENTRIES: TableDefinition<'_, &'static str, &'static [u8]> =
    TableDefinition::new("hdb_entries");

/// The change-password rules, in the same database file as the principals.
///
/// Same file and not a second one: a backup that has the principals and not the
/// rules restores a realm where nobody may change a password, and an operator has
/// no way to notice until they try.
const ACL: TableDefinition<'_, &'static str, &'static [u8]> = TableDefinition::new("hdb_acl");

/// `alias key` → `the entry's key`, so that a name one entry answers to finds that entry
/// without walking the whole database. An alias is a name, not an identity: the entry keeps its
/// own principal and its own keys, and this table only says which entry to fetch.
const ALIASES: TableDefinition<'_, &'static str, &'static str> =
    TableDefinition::new("hdb_aliases");

/// `policy name` → the policy, DER-encoded by [`super::policy`]. Same file as the principals for
/// the reason the ACL is: a backup that restores accounts without the rules they were made under
/// restores a realm whose passwords suddenly have no length limit, and nothing says so.
const POLICIES: TableDefinition<'_, &'static str, &'static [u8]> =
    TableDefinition::new("hdb_policies");

/// The `hdb` interface over a redb file.
#[derive(Debug)]
pub struct RedbHdb {
    db: Database,
    path: PathBuf,
    /// The realm's master keys, when this database stores its keys sealed.
    ///
    /// `None` is not an oversight: a realm that has not provisioned a master key stores plaintext
    /// keys, and the file is then only as private as its permissions. Every caller that means to
    /// protect the database has to say so, which is why this is not a default.
    master: Option<MasterKeys>,
    /// The realm's cipher, for sealing and opening. Unused without a master key.
    cipher: std::sync::Arc<dyn Cipher>,
}

impl RedbHdb {
    /// Opens (or creates) a database file.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let db = Database::create(&path)
            .map_err(|e| Error::Hdb(format!("cannot open {}: {e}", path.display())))?;
        // Create the table on open, so a read of an empty database is a read of
        // an empty table rather than a "table does not exist" error that every
        // caller would have to special-case.
        let txn = db.begin_write().map_err(store_err)?;
        {
            txn.open_table(ENTRIES).map_err(store_err)?;
            txn.open_table(ACL).map_err(store_err)?;
            txn.open_table(ALIASES).map_err(store_err)?;
            txn.open_table(POLICIES).map_err(store_err)?;
        }
        txn.commit().map_err(store_err)?;
        Ok(RedbHdb {
            db,
            path,
            master: None,
            cipher: std::sync::Arc::new(OwnCipher),
        })
    }

    /// Opens (or creates) a database that stores its keys sealed under `master`.
    ///
    /// The keys are the realm: a file of them in the clear is a file that forges tickets. With a
    /// master key every key on disk is `encrypt(master_key, HDB_KU_MKEY, key_bytes)`, and the file is
    /// worthless without the keytab — which is the arrangement Heimdal has and the one an operator
    /// expects from a KDC.
    ///
    /// An existing database is **read** through the same key set, so a realm that seals its keys can
    /// still open a file written before it did: a key with no `mkvno` is plaintext, and this backend
    /// leaves it alone until it is written again.
    pub fn open_sealed(
        path: impl AsRef<Path>,
        master: MasterKeys,
        cipher: std::sync::Arc<dyn Cipher>,
    ) -> Result<Self> {
        let mut hdb = Self::open(path)?;
        if master.is_empty() {
            return Err(Error::Hdb(
                "open_sealed was given no master key: a sealed database needs at least one, and a \
                 database that silently stored plaintext under this name would be the mistake this \
                 constructor exists to prevent"
                    .into(),
            ));
        }
        hdb.master = Some(master);
        hdb.cipher = cipher;
        Ok(hdb)
    }

    /// Whether this handle writes sealed keys.
    pub fn is_sealed(&self) -> bool {
        self.master.is_some()
    }

    /// The master key set, when there is one.
    pub fn master_keys(&self) -> Option<&MasterKeys> {
        self.master.as_ref()
    }

    /// The stored bytes of one entry, exactly as the file holds them.
    ///
    /// A test needs this to judge the storage rather than the API: an entry that round trips through
    /// `store`/`fetch` says nothing about what is on disk.
    pub fn raw_record(&self, principal: &Principal) -> Result<Vec<u8>> {
        let k = record::key(principal);
        let txn = self.db.begin_read().map_err(store_err)?;
        let table = txn.open_table(ENTRIES).map_err(store_err)?;
        match table.get(k.as_str()).map_err(store_err)? {
            None => Err(Error::Hdb(format!("{principal} is not in this database"))),
            Some(value) => Ok(value.value().to_vec()),
        }
    }

    /// The pair `record::encode_with`/`decode_with` take.
    fn codec(&self) -> Option<(&dyn Cipher, &MasterKeys)> {
        self.master
            .as_ref()
            .map(|keys| (self.cipher.as_ref(), keys))
    }

    /// Re-seals every entry under the newest master key.
    ///
    /// This is what a master-key roll needs: add a key, call this, and every record names the new one;
    /// the old key can then be removed. Entries already sealed with the newest key are rewritten as
    /// they are, so a second call is harmless.
    ///
    /// One transaction for the whole database: a roll that stopped half way would leave a realm whose
    /// entries name two keys, and the point of the operation is that it stops naming the old one.
    pub fn reseal(&self) -> Result<usize> {
        let Some(codec) = self.codec() else {
            return Err(Error::Hdb(
                "reseal needs a master key: this handle stores plaintext keys".into(),
            ));
        };
        let entries: Vec<(String, Vec<u8>)> = {
            let txn = self.db.begin_read().map_err(store_err)?;
            let table = txn.open_table(ENTRIES).map_err(store_err)?;
            let mut out = Vec::new();
            for row in table.iter().map_err(store_err)? {
                let (k, v) = row.map_err(store_err)?;
                out.push((k.value().to_owned(), v.value().to_vec()));
            }
            out
        };
        let mut resealed = Vec::with_capacity(entries.len());
        for (key, bytes) in entries {
            // Opened, then written again: that is what turns the old `mkvno` into the new one.
            let entry = record::decode_with(&bytes, Some(codec))?;
            resealed.push((key, record::encode_with(&entry, Some(codec))?));
        }
        let txn = self.db.begin_write().map_err(store_err)?;
        {
            let mut table = txn.open_table(ENTRIES).map_err(store_err)?;
            for (key, bytes) in &resealed {
                table
                    .insert(key.as_str(), bytes.as_slice())
                    .map_err(store_err)?;
            }
        }
        txn.commit().map_err(store_err)?;
        Ok(resealed.len())
    }

    /// The file this backend is using.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

fn store_err(e: impl std::fmt::Display) -> Error {
    Error::Hdb(format!("redb: {e}"))
}

impl RedbHdb {
    /// `principal`, or the entry an alias of it names.
    ///
    /// The alias table is consulted only after the entry table missed, so a stored principal is
    /// never shadowed by an alias that happens to spell the same name.
    fn resolve(&self, principal: &Principal) -> Result<Option<HdbEntry>> {
        let k = record::key(principal);
        let txn = self.db.begin_read().map_err(store_err)?;
        let entries = txn.open_table(ENTRIES).map_err(store_err)?;
        if let Some(value) = entries.get(k.as_str()).map_err(store_err)? {
            return Ok(Some(record::decode_with(value.value(), self.codec())?));
        }
        let aliases = txn.open_table(ALIASES).map_err(store_err)?;
        let Some(target) = aliases.get(k.as_str()).map_err(store_err)? else {
            return Ok(None);
        };
        let target = target.value().to_owned();
        match entries.get(target.as_str()).map_err(store_err)? {
            None => Ok(None),
            Some(value) => Ok(Some(record::decode_with(value.value(), self.codec())?)),
        }
    }
}

impl Hdb for RedbHdb {
    fn fetch(&self, principal: &Principal) -> Result<Option<HdbEntry>> {
        self.resolve(principal)
    }

    fn fetch_for_service(&self, service: &Principal) -> Result<Option<HdbEntry>> {
        self.resolve(service)
    }

    fn fetch_policy(&self, name: &str) -> Result<Option<Policy>> {
        let txn = self.db.begin_read().map_err(store_err)?;
        let table = txn.open_table(POLICIES).map_err(store_err)?;
        match table.get(name).map_err(store_err)? {
            None => Ok(None),
            Some(value) => Ok(Some(Policy::decode(value.value())?)),
        }
    }

    fn store_policy(&self, policy: Policy) -> Result<()> {
        let name = policy.name.clone();
        let bytes = policy.encode();
        let txn = self.db.begin_write().map_err(store_err)?;
        {
            let mut table = txn.open_table(POLICIES).map_err(store_err)?;
            table
                .insert(name.as_str(), bytes.as_slice())
                .map_err(store_err)?;
        }
        txn.commit().map_err(store_err)?;
        Ok(())
    }

    fn remove_policy(&self, name: &str) -> Result<bool> {
        let txn = self.db.begin_write().map_err(store_err)?;
        let removed = {
            let mut table = txn.open_table(POLICIES).map_err(store_err)?;
            table.remove(name).map_err(store_err)?.is_some()
        };
        txn.commit().map_err(store_err)?;
        Ok(removed)
    }

    fn policies(&self) -> Result<Vec<String>> {
        let txn = self.db.begin_read().map_err(store_err)?;
        let table = txn.open_table(POLICIES).map_err(store_err)?;
        let mut names = Vec::new();
        for row in table.iter().map_err(store_err)? {
            let (name, _) = row.map_err(store_err)?;
            names.push(name.value().to_owned());
        }
        Ok(names)
    }

    fn store(&self, entry: HdbEntry) -> Result<()> {
        let k = record::key(&entry.principal);
        // Sealed here, on the way out: `entry` holds plaintext because that is what a KDC works
        // with, and what a file should hold is not the same thing.
        let bytes = record::encode_with(&entry, self.codec())?;
        // Every alias this entry used to answer to and no longer does has to go: an alias row
        // left behind would send a request for an old name to an entry that no longer claims it.
        let wanted: Vec<String> = entry
            .names()
            .into_iter()
            .filter(|n| n != &entry.principal)
            .map(|n| record::key(&n))
            .collect();
        let txn = self.db.begin_write().map_err(store_err)?;
        {
            let mut table = txn.open_table(ENTRIES).map_err(store_err)?;
            table
                .insert(k.as_str(), bytes.as_slice())
                .map_err(store_err)?;
        }
        {
            let mut aliases = txn.open_table(ALIASES).map_err(store_err)?;
            let stale: Vec<String> = aliases
                .iter()
                .map_err(store_err)?
                .filter_map(|row| {
                    let (alias, target) = row.ok()?;
                    (target.value() == k).then(|| alias.value().to_owned())
                })
                .collect();
            for alias in stale {
                aliases.remove(alias.as_str()).map_err(store_err)?;
            }
            for alias in &wanted {
                aliases
                    .insert(alias.as_str(), k.as_str())
                    .map_err(store_err)?;
            }
        }
        txn.commit().map_err(store_err)?;
        Ok(())
    }

    fn remove(&self, principal: &Principal) -> Result<bool> {
        let k = record::key(principal);
        let txn = self.db.begin_write().map_err(store_err)?;
        let removed = {
            let mut table = txn.open_table(ENTRIES).map_err(store_err)?;
            let old = table.remove(k.as_str()).map_err(store_err)?;
            old.is_some()
        };
        {
            let mut aliases = txn.open_table(ALIASES).map_err(store_err)?;
            let stale: Vec<String> = aliases
                .iter()
                .map_err(store_err)?
                .filter_map(|row| {
                    let (alias, target) = row.ok()?;
                    (target.value() == k).then(|| alias.value().to_owned())
                })
                .collect();
            for alias in stale {
                aliases.remove(alias.as_str()).map_err(store_err)?;
            }
        }
        txn.commit().map_err(store_err)?;
        Ok(removed)
    }

    fn rename(&self, from: &Principal, to: &Principal) -> Result<()> {
        let from_key = record::key(from);
        let to_key = record::key(to);
        let bytes = {
            let txn = self.db.begin_read().map_err(store_err)?;
            let table = txn.open_table(ENTRIES).map_err(store_err)?;
            let value = table
                .get(from_key.as_str())
                .map_err(store_err)?
                .ok_or_else(|| Error::Hdb(format!("cannot rename {from}: no such principal")))?;
            value.value().to_vec()
        };
        // One transaction for the remove and the insert: a rename that half
        // happened would lose either the keys or the name, and neither is
        // recoverable from the other.
        let mut entry = record::decode_with(&bytes, self.codec())?;
        entry.principal = to.clone();
        let encoded = record::encode_with(&entry, self.codec())?;
        let txn = self.db.begin_write().map_err(store_err)?;
        {
            let mut table = txn.open_table(ENTRIES).map_err(store_err)?;
            table.remove(from_key.as_str()).map_err(store_err)?;
            table
                .insert(to_key.as_str(), encoded.as_slice())
                .map_err(store_err)?;
        }
        // The entry's aliases travel with it, so the rows that pointed at the old key have to
        // point at the new one: a rename that left them behind would resolve an alias to nothing.
        {
            let mut aliases = txn.open_table(ALIASES).map_err(store_err)?;
            let moved: Vec<String> = aliases
                .iter()
                .map_err(store_err)?
                .filter_map(|row| {
                    let (alias, target) = row.ok()?;
                    (target.value() == from_key).then(|| alias.value().to_owned())
                })
                .collect();
            for alias in moved {
                aliases
                    .insert(alias.as_str(), to_key.as_str())
                    .map_err(store_err)?;
            }
        }
        txn.commit().map_err(store_err)?;
        Ok(())
    }

    fn first(&self) -> Result<Option<Principal>> {
        self.walk(None)
    }

    fn next(&self, after: &Principal) -> Result<Option<Principal>> {
        self.walk(Some(after))
    }
}

impl RedbHdb {
    /// The first principal, or the first one after `after`.
    ///
    /// The walk orders by the stored key, which is `name@realm`: one realm's
    /// principals come out together, and a walk does not need a secondary index.
    fn walk(&self, after: Option<&Principal>) -> Result<Option<Principal>> {
        let txn = self.db.begin_read().map_err(store_err)?;
        let table = txn.open_table(ENTRIES).map_err(store_err)?;
        let bound = after.map(record::key);
        let mut range = match &bound {
            None => table.iter().map_err(store_err)?,
            Some(k) => table.range(k.as_str()..).map_err(store_err)?,
        };
        // `range` starts *at* the bound, so the bound itself is skipped rather
        // than being reported as the next principal — which would make every
        // walk loop forever on its first element.
        for entry in range.by_ref() {
            let (k, value) = entry.map_err(store_err)?;
            let key = k.value().to_string();
            if bound.as_deref() == Some(key.as_str()) {
                continue;
            }
            // The name only: a walk over a sealed database must not need the master key, and
            // unsealing every key of every entry to list names would need it for no reason.
            return Ok(Some(record::principal_of(value.value())?));
        }
        Ok(None)
    }
}

/// The change-password rules live in the same file as the principals, behind
/// the same handle.
///
/// Not a second `Database`: redb takes a lock on the file, and a second handle —
/// even from the same process — fails to open it. One connection answering two
/// questions is also the honest model, because a backup that carries the
/// principals and not the rules restores a realm where nobody may change a
/// password. A caller that wants both shares one `Arc<RedbHdb>` and views it as
/// `Arc<dyn Hdb>` and `Arc<dyn AclStore>`.
impl AclStore for RedbHdb {
    fn rules(&self) -> Result<Vec<AclRule>> {
        let txn = self.db.begin_read().map_err(store_err)?;
        let table = txn.open_table(ACL).map_err(store_err)?;
        let mut out = Vec::new();
        for entry in table.iter().map_err(store_err)? {
            let (k, _) = entry.map_err(store_err)?;
            out.push(parse_acl_key(k.value())?);
        }
        Ok(out)
    }

    fn grant(&self, actor: &Principal, targets: Targets) -> Result<()> {
        let key = acl_key(actor, &targets);
        let txn = self.db.begin_write().map_err(store_err)?;
        {
            let mut table = txn.open_table(ACL).map_err(store_err)?;
            table.insert(key.as_str(), &[][..]).map_err(store_err)?;
        }
        txn.commit().map_err(store_err)?;
        Ok(())
    }

    fn revoke(&self, actor: &Principal, targets: &Targets) -> Result<bool> {
        let key = acl_key(actor, targets);
        let txn = self.db.begin_write().map_err(store_err)?;
        let removed = {
            let mut table = txn.open_table(ACL).map_err(store_err)?;
            table.remove(key.as_str()).map_err(store_err)?.is_some()
        };
        txn.commit().map_err(store_err)?;
        Ok(removed)
    }

    fn revoke_all(&self, actor: &Principal) -> Result<usize> {
        let prefix = format!("{actor}\t");
        let keys: Vec<String> = {
            let txn = self.db.begin_read().map_err(store_err)?;
            let table = txn.open_table(ACL).map_err(store_err)?;
            let mut keys = Vec::new();
            for entry in table.iter().map_err(store_err)? {
                let (k, _) = entry.map_err(store_err)?;
                let key = k.value();
                if key.starts_with(&prefix) {
                    keys.push(key.to_owned());
                }
            }
            keys
        };
        let txn = self.db.begin_write().map_err(store_err)?;
        {
            let mut table = txn.open_table(ACL).map_err(store_err)?;
            for key in &keys {
                table.remove(key.as_str()).map_err(store_err)?;
            }
        }
        txn.commit().map_err(store_err)?;
        Ok(keys.len())
    }
}

/// `actor` and `target` in one key: a tab cannot appear in a principal name, and
/// redb orders by it, so a listing comes out grouped by actor.
fn acl_key(actor: &Principal, targets: &Targets) -> String {
    let target = match targets {
        Targets::Any => "*".to_owned(),
        Targets::Only(p) => p.to_string(),
    };
    format!("{actor}\t{target}")
}

fn parse_acl_key(key: &str) -> Result<AclRule> {
    let (actor, target) = key
        .split_once('\t')
        .ok_or_else(|| Error::Hdb(format!("acl key {key:?} has no separator")))?;
    let actor = Principal::parse(actor)?;
    Ok(if target == "*" {
        AclRule::any(actor)
    } else {
        AclRule::only(actor, Principal::parse(target)?)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{Enctype, OwnCipher};
    use crate::hdb::flags;

    /// A database in a directory nobody else uses, removed when the test ends.
    ///
    /// The name carries the process id and the clock: `cargo test` runs the
    /// tests of one binary in parallel, so two of them that shared a file would
    /// see each other's principals and redb would refuse the second open.
    struct TempDb {
        dir: std::path::PathBuf,
        hdb: RedbHdb,
    }

    impl Drop for TempDb {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn temp_db() -> TempDb {
        let dir = std::env::temp_dir().join(format!(
            "rhk-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let hdb = RedbHdb::open(dir.join("hdb.redb")).unwrap();
        TempDb { dir, hdb }
    }

    /// A directory no other test uses, for the tests that want a file rather than a `TempDb`.
    fn temp_dir() -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "rhk-sealed-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn alice() -> HdbEntry {
        let cipher = OwnCipher;
        let mut e = HdbEntry::user(Principal::parse("alice@R").unwrap());
        e.add_password_key(&cipher, Enctype::Aes256Sha1, b"pw", 1)
            .unwrap();
        e.flags |= flags::REQUIRE_PREAUTH;
        e
    }

    #[test]
    fn an_entry_survives_a_store_and_a_fetch() {
        let t = temp_db();
        let hdb = &t.hdb;
        hdb.store(alice()).unwrap();
        let got = hdb
            .fetch(&Principal::parse("alice@R").unwrap())
            .unwrap()
            .unwrap();
        assert_eq!(got.principal.to_string(), "alice@R");
        assert_eq!(got.keys.len(), 1);
        assert_eq!(got.keys[0].key, alice().keys[0].key);
        assert_ne!(got.flags & flags::REQUIRE_PREAUTH, 0);
    }

    #[test]
    fn an_entry_survives_a_reopen() {
        // The point of a database rather than a map: it is still there after the
        // process that wrote it has gone.
        let dir = std::env::temp_dir().join(format!(
            "rhk-reopen-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("hdb.redb");
        {
            let hdb = RedbHdb::open(&path).unwrap();
            hdb.store(alice()).unwrap();
        }
        {
            let hdb = RedbHdb::open(&path).unwrap();
            let got = hdb.fetch(&Principal::parse("alice@R").unwrap()).unwrap();
            assert!(
                got.is_some(),
                "an entry must outlive the handle that wrote it"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ------------------------------------------------------------ keys at rest

    /// A master key for the sealing tests.
    fn master_pair() -> (crate::hdb::mkey::MasterKeys, crate::crypto::Key) {
        let key = OwnCipher.random(Enctype::Aes256Sha1).expect("a key");
        (crate::hdb::mkey::MasterKeys::single(key.clone(), 1), key)
    }

    /// A sealed database holds no key in the clear, and the same handle reads it back.
    ///
    /// The assertion is about the bytes on disk, not about the API: a store that sealed on the way
    /// out and unsealed on the way in but wrote plaintext in between would pass every round trip and
    /// protect nothing.
    #[test]
    fn a_sealed_database_holds_no_plaintext_key() {
        let dir = temp_dir();
        let path = dir.join("hdb.redb");
        let (master, mkey) = master_pair();
        let plain = alice().keys[0].key.bytes().to_vec();
        assert_eq!(plain.len(), 32);

        {
            let hdb = RedbHdb::open_sealed(&path, master, std::sync::Arc::new(OwnCipher))
                .expect("a sealed database");
            assert!(hdb.is_sealed());
            hdb.store(alice()).expect("stored");
            let got = hdb
                .fetch(&Principal::parse("alice@R").unwrap())
                .expect("a fetch")
                .expect("alice");
            assert_eq!(
                got.keys[0].key.bytes(),
                plain.as_slice(),
                "the handle that sealed it reads plaintext back"
            );
        }

        // The file itself: the key must not appear in it.
        let bytes = std::fs::read(&path).expect("the file");
        assert!(
            !bytes.windows(plain.len()).any(|w| w == plain.as_slice()),
            "a 32-octet key was found in the database file in the clear"
        );

        // And the record on disk is sealed in the form the codec defines: reading it **without** a
        // master key is refused, and reading it with one gives the key back. Checking the bytes for
        // absence alone would pass a store that wrote nothing at all.
        let raw = RedbHdb::open(&path)
            .expect("a plaintext handle reads the same file")
            .raw_record(&Principal::parse("alice@R").unwrap())
            .expect("the record");
        let err = record::decode(&raw).expect_err("the record is sealed");
        assert!(err.to_string().contains("sealed under master key"), "{err}");
        let opened = record::decode_with(
            &raw,
            Some((
                &OwnCipher,
                &crate::hdb::mkey::MasterKeys::single(mkey.clone(), 1),
            )),
        )
        .expect("the master key opens it");
        assert_eq!(opened.keys[0].key.bytes(), plain.as_slice());

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A sealed database opens with the same key set later — including across a handle, which is the
    /// arrangement a KDC restarts into.
    #[test]
    fn a_sealed_database_reopens_with_the_same_master_key() {
        let dir = temp_dir();
        let path = dir.join("hdb.redb");
        let (master, key) = master_pair();
        let plain = alice().keys[0].key.bytes().to_vec();
        {
            let hdb = RedbHdb::open_sealed(&path, master, std::sync::Arc::new(OwnCipher)).unwrap();
            hdb.store(alice()).unwrap();
        }
        {
            let master = crate::hdb::mkey::MasterKeys::single(key, 1);
            let hdb = RedbHdb::open_sealed(&path, master, std::sync::Arc::new(OwnCipher)).unwrap();
            let got = hdb
                .fetch(&Principal::parse("alice@R").unwrap())
                .unwrap()
                .expect("alice survived");
            assert_eq!(got.keys[0].key.bytes(), plain.as_slice());
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Without the master key the fetch is refused by name, and it says which key is missing: a
    /// caller that received 60 octets and called them a key would fail later, somewhere worse.
    #[test]
    fn a_sealed_database_without_its_master_key_refuses_by_name() {
        let dir = temp_dir();
        let path = dir.join("hdb.redb");
        let (master, _key) = master_pair();
        {
            let hdb = RedbHdb::open_sealed(&path, master, std::sync::Arc::new(OwnCipher)).unwrap();
            hdb.store(alice()).unwrap();
        }
        // The same file, opened without a master key: the plaintext constructor.
        let hdb = RedbHdb::open(&path).unwrap();
        let err = hdb
            .fetch(&Principal::parse("alice@R").unwrap())
            .expect_err("a sealed key needs the master key");
        let text = err.to_string();
        assert!(text.contains("sealed under master key"), "{text}");
        assert!(text.contains("no master key"), "{text}");

        // A walk still works: listing names is not reading keys, and a slave that lists its
        // principals should not need the keytab to do it.
        assert_eq!(
            hdb.first().unwrap().map(|p| p.name()),
            Some("alice".to_owned()),
            "the walk reads names only"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A master key that is not the one the database was sealed with is refused, and the refusal is
    /// about the key rather than about the record.
    #[test]
    fn the_wrong_master_key_is_refused() {
        let dir = temp_dir();
        let path = dir.join("hdb.redb");
        let (master, _key) = master_pair();
        {
            let hdb = RedbHdb::open_sealed(&path, master, std::sync::Arc::new(OwnCipher)).unwrap();
            hdb.store(alice()).unwrap();
        }
        let other = OwnCipher.random(Enctype::Aes256Sha1).unwrap();
        let hdb = RedbHdb::open_sealed(
            &path,
            crate::hdb::mkey::MasterKeys::single(other, 1),
            std::sync::Arc::new(OwnCipher),
        )
        .unwrap();
        let err = hdb
            .fetch(&Principal::parse("alice@R").unwrap())
            .expect_err("the wrong key");
        assert!(err.to_string().contains("does not open"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Rolling the master key re-seals every entry under the newest one, and the old key stops being
    /// needed: that is what makes a roll a roll rather than a permanent pair of keys.
    #[test]
    fn a_roll_reseals_everything_under_the_new_key() {
        let dir = temp_dir();
        let path = dir.join("hdb.redb");
        let old = OwnCipher.random(Enctype::Aes256Sha1).unwrap();
        let new = OwnCipher.random(Enctype::Aes256Sha1).unwrap();
        let plain = alice().keys[0].key.bytes().to_vec();
        {
            let hdb = RedbHdb::open_sealed(
                &path,
                crate::hdb::mkey::MasterKeys::single(old.clone(), 1),
                std::sync::Arc::new(OwnCipher),
            )
            .unwrap();
            hdb.store(alice()).unwrap();
        }
        {
            // The roll as it is actually done: the set holds the old key and the new one, every
            // entry is rewritten under the newest, and only then is the old one dropped.
            let hdb = RedbHdb::open_sealed(
                &path,
                crate::hdb::mkey::MasterKeys::from_keys([(old.clone(), 1), (new.clone(), 2)]),
                std::sync::Arc::new(OwnCipher),
            )
            .unwrap();
            assert_eq!(hdb.reseal().unwrap(), 1, "one entry, resealed");
        }
        {
            // Only the new key: the entries must no longer name the old one.
            let hdb = RedbHdb::open_sealed(
                &path,
                crate::hdb::mkey::MasterKeys::single(new, 2),
                std::sync::Arc::new(OwnCipher),
            )
            .unwrap();
            let got = hdb
                .fetch(&Principal::parse("alice@R").unwrap())
                .expect("the new key opens what the roll wrote")
                .expect("alice");
            assert_eq!(got.keys[0].key.bytes(), plain.as_slice());
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A set with several versions opens a record sealed under any of them, which is the state a
    /// database is in between the reseal and the removal of the old key.
    #[test]
    fn a_set_of_versions_opens_an_entry_sealed_by_an_older_one() {
        let dir = temp_dir();
        let path = dir.join("hdb.redb");
        let old = OwnCipher.random(Enctype::Aes256Sha1).unwrap();
        let new = OwnCipher.random(Enctype::Aes256Sha1).unwrap();
        {
            let hdb = RedbHdb::open_sealed(
                &path,
                crate::hdb::mkey::MasterKeys::single(old.clone(), 1),
                std::sync::Arc::new(OwnCipher),
            )
            .unwrap();
            hdb.store(alice()).unwrap();
        }
        let both = crate::hdb::mkey::MasterKeys::from_keys([(old, 1), (new, 2)]);
        let hdb = RedbHdb::open_sealed(&path, both, std::sync::Arc::new(OwnCipher)).unwrap();
        assert!(
            hdb.fetch(&Principal::parse("alice@R").unwrap())
                .expect("the old key is in the set")
                .is_some()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// An empty key set is refused at open: a database that silently stored plaintext under
    /// `open_sealed` would be the exact mistake that constructor exists to prevent.
    #[test]
    fn an_empty_key_set_is_refused_at_open() {
        let dir = temp_dir();
        let err = RedbHdb::open_sealed(
            dir.join("hdb.redb"),
            crate::hdb::mkey::MasterKeys::none(),
            std::sync::Arc::new(OwnCipher),
        )
        .expect_err("no key");
        assert!(err.to_string().contains("no master key"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A rename does not lose the sealing: the record moves and stays sealed, and the entry reads
    /// back with its key.
    #[test]
    fn a_rename_keeps_the_keys_sealed() {
        let dir = temp_dir();
        let path = dir.join("hdb.redb");
        let (master, key) = master_pair();
        let plain = alice().keys[0].key.bytes().to_vec();
        {
            let hdb = RedbHdb::open_sealed(&path, master, std::sync::Arc::new(OwnCipher)).unwrap();
            hdb.store(alice()).unwrap();
            hdb.rename(
                &Principal::parse("alice@R").unwrap(),
                &Principal::parse("carol@R").unwrap(),
            )
            .unwrap();
        }
        let bytes = std::fs::read(&path).unwrap();
        assert!(
            !bytes.windows(plain.len()).any(|w| w == plain.as_slice()),
            "a rename must not write the key in the clear"
        );
        let hdb = RedbHdb::open_sealed(
            &path,
            crate::hdb::mkey::MasterKeys::single(key, 1),
            std::sync::Arc::new(OwnCipher),
        )
        .unwrap();
        let carol = hdb
            .fetch(&Principal::parse("carol@R").unwrap())
            .unwrap()
            .expect("carol");
        assert_eq!(carol.keys[0].key.bytes(), plain.as_slice());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// An unsealed database still opens through a sealed handle: a realm that provisions a master
    /// key does not have to rebuild its database, and the plaintext keys are re-sealed the next time
    /// they are written.
    #[test]
    fn a_plaintext_database_is_readable_through_a_sealed_handle() {
        let dir = temp_dir();
        let path = dir.join("hdb.redb");
        let plain = alice().keys[0].key.bytes().to_vec();
        {
            let hdb = RedbHdb::open(&path).unwrap();
            hdb.store(alice()).unwrap();
        }
        let (master, _key) = master_pair();
        let hdb = RedbHdb::open_sealed(&path, master, std::sync::Arc::new(OwnCipher)).unwrap();
        let got = hdb
            .fetch(&Principal::parse("alice@R").unwrap())
            .unwrap()
            .expect("alice");
        assert_eq!(got.keys[0].key.bytes(), plain.as_slice());
        // And one reseal makes the file require the master key.
        assert_eq!(hdb.reseal().unwrap(), 1);
        drop(hdb);
        let plain_handle = RedbHdb::open(&path).unwrap();
        assert!(
            plain_handle
                .fetch(&Principal::parse("alice@R").unwrap())
                .is_err(),
            "after a reseal the file needs the master key"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_unknown_principal_is_none() {
        let t = temp_db();
        let hdb = &t.hdb;
        assert!(
            hdb.fetch(&Principal::parse("nobody@R").unwrap())
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn removing_twice_reports_the_second_as_absent() {
        let t = temp_db();
        let hdb = &t.hdb;
        hdb.store(alice()).unwrap();
        assert!(hdb.remove(&Principal::parse("alice@R").unwrap()).unwrap());
        assert!(!hdb.remove(&Principal::parse("alice@R").unwrap()).unwrap());
        assert!(
            hdb.fetch(&Principal::parse("alice@R").unwrap())
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn rename_moves_the_keys_and_leaves_nothing_behind() {
        let t = temp_db();
        let hdb = &t.hdb;
        hdb.store(alice()).unwrap();
        hdb.rename(
            &Principal::parse("alice@R").unwrap(),
            &Principal::parse("carol@R").unwrap(),
        )
        .unwrap();
        assert!(
            hdb.fetch(&Principal::parse("alice@R").unwrap())
                .unwrap()
                .is_none()
        );
        let carol = hdb
            .fetch(&Principal::parse("carol@R").unwrap())
            .unwrap()
            .unwrap();
        assert_eq!(carol.principal.to_string(), "carol@R");
        assert_eq!(carol.keys.len(), 1);
        assert_eq!(carol.keys[0].key, alice().keys[0].key);
    }

    #[test]
    fn renaming_a_principal_that_is_not_there_is_an_error() {
        let t = temp_db();
        let hdb = &t.hdb;
        assert!(
            hdb.rename(
                &Principal::parse("nobody@R").unwrap(),
                &Principal::parse("x@R").unwrap()
            )
            .is_err()
        );
    }

    #[test]
    fn the_walk_visits_every_principal_once() {
        let t = temp_db();
        let hdb = &t.hdb;
        for name in ["bob", "alice", "dave", "carol"] {
            hdb.store(HdbEntry::user(
                Principal::parse(&format!("{name}@R")).unwrap(),
            ))
            .unwrap();
        }
        let mut seen = Vec::new();
        let mut cur = hdb.first().unwrap();
        while let Some(p) = cur {
            seen.push(p.name());
            cur = hdb.next(&p).unwrap();
        }
        // Ordered by the stored key, which is `name@realm`.
        assert_eq!(seen, ["alice", "bob", "carol", "dave"]);
    }

    #[test]
    fn a_walk_over_an_empty_database_ends_immediately() {
        let t = temp_db();
        let hdb = &t.hdb;
        assert!(hdb.first().unwrap().is_none());
        assert!(
            hdb.next(&Principal::parse("a@R").unwrap())
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn a_walk_orders_by_name_across_realms() {
        let t = temp_db();
        let hdb = &t.hdb;
        for (name, realm) in [("a", "ONE"), ("b", "TWO"), ("c", "ONE")] {
            hdb.store(HdbEntry::user(
                Principal::parse(&format!("{name}@{realm}")).unwrap(),
            ))
            .unwrap();
        }
        let mut seen = Vec::new();
        let mut cur = hdb.first().unwrap();
        while let Some(p) = cur {
            seen.push(p.to_string());
            cur = hdb.next(&p).unwrap();
        }
        // The stored key is `name@realm`, so the walk orders by name first and
        // the two realms interleave: `a@ONE` < `b@TWO` < `c@ONE`.
        assert_eq!(seen, ["a@ONE", "b@TWO", "c@ONE"]);
    }
}
