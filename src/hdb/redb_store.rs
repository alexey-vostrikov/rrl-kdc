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

use crate::error::{Error, Result};
use crate::name::Principal;

use crate::acl::{AclRule, AclStore, Targets};

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

/// The `hdb` interface over a redb file.
#[derive(Debug)]
pub struct RedbHdb {
    db: Database,
    path: PathBuf,
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
        }
        txn.commit().map_err(store_err)?;
        Ok(RedbHdb { db, path })
    }

    /// The file this backend is using.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

fn store_err(e: impl std::fmt::Display) -> Error {
    Error::Hdb(format!("redb: {e}"))
}

impl Hdb for RedbHdb {
    fn fetch(&self, principal: &Principal) -> Result<Option<HdbEntry>> {
        let k = record::key(principal);
        let txn = self.db.begin_read().map_err(store_err)?;
        let table = txn.open_table(ENTRIES).map_err(store_err)?;
        match table.get(k.as_str()).map_err(store_err)? {
            None => Ok(None),
            Some(value) => Ok(Some(record::decode(value.value())?)),
        }
    }

    fn store(&self, entry: HdbEntry) -> Result<()> {
        let k = record::key(&entry.principal);
        let bytes = record::encode(&entry);
        let txn = self.db.begin_write().map_err(store_err)?;
        {
            let mut table = txn.open_table(ENTRIES).map_err(store_err)?;
            table
                .insert(k.as_str(), bytes.as_slice())
                .map_err(store_err)?;
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
        let mut entry = record::decode(&bytes)?;
        entry.principal = to.clone();
        let encoded = record::encode(&entry);
        let txn = self.db.begin_write().map_err(store_err)?;
        {
            let mut table = txn.open_table(ENTRIES).map_err(store_err)?;
            table.remove(from_key.as_str()).map_err(store_err)?;
            table
                .insert(to_key.as_str(), encoded.as_slice())
                .map_err(store_err)?;
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
            let principal = record::decode(value.value())?.principal;
            return Ok(Some(principal));
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
