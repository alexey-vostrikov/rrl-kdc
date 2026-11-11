//! Managing a realm: create, delete, modify, re-key, export a keytab.
//!
//! This is the layer `kadmin` is a client of. It lives here, as a library, for
//! the reason the KDC does: the operations are the same whatever transport
//! carries them, and an embedder that already has a directory (or an HTTP API, or
//! a CLI) should not have to speak `kadmin`'s RPC to add a principal.
//!
//! # Rules that are not negotiable
//!
//! * **Creating never overwrites.** [`Admin::create`] fails on an existing
//!   principal. An "add" that silently replaced an entry would reset the keys of
//!   an account somebody is using, and the operator would read success.
//! * **Re-keying moves the kvno and keeps the old keys.** Tickets issued a
//!   moment ago stay valid, and a service that has not re-read its keytab yet can
//!   still read them. The oldest keys are dropped only when the caller asks.
//! * **`krbtgt` is immutable.** Every ticket in the realm is sealed with it; a
//!   delete is an outage that cannot be undone from the database alone.
//! * **The keytab carries every key, not just the newest.** A service that
//!   deploys a new keytab before the KDC changes the password must accept tickets
//!   sealed with either — that is what a kvno is for.

#[cfg(feature = "admin-json")]
pub mod json;
pub mod wire;

use std::sync::Arc;

use crate::crypto::{Cipher, Enctype, Key};
use crate::error::{Error, Result};
use crate::hdb::{Hdb, HdbEntry, Keytab, Policy, flags as entry_flags, keytab::KeytabEntry};
use crate::name::Principal;

/// What to give a new account.
#[derive(Clone, Debug)]
pub struct NewPrincipal {
    /// The principal to create.
    pub principal: Principal,
    /// The password its keys are derived from. Empty means "keys only, added
    /// later" — a service whose key comes from a keytab, say.
    pub password: Vec<u8>,
    /// The enctypes to derive keys for. Empty means every enctype this KDC
    /// issues.
    pub enctypes: Vec<Enctype>,
    /// Whether it may ask for tickets (`client`), be issued them (`server`), or
    /// both.
    pub role: Role,
}

impl NewPrincipal {
    /// A user account, keyed with every enctype this KDC issues.
    pub fn user(principal: Principal, password: impl Into<Vec<u8>>) -> Self {
        NewPrincipal {
            principal,
            password: password.into(),
            enctypes: Vec::new(),
            role: Role::Client,
        }
    }

    /// A service account — `host/x`, `nfs/y`, and anything a keytab is for.
    pub fn service(principal: Principal, password: impl Into<Vec<u8>>) -> Self {
        NewPrincipal {
            principal,
            password: password.into(),
            enctypes: Vec::new(),
            role: Role::Server,
        }
    }

    /// Restricts the enctypes keys are derived for.
    pub fn with_enctypes(mut self, enctypes: &[Enctype]) -> Self {
        self.enctypes = enctypes.to_vec();
        self
    }
}

/// What a principal may do.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// May ask for tickets.
    Client,
    /// May be the target of one.
    Server,
    /// Both — a principal that is both a person and a service, as a machine
    /// account is.
    Both,
}

impl Role {
    fn flags(self) -> u32 {
        match self {
            Role::Client => entry_flags::CLIENT | entry_flags::REQUIRE_PREAUTH,
            Role::Server => entry_flags::SERVER,
            Role::Both => entry_flags::CLIENT | entry_flags::SERVER | entry_flags::REQUIRE_PREAUTH,
        }
    }
}

/// A change to an existing entry.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Modify {
    /// Turn `invalid` on or off.
    pub invalid: Option<bool>,
    /// Turn `locked-out` on or off.
    pub locked_out: Option<bool>,
    /// Set or clear `valid-end`.
    pub valid_end: Option<Option<i64>>,
    /// Set or clear `pw-end`.
    pub pw_end: Option<Option<i64>>,
    /// Set or clear `max-life`.
    pub max_life: Option<Option<i64>>,
    /// Set or clear `max-renewable-life` — MIT's `KADM5_MAX_RLIFE`.
    pub max_renew: Option<Option<i64>>,
    /// Set or clear `ok-as-delegate`.
    pub ok_as_delegate: Option<bool>,
    /// Turn `require-preauth` on or off — MIT's `REQUIRES_PRE_AUTH`.
    ///
    /// Modelled separately from the rest of the attribute word because turning it *off* has a
    /// consequence — a principal without pre-authentication is one whose password can be cracked
    /// offline from a single captured reply — so it is an attribute an operator has to name rather
    /// than one a shared mask toggles by accident.
    pub require_preauth: Option<bool>,
    /// Turn `require-hwauth` on or off — MIT's `REQUIRES_HW_AUTH`.
    pub require_hwauth: Option<bool>,
    /// Whether a ticket may be issued *for* the principal — MIT's `DISALLOW_SVR`, inverted.
    pub allow_server: Option<bool>,
    /// Turn the password-change service on or off — MIT's `PWCHANGE_SERVICE`.
    pub change_password_service: Option<bool>,
    /// The `DISALLOW_*` ticket attributes, inverted: whether a ticket may be forwardable,
    /// proxiable, renewable or postdated.
    ///
    /// Four fields rather than one word because these are the four an operator actually sets, and
    /// the KDC reads each of them separately (`hdb` flags `forwardable`, `proxiable`, `renewable`,
    /// `postdate`).
    pub forwardable: Option<bool>,
    /// See [`Modify::forwardable`].
    pub proxiable: Option<bool>,
    /// See [`Modify::forwardable`].
    pub renewable: Option<bool>,
    /// See [`Modify::forwardable`].
    pub postdated: Option<bool>,
    /// The policy to put the principal under — MIT's `KADM5_POLICY` (`Some(Some(name))`),
    /// `KADM5_POLICY_CLR` (`Some(None)`), or neither (`None`, which leaves the policy alone).
    ///
    /// A name, not the rules: changing the policy changes every account under it, which is the
    /// reason an operator gives an account a policy instead of repeating the numbers on each one.
    pub policy: Option<Option<String>>,
    /// The key version to set — MIT's `KADM5_KVNO`.
    ///
    /// Not the keys themselves: it renumbers what is there, which is what an operator does after
    /// restoring keys from a backup. Zero, and a value below the highest key, are refused by
    /// [`Admin::modify`], because neither names a state a keytab can be built from.
    pub kvno: Option<u32>,
}

impl Modify {
    /// Whether this change would alter anything.
    pub fn is_empty(&self) -> bool {
        self == &Modify::default()
    }
}

/// The realm, from the managing side.
#[derive(Debug, Clone)]
pub struct Admin {
    realm: String,
    hdb: Arc<dyn Hdb>,
    cipher: Arc<dyn Cipher>,
    allowed: Vec<Enctype>,
    /// Who may do what. `DenyAll` until the embedder says otherwise, because a
    /// default that allows turns a forgotten configuration into an open realm.
    policy: Arc<dyn wire::Policy>,
}

impl Admin {
    /// An administrator over `hdb`, issuing `allowed` enctypes.
    pub fn new(
        realm: impl Into<String>,
        hdb: Arc<dyn Hdb>,
        cipher: Arc<dyn Cipher>,
        allowed: &[Enctype],
    ) -> Self {
        Admin {
            realm: realm.into(),
            hdb,
            cipher,
            allowed: allowed.to_vec(),
            policy: Arc::new(wire::DenyAll),
        }
    }

    /// An administrator whose enctypes are the four this crate issues.
    pub fn with_defaults(
        realm: impl Into<String>,
        hdb: Arc<dyn Hdb>,
        cipher: Arc<dyn Cipher>,
    ) -> Self {
        Admin::new(realm, hdb, cipher, &Enctype::ALL)
    }

    /// The realm being managed.
    pub fn realm(&self) -> &str {
        &self.realm
    }

    /// Every principal, in the backend's order.
    pub fn list(&self) -> Result<Vec<Principal>> {
        let mut out = Vec::new();
        let mut next = self.hdb.first()?;
        while let Some(p) = next {
            // The walk's own bound is the principal it just returned; a backend
            // that returned it again would loop forever, so the client passes
            // it back and expects the *next* one.
            next = self.hdb.next(&p)?;
            out.push(p);
        }
        Ok(out)
    }

    /// One entry.
    pub fn get(&self, principal: &Principal) -> Result<HdbEntry> {
        self.hdb
            .fetch(principal)?
            // `NotFound` and not `Hdb`: an absent account is a fact about the
            // realm, not a storage failure, and a transport answers the two with
            // different status codes.
            .ok_or_else(|| Error::NotFound(principal.to_string()))
    }

    /// Creates a principal, or fails if it exists.
    pub fn create(&self, new: NewPrincipal) -> Result<HdbEntry> {
        let mut principal = new.principal;
        if principal.realm.is_empty() {
            principal.realm = self.realm.clone();
        }
        if principal.realm != self.realm {
            return Err(Error::Config(format!(
                "{principal} is in {}, and this administrator manages {}",
                principal.realm, self.realm
            )));
        }
        if self.hdb.fetch(&principal)?.is_some() {
            return Err(Error::Exists(format!(
                "{principal}: creating it would replace its keys, which would invalidate every \
                 ticket already issued to it"
            )));
        }

        let mut entry = HdbEntry {
            principal: principal.clone(),
            keys: Vec::new(),
            kvno: 0,
            flags: new.role.flags()
                | entry_flags::INITIAL
                | entry_flags::FORWARDABLE
                | entry_flags::PROXIABLE
                | entry_flags::RENEWABLE,
            valid_start: None,
            valid_end: None,
            pw_end: None,
            max_life: None,
            max_renew: None,
            etypes: None,
            modified: 0,
            // Delegation limits are an HDB extension a directory cannot hold; a principal
            // created through the admin interface delegates nowhere but itself.
            constrained_delegation: None,
            // Nor does a new principal have other names; `rename` and `alias` are separate
            // operations, and an alias list invented here would be one nobody asked for.
            aliases: None,
            policy: None,
            strings: Vec::new(),
        };

        let enctypes = if new.enctypes.is_empty() {
            self.allowed.clone()
        } else {
            new.enctypes
        };
        if !new.password.is_empty() {
            if enctypes.is_empty() {
                return Err(Error::Config(
                    "no enctypes to derive keys for: the KDC may issue none".into(),
                ));
            }
            for enctype in &enctypes {
                entry.add_password_key(self.cipher.as_ref(), *enctype, &new.password, 1)?;
            }
        }
        self.hdb.store(entry.clone())?;
        Ok(entry)
    }

    /// Removes a principal; returns whether there was one.
    ///
    /// Refuses `krbtgt`: every ticket in the realm is sealed with its key, and a
    /// delete is an outage that no later re-create repairs, because the new key
    /// will not open the old tickets.
    pub fn delete(&self, principal: &Principal) -> Result<bool> {
        let entry = match self.hdb.fetch(principal)? {
            None => return Ok(false),
            Some(e) => e,
        };
        if entry.has(entry_flags::IMMUTABLE) || principal.is_krbtgt() {
            return Err(Error::Kdc {
                code: crate::error::codes::KDC_ERR_POLICY,
                text: format!("{principal} may not be deleted"),
            });
        }
        self.hdb.remove(principal)
    }

    /// Renames a principal, taking its keys, kvno and flags with it.
    ///
    /// Two refusals before anything moves, both MIT's and both for the same reason — a rename that
    /// half happened loses either the keys or the name, and neither is recoverable from the other:
    /// the source must exist, and the target must not. A name that already exists is a merge, and
    /// merging two accounts is not a rename: it would silently decide whose keys win.
    ///
    /// `krbtgt` and `immutable` entries are refused as well, the same two that [`Admin::delete`]
    /// refuses; renaming either leaves a realm that cannot issue a ticket.
    pub fn rename(&self, from: &Principal, to: &Principal) -> Result<()> {
        if from == to {
            return Err(Error::Config(format!("{from} is already its own name")));
        }
        let entry = self.get(from)?;
        if entry.has(entry_flags::IMMUTABLE) || from.is_krbtgt() {
            return Err(Error::Kdc {
                code: crate::error::codes::KDC_ERR_POLICY,
                text: format!("{from} may not be renamed"),
            });
        }
        if self.hdb.fetch(to)?.is_some() {
            return Err(Error::Exists(format!(
                "{to} already exists; a rename onto an existing principal would merge two accounts"
            )));
        }
        self.hdb.rename(from, to)
    }

    /// The string attributes of a principal, in the order they were set.
    pub fn strings(&self, principal: &Principal) -> Result<Vec<(String, String)>> {
        Ok(self.get(principal)?.strings)
    }

    /// Sets one string attribute, replacing a value with the same key.
    ///
    /// An empty key is refused: a pair with no name is one no caller can ask for, so storing it
    /// would be storing something nothing reads. An empty value is allowed and means "present and
    /// empty", which is not the same as absent — the distinction is how an operator says "this
    /// attribute exists but is blank" to whatever reads it.
    pub fn set_string(&self, principal: &Principal, key: &str, value: &str) -> Result<HdbEntry> {
        if key.is_empty() {
            return Err(Error::Config(
                "an empty string-attribute key: a pair with no name is one nothing can ask for"
                    .into(),
            ));
        }
        let mut entry = self.get(principal)?;
        match entry.strings.iter_mut().find(|(k, _)| k == key) {
            Some(pair) => pair.1 = value.to_owned(),
            None => entry.strings.push((key.to_owned(), value.to_owned())),
        }
        self.hdb.store(entry.clone())?;
        Ok(entry)
    }

    /// Removes one string attribute; returns whether it was there.
    ///
    /// Removing what is not there is not an error, for the same reason deleting an unknown
    /// principal is not: the caller asked for an end state, and the end state is what it gets.
    /// [`Admin::strings`] is how it can tell.
    pub fn delete_string(&self, principal: &Principal, key: &str) -> Result<bool> {
        let mut entry = self.get(principal)?;
        let before = entry.strings.len();
        entry.strings.retain(|(k, _)| k != key);
        if entry.strings.len() == before {
            return Ok(false);
        }
        self.hdb.store(entry)?;
        Ok(true)
    }

    /// Applies `change` to an existing entry.
    pub fn modify(&self, principal: &Principal, change: Modify) -> Result<HdbEntry> {
        if change.is_empty() {
            return Err(Error::Config(
                "an empty modification: nothing to do, and a no-op that reports success is a \
                 change an operator will believe happened"
                    .into(),
            ));
        }
        let mut entry = self.get(principal)?;
        if let Some(invalid) = change.invalid {
            entry.flags = set_flag(entry.flags, entry_flags::INVALID, invalid);
        }
        if let Some(locked) = change.locked_out {
            entry.flags = set_flag(entry.flags, entry_flags::LOCKED_OUT, locked);
        }
        if let Some(delegate) = change.ok_as_delegate {
            entry.flags = set_flag(entry.flags, entry_flags::OK_AS_DELEGATE, delegate);
        }
        if let Some(end) = change.valid_end {
            entry.valid_end = end;
        }
        if let Some(end) = change.pw_end {
            entry.pw_end = end;
        }
        if let Some(life) = change.max_life {
            entry.max_life = life;
        }
        if let Some(renew) = change.max_renew {
            entry.max_renew = renew;
        }
        // Each attribute is applied on its own: the caller names the ones it means, and one it
        // leaves out keeps whatever the entry had.
        for (value, flag) in [
            (change.require_preauth, entry_flags::REQUIRE_PREAUTH),
            (change.require_hwauth, entry_flags::REQUIRE_HWAUTH),
            (change.allow_server, entry_flags::SERVER),
            (change.change_password_service, entry_flags::CHANGE_PW),
            (change.forwardable, entry_flags::FORWARDABLE),
            (change.proxiable, entry_flags::PROXIABLE),
            (change.renewable, entry_flags::RENEWABLE),
            (change.postdated, entry_flags::POSTDATE),
        ] {
            if let Some(on) = value {
                entry.flags = set_flag(entry.flags, flag, on);
            }
        }
        if let Some(policy) = change.policy {
            // A policy that does not exist would leave the entry citing nothing, and every later
            // lookup of its rules would fail — or worse, be treated as "no limits".
            if let Some(name) = &policy
                && self.hdb.fetch_policy(name)?.is_none()
            {
                return Err(Error::NotFound(format!("no policy {name}")));
            }
            entry.policy = policy;
        }
        if let Some(kvno) = change.kvno {
            // The keys keep their own versions; only the entry's moves, and only forward: an entry
            // below its highest key is a state `HdbEntry::kvno` will not derive, and the backends
            // report it rather than repair it.
            if kvno == 0 {
                return Err(Error::Config(
                    "kvno 0: a principal at version zero has keys nothing can name".into(),
                ));
            }
            if kvno < entry.kvno() {
                return Err(Error::Config(format!(
                    "kvno {kvno} is below the highest key version {}; an entry cannot go back",
                    entry.kvno()
                )));
            }
            entry.kvno = kvno;
        }
        self.hdb.store(entry.clone())?;
        Ok(entry)
    }

    /// Creates a policy.
    ///
    /// Refuses a name that is taken (`Error::Exists`) and one a [`Policy::check`] rejects. Not a
    /// replace: an `addpol` that silently overwrote would move every account under that policy
    /// without the operator having asked, which is what `modpol` is for.
    pub fn create_policy(&self, policy: Policy) -> Result<Policy> {
        policy.check()?;
        if self.hdb.fetch_policy(&policy.name)?.is_some() {
            return Err(Error::Exists(format!("policy {}", policy.name)));
        }
        self.hdb.store_policy(policy.clone())?;
        Ok(policy)
    }

    /// Replaces an existing policy; the name is the key, so it must already be there.
    pub fn modify_policy(&self, policy: Policy) -> Result<Policy> {
        policy.check()?;
        if self.hdb.fetch_policy(&policy.name)?.is_none() {
            return Err(Error::NotFound(format!("no policy {}", policy.name)));
        }
        self.hdb.store_policy(policy.clone())?;
        Ok(policy)
    }

    /// Removes a policy; returns whether there was one.
    ///
    /// A policy an entry cites is not removed: the entry would go on citing a name that resolves
    /// to nothing, and every read of its rules would have to guess whether that means "no limits".
    /// [`Hdb::policy_refcount`] is what says so, counted rather than kept as a number.
    pub fn delete_policy(&self, name: &str) -> Result<bool> {
        if self.hdb.fetch_policy(name)?.is_none() {
            return Ok(false);
        }
        let in_use = self.hdb.policy_refcount(name)?;
        if in_use > 0 {
            return Err(Error::Forbidden(format!(
                "policy {name} is in use by {in_use} principal(s)"
            )));
        }
        self.hdb.remove_policy(name)
    }

    /// The policy called `name`, if there is one.
    ///
    /// Not `policy`: that name belongs to the accessor that hands out the authorization rules,
    /// and two things called a policy in one type is one too many.
    pub fn fetch_policy(&self, name: &str) -> Result<Option<Policy>> {
        self.hdb.fetch_policy(name)
    }

    /// Every policy's name, sorted.
    pub fn policies(&self) -> Result<Vec<String>> {
        let mut names = self.hdb.policies()?;
        names.sort();
        Ok(names)
    }

    /// The policy `principal` is under, if any.
    pub fn policy_of(&self, principal: &Principal) -> Result<Option<Policy>> {
        match self.get(principal)?.policy {
            None => Ok(None),
            Some(name) => self.hdb.fetch_policy(&name),
        }
    }

    /// Sets a password: new keys at the next kvno, the old ones kept.
    ///
    /// Returns the kvno the new keys are at, which is what a service needs to
    /// know when it re-reads its keytab.
    pub fn set_password(&self, principal: &Principal, password: &[u8]) -> Result<u32> {
        if password.is_empty() {
            return Err(Error::Config(
                "an empty password: a key derived from nothing is a key everybody has".into(),
            ));
        }
        let entry = self.get(principal)?;
        // The policy is checked before the keys are derived: a refused password must not leave a
        // half-made key behind, and the operator wants the rule named, not a mismatched ticket.
        if let Some(name) = &entry.policy {
            match self.hdb.fetch_policy(name)? {
                Some(policy) => policy.admits_password(password)?,
                // An entry citing a policy the database does not have is a broken database, and a
                // password accepted under a rule nobody can read is the wrong way to report it.
                None => {
                    return Err(Error::Hdb(format!(
                        "{principal} is under policy {name}, which is not in the database"
                    )));
                }
            }
        }
        let updated = entry.rekey(self.cipher.as_ref(), password)?;
        let kvno = updated.kvno();
        self.hdb.store(updated)?;
        Ok(kvno)
    }

    /// Drops every key below the current kvno.
    ///
    /// The one operation that makes old tickets stop working, which is why it is
    /// separate from [`Self::set_password`]: a password change should not
    /// invalidate the tickets a user just obtained, and an operator who wants that
    /// says so.
    pub fn prune_old_keys(&self, principal: &Principal) -> Result<usize> {
        let mut entry = self.get(principal)?;
        let current = entry.kvno();
        let before = entry.keys.len();
        entry.keys.retain(|k| k.kvno == current);
        let removed = before - entry.keys.len();
        if removed > 0 {
            self.hdb.store(entry)?;
        }
        Ok(removed)
    }

    /// A keytab of `principals`, carrying every key each entry holds.
    pub fn keytab(&self, principals: &[Principal]) -> Result<Keytab> {
        let mut keytab = Keytab::new();
        for principal in principals {
            let entry = self.get(principal)?;
            if entry.keys.is_empty() {
                return Err(Error::Hdb(format!(
                    "{principal} has no keys, so a keytab for it would be empty"
                )));
            }
            for held in &entry.keys {
                keytab.add(KeytabEntry {
                    principal: entry.principal.clone(),
                    key: held.key.clone(),
                    kvno: held.kvno,
                    // The keytab's timestamp is informational; zero means "not
                    // recorded", which is more honest than a made-up instant.
                    timestamp: 0,
                });
            }
        }
        Ok(keytab)
    }

    /// A keytab of one principal.
    pub fn keytab_for(&self, principal: &Principal) -> Result<Keytab> {
        self.keytab(std::slice::from_ref(principal))
    }

    /// Adds a raw key to an entry — what importing a keytab does.
    pub fn add_key(
        &self,
        principal: &Principal,
        key: Key,
        kvno: u32,
        salt: Option<Vec<u8>>,
    ) -> Result<()> {
        let mut entry = self.get(principal)?;
        if entry.key_for(key.enctype()).is_some_and(|k| k.kvno > kvno) {
            return Err(Error::Hdb(format!(
                "{principal} already holds a {} key at a higher kvno",
                key.enctype().name()
            )));
        }
        entry.add_key(key, kvno, salt);
        self.hdb.store(entry)
    }
}

fn set_flag(flags: u32, flag: u32, on: bool) -> u32 {
    if on { flags | flag } else { flags & !flag }
}
