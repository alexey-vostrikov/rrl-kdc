//! Who may change whose password, stored rather than configured.
//!
//! Heimdal keeps this in `kadmind.acl`, a text file an administrator edits. That
//! is wrong for an embedded KDC for two reasons: the file is a second source of
//! truth next to the database (so a change needs a restart, and a backup needs
//! two files), and it cannot be managed by whatever already manages the
//! principals — for an LDAP-backed realm, that is the directory itself.
//!
//! So the rules live in a store, [`AclStore`], with [`MemoryAcl`] for a stand and
//! [`RedbAcl`](crate::hdb::redb_store::RedbAcl) for a real one. The policy is
//! read on every decision rather than cached: a password change is rare, and a
//! cached rule that survives a revocation is a rule that lets somebody in after
//! they were removed.
//!
//! # What a rule says
//!
//! One rule grants one actor the right to change passwords of some targets. There
//! is no deny rule and no ordering: a KDC's password-change ACL in Heimdal has
//! exactly one positive right (`change-password`), and a system that can say
//! "no" in two ways needs a policy engine to explain which one won.

use std::collections::BTreeMap;
use std::sync::RwLock;

use crate::error::{Error, Result};
use crate::kdc::ChangePolicy;
use crate::name::Principal;

/// Which accounts an actor may change.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Targets {
    /// Any principal in the realm this rule belongs to.
    Any,
    /// One named principal.
    Only(Principal),
}

/// One rule: `actor` may change `targets`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AclRule {
    /// Who is allowed.
    pub actor: Principal,
    /// What they are allowed to change.
    pub targets: Targets,
}

impl AclRule {
    /// A rule allowing `actor` to change any password.
    pub fn any(actor: Principal) -> Self {
        AclRule {
            actor,
            targets: Targets::Any,
        }
    }

    /// A rule allowing `actor` to change `target`'s password.
    pub fn only(actor: Principal, target: Principal) -> Self {
        AclRule {
            actor,
            targets: Targets::Only(target),
        }
    }
}

/// Where the change-password rules live.
///
/// A store rather than a list because the question a KDC asks (`may alice change
/// bob's password?`) has to be answered from durable state: a rule granted before
/// a restart and forgotten after it is a rule that did not exist.
pub trait AclStore: std::fmt::Debug + Send + Sync {
    /// Every rule, for an administrator to look at.
    fn rules(&self) -> Result<Vec<AclRule>>;

    /// Grants `actor` the right to change `targets`.
    ///
    /// Idempotent: granting a right that is already granted succeeds and changes
    /// nothing, because an operator repeating a command must not have to know
    /// whether it was already there.
    fn grant(&self, actor: &Principal, targets: Targets) -> Result<()>;

    /// Withdraws one grant; returns whether there was one.
    fn revoke(&self, actor: &Principal, targets: &Targets) -> Result<bool>;

    /// Withdraws everything `actor` was allowed to do.
    fn revoke_all(&self, actor: &Principal) -> Result<usize>;
}

/// Rules in memory: what a stand uses, and what a test drives.
#[derive(Debug, Default)]
pub struct MemoryAcl {
    rules: RwLock<Vec<AclRule>>,
}

impl MemoryAcl {
    /// An empty set of rules.
    pub fn new() -> Self {
        MemoryAcl::default()
    }

    /// A store shared the way a KDC holds one.
    pub fn shared(self) -> std::sync::Arc<dyn AclStore> {
        std::sync::Arc::new(self)
    }

    /// How many rules there are — for tests and diagnostics.
    pub fn len(&self) -> usize {
        self.rules.read().map(|r| r.len()).unwrap_or(0)
    }

    /// Whether there are no rules at all.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl AclStore for MemoryAcl {
    fn rules(&self) -> Result<Vec<AclRule>> {
        Ok(self
            .rules
            .read()
            .map_err(|_| Error::Hdb("acl lock poisoned".into()))?
            .clone())
    }

    fn grant(&self, actor: &Principal, targets: Targets) -> Result<()> {
        let mut rules = self
            .rules
            .write()
            .map_err(|_| Error::Hdb("acl lock poisoned".into()))?;
        let rule = AclRule {
            actor: actor.clone(),
            targets,
        };
        if !rules.contains(&rule) {
            rules.push(rule);
        }
        Ok(())
    }

    fn revoke(&self, actor: &Principal, targets: &Targets) -> Result<bool> {
        let mut rules = self
            .rules
            .write()
            .map_err(|_| Error::Hdb("acl lock poisoned".into()))?;
        let before = rules.len();
        rules.retain(|r| !(r.actor == *actor && r.targets == *targets));
        Ok(rules.len() != before)
    }

    fn revoke_all(&self, actor: &Principal) -> Result<usize> {
        let mut rules = self
            .rules
            .write()
            .map_err(|_| Error::Hdb("acl lock poisoned".into()))?;
        let before = rules.len();
        rules.retain(|r| r.actor != *actor);
        Ok(before - rules.len())
    }
}

/// A [`ChangePolicy`] that reads the rules from a store.
///
/// Self-service is always allowed and needs no rule: a person changing their own
/// password is not a privilege, and requiring a rule for it would mean a fresh
/// realm in which nobody can change their password at all.
#[derive(Debug)]
pub struct StoredAclPolicy {
    store: std::sync::Arc<dyn AclStore>,
}

impl StoredAclPolicy {
    /// A policy over `store`.
    pub fn new(store: std::sync::Arc<dyn AclStore>) -> Self {
        StoredAclPolicy { store }
    }

    /// The store, for an administrator's grants and revocations.
    pub fn store(&self) -> &std::sync::Arc<dyn AclStore> {
        &self.store
    }

    /// A KDC policy, boxed for [`crate::kdc::Kdc::with_change_policy`].
    pub fn policy(self) -> std::sync::Arc<dyn ChangePolicy> {
        std::sync::Arc::new(self)
    }
}

impl ChangePolicy for StoredAclPolicy {
    fn may_change(&self, actor: &Principal, target: &Principal) -> bool {
        if actor == target {
            return true;
        }
        // A store that cannot be read must not grant anything: answering "yes"
        // on a failure is how a broken database becomes an open door.
        let Ok(rules) = self.store.rules() else {
            return false;
        };
        rules.iter().any(|rule| {
            rule.actor == *actor
                && match &rule.targets {
                    Targets::Any => true,
                    Targets::Only(p) => p == target,
                }
        })
    }
}

/// The rules an operator would write, as one string per rule:
/// `actor<tab>target`, where `target` may be `*`.
///
/// It exists so a test file or a command-line tool can express a policy without
/// building `Principal`s by hand, and it refuses what it cannot parse instead of
/// skipping a line: a silently ignored rule is a right that was not granted and
/// an administrator who believes it was.
pub fn parse_rules(text: &str) -> Result<Vec<AclRule>> {
    let mut out = Vec::new();
    for (n, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (actor, target) = line.split_once(['\t', ' ']).ok_or_else(|| {
            Error::Config(format!(
                "acl line {}: expected `actor<space>target`, got {line:?}",
                n + 1
            ))
        })?;
        let actor = Principal::parse(actor.trim())?;
        let target = target.trim();
        out.push(if target == "*" {
            AclRule::any(actor)
        } else {
            AclRule::only(actor, Principal::parse(target)?)
        });
    }
    Ok(out)
}

/// Applies parsed rules to a store, as loading a configuration would.
pub fn load_rules(store: &dyn AclStore, rules: &[AclRule]) -> Result<()> {
    for rule in rules {
        store.grant(&rule.actor, rule.targets.clone())?;
    }
    Ok(())
}

/// Rules grouped by actor, for a listing an administrator reads.
pub fn by_actor(rules: &[AclRule]) -> BTreeMap<String, Vec<String>> {
    let mut out: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for rule in rules {
        let target = match &rule.targets {
            Targets::Any => "*".to_owned(),
            Targets::Only(p) => p.to_string(),
        };
        out.entry(rule.actor.to_string()).or_default().push(target);
    }
    for targets in out.values_mut() {
        targets.sort();
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> Principal {
        Principal::parse(s).unwrap()
    }

    #[test]
    fn a_fresh_store_grants_only_self_service() {
        let policy = StoredAclPolicy::new(MemoryAcl::new().shared());
        assert!(policy.may_change(&p("alice@R"), &p("alice@R")));
        assert!(!policy.may_change(&p("alice@R"), &p("bob@R")));
    }

    #[test]
    fn a_granted_rule_lets_one_actor_change_one_target() {
        let store = MemoryAcl::new();
        store
            .grant(&p("admin@R"), Targets::Only(p("bob@R")))
            .unwrap();
        let policy = StoredAclPolicy::new(std::sync::Arc::new(store));
        assert!(policy.may_change(&p("admin@R"), &p("bob@R")));
        assert!(
            !policy.may_change(&p("admin@R"), &p("carol@R")),
            "a rule for one target must not extend to another"
        );
        assert!(
            !policy.may_change(&p("alice@R"), &p("bob@R")),
            "a rule for one actor must not extend to another"
        );
    }

    #[test]
    fn an_any_rule_covers_everyone() {
        let store = MemoryAcl::new();
        store.grant(&p("admin@R"), Targets::Any).unwrap();
        let policy = StoredAclPolicy::new(std::sync::Arc::new(store));
        assert!(policy.may_change(&p("admin@R"), &p("bob@R")));
        assert!(policy.may_change(&p("admin@R"), &p("carol@R")));
    }

    #[test]
    fn granting_twice_is_idempotent() {
        let store = MemoryAcl::new();
        store.grant(&p("admin@R"), Targets::Any).unwrap();
        store.grant(&p("admin@R"), Targets::Any).unwrap();
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn revoking_takes_the_right_away() {
        let store = MemoryAcl::new();
        store.grant(&p("admin@R"), Targets::Any).unwrap();
        assert!(store.revoke(&p("admin@R"), &Targets::Any).unwrap());
        assert!(!store.revoke(&p("admin@R"), &Targets::Any).unwrap());
        let policy = StoredAclPolicy::new(std::sync::Arc::new(store));
        assert!(
            !policy.may_change(&p("admin@R"), &p("bob@R")),
            "a revoked rule must stop working immediately, not after a restart"
        );
    }

    #[test]
    fn revoke_all_removes_every_rule_of_one_actor() {
        let store = MemoryAcl::new();
        store.grant(&p("admin@R"), Targets::Any).unwrap();
        store
            .grant(&p("admin@R"), Targets::Only(p("bob@R")))
            .unwrap();
        store.grant(&p("other@R"), Targets::Any).unwrap();
        assert_eq!(store.revoke_all(&p("admin@R")).unwrap(), 2);
        assert_eq!(store.rules().unwrap().len(), 1);
    }

    #[test]
    fn a_store_that_cannot_be_read_grants_nothing() {
        #[derive(Debug)]
        struct Broken;
        impl AclStore for Broken {
            fn rules(&self) -> Result<Vec<AclRule>> {
                Err(Error::Hdb("broken".into()))
            }
            fn grant(&self, _: &Principal, _: Targets) -> Result<()> {
                Err(Error::Hdb("broken".into()))
            }
            fn revoke(&self, _: &Principal, _: &Targets) -> Result<bool> {
                Err(Error::Hdb("broken".into()))
            }
            fn revoke_all(&self, _: &Principal) -> Result<usize> {
                Err(Error::Hdb("broken".into()))
            }
        }
        let policy = StoredAclPolicy::new(std::sync::Arc::new(Broken));
        assert!(!policy.may_change(&p("admin@R"), &p("bob@R")));
        // Self-service does not consult the store at all.
        assert!(policy.may_change(&p("alice@R"), &p("alice@R")));
    }

    #[test]
    fn the_text_form_parses_and_refuses_what_it_cannot_read() {
        let rules = parse_rules("# an administrator\nadmin@R *\nhelpdesk@R alice@R\n\n").unwrap();
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].targets, Targets::Any);
        assert_eq!(rules[1].targets, Targets::Only(p("alice@R")));

        assert!(parse_rules("admin@R").is_err(), "a line with no target");
        assert!(
            parse_rules("admin@R nosuchrealm@").is_err(),
            "a malformed principal"
        );
    }

    #[test]
    fn listing_groups_rules_by_actor() {
        let rules = parse_rules("admin@R *\nhelpdesk@R alice@R\nadmin@R bob@R\n").unwrap();
        let grouped = by_actor(&rules);
        assert_eq!(
            grouped["admin@R"],
            vec!["*".to_string(), "bob@R".to_string()]
        );
        assert_eq!(grouped["helpdesk@R"], vec!["alice@R".to_string()]);
    }
}
