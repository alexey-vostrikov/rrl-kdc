//! The administrator's operations as values, so a transport carries them and
//! nothing else.
//!
//! # Why a vocabulary instead of exposing `Admin`
//!
//! A REST route, a CLI and an in-process caller all want the same five things:
//! run an operation, get a value back, know who asked, and get a failure it can
//! turn into a status code. If the transport calls `Admin::create` directly, then
//! every transport has to remember the authorization check, and the one that
//! forgets is the one that ships.
//!
//! So the check lives in [`Admin::handle`]. A route is
//!
//! ```text
//! let reply = admin.handle(serde_json::from_str(&body)?)?;
//! ```
//!
//! and cannot skip the check, because there is no other entry point that performs
//! an operation.
//!
//! # Rights are finer than "administrator"
//!
//! Reading an entry and exporting a keytab are both reads, and only one hands over
//! password-equivalent material. A realm where the auditor's account can walk away
//! with every service key because it was allowed to look at the realm is a realm
//! with one privilege and two names for it.
//!
//! Nothing is granted by default: [`DenyAll`] is the policy an `Admin` starts
//! with, so a transport that forgets to configure authorization serves nobody
//! rather than everybody.

use std::sync::Arc;

use crate::acl::Targets;
use crate::admin::{Admin, Modify, NewPrincipal, Role};
use crate::crypto::Enctype;
use crate::error::{Error, Result};
use crate::hdb::HdbEntry;
use crate::name::Principal;

/// One thing an administrator may be allowed to do.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Right {
    /// List the principal names in the realm.
    List,
    /// Read one entry's metadata.
    Read,
    /// Create a principal.
    Create,
    /// Change an entry's flags and validity.
    Modify,
    /// Remove a principal.
    Delete,
    /// Set a password, which re-keys the entry.
    SetPassword,
    /// Drop the keys below the current kvno.
    PruneKeys,
    /// Export a keytab, which is the entry's long-term keys in a file.
    ExportKeytab,
}

/// A set of [`Right`]s.
///
/// A set and not a list, because every check is "does this actor have this
/// right", and a list would make an accidental duplicate a subtle bug.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Rights(u32);

impl Rights {
    /// No rights at all.
    pub const NONE: Rights = Rights(0);
    /// Listing the realm.
    pub const LIST: Rights = Rights(1 << 0);
    /// Reading entries.
    pub const READ: Rights = Rights(1 << 1);
    /// Creating principals.
    pub const CREATE: Rights = Rights(1 << 2);
    /// Modifying entries.
    pub const MODIFY: Rights = Rights(1 << 3);
    /// Deleting principals.
    pub const DELETE: Rights = Rights(1 << 4);
    /// Setting passwords.
    pub const SET_PASSWORD: Rights = Rights(1 << 5);
    /// Dropping old keys.
    pub const PRUNE_KEYS: Rights = Rights(1 << 6);
    /// Exporting keytabs.
    pub const EXPORT_KEYTAB: Rights = Rights(1 << 7);
    /// Everything.
    pub const ALL: Rights = Rights(0xff);

    /// Adds a right.
    pub fn with(self, right: Right) -> Rights {
        Rights(self.0 | Rights::of(right).0)
    }

    /// The set holding exactly `right`.
    pub const fn of(right: Right) -> Rights {
        Rights(match right {
            Right::List => 1 << 0,
            Right::Read => 1 << 1,
            Right::Create => 1 << 2,
            Right::Modify => 1 << 3,
            Right::Delete => 1 << 4,
            Right::SetPassword => 1 << 5,
            Right::PruneKeys => 1 << 6,
            Right::ExportKeytab => 1 << 7,
        })
    }

    /// Whether `right` is in the set.
    pub fn has(self, right: Right) -> bool {
        self.0 & Rights::of(right).0 != 0
    }

    /// Whether every right in `other` is in this set.
    pub fn contains(self, other: Rights) -> bool {
        self.0 & other.0 == other.0
    }
}

impl std::ops::BitOr for Rights {
    type Output = Rights;
    fn bitor(self, other: Rights) -> Rights {
        Rights(self.0 | other.0)
    }
}

impl std::ops::BitOr<Right> for Rights {
    type Output = Rights;
    fn bitor(self, right: Right) -> Rights {
        self.with(right)
    }
}

/// Who may do what.
///
/// Read on every operation rather than cached, for the reason the password ACL is:
/// a right that survives a revocation lets somebody in after they were removed.
pub trait Policy: std::fmt::Debug + Send + Sync {
    /// Whether `actor` may exercise `right`, optionally on `target`.
    ///
    /// `target` is `None` for realm-wide operations such as listing. A policy that
    /// narrows a grant to particular principals must not answer `true` for `None`:
    /// being allowed to reset one department's passwords is not being allowed to
    /// enumerate the realm.
    fn may(&self, actor: &Principal, right: Right, target: Option<&Principal>) -> bool;
}

/// The policy an `Admin` starts with: nobody may do anything.
#[derive(Debug, Clone, Copy, Default)]
pub struct DenyAll;

impl Policy for DenyAll {
    fn may(&self, _actor: &Principal, _right: Right, _target: Option<&Principal>) -> bool {
        false
    }
}

/// One grant: `actor` may exercise `rights` over `targets`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Grant {
    /// Who.
    pub actor: Principal,
    /// Over whom.
    pub targets: Targets,
    /// What.
    pub rights: Rights,
}

/// Grants held in memory — what a deployment with a handful of operators writes.
///
/// For a directory that already holds its own groups, an embedder implements
/// [`Policy`] over them instead; this exists so that a stand, a test and a small
/// realm do not have to.
#[derive(Clone, Debug, Default)]
pub struct Grants {
    grants: Vec<Grant>,
}

impl Grants {
    /// No grants.
    pub fn new() -> Self {
        Grants::default()
    }

    /// Grants `actor` `rights` over every principal in the realm.
    pub fn grant(mut self, actor: &Principal, rights: Rights) -> Self {
        self.grants.push(Grant {
            actor: actor.clone(),
            targets: Targets::Any,
            rights,
        });
        self
    }

    /// Grants `actor` `rights` over `targets` only.
    pub fn grant_for(mut self, actor: &Principal, targets: Targets, rights: Rights) -> Self {
        self.grants.push(Grant {
            actor: actor.clone(),
            targets,
            rights,
        });
        self
    }

    /// Every grant, for an administrator to look at.
    pub fn list(&self) -> &[Grant] {
        &self.grants
    }
}

impl Policy for Grants {
    fn may(&self, actor: &Principal, right: Right, target: Option<&Principal>) -> bool {
        self.grants.iter().any(|grant| {
            if grant.actor != *actor || !grant.rights.has(right) {
                return false;
            }
            match (&grant.targets, target) {
                // A realm-wide question is answered only by a realm-wide grant,
                // Or a grant that names every target it could mean — which a
                // narrowed grant does not.
                (Targets::Any, _) => true,
                (Targets::Only(_), None) => false,
                (Targets::Only(only), Some(who)) => only == who,
            }
        })
    }
}

/// What to do.
#[derive(Clone, Debug, PartialEq)]
pub enum Operation {
    /// List the principal names.
    List,
    /// Read one entry.
    Get {
        /// Whose.
        principal: Principal,
    },
    /// Create a principal.
    Create {
        /// Whose.
        principal: Principal,
        /// The password its keys come from; empty means keys added later.
        password: Vec<u8>,
        /// Enctypes to key it with; empty means every enctype this KDC issues.
        enctypes: Vec<Enctype>,
        /// Client, server, or both.
        role: Role,
    },
    /// Change flags and validity.
    Modify {
        /// Whose.
        principal: Principal,
        /// What to change.
        change: Modify,
    },
    /// Remove a principal.
    Delete {
        /// Whose.
        principal: Principal,
    },
    /// Set a password: new keys at the next kvno.
    SetPassword {
        /// Whose.
        principal: Principal,
        /// The new password.
        password: Vec<u8>,
    },
    /// Drop the keys below the current kvno.
    PruneOldKeys {
        /// Whose.
        principal: Principal,
    },
    /// Export a keytab.
    Keytab {
        /// Whose keys the file carries, in order.
        principals: Vec<Principal>,
    },
}

impl Operation {
    /// The right this operation needs, and the principal it acts on.
    ///
    /// In one place because a transport must not decide either: the mapping from
    /// "what was asked" to "what it costs" is policy, and policy belongs where it
    /// can be read and tested.
    fn requirement(&self) -> (Right, Option<&Principal>) {
        match self {
            Operation::List => (Right::List, None),
            Operation::Get { principal } => (Right::Read, Some(principal)),
            Operation::Create { principal, .. } => (Right::Create, Some(principal)),
            Operation::Modify { principal, .. } => (Right::Modify, Some(principal)),
            Operation::Delete { principal } => (Right::Delete, Some(principal)),
            Operation::SetPassword { principal, .. } => (Right::SetPassword, Some(principal)),
            Operation::PruneOldKeys { principal } => (Right::PruneKeys, Some(principal)),
            // Checked per principal below; this is the fallback for none of them.
            Operation::Keytab { .. } => (Right::ExportKeytab, None),
        }
    }
}

/// Who is asking, and what for.
#[derive(Clone, Debug, PartialEq)]
pub struct AdminRequest {
    /// The authenticated actor. A transport establishes this before building the
    /// request, and must not take it from the body it also carries.
    pub actor: Principal,
    /// What to do.
    pub operation: Operation,
}

/// An entry as an administrator sees it: what it is, never what it can do.
///
/// `key_count` and `enctypes` say how many keys there are and in which enctypes.
/// The keys themselves never appear: a read that returns them turns every
/// permission to look into a permission to impersonate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EntryView {
    /// The principal.
    pub principal: Principal,
    /// The current kvno.
    pub kvno: u32,
    /// The `HDBFlags` bitset.
    pub flags: u32,
    /// How many keys the entry holds, across all kvnos.
    pub key_count: usize,
    /// The enctypes those keys are in.
    pub enctypes: Vec<Enctype>,
    /// `valid-start`, if set.
    pub valid_start: Option<i64>,
    /// `valid-end`, if set.
    pub valid_end: Option<i64>,
    /// `pw-end`, if set.
    pub pw_end: Option<i64>,
    /// `max-life`, if set.
    pub max_life: Option<i64>,
}

impl EntryView {
    /// The view of `entry`.
    pub fn of(entry: &HdbEntry) -> Self {
        EntryView {
            principal: entry.principal.clone(),
            kvno: entry.kvno(),
            flags: entry.flags,
            key_count: entry.keys.len(),
            enctypes: entry.enctypes(),
            valid_start: entry.valid_start,
            valid_end: entry.valid_end,
            pw_end: entry.pw_end,
            max_life: entry.max_life,
        }
    }
}

/// The answer to an [`Operation`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reply {
    /// The names in the realm.
    Principals {
        /// Every principal, in the backend's order.
        principals: Vec<Principal>,
    },
    /// One entry's metadata.
    Entry {
        /// What was asked for.
        entry: EntryView,
    },
    /// A principal was created.
    Created {
        /// What was created.
        entry: EntryView,
    },
    /// An entry was changed.
    Modified {
        /// What it looks like now.
        entry: EntryView,
    },
    /// A password was set; the new keys are at `kvno`.
    PasswordSet {
        /// The kvno a service must re-read its keytab to get.
        kvno: u32,
    },
    /// Old keys were dropped.
    Pruned {
        /// How many keys went away.
        removed: usize,
    },
    /// A delete happened, or did not because there was nothing to delete.
    Deleted {
        /// Whether something was there.
        existed: bool,
    },
    /// A keytab file.
    Keytab {
        /// The file, byte for byte.
        bytes: Vec<u8>,
    },
}

impl Admin {
    /// An administrator with this policy.
    pub fn with_policy(mut self, policy: Arc<dyn Policy>) -> Self {
        self.policy = policy;
        self
    }

    /// The policy in force.
    pub fn policy(&self) -> &Arc<dyn Policy> {
        &self.policy
    }

    /// Checks the right and runs the operation.
    ///
    /// The authorization happens first and covers every principal the operation
    /// touches, so a refused request leaves the database exactly as it was.
    pub fn handle(&self, request: AdminRequest) -> Result<Reply> {
        if request.actor.realm.is_empty() || request.actor.components.is_empty() {
            return Err(Error::Config(
                "the operation has no actor: a caller has to say who is asking".into(),
            ));
        }

        // Every principal an operation acts on has to be covered. Checking only
        // the first would make a keytab export a way to read somebody else's keys
        // by appending them to the list.
        match &request.operation {
            Operation::Keytab { principals } => {
                for principal in principals {
                    if !self
                        .policy
                        .may(&request.actor, Right::ExportKeytab, Some(principal))
                    {
                        return Err(self.refuse(&request.actor, Right::ExportKeytab, principal));
                    }
                }
            }
            operation => {
                let (right, target) = operation.requirement();
                if !self.policy.may(&request.actor, right, target) {
                    let what = target.map_or_else(|| self.realm.clone(), ToString::to_string);
                    return Err(self.refuse(&request.actor, right, &what));
                }
            }
        }

        match request.operation {
            Operation::List => Ok(Reply::Principals {
                principals: self.list()?,
            }),
            Operation::Get { principal } => Ok(Reply::Entry {
                entry: EntryView::of(&self.get(&principal)?),
            }),
            Operation::Create {
                principal,
                password,
                enctypes,
                role,
            } => {
                let mut new = NewPrincipal {
                    principal,
                    password,
                    enctypes,
                    role,
                };
                // The administrator's realm fills a bare name; `create` does the
                // same, but the policy above already had to see the target, so do
                // it here too and answer about the same principal in both places.
                if new.principal.realm.is_empty() {
                    new.principal.realm = self.realm.clone();
                }
                Ok(Reply::Created {
                    entry: EntryView::of(&self.create(new)?),
                })
            }
            Operation::Modify { principal, change } => Ok(Reply::Modified {
                entry: EntryView::of(&self.modify(&principal, change)?),
            }),
            Operation::Delete { principal } => Ok(Reply::Deleted {
                existed: self.delete(&principal)?,
            }),
            Operation::SetPassword {
                principal,
                password,
            } => Ok(Reply::PasswordSet {
                kvno: self.set_password(&principal, &password)?,
            }),
            Operation::PruneOldKeys { principal } => Ok(Reply::Pruned {
                removed: self.prune_old_keys(&principal)?,
            }),
            Operation::Keytab { principals } => {
                let keytab = self.keytab(&principals)?;
                Ok(Reply::Keytab {
                    bytes: keytab.to_bytes(),
                })
            }
        }
    }

    fn refuse(&self, actor: &Principal, right: Right, what: impl std::fmt::Display) -> Error {
        Error::Forbidden(format!("{actor} may not {right:?} {what}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> Principal {
        Principal::parse(s).unwrap()
    }

    #[test]
    fn a_right_is_in_a_set_exactly_when_granted() {
        let set = Rights::LIST | Rights::READ;
        assert!(set.has(Right::List));
        assert!(set.has(Right::Read));
        assert!(
            !set.has(Right::Delete),
            "a set must not answer for a right it lacks"
        );
        assert!(!set.has(Right::ExportKeytab));
    }

    #[test]
    fn contains_needs_every_right() {
        let all = Rights::ALL;
        assert!(all.contains(Rights::LIST | Rights::EXPORT_KEYTAB));
        assert!(!Rights::LIST.contains(Rights::LIST | Rights::READ));
    }

    #[test]
    fn a_narrowed_grant_does_not_answer_a_realm_wide_question() {
        let grants = Grants::new().grant_for(
            &p("helpdesk@R"),
            Targets::Only(p("alice@R")),
            Rights::SET_PASSWORD,
        );
        assert!(grants.may(&p("helpdesk@R"), Right::SetPassword, Some(&p("alice@R"))));
        assert!(
            !grants.may(&p("helpdesk@R"), Right::SetPassword, Some(&p("bob@R"))),
            "one target is not every target"
        );
        assert!(
            !grants.may(&p("helpdesk@R"), Right::SetPassword, None),
            "being allowed over one principal is not being allowed over the realm"
        );
    }

    #[test]
    fn a_realm_wide_grant_covers_a_single_target() {
        let grants = Grants::new().grant(&p("admin@R"), Rights::DELETE);
        assert!(grants.may(&p("admin@R"), Right::Delete, Some(&p("alice@R"))));
        assert!(grants.may(&p("admin@R"), Right::Delete, None));
    }

    #[test]
    fn a_grant_for_one_actor_does_not_reach_another() {
        let grants = Grants::new().grant(&p("admin@R"), Rights::ALL);
        assert!(!grants.may(&p("guest@R"), Right::List, None));
    }

    #[test]
    fn the_entry_view_reports_the_enctypes_and_the_count_but_not_the_keys() {
        use crate::crypto::{Cipher, OwnCipher};
        let mut entry = HdbEntry::user(p("alice@R"));
        for e in [Enctype::Aes256Sha1, Enctype::Aes128Sha1] {
            entry.add_password_key(&OwnCipher, e, b"pw", 1).unwrap();
        }
        let view = EntryView::of(&entry);
        assert_eq!(view.key_count, 2);
        assert_eq!(view.enctypes.len(), 2);
        assert_eq!(view.kvno, 1);
        let debug = format!("{view:?}");
        for e in view.enctypes {
            let key = OwnCipher
                .s2k(e, b"pw", &p("alice@R").default_salt(), None)
                .unwrap();
            assert!(
                !debug.contains(&format!("{key:?}")),
                "the view must not print keys"
            );
        }
    }
}
