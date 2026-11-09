//! The protocol engine: one request in, one reply out, no socket in sight.
//!
//! ```no_run
//! use std::sync::Arc;
//! use rust_heimdal_kdc::crypto::OwnCipher;
//! use rust_heimdal_kdc::hdb::MemoryHdb;
//! use rust_heimdal_kdc::kdc::{Kdc, KdcConfig};
//!
//! # fn main() -> rust_heimdal_kdc::Result<()> {
//! let kdc = Kdc::new(
//!     KdcConfig::new("EXAMPLE.COM")?,
//!     Arc::new(MemoryHdb::new()),
//!     Arc::new(OwnCipher),
//! );
//! let reply = kdc.handle(&[], 1_700_000_000); // a request's octets, this KDC's time
//! # let _ = reply;
//! # Ok(())
//! # }
//! ```
//!
//! The time is a parameter and not a call to the system clock: a KDC whose
//! behaviour cannot be pinned to an instant cannot be tested, and every check in
//! here — ticket lifetimes, clock skew, expiry — is about an instant.

pub mod config;

mod as_exchange;
mod tgs_exchange;

/// The change-password service (RFC 3244): protocol constants, the reply a
/// caller frames, and the `kadmin/changepw` entry a realm needs.
pub mod kpasswd;
pub mod logon_info;
pub mod pac;

pub use kpasswd::{VERSION_CHANGE, VERSION_SET, changepw_entry, result_payload};

use std::sync::Arc;

use std::net::IpAddr;

use crate::address;
use crate::crypto::Cipher;
use crate::error::{Error, codes};
use crate::hdb::Hdb;
use crate::msg::KdcReq;
use crate::name::Principal;

pub use as_exchange::Purpose;
pub use as_exchange::{endtime, renew_till, starttime, ticket_flags, usable_enctypes};
pub use config::KdcConfig;

/// Who may change whose password (RFC 3244 §2: the service is told, not told
/// what to decide).
///
/// It is a trait rather than a file because the decision is an authorization
/// question, and this crate does not own authorization: the process that embeds
/// the KDC almost always has a directory, a group membership and a policy of its
/// own, and a KDC that read `/var/heimdal/kadmind.acl` would be inventing a
/// second answer to a question already answered. [`SelfOnly`] is the default,
/// because it needs no configuration and cannot grant too much.
pub trait ChangePolicy: std::fmt::Debug + Send + Sync {
    /// Whether `actor` may set the password of `target`.
    fn may_change(&self, actor: &Principal, target: &Principal) -> bool;
}

/// Everyone changes only their own password.
#[derive(Debug, Clone, Copy, Default)]
pub struct SelfOnly;

impl ChangePolicy for SelfOnly {
    fn may_change(&self, actor: &Principal, target: &Principal) -> bool {
        actor == target
    }
}

/// The engine: a configuration, a database, a cipher, and who may change whose
/// password.
#[derive(Debug)]
pub struct Kdc {
    config: KdcConfig,
    hdb: Arc<dyn Hdb>,
    cipher: Arc<dyn Cipher>,
    policy: Arc<dyn ChangePolicy>,
}

impl Kdc {
    /// A KDC for `config`, reading principals from `hdb`.
    pub fn new(config: KdcConfig, hdb: Arc<dyn Hdb>, cipher: Arc<dyn Cipher>) -> Self {
        Kdc {
            config,
            hdb,
            cipher,
            policy: Arc::new(SelfOnly),
        }
    }

    /// The same KDC with `policy` deciding who may change whose password.
    pub fn with_change_policy(mut self, policy: Arc<dyn ChangePolicy>) -> Self {
        self.policy = policy;
        self
    }

    /// The policy in force.
    pub fn change_policy(&self) -> &dyn ChangePolicy {
        self.policy.as_ref()
    }

    /// Shorthand for the change-password paths, which ask one question.
    pub(super) fn policy(&self) -> &dyn ChangePolicy {
        self.policy.as_ref()
    }

    /// The configuration in force.
    pub fn config(&self) -> &KdcConfig {
        &self.config
    }

    /// The database.
    pub fn hdb(&self) -> &dyn Hdb {
        self.hdb.as_ref()
    }

    /// The cipher.
    pub fn cipher(&self) -> &dyn Cipher {
        self.cipher.as_ref()
    }

    /// The database as a shared handle, for a front end that needs to own one —
    /// `kadmind` builds an `Admin` over the same database the KDC serves from, so
    /// that a principal it creates and a ticket the KDC issues cannot disagree.
    #[cfg(feature = "kadmin")]
    pub(crate) fn hdb_arc(&self) -> Arc<dyn Hdb> {
        Arc::clone(&self.hdb)
    }

    /// The crypto backend as a shared handle.
    #[cfg(feature = "kadmin")]
    pub(crate) fn cipher_arc(&self) -> Arc<dyn Cipher> {
        Arc::clone(&self.cipher)
    }

    /// Answers one request whose peer address is not known.
    ///
    /// Address checks behave as Heimdal's do when the source is unknown: a
    /// request that names addresses is refused, because a check that cannot be
    /// answered must not pass. A transport that knows the peer should call
    /// [`Kdc::handle_from`] instead.
    pub fn handle(&self, request: &[u8], now: i64) -> Vec<u8> {
        self.handle_from(request, now, None)
    }

    /// Answers one request that arrived from `peer`: the reply's octets, always
    /// a reply.
    ///
    /// Every failure becomes a `KRB-ERROR` rather than a Rust error, because a
    /// KDC that says nothing leaves the client waiting for a timeout and
    /// guessing. The Rust error is what the caller logs.
    pub fn handle_from(&self, request: &[u8], now: i64, peer: Option<IpAddr>) -> Vec<u8> {
        let req = match KdcReq::decode(request) {
            Ok(req) => req,
            Err(err) => return self.error(None, &err, now),
        };
        let outcome = match address::check(
            self.config.address_policy(),
            req.body.addresses.as_deref(),
            peer,
        ) {
            Err(err) => Err(err),
            Ok(verdict) if verdict.is_allowed() => {
                if req.msg_type == crate::msg::TGS_REQ {
                    self.handle_tgs(&req, now)
                } else {
                    self.handle_as(&req, now)
                }
            }
            Ok(_verdict) => {
                // `warn-ticket-addresses`: the mismatch is logged and the
                // request is served anyway, which is what an operator migrating
                // to address checks needs to see before enforcing them.
                Err(address::refused())
            }
        };
        match outcome {
            Ok(reply) => reply,
            Err(err) => self.error(Some(&req), &err, now),
        }
    }

    /// Renders `err` as the reply, attaching `METHOD-DATA` where the code needs
    /// it.
    fn error(&self, req: Option<&KdcReq>, err: &Error, now: i64) -> Vec<u8> {
        let (code, method_data) = match err {
            Error::Preauth {
                code, method_data, ..
            } => (*code, Some(method_data.clone())),
            other => (other.kdc_code(), None),
        };
        let text = err.is_client_facing().then(|| err.to_string());
        let (realm, sname, crealm, cname) = match req {
            Some(r) => (
                r.body.realm.clone(),
                r.body
                    .sname
                    .clone()
                    .unwrap_or_else(|| crate::name::Principal::krbtgt(self.config.realm())),
                r.body.cname.as_ref().map(|c| c.realm.clone()),
                r.body.cname.clone(),
            ),
            None => (
                self.config.realm().to_owned(),
                crate::name::Principal::krbtgt(self.config.realm()),
                None,
                None,
            ),
        };
        crate::msg::KrbError {
            ctime: None,
            cusec: None,
            stime: now,
            susec: 0,
            code,
            crealm,
            cname,
            realm,
            sname,
            e_text: text,
            e_data: method_data,
        }
        .encode()
    }
}

/// The error a realm that is not ours gets. Naming the realm we do serve tells
/// the operator what went wrong without telling the client anything it did not
/// already send.
pub(super) fn wrong_realm(requested: &str, ours: &str) -> Error {
    Error::Kdc {
        code: codes::KDC_ERR_WRONG_REALM,
        text: format!("this KDC serves {ours}, not {requested}"),
    }
}
