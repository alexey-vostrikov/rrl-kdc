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

use std::sync::Arc;

use crate::crypto::Cipher;
use crate::error::{Error, codes};
use crate::hdb::Hdb;
use crate::msg::KdcReq;

pub use as_exchange::{endtime, renew_till, starttime, ticket_flags, usable_enctypes};
pub use config::KdcConfig;

/// The engine: a configuration, a database and a cipher.
#[derive(Debug)]
pub struct Kdc {
    config: KdcConfig,
    hdb: Arc<dyn Hdb>,
    cipher: Arc<dyn Cipher>,
}

impl Kdc {
    /// A KDC for `config`, reading principals from `hdb`.
    pub fn new(config: KdcConfig, hdb: Arc<dyn Hdb>, cipher: Arc<dyn Cipher>) -> Self {
        Kdc {
            config,
            hdb,
            cipher,
        }
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

    /// Answers one request: the reply's octets, always a reply.
    ///
    /// Every failure becomes a `KRB-ERROR` rather than a Rust error, because a
    /// KDC that says nothing leaves the client waiting for a timeout and
    /// guessing. The Rust error is what the caller logs.
    pub fn handle(&self, request: &[u8], now: i64) -> Vec<u8> {
        let req = match KdcReq::decode(request) {
            Ok(req) => req,
            Err(err) => return self.error(None, &err, now),
        };
        let outcome = if req.msg_type == crate::msg::TGS_REQ {
            // Step 1 issues TGTs only. A TGS request is answered with the code
            // that tells the client to try another KDC, rather than with a
            // timeout or with an invented ticket.
            Err(Error::Kdc {
                code: codes::KDC_ERR_SVC_UNAVAILABLE,
                text: "the TGS exchange is not implemented yet".into(),
            })
        } else {
            self.handle_as(&req, now)
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
