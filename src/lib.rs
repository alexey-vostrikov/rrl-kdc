//! A Kerberos KDC core, written from scratch, with Heimdal's behaviour as the
//! specification.
//!
//! # What this is
//!
//! A **library**, not an application: the protocol engine is sans-io. Sockets,
//! clocks, randomness and storage are supplied by the caller, so the same code
//! serves a standalone daemon, an in-process KDC inside an LDAP server, and a
//! deterministic test that replays recorded requests.
//!
//! ```text
//!   der   ── strict DER for RFC 4120 (minimal lengths: the KDC hashes them)
//!   crypto ── RFC 3961 §5.1 DR/DK, §5.3 profile; RFC 3962/8009 AES-CTS
//!   msg   ── RFC 4120 messages, KDC side: decode KDC-REQ, encode KDC-REP
//!   hdb   ── principal records, shaped after Heimdal's lib/hdb/hdb.asn1
//!   kdc   ── the engine: AS-REQ → AS-REP, TGS-REQ → TGS-REP
//! ```
//!
//! # What this is not
//!
//! Not a fork of anything, and not a client. The clients this KDC is tested
//! against are other people's implementations (`krb5` in dev-dependencies), on
//! the principle that a KDC which only agrees with itself agrees with nothing.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(rust_2018_idioms)]

/// RFC 3961/3962/8009 cryptography: keys, enctypes and the encryption profile.
pub mod crypto;
/// Strict DER for RFC 4120: minimal lengths, because the KDC hashes the octets.
pub mod der;
/// The single error type, and its mapping to `KRB-ERROR` codes.
pub mod error;
/// `KerberosTime`: `GeneralizedTime` in `YYYYMMDDHHMMSSZ`.
pub mod time;

/// Ticket addresses: `HostAddress`, and the check a KDC makes against them.
pub mod address;
/// The principal database, shaped after Heimdal's `lib/hdb/hdb.asn1`.
pub mod hdb;
/// Who may change whose password, stored rather than configured.
pub mod acl;
/// The protocol engine: AS and TGS exchanges.
pub mod kdc;
/// RFC 4120 messages: the KDC reads requests and writes replies.
pub mod msg;
/// Principal names and realms, where the name type is metadata and not
/// identity.
pub mod name;
/// RFC 4120 transport: UDP and TCP framing, and a loopback server for tests.
pub mod transport;

pub use error::{Error, Result};
pub use time::{format_generalized_time, parse_generalized_time};
