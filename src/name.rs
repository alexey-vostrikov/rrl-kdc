//! Principal names, in the `rrl-krb` crate.
//!
//! Shared with the acceptor: a name this KDC puts in a ticket is a name the acceptor compares
//! against its keytab, and the comparison rule — components and realm, never the name type — has
//! to be the same on both sides or a valid ticket is refused.
//!
//! Re-exported rather than wrapped so that `Principal` is one type, not two that have to be
//! converted between.

pub use rrl_krb::name::*;
