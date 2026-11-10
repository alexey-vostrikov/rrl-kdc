//! `KerberosTime`, in the `rrl-krb-common` crate.
//!
//! Shared with the acceptor: a ticket's `endtime` written here and read there has to be the same
//! instant, and the calendar arithmetic that decides it is not something to keep in two places.

pub use rrl_krb_common::time::*;
