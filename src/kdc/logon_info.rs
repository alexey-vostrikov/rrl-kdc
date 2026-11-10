//! `KERB_VALIDATION_INFO` and the identity seam, in the `rrl-krb` crate.
//!
//! Shared with the acceptor: the NDR this KDC writes into a PAC is the NDR a server reads out of
//! it, and every pointer in it is an offset the reader has to compute the same way.
//!
//! The seam stays a trait — [`PacIdentities`] — because the facts behind it live in two places: the
//! directory knows a RID and a SID, the KDC knows the logon time, and neither may invent the
//! other's.

pub use rrl_krb::logon_info::*;

/// What the seam's methods return.
///
/// The shared crate's error, aliased here because that is the type the trait names and an
/// implementation has to spell: the trait lives in `rrl-krb`, which cannot depend on this KDC's
/// error, and the KDC converts with `From` at the seam.
pub use rrl_krb::Result as PacResult;
