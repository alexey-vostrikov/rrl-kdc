//! MS-PAC, in the `rrl-krb` crate.
//!
//! Shared with the acceptor: the envelope, the two signatures and `PAC_CLIENT_INFO` are built here
//! and parsed there, and a PAC is only useful if the verifier reads the octets the signer wrote.
//! Two implementations of the signature are two ways to produce a PAC Windows refuses, and that
//! shows up on a domain rather than in a test.
//!
//! Re-exported rather than wrapped so that `pac::Buffer`, `pac::SignatureType` and the type codes
//! keep resolving here and are the same items on both sides.

pub use rrl_krb::pac::*;
