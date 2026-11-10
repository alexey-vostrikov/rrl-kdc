//! RFC 4120 messages, in the `rrl-krb` crate.
//!
//! Shared with the acceptor: the `Ticket` this module writes is the `Ticket` it parses, and the
//! `EncTicketPart` it seals is the one the acceptor opens. That is the whole point of the crate —
//! a second copy of these structures is a second way to encode the field a checksum covers.
//!
//! The one thing that stays here is `kpasswd` (RFC 3244), which is a server-side protocol this
//! KDC implements and an acceptor has no use for.

pub mod kpasswd;

pub use rrl_krb::msg::*;
