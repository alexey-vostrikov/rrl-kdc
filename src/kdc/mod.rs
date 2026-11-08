//! The protocol engine.
//!
//! Two exchanges, one state machine each, and neither touches a socket: the
//! caller hands over the request's octets and the time, and gets back the
//! reply's octets. That is what lets the same engine drive a daemon, an
//! in-process KDC inside a directory server, and a test that replays recorded
//! requests.

pub mod config;

pub use config::KdcConfig;
