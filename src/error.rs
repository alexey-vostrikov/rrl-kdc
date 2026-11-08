//! One error type for the whole crate.
//!
//! A KDC has to answer in Kerberos' own vocabulary: every failure that reaches
//! a client becomes a `KRB-ERROR` with a protocol code. [`Error::kdc_code`]
//! is that mapping, kept in one place so a new check cannot invent its own
//! answer. Internal failures that have no protocol code (`Hdb`, `Config`,
//! `Io`) map to `KDC_ERR_SVC_UNAVAILABLE`, which is what Heimdal returns when
//! the database cannot be read: the client is told to try another KDC rather
//! than that its credentials are wrong.

use crate::crypto::Enctype;

#[derive(Debug, thiserror::Error)]
/// Everything this crate can fail with, mapped to a protocol code where one exists.
pub enum Error {
    #[error("DER: {0}")]
    /// A message did not decode: wrong tag, wrong length, truncated buffer.
    Der(#[from] crate::der::DerError),

    #[error("enctype {0} is not one this KDC implements (17, 18, 19, 20)")]
    /// An enctype this KDC does not implement (it issues 17, 18, 19 and 20).
    UnsupportedEnctype(i32),

    #[error("enctype {enctype:?} takes a {want}-octet key, got {got}")]
    /// A key of the wrong size for its enctype.
    KeyLength {
        /// The enctype the key was built for.
        enctype: Enctype,
        /// The size that enctype requires.
        want: usize,
        /// The size that arrived.
        got: usize,
    },

    #[error("crypto: {0}")]
    /// A cryptographic operation failed: bad tag, short ciphertext, missing key.
    Crypto(String),

    #[error("message is not a KDC-REQ: {0}")]
    /// The bytes are not a `KDC-REQ` this KDC will answer.
    NotARequest(String),

    #[error("protocol: {0}")]
    /// A message decoded but says something a KDC must not accept.
    Protocol(String),

    #[error("principal {0} is unknown")]
    /// No such principal in the database.
    UnknownPrincipal(String),

    #[error("pre-authentication required for {0}")]
    /// The client must authenticate before a ticket is issued.
    PreauthRequired(String),

    #[error("pre-authentication failed for {0}")]
    /// The client's pre-authentication did not verify.
    PreauthFailed(String),

    #[error("{text} (KRB-ERROR {code})")]
    /// A check failed and the protocol has a code for exactly that, which is
    /// not one of the variants above: `KDC_ERR_POLICY`, `KDC_ERR_NEVER_VALID`,
    /// `KDC_ERR_WRONG_REALM`.
    Kdc {
        /// The RFC 4120 §7.5 code to put in the reply.
        code: i32,
        /// The `e-text`, if any.
        text: String,
    },

    #[error("clock skew too great: {skew}s against a {allowed}s allowance")]
    /// The client's clock and this KDC's differ by more than the allowance.
    Skew {
        /// What the client's clock claims, in seconds relative to this KDC's.
        skew: i64,
        /// The configured `clockskew`.
        allowed: i64,
    },

    #[error("hdb: {0}")]
    /// The database could not be read or written.
    Hdb(String),

    #[error("config: {0}")]
    /// The configuration is wrong: an unimplemented option, a bad enctype name.
    Config(String),

    #[error("io: {0}")]
    /// A file could not be read: a keytab, a `krb5.conf`, a database file.
    Io(#[from] std::io::Error),
}

/// Result of anything in this crate.
pub type Result<T> = std::result::Result<T, Error>;

/// RFC 4120 §7.5 error codes this KDC emits.
/// The RFC 4120 §7.5 codes this KDC emits, by name.
pub mod codes {
    /// No error.
    pub const KDC_ERR_NONE: i32 = 0;
    /// The client principal is not in the database.
    pub const KDC_ERR_C_PRINCIPAL_UNKNOWN: i32 = 6;
    /// The service principal is not in the database.
    pub const KDC_ERR_S_PRINCIPAL_UNKNOWN: i32 = 7;
    /// The principal name resolves to more than one entry.
    pub const KDC_ERR_PRINCIPAL_NOT_UNIQUE: i32 = 8;
    /// The request asks for a lifetime that ends before it starts.
    pub const KDC_ERR_NEVER_VALID: i32 = 11;
    /// The realm's policy forbids what was asked for (a proxiable ticket, a
    /// postdated one, a service that may not be issued).
    pub const KDC_ERR_POLICY: i32 = 12;
    /// No requested enctype is one this KDC implements.
    pub const KDC_ERR_ETYPE_NOSUPP: i32 = 14;
    /// The account is locked, disabled or expired.
    pub const KDC_ERR_CLIENT_REVOKED: i32 = 18;
    /// Pre-authentication data did not verify.
    pub const KDC_ERR_PREAUTH_FAILED: i32 = 24;
    /// More pre-authentication is needed; `e-data` carries METHOD-DATA.
    pub const KDC_ERR_PREAUTH_REQUIRED: i32 = 25;
    /// The requested server does not match the ticket granted.
    pub const KDC_ERR_SERVER_NOMATCH: i32 = 26;
    /// The service requires a user-to-user ticket.
    pub const KDC_ERR_MUST_USE_USER2USER: i32 = 27;
    /// This KDC cannot answer; the client should try another.
    pub const KDC_ERR_SVC_UNAVAILABLE: i32 = 29;
    /// The realm in the request is not one this KDC serves.
    pub const KDC_ERR_WRONG_REALM: i32 = 68;
    /// A decrypted value failed its integrity check.
    pub const KRB_AP_ERR_BAD_INTEGRITY: i32 = 31;
    /// The ticket has expired.
    pub const KRB_AP_ERR_TKT_EXPIRED: i32 = 32;
    /// The ticket is not valid yet.
    pub const KRB_AP_ERR_TKT_NYV: i32 = 33;
    /// The clocks differ by more than the allowance.
    pub const KRB_AP_ERR_SKEW: i32 = 37;
    /// The client's address is not one the ticket allows.
    pub const KRB_AP_ERR_BADADDR: i32 = 38;
    /// The protocol version is not 5.
    pub const KRB_AP_ERR_BADVERSION: i32 = 39;
    /// The message type is wrong for this exchange.
    pub const KRB_AP_ERR_MSG_TYPE: i32 = 41;
    /// The message could not be decoded or was altered.
    pub const KRB_AP_ERR_MODIFIED: i32 = 42;
}

impl Error {
    /// The `KRB-ERROR` code this failure becomes on the wire.
    pub fn kdc_code(&self) -> i32 {
        use codes::*;
        match self {
            Error::Der(_) | Error::NotARequest(_) | Error::Protocol(_) => KRB_AP_ERR_MODIFIED,
            Error::UnsupportedEnctype(_) => KDC_ERR_ETYPE_NOSUPP,
            Error::KeyLength { .. } | Error::Crypto(_) => KRB_AP_ERR_BAD_INTEGRITY,
            Error::UnknownPrincipal(_) => KDC_ERR_C_PRINCIPAL_UNKNOWN,
            Error::Kdc { code, .. } => *code,
            Error::PreauthRequired(_) => KDC_ERR_PREAUTH_REQUIRED,
            Error::PreauthFailed(_) => KDC_ERR_PREAUTH_FAILED,
            Error::Skew { .. } => KRB_AP_ERR_SKEW,
            Error::Hdb(_) | Error::Config(_) | Error::Io(_) => KDC_ERR_SVC_UNAVAILABLE,
        }
    }

    /// Whether an e-text belongs in the reply. Internal failures do not: an
    /// I/O error string is an operator's business, not a client's.
    pub fn is_client_facing(&self) -> bool {
        !matches!(
            self,
            Error::Hdb(_) | Error::Config(_) | Error::Io(_) | Error::Crypto(_)
        )
    }
}
