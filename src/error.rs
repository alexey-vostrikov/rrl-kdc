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

    #[error(
        "no enctype in the request is allowed for {principal}: it may be issued {allowed:?}, \
         and the request asked for {asked:?}"
    )]
    /// The intersection of what the client asked for, what this KDC issues, and what the entry
    /// allows is empty.
    ///
    /// A separate variant from [`Error::UnsupportedEnctype`] because the two need different
    /// answers: "this KDC does not implement that" is a client asking for DES, while "this
    /// account may not be issued that" is an administrator's restriction, and an operator who
    /// reads one when the other is true goes looking in the wrong place.
    NoUsableEnctype {
        /// The principal that restricts.
        principal: crate::name::Principal,
        /// What its entry declares, or an empty list when it has no keys at all.
        allowed: Vec<crate::crypto::Enctype>,
        /// What the request asked for.
        asked: Vec<i32>,
    },

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

    #[error("{0} is not in the database")]
    /// An administrative operation named a principal that is not there.
    ///
    /// Separate from [`Error::UnknownPrincipal`] because the two answer different
    /// callers: an AS request for an unknown client is a protocol failure a
    /// client must not be able to distinguish from any other, while an
    /// administrator asking about an absent account wants to be told exactly
    /// that. A transport maps this to 404 and the other to the reply it belongs
    /// to.
    NotFound(String),

    #[error("{0} already exists")]
    /// An administrative operation tried to create what is already there.
    Exists(String),

    #[error("not permitted: {0}")]
    /// The actor has no right to do this.
    Forbidden(String),

    #[error("pre-authentication: {text}")]
    /// `PREAUTH_REQUIRED` or `PREAUTH_FAILED`, with the `METHOD-DATA` that has
    /// to travel in `e-data`: a client told only "no" cannot tell whether its
    /// password was wrong or its salt.
    Preauth {
        /// `KDC_ERR_PREAUTH_REQUIRED` or `KDC_ERR_PREAUTH_FAILED`.
        code: i32,
        /// The `e-text`.
        text: String,
        /// The encoded `METHOD-DATA`.
        method_data: Vec<u8>,
    },

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
    /// The request asked for an option that does not apply: renewing a ticket
    /// that is not renewable, validating one that is not invalid.
    pub const KDC_ERR_BADOPTION: i32 = 13;
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
    /// The reply does not fit in a datagram; the client should retry over TCP.
    pub const KDC_ERR_RESPONSE_TOO_BIG: i32 = 52;
    /// The realm in the request is not one this KDC serves.
    pub const KDC_ERR_WRONG_REALM: i32 = 68;
    /// RFC 4120 §7.5.9: the KDC has no key to encrypt the reply with. Anonymous PKINIT
    /// says this when the realm has no KDC certificate (RFC 8062 §4.1).
    pub const KDC_ERR_NULL_KEY: i32 = 21;
    /// RFC 4556 §3.2.1: a PKINIT client asked for key transport where the exchange needs
    /// Diffie-Hellman (which is also the anonymous case, where it has no key pair at all).
    pub const KDC_ERR_PUBLIC_KEY_ENCRYPTION_NOT_SUPPORTED: i32 = 81;
    /// RFC 6113 §5.4.4.2: a `fast-options` bit this KDC does not implement, set by the
    /// client. Bits 1 through 15 are critical, so an unknown one must fail the request
    /// rather than be ignored — the client asked for something it will not get.
    pub const KDC_ERR_UNKNOWN_CRITICAL_FAST_OPTIONS: i32 = 93;
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
    pub const KRB_AP_ERR_MSG_TYPE: i32 = 40;
    /// The message could not be decoded or was altered.
    pub const KRB_AP_ERR_MODIFIED: i32 = 41;
    /// The authenticator names a different principal than the ticket does.
    pub const KRB_AP_ERR_BADMATCH: i32 = 36;
    /// RFC 4120 §7.5.3: an authenticator that has been seen before, inside the clock skew.
    pub const KRB_AP_ERR_REPEAT: i32 = 34;
    /// The ticket is postdated and has not been validated.
    pub const KRB_AP_ERR_TKT_INVALID: i32 = 49;
    /// A checksum that must be present is absent, or is of the wrong type.
    pub const KRB_AP_ERR_INAPP_CKSUM: i32 = 50;
}

#[cfg(feature = "serde")]
impl serde::Serialize for Error {
    /// The failure as a transport sees it: `{"kind": "...", "message": "..."}`.
    ///
    /// Only the two fields a caller can act on. A nested error chain would invite
    /// a transport to depend on this crate's internal shape, and the internal
    /// shape is free to change.
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut out = serializer.serialize_struct("Error", 2)?;
        out.serialize_field("kind", self.kind())?;
        out.serialize_field("message", &self.to_string())?;
        out.end()
    }
}

impl Error {
    /// The `KRB-ERROR` code this failure becomes on the wire.
    pub fn kdc_code(&self) -> i32 {
        use codes::*;
        match self {
            Error::Der(_) | Error::NotARequest(_) | Error::Protocol(_) => KRB_AP_ERR_MODIFIED,
            Error::UnsupportedEnctype(_) | Error::NoUsableEnctype { .. } => KDC_ERR_ETYPE_NOSUPP,
            Error::KeyLength { .. } | Error::Crypto(_) => KRB_AP_ERR_BAD_INTEGRITY,
            Error::UnknownPrincipal(_) => KDC_ERR_C_PRINCIPAL_UNKNOWN,
            Error::NotFound(_) => KDC_ERR_S_PRINCIPAL_UNKNOWN,
            // Neither of these is a protocol answer: a create that collided and a
            // refused right both mean the realm's policy said no.
            Error::Exists(_) | Error::Forbidden(_) => KDC_ERR_POLICY,
            Error::Kdc { code, .. } => *code,
            Error::Preauth { code, .. } => *code,
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

    /// A stable, machine-readable name for the failure.
    ///
    /// A transport that has to answer with a status code cannot parse prose: the
    /// message is for a human and will change. These names will not. They are the
    /// vocabulary a REST layer switches on, so adding one is a deliberate act.
    pub fn kind(&self) -> &'static str {
        match self {
            Error::Der(_) => "der",
            Error::UnsupportedEnctype(_)
            | Error::NoUsableEnctype { .. }
            | Error::KeyLength { .. }
            | Error::Crypto(_) => "crypto",
            Error::NotARequest(_) | Error::Protocol(_) => "protocol",
            Error::UnknownPrincipal(_) | Error::NotFound(_) => "not_found",
            Error::Exists(_) => "already_exists",
            Error::Forbidden(_) => "forbidden",
            Error::Preauth { .. } | Error::PreauthFailed(_) => "preauth",
            Error::Kdc { .. } => "policy",
            Error::Skew { .. } => "clock_skew",
            Error::Hdb(_) => "storage",
            Error::Config(_) => "bad_request",
            Error::Io(_) => "io",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::codes;

    #[test]
    fn every_failure_has_a_stable_kind_for_a_transport_to_switch_on() {
        // `kind` is the vocabulary a REST layer switches on — the doc comment says so — and it
        // had no test, so replacing the whole method with a constant survived everything. A
        // transport that receives one name for every failure turns every client error into a
        // 500 or every 500 into a 400, and the reason is invisible from outside.
        let cases: Vec<(super::Error, &str)> = vec![
            (super::Error::Protocol("x".into()), "protocol"),
            (super::Error::UnsupportedEnctype(3), "crypto"),
            (
                super::Error::NoUsableEnctype {
                    principal: crate::name::Principal::parse("a@B").unwrap(),
                    allowed: Vec::new(),
                    asked: Vec::new(),
                },
                "crypto",
            ),
            (super::Error::UnknownPrincipal("a@B".into()), "not_found"),
            (super::Error::NotFound("a@B".into()), "not_found"),
            (super::Error::Exists("a@B".into()), "already_exists"),
            (super::Error::Forbidden("no".into()), "forbidden"),
            (super::Error::PreauthFailed("no".into()), "preauth"),
            (
                super::Error::Kdc {
                    code: 13,
                    text: "no".into(),
                },
                "policy",
            ),
            (super::Error::Hdb("disk".into()), "storage"),
            (super::Error::Config("bad".into()), "bad_request"),
            (super::Error::Io(std::io::Error::other("x")), "io"),
        ];
        for (error, expected) in cases {
            assert_eq!(error.kind(), expected, "{error} got the wrong kind");
        }
    }

    #[test]
    fn every_failure_becomes_the_code_rfc_4120_gives_it() {
        // The mapping the wire depends on, variant by variant. It had no test of its own:
        // integration tests assert codes for the failures they provoke, so a `kdc_code` that
        // answered a constant survived everything — and a client reads the number, not our
        // prose.
        use crate::crypto::Enctype;
        let cases: Vec<(super::Error, i32)> = vec![
            (
                super::Error::UnsupportedEnctype(3),
                super::codes::KDC_ERR_ETYPE_NOSUPP,
            ),
            (
                super::Error::NoUsableEnctype {
                    principal: crate::name::Principal::parse("svc/host@EXAMPLE.COM").unwrap(),
                    allowed: vec![Enctype::Aes128Sha1],
                    asked: vec![18],
                },
                super::codes::KDC_ERR_ETYPE_NOSUPP,
            ),
            (
                super::Error::UnknownPrincipal("nobody@EXAMPLE.COM".into()),
                super::codes::KDC_ERR_C_PRINCIPAL_UNKNOWN,
            ),
            (
                super::Error::NotFound("host/x@EXAMPLE.COM".into()),
                super::codes::KDC_ERR_S_PRINCIPAL_UNKNOWN,
            ),
            (
                super::Error::Forbidden("not yours".into()),
                super::codes::KDC_ERR_POLICY,
            ),
            (
                super::Error::PreauthFailed("no key".into()),
                super::codes::KDC_ERR_PREAUTH_FAILED,
            ),
            (
                super::Error::Skew {
                    skew: 600,
                    allowed: 300,
                },
                super::codes::KRB_AP_ERR_SKEW,
            ),
            (
                super::Error::Hdb("the database is on fire".into()),
                super::codes::KDC_ERR_SVC_UNAVAILABLE,
            ),
            (
                super::Error::Protocol("bad message".into()),
                super::codes::KRB_AP_ERR_MODIFIED,
            ),
            (
                super::Error::Kdc {
                    code: super::codes::KDC_ERR_BADOPTION,
                    text: "no".into(),
                },
                super::codes::KDC_ERR_BADOPTION,
            ),
        ];
        for (error, expected) in cases {
            assert_eq!(
                error.kdc_code(),
                expected,
                "{error} became the wrong code on the wire"
            );
        }
    }

    #[test]
    fn internal_failures_do_not_put_their_text_in_a_reply() {
        // The other half of the wire contract: an I/O or storage error is the operator's
        // business, and a client that receives "connection reset by peer" learns about our
        // filesystem instead of about its ticket.
        assert!(!super::Error::Hdb("disk".into()).is_client_facing());
        assert!(!super::Error::Io(std::io::Error::other("x")).is_client_facing());
        assert!(super::Error::NotFound("svc@R".into()).is_client_facing());
        assert!(super::Error::Protocol("bad".into()).is_client_facing());
    }

    /// Every code on the wire, against the literal RFC 4120 §7.5 quotes.
    ///
    /// These were two off by one — `MSG_TYPE` at 41 and `MODIFIED` at 42 — because the
    /// error list is easy to write from memory and impossible to notice from inside: the
    /// crate's own tests compare against the same constants, so a shifted pair agrees with
    /// itself perfectly. A third-party client reading 42 as `KRB_AP_ERR_BADORDER` is the
    /// only thing that would have said so. The literals stay in the test for the same
    /// reason they must not appear only in the constants: a test that reads the constant
    /// proves that the constant equals itself.
    #[test]
    fn the_error_codes_are_the_numbers_rfc_4120_quotes() {
        for (code, want, name) in [
            (codes::KDC_ERR_POLICY, 12, "KDC_ERR_POLICY"),
            (codes::KDC_ERR_ETYPE_NOSUPP, 14, "KDC_ERR_ETYPE_NOSUPP"),
            (codes::KDC_ERR_PREAUTH_FAILED, 24, "KDC_ERR_PREAUTH_FAILED"),
            (
                codes::KDC_ERR_PREAUTH_REQUIRED,
                25,
                "KDC_ERR_PREAUTH_REQUIRED",
            ),
            (codes::KDC_ERR_SERVER_NOMATCH, 26, "KDC_ERR_SERVER_NOMATCH"),
            (
                codes::KDC_ERR_RESPONSE_TOO_BIG,
                52,
                "KDC_ERR_RESPONSE_TOO_BIG",
            ),
            (codes::KDC_ERR_WRONG_REALM, 68, "KDC_ERR_WRONG_REALM"),
            (
                codes::KRB_AP_ERR_BAD_INTEGRITY,
                31,
                "KRB_AP_ERR_BAD_INTEGRITY",
            ),
            (codes::KRB_AP_ERR_TKT_EXPIRED, 32, "KRB_AP_ERR_TKT_EXPIRED"),
            (codes::KRB_AP_ERR_TKT_NYV, 33, "KRB_AP_ERR_TKT_NYV"),
            (codes::KRB_AP_ERR_BADMATCH, 36, "KRB_AP_ERR_BADMATCH"),
            (codes::KRB_AP_ERR_SKEW, 37, "KRB_AP_ERR_SKEW"),
            (codes::KRB_AP_ERR_BADADDR, 38, "KRB_AP_ERR_BADADDR"),
            (codes::KRB_AP_ERR_BADVERSION, 39, "KRB_AP_ERR_BADVERSION"),
            (codes::KRB_AP_ERR_MSG_TYPE, 40, "KRB_AP_ERR_MSG_TYPE"),
            (codes::KRB_AP_ERR_MODIFIED, 41, "KRB_AP_ERR_MODIFIED"),
        ] {
            assert_eq!(code, want, "{name} must be {want}");
        }
    }

    #[test]
    fn the_fast_option_error_is_the_one_rfc_6113_adds() {
        // RFC 6113 §5.4.4.2: `KDC_ERR_UNKNOWN_CRITICAL_FAST_OPTIONS` is 93, in the KDC
        // range, next to nothing else this crate uses.
        assert_eq!(codes::KDC_ERR_UNKNOWN_CRITICAL_FAST_OPTIONS, 93);
    }
}
