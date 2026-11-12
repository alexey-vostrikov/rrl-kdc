//! `require-hwauth`: whether the way a client authenticated counts as hardware.
//!
//! `HDBFlags::REQUIRE_HWAUTH` says an account may only get a ticket through something stronger than
//! a password in software. The flag alone cannot answer the question it raises — whether *this*
//! authentication was hardware — so it needs a policy, and Heimdal has one:
//! `_kdc_hwauth_policy` (`kdc/kdc-plugin.c`) asks a plugin, and when no plugin answers it falls back
//! to its own table.
//!
//! # Heimdal's own answer, and why it is what it is
//!
//! In `kdc/kerberos5.c` the pre-authentication table carries a `PA_HARDWARE_AUTH` flag, and the
//! check is skipped only for entries that set it. Exactly two do, and both are PKINIT:
//! `KRB5_PADATA_PK_AS_REQ` ("PK-INIT(ietf)") and `KRB5_PADATA_PK_AS_REQ_WIN` ("PK-INIT(win2k)").
//! Everything else — `ENC-TS`, GSS pre-authentication, OTP, SPAKE, the FAST challenge — does **not**
//! set it, so an account with the flag is refused when it arrives that way, unless a plugin says
//! otherwise.
//!
//! That is not an oversight in Heimdal: a certificate plus a private key is the one thing in the
//! protocol that can live in a smartcard or a TPM without the secret ever reaching software. A
//! password sealed in the long-term key, a SPAKE exchange and an OTP are all reachable by whoever
//! holds a copy of a secret in memory, which is the threat the flag exists against. [`CertificateOnly`]
//! reproduces that answer here, so a realm that turns the flag on behaves as an administrator
//! migrating from Heimdal expects.
//!
//! # One consequence worth stating: the flag alone does not force pre-authentication
//!
//! Heimdal checks the policy **inside** the loop over pre-authentication types that matched
//! (`if (req->padata)` guards it), so an account with `require-hwauth` and **without**
//! `require-preauth` still gets a ticket when it presents nothing — a ticket sealed in its long-term
//! key, which is an offline-attackable blob under the same conditions as any AS-REP. This crate
//! reproduces that, because Heimdal's behaviour is the specification here, and it is a fact an
//! administrator needs: `require-hwauth` is meaningful together with `require-preauth`, and setting
//! only the former buys nothing against a client that sends no pre-authentication at all.
//!
//! Closing it would be a deviation — a defensible one, since a realm that sets the flag plainly means
//! "not a password in software" — and it is deliberately not taken silently: a policy that refuses
//! where Heimdal issues would break a client that works against Heimdal.
//!
//! # Where the seam is, and what it is for
//!
//! [`HwAuthPolicy`] receives the client and the method, and answers yes or no. A deployment that
//! knows better — an estate where every laptop has a TPM-backed keytab, or one that treats a
//! hardware OTP as sufficient — implements it, and the decisions are its own. The trait returns a
//! bool rather than an error because the only two answers are "admit" and "this flag refuses you":
//! whether the client would have authenticated otherwise is not the policy's business, and answering
//! it with the wrong error code turns a policy decision into a password oracle.

use crate::hdb::HdbEntry;
use crate::name::Principal;

/// How a client authenticated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    /// `PA-PK-AS-REQ`: a certificate, whose private key need never be in software.
    Certificate,
    /// `PA-ENC-TIMESTAMP`: the password, sealed in the client's long-term key.
    Timestamp,
    /// `PA-ENCRYPTED-CHALLENGE`: the password, inside FAST armor.
    EncryptedChallenge,
    /// A multi-round mechanism, named by the PA type it answers (`PA-OTP-REQUEST`, SPAKE's, GSS's).
    Mechanism(i32),
}

impl Method {
    /// The name a log line should use. Not a PA type number: an operator reading "refused" wants to
    /// know it was a password, and the number for the GSS mechanism is not even in the IANA registry.
    pub fn as_str(self) -> &'static str {
        match self {
            Method::Certificate => "certificate",
            Method::Timestamp => "timestamp",
            Method::EncryptedChallenge => "encrypted-challenge",
            Method::Mechanism(_) => "mechanism",
        }
    }
}

/// Whether an authentication satisfies `require-hwauth`.
pub trait HwAuthPolicy: std::fmt::Debug + Send + Sync {
    /// Whether `method`, which is how `client` authenticated, satisfies the entry's requirement.
    ///
    /// Only called for an entry that has the flag: an account without it is not asked the question,
    /// and a policy that assumed it was called for every login would be a policy with a bug.
    fn admits(&self, client: &Principal, method: Method) -> bool;
}

/// Heimdal's own answer when no plugin is configured: a certificate counts, nothing else does.
///
/// See the module documentation for why the set is one entry long. In particular this is **not**
/// "PKINIT is stronger than passwords" as an opinion about cryptography — it is what Heimdal's
/// `PA_HARDWARE_AUTH` flags say, and this crate's standard is Heimdal's behaviour.
#[derive(Debug, Clone, Copy, Default)]
pub struct CertificateOnly;

impl HwAuthPolicy for CertificateOnly {
    fn admits(&self, _client: &Principal, method: Method) -> bool {
        matches!(method, Method::Certificate)
    }
}

/// Admits everything. A policy for a realm that wants the flag to have no effect — declared, rather
/// than achieved by not implementing the check at all.
#[derive(Debug, Clone, Copy, Default)]
pub struct AnyMethod;

impl HwAuthPolicy for AnyMethod {
    fn admits(&self, _client: &Principal, _method: Method) -> bool {
        true
    }
}

/// A policy over a fixed list of method names, for a realm whose rules are configuration.
///
/// Names are [`Method::as_str`]'s: `certificate`, `timestamp`, `encrypted-challenge`, `mechanism`.
/// An unknown name is refused at construction rather than ignored — a typo in a configuration file
/// that silently admits nothing is an outage nobody can explain.
#[derive(Debug, Clone)]
pub struct AllowList {
    certificate: bool,
    timestamp: bool,
    encrypted_challenge: bool,
    mechanism: bool,
}

impl AllowList {
    /// Builds the policy, refusing a name it does not know.
    pub fn new(methods: &[&str]) -> crate::error::Result<Self> {
        let mut policy = Self {
            certificate: false,
            timestamp: false,
            encrypted_challenge: false,
            mechanism: false,
        };
        for name in methods {
            match *name {
                "certificate" => policy.certificate = true,
                "timestamp" => policy.timestamp = true,
                "encrypted-challenge" => policy.encrypted_challenge = true,
                "mechanism" => policy.mechanism = true,
                other => {
                    return Err(crate::error::Error::Config(format!(
                        "require-hwauth admits the methods certificate, timestamp, \
                         encrypted-challenge and mechanism; {other:?} is not one of them"
                    )));
                }
            }
        }
        Ok(policy)
    }
}

impl HwAuthPolicy for AllowList {
    fn admits(&self, _client: &Principal, method: Method) -> bool {
        match method {
            Method::Certificate => self.certificate,
            Method::Timestamp => self.timestamp,
            Method::EncryptedChallenge => self.encrypted_challenge,
            Method::Mechanism(_) => self.mechanism,
        }
    }
}

/// Whether a flag on `entry` makes this question apply at all.
///
/// A function rather than a method on the policy, because the answer does not depend on the policy
/// and a policy that got it wrong would be refusing entries nobody asked it to refuse.
pub fn applies(entry: &HdbEntry) -> bool {
    entry.has(crate::hdb::flags::REQUIRE_HWAUTH)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hdb::flags;

    fn principal() -> Principal {
        Principal::parse("alice@EXAMPLE.COM").unwrap()
    }

    /// Heimdal's answer: a certificate admits, and every way of presenting a password does not.
    ///
    /// The set is pinned by value rather than by a range check, because a later "well, SPAKE is
    /// strong too" would be a change of behaviour for every realm that set the flag expecting
    /// Heimdal's.
    #[test]
    fn a_certificate_is_the_only_hardware_method_heimdal_names() {
        let policy = CertificateOnly;
        assert!(policy.admits(&principal(), Method::Certificate));
        for method in [
            Method::Timestamp,
            Method::EncryptedChallenge,
            Method::Mechanism(141),
            Method::Mechanism(655),
        ] {
            assert!(
                !policy.admits(&principal(), method),
                "{} is not hardware authentication",
                method.as_str()
            );
        }
    }

    /// The flag is what makes the question apply, and an entry without it is never asked.
    #[test]
    fn the_flag_is_what_applies_the_policy() {
        let mut entry = HdbEntry::user(principal());
        assert!(
            !applies(&entry),
            "a new account does not require hardware auth"
        );
        entry.flags |= flags::REQUIRE_HWAUTH;
        assert!(applies(&entry));
    }

    /// A list admits exactly what it names, and an unknown name is refused at construction.
    #[test]
    fn a_list_admits_what_it_names_and_nothing_else() {
        let policy = AllowList::new(&["certificate", "mechanism"]).expect("known names");
        assert!(policy.admits(&principal(), Method::Certificate));
        assert!(policy.admits(&principal(), Method::Mechanism(141)));
        assert!(!policy.admits(&principal(), Method::Timestamp));
        assert!(!policy.admits(&principal(), Method::EncryptedChallenge));

        let err = AllowList::new(&["hardware"])
            .expect_err("`hardware` is not a method name")
            .to_string();
        assert!(
            err.contains("hardware") && err.contains("certificate"),
            "the message must name the wrong value and the right ones: {err}"
        );
    }
}
