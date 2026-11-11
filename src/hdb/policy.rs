//! `kadm5_policy_ent_rec`: the named rules a principal is created under.
//!
//! MIT keeps policies in the same database as the principals and names one from each principal's
//! record. The policy is what an operator says once — "accounts of the `staff` policy expire after
//! ninety days, their passwords after thirty, and a password is at least twelve characters" — and
//! then applies to every account created under it, rather than repeating the numbers on each.
//!
//! Every lifetime here is in seconds, and **zero means "no limit"**: that is MIT's spelling, and it
//! is why the fields are plain numbers rather than `Option`s — the wire has no separate "absent" for
//! them, and the mask on a modify request is what distinguishes "leave it" from "set it to zero".

use std::fmt;

use crate::der;
use crate::error::{Error, Result};

/// Why a password was refused by a policy.
///
/// Reasons rather than a message, because the two an operator can act on have different answers in
/// `kadm5` — "too short" and "not enough classes" are separate codes, and a server that collapsed
/// them into one string would leave the operator guessing which rule they missed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Breach {
    /// Shorter than `pw_min_length`.
    TooShort {
        /// How many characters it had.
        have: usize,
        /// How many the policy wants.
        want: u32,
    },
    /// Fewer of the four character classes than `pw_min_classes`.
    TooFewClasses {
        /// How many it used.
        have: u32,
        /// How many the policy wants.
        want: u32,
    },
}

impl fmt::Display for Breach {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Breach::TooShort { have, want } => {
                write!(
                    f,
                    "the password is {have} characters, the policy wants {want}"
                )
            }
            Breach::TooFewClasses { have, want } => write!(
                f,
                "the password uses {have} character classes, the policy wants {want}"
            ),
        }
    }
}

impl std::error::Error for Breach {}

/// One policy.
#[cfg_attr(feature = "admin-json", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Policy {
    /// Its name, which is what a principal's record cites and what `kadmin` shows.
    pub name: String,
    /// The shortest time a password may be kept (`pw_min_life`).
    pub pw_min_life: i64,
    /// The longest time a password may be kept; zero is no limit (`pw_max_life`).
    pub pw_max_life: i64,
    /// The fewest characters a password may have (`pw_min_length`).
    pub pw_min_length: u32,
    /// How many of the character classes a password must use: upper, lower, digit, other
    /// (`pw_min_classes`).
    pub pw_min_classes: u32,
    /// How many past passwords are remembered (`pw_history_num`).
    pub pw_history_num: u32,
    /// How many failed authentications lock the account (`pw_max_fail`).
    pub pw_max_fail: u32,
    /// The window failures are counted in; zero is forever (`pw_failcnt_interval`).
    pub pw_failcnt_interval: i64,
    /// How long a lockout lasts; zero is until an administrator clears it
    /// (`pw_lockout_duration`).
    pub pw_lockout_duration: i64,
    /// The longest ticket a principal under this policy may hold (`max_life`).
    pub max_life: i64,
    /// The longest a ticket may be renewed for (`max_renewable_life`).
    pub max_renewable_life: i64,
    /// The enctypes a key may be made in, as `krb5.conf` names them, comma-separated; empty is all
    /// (`allowed_keysalts`).
    pub allowed_keysalts: String,
}

impl Policy {
    /// A policy with a name and every limit absent.
    pub fn new(name: &str) -> Self {
        Policy {
            name: name.to_owned(),
            ..Policy::default()
        }
    }

    /// Checks what a policy cannot say about itself.
    ///
    /// An empty name is refused: it is the key a principal cites, and no principal can cite
    /// nothing. So is `min_life > max_life` where both are set, because no password satisfies both
    /// and every account under the policy would be stuck with a password it may not change.
    pub fn check(&self) -> Result<()> {
        if self.name.is_empty() {
            return Err(Error::Config(
                "a policy with no name: it is the name a principal cites".into(),
            ));
        }
        if self.pw_max_life != 0 && self.pw_min_life > self.pw_max_life {
            return Err(Error::Config(format!(
                "policy {}: pw_min_life {} is longer than pw_max_life {}",
                self.name, self.pw_min_life, self.pw_max_life
            )));
        }
        // 32 is the most distinct characters a `u32` can hold a class count for, and the four
        // classes MIT defines are what the count is over: a policy that demands more than four can
        // never be satisfied.
        if self.pw_min_classes > 4 {
            return Err(Error::Config(format!(
                "policy {}: pw_min_classes {} over the four classes that exist",
                self.name, self.pw_min_classes
            )));
        }
        Ok(())
    }

    /// Whether `password` satisfies the length and class rules.
    ///
    /// Length and class count only: those are the two an operator can be held to here. History is
    /// not checked because this server keeps no record of past passwords, and a check that cannot
    /// be made must not be reported as passed — [`Policy::pw_history_num`] is stored and reported,
    /// and nothing in this crate enforces it.
    pub fn admits_password(&self, password: &[u8]) -> std::result::Result<(), Breach> {
        if (password.len() as u32) < self.pw_min_length {
            return Err(Breach::TooShort {
                have: password.len(),
                want: self.pw_min_length,
            });
        }
        let classes = classes_of(password);
        if classes < self.pw_min_classes {
            return Err(Breach::TooFewClasses {
                have: classes,
                want: self.pw_min_classes,
            });
        }
        Ok(())
    }
}

/// The on-disk form: a `SEQUENCE` of numbered fields, so that a policy written by this crate reads
/// back the same way after a restart and a field added later does not shift the ones beside it.
impl Policy {
    /// This policy as DER.
    pub fn encode(&self) -> Vec<u8> {
        der::seq(&[
            der::field(0, der::tlv(0x0c, self.name.as_bytes())),
            der::field(1, der::int(self.pw_min_life)),
            der::field(2, der::int(self.pw_max_life)),
            der::field(3, der::int(i64::from(self.pw_min_length))),
            der::field(4, der::int(i64::from(self.pw_min_classes))),
            der::field(5, der::int(i64::from(self.pw_history_num))),
            der::field(6, der::int(i64::from(self.pw_max_fail))),
            der::field(7, der::int(self.pw_failcnt_interval)),
            der::field(8, der::int(self.pw_lockout_duration)),
            der::field(9, der::int(self.max_life)),
            der::field(10, der::int(self.max_renewable_life)),
            der::field(11, der::tlv(0x0c, self.allowed_keysalts.as_bytes())),
        ])
    }

    /// A policy from [`Policy::encode`].
    pub fn decode(bytes: &[u8]) -> Result<Policy> {
        const CTX: &str = "hdb policy";
        let f = der::Fields::parse_tagged(CTX, der::SEQUENCE, bytes)?;
        // `Fields::bytes` gives the *content* of field `[n]`, and the content here is itself one
        // encoded value (a `UTF8String`, an `INTEGER`): reading it as the value would put the tag
        // and the length inside the number — `staff` arriving as `"\u{c}\u{5}staff"` — which is
        // exactly the shape a round-trip test catches and a reader does not.
        let text = |n: u8| -> Result<String> {
            let mut r = der::Reader::new(f.bytes(n, CTX)?);
            Ok(der::as_string(CTX, r.expect_in(CTX, 0x0c)?)?)
        };
        let long = |n: u8| -> Result<i64> {
            let mut r = der::Reader::new(f.bytes(n, CTX)?);
            Ok(der::as_int(CTX, r.expect_in(CTX, der::INTEGER)?)?)
        };
        let wide = |n: u8| -> Result<u32> {
            let mut r = der::Reader::new(f.bytes(n, CTX)?);
            Ok(der::as_u32(CTX, r.expect_in(CTX, der::INTEGER)?)?)
        };
        Ok(Policy {
            name: text(0)?,
            pw_min_life: long(1)?,
            pw_max_life: long(2)?,
            pw_min_length: wide(3)?,
            pw_min_classes: wide(4)?,
            pw_history_num: wide(5)?,
            pw_max_fail: wide(6)?,
            pw_failcnt_interval: long(7)?,
            pw_lockout_duration: long(8)?,
            max_life: long(9)?,
            max_renewable_life: long(10)?,
            allowed_keysalts: text(11)?,
        })
    }
}

/// How many of upper, lower, digit and other a password uses.
fn classes_of(password: &[u8]) -> u32 {
    let mut upper = false;
    let mut lower = false;
    let mut digit = false;
    let mut other = false;
    for byte in password {
        match *byte {
            b'A'..=b'Z' => upper = true,
            b'a'..=b'z' => lower = true,
            b'0'..=b'9' => digit = true,
            _ => other = true,
        }
    }
    u32::from(upper) + u32::from(lower) + u32::from(digit) + u32::from(other)
}

impl fmt::Display for Policy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_password_is_measured_against_the_length_and_the_classes() {
        let mut policy = Policy::new("staff");
        policy.pw_min_length = 8;
        policy.pw_min_classes = 3;
        assert!(
            policy.admits_password(b"short1!").is_err(),
            "seven characters"
        );
        assert!(
            policy.admits_password(b"alllowercase").is_err(),
            "one class"
        );
        // Two classes are enough for this policy and three are not: the difference between the two
        // spellings below is one letter's case, which is the whole point of counting classes.
        assert!(
            policy.admits_password(b"lower&UPPER").is_ok(),
            "lower, upper and other: three classes, eleven characters"
        );
        assert!(
            policy.admits_password(b"lower&upper").is_err(),
            "no upper-case letter"
        );
        assert!(policy.admits_password(b"lower&UPPER1").is_ok());
        // A space and a punctuation mark are the same class: "other" is everything that is not a
        // letter or a digit, so a passphrase of three words is not four classes.
        assert_eq!(classes_of(b"a b"), 2);
        // Only ASCII letters count as letters: Cyrillic octets land in "other", so a policy that
        // asks for three classes is not satisfied by a Cyrillic word and a digit.
        assert_eq!(classes_of("Пароль1".as_bytes()), 2);
    }

    #[test]
    fn a_policy_round_trips_through_its_stored_form() {
        let policy = Policy {
            name: "staff".into(),
            pw_min_life: 3600,
            pw_max_life: 2_592_000,
            pw_min_length: 12,
            pw_min_classes: 3,
            pw_history_num: 5,
            pw_max_fail: 6,
            pw_failcnt_interval: 300,
            pw_lockout_duration: 900,
            max_life: 86_400,
            max_renewable_life: 604_800,
            allowed_keysalts: "aes256-cts-hmac-sha1-96".into(),
        };
        assert_eq!(Policy::decode(&policy.encode()).unwrap(), policy);

        // An empty one too: the empty `allowed_keysalts` and a zero lifetime are both "no limit",
        // and a decoder that treated the empty string as a missing field would fail here.
        let empty = Policy::new("open");
        assert_eq!(Policy::decode(&empty.encode()).unwrap(), empty);
    }

    #[test]
    fn a_policy_that_cannot_be_satisfied_is_refused() {
        let mut policy = Policy::new("staff");
        policy.pw_min_life = 100;
        policy.pw_max_life = 50;
        assert!(policy.check().is_err(), "min above max");

        let mut policy = Policy::new("staff");
        policy.pw_min_classes = 5;
        assert!(policy.check().is_err(), "five classes do not exist");

        assert!(Policy::new("").check().is_err(), "no name");

        let mut policy = Policy::new("staff");
        policy.pw_min_life = 50;
        policy.pw_max_life = 0;
        assert!(
            policy.check().is_ok(),
            "zero max is no limit, not a limit of zero"
        );
    }
}
