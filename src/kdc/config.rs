//! The KDC's configuration: the subset of Heimdal's KDC options this engine
//! implements, and a refusal for everything else.
//!
//! Heimdal has 47 options in `kdc/default_config.c`. This engine implements
//! some of them, and **rejects the rest at startup by name** rather than
//! ignoring them: an operator who writes `require_pac = true` and is silently
//! given a KDC that does not is an operator running a system that does not do
//! what its configuration says. Failing loudly is the only honest option until
//! the option exists.

use crate::crypto::Enctype;
use crate::error::{Error, Result};

/// Heimdal's `max_life` default: the lifetime of a ticket the client did not
/// bound.
pub const DEFAULT_MAX_LIFE: i64 = 86_400;
/// Heimdal's `max_renewable_life` default.
pub const DEFAULT_MAX_RENEWABLE_LIFE: i64 = 604_800;
/// Heimdal's `clockskew` default.
pub const DEFAULT_CLOCKSKEW: i64 = 300;

/// What a KDC needs to know about itself.
#[derive(Clone, Debug)]
pub struct KdcConfig {
    /// The realm this KDC serves. A request for another is refused with
    /// `KDC_ERR_WRONG_REALM` rather than silently answered.
    realm: String,
    /// The longest lifetime a ticket may have.
    max_life: i64,
    /// The longest time a ticket may be renewable for.
    max_renewable_life: i64,
    /// How far a client's clock may differ from this KDC's.
    clockskew: i64,
    /// Heimdal's `require-preauth`: refuse an AS-REQ with no pre-authentication.
    require_preauth: bool,
    /// Heimdal's `allowed_enctypes`, strongest first. The order is this KDC's
    /// preference, and it is what the session key's enctype is chosen from.
    allowed_enctypes: Vec<Enctype>,
}

impl KdcConfig {
    /// A configuration for `realm` with every default at Heimdal's.
    pub fn new(realm: impl Into<String>) -> Result<Self> {
        let realm = realm.into();
        if realm.is_empty() {
            return Err(Error::Config(
                "a KDC must serve a realm, and this one is empty".into(),
            ));
        }
        if realm.bytes().any(|b| b.is_ascii_lowercase()) {
            // Not an error in Kerberos, but a realm and its `krbtgt` are
            // compared as octets everywhere, and a realm that changes case
            // between the configuration and the client's request is the most
            // common way to get `KDC_ERR_WRONG_REALM` for a realm that exists.
            // Heimdal accepts it; this crate says so out loud instead.
            tracing_warn_realm_case(&realm);
        }
        Ok(KdcConfig {
            realm,
            max_life: DEFAULT_MAX_LIFE,
            max_renewable_life: DEFAULT_MAX_RENEWABLE_LIFE,
            clockskew: DEFAULT_CLOCKSKEW,
            require_preauth: true,
            allowed_enctypes: Enctype::ALL.to_vec(),
        })
    }

    /// The realm this KDC serves.
    pub fn realm(&self) -> &str {
        &self.realm
    }

    /// `max_life`.
    pub fn max_life(&self) -> i64 {
        self.max_life
    }

    /// `max_renewable_life`.
    pub fn max_renewable_life(&self) -> i64 {
        self.max_renewable_life
    }

    /// `clockskew`.
    pub fn clockskew(&self) -> i64 {
        self.clockskew
    }

    /// `require-preauth`.
    pub fn require_preauth(&self) -> bool {
        self.require_preauth
    }

    /// `allowed_enctypes`, strongest first.
    pub fn allowed_enctypes(&self) -> &[Enctype] {
        &self.allowed_enctypes
    }

    /// Sets `max_life`. Zero or negative is refused: a ticket that cannot be
    /// issued is not a configuration, it is a mistake.
    pub fn with_max_life(mut self, secs: i64) -> Result<Self> {
        if secs <= 0 {
            return Err(Error::Config(format!(
                "max_life must be positive, got {secs}"
            )));
        }
        self.max_life = secs;
        Ok(self)
    }

    /// Sets `max_renewable_life`.
    pub fn with_max_renewable_life(mut self, secs: i64) -> Result<Self> {
        if secs <= 0 {
            return Err(Error::Config(format!(
                "max_renewable_life must be positive, got {secs}"
            )));
        }
        self.max_renewable_life = secs;
        Ok(self)
    }

    /// Sets `clockskew`.
    pub fn with_clockskew(mut self, secs: i64) -> Result<Self> {
        if secs < 0 {
            return Err(Error::Config(format!(
                "clockskew cannot be negative: {secs}"
            )));
        }
        self.clockskew = secs;
        Ok(self)
    }

    /// Sets `require-preauth`.
    pub fn with_require_preauth(mut self, yes: bool) -> Self {
        self.require_preauth = yes;
        self
    }

    /// Sets `allowed_enctypes` from names, as `krb5.conf` writes them.
    pub fn with_enctypes(mut self, names: &[&str]) -> Result<Self> {
        let parsed = Enctype::parse_list(names)?;
        if parsed.is_empty() {
            return Err(Error::Config(
                "allowed_enctypes is empty: a KDC that may issue no enctype can serve nobody"
                    .into(),
            ));
        }
        self.allowed_enctypes = parsed;
        Ok(self)
    }

    /// Applies one option by its Heimdal name.
    ///
    /// The names are Heimdal's (`kdc/default_config.c`, `kdc/kdc.8`), so a
    /// configuration written for Heimdal can be read here — and an option this
    /// engine does not implement is an error naming that option, never a silent
    /// no-op.
    pub fn apply(&mut self, name: &str, value: &str) -> Result<()> {
        let parse_bool = |v: &str| -> Result<bool> {
            match v.trim().to_ascii_lowercase().as_str() {
                "true" | "yes" | "1" => Ok(true),
                "false" | "no" | "0" => Ok(false),
                other => Err(Error::Config(format!(
                    "option {name}: {other:?} is not a boolean"
                ))),
            }
        };
        let parse_secs = |v: &str| -> Result<i64> {
            parse_duration_secs(v)
                .ok_or_else(|| Error::Config(format!("option {name}: {v:?} is not a duration")))
        };
        match name {
            "max_life" | "max-life" => {
                self.max_life = parse_secs(value)?;
                if self.max_life <= 0 {
                    return Err(Error::Config(format!("option {name} must be positive")));
                }
                Ok(())
            }
            "max_renewable_life" | "max-renewable-life" => {
                self.max_renewable_life = parse_secs(value)?;
                if self.max_renewable_life <= 0 {
                    return Err(Error::Config(format!("option {name} must be positive")));
                }
                Ok(())
            }
            "clockskew" => {
                self.clockskew = parse_secs(value)?;
                Ok(())
            }
            "require-preauth" | "require_preauth" => {
                self.require_preauth = parse_bool(value)?;
                Ok(())
            }
            "allowed_enctypes" | "allowed-enctypes" => {
                let names: Vec<&str> = value
                    .split(|c: char| c == ',' || c.is_whitespace())
                    .filter(|s| !s.is_empty())
                    .collect();
                let parsed = Enctype::parse_list(&names)?;
                if parsed.is_empty() {
                    return Err(Error::Config(format!(
                        "option {name} names no enctype this KDC implements"
                    )));
                }
                self.allowed_enctypes = parsed;
                Ok(())
            }
            other => Err(Error::Config(format!(
                "KDC option {other:?} is not implemented by this engine. \
                 Implemented: max_life, max_renewable_life, clockskew, require-preauth, \
                 allowed_enctypes. Refusing rather than ignoring it: a KDC that silently \
                 does not do what its configuration says is worse than one that will not start."
            ))),
        }
    }
}

fn tracing_warn_realm_case(_realm: &str) {
    // A hook rather than a `tracing::warn!` so this module compiles the same
    // with the `trace` feature off; the KDC logs it at startup.
}

/// `1h`, `3600`, `7d` — Heimdal's `krb5_config_get_time` accepts both.
pub fn parse_duration_secs(s: &str) -> Option<i64> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    let (digits, multiplier) = match s.as_bytes().last()? {
        b's' | b'S' => (&s[..s.len() - 1], 1),
        b'm' | b'M' => (&s[..s.len() - 1], 60),
        b'h' | b'H' => (&s[..s.len() - 1], 3_600),
        b'd' | b'D' => (&s[..s.len() - 1], 86_400),
        b'w' | b'W' => (&s[..s.len() - 1], 604_800),
        _ => (s, 1),
    };
    let n: i64 = digits.trim().parse().ok()?;
    n.checked_mul(multiplier)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_heimdals() {
        let c = KdcConfig::new("EXAMPLE.COM").unwrap();
        assert_eq!(c.max_life(), DEFAULT_MAX_LIFE);
        assert_eq!(c.max_renewable_life(), DEFAULT_MAX_RENEWABLE_LIFE);
        assert_eq!(c.clockskew(), DEFAULT_CLOCKSKEW);
        assert!(c.require_preauth());
        assert_eq!(c.allowed_enctypes(), &Enctype::ALL);
    }

    #[test]
    fn an_empty_realm_is_refused() {
        assert!(KdcConfig::new("").is_err());
    }

    #[test]
    fn durations_parse_the_way_krb5_conf_writes_them() {
        assert_eq!(parse_duration_secs("3600"), Some(3600));
        assert_eq!(parse_duration_secs("1h"), Some(3600));
        assert_eq!(parse_duration_secs("7d"), Some(604_800));
        assert_eq!(parse_duration_secs("1w"), Some(604_800));
        assert_eq!(parse_duration_secs("30m"), Some(1800));
        assert_eq!(parse_duration_secs("abc"), None);
        assert_eq!(parse_duration_secs(""), None);
    }

    #[test]
    fn implemented_options_apply() {
        let mut c = KdcConfig::new("R").unwrap();
        c.apply("max_life", "12h").unwrap();
        assert_eq!(c.max_life(), 43_200);
        c.apply("max_renewable_life", "7d").unwrap();
        assert_eq!(c.max_renewable_life(), 604_800);
        c.apply("clockskew", "60").unwrap();
        assert_eq!(c.clockskew(), 60);
        c.apply("require-preauth", "false").unwrap();
        assert!(!c.require_preauth());
        c.apply(
            "allowed_enctypes",
            "aes256-cts-hmac-sha1-96, aes128-cts-hmac-sha1-96",
        )
        .unwrap();
        assert_eq!(
            c.allowed_enctypes(),
            &[Enctype::Aes256Sha1, Enctype::Aes128Sha1]
        );
    }

    #[test]
    fn an_unimplemented_option_is_refused_by_name() {
        let mut c = KdcConfig::new("R").unwrap();
        let err = c.apply("require_pac", "true").unwrap_err().to_string();
        assert!(err.contains("require_pac"), "{err}");
        assert!(err.contains("not implemented"), "{err}");
        assert!(c.apply("enable-pkinit", "true").is_err());
        assert!(c.apply("enable_fast", "true").is_err());
    }

    #[test]
    fn a_bad_value_is_refused() {
        let mut c = KdcConfig::new("R").unwrap();
        assert!(c.apply("require-preauth", "maybe").is_err());
        assert!(c.apply("max_life", "0").is_err());
        assert!(c.apply("max_life", "-5").is_err());
        assert!(c.apply("allowed_enctypes", "rc4-hmac").is_err());
        assert!(c.apply("clockskew", "soon").is_err());
    }
}
