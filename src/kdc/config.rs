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

/// Heimdal's `[kdc] transited-policy` (`kdc/default_config.c`), which decides whether the path
/// in a presented ticket is checked before a ticket is issued on it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransitedPolicy {
    /// Check on every request. Heimdal's default.
    AlwaysCheck,
    /// Heimdal's `allow-per-principal`. Both per-principal hooks are compiled out there
    /// (`PRINCIPAL_FORCE_TRANSITED_CHECK` and `PRINCIPAL_ALLOW_DISABLE_TRANSITED_CHECK` are
    /// `0` in `kdc/krb5tgs.c`), so the value reduces to `always-check`; accepting it is what
    /// makes a Heimdal configuration readable here, and inventing a per-principal database
    /// field that Heimdal does not have would be a different feature.
    AllowPerPrincipal,
    /// Honour the client's `disable-transited-check` (RFC 4120 §5.4.1, bit 26), which is
    /// what Heimdal's `always-honour-request` does. A ticket issued without the check says so
    /// by leaving `TRANSITED-POLICY-CHECKED` clear, and the service then checks the path
    /// itself — refusing the request instead would let a client break its own logon by
    /// setting a bit, and accepting it silently would hide the fact that nobody checked.
    AlwaysHonourRequest,
}

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
    /// Whether this realm issues anonymous tickets (RFC 8062).
    anonymous_pkinit: bool,
    /// Heimdal's `allowed_enctypes`, strongest first. The order is this KDC's
    /// preference, and it is what the session key's enctype is chosen from.
    allowed_enctypes: Vec<Enctype>,
    /// The address policy: `check-ticket-addresses`,
    /// `allow-null-ticket-addresses`, `warn-ticket-addresses`.
    addresses: crate::address::AddressPolicy,
    /// Whether the path in a presented ticket is checked.
    transited_policy: TransitedPolicy,
    /// The realms this KDC accepts as transit realms, `None` when the DNS hierarchy between
    /// the two endpoints decides.
    ///
    /// Heimdal takes this list from `[capaths]` in `krb5.conf` and, when a pair of realms has
    /// no entry there, walks the DNS tree (`_krb5_find_capath` with `use_hierarchical`).
    /// This crate's KDC has no `krb5.conf` reader — it is a library and the embedder owns
    /// configuration — so the explicit list is an option here and the hierarchy is the
    /// default.
    transited_realms: Option<Vec<String>>,
    /// `require-pac`: a ticket-granting ticket that carries no PAC is treated as revoked.
    ///
    /// Heimdal's meaning, and narrower than it sounds: the KDC does not refuse to *issue* a
    /// ticket when no PAC can be built (it issues one without, which is a realm that answers for
    /// an account the directory does not know). What it refuses is to *accept* such a TGT in the
    /// TGS — a client holding a TGT without a PAC in a realm that requires one holds a TGT this
    /// KDC would not have issued, and the code for that is `KRB5KDC_ERR_TGT_REVOKED`.
    require_pac: bool,
    /// `disable-pac`: issue no PAC at all, whatever the entry flags and the client ask for.
    disable_pac: bool,
    /// `tgt-use-strongest-session-key`: pick the TGS session key's enctype by this KDC's own
    /// preference rather than by the client's list.
    ///
    /// Heimdal's default is off, and off means **the client's order** — the first enctype in the
    /// request's `etype` list that this KDC and the service both support. The option exists to
    /// encourage stronger enctypes against a client that still lists weaker ones first; it does
    /// not exist to make "strongest" the default, and a KDC that always used its own order would
    /// be answering a question the client asked in a particular order.
    tgt_use_strongest_session_key: bool,
    /// `svc-use-strongest-session-key`: the same for a session key granted in an AS exchange —
    /// the TGT's own session key, whose "service" is `krbtgt`. Heimdal's name for the AS case;
    /// its defaults and its meaning are the same as the TGS one's.
    svc_use_strongest_session_key: bool,
    /// `preauth-use-strongest-session-key`: the same for the enctype a client is asked to
    /// pre-authenticate with (`ETYPE-INFO2`). Separate from the two above because a realm may
    /// want strong pre-authentication keys long before it is willing to change what every
    /// service's tickets are sealed with.
    preauth_use_strongest_session_key: bool,
    /// `use-strongest-server-key`: seal a ticket in the strongest key the *service* has, by this
    /// KDC's preference, rather than in the first of the service's keys in storage order.
    ///
    /// Heimdal's default is **on**, which is why this one reads the other way round from the
    /// three session-key options above: with it on, the KDC ignores the entry's key order and
    /// walks its own list. Turning it off is for an entry whose key order was chosen on purpose.
    use_strongest_server_key: bool,
    /// `strict-nametypes`: refuse a `krbtgt` name whose name type is neither `NT-SRV-INST` nor
    /// `NT-UNKNOWN`.
    ///
    /// Heimdal's rule (`kdc/misc.c:name_type_ok`) and nothing wider: names that are not `krbtgt`
    /// are unaffected, and `NT-ENTERPRISE` is handled where enterprise names are resolved, not
    /// here. What it protects is the cross-realm lookup: a `krbtgt/REALM@REALM` sent as
    /// `NT-PRINCIPAL` is a different name in Heimdal's database, and a KDC that ignored the type
    /// would answer for a ticket-granting ticket nobody asked for. Heimdal's default is
    /// **off** — the parenthetical in the task list that called it `true` was wrong.
    strict_nametypes: bool,
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
            // Off by default: an anonymous ticket is an opening into the realm, and an
            // opening nobody configured is a surprise rather than a convenience.
            anonymous_pkinit: false,
            allowed_enctypes: Enctype::ALL.to_vec(),
            addresses: crate::address::AddressPolicy::default(),
            transited_policy: TransitedPolicy::AlwaysCheck,
            transited_realms: None,
            // Every default below is Heimdal's (`kdc/default_config.c`). The three session-key
            // options are off and `use_strongest_server_key` is on: the KDC's own order decides
            // which key seals a ticket, and the client's order decides the session key.
            require_pac: false,
            disable_pac: false,
            tgt_use_strongest_session_key: false,
            svc_use_strongest_session_key: false,
            preauth_use_strongest_session_key: false,
            use_strongest_server_key: true,
            strict_nametypes: false,
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

    /// Whether anonymous PKINIT is offered (RFC 8062).
    pub fn anonymous_pkinit(&self) -> bool {
        self.anonymous_pkinit
    }

    /// Enables or disables anonymous PKINIT.
    pub fn with_anonymous_pkinit(mut self, yes: bool) -> Self {
        self.anonymous_pkinit = yes;
        self
    }

    /// `allowed_enctypes`, strongest first.
    pub fn allowed_enctypes(&self) -> &[Enctype] {
        &self.allowed_enctypes
    }

    /// The address policy, as `crate::address::check` wants it.
    pub fn address_policy(&self) -> crate::address::AddressPolicy {
        self.addresses
    }

    /// Sets `check-ticket-addresses`.
    pub fn with_check_ticket_addresses(mut self, yes: bool) -> Self {
        self.addresses.check = yes;
        self
    }

    /// Sets `allow-null-ticket-addresses`.
    pub fn with_allow_null_ticket_addresses(mut self, yes: bool) -> Self {
        self.addresses.allow_null = yes;
        self
    }

    /// Sets `warn-ticket-addresses`.
    pub fn with_warn_ticket_addresses(mut self, yes: bool) -> Self {
        self.addresses.warn = yes;
        self
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

    /// `transited-policy`.
    pub fn transited_policy(&self) -> TransitedPolicy {
        self.transited_policy
    }

    /// Sets `transited-policy`.
    pub fn with_transited_policy(mut self, policy: TransitedPolicy) -> Self {
        self.transited_policy = policy;
        self
    }

    /// `require-pac`: is a TGT without a PAC revoked?
    pub fn require_pac(&self) -> bool {
        self.require_pac
    }

    /// `disable-pac`: does this realm issue PACs at all?
    pub fn disable_pac(&self) -> bool {
        self.disable_pac
    }

    /// Whether the TGS session key's enctype follows this KDC's preference rather than the
    /// client's.
    pub fn tgt_use_strongest_session_key(&self) -> bool {
        self.tgt_use_strongest_session_key
    }

    /// The same for the session key granted in an AS exchange.
    pub fn svc_use_strongest_session_key(&self) -> bool {
        self.svc_use_strongest_session_key
    }

    /// The same for the enctype a client is asked to pre-authenticate with.
    pub fn preauth_use_strongest_session_key(&self) -> bool {
        self.preauth_use_strongest_session_key
    }

    /// Whether a ticket is sealed in the strongest key the service has, by this KDC's
    /// preference, rather than in the first of the service's keys.
    pub fn use_strongest_server_key(&self) -> bool {
        self.use_strongest_server_key
    }

    /// `strict-nametypes`.
    pub fn strict_nametypes(&self) -> bool {
        self.strict_nametypes
    }

    /// The realms this KDC accepts as transit realms, when an operator listed them. `None`
    /// means the DNS hierarchy between the endpoints decides.
    pub fn transited_realms(&self) -> Option<&[String]> {
        self.transited_realms.as_deref()
    }

    /// Sets the accepted transit realms. An empty list is refused: it reads as "none", but a
    /// KDC whose every cross-realm request fails with `PATH_NOT_ACCEPTED` is a deployment that
    /// will be debugged for an hour, and the honest spelling of "none" is a one-element list
    /// that names a realm nobody uses, if that is really wanted.
    pub fn with_transited_realms(mut self, realms: Vec<String>) -> Result<Self> {
        if realms.is_empty() {
            return Err(Error::Config(
                "transited-realms names no realm; remove the option to let the DNS hierarchy \
                 decide instead of listing nothing"
                    .into(),
            ));
        }
        self.transited_realms = Some(realms);
        Ok(self)
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
            "check-ticket-addresses" | "check_ticket_addresses" => {
                self.addresses.check = parse_bool(value)?;
                Ok(())
            }
            "allow-null-ticket-addresses" | "allow_null_ticket_addresses" => {
                self.addresses.allow_null = parse_bool(value)?;
                Ok(())
            }
            "warn-ticket-addresses" | "warn_ticket_addresses" => {
                self.addresses.warn = parse_bool(value)?;
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
            "transited-policy" | "transited_policy" => {
                self.transited_policy = match value.trim().to_ascii_lowercase().as_str() {
                    "always-check" => TransitedPolicy::AlwaysCheck,
                    // Heimdal's per-principal hooks are compiled out, so this is `always-check`
                    // there too; accepting the name keeps a Heimdal configuration readable.
                    "allow-per-principal" => TransitedPolicy::AllowPerPrincipal,
                    "always-honour-request" => TransitedPolicy::AlwaysHonourRequest,
                    other => {
                        return Err(Error::Config(format!(
                            "option {name}: {other:?} is not a transited policy; \
                             expected always-check, allow-per-principal or always-honour-request"
                        )));
                    }
                };
                Ok(())
            }
            "transited-realms" | "transited_realms" => {
                let realms: Vec<String> = value
                    .split(|c: char| c == ',' || c.is_whitespace())
                    .filter(|s| !s.is_empty())
                    .map(str::to_owned)
                    .collect();
                if realms.is_empty() {
                    return Err(Error::Config(format!(
                        "option {name} names no realm; remove it to let the DNS hierarchy decide"
                    )));
                }
                self.transited_realms = Some(realms);
                Ok(())
            }
            "require_pac" | "require-pac" => {
                self.require_pac = parse_bool(value)?;
                Ok(())
            }
            "disable_pac" | "disable-pac" => {
                self.disable_pac = parse_bool(value)?;
                Ok(())
            }
            "tgt-use-strongest-session-key" | "tgt_use_strongest_session_key" => {
                self.tgt_use_strongest_session_key = parse_bool(value)?;
                Ok(())
            }
            "svc-use-strongest-session-key" | "svc_use_strongest_session_key" => {
                self.svc_use_strongest_session_key = parse_bool(value)?;
                Ok(())
            }
            "preauth-use-strongest-session-key" | "preauth_use_strongest_session_key" => {
                self.preauth_use_strongest_session_key = parse_bool(value)?;
                Ok(())
            }
            "use-strongest-server-key" | "use_strongest_server_key" => {
                self.use_strongest_server_key = parse_bool(value)?;
                Ok(())
            }
            "strict-nametypes" | "strict_nametypes" => {
                self.strict_nametypes = parse_bool(value)?;
                Ok(())
            }
            other => Err(Error::Config(format!(
                "KDC option {other:?} is not implemented by this engine. \
                 Implemented: max_life, max_renewable_life, clockskew, require-preauth, \
                 allowed_enctypes, check-ticket-addresses, allow-null-ticket-addresses, \
                 warn-ticket-addresses, transited-policy, transited-realms, require-pac, \
                 disable-pac, tgt-use-strongest-session-key, svc-use-strongest-session-key, \
                 preauth-use-strongest-session-key, use-strongest-server-key, strict-nametypes. \
                 Refusing rather than \
                 ignoring it: a KDC that silently \
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
        // `max-kdc-datagram-reply-length` is Heimdal's and is not implemented here yet, which is
        // what this test is for: the refusal has to name the option, not just happen.
        let err = c
            .apply("max-kdc-datagram-reply-length", "1400")
            .unwrap_err()
            .to_string();
        assert!(err.contains("max-kdc-datagram-reply-length"), "{err}");
        assert!(err.contains("not implemented"), "{err}");
        assert!(c.apply("enable-pkinit", "true").is_err());
        assert!(c.apply("enable_fast", "true").is_err());
    }

    /// Every option this engine understands, with its default and its non-default, so that a name
    /// accepted by `apply` but wired to nothing is visible: the value has to change.
    #[test]
    fn every_accepted_option_changes_the_configuration() {
        let mut c = KdcConfig::new("R").unwrap();
        for (option, default, flipped, getter) in [
            (
                "require_pac",
                false,
                true,
                KdcConfig::require_pac as fn(&KdcConfig) -> bool,
            ),
            ("disable-pac", false, true, KdcConfig::disable_pac),
            (
                "tgt-use-strongest-session-key",
                false,
                true,
                KdcConfig::tgt_use_strongest_session_key,
            ),
            (
                "svc-use-strongest-session-key",
                false,
                true,
                KdcConfig::svc_use_strongest_session_key,
            ),
            (
                "preauth-use-strongest-session-key",
                false,
                true,
                KdcConfig::preauth_use_strongest_session_key,
            ),
            // The one whose default is the other way round: Heimdal seals a ticket with its own
            // preference unless told not to.
            (
                "use-strongest-server-key",
                true,
                false,
                KdcConfig::use_strongest_server_key,
            ),
            ("strict-nametypes", false, true, KdcConfig::strict_nametypes),
        ] {
            assert_eq!(getter(&c), default, "{option}: default is Heimdal's");
            c.apply(option, if flipped { "true" } else { "false" })
                .unwrap_or_else(|e| panic!("{option}: {e}"));
            assert_eq!(
                getter(&c),
                flipped,
                "{option}: the option has to do something"
            );
            c.apply(option, if flipped { "false" } else { "true" })
                .unwrap();
            assert_eq!(getter(&c), default, "{option}: and to be reversible");
        }
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
