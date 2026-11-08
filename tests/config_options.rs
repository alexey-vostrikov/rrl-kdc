//! Every option a `krb5.conf`-style `[kdc]` section may set, and every one it
//! may not.
//!
//! The rule this file enforces is the one the project was built on: **a KDC either
//! honours an option or refuses to start.** A silently ignored `max_life` is worse
//! than a crash, because the operator believes the realm has a one-hour ceiling
//! while every ticket is issued for ten, and the first evidence is a security
//! review.
//!
//! So the tests below are symmetric: one table of names that must be accepted with
//! the value taking effect, one of names that must be refused *by name*, and the
//! unit suffixes Heimdal allows.

use rust_heimdal_kdc::crypto::Enctype;
use rust_heimdal_kdc::error::Error;
use rust_heimdal_kdc::kdc::config::KdcConfig;

const REALM: &str = "EXAMPLE.COM";

fn config() -> KdcConfig {
    KdcConfig::new(REALM).unwrap()
}

/// Sets one option, the way a configuration file would.
fn set(key: &str, value: &str) -> Result<KdcConfig, Error> {
    let mut config = config();
    config.apply(key, value)?;
    Ok(config)
}

#[test]
fn every_string_key_is_accepted_in_both_spellings() {
    // Heimdal's own file uses `dashes`; its programmatic options use
    // `underscores`; a realm administered by hand has both in it. Refusing one
    // spelling of the same option would make half the documentation wrong.
    let pairs = [
        ("require-preauth", "require_preauth"),
        ("check-ticket-addresses", "check_ticket_addresses"),
        ("allow-null-ticket-addresses", "allow_null_ticket_addresses"),
        ("warn-ticket-addresses", "warn_ticket_addresses"),
    ];
    for (dashed, underscored) in pairs {
        let a = set(dashed, "false").unwrap_or_else(|e| panic!("{dashed}: {e}"));
        let b = set(underscored, "false").unwrap_or_else(|e| panic!("{underscored}: {e}"));
        assert_eq!(
            format!("{a:?}"),
            format!("{b:?}"),
            "{dashed} and {underscored} must be the same option"
        );
    }

    for key in ["max_life", "max_renewable_life"] {
        let underscored = set(key, "1h").unwrap_or_else(|e| panic!("{key}: {e}"));
        let dashed = set(&key.replace('_', "-"), "1h").unwrap();
        assert_eq!(format!("{underscored:?}"), format!("{dashed:?}"), "{key}");
    }
}

#[test]
fn a_lifetime_keeps_its_value() {
    let config = set("max_life", "10h").unwrap();
    assert_eq!(config.max_life(), 36_000);
    let config = set("max-renewable-life", "7d").unwrap();
    assert_eq!(config.max_renewable_life(), 604_800);
}

#[test]
fn every_duration_suffix_is_honoured() {
    // Kerberos configurations are written by hand in all five of these, and a
    // suffix swallowed into the number would turn 10 minutes into 10 seconds.
    for (written, seconds) in [
        ("30s", 30),
        ("30S", 30),
        ("2m", 120),
        ("2M", 120),
        ("1h", 3_600),
        ("1H", 3_600),
        ("1d", 86_400),
        ("1D", 86_400),
        ("1w", 604_800),
        ("1W", 604_800),
        // No suffix is seconds, which is what Heimdal does.
        ("90", 90),
    ] {
        let config = set("max_life", written).unwrap_or_else(|e| panic!("{written}: {e}"));
        assert_eq!(config.max_life(), seconds, "{written}");
    }
}

#[test]
fn a_boolean_takes_every_spelling_a_config_writer_uses() {
    for truthy in ["true", "yes", "1"] {
        let config = set("require-preauth", truthy).unwrap_or_else(|e| panic!("{truthy}: {e}"));
        assert!(config.require_preauth(), "{truthy}");
    }
    for falsy in ["false", "no", "0"] {
        let config = set("require-preauth", falsy).unwrap_or_else(|e| panic!("{falsy}: {e}"));
        assert!(!config.require_preauth(), "{falsy}");
    }
}

#[test]
fn a_boolean_that_is_neither_is_refused_with_the_value_in_the_message() {
    let err = set("require-preauth", "maybe").unwrap_err().to_string();
    assert!(
        err.contains("maybe"),
        "the message must quote the value: {err}"
    );
}

#[test]
fn the_address_options_are_three_different_switches() {
    // Heimdal has three, and collapsing them into one would silently change what
    // a realm does with a ticket issued for another host.
    let mut config = config();
    config.apply("check-ticket-addresses", "false").unwrap();
    config
        .apply("allow-null-ticket-addresses", "false")
        .unwrap();
    config.apply("warn-ticket-addresses", "true").unwrap();
    let policy = config.address_policy();
    assert!(
        !policy.check,
        "check-ticket-addresses=false must switch the check off"
    );
    assert!(
        !policy.allow_null,
        "a request naming no address must be refused"
    );
    assert!(policy.warn, "a mismatch must be logged rather than refused");
}

#[test]
fn clock_skew_is_a_number_of_seconds() {
    let config = set("clockskew", "300").unwrap();
    assert_eq!(config.clockskew(), 300);
}

#[test]
fn the_enctype_list_is_parsed_by_name_and_by_number() {
    let config = set("allowed_enctypes", "aes256-cts-hmac-sha1-96 aes128-sha2").unwrap();
    assert_eq!(
        config.allowed_enctypes(),
        &[Enctype::Aes256Sha1, Enctype::Aes128Sha256]
    );

    let config = set("allowed-enctypes", "18 20").unwrap();
    assert_eq!(
        config.allowed_enctypes(),
        &[Enctype::Aes256Sha1, Enctype::Aes256Sha384]
    );

    // An enctype this KDC does not implement is refused at startup, not ignored:
    // a realm that quietly drops aes256 for rc4 is a realm that issues rc4.
    let err = set("allowed-enctypes", "rc4-hmac").unwrap_err().to_string();
    assert!(err.contains("rc4"), "{err}");
}

#[test]
fn an_unknown_option_is_refused_by_name() {
    // The whole point of the project's fail-fast rule: the operator must be told
    // *which* word was not understood, not that the file is invalid.
    let err = set("verbose_logging", "true").unwrap_err();
    assert!(matches!(err, Error::Config(_)));
    let message = err.to_string();
    assert!(
        message.contains("verbose_logging"),
        "the message must name the option it did not understand: {message}"
    );
}

#[test]
fn a_misspelling_of_a_real_option_is_refused_and_not_guessed() {
    // `max_lif` must not be silently read as `max_life`: guessing is how an
    // operator's ceiling disappears.
    for typo in ["max_lif", "max_live", "clock_skew", "require_preauth2"] {
        assert!(
            set(typo, "1h").is_err(),
            "{typo} was accepted, and the realm now has an option the operator did not set"
        );
    }
}

#[test]
fn every_option_is_reachable_through_a_name_that_is_documented() {
    // A name accepted only by the parser and never mentioned anywhere is an
    // option nobody will use; this table is the list the README has to match.
    let documented = [
        "max_life",
        "max_renewable_life",
        "clockskew",
        "require-preauth",
        "check-ticket-addresses",
        "allow-null-ticket-addresses",
        "warn-ticket-addresses",
        "allowed_enctypes",
    ];
    for key in documented {
        let value = if key == "allowed_enctypes" {
            "aes256-cts-hmac-sha1-96"
        } else if key.contains("address") || key.contains("preauth") {
            "true"
        } else if key == "clockskew" {
            "300"
        } else {
            "1h"
        };
        set(key, value).unwrap_or_else(|e| panic!("{key} is documented but refused: {e}"));
    }
}

#[test]
fn a_realm_name_is_required_and_a_bad_one_is_refused() {
    assert!(
        KdcConfig::new("").is_err(),
        "a KDC without a realm has no tickets to issue"
    );
    assert!(KdcConfig::new(REALM).is_ok());
    let config = KdcConfig::new(REALM).unwrap();
    assert_eq!(config.realm(), REALM);
}

#[test]
fn a_value_that_is_not_a_number_is_refused() {
    let err = set("clockskew", "five minutes").unwrap_err().to_string();
    assert!(err.contains("clockskew") || err.contains("five"), "{err}");
}
