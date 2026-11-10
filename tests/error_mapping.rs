//! Every failure this crate can produce, classified once.
//!
//! Two things are being pinned here, and neither is "the message reads nicely":
//!
//! * **The classification is total.** Every `Error` variant has a `kind()` a
//!   transport can switch on and a `kdc_code()` a client can be told. A new
//!   variant that skips this test is a transport answering 500 because it met a
//!   string it did not recognise.
//! * **Internal failures do not leak.** `is_client_facing` decides whether an
//!   e-text travels, and a database path or an I/O message in a `KRB-ERROR` is an
//!   operator's business, not a client's — and, on a hostile network, it is a hint
//!   about the host.

use rrl_kdc::crypto::Enctype;
use rrl_kdc::der::DerError;
use rrl_kdc::error::{Error, codes};

/// One value of every variant, so the table below cannot silently miss one.
fn all_variants() -> Vec<Error> {
    vec![
        Error::Der(DerError("TGS-REQ: expected tag 0x1b, got 0x30".into())),
        Error::Krb(rrl_krb_common::Error::Protocol(
            "a shared-crate failure".into(),
        )),
        Error::UnsupportedEnctype(23),
        Error::KeyLength {
            enctype: Enctype::Aes256Sha1,
            want: 32,
            got: 16,
        },
        Error::Crypto("bad tag".into()),
        Error::NotARequest("expected [APPLICATION 10]".into()),
        Error::Protocol("pvno is not 5".into()),
        Error::UnknownPrincipal("nobody@EXAMPLE.COM".into()),
        Error::NotFound("nobody@EXAMPLE.COM".into()),
        Error::Exists("alice@EXAMPLE.COM already exists".into()),
        Error::Forbidden("guest@EXAMPLE.COM may not Delete".into()),
        Error::Preauth {
            code: codes::KDC_ERR_PREAUTH_REQUIRED,
            text: "need PA-ENC-TIMESTAMP".into(),
            method_data: vec![0x30, 0x00],
            state: Vec::new(),
        },
        Error::PreauthFailed("alice@EXAMPLE.COM".into()),
        Error::Kdc {
            code: codes::KDC_ERR_POLICY,
            text: "may not be deleted".into(),
        },
        Error::Skew {
            skew: 400,
            allowed: 300,
        },
        Error::Hdb("cannot open hdb.redb".into()),
        Error::Config("unknown option verbose".into()),
        Error::Io(std::io::Error::other("no such file")),
    ]
}

#[test]
fn every_variant_has_a_kind_a_transport_can_switch_on() {
    let seen: Vec<&str> = all_variants().iter().map(Error::kind).collect();
    for kind in &seen {
        assert!(!kind.is_empty(), "a kind must not be empty");
        assert!(
            kind.chars().all(|c| c.is_ascii_lowercase() || c == '_'),
            "{kind} is not the snake_case vocabulary a transport matches: it would be tempting \
             to match on the message instead"
        );
    }
    // The mapping is many-to-one by design, but these must stay distinct: a
    // transport answers 404 for one and 409 for the other.
    assert!(seen.contains(&"not_found"));
    assert!(seen.contains(&"already_exists"));
    assert!(seen.contains(&"forbidden"));
    assert!(seen.contains(&"bad_request"));
}

#[test]
fn a_transport_can_map_every_kind_to_a_status_without_meeting_a_surprise() {
    // The set of kinds a REST layer has to know. A new one appearing here without
    // a status is a 500 the caller will read as "the server broke".
    let known = [
        "der",
        "crypto",
        "protocol",
        "not_found",
        "already_exists",
        "forbidden",
        "preauth",
        "policy",
        "clock_skew",
        "storage",
        "bad_request",
        "io",
    ];
    for error in all_variants() {
        assert!(
            known.contains(&error.kind()),
            "{error:?} has kind {:?}, which no status mapping covers",
            error.kind()
        );
    }
}

#[test]
fn every_variant_becomes_a_protocol_code() {
    for error in all_variants() {
        let code = error.kdc_code();
        assert!(code != 0, "{error:?} must not answer KDC_ERR_NONE");
        assert!(
            (1..=60).contains(&code),
            "{error:?} answered {code}, which is not an RFC 4120 §7.5 code"
        );
    }
}

#[test]
fn a_storage_failure_tells_the_client_to_try_another_kdc() {
    // Heimdal answers SVC_UNAVAILABLE when the database cannot be read, and that
    // is the right answer: the client's credentials are fine, this KDC is not.
    for error in [
        Error::Hdb("disk full".into()),
        Error::Config("bad krb5.conf".into()),
        Error::Io(std::io::Error::other("permission denied")),
    ] {
        assert_eq!(error.kdc_code(), codes::KDC_ERR_SVC_UNAVAILABLE);
    }
}

#[test]
fn an_absent_principal_and_an_unknown_client_are_different_answers() {
    // The protocol has one code for "no such client"; an administrator asking
    // about an absent account needs a different one, or a `kadmin` listing shows
    // unknown accounts as unknown *clients*.
    assert_eq!(
        Error::UnknownPrincipal("x".into()).kdc_code(),
        codes::KDC_ERR_C_PRINCIPAL_UNKNOWN
    );
    assert_eq!(
        Error::NotFound("x".into()).kdc_code(),
        codes::KDC_ERR_S_PRINCIPAL_UNKNOWN
    );
    assert_ne!(
        Error::UnknownPrincipal("x".into()).kind(),
        Error::Exists("x".into()).kind()
    );
}

#[test]
fn internal_failures_do_not_travel_to_a_client() {
    for error in [
        Error::Hdb("cannot open /var/lib/kdc/hdb.redb".into()),
        Error::Config("unknown option".into()),
        Error::Crypto("AES key of the wrong size".into()),
        Error::Io(std::io::Error::other("no such file")),
    ] {
        assert!(
            !error.is_client_facing(),
            "{error:?} names the host's innards and must not be sent: {}",
            error
        );
    }
}

#[test]
fn protocol_failures_do_travel() {
    // The other half: suppressing every e-text would leave a client with an
    // integer and no idea which of its own assumptions was wrong.
    for error in [
        Error::Protocol("pvno is not 5".into()),
        Error::PreauthFailed("alice@EXAMPLE.COM".into()),
        Error::Skew {
            skew: 400,
            allowed: 300,
        },
        Error::Kdc {
            code: codes::KDC_ERR_POLICY,
            text: "may not be deleted".into(),
        },
    ] {
        assert!(
            error.is_client_facing(),
            "{error:?} is the client's business"
        );
    }
}

#[test]
fn the_message_names_what_was_missing() {
    // A message an operator can act on names the principal, the file or the
    // option — not only what kind of thing went wrong.
    assert!(
        Error::NotFound("alice@EXAMPLE.COM".into())
            .to_string()
            .contains("alice@EXAMPLE.COM")
    );
    assert!(
        Error::Hdb("/var/lib/kdc/hdb.redb".into())
            .to_string()
            .contains("hdb.redb")
    );
    assert!(
        Error::Config("verbose".into())
            .to_string()
            .contains("verbose")
    );
    let skew = Error::Skew {
        skew: 400,
        allowed: 300,
    }
    .to_string();
    assert!(skew.contains("400") && skew.contains("300"), "{skew}");
}

#[test]
fn a_kdc_failure_carries_its_code_in_the_message() {
    // So that a log line from a KDC can be matched against a client report
    // without the operator decoding integers.
    let text = Error::Kdc {
        code: codes::KDC_ERR_BADOPTION,
        text: "cannot renew a ticket that is not renewable".into(),
    }
    .to_string();
    assert!(text.contains("13"), "{text}");
    assert!(text.contains("not renewable"), "{text}");
}
