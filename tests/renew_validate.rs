//! Renewal and validation, which are the two TGS requests that ask for a ticket
//! for the TGT itself.
//!
//! RFC 4120 §3.3.3: a renewed ticket has a **new session key** and a later
//! expiration time, and *all other fields are left unmodified*. Heimdal's
//! `check_tgs_flags` (`kdc/krb5tgs.c`) says how it decides the rest:
//!
//! * `RENEW` needs a renewable TGT with a `renew-till`, else `KDC_ERR_BADOPTION`;
//!   the new lifetime is the old one counted from now, capped by `renew-till`;
//! * `VALIDATE` needs a TGT with the `INVALID` flag and a `starttime`, else
//!   `KDC_ERR_BADOPTION`; a `starttime` still in the future is `TKT_NYV`; the
//!   `INVALID` flag is cleared;
//! * an `INVALID` TGT presented *without* `VALIDATE` is `KRB_AP_ERR_TKT_INVALID`,
//!   which is how a postdated ticket stays unusable until it is validated.

mod common;

use common::*;
use rust_heimdal_kdc::crypto::usage;
use rust_heimdal_kdc::error::codes;
use rust_heimdal_kdc::msg::tkt_flags;

/// A renewable TGT with a `renew-till` an hour of renewals away.
fn renewable(krbtgt_key: &rust_heimdal_kdc::crypto::Key) -> Tgt {
    tgt_with(
        krbtgt_key,
        &alice(),
        NOW + 3600,
        None,
        tkt_flags::INITIAL | tkt_flags::RENEWABLE | tkt_flags::PRE_AUTHENT,
        Some(NOW + 86_400),
    )
}

#[test]
fn a_renewable_tgt_can_be_renewed() {
    let (_, krbtgt_key) = realm();
    let t = renewable(&krbtgt_key);
    let reply = kdc().handle(&tgs_req(&t, Knobs::renew()), NOW);
    let part = read_reply(&reply, &t.session_key, usage::TGS_REP_ENCPART_SESSKEY);

    assert!(
        part.endtime > NOW + 3600,
        "a renewed ticket must outlive the one it replaced: ends at {}, the old one at {}",
        part.endtime,
        NOW + 3600
    );
    assert_eq!(
        part.renew_till,
        Some(NOW + 86_400),
        "renewal must not move the renewable deadline; RFC 4120 leaves the other fields unmodified"
    );
    assert_eq!(
        part.authtime,
        NOW - 60,
        "renewal is not authentication: the authtime stays the one the client proved"
    );
    assert_ne!(
        part.session_key.bytes(),
        t.session_key.bytes(),
        "RFC 4120 §3.3.3: the renewal carries a new session key"
    );
    assert_ne!(
        part.flags & tkt_flags::RENEWABLE,
        0,
        "the renewed ticket is still renewable"
    );
}

#[test]
fn renewal_reuses_the_old_lifetime_rather_than_the_requested_one() {
    // The TGT's lifetime is one hour — measured, as Heimdal measures it, from its
    // start, or from its authtime when it has no start. Asking for seven days
    // must not give seven, or renewal would be a way to grow a ticket's lifetime
    // without re-authenticating.
    let (_, krbtgt_key) = realm();
    let t = tgt_with(
        &krbtgt_key,
        &alice(),
        NOW + 3600,
        // A start time, so the lifetime is exactly `endtime - starttime` and the
        // test does not have to reason about the authtime.
        Some(NOW),
        tkt_flags::INITIAL | tkt_flags::RENEWABLE,
        Some(NOW + 7 * 86_400),
    );
    let knobs = Knobs {
        till: Some(NOW + 7 * 86_400),
        ..Knobs::renew()
    };
    let reply = kdc().handle(&tgs_req(&t, knobs), NOW);
    let part = read_reply(&reply, &t.session_key, usage::TGS_REP_ENCPART_SESSKEY);
    assert_eq!(
        part.endtime,
        NOW + 3600,
        "the renewed ticket must keep the one-hour lifetime and ignore the seven days asked for"
    );
}

#[test]
fn renewal_measures_the_old_lifetime_from_the_authtime_when_there_is_no_start() {
    // Heimdal's other branch: no `starttime`, so the lifetime runs from
    // `authtime`. The helper's TGT authenticates a minute before it starts, so
    // a renewal at `NOW` ends at `NOW + 3660`, not `NOW + 3600`.
    let (_, krbtgt_key) = realm();
    let t = renewable(&krbtgt_key);
    let reply = kdc().handle(&tgs_req(&t, Knobs::renew()), NOW);
    let part = read_reply(&reply, &t.session_key, usage::TGS_REP_ENCPART_SESSKEY);
    assert_eq!(
        part.endtime,
        NOW + 3660,
        "the lifetime is `endtime - authtime`, which is 60 seconds more than an hour here"
    );
}

#[test]
fn renewal_does_not_go_past_the_renew_till() {
    let (_, krbtgt_key) = realm();
    // A TGT whose whole point is that it may not be renewed beyond an hour, with
    // a lifetime of two: the cap has to bite.
    let t = tgt_with(
        &krbtgt_key,
        &alice(),
        NOW + 7200,
        None,
        tkt_flags::INITIAL | tkt_flags::RENEWABLE,
        Some(NOW + 3700),
    );
    let reply = kdc().handle(&tgs_req(&t, Knobs::renew()), NOW);
    let part = read_reply(&reply, &t.session_key, usage::TGS_REP_ENCPART_SESSKEY);
    assert_eq!(
        part.endtime,
        NOW + 3700,
        "the renewed lifetime must stop at renew-till"
    );
}

#[test]
fn renewing_a_non_renewable_tgt_is_badoption() {
    let (_, krbtgt_key) = realm();
    let t = tgt(&krbtgt_key, &alice(), NOW + 3600, None, tkt_flags::INITIAL);
    assert_eq!(
        code_of(&kdc().handle(&tgs_req(&t, Knobs::renew()), NOW)),
        codes::KDC_ERR_BADOPTION
    );
}

#[test]
fn renewing_past_the_renew_till_is_refused() {
    let (_, krbtgt_key) = realm();
    // Renewable, but the deadline has passed: there is nothing left to extend.
    let t = tgt_with(
        &krbtgt_key,
        &alice(),
        NOW + 3600,
        None,
        tkt_flags::INITIAL | tkt_flags::RENEWABLE,
        Some(NOW - 10),
    );
    let code = code_of(&kdc().handle(&tgs_req(&t, Knobs::renew()), NOW));
    assert!(
        code == codes::KDC_ERR_NEVER_VALID || code == codes::KDC_ERR_BADOPTION,
        "renewing past the deadline must be refused, got {code}"
    );
}

#[test]
fn a_postdated_ticket_can_be_validated() {
    let (_, krbtgt_key) = realm();
    // Postdated: started in the past but stamped INVALID until validated.
    let t = tgt(
        &krbtgt_key,
        &alice(),
        NOW + 3600,
        Some(NOW - 60),
        tkt_flags::INITIAL | tkt_flags::POSTDATED | tkt_flags::INVALID,
    );
    let reply = kdc().handle(&tgs_req(&t, Knobs::validate()), NOW);
    let part = read_reply(&reply, &t.session_key, usage::TGS_REP_ENCPART_SESSKEY);
    assert_eq!(
        part.flags & tkt_flags::INVALID,
        0,
        "validation is exactly the clearing of the INVALID flag"
    );
}

#[test]
fn validating_a_ticket_that_is_not_invalid_is_badoption() {
    let (_, krbtgt_key) = realm();
    let t = tgt(&krbtgt_key, &alice(), NOW + 3600, None, tkt_flags::INITIAL);
    assert_eq!(
        code_of(&kdc().handle(&tgs_req(&t, Knobs::validate()), NOW)),
        codes::KDC_ERR_BADOPTION
    );
}

#[test]
fn validating_before_the_start_time_is_tkt_nyv() {
    let (_, krbtgt_key) = realm();
    let t = tgt(
        &krbtgt_key,
        &alice(),
        NOW + 7200,
        Some(NOW + 3600),
        tkt_flags::INITIAL | tkt_flags::POSTDATED | tkt_flags::INVALID,
    );
    assert_eq!(
        code_of(&kdc().handle(&tgs_req(&t, Knobs::validate()), NOW)),
        codes::KRB_AP_ERR_TKT_NYV
    );
}

#[test]
fn an_invalid_tgt_is_refused_without_validate() {
    // A postdated ticket stays unusable until it is validated: presenting it
    // for a service ticket must not work.
    let (_, krbtgt_key) = realm();
    let t = tgt(
        &krbtgt_key,
        &alice(),
        NOW + 3600,
        Some(NOW - 60),
        tkt_flags::INITIAL | tkt_flags::POSTDATED | tkt_flags::INVALID,
    );
    assert_eq!(
        code_of(&kdc().handle(&tgs_req(&t, Knobs::default()), NOW)),
        codes::KRB_AP_ERR_TKT_INVALID
    );
}

#[test]
fn renewal_keeps_the_client_the_tgt_named() {
    let (_, krbtgt_key) = realm();
    let t = renewable(&krbtgt_key);
    let reply = kdc().handle(&tgs_req(&t, Knobs::renew()), NOW);
    let f = rust_heimdal_kdc::der::Fields::parse_app("TGS-REP", 13, &reply).unwrap();
    let crealm = f.string(3, "TGS-REP").unwrap();
    let cname = rust_heimdal_kdc::name::Principal::decode_field(&f, 4, "cname", &crealm).unwrap();
    assert_eq!(cname, alice(), "a renewal is for the same client");
}
