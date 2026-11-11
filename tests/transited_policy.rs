//! The transited path: what this KDC accepts, what it refuses, and what it says about it.
//!
//! RFC 4120 §2.7: "The application server is ultimately responsible for accepting or rejecting
//! authentication and SHOULD check the transited field. The application server may choose to rely
//! on the KDC for the application server's realm to check the transited field. The application
//! server's KDC will set the TRANSITED-POLICY-CHECKED flag in this case." So the flag is the whole
//! observable outcome of the check, and these tests pin both halves: the refusal when the path is
//! not acceptable, and the flag when it is.
//!
//! Every case here presents a TGT this KDC itself sealed — the point is the `transited` field, not
//! the ticket, and a forged field is what a hostile or simply misconfigured neighbour KDC puts on
//! the wire.

mod common;

use std::sync::Arc;

use common::{Knobs, REALM, Tgt, alice, code_of, read_reply, realm, service, tgs_req};
use rrl_kdc::crypto::{Cipher, Enctype, OwnCipher, usage};
use rrl_kdc::hdb::MemoryHdb;
use rrl_kdc::kdc::TransitedPolicy;
use rrl_kdc::kdc::{Kdc, KdcConfig};
use rrl_kdc::msg::{self, EncTicketPart, EncryptedData, Ticket, kdc_options, tkt_flags};
use rrl_kdc::name::Principal;

/// A TGT whose `transited` field says what the test wants it to say.
fn tgt_carrying(krbtgt_key: &rrl_kdc::crypto::Key, transited_type: i32, transited: &[u8]) -> Tgt {
    let cipher = OwnCipher;
    let session_key = cipher.random(Enctype::Aes256Sha1).unwrap();
    let part = EncTicketPart {
        flags: tkt_flags::FORWARDABLE | tkt_flags::PRE_AUTHENT,
        session_key: session_key.clone(),
        crealm: REALM.into(),
        cname: alice(),
        transited_type,
        transited: transited.to_vec(),
        authtime: common::NOW - 60,
        starttime: None,
        endtime: common::NOW + 3600,
        renew_till: None,
        caddr: None,
        authorization_data: None,
    };
    let ticket = Ticket {
        realm: REALM.into(),
        sname: Principal::krbtgt(REALM),
        enc: EncryptedData::seal(
            &cipher,
            krbtgt_key,
            usage::KDC_REP_TICKET,
            Some(1),
            &part.encode(),
        )
        .unwrap(),
    };
    Tgt {
        ticket: ticket.encode(),
        session_key,
    }
}

fn kdc_with(config: KdcConfig, db: MemoryHdb) -> Kdc {
    Kdc::new(config, Arc::new(db), Arc::new(OwnCipher))
}

/// The forged path: a realm that no hierarchy between this KDC's own realms contains. The client
/// and the server are both `EXAMPLE.COM`, so the only admissible path is the empty one — a ticket
/// that claims a realm travelled is claiming a route that does not exist.
const FORGED: &[u8] = b"FOREIGN.REALM";

#[test]
fn a_path_this_realm_does_not_accept_is_refused_by_name() {
    let (db, key) = realm();
    let kdc = kdc_with(KdcConfig::new(REALM).unwrap(), db);
    let tgt = tgt_carrying(&key, 1, FORGED);

    let reply = kdc.handle(&tgs_req(&tgt, Knobs::default()), common::NOW);
    let err = msg::KrbError::decode(&reply).expect("a refusal is a KRB-ERROR");
    assert_eq!(
        err.code,
        rrl_kdc::error::codes::KDC_ERR_PATH_NOT_ACCEPTED,
        "the path is the reason for the refusal, and the code says which policy"
    );
    let text = err.e_text.unwrap_or_default();
    assert!(
        text.contains("FOREIGN.REALM") && text.contains("FOREIGN.REALM,"),
        "the refusal must name the realm and show the whole path: {text}"
    );
}

#[test]
fn a_listed_transit_realm_is_accepted_and_the_ticket_says_so() {
    // The same path, and the operator says the realm is trusted. The ticket must then carry
    // TRANSITED-POLICY-CHECKED, which is what lets a service skip its own check (RFC 4120 §2.7).
    let (db, key) = realm();
    let config = KdcConfig::new(REALM)
        .unwrap()
        .with_transited_realms(vec!["FOREIGN.REALM".to_owned()])
        .unwrap();
    let kdc = kdc_with(config, db);
    let tgt = tgt_carrying(&key, 1, FORGED);

    let reply = kdc.handle(&tgs_req(&tgt, Knobs::default()), common::NOW);
    let part = read_reply(&reply, &tgt.session_key, usage::TGS_REP_ENCPART_SESSKEY);
    assert_eq!(part.sname, service());
    assert!(
        part.flags & tkt_flags::TRANSITED_POLICY_CHECKED != 0,
        "the path was checked and accepted, and the flag is how the service learns that"
    );
}

#[test]
fn an_empty_path_is_checked_and_flagged_too() {
    // A single-realm ticket has nothing to check, but the flag is not about what was found: it is
    // about who is responsible for the path. Heimdal sets it for every checked exchange.
    let (db, key) = realm();
    let kdc = kdc_with(KdcConfig::new(REALM).unwrap(), db);
    let tgt = tgt_carrying(&key, 0, b"");

    let reply = kdc.handle(&tgs_req(&tgt, Knobs::default()), common::NOW);
    let part = read_reply(&reply, &tgt.session_key, usage::TGS_REP_ENCPART_SESSKEY);
    assert!(part.flags & tkt_flags::TRANSITED_POLICY_CHECKED != 0);
}

#[test]
fn an_unknown_transited_type_is_refused_with_its_own_code() {
    // RFC 4120 defines DOMAIN-X500-COMPRESS and nothing else; type 0 is Microsoft's empty field.
    // A type this KDC cannot read must be named, not parsed as if it were the one it knows.
    let (db, key) = realm();
    let kdc = kdc_with(KdcConfig::new(REALM).unwrap(), db);
    let tgt = tgt_carrying(&key, 2, b"whatever");

    let reply = kdc.handle(&tgs_req(&tgt, Knobs::default()), common::NOW);
    assert_eq!(
        code_of(&reply),
        rrl_kdc::error::codes::KDC_ERR_TRTYPE_NOSUPP
    );
}

#[test]
fn a_global_policy_outranks_the_clients_request_to_skip_the_check() {
    // RFC 4120 §5.4.1 says KDCs are "encouraged but not required" to honour
    // disable-transited-check, and Heimdal's always-check is the default. A client cannot turn the
    // check off by setting a bit; the forged path is still caught.
    let (db, key) = realm();
    let kdc = kdc_with(KdcConfig::new(REALM).unwrap(), db);
    let tgt = tgt_carrying(&key, 1, FORGED);

    let knobs = Knobs {
        options: kdc_options::FORWARDABLE | kdc_options::DISABLE_TRANSITED_CHECK,
        ..Knobs::default()
    };
    let reply = kdc.handle(&tgs_req(&tgt, knobs), common::NOW);
    assert_eq!(
        code_of(&reply),
        rrl_kdc::error::codes::KDC_ERR_PATH_NOT_ACCEPTED
    );
}

#[test]
fn honouring_the_request_issues_a_ticket_without_the_flag() {
    // The other policy: the client asked not to have the path checked and the realm honours it.
    // The exchange must still succeed — refusing would let a client break its own logon by setting
    // a bit — and the ticket must say the check did not happen.
    let (db, key) = realm();
    let config = KdcConfig::new(REALM)
        .unwrap()
        .with_transited_policy(TransitedPolicy::AlwaysHonourRequest);
    let kdc = kdc_with(config, db);
    let tgt = tgt_carrying(&key, 1, FORGED);

    let knobs = Knobs {
        options: kdc_options::FORWARDABLE | kdc_options::DISABLE_TRANSITED_CHECK,
        ..Knobs::default()
    };
    let reply = kdc.handle(&tgs_req(&tgt, knobs), common::NOW);
    let part = read_reply(&reply, &tgt.session_key, usage::TGS_REP_ENCPART_SESSKEY);
    assert!(
        part.flags & tkt_flags::TRANSITED_POLICY_CHECKED == 0,
        "nobody checked this path, and the ticket must not claim otherwise"
    );
}

#[test]
fn the_policy_names_are_heimdals() {
    // A configuration written for Heimdal has to load here, and a name that is not a policy has to
    // fail loudly instead of quietly meaning always-check.
    let mut c = KdcConfig::new(REALM).unwrap();
    for (name, want) in [
        ("always-check", TransitedPolicy::AlwaysCheck),
        ("allow-per-principal", TransitedPolicy::AllowPerPrincipal),
        (
            "always-honour-request",
            TransitedPolicy::AlwaysHonourRequest,
        ),
    ] {
        c.apply("transited-policy", name).unwrap();
        assert_eq!(c.transited_policy(), want, "{name}");
    }
    let err = c
        .apply("transited-policy", "sometimes")
        .unwrap_err()
        .to_string();
    assert!(err.contains("not a transited policy"), "{err}");
    // And the list: an empty value is a mistake, not "accept nothing".
    let err = c.apply("transited-realms", " , ").unwrap_err().to_string();
    assert!(err.contains("names no realm"), "{err}");
    assert!(
        c.apply("transited-realms", "A.REALM, B.REALM").is_ok(),
        "a list is comma or space separated"
    );
}
