//! The three `kdc-plugin.c` hooks, through the engine.
//!
//! Each hook is checked twice: that it does what it says when installed, and that **the realm is
//! unchanged when it is not**. The second half is not ceremony — a seam that alters behaviour by
//! existing is a seam an operator cannot adopt gradually, and the only way to know is to compare
//! what a realm without hooks produces with what it produced before.

mod common;

use std::sync::{Arc, Mutex};

use common::{Knobs, NOW, REALM, alice, realm, service, tgs_req, tgt};
use rrl_kdc::crypto::{Cipher, Enctype, OwnCipher, usage};
use rrl_kdc::der;
use rrl_kdc::error::codes;
use rrl_kdc::hdb::{HdbEntry, MemoryHdb};
use rrl_kdc::kdc::hooks::{AccessPolicy, FinalizeReply, Hooks, ReferralPolicy, TicketRequest};
use rrl_kdc::kdc::{Kdc, KdcConfig};
use rrl_kdc::msg::{
    self, EncryptedData, PA_ENC_TIMESTAMP, encode_enc_ts_enc, encode_pa_data, kdc_options,
};
use rrl_kdc::name::Principal;

const PASSWORD: &str = "pw";

/// A realm built by `common`, plus a service other than its own — so one file can ask for a name
/// that exists and one that does not.
fn db() -> MemoryHdb {
    let (db, _) = realm();
    let mut extra = HdbEntry::service(Principal::parse(&format!("cifs/files@{REALM}")).unwrap());
    extra
        .add_password_key(&OwnCipher, Enctype::Aes256Sha1, b"svc", 1)
        .unwrap();
    db.insert(extra).unwrap();
    db
}

fn kdc(hooks: Hooks) -> Kdc {
    Kdc::new(
        KdcConfig::new(REALM).unwrap(),
        Arc::new(db()),
        Arc::new(OwnCipher),
    )
    .with_hooks(hooks)
}

/// An `AS-REQ` for `alice` with a valid encrypted timestamp.
fn as_req() -> Vec<u8> {
    let body = der::seq(&[
        der::field(0, der::flags32(kdc_options::FORWARDABLE)),
        der::field(1, alice().encode_name()),
        der::field(2, der::general_string(REALM)),
        der::field(3, Principal::krbtgt(REALM).encode_name()),
        der::field(5, der::time(NOW + 3600)),
        der::field(7, der::int(0x1234_5678)),
        der::field(8, der::seq(&[der::int(18)])),
    ]);
    let key = OwnCipher
        .s2k(
            Enctype::Aes256Sha1,
            PASSWORD.as_bytes(),
            format!("{REALM}alice").as_bytes(),
            None,
        )
        .unwrap();
    let plain = encode_enc_ts_enc(NOW, None);
    let sealed = EncryptedData::seal(&OwnCipher, &key, usage::AS_REQ_PA_ENC_TS, None, &plain)
        .unwrap()
        .encode();
    let parts = vec![
        der::field(1, der::int(5)),
        der::field(2, der::int(10)),
        der::field(3, encode_pa_data(&[(PA_ENC_TIMESTAMP, sealed)])),
        der::field(4, body),
    ];
    der::cons(der::app(10), &[der::seq(&parts)])
}

/// A `TGS-REQ` for `target`, built by `common` from a TGT sealed with the realm's `krbtgt` key.
fn request_for(target: Principal) -> Vec<u8> {
    let (_, krbtgt_key) = realm();
    let tgt = tgt(
        &krbtgt_key,
        &alice(),
        NOW + 3600,
        None,
        msg::tkt_flags::FORWARDABLE,
    );
    tgs_req(
        &tgt,
        Knobs {
            authenticator_ctime: NOW,
            target: Some(target),
            ..Default::default()
        },
    )
}

fn files() -> Principal {
    Principal::parse(&format!("cifs/files@{REALM}")).unwrap()
}

/// A `cifs/` name this realm does **not** hold: `files` is in the database, and a referral policy is
/// only consulted about a name the lookup failed on.
fn absent() -> Principal {
    Principal::parse(&format!("cifs/absent@{REALM}")).unwrap()
}

/// The code a reply refuses with, or `None` when it issued a ticket.
fn outcome(reply: &[u8]) -> Option<i32> {
    msg::KrbError::decode(reply).ok().map(|e| e.code)
}

/// With no hooks installed, a login and a service ticket are exactly what they were.
#[test]
fn without_hooks_nothing_changes() {
    let kdc = kdc(Hooks::new());
    let reply = kdc.handle_from(&as_req(), NOW, None);
    assert_eq!(outcome(&reply), None, "the TGT was issued");
    assert!(
        msg::KrbError::decode(&reply).is_err(),
        "and the reply is an AS-REP, not an error"
    );

    // The same realm's own service, through the path the access hook sits on.
    assert_eq!(
        outcome(&kdc.handle_from(&request_for(service()), NOW, None)),
        None,
        "the service ticket was issued"
    );
    // A service the realm does not hold, decided by the built-in path: without a referral policy
    // this is the refusal it always was.
    assert_eq!(
        outcome(&kdc.handle_from(&request_for(absent()), NOW, None)),
        Some(codes::KDC_ERR_S_PRINCIPAL_UNKNOWN),
        "no hook, no referral: the refusal stands"
    );
}

/// An access policy that refuses one service stops that ticket and nothing else.
#[test]
fn an_access_policy_refuses_one_service() {
    #[derive(Debug)]
    struct NoCifs;
    impl AccessPolicy for NoCifs {
        fn allows(&self, request: &TicketRequest) -> bool {
            !request.service.name().starts_with("cifs/")
        }
    }

    let kdc = kdc(Hooks::new().with_access(Arc::new(NoCifs)));
    assert_eq!(
        outcome(&kdc.handle_from(&request_for(files()), NOW, None)),
        Some(codes::KDC_ERR_POLICY),
        "a cifs ticket is refused with POLICY"
    );
    // The same realm still issues its own service and the TGT, so the refusal is about the service.
    assert_eq!(
        outcome(&kdc.handle_from(&request_for(service()), NOW, None)),
        None
    );
    assert_eq!(outcome(&kdc.handle_from(&as_req(), NOW, None)), None);
}

/// A policy that refuses everything stops the TGT too: the check runs in the AS exchange, where
/// Heimdal's `_kdc_check_access` runs.
#[test]
fn an_access_policy_refuses_the_tgt_too() {
    #[derive(Debug)]
    struct NoOne;
    impl AccessPolicy for NoOne {
        fn allows(&self, _request: &TicketRequest) -> bool {
            false
        }
    }
    let kdc = kdc(Hooks::new().with_access(Arc::new(NoOne)));
    assert_eq!(
        outcome(&kdc.handle_from(&as_req(), NOW, None)),
        Some(codes::KDC_ERR_POLICY)
    );
}

/// A referral policy turns a missing service into a ticket toward the realm it names.
#[test]
fn a_referral_policy_answers_instead_of_the_refusal() {
    #[derive(Debug)]
    struct ToOwnRealm;
    impl ReferralPolicy for ToOwnRealm {
        fn instead_of_refusal(&self, request: &TicketRequest, code: i32) -> Option<Principal> {
            // Only for a `cifs/` name, and only when the service really was unknown. The realm it
            // names is this one, whose `krbtgt` exists — a hop a client can follow.
            (code == codes::KDC_ERR_S_PRINCIPAL_UNKNOWN
                && request.service.name().starts_with("cifs/"))
            .then(|| Principal::krbtgt(REALM))
        }
    }

    let kdc = kdc(Hooks::new().with_referral(Arc::new(ToOwnRealm)));
    assert_eq!(
        outcome(&kdc.handle_from(&request_for(absent()), NOW, None)),
        None,
        "a referral ticket instead of the refusal"
    );
    // A name the policy does not claim keeps the refusal.
    let absent = Principal::parse(&format!("host/absent@{REALM}")).unwrap();
    assert_eq!(
        outcome(&kdc.handle_from(&request_for(absent), NOW, None)),
        Some(codes::KDC_ERR_S_PRINCIPAL_UNKNOWN)
    );
}

/// A referral to a realm this KDC holds no `krbtgt` for is refused, and names the hop.
///
/// A policy is configuration. A hop nobody can follow sends the client to a KDC that does not exist,
/// and the failure surfaces far from the typo that caused it.
#[test]
fn a_referral_to_a_realm_this_kdc_cannot_issue_for_is_refused() {
    #[derive(Debug)]
    struct Nowhere;
    impl ReferralPolicy for Nowhere {
        fn instead_of_refusal(&self, _request: &TicketRequest, _code: i32) -> Option<Principal> {
            Some(Principal::krbtgt("NOWHERE.EXAMPLE"))
        }
    }
    let kdc = kdc(Hooks::new().with_referral(Arc::new(Nowhere)));
    let reply = kdc.handle_from(&request_for(absent()), NOW, None);
    assert_eq!(
        outcome(&reply),
        Some(codes::KDC_ERR_S_PRINCIPAL_UNKNOWN),
        "the referral cannot be followed, so the refusal stands"
    );
    let err = msg::KrbError::decode(&reply).expect("a KRB-ERROR");
    assert!(
        err.e_text
            .as_deref()
            .is_some_and(|t| t.contains("NOWHERE.EXAMPLE")),
        "the message names the hop it could not follow: {:?}",
        err.e_text
    );
}

/// A reply hook sees the reply and may pass it on; one that refuses turns into a `KRB-ERROR`.
#[test]
fn a_reply_hook_may_pass_through_or_refuse() {
    #[derive(Debug)]
    struct Count {
        seen: Mutex<usize>,
    }
    impl FinalizeReply for Count {
        fn finalize(
            &self,
            _request: &TicketRequest,
            reply: Vec<u8>,
        ) -> rrl_kdc::error::Result<Vec<u8>> {
            *self.seen.lock().expect("a test's lock") += 1;
            Ok(reply)
        }
    }
    let counter = Arc::new(Count {
        seen: Mutex::new(0),
    });
    let kdc = kdc(Hooks::new().with_finalize(Arc::clone(&counter) as Arc<dyn FinalizeReply>));
    assert_eq!(outcome(&kdc.handle_from(&as_req(), NOW, None)), None);
    assert_eq!(
        *counter.seen.lock().expect("a test's lock"),
        1,
        "it saw the reply"
    );

    #[derive(Debug)]
    struct Refuse;
    impl FinalizeReply for Refuse {
        fn finalize(
            &self,
            _request: &TicketRequest,
            _reply: Vec<u8>,
        ) -> rrl_kdc::error::Result<Vec<u8>> {
            Err(rrl_kdc::error::Error::Kdc {
                code: codes::KDC_ERR_POLICY,
                text: "refused at the last moment".into(),
            })
        }
    }
    let refusing = kdc_with(Hooks::new().with_finalize(Arc::new(Refuse)));
    assert_eq!(
        outcome(&refusing.handle_from(&as_req(), NOW, None)),
        Some(codes::KDC_ERR_POLICY),
        "what the client gets is the refusal"
    );
}

/// A second `Kdc` over the same realm, for the test that needs two hooks in one function.
fn kdc_with(hooks: Hooks) -> Kdc {
    Kdc::new(
        KdcConfig::new(REALM).unwrap(),
        Arc::new(db()),
        Arc::new(OwnCipher),
    )
    .with_hooks(hooks)
}

/// Hooks are told the names the KDC decided on, not the spellings the request carried.
#[test]
fn a_hook_is_told_the_name_the_kdc_decided_on() {
    #[derive(Debug)]
    struct Record {
        seen: Mutex<Vec<(String, String, &'static str)>>,
    }
    impl AccessPolicy for Record {
        fn allows(&self, request: &TicketRequest) -> bool {
            self.seen.lock().expect("a test's lock").push((
                request.client.to_string(),
                request.service.to_string(),
                request.exchange.as_str(),
            ));
            // Refuse, so nothing after the check matters to this test.
            false
        }
    }
    let hook = Arc::new(Record {
        seen: Mutex::new(Vec::new()),
    });
    let kdc = kdc_with(Hooks::new().with_access(Arc::clone(&hook) as Arc<dyn AccessPolicy>));
    let _ = kdc.handle_from(&request_for(files()), NOW, None);
    let _ = kdc.handle_from(&as_req(), NOW, None);
    let seen = hook.seen.lock().expect("a test's lock").clone();
    assert_eq!(
        seen,
        vec![
            (
                format!("alice@{REALM}"),
                format!("cifs/files@{REALM}"),
                "tgs"
            ),
            (
                format!("alice@{REALM}"),
                format!("krbtgt/{REALM}@{REALM}"),
                "as"
            ),
        ],
        "both exchanges consult it, with the client from the ticket and the service it would name"
    );
}

/// A realm whose access policy is the passthrough reports so, and the check is skipped.
#[test]
fn the_default_policy_is_recognised_as_the_passthrough() {
    assert!(!Hooks::new().has_access());
    #[derive(Debug)]
    struct Refuse;
    impl AccessPolicy for Refuse {
        fn allows(&self, _request: &TicketRequest) -> bool {
            false
        }
    }
    assert!(Hooks::new().with_access(Arc::new(Refuse)).has_access());
}
