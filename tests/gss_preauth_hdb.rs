//! The concrete GSS acceptor, exercised by a real GSS-API handshake against a live KDC.
//!
//! Nothing here is hand-assembled: the realm is served on loopback, the client is `rrl-krb5`'s
//! `KdcClient` logging in as `alice`, the token is `rrl-krb5`'s initiator wrapping the TGT it just
//! received, and the acceptor is asked whether the result authenticates the principal the request
//! names. That is the whole chain a real deployment would walk, minus the network hop to a remote
//! host.
//!
//! Five properties are pinned, and each is one a plausible implementation could get wrong:
//!
//! * a token in the right envelope authenticates its own principal, and the reply key is the
//!   ticket's session key — not something derived from a long-term key the client never sent;
//! * a token that proves one principal does not authenticate a request for another;
//! * a token bound to nothing is refused, because it answers no particular request;
//! * a token bound to a *different* request body is refused;
//! * a realm with no `krbtgt` key says so instead of reporting a bad token.

#![cfg(feature = "gss-preauth")]

use std::sync::Arc;

use rrl_kdc::crypto::{Cipher, Enctype, OwnCipher};
use rrl_kdc::hdb::{Hdb, HdbEntry, MemoryHdb};
use rrl_kdc::kdc::gss_hdb::HdbGssAcceptor;
use rrl_kdc::kdc::gss_preauth::{GssAcceptor, GssError, GssPreauth, encode_pa_gss};
use rrl_kdc::kdc::preauth::{Mechanism, Request, Step};
use rrl_kdc::kdc::{Kdc, KdcConfig};
use rrl_kdc::name::Principal;
use rrl_kdc::transport::serve_loopback;

const REALM: &str = "EXAMPLE.COM";
const PASSWORD: &str = "correct horse battery staple";
/// The `KDC-REQ-BODY` the exchange is bound to. A real client binds the body it is about to send;
/// here it is a constant because the acceptor only ever compares octets.
const BODY: &[u8] = b"the KDC-REQ-BODY";

fn principal(name: &str) -> Principal {
    Principal::parse(&format!("{name}@{REALM}")).unwrap()
}

/// A realm with a `krbtgt` and one user, served on loopback.
fn realm() -> (rrl_kdc::transport::RunningKdc, Arc<MemoryHdb>) {
    let cipher = OwnCipher;
    let db = Arc::new(MemoryHdb::new());

    let mut krbtgt = HdbEntry::krbtgt(REALM);
    krbtgt.add_key(cipher.random(Enctype::Aes256Sha1).unwrap(), 1, None);
    db.insert(krbtgt).unwrap();

    let mut user = HdbEntry::user(principal("alice"));
    user.flags |= rrl_kdc::hdb::flags::REQUIRE_PREAUTH;
    user.add_password_key(&cipher, Enctype::Aes256Sha1, PASSWORD.as_bytes(), 1)
        .unwrap();
    db.insert(user).unwrap();

    let kdc = Kdc::new(
        KdcConfig::new(REALM).unwrap().with_require_preauth(true),
        Arc::clone(&db) as Arc<dyn Hdb>,
        Arc::new(OwnCipher),
    );
    (serve_loopback(kdc), db)
}

/// A TGT for `alice`, obtained over the wire from the realm above.
fn alice_tgt(stand: &rrl_kdc::transport::RunningKdc) -> rrl_krb5::Credentials {
    let client = rrl_krb5::KdcClient::new(REALM, [stand.addr().as_str()]);
    client
        .login_with_password(
            &rrl_krb5::Principal::parse(&format!("alice@{REALM}")).unwrap(),
            PASSWORD,
        )
        .expect("alice logs in and gets a TGT")
}

/// The GSS initiator token for `creds`, bound to `bindings` (`None` sends no bindings at all).
fn token(creds: &rrl_krb5::Credentials, bindings: Option<&[u8]>) -> Vec<u8> {
    let bound = bindings.map(rrl_krb5::ChannelBindings::new);
    let flags = rrl_krb5::initiator::GSS_C_MUTUAL_FLAG
        | if bindings.is_some() {
            rrl_krb5::initiator::GSS_C_CHANNEL_BOUND_FLAG
        } else {
            0
        };
    let mut options = rrl_krb5::initiator::InitOptions::default();
    options.channel_bindings = bound.as_ref();
    rrl_krb5::InitiatorContext::with_options(creds, flags, options)
        .expect("the initiator builds a token")
        .1
}

/// A pre-authentication request as the mechanism sees it: `cname` asking for a TGT.
fn request<'a>(cname: &'a Principal, body: &'a [u8]) -> Request<'a> {
    Request {
        cname,
        realm: REALM,
        body,
        longterm: &[],
        armor: None,
        now: 0,
        cipher: &OwnCipher,
    }
}

fn acceptor(db: &Arc<MemoryHdb>) -> GssPreauth {
    GssPreauth::new(
        Arc::new(HdbGssAcceptor::new(Arc::clone(db) as Arc<dyn Hdb>, REALM).unwrap()),
        Vec::new(),
        false,
        REALM,
    )
}

/// The whole point: a real GSS handshake against a real TGT authenticates, and the reply key is the
/// ticket's session key.
#[test]
fn a_real_gss_handshake_authenticates_the_client_its_ticket_names() {
    let (stand, db) = realm();
    let tgt = alice_tgt(&stand);

    let mechanism = acceptor(&db);
    let padata = encode_pa_gss(None, &token(&tgt, Some(BODY)));
    let step = mechanism
        .round(&request(&principal("alice"), BODY), &[], &padata)
        .expect("the token is accepted");

    match step {
        Step::Done {
            reply_key, padata, ..
        } => {
            assert_eq!(
                reply_key.bytes(),
                tgt.session_key.bytes(),
                "the reply key is the ticket's session key, which the client already holds"
            );
            // The AP-REP: an empty token unless the initiator asked for mutual authentication,
            // and this one did.
            assert!(
                padata.expect("a reply token").len() > 2,
                "mutual authentication means an AP-REP comes back"
            );
        }
        other => panic!("expected a completed exchange, got {other:?}"),
    }
}

/// Authentication is not impersonation: a token that proves `alice` does not authenticate a
/// request for `bob`, even though both are ordinary users of this realm.
#[test]
fn a_token_for_one_principal_does_not_authenticate_another() {
    let (stand, db) = realm();
    let tgt = alice_tgt(&stand);

    let mechanism = acceptor(&db);
    let padata = encode_pa_gss(None, &token(&tgt, Some(BODY)));
    let err = mechanism
        .round(&request(&principal("bob"), BODY), &[], &padata)
        .expect_err("a token for alice must not authenticate bob");
    let text = err.to_string();
    assert!(text.contains("alice@EXAMPLE.COM"), "{text}");
    assert!(text.contains("bob@EXAMPLE.COM"), "{text}");
}

/// A token that carries no channel binding answers no particular request, so it is refused — the
/// option exists because the underlying acceptor would otherwise take it, as MIT's does for an
/// ordinary service.
#[test]
fn a_token_bound_to_nothing_is_refused() {
    let (stand, db) = realm();
    let tgt = alice_tgt(&stand);
    let padata = encode_pa_gss(None, &token(&tgt, None));

    let err = acceptor(&db)
        .round(&request(&principal("alice"), BODY), &[], &padata)
        .expect_err("an unbound token must be refused");
    assert!(
        err.to_string().contains("gss-require-bound-request"),
        "{err}"
    );

    // And the same token is accepted when the realm has decided to take unbound ones.
    let relaxed = GssPreauth::new(
        Arc::new(
            HdbGssAcceptor::new(Arc::clone(&db) as Arc<dyn Hdb>, REALM)
                .unwrap()
                .with_require_bound_request(false),
        ),
        Vec::new(),
        false,
        REALM,
    );
    // A second token, not the same one: the acceptor records accepted authenticators, and
    // presenting the first one twice is a replay — a refusal this test is not about.
    let padata = encode_pa_gss(None, &token(&alice_tgt(&stand), None));
    let relaxed_step = relaxed.round(&request(&principal("alice"), BODY), &[], &padata);
    assert!(
        matches!(relaxed_step, Ok(Step::Done { .. })),
        "with the option off the token is accepted: {relaxed_step:?}"
    );
}

/// A token bound to a *different* request body is refused: that is the replay the binding prevents.
#[test]
fn a_token_bound_to_another_request_is_refused() {
    let (stand, db) = realm();
    let tgt = alice_tgt(&stand);

    let padata = encode_pa_gss(None, &token(&tgt, Some(b"a different body")));
    let err = acceptor(&db)
        .round(&request(&principal("alice"), BODY), &[], &padata)
        .expect_err("bindings that do not match must be refused");
    assert!(err.to_string().to_lowercase().contains("binding"), "{err}");
}

/// A realm without a `krbtgt` key says so instead of reporting a bad token: it is the realm's own
/// state, and a client cannot do anything about it.
#[test]
fn a_realm_without_a_krbtgt_key_says_so() {
    // A real realm, a real token — and an acceptor over a database that has no `krbtgt` in it,
    // which is what a realm looks like when its own entry was never created.
    let (stand, _db) = realm();
    let tgt = alice_tgt(&stand);
    let stripped = Arc::new(MemoryHdb::new());
    let mut user = HdbEntry::user(principal("alice"));
    user.add_password_key(&OwnCipher, Enctype::Aes256Sha1, PASSWORD.as_bytes(), 1)
        .unwrap();
    stripped.insert(user).unwrap();

    let acceptor = HdbGssAcceptor::new(Arc::clone(&stripped) as Arc<dyn Hdb>, REALM).unwrap();
    match acceptor.step(None, &token(&tgt, Some(BODY)), &[], BODY) {
        Err(GssError::Unavailable(text)) => assert!(text.contains("krbtgt"), "{text}"),
        other => panic!("expected an unavailable acceptor, got {other:?}"),
    }
}

/// The acceptor refuses a token framed for a mechanism it does not implement, and names it.
#[test]
fn a_token_for_another_mechanism_is_refused_by_name() {
    let (_stand, db) = realm();
    let err = acceptor(&db)
        .round(
            &request(&principal("alice"), BODY),
            &[],
            &encode_pa_gss(Some("1.3.6.1.5.2.5"), b"a spnego token"),
        )
        .expect_err("only the Kerberos mechanism is implemented");
    assert!(err.to_string().contains("1.3.6.1.5.2.5"), "{err}");
}

/// An empty `PA-GSS` value is not a token, and the acceptor says so rather than accepting nothing.
#[test]
fn an_empty_token_is_not_accepted() {
    let (_stand, db) = realm();
    let err = acceptor(&db)
        .round(&request(&principal("alice"), BODY), &[], &[])
        .expect_err("an empty value is not a token");
    assert!(err.to_string().contains("GSS"), "{err}");
}
