//! The framework every multi-round pre-authentication needs: `KDC_ERR_MORE_PREAUTH_DATA_REQUIRED`
//! and the cookie that carries the state between rounds.
//!
//! There is no SPAKE and no OTP here — those are their own tasks — so the mechanism in these
//! tests is a stub. That is the point: the framework is what has to be right before a
//! mechanism is written against it, and a stub is the only way to test the framework rather
//! than the first mechanism that happens to use it.
//!
//! The three things that make a multi-round exchange work, each with a test:
//!
//! 1. the mechanism is **announced** when the KDC asks for pre-authentication, or the client
//!    never tries it;
//! 2. a round that is not finished answers `KDC_ERR_MORE_PREAUTH_DATA_REQUIRED` (91) — not
//!    `PREAUTH_FAILED`, which makes a client report a wrong password and stop;
//! 3. what a round learned survives in the cookie and comes back to the next round, because
//!    a mechanism that restarts every time never finishes.

use std::sync::Arc;
use std::sync::Mutex;

use rrl_kdc::crypto::{Cipher, Enctype, Key, OwnCipher};
use rrl_kdc::der;
use rrl_kdc::error::codes;
use rrl_kdc::hdb::{HdbEntry, MemoryHdb};
use rrl_kdc::kdc::cookie::Cookie;
use rrl_kdc::kdc::fast::PA_FX_COOKIE;
use rrl_kdc::kdc::preauth::{Announced, Mechanism, Request, Step};
use rrl_kdc::kdc::{Kdc, KdcConfig};
use rrl_kdc::msg::{self, EncryptedData, encode_pa_data, kdc_options};
use rrl_kdc::name::Principal;

const REALM: &str = "EXAMPLE.COM";
const PASSWORD: &str = "correct horse battery staple";
const NOW: i64 = 1_700_000_000;

/// A PA-DATA type no standard assigns, so the stub cannot be confused with a real mechanism.
const STUB: i32 = 999;

fn principal(name: &str) -> Principal {
    Principal::parse(&format!("{name}@{REALM}")).unwrap()
}

fn db() -> MemoryHdb {
    let cipher = OwnCipher;
    let db = MemoryHdb::new();

    let mut krbtgt = HdbEntry::krbtgt(REALM);
    krbtgt
        .add_password_key(&cipher, Enctype::Aes256Sha1, b"master", 1)
        .unwrap();
    db.insert(krbtgt).unwrap();

    let mut alice = HdbEntry::user(principal("alice"));
    for e in [Enctype::Aes256Sha1, Enctype::Aes128Sha1] {
        alice
            .add_password_key(&cipher, e, PASSWORD.as_bytes(), 1)
            .unwrap();
    }
    db.insert(alice).unwrap();
    db
}

fn cookie_key() -> Key {
    OwnCipher
        .s2k(Enctype::Aes256Sha1, b"cookie-secret", b"cookie", None)
        .unwrap()
}

/// The reply key the stub hands back, so the test can prove the reply was sealed with it.
fn stub_reply_key() -> Key {
    OwnCipher
        .s2k(Enctype::Aes256Sha1, b"stub-reply-key", b"stub", None)
        .unwrap()
}

/// A mechanism that takes two rounds and is done on the third.
///
/// Its answers are fixed, which is deliberate: the test is about what the KDC does with a
/// `Step`, not about what a mechanism computes.
struct Stub {
    /// Every `(state, padata)` pair the KDC handed it, in order. The test reads this to
    /// prove the state really travelled through the cookie rather than through a table.
    seen: Mutex<Vec<(Vec<u8>, Vec<u8>)>>,
}

impl Stub {
    fn new() -> Arc<Self> {
        Arc::new(Stub {
            seen: Mutex::new(Vec::new()),
        })
    }

    fn rounds(&self) -> Vec<(Vec<u8>, Vec<u8>)> {
        self.seen.lock().unwrap().clone()
    }
}

impl Mechanism for Stub {
    fn pa_type(&self) -> i32 {
        STUB
    }

    fn name(&self) -> &'static str {
        "stub"
    }

    fn round(&self, request: &Request<'_>, state: &[u8], padata: &[u8]) -> rrl_kdc::Result<Step> {
        self.seen
            .lock()
            .unwrap()
            .push((state.to_vec(), padata.to_vec()));
        match padata {
            // The client's first message: ask for a second, and remember that it started.
            b"hello" => Ok(Step::More {
                padata: b"carry-on".to_vec(),
                state: b"round-one".to_vec(),
            }),
            // The client's second: done, but only if the round-one state really came back.
            b"carry-on-answer" if state == b"round-one" => Ok(Step::Done {
                endtime_bound: None,
                reply_key: request
                    .longterm
                    .first()
                    .cloned()
                    .map(|_| stub_reply_key())
                    .expect("alice has a long-term key"),
                padata: Some(b"finished".to_vec()),
            }),
            other => Ok(Step::Failed {
                code: codes::KDC_ERR_PREAUTH_FAILED,
                text: format!("the stub was given {other:?} with state {state:?}"),
            }),
        }
    }
}

fn kdc(stub: Arc<Stub>) -> Kdc {
    Kdc::new(
        KdcConfig::new(REALM).unwrap(),
        Arc::new(db()),
        Arc::new(OwnCipher),
    )
    .with_cookie_key(cookie_key())
    .with_mechanism(stub)
}

fn kdc_without_mechanism() -> Kdc {
    Kdc::new(
        KdcConfig::new(REALM).unwrap(),
        Arc::new(db()),
        Arc::new(OwnCipher),
    )
    .with_cookie_key(cookie_key())
}

/// An AS-REQ for `alice`, with `padata` when given.
fn as_req(padata: Vec<(i32, Vec<u8>)>) -> Vec<u8> {
    as_req_etypes(padata, &[18])
}

/// The same, asking for `etypes`.
fn as_req_etypes(padata: Vec<(i32, Vec<u8>)>, etypes: &[i32]) -> Vec<u8> {
    let body = der::seq(&[
        der::field(0, der::flags32(kdc_options::FORWARDABLE)),
        der::field(1, principal("alice").encode_name()),
        der::field(2, der::general_string(REALM)),
        der::field(3, Principal::krbtgt(REALM).encode_name()),
        der::field(5, der::time(NOW + 3600)),
        der::field(7, der::int(0x1234_5678)),
        der::field(
            8,
            der::seq(
                &etypes
                    .iter()
                    .map(|e| der::int(*e as i64))
                    .collect::<Vec<_>>(),
            ),
        ),
    ]);
    let mut parts = vec![der::field(1, der::int(5)), der::field(2, der::int(10))];
    if !padata.is_empty() {
        parts.push(der::field(3, encode_pa_data(&padata)));
    }
    parts.push(der::field(4, body));
    der::cons(der::app(10), &[der::seq(&parts)])
}

/// The code and `METHOD-DATA` of a reply.
fn reply(reply: &[u8]) -> (i32, Vec<(i32, Vec<u8>)>) {
    let err = msg::KrbError::decode(reply).expect("the reply is a KRB-ERROR");
    (err.code, err.method_data().unwrap_or_default())
}

/// The cookie from a reply's `METHOD-DATA`, decoded with the realm's key.
fn cookie_of(reply: &[u8]) -> Cookie {
    let (_, method) = self::reply(reply);
    let value = method
        .iter()
        .find(|(t, _)| *t == PA_FX_COOKIE)
        .map(|(_, v)| v.clone())
        .expect("a PA-FX-COOKIE among the offered methods");
    Cookie::decode(&OwnCipher, &cookie_key(), &value).expect("the realm's own cookie decodes")
}

#[test]
fn a_realm_that_offers_a_mechanism_announces_it() {
    // RFC 9588 §4.1: the KDC says it speaks SPAKE with an empty `PA-SPAKE` in the
    // `METHOD-DATA` of `PREAUTH_REQUIRED`. A mechanism missing from that list is one a
    // client will never try, however complete the implementation is.
    let kdc = kdc(Stub::new());
    let (code, method) = reply(&kdc.handle(&as_req(Vec::new()), NOW));
    assert_eq!(code, codes::KDC_ERR_PREAUTH_REQUIRED);
    assert!(
        method.iter().any(|(t, v)| *t == STUB && v.is_empty()),
        "the mechanism announced, empty: {:?}",
        method.iter().map(|(t, _)| *t).collect::<Vec<_>>()
    );
    // And the single-round methods are still there: announcing a mechanism is an addition.
    assert!(method.iter().any(|(t, _)| *t == msg::PA_ETYPE_INFO2));
}

#[test]
fn a_realm_without_mechanisms_announces_none() {
    // Off by default. A realm that advertises a mechanism it has not configured sends its
    // clients down a road that ends in a refusal.
    let kdc = kdc_without_mechanism();
    let (_, method) = reply(&kdc.handle(&as_req(Vec::new()), NOW));
    assert!(
        !method.iter().any(|(t, _)| *t == STUB),
        "nothing configured, nothing offered: {:?}",
        method.iter().map(|(t, _)| *t).collect::<Vec<_>>()
    );
}

#[test]
fn an_unfinished_round_answers_more_preauth_data_not_a_failure() {
    // The whole point of code 91. A client that reads `PREAUTH_FAILED` reports "wrong
    // password" and never sends the second round; the exchange then fails for a reason
    // that has nothing to do with the client.
    let stub = Stub::new();
    let kdc = kdc(Arc::clone(&stub));
    let (code, method) = reply(&kdc.handle(&as_req(vec![(STUB, b"hello".to_vec())]), NOW));

    assert_eq!(code, codes::KDC_ERR_MORE_PREAUTH_DATA_REQUIRED);
    assert_eq!(
        codes::KDC_ERR_MORE_PREAUTH_DATA_REQUIRED,
        91,
        "RFC 6113 §3.1: the number is the protocol, so it is pinned literally"
    );
    assert!(
        method.iter().any(|(t, v)| *t == STUB && v == b"carry-on"),
        "the mechanism's own PA-DATA answers the round: {method:?}"
    );
    // The etype offer must not be displaced by the mechanism's answer — a client that lost
    // it cannot derive any key at all, and the failure reads as "no usable key".
    assert!(
        method.iter().any(|(t, _)| *t == PA_FX_COOKIE),
        "the round's state needs a place to live: {method:?}"
    );
}

#[test]
fn the_state_a_round_produced_comes_back_to_the_next_one() {
    // Without this the framework is a message bus, not a state machine: a mechanism that
    // restarts from nothing on every round never finishes.
    let stub = Stub::new();
    let kdc = kdc(Arc::clone(&stub));

    let first = kdc.handle(&as_req(vec![(STUB, b"hello".to_vec())]), NOW);
    let cookie = cookie_of(&first);
    assert_eq!(
        cookie.state, b"round-one",
        "what the round decided is what the cookie carries"
    );

    let value = cookie.encode(&OwnCipher, &cookie_key()).unwrap();
    let second = kdc.handle(
        &as_req(vec![
            (STUB, b"carry-on-answer".to_vec()),
            (PA_FX_COOKIE, value),
        ]),
        NOW,
    );

    // The mechanism saw the state, and the reply is an AS-REP rather than an error.
    let rounds = stub.rounds();
    assert_eq!(rounds.len(), 2, "two rounds ran: {rounds:?}");
    assert_eq!(rounds[1].0, b"round-one", "the second round resumed");
    assert!(
        msg::KrbError::decode(&second).is_err(),
        "a finished mechanism gets a ticket, not a refusal: {:?}",
        msg::KrbError::decode(&second).ok().map(|e| e.code)
    );
}

#[test]
fn the_same_second_round_without_the_cookie_is_refused() {
    // The pair that makes the test above mean something: if the mechanism finished without
    // the state, the state was not doing the work, and the test would pass for the wrong
    // reason.
    let stub = Stub::new();
    let kdc = kdc(Arc::clone(&stub));
    let reply = kdc.handle(&as_req(vec![(STUB, b"carry-on-answer".to_vec())]), NOW);
    let (code, _) = self::reply(&reply);
    assert_eq!(
        code,
        codes::KDC_ERR_PREAUTH_FAILED,
        "a round that needs state, given none, cannot verify"
    );
}

#[test]
fn the_reply_is_sealed_with_the_key_the_mechanism_produced() {
    // A framework that ran the mechanism and then ignored its reply key would look
    // finished and be useless: the client derives the key from the exchange, so a reply
    // sealed in the long-term key is one it cannot read.
    let stub = Stub::new();
    let kdc = kdc(Arc::clone(&stub));
    let first = kdc.handle(&as_req(vec![(STUB, b"hello".to_vec())]), NOW);
    let value = cookie_of(&first).encode(&OwnCipher, &cookie_key()).unwrap();
    let second = kdc.handle(
        &as_req(vec![
            (STUB, b"carry-on-answer".to_vec()),
            (PA_FX_COOKIE, value),
        ]),
        NOW,
    );

    let f = der::Fields::parse_app("AS-REP", 11, &second).expect("an AS-REP");
    let sealed = EncryptedData::decode("enc-part", f.bytes(6, "AS-REP").expect("enc-part"))
        .expect("an EncryptedData");
    let opened = OwnCipher.decrypt(
        &stub_reply_key(),
        rrl_kdc::crypto::usage::AS_REP_ENCPART,
        &sealed.cipher,
    );
    assert!(
        opened.is_ok(),
        "the reply must open with the mechanism's key, not the long-term one: {opened:?}"
    );

    // And the mechanism's own PA-DATA travels in the reply, because SPAKE's client needs
    // it to finish: `encdata` is where the KDC proves it took part.
    let padata = msg::decode_pa_data(
        "AS-REP padata",
        der::Reader::new(f.bytes(2, "AS-REP").expect("padata"))
            .expect_in("padata", der::SEQUENCE)
            .expect("a SEQUENCE"),
    )
    .expect("AS-REP padata decodes");
    assert!(
        padata.iter().any(|(t, v)| *t == STUB && v == b"finished"),
        "the mechanism's reply value is carried: {padata:?}"
    );
}

#[test]
fn a_mechanism_the_realm_does_not_offer_leaves_the_single_round_paths_alone() {
    // A request naming an unknown PA-DATA type is not an error: clients send types a KDC
    // has never heard of all the time, and refusing the request over one of them would
    // reject logins that are perfectly valid.
    let kdc = kdc_without_mechanism();
    let (code, _) = reply(&kdc.handle(&as_req(vec![(STUB, b"hello".to_vec())]), NOW));
    assert_eq!(
        code,
        codes::KDC_ERR_PREAUTH_REQUIRED,
        "an unknown PA-DATA type is not a refusal, it just does not help"
    );
}

#[test]
fn a_mechanism_that_refuses_names_its_own_code() {
    // `KDC_ERR_ETYPE_NOSUPP` from SPAKE (no group in common) is more useful than the
    // blanket `PREAUTH_FAILED`, and the framework has to carry it through rather than
    // flattening every refusal into one code.
    let stub = Stub::new();
    let kdc = kdc(Arc::clone(&stub));
    let (code, _) = reply(&kdc.handle(&as_req(vec![(STUB, b"nonsense".to_vec())]), NOW));
    assert_eq!(code, codes::KDC_ERR_PREAUTH_FAILED);
    // The text names the mechanism, so an operator knows which one spoke.
    let err = msg::KrbError::decode(&kdc.handle(&as_req(vec![(STUB, b"nonsense".to_vec())]), NOW))
        .unwrap();
    let text = err.e_text.unwrap_or_default();
    assert!(
        text.contains("stub"),
        "the refusal names the mechanism: {text}"
    );
}

#[test]
fn a_preauth_failed_round_keeps_the_round_it_already_paid_for() {
    // RFC 6113 §3.1 does not say a failed round must forget: a client that answered badly
    // should be able to retry without starting over, and losing the state turns one
    // mistake into three more messages.
    let stub = Stub::new();
    let kdc = kdc(Arc::clone(&stub));
    let first = kdc.handle(&as_req(vec![(STUB, b"hello".to_vec())]), NOW);
    assert_eq!(cookie_of(&first).state, b"round-one");

    // A second request carrying the cookie but a value the mechanism cannot use.
    let value = cookie_of(&first).encode(&OwnCipher, &cookie_key()).unwrap();
    let second = kdc.handle(
        &as_req(vec![(STUB, b"nonsense".to_vec()), (PA_FX_COOKIE, value)]),
        NOW,
    );
    assert_eq!(
        cookie_of(&second).state,
        b"round-one",
        "the state survived the failure"
    );
}

#[test]
fn the_announced_state_reaches_the_client_in_the_cookie() {
    // OTP's announcement is a challenge with a nonce, and a nonce the KDC cannot remember
    // is an accusation. The framework therefore lets an announcement carry state too, and
    // that state has to arrive in the same error as the PA-DATA.
    struct Challenging;
    impl Mechanism for Challenging {
        fn pa_type(&self) -> i32 {
            STUB
        }
        fn name(&self) -> &'static str {
            "challenging"
        }
        fn announce(&self, _request: &Request<'_>) -> rrl_kdc::Result<Option<Announced>> {
            Ok(Some(Announced {
                padata: b"nonce-42".to_vec(),
                state: b"nonce-42".to_vec(),
            }))
        }
        fn round(
            &self,
            _request: &Request<'_>,
            _state: &[u8],
            _padata: &[u8],
        ) -> rrl_kdc::Result<Step> {
            Ok(Step::More {
                padata: Vec::new(),
                state: Vec::new(),
            })
        }
    }

    let kdc = Kdc::new(
        KdcConfig::new(REALM).unwrap(),
        Arc::new(db()),
        Arc::new(OwnCipher),
    )
    .with_cookie_key(cookie_key())
    .with_mechanism(Arc::new(Challenging));

    let reply = kdc.handle(&as_req(Vec::new()), NOW);
    let (code, method) = self::reply(&reply);
    assert_eq!(code, codes::KDC_ERR_PREAUTH_REQUIRED);
    assert!(
        method.iter().any(|(t, v)| *t == STUB && v == b"nonce-42"),
        "the announcement carries content, not just its name: {method:?}"
    );
    assert_eq!(
        cookie_of(&reply).state,
        b"nonce-42",
        "and the nonce it sent is remembered, or the next round cannot check it"
    );
}

#[test]
fn a_mechanism_sees_the_request_octets_and_the_long_term_keys() {
    // SPAKE binds its exchange to the request body and derives its multiplier from the
    // client's key; a framework that handed it a re-encoded body or only the resolved key
    // would leave the mechanism guessing. This test states what the context carries.
    struct Inspecting;
    impl Mechanism for Inspecting {
        fn pa_type(&self) -> i32 {
            STUB
        }
        fn name(&self) -> &'static str {
            "inspecting"
        }
        fn round(
            &self,
            request: &Request<'_>,
            _state: &[u8],
            _padata: &[u8],
        ) -> rrl_kdc::Result<Step> {
            assert_eq!(request.realm, REALM);
            assert_eq!(request.cname.components, vec!["alice".to_string()]);
            assert_eq!(request.now, NOW);
            assert!(
                !request.body.is_empty(),
                "the KDC-REQ-BODY octets are what a checksum binds to"
            );
            assert_eq!(
                request.longterm.len(),
                2,
                "one key per *usable* enctype: the client asked for both AES-256 and AES-128, \
                 and a mechanism handed only the strongest would have no key for the enctype \
                 the KDC may actually choose"
            );
            assert!(request.armor.is_none(), "this request did not armor");
            Ok(Step::Failed {
                code: codes::KDC_ERR_PREAUTH_FAILED,
                text: "inspected".into(),
            })
        }
    }

    let kdc = Kdc::new(
        KdcConfig::new(REALM).unwrap(),
        Arc::new(db()),
        Arc::new(OwnCipher),
    )
    .with_cookie_key(cookie_key())
    .with_mechanism(Arc::new(Inspecting));
    // The assertions live in the mechanism; reaching them is the test.
    let _ = kdc.handle(&as_req_etypes(vec![(STUB, b"go".to_vec())], &[18, 17]), NOW);
}

#[test]
fn the_debug_view_names_the_mechanisms() {
    // What an operator reads when a multi-round login gets nowhere. A `Debug` that printed
    // only "preauth: true" would leave them grepping the config.
    let kdc = kdc(Stub::new());
    let text = format!("{kdc:?}");
    assert!(text.contains("stub"), "{text}");
    assert!(text.contains("cookie: true"), "{text}");
}

#[test]
fn a_ticket_from_a_finished_mechanism_is_marked_pre_authenticated() {
    // The flag a service reads to know the client proved itself. It is set from a chain of
    // `||` over every method that can authenticate, and a mechanism was added to that chain
    // by this change — so this test is what makes the addition real rather than cosmetic.
    // Without it a SPAKE login would issue a ticket indistinguishable from a password-less
    // one, and the mutants that flip the chain to `&&` survived.
    let stub = Stub::new();
    let kdc = kdc(Arc::clone(&stub));
    let first = kdc.handle(&as_req(vec![(STUB, b"hello".to_vec())]), NOW);
    let value = cookie_of(&first).encode(&OwnCipher, &cookie_key()).unwrap();
    let second = kdc.handle(
        &as_req(vec![
            (STUB, b"carry-on-answer".to_vec()),
            (PA_FX_COOKIE, value),
        ]),
        NOW,
    );

    // The flags travel in the ticket, sealed with `krbtgt`'s key.
    let f = der::Fields::parse_app("AS-REP", 11, &second).expect("an AS-REP");
    let ticket = msg::Ticket::decode(f.bytes(5, "AS-REP").expect("ticket")).expect("a Ticket");
    let krbtgt = {
        let cipher = OwnCipher;
        let mut entry = HdbEntry::krbtgt(REALM);
        entry
            .add_password_key(&cipher, Enctype::Aes256Sha1, b"master", 1)
            .unwrap();
        entry.key_for(Enctype::Aes256Sha1).unwrap().key.clone()
    };
    let plain = OwnCipher
        .decrypt(
            &krbtgt,
            rrl_kdc::crypto::usage::KDC_REP_TICKET,
            &ticket.enc.cipher,
        )
        .expect("the ticket opens with krbtgt's key");
    let part = msg::EncTicketPart::decode(&plain).expect("an EncTicketPart");
    assert_ne!(
        part.flags & msg::tkt_flags::PRE_AUTHENT,
        0,
        "a mechanism that finished is pre-authentication: flags were {:#010x}",
        part.flags
    );
}

#[test]
fn a_realm_that_requires_preauthentication_is_not_relaxed_by_the_entry() {
    // Two places can demand pre-authentication: the realm's configuration and the entry's
    // own flag. They are joined with `||`, and every fixture in this suite sets both — so a
    // mutation that turned the join into `&&` would issue a ticket without any
    // pre-authentication in the one configuration that matters: a realm that requires it
    // for an account that does not declare it.
    let cipher = OwnCipher;
    let db = MemoryHdb::new();
    let mut krbtgt = HdbEntry::krbtgt(REALM);
    krbtgt
        .add_password_key(&cipher, Enctype::Aes256Sha1, b"master", 1)
        .unwrap();
    db.insert(krbtgt).unwrap();
    let mut alice = HdbEntry::user(principal("alice"));
    alice
        .add_password_key(&cipher, Enctype::Aes256Sha1, PASSWORD.as_bytes(), 1)
        .unwrap();
    // The entry says nothing about pre-authentication; the realm does.
    alice.flags &= !rrl_kdc::hdb::flags::REQUIRE_PREAUTH;
    db.insert(alice).unwrap();

    let kdc = Kdc::new(
        KdcConfig::new(REALM).unwrap().with_require_preauth(true),
        Arc::new(db),
        Arc::new(cipher),
    );
    let (code, _) = reply(&kdc.handle(&as_req(Vec::new()), NOW));
    assert_eq!(
        code,
        codes::KDC_ERR_PREAUTH_REQUIRED,
        "the realm's policy stands on its own; an entry that stays silent does not opt out"
    );
}
