//! OTP at the mechanism: the properties a successful exchange does not prove.
//!
//! The live client shows that a correct value gets a ticket. What it cannot show is that a
//! *replayed* request does not, or that a nonce issued to one exchange is useless in another —
//! and those are the two things standing between a recorded login and a free one.
//!
//! These tests drive [`Otp::round`] directly, because each case needs a `PA-OTP-REQUEST` that a
//! real client would never send: one with no state behind it, one carrying another exchange's
//! nonce, one whose value the verifier refuses.

#![cfg(feature = "otp")]

use std::sync::Arc;

use rrl_kdc::crypto::{Cipher, Enctype, Key, OwnCipher};
use rrl_kdc::der;
use rrl_kdc::error::codes;
use rrl_kdc::kdc::otp::{KU_PA_OTP_REQUEST, Otp, PA_OTP_REQUEST, Verifier};
use rrl_kdc::kdc::preauth::{Mechanism, Request, Step};
use rrl_kdc::msg::EncryptedData;
use rrl_kdc::name::Principal;

const REALM: &str = "EXAMPLE.COM";
const OTP: &str = "942617";
const NOW: i64 = 1_700_000_000;

/// A verifier that answers from a fixed value, or fails if `broken`.
struct Judge {
    accept: &'static str,
    broken: bool,
}

impl Verifier for Judge {
    fn verify(&self, _client: &Principal, value: &str) -> rrl_kdc::Result<bool> {
        if self.broken {
            return Err(rrl_kdc::Error::Kdc {
                code: codes::KDC_ERR_SVC_UNAVAILABLE,
                text: "the RADIUS server did not answer".into(),
            });
        }
        Ok(value == self.accept)
    }
}

fn armor_key() -> Key {
    OwnCipher
        .s2k(Enctype::Aes256Sha1, b"armor-secret", b"armor", None)
        .unwrap()
}

fn alice() -> Principal {
    Principal::parse(&format!("alice@{REALM}")).unwrap()
}

/// The `Request` a mechanism sees. `armor` is the key the exchange was armored with.
fn context<'a>(armor: Option<&'a Key>, cipher: &'a dyn Cipher) -> Request<'a> {
    let cname = alice();
    // The principal has to outlive the borrow, and a `Request` is built per call in these tests;
    // leaking one small name per case keeps the fixture honest about what the mechanism sees.
    let cname: &'a Principal = Box::leak(Box::new(cname));
    Request {
        cname,
        realm: REALM,
        body: &[],
        longterm: &[],
        armor,
        now: NOW,
        cipher,
    }
}

fn otp() -> Otp<Judge> {
    Otp::new(Arc::new(Judge {
        accept: OTP,
        broken: false,
    }))
}

/// A `PA-OTP-REQUEST` answering `nonce`, with `value`, sealed in `armor`.
fn request(nonce: &[u8], value: &str, armor: &Key) -> Vec<u8> {
    let plain = der::seq(&[der::tlv(0x80, nonce)]);
    let sealed = EncryptedData::seal(&OwnCipher, armor, KU_PA_OTP_REQUEST, None, &plain).unwrap();
    // `[2]` is an IMPLICIT `EncryptedData`: the tag replaces its SEQUENCE, so the field carries
    // that SEQUENCE's content.
    let encoded = sealed.encode();
    let mut r = der::Reader::new(&encoded);
    let content = r.expect_in("EncryptedData", der::SEQUENCE).unwrap();
    der::seq(&[der::tlv(0xa2, content), der::tlv(0x85, value.as_bytes())])
}

/// The nonce out of the state an announcement produced.
fn nonce_of(state: &[u8]) -> Vec<u8> {
    let mut r = der::Reader::new(state);
    let f = der::Fields::parse("state", r.expect_in("state", der::SEQUENCE).unwrap()).unwrap();
    f.octets(1, "state").unwrap().to_vec()
}

#[test]
fn an_unarmored_request_is_offered_nothing() {
    // RFC 6560 §3.2 carries the challenge inside `enc-fast-rep`. Announcing it outside the armor
    // would offer a method whose challenge the client cannot be given.
    let cipher = OwnCipher;
    let announced = otp().announce(&context(None, &cipher)).unwrap();
    assert!(
        announced.is_none(),
        "an unarmored request must not be told that OTP exists"
    );
}

#[test]
fn an_armored_request_is_challenged_with_a_nonce_and_its_state() {
    let cipher = OwnCipher;
    let armor = armor_key();
    let announced = otp()
        .announce(&context(Some(&armor), &cipher))
        .unwrap()
        .expect("OTP announces inside the armor");

    let nonce = nonce_of(&announced.state);
    assert_eq!(
        nonce.len(),
        armor.bytes().len(),
        "§3.2: the nonce is at least as long as the armor key"
    );
    assert!(
        nonce.iter().any(|b| *b != 0),
        "a nonce of zeros is not random"
    );

    // Two announcements must differ, or one captured challenge answers every login.
    let again = nonce_of(
        &otp()
            .announce(&context(Some(&armor), &cipher))
            .unwrap()
            .unwrap()
            .state,
    );
    assert_ne!(nonce, again, "the nonce is fresh per challenge");
}

#[test]
fn a_request_without_a_cookie_cannot_be_verified() {
    // No state, so no nonce, so no way to tell this request from a replay of somebody else's.
    // The answer is "ask again" rather than a guess, and certainly not a ticket.
    let cipher = OwnCipher;
    let armor = armor_key();
    let value = request(&[1u8; 32], OTP, &armor);
    let step = otp()
        .round(&context(Some(&armor), &cipher), &[], &value)
        .unwrap();
    match step {
        Step::Failed { code, .. } => assert_eq!(
            code,
            codes::KDC_ERR_MORE_PREAUTH_DATA_REQUIRED,
            "a stateless request is restarted, not refused outright"
        ),
        other => panic!("a request with no state must not be accepted: {other:?}"),
    }
}

#[test]
fn a_nonce_from_another_exchange_is_refused() {
    // The replay defence. Both nonces are legitimate and both decrypt; only the one this
    // exchange issued may be answered.
    let cipher = OwnCipher;
    let armor = armor_key();
    let mine = nonce_of(
        &otp()
            .announce(&context(Some(&armor), &cipher))
            .unwrap()
            .unwrap()
            .state,
    );
    let somebody_elses = vec![0x5a_u8; mine.len()];

    let step = otp()
        .round(
            &context(Some(&armor), &cipher),
            &state_with(&mine),
            &request(&somebody_elses, OTP, &armor),
        )
        .unwrap();
    match step {
        Step::Failed { code, text } => {
            assert_eq!(code, codes::KDC_ERR_PREAUTH_FAILED);
            assert!(text.contains("nonce"), "{text}");
        }
        other => panic!("another exchange's nonce must not be accepted: {other:?}"),
    }
}

#[test]
fn the_right_nonce_with_the_right_value_completes_with_the_armor_key() {
    // RFC 6560 §3.3: with `must-encrypt-nonce` clear the reply key *is* the armor key, which is
    // what lets a KDC that delegates the judgement to somebody else still seal a reply.
    let cipher = OwnCipher;
    let armor = armor_key();
    let nonce = nonce_of(
        &otp()
            .announce(&context(Some(&armor), &cipher))
            .unwrap()
            .unwrap()
            .state,
    );
    let step = otp()
        .round(
            &context(Some(&armor), &cipher),
            &state_with(&nonce),
            &request(&nonce, OTP, &armor),
        )
        .unwrap();
    match step {
        Step::Done { reply_key, .. } => {
            assert_eq!(
                reply_key.bytes(),
                armor.bytes(),
                "the reply key is the armor key"
            );
        }
        other => panic!("a correct value must complete the exchange: {other:?}"),
    }
}

#[test]
fn a_value_the_verifier_refuses_does_not_complete() {
    let cipher = OwnCipher;
    let armor = armor_key();
    let nonce = nonce_of(
        &otp()
            .announce(&context(Some(&armor), &cipher))
            .unwrap()
            .unwrap()
            .state,
    );
    let step = otp()
        .round(
            &context(Some(&armor), &cipher),
            &state_with(&nonce),
            &request(&nonce, "000000", &armor),
        )
        .unwrap();
    match step {
        Step::Failed { code, text } => {
            assert_eq!(code, codes::KDC_ERR_PREAUTH_FAILED);
            assert!(text.contains("one-time value"), "{text}");
        }
        other => panic!("a refused value must not produce a ticket: {other:?}"),
    }
}

#[test]
fn a_verifier_that_could_not_answer_is_not_a_wrong_token() {
    // A RADIUS server that timed out is an outage, not a bad OTP. Reporting it as
    // `PREAUTH_FAILED` sends the user to retype a value that was never judged, and hides the
    // outage from whoever is on call.
    let cipher = OwnCipher;
    let armor = armor_key();
    let broken = Otp::new(Arc::new(Judge {
        accept: OTP,
        broken: true,
    }));
    let nonce = nonce_of(
        &broken
            .announce(&context(Some(&armor), &cipher))
            .unwrap()
            .unwrap()
            .state,
    );
    let err = broken
        .round(
            &context(Some(&armor), &cipher),
            &state_with(&nonce),
            &request(&nonce, OTP, &armor),
        )
        .expect_err("an unavailable verifier is an error, not a refusal");
    assert_eq!(err.kdc_code(), codes::KDC_ERR_SVC_UNAVAILABLE);
}

#[test]
fn a_request_outside_the_armor_is_refused_even_with_a_valid_nonce() {
    // The one-time value would have travelled in the clear. §3.2 does not allow it and neither
    // does this KDC — the nonce being right does not make the request acceptable.
    let cipher = OwnCipher;
    let armor = armor_key();
    let nonce = vec![3u8; 32];
    let step = otp()
        .round(
            &context(None, &cipher),
            &state_with(&nonce),
            &request(&nonce, OTP, &armor),
        )
        .unwrap();
    match step {
        Step::Failed { code, text } => {
            assert_eq!(code, codes::KDC_ERR_PREAUTH_FAILED);
            assert!(text.contains("armor"), "{text}");
        }
        other => panic!("an unarmored request must be refused: {other:?}"),
    }
}

#[test]
fn the_mechanism_is_offered_as_the_challenge_type_and_answered_as_the_request_type() {
    let otp = otp();
    assert_eq!(otp.pa_type(), PA_OTP_REQUEST);
    assert_eq!(otp.announce_type(), rrl_kdc::kdc::otp::PA_OTP_CHALLENGE);
    assert_ne!(
        otp.pa_type(),
        otp.announce_type(),
        "OTP is why the framework has two of these"
    );
}

/// The state a challenge leaves, without going through `announce` in the negative cases.
fn state_with(nonce: &[u8]) -> Vec<u8> {
    der::seq(&[
        der::field(0, der::int(1)),
        der::field(1, der::octets(nonce)),
    ])
}
