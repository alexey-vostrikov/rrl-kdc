//! The `must-encrypt-nonce` variant of RFC 6560, end to end through the engine.
//!
//! §3.3 splits OTP pre-authentication on one flag. With it **clear**, the one-time value travels in
//! `otp-value` and the reply key is the armor key — the variant this crate shipped first, because it
//! is what a KDC that asks somebody else needs. With it **set**, the value never leaves the token:
//! both keys are derived from it (§3.6), and the KDC has to hold the value to follow.
//!
//! The client half below is written from the RFC's formulas, not from this crate's helpers — that is
//! the whole point of the file. A wrong pepper or a missing base64 in `keys_from_value` would agree
//! with itself and every exchange would still pass; here it stops the client's nonce from opening.
//!
//! What this cannot prove: interop with a real OTP client. None in the stand speaks this variant
//! (`krb5` 1.0 does not, and `kinit -T` needs a token plugin), so the honest claim is "the exchange
//! matches the formula, checked against a second implementation of it", not "a token works".

#![cfg(feature = "otp")]

use std::sync::Arc;

use rrl_kdc::crypto::{Cipher, Enctype, Key, OwnCipher};
use rrl_kdc::der;
use rrl_kdc::error::codes;
use rrl_kdc::hdb::{HdbEntry, MemoryHdb};
use rrl_kdc::kdc::otp::{Challenge, Otp, OtpSource, Verifier};
use rrl_kdc::kdc::{Kdc, KdcConfig};
use rrl_kdc::msg::EncryptedData;
use rrl_kdc::name::Principal;

const REALM: &str = "EXAMPLE.COM";
const PASSWORD: &str = "correct horse battery staple";
const NOW: i64 = 1_700_000_000;
const PA_OTP_CHALLENGE: i32 = 141;
const PA_OTP_REQUEST: i32 = 142;
const PA_FX_COOKIE: i32 = 133;
const KU_PA_OTP_REQUEST: u32 = 45;

/// A token whose value is a number the test decides.
///
/// It answers for `alice` only: `bob` is a user the realm knows and whose token value this KDC does
/// not hold, which is a case the withheld variant has to refuse by name.
#[derive(Debug)]
struct Tokens(&'static str);

impl OtpSource for Tokens {
    fn value(&self, client: &Principal) -> Option<String> {
        (client.name() == "alice").then(|| self.0.to_owned())
    }
}

/// A verifier that refuses to be asked: with the value withheld there is nothing to verify, and a
/// realm that installed both must not have its tokens judged by a string comparison.
#[derive(Debug)]
struct NeverAsked;

impl Verifier for NeverAsked {
    fn verify(&self, _client: &Principal, _value: &str) -> rrl_kdc::error::Result<bool> {
        panic!("the verifier must not be consulted when the value is withheld");
    }
}

/// The other variant's verifier: the value arrives, and this is the only judge of it.
#[derive(Debug)]
struct Accepts(&'static str);

impl Verifier for Accepts {
    fn verify(&self, _client: &Principal, value: &str) -> rrl_kdc::error::Result<bool> {
        Ok(value == self.0)
    }
}

fn principal(name: &str) -> Principal {
    Principal::parse(&format!("{name}@{REALM}")).unwrap()
}

/// A realm with `alice`, `bob`, and a `krbtgt`.
fn db() -> MemoryHdb {
    let cipher = OwnCipher;
    let db = MemoryHdb::new();
    let mut krbtgt = HdbEntry::krbtgt(REALM);
    krbtgt
        .add_password_key(&cipher, Enctype::Aes256Sha1, b"master", 1)
        .unwrap();
    db.insert(krbtgt).unwrap();
    for name in ["alice", "bob"] {
        let mut user = HdbEntry::user(principal(name));
        user.add_password_key(&cipher, Enctype::Aes256Sha1, PASSWORD.as_bytes(), 1)
            .unwrap();
        db.insert(user).unwrap();
    }
    db
}

fn kdc_with(mechanism: Arc<Otp<impl Verifier + 'static>>) -> Kdc {
    Kdc::new(
        KdcConfig::new(REALM).unwrap(),
        Arc::new(db()),
        Arc::new(OwnCipher),
    )
    // Without a cookie key the realm offers no cookie, and a two-round exchange has nowhere to
    // keep the nonce — the client would be asked again for a value it already sent. The state the
    // first round computes is the nonce *and* which variant the realm chose, so a resumed round
    // that lost it would derive the wrong keys.
    .with_cookie_key(
        OwnCipher
            .s2k(Enctype::Aes256Sha1, b"cookie-secret", b"cookie", None)
            .unwrap(),
    )
    .with_mechanism(mechanism)
}

/// A realm that holds its tokens' values, so the challenge withholds them.
fn kdc(value: &'static str) -> Kdc {
    kdc_with(Arc::new(
        Otp::new(Arc::new(NeverAsked)).with_source(Arc::new(Tokens(value))),
    ))
}

/// A realm that does not hold the values, so the client has to send one.
fn kdc_verifying(value: &'static str) -> Kdc {
    kdc_with(Arc::new(Otp::new(Arc::new(Accepts(value)))))
}

/// A client's armor: one TGT and its session key, reused for every round of one login.
///
/// Reused, not rebuilt. The armor key is derived from this ticket (RFC 6113 §5.4.1), so a client
/// that built a fresh one per round would hand the KDC a different key in each — and the second
/// round would fail at the nonce, pointing at the token rather than at the armor. The first version
/// of this file did exactly that, and the diagnosis took longer than writing the mechanism.
struct Armor {
    ticket: Vec<u8>,
    key: Key,
}

fn armor(cname: &str) -> Armor {
    use rrl_kdc::crypto::usage;
    use rrl_kdc::msg::{EncTicketPart, Ticket, tkt_flags};

    let cipher = OwnCipher;
    let mut krbtgt = HdbEntry::krbtgt(REALM);
    krbtgt
        .add_password_key(&cipher, Enctype::Aes256Sha1, b"master", 1)
        .unwrap();
    let krbtgt_key = krbtgt.key_for(Enctype::Aes256Sha1).unwrap().key.clone();

    let key = cipher.random(Enctype::Aes256Sha1).unwrap();
    let part = EncTicketPart {
        flags: tkt_flags::INITIAL | tkt_flags::PRE_AUTHENT,
        session_key: key.clone(),
        crealm: REALM.into(),
        cname: principal(cname),
        transited_type: 0,
        transited: Vec::new(),
        authtime: NOW - 60,
        starttime: None,
        endtime: NOW + 3600,
        renew_till: None,
        caddr: None,
        authorization_data: None,
    };
    let ticket = Ticket {
        realm: REALM.into(),
        sname: Principal::krbtgt(REALM),
        enc: EncryptedData::seal(
            &cipher,
            &krbtgt_key,
            usage::KDC_REP_TICKET,
            Some(1),
            &part.encode(),
        )
        .unwrap(),
    };
    Armor {
        ticket: ticket.encode(),
        key,
    }
}

/// An armored `AS-REQ` carrying `padata` inside the armor.
///
/// Built with the crate's own FAST encoders — `ArmoredRequest`, `FastRequest`, `Armor` — because the
/// armor has a `req-checksum` over the outer body and an `enc-fast-req` sealed in the armor key, and
/// hand-rolling those is how a test ends up proving that a malformed request is malformed.
fn armored_as_req(armor: &Armor, cname: &str, padata: Vec<(i32, Vec<u8>)>) -> Vec<u8> {
    use rrl_kdc::kdc::fast;
    use rrl_kdc::msg::{ApReq, Authenticator};

    let cipher = OwnCipher;
    // No `subkey` in the authenticator, so the armor key is the ticket's session key (RFC 6113
    // §5.4.1) — the same thing `Armor::key` holds.
    let authenticator = Authenticator {
        crealm: REALM.into(),
        cname: principal(cname),
        cksum: None,
        cusec: 0,
        ctime: NOW,
        subkey: None,
        seq_number: None,
        authorization_data: None,
    };
    let ap_req = ApReq {
        ap_options: 0,
        ticket: armor.ticket.clone(),
        authenticator: EncryptedData::seal(
            &cipher,
            &armor.key,
            fast::usage::AP_REQ_AUTH,
            None,
            &authenticator.encode(),
        )
        .unwrap(),
    };

    let body = der::seq(&[
        der::field(0, der::flags32(rrl_kdc::msg::kdc_options::FORWARDABLE)),
        der::field(1, principal(cname).encode_name()),
        der::field(2, der::general_string(REALM)),
        der::field(3, Principal::krbtgt(REALM).encode_name()),
        der::field(5, der::time(NOW + 3600)),
        der::field(7, der::int(0x5150)),
        der::field(8, der::seq(&[der::int(18), der::int(17)])),
    ]);

    let inner = fast::FastRequest {
        fast_options: fast::options_bits(0),
        padata,
        req_body: body.clone(),
    };
    let enc = EncryptedData::seal(
        &cipher,
        &armor.key,
        fast::usage::FAST_ENC,
        None,
        &inner.encode(),
    )
    .unwrap();
    let armored = fast::ArmoredRequest {
        armor: Some(fast::Armor {
            armor_type: 1,
            armor_value: ap_req.encode(),
        }),
        req_checksum: (
            Enctype::Aes256Sha1.checksum_type(),
            cipher
                .checksum(&armor.key, fast::usage::FAST_REQ_CHKSUM, &body)
                .unwrap(),
        ),
        enc_fast_req: enc.encode(),
    };

    der::cons(
        der::app(10),
        &[der::seq(&[
            der::field(1, der::int(5)),
            der::field(2, der::int(10)),
            der::field(
                3,
                rrl_kdc::msg::encode_pa_data(&[(fast::PA_FX_FAST, armored.encode())]),
            ),
            der::field(4, body),
        ])],
    )
}

/// The `PA-DATA` a reply carries, opened out of FAST.
///
/// An armored exchange answers in armor (RFC 6113 §5.4.2): the `METHOD-DATA` a client reads is the
/// `[0]` of the response sealed in `PA-FX-FAST`, in an error as in a ticket. Reading the outer
/// `e-data` instead shows one `PA-DATA` of type 136 and nothing else — which is exactly how a client
/// that forgot to open the armor concludes the KDC has no mechanisms.
fn method_data(reply: &[u8], armor: &Key) -> Vec<(i32, Vec<u8>)> {
    use rrl_kdc::kdc::fast;

    let err = rrl_kdc::msg::KrbError::decode(reply).expect("a KRB-ERROR");
    let value = err
        .method_data()
        .expect("METHOD-DATA")
        .into_iter()
        .find(|(t, _)| *t == fast::PA_FX_FAST_REPLY)
        .map(|(_, v)| v)
        .expect("the armored reply");

    let mut r = der::Reader::new(&value);
    let choice = r.next_tlv("PA-FX-FAST").expect("armored-data [0]");
    assert_eq!(choice.tag, 0xa0, "armored-data [0]");
    let mut inner = der::Reader::new(choice.content);
    let seq = inner.next_tlv("KrbFastArmoredRep").expect("a SEQUENCE");
    let f = der::Fields::parse("KrbFastArmoredRep", seq.content).expect("fields");
    let enc = EncryptedData::decode("enc-fast-rep", f.bytes(0, "enc-fast-rep").expect("enc"))
        .expect("an EncryptedData");
    let plain = OwnCipher
        .decrypt(armor, fast::usage::FAST_REP, &enc.cipher)
        .expect("the armor key opens the reply");
    let mut rr = der::Reader::new(&plain);
    let response = rr.next_tlv("KrbFastResponse").expect("a SEQUENCE");
    let rf = der::Fields::parse("KrbFastResponse", response.content).expect("fields");
    let mut pr = der::Reader::new(rf.bytes(0, "padata").expect("padata"));
    rrl_kdc::msg::decode_pa_data(
        "METHOD-DATA",
        pr.expect_in("METHOD-DATA", der::SEQUENCE)
            .expect("a SEQUENCE"),
    )
    .expect("METHOD-DATA")
}

/// The challenge of a reply, read with the crate's own reader.
///
/// Deliberately not hand-parsed here: the point of `Challenge::decode` is that the structure the KDC
/// writes has one reader in this crate, and a test that climbs the DER itself is a second opinion
/// that can be wrong in the same direction as the encoder. The octet-level shape is pinned in
/// `kdc::otp`'s own tests, where a literal hex string is compared.
fn challenge_of(data: &[(i32, Vec<u8>)]) -> Challenge {
    let value = data
        .iter()
        .find(|(t, _)| *t == PA_OTP_CHALLENGE)
        .map(|(_, v)| v)
        .unwrap_or_else(|| {
            panic!(
                "no PA-OTP-CHALLENGE; the reply carried {:?}",
                data.iter().map(|(t, _)| *t).collect::<Vec<_>>()
            )
        });
    Challenge::decode(value).expect("a PA-OTP-CHALLENGE")
}

/// The cookie of a reply, which is where the next round's state lives.
fn cookie_of(data: &[(i32, Vec<u8>)]) -> Vec<u8> {
    data.iter()
        .find(|(t, _)| *t == PA_FX_COOKIE)
        .map(|(_, v)| v.clone())
        .unwrap_or_else(|| {
            panic!(
                "no PA-FX-COOKIE; the reply carried {:?}",
                data.iter().map(|(t, _)| *t).collect::<Vec<_>>()
            )
        })
}

/// The client's `encData`: a `PA-OTP-ENC-REQUEST` holding `nonce`, sealed in `key` under
/// `KEY_USAGE_OTP_REQUEST`.
///
/// `nonce [0]` is IMPLICIT over an OCTET STRING (RFC 6560's module says `IMPLICIT TAGS`), so the
/// field carries the nonce itself and not an OCTET STRING inside it — the same distinction that
/// makes `[2] otp-tokenInfo` a concatenation rather than a wrapper.
fn seal_nonce(key: &Key, nonce: &[u8]) -> EncryptedData {
    let plain = der::seq(&[der::tlv(0x80, nonce)]);
    EncryptedData::seal(&OwnCipher, key, KU_PA_OTP_REQUEST, None, &plain).unwrap()
}

/// A `PA-OTP-REQUEST`: `SEQUENCE { flags [0], nonce [1], encData [2], ..., otp-value [5] }`.
///
/// `otp-value` is sent only when the challenge did not withhold the value — that is the whole
/// difference between the two variants of §3.3.
fn otp_request(value: Option<&str>, enc_data: &EncryptedData) -> Vec<u8> {
    // `[0] flags` is IMPLICIT over a `KerberosFlags`, so the field carries the BIT STRING's content:
    // an unused-bit count and then the bits. `flags32` builds the whole BIT STRING, and its first
    // two octets are the tag and the length.
    let flags = der::flags32(0);
    let enc = enc_data.encode();
    let content = der::as_sequence("PA-OTP-REQUEST encData", &enc).expect("a SEQUENCE");
    let mut fields = vec![
        der::tlv(0x80, &flags[2..]),
        // `[2] encData` is IMPLICIT over an `EncryptedData`: the tag replaces its SEQUENCE tag, so
        // what goes in is that SEQUENCE's content.
        der::tlv(0xa2, content),
    ];
    if let Some(value) = value {
        fields.push(der::tlv(0x85, value.as_bytes()));
    }
    der::seq(&fields)
}

/// The client half of §3.6, written from the formula rather than from the crate.
fn client_keys(armor: &Key, value: &str) -> (Key, Key) {
    use base64::Engine as _;
    let cipher = OwnCipher;
    let enctype = armor.enctype();
    let mut secret = base64::engine::general_purpose::STANDARD
        .encode(value.as_bytes())
        .into_bytes();
    secret.extend_from_slice(b"Krb-preAuth");
    let k2 = cipher
        .s2k(enctype, &secret, &principal("alice").default_salt(), None)
        .unwrap();
    let client =
        rrl_kdc::crypto::kdf::cf2(armor.bytes(), "OTPComb1", enctype, k2.bytes(), "OTPComb2")
            .unwrap();
    let reply =
        rrl_kdc::crypto::kdf::cf2(armor.bytes(), "OTPComb3", enctype, k2.bytes(), "OTPComb4")
            .unwrap();
    (
        Key::new(enctype, client).unwrap(),
        Key::new(enctype, reply).unwrap(),
    )
}

/// The whole exchange: the challenge sets the flag, the client withholds the value, and the KDC
/// accepts a nonce sealed in a key only the value could produce.
#[test]
fn the_value_never_travels_and_the_nonce_proves_it_was_known() {
    let kdc = kdc("123456");
    let armor = armor("alice");
    let data = method_data(
        &kdc.handle_from(&armored_as_req(&armor, "alice", Vec::new()), NOW, None),
        &armor.key,
    );

    let challenge = challenge_of(&data);
    assert!(
        challenge.must_encrypt(),
        "must-encrypt-nonce is set: this realm holds the value and does not want it sent"
    );
    assert!(!challenge.tokens[0].collect_pin(), "no PIN is asked for");
    let cookie = cookie_of(&data);

    // The client's half: keys from the value, nonce sealed in the Client Key, no `otp-value` at all.
    let (client_key, reply_key) = client_keys(&armor.key, "123456");
    let request = otp_request(None, &seal_nonce(&client_key, &challenge.nonce));
    let answer = kdc.handle_from(
        &armored_as_req(
            &armor,
            "alice",
            vec![(PA_OTP_REQUEST, request), (PA_FX_COOKIE, cookie)],
        ),
        NOW,
        None,
    );

    // A granted ticket, not an error: `KRB-ERROR` is application 30 and an AS-REP is not, so its
    // absence from the reply is the proof.
    assert!(
        rrl_kdc::msg::KrbError::decode(&answer).is_err(),
        "the exchange completed: {:?}",
        rrl_kdc::msg::KrbError::decode(&answer).map(|e| (e.code, e.e_text))
    );
    // And the reply key is the derived one, not the armor key — which is what makes the distinction
    // between the two variants visible at all.
    assert_ne!(reply_key.bytes(), armor.key.bytes());
}

/// A wrong value seals the nonce in a key the KDC does not have, and the login fails.
#[test]
fn a_wrong_value_cannot_open_the_nonce() {
    let kdc = kdc("123456");
    let armor = armor("alice");
    let data = method_data(
        &kdc.handle_from(&armored_as_req(&armor, "alice", Vec::new()), NOW, None),
        &armor.key,
    );
    let challenge = challenge_of(&data);
    let cookie = cookie_of(&data);

    // The client guesses 000000 and seals the nonce in the key that guess produces.
    let (wrong_key, _) = client_keys(&armor.key, "000000");
    let answer = kdc.handle_from(
        &armored_as_req(
            &armor,
            "alice",
            vec![
                (
                    PA_OTP_REQUEST,
                    otp_request(None, &seal_nonce(&wrong_key, &challenge.nonce)),
                ),
                (PA_FX_COOKIE, cookie),
            ],
        ),
        NOW,
        None,
    );
    let err = rrl_kdc::msg::KrbError::decode(&answer).expect("a KRB-ERROR");
    assert_eq!(err.code, codes::KDC_ERR_PREAUTH_FAILED);
    assert!(
        err.e_text
            .as_deref()
            .is_some_and(|t| t.contains("did not decrypt")),
        "the refusal names the nonce rather than the token: {:?}",
        err.e_text
    );
}

/// An account this realm holds no value for is refused by name — not as a wrong token, which would
/// send the user to retype a value nothing was compared against.
#[test]
fn an_account_with_no_value_is_refused_by_name() {
    let kdc = kdc("123456");
    let armor = armor("bob");
    let data = method_data(
        &kdc.handle_from(&armored_as_req(&armor, "bob", Vec::new()), NOW, None),
        &armor.key,
    );
    let challenge = challenge_of(&data);
    let cookie = cookie_of(&data);

    // A well-formed request: `bob` has a token, it is just not one whose value this realm knows.
    let key = OwnCipher.random(Enctype::Aes256Sha1).unwrap();
    let answer = kdc.handle_from(
        &armored_as_req(
            &armor,
            "bob",
            vec![
                (
                    PA_OTP_REQUEST,
                    otp_request(None, &seal_nonce(&key, &challenge.nonce)),
                ),
                (PA_FX_COOKIE, cookie),
            ],
        ),
        NOW,
        None,
    );
    let err = rrl_kdc::msg::KrbError::decode(&answer).expect("a KRB-ERROR");
    assert_eq!(err.code, codes::KDC_ERR_PREAUTH_FAILED);
    let text = err.e_text.unwrap_or_default();
    assert!(
        text.contains("no one-time value on record"),
        "the refusal says the realm has no value for him, rather than blaming the value: {text}"
    );
}

/// The other variant, unchanged: a realm with only a verifier asks for the value and judges it.
///
/// This is the test that would have caught a `decode_request` that required `otp-value`
/// unconditionally — a defect the withheld variant found instead, when its own request stopped
/// parsing.
#[test]
fn a_realm_without_the_values_still_takes_the_one_the_client_sends() {
    let kdc = kdc_verifying("123456");
    let armor = armor("alice");
    let data = method_data(
        &kdc.handle_from(&armored_as_req(&armor, "alice", Vec::new()), NOW, None),
        &armor.key,
    );
    let challenge = challenge_of(&data);
    assert!(
        !challenge.must_encrypt(),
        "a realm that cannot obtain the value must not ask for it to be withheld (§3.2)"
    );
    let cookie = cookie_of(&data);

    // §3.6: with the value sent, Client Key and Reply Key are the armor key.
    let request = otp_request(Some("123456"), &seal_nonce(&armor.key, &challenge.nonce));
    let answer = kdc.handle_from(
        &armored_as_req(
            &armor,
            "alice",
            vec![(PA_OTP_REQUEST, request), (PA_FX_COOKIE, cookie)],
        ),
        NOW,
        None,
    );
    assert!(
        rrl_kdc::msg::KrbError::decode(&answer).is_err(),
        "the exchange completed: {:?}",
        rrl_kdc::msg::KrbError::decode(&answer).map(|e| (e.code, e.e_text))
    );
}

/// A value sent although the challenge withheld it is refused, not ignored.
///
/// RFC 6560 §3.3 makes it a MUST NOT. A realm that asked for the value never to travel and then
/// accepted one anyway would have that value in whatever the armor passed through — accepting it
/// does not untravel it, and the client needs to hear that it is the one that is wrong.
#[test]
fn a_value_that_travels_anyway_is_refused() {
    let kdc = kdc("123456");
    let armor = armor("alice");
    let data = method_data(
        &kdc.handle_from(&armored_as_req(&armor, "alice", Vec::new()), NOW, None),
        &armor.key,
    );
    let challenge = challenge_of(&data);
    let cookie = cookie_of(&data);
    let (client_key, _) = client_keys(&armor.key, "123456");

    let request = otp_request(Some("123456"), &seal_nonce(&client_key, &challenge.nonce));
    let answer = kdc.handle_from(
        &armored_as_req(
            &armor,
            "alice",
            vec![(PA_OTP_REQUEST, request), (PA_FX_COOKIE, cookie)],
        ),
        NOW,
        None,
    );
    let err = rrl_kdc::msg::KrbError::decode(&answer).expect("a KRB-ERROR");
    assert_eq!(err.code, codes::KDC_ERR_PREAUTH_FAILED);
    assert!(
        err.e_text
            .as_deref()
            .is_some_and(|t| t.contains("carried it anyway")),
        "the refusal says the rule that was broken: {:?}",
        err.e_text
    );
}
