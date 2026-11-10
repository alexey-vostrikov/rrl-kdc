//! FAST, judged by the property rather than by the encoding.
//!
//! Without FAST the AS exchange hands an attacker an offline password oracle twice:
//! once in `PA-ENC-TIMESTAMP`, sealed directly in the client's long-term key, and once
//! in the reply's `enc-part`, sealed in the same key. Both let a recorded exchange be
//! attacked at leisure.
//!
//! So the test that matters is not "the armored request parses". It is:
//!
//! * the reply's `enc-part` **does not open** with the key derived from the password;
//! * it opens with `cf2(strengthen_key, "strengthenkey", password key, "replykey")`,
//!   where `strengthen_key` is a random value delivered only inside the armor;
//! * the etype information, which carries the salt, is not in the clear either.
//!
//! The request side is checked the same way: the `PA-ENC-TIMESTAMP` the KDC verifies is
//! the one inside the armor, and nothing outside the armor carries it.

use std::sync::Arc;

use rust_kdc::crypto::{Cipher, Enctype, Key, OwnCipher, kdf, usage};
use rust_kdc::der;
use rust_kdc::hdb::{HdbEntry, MemoryHdb};
use rust_kdc::kdc::fast::{self, Armor, ArmoredRequest, FastRequest};
use rust_kdc::kdc::{Kdc, KdcConfig};
use rust_kdc::msg;
use rust_kdc::msg::{
    ApReq, Authenticator, EncTicketPart, EncryptedData, Ticket, encode_enc_ts_enc, encode_pa_data,
    kdc_options, tkt_flags,
};
use rust_kdc::name::Principal;

const REALM: &str = "EXAMPLE.COM";
const PASSWORD: &str = "correct horse battery staple";
const NOW: i64 = 1_700_000_000;

fn alice() -> Principal {
    Principal::parse(&format!("alice@{REALM}")).unwrap()
}

fn db() -> MemoryHdb {
    let cipher = OwnCipher;
    let db = MemoryHdb::new();
    let mut krbtgt = HdbEntry::krbtgt(REALM);
    for e in [Enctype::Aes256Sha1, Enctype::Aes128Sha1] {
        krbtgt
            .add_password_key(&cipher, e, b"master-key-of-the-realm", 1)
            .unwrap();
    }
    db.insert(krbtgt).unwrap();

    let mut user = HdbEntry::user(alice());
    for e in [Enctype::Aes256Sha1, Enctype::Aes128Sha1] {
        user.add_password_key(&cipher, e, PASSWORD.as_bytes(), 1)
            .unwrap();
    }
    db.insert(user).unwrap();
    db
}

fn kdc() -> Kdc {
    Kdc::new(
        KdcConfig::new(REALM).unwrap(),
        Arc::new(db()),
        Arc::new(OwnCipher),
    )
}

/// The `krbtgt` key the armor ticket is sealed with.
fn krbtgt_key() -> Key {
    let mut entry = HdbEntry::krbtgt(REALM);
    entry
        .add_password_key(
            &OwnCipher,
            Enctype::Aes256Sha1,
            b"master-key-of-the-realm",
            1,
        )
        .unwrap();
    entry.key_for(Enctype::Aes256Sha1).unwrap().key.clone()
}

/// The client's long-term key, as the client derives it from the password.
fn client_key() -> Key {
    let raw = kdf::s2k(
        Enctype::Aes256Sha1,
        PASSWORD.as_bytes(),
        format!("{REALM}alice").as_bytes(),
        None,
    )
    .unwrap();
    Key::new(Enctype::Aes256Sha1, raw).unwrap()
}

/// A TGT for `alice`, and its session key — the armor key.
fn armor_ticket() -> (Vec<u8>, Key) {
    let cipher = OwnCipher;
    let session = cipher.random(Enctype::Aes256Sha1).unwrap();
    let part = EncTicketPart {
        flags: tkt_flags::INITIAL | tkt_flags::PRE_AUTHENT,
        session_key: session.clone(),
        crealm: REALM.into(),
        cname: alice(),
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
            &krbtgt_key(),
            usage::KDC_REP_TICKET,
            Some(1),
            &part.encode(),
        )
        .unwrap(),
    };
    (ticket.encode(), session)
}

/// An `AP-REQ` presenting that ticket: the armor value.
fn armor_ap_req(ticket: &[u8], session: &Key) -> Vec<u8> {
    armor_ap_req_at(ticket, session, NOW, 0)
}

/// The same at a chosen `ctime`/`cusec`: the pair is what the replay cache keys on, and
/// what the clock skew is measured against.
fn armor_ap_req_at(ticket: &[u8], session: &Key, ctime: i64, cusec: u32) -> Vec<u8> {
    let authenticator = Authenticator {
        crealm: REALM.into(),
        cname: alice(),
        cksum: None,
        cusec,
        ctime,
        subkey: None,
        seq_number: None,
        authorization_data: None,
    };
    ApReq {
        ap_options: 0,
        ticket: ticket.to_vec(),
        authenticator: EncryptedData::seal(
            &OwnCipher,
            session,
            // RFC 4120 §5.5.1: the AP-REQ authenticator's usage is its own, not the
            // timestamp one — and the armor path decrypts it to read the subkey.
            fast::usage::AP_REQ_AUTH,
            None,
            &authenticator.encode(),
        )
        .unwrap(),
    }
    .encode()
}

/// The `KDC-REQ-BODY` both the outer request and the inner one carry.
fn body(nonce: u32) -> Vec<u8> {
    der::seq(&[
        der::field(0, der::flags32(kdc_options::FORWARDABLE)),
        der::field(1, alice().encode_name()),
        der::field(2, der::general_string(REALM)),
        der::field(3, Principal::krbtgt(REALM).encode_name()),
        der::field(5, der::time(NOW + 3600)),
        der::field(7, der::int(i64::from(nonce))),
        der::field(8, der::seq(&[der::int(18), der::int(17)])),
    ])
}

/// An armored `AS-REQ`, built the way a client that holds a TGT builds one.
fn armored_as_req(nonce: u32) -> (Vec<u8>, Key) {
    armored_as_req_with(nonce, 0)
}

/// The same, with `fast-options` bits set — `0x4000_0000` is `hide-client-names`.
fn armored_as_req_with(nonce: u32, options: u32) -> (Vec<u8>, Key) {
    armored_as_req_at(nonce, options, NOW, 0)
}

/// The same, with the armor authenticator dated at `ctime` and `cusec`.
fn armored_as_req_at(nonce: u32, options: u32, ctime: i64, cusec: u32) -> (Vec<u8>, Key) {
    let cipher = OwnCipher;
    let (ticket, armor_key) = armor_ticket();
    let outer_body = body(nonce);

    // Inside FAST the pre-authentication is the encrypted challenge, not a plain
    // timestamp: the challenge mixes the armor and the long-term key, so it proves both
    // at once and neither alone.
    let challenge_key = fast::client_challenge_key(&armor_key, &client_key()).unwrap();
    let timestamp = EncryptedData::seal(
        &cipher,
        &challenge_key,
        fast::usage::ENC_CHALLENGE_CLIENT,
        None,
        &encode_enc_ts_enc(NOW, None),
    )
    .unwrap();

    // `BIT STRING` content: the unused-bit count, then the bits, bit 0 the most
    // significant — so `hide-client-names`, bit 1, is the high bit of the second octet.
    let inner = FastRequest {
        fast_options: fast::options_bits(options),
        padata: vec![(fast::PA_ENCRYPTED_CHALLENGE, timestamp.encode())],
        req_body: outer_body.clone(),
    };
    let enc = EncryptedData::seal(
        &cipher,
        &armor_key,
        fast::usage::FAST_ENC,
        None,
        &inner.encode(),
    )
    .unwrap();
    let armored = ArmoredRequest {
        armor: Some(Armor {
            armor_type: 1,
            armor_value: armor_ap_req_at(&ticket, &armor_key, ctime, cusec),
        }),
        req_checksum: (
            Enctype::Aes256Sha1.checksum_type(),
            cipher
                .checksum(&armor_key, fast::usage::FAST_REQ_CHKSUM, &outer_body)
                .unwrap(),
        ),
        enc_fast_req: enc.encode(),
    };

    let request = der::cons(
        der::app(10),
        &[der::seq(&[
            der::field(1, der::int(5)),
            der::field(2, der::int(10)),
            der::field(3, encode_pa_data(&[(fast::PA_FX_FAST, armored.encode())])),
            der::field(4, outer_body),
        ])],
    );
    (request, armor_key)
}

/// The `PA-DATA` of a reply, and its ticket.
fn reply_parts(reply: &[u8]) -> (Vec<(i32, Vec<u8>)>, Vec<u8>) {
    let f = der::Fields::parse_app("AS-REP", 11, reply).expect("an AS-REP");
    let padata = match f.opt_bytes(2) {
        None => Vec::new(),
        Some(raw) => {
            let mut r = der::Reader::new(raw);
            let seq = r.next_tlv("PA-DATA").expect("a SEQUENCE of PA-DATA");
            rust_kdc::msg::decode_pa_data("AS-REP", seq.content).expect("PA-DATA")
        }
    };
    (padata, f.bytes(5, "AS-REP").expect("the ticket").to_vec())
}

/// The `EncryptedData` of the reply's `enc-part`.
fn reply_enc_part(reply: &[u8]) -> EncryptedData {
    let f = der::Fields::parse_app("AS-REP", 11, reply).expect("an AS-REP");
    EncryptedData::decode("enc-part", f.bytes(6, "AS-REP").expect("enc-part"))
        .expect("an EncryptedData")
}

/// The `KrbFastResponse` a `PA-FX-FAST-REPLY` carries, decrypted with the armor key.
fn fast_response(reply: &[u8], armor_key: &Key) -> Vec<u8> {
    let (padata, _) = reply_parts(reply);
    let value = padata
        .iter()
        .find(|(t, _)| *t == fast::PA_FX_FAST_REPLY)
        .map(|(_, v)| v.clone())
        .expect("the reply must carry PA-FX-FAST-REPLY");
    let mut r = der::Reader::new(&value);
    let choice = r.next_tlv("PA-FX-FAST-REPLY").unwrap();
    assert_eq!(choice.tag, 0xa0, "armored-data [0]");
    let mut inner = der::Reader::new(choice.content);
    let seq = inner.next_tlv("KrbFastArmoredRep").unwrap();
    let f = der::Fields::parse("KrbFastArmoredRep", seq.content).unwrap();
    let enc = EncryptedData::decode("enc-fast-rep", f.bytes(0, "enc-fast-rep").unwrap()).unwrap();
    let plain = OwnCipher
        .decrypt(armor_key, fast::usage::FAST_REP, &enc.cipher)
        .expect("the armor key opens PA-FX-FAST-REPLY");
    let mut rr = der::Reader::new(&plain);
    let response = rr.next_tlv("KrbFastResponse").unwrap();
    response.content.to_vec()
}

#[test]
fn a_password_login_succeeds_inside_the_armor() {
    let (request, _) = armored_as_req(0x4242);
    let reply = kdc().handle(&request, NOW);
    assert!(
        rust_kdc::msg::KrbError::decode(&reply).is_err(),
        "an armored AS-REQ must be answered with a ticket, not an error: {:?}",
        rust_kdc::msg::KrbError::decode(&reply)
    );
}

#[test]
fn the_reply_does_not_open_with_the_password_key() {
    // **The property FAST exists for.** Before FAST, this decryption succeeds, which is
    // what turns a recorded exchange into an unlimited password oracle. After it, the
    // reply key is `cf2(strengthen_key, "strengthenkey", password key, "replykey")`, and
    // `strengthen_key` is a random value that travelled only inside the armor.
    let (request, _) = armored_as_req(0x4242);
    let reply = kdc().handle(&request, NOW);
    let enc_part = reply_enc_part(&reply);
    let attempt = OwnCipher.decrypt(&client_key(), usage::AS_REP_ENCPART, &enc_part.cipher);
    assert!(
        attempt.is_err(),
        "the reply opened with the key derived from the password, so a recorded \
         exchange can be attacked offline — the very thing FAST exists to prevent"
    );
}

#[test]
fn the_reply_opens_with_the_strengthened_key() {
    // And the legitimate client can still read it: the strengthen key arrives inside
    // the armor, so only the holder of the armor key can rebuild the reply key.
    let (request, armor_key) = armored_as_req(0x4242);
    let reply = kdc().handle(&request, NOW);

    let response = fast_response(&reply, &armor_key);
    let fields = der::Fields::parse("KrbFastResponse", &response).expect("KrbFastResponse");

    let strength = fields
        .opt_bytes(1)
        .map(|raw| {
            let mut r = der::Reader::new(raw);
            let seq = r.next_tlv("EncryptionKey").unwrap();
            rust_kdc::msg::decode_key(seq.content).unwrap()
        })
        .expect("a FAST reply must carry a strengthen key, or the reply is an oracle");

    let strengthened = Key::new(
        strength.enctype(),
        kdf::cf2(
            strength.bytes(),
            "strengthenkey",
            client_key().enctype(),
            client_key().bytes(),
            "replykey",
        )
        .unwrap(),
    )
    .unwrap();

    let enc_part = reply_enc_part(&reply);
    let plain = OwnCipher
        .decrypt(&strengthened, usage::AS_REP_ENCPART, &enc_part.cipher)
        .expect("the strengthened key must open the reply");
    assert!(!plain.is_empty());
}

#[test]
fn the_salt_is_not_in_the_clear() {
    // `PA-ETYPE-INFO2` carries the salt, and a visible salt is one more input to an
    // offline attack. Inside FAST it travels in the armor, so the outer reply must not
    // carry it at all.
    let (request, _) = armored_as_req(0x4242);
    let reply = kdc().handle(&request, NOW);
    let (padata, _) = reply_parts(&reply);
    let outer: Vec<i32> = padata.iter().map(|(t, _)| *t).collect();
    assert!(
        !outer.contains(&rust_kdc::msg::PA_ETYPE_INFO2),
        "the reply carries PA-ETYPE-INFO2 in the clear: {outer:?}"
    );
    assert!(
        outer.contains(&fast::PA_FX_FAST_REPLY),
        "and instead carries the armored reply: {outer:?}"
    );
}

#[test]
fn a_request_whose_armor_is_not_a_tgt_is_refused() {
    // Armor with a ticket for something other than the realm's `krbtgt` would let any
    // service's key open a login it has nothing to do with.
    let cipher = OwnCipher;
    let session = cipher.random(Enctype::Aes256Sha1).unwrap();
    let service = Principal::parse(&format!("host/x@{REALM}")).unwrap();
    let part = EncTicketPart {
        flags: tkt_flags::INITIAL,
        session_key: session.clone(),
        crealm: REALM.into(),
        cname: alice(),
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
        sname: service,
        enc: EncryptedData::seal(
            &cipher,
            &krbtgt_key(),
            usage::KDC_REP_TICKET,
            Some(1),
            &part.encode(),
        )
        .unwrap(),
    };
    let outer_body = body(7);
    let armored = ArmoredRequest {
        armor: Some(Armor {
            armor_type: 1,
            armor_value: armor_ap_req(&ticket.encode(), &session),
        }),
        req_checksum: (
            Enctype::Aes256Sha1.checksum_type(),
            cipher
                .checksum(&session, fast::usage::FAST_REQ_CHKSUM, &outer_body)
                .unwrap(),
        ),
        enc_fast_req: EncryptedData::seal(&cipher, &session, fast::usage::FAST_ENC, None, b"")
            .unwrap()
            .encode(),
    };
    let request = der::cons(
        der::app(10),
        &[der::seq(&[
            der::field(1, der::int(5)),
            der::field(2, der::int(10)),
            der::field(3, encode_pa_data(&[(fast::PA_FX_FAST, armored.encode())])),
            der::field(4, outer_body),
        ])],
    );
    let reply = kdc().handle(&request, NOW);
    let err = rust_kdc::msg::KrbError::decode(&reply).expect("a refusal");
    assert_eq!(
        err.code,
        rust_kdc::error::codes::KRB_AP_ERR_MODIFIED,
        "{}",
        err.e_text.unwrap_or_default()
    );
}

#[test]
fn a_plain_timestamp_inside_the_armor_is_refused() {
    // Accepting it would defeat the armor: a `PA-ENC-TIMESTAMP` in the long-term key is
    // the offline oracle FAST exists to remove, and a stolen TGT would be enough to log
    // in without the password.
    let cipher = OwnCipher;
    let (ticket, armor_key) = armor_ticket();
    let outer_body = body(0x4243);
    let timestamp = EncryptedData::seal(
        &cipher,
        &client_key(),
        usage::AS_REQ_PA_ENC_TS,
        None,
        &encode_enc_ts_enc(NOW, None),
    )
    .unwrap();
    let inner = FastRequest {
        fast_options: vec![0],
        padata: vec![(rust_kdc::msg::PA_ENC_TIMESTAMP, timestamp.encode())],
        req_body: outer_body.clone(),
    };
    let armored = ArmoredRequest {
        armor: Some(Armor {
            armor_type: 1,
            armor_value: armor_ap_req(&ticket, &armor_key),
        }),
        req_checksum: (
            Enctype::Aes256Sha1.checksum_type(),
            cipher
                .checksum(&armor_key, fast::usage::FAST_REQ_CHKSUM, &outer_body)
                .unwrap(),
        ),
        enc_fast_req: EncryptedData::seal(
            &cipher,
            &armor_key,
            fast::usage::FAST_ENC,
            None,
            &inner.encode(),
        )
        .unwrap()
        .encode(),
    };
    let request = der::cons(
        der::app(10),
        &[der::seq(&[
            der::field(1, der::int(5)),
            der::field(2, der::int(10)),
            der::field(3, encode_pa_data(&[(fast::PA_FX_FAST, armored.encode())])),
            der::field(4, outer_body),
        ])],
    );
    let reply = kdc().handle(&request, NOW);
    let err = rust_kdc::msg::KrbError::decode(&reply).expect("a refusal");
    assert_eq!(
        err.code,
        rust_kdc::error::codes::KDC_ERR_PREAUTH_FAILED,
        "{}",
        err.e_text.unwrap_or_default()
    );
}

#[test]
fn the_kdc_proves_it_holds_the_long_term_key() {
    // The reply carries a challenge sealed in `cf2(armor, "kdcchallengearmor", …)`: a
    // value only a server holding the user's long-term key can produce. Without it a
    // relay that passes the armor along could impersonate this KDC.
    let (request, armor_key) = armored_as_req(0x4244);
    let reply = kdc().handle(&request, NOW);
    let response = fast_response(&reply, &armor_key);
    let fields = der::Fields::parse("KrbFastResponse", &response).expect("KrbFastResponse");

    let challenge = fields
        .opt_bytes(0)
        .map(|raw| {
            let mut r = der::Reader::new(raw);
            let seq = r.next_tlv("PA-DATA").unwrap();
            rust_kdc::msg::decode_pa_data("PA-DATA", seq.content).unwrap()
        })
        .unwrap_or_default()
        .into_iter()
        .find(|(t, _)| *t == fast::PA_ENCRYPTED_CHALLENGE)
        .map(|(_, v)| v)
        .expect("the reply must carry PA-ENCRYPTED-CHALLENGE");

    let ed = EncryptedData::decode("PA-ENCRYPTED-CHALLENGE", &challenge).unwrap();
    let key = fast::kdc_challenge_key(&armor_key, &client_key()).unwrap();
    let plain = OwnCipher
        .decrypt(&key, fast::usage::ENC_CHALLENGE_KDC, &ed.cipher)
        .expect("the KDC challenge must open with the long-term key");
    assert!(!plain.is_empty());
}

#[test]
fn the_reply_names_the_ticket_it_answers() {
    // `finished` checksums the ticket, so the reply cannot be paired with a different
    // one on the way back.
    let (request, armor_key) = armored_as_req(0x4245);
    let reply = kdc().handle(&request, NOW);
    let (_, ticket) = reply_parts(&reply);
    let response = fast_response(&reply, &armor_key);
    let fields = der::Fields::parse("KrbFastResponse", &response).expect("KrbFastResponse");

    let finished = fields.opt_bytes(2).expect("KrbFastResponse.finished");
    let mut r = der::Reader::new(finished);
    let seq = r.next_tlv("KrbFastFinished").unwrap();
    let f = der::Fields::parse("KrbFastFinished", seq.content).unwrap();
    let ck = f.bytes(4, "KrbFastFinished ticket-checksum").unwrap();
    let mut cr = der::Reader::new(ck);
    let ckseq = cr.next_tlv("Checksum").unwrap();
    let cf = der::Fields::parse("Checksum", ckseq.content).unwrap();
    // `Fields::get` returns the whole TLV, so the octets are unwrapped explicitly.
    let sum_raw = cf.bytes(1, "Checksum").unwrap();
    let mut sr = der::Reader::new(sum_raw);
    let sum = sr.next_tlv("Checksum.checksum").unwrap().content;
    assert!(
        OwnCipher
            .verify_checksum(&armor_key, fast::usage::FAST_FINISHED, &ticket, sum)
            .is_ok(),
        "the checksum does not cover the ticket that was sent"
    );
}

#[test]
fn hide_client_names_keeps_the_client_out_of_the_reply() {
    // RFC 6113 §5.4.4.2. Without this option the outer AS-REP carries the client's name in
    // cleartext, which is what makes traffic analysis of a Kerberos realm trivial: an
    // observer on the wire learns who logged in, when, and how often.
    let (request, _) = armored_as_req_with(0x4246, fast::HIDE_CLIENT_NAMES);
    let reply = kdc().handle(&request, NOW);
    assert!(
        rust_kdc::msg::KrbError::decode(&reply).is_err(),
        "a request with hide-client-names must still be answered: {:?}",
        rust_kdc::msg::KrbError::decode(&reply)
    );

    let f = der::Fields::parse_app("AS-REP", 11, &reply).expect("an AS-REP");
    let crealm = f.string(3, "AS-REP").unwrap();
    let cname = f
        .opt_bytes(4)
        .map(|raw| {
            let mut r = der::Reader::new(raw);
            let seq = r.next_tlv("cname").unwrap();
            rust_kdc::name::Principal::decode("cname", seq.content, &crealm).unwrap()
        })
        .expect("the reply names some client");
    assert_eq!(crealm, "WELLKNOWN:ANONYMOUS");
    assert_eq!(cname.to_string(), "WELLKNOWN/ANONYMOUS@WELLKNOWN:ANONYMOUS");

    // And the property behind the name: the octets on the wire do not contain the real
    // client's name at all. The ticket is sealed with the service key, so the identity
    // survives only inside it.
    assert!(
        !reply.windows(5).any(|w| w == b"alice"),
        "the reply still carries the client's name in cleartext"
    );
}

#[test]
fn without_the_option_the_reply_names_the_client() {
    // The pair that makes the test above mean something: a reply that never named the
    // client would pass it for the wrong reason.
    let (request, _) = armored_as_req_with(0x4247, 0);
    let reply = kdc().handle(&request, NOW);
    let f = der::Fields::parse_app("AS-REP", 11, &reply).expect("an AS-REP");
    assert_eq!(f.string(3, "AS-REP").unwrap(), REALM);
    assert!(
        reply.windows(5).any(|w| w == b"alice"),
        "the client's name must be in the clear when the option is not requested"
    );
}

#[test]
fn an_unknown_critical_fast_option_is_refused() {
    // Bit 2 (0x2000_0000) is in the critical range and is not defined by RFC 6113: the
    // client asked for behaviour this KDC will not provide, and answering would give it a
    // reply whose guarantees it misreads.
    let (request, armor_key) = armored_as_req_with(0x4248, 0x2000_0000);
    let reply = kdc().handle(&request, NOW);
    let err = rust_kdc::msg::KrbError::decode(&reply)
        .expect("an unknown critical fast-option must be refused");
    assert_eq!(
        err.code,
        rust_kdc::error::codes::KDC_ERR_UNKNOWN_CRITICAL_FAST_OPTIONS,
        "{}",
        err.e_text.clone().unwrap_or_default()
    );
    assert!(
        !err.padata.is_empty() || err.e_data.is_some(),
        "the error must travel inside the armor, so the client can read it"
    );
    let _ = armor_key;
}

#[test]
fn a_non_critical_fast_option_is_ignored() {
    // Bit 16 onwards are non-critical: RFC 6113 requires a conforming KDC to ignore what it
    // does not implement, so bit 16 must not cost the client its ticket.
    let (request, _) = armored_as_req_with(0x4249, 0x0000_8000);
    let reply = kdc().handle(&request, NOW);
    assert!(
        rust_kdc::msg::KrbError::decode(&reply).is_err(),
        "an unknown non-critical option must be ignored: {:?}",
        rust_kdc::msg::KrbError::decode(&reply)
    );
}

#[test]
fn the_same_armor_ap_req_can_come_twice() {
    // Deliberately the opposite of a replay cache, and the live client is the reason:
    // `krb5` 1.0 builds its armor once per login and re-sends the same `AP-REQ` after
    // `PREAUTH_REQUIRED`, when it has the challenge to send. A KDC that refused the second
    // use would fail every login through a real client, and MIT's own KDC accepts it — so
    // the armor is a key identifier, not a single-use token.
    let kdc = kdc();
    let (request, _) = armored_as_req(0x4250);
    let first = kdc.handle(&request, NOW);
    assert!(
        rust_kdc::msg::KrbError::decode(&first).is_err(),
        "the first use must succeed: {:?}",
        rust_kdc::msg::KrbError::decode(&first)
    );
    let second = kdc.handle(&request, NOW);
    assert!(
        rust_kdc::msg::KrbError::decode(&second).is_err(),
        "re-sending the armor AP-REQ must not be refused as a replay: {:?}",
        rust_kdc::msg::KrbError::decode(&second)
    );
}

#[test]
fn a_request_whose_authenticator_is_stale_is_refused() {
    // Outside the skew, an authenticator is either a replay from long ago or a client with
    // a broken clock; both fail before anything is derived from it.
    let (request, _) = armored_as_req_at(0x4251, 0, NOW - 4000, 0);
    let reply = kdc().handle(&request, NOW);
    let err =
        rust_kdc::msg::KrbError::decode(&reply).expect("a stale authenticator must be refused");
    assert_eq!(
        err.code,
        rust_kdc::error::codes::KRB_AP_ERR_SKEW,
        "{}",
        err.e_text.clone().unwrap_or_default()
    );
}

#[test]
fn a_different_microsecond_is_not_a_replay() {
    // The pair that keeps the cache from refusing honest clients: two logins in the same
    // second are two authenticators, and a client is entitled to make both.
    let kdc = kdc();
    let (first_request, _) = armored_as_req_at(0x4252, 0, NOW, 1);
    let (second_request, _) = armored_as_req_at(0x4253, 0, NOW, 2);
    assert!(rust_kdc::msg::KrbError::decode(&kdc.handle(&first_request, NOW)).is_err());
    assert!(
        rust_kdc::msg::KrbError::decode(&kdc.handle(&second_request, NOW)).is_err(),
        "a second login in the same second must not be read as a replay"
    );
}

#[test]
fn a_login_inside_the_armor_marks_the_ticket_pre_authenticated() {
    // The flag a service reads to know the client proved itself. It is computed from a chain
    // of `||` over every method that can authenticate, and a mutation of that chain to `&&`
    // survives everything else in this file: with the armored challenge and no PKINIT, the
    // ticket would be issued *without* `PRE_AUTHENT`, so an armored login would look to the
    // service exactly like a login that proved nothing.
    let (request, armor_key) = armored_as_req(0x5151);
    let kdc = kdc();
    let reply = kdc.handle(&request, NOW);
    assert!(
        msg::KrbError::decode(&reply).is_err(),
        "the armored login must succeed: {:?}",
        msg::KrbError::decode(&reply).ok().map(|e| e.code)
    );

    // Inside FAST the reply is sealed in the strengthened key, so the ticket is the part
    // reachable without opening anything.
    let (_, ticket_der) = reply_parts(&reply);
    let ticket = msg::Ticket::decode(&ticket_der).expect("a Ticket");
    let plain = OwnCipher
        .decrypt(&krbtgt_key(), usage::KDC_REP_TICKET, &ticket.enc.cipher)
        .expect("the ticket opens with krbtgt's key");
    let part = msg::EncTicketPart::decode(&plain).expect("an EncTicketPart");
    assert_ne!(
        part.flags & msg::tkt_flags::PRE_AUTHENT,
        0,
        "a login that presented the armored challenge is pre-authenticated: flags {:#010x}",
        part.flags
    );
    let _ = armor_key;
}
