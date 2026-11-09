//! The refusal paths of the armored TGS exchange.
//!
//! `tests/fast_tgs.rs` has the primary client prove the happy path. This file builds the
//! requests by hand, because a well-behaved client cannot produce a request with an
//! explicit armor ticket, a missing `PA-TGS-REQ`, an authenticator without a subkey, or an
//! undefined critical fast-option — and each of those must fail with a reason an operator
//! can act on, not with a ticket.
//!
//! The shapes are the ones RFC 6113 §5.4.2.6 defines: the body travels both outside the
//! armor and inside it, `PA-TGS-REQ` stays outside, and the request checksum covers the
//! `AP-REQ`.

use std::sync::Arc;

use rust_kdc::crypto::{Cipher, Enctype, Key, OwnCipher, usage};
use rust_kdc::der;
use rust_kdc::error::codes;
use rust_kdc::hdb::{HdbEntry, MemoryHdb};
use rust_kdc::kdc::fast::{self, Armor, ArmoredRequest, FastRequest};
use rust_kdc::kdc::{Kdc, KdcConfig};
use rust_kdc::msg::{
    self, ApReq, Authenticator, EncTicketPart, EncryptedData, Ticket, encode_pa_data, kdc_options,
    tkt_flags,
};
use rust_kdc::name::Principal;

const REALM: &str = "EXAMPLE.COM";
const SERVICE: &str = "host/server.example.com";
const NOW: i64 = 1_700_000_000;

fn alice() -> Principal {
    Principal::parse(&format!("alice@{REALM}")).unwrap()
}

fn service() -> Principal {
    Principal::parse(&format!("{SERVICE}@{REALM}")).unwrap()
}

fn realm() -> (MemoryHdb, Key) {
    let cipher = OwnCipher;
    let db = MemoryHdb::new();

    let mut krbtgt = HdbEntry::krbtgt(REALM);
    let krbtgt_key = cipher.random(Enctype::Aes256Sha1).unwrap();
    krbtgt.add_key(krbtgt_key.clone(), 1, None);
    db.insert(krbtgt).unwrap();

    let mut user = HdbEntry::user(alice());
    user.add_password_key(&cipher, Enctype::Aes256Sha1, b"password", 1)
        .unwrap();
    db.insert(user).unwrap();

    let mut svc = HdbEntry::service(service());
    svc.add_password_key(
        &cipher,
        Enctype::Aes256Sha1,
        b"the-service-key-which-nobody-knows",
        1,
    )
    .unwrap();
    db.insert(svc).unwrap();

    (db, krbtgt_key)
}

fn kdc() -> (Kdc, Key) {
    let (db, krbtgt_key) = realm();
    (
        Kdc::new(
            KdcConfig::new(REALM).unwrap(),
            Arc::new(db),
            Arc::new(OwnCipher),
        ),
        krbtgt_key,
    )
}

/// A TGT as the AS exchange would have issued it.
struct Tgt {
    ticket: Vec<u8>,
    session_key: Key,
}

fn tgt(krbtgt_key: &Key) -> Tgt {
    let cipher = OwnCipher;
    let session_key = cipher.random(Enctype::Aes256Sha1).unwrap();
    let part = EncTicketPart {
        flags: tkt_flags::INITIAL | tkt_flags::PRE_AUTHENT,
        session_key: session_key.clone(),
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

/// The `KDC-REQ-BODY` of a TGS request for `service`.
fn body(nonce: u32) -> Vec<u8> {
    der::seq(&[
        der::field(0, der::flags32(kdc_options::FORWARDABLE)),
        der::field(2, der::general_string(REALM)),
        der::field(3, service().encode_name()),
        der::field(5, der::time(NOW + 3600)),
        der::field(7, der::int(i64::from(nonce))),
        der::field(8, der::seq(&[der::int(18)])),
    ])
}

/// What the test can vary about the request it builds.
struct Knobs {
    /// Put a subkey in the authenticator. The implicit armor key cannot exist without
    /// one, so `false` is the "client forgot" case.
    subkey: bool,
    /// Send `PA-FX-FAST` but no `PA-TGS-REQ`.
    no_evidence: bool,
    /// Send an explicit armor ticket in the `PA-FX-FAST` structure.
    explicit_armor: bool,
    /// The fast-options bits.
    options: u32,
}

impl Default for Knobs {
    fn default() -> Self {
        Knobs {
            subkey: true,
            no_evidence: false,
            explicit_armor: false,
            options: 0,
        }
    }
}

/// An armored `TGS-REQ`, built the way RFC 6113 §5.4.2.6 describes, with the armor key the
/// client derived — the tests that open the reply need it, and recomputing it from the
/// ticket's session key would be a different key.
fn armored_tgs(tgt: &Tgt, knobs: Knobs) -> (Vec<u8>, Option<Key>) {
    let cipher = OwnCipher;
    let nonce = 0x4242u32;
    let body = body(nonce);
    let subkey = knobs
        .subkey
        .then(|| cipher.random(Enctype::Aes256Sha1).unwrap());

    // The authenticator's checksum covers the body, not the AP-REQ: the body is sent both
    // outside and inside, and a client that checksummed the AP-REQ would be checksumming
    // the container rather than the request.
    let cksum = cipher
        .checksum(&tgt.session_key, usage::TGS_REQ_AUTH_CKSUM, &body)
        .unwrap();
    let authenticator = Authenticator {
        crealm: REALM.into(),
        cname: alice(),
        cksum: Some((Enctype::Aes256Sha1.checksum_type(), cksum)),
        cusec: 0,
        ctime: NOW,
        subkey: subkey.clone(),
        seq_number: None,
        authorization_data: None,
    };
    let ap_req = ApReq {
        ap_options: 0,
        ticket: tgt.ticket.clone(),
        authenticator: EncryptedData::seal(
            &cipher,
            &tgt.session_key,
            usage::TGS_REQ_AUTH,
            None,
            &authenticator.encode(),
        )
        .unwrap(),
    }
    .encode();

    let inner = FastRequest {
        fast_options: fast::options_bits(knobs.options),
        padata: Vec::new(),
        req_body: body.clone(),
    };

    let mut padata = Vec::new();
    let mut armor_key_out = None;
    if !knobs.no_evidence {
        padata.push((msg::PA_TGS_REQ, ap_req.clone()));
    }

    // The armor key is derived from the subkey the client just sent, which is the whole
    // point of the implicit form: no second ticket is needed.
    //
    // Without a subkey there is no key to derive, and a real client would have nothing to
    // encrypt with — but the KDC must still refuse rather than answer, so the test sends
    // the structure under a key of its own. The refusal happens before anything is read
    // from it, which is exactly what the test is checking.
    if true {
        let armor_key = match &subkey {
            Some(subkey) => fast::implicit_armor_key(subkey, &tgt.session_key).unwrap(),
            None => cipher.random(Enctype::Aes256Sha1).unwrap(),
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
            armor: knobs.explicit_armor.then(|| Armor {
                armor_type: 1,
                armor_value: Vec::new(),
            }),
            req_checksum: (
                Enctype::Aes256Sha1.checksum_type(),
                cipher
                    .checksum(&armor_key, fast::usage::FAST_REQ_CHKSUM, &ap_req)
                    .unwrap(),
            ),
            enc_fast_req: enc.encode(),
        };
        padata.push((fast::PA_FX_FAST, armored.encode()));
        // Only a key the client could have derived is useful to a caller.
        armor_key_out = subkey.is_some().then_some(armor_key);
    }

    let mut parts = vec![der::field(1, der::int(5)), der::field(2, der::int(12))];
    if !padata.is_empty() {
        parts.push(der::field(3, encode_pa_data(&padata)));
    }
    parts.push(der::field(4, body));
    (der::cons(der::app(12), &[der::seq(&parts)]), armor_key_out)
}

fn error_of(reply: &[u8]) -> msg::KrbError {
    msg::KrbError::decode(reply)
        .unwrap_or_else(|e| panic!("expected a KRB-ERROR, got a reply this test cannot read: {e}"))
}

#[test]
fn an_explicit_armor_ticket_is_refused_by_name() {
    // Legal under the RFC and not implemented here. The client asked for a *different*
    // ticket to armor the exchange, and answering as though the implicit armor had been
    // used would silently substitute one ticket for another.
    let (kdc, krbtgt_key) = kdc();
    let tgt = tgt(&krbtgt_key);
    let (request, _) = armored_tgs(
        &tgt,
        Knobs {
            explicit_armor: true,
            ..Default::default()
        },
    );
    let reply = kdc.handle(&request, NOW);
    let err = error_of(&reply);
    assert_eq!(err.code, codes::KDC_ERR_PREAUTH_FAILED);
    let text = err.e_text.unwrap_or_default();
    assert!(
        text.contains("explicit armor"),
        "the refusal must say which form is unsupported: {text}"
    );
}

#[test]
fn armor_without_pa_tgs_req_has_nothing_to_derive_a_key_from() {
    // The implicit armor key comes from the `PA-TGS-REQ` subkey and the TGT's session key.
    // Without the AP-REQ there is neither, and the only honest answer is a refusal.
    let (kdc, krbtgt_key) = kdc();
    let tgt = tgt(&krbtgt_key);
    let (request, _) = armored_tgs(
        &tgt,
        Knobs {
            no_evidence: true,
            ..Default::default()
        },
    );
    let reply = kdc.handle(&request, NOW);
    let err = error_of(&reply);
    assert_eq!(
        err.code,
        codes::KRB_AP_ERR_MODIFIED,
        "{}",
        err.e_text.clone().unwrap_or_default()
    );
    assert!(
        err.e_text.unwrap_or_default().contains("PA-TGS-REQ"),
        "the refusal must name the missing field"
    );
}

#[test]
fn an_authenticator_without_a_subkey_cannot_armor() {
    // Without a subkey the client has no secret to mix into the armor key, so the armored
    // body cannot be opened. Saying so beats failing later on a checksum mismatch, which
    // would read as a corrupted request.
    let (kdc, krbtgt_key) = kdc();
    let tgt = tgt(&krbtgt_key);
    let (request, _) = armored_tgs(
        &tgt,
        Knobs {
            subkey: false,
            ..Default::default()
        },
    );
    let reply = kdc.handle(&request, NOW);
    let err = error_of(&reply);
    assert_eq!(err.code, codes::KRB_AP_ERR_MODIFIED);
    let text = err.e_text.unwrap_or_default();
    assert!(
        text.contains("subkey"),
        "the refusal must name what is missing: {text}"
    );
    assert!(
        text.contains("subkeyarmor"),
        "and the construction that needs it: {text}"
    );
}

#[test]
fn an_unknown_critical_option_is_refused_in_a_tgs_request_too() {
    // The same rule as in the AS exchange, because §5.4.4.2 has no notion of which
    // exchange it is in. Bit 2 is critical and undefined.
    let (kdc, krbtgt_key) = kdc();
    let tgt = tgt(&krbtgt_key);
    let (request, _) = armored_tgs(
        &tgt,
        Knobs {
            options: 0x2000_0000,
            ..Default::default()
        },
    );
    let reply = kdc.handle(&request, NOW);
    let err = error_of(&reply);
    assert_eq!(
        err.code,
        codes::KDC_ERR_UNKNOWN_CRITICAL_FAST_OPTIONS,
        "{}",
        err.e_text.clone().unwrap_or_default()
    );
}

#[test]
fn hide_client_names_hides_the_client_in_a_tgs_reply() {
    // The outer TGS-REP carries `crealm`/`cname` in cleartext, exactly as the AS-REP does,
    // so the option has to apply here or it would leak the name one exchange later.
    let (kdc, krbtgt_key) = kdc();
    let tgt = tgt(&krbtgt_key);
    let (request, _) = armored_tgs(
        &tgt,
        Knobs {
            options: fast::HIDE_CLIENT_NAMES,
            ..Default::default()
        },
    );
    let reply = kdc.handle(&request, NOW);
    assert!(
        msg::KrbError::decode(&reply).is_err(),
        "the request must be answered: {:?}",
        msg::KrbError::decode(&reply)
    );
    let f = der::Fields::parse_app("TGS-REP", 13, &reply).expect("a TGS-REP");
    assert_eq!(f.string(3, "TGS-REP").unwrap(), "WELLKNOWN:ANONYMOUS");
    assert!(
        !reply.windows(5).any(|w| w == b"alice"),
        "the client's name must not be in the clear"
    );
}

#[test]
fn without_the_option_the_tgs_reply_names_the_client() {
    // The pair that keeps the test above from passing for the wrong reason.
    let (kdc, krbtgt_key) = kdc();
    let tgt = tgt(&krbtgt_key);
    let (request, _) = armored_tgs(&tgt, Knobs::default());
    let reply = kdc.handle(&request, NOW);
    assert!(
        msg::KrbError::decode(&reply).is_err(),
        "a plain armored request must be answered: {:?}",
        msg::KrbError::decode(&reply)
    );
    let f = der::Fields::parse_app("TGS-REP", 13, &reply).expect("a TGS-REP");
    assert_eq!(f.string(3, "TGS-REP").unwrap(), REALM);
    assert!(
        reply.windows(5).any(|w| w == b"alice"),
        "the client's name must be in the clear when the option is not requested"
    );
}

#[test]
fn the_armored_tgs_reply_carries_a_finished_checksum_over_the_ticket() {
    // `finished` is what makes the reply provably the answer to this request: the checksum
    // is taken over the ticket in usage 53, so a reply cannot be paired with a different
    // ticket on the way back. A client that reads it can tell; one that ignores it cannot,
    // which is why the test reads it here rather than trusting the field's presence.
    let (kdc, krbtgt_key) = kdc();
    let tgt = tgt(&krbtgt_key);
    let (request, armor_key) = armored_tgs(&tgt, Knobs::default());
    let armor_key = armor_key.expect("the request was armored, so a key was derived");
    let reply = kdc.handle(&request, NOW);
    assert!(
        msg::KrbError::decode(&reply).is_err(),
        "the request must be answered: {:?}",
        msg::KrbError::decode(&reply)
    );

    let f = der::Fields::parse_app("TGS-REP", 13, &reply).expect("a TGS-REP");
    let padata = match f.opt(2) {
        None => Vec::new(),
        Some(raw) => {
            let mut r = der::Reader::new(raw);
            let seq = r.next("PA-DATA").expect("a SEQUENCE");
            msg::decode_pa_data("TGS-REP", seq.content).expect("PA-DATA")
        }
    };
    let wrapped = padata
        .iter()
        .find(|(t, _)| *t == fast::PA_FX_FAST_REPLY)
        .map(|(_, v)| v.clone())
        .expect("an armored reply must carry PA-FX-FAST-REPLY");

    // `PA-FX-FAST-REPLY ::= [0] KrbFastArmoredRep { enc-fast-rep [0] }`.
    let mut r = der::Reader::new(&wrapped);
    let choice = r.next("PA-FX-FAST-REPLY").expect("the choice");
    assert_eq!(choice.tag, 0xa0, "armored-data [0]");
    let mut inner = der::Reader::new(choice.content);
    let seq = inner.next("KrbFastArmoredRep").expect("a SEQUENCE");
    let af = der::Fields::parse("KrbFastArmoredRep", seq.content).expect("fields");
    let enc = EncryptedData::decode("enc-fast-rep", af.get(0, "enc-fast-rep").unwrap())
        .expect("an EncryptedData");
    let plain = OwnCipher
        .decrypt(&armor_key, fast::usage::FAST_REP, &enc.cipher)
        .expect("the armor key must open the reply");

    let mut pr = der::Reader::new(&plain);
    let response = pr.next("KrbFastResponse").expect("a KrbFastResponse");
    let rf = der::Fields::parse("KrbFastResponse", response.content).expect("fields");
    let finished_tlv = rf.opt(2).expect("KrbFastResponse.finished");
    let mut fr = der::Reader::new(finished_tlv);
    let fin_seq = fr.next("KrbFastFinished").expect("a SEQUENCE");
    let finf = der::Fields::parse("KrbFastFinished", fin_seq.content).expect("fields");

    let ticket_tlv = f.get(5, "TGS-REP").expect("the ticket");
    let mut tr = der::Reader::new(ticket_tlv);
    let ticket_seq = tr.next("Ticket").expect("a SEQUENCE");
    let ticket_der = der::tlv(der::app(1), ticket_seq.content);

    let ck = finf.get(4, "ticket-checksum").expect("the checksum");
    let mut cr = der::Reader::new(ck);
    let ck_seq = cr.next("Checksum").expect("a SEQUENCE");
    let ckf = der::Fields::parse("Checksum", ck_seq.content).expect("fields");
    let sum_tlv = ckf.get(1, "Checksum").expect("the checksum octets");
    let mut sr = der::Reader::new(sum_tlv);
    let sum = sr.next("checksum").expect("an OCTET STRING").content;

    assert!(
        OwnCipher
            .verify_checksum(&armor_key, fast::usage::FAST_FINISHED, &ticket_der, sum)
            .is_ok(),
        "the finished checksum must cover the ticket that was sent"
    );
}
