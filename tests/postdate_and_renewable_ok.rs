//! Postdating and `renewable-ok`: the two things an entry grants that a client can only ask for.
//!
//! `may-postdate` is not a ticket flag a client sets — RFC 4120 §2.4 makes it a promise the KDC
//! makes about *future* requests, so it needs both entries to allow it, and a request that asks
//! for `allow-postdate` from a realm that does not is refused rather than quietly granted nothing.
//! A postdated ticket itself starts at the requested `from` and carries `invalid` until somebody
//! validates it; an acceptor that ignored the flag would honour a ticket before it begins.
//!
//! `renewable-ok` is Heimdal's reading of RFC 4120 §5.4.1: "if you cannot give me a ticket that
//! lives as long as I asked, give me a renewable one". Where the lifetime was granted in full the
//! flag must do nothing — otherwise it means "always renewable" and the client's request stops
//! being a request.

use std::sync::Arc;

use rrl_kdc::crypto::{Cipher, Enctype, Key, OwnCipher, usage};
use rrl_kdc::der;
use rrl_kdc::error::codes;
use rrl_kdc::hdb::{HdbEntry, MemoryHdb, flags as entry_flags};
use rrl_kdc::kdc::{Kdc, KdcConfig, RENEWABLE_OK};
use rrl_kdc::msg::{self, EncKdcRepPart, EncryptedData, encode_pa_data, kdc_options, tkt_flags};
use rrl_kdc::name::Principal;

const REALM: &str = "EXAMPLE.COM";
const PASSWORD: &str = "correct horse battery staple";
const NOW: i64 = 1_700_000_000;

fn alice() -> Principal {
    Principal::parse(&format!("alice@{REALM}")).unwrap()
}

/// A realm where `alice` may be postdated, sealed with `postdate` in both entries or not.
fn realm(postdate: bool) -> (Kdc, Key) {
    let cipher = OwnCipher;
    let db = MemoryHdb::new();

    let mut krbtgt = HdbEntry::krbtgt(REALM);
    let krbtgt_key = cipher.random(Enctype::Aes256Sha1).unwrap();
    krbtgt.add_key(krbtgt_key.clone(), 1, None);
    if postdate {
        krbtgt.flags |= entry_flags::POSTDATE;
    }
    db.insert(krbtgt).unwrap();

    let mut user = HdbEntry::user(alice());
    user.flags &= !entry_flags::REQUIRE_PREAUTH;
    if postdate {
        user.flags |= entry_flags::POSTDATE;
    }
    user.add_password_key(&cipher, Enctype::Aes256Sha1, PASSWORD.as_bytes(), 1)
        .unwrap();
    db.insert(user).unwrap();

    (
        Kdc::new(
            KdcConfig::new(REALM).unwrap().with_require_preauth(false),
            Arc::new(db),
            Arc::new(OwnCipher),
        ),
        krbtgt_key,
    )
}

/// A `PA-ENC-TIMESTAMP` for `alice`'s password.
fn enc_timestamp() -> Vec<u8> {
    let cipher = OwnCipher;
    let key = cipher
        .s2k(
            Enctype::Aes256Sha1,
            PASSWORD.as_bytes(),
            format!("{REALM}alice").as_bytes(),
            None,
        )
        .unwrap();
    EncryptedData::seal(
        &cipher,
        &key,
        usage::AS_REQ_PA_ENC_TS,
        None,
        &rrl_kdc::msg::encode_enc_ts_enc(NOW, None),
    )
    .unwrap()
    .encode()
}

/// An `AS-REQ` for `alice` with `options`, and `from` when the request is postdated.
fn as_req(options: u32, from: Option<i64>, till: i64) -> Vec<u8> {
    let mut body = vec![
        der::field(0, der::flags32(options)),
        der::field(1, alice().encode_name()),
        der::field(2, der::general_string(REALM)),
        der::field(3, Principal::krbtgt(REALM).encode_name()),
        der::field(5, der::time(till)),
        der::field(7, der::int(0x1234_5678)),
        der::field(8, der::seq(&[der::int(18)])),
    ];
    if let Some(from) = from {
        body.insert(4, der::field(4, der::time(from)));
    }
    der::cons(
        der::app(10),
        &[der::seq(&[
            der::field(1, der::int(5)),
            der::field(2, der::int(10)),
            der::field(
                3,
                encode_pa_data(&[(msg::PA_ENC_TIMESTAMP, enc_timestamp())]),
            ),
            der::field(4, der::seq(&body)),
        ])],
    )
}

/// The `EncASRepPart` of a reply, opened with `alice`'s password key.
fn reply_part(reply: &[u8]) -> EncKdcRepPart {
    let cipher = OwnCipher;
    let key = cipher
        .s2k(
            Enctype::Aes256Sha1,
            PASSWORD.as_bytes(),
            format!("{REALM}alice").as_bytes(),
            None,
        )
        .unwrap();
    let f = der::Fields::parse_app("AS-REP", 11, reply).unwrap_or_else(|_| {
        panic!(
            "the request was refused: {:?}",
            msg::KrbError::decode(reply).map(|e| (e.code, e.e_text))
        )
    });
    let enc = EncryptedData::decode("enc-part", f.bytes(6, "AS-REP").expect("enc-part")).unwrap();
    let plain = cipher
        .decrypt(&key, usage::AS_REP_ENCPART, &enc.cipher)
        .expect("the reply opens with the client's key");
    EncKdcRepPart::decode(&plain).expect("an EncASRepPart")
}

/// `allow-postdate` from a realm that allows it: the flag is set, and the ticket is not postdated
/// itself — asking to *be allowed* to postdate later is not asking for a postdated ticket.
#[test]
fn may_postdate_is_granted_when_both_entries_allow_it() {
    let (kdc, _) = realm(true);
    let reply = kdc.handle(&as_req(kdc_options::ALLOW_POSTDATE, None, NOW + 3600), NOW);
    let part = reply_part(&reply);
    assert_ne!(part.flags & tkt_flags::MAY_POSTDATE, 0);
    assert_eq!(part.flags & tkt_flags::INVALID, 0);
    assert_eq!(part.flags & tkt_flags::POSTDATED, 0);
}

/// The same request from a realm whose entries forbid postdating is refused, not silently granted
/// without the flag: a client reads the flag to decide whether a later postdated request can work.
#[test]
fn may_postdate_is_refused_with_policy_when_the_entry_forbids_it() {
    let (kdc, _) = realm(false);
    let reply = kdc.handle(&as_req(kdc_options::ALLOW_POSTDATE, None, NOW + 3600), NOW);
    let err = msg::KrbError::decode(&reply).expect("a refusal");
    assert_eq!(err.code, codes::KDC_ERR_POLICY, "{err:?}");
}

/// A postdated ticket starts when it says, and is `invalid` until validated.
#[test]
fn a_postdated_ticket_starts_later_and_is_invalid() {
    let (kdc, _) = realm(true);
    let from = NOW + 1800;
    let reply = kdc.handle(
        &as_req(
            kdc_options::ALLOW_POSTDATE | kdc_options::POSTDATED,
            Some(from),
            NOW + 7200,
        ),
        NOW,
    );
    let part = reply_part(&reply);
    assert_eq!(part.starttime, Some(from), "it starts when it was told to");
    assert_ne!(
        part.flags & tkt_flags::INVALID,
        0,
        "an acceptor must refuse it before then"
    );
    assert_ne!(part.flags & tkt_flags::POSTDATED, 0);
    assert_eq!(part.authtime, NOW, "authtime is when it was issued");
}

/// `renewable-ok` where the lifetime was cut short: a renewable ticket reaching the requested
/// `till`.
#[test]
fn renewable_ok_turns_a_short_ticket_into_a_renewable_one() {
    let (kdc, _) = realm(true);
    let max_life = KdcConfig::new(REALM).unwrap().max_life();
    let asked = NOW + max_life * 2;
    let reply = kdc.handle(&as_req(RENEWABLE_OK, None, asked), NOW);
    let part = reply_part(&reply);
    assert_eq!(part.endtime, NOW + max_life, "shorter than asked");
    assert_ne!(part.flags & tkt_flags::RENEWABLE, 0);
    assert_eq!(
        part.renew_till,
        Some(asked),
        "the renewable lifetime has to reach what the client asked for"
    );
}

/// And where it was not cut short, nothing happens: the flag is a fallback, not a request for
/// renewability.
#[test]
fn renewable_ok_does_nothing_when_the_lifetime_was_granted() {
    let (kdc, _) = realm(true);
    let reply = kdc.handle(&as_req(RENEWABLE_OK, None, NOW + 600), NOW);
    let part = reply_part(&reply);
    assert_eq!(part.endtime, NOW + 600);
    assert_eq!(part.flags & tkt_flags::RENEWABLE, 0);
    assert_eq!(part.renew_till, None);
}
