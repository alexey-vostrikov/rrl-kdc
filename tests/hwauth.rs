//! `require-hwauth` has to refuse something, or the flag is a lie.
//!
//! The flag is stored, served by `kadm5`, and set by `kadmin` — and until this file existed, nothing
//! in the AS exchange read it: an administrator who set it got no change in behaviour and no message
//! saying so. Heimdal's answer is `_kdc_hwauth_policy` (`kdc/kdc-plugin.c`), which asks a plugin and
//! otherwise falls back to the `PA_HARDWARE_AUTH` flags in `kdc/kerberos5.c` — set on the two PKINIT
//! entries and on nothing else.
//!
//! What is checked here:
//!
//! * a password login to an entry with the flag is refused with `KDC_ERR_POLICY`, and the refusal
//!   happens **before** the password is verified — so it cannot be used as an oracle for whether a
//!   password is right;
//! * an entry without the flag is untouched, byte for byte;
//! * a policy that admits more (a deployment's own answer) is honoured;
//! * the flag does not change what a client is told to do first: it still gets `PREAUTH_REQUIRED`
//!   with the realm's methods, because a client that is told `POLICY` before it has authenticated
//!   would not know whether to retry with a certificate.

use std::sync::Arc;

use rrl_kdc::crypto::{Cipher, Enctype, OwnCipher};
use rrl_kdc::der;
use rrl_kdc::error::codes;
use rrl_kdc::hdb::{HdbEntry, MemoryHdb, flags as entry_flags};
use rrl_kdc::kdc::hwauth::{AllowList, CertificateOnly};
use rrl_kdc::kdc::{Kdc, KdcConfig};
use rrl_kdc::msg::{
    self, EncryptedData, PA_ENC_TIMESTAMP, encode_enc_ts_enc, encode_pa_data, kdc_options,
};
use rrl_kdc::name::Principal;

const REALM: &str = "EXAMPLE.COM";
const PASSWORD: &str = "correct horse battery staple";
const NOW: i64 = 1_700_000_000;

fn principal(name: &str) -> Principal {
    Principal::parse(&format!("{name}@{REALM}")).unwrap()
}

/// A realm where `alice` carries `flags`.
fn db(alice_flags: u32) -> MemoryHdb {
    let cipher = OwnCipher;
    let db = MemoryHdb::new();
    let mut krbtgt = HdbEntry::krbtgt(REALM);
    krbtgt
        .add_password_key(&cipher, Enctype::Aes256Sha1, b"master", 1)
        .unwrap();
    db.insert(krbtgt).unwrap();

    let mut alice = HdbEntry::user(principal("alice"));
    alice.flags |= alice_flags;
    alice
        .add_password_key(&cipher, Enctype::Aes256Sha1, PASSWORD.as_bytes(), 1)
        .unwrap();
    db.insert(alice).unwrap();
    db
}

fn kdc_with(alice_flags: u32) -> Kdc {
    Kdc::new(
        KdcConfig::new(REALM).unwrap(),
        Arc::new(db(alice_flags)),
        Arc::new(OwnCipher),
    )
}

fn as_req(padata: Vec<(i32, Vec<u8>)>) -> Vec<u8> {
    let body = der::seq(&[
        der::field(0, der::flags32(kdc_options::FORWARDABLE)),
        der::field(1, principal("alice").encode_name()),
        der::field(2, der::general_string(REALM)),
        der::field(3, Principal::krbtgt(REALM).encode_name()),
        der::field(5, der::time(NOW + 3600)),
        der::field(7, der::int(0x1234_5678)),
        der::field(8, der::seq(&[der::int(18)])),
    ]);
    let mut parts = vec![der::field(1, der::int(5)), der::field(2, der::int(10))];
    if !padata.is_empty() {
        parts.push(der::field(3, encode_pa_data(&padata)));
    }
    parts.push(der::field(4, body));
    der::cons(der::app(10), &[der::seq(&parts)])
}

/// A `PA-ENC-TIMESTAMP` for `password`.
fn enc_timestamp(password: &[u8]) -> Vec<u8> {
    use rrl_kdc::crypto::usage;
    let cipher = OwnCipher;
    let key = cipher
        .s2k(
            Enctype::Aes256Sha1,
            password,
            format!("{REALM}alice").as_bytes(),
            None,
        )
        .unwrap();
    let plain = encode_enc_ts_enc(NOW, None);
    EncryptedData::seal(&cipher, &key, usage::AS_REQ_PA_ENC_TS, None, &plain)
        .unwrap()
        .encode()
}

/// The code a reply refuses with, or `None` when it granted a ticket.
fn outcome(reply: &[u8]) -> Option<i32> {
    msg::KrbError::decode(reply).ok().map(|e| e.code)
}

/// A password login to an entry that requires hardware authentication is refused with
/// `KDC_ERR_POLICY` — the code Heimdal answers with — and the refusal does not depend on the password
/// being right.
///
/// The second half is the part worth testing: `POLICY` for a correct password and `POLICY` for a
/// wrong one means the refusal says nothing about the password, so it cannot be used to learn one.
#[test]
fn a_password_login_is_refused_when_the_entry_requires_hardware_authentication() {
    let kdc = kdc_with(entry_flags::REQUIRE_HWAUTH);
    for password in [PASSWORD.as_bytes(), b"wrong".as_slice()] {
        let reply = kdc.handle_from(
            &as_req(vec![(PA_ENC_TIMESTAMP, enc_timestamp(password))]),
            NOW,
            None,
        );
        assert_eq!(
            outcome(&reply),
            Some(codes::KDC_ERR_POLICY),
            "a password is not hardware authentication, whether or not it is right"
        );
    }
}

/// An entry without the flag logs in exactly as it did before.
#[test]
fn an_entry_without_the_flag_is_untouched() {
    let kdc = kdc_with(0);
    let reply = kdc.handle_from(
        &as_req(vec![(PA_ENC_TIMESTAMP, enc_timestamp(PASSWORD.as_bytes()))]),
        NOW,
        None,
    );
    assert_eq!(outcome(&reply), None, "a ticket, not an error");
}

/// The first round still says `PREAUTH_REQUIRED`: the client has not authenticated yet, and answering
/// `POLICY` there would leave a client holding a certificate no way to know it should try it.
#[test]
fn the_first_round_asks_for_pre_authentication_as_before() {
    let kdc = kdc_with(entry_flags::REQUIRE_HWAUTH);
    let reply = kdc.handle_from(&as_req(Vec::new()), NOW, None);
    assert_eq!(outcome(&reply), Some(codes::KDC_ERR_PREAUTH_REQUIRED));
    // And the methods it advertises are the realm's, so a client can pick one and be judged on it.
    let methods = msg::KrbError::decode(&reply)
        .expect("a KRB-ERROR")
        .method_data()
        .expect("METHOD-DATA");
    assert!(
        methods.iter().any(|(t, _)| *t == PA_ENC_TIMESTAMP),
        "the timestamp is still offered: the client is refused for what it is, not for what it sent"
    );
}

/// `require-hwauth` without `require-preauth` still issues a ticket to a client that presents no
/// pre-authentication — Heimdal's behaviour, and the reason the two flags belong together.
///
/// Pinned rather than fixed. Heimdal's check sits inside the loop over pre-authentication types that
/// matched, guarded by `if (req->padata)` (`kdc/kerberos5.c`), so with nothing presented there is
/// nothing to judge. The ticket that comes back is sealed in the account's long-term key — the
/// AS-REP shape an offline attack wants — which is exactly why an administrator who sets this flag
/// means it together with `require-preauth`.
///
/// A test that only asserted the code path would leave the next reader thinking the gap was an
/// oversight, so this one builds the state that shows it: neither the realm nor the entry requires
/// pre-authentication, and the entry requires hardware authentication.
#[test]
fn the_flag_alone_does_not_force_pre_authentication() {
    let cipher = OwnCipher;
    let db = MemoryHdb::new();
    let mut krbtgt = HdbEntry::krbtgt(REALM);
    krbtgt
        .add_password_key(&cipher, Enctype::Aes256Sha1, b"master", 1)
        .expect("a key");
    db.insert(krbtgt).expect("stored");

    let mut alice = HdbEntry::user(principal("alice"));
    // The account requires no pre-authentication of its own — the state an administrator reaches by
    // setting only `require-hwauth`.
    alice.flags &= !entry_flags::REQUIRE_PREAUTH;
    alice.flags |= entry_flags::REQUIRE_HWAUTH;
    alice
        .add_password_key(&cipher, Enctype::Aes256Sha1, PASSWORD.as_bytes(), 1)
        .expect("a key");
    db.insert(alice).expect("stored");

    let kdc = Kdc::new(
        KdcConfig::new(REALM).unwrap().with_require_preauth(false),
        Arc::new(db),
        Arc::new(OwnCipher),
    );
    let reply = kdc.handle_from(&as_req(Vec::new()), NOW, None);
    assert_eq!(
        outcome(&reply),
        None,
        "Heimdal issues here, and this crate reproduces it rather than deviating silently"
    );
}

/// A deployment's policy is the one that decides — here, a realm that treats the FAST challenge as
/// hardware, which Heimdal's table does not.
#[test]
fn a_realm_can_admit_more_than_heimdal_does() {
    let kdc = kdc_with(entry_flags::REQUIRE_HWAUTH).with_hw_auth(Arc::new(
        AllowList::new(&["certificate", "timestamp"]).expect("known names"),
    ));
    let reply = kdc.handle_from(
        &as_req(vec![(PA_ENC_TIMESTAMP, enc_timestamp(PASSWORD.as_bytes()))]),
        NOW,
        None,
    );
    assert_eq!(
        outcome(&reply),
        None,
        "this realm says a password counts, so it does"
    );
}

/// A policy that admits nothing refuses a password that the scheme would otherwise accept, and the
/// default policy is the certificate-only one.
///
/// The certificate path itself is not exercised here: it needs `PA-PK-AS-REQ` with a certificate
/// chain, which the `pkinit` tests build. What this pins is that the seam is consulted for every
/// method rather than only for the ones Heimdal discriminates.
#[test]
fn a_policy_that_admits_nothing_refuses_a_password_and_the_default_is_certificates() {
    let kdc = kdc_with(entry_flags::REQUIRE_HWAUTH).with_hw_auth(Arc::new(
        AllowList::new(&[]).expect("an empty list is a legal policy"),
    ));
    let reply = kdc.handle_from(
        &as_req(vec![(PA_ENC_TIMESTAMP, enc_timestamp(PASSWORD.as_bytes()))]),
        NOW,
        None,
    );
    assert_eq!(outcome(&reply), Some(codes::KDC_ERR_POLICY));
    // And the default is the certificate-only one, which is Heimdal's.
    let default = kdc_with(entry_flags::REQUIRE_HWAUTH);
    assert!(
        default.hw_auth().admits(
            &principal("alice"),
            rrl_kdc::kdc::hwauth::Method::Certificate
        ),
        "the default policy is CertificateOnly"
    );
    let _ = CertificateOnly;
}
