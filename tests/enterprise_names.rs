//! Enterprise principal names (RFC 6806 §6) in the AS exchange.
//!
//! A Windows or Samba client that knows only a user's UPN sends it as an
//! `NT-ENTERPRISE` name: one component, `user@realm`, with type 10. The KDC resolves it to
//! the principal it names and answers with the canonical name — which is exactly the thing
//! that requires the client to have asked for `canonicalize`, because the reply's name then
//! differs from the request's.
//!
//! §6 also says names **must not** change in a TGS response, so this is an AS-only concern;
//! the TGS path is left alone on purpose, and a test pins that too.
//!
//! Without the option, an enterprise name cannot be answered: resolving it would mean
//! replying with a name the client never agreed to see. The refusal says so instead of
//! answering with a principal whose name happens to contain an `@`.

use std::sync::Arc;

use rrl_kdc::crypto::{Enctype, OwnCipher};
use rrl_kdc::der;
use rrl_kdc::error::codes;
use rrl_kdc::hdb::{HdbEntry, MemoryHdb};
use rrl_kdc::kdc::{Kdc, KdcConfig};
use rrl_kdc::msg::{self, kdc_options};
use rrl_kdc::name::{self, Principal};

const REALM: &str = "EXAMPLE.COM";
const PASSWORD: &str = "correct horse battery staple";
const NOW: i64 = 1_700_000_000;

fn alice() -> Principal {
    Principal::parse(&format!("alice@{REALM}")).unwrap()
}

fn kdc() -> Kdc {
    kdc_with(|config| config)
}

/// The same realm, with the configuration a test wants to change.
fn kdc_with(tweak: impl FnOnce(KdcConfig) -> KdcConfig) -> Kdc {
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
    // `HdbEntry::user` demands pre-authentication, which is right in a realm and noise
    // here: this file is about which principal a name resolves to, not about how the client
    // proves it owns the key.
    user.flags &= !rrl_kdc::hdb::flags::REQUIRE_PREAUTH;
    for e in [Enctype::Aes256Sha1, Enctype::Aes128Sha1] {
        user.add_password_key(&cipher, e, PASSWORD.as_bytes(), 1)
            .unwrap();
    }
    db.insert(user).unwrap();

    // Pre-authentication is not what this file is about, and demanding it would make every
    // assertion here read as "the name resolved enough to be asked for a timestamp", which
    // is a weaker claim than "the name resolved to a ticket".
    Kdc::new(
        tweak(KdcConfig::new(REALM).unwrap().with_require_preauth(false)),
        Arc::new(db),
        Arc::new(OwnCipher),
    )
}

/// An `AS-REQ` whose client name is `enterprise` (one component, `user@realm`), asking for
/// the options in `options`.
fn enterprise_as_req(enterprise: &str, options: u32) -> Vec<u8> {
    let cname = Principal::new(name::NT_ENTERPRISE, [enterprise], REALM);
    let body = der::seq(&[
        der::field(0, der::flags32(options)),
        der::field(1, cname.encode_name()),
        der::field(2, der::general_string(REALM)),
        der::field(3, Principal::krbtgt(REALM).encode_name()),
        der::field(5, der::time(NOW + 3600)),
        der::field(7, der::int(0x4242)),
        der::field(8, der::seq(&[der::int(18), der::int(17)])),
    ]);
    der::cons(
        der::app(10),
        &[der::seq(&[
            der::field(1, der::int(5)),
            der::field(2, der::int(10)),
            der::field(4, body),
        ])],
    )
}

/// The `cname`/`crealm` an AS-REP carries.
fn reply_identity(reply: &[u8]) -> (String, Principal) {
    let f = der::Fields::parse_app("AS-REP", 11, reply).expect("an AS-REP");
    let crealm = f.string(3, "AS-REP").expect("crealm");
    let mut r = der::Reader::new(f.bytes(4, "AS-REP").expect("cname"));
    let seq = r.next_tlv("cname").expect("a SEQUENCE");
    let cname = Principal::decode("cname", seq.content, &crealm).expect("the cname is decodable");
    (crealm, cname)
}

#[test]
fn an_enterprise_name_resolves_when_the_client_asked_to_canonicalize() {
    // The case a Windows or Samba client produces: `alice@EXAMPLE.COM` as one component of
    // type 10, with `canonicalize` set. The KDC resolves it and answers with the canonical
    // `alice` of type 1.
    let reply = kdc().handle(
        &enterprise_as_req(&format!("alice@{REALM}"), kdc_options::CANONICALIZE),
        NOW,
    );
    assert!(
        msg::KrbError::decode(&reply).is_err(),
        "an enterprise name with canonicalize must be answered: {:?}",
        msg::KrbError::decode(&reply)
    );

    let (crealm, cname) = reply_identity(&reply);
    assert_eq!(crealm, REALM);
    assert_eq!(cname.to_string(), format!("alice@{REALM}"));
    // The reply's type comes from the directory entry, not from the canonicalisation
    // itself: `Principal`'s identity is (components, realm) and the name type is decoration
    // (`name::tests::the_name_type_is_not_identity`). Asserting it here documents what a
    // client receives — a principal name, not the enterprise form it sent — and a mutation
    // that made `canonical_client_name` return `NT_ENTERPRISE` would survive, because the
    // reply never takes its type from that function.
    assert_eq!(
        cname.name_type,
        name::NT_PRINCIPAL,
        "the client receives a principal name, not the enterprise form it sent"
    );
}

#[test]
fn an_enterprise_name_without_the_option_is_refused() {
    // Resolving it would answer with a name the client never agreed to see, which is the
    // one thing `canonicalize` exists to permit. The refusal names the option rather than
    // reporting an unknown user, because the user is known.
    let reply = kdc().handle(&enterprise_as_req(&format!("alice@{REALM}"), 0), NOW);
    let err = msg::KrbError::decode(&reply).expect("a refusal");
    assert_eq!(err.code, codes::KDC_ERR_C_PRINCIPAL_UNKNOWN);
    let text = err.e_text.unwrap_or_default();
    assert!(
        text.contains("canonicalize"),
        "the refusal must point at the missing option: {text}"
    );
}

#[test]
fn an_enterprise_name_resolves_without_the_option_when_the_realm_allows_it() {
    // Active Directory resolves the name and answers with it, and Windows on a UPN logon does not
    // set `canonicalize` (measured: `kdc-options` 0x40800010). A realm configured to accept such a
    // client therefore resolves the name, and still refuses when the option is left on.
    let reply = kdc_with(|config| config.with_enterprise_requires_canonicalize(false))
        .handle(&enterprise_as_req(&format!("alice@{REALM}"), 0), NOW);
    assert!(
        msg::KrbError::decode(&reply).is_err(),
        "an enterprise name must be answered when the realm resolves it: {:?}",
        msg::KrbError::decode(&reply)
    );
    let (crealm, cname) = reply_identity(&reply);
    assert_eq!(crealm, REALM);
    assert_eq!(cname.to_string(), format!("alice@{REALM}"));
}

#[test]
fn an_enterprise_name_of_an_unknown_user_is_unknown_even_with_the_option() {
    // The option permits a rename; it does not invent an account.
    let reply = kdc().handle(
        &enterprise_as_req(&format!("nobody@{REALM}"), kdc_options::CANONICALIZE),
        NOW,
    );
    let err = msg::KrbError::decode(&reply).expect("a refusal");
    assert_eq!(err.code, codes::KDC_ERR_C_PRINCIPAL_UNKNOWN);
    assert!(
        !err.e_text.unwrap_or_default().contains("canonicalize"),
        "the user really is unknown; the option is not the problem"
    );
}

#[test]
fn an_enterprise_name_for_another_realm_is_wrong_realm() {
    // The realm inside the enterprise name is the one the user belongs to, and this KDC
    // serves one realm. Answering would hand out a ticket for somebody it does not know.
    let reply = kdc().handle(
        &enterprise_as_req("alice@OTHER.EXAMPLE", kdc_options::CANONICALIZE),
        NOW,
    );
    let err = msg::KrbError::decode(&reply).expect("a refusal");
    assert_eq!(
        err.code,
        codes::KDC_ERR_WRONG_REALM,
        "{}",
        err.e_text.unwrap_or_default()
    );
}

#[test]
fn a_plain_name_is_not_renamed_by_the_option() {
    // The pair that keeps the tests above from passing for the wrong reason: with
    // `canonicalize` set and an ordinary NT-PRINCIPAL name, nothing changes. A KDC that
    // always rewrote names would pass the first test and fail a real client here.
    let body = der::seq(&[
        der::field(0, der::flags32(kdc_options::CANONICALIZE)),
        der::field(1, alice().encode_name()),
        der::field(2, der::general_string(REALM)),
        der::field(3, Principal::krbtgt(REALM).encode_name()),
        der::field(5, der::time(NOW + 3600)),
        der::field(7, der::int(0x4243)),
        der::field(8, der::seq(&[der::int(18)])),
    ]);
    let request = der::cons(
        der::app(10),
        &[der::seq(&[
            der::field(1, der::int(5)),
            der::field(2, der::int(10)),
            der::field(4, body),
        ])],
    );
    let reply = kdc().handle(&request, NOW);
    assert!(msg::KrbError::decode(&reply).is_err());
    let (_, cname) = reply_identity(&reply);
    assert_eq!(cname.to_string(), format!("alice@{REALM}"));
    assert_eq!(cname.name_type, name::NT_PRINCIPAL);
}

#[test]
fn an_enterprise_name_with_more_than_one_component_is_refused() {
    // `NT-ENTERPRISE` is one component by definition (RFC 6806 §3). A name that is not one
    // is malformed, and treating it as anything else would make the type meaningless.
    let reply = kdc().handle(
        &enterprise_as_req("alice/extra", kdc_options::CANONICALIZE),
        NOW,
    );
    let err = msg::KrbError::decode(&reply).expect("a refusal");
    assert_eq!(err.code, codes::KDC_ERR_C_PRINCIPAL_UNKNOWN);
    let text = err.e_text.unwrap_or_default();
    assert!(
        text.contains("component"),
        "the refusal must say the shape is wrong: {text}"
    );
}

#[test]
fn an_enterprise_name_without_a_realm_part_is_refused() {
    // `alice` alone has no realm, so there is nothing to canonicalize it to.
    let reply = kdc().handle(&enterprise_as_req("alice", kdc_options::CANONICALIZE), NOW);
    let err = msg::KrbError::decode(&reply).expect("a refusal");
    assert_eq!(err.code, codes::KDC_ERR_C_PRINCIPAL_UNKNOWN);
}
