//! Anonymous PKINIT (RFC 8062): a ticket that names nobody.
//!
//! The point of this mode is the first login on a machine that holds no ticket: a client can
//! armour an AS exchange only with a ticket, and without one its password pre-authentication
//! is an offline oracle again. An anonymous TGT, obtained without revealing who asked, is
//! what breaks that circle — and it is what MIT's `auto_fast_armor` reaches for.
//!
//! Three things make it safe rather than merely empty, and each is a test here:
//!
//! * the ticket says it is anonymous (`anonymous` flag, RFC 8062 §3) and names
//!   `WELLKNOWN/ANONYMOUS` in the anonymous realm, so no service can mistake it for a real
//!   credential;
//! * it carries no PAC and no identity in authorization data — §4.1 requires that the KDC
//!   reveal nothing about who asked;
//! * `PA-PKINIT-KX` proves the session key was contributed to by both sides, so a KDC (or
//!   anything on the path) cannot pick a key the client does not know (RFC 8062 §7).
//!
//! A realm that has not enabled it refuses by name: an anonymous TGT is an opening, and an
//! opening nobody configured is a surprise.

#![cfg(feature = "pkinit")]

use std::sync::Arc;

use rrl_kdc::crypto::{Cipher, Enctype, Key, OwnCipher, usage};
use rrl_kdc::der;
use rrl_kdc::error::codes;
use rrl_kdc::hdb::{HdbEntry, MemoryHdb, flags as entry_flags};
use rrl_kdc::kdc::pkinit::{self, reply};
use rrl_kdc::kdc::{Kdc, KdcConfig};
use rrl_kdc::msg::{self, kdc_options, tkt_flags};
use rrl_kdc::name::{self, Principal};

const REALM: &str = "EXAMPLE.COM";
const ANON_REALM: &str = "WELLKNOWN:ANONYMOUS";
const NOW: i64 = 1_800_000_000;

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!(
        "{}/tests/pkinit/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap_or_else(|e| panic!("read {name}: {e}"))
}

fn pem_to_der(pem: &[u8]) -> Vec<u8> {
    use base64::Engine;
    let text = String::from_utf8_lossy(pem);
    let body: String = text
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect::<Vec<_>>()
        .join("");
    base64::engine::general_purpose::STANDARD
        .decode(body.trim())
        .expect("PEM body is base64")
}

/// The anonymous principal **as a client sends it**: name type 11, and the realm of the AS.
///
/// RFC 8062 §4.1 is explicit about the asymmetry: the request names the anonymous principal
/// in *this* realm, and only the reply widens the realm to `WELLKNOWN:ANONYMOUS`.
fn anonymous() -> Principal {
    Principal::new(name::NT_WELLKNOWN, ["WELLKNOWN", "ANONYMOUS"], REALM)
}

fn state() -> Arc<reply::State> {
    let mut anchors = pkinit::TrustAnchors::new();
    anchors.add(&pem_to_der(&fixture("ca.pem"))).unwrap();
    Arc::new(reply::State {
        identity: reply::Identity::from_der(
            &pem_to_der(&fixture("kdc.pem")),
            &pem_to_der(&fixture("kdc-key.pem")),
        )
        .expect("the KDC identity"),
        anchors,
    })
}

/// A realm that offers anonymous PKINIT, with a real user to prove nothing leaks.
fn kdc(anonymous_enabled: bool) -> Kdc {
    let cipher = OwnCipher;
    let db = MemoryHdb::new();

    let mut krbtgt = HdbEntry::krbtgt(REALM);
    for e in [Enctype::Aes256Sha1, Enctype::Aes128Sha1] {
        krbtgt
            .add_password_key(&cipher, e, b"master-key-of-the-realm", 1)
            .unwrap();
    }
    db.insert(krbtgt).unwrap();

    let mut user = HdbEntry::user(Principal::parse(&format!("alice@{REALM}")).unwrap());
    user.flags &= !entry_flags::REQUIRE_PREAUTH;
    user.add_password_key(&cipher, Enctype::Aes256Sha1, b"password-of-alice", 1)
        .unwrap();
    db.insert(user).unwrap();

    Kdc::new(
        KdcConfig::new(REALM)
            .unwrap()
            .with_require_preauth(false)
            .with_anonymous_pkinit(anonymous_enabled),
        Arc::new(db),
        Arc::new(OwnCipher),
    )
    .with_pkinit(state())
}

/// The `KDC-REQ-BODY` of an anonymous AS-REQ.
fn body(client: &Principal, options: u32) -> Vec<u8> {
    der::seq(&[
        der::field(0, der::flags32(options)),
        der::field(1, client.encode_name()),
        der::field(2, der::general_string(&client.realm)),
        der::field(3, Principal::krbtgt(REALM).encode_name()),
        der::field(5, der::time(NOW + 3600)),
        der::field(7, der::int(0x4242)),
        der::field(8, der::seq(&[der::int(18), der::int(17)])),
    ])
}

/// An `AS-REQ` carrying an **una**uthenticated `PA-PK-AS-REQ` in the DH form.
///
/// RFC 8062 §4.1: the `AuthPack` goes in a bare `ContentInfo` with no `SignedData` — an
/// `id-pkinit-authData` envelope holding the pack directly. The signature is what would name
/// the client, so its absence is the whole mechanism.
fn anonymous_as_req(options: u32, with_public_value: bool) -> Vec<u8> {
    anonymous_as_req_with_exponent(options, with_public_value).0
}

/// The same request, plus the private exponent — a test that checks the derived keys has to
/// hold the client's half of the Diffie-Hellman exchange, and rebuilding it would be a
/// different exponent producing different keys.
fn anonymous_as_req_with_exponent(
    options: u32,
    with_public_value: bool,
) -> (Vec<u8>, num_bigint::BigUint) {
    use sha1::Digest;

    let group = pkinit::dh::Group::at_least(2048);
    let exponent: num_bigint::BigUint =
        num_bigint::BigUint::from(0x5deece66du64) + (num_bigint::BigUint::from(1u32) << 200);
    let ours = pkinit::dh::KeyPair::from_private(group, exponent.clone());

    let b = body(&anonymous(), options);
    let checksum = sha1::Sha1::digest(&b);

    let mut pack_parts = vec![der::field(
        0,
        der::seq(&[
            der::field(0, der::int(0)),
            der::field(1, der::time(NOW - 10)),
            der::field(2, der::int(0x4242)),
            der::field(3, der::octets(&checksum)),
        ]),
    )];
    if with_public_value {
        let params = der::seq(&[
            der::int_bytes(&group.p().to_bytes_be()),
            der::int(2),
            der::int_bytes(&group.q().to_bytes_be()),
        ]);
        let mut bits = vec![0u8];
        bits.extend_from_slice(&ours.public_bytes());
        pack_parts.push(der::field(
            1,
            der::seq(&[
                der::seq(&[
                    der::tlv(
                        der::OBJECT_IDENTIFIER,
                        &oid_content(pkinit::dh::DH_PUBLIC_NUMBER),
                    ),
                    params,
                ]),
                der::tlv(0x03, &bits),
            ]),
        ));
    }
    let auth_pack = der::seq(&pack_parts);

    // `ContentInfo { id-pkinit-authData, [0] EXPLICIT OCTET STRING }` — no SignedData.
    let content_info = der::seq(&[
        der::tlv(
            der::OBJECT_IDENTIFIER,
            &oid_content(pkinit::ID_PKINIT_AUTH_DATA),
        ),
        der::field(0, der::octets(&auth_pack)),
    ]);
    let pa_value = der::seq(&[der::field(0, content_info)]);

    let message = der::cons(
        der::app(10),
        &[der::seq(&[
            der::field(1, der::int(5)),
            der::field(2, der::int(10)),
            der::field(
                3,
                der::seq(&[der::seq(&[
                    der::field(1, der::int(i64::from(pkinit::PA_PK_AS_REQ))),
                    der::field(2, der::octets(&pa_value)),
                ])]),
            ),
            der::field(4, b),
        ])],
    );
    (message, exponent)
}

fn oid_content(text: &str) -> Vec<u8> {
    let parts: Vec<u64> = text.split('.').map(|p| p.parse().unwrap()).collect();
    let mut out = vec![(40 * parts[0] + parts[1]) as u8];
    for &part in &parts[2..] {
        let mut chunk = vec![(part & 0x7f) as u8];
        let mut rest = part >> 7;
        while rest > 0 {
            chunk.push(0x80 | (rest & 0x7f) as u8);
            rest >>= 7;
        }
        chunk.reverse();
        out.extend(chunk);
    }
    out
}

fn rep_padata(reply: &[u8]) -> Vec<(i32, Vec<u8>)> {
    let f = der::Fields::parse_app("AS-REP", 11, reply).expect("an AS-REP");
    match f.opt_bytes(2) {
        None => Vec::new(),
        Some(raw) => {
            let mut r = der::Reader::new(raw);
            let seq = r.next_tlv("PA-DATA").expect("a SEQUENCE");
            msg::decode_pa_data("AS-REP", seq.content).expect("PA-DATA")
        }
    }
}

#[test]
fn an_anonymous_request_gets_a_ticket_that_names_nobody() {
    // The happy path, and the three properties RFC 8062 §3 requires of an anonymous ticket:
    // the anonymous principal, the anonymous realm, and the flag that says so.
    let reply = kdc(true).handle(&anonymous_as_req(kdc_options::ANONYMOUS, true), NOW);
    assert!(
        msg::KrbError::decode(&reply).is_err(),
        "an anonymous request must be answered: {:?}",
        msg::KrbError::decode(&reply)
    );

    let f = der::Fields::parse_app("AS-REP", 11, &reply).expect("an AS-REP");
    let crealm = f.string(3, "AS-REP").expect("crealm");
    assert_eq!(
        crealm, ANON_REALM,
        "an anonymous reply names the anonymous realm"
    );

    let mut r = der::Reader::new(f.bytes(4, "AS-REP").expect("cname"));
    let seq = r.next_tlv("cname").expect("a SEQUENCE");
    let cname = Principal::decode("cname", seq.content, &crealm).expect("a principal");
    assert_eq!(cname.components, vec!["WELLKNOWN", "ANONYMOUS"]);
    assert_eq!(
        cname.name_type,
        name::NT_WELLKNOWN,
        "the wire type must be KRB_NT_WELLKNOWN, which is how a client reads the name"
    );

    // The ticket itself carries the anonymous flag.
    let ticket = msg::Ticket::decode(f.bytes(5, "AS-REP").expect("the ticket")).expect("a Ticket");
    let mut entry = HdbEntry::krbtgt(REALM);
    for e in [Enctype::Aes256Sha1, Enctype::Aes128Sha1] {
        entry
            .add_password_key(&OwnCipher, e, b"master-key-of-the-realm", 1)
            .unwrap();
    }
    let key = entry
        .key_for(ticket.enc.etype)
        .map(|k| k.key.clone())
        .expect("krbtgt has a key of the ticket's enctype");
    let plain = OwnCipher
        .decrypt(&key, usage::KDC_REP_TICKET, &ticket.enc.cipher)
        .expect("the ticket opens under krbtgt");
    let part = msg::EncTicketPart::decode(&plain).expect("an EncTicketPart");
    assert!(
        part.flags & tkt_flags::ANONYMOUS != 0,
        "the anonymous flag must be set: {:#010x}",
        part.flags
    );
    assert_eq!(
        part.cname.components,
        vec!["WELLKNOWN", "ANONYMOUS"],
        "the ticket's client is the anonymous principal"
    );
}

#[test]
fn an_anonymous_ticket_carries_no_identity_in_authorization_data() {
    // §4.1: "The KDC MUST NOT reveal the client's identity in the authorization data of the
    // returned ticket." A PAC would carry the account's SID — the one thing this mode exists
    // to withhold.
    let reply = kdc(true).handle(&anonymous_as_req(kdc_options::ANONYMOUS, true), NOW);
    assert!(msg::KrbError::decode(&reply).is_err());

    let f = der::Fields::parse_app("AS-REP", 11, &reply).expect("an AS-REP");
    let ticket = msg::Ticket::decode(f.bytes(5, "AS-REP").expect("the ticket")).expect("a Ticket");
    let mut entry = HdbEntry::krbtgt(REALM);
    for e in [Enctype::Aes256Sha1, Enctype::Aes128Sha1] {
        entry
            .add_password_key(&OwnCipher, e, b"master-key-of-the-realm", 1)
            .unwrap();
    }
    let key = entry
        .key_for(ticket.enc.etype)
        .map(|k| k.key.clone())
        .unwrap();
    let plain = OwnCipher
        .decrypt(&key, usage::KDC_REP_TICKET, &ticket.enc.cipher)
        .expect("the ticket opens");
    let part = msg::EncTicketPart::decode(&plain).expect("an EncTicketPart");
    assert!(
        part.authorization_data.is_none(),
        "an anonymous ticket must carry no authorization data"
    );
}

/// The KDC's public value out of a `DHRepInfo`, as a client reads it.
fn kdc_public_value(pa_value: &[u8]) -> Vec<u8> {
    let mut r = der::Reader::new(pa_value);
    let dh_info = r.next_tlv("PA-PK-AS-REP").expect("the choice");
    assert_eq!(dh_info.tag, der::ctx(0), "dhInfo [0]");
    let mut ir = der::Reader::new(dh_info.content);
    let seq = ir.next_tlv("DHRepInfo").expect("a SEQUENCE");
    let mut sr = der::Reader::new(seq.content);
    let signed_tlv = sr.next_tlv("dhSignedData").expect("dhSignedData");
    let mut dr = der::Reader::new(signed_tlv.content);
    let octets = dr.next_tlv("OCTET STRING").expect("an OCTET STRING");

    let mut cr = der::Reader::new(octets.content);
    let ci = cr.next_tlv("ContentInfo").expect("a ContentInfo");
    let mut cir = der::Reader::new(ci.content);
    cir.next_tlv("contentType").expect("the OID");
    let wrapped = cir.next_tlv("content").expect("the content");
    let mut wr = der::Reader::new(wrapped.content);
    let sd = wr.next_tlv("SignedData").expect("a SignedData");
    let mut sdr = der::Reader::new(sd.content);
    sdr.next_tlv("version").unwrap();
    sdr.next_tlv("digestAlgorithms").unwrap();
    let encap = sdr.next_tlv("EncapsulatedContentInfo").unwrap();
    let mut er = der::Reader::new(encap.content);
    er.next_tlv("eContentType").unwrap();
    let econtent = er.next_tlv("eContent").unwrap();
    let mut ecr = der::Reader::new(econtent.content);
    let info_octets = ecr
        .next_tlv("OCTET STRING")
        .expect("the KDCDHKeyInfo octets");

    let mut kr = der::Reader::new(info_octets.content);
    let info = kr.next_tlv("KDCDHKeyInfo").expect("a SEQUENCE");
    let mut krr = der::Reader::new(info.content);
    let key_tlv = krr.next_tlv("subjectPublicKey").expect("the key");
    let mut br = der::Reader::new(key_tlv.content);
    let bits = br.next_tlv("BIT STRING").expect("a BIT STRING");
    bits.content[1..].to_vec()
}

#[test]
fn the_reply_proves_the_session_key_was_contributed_to_by_both_sides() {
    // §7: `session key = cf2(KDC contribution, "PKINIT", reply key, "KEYEXCHANGE")`, and the
    // contribution arrives in `PA-PKINIT-KX` sealed under the reply key.
    //
    // This recomputes the session key from the client's side — its own exponent, the KDC's
    // public value, the contribution — and compares it with the key the KDC put in the
    // ticket. Checking only that `PA-PKINIT-KX` is present would pass for a KDC that sent a
    // contribution and then chose the session key itself, which is exactly the failure the
    // section exists to prevent: it would make "anonymous" mean "trusts whoever answered".
    let (request, exponent) = anonymous_as_req_with_exponent(kdc_options::ANONYMOUS, true);
    let reply = kdc(true).handle(&request, NOW);
    assert!(
        msg::KrbError::decode(&reply).is_err(),
        "an anonymous request must be answered: {:?}",
        msg::KrbError::decode(&reply)
    );

    let padata = rep_padata(&reply);
    let pa_pk_as_rep = padata
        .iter()
        .find(|(t, _)| *t == pkinit::PA_PK_AS_REP)
        .map(|(_, v)| v.clone())
        .expect("the reply carries PA-PK-AS-REP");
    let kx = padata
        .iter()
        .find(|(t, _)| *t == 147)
        .map(|(_, v)| v.clone())
        .expect("an anonymous reply must carry PA-PKINIT-KX");

    let f = der::Fields::parse_app("AS-REP", 11, &reply).expect("an AS-REP");
    let enc_part = msg::EncryptedData::decode("enc-part", f.bytes(6, "AS-REP").expect("enc-part"))
        .expect("an EncryptedData");

    // The client's half of the exchange, done as a client does it.
    let group = pkinit::dh::Group::at_least(2048);
    let ours = pkinit::dh::KeyPair::from_private(group, exponent);
    let z = ours
        .agree(&kdc_public_value(&pa_pk_as_rep))
        .expect("the KDC's value is in the group");
    let reply_key = Key::new(
        enc_part.etype,
        reply::reply_key(
            &z,
            None,
            &anonymous(),
            &Principal::krbtgt(REALM),
            enc_part.etype,
            &request,
            &pa_pk_as_rep,
        )
        .expect("the legacy KDF"),
    )
    .expect("a key");

    // The contribution, and the key it must produce.
    let kx_data = msg::EncryptedData::decode("PA-PKINIT-KX", &kx).expect("an EncryptedData");
    let kx_plain = OwnCipher
        .decrypt(&reply_key, 44, &kx_data.cipher)
        .expect("PA-PKINIT-KX opens under the reply key");
    // `decode_key` takes the content of the `EncryptionKey` SEQUENCE, not the TLV.
    let mut kxr = der::Reader::new(&kx_plain);
    let key_seq = kxr.next_tlv("EncryptionKey").expect("a SEQUENCE");
    let contribution = msg::decode_key(key_seq.content).expect("an EncryptionKey");
    let expected = rrl_kdc::crypto::kdf::cf2(
        contribution.bytes(),
        "PKINIT",
        reply_key.enctype(),
        reply_key.bytes(),
        "KEYEXCHANGE",
    )
    .expect("cf2");

    // The session key the KDC actually issued, out of the reply the client can open.
    let rep_plain = OwnCipher
        .decrypt(&reply_key, usage::AS_REP_ENCPART, &enc_part.cipher)
        .expect("the reply opens with the key the client derived");
    let session_key = msg::EncKdcRepPart::decode(&rep_plain)
        .expect("an EncKDCRepPart")
        .session_key;

    assert_eq!(
        session_key.bytes(),
        expected.as_slice(),
        "the session key must be cf2(contribution, \"PKINIT\", reply key, \"KEYEXCHANGE\")
         over a contribution the client can see"
    );
}

#[test]
fn a_realm_that_has_not_enabled_it_refuses_by_name() {
    // An anonymous TGT is an opening. A realm that did not configure it says so rather than
    // quietly issuing one, and the client learns which knob to ask its administrator about.
    let reply = kdc(false).handle(&anonymous_as_req(kdc_options::ANONYMOUS, true), NOW);
    let err = msg::KrbError::decode(&reply).expect("a refusal");
    assert_eq!(err.code, codes::KDC_ERR_POLICY);
    let text = err.e_text.unwrap_or_default();
    assert!(
        text.contains("anonymous"),
        "the refusal must say which mode is off: {text}"
    );
}

#[test]
fn the_anonymous_principal_without_the_option_is_refused() {
    // §4.1: "If the client in the AS request is anonymous, the anonymous KDC option MUST be
    // set in the request. Otherwise, the KDC MUST return ... KDC_ERR_BADOPTION."
    let reply = kdc(true).handle(&anonymous_as_req(0, true), NOW);
    let err = msg::KrbError::decode(&reply).expect("a refusal");
    assert_eq!(err.code, codes::KDC_ERR_BADOPTION);
}

#[test]
fn anonymous_pkinit_without_a_public_value_is_refused() {
    // §4.1: the client has no key pair, so it MUST use Diffie-Hellman. Asking for key
    // transport is refused with the code RFC 4556 defines for it rather than answered with
    // a key the client cannot derive.
    let reply = kdc(true).handle(&anonymous_as_req(kdc_options::ANONYMOUS, false), NOW);
    let err = msg::KrbError::decode(&reply).expect("a refusal");
    assert_eq!(
        err.code,
        codes::KDC_ERR_PUBLIC_KEY_ENCRYPTION_NOT_SUPPORTED,
        "{}",
        err.e_text.clone().unwrap_or_default()
    );
}

#[test]
fn the_anonymous_principal_is_a_well_known_name_not_a_plain_one() {
    // The pair that keeps the first test honest: `Principal`'s identity ignores the name
    // type, so a wrong type would pass every comparison in this crate and only reach a
    // client that reads the wire. RFC 6111 gives the well-known type the number 11.
    let ours = pkinit::fast_anonymous_principal();
    assert_eq!(ours.name_type, 11, "KRB_NT_WELLKNOWN");
    assert_eq!(ours.components, vec!["WELLKNOWN", "ANONYMOUS"]);
    assert_eq!(ours.realm, ANON_REALM);
}
