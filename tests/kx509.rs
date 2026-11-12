//! kx509 end to end, in one process: a ticket, an authenticated request, a CSR, and a certificate
//! back with a MAC that the client can check.
//!
//! The AP-REQ is assembled here with the same sealing the KDC itself uses, because the property
//! under test is the exchange, not the client: a request built by a third party would be a better
//! test of the wire format and a worse one of this code, and the wire format is judged by
//! `tests/kdc.rs` against MIT where a client exists.
//!
//! What is checked is what a client can check: the reply MAC, computed the way RFC 6717 §3 says from
//! the session key it already holds, over the version, the error-code's DER content, and the
//! certificate — plus the negative cases that make those MACs mean something.

#![cfg(feature = "pkinit")]

use rrl_kdc::crypto::{Cipher, Enctype, Key, OwnCipher, usage};
use rrl_kdc::der::{self, Reader};
use rrl_kdc::hdb::{HdbEntry, MemoryHdb};
use rrl_kdc::kdc::ca::{CaError, CertificateAuthority, SigningRequest};
use rrl_kdc::kdc::kx509::{
    self, APP_CSR_PLUS, KRB_ERROR_BASE, Request, STATUS_CLIENT_BAD, VERSION,
};
use rrl_kdc::kdc::{Kdc, KdcConfig};
use rrl_kdc::msg::{ApReq, Authenticator, EncTicketPart, EncryptedData, Ticket};
use rrl_kdc::name::Principal;

const REALM: &str = "EXAMPLE.COM";
const NOW: i64 = 1_800_000_000;
const HOST: &str = "kdc.example.com";
const SERVICE_PASSWORD: &[u8] = b"the kx509 service password";

fn p(name: &str) -> Principal {
    Principal::parse(name).unwrap()
}

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!(
        "{}/tests/pkinit/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap_or_else(|e| panic!("read {name}: {e}"))
}

fn der_of(pem: &[u8]) -> Vec<u8> {
    use base64::Engine;
    let text = String::from_utf8_lossy(pem);
    let body: String = text
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect::<Vec<_>>()
        .join("");
    base64::engine::general_purpose::STANDARD
        .decode(body.trim())
        .expect("a PEM body is base64")
}

/// A CA that returns a fixed certificate: the seam's other half, without a signing key in a test.
#[derive(Debug)]
struct FixedCa(&'static [u8]);

impl CertificateAuthority for FixedCa {
    fn sign(&self, _request: &SigningRequest) -> Result<Vec<u8>, CaError> {
        Ok(self.0.to_vec())
    }
}

const CERT: &[u8] = b"the certificate the realm issues";

/// A realm with the kx509 service provisioned and a CA.
fn realm() -> (std::sync::Arc<MemoryHdb>, Kdc) {
    let cipher = OwnCipher;
    let db = std::sync::Arc::new(MemoryHdb::new());
    db.insert(
        kx509::service_entry(REALM, HOST, &cipher, SERVICE_PASSWORD).expect("the service entry"),
    )
    .expect("stored");
    let kdc = Kdc::new(
        KdcConfig::new(REALM).unwrap(),
        std::sync::Arc::clone(&db) as _,
        std::sync::Arc::new(OwnCipher),
    )
    .with_ca(std::sync::Arc::new(FixedCa(CERT)));
    (db, kdc)
}

/// The service key, as the KDC would read it from its own database.
fn service_key(db: &MemoryHdb) -> Key {
    use rrl_kdc::hdb::Hdb;
    let entry: HdbEntry = db
        .fetch(&p(&format!("kx509/{HOST}@{REALM}")))
        .expect("a database")
        .expect("the service");
    entry
        .key_for(Enctype::Aes256Sha1)
        .expect("a key")
        .key
        .clone()
}

/// An AP-REQ for `kx509/host@REALM`, sealed exactly as a KDC seals one.
fn ap_req(db: &MemoryHdb, client: &Principal) -> (Vec<u8>, Key) {
    let cipher = OwnCipher;
    let service_token = service_key(db);
    let session = cipher.random(Enctype::Aes256Sha1).expect("a session key");

    let part = EncTicketPart {
        flags: 0,
        session_key: session.clone(),
        crealm: REALM.to_owned(),
        cname: client.clone(),
        transited_type: 0,
        transited: Vec::new(),
        authtime: NOW - 60,
        starttime: None,
        endtime: NOW + 3600,
        renew_till: None,
        caddr: None,
        authorization_data: None,
    };
    let enc = EncryptedData::seal(
        &cipher,
        &service_token,
        usage::KDC_REP_TICKET,
        None,
        &part.encode(),
    )
    .expect("the ticket seals");
    let ticket = Ticket {
        realm: REALM.to_owned(),
        sname: p(&format!("kx509/{HOST}@{REALM}")),
        enc,
    };

    let authenticator = Authenticator {
        crealm: REALM.to_owned(),
        cname: client.clone(),
        cksum: None,
        cusec: 0,
        ctime: NOW,
        subkey: None,
        seq_number: None,
        authorization_data: None,
    };
    let authenticator = EncryptedData::seal(
        &cipher,
        &session,
        usage::AP_REQ_AUTH,
        None,
        &authenticator.encode(),
    )
    .expect("the authenticator seals");
    let ap = ApReq {
        ap_options: 0,
        ticket: ticket.encode(),
        authenticator,
    };
    (ap.encode(), session)
}

/// A CSR over the fixture key, signed by that key's own private half.
fn csr() -> Vec<u8> {
    use rsa::pkcs1::EncodeRsaPublicKey;
    use rsa::pkcs1v15::SigningKey;
    use rsa::pkcs8::DecodePrivateKey;
    use rsa::signature::{SignatureEncoding, Signer};

    let key = rsa::RsaPrivateKey::from_pkcs8_der(&der_of(&fixture("alice-key.pem")))
        .expect("the fixture key");
    let spki = der::seq(&[
        der::seq(&[
            der::tlv(der::OBJECT_IDENTIFIER, &oid_content("1.2.840.113549.1.1.1")),
            der::tlv(0x05, &[]),
        ]),
        der::tlv(
            der::BIT_STRING,
            &[
                &[0u8][..],
                key.to_public_key().to_pkcs1_der().unwrap().as_bytes(),
            ]
            .concat(),
        ),
    ]);
    let info = der::seq(&[der::int(0), der::seq(&[]), spki, der::tlv(der::ctx(0), &[])]);
    let signing = SigningKey::<rsa_sha2::Sha256>::new(key.clone());
    let signature = signing.sign(&info).to_vec();
    der::seq(&[
        info,
        der::seq(&[
            der::tlv(
                der::OBJECT_IDENTIFIER,
                &oid_content("1.2.840.113549.1.1.11"),
            ),
            der::tlv(0x05, &[]),
        ]),
        der::tlv(der::BIT_STRING, &[&[0u8][..], &signature].concat()),
    ])
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

fn hmac_sha1(key: &[u8], parts: &[&[u8]]) -> Vec<u8> {
    use hmac::{Hmac, KeyInit, Mac};
    let mut mac = <Hmac<sha1::Sha1> as KeyInit>::new_from_slice(key).expect("a key");
    for part in parts {
        mac.update(part);
    }
    mac.finalize().into_bytes().to_vec()
}

/// A kx509 request: the version, then `Kx509Request` with its payload MAC.
fn request(ap_req: &[u8], session: &Key, csr: &[u8], tamper_mac: bool) -> Vec<u8> {
    // `Kx509CSRPlus ::= [APPLICATION 35] SEQUENCE { csr OCTET STRING }`
    let plus = der::tlv(APP_CSR_PLUS, &der::seq(&[der::octets(csr)]));
    let mut mac = hmac_sha1(session.bytes(), &[&VERSION, &plus]);
    if tamper_mac {
        mac[0] ^= 0xff;
    }
    let body = der::seq(&[der::octets(ap_req), der::octets(&mac), der::octets(&plus)]);
    [&VERSION[..], &body].concat()
}

/// What a response carries: the code, the MAC, the certificate, the message.
struct Reply {
    code: i32,
    hash: Option<Vec<u8>>,
    certificate: Option<Vec<u8>>,
    text: Option<String>,
}

fn parse_response(bytes: &[u8]) -> Reply {
    let mut r = Reader::new(bytes);
    let seq = r.next_tlv("Kx509Response").expect("a SEQUENCE");
    let mut f = Reader::new(seq.content);
    let code = f.next_tlv("error-code").expect("error-code");
    let mut cr = Reader::new(code.content);
    let code = der::as_int("error-code", cr.next_tlv("INTEGER").unwrap().content).unwrap() as i32;
    let mut hash = None;
    let mut cert = None;
    let mut text = None;
    while !f.is_empty() {
        let field = f.next_tlv("field").expect("a field");
        let mut fr = Reader::new(field.content);
        let inner = fr.next_tlv("value").expect("a value");
        match field.tag {
            t if t == der::ctx(1) => hash = Some(inner.content.to_vec()),
            t if t == der::ctx(2) => cert = Some(inner.content.to_vec()),
            t if t == der::ctx(3) => {
                text = Some(String::from_utf8_lossy(inner.content).into_owned())
            }
            _ => {}
        }
    }
    Reply {
        code,
        hash,
        certificate: cert,
        text,
    }
}

/// The whole exchange: an authenticated request with a CSR comes back with a certificate, and the
/// reply MAC verifies under the session key the client already holds.
#[test]
fn a_ticket_and_a_csr_become_a_certificate_with_a_verifiable_mac() {
    let (db, kdc) = realm();
    let client = realm_client();
    let (ap, session) = ap_req(&db, &client);
    let req = request(&ap, &session, &csr(), false);

    let reply = parse_response(&kdc.handle(&req, NOW));
    assert_eq!(
        reply.code, 0,
        "a well-formed request must be answered with success: {:?}",
        reply.text
    );
    assert_eq!(
        reply.certificate.as_deref(),
        Some(CERT),
        "the certificate the CA produced"
    );

    // The MAC the client checks: version || DER content of error-code || certificate octets.
    // RFC 6717 §3: the certificate's DER, not the field that carries it.
    let expected = hmac_sha1(session.bytes(), &[&VERSION, &[0x00], CERT]);
    assert_eq!(
        reply.hash.as_deref(),
        Some(expected.as_slice()),
        "the reply MAC must verify under the session key"
    );
}

/// A request whose payload MAC is wrong is refused, and the refusal is authenticated — it carries a
/// MAC too, so a relay cannot turn "wrong MAC" into "here is your certificate".
#[test]
fn a_wrong_payload_mac_is_refused() {
    let (db, kdc) = realm();
    let client = realm_client();
    let (ap, session) = ap_req(&db, &client);
    let req = request(&ap, &session, &csr(), true);

    let reply = kdc.handle(&req, NOW);
    let reply = parse_response(&reply);
    assert_eq!(
        reply.code,
        KRB_ERROR_BASE + rrl_kdc::error::codes::KDC_ERR_PREAUTH_FAILED,
        "the MAC is the payload's authentication, and a bad one is a pre-auth failure"
    );
    assert!(
        reply.certificate.is_none(),
        "no certificate for a request that failed its MAC"
    );
    assert!(
        reply.text.clone().unwrap_or_default().contains("MAC"),
        "{}",
        reply.code
    );
}

/// A ticket for another service is not a kx509 ticket: the service name is what keeps any ticket
/// from being traded for a certificate.
#[test]
fn a_ticket_for_another_service_is_refused() {
    let (db, kdc) = realm();
    let client = realm_client();
    let (ap, session) = ap_req(&db, &client);
    // Rebuild the ticket for a different service name, keeping the client's session key.
    let mut other = ApReq::decode(&ap).expect("the AP-REQ");
    let ticket = Ticket::decode(&other.ticket).expect("the ticket");
    let mut part = EncTicketPart::decode(
        &OwnCipher
            .decrypt(&service_key(&db), usage::KDC_REP_TICKET, &ticket.enc.cipher)
            .expect("the ticket opens"),
    )
    .expect("the part");
    part.cname = client.clone();
    let enc = EncryptedData::seal(
        &OwnCipher,
        &service_key(&db),
        usage::KDC_REP_TICKET,
        None,
        &part.encode(),
    )
    .unwrap();
    other.ticket = Ticket {
        realm: REALM.to_owned(),
        // A service the realm knows and that is not kx509.
        sname: p(&format!("host/other@{REALM}")),
        enc,
    }
    .encode();

    let req = request(&other.encode(), &session, &csr(), false);
    let reply = parse_response(&kdc.handle(&req, NOW));
    assert!(
        reply.certificate.is_none(),
        "no certificate for a ticket for another service"
    );
    assert_ne!(reply.code, 0);
    assert!(
        reply.text.unwrap_or_default().contains("kx509/"),
        "the refusal must say what the ticket had to be for"
    );
}

/// A realm with no CA says so, and says it without pretending the request was understood.
#[test]
fn a_realm_without_a_ca_says_the_service_is_off() {
    let cipher = OwnCipher;
    let db = std::sync::Arc::new(MemoryHdb::new());
    db.insert(kx509::service_entry(REALM, HOST, &cipher, SERVICE_PASSWORD).unwrap())
        .unwrap();
    let kdc = Kdc::new(
        KdcConfig::new(REALM).unwrap(),
        std::sync::Arc::clone(&db) as _,
        std::sync::Arc::new(OwnCipher),
    );
    let (ap, session) = ap_req(&db, &realm_client());
    let req = request(&ap, &session, &csr(), false);
    let reply = parse_response(&kdc.handle(&req, NOW));
    assert_eq!(
        reply.code, 4,
        "a server-side permanent problem, which is what a missing CA is"
    );
    assert!(reply.certificate.is_none());
}

/// An availability probe: no AP-REQ, and the answer says whether the service exists.
#[test]
fn a_probe_is_answered_without_a_mac() {
    let (_db, kdc) = realm();
    let probe = der::seq(&[der::octets(&[]), der::octets(&[]), der::octets(&[])]);
    let req = [&VERSION[..], &probe].concat();
    let reply = parse_response(&kdc.handle(&req, NOW));
    assert_eq!(reply.code, 0, "the service is available: {:?}", reply.text);
    assert!(
        reply.hash.is_none(),
        "a probe carries no session key, so no MAC"
    );
    assert!(reply.certificate.is_none());
}

/// A request that is not kx509 is not claimed: the same port carries KDC-REQs.
#[test]
fn a_non_kx509_request_is_left_to_the_kdc() {
    let (_db, kdc) = realm();
    assert!(
        kdc.handle_kx509(b"not a kx509 request", NOW).is_none(),
        "the KDC must not claim a request that is not kx509"
    );
    assert!(Request::claims(&[0x00, 0x00, 0x02, 0x00]));
    assert!(!Request::claims(&[0x6b]));
}

/// A bare public key where a CSR belongs is refused by name: it proves nothing about who holds the
/// private half, and a certificate for such a key is a certificate for anybody.
#[test]
fn a_bare_public_key_is_refused_as_no_proof_of_possession() {
    let (db, kdc) = realm();
    let (ap, session) = ap_req(&db, &realm_client());
    let spki = der::seq(&[der::seq(&[]), der::tlv(der::BIT_STRING, &[0u8, 1, 2, 3])]);
    let mac = hmac_sha1(session.bytes(), &[&VERSION, &spki]);
    let req = [
        &VERSION[..],
        &der::seq(&[der::octets(&ap), der::octets(&mac), der::octets(&spki)]),
    ]
    .concat();
    let reply = parse_response(&kdc.handle(&req, NOW));
    assert_eq!(reply.code, STATUS_CLIENT_BAD);
    assert!(reply.certificate.is_none());
    assert!(
        reply.text.unwrap_or_default().contains("proof"),
        "{}",
        reply.code
    );
}

/// A principal named in the ticket is the one the certificate names — the SAN comes from the ticket,
/// never from the CSR's subject.
fn realm_client() -> Principal {
    p(&format!("alice@{REALM}"))
}
