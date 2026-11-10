//! The TGS exchange, judged by the primary client.
//!
//! `krb5` does here what `kinit` then `kvno` do: a TGT for `alice`, then a
//! service ticket for `host/server.example.com`. Everything the client checks on
//! the way — that the authenticator's checksum covers the exact octets of
//! `KDC-REQ-BODY`, that the ticket decrypts under the service key, that the
//! reply's nonce matches — is a check this KDC has to pass.

use std::sync::Arc;

use rrl_kdc::crypto::{Enctype, OwnCipher};
use rrl_kdc::hdb::{Hdb, HdbEntry, MemoryHdb};
use rrl_kdc::kdc::{Kdc, KdcConfig};
use rrl_kdc::name::Principal;
use rrl_kdc::transport::{RunningKdc, serve_loopback};

const REALM: &str = "EXAMPLE.COM";
const PASSWORD: &str = "correct horse battery staple";
const SERVICE_KEY_BYTES: &[u8] = b"the-service-key-which-nobody-knows";
const SERVICE: &str = "host/server.example.com";

/// The realm, with `krbtgt`, `alice`, and one service.
fn realm() -> (Arc<dyn Hdb>, HdbEntry) {
    let cipher = OwnCipher;
    let db = MemoryHdb::new();

    let mut krbtgt = HdbEntry::krbtgt(REALM);
    for e in [Enctype::Aes256Sha1, Enctype::Aes128Sha1] {
        krbtgt
            .add_password_key(&cipher, e, b"master-key-of-the-realm", 1)
            .unwrap();
    }
    db.insert(krbtgt).unwrap();

    let mut alice = HdbEntry::user(Principal::parse(&format!("alice@{REALM}")).unwrap());
    for e in [Enctype::Aes256Sha1, Enctype::Aes128Sha1] {
        alice
            .add_password_key(&cipher, e, PASSWORD.as_bytes(), 1)
            .unwrap();
    }
    db.insert(alice).unwrap();

    let mut service = HdbEntry::service(Principal::parse(&format!("{SERVICE}@{REALM}")).unwrap());
    for e in [Enctype::Aes256Sha1, Enctype::Aes128Sha1] {
        service
            .add_password_key(&cipher, e, SERVICE_KEY_BYTES, 1)
            .unwrap();
    }
    db.insert(service.clone()).unwrap();

    (Arc::new(db), service)
}

fn start() -> RunningKdc {
    let (db, _) = realm();
    let kdc = Kdc::new(KdcConfig::new(REALM).unwrap(), db, Arc::new(OwnCipher));
    serve_loopback(kdc)
}

fn client(stand: &RunningKdc) -> krb5::KdcClient {
    krb5::KdcClient::new(REALM, [stand.addr().as_str()])
}

fn alice() -> krb5::Principal {
    krb5::Principal::parse(&format!("alice@{REALM}")).unwrap()
}

#[test]
fn a_client_gets_a_service_ticket_with_its_tgt() {
    let stand = start();
    let c = client(&stand);
    let tgt = c
        .login_with_password(&alice(), PASSWORD)
        .unwrap_or_else(|e| panic!("kinit failed: {e}"));
    let service = krb5::Principal::parse(&format!("{SERVICE}@{REALM}")).unwrap();
    let ticket = c
        .service_ticket(&tgt, &service)
        .unwrap_or_else(|e| panic!("the TGS exchange failed: {e}"));

    assert_eq!(
        ticket.server.to_string(),
        format!("{SERVICE}@{REALM}"),
        "the ticket must be for the service that was asked for"
    );
    assert_eq!(
        ticket.client.to_string(),
        format!("alice@{REALM}"),
        "the ticket must name the client the TGT proved"
    );
    assert!(
        ticket.endtime <= tgt.endtime,
        "a service ticket cannot outlive the TGT it came from: {} > {}",
        ticket.endtime,
        tgt.endtime
    );
    assert!(
        ticket.endtime > ticket.authtime,
        "the ticket must have a positive lifetime"
    );
    assert_ne!(
        ticket.session_key.bytes(),
        tgt.session_key.bytes(),
        "a service ticket gets its own session key, not the TGT's"
    );
    assert_ne!(
        ticket.ticket, tgt.ticket,
        "the ticket itself must differ from the TGT"
    );
}

#[test]
fn two_service_tickets_differ_in_their_session_keys() {
    let stand = start();
    let c = client(&stand);
    let tgt = c.login_with_password(&alice(), PASSWORD).unwrap();
    let service = krb5::Principal::parse(&format!("{SERVICE}@{REALM}")).unwrap();
    let a = c.service_ticket(&tgt, &service).unwrap();
    let b = c.service_ticket(&tgt, &service).unwrap();
    assert_eq!(a.server, b.server);
    assert_ne!(
        a.session_key.bytes(),
        b.session_key.bytes(),
        "two tickets for one service must not share a session key"
    );
}

/// A TGS request without a valid `PA-TGS-REQ` is refused, and refused with
/// `KRB_AP_ERR_MODIFIED` rather than with a ticket: the KDC has no idea who is
/// asking.
#[test]
fn a_tgs_request_without_evidence_is_refused() {
    let (db, _) = realm();
    let kdc = Kdc::new(KdcConfig::new(REALM).unwrap(), db, Arc::new(OwnCipher));
    let reply = kdc.handle(&bare_tgs_request(), 1_700_000_000);
    let err = rrl_kdc::msg::KrbError::decode(&reply)
        .expect("a TGS request without PA-TGS-REQ must be answered with KRB-ERROR");
    assert_eq!(err.code, rrl_kdc::error::codes::KRB_AP_ERR_MODIFIED);
}

/// A `TGS-REQ` with no `PA-TGS-REQ` at all: the body is valid, the evidence is
/// absent.
fn bare_tgs_request() -> Vec<u8> {
    use rrl_kdc::der;
    let body = der::seq(&[
        der::field(0, der::flags32(0)),
        der::field(2, der::general_string(REALM)),
        der::field(
            3,
            Principal::parse(&format!("{SERVICE}@{REALM}"))
                .unwrap()
                .encode_name(),
        ),
        der::field(5, der::time(1_700_003_600)),
        der::field(7, der::int(1)),
        der::field(8, der::seq(&[der::int(18)])),
    ]);
    der::cons(
        der::app(12),
        &[der::seq(&[
            der::field(1, der::int(5)),
            der::field(2, der::int(12)),
            der::field(4, body),
        ])],
    )
}
