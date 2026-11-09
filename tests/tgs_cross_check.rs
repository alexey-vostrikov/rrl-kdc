//! The other direction: a ticket this KDC issued, accepted by somebody else's
//! service.
//!
//! `krb5` proves the exchange works. This proves the *ticket* works: the service
//! — modelled with `rskrb5::service::ServiceValidator`, a second implementation
//! of the acceptor side — reads the ticket with its own key, sees the client the
//! KDC named, and accepts the authenticator the client built over that ticket's
//! session key.
//!
//! Secondary on purpose, and behind the feature: `krb5` is what defines this
//! KDC's behaviour. A failure here means a wire-format disagreement between two
//! implementations, which is worth knowing about, and it is why the test exists
//! rather than being dropped.
#![cfg(feature = "crypto-rskrb5")]

use std::sync::Arc;

use rust_kdc::crypto::{Cipher, Enctype, OwnCipher, usage};
use rust_kdc::hdb::{Hdb, HdbEntry, MemoryHdb};
use rust_kdc::kdc::{Kdc, KdcConfig};
use rust_kdc::msg::{ApReq, Authenticator, EncryptedData};
use rust_kdc::name::Principal;
use rust_kdc::transport::{RunningKdc, serve_loopback};

const REALM: &str = "EXAMPLE.COM";
const PASSWORD: &str = "correct horse battery staple";
const SERVICE: &str = "host/server.example.com";

/// The realm, and the service's own key as the database holds it.
fn realm() -> (Arc<dyn Hdb>, Vec<u8>) {
    let cipher = OwnCipher;
    let db = MemoryHdb::new();
    let mut krbtgt = HdbEntry::krbtgt(REALM);
    krbtgt
        .add_password_key(&cipher, Enctype::Aes256Sha1, b"master", 1)
        .unwrap();
    db.insert(krbtgt).unwrap();
    let mut alice = HdbEntry::user(Principal::parse(&format!("alice@{REALM}")).unwrap());
    alice
        .add_password_key(&cipher, Enctype::Aes256Sha1, PASSWORD.as_bytes(), 1)
        .unwrap();
    db.insert(alice).unwrap();
    let mut service = HdbEntry::service(Principal::parse(&format!("{SERVICE}@{REALM}")).unwrap());
    service
        .add_password_key(&cipher, Enctype::Aes256Sha1, b"the-service-key", 1)
        .unwrap();
    let service_key = service
        .key_for(Enctype::Aes256Sha1)
        .unwrap()
        .key
        .bytes()
        .to_vec();
    db.insert(service).unwrap();
    (Arc::new(db), service_key)
}

fn start() -> (RunningKdc, Vec<u8>) {
    let (db, service_key) = realm();
    let stand = serve_loopback(Kdc::new(
        KdcConfig::new(REALM).unwrap(),
        db,
        Arc::new(OwnCipher),
    ));
    (stand, service_key)
}

#[test]
fn a_second_implementation_accepts_the_ticket_this_kdc_issued() {
    let (stand, service_key_bytes) = start();
    let client = krb5::KdcClient::new(REALM, [stand.addr().as_str()]);
    let alice = krb5::Principal::parse(&format!("alice@{REALM}")).unwrap();
    let tgt = client.login_with_password(&alice, PASSWORD).unwrap();
    let service_principal = krb5::Principal::parse(&format!("{SERVICE}@{REALM}")).unwrap();
    let ticket = client.service_ticket(&tgt, &service_principal).unwrap();

    // The client builds an AP-REQ over the ticket it was given, the way any
    // service client does: the authenticator in the ticket's session key,
    // usage 11, carrying a checksum the service could check if it wanted to.
    let cipher = OwnCipher;
    let session = rust_kdc::crypto::Key::new(
        Enctype::from_id(ticket.session_key.enctype()).unwrap(),
        ticket.session_key.bytes().to_vec(),
    )
    .unwrap();
    let authenticator = Authenticator {
        crealm: REALM.to_owned(),
        cname: Principal::parse(&format!("alice@{REALM}")).unwrap(),
        cksum: Some((
            session.enctype().checksum_type(),
            cipher
                .checksum(&session, usage::AP_REQ_AUTH_CKSUM, b"the application data")
                .unwrap(),
        )),
        cusec: 0,
        ctime: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64,
        subkey: None,
        seq_number: None,
        authorization_data: None,
    };
    let ap_req = ApReq {
        ap_options: 0,
        ticket: ticket.ticket.clone(),
        authenticator: EncryptedData::seal(
            &cipher,
            &session,
            usage::AP_REQ_AUTH,
            None,
            &authenticator.encode(),
        )
        .unwrap(),
    }
    .encode();

    // The service holds its key in a keytab, as a real service does.
    let mut keytab = rskrb5::keytab::Keytab::new();
    keytab.entries_mut().push(rskrb5::keytab::Entry {
        principal: rskrb5::keytab::Principal::new(
            REALM,
            rust_kdc::name::NT_SRV_INST,
            ["host", "server.example.com"],
        ),
        timestamp: 1_700_000_000,
        kvno8: 1,
        key: rskrb5::keytab::EncryptionKey {
            etype: Enctype::Aes256Sha1.id(),
            value: service_key_bytes,
        },
        kvno: 1,
    });

    let mut validator = rskrb5::service::ServiceValidator::new(&keytab);
    let validated = validator
        .validate_ap_req(&ap_req)
        .unwrap_or_else(|e| panic!("a second implementation refused our ticket: {e}"));

    assert_eq!(
        validated.client.name(),
        "alice",
        "the service must see the client the KDC named"
    );
    assert_eq!(
        validated.service.name(),
        SERVICE,
        "the service must see itself as the ticket's target"
    );
    assert_eq!(
        validated.client.realm, REALM,
        "the client's realm comes from the ticket the KDC issued"
    );
    assert_eq!(
        validated.session_key.value,
        ticket.session_key.bytes(),
        "the session key the service recovered must be the one the KDC put in the reply"
    );
}
