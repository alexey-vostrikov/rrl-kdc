//! A propagation from this crate to this crate, over a real socket.
//!
//! Both ends are ours, so this proves the two halves agree — the claim a self-test *can* make, and
//! the one it cannot is interop, which is covered elsewhere: Heimdal's own `hprop` pushes into
//! [`super::Hprop`] in `scripts/hprop-stand.sh`, and it is Heimdal's *reader* that has no equivalent
//! here (its `hprop` reads a Heimdal HDB sealed under a master key this crate does not implement).
//!
//! What is checked, in the order the protocol does it:
//!
//! * the version handshake and the AP-REQ are accepted, and the AP-REP comes back with a subkey —
//!   without mutual authentication a receiver would answer the empty message and the pusher would
//!   read its acknowledgement from an unauthenticated peer;
//! * every entry of the master's database arrives, and the slave installs them only at the end;
//! * the acknowledgement is sealed in the slave's subkey, so a pusher that opened it with its own
//!   would fail the integrity check — the mistake that looks like a perfect handshake;
//! * a push from a name the receiver does not accept is refused, and the pusher says so rather than
//!   hanging.

mod common;

use std::sync::Arc;

use rrl_kdc::crypto::{Cipher, Enctype, Key, OwnCipher};
use rrl_kdc::der;
use rrl_kdc::hdb::{Hdb, HdbEntry, MemoryHdb};
use rrl_kdc::hprop::push::{Pusher, ServiceTicket};
use rrl_kdc::hprop::{self, Hprop, StagedHdb};
use rrl_kdc::msg::{EncTicketPart, EncryptedData, Ticket, tkt_flags};
use rrl_kdc::name::Principal;

const REALM: &str = "EXAMPLE.COM";
const HOST: &str = "localhost";

/// The receiver decides freshness against the wall clock — it serves real clients, and a clock it
/// was told about would be a clock an attacker could choose. So the ticket has to be minted for now,
/// not for a fixed instant: with a stand-in timestamp the receiver answers `KRB_AP_ERR_TKT_EXPIRED`,
/// which is correct and reads like a protocol defect.
fn now() -> i64 {
    rrl_kdc::hprop::now()
}

fn principal(name: &str) -> Principal {
    Principal::parse(&format!("{name}@{REALM}")).unwrap()
}

/// The master's database: a `krbtgt`, the service the push authenticates to, the only client allowed
/// to push, and one user whose arrival is the evidence.
fn master_db() -> (Arc<dyn Hdb>, Key) {
    let cipher = OwnCipher;
    let db = MemoryHdb::new();

    let mut krbtgt = HdbEntry::krbtgt(REALM);
    krbtgt
        .add_password_key(&cipher, Enctype::Aes256Sha1, b"master", 1)
        .unwrap();
    db.insert(krbtgt).unwrap();

    let service = hprop::service_entry(REALM, HOST, &cipher, b"service-pw").unwrap();
    let service_key = service.key_for(Enctype::Aes256Sha1).unwrap().key.clone();
    db.insert(service).unwrap();

    let mut client = HdbEntry::user(principal(hprop::CLIENT));
    client
        .add_password_key(&cipher, Enctype::Aes256Sha1, b"client-pw", 1)
        .unwrap();
    db.insert(client).unwrap();

    let mut alice = HdbEntry::user(principal("alice"));
    alice
        .add_password_key(&cipher, Enctype::Aes256Sha1, b"pw", 1)
        .unwrap();
    db.insert(alice).unwrap();

    (Arc::new(db), service_key)
}

/// A ticket for `hprop/HOST` issued to `client`, as a KDC would have issued it.
///
/// Built here rather than obtained through an AS and a TGS exchange: those are the client's half of
/// Kerberos, and this file is about the propagation that happens after them.
fn ticket_for(service_key: &Key, client: &str) -> ServiceTicket {
    let session_key = OwnCipher.random(Enctype::Aes256Sha1).unwrap();
    let part = EncTicketPart {
        flags: tkt_flags::INITIAL | tkt_flags::PRE_AUTHENT,
        session_key: session_key.clone(),
        crealm: REALM.into(),
        cname: principal(client),
        transited_type: 0,
        transited: Vec::new(),
        authtime: now() - 60,
        starttime: None,
        endtime: now() + 3600,
        renew_till: None,
        caddr: None,
        authorization_data: None,
    };
    let ticket = Ticket {
        realm: REALM.into(),
        sname: Principal::parse(&format!("{}/{HOST}@{REALM}", hprop::SERVICE)).unwrap(),
        enc: EncryptedData::seal(
            &OwnCipher,
            service_key,
            rrl_kdc::crypto::usage::KDC_REP_TICKET,
            Some(1),
            &part.encode(),
        )
        .unwrap(),
    };
    ServiceTicket {
        ticket: ticket.encode(),
        session_key,
    }
}

/// A receiver with an empty staging database, and that database.
fn receiver(master: Arc<dyn Hdb>) -> (rrl_kdc::hprop::RunningHprop, Arc<dyn Hdb>) {
    let staging: Arc<dyn Hdb> = Arc::new(MemoryHdb::new());
    let service = Hprop::new(
        master,
        Arc::new(OwnCipher),
        REALM,
        Arc::new(StagedHdb::new(Arc::clone(&staging))),
    )
    .unwrap();
    (
        hprop::serve_loopback(service).expect("a receiver on loopback"),
        staging,
    )
}

/// The whole propagation: every entry leaves the master, the slave installs them, and both sides
/// know it happened.
#[test]
fn a_master_pushes_its_database_into_a_slave_of_the_same_crate() {
    let (master, service_key) = master_db();
    let ticket = ticket_for(&service_key, hprop::CLIENT);
    let (stand, slave) = receiver(Arc::clone(&master));

    let pusher = Pusher::new(REALM, principal(hprop::CLIENT), Arc::new(OwnCipher));
    let summary = pusher
        .push_to(stand.addr().as_str(), master.as_ref(), &ticket, now())
        .unwrap_or_else(|e| {
            // The receiver's own account of the refusal: a pusher that only reports the missing
            // answer leaves whoever runs it guessing which check the slave objected to.
            std::thread::sleep(std::time::Duration::from_millis(200));
            panic!("the push failed: {e}; the slave said {:?}", stand.results())
        });

    // Four entries: krbtgt, hprop/HOST, kadmin/hprop, alice. The count is asserted rather than
    // bounded: a push that silently dropped one would still install a usable-looking database.
    assert_eq!(summary.entries, 4, "every entry of the master's database");

    // `krbtgt/REALM`, not `krbtgt`: the two-component name is the one a realm uses, and asking for
    // the short form would report a missing entry for a principal that was never supposed to exist.
    for who in [
        principal("alice"),
        principal(hprop::CLIENT),
        Principal::krbtgt(REALM),
    ] {
        assert!(
            slave
                .fetch(&who)
                .unwrap_or_else(|e| panic!("reading {who} from the slave: {e}"))
                .is_some(),
            "{who} did not arrive: the slave holds {} entries",
            count(&slave)
        );
    }
    assert_eq!(count(&slave), 4, "and nothing else was invented");
}

/// The slave's copy serves tickets — which is what makes it a domain controller rather than a
/// replica of a file.
#[test]
fn the_slave_serves_a_ticket_from_what_it_was_pushed() {
    use rrl_kdc::kdc::{Kdc, KdcConfig};

    let (master, service_key) = master_db();
    let ticket = ticket_for(&service_key, hprop::CLIENT);
    let (stand, slave) = receiver(Arc::clone(&master));
    Pusher::new(REALM, principal(hprop::CLIENT), Arc::new(OwnCipher))
        .push_to(stand.addr().as_str(), master.as_ref(), &ticket, now())
        .expect("the push");

    let kdc = Kdc::new(
        KdcConfig::new(REALM).unwrap(),
        Arc::clone(&slave),
        Arc::new(OwnCipher),
    );
    // An AS-REQ for the user the push brought: what a client would do against this controller.
    let request = as_req("alice");
    let reply = kdc.handle_from(&request, now(), None);
    // `PREAUTH_REQUIRED` is the right answer for a user this realm knows: the slave read her entry,
    // looked at her keys and asked for pre-authentication. An unknown principal would answer
    // `KDC_ERR_C_PRINCIPAL_UNKNOWN` (6), and a ticket would mean pre-authentication is off — so the
    // code, not the absence of an error, is what says the entry arrived.
    let err = rrl_kdc::msg::KrbError::decode(&reply)
        .unwrap_or_else(|_| panic!("expected a pre-authentication challenge, got a ticket"));
    assert_eq!(
        err.code,
        rrl_kdc::error::codes::KDC_ERR_PREAUTH_REQUIRED,
        "the slave answered {:?} for the user it was pushed",
        (err.code, err.e_text)
    );
}

/// A push from a name the receiver does not authorise is refused, and the pusher hears about it.
///
/// The refusal happens *after* the version handshake — the receiver writes its ok octet, then
/// refuses the AP-REQ — so the pusher is left waiting for a message that will not come. That is the
/// protocol's shape, and the test pins that the failure is reported rather than hanging.
#[test]
fn a_push_from_an_unauthorised_client_is_refused() {
    let (master, service_key) = master_db();
    // A ticket issued to `alice` instead of `kadmin/hprop`: she may reach the service and may not
    // push to it.
    let ticket = ticket_for(&service_key, "alice");
    let (stand, slave) = receiver(Arc::clone(&master));

    let err = Pusher::new(REALM, principal("alice"), Arc::new(OwnCipher))
        .push_to(stand.addr().as_str(), master.as_ref(), &ticket, now())
        .expect_err("only kadmin/hprop may push");
    let text = err.to_string();
    assert!(
        text.contains("closed") || text.contains("acknowledgement"),
        "the refusal is reported as the missing answer it is: {text}"
    );
    assert_eq!(count(&slave), 0, "and nothing was installed");
}

/// How many principals the database holds, walked the way the pusher walks it.
fn count(hdb: &Arc<dyn Hdb>) -> usize {
    let mut seen = 0;
    let mut after = None;
    loop {
        let next = match &after {
            None => hdb.first().unwrap(),
            Some(principal) => hdb.next(principal).unwrap(),
        };
        let Some(principal) = next else { break };
        after = Some(principal);
        seen += 1;
    }
    seen
}

/// A bare `AS-REQ`, as `common` builds one for the TGS tests.
fn as_req(name: &str) -> Vec<u8> {
    let body = der::seq(&[
        der::field(0, der::flags32(0)),
        der::field(1, principal(name).encode_name()),
        der::field(2, der::general_string(REALM)),
        der::field(3, Principal::krbtgt(REALM).encode_name()),
        der::field(5, der::time(now() + 3600)),
        der::field(7, der::int(0x9001)),
        der::field(8, der::seq(&[der::int(18)])),
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
