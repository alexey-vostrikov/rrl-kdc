//! What the audit trail records, checked against the engine rather than described.
//!
//! Three properties are worth pinning, because each of them is a way an audit trail becomes useless
//! without anybody noticing:
//!
//! * **one record per request** — a request with no record is indistinguishable from a request that
//!   never arrived, and that ambiguity is exactly what an incident review cannot afford;
//! * **the subject is what was granted**, not what was asked for — a `TGS-REQ` names its client
//!   inside the ticket, and an alias or a canonicalization changes it;
//! * **a refusal is recorded with the code the client received** — a trail naming a different code
//!   sends an operator looking for a failure that did not happen.
//!
//! And one that is a design decision rather than a property: an undecodable request is recorded too,
//! because a trail that begins after decoding cannot count probes.

use std::sync::Arc;

use rrl_kdc::crypto::{Enctype, OwnCipher};
use rrl_kdc::der;
use rrl_kdc::error::codes;
use rrl_kdc::hdb::{HdbEntry, MemoryHdb, flags as entry_flags};
use rrl_kdc::kdc::audit::{Audit, Collector, Exchange, Outcome, Record};
use rrl_kdc::kdc::{Kdc, KdcConfig};
use rrl_kdc::msg::{self, PA_ENC_TIMESTAMP, encode_pa_data, kdc_options};
use rrl_kdc::name::Principal;

const REALM: &str = "EXAMPLE.COM";
const PASSWORD: &str = "correct horse battery staple";
const NOW: i64 = 1_700_000_000;

fn principal(name: &str) -> Principal {
    Principal::parse(&format!("{name}@{REALM}")).unwrap()
}

fn db() -> MemoryHdb {
    let cipher = OwnCipher;
    let db = MemoryHdb::new();
    let mut krbtgt = HdbEntry::krbtgt(REALM);
    krbtgt
        .add_password_key(&cipher, Enctype::Aes256Sha1, b"master", 1)
        .unwrap();
    db.insert(krbtgt).unwrap();
    let mut alice = HdbEntry::user(principal("alice"));
    alice
        .add_password_key(&cipher, Enctype::Aes256Sha1, PASSWORD.as_bytes(), 1)
        .unwrap();
    db.insert(alice).unwrap();
    db
}

fn kdc(audit: Arc<dyn Audit>) -> Kdc {
    Kdc::new(
        KdcConfig::new(REALM).unwrap(),
        Arc::new(db()),
        Arc::new(OwnCipher),
    )
    .with_audit(audit)
}

/// An `AS-REQ` for `name`, with optional pre-authentication.
fn as_req(name: &str, padata: Vec<(i32, Vec<u8>)>) -> Vec<u8> {
    let client = principal(name);
    let body = der::seq(&[
        der::field(0, der::flags32(kdc_options::FORWARDABLE)),
        der::field(1, client.encode_name()),
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

/// An encrypted timestamp for `password`.
fn enc_timestamp(password: &[u8]) -> Vec<u8> {
    use rrl_kdc::crypto::{Cipher, usage};
    let cipher = OwnCipher;
    let key = cipher
        .s2k(
            Enctype::Aes256Sha1,
            password,
            format!("{REALM}alice").as_bytes(),
            None,
        )
        .unwrap();
    let plain = msg::encode_enc_ts_enc(NOW, None);
    msg::EncryptedData::seal(&cipher, &key, usage::AS_REQ_PA_ENC_TS, None, &plain)
        .unwrap()
        .encode()
}

/// A successful login is one record, and it says what was issued.
#[test]
fn an_issued_ticket_is_one_record_and_it_names_the_client() {
    let collector = Arc::new(Collector::new());
    let kdc = kdc(Arc::clone(&collector) as Arc<dyn Audit>);
    let reply = kdc.handle_from(
        &as_req(
            "alice",
            vec![(PA_ENC_TIMESTAMP, enc_timestamp(PASSWORD.as_bytes()))],
        ),
        NOW,
        Some("192.0.2.5".parse().unwrap()),
    );
    // The reply is a real one, so the record describes a decision that happened. A `KDC-REP`
    // decodes as an error only if it is one, which is the cheapest way to say "this was granted".
    assert!(
        msg::KrbError::decode(&reply).is_err(),
        "an issued ticket is not a KRB-ERROR"
    );

    let records = collector.records();
    assert_eq!(records.len(), 1, "one request, one record");
    let record = &records[0];
    assert_eq!(record.exchange, Exchange::As);
    assert_eq!(record.outcome, Outcome::Issued);
    assert_eq!(record.code, None);
    assert_eq!(
        record.client.as_ref().map(ToString::to_string).as_deref(),
        Some("alice@EXAMPLE.COM"),
        "the client the ticket was issued to"
    );
    assert_eq!(
        record.service.as_ref().map(ToString::to_string).as_deref(),
        Some("krbtgt/EXAMPLE.COM@EXAMPLE.COM")
    );
    assert_eq!(
        record.peer.map(|p| p.to_string()).as_deref(),
        Some("192.0.2.5")
    );
    assert_eq!(record.at, NOW);
}

/// A refusal is one record carrying the code the client was given.
///
/// The code comes from the same place the reply's does, so the trail cannot name a failure the
/// client never saw.
#[test]
fn a_refusal_is_recorded_with_the_code_the_client_received() {
    let collector = Arc::new(Collector::new());
    let kdc = kdc(Arc::clone(&collector) as Arc<dyn Audit>);
    // A wrong password: pre-authentication fails.
    let reply = kdc.handle_from(
        &as_req("alice", vec![(PA_ENC_TIMESTAMP, enc_timestamp(b"wrong"))]),
        NOW,
        None,
    );
    let error = msg::KrbError::decode(&reply).expect("a KRB-ERROR");

    let records = collector.records();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].outcome, Outcome::Refused);
    assert_eq!(
        records[0].code,
        Some(error.code),
        "the trail names the code the client got"
    );
    assert_eq!(
        records[0]
            .client
            .as_ref()
            .map(ToString::to_string)
            .as_deref(),
        Some("alice@EXAMPLE.COM"),
        "a refusal records who asked, because the error reply carries no client"
    );
}

/// A principal that does not exist is refused and recorded, and the two agree.
#[test]
fn a_missing_principal_is_one_refusal() {
    let collector = Arc::new(Collector::new());
    let kdc = kdc(Arc::clone(&collector) as Arc<dyn Audit>);
    let reply = kdc.handle_from(&as_req("nobody", Vec::new()), NOW, None);
    let error = msg::KrbError::decode(&reply).expect("a KRB-ERROR");
    assert_eq!(error.code, codes::KDC_ERR_C_PRINCIPAL_UNKNOWN);

    let records = collector.records();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].code, Some(codes::KDC_ERR_C_PRINCIPAL_UNKNOWN));
}

/// A request that is not a `KDC-REQ` is still recorded: a burst of these is what a probe looks like.
#[test]
fn an_undecodable_request_is_recorded_too() {
    let collector = Arc::new(Collector::new());
    let kdc = kdc(Arc::clone(&collector) as Arc<dyn Audit>);
    let reply = kdc.handle_from(b"this is not a kerberos message", NOW, None);
    assert!(!reply.is_empty(), "a request always gets an answer");

    let records = collector.records();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].exchange, Exchange::Undecodable);
    assert_eq!(records[0].outcome, Outcome::Refused);
    assert_eq!(records[0].client, None, "there is no client to name");
    assert_eq!(records[0].realm, REALM, "the realm is this KDC's own");
    assert!(records[0].code.is_some(), "and the code is the one sent");
}

/// The whole path end to end through a driver: a closure receives one line per decision, and the
/// lines say what the records said.
///
/// This is the shape a deployment takes — a `syslog` call, a channel, a counter — and testing it
/// through the engine rather than through the types is what proves the wiring: a `StreamAudit` that
/// nobody handed to a `Kdc` would pass every test in the module above.
#[test]
fn a_driver_receives_one_line_per_decision() {
    use rrl_kdc::kdc::audit::StreamAudit;
    use std::sync::Mutex;

    let lines = Arc::new(Mutex::new(Vec::<String>::new()));
    let sink = StreamAudit::new({
        let lines = Arc::clone(&lines);
        move |line: &str| {
            lines
                .lock()
                .expect("a test's lock is never poisoned")
                .push(line.to_owned())
        }
    });
    let kdc = kdc(Arc::new(sink) as Arc<dyn Audit>);

    // One granted, one refused: two decisions, two lines.
    kdc.handle_from(
        &as_req(
            "alice",
            vec![(PA_ENC_TIMESTAMP, enc_timestamp(PASSWORD.as_bytes()))],
        ),
        NOW,
        Some("192.0.2.9".parse().unwrap()),
    );
    kdc.handle_from(&as_req("nobody", Vec::new()), NOW, None);

    let lines = lines.lock().expect("a test's lock").clone();
    assert_eq!(lines.len(), 2, "two requests, two lines: {lines:?}");
    assert_eq!(
        lines[0],
        format!(
            "at={NOW} as issued client=alice@EXAMPLE.COM service=krbtgt/EXAMPLE.COM@EXAMPLE.COM \
             realm=EXAMPLE.COM peer=192.0.2.9"
        )
    );
    assert!(
        lines[1].contains("as refused") && lines[1].contains("client=nobody@EXAMPLE.COM"),
        "the refusal names who asked: {}",
        lines[1]
    );
    assert!(
        lines[1].contains(&format!("code={}", codes::KDC_ERR_C_PRINCIPAL_UNKNOWN)),
        "and the code the client got: {}",
        lines[1]
    );
}

/// A realm with no sink records nothing and answers exactly as before.
///
/// The default is silence, and silence must not change a decision: an audit trail that altered
/// behaviour would be a new failure mode rather than an observer.
#[test]
fn without_a_sink_answers_are_unchanged() {
    // Two realms with the same keys: `MemoryHdb` is not `Clone`, and copying one would not prove
    // anything the same content does not.
    let plain = Kdc::new(
        KdcConfig::new(REALM).unwrap(),
        Arc::new(db()),
        Arc::new(OwnCipher),
    );
    let collector = Arc::new(Collector::new());
    let watched = Kdc::new(
        KdcConfig::new(REALM).unwrap(),
        Arc::new(db()),
        Arc::new(OwnCipher),
    )
    .with_audit(Arc::clone(&collector) as Arc<dyn Audit>);

    let request = as_req(
        "alice",
        vec![(PA_ENC_TIMESTAMP, enc_timestamp(PASSWORD.as_bytes()))],
    );
    let a = plain.handle_from(&request, NOW, None);
    let b = watched.handle_from(&request, NOW, None);
    // Not byte equality: a granted ticket carries a random session key and a confounder, so two
    // honest replies to one request differ. What must not differ is the **decision**.
    assert!(
        msg::KrbError::decode(&a).is_err() && msg::KrbError::decode(&b).is_err(),
        "both granted the ticket"
    );
    assert_eq!(
        a.len(),
        b.len(),
        "and neither reply grew or shrank because a sink was watching"
    );
    assert_eq!(collector.len(), 1, "and the watched one recorded it");
}

/// A sink that does nothing is a legal sink, and the KDC does not require one to be interested.
#[test]
fn a_sink_that_keeps_nothing_is_legal() {
    struct Quiet;
    impl Audit for Quiet {
        fn record(&self, _record: &Record) {}
    }
    let kdc = kdc(Arc::new(Quiet));
    let reply = kdc.handle_from(&as_req("alice", Vec::new()), NOW, None);
    assert_eq!(
        msg::KrbError::decode(&reply).expect("a KRB-ERROR").code,
        codes::KDC_ERR_PREAUTH_REQUIRED,
        "a request with no pre-authentication is answered as it always was"
    );
}

/// The flag an entry carries is visible to the trail's reader through the code, not through prose:
/// a locked or disabled account is refused, and the refusal is one record.
#[test]
fn a_disabled_entry_is_one_refusal() {
    let cipher = OwnCipher;
    let db = MemoryHdb::new();
    let mut krbtgt = HdbEntry::krbtgt(REALM);
    krbtgt
        .add_password_key(&cipher, Enctype::Aes256Sha1, b"master", 1)
        .unwrap();
    db.insert(krbtgt).unwrap();
    let mut alice = HdbEntry::user(principal("alice"));
    alice.flags |= entry_flags::INVALID;
    alice
        .add_password_key(&cipher, Enctype::Aes256Sha1, PASSWORD.as_bytes(), 1)
        .unwrap();
    db.insert(alice).unwrap();

    let collector = Arc::new(Collector::new());
    let kdc = Kdc::new(
        KdcConfig::new(REALM).unwrap(),
        Arc::new(db),
        Arc::new(OwnCipher),
    )
    .with_audit(Arc::clone(&collector) as Arc<dyn Audit>);
    let reply = kdc.handle_from(
        &as_req(
            "alice",
            vec![(PA_ENC_TIMESTAMP, enc_timestamp(PASSWORD.as_bytes()))],
        ),
        NOW,
        None,
    );
    let error = msg::KrbError::decode(&reply).expect("a KRB-ERROR");
    let records = collector.records();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].outcome, Outcome::Refused);
    assert_eq!(records[0].code, Some(error.code));
}
