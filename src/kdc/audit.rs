//! The audit trail: one record per decision, and nothing else.
//!
//! Heimdal reaches this through `kdc/kdc-plugin.c`'s `audit` hook, which hands a plugin the whole
//! request — decrypted ticket, outcome, error code. The equivalent here is a trait a deployment
//! implements over whatever log it already has, and a [`Record`] carrying the facts an operator
//! greps for: who asked for what, from where, and whether it was granted.
//!
//! # What a record deliberately does not carry
//!
//! **No key material, no PAC, no pre-authentication secret, and no password.** A log that leaks any
//! of those is worse than no log, because it is a copy of the realm's secrets written to a place
//! nobody hardened. The pre-authentication mechanism's *name* is not recorded either: the reply says
//! what it accepted, and a name in a log would invite a reader to treat a weaker mechanism as
//! equivalent to a stronger one that achieved the same ticket.
//!
//! # Why the record is emitted here and not inside the exchanges
//!
//! Exactly one place answers a request — [`crate::kdc::Kdc::handle_from`] — so exactly one place
//! can guarantee that every request produces exactly one record. An exchange that emitted its own
//! records would emit none for the requests refused before it ran, and two for any it answered
//! through a second path; a log where a request's absence is ambiguous is a log an incident review
//! cannot use.
//!
//! The **client** is taken from the reply, not from the request: a `TGS-REQ` names its client
//! inside the presented ticket, which only the KDC can open, and the reply states the name the KDC
//! decided on — after canonicalization, after an alias, after `PA-FOR-USER`. Recording the request's
//! spelling would be a record of what was asked rather than of what was granted.
//!
//! # Three layers, and why there are three
//!
//! * [`Record`] is the decision, as data. Everything above can be replaced without changing it.
//! * [`Audit`] takes records. A deployment that batches, samples, signs or ships them implements
//!   this, and the KDC calls nothing else.
//! * [`AuditDriver`] takes records too, and is where an exporter lives. It exists so that the
//!   transport is a seam: `syslog(3)`, journald, a file and an OTLP exporter have nothing in common
//!   except that they want the decision.
//!
//! [`DriverAudit`] is the bridge a deployment usually wants: `Audit` over a driver. It renders
//! nothing — a driver that wants text asks for [`Record::to_line`], which is one rendering among
//! several and a lossy one by construction.
//!
//! # OpenTelemetry
//!
//! An OTLP log record carries a body **and** attributes, so the mapping is part of the contract
//! rather than something an exporter invents: [`Record::attributes`] gives a stable key set
//! (`kerberos.*` for this protocol's own facts, `client.address` where the OpenTelemetry semantic
//! conventions already name one), [`Record::severity_number`] follows their `SeverityNumber`
//! enumeration (9 `INFO`, 13 `WARN`), and the body is [`Record::to_line`]. An exporter ships those
//! four things and nothing else, which means two deployments' dashboards agree.
//!
//! # A sink cannot fail
//!
//! [`Audit::record`] and [`AuditDriver::emit`] return nothing. A log file that is full must not
//! refuse a login the realm would otherwise grant: an audit trail is evidence, and evidence that can
//! be switched off by filling a disk is not evidence. A sink that wants to report a write failure
//! reports it on its own channel, where it does not become an authentication decision.

use std::net::IpAddr;
use std::sync::Mutex;

use crate::der::{Fields, Reader, SEQUENCE};
use crate::name::Principal;

/// Which exchange a record describes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Exchange {
    /// An `AS-REQ`: a client asking for a ticket-granting ticket.
    As,
    /// A `TGS-REQ`: a client presenting a ticket and asking for another.
    Tgs,
    /// A request that did not decode as either. Recorded rather than dropped: a burst of these is
    /// what a probe looks like, and a trail that starts only after decoding has a blind spot exactly
    /// where an attacker is cheapest.
    Undecodable,
}

impl Exchange {
    /// The name an operator reads.
    pub fn as_str(self) -> &'static str {
        match self {
            Exchange::As => "as",
            Exchange::Tgs => "tgs",
            Exchange::Undecodable => "undecodable",
        }
    }
}

/// Whether the request was answered or refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// A reply the client can use.
    Issued,
    /// A `KRB-ERROR`.
    Refused,
}

/// One decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    /// When the KDC answered, in seconds since the Unix epoch.
    ///
    /// A number rather than a formatted string: a KDC has no business carrying a calendar, and
    /// whatever collects these records already knows how to print a timestamp.
    pub at: i64,
    /// Which exchange this was.
    pub exchange: Exchange,
    /// The client, as the reply states it. `None` when the request was refused before a client was
    /// established — an undecodable request, or a `TGS-REQ` whose ticket did not open.
    pub client: Option<Principal>,
    /// The service the ticket was for, as the request named it.
    pub service: Option<Principal>,
    /// The realm the request named.
    pub realm: String,
    /// Where the request came from, when the transport knows.
    pub peer: Option<IpAddr>,
    /// Granted or refused.
    pub outcome: Outcome,
    /// The Kerberos error code, for a refusal. `None` when the request was answered.
    pub code: Option<i32>,
}

/// Where a record goes.
///
/// Implemented by a deployment over its own log. The one rule is in the trait's shape: `record`
/// cannot fail, so a broken sink cannot turn a login into a refusal.
pub trait Audit: Send + Sync {
    /// Takes one decision. Called at most once per request, on the thread that answered it.
    fn record(&self, record: &Record);
}

/// A sink that keeps records in memory, for tests and for a caller that batches its own writes.
#[derive(Debug, Default)]
pub struct Collector {
    records: Mutex<Vec<Record>>,
}

impl Collector {
    /// An empty collector.
    pub fn new() -> Self {
        Self::default()
    }

    /// Everything recorded so far, oldest first.
    pub fn records(&self) -> Vec<Record> {
        self.records
            .lock()
            .expect("a collector's lock is never held across a panic")
            .clone()
    }

    /// How many records there are.
    pub fn len(&self) -> usize {
        self.records
            .lock()
            .expect("a collector's lock is never held across a panic")
            .len()
    }

    /// Whether nothing has been recorded.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Audit for Collector {
    fn record(&self, record: &Record) {
        self.records
            .lock()
            .expect("a collector's lock is never held across a panic")
            .push(record.clone());
    }
}

/// Where an audit record goes: a file, a pipe, syslog, journald, an OTLP exporter.
///
/// **A driver receives the [`Record`], not a rendered line.** The line is one rendering among
/// several, and a driver that could only take text would force every destination through it: an
/// OpenTelemetry log record carries a body *and* attributes, a journald entry carries fields, and a
/// collector indexes by attribute. Handing a driver a string would mean re-parsing our own line at
/// the far end, which is a private format nobody asked to support.
///
/// Not `std::io::Write` either: `syslog(3)` is a C function that returns nothing, journald frames
/// fields over a socket, and an OTLP exporter is a client with its own batching and retry. Each is a
/// few lines behind this trait; none of them is a writer.
///
/// A driver is where batching and retry live — an OTLP exporter is expected to buffer and to fail
/// asynchronously — which is why the trait has no `flush` and no error. The seam is the record; what
/// happens after it is the exporter's business.
pub trait AuditDriver: Send + Sync {
    /// Takes one decision.
    ///
    /// Returns nothing: a driver that cannot deliver has nowhere to report it that is not the
    /// authentication path. It reports on its own channel — an exporter's metrics, the deployment's
    /// logging — or not at all.
    fn emit(&self, record: &Record);
}

/// Any closure is a driver, which is what makes a deployment's own sink short: a `syslog` call, a
/// channel send, a counter in a test.
impl<F> AuditDriver for F
where
    F: Fn(&Record) + Send + Sync,
{
    fn emit(&self, record: &Record) {
        self(record);
    }
}

/// A driver over anything that takes bytes, writing [`Record::to_line`] and flushing after every
/// record.
///
/// **The flush is the point.** An audit trail that sits in a buffer when the process dies is a trail
/// missing exactly the records that matter — the last ones, before whatever killed it. The cost is a
/// write syscall per request, which a KDC issuing thousands of tickets a second will feel; a
/// deployment that wants batching writes its own [`Audit`] — or its own driver — where the trade is
/// visible rather than hidden in a sink that claims to be durable.
pub struct ToWriter<W: std::io::Write + Send> {
    out: Mutex<W>,
}

impl<W: std::io::Write + Send> ToWriter<W> {
    /// Wraps `out`.
    pub fn new(out: W) -> Self {
        Self {
            out: Mutex::new(out),
        }
    }

    /// The writer back, for a caller that wants to close it or read what it wrote.
    pub fn into_inner(self) -> W {
        self.out
            .into_inner()
            .expect("a writer driver's lock is never held across a panic")
    }
}

impl<W: std::io::Write + Send> AuditDriver for ToWriter<W> {
    fn emit(&self, record: &Record) {
        // A write failure is swallowed here for the same reason the trait returns nothing: a full
        // disk must not refuse a login the realm would grant.
        let Ok(mut out) = self.out.lock() else {
            return;
        };
        let _ = writeln!(out, "{}", record.to_line());
        let _ = out.flush();
    }
}

/// An [`Audit`] that hands every record to a driver.
///
/// The shortest wiring a deployment needs: `Kdc::with_audit(Arc::new(DriverAudit::new(exporter)))`.
/// It does not render, aggregate or batch — a driver that wants any of that does it, because the
/// record is structured and the exporter is the only thing that knows what its destination takes.
pub struct DriverAudit<D: AuditDriver> {
    driver: D,
}

impl<D: AuditDriver> DriverAudit<D> {
    /// Wraps `driver`.
    pub fn new(driver: D) -> Self {
        Self { driver }
    }

    /// The driver back.
    pub fn into_driver(self) -> D {
        self.driver
    }
}

impl<D: AuditDriver> Audit for DriverAudit<D> {
    fn record(&self, record: &Record) {
        self.driver.emit(record);
    }
}

impl Record {
    /// The record as one line — **a rendering, not the record**.
    ///
    /// One line because that is what every line-oriented collector can index: a multi-line record is
    /// one event split into several, and the next record's first line arrives in the middle of it.
    /// Anything that can carry structure should take [`Record::attributes`] instead; this is for
    /// files, `syslog` and pipes.
    pub fn to_line(&self) -> String {
        let mut out = format!("at={} {}", self.at, self.exchange.as_str());
        out.push_str(match self.outcome {
            Outcome::Issued => " issued",
            Outcome::Refused => " refused",
        });
        if let Some(client) = &self.client {
            out.push_str(&format!(" client={client}"));
        }
        if let Some(service) = &self.service {
            out.push_str(&format!(" service={service}"));
        }
        out.push_str(&format!(" realm={}", self.realm));
        if let Some(peer) = self.peer {
            out.push_str(&format!(" peer={peer}"));
        }
        if let Some(code) = self.code {
            out.push_str(&format!(" code={code}"));
        }
        out
    }

    /// The record as OpenTelemetry attributes: a stable key set, in a stable order.
    ///
    /// The `kerberos.*` keys are this crate's own — the protocol has facts OpenTelemetry's semantic
    /// conventions do not name, and inventing a key per deployment would make two dashboards
    /// describe different realms. `client.address` is theirs, and is used where they define it.
    ///
    /// Absent facts are **absent keys**, not empty strings: an exporter that emitted
    /// `kerberos.client=""` for a refusal that never named a client would put an account with no
    /// name into a group-by.
    pub fn attributes(&self) -> Vec<(&'static str, String)> {
        let mut out = vec![
            ("kerberos.exchange", self.exchange.as_str().to_owned()),
            (
                "kerberos.outcome",
                match self.outcome {
                    Outcome::Issued => "issued".to_owned(),
                    Outcome::Refused => "refused".to_owned(),
                },
            ),
            ("kerberos.realm", self.realm.clone()),
        ];
        if let Some(client) = &self.client {
            out.push(("kerberos.client", client.to_string()));
        }
        if let Some(service) = &self.service {
            out.push(("kerberos.service", service.to_string()));
        }
        if let Some(peer) = self.peer {
            // The semantic convention's own key, so a collector can join this with whatever else it
            // knows about that address without being taught a second spelling.
            out.push(("client.address", peer.to_string()));
        }
        if let Some(code) = self.code {
            out.push(("kerberos.error_code", code.to_string()));
        }
        out
    }

    /// The OpenTelemetry `SeverityNumber` for this decision.
    ///
    /// `9` (`INFO`) for a ticket, `13` (`WARN`) for a refusal. Not `ERROR`: a refusal is the KDC
    /// working — a wrong password is a fact about a client, not a fault in this server — and a
    /// dashboard that paints every wrong password red teaches its readers to ignore red. A realm
    /// that wants errors has [`Record::code`] to alert on, which is the number that distinguishes
    /// "wrong password" from "the database is gone".
    pub fn severity_number(&self) -> i32 {
        match self.outcome {
            Outcome::Issued => 9,
            Outcome::Refused => 13,
        }
    }

    /// The OpenTelemetry `SeverityText` that goes with [`Self::severity_number`].
    pub fn severity_text(&self) -> &'static str {
        match self.outcome {
            Outcome::Issued => "INFO",
            Outcome::Refused => "WARN",
        }
    }
}

impl std::fmt::Display for Record {
    /// [`Record::to_line`], so that `{record}` and `record.to_line()` cannot disagree.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_line())
    }
}

/// The client a `KDC-REP` names, read out of the reply's **outer** part.
///
/// `KDC-REP ::= [APPLICATION 13] SEQUENCE { pvno [0], msg-type [1], padata [2] OPTIONAL,
/// crealm [3], cname [4], ticket [5], enc-part [6] }` (RFC 4120 §5.4.2) — the client and its realm
/// are outside the encryption, which is why a reply can be read for them without a key.
///
/// Returns `None` on anything unexpected rather than an error: this runs while building a log
/// record, and a reply this crate produced must never be affected by the audit trail reading it.
/// A record with no client is a smaller loss than a reply that failed to go out.
pub(crate) fn reply_subject(reply: &[u8], fallback_realm: &str) -> Option<Principal> {
    let mut r = Reader::new(reply);
    let application = r.next_tlv("KDC-REP").ok()?;
    // `[APPLICATION 13] KDC-REP`, and `KDC-REP` is a `SEQUENCE`: the application tag wraps it.
    let mut inner = Reader::new(application.content);
    let content = inner.expect_in("KDC-REP", SEQUENCE).ok()?;
    let f = Fields::parse("KDC-REP", content).ok()?;
    let realm = f.string(3, "KDC-REP").ok()?;
    // `Principal::decode_field` and not `Principal::decode`: `cname [4]` is a tagged wrapper around
    // the `PrincipalName` SEQUENCE, and reading its bytes as the structure itself yields a name type
    // of 0 and no components — a subject that parses and names nobody.
    let _ = fallback_realm;
    Principal::decode_field(&f, 4, "KDC-REP", &realm).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Enctype;
    use crate::msg::{KdcRep, Ticket};
    use std::io::Write;

    fn principal(name: &str) -> Principal {
        Principal::parse(name).expect("a principal")
    }

    /// A reply's client is read from the reply, not from what a request asked for.
    ///
    /// The two differ whenever the KDC decides a name: an alias, a canonicalization, a
    /// `PA-FOR-USER`. A trail that recorded the request would say a ticket was issued to a name no
    /// ticket was issued to.
    #[test]
    fn the_subject_comes_from_the_reply() {
        let rep = KdcRep {
            msg_type: crate::msg::AS_REP,
            padata: Vec::new(),
            crealm: "EXAMPLE.COM".into(),
            cname: principal("alice@EXAMPLE.COM"),
            ticket: Ticket {
                realm: "EXAMPLE.COM".into(),
                sname: Principal::krbtgt("EXAMPLE.COM"),
                enc: crate::msg::EncryptedData {
                    etype: Enctype::Aes256Sha1,
                    kvno: None,
                    cipher: vec![0u8; 16],
                },
            },
            enc_part: crate::msg::EncryptedData {
                etype: Enctype::Aes256Sha1,
                kvno: None,
                cipher: vec![0u8; 16],
            },
        };
        let subject = reply_subject(&rep.encode(), "OTHER.REALM").expect("a client");
        assert_eq!(subject.to_string(), "alice@EXAMPLE.COM");
    }

    /// A reply that is not one returns `None` instead of failing: the audit trail may not break a
    /// reply it is describing.
    #[test]
    fn a_reply_that_is_not_a_kdc_rep_yields_no_subject() {
        for bytes in [&b""[..], b"\x00", b"not a reply", &[0x6d, 0x00][..]] {
            assert_eq!(reply_subject(bytes, "EXAMPLE.COM"), None);
        }
    }

    /// A collector keeps the records in order, and a sink cannot fail.
    #[test]
    fn a_collector_keeps_every_record_in_order() {
        let collector = Collector::new();
        assert!(collector.is_empty());
        for at in [10, 20, 30] {
            collector.record(&Record {
                at,
                exchange: Exchange::As,
                client: Some(principal("alice@EXAMPLE.COM")),
                service: Some(Principal::krbtgt("EXAMPLE.COM")),
                realm: "EXAMPLE.COM".into(),
                peer: None,
                outcome: Outcome::Issued,
                code: None,
            });
        }
        assert_eq!(collector.len(), 3);
        let ats: Vec<i64> = collector.records().iter().map(|r| r.at).collect();
        assert_eq!(ats, vec![10, 20, 30]);
    }

    /// A closure is a driver, and it receives the **record**, not a rendering of it.
    ///
    /// That is the property an OTLP exporter depends on: a driver handed a formatted line would have
    /// to re-parse this crate's private text to recover the fields, and a collector indexing by
    /// attribute would be indexing a string it was never given.
    #[test]
    fn a_closure_is_a_driver_and_receives_the_record() {
        let seen = std::sync::Arc::new(Mutex::new(Vec::<Record>::new()));
        let sink = {
            let seen = std::sync::Arc::clone(&seen);
            DriverAudit::new(move |record: &Record| {
                seen.lock().expect("a test's lock").push(record.clone());
            })
        };
        for at in [1, 2] {
            sink.record(&Record {
                at,
                exchange: Exchange::As,
                client: Some(principal("alice@EXAMPLE.COM")),
                service: None,
                realm: "EXAMPLE.COM".into(),
                peer: Some("198.51.100.4".parse().expect("an address")),
                outcome: Outcome::Issued,
                code: None,
            });
        }
        let seen = seen.lock().expect("a test's lock").clone();
        assert_eq!(seen.len(), 2, "one record per decision, in order");
        assert_eq!(seen[1].at, 2);
        // The structure survived: fields are fields, not bytes in a line.
        assert_eq!(
            seen[0].client.as_ref().map(ToString::to_string).as_deref(),
            Some("alice@EXAMPLE.COM")
        );
        assert_eq!(
            seen[0].peer.map(|p| p.to_string()).as_deref(),
            Some("198.51.100.4")
        );
    }

    /// The writer adapter writes one line and flushes it before the record is considered taken.
    ///
    /// The flush is what makes the trail durable, and a `Vec<u8>` cannot show it: the test counts
    /// flushes rather than inspecting bytes.
    #[test]
    fn the_writer_driver_flushes_every_line() {
        #[derive(Clone)]
        struct Tap(std::sync::Arc<Mutex<(String, usize)>>);
        impl Write for Tap {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.0
                    .lock()
                    .expect("a test's lock")
                    .0
                    .push_str(&String::from_utf8_lossy(bytes));
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                self.0.lock().expect("a test's lock").1 += 1;
                Ok(())
            }
        }

        let log = std::sync::Arc::new(Mutex::new((String::new(), 0usize)));
        let sink = DriverAudit::new(ToWriter::new(Tap(std::sync::Arc::clone(&log))));
        sink.record(&Record {
            at: 7,
            exchange: Exchange::Tgs,
            client: None,
            service: None,
            realm: "EXAMPLE.COM".into(),
            peer: None,
            outcome: Outcome::Refused,
            code: Some(crate::error::codes::KDC_ERR_POLICY),
        });

        let (text, flushes) = log.lock().expect("a test's lock").clone();
        assert_eq!(text, "at=7 tgs refused realm=EXAMPLE.COM code=12\n");
        assert_eq!(flushes, 1, "flushed before the record was taken");
    }

    /// The OpenTelemetry attributes carry a stable key set, and an unknown fact is an absent key.
    ///
    /// An exporter that emitted `kerberos.client=""` for a refusal that named nobody would put an
    /// account with no name into a group-by — so absence is expressed by absence.
    #[test]
    fn the_attributes_are_stable_and_absent_facts_are_absent_keys() {
        let full = Record {
            at: 1_700_000_000,
            exchange: Exchange::Tgs,
            client: Some(principal("alice@EXAMPLE.COM")),
            service: Some(principal("cifs/files@EXAMPLE.COM")),
            realm: "EXAMPLE.COM".into(),
            peer: Some("192.0.2.7".parse().expect("an address")),
            outcome: Outcome::Refused,
            code: Some(crate::error::codes::KDC_ERR_S_PRINCIPAL_UNKNOWN),
        };
        assert_eq!(
            full.attributes(),
            vec![
                ("kerberos.exchange", "tgs".to_owned()),
                ("kerberos.outcome", "refused".to_owned()),
                ("kerberos.realm", "EXAMPLE.COM".to_owned()),
                ("kerberos.client", "alice@EXAMPLE.COM".to_owned()),
                ("kerberos.service", "cifs/files@EXAMPLE.COM".to_owned()),
                ("client.address", "192.0.2.7".to_owned()),
                ("kerberos.error_code", "7".to_owned()),
            ],
            "keys and order are the contract an exporter ships"
        );

        // A refusal that named nobody: no `kerberos.client` key at all, not an empty value.
        let bare = Record {
            client: None,
            service: None,
            peer: None,
            code: Some(60),
            ..full.clone()
        };
        let keys: Vec<&str> = bare.attributes().into_iter().map(|(k, _)| k).collect();
        assert_eq!(
            keys,
            vec![
                "kerberos.exchange",
                "kerberos.outcome",
                "kerberos.realm",
                "kerberos.error_code"
            ]
        );

        // The address uses the semantic convention's key, so a collector can join on it.
        assert!(
            full.attributes()
                .iter()
                .any(|(k, _)| *k == "client.address")
        );
    }

    /// Severity: a refusal is `WARN`, not `ERROR`. A dashboard that paints every wrong password red
    /// teaches its readers to ignore red.
    #[test]
    fn severity_separates_a_refusal_from_a_fault() {
        let issued = Record {
            at: 1,
            exchange: Exchange::As,
            client: None,
            service: None,
            realm: "EXAMPLE.COM".into(),
            peer: None,
            outcome: Outcome::Issued,
            code: None,
        };
        assert_eq!(issued.severity_number(), 9);
        assert_eq!(issued.severity_text(), "INFO");
        let refused = Record {
            outcome: Outcome::Refused,
            code: Some(24),
            ..issued.clone()
        };
        assert_eq!(refused.severity_number(), 13);
        assert_eq!(refused.severity_text(), "WARN");
    }

    /// `{record}` and `record.to_line()` cannot disagree, because one is the other.
    #[test]
    fn display_and_to_line_are_one_rendering() {
        let record = Record {
            at: 42,
            exchange: Exchange::Undecodable,
            client: None,
            service: None,
            realm: "EXAMPLE.COM".into(),
            peer: None,
            outcome: Outcome::Refused,
            code: Some(60),
        };
        assert_eq!(record.to_string(), record.to_line());
    }

    /// A record prints as one line, and a refusal names its code.
    #[test]
    fn a_record_prints_as_one_line() {
        let record = Record {
            at: 1_700_000_000,
            exchange: Exchange::Tgs,
            client: Some(principal("alice@EXAMPLE.COM")),
            service: Some(principal("cifs/files@EXAMPLE.COM")),
            realm: "EXAMPLE.COM".into(),
            peer: Some("192.0.2.7".parse().expect("an address")),
            outcome: Outcome::Refused,
            code: Some(crate::error::codes::KDC_ERR_S_PRINCIPAL_UNKNOWN),
        };
        let line = record.to_string();
        assert_eq!(
            line,
            "at=1700000000 tgs refused client=alice@EXAMPLE.COM service=cifs/files@EXAMPLE.COM \
             realm=EXAMPLE.COM peer=192.0.2.7 code=7"
        );
    }

    /// An undecodable request is a record too. A trail that begins only after decoding has its
    /// blind spot exactly where probing is cheapest.
    #[test]
    fn an_undecodable_request_is_still_a_record() {
        let record = Record {
            at: 5,
            exchange: Exchange::Undecodable,
            client: None,
            service: None,
            realm: "EXAMPLE.COM".into(),
            peer: None,
            outcome: Outcome::Refused,
            // `KRB-ERR-GENERIC`, 60: what an undecodable request is answered with.
            code: Some(60),
        };
        assert_eq!(
            record.to_string(),
            "at=5 undecodable refused realm=EXAMPLE.COM code=60"
        );
    }
}
