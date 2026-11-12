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
//! # A sink cannot fail
//!
//! [`Audit::record`] returns nothing. A log file that is full must not refuse a login the realm
//! would otherwise grant: an audit trail is evidence, and evidence that can be switched off by
//! filling a disk is not evidence. A sink that wants to report a write failure reports it on its
//! own channel, where it does not become an authentication decision.

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

/// A sink that writes one line per record to anything that takes bytes — a file, a pipe, a syslog
/// socket wrapped by the deployment.
///
/// **Each line is flushed before the record is considered taken.** An audit trail that sits in a
/// buffer when the process dies is a trail missing exactly the records that matter — the last ones,
/// before whatever killed it. The cost is a write syscall per request, which a KDC that issues
/// thousands of tickets a second will feel; that is the trade this sink makes, and a deployment that
/// wants batching writes its own [`Audit`] over the same [`Record`].
pub struct StreamAudit<W: std::io::Write + Send> {
    out: Mutex<W>,
}

impl<W: std::io::Write + Send> StreamAudit<W> {
    /// Wraps `out`.
    pub fn new(out: W) -> Self {
        Self {
            out: Mutex::new(out),
        }
    }

    /// The sink back, for a caller that wants to close it or read what it wrote.
    pub fn into_inner(self) -> W {
        self.out
            .into_inner()
            .expect("a stream audit's lock is never held across a panic")
    }
}

impl<W: std::io::Write + Send> Audit for StreamAudit<W> {
    fn record(&self, record: &Record) {
        // A write failure is swallowed: `Audit::record` cannot fail, because a full disk must not
        // refuse a login the realm would grant. The deployment's own logging is where a failure
        // belongs — and a sink that cannot write is a deployment problem, not an authentication
        // decision.
        let Ok(mut out) = self.out.lock() else {
            return;
        };
        let _ = writeln!(out, "{record}");
        let _ = out.flush();
    }
}

impl std::fmt::Display for Record {
    /// One line, for a sink that writes to a file: `at=… as refused service=… realm=… peer=… code=…`.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "at={} {}", self.at, self.exchange.as_str())?;
        match self.outcome {
            Outcome::Issued => write!(f, " issued")?,
            Outcome::Refused => write!(f, " refused")?,
        }
        if let Some(client) = &self.client {
            write!(f, " client={client}")?;
        }
        if let Some(service) = &self.service {
            write!(f, " service={service}")?;
        }
        write!(f, " realm={}", self.realm)?;
        if let Some(peer) = self.peer {
            write!(f, " peer={peer}")?;
        }
        if let Some(code) = self.code {
            write!(f, " code={code}")?;
        }
        Ok(())
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

    /// The stream sink writes one flushed line per record, in order.
    #[test]
    fn a_stream_sink_writes_one_line_per_record() {
        // A writer that records what it was given and when it was flushed: the flush is the
        // property that matters, and a `Vec<u8>` alone cannot show it.
        #[derive(Clone)]
        struct Tap(std::sync::Arc<Mutex<(String, usize)>>);
        impl Write for Tap {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.0
                    .lock()
                    .unwrap()
                    .0
                    .push_str(&String::from_utf8_lossy(bytes));
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                self.0.lock().unwrap().1 += 1;
                Ok(())
            }
        }

        let log = std::sync::Arc::new(Mutex::new((String::new(), 0usize)));
        let sink = StreamAudit::new(Tap(std::sync::Arc::clone(&log)));
        for at in [1, 2] {
            sink.record(&Record {
                at,
                exchange: Exchange::As,
                client: Some(principal("alice@EXAMPLE.COM")),
                service: None,
                realm: "EXAMPLE.COM".into(),
                peer: None,
                outcome: Outcome::Issued,
                code: None,
            });
        }
        let (text, flushes) = log.lock().unwrap().clone();
        assert_eq!(
            text,
            "at=1 as issued client=alice@EXAMPLE.COM realm=EXAMPLE.COM\n\
             at=2 as issued client=alice@EXAMPLE.COM realm=EXAMPLE.COM\n",
            "one line per record, in order"
        );
        assert_eq!(
            flushes, 2,
            "each line was flushed before the record was taken"
        );
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
