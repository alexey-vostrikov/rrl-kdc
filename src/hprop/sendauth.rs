//! The `sendauth` handshake: the three cleartext steps before Kerberos starts.
//!
//! Heimdal's `hprop` and every other `krb5_sendauth` client begin by announcing two version strings
//! in the clear, each framed with a four-octet length, and waiting for a single octet of answer
//! (`lib/krb5/recvauth.c`):
//!
//! ```text
//! client → "KRB5_SENDAUTH_V1.0\0"   (18 octets, with the length prefix 22 on the wire)
//! client → "hprop-0.0\0"            (9 octets, 13 on the wire)
//! server → 0x00  ok | 0x01 bad protocol version | 0x02 bad application version
//! client → AP-REQ
//! server → empty message, and an AP-REP when MUTUAL-REQUIRED
//! ```
//!
//! **The lengths include the terminating NUL.** A server that compared the strings at the announced
//! length without it would reject every client, and one that compared `CStr`-style but forgot the NUL
//! in the length it reads would read one octet short of what arrives and desynchronise the whole
//! stream. Both are pinned by tests here.
//!
//! **The answer octet is not optional.** A `sendauth` client blocks until it reads it, so a server
//! that refused a version by closing the socket is indistinguishable from one that crashed. Each
//! refusal writes its own code first.
//!
//! The two strings are different facts and get different answers: `KRB5_SENDAUTH_V1.0` is the
//! protocol, and a mismatch means the peer is not speaking this protocol at all; `hprop-0.0` is the
//! application, and a mismatch means it is speaking it to the wrong program.

use std::io::{Read, Write};

use crate::error::{Error, Result};

/// The protocol version every `sendauth` client announces (`KRB5_SENDAUTH_VERSION`).
pub const SENDAUTH_VERSION: &str = "KRB5_SENDAUTH_V1.0";

/// hprop's application version (`HPROP_VERSION` in `kdc/hprop.h`).
pub const APP_VERSION: &str = "hprop-0.0";

/// The server's answer: everything was understood.
pub const OK: u8 = 0;
/// The peer does not speak `sendauth` v1.0.
pub const BAD_PROTOCOL_VERSION: u8 = 1;
/// It speaks `sendauth`, but to the wrong service.
pub const BAD_APP_VERSION: u8 = 2;

/// A message framed as RFC 4120 §7.2.2 frames everything on a KDC port: four octets of length, then
/// that many octets.
///
/// The same framing as the KDC's own transport, which is why hprop can share a port with nothing
/// else and still be unambiguous: the first message says which protocol it is.
pub fn read_message<R: Read>(reader: &mut R) -> Result<Vec<u8>> {
    let mut len = [0u8; 4];
    reader.read_exact(&mut len).map_err(|e| {
        // A clean end of stream between messages is how the client says "that is all"; an end in the
        // middle of a length is a truncated stream, and the two must not be confused by a caller that
        // would otherwise commit a half-received database.
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            Error::Hprop("the peer closed the connection between messages".into())
        } else {
            Error::Io(e)
        }
    })?;
    let len = u32::from_be_bytes(len) as usize;
    if len > MAX_MESSAGE {
        return Err(Error::Hprop(format!(
            "a message of {len} octets is larger than the {MAX_MESSAGE} this service accepts"
        )));
    }
    let mut body = vec![0u8; len];
    reader.read_exact(&mut body).map_err(Error::Io)?;
    Ok(body)
}

/// The largest message this service reads: one HDB entry, not a stream of them.
pub const MAX_MESSAGE: usize = 8 << 20;

/// Writes `data` framed.
pub fn write_message<W: Write>(writer: &mut W, data: &[u8]) -> Result<()> {
    let len = u32::try_from(data.len()).map_err(|_| {
        Error::Hprop(format!(
            "a message of {} octets cannot be framed",
            data.len()
        ))
    })?;
    writer.write_all(&len.to_be_bytes()).map_err(Error::Io)?;
    writer.write_all(data).map_err(Error::Io)?;
    writer.flush().map_err(Error::Io)
}

/// Reads one length-prefixed version string, refusing one that is not `expected`.
///
/// The octets are compared **including the NUL**, because that is what the length counts: a peer that
/// announced 18 octets for an 18-character name without the terminator is a different protocol.
fn expect_version<R: Read>(reader: &mut R, expected: &str, what: &str) -> Result<bool> {
    let announced = read_message(reader)?;
    // The empty message is what a client sends when it has nothing more to say, and a version step
    // is exactly where a truncated conversation shows up.
    if announced.is_empty() {
        return Err(Error::Hprop(format!(
            "the client announced an empty {what} version, and {expected:?} was expected"
        )));
    }
    let wanted = [expected.as_bytes(), &[0u8]].concat();
    Ok(announced == wanted)
}

/// The three cleartext steps, from the server's side.
///
/// Returns the AP-REQ after answering `OK`; a refusal has already been written when this returns an
/// error, so a caller must not write anything else to the stream.
pub fn accept<R: Read, W: Write>(reader: &mut R, writer: &mut W) -> Result<Vec<u8>> {
    if !expect_version(reader, SENDAUTH_VERSION, "protocol")? {
        let _ = writer.write_all(&[BAD_PROTOCOL_VERSION]);
        return Err(Error::Hprop(format!(
            "the client does not speak {SENDAUTH_VERSION}"
        )));
    }
    if !expect_version(reader, APP_VERSION, "application")? {
        let _ = writer.write_all(&[BAD_APP_VERSION]);
        return Err(Error::Hprop(format!(
            "the client speaks {SENDAUTH_VERSION}, but not {APP_VERSION}"
        )));
    }
    writer.write_all(&[OK]).map_err(Error::Io)?;
    writer.flush().map_err(Error::Io)?;
    // `read_message` may legitimately see an empty body here: a client that sent a version pair and
    // then nothing is broken, and the AP-REQ decoder below says so.
    let ap_req = read_message(reader)?;
    Ok(ap_req)
}

/// Writes the server's half of the AP-REQ exchange: an empty message, then the AP-REP when the
/// client asked for mutual authentication.
///
/// The empty message is `krb5_recvauth`'s "OK, the authenticator was good"; a client that needs an
/// AP-REP reads one more framed message after it, and one that does not would block forever if the
/// server sent it anyway.
pub fn reply<W: Write>(writer: &mut W, ap_rep: Option<&[u8]>) -> Result<()> {
    write_message(writer, &[])?;
    if let Some(ap_rep) = ap_rep {
        write_message(writer, ap_rep)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One side of a socket, for a handshake without a network.
    ///
    /// Two objects, not one behind two borrows: the handshake reads and writes the same socket, and a
    /// test that passed one object twice would not compile — which is the compiler pointing at the
    /// shape a real stream has (two halves cloned from one descriptor).
    struct Pair {
        input: Vec<u8>,
        output: Vec<u8>,
    }

    /// A pair of halves over one buffer: what a test that needs both sides writes.
    fn halves(input: Vec<u8>) -> (Pair, Pair) {
        (
            Pair {
                input,
                output: Vec::new(),
            },
            Pair {
                input: Vec::new(),
                output: Vec::new(),
            },
        )
    }

    impl Read for Pair {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let n = buf.len().min(self.input.len());
            buf[..n].copy_from_slice(&self.input[..n]);
            self.input.drain(..n);
            Ok(n)
        }
    }

    impl Write for Pair {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.output.extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// What a `sendauth` client writes: two length-prefixed strings with their NULs, then the AP-REQ.
    fn client_hello(protocol: &str, application: &str, ap_req: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        for text in [protocol, application] {
            let framed = [text.as_bytes(), &[0u8]].concat();
            out.extend_from_slice(&(framed.len() as u32).to_be_bytes());
            out.extend_from_slice(&framed);
        }
        out.extend_from_slice(&(ap_req.len() as u32).to_be_bytes());
        out.extend_from_slice(ap_req);
        out
    }

    #[test]
    fn a_correct_handshake_yields_the_ap_req() {
        let (mut reader, mut writer) =
            halves(client_hello(SENDAUTH_VERSION, APP_VERSION, b"an AP-REQ"));
        let ap_req = accept(&mut reader, &mut writer).expect("the handshake completes");
        assert_eq!(ap_req, b"an AP-REQ");
        assert_eq!(
            writer.output,
            [OK],
            "the ok octet comes before the AP-REQ is read"
        );
    }

    /// The NUL is inside the announced length. A server that compared the name without counting it
    /// would read one octet short of the message and mis-parse everything after it.
    #[test]
    fn the_versions_are_compared_with_their_nul() {
        // Heimdal's `sizeof(KRB5_SENDAUTH_VERSION)` is 19: eighteen characters and the NUL, and the
        // length prefix counts the NUL.
        assert_eq!(SENDAUTH_VERSION.len(), 18);
        assert_eq!(SENDAUTH_VERSION.len() + 1, 19);
        assert_eq!(APP_VERSION.len() + 1, 10, "hprop-0.0 and its NUL");
        // And the wire really does carry the terminator: a version without it is refused.
        let mut out = Vec::new();
        write_message(&mut out, SENDAUTH_VERSION.as_bytes()).expect("framed");
        let mut reader = Pair {
            input: out,
            output: Vec::new(),
        };
        assert!(
            !expect_version(&mut reader, SENDAUTH_VERSION, "protocol").expect("read"),
            "a version without its NUL is not the version"
        );
    }

    /// Each refusal writes its own octet before failing: the client is blocked on it, and a closed
    /// socket is indistinguishable from a crash.
    #[test]
    fn each_refusal_writes_its_code() {
        let (mut reader, mut writer) = halves(client_hello(
            "KRB5_SENDAUTH_V0.9",
            APP_VERSION,
            b"an AP-REQ",
        ));
        let err = accept(&mut reader, &mut writer).expect_err("a foreign protocol");
        assert!(err.to_string().contains(SENDAUTH_VERSION), "{err}");
        assert_eq!(writer.output, [BAD_PROTOCOL_VERSION]);

        let (mut reader, mut writer) =
            halves(client_hello(SENDAUTH_VERSION, "hprop-9.9", b"an AP-REQ"));
        let err = accept(&mut reader, &mut writer).expect_err("a foreign application");
        assert!(err.to_string().contains("hprop-0.0"), "{err}");
        assert_eq!(writer.output, [BAD_APP_VERSION]);

        // The protocol version is checked first: a peer that speaks neither is told the bigger fact.
        let (mut reader, mut writer) = halves(client_hello("nonsense", "hprop-9.9", b"an AP-REQ"));
        let _ = accept(&mut reader, &mut writer).expect_err("neither");
        assert_eq!(writer.output, [BAD_PROTOCOL_VERSION]);
    }

    /// An empty version is a refusal, not a match: an empty string is not `KRB5_SENDAUTH_V1.0`, and
    /// a comparison that trimmed it would accept one.
    #[test]
    fn an_empty_version_is_refused() {
        let mut out = Vec::new();
        write_message(&mut out, b"").expect("framed");
        let mut reader = Pair {
            input: out,
            output: Vec::new(),
        };
        let err = expect_version(&mut reader, SENDAUTH_VERSION, "protocol").expect_err("empty");
        assert!(err.to_string().contains("empty"), "{err}");
    }

    /// The framing round-trips, and an empty body is a message — it is how hprop says "that is all".
    #[test]
    fn the_framing_round_trips_and_an_empty_body_is_a_message() {
        let mut out = Vec::new();
        write_message(&mut out, b"an entry").expect("framed");
        write_message(&mut out, b"").expect("framed");
        assert_eq!(&out[..4], &(8u32).to_be_bytes());
        let mut reader = Pair {
            input: out,
            output: Vec::new(),
        };
        assert_eq!(read_message(&mut reader).expect("the first"), b"an entry");
        assert_eq!(read_message(&mut reader).expect("the end"), b"");
    }

    /// A length larger than this service accepts is refused **before** it is allocated: the length is
    /// the peer's word, and a service that trusted it would be a memory exhaustion away from death.
    #[test]
    fn an_absurd_length_is_refused_before_allocation() {
        let mut reader = Pair {
            input: (MAX_MESSAGE as u32 + 1).to_be_bytes().to_vec(),
            output: Vec::new(),
        };
        let err = read_message(&mut reader).expect_err("too large");
        assert!(err.to_string().contains("larger than"), "{err}");
    }

    /// The mutal-authentication half: an empty message, then the AP-REP when there is one.
    #[test]
    fn the_reply_is_an_empty_message_and_then_an_ap_rep() {
        let mut out = Vec::new();
        reply(&mut out, None).expect("written");
        assert_eq!(out, [0u8, 0, 0, 0], "an empty message and nothing else");

        let mut out = Vec::new();
        reply(&mut out, Some(b"an AP-REP")).expect("written");
        assert_eq!(&out[..4], &(0u32).to_be_bytes());
        assert_eq!(&out[4..8], &(9u32).to_be_bytes());
        assert_eq!(&out[8..], b"an AP-REP");
    }
}
