//! ONC RPC (RFC 5531) over TCP, with the RPCSEC_GSS handshake of RFC 2203.
//!
//! The framing is the easy part; two details are where a server that "works"
//! against itself fails against a real `kadmin`:
//!
//! * **The MIC verifier covers the call header as it arrived**, from `xid` through
//!   the credential and no further. A server that re-encodes the header to check
//!   the MIC usually gets the same octets — and stops getting them the moment a
//!   client pads an opaque differently.
//! * **The GSS token of an INIT call is in the *arguments*, not the verifier.**
//!   MIT's client sends `AUTH_NONE` as the verifier and the AP-REQ as the first
//!   argument of NULLPROC. Looking for it in the verifier finds nothing and the
//!   handshake never starts.
//!
//! Record marking (RFC 5531 §11) allows one message in several fragments; a
//! reader that stops at the first fragment decodes half an argument list.

use std::io::{Read, Write};
use std::net::TcpStream;

use crate::error::{Error, Result};

use super::Kadmin;
use super::gss::AcceptorContext;
use super::xdr::{Reader, Writer};

/// `CALL` and `REPLY` message types.
const CALL: u32 = 0;
const REPLY: u32 = 1;
/// The only RPC version anyone speaks.
const RPC_VERSION: u32 = 2;
/// `AUTH_NONE`.
pub const AUTH_NONE: u32 = 0;
/// `RPCSEC_GSS`.
pub const RPCSEC_GSS: u32 = 6;
/// `RPCSEC_GSS_VERSION`.
const RPCSEC_GSS_VERSION: u32 = 1;
/// `RPCSEC_GSS_DATA`.
pub const RPCSEC_GSS_DATA: u32 = 0;
/// `RPCSEC_GSS_INIT`.
pub const RPCSEC_GSS_INIT: u32 = 1;
/// `RPCSEC_GSS_DESTROY`.
pub const RPCSEC_GSS_DESTROY: u32 = 3;
/// `RPCSEC_GSS_SVC_PRIVACY`.
const RPCSEC_GSS_SVC_PRIVACY: u32 = 3;
/// The GSS sequence window offered in the handshake.
const WINDOW: u32 = 128;
/// The largest request accepted, so that a length prefix cannot make the server
/// allocate a gigabyte.
const MAX_RECORD: usize = 16 << 20;

/// The RPCSEC_GSS part of a credential.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GssCredential {
    /// `rpc_gss_version`.
    pub version: u32,
    /// `rpc_gss_proc`: INIT, DATA or DESTROY.
    pub procedure: u32,
    /// `rpc_gss_seq_num`.
    pub seq: u32,
    /// `rpc_gss_service`.
    pub service: u32,
    /// The context handle the server issued.
    pub handle: Vec<u8>,
}

/// One parsed call.
#[derive(Debug)]
pub struct Call {
    /// `xid`, echoed in the reply.
    pub xid: u32,
    /// The program number.
    pub prog: u32,
    /// The version.
    pub vers: u32,
    /// The procedure.
    pub proc_: u32,
    /// The credential's flavour.
    pub cred_flavor: u32,
    /// The credential, when it is RPCSEC_GSS.
    pub gss: Option<GssCredential>,
    /// The verifier's flavour and body.
    pub verf: (u32, Vec<u8>),
    /// The arguments.
    pub args: Vec<u8>,
    /// How many octets of the message the header occupies — the span the MIC
    /// covers.
    pub header_len: usize,
}

impl Call {
    /// Parses a call, or says what is wrong with it.
    pub fn parse(message: &[u8]) -> Result<Call> {
        let mut r = Reader::new(message);
        let xid = r.u32()?;
        if r.u32()? != CALL {
            return Err(Error::Protocol("RPC: not a call".into()));
        }
        if r.u32()? != RPC_VERSION {
            return Err(Error::Protocol("RPC: not version 2".into()));
        }
        let prog = r.u32()?;
        let vers = r.u32()?;
        let proc_ = r.u32()?;
        let cred_flavor = r.u32()?;
        let cred = r.opaque()?.to_vec();
        // Exactly here: the MIC the client sent covers everything above.
        let header_len = message.len() - r.remaining();
        let gss = if cred_flavor == RPCSEC_GSS {
            Some(parse_credential(&cred)?)
        } else {
            None
        };
        let verf_flavor = r.u32()?;
        let verf = r.opaque()?.to_vec();
        Ok(Call {
            xid,
            prog,
            vers,
            proc_,
            cred_flavor,
            gss,
            verf: (verf_flavor, verf),
            args: r.rest().to_vec(),
            header_len,
        })
    }
}

fn parse_credential(cred: &[u8]) -> Result<GssCredential> {
    let mut r = Reader::new(cred);
    let version = r.u32()?;
    if version != RPCSEC_GSS_VERSION {
        return Err(Error::Protocol(format!(
            "RPCSEC_GSS: version {version}, expected 1"
        )));
    }
    Ok(GssCredential {
        version,
        procedure: r.u32()?,
        seq: r.u32()?,
        service: r.u32()?,
        handle: r.opaque()?.to_vec(),
    })
}

/// Encodes an accepted reply.
pub fn accepted(xid: u32, verf_flavor: u32, verf: &[u8], results: &[u8]) -> Vec<u8> {
    let mut w = Writer::new();
    w.u32(xid)
        .u32(REPLY)
        .u32(0) // MSG_ACCEPTED
        .u32(verf_flavor)
        .opaque(verf)
        .u32(0) // SUCCESS
        .raw(results);
    w.into_bytes()
}

/// Encodes a denied reply: the RPC layer refused, before any procedure ran.
pub fn denied(xid: u32, auth_stat: u32) -> Vec<u8> {
    let mut w = Writer::new();
    w.u32(xid)
        .u32(REPLY)
        .u32(1) // MSG_DENIED
        .u32(1) // AUTH_ERROR
        .u32(auth_stat);
    w.into_bytes()
}

/// Reads one record, reassembling its fragments.
pub fn read_record(stream: &mut TcpStream) -> Result<Vec<u8>> {
    let mut message = Vec::new();
    loop {
        let mut marker = [0u8; 4];
        stream.read_exact(&mut marker).map_err(Error::Io)?;
        let word = u32::from_be_bytes(marker);
        let last = word & 0x8000_0000 != 0;
        let len = (word & 0x7fff_ffff) as usize;
        if len > MAX_RECORD || message.len() + len > MAX_RECORD {
            return Err(Error::Protocol(format!(
                "RPC: a record of {len} octets is larger than this server accepts"
            )));
        }
        let mut fragment = vec![0u8; len];
        stream.read_exact(&mut fragment).map_err(Error::Io)?;
        message.extend_from_slice(&fragment);
        if last {
            return Ok(message);
        }
    }
}

/// Writes one record, in a single fragment.
pub fn write_record(stream: &mut TcpStream, message: &[u8]) -> Result<()> {
    let mut framed = ((message.len() as u32) | 0x8000_0000)
        .to_be_bytes()
        .to_vec();
    framed.extend_from_slice(message);
    stream.write_all(&framed).map_err(Error::Io)?;
    stream.flush().map_err(Error::Io)
}

/// Serves one connection until the client closes it.
///
/// Every call is answered, including the ones that fail: a `kadmind` that hangs
/// up on a bad request leaves `kadmin` printing a network error instead of the
/// reason, and the operator has nothing to act on.
pub fn serve_connection(mut stream: TcpStream, kadmin: &Kadmin, now: i64) {
    let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(30)));
    let mut context: Option<(crate::name::Principal, AcceptorContext)> = None;
    // The handle is the only thing that ties a later call to this context, and it
    // is never reused across connections.
    let handle = b"kadm5-context".to_vec();
    // The GSS sequence numbers, which are *not* the RPCSEC ones: the credential's
    // `seq_num` counts calls, and each call spends two GSS tokens (a MIC and a
    // Wrap). Comparing the two is the mistake this variable exists to prevent.
    let mut last_gss_seq: u64 = 0;

    loop {
        let message = match read_record(&mut stream) {
            Ok(message) => message,
            Err(_) => return,
        };
        let call = match Call::parse(&message) {
            Ok(call) => call,
            Err(_) => {
                // A call whose xid cannot be read has no reply to address; the
                // best this can do is stop.
                return;
            }
        };
        if call.cred_flavor != RPCSEC_GSS {
            let _ = write_record(&mut stream, &denied(call.xid, 1)); // AUTH_BADCRED
            continue;
        }
        let Some(credential) = &call.gss else {
            let _ = write_record(&mut stream, &denied(call.xid, 1));
            continue;
        };

        match credential.procedure {
            RPCSEC_GSS_INIT => {
                // The AP-REQ travels as the first argument of the NULLPROC call.
                let mut arguments = Reader::new(&call.args);
                let token = match arguments.opaque() {
                    Ok(token) => token.to_vec(),
                    Err(_) => {
                        let _ = write_record(&mut stream, &denied(call.xid, 1));
                        continue;
                    }
                };
                match kadmin.accept(&token, now) {
                    Ok((actor, accepted_context, ap_rep)) => {
                        // rpc_gss_init_res ::= { handle, major, minor, window, token }
                        let mut body = Writer::new();
                        body.opaque(&handle)
                            .u32(0) // GSS_S_COMPLETE
                            .u32(0) // minor
                            .u32(WINDOW)
                            .opaque(&ap_rep);
                        // RFC 2203 §5.2.3.1: the verifier of this reply is a MIC
                        // over the sequence window.
                        let verifier = match accepted_context.emit_mic(0, &WINDOW.to_be_bytes()) {
                            Ok(verifier) => verifier,
                            Err(_) => {
                                let _ = write_record(&mut stream, &denied(call.xid, 13));
                                continue;
                            }
                        };
                        let reply = accepted(call.xid, RPCSEC_GSS, &verifier, &body.into_bytes());
                        let _ = write_record(&mut stream, &reply);
                        context = Some((actor, accepted_context));
                    }
                    Err(error) => {
                        // A `kadmind` that refuses a context has to say why: the
                        // client is told only "GSS_S_FAILURE", and an operator with
                        // no log has nothing to act on.
                        crate::kadmin::log_refusal(&format!("AP-REQ: {error}"));
                        // GSS_S_FAILURE, so the client reports an authentication
                        // error rather than waiting for a reply that never comes.
                        let mut body = Writer::new();
                        body.opaque(&[])
                            .u32(2) // GSS_S_FAILURE
                            .u32(0)
                            .u32(0)
                            .opaque(&[]);
                        let reply = accepted(call.xid, AUTH_NONE, &[], &body.into_bytes());
                        let _ = write_record(&mut stream, &reply);
                    }
                }
            }
            RPCSEC_GSS_DESTROY => {
                let _ = write_record(&mut stream, &accepted(call.xid, AUTH_NONE, &[], &[]));
                context = None;
            }
            RPCSEC_GSS_DATA => {
                // Integrity without confidentiality would put a password on the
                // wire in the clear, so the weaker service is refused rather than
                // served.
                if requires_privacy(credential).is_err() {
                    let _ = write_record(&mut stream, &denied(call.xid, 13));
                    continue;
                }
                let Some((actor, context)) = &context else {
                    let _ = write_record(&mut stream, &denied(call.xid, 14)); // context problem
                    continue;
                };
                // The verifier is a MIC over the header as it arrived.
                let header = &message[..call.header_len];
                match context.verify_mic(&call.verf.1, header) {
                    Ok(verified) if verified.seq > last_gss_seq => {
                        last_gss_seq = verified.seq;
                    }
                    Ok(verified) => {
                        // A MIC that verifies but is not newer is a replay: the
                        // checksum proves who sent it, the sequence proves when.
                        super::log_refusal(&format!(
                            "a replayed MIC: sequence {} after {last_gss_seq}",
                            verified.seq
                        ));
                        let _ = write_record(&mut stream, &denied(call.xid, 14));
                        continue;
                    }
                    Err(error) => {
                        super::log_refusal(&format!("MIC: {error}"));
                        let _ = write_record(&mut stream, &denied(call.xid, 13));
                        continue;
                    }
                }

                // The arguments are the sealed body: an opaque holding
                // `seq || args`.
                let mut reader = Reader::new(&call.args);
                let sealed = match reader.opaque() {
                    Ok(sealed) => sealed,
                    Err(_) => {
                        let _ = write_record(&mut stream, &denied(call.xid, 13));
                        continue;
                    }
                };
                let opened = match context.unwrap(sealed) {
                    Ok(opened) if opened.seq > last_gss_seq => {
                        last_gss_seq = opened.seq;
                        opened
                    }
                    Ok(opened) => {
                        super::log_refusal(&format!(
                            "a replayed Wrap token: sequence {} after {last_gss_seq}",
                            opened.seq
                        ));
                        let _ = write_record(&mut stream, &denied(call.xid, 14));
                        continue;
                    }
                    Err(error) => {
                        super::log_refusal(&format!("unwrap: {error}"));
                        let _ = write_record(&mut stream, &denied(call.xid, 13));
                        continue;
                    }
                };
                let mut inner = Reader::new(&opened.message);
                if !matches!(inner.u32(), Ok(seq) if seq == credential.seq) {
                    let _ = write_record(&mut stream, &denied(call.xid, 13));
                    continue;
                }
                let arguments = inner.rest().to_vec();

                let results = kadmin.dispatch(actor, &call, &arguments);
                let mut to_seal = Writer::new();
                to_seal.u32(credential.seq).raw(&results);
                let sealed_reply = match context.seal(credential.seq as u64, to_seal.bytes()) {
                    Ok(sealed) => sealed,
                    Err(_) => {
                        let _ = write_record(&mut stream, &denied(call.xid, 13));
                        continue;
                    }
                };
                // The reply's verifier is the acceptor's MIC over the sequence
                // number, and its body is the sealed results.
                let verifier = match context.emit_mic(0, &credential.seq.to_be_bytes()) {
                    Ok(verifier) => verifier,
                    Err(_) => {
                        let _ = write_record(&mut stream, &denied(call.xid, 13));
                        continue;
                    }
                };
                let mut body = Writer::new();
                body.opaque(&sealed_reply);
                let reply = accepted(call.xid, RPCSEC_GSS, &verifier, &body.into_bytes());
                let _ = write_record(&mut stream, &reply);
            }
            _ => {
                let _ = write_record(&mut stream, &denied(call.xid, 13));
            }
        }
    }
}

/// Whether the credential asked for privacy, which is the only service this
/// server offers: integrity without confidentiality would put a password on the
/// wire in clear.
pub fn requires_privacy(credential: &GssCredential) -> Result<()> {
    if credential.service == RPCSEC_GSS_SVC_PRIVACY {
        Ok(())
    } else {
        Err(Error::Protocol(
            "RPCSEC_GSS: only the privacy service is offered; a password must not travel in the \
             clear"
                .into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a_call() -> Vec<u8> {
        let mut w = Writer::new();
        w.u32(7)
            .u32(CALL)
            .u32(RPC_VERSION)
            .u32(2112)
            .u32(2)
            .u32(5)
            .u32(RPCSEC_GSS);
        let mut cred = Writer::new();
        cred.u32(1)
            .u32(RPCSEC_GSS_DATA)
            .u32(4)
            .u32(3)
            .opaque(b"ctx");
        w.opaque(cred.bytes())
            .u32(AUTH_NONE)
            .opaque(&[])
            .raw(b"args");
        w.into_bytes()
    }

    #[test]
    fn a_call_is_parsed_field_by_field() {
        let call = Call::parse(&a_call()).unwrap();
        assert_eq!(call.xid, 7);
        assert_eq!(call.prog, 2112);
        assert_eq!(call.vers, 2);
        assert_eq!(call.proc_, 5);
        assert_eq!(call.cred_flavor, RPCSEC_GSS);
        let gss = call.gss.expect("an RPCSEC_GSS credential");
        assert_eq!(gss.procedure, RPCSEC_GSS_DATA);
        assert_eq!(gss.seq, 4);
        assert_eq!(gss.service, 3);
        assert_eq!(gss.handle, b"ctx");
        assert_eq!(call.args, b"args");
    }

    #[test]
    fn the_header_length_covers_the_credential_and_no_more() {
        // The MIC is over exactly this span, so an off-by-one here shows up as
        // "the verifier is wrong" against every real client.
        let message = a_call();
        let call = Call::parse(&message).unwrap();
        let header = &message[..call.header_len];
        assert_eq!(
            header.len(),
            4 * 7 + 4 + 24,
            "xid..proc, cred flavour, cred"
        );
        assert_eq!(&header[..4], &7u32.to_be_bytes());
        assert!(
            &message[call.header_len..].starts_with(&AUTH_NONE.to_be_bytes()),
            "the header ends where the verifier's flavour begins"
        );
    }

    #[test]
    fn a_reply_is_what_rfc_5531_says() {
        let reply = accepted(7, RPCSEC_GSS, b"mic", b"results");
        assert_eq!(
            reply,
            [
                0, 0, 0, 7, // xid
                0, 0, 0, 1, // REPLY
                0, 0, 0, 0, // MSG_ACCEPTED
                0, 0, 0, 6, // RPCSEC_GSS
                0, 0, 0, 3, b'm', b'i', b'c', 0, // opaque with padding
                0, 0, 0, 0, // SUCCESS
                b'r', b'e', b's', b'u', b'l', b't',
                b's', // 7 octets: the body
                      // is raw, not length-prefixed, so there is no padding here
            ]
        );
    }

    #[test]
    fn a_refusal_does_not_pretend_to_be_success() {
        let reply = denied(9, 14);
        assert_eq!(
            reply,
            [0, 0, 0, 9, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 14]
        );
    }

    #[test]
    fn a_message_that_is_not_a_call_is_refused() {
        assert!(Call::parse(&[0, 0, 0, 1]).is_err());
        let mut w = Writer::new();
        w.u32(1).u32(REPLY);
        assert!(Call::parse(w.bytes()).is_err());
    }

    #[test]
    fn only_privacy_is_accepted() {
        let privacy = GssCredential {
            version: 1,
            procedure: RPCSEC_GSS_DATA,
            seq: 1,
            service: 3,
            handle: Vec::new(),
        };
        assert!(requires_privacy(&privacy).is_ok());
        let integrity = GssCredential {
            service: 1,
            ..privacy
        };
        assert!(
            requires_privacy(&integrity).is_err(),
            "integrity without confidentiality puts the password on the wire"
        );
    }
}

#[cfg(test)]
mod extra_tests {
    use super::*;

    /// A listener that accepts one connection and hands it over.
    fn pair() -> (TcpStream, TcpStream) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr).unwrap();
        let (server, _) = listener.accept().unwrap();
        (client, server)
    }

    #[test]
    fn a_record_split_into_fragments_is_reassembled() {
        // RFC 5531 §11: a message may arrive in pieces, and a reader that stops
        // at the first one decodes half an argument list.
        let (mut client, mut server) = pair();
        use std::io::Write;
        // The markers carry the length of what follows, not of the marker.
        let mut wire = Vec::new();
        wire.extend_from_slice(&3u32.to_be_bytes()); // not last
        wire.extend_from_slice(b"abc");
        wire.extend_from_slice(&(5u32 | 0x8000_0000).to_be_bytes()); // last
        wire.extend_from_slice(b"defgh");
        client.write_all(&wire).unwrap();
        assert_eq!(read_record(&mut server).unwrap(), b"abcdefgh");
    }

    #[test]
    fn a_record_that_claims_to_be_enormous_is_refused() {
        let (mut client, mut server) = pair();
        use std::io::Write;
        client
            .write_all(&((MAX_RECORD as u32 + 1) | 0x8000_0000).to_be_bytes())
            .unwrap();
        let error = read_record(&mut server).unwrap_err().to_string();
        assert!(error.contains("larger than"), "{error}");
    }

    #[test]
    fn a_written_record_round_trips() {
        let (mut client, mut server) = pair();
        write_record(&mut client, b"a message").unwrap();
        assert_eq!(read_record(&mut server).unwrap(), b"a message");
    }

    #[test]
    fn a_call_without_an_rpcsec_credential_has_no_gss_credential() {
        let mut w = Writer::new();
        w.u32(1)
            .u32(CALL)
            .u32(RPC_VERSION)
            .u32(2112)
            .u32(2)
            .u32(13)
            .u32(AUTH_NONE)
            .opaque(&[])
            .u32(AUTH_NONE)
            .opaque(&[]);
        let call = Call::parse(w.bytes()).unwrap();
        assert_eq!(call.cred_flavor, AUTH_NONE);
        assert!(call.gss.is_none());
    }

    #[test]
    fn a_credential_of_the_wrong_version_is_refused() {
        let mut w = Writer::new();
        w.u32(1)
            .u32(CALL)
            .u32(RPC_VERSION)
            .u32(2112)
            .u32(2)
            .u32(13)
            .u32(RPCSEC_GSS);
        let mut cred = Writer::new();
        cred.u32(9).u32(1).u32(0).u32(3).opaque(&[]);
        w.opaque(cred.bytes()).u32(AUTH_NONE).opaque(&[]);
        let error = Call::parse(w.bytes()).unwrap_err().to_string();
        assert!(error.contains("version"), "{error}");
    }
}
