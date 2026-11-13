//! The sending half of `hprop`: read a database here, install it there.
//!
//! [`super::Hprop`] is the receiver — the slave. This is the master's client, and without it a
//! second domain controller cannot be created: the mechanism existed on one side only, so
//! `rrl-kdc` could accept a database and had no way to send one.
//!
//! # What the caller supplies, and what it does not
//!
//! A push needs a **service ticket for `hprop/HOST`** — that is an AS exchange plus a TGS exchange,
//! and this crate is a KDC: its client half lives in `krb5`, and a KDC that grew its own client to
//! push would be two protocols in one crate. So the caller hands over a [`ServiceTicket`] it obtained
//! however it likes (a keytab login, a cache, a stand), and everything here works with it.
//!
//! That splits along the seam the protocol already has: the ticket proves the master's identity, and
//! the stream below is the propagation.
//!
//! # The exchange, in order
//!
//! ```text
//! client → "KRB5_SENDAUTH_V1.0\0", "hprop-0.0\0"     (sendauth, framed)
//! server → 0x00
//! client → AP-REQ                                    (MUTUAL-REQUIRED | USE-SUBKEY)
//! server → empty message, then AP-REP                (with the server's subkey)
//! client → KRB-PRIV(HDB_entry) …                     (sealed in the client's subkey)
//! client → empty message                             (end of stream)
//! server → KRB-PRIV(empty)                           (the acknowledgement)
//! ```
//!
//! **The subkeys are the part that goes wrong quietly.** The client seals entries in the subkey it
//! put in its authenticator, and reads the acknowledgement in the subkey the server put in the
//! AP-REP. Those are two different keys, and a client that used one for both would pass every
//! integrity check on one direction and fail the other — with the handshake looking perfect. The
//! receiving side in [`super`] documents the same rule from its end.
//!
//! **The AP-REP is checked, not merely read.** Its `ctime` has to be the one this client sent: that
//! is the whole point of asking for mutual authentication, and a client that decrypted the reply and
//! ignored the timestamp would be authenticating nothing.

use std::io::{Read, Write};
use std::sync::Arc;

use crate::crypto::usage;
use crate::crypto::{Cipher, Key};
use crate::error::{Error, Result};
use crate::hdb::{Hdb, value};
use crate::msg::kpasswd::{EncApRepPart, open_krb_priv_part, seal_krb_priv};
use crate::msg::{AP_OPTS_MUTUAL_REQUIRED, ApReq, Authenticator, EncryptedData};
use crate::name::Principal;

use super::sendauth;

/// `AP_OPTS_USE_SUBKEY` (RFC 4120 §5.5.1): the client names the key its messages are sealed in.
///
/// Every real `hprop` sets it, and the receiver requires it implicitly — the entries are read with
/// the authenticator's subkey, falling back to the session key. Setting it is what makes the
/// propagation traffic independent of the ticket's session key, which is the point of a subkey.
pub const AP_OPTS_USE_SUBKEY: u32 = 0x0000_0040;

/// A ticket the caller obtained for `hprop/HOST`, and its session key.
///
/// The ticket is kept encoded because the pusher only passes it on: it appears in the AP-REQ and is
/// never inspected, so decoding and re-encoding it would be a way to disagree with the KDC that
/// issued it over octets nobody asked about.
#[derive(Debug, Clone)]
pub struct ServiceTicket {
    /// The `Ticket` as the KDC issued it.
    pub ticket: Vec<u8>,
    /// Its session key.
    pub session_key: Key,
}

/// What a push did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PushSummary {
    /// Entries sent, and acknowledged by the slave.
    pub entries: usize,
}

/// The master's side of a propagation.
#[derive(Debug)]
pub struct Pusher {
    realm: String,
    client: Principal,
    cipher: Arc<dyn Cipher>,
    max_skew: i64,
}

impl Pusher {
    /// A pusher for `client` in `realm`.
    ///
    /// `client` is who the ticket was obtained for — `kadmin/hprop@REALM` for a real realm, because
    /// that is the only name a receiver accepts.
    pub fn new(realm: impl Into<String>, client: Principal, cipher: Arc<dyn Cipher>) -> Pusher {
        Pusher {
            realm: realm.into(),
            client,
            cipher,
            // The receiver's own default, mirrored: a master and a slave that allowed different
            // skews would disagree about the same stream, and the slave's opinion is the one that
            // decides.
            max_skew: 300,
        }
    }

    /// The same, with a different tolerance for clock difference.
    pub fn with_clock_skew(mut self, max_skew: i64) -> Pusher {
        self.max_skew = max_skew;
        self
    }

    /// The name this pusher authenticates as.
    pub fn client(&self) -> &Principal {
        &self.client
    }

    /// Sends every entry of `hdb` over an already-open connection.
    ///
    /// Both halves of the stream are passed in rather than one `TcpStream`, which is what makes the
    /// exchange testable without a network — and what a caller with a TLS-wrapped or a proxied
    /// socket needs.
    ///
    /// Returns only after the slave has acknowledged: a summary means the database was installed
    /// there, not that it was written into a socket buffer.
    pub fn push<R: Read, W: Write>(
        &self,
        hdb: &dyn Hdb,
        ticket: &ServiceTicket,
        reader: &mut R,
        writer: &mut W,
        now: i64,
    ) -> Result<PushSummary> {
        let (seal_key, reply_key) = self.handshake(ticket, reader, writer, now)?;

        let mut entries = 0usize;
        let mut after: Option<Principal> = None;
        loop {
            let next = match &after {
                None => hdb.first()?,
                Some(principal) => hdb.next(principal)?,
            };
            let Some(principal) = next else { break };
            let entry = hdb.fetch(&principal)?.ok_or_else(|| {
                // A backend that lists a principal and then cannot produce it is broken, and
                // skipping it would push a database that is missing a user with no sign of it.
                Error::Hprop(format!(
                    "{principal} was listed by the database and then could not be read"
                ))
            })?;
            // Heimdal's `HDB_entry`, the format the receiver decodes: an entry encoded in this
            // crate's own record shape would be refused at the far end with a DER error.
            let packed = value::encode(&entry);
            let sealed = seal_krb_priv(self.cipher.as_ref(), &seal_key, &packed, None, now)?;
            sendauth::write_message(writer, &sealed)
                .map_err(|e| Error::Hprop(format!("entry {} of the stream: {e}", entries + 1)))?;
            after = Some(principal);
            entries += 1;
        }

        // The end of the stream. This is the message that makes the slave commit.
        sendauth::write_message(writer, &[])
            .map_err(|e| Error::Hprop(format!("the end of the stream: {e}")))?;

        // And the acknowledgement, which is what distinguishes "installed" from "received".
        let ack = sendauth::read_message(reader)
            .map_err(|e| Error::Hprop(format!("the acknowledgement: {e}")))?;
        let part = open_krb_priv_part(self.cipher.as_ref(), &reply_key, &ack)
            .map_err(|e| Error::Hprop(format!("the acknowledgement does not open: {e}")))?;
        if !part.user_data.is_empty() {
            // Heimdal's receiver acknowledges with an empty message. Anything else is a peer that
            // speaks this protocol differently, which is worth saying rather than ignoring.
            return Err(Error::Hprop(format!(
                "the acknowledgement carries {} octets, and the protocol has it empty",
                part.user_data.len()
            )));
        }
        Ok(PushSummary { entries })
    }

    /// The same over a connected socket.
    pub fn push_stream(
        &self,
        stream: std::net::TcpStream,
        hdb: &dyn Hdb,
        ticket: &ServiceTicket,
        now: i64,
    ) -> Result<PushSummary> {
        let mut reader = stream.try_clone().map_err(Error::Io)?;
        let mut writer = stream;
        self.push(hdb, ticket, &mut reader, &mut writer, now)
    }

    /// Connects to `addr` and pushes.
    pub fn push_to<A: std::net::ToSocketAddrs>(
        &self,
        addr: A,
        hdb: &dyn Hdb,
        ticket: &ServiceTicket,
        now: i64,
    ) -> Result<PushSummary> {
        let stream = std::net::TcpStream::connect(addr).map_err(Error::Io)?;
        self.push_stream(stream, hdb, ticket, now)
    }

    /// The three cleartext steps, the AP-REQ, and the AP-REP check.
    ///
    /// Returns the two keys the connection needs — the client's subkey for what it sends, and the
    /// server's for the acknowledgement. Per connection, not per pusher: a `Pusher` is reusable, and
    /// keys kept as fields would be the first connection's keys in the second one.
    fn handshake<R: Read, W: Write>(
        &self,
        ticket: &ServiceTicket,
        reader: &mut R,
        writer: &mut W,
        now: i64,
    ) -> Result<(Key, Key)> {
        for version in [sendauth::SENDAUTH_VERSION, sendauth::APP_VERSION] {
            // The NUL is inside the announced length; the receiver compares it there.
            let framed = [version.as_bytes(), &[0u8]].concat();
            sendauth::write_message(writer, &framed)
                .map_err(|e| Error::Hprop(format!("announcing {version}: {e}")))?;
        }
        let mut answer = [0u8; 1];
        reader.read_exact(&mut answer).map_err(|e| {
            Error::Hprop(format!(
                "the slave closed the connection instead of answering the version: {e}"
            ))
        })?;
        match answer[0] {
            sendauth::OK => {}
            sendauth::BAD_PROTOCOL_VERSION => {
                return Err(Error::Hprop(format!(
                    "the peer does not speak {}",
                    sendauth::SENDAUTH_VERSION
                )));
            }
            sendauth::BAD_APP_VERSION => {
                return Err(Error::Hprop(format!(
                    "the peer speaks sendauth but not {}",
                    sendauth::APP_VERSION
                )));
            }
            other => {
                return Err(Error::Hprop(format!(
                    "the peer answered {other:#04x}, and sendauth defines 0, 1 and 2"
                )));
            }
        }

        let subkey = self
            .cipher
            .random(ticket.session_key.enctype())
            .map_err(|e| Error::Hprop(format!("a subkey: {e}")))?;
        let authenticator = Authenticator {
            crealm: self.realm.clone(),
            cname: self.client.clone(),
            cksum: None,
            cusec: 0,
            ctime: now,
            subkey: Some(subkey.clone()),
            seq_number: None,
            authorization_data: None,
        };
        let ap_req = ApReq {
            ap_options: AP_OPTS_MUTUAL_REQUIRED | AP_OPTS_USE_SUBKEY,
            ticket: ticket.ticket.clone(),
            authenticator: EncryptedData::seal(
                self.cipher.as_ref(),
                &ticket.session_key,
                usage::AP_REQ_AUTH,
                None,
                &authenticator.encode(),
            )?,
        };
        sendauth::write_message(writer, &ap_req.encode())
            .map_err(|e| Error::Hprop(format!("the AP-REQ: {e}")))?;

        let empty = sendauth::read_message(reader)
            .map_err(|e| Error::Hprop(format!("the reply to the AP-REQ: {e}")))?;
        if !empty.is_empty() {
            return Err(Error::Hprop(format!(
                "the slave answered the AP-REQ with {} octets, and that message is empty",
                empty.len()
            )));
        }
        let raw =
            sendauth::read_message(reader).map_err(|e| Error::Hprop(format!("the AP-REP: {e}")))?;
        let ap_rep = crate::msg::kpasswd::ApRep::decode(&raw)?;
        let opened = self.cipher.decrypt(
            &ticket.session_key,
            usage::AP_REP_ENCPART,
            &ap_rep.enc_part.cipher,
        )?;
        let part = EncApRepPart::decode(&opened)?;
        if part.ctime != now {
            return Err(Error::Hprop(format!(
                "the AP-REP is for a different exchange: it answers ctime {} and this one is {now}",
                part.ctime
            )));
        }
        // The server's own subkey, if it made one; otherwise the session key seals the
        // acknowledgement, which is the fallback the receiving side documents.
        let reply_key = part.subkey.unwrap_or_else(|| ticket.session_key.clone());
        Ok((subkey, reply_key))
    }
}
