//! RFC 4120 §7.2 transport: UDP and TCP, with no dependency on an async
//! runtime.
//!
//! The engine is sans-io, so this is the only module that touches a socket, and
//! it does two things: it puts a four-octet length in front of a TCP message,
//! and it refuses to send a datagram larger than the client can be expected to
//! receive.
//!
//! The loopback server exists for the tests and for `examples/`. A daemon wants
//! its own supervision, its own readiness reporting and its own privilege
//! dropping, none of which belong in a library.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use crate::error::{Error, Result, codes};
use crate::kdc::Kdc;

/// RFC 4120 §7.2.1: a reply that does not fit in this many octets goes over
/// TCP, and UDP gets `KDC_ERR_RESPONSE_TOO_BIG` instead.
pub const MAX_DATAGRAM_REPLY: usize = 1400;

/// A KDC answering on loopback until it is dropped.
pub struct RunningKdc {
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
    udp: std::thread::JoinHandle<()>,
    tcp: std::thread::JoinHandle<()>,
}

impl RunningKdc {
    /// The address to hand a client, as `host:port`.
    pub fn addr(&self) -> String {
        self.addr.to_string()
    }

    /// Asks both loops to stop and waits for them.
    pub fn stop(mut self) {
        self.shutdown();
    }

    fn shutdown(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        // The threads poll their sockets with a timeout, so joining them is
        // bounded by that timeout; a `join` on a thread that never wakes would
        // hang the test that just passed.
        let udp = std::mem::replace(&mut self.udp, std::thread::spawn(|| {}));
        let tcp = std::mem::replace(&mut self.tcp, std::thread::spawn(|| {}));
        let _ = udp.join();
        let _ = tcp.join();
    }
}

impl Drop for RunningKdc {
    fn drop(&mut self) {
        self.shutdown();
    }
}

impl std::fmt::Debug for RunningKdc {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RunningKdc({})", self.addr)
    }
}

/// Binds UDP and TCP on the same loopback port and answers with `kdc`.
///
/// The same port on both protocols is what a client expects: it discovers a KDC
/// by name, not by transport, and picks the protocol per request.
pub fn serve_loopback(kdc: Kdc) -> RunningKdc {
    serve_on(("127.0.0.1", 0), kdc)
}

/// Binds UDP and TCP on `addr` and answers with `kdc`.
///
/// The address a real deployment needs: port 88 is below 1024, so it takes a
/// privileged process or a capability, and a KDC that could only bind loopback
/// would be a library no daemon could wrap. `serve_loopback` is this with a
/// loopback address and an ephemeral port.
///
/// Panics when the pair cannot be bound. The alternative — returning an error a
/// caller might ignore — leaves a KDC that looks alive and answers nothing, and a
/// realm whose first symptom is a client timing out.
pub fn serve_on<A: std::net::ToSocketAddrs>(addr: A, kdc: Kdc) -> RunningKdc {
    let kdc = Arc::new(kdc);
    let addr = addr
        .to_socket_addrs()
        .unwrap_or_else(|e| panic!("cannot resolve the KDC address: {e}"))
        .next()
        .unwrap_or_else(|| panic!("the KDC address resolved to nothing"));
    // Bind TCP first, then UDP on the same address: the pair can collide with
    // another process between the two binds, so a few attempts are made rather
    // than panicking on the first race. With an explicit port the retry cannot
    // help, and the bind either works or says why.
    let mut attempt = 0;
    let (listener, udp) = loop {
        attempt += 1;
        let listener = TcpListener::bind(addr)
            .unwrap_or_else(|e| panic!("cannot bind the TCP listener on {addr}: {e}"));
        let bound = listener
            .local_addr()
            .expect("bound listener has an address");
        match UdpSocket::bind(bound) {
            Ok(udp) => break (listener, udp),
            Err(_) if attempt < 16 && addr.port() == 0 => continue,
            Err(e) => panic!("cannot bind UDP on {bound}: {e}"),
        }
    };
    let addr = listener
        .local_addr()
        .expect("bound listener has an address");
    let stop = Arc::new(AtomicBool::new(false));

    let udp_thread = {
        let kdc = Arc::clone(&kdc);
        let stop = Arc::clone(&stop);
        std::thread::spawn(move || serve_udp(&udp, kdc.as_ref(), &stop))
    };
    let tcp_thread = {
        let kdc = Arc::clone(&kdc);
        let stop = Arc::clone(&stop);
        std::thread::spawn(move || serve_tcp(&listener, kdc.as_ref(), &stop))
    };

    RunningKdc {
        addr,
        stop,
        udp: udp_thread,
        tcp: tcp_thread,
    }
}

fn serve_udp(socket: &UdpSocket, kdc: &Kdc, stop: &AtomicBool) {
    // A read timeout is what makes the loop stoppable: a blocking `recv_from`
    // never returns when nobody sends, and a server that cannot be shut down is
    // a server that leaks in every test that starts one.
    let _ = socket.set_read_timeout(Some(Duration::from_millis(50)));
    let mut buf = vec![0u8; 65_535];
    while !stop.load(Ordering::Relaxed) {
        let (n, from) = match socket.recv_from(&mut buf) {
            Ok(v) => v,
            Err(_) => continue, // timeout, or a datagram we could not read
        };
        // The peer's address is known here and nowhere else: the engine cannot
        // see a socket, and a check it cannot answer would have to pass.
        let reply = kdc.handle_from(&buf[..n], now(), Some(from.ip()));
        let reply = if reply.len() > MAX_DATAGRAM_REPLY {
            too_big(&reply, kdc)
        } else {
            reply
        };
        let _ = socket.send_to(&reply, from);
    }
}

/// `KDC_ERR_RESPONSE_TOO_BIG`: a real error, not an empty reply, so the client
/// retries over TCP instead of waiting.
fn too_big(_reply: &[u8], kdc: &Kdc) -> Vec<u8> {
    crate::msg::KrbError {
        ctime: None,
        cusec: None,
        stime: now(),
        susec: 0,
        code: codes::KDC_ERR_RESPONSE_TOO_BIG,
        crealm: None,
        cname: None,
        realm: kdc.config().realm().to_owned(),
        sname: crate::name::Principal::krbtgt(kdc.config().realm()),
        e_text: Some("reply too big for UDP; retry over TCP".into()),
        e_data: None,
    }
    .encode()
}

fn serve_tcp(listener: &TcpListener, kdc: &Kdc, stop: &AtomicBool) {
    let _ = listener.set_nonblocking(true);
    while !stop.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((stream, peer)) => {
                let _ = stream.set_nodelay(true);
                serve_stream(stream, kdc, stop, peer.ip());
            }
            // Nothing waiting: yield instead of spinning.
            Err(_) => std::thread::sleep(Duration::from_millis(10)),
        }
    }
}

/// One TCP connection: RFC 4120 §7.2.2 frames each message with a four-octet
/// big-endian length, and a connection may carry several requests.
fn serve_stream(mut stream: TcpStream, kdc: &Kdc, stop: &AtomicBool, peer: std::net::IpAddr) {
    let _ = stream.set_read_timeout(Some(Duration::from_millis(200)));
    loop {
        if stop.load(Ordering::Relaxed) {
            return;
        }
        let mut len = [0u8; 4];
        if stream.read_exact(&mut len).is_err() {
            return;
        }
        let len = u32::from_be_bytes(len) as usize;
        if len == 0 || len > 1 << 20 {
            return;
        }
        let mut msg = vec![0u8; len];
        if stream.read_exact(&mut msg).is_err() {
            return;
        }
        let reply = kdc.handle_from(&msg, now(), Some(peer));
        let mut framed = (reply.len() as u32).to_be_bytes().to_vec();
        framed.extend_from_slice(&reply);
        if stream.write_all(&framed).is_err() {
            return;
        }
        let _ = stream.flush();
    }
}

/// A change-password service on loopback, for the tests and for a stand.
///
/// Port 464 in a real deployment; the framing is RFC 3244 §3 — a two-octet total
/// length, a version, an `AP-REQ` length, then the `AP-REQ` and the sealed
/// request — wrapped in the same four-octet TCP length everything else uses.
pub fn serve_kpasswd_loopback(kdc: Kdc) -> RunningKpasswd {
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .unwrap_or_else(|e| panic!("cannot bind the kpasswd listener: {e}"));
    let addr = listener
        .local_addr()
        .expect("bound listener has an address");
    let stop = Arc::new(AtomicBool::new(false));
    let thread = {
        let kdc = Arc::new(kdc);
        let stop = Arc::clone(&stop);
        std::thread::spawn(move || {
            let _ = listener.set_nonblocking(true);
            while !stop.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, _)) => serve_kpasswd_stream(stream, kdc.as_ref()),
                    Err(_) => std::thread::sleep(Duration::from_millis(10)),
                }
            }
        })
    };
    RunningKpasswd {
        addr,
        stop,
        thread: Some(thread),
    }
}

/// A change-password service answering on loopback until it is dropped.
pub struct RunningKpasswd {
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl RunningKpasswd {
    /// The address to hand a client, as `host:port`.
    pub fn addr(&self) -> String {
        self.addr.to_string()
    }
}

impl Drop for RunningKpasswd {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

impl std::fmt::Debug for RunningKpasswd {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RunningKpasswd({})", self.addr)
    }
}

/// One request, one reply. RFC 3244 lets a connection carry several, but a
/// client sends one and closes, and holding the socket open across a password
/// change is a liability rather than a feature.
fn serve_kpasswd_stream(mut stream: TcpStream, kdc: &Kdc) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let mut framing = [0u8; 4];
    if stream.read_exact(&mut framing).is_err() {
        return;
    }
    let n = u32::from_be_bytes(framing) as usize;
    if n == 0 || n > 65_536 {
        return;
    }
    let mut request = vec![0u8; n];
    if stream.read_exact(&mut request).is_err() {
        return;
    }
    let reply = match kpasswd_reply(kdc, &request) {
        Ok(reply) => reply,
        Err(err) => {
            // A refusal still gets a KRB-ERROR, so the client learns why
            // instead of waiting for a timeout it will read as a network fault.
            crate::msg::KrbError {
                ctime: None,
                cusec: None,
                stime: now(),
                susec: 0,
                code: err.kdc_code(),
                crealm: None,
                cname: None,
                realm: kdc.config().realm().to_owned(),
                sname: crate::name::Principal::krbtgt(kdc.config().realm()),
                e_text: err.is_client_facing().then(|| err.to_string()),
                e_data: None,
            }
            .encode()
        }
    };
    let mut framed = (reply.len() as u32).to_be_bytes().to_vec();
    framed.extend_from_slice(&reply);
    let _ = stream.write_all(&framed);
    let _ = stream.flush();
}

/// Unpacks one RFC 3244 request and answers it.
fn kpasswd_reply(kdc: &Kdc, request: &[u8]) -> Result<Vec<u8>> {
    if request.len() < 6 {
        return Err(Error::Protocol("kpasswd request is too short".into()));
    }
    let total = u16::from_be_bytes([request[0], request[1]]) as usize;
    if total != request.len() {
        return Err(Error::Protocol(format!(
            "kpasswd request says {total} octets, {} arrived",
            request.len()
        )));
    }
    let version = u16::from_be_bytes([request[2], request[3]]);
    let ap_len = u16::from_be_bytes([request[4], request[5]]) as usize;
    let rest = &request[6..];
    if ap_len > rest.len() {
        return Err(Error::Protocol("the AP-REQ overruns the request".into()));
    }
    let (ap_req, priv_message) = rest.split_at(ap_len);
    let reply = kdc.handle_kpasswd(ap_req, priv_message, version, now())?;
    Ok(reply.encode(version))
}

/// The clock, read only here: everything above it takes the instant as a
/// parameter.
fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// A frame reader, for a client side that wants to talk to this KDC over TCP
/// without a Kerberos library.
pub fn read_frame(stream: &mut TcpStream) -> Result<Vec<u8>> {
    let mut len = [0u8; 4];
    stream.read_exact(&mut len).map_err(Error::Io)?;
    let len = u32::from_be_bytes(len) as usize;
    let mut msg = vec![0u8; len];
    stream.read_exact(&mut msg).map_err(Error::Io)?;
    Ok(msg)
}

/// Writes one frame.
pub fn write_frame(stream: &mut TcpStream, msg: &[u8]) -> Result<()> {
    let mut framed = (msg.len() as u32).to_be_bytes().to_vec();
    framed.extend_from_slice(msg);
    stream.write_all(&framed).map_err(Error::Io)
}
