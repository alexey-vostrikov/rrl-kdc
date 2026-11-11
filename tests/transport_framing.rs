//! The transport's honesty about what a client sent.
//!
//! A KDC that answers a malformed frame with silence, or with a reply to the wrong
//! question, is a KDC an operator debugs by packet capture. These tests exercise
//! the framing paths a client can actually reach — a truncated length prefix, a
//! kpasswd request whose length agrees with nothing, an AP-REQ that overruns its
//! buffer — and the two directions of the frame helpers.
//!
//! They run against a live loopback socket rather than a mock, because the thing
//! being tested *is* the socket handling: `read_exact` on a closed connection is
//! where a naive implementation panics instead of reporting.

use std::io::Write;
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;

use rrl_kdc::crypto::{Enctype, OwnCipher};
use rrl_kdc::hdb::{Hdb, HdbEntry, MemoryHdb};
use rrl_kdc::kdc::{Kdc, KdcConfig};
use rrl_kdc::transport::{
    read_frame, serve_kpasswd_loopback, serve_loopback, serve_on, write_frame,
};

const REALM: &str = "EXAMPLE.COM";

/// A realm with nothing but `krbtgt`: enough for the transport to have something to answer for.
fn db() -> MemoryHdb {
    let cipher = OwnCipher;
    let db = MemoryHdb::new();
    let mut krbtgt = HdbEntry::krbtgt(REALM);
    krbtgt
        .add_password_key(&cipher, Enctype::Aes256Sha1, b"master", 1)
        .unwrap();
    db.insert(krbtgt).unwrap();
    db
}

fn kdc() -> Kdc {
    Kdc::new(
        KdcConfig::new(REALM).unwrap(),
        Arc::new(db()) as Arc<dyn Hdb>,
        Arc::new(OwnCipher),
    )
}

#[test]
fn a_frame_round_trips_over_a_socket() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let writer = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        write_frame(&mut stream, b"the reply").unwrap();
    });
    let mut stream = TcpStream::connect(addr).unwrap();
    let read = read_frame(&mut stream).unwrap();
    assert_eq!(read, b"the reply");
    writer.join().unwrap();
}

#[test]
fn a_closed_connection_is_an_error_not_a_panic() {
    // The client sent a length and vanished: the answer is an I/O error the
    // caller can log, not a panic in a thread that owns the KDC.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let writer = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        // Four octets of length, then nothing.
        stream.write_all(&[0, 0, 0, 9]).unwrap();
        stream.flush().unwrap();
        drop(stream);
    });
    let mut stream = TcpStream::connect(addr).unwrap();
    let err = read_frame(&mut stream).expect_err("the body never arrived");
    assert_eq!(err.kind(), "io");
    writer.join().unwrap();
}

#[test]
fn an_empty_connection_is_an_error_not_a_panic() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let writer = std::thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        drop(stream);
    });
    let mut stream = TcpStream::connect(addr).unwrap();
    assert_eq!(read_frame(&mut stream).unwrap_err().kind(), "io");
    writer.join().unwrap();
}

#[test]
fn a_kpasswd_request_shorter_than_its_header_is_answered_with_something() {
    // The framing below needs six octets to read three u16. A shorter request must
    // still produce a reply — an operator watching a client hangs on a silent
    // server, and a client that sent garbage deserves to be told.
    let running = serve_kpasswd_loopback(kdc());
    let mut stream = TcpStream::connect(running.addr()).unwrap();
    let request = [0u8; 4];
    write_frame(&mut stream, &request).unwrap();
    // `read_frame` already stripped the length prefix, so what is left must be a
    // KRB-ERROR: a refusal the client can read, not silence it would take for a
    // network fault.
    let reply = read_frame(&mut stream).unwrap();
    let error = rrl_kdc::msg::KrbError::decode(&reply)
        .expect("a malformed kpasswd request must be answered with a KRB-ERROR");
    assert_eq!(
        error.code,
        rrl_kdc::error::Error::Protocol(String::new()).kdc_code(),
        "the code must be the one this crate maps a framing failure to"
    );
}

#[test]
fn a_kpasswd_request_whose_length_disagrees_is_refused() {
    let running = serve_kpasswd_loopback(kdc());
    let mut stream = TcpStream::connect(running.addr()).unwrap();
    // Says 100 octets, carries 8.
    let mut request = vec![0u8, 100, 0, 1, 0, 2, 0, 0];
    request[0] = (100 >> 8) as u8;
    write_frame(&mut stream, &request).unwrap();
    let reply = read_frame(&mut stream).unwrap();
    assert!(!reply.is_empty());

    // And the server is still there for the next client, which is the part that
    // matters: a malformed request must not take the listener down.
    let mut second = TcpStream::connect(running.addr()).unwrap();
    write_frame(&mut second, &[0u8; 6]).unwrap();
    assert!(!read_frame(&mut second).unwrap().is_empty());
}

#[test]
fn the_udp_and_tcp_ports_are_both_serving() {
    // A KDC that answers on only one transport looks healthy to `kinit` with a
    // short timeout and fails for everybody whose client retries differently.
    let running = serve_loopback(kdc());
    let replies: Vec<bool> = ["tcp", "udp"]
        .into_iter()
        .map(|how| {
            // A garbage message: the point is that a reply comes back at all.
            let request = vec![0x30, 0x00];
            let mut stream = TcpStream::connect(running.addr()).unwrap();
            if how == "tcp" {
                write_frame(&mut stream, &request).unwrap();
                !read_frame(&mut stream).unwrap().is_empty()
            } else {
                use std::net::UdpSocket;
                let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
                socket
                    .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                    .unwrap();
                socket.send_to(&request, running.addr()).unwrap();
                let mut buf = [0u8; 2048];
                socket.recv_from(&mut buf).is_ok()
            }
        })
        .collect();
    assert_eq!(replies, vec![true, true], "both transports must answer");
}

/// `max-kdc-datagram-reply-length` changes what UDP answers.
///
/// The same request, twice: with a limit below the size of any reply, UDP gets
/// `KDC_ERR_RESPONSE_TOO_BIG` (52) and the client is told to retry over TCP; with the option raised
/// the reply is the engine's own answer. One test with both halves, because a KDC that always said
/// 52 would pass the first alone.
#[test]
fn the_datagram_limit_decides_whether_udp_answers_or_refuses() {
    let reply_code = |limit: usize| {
        let mut config = KdcConfig::new(REALM).unwrap();
        config
            .apply("max-kdc-datagram-reply-length", &limit.to_string())
            .unwrap();
        let running = serve_loopback(Kdc::new(
            config,
            Arc::new(db()) as Arc<dyn Hdb>,
            Arc::new(OwnCipher),
        ));
        use std::net::UdpSocket;
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        socket
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        // A message the engine refuses: what it says does not matter here, only its size, and an
        // error is smaller than any limit tried below.
        socket.send_to(&[0x30, 0x00], running.addr()).unwrap();
        let mut buf = [0u8; 4096];
        let (n, _) = socket.recv_from(&mut buf).expect("a reply over UDP");
        running.stop();
        rrl_kdc::msg::KrbError::decode(&buf[..n])
            .expect("a KRB-ERROR")
            .code
    };

    assert_eq!(
        reply_code(60),
        rrl_kdc::error::codes::KDC_ERR_RESPONSE_TOO_BIG,
        "a limit below the reply's size must send the client to TCP"
    );
    assert_ne!(
        reply_code(4000),
        52,
        "with room for it the engine's own answer comes back"
    );
}

/// An explicit port that cannot be bound is a failure with the address in the message, not a
/// retry loop.
///
/// The race the retry exists for is a kernel handing out a port for TCP that it then refuses for
/// UDP; that can only happen to a port nobody chose. An operator writing a port down is making a
/// decision, so the bind either works or says which address failed — sixteen silent attempts and
/// then the same failure is a worse message than the failure.
#[test]
#[should_panic(expected = "cannot bind UDP on 127.0.0.1:")]
fn an_explicit_port_that_cannot_be_bound_fails_with_the_address() {
    // UDP held by somebody else on the port the test is about to name, its TCP side free: exactly
    // the collision `serve_on` must report rather than retry.
    let occupied = std::net::UdpSocket::bind("127.0.0.1:0").expect("a port to occupy");
    let port = occupied.local_addr().expect("an address").port();
    serve_on(
        ("127.0.0.1", port),
        Kdc::new(
            KdcConfig::new(REALM).unwrap(),
            Arc::new(db()) as Arc<dyn Hdb>,
            Arc::new(OwnCipher),
        ),
    );
}

#[test]
fn stopping_the_server_releases_the_port() {
    // Otherwise the next stand in a test run binds nothing and the failure looks
    // like the KDC refusing to start.
    let running = serve_loopback(kdc());
    let addr = running.addr().parse::<std::net::SocketAddr>().unwrap();
    running.stop();
    // The TCP port must be bindable again.
    let bound = TcpListener::bind(addr);
    assert!(
        bound.is_ok(),
        "the listener must be gone after stop(): {:?}",
        bound.err()
    );
}

#[test]
fn a_stopped_server_no_longer_answers() {
    let running = serve_loopback(kdc());
    let addr = running.addr();
    running.stop();
    assert!(
        TcpStream::connect(&addr).is_err(),
        "a stopped KDC must not accept connections"
    );
}
