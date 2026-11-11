//! A referral chain, end to end: three KDCs and a client that walks it.
//!
//! RFC 6806 §8, quoted with its own example:
//!
//! ```text
//! C: TGS-REQ sname=http/foo.dev.example.com +NC to ADMIN.EXAMPLE.COM
//! S: TGS-REP sname=krbtgt/EXAMPLE.COM@ADMIN.EXAMPLE.COM
//! C: TGS-REQ sname=http/foo.dev.example.com +NC to EXAMPLE.COM
//! S: TGS-REP sname=krbtgt/DEV.EXAMPLE.COM@EXAMPLE.COM
//! C: TGS-REQ sname=http/foo.dev.example.com +NC to DEV.EXAMPLE.COM
//! S: TGS-REP sname=http/foo.dev.example.com@DEV.EXAMPLE.COM
//! ```
//!
//! Every exchange here goes over a socket: three KDCs on loopback, and the test plays the client,
//! following exactly the chain the RFC draws. What that buys over the engine-level tests in
//! `referral.rs` is the middle hop — a realm that is neither where the client started nor where it
//! ends, holding two trust entries and choosing between them.
//!
//! The chain is also the only place where `transited` is not empty: the last KDC has to add the
//! realm before it, accept it, and say so in the ticket's flags.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;

use rrl_kdc::crypto::{Cipher, Enctype, Key, OwnCipher, usage};
use rrl_kdc::der;
use rrl_kdc::hdb::{HdbEntry, MemoryHdb};
use rrl_kdc::kdc::{Kdc, KdcConfig};
use rrl_kdc::msg::{
    self, ApReq, Authenticator, EncKdcRepPart, EncTicketPart, EncryptedData, Ticket,
    encode_pa_data, kdc_options, tkt_flags,
};
use rrl_kdc::name::Principal;
use rrl_kdc::transport::{RunningKdc, serve_loopback};

const ADMIN: &str = "ADMIN.EXAMPLE.COM";
const MID: &str = "EXAMPLE.COM";
const DEV: &str = "DEV.EXAMPLE.COM";
const PASSWORD: &str = "correct horse battery staple";

fn srv(components: &[&str], realm: &str) -> Principal {
    Principal {
        name_type: rrl_kdc::name::NT_SRV_INST,
        components: components.iter().map(|c| (*c).to_owned()).collect(),
        realm: realm.to_owned(),
    }
}

/// `krbtgt/X` as stored in `realm` — one side of a trust.
fn trust(realm: &str, x: &str) -> Principal {
    srv(&["krbtgt", x], realm)
}

/// The key every trust in this stand shares. One key keeps the arithmetic out of the way; what the
/// chain is about is which entry each KDC picks and what it says in the ticket.
fn shared_key() -> Key {
    OwnCipher
        .s2k(
            Enctype::Aes256Sha1,
            b"trust",
            b"shared between realms",
            None,
        )
        .unwrap()
}

fn alice() -> Principal {
    Principal::parse(&format!("alice@{ADMIN}")).unwrap()
}

fn service() -> Principal {
    srv(&["cifs", "files"], DEV)
}

/// The realm the client starts in: its own `krbtgt`, its user, and a trust with the middle realm.
fn realm_admin() -> MemoryHdb {
    let cipher = OwnCipher;
    let db = MemoryHdb::new();
    let mut krbtgt = HdbEntry::krbtgt(ADMIN);
    krbtgt
        .add_password_key(&cipher, Enctype::Aes256Sha1, b"master admin", 1)
        .unwrap();
    db.insert(krbtgt).unwrap();

    let mut user = HdbEntry::user(alice());
    user.add_password_key(&cipher, Enctype::Aes256Sha1, PASSWORD.as_bytes(), 1)
        .unwrap();
    db.insert(user).unwrap();

    // Towards the parent, and nothing towards DEV: that is what makes the client need a second hop.
    let mut towards_mid = HdbEntry::service(trust(ADMIN, MID));
    towards_mid.add_key(shared_key(), 1, None);
    db.insert(towards_mid).unwrap();
    db
}

/// The middle realm: the mirror of ADMIN's trust, and the trust towards DEV.
fn realm_mid() -> MemoryHdb {
    let cipher = OwnCipher;
    let db = MemoryHdb::new();
    let mut krbtgt = HdbEntry::krbtgt(MID);
    krbtgt
        .add_password_key(&cipher, Enctype::Aes256Sha1, b"master mid", 1)
        .unwrap();
    db.insert(krbtgt).unwrap();

    for name in [trust(MID, ADMIN), trust(MID, DEV)] {
        let mut entry = HdbEntry::service(name);
        entry.add_key(shared_key(), 1, None);
        db.insert(entry).unwrap();
    }
    db
}

/// The realm the service lives in.
fn realm_dev() -> MemoryHdb {
    let cipher = OwnCipher;
    let db = MemoryHdb::new();
    let mut krbtgt = HdbEntry::krbtgt(DEV);
    krbtgt
        .add_password_key(&cipher, Enctype::Aes256Sha1, b"master dev", 1)
        .unwrap();
    db.insert(krbtgt).unwrap();

    let mut from_mid = HdbEntry::service(trust(DEV, MID));
    from_mid.add_key(shared_key(), 1, None);
    db.insert(from_mid).unwrap();

    let mut svc = HdbEntry::service(service());
    svc.add_password_key(&cipher, Enctype::Aes256Sha1, b"svc", 1)
        .unwrap();
    db.insert(svc).unwrap();
    db
}

fn start(realm: &str, db: MemoryHdb) -> RunningKdc {
    serve_loopback(Kdc::new(
        KdcConfig::new(realm).unwrap(),
        Arc::new(db),
        Arc::new(OwnCipher),
    ))
}

fn ask(addr: &str, request: &[u8]) -> Vec<u8> {
    let mut stream = TcpStream::connect(addr).expect("the KDC listens");
    let mut framed = (request.len() as u32).to_be_bytes().to_vec();
    framed.extend_from_slice(request);
    stream.write_all(&framed).expect("the request goes out");
    let mut header = [0u8; 4];
    stream.read_exact(&mut header).expect("a reply arrives");
    let len = u32::from_be_bytes(header) as usize;
    let mut reply = vec![0u8; len];
    stream.read_exact(&mut reply).expect("the reply is whole");
    reply
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

fn as_req(client: &Principal, timestamp: i64) -> Vec<u8> {
    let cipher = OwnCipher;
    let realm = client.realm.as_str();
    let key = cipher
        .s2k(
            Enctype::Aes256Sha1,
            PASSWORD.as_bytes(),
            &client.default_salt(),
            None,
        )
        .unwrap();
    let stamped = msg::encode_enc_ts_enc(timestamp, None);
    let value = EncryptedData::seal(&cipher, &key, usage::AS_REQ_PA_ENC_TS, None, &stamped)
        .unwrap()
        .encode();
    let body = der::seq(&[
        der::field(0, der::flags32(kdc_options::FORWARDABLE)),
        der::field(1, client.encode_name()),
        der::field(2, der::general_string(realm)),
        der::field(3, Principal::krbtgt(realm).encode_name()),
        der::field(5, der::time(timestamp + 3600)),
        der::field(7, der::int(0x1111_2222)),
        der::field(8, der::seq(&[der::int(18)])),
    ]);
    der::cons(
        der::app(10),
        &[der::seq(&[
            der::field(1, der::int(5)),
            der::field(2, der::int(10)),
            der::field(3, encode_pa_data(&[(msg::PA_ENC_TIMESTAMP, value)])),
            der::field(4, body),
        ])],
    )
}

/// A `TGS-REQ` to the KDC of `tgt_realm_of_kdc`, for `target`, presenting `ticket`.
///
/// The body's realm is the *target's* realm (RFC 4120 §5.4.1 field [2]) — which is what lets one
/// request name a service in a realm other than the KDC's own.
fn tgs_req(
    ticket: &[u8],
    session_key: &Key,
    target: &Principal,
    client: &Principal,
    timestamp: i64,
    options: u32,
) -> Vec<u8> {
    let cipher = OwnCipher;
    let body = der::seq(&[
        der::field(0, der::flags32(options)),
        der::field(2, der::general_string(&target.realm)),
        der::field(3, target.encode_name()),
        der::field(5, der::time(timestamp + 3600)),
        der::field(7, der::int(0x3333_4444)),
        der::field(8, der::seq(&[der::int(18)])),
    ]);
    let cksum = cipher
        .checksum(session_key, usage::TGS_REQ_AUTH_CKSUM, &body)
        .unwrap();
    let authenticator = Authenticator {
        crealm: client.realm.clone(),
        cname: client.clone(),
        cksum: Some((Enctype::Aes256Sha1.checksum_type(), cksum)),
        cusec: 0,
        ctime: timestamp,
        subkey: None,
        seq_number: None,
        authorization_data: None,
    };
    let ap_req = ApReq {
        ap_options: 0,
        ticket: ticket.to_vec(),
        authenticator: EncryptedData::seal(
            &cipher,
            session_key,
            usage::TGS_REQ_AUTH,
            None,
            &authenticator.encode(),
        )
        .unwrap(),
    };
    der::cons(
        der::app(12),
        &[der::seq(&[
            der::field(1, der::int(5)),
            der::field(2, der::int(12)),
            der::field(3, encode_pa_data(&[(msg::PA_TGS_REQ, ap_req.encode())])),
            der::field(4, body),
        ])],
    )
}

/// One reply, split into the parts a client needs: the encrypted part (opened with the reply key),
/// the ticket, and that ticket's contents (opened with the key of the realm it was issued to).
fn open_reply(reply: &[u8], reply_key: &Key) -> (EncKdcRepPart, Ticket) {
    let f = der::Fields::parse_app("TGS-REP", 13, reply).unwrap_or_else(|_| {
        panic!(
            "expected a TGS-REP, got {:?}",
            msg::KrbError::decode(reply).map(|e| (e.code, e.e_text))
        )
    });
    let mut r = der::Reader::new(f.bytes(6, "enc-part").unwrap());
    let content = r.expect_in("enc-part", der::SEQUENCE).unwrap();
    let enc = EncryptedData::decode_content("enc-part", content).unwrap();
    let plain = OwnCipher
        .decrypt(reply_key, usage::TGS_REP_ENCPART_SESSKEY, &enc.cipher)
        .expect("the reply must open under the TGT's session key");
    (
        EncKdcRepPart::decode(&plain).expect("an EncTGSRepPart"),
        Ticket::decode(f.bytes(5, "ticket").unwrap()).expect("the ticket decodes"),
    )
}

fn ticket_part(ticket: &Ticket, key: &Key) -> EncTicketPart {
    let plain = OwnCipher
        .decrypt(key, usage::KDC_REP_TICKET, &ticket.enc.cipher)
        .expect("the ticket must open under the key of the realm it was issued to");
    EncTicketPart::decode(&plain).expect("an EncTicketPart")
}

#[test]
fn a_client_walks_two_referrals_to_reach_a_service_two_realms_away() {
    let admin = start(ADMIN, realm_admin());
    let mid = start(MID, realm_mid());
    let dev = start(DEV, realm_dev());
    let now = now();
    let client = alice();

    // 1. An ordinary login in ADMIN, which is where the client knows its password.
    let as_reply = ask(&admin.addr(), &as_req(&client, now));
    let password_key = OwnCipher
        .s2k(
            Enctype::Aes256Sha1,
            PASSWORD.as_bytes(),
            &client.default_salt(),
            None,
        )
        .unwrap();
    let f = der::Fields::parse_app("AS-REP", 11, &as_reply).expect("an AS-REP");
    let mut r = der::Reader::new(f.bytes(6, "AS-REP").unwrap());
    let content = r.expect_in("AS-REP", der::SEQUENCE).unwrap();
    let enc = EncryptedData::decode_content("AS-REP", content).unwrap();
    let plain = OwnCipher
        .decrypt(&password_key, usage::AS_REP_ENCPART, &enc.cipher)
        .expect("the AS reply opens in the user's key");
    let as_part = EncKdcRepPart::decode(&plain).expect("an EncASRepPart");
    let mut tgt = Ticket::decode(f.bytes(5, "AS-REP").unwrap()).expect("the TGT decodes");
    let mut tgt_key = as_part.session_key.clone();

    // 2. To ADMIN: the service lives two realms away, and ADMIN can only say which way to go.
    let reply = ask(
        &admin.addr(),
        &tgs_req(
            &tgt.encode(),
            &tgt_key,
            &service(),
            &client,
            now,
            kdc_options::CANONICALIZE,
        ),
    );
    let (part, ticket) = open_reply(&reply, &tgt_key);
    assert_eq!(
        part.sname,
        trust(ADMIN, MID),
        "the first hop is the trust ADMIN holds, not the service it cannot reach"
    );
    tgt_key = part.session_key.clone();
    tgt = ticket;

    // 3. To EXAMPLE.COM: the middle realm knows where DEV is, and says so.
    let reply = ask(
        &mid.addr(),
        &tgs_req(
            &tgt.encode(),
            &tgt_key,
            &service(),
            &client,
            now,
            kdc_options::CANONICALIZE,
        ),
    );
    let (part, ticket) = open_reply(&reply, &tgt_key);
    assert_eq!(
        part.sname,
        trust(MID, DEV),
        "the middle realm refers onward instead of answering for DEV"
    );
    let crossed = ticket_part(&ticket, &shared_key());
    assert!(
        crossed.transited.is_empty(),
        "the client has not transited anything yet: it is still one hop from home"
    );
    tgt_key = part.session_key.clone();
    tgt = ticket;

    // 4. To DEV: the service ticket, at last.
    let reply = ask(
        &dev.addr(),
        &tgs_req(&tgt.encode(), &tgt_key, &service(), &client, now, 0),
    );
    let (part, ticket) = open_reply(&reply, &tgt_key);
    assert_eq!(part.sname, service());
    assert_eq!(part.srealm, DEV);

    let service_key = OwnCipher
        .s2k(Enctype::Aes256Sha1, b"svc", &service().default_salt(), None)
        .unwrap();
    let part_of_service = ticket_part(&ticket, &service_key);
    assert_eq!(part_of_service.cname, client);
    assert_eq!(part_of_service.crealm, ADMIN, "her realm, not DEV's");
    assert_eq!(
        part_of_service.transited_type, 1,
        "DOMAIN-X500-COMPRESS is the only type RFC 4120 defines"
    );
    assert_eq!(
        String::from_utf8(part_of_service.transited.clone()).unwrap(),
        MID,
        "the realm between ADMIN and DEV is the one the path must name"
    );
    assert!(
        part_of_service.flags & tkt_flags::TRANSITED_POLICY_CHECKED != 0,
        "DEV checked that path and accepted it, and the service has to be able to tell"
    );
    assert_eq!(part.flags, part_of_service.flags);

    admin.stop();
    mid.stop();
    dev.stop();
}
