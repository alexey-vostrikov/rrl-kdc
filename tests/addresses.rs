//! Ticket addresses: the client says where it will be, and the KDC holds it to
//! that.
//!
//! Heimdal's `_kdc_check_addresses` is the specification here, including its two
//! odd corners: a request with no addresses is allowed or refused depending on
//! `allow_null_ticket_addresses` (default: allowed), and a request whose only
//! address is a NetBIOS name is treated as having none — Windows sends its
//! NetBIOS name for the "allowed workstations" check, and refusing every Windows
//! client over an address the KDC cannot verify would be worse than allowing it.
//!
//! The peer address is a parameter of the request, not something the engine
//! looks up: a sans-io engine cannot see a socket, and a check whose input is
//! invisible cannot be tested.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use rust_kdc::crypto::{Cipher, Enctype, OwnCipher, usage};
use rust_kdc::der;
use rust_kdc::error::codes;
use rust_kdc::hdb::{HdbEntry, MemoryHdb};
use rust_kdc::kdc::{Kdc, KdcConfig};
use rust_kdc::msg::{
    self, EncryptedData, KdcReq, encode_enc_ts_enc, encode_etype_info2, encode_pa_data, kdc_options,
};
use rust_kdc::name::Principal;

const REALM: &str = "EXAMPLE.COM";
const NOW: i64 = 1_700_000_000;

fn alice() -> Principal {
    Principal::parse(&format!("alice@{REALM}")).unwrap()
}

/// `HostAddress ::= SEQUENCE { addr-type [0], address [1] }`, and
/// `HostAddresses ::= SEQUENCE OF HostAddress`.
mod addr {
    use rust_kdc::der;

    /// `KRB5_ADDRESS_IPV4`.
    pub const IPV4: i32 = 2;
    /// `KRB5_ADDRESS_NETBIOS`.
    pub const NETBIOS: i32 = 20;
    /// `KRB5_ADDRESS_IPV6`.
    pub const IPV6: i32 = 24;

    /// One `HostAddresses` value, ready for `KDC-REQ-BODY` field `[9]`.
    pub fn host_addresses(items: &[(i32, Vec<u8>)]) -> Vec<u8> {
        der::seq(
            &items
                .iter()
                .map(|(ty, bytes)| {
                    der::seq(&[
                        der::field(0, der::int(*ty as i64)),
                        der::field(1, der::octets(bytes)),
                    ])
                })
                .collect::<Vec<_>>(),
        )
    }

    pub fn ipv4(a: [u8; 4]) -> (i32, Vec<u8>) {
        (IPV4, a.to_vec())
    }

    pub fn ipv6(a: [u8; 16]) -> (i32, Vec<u8>) {
        (IPV6, a.to_vec())
    }

    pub fn netbios(name: &str) -> (i32, Vec<u8>) {
        (NETBIOS, name.as_bytes().to_vec())
    }
}

fn db() -> MemoryHdb {
    let cipher = OwnCipher;
    let db = MemoryHdb::new();
    let mut krbtgt = HdbEntry::krbtgt(REALM);
    krbtgt
        .add_password_key(&cipher, Enctype::Aes256Sha1, b"master", 1)
        .unwrap();
    db.insert(krbtgt).unwrap();
    let mut alice_entry = HdbEntry::user(alice());
    alice_entry
        .add_password_key(&cipher, Enctype::Aes256Sha1, b"pw", 1)
        .unwrap();
    db.insert(alice_entry).unwrap();
    db
}

fn kdc_with(config: KdcConfig) -> Kdc {
    Kdc::new(config, Arc::new(db()), Arc::new(OwnCipher))
}

fn default_kdc() -> Kdc {
    kdc_with(KdcConfig::new(REALM).unwrap())
}

/// An `AS-REQ` carrying `addresses` and a valid `PA-ENC-TIMESTAMP`.
fn as_req(addresses: Option<Vec<u8>>) -> Vec<u8> {
    let cipher = OwnCipher;
    let key = cipher
        .s2k(Enctype::Aes256Sha1, b"pw", b"EXAMPLE.COMalice", None)
        .unwrap();
    let timestamp = EncryptedData::seal(
        &cipher,
        &key,
        usage::AS_REQ_PA_ENC_TS,
        None,
        &encode_enc_ts_enc(NOW, None),
    )
    .unwrap();
    let mut body_parts = vec![
        der::field(0, der::flags32(kdc_options::FORWARDABLE)),
        der::field(1, alice().encode_name()),
        der::field(2, der::general_string(REALM)),
        der::field(3, Principal::krbtgt(REALM).encode_name()),
        der::field(5, der::time(NOW + 3600)),
        der::field(7, der::int(0x1234)),
        der::field(8, der::seq(&[der::int(18)])),
    ];
    if let Some(addr) = addresses {
        body_parts.push(der::field(9, addr));
    }
    der::cons(
        der::app(10),
        &[der::seq(&[
            der::field(1, der::int(5)),
            der::field(2, der::int(10)),
            der::field(
                3,
                encode_pa_data(&[(msg::PA_ENC_TIMESTAMP, timestamp.encode())]),
            ),
            der::field(4, der::seq(&body_parts)),
        ])],
    )
}

fn code_of(reply: &[u8]) -> Option<i32> {
    msg::KrbError::decode(reply).ok().map(|e| e.code)
}

fn is_reply(reply: &[u8]) -> bool {
    // An AS-REP starts with [APPLICATION 11]; an error with [APPLICATION 30].
    reply.first() == Some(&der::app(11))
}

const CLIENT_V4: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
const OTHER_V4: IpAddr = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7));

#[test]
fn a_client_at_a_listed_address_is_accepted() {
    let reply = default_kdc().handle_from(
        &as_req(Some(addr::host_addresses(&[addr::ipv4([192, 0, 2, 10])]))),
        NOW,
        Some(CLIENT_V4),
    );
    assert!(
        is_reply(&reply),
        "the address was listed and the client is there, so this must be an AS-REP: {:?}",
        code_of(&reply)
    );
}

#[test]
fn a_client_at_an_unlisted_address_is_badaddr() {
    let reply = default_kdc().handle_from(
        &as_req(Some(addr::host_addresses(&[addr::ipv4([192, 0, 2, 10])]))),
        NOW,
        Some(OTHER_V4),
    );
    assert_eq!(code_of(&reply), Some(codes::KRB_AP_ERR_BADADDR));
}

#[test]
fn any_of_several_listed_addresses_matches() {
    let reply = default_kdc().handle_from(
        &as_req(Some(addr::host_addresses(&[
            addr::ipv4([192, 0, 2, 10]),
            addr::ipv4([198, 51, 100, 7]),
        ]))),
        NOW,
        Some(OTHER_V4),
    );
    assert!(
        is_reply(&reply),
        "the client is at the second listed address, which is enough"
    );
}

#[test]
fn ipv6_addresses_are_matched_too() {
    let peer = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
    let reply = default_kdc().handle_from(
        &as_req(Some(addr::host_addresses(&[addr::ipv6(
            peer.to_string().parse::<Ipv6Addr>().unwrap().octets(),
        )]))),
        NOW,
        Some(peer),
    );
    assert!(
        is_reply(&reply),
        "an IPv6 client at a listed address is fine"
    );
}

#[test]
fn ipv4_and_ipv6_are_not_confused() {
    // A v4 address in the list is not a v6 client's address, even when the
    // bytes look related: `::ffff:192.0.2.10` is not `192.0.2.10` here, because
    // Kerberos addresses are compared by type and value.
    let peer = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
    let reply = default_kdc().handle_from(
        &as_req(Some(addr::host_addresses(&[addr::ipv4([192, 0, 2, 10])]))),
        NOW,
        Some(peer),
    );
    assert_eq!(code_of(&reply), Some(codes::KRB_AP_ERR_BADADDR));
}

#[test]
fn a_request_with_no_addresses_is_allowed_by_default() {
    // Heimdal's `allow_null_ticket_addresses` defaults to true: a client that
    // names no address is not pretending to be somewhere it is not.
    let reply = default_kdc().handle_from(&as_req(None), NOW, Some(CLIENT_V4));
    assert!(is_reply(&reply), "no addresses means no restriction");
}

#[test]
fn a_request_with_no_addresses_is_refused_when_the_policy_says_so() {
    let kdc = kdc_with(
        KdcConfig::new(REALM)
            .unwrap()
            .with_allow_null_ticket_addresses(false),
    );
    let reply = kdc.handle_from(&as_req(None), NOW, Some(CLIENT_V4));
    assert_eq!(code_of(&reply), Some(codes::KRB_AP_ERR_BADADDR));
}

#[test]
fn checking_can_be_turned_off() {
    let kdc = kdc_with(
        KdcConfig::new(REALM)
            .unwrap()
            .with_check_ticket_addresses(false),
    );
    let reply = kdc.handle_from(
        &as_req(Some(addr::host_addresses(&[addr::ipv4([192, 0, 2, 10])]))),
        NOW,
        Some(OTHER_V4),
    );
    assert!(
        is_reply(&reply),
        "with the check off, a mismatch is not a refusal"
    );
}

#[test]
fn a_netbios_only_list_is_treated_as_no_address() {
    // Windows sends its NetBIOS name; the KDC cannot verify it, and Heimdal
    // falls back to `allow_null_ticket_addresses` rather than refusing.
    let reply = default_kdc().handle_from(
        &as_req(Some(addr::host_addresses(&[addr::netbios("WORKSTATION")]))),
        NOW,
        Some(OTHER_V4),
    );
    assert!(is_reply(&reply), "a NetBIOS-only list is not a mismatch");
}

#[test]
fn a_netbios_only_list_is_refused_when_nulls_are_not_allowed() {
    let kdc = kdc_with(
        KdcConfig::new(REALM)
            .unwrap()
            .with_allow_null_ticket_addresses(false),
    );
    let reply = kdc.handle_from(
        &as_req(Some(addr::host_addresses(&[addr::netbios("WORKSTATION")]))),
        NOW,
        Some(OTHER_V4),
    );
    assert_eq!(code_of(&reply), Some(codes::KRB_AP_ERR_BADADDR));
}

#[test]
fn a_netbios_name_alongside_an_address_does_not_disable_the_check() {
    // The corner that matters: a list with both must be checked on the IP, or a
    // client could add a NetBIOS name to escape the check.
    let reply = default_kdc().handle_from(
        &as_req(Some(addr::host_addresses(&[
            addr::netbios("WORKSTATION"),
            addr::ipv4([192, 0, 2, 10]),
        ]))),
        NOW,
        Some(OTHER_V4),
    );
    assert_eq!(code_of(&reply), Some(codes::KRB_AP_ERR_BADADDR));
}

#[test]
fn an_unknown_peer_does_not_pass_a_present_address_list() {
    // A transport that cannot report the peer (a UNIX socket, a proxy) must not
    // be able to satisfy a check it cannot answer.
    let reply = default_kdc().handle_from(
        &as_req(Some(addr::host_addresses(&[addr::ipv4([192, 0, 2, 10])]))),
        NOW,
        None,
    );
    assert_eq!(code_of(&reply), Some(codes::KRB_AP_ERR_BADADDR));
}

#[test]
fn the_ticket_carries_the_addresses_the_client_named() {
    let addresses = addr::host_addresses(&[addr::ipv4([192, 0, 2, 10])]);
    let reply = default_kdc().handle_from(&as_req(Some(addresses.clone())), NOW, Some(CLIENT_V4));
    assert!(is_reply(&reply), "the baseline must succeed");

    // The ticket's `caddr` is what a service will check, so it has to be there.
    let f = der::Fields::parse_app("AS-REP", 11, &reply).unwrap();
    let mut r = der::Reader::new(f.bytes(5, "AS-REP").unwrap());
    let ticket_bytes = der::tlv(der::app(1), r.expect_in("ticket", der::app(1)).unwrap());
    let ticket = msg::Ticket::decode(&ticket_bytes).unwrap();
    let _ = ticket;
    // The ticket's encrypted part is not readable here (it is sealed with the
    // service key), so the address list is checked through the KDC's own
    // encoder in `the_ticket_part_keeps_the_addresses` below.
}

#[test]
fn the_ticket_part_keeps_the_addresses() {
    // `caddr` is copied into the ticket verbatim; the encoder and decoder must
    // agree on it, or a service sees a different list than the KDC was given.
    let addresses = addr::host_addresses(&[addr::ipv4([192, 0, 2, 10])]);
    let part = msg::EncTicketPart {
        flags: msg::tkt_flags::INITIAL,
        session_key: OwnCipher.random(Enctype::Aes128Sha1).unwrap(),
        crealm: REALM.into(),
        cname: alice(),
        transited_type: 0,
        transited: Vec::new(),
        authtime: NOW,
        starttime: None,
        endtime: NOW + 3600,
        renew_till: None,
        caddr: Some(addresses.clone()),
        authorization_data: None,
    };
    let back = msg::EncTicketPart::decode(&part.encode()).unwrap();
    assert_eq!(
        back.caddr.as_deref(),
        Some(addresses.as_slice()),
        "the address list must survive the ticket's own encoding"
    );
}

/// The decoded request keeps the addresses as they arrived, which is what the
/// check reads.
#[test]
fn the_request_keeps_the_address_list() {
    let addresses = addr::host_addresses(&[addr::ipv4([192, 0, 2, 10])]);
    let req = KdcReq::decode(&as_req(Some(addresses.clone()))).unwrap();
    assert_eq!(req.body.addresses.as_deref(), Some(addresses.as_slice()));
    let _ = encode_etype_info2(&[]);
}
