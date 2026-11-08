//! Ticket addresses: `HostAddress`, and the check Heimdal calls
//! `_kdc_check_addresses`.
//!
//! A client may say where its ticket will be used; a ticket naming addresses is
//! only good from one of them. The three corners that matter are Heimdal's, and
//! each of them has a reason:
//!
//! * no address list at all — allowed or refused by
//!   `allow_null_ticket_addresses`, which defaults to allowed, because a client
//!   that names nothing is not claiming to be somewhere it is not;
//! * a list of nothing but NetBIOS names — treated as no list. Windows sends its
//!   NetBIOS name for the "allowed workstations" check, and a KDC that refuses
//!   every Windows client over an address it cannot verify is a KDC that does
//!   not work in a Windows realm;
//! * an address list and an unknown peer — refused. A transport that cannot say
//!   where a request came from must not silently pass a check it cannot answer.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::der::{self, Fields, Reader};
use crate::error::{Error, Result};

/// `KRB5_ADDRESS_IPV4`.
pub const ADDRTYPE_IPV4: i32 = 2;
/// `KRB5_ADDRESS_NETBIOS`.
pub const ADDRTYPE_NETBIOS: i32 = 20;
/// `KRB5_ADDRESS_IPV6`.
pub const ADDRTYPE_IPV6: i32 = 24;

/// `HostAddress ::= SEQUENCE { addr-type [0] Int32, address [1] OCTET STRING }`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostAddress {
    /// `addr-type`.
    pub addr_type: i32,
    /// `address`, in network order for the IP types.
    pub address: Vec<u8>,
}

impl HostAddress {
    /// The `HostAddress` for `ip`.
    pub fn from_ip(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(v4) => HostAddress {
                addr_type: ADDRTYPE_IPV4,
                address: v4.octets().to_vec(),
            },
            IpAddr::V6(v6) => HostAddress {
                addr_type: ADDRTYPE_IPV6,
                address: v6.octets().to_vec(),
            },
        }
    }

    /// The address as an IP, when it is one this crate understands.
    pub fn as_ip(&self) -> Option<IpAddr> {
        match self.addr_type {
            ADDRTYPE_IPV4 => {
                let bytes: [u8; 4] = self.address.as_slice().try_into().ok()?;
                Some(IpAddr::V4(Ipv4Addr::from(bytes)))
            }
            ADDRTYPE_IPV6 => {
                let bytes: [u8; 16] = self.address.as_slice().try_into().ok()?;
                Some(IpAddr::V6(Ipv6Addr::from(bytes)))
            }
            _ => None,
        }
    }

    /// Whether this is `ip`. Type and value both, never the octets alone: a
    /// four-octet IPv4 address and the first four octets of an IPv6 address are
    /// not the same address.
    pub fn matches(&self, ip: IpAddr) -> bool {
        self.as_ip() == Some(ip)
    }

    /// The DER of one `HostAddress` SEQUENCE.
    pub fn encode(&self) -> Vec<u8> {
        der::seq(&[
            der::field(0, der::int(self.addr_type as i64)),
            der::field(1, der::octets(&self.address)),
        ])
    }

    /// Decodes one `HostAddress` SEQUENCE from the content of its `SEQUENCE`.
    ///
    /// The content, not the whole TLV, because every caller here has already
    /// stripped the tag: `[4]` of an `EncKrbPrivPart`, or an element of a
    /// `HostAddresses`.
    pub fn decode_content(content: &[u8]) -> Result<Self> {
        let f = Fields::parse("HostAddress", content)?;
        Ok(HostAddress {
            addr_type: f.int(0, "HostAddress")? as i32,
            address: f.octets(1, "HostAddress")?.to_vec(),
        })
    }

    /// Decodes one whole `HostAddress` SEQUENCE, tag included.
    pub fn decode(data: &[u8]) -> Result<Self> {
        let mut r = Reader::new(data);
        HostAddress::decode_content(r.expect("HostAddress", der::SEQUENCE)?)
    }
}

/// `HostAddresses ::= SEQUENCE OF HostAddress`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HostAddresses(pub Vec<HostAddress>);

impl HostAddresses {
    /// Decodes a `HostAddresses` value: the whole SEQUENCE, tag included —
    /// which is what a `KDC-REQ-BODY`'s `[9]` carries.
    pub fn decode(data: &[u8]) -> Result<Self> {
        let mut r = Reader::new(data);
        let content = r.expect("HostAddresses", der::SEQUENCE)?;
        let mut s = Reader::new(content);
        let mut out = Vec::new();
        while !s.is_empty() {
            out.push(HostAddress::decode_content(
                s.expect("HostAddresses", der::SEQUENCE)?,
            )?);
        }
        Ok(HostAddresses(out))
    }

    /// The DER of the `HostAddresses` SEQUENCE.
    pub fn encode(&self) -> Vec<u8> {
        der::seq(&self.0.iter().map(HostAddress::encode).collect::<Vec<_>>())
    }

    /// Whether the list holds an address the KDC cannot verify — only NetBIOS
    /// names, which is what Windows sends.
    pub fn is_netbios_only(&self) -> bool {
        !self.0.is_empty() && self.0.iter().all(|a| a.addr_type == ADDRTYPE_NETBIOS)
    }

    /// Whether `ip` is in the list.
    pub fn contains(&self, ip: IpAddr) -> bool {
        self.0.iter().any(|a| a.matches(ip))
    }
}

/// The address policy, as Heimdal's `check-ticket-addresses`,
/// `allow-null-ticket-addresses` and `warn-ticket-addresses` express it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AddressPolicy {
    /// `check-ticket-addresses`: verify a ticket's addresses at all.
    pub check: bool,
    /// `allow-null-ticket-addresses`: a request naming no address is allowed.
    pub allow_null: bool,
    /// `warn-ticket-addresses`: a mismatch is logged instead of refused.
    pub warn: bool,
}

impl Default for AddressPolicy {
    fn default() -> Self {
        // Heimdal's defaults: check, allow nulls, do not warn.
        AddressPolicy {
            check: true,
            allow_null: true,
            warn: false,
        }
    }
}

/// What the check decided, so the caller can log a warning it chose to allow.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AddressCheck {
    /// Nothing to check, or the address matched.
    Allowed,
    /// The addresses do not include the client, and the policy says warn.
    Mismatched,
}

impl AddressCheck {
    /// Whether the request may proceed.
    pub fn is_allowed(self) -> bool {
        matches!(self, AddressCheck::Allowed)
    }
}

/// Heimdal's `_kdc_check_addresses`, as a decision rather than a side effect.
///
/// `addresses` is the encoded `HostAddresses` from the request, if it sent one;
/// `peer` is where the request came from, when the transport knows.
pub fn check(
    policy: AddressPolicy,
    addresses: Option<&[u8]>,
    peer: Option<IpAddr>,
) -> Result<AddressCheck> {
    if !policy.check && !policy.warn {
        return Ok(AddressCheck::Allowed);
    }
    let Some(raw) = addresses else {
        return Ok(if policy.allow_null {
            AddressCheck::Allowed
        } else {
            AddressCheck::Mismatched
        });
    };
    let list = HostAddresses::decode(raw)?;
    if list.0.is_empty() {
        return Ok(if policy.allow_null {
            AddressCheck::Allowed
        } else {
            AddressCheck::Mismatched
        });
    }
    if list.is_netbios_only() {
        // Windows' "allowed workstations" name: unverifiable here, so the null
        // policy decides, exactly as Heimdal does.
        return Ok(if policy.allow_null {
            AddressCheck::Allowed
        } else {
            AddressCheck::Mismatched
        });
    }
    // A list with a real address in it is checked, NetBIOS names and all: a
    // client that could escape the check by adding a NetBIOS name beside its IP
    // would make the check meaningless.
    let Some(peer) = peer else {
        return Ok(AddressCheck::Mismatched);
    };
    Ok(if list.contains(peer) {
        AddressCheck::Allowed
    } else {
        AddressCheck::Mismatched
    })
}

/// The error a refused address check produces.
pub fn refused() -> Error {
    Error::Kdc {
        code: crate::error::codes::KRB_AP_ERR_BADADDR,
        text: "the ticket's addresses do not include the client".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn addresses_round_trip() {
        let list = HostAddresses(vec![
            HostAddress::from_ip(ip("192.0.2.10")),
            HostAddress::from_ip(ip("2001:db8::1")),
            HostAddress {
                addr_type: ADDRTYPE_NETBIOS,
                address: b"WORKSTATION".to_vec(),
            },
        ]);
        assert_eq!(HostAddresses::decode(&list.encode()).unwrap(), list);
    }

    #[test]
    fn an_ipv4_address_is_not_an_ipv6_address() {
        let v4 = HostAddress::from_ip(ip("192.0.2.10"));
        assert!(v4.matches(ip("192.0.2.10")));
        assert!(!v4.matches(ip("2001:db8::1")));
        // Same leading octets, different type.
        let v6 = HostAddress::from_ip(ip("c000:020a::"));
        assert!(!v6.matches(ip("192.0.2.10")));
        assert_eq!(v6.address[..4], [0xc0, 0x00, 0x02, 0x0a]);
    }

    #[test]
    fn an_address_of_the_wrong_length_does_not_match() {
        let bad = HostAddress {
            addr_type: ADDRTYPE_IPV4,
            address: vec![192, 0, 2],
        };
        assert_eq!(bad.as_ip(), None);
        assert!(!bad.matches(ip("192.0.2.10")));
    }

    #[test]
    fn no_addresses_follow_the_null_policy() {
        let allow = AddressPolicy::default();
        assert_eq!(
            check(allow, None, Some(ip("192.0.2.10"))).unwrap(),
            AddressCheck::Allowed
        );
        let deny = AddressPolicy {
            allow_null: false,
            ..AddressPolicy::default()
        };
        assert_eq!(
            check(deny, None, Some(ip("192.0.2.10"))).unwrap(),
            AddressCheck::Mismatched
        );
    }

    #[test]
    fn an_empty_list_follows_the_null_policy_too() {
        let empty = HostAddresses(Vec::new()).encode();
        assert_eq!(
            check(AddressPolicy::default(), Some(&empty), None).unwrap(),
            AddressCheck::Allowed
        );
    }

    #[test]
    fn netbios_only_is_a_null_list() {
        let list = HostAddresses(vec![HostAddress {
            addr_type: ADDRTYPE_NETBIOS,
            address: b"WORKSTATION".to_vec(),
        }])
        .encode();
        assert!(HostAddresses::decode(&list).unwrap().is_netbios_only());
        assert_eq!(
            check(
                AddressPolicy::default(),
                Some(&list),
                Some(ip("198.51.100.7"))
            )
            .unwrap(),
            AddressCheck::Allowed
        );
    }

    #[test]
    fn a_netbios_name_beside_an_address_does_not_disable_the_check() {
        let list = HostAddresses(vec![
            HostAddress {
                addr_type: ADDRTYPE_NETBIOS,
                address: b"WORKSTATION".to_vec(),
            },
            HostAddress::from_ip(ip("192.0.2.10")),
        ])
        .encode();
        assert_eq!(
            check(
                AddressPolicy::default(),
                Some(&list),
                Some(ip("198.51.100.7"))
            )
            .unwrap(),
            AddressCheck::Mismatched
        );
        assert_eq!(
            check(
                AddressPolicy::default(),
                Some(&list),
                Some(ip("192.0.2.10"))
            )
            .unwrap(),
            AddressCheck::Allowed
        );
    }

    #[test]
    fn an_unknown_peer_does_not_pass_a_real_list() {
        let list = HostAddresses(vec![HostAddress::from_ip(ip("192.0.2.10"))]).encode();
        assert_eq!(
            check(AddressPolicy::default(), Some(&list), None).unwrap(),
            AddressCheck::Mismatched
        );
    }

    #[test]
    fn the_check_can_be_off() {
        let off = AddressPolicy {
            check: false,
            ..AddressPolicy::default()
        };
        let list = HostAddresses(vec![HostAddress::from_ip(ip("192.0.2.10"))]).encode();
        assert_eq!(
            check(off, Some(&list), Some(ip("198.51.100.7"))).unwrap(),
            AddressCheck::Allowed
        );
        assert!(check(off, None, None).unwrap().is_allowed());
    }

    #[test]
    fn a_broken_address_list_is_an_error_not_a_pass() {
        assert!(
            check(
                AddressPolicy::default(),
                Some(&[0xff, 0xff]),
                Some(ip("192.0.2.10"))
            )
            .is_err()
        );
    }
}
