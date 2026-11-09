//! Principal names (RFC 4120 §5.2.1) and realms (§5.2.6).
//!
//! # Name types are metadata, not identity
//!
//! MIT's `krb5_principal_compare` and Heimdal's `krb5_principal_compare` both
//! ignore the name type: `alice` as `NT-PRINCIPAL` and `alice` as
//! `NT-UNKNOWN` are the same principal. This type follows them — [`Eq`],
//! [`Ord`] and [`Hash`] are written by hand over the components and realm only.
//! Getting this wrong is the classic first bug in a KDC: the database lookup
//! misses because the client sent `NT-PRINCIPAL` and the entry was stored as
//! `NT-SRV-INST`, and the reply is "client unknown" for a principal that is
//! right there.

use std::cmp::Ordering;
use std::fmt;
use std::hash::{Hash, Hasher};

use crate::der::{self, Fields, Reader};
use crate::error::{Error, Result};

/// `KRB5_NT_UNKNOWN`.
pub const NT_UNKNOWN: i32 = 0;
/// `KRB5_NT_PRINCIPAL` — a user.
pub const NT_PRINCIPAL: i32 = 1;
/// `KRB5_NT_SRV_INST` — a service, as `krbtgt/REALM`.
pub const NT_SRV_INST: i32 = 2;
/// `KRB5_NT_SRV_HST` — a service named by host.
pub const NT_SRV_HST: i32 = 3;
/// `KRB5_NT_WELLKNOWN` (RFC 6111): the name type of a well-known principal.
///
/// `WELLKNOWN/ANONYMOUS` carries it, and a client that receives an anonymous ticket reads
/// the name by this type: the same components under another type are a different name.
pub const NT_WELLKNOWN: i32 = 11;

/// `KRB5_NT_ENTERPRISE` (RFC 6806 §6): one component, `user@realm`.
///
/// A client that knows only a UPN sends this form, and resolving it means answering with a
/// name the client did not send — which is why it is only legal together with the
/// `canonicalize` KDC option.
pub const NT_ENTERPRISE: i32 = 10;

/// A principal: components, a realm, and the name type it was learnt with.
#[derive(Clone, Debug)]
pub struct Principal {
    /// The name type (RFC 4120 §6.2). Not part of identity.
    pub name_type: i32,
    /// The name components, in order. Never empty.
    pub components: Vec<String>,
    /// The realm.
    pub realm: String,
}

#[cfg(feature = "serde")]
impl serde::Serialize for Principal {
    /// A principal as the string every Kerberos tool prints: `name@REALM`.
    ///
    /// Not as a struct: a transport's clients are administrators and their
    /// scripts, and `alice@EXAMPLE.COM` is what they already write.
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Principal {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Principal::parse(&s).map_err(serde::de::Error::custom)
    }
}

impl Principal {
    /// A principal from its parts.
    pub fn new<I, S>(name_type: i32, components: I, realm: impl Into<String>) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Principal {
            name_type,
            components: components.into_iter().map(Into::into).collect(),
            realm: realm.into(),
        }
    }

    /// `alice@EXAMPLE.COM`, or `host/h.example.com@EXAMPLE.COM`.
    ///
    /// The realm is mandatory: a bare `alice` is ambiguous, and a KDC that
    /// guesses the realm for a request is a KDC that answers for a realm it
    /// does not serve.
    pub fn parse(s: &str) -> Result<Self> {
        let (name, realm) = s.rsplit_once('@').ok_or_else(|| {
            Error::Protocol(format!("principal {s:?} has no realm: expected name@REALM"))
        })?;
        if name.is_empty() || realm.is_empty() {
            return Err(Error::Protocol(format!(
                "principal {s:?} has an empty name or realm"
            )));
        }
        Self::parse_in_realm(name, realm)
    }

    /// `name` — possibly `a/b` — inside `realm`.
    pub fn parse_in_realm(name: &str, realm: &str) -> Result<Self> {
        if name.is_empty() {
            return Err(Error::Protocol("empty principal name".into()));
        }
        let components: Vec<String> = name.split('/').map(str::to_owned).collect();
        if components.iter().any(String::is_empty) {
            return Err(Error::Protocol(format!(
                "principal {name:?} has an empty component"
            )));
        }
        let name_type = if components.len() > 1 {
            NT_SRV_INST
        } else {
            NT_PRINCIPAL
        };
        Ok(Principal {
            name_type,
            components,
            realm: realm.to_owned(),
        })
    }

    /// `krbtgt/REALM@REALM`, the ticket-granting service.
    pub fn krbtgt(realm: &str) -> Self {
        Principal {
            name_type: NT_SRV_INST,
            components: vec!["krbtgt".to_owned(), realm.to_owned()],
            realm: realm.to_owned(),
        }
    }

    /// `WELLKNOWN/ANONYMOUS@WELLKNOWN:ANONYMOUS`'s two components, in `realm`.
    pub fn anonymous(realm: &str) -> Self {
        Principal {
            name_type: NT_PRINCIPAL,
            components: vec!["WELLKNOWN".to_owned(), "ANONYMOUS".to_owned()],
            realm: realm.to_owned(),
        }
    }

    /// `kadmin/changepw` and friends: a service whose first component is a
    /// service name and whose second names the function.
    pub fn is_krbtgt(&self) -> bool {
        self.components.len() == 2 && self.components[0] == "krbtgt"
    }

    /// The components joined by `/`, without the realm.
    pub fn name(&self) -> String {
        self.components.join("/")
    }

    /// The salt Kerberos uses when the KDC names none: the realm, then every
    /// component, with nothing between them (`krb5_principal2salt`).
    pub fn default_salt(&self) -> Vec<u8> {
        let mut s = Vec::with_capacity(self.realm.len() + self.name().len());
        s.extend_from_slice(self.realm.as_bytes());
        for c in &self.components {
            s.extend_from_slice(c.as_bytes());
        }
        s
    }

    /// `PrincipalName ::= SEQUENCE { name-type [0], name-string [1] }`, without
    /// the enclosing field. This is what a `[n] PrincipalName` carries.
    pub fn encode_name(&self) -> Vec<u8> {
        der::seq(&[
            der::field(0, der::int(self.name_type as i64)),
            der::field(
                1,
                der::seq(
                    &self
                        .components
                        .iter()
                        .map(|c| der::general_string(c))
                        .collect::<Vec<_>>(),
                ),
            ),
        ])
    }

    /// Decodes a `PrincipalName` from the content of its `SEQUENCE`.
    ///
    /// `realm` is passed in: a `PrincipalName` does not carry one, and the
    /// realm is written next to it (in `KDC-REP.crealm`, `Ticket.realm`, …).
    pub fn decode(context: &'static str, content: &[u8], realm: &str) -> Result<Self> {
        let f = Fields::parse(context, content)?;
        let name_type = f.int(0, context)? as i32;
        let mut r = Reader::new(f.get(1, context)?);
        let inner = r.expect(context, der::SEQUENCE)?;
        let mut s = Reader::new(inner);
        let mut components = Vec::new();
        while !s.is_empty() {
            components.push(der::as_string(
                context,
                s.expect(context, der::GENERAL_STRING)?,
            )?);
        }
        if components.is_empty() {
            return Err(Error::Protocol(format!(
                "{context}: principal with no components"
            )));
        }
        Ok(Principal {
            name_type,
            components,
            realm: realm.to_owned(),
        })
    }

    /// Decodes a `[n] PrincipalName` field of a `Fields`.
    pub fn decode_field(
        fields: &Fields<'_>,
        field: u8,
        context: &'static str,
        realm: &str,
    ) -> Result<Self> {
        let mut r = Reader::new(fields.get(field, context)?);
        let content = r.expect(context, der::SEQUENCE)?;
        Principal::decode(context, content, realm)
    }
}

impl fmt::Display for Principal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}@{}", self.name(), self.realm)
    }
}

impl PartialEq for Principal {
    fn eq(&self, other: &Self) -> bool {
        self.realm == other.realm && self.components == other.components
    }
}

impl Eq for Principal {}

impl Hash for Principal {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.realm.hash(state);
        self.components.hash(state);
    }
}

impl PartialOrd for Principal {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Principal {
    fn cmp(&self, other: &Self) -> Ordering {
        self.realm
            .cmp(&other.realm)
            .then_with(|| self.components.cmp(&other.components))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_like_mit() {
        let p = Principal::parse("nfs/server.example.com@EXAMPLE.COM").unwrap();
        assert_eq!(p.components, ["nfs", "server.example.com"]);
        assert_eq!(p.realm, "EXAMPLE.COM");
        assert_eq!(p.name_type, NT_SRV_INST);
        assert_eq!(p.to_string(), "nfs/server.example.com@EXAMPLE.COM");
        assert_eq!(
            Principal::parse("krbtgt/R@R").unwrap(),
            Principal::krbtgt("R")
        );
        assert!(Principal::parse("alice").is_err(), "no realm");
        assert!(Principal::parse("a//b@R").is_err(), "empty component");
        assert!(Principal::parse("@R").is_err(), "empty name");
    }

    #[test]
    fn the_name_type_is_not_identity() {
        let a = Principal::new(NT_PRINCIPAL, ["alice"], "R");
        let b = Principal::new(NT_UNKNOWN, ["alice"], "R");
        assert_eq!(a, b);
        let mut set = std::collections::HashSet::new();
        set.insert(a);
        assert!(
            set.contains(&b),
            "a name-type change must not lose the entry"
        );
    }

    #[test]
    fn the_default_salt_is_the_realm_then_the_components() {
        let p = Principal::parse("host/a.b@EX.COM").unwrap();
        assert_eq!(p.default_salt(), b"EX.COMhosta.b");
        assert_eq!(
            Principal::parse("alice@EX.COM").unwrap().default_salt(),
            b"EX.COMalice"
        );
    }

    #[test]
    fn names_round_trip_through_der() {
        let p = Principal::parse("svc/h.example.com@R").unwrap();
        let fields = der::seq(&[der::field(4, p.encode_name())]);
        let mut r = Reader::new(&fields);
        let f = Fields::parse("KDC-REP", r.expect("rep", der::SEQUENCE).unwrap()).unwrap();
        let back = Principal::decode_field(&f, 4, "cname", "R").unwrap();
        assert_eq!(back, p);
        assert_eq!(back.name_type, p.name_type);
    }

    #[test]
    fn a_nameless_principal_is_refused() {
        let content = der::seq(&[der::field(0, der::int(1)), der::field(1, der::seq(&[]))]);
        assert!(Principal::decode("PrincipalName", &content, "R").is_err());
    }
}
