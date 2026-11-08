//! The LDAP form of a realm, without an LDAP client.
//!
//! Heimdal keeps its principals in a directory (`lib/hdb/hdb-ldap.c`) and so does
//! every deployment that has one already: the whole point of an in-process KDC is
//! that the accounts it issues tickets for are the accounts the directory holds,
//! not a second copy of them in a `hdb` file.
//!
//! # What this module is, and what it deliberately is not
//!
//! It is the **mapping**: [`to_attributes`] writes an [`HdbEntry`] as the
//! attributes Heimdal's schema defines, [`from_attributes`] reads one back, and
//! [`Directory`] is the three operations a KDC needs from whatever holds the
//! entries. It is not an LDAP client. A `\*_sys` crate, or a socket, or a
//! `ber`-encoder would each drag a dependency into a KDC that an embedder might
//! already have its own of — and the embedder that motivates this module is a
//! directory server, which would then be talking LDAP to itself over the
//! loopback.
//!
//! So [`LdapHdb`] is an `Hdb` over any [`Directory`], and an embedder implements
//! `Directory` over its own storage in a few dozen lines.
//!
//! # Binary over BER, not over this crate's DER
//!
//! `krb5Key` is an ASN.1 `Key` encoded as octets, and that part is DER — the same
//! encoding [`crate::hdb::record`] writes per key. The *envelope* is not: LDAP is
//! BER, which permits lengths and INTEGERs this crate's strict DER reader refuses
//! on purpose. Values that arrive here have already been decoded by whatever
//! spoke to the directory, so no strictness is lost by accepting the octets as
//! they are.
//!
//! # Active Directory attributes are written, not required
//!
//! `msDS-KeyVersionNumber`, `msDS-SupportedEncryptionTypes`, `userAccountControl`
//! and `servicePrincipalName` are real Microsoft OIDs and are written when the
//! entry has something to say in them, so that `sssd`, `realmd`, `adcli` and an
//! administrator's scripts find what they look for. They are never *required*:
//! an entry that carries only the Heimdal attributes is complete.
//!
//! Where both vocabularies describe the same fact and disagree, the mapping
//! refuses rather than picking one.
//!
//! `supplementalCredentials` is written and never read: it is a projection of
//! `krb5Key` for tools that look for an Active Directory's shape, so reading it
//! back would make the projection a second source of truth for the keys. A KDC that silently preferred
//! `userAccountControl` would leave an entry enabled in the directory and
//! disabled in the realm, and the operator would find out from a user.

use std::collections::BTreeMap;
use std::sync::Arc;

use crate::crypto::{Enctype, Key};
use crate::error::{Error, Result};
use crate::hdb::{Hdb, HdbEntry, HdbKey, flags};
use crate::name::Principal;
use crate::time::{format_generalized_time, parse_generalized_time};

/// Heimdal's attribute names (`lib/hdb/hdb.schema`, OID base
/// `1.3.6.1.4.1.5322.10.1.*`).
pub mod attrs {
    /// The principal as `name@REALM`. Presence of this attribute is what makes an
    /// entry a principal at all.
    pub const PRINCIPAL_NAME: &str = "krb5PrincipalName";
    /// The realm, as a DN of the `krb5Realm` entry.
    pub const PRINCIPAL_REALM: &str = "krb5PrincipalRealm";
    /// One ASN.1 `Key`, multivalued: an entry has one value per key.
    pub const KEY: &str = "krb5Key";
    /// The current key version number.
    pub const KEY_VERSION_NUMBER: &str = "krb5KeyVersionNumber";
    /// `HDBFlags` as an integer.
    pub const KDC_FLAGS: &str = "krb5KDCFlags";
    /// The enctypes this principal may be issued, as integers.
    pub const ENCRYPTION_TYPE: &str = "krb5EncryptionType";
    /// `valid_start`, `GeneralizedTime`.
    pub const VALID_START: &str = "krb5ValidStart";
    /// `valid_end`, `GeneralizedTime`.
    pub const VALID_END: &str = "krb5ValidEnd";
    /// `pw_end`, `GeneralizedTime`.
    pub const PASSWORD_END: &str = "krb5PasswordEnd";
    /// `max_life`, seconds.
    pub const MAX_LIFE: &str = "krb5MaxLife";
    /// `max_renew`, seconds.
    pub const MAX_RENEW: &str = "krb5MaxRenew";
    /// Heimdal's extension blob; kept so a value written by Heimdal survives a
    /// read and write through this crate.
    pub const EXTENDED_ATTRIBUTES: &str = "krb5ExtendedAttributes";

    /// Microsoft's key version number.
    pub const AD_KEY_VERSION_NUMBER: &str = "msDS-KeyVersionNumber";
    /// Microsoft's enctype declaration ([MS-KILE] 2.2.7 bit flags).
    pub const AD_SUPPORTED_ENCRYPTION_TYPES: &str = "msDS-SupportedEncryptionTypes";
    /// Microsoft's per-account switches.
    pub const AD_USER_ACCOUNT_CONTROL: &str = "userAccountControl";
    /// Microsoft's service names: `HOST/server.example.com`, no realm.
    pub const AD_SERVICE_PRINCIPAL_NAME: &str = "servicePrincipalName";
    /// Microsoft's binary blob of every long-term key, a `USER_PROPERTIES`
    /// structure. Written here as a projection of `krb5Key`, never read: see
    /// [`crate::hdb::ad_blob`].
    pub const AD_SUPPLEMENTAL_CREDENTIALS: &str = "supplementalCredentials";
}

/// `userAccountControl` bits ([MS-ADTS] 2.2.9), the ones that describe a Kerberos
/// account rather than a Windows policy.
pub mod uac {
    /// `ACCOUNTDISABLE`.
    pub const ACCOUNTDISABLE: u32 = 0x0000_0002;
    /// `LOCKOUT`.
    pub const LOCKOUT: u32 = 0x0000_0010;
    /// `DONT_EXPIRE_PASSWORD`.
    pub const DONT_EXPIRE_PASSWORD: u32 = 0x0001_0000;
    /// `TRUSTED_FOR_DELEGATION`.
    pub const TRUSTED_FOR_DELEGATION: u32 = 0x0008_0000;
    /// `DONT_REQ_PREAUTH`.
    pub const DONT_REQ_PREAUTH: u32 = 0x0040_0000;
    /// `USE_DES_KEY_ONLY`.
    pub const USE_DES_KEY_ONLY: u32 = 0x0020_0000;
    /// `NOT_DELEGATED`.
    pub const NOT_DELEGATED: u32 = 0x0010_0000;
}

/// `msDS-SupportedEncryptionTypes` bits ([MS-KILE] 2.2.7).
pub mod etype_bits {
    /// DES-CBC-CRC.
    pub const DES_CBC_CRC: u32 = 0x0000_0001;
    /// DES-CBC-MD5.
    pub const DES_CBC_MD5: u32 = 0x0000_0002;
    /// RC4-HMAC.
    pub const RC4_HMAC: u32 = 0x0000_0004;
    /// AES128-CTS-HMAC-SHA1-96 (enctype 17).
    pub const AES128_SHA1: u32 = 0x0000_0008;
    /// AES256-CTS-HMAC-SHA1-96 (enctype 18).
    pub const AES256_SHA1: u32 = 0x0000_0010;
    /// FAST is supported by the account.
    pub const FAST: u32 = 0x0000_0020;
    /// Compound identity is supported.
    pub const COMPOUND_IDENTITY: u32 = 0x0000_0040;
    /// Claims are supported.
    pub const CLAIMS: u32 = 0x0000_0080;
    /// AES256-CTS-HMAC-SHA1-96-SK.
    pub const AES256_SHA1_SK: u32 = 0x0000_0200;
    /// AES128-CTS-HMAC-SHA256-128 (enctype 19).
    pub const AES128_SHA2: u32 = 0x0000_0400;
    /// AES256-CTS-HMAC-SHA384-192 (enctype 20).
    pub const AES256_SHA2: u32 = 0x0000_0800;
}

/// The object classes an entry carries.
///
/// `krb5Principal` is what makes it a principal; `krb5KDCEntry` adds the keys and
/// the flags. Both are `AUXILIARY`, so the entry keeps whatever structural class
/// the directory gave it — `inetOrgPerson` or `user`, not something invented here.
pub const OBJECT_CLASSES: [&str; 3] = ["top", "krb5Principal", "krb5KDCEntry"];

/// One entry's attributes, as a directory hands them over.
///
/// Names are case-insensitive, because LDAP says so and because
/// `msDS-KeyVersionNumber` is written `msds-keyversionnumber` by half the clients
/// in existence. Values stay as octets: `krb5Key` is binary and decoding it to a
/// `String` would corrupt it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Attributes {
    values: BTreeMap<String, Vec<Vec<u8>>>,
}

impl Attributes {
    /// No attributes.
    pub fn new() -> Self {
        Attributes::default()
    }

    /// Every value of `name`, in the order the directory gave them.
    pub fn get(&self, name: &str) -> &[Vec<u8>] {
        self.values
            .get(&name.to_ascii_lowercase())
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    /// The first value of `name`, if there is one.
    pub fn first(&self, name: &str) -> Option<&[u8]> {
        self.get(name).first().map(Vec::as_slice)
    }

    /// Whether `name` is present.
    pub fn has(&self, name: &str) -> bool {
        !self.get(name).is_empty()
    }

    /// Adds one value, replacing what was there.
    ///
    /// Replacing rather than appending because every caller here is writing a
    /// whole fact (`kvno`, `flags`, a validity time) and an entry with two values
    /// for one of those is an entry no reader can interpret.
    pub fn set(&mut self, name: &str, value: impl Into<Vec<u8>>) {
        self.values
            .insert(name.to_ascii_lowercase(), vec![value.into()]);
    }

    /// Adds one value, keeping the others. What `krb5Key` needs: one value per
    /// key.
    pub fn add(&mut self, name: &str, value: impl Into<Vec<u8>>) {
        self.values
            .entry(name.to_ascii_lowercase())
            .or_default()
            .push(value.into());
    }

    /// Removes `name` and everything under it; returns whether there was any.
    pub fn remove(&mut self, name: &str) -> bool {
        self.values.remove(&name.to_ascii_lowercase()).is_some()
    }

    /// The names present, sorted.
    pub fn names(&self) -> Vec<&str> {
        self.values.keys().map(String::as_str).collect()
    }

    /// One value as text, or an error naming the attribute.
    fn text(&self, name: &str, context: &str) -> Result<Option<String>> {
        match self.first(name) {
            None => Ok(None),
            Some(bytes) => std::str::from_utf8(bytes)
                .map(|s| Some(s.to_owned()))
                .map_err(|_| Error::Hdb(format!("{context}: {name} is not valid UTF-8"))),
        }
    }

    /// One value as an unsigned integer.
    fn number(&self, name: &str, context: &str) -> Result<Option<u32>> {
        let Some(text) = self.text(name, context)? else {
            return Ok(None);
        };
        text.trim().parse::<u32>().map(Some).map_err(|_| {
            Error::Hdb(format!(
                "{context}: {name} is {text:?}, which is not a number"
            ))
        })
    }

    /// One value as a `GeneralizedTime`.
    fn time(&self, name: &str, context: &str) -> Result<Option<i64>> {
        let Some(text) = self.text(name, context)? else {
            return Ok(None);
        };
        parse_generalized_time(&text).map(Some).ok_or_else(|| {
            Error::Hdb(format!(
                "{context}: {name} is {text:?}, which is not a GeneralizedTime"
            ))
        })
    }
}

/// An entry as the attributes a directory holds.
///
/// The write direction. Every attribute it produces is one Heimdal's schema
/// defines, plus the Microsoft ones when the entry has something to say in them.
pub fn to_attributes(entry: &HdbEntry) -> Attributes {
    let context = entry.principal.to_string();
    let mut out = Attributes::new();

    out.set(attrs::PRINCIPAL_NAME, context.as_bytes());
    out.add(attrs::PRINCIPAL_REALM, entry.principal.realm.as_bytes());
    out.set(
        attrs::KEY_VERSION_NUMBER,
        entry.kvno().to_string().into_bytes(),
    );
    out.set(attrs::KDC_FLAGS, entry.flags.to_string().into_bytes());

    for key in &entry.keys {
        out.add(attrs::KEY, encode_key(key));
    }

    if let Some(etypes) = &entry.etypes {
        for enctype in etypes {
            out.add(
                attrs::ENCRYPTION_TYPE,
                enctype.id().to_string().into_bytes(),
            );
        }
        // The same fact in Microsoft's spelling, so that an `sssd` client reads
        // the same restriction the KDC enforces.
        out.set(
            attrs::AD_SUPPORTED_ENCRYPTION_TYPES,
            enctypes_to_ad_bits(etypes).to_string().into_bytes(),
        );
    }

    for (name, value) in [
        (attrs::VALID_START, entry.valid_start),
        (attrs::VALID_END, entry.valid_end),
        (attrs::PASSWORD_END, entry.pw_end),
    ] {
        if let Some(instant) = value {
            out.set(name, format_generalized_time(instant).into_bytes());
        }
    }
    for (name, value) in [
        (attrs::MAX_LIFE, entry.max_life),
        (attrs::MAX_RENEW, entry.max_renew),
    ] {
        if let Some(seconds) = value {
            out.set(name, seconds.to_string().into_bytes());
        }
    }

    // Microsoft's copies of the facts a client asks about by those names.
    out.set(
        attrs::AD_KEY_VERSION_NUMBER,
        entry.kvno().to_string().into_bytes(),
    );
    out.set(
        attrs::AD_USER_ACCOUNT_CONTROL,
        ad_uac(entry).to_string().into_bytes(),
    );
    if let Some(spn) = service_principal_name(&entry.principal) {
        out.set(attrs::AD_SERVICE_PRINCIPAL_NAME, spn.into_bytes());
    }
    // The AD projection of the keys, so that an audit tool looking for it finds
    // something. Not written for an entry with no keys: an empty blob would say
    // "this account has no credentials", and absent says "nobody has filled this
    // in yet" — the second is true and the first is a claim about an account that
    // may not have been provisioned.
    if !entry.keys.is_empty() {
        out.set(
            attrs::AD_SUPPLEMENTAL_CREDENTIALS,
            crate::hdb::ad_blob::supplemental_credentials(entry),
        );
    }

    for class in OBJECT_CLASSES {
        out.add("objectClass", class.as_bytes());
    }
    out
}

/// An entry from the attributes a directory holds.
///
/// The read direction, and the one that has to be suspicious: a directory is
/// written by other programs, and an entry that says two contradictory things is
/// a fact an operator needs to hear about rather than a coin to flip.
pub fn from_attributes(attributes: &Attributes) -> Result<HdbEntry> {
    let context = "krb5Principal";
    let name = attributes
        .text(attrs::PRINCIPAL_NAME, context)?
        .ok_or_else(|| {
            Error::Hdb(format!(
                "{context}: no {} attribute, so this is not a principal",
                attrs::PRINCIPAL_NAME
            ))
        })?;
    let principal = Principal::parse(&name)?;

    let mut keys = Vec::new();
    for value in attributes.get(attrs::KEY) {
        keys.push(
            decode_key(value)
                .map_err(|e| Error::Hdb(format!("{principal}: {}: {e}", attrs::KEY)))?,
        );
    }

    let kvno_heimdal = attributes.number(attrs::KEY_VERSION_NUMBER, &name)?;
    let kvno_ad = attributes.number(attrs::AD_KEY_VERSION_NUMBER, &name)?;
    // Agreed first, so a contradiction is reported even when the keys would
    // otherwise pass the check below.
    let declared_kvno = agree(
        &name,
        attrs::KEY_VERSION_NUMBER,
        kvno_heimdal,
        attrs::AD_KEY_VERSION_NUMBER,
        kvno_ad,
    )?;
    // An entry with keys but no kvno is an entry whose keys nothing can match.
    // Reading the highest one is what Heimdal's LDAP backend does when the
    // attribute is absent, and it is the only value that cannot be wrong.
    if let Some(declared) = declared_kvno {
        let highest = keys.iter().map(|k: &HdbKey| k.kvno).max();
        match highest {
            Some(highest) if highest > declared => {
                return Err(Error::Hdb(format!(
                    "{name}: a key is at kvno {highest} but the entry says {declared}; the \
                     directory and the keys disagree about which is current"
                )));
            }
            None if declared > 0 => {
                // A principal created before its keys are known: the directory
                // has a version and no keys, which is a state this record keeps
                // rather than repairs.
            }
            _ => {}
        }
    }

    let flags_heimdal = attributes.number(attrs::KDC_FLAGS, &name)?;
    let uac = attributes.number(attrs::AD_USER_ACCOUNT_CONTROL, &name)?;
    let flags = reconcile_flags(&name, flags_heimdal, uac)?;

    let etypes = enctypes(attributes, &name)?;

    // Declared version, or the highest key when the directory does not say: an
    // entry whose keys are newer than its attribute is caught above rather than
    // silently preferred.
    let kvno = declared_kvno.unwrap_or_else(|| keys.iter().map(|k| k.kvno).max().unwrap_or(0));
    Ok(HdbEntry {
        principal,
        keys,
        kvno,
        flags,
        valid_start: attributes.time(attrs::VALID_START, &name)?,
        valid_end: attributes.time(attrs::VALID_END, &name)?,
        pw_end: attributes.time(attrs::PASSWORD_END, &name)?,
        max_life: attributes.number(attrs::MAX_LIFE, &name)?.map(|v| v as i64),
        max_renew: attributes
            .number(attrs::MAX_RENEW, &name)?
            .map(|v| v as i64),
        etypes,
        // The directory keeps its own timestamps (`modifyTimestamp`); this one is
        // this crate's, and a value read from a file that has none is zero rather
        // than "now", which would be a lie about when it changed.
        modified: 0,
    })
}

/// Two attributes describing the same fact: either they agree or the entry is
/// refused.
fn agree<T: PartialEq + std::fmt::Display>(
    principal: &str,
    a_name: &str,
    a: Option<T>,
    b_name: &str,
    b: Option<T>,
) -> Result<Option<T>> {
    match (a, b) {
        (Some(a), Some(b)) if a != b => Err(Error::Hdb(format!(
            "{principal}: {a_name} says {a} and {b_name} says {b}; the directory contradicts \
             itself and guessing would put the KDC and the directory out of step"
        ))),
        (Some(a), _) => Ok(Some(a)),
        (None, b) => Ok(b),
    }
}

/// `krb5KDCFlags` and `userAccountControl` describe one account twice.
///
/// Heimdal's flags are the ones this crate acts on, so `krb5KDCFlags` wins where
/// it speaks; but where `userAccountControl` says something `krb5KDCFlags` does
/// not, the answer is the bits both agree on and an error for the rest. An
/// account disabled in the directory and enabled in the realm is a user who
/// cannot log in and an administrator who cannot see why.
fn reconcile_flags(principal: &str, heimdal: Option<u32>, uac: Option<u32>) -> Result<u32> {
    let Some(uac) = uac else {
        return Ok(heimdal.unwrap_or(0));
    };
    let ad_disabled = uac & uac::ACCOUNTDISABLE != 0;
    let ad_locked = uac & uac::LOCKOUT != 0;

    let Some(flags) = heimdal else {
        // Only Microsoft's vocabulary: translate it.
        let mut flags = 0;
        if ad_disabled {
            flags |= flags::INVALID;
        }
        if ad_locked {
            flags |= flags::LOCKED_OUT;
        }
        if uac & uac::TRUSTED_FOR_DELEGATION != 0 {
            flags |= flags::TRUSTED_FOR_DELEGATION;
        }
        if uac & uac::DONT_REQ_PREAUTH != 0 {
            // Heimdal spells "no pre-authentication" as the absence of
            // `require-preauth`; nothing to set.
        } else {
            flags |= flags::REQUIRE_PREAUTH;
        }
        if uac & uac::DONT_EXPIRE_PASSWORD == 0 {
            // A password that expires is the norm; `pw_end` carries the instant.
        }
        return Ok(flags);
    };

    // Both present: every fact they share has to agree.
    let h_disabled = flags & flags::INVALID != 0;
    if ad_disabled != h_disabled {
        return Err(Error::Hdb(format!(
            "{principal}: userAccountControl says {}, krb5KDCFlags says {}; the directory and the \
             realm disagree about whether this account is enabled",
            if ad_disabled { "disabled" } else { "enabled" },
            if h_disabled { "disabled" } else { "enabled" }
        )));
    }
    let h_locked = flags & flags::LOCKED_OUT != 0;
    if ad_locked != h_locked {
        return Err(Error::Hdb(format!(
            "{principal}: userAccountControl and krb5KDCFlags disagree about whether this account \
             is locked out"
        )));
    }
    Ok(flags)
}

/// The two spellings of the enctype restriction, reconciled.
fn enctypes(attributes: &Attributes, principal: &str) -> Result<Option<Vec<Enctype>>> {
    let heimdal = attributes
        .get(attrs::ENCRYPTION_TYPE)
        .iter()
        .map(|value| {
            let text = std::str::from_utf8(value).map_err(|_| {
                Error::Hdb(format!(
                    "{principal}: {} is not valid UTF-8",
                    attrs::ENCRYPTION_TYPE
                ))
            })?;
            let id = text.trim().parse::<i32>().map_err(|_| {
                Error::Hdb(format!(
                    "{principal}: {} is {text:?}, which is not an enctype number",
                    attrs::ENCRYPTION_TYPE
                ))
            })?;
            Enctype::from_id(id).ok_or_else(|| {
                Error::Hdb(format!(
                    "{principal}: {} names enctype {id}, which this KDC does not implement",
                    attrs::ENCRYPTION_TYPE
                ))
            })
        })
        .collect::<Result<Vec<Enctype>>>()?;

    let ad = attributes
        .number(attrs::AD_SUPPORTED_ENCRYPTION_TYPES, principal)?
        .map(ad_bits_to_enctypes);

    match (heimdal.is_empty(), ad) {
        // Neither attribute: no restriction at all, which is not the same as an
        // empty list.
        (true, None) => Ok(None),
        (false, None) => Ok(Some(heimdal)),
        (true, Some(from_bits)) => Ok(Some(from_bits)),
        (false, Some(from_bits)) => {
            let mut sorted_heimdal = heimdal.clone();
            sorted_heimdal.sort_by_key(|e| e.id());
            let mut sorted_ad = from_bits.clone();
            sorted_ad.sort_by_key(|e| e.id());
            if sorted_heimdal != sorted_ad {
                return Err(Error::Hdb(format!(
                    "{principal}: {} lists {:?} and {} lists {:?}; two spellings of one fact that \
                     do not agree",
                    attrs::ENCRYPTION_TYPE,
                    heimdal.iter().map(|e| e.id()).collect::<Vec<_>>(),
                    attrs::AD_SUPPORTED_ENCRYPTION_TYPES,
                    from_bits.iter().map(|e| e.id()).collect::<Vec<_>>()
                )));
            }
            Ok(Some(heimdal))
        }
    }
}

/// The Microsoft bitmask for a set of enctypes.
///
/// Only the bits that name an enctype this crate implements, plus the two "can do
/// this" bits an AES-only KDC truthfully sets. A bit for RC4 or DES is never set:
/// claiming support that does not exist is how a client negotiates an enctype the
/// KDC then refuses.
pub fn enctypes_to_ad_bits(etypes: &[Enctype]) -> u32 {
    let mut bits = 0;
    for enctype in etypes {
        bits |= match enctype {
            Enctype::Aes128Sha1 => etype_bits::AES128_SHA1,
            Enctype::Aes256Sha1 => etype_bits::AES256_SHA1,
            Enctype::Aes128Sha256 => etype_bits::AES128_SHA2,
            Enctype::Aes256Sha384 => etype_bits::AES256_SHA2,
        };
    }
    bits
}

/// The enctypes a Microsoft bitmask names, ignoring bits this KDC cannot honour.
///
/// Ignoring rather than refusing: an AD entry routinely declares RC4 and DES, and
/// a KDC that refused to read such an entry would refuse most of a real
/// directory. What it must not do is *claim* them.
pub fn ad_bits_to_enctypes(bits: u32) -> Vec<Enctype> {
    let mut out = Vec::new();
    for (bit, enctype) in [
        (etype_bits::AES256_SHA2, Enctype::Aes256Sha384),
        (etype_bits::AES256_SHA1, Enctype::Aes256Sha1),
        (etype_bits::AES128_SHA2, Enctype::Aes128Sha256),
        (etype_bits::AES128_SHA1, Enctype::Aes128Sha1),
    ] {
        if bits & bit != 0 {
            out.push(enctype);
        }
    }
    out
}

/// `userAccountControl` for an entry.
fn ad_uac(entry: &HdbEntry) -> u32 {
    let mut uac = 0;
    if entry.has(flags::INVALID) {
        uac |= uac::ACCOUNTDISABLE;
    }
    if entry.has(flags::LOCKED_OUT) {
        uac |= uac::LOCKOUT;
    }
    if entry.has(flags::TRUSTED_FOR_DELEGATION) {
        uac |= uac::TRUSTED_FOR_DELEGATION;
    }
    if !entry.has(flags::REQUIRE_PREAUTH) {
        uac |= uac::DONT_REQ_PREAUTH;
    }
    // A normal account, which is what an account with no switches set is. The
    // bit has to be there or a client reads the account as a workstation trust.
    uac | NORMAL_ACCOUNT
}

/// `NORMAL_ACCOUNT`, the `userAccountControl` bit every user account carries.
pub const NORMAL_ACCOUNT: u32 = 0x0000_0200;

/// The `servicePrincipalName` for a principal, or `None` when it has one
/// component.
///
/// `HOST/server.example.com`: no realm, because in AD the realm *is* the domain.
/// A client asks for a ticket by SPN and the KDC has to find the principal, so
/// the two spellings have to convert both ways without losing anything — and a
/// single-component name is a user, not a service, which has no SPN.
pub fn service_principal_name(principal: &Principal) -> Option<String> {
    if principal.components.len() < 2 {
        return None;
    }
    Some(principal.components.join("/"))
}

/// The principal an SPN names, in `realm`.
pub fn principal_from_spn(spn: &str, realm: &str) -> Result<Principal> {
    let mut parts = spn.split('/');
    let first = parts.next().unwrap_or_default();
    if first.is_empty() || parts.clone().count() == 0 {
        return Err(Error::Protocol(format!(
            "{spn:?} is not a service principal name: expected `service/host`"
        )));
    }
    if spn.contains('@') {
        return Err(Error::Protocol(format!(
            "{spn:?} carries a realm, which a servicePrincipalName must not"
        )));
    }
    Principal::parse_in_realm(spn, realm)
}

/// One `krb5Key` value: the ASN.1 `Key`, DER.
fn encode_key(key: &HdbKey) -> Vec<u8> {
    let mut parts = vec![
        crate::der::field(0, crate::der::int(key.kvno as i64)),
        crate::der::field(
            1,
            crate::der::seq(&[
                crate::der::field(0, crate::der::int(key.key.enctype().id() as i64)),
                crate::der::field(1, crate::der::octets(key.key.bytes())),
            ]),
        ),
    ];
    if let Some(salt) = &key.salt {
        parts.push(crate::der::field(2, crate::der::octets(salt)));
    }
    crate::der::seq(&parts)
}

/// The key a `krb5Key` value holds.
fn decode_key(value: &[u8]) -> Result<HdbKey> {
    use crate::der::{Fields, Reader};
    let context = "krb5Key";
    let mut r = Reader::new(value);
    let f = Fields::parse(context, r.expect(context, crate::der::SEQUENCE)?)?;
    let kvno = f.u32(0, context)?;
    let mut er = Reader::new(f.get(1, context)?);
    let ef = Fields::parse(context, er.expect(context, crate::der::SEQUENCE)?)?;
    let id = ef.int(0, context)? as i32;
    let enctype = Enctype::from_id(id)
        .ok_or_else(|| Error::Hdb(format!("enctype {id} is not one this KDC implements")))?;
    let key = Key::new(enctype, ef.octets(1, context)?)?;
    Ok(HdbKey {
        kvno,
        key,
        salt: f.opt_octets(2, context)?.map(<[u8]>::to_vec),
    })
}

/// What a KDC needs from whatever holds the entries.
///
/// Four operations, by principal rather than by DN: a directory that wants to
/// place an entry somewhere of its own choosing can, and the KDC does not have to
/// know its naming. [`dn_for`] is offered for the common layout.
///
/// Every method is `&self` because a KDC answers requests concurrently.
pub trait Directory: std::fmt::Debug + Send + Sync {
    /// The attributes of `principal`'s entry, or `None` if there is no such entry.
    fn get(&self, principal: &Principal) -> Result<Option<Attributes>>;

    /// Writes `principal`'s entry, creating it if it is not there.
    fn put(&self, principal: &Principal, attributes: &Attributes) -> Result<()>;

    /// Removes `principal`'s entry; returns whether there was one.
    fn delete(&self, principal: &Principal) -> Result<bool>;

    /// Every principal in the realm, in the directory's own order.
    fn list(&self) -> Result<Vec<Principal>>;
}

/// The `HDB` interface over a [`Directory`].
#[derive(Debug, Clone)]
pub struct LdapHdb {
    directory: Arc<dyn Directory>,
}

impl LdapHdb {
    /// An `HDB` over `directory`.
    pub fn new(directory: Arc<dyn Directory>) -> Self {
        LdapHdb { directory }
    }

    /// The directory, for an embedder that needs to reach past the mapping.
    pub fn directory(&self) -> &Arc<dyn Directory> {
        &self.directory
    }
}

impl Hdb for LdapHdb {
    fn fetch(&self, principal: &Principal) -> Result<Option<HdbEntry>> {
        match self.directory.get(principal)? {
            None => Ok(None),
            Some(attributes) => {
                let entry = from_attributes(&attributes)?;
                // A directory that returned somebody else's entry is a directory
                // with a naming bug, and silently answering for the wrong
                // principal would issue tickets for an account nobody asked for.
                if entry.principal != *principal {
                    return Err(Error::Hdb(format!(
                        "{principal}: the directory returned the entry for {}",
                        entry.principal
                    )));
                }
                Ok(Some(entry))
            }
        }
    }

    fn store(&self, entry: HdbEntry) -> Result<()> {
        let attributes = to_attributes(&entry);
        self.directory.put(&entry.principal, &attributes)
    }

    fn remove(&self, principal: &Principal) -> Result<bool> {
        self.directory.delete(principal)
    }

    fn first(&self) -> Result<Option<Principal>> {
        Ok(self.directory.list()?.into_iter().next())
    }

    /// Moves an entry: the new name is written first, then the old one removed.
    ///
    /// That order on purpose. A failed write leaves the entry where it was; a
    /// failed delete leaves two copies, which an operator can see and settle. The
    /// other order can leave neither.
    ///
    /// The salts travel with the keys, because they belong to the principal's
    /// history: a client that derived its key with the old salt must keep being
    /// able to, and RFC 4120's default salt would silently stop matching.
    fn rename(&self, from: &Principal, to: &Principal) -> Result<()> {
        if from == to {
            return Ok(());
        }
        if self.directory.get(to)?.is_some() {
            return Err(Error::Exists(format!(
                "{to}: renaming {from} here would overwrite it"
            )));
        }
        let mut entry = match self.directory.get(from)? {
            None => {
                return Err(Error::NotFound(from.to_string()));
            }
            Some(attributes) => from_attributes(&attributes)?,
        };
        entry.principal = to.clone();
        self.store(entry)?;
        self.directory.delete(from)?;
        Ok(())
    }

    fn next(&self, after: &Principal) -> Result<Option<Principal>> {
        // By name, not by the directory's order: `next` must be a function of the
        // principal it is given, or two walks over one realm visit different
        // principals. The list is sorted here for that reason.
        let mut all = self.directory.list()?;
        all.sort();
        Ok(all.into_iter().find(|p| p > after))
    }
}

/// `krb5PrincipalName=<principal>,krb5RealmName=<realm>,<base>` — where Heimdal
/// puts an entry when the directory does not say.
///
/// The values are escaped per RFC 4514. A principal component may contain `,`,
/// `+`, `"`, `\`, `<`, `>` or a leading `#`, and an unescaped one turns one RDN
/// into two.
pub fn dn_for(principal: &Principal, base: &str) -> String {
    let name = escape_dn_value(&principal.to_string());
    let realm = escape_dn_value(&principal.realm);
    let realm_rdn = format!("{}={realm}", REALM_ATTRIBUTE);

    if base.is_empty() {
        format!("{}={name},{realm_rdn}", attrs::PRINCIPAL_NAME)
    } else {
        format!("{}={name},{realm_rdn},{base}", attrs::PRINCIPAL_NAME)
    }
}

/// RFC 4514 §2.4 escaping for an attribute value in a DN.
pub fn escape_dn_value(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for (i, ch) in value.chars().enumerate() {
        match ch {
            ',' | '+' | '"' | '\\' | '<' | '>' | ';' | '=' => {
                out.push('\\');
                out.push(ch);
            }
            ' ' | '#' if i == 0 => {
                // A leading space or `#` would be read as syntax.
                out.push('\\');
                out.push(ch);
            }
            ' ' if i + 1 == value.len() => {
                out.push('\\');
                out.push(ch);
            }
            '\0' => out.push_str("\\00"),
            c => out.push(c),
        }
    }
    out
}

/// `krb5RealmName`, the attribute of a realm entry (`hdb.schema`).
pub const REALM_ATTRIBUTE: &str = "krb5RealmName";

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Cipher;
    use crate::crypto::OwnCipher;

    fn principal(name: &str) -> Principal {
        Principal::parse(name).unwrap()
    }

    fn entry() -> HdbEntry {
        let mut entry = HdbEntry::user(principal("alice@EXAMPLE.COM"));
        entry
            .add_password_key(&OwnCipher, Enctype::Aes256Sha1, b"pw", 1)
            .unwrap();
        entry
    }

    #[test]
    fn attribute_names_are_case_insensitive() {
        let mut attributes = Attributes::new();
        attributes.set("krb5KeyVersionNumber", "3");
        assert_eq!(attributes.first("KRB5KEYVERSIONNUMBER"), Some(&b"3"[..]));
        assert_eq!(attributes.first("krb5keyversionnumber"), Some(&b"3"[..]));
    }

    #[test]
    fn a_key_is_binary_and_survives_a_round_trip() {
        // The value that must never be decoded as text on its way through.
        let entry = entry();
        let attributes = to_attributes(&entry);
        let keys = attributes.get(attrs::KEY);
        assert_eq!(keys.len(), 1);
        assert!(
            keys[0].iter().any(|b| !b.is_ascii_graphic()),
            "a DER key contains octets that are not printable, and a client that \
             treated it as text would corrupt it"
        );
        let back = from_attributes(&attributes).unwrap();
        assert_eq!(back.keys.len(), 1);
        assert_eq!(back.keys[0].key.bytes(), entry.keys[0].key.bytes());
        assert_eq!(back.keys[0].kvno, 1);
    }

    #[test]
    fn an_entry_round_trips_through_attributes() {
        let mut entry = entry();
        entry.flags |= flags::SERVER | flags::OK_AS_DELEGATE;
        entry.valid_end = Some(1_767_225_600);
        entry.pw_end = Some(1_767_000_000);
        entry.max_life = Some(36_000);
        entry.max_renew = Some(604_800);
        entry.etypes = Some(vec![Enctype::Aes256Sha1, Enctype::Aes128Sha256]);

        let back = from_attributes(&to_attributes(&entry)).unwrap();
        assert_eq!(back.principal, entry.principal);
        assert_eq!(back.flags, entry.flags);
        assert_eq!(back.valid_end, entry.valid_end);
        assert_eq!(back.pw_end, entry.pw_end);
        assert_eq!(back.max_life, entry.max_life);
        assert_eq!(back.max_renew, entry.max_renew);
        assert_eq!(back.etypes, entry.etypes);
        assert_eq!(back.kvno(), entry.kvno());
    }

    #[test]
    fn no_enctype_declaration_and_an_empty_one_are_different() {
        let mut entry = entry();
        entry.etypes = None;
        assert_eq!(
            from_attributes(&to_attributes(&entry)).unwrap().etypes,
            None
        );

        entry.etypes = Some(Vec::new());
        assert_eq!(
            from_attributes(&to_attributes(&entry)).unwrap().etypes,
            Some(Vec::new()),
            "a principal that may be issued nothing is a decision, not an absence"
        );
    }

    #[test]
    fn the_ad_enctype_bits_match_ms_kile() {
        // Checked against [MS-KILE] 2.2.7: 0x8 AES128-SHA1, 0x10 AES256-SHA1,
        // 0x400 AES128-SHA2, 0x800 AES256-SHA2.
        let all = [
            Enctype::Aes256Sha384,
            Enctype::Aes256Sha1,
            Enctype::Aes128Sha256,
            Enctype::Aes128Sha1,
        ];
        assert_eq!(enctypes_to_ad_bits(&all), 0x0c18);
        assert_eq!(ad_bits_to_enctypes(0x0c18).len(), 4);
        assert_eq!(ad_bits_to_enctypes(0x10), vec![Enctype::Aes256Sha1]);
    }

    #[test]
    fn a_bit_for_an_enctype_this_kdc_does_not_implement_is_ignored_not_claimed() {
        // A real AD entry declares RC4 and DES. Reading it must work; writing it
        // back must not claim what this KDC cannot do.
        assert!(ad_bits_to_enctypes(etype_bits::RC4_HMAC).is_empty());
        assert_eq!(
            enctypes_to_ad_bits(&[Enctype::Aes256Sha1]) & etype_bits::RC4_HMAC,
            0,
            "claiming RC4 support is how a client negotiates an enctype the KDC refuses"
        );
    }

    #[test]
    fn a_contradiction_between_the_two_kvnos_is_refused() {
        let mut attributes = to_attributes(&entry());
        attributes.set(attrs::AD_KEY_VERSION_NUMBER, "7");
        let err = from_attributes(&attributes).unwrap_err().to_string();
        assert!(
            err.contains("contradicts") || err.contains("disagree"),
            "the message must say the two attributes contradict: {err}"
        );
    }

    #[test]
    fn an_account_disabled_in_one_vocabulary_and_enabled_in_the_other_is_refused() {
        let mut entry = entry();
        entry.flags &= !flags::INVALID;
        let mut attributes = to_attributes(&entry);
        attributes.set(
            attrs::AD_USER_ACCOUNT_CONTROL,
            (NORMAL_ACCOUNT | uac::ACCOUNTDISABLE).to_string(),
        );
        let err = from_attributes(&attributes).unwrap_err().to_string();
        assert!(
            err.contains("enabled") && err.contains("disabled"),
            "the message must describe both sides: {err}"
        );
    }

    #[test]
    fn an_entry_with_only_microsoft_attributes_reads() {
        // What a directory that was an AD, then stopped being one, looks like.
        let mut attributes = Attributes::new();
        attributes.set(attrs::PRINCIPAL_NAME, "host/web.example.com@EXAMPLE.COM");
        attributes.set(attrs::AD_KEY_VERSION_NUMBER, "4");
        attributes.set(
            attrs::AD_USER_ACCOUNT_CONTROL,
            (NORMAL_ACCOUNT | uac::ACCOUNTDISABLE | uac::DONT_REQ_PREAUTH).to_string(),
        );
        attributes.set(attrs::AD_SUPPORTED_ENCRYPTION_TYPES, "24");
        let entry = from_attributes(&attributes).unwrap();
        assert_eq!(entry.kvno(), 4);
        assert!(
            entry.has(flags::INVALID),
            "ACCOUNTDISABLE is an invalid entry here"
        );
        assert!(
            !entry.has(flags::REQUIRE_PREAUTH),
            "DONT_REQ_PREAUTH must clear require-preauth, or the account cannot log in the way \
             the directory says it should"
        );
        assert_eq!(
            entry.etypes,
            Some(vec![Enctype::Aes256Sha1, Enctype::Aes128Sha1]),
            "0x18 is AES128 and AES256 with SHA1"
        );
    }

    #[test]
    fn a_principal_without_a_name_attribute_is_not_a_principal() {
        let mut attributes = Attributes::new();
        attributes.set(attrs::KEY_VERSION_NUMBER, "1");
        let err = from_attributes(&attributes).unwrap_err().to_string();
        assert!(err.contains("not a principal"), "{err}");
    }

    #[test]
    fn a_key_newer_than_the_declared_kvno_is_refused() {
        let mut entry = entry();
        // A key at kvno 2 while the attribute still says 1.
        let key = OwnCipher
            .s2k(Enctype::Aes128Sha1, b"pw", b"EXAMPLE.COMalice", None)
            .unwrap();
        entry.add_key(key, 2, None);
        let mut attributes = to_attributes(&entry);
        // Both spellings say 1 while a key is at 2: one fact, no contradiction,
        // and the keys still newer than the entry claims.
        attributes.set(attrs::KEY_VERSION_NUMBER, "1");
        attributes.set(attrs::AD_KEY_VERSION_NUMBER, "1");
        let err = from_attributes(&attributes).unwrap_err().to_string();
        assert!(
            err.contains("kvno") && err.contains('2'),
            "the message must name both versions: {err}"
        );
    }

    #[test]
    fn a_dn_escapes_what_rfc_4514_requires() {
        let principal = principal(r"ali,ce+x@EXAMPLE.COM");
        let dn = dn_for(&principal, "cn=Kerberos,dc=example,dc=com");
        assert!(
            dn.starts_with(r"krb5PrincipalName=ali\,ce\+x@EXAMPLE.COM,krb5RealmName=EXAMPLE.COM,"),
            "{dn}"
        );
        assert_eq!(escape_dn_value("#lead"), r"\#lead");
        assert_eq!(escape_dn_value("trail "), r"trail\ ");
        assert_eq!(escape_dn_value("plain"), "plain");
    }

    #[test]
    fn an_spn_has_no_realm_and_converts_both_ways() {
        let service = principal("host/web.example.com@EXAMPLE.COM");
        let spn = service_principal_name(&service).unwrap();
        assert_eq!(spn, "host/web.example.com");
        assert_eq!(
            principal_from_spn(&spn, "EXAMPLE.COM").unwrap(),
            service,
            "a client asks for a ticket by SPN, and the KDC must find the same principal"
        );
        assert!(
            service_principal_name(&principal("alice@EXAMPLE.COM")).is_none(),
            "a user is not a service and has no SPN"
        );
        assert!(principal_from_spn("host/web@EXAMPLE.COM", "EXAMPLE.COM").is_err());
    }
}
