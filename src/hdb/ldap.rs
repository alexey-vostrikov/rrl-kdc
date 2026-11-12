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
    /// Microsoft's constrained-delegation list: the SPNs this account may delegate to.
    ///
    /// One value per target, each an SPN without a realm (`cifs/files.example.com`). AD's own
    /// attribute, rather than a private one, so that a directory populated by AD tools and a
    /// directory populated by this crate mean the same thing.
    pub const AD_ALLOWED_TO_DELEGATE_TO: &str = "msDS-AllowedToDelegateTo";
    /// Microsoft's binary blob of every long-term key, a `USER_PROPERTIES`
    /// structure. Written here as a projection of `krb5Key`, never read: see
    /// [`crate::hdb::ad_blob`].
    pub const AD_SUPPLEMENTAL_CREDENTIALS: &str = "supplementalCredentials";

    /// The account's NT hash, in the attribute Samba writes it to.
    ///
    /// `sambaNTPassword` and not `unicodePwd`: `unicodePwd` holds the same secret but only ever
    /// accepts a cleartext password over an encrypted channel, so a directory cannot be given a
    /// hash through it. Samba's attribute is the one an estate actually keeps, thirty-two
    /// hexadecimal digits in **upper** case, and it is what a domain migration or an NTLM logon
    /// reads.
    pub const SAMBA_NT_PASSWORD: &str = "sambaNTPassword";
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
    // The plaintext path cannot fail: it seals nothing. `expect` states that rather than hiding an
    // error — `to_attributes_with`'s only failure is a master key that cannot seal.
    to_attributes_with(entry, None).expect("mapping an entry without a master key seals nothing")
}

/// The attributes of `entry`, sealing its keys under `master` when one is given.
///
/// A directory is a store like any other, and sealing here is what stops a read-only account that can
/// see `krb5Key` from holding every key it can see. Heimdal does the same: `hdb-ldap.c` unseals each
/// key it reads when the backend has a master key, and seals them when it writes.
pub fn to_attributes_with(
    entry: &HdbEntry,
    master: Option<(&dyn crate::crypto::Cipher, &crate::hdb::mkey::MasterKeys)>,
) -> Result<Attributes> {
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
        out.add(attrs::KEY, encode_key(key, master)?);
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
    // The constrained-delegation list, one SPN per value and no realm: that is how AD stores
    // it, and a realm here would make the same entry mean different things in two realms.
    if let Some(acl) = &entry.constrained_delegation {
        for target in acl {
            if let Some(spn) = service_principal_name(target) {
                out.add(attrs::AD_ALLOWED_TO_DELEGATE_TO, spn.into_bytes());
            }
        }
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
    // The NT hash, in the spelling Samba writes and reads: thirty-two hexadecimal digits, upper
    // case. Absent when the entry has none — a hash invented to fill the attribute would be a hash
    // no logon ever matches, which is worse than an attribute a reader finds missing.
    if let Some(nt_hash) = &entry.nt_hash {
        out.set(attrs::SAMBA_NT_PASSWORD, nt_hash_hex(nt_hash).into_bytes());
    }

    for class in OBJECT_CLASSES {
        out.add("objectClass", class.as_bytes());
    }
    Ok(out)
}

/// An entry from the attributes a directory holds.
///
/// The read direction, and the one that has to be suspicious: a directory is
/// written by other programs, and an entry that says two contradictory things is
/// a fact an operator needs to hear about rather than a coin to flip.
pub fn from_attributes(attributes: &Attributes) -> Result<HdbEntry> {
    from_attributes_with(attributes, None)
}

/// [`from_attributes`], opening sealed keys with `master`.
pub fn from_attributes_with(
    attributes: &Attributes,
    master: Option<(&dyn crate::crypto::Cipher, &crate::hdb::mkey::MasterKeys)>,
) -> Result<HdbEntry> {
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

    // The version is read **before** the keys: it is where Heimdal keeps a key's version, and a value
    // in Heimdal's layout does not carry one at all. Reading the keys first would mean guessing a
    // version and then re-checking it.
    let kvno_krb5 = attributes.number(attrs::KEY_VERSION_NUMBER, &name)?;
    let kvno_ad = attributes.number(attrs::AD_KEY_VERSION_NUMBER, &name)?;
    // Agreed first, so a contradiction is reported even when the keys would
    // otherwise pass the check below.
    let declared_kvno = agree(
        &name,
        attrs::KEY_VERSION_NUMBER,
        kvno_krb5,
        attrs::AD_KEY_VERSION_NUMBER,
        kvno_ad,
    )?;

    let mut keys = Vec::new();
    for value in attributes.get(attrs::KEY) {
        keys.push(
            decode_key(value, declared_kvno, master)
                .map_err(|e| Error::Hdb(format!("{principal}: {}: {e}", attrs::KEY)))?,
        );
    }
    // An entry with keys but no kvno is an entry whose keys nothing can match.
    // Reading the highest one is what Heimdal's LDAP backend does when the
    // attribute is absent, and it is the only value that cannot be wrong.
    //
    // `krb5Key` is the canonical attribute. The AD projection is read only when
    // the canonical attribute is absent — an account that was written by an
    // AD-shaped tool has its keys in `supplementalCredentials` and nowhere else —
    // because reading it back loses what the projection cannot carry: the blob has
    // no key version, and it has one salt for all keys. An entry that has both is
    // an entry whose `krb5Key` wins, and that is the direction the plan fixed:
    // written by us, read only as a fallback.
    if keys.is_empty()
        && let Some(blob) = attributes.get(attrs::AD_SUPPLEMENTAL_CREDENTIALS).first()
    {
        // The blob carries no version of its own — `KERB_STORED_CREDENTIAL_NEW` has no field for
        // one — so the version has to come from the directory, which is where AD keeps it. Without
        // it the keys would be read at version 0, and a key at version 0 matches no ticket: the
        // KDC would serve the account's tickets sealed under a key its clients never held, and the
        // failure would surface as a decryption error at the client, long after the directory that
        // caused it. Refusing here names the missing attribute instead.
        let Some(kvno) = declared_kvno else {
            return Err(Error::Hdb(format!(
                "{name}: {} holds keys but the directory declares no version — a key needs one, \
                 and the projection does not carry it: set {} (AD) or {} (Heimdal)",
                attrs::AD_SUPPLEMENTAL_CREDENTIALS,
                attrs::AD_KEY_VERSION_NUMBER,
                attrs::KEY_VERSION_NUMBER
            )));
        };
        keys = crate::hdb::ad_blob::keys(blob, kvno).map_err(|e| {
            Error::Hdb(format!(
                "{name}: {}: {e}",
                attrs::AD_SUPPLEMENTAL_CREDENTIALS
            ))
        })?;
    }
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

    let flags_krb5 = attributes.number(attrs::KDC_FLAGS, &name)?;
    let uac = attributes.number(attrs::AD_USER_ACCOUNT_CONTROL, &name)?;
    let flags = reconcile_flags(
        &name,
        flags_krb5,
        uac,
        attributes.has(attrs::AD_SERVICE_PRINCIPAL_NAME),
    )?;

    let etypes = enctypes(attributes, &name)?;
    let constrained_delegation = delegation_acl(attributes, &principal)?;

    // Declared version, or the highest key when the directory does not say: an
    // entry whose keys are newer than its attribute is caught above rather than
    // silently preferred.
    let kvno = declared_kvno.unwrap_or_else(|| keys.iter().map(|k| k.kvno).max().unwrap_or(0));
    // The NT hash is read as Samba wrote it. It is **not** a Kerberos key and it is not sealed by
    // this backend: the attribute exists for tools that expect to find a plaintext hash there, and
    // sealing it would make it unreadable to exactly those tools. A deployment that cannot keep a
    // password-equivalent secret in its directory must not write the attribute at all — which is a
    // policy, so it is stated here rather than decided silently.
    let nt_hash = match attributes.text(attrs::SAMBA_NT_PASSWORD, &name)? {
        Some(text) => Some(nt_hash_from_hex(&name, text.trim())?),
        None => None,
    };
    Ok(HdbEntry {
        principal,
        keys,
        nt_hash,
        kvno,
        flags,
        // A directory has no column for Heimdal's HDB extensions, and inventing one would put
        // this crate's private format into somebody's schema. Delegation limits therefore come
        // from the record backend; an LDAP-backed realm delegates only to itself, which is the
        // conservative reading of "no list".
        constrained_delegation,
        // Aliases live in an HDB extension, and a directory keeps its own (`spn`, `aliases` in
        // AD are attributes this backend reads as service names, not as Heimdal's extension).
        aliases: None,
        // A policy is a name in an HDB extension; a directory keeps its own idea of account
        // rules, and reading nothing here is honest about which one governs the entry.
        policy: None,
        strings: Vec::new(),
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
fn reconcile_flags(
    principal: &str,
    krb5: Option<u32>,
    uac: Option<u32>,
    publishes_spn: bool,
) -> Result<u32> {
    let Some(uac) = uac else {
        return Ok(krb5.unwrap_or(0));
    };
    let ad_disabled = uac & uac::ACCOUNTDISABLE != 0;
    let ad_locked = uac & uac::LOCKOUT != 0;

    let Some(flags) = krb5 else {
        // Only Microsoft's vocabulary: translate it.
        //
        // An account is a client, and a machine account is also a server. Neither fact has a bit
        // in `userAccountControl`, so a translation that set only the negative bits produced an
        // entry the KDC refused to issue anything for: measured, `kinit` against an account
        // written in AD's vocabulary answered KDC_ERR_POLICY, because the entry was "not a client
        // principal". `servicePrincipalName` is what makes an account a server here, the same
        // attribute a ticket request names.
        let mut flags = flags::CLIENT;
        if publishes_spn {
            flags |= flags::SERVER;
        }
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
    let krb5 = attributes
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

    // A zero is "declared nothing", not "nothing allowed": [MS-KILE] 2.2.7 gives the attribute
    // no bit for a prohibition, and an account that declares nothing is one the KDC applies its
    // defaults to. Read literally, zero becomes an empty set, and every such account can be
    // issued nothing at all — a login that fails with `KDC_ERR_ETYPE_NOSUPP` while the
    // directory looks perfectly ordinary.
    let ad = attributes
        .number(attrs::AD_SUPPORTED_ENCRYPTION_TYPES, principal)?
        .filter(|bits| *bits != 0)
        .map(ad_bits_to_enctypes);

    match (krb5.is_empty(), ad) {
        // Neither attribute: no restriction at all, which is not the same as an
        // empty list.
        (true, None) => Ok(None),
        (false, None) => Ok(Some(krb5)),
        (true, Some(from_bits)) => Ok(Some(from_bits)),
        (false, Some(from_bits)) => {
            let mut sorted_krb5 = krb5.clone();
            sorted_krb5.sort_by_key(|e| e.id());
            let mut sorted_ad = from_bits.clone();
            sorted_ad.sort_by_key(|e| e.id());
            if sorted_krb5 != sorted_ad {
                return Err(Error::Hdb(format!(
                    "{principal}: {} lists {:?} and {} lists {:?}; two spellings of one fact that \
                     do not agree",
                    attrs::ENCRYPTION_TYPE,
                    krb5.iter().map(|e| e.id()).collect::<Vec<_>>(),
                    attrs::AD_SUPPORTED_ENCRYPTION_TYPES,
                    from_bits.iter().map(|e| e.id()).collect::<Vec<_>>()
                )));
            }
            Ok(Some(krb5))
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
            // Nothing, deliberately. The bit exists in MS-KILE, and setting it would tell a domain
            // controller this account is issued RC4 — a claim this KDC does not make unless the
            // realm lists the enctype, and one that no client should negotiate from a mask. The
            // comment above the function says exactly this; the arm makes it true.
            Enctype::Rc4Hmac => 0,
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

/// The constrained-delegation list, from `msDS-AllowedToDelegateTo`.
///
/// One value per target, each an SPN without a realm — AD's spelling. Three states are kept
/// apart, because the difference is the authorization decision:
///
/// * absent — this entry never declared a list, and the KDC then allows delegation only to the
///   service itself (MS-SFU §3.1.4);
/// * present, with targets — delegation where the administrator said;
/// * present and empty — a directory cannot express it: the attribute has no value to hold
///   "nobody", so `Some([])` degrades to absent on a round trip. A realm that needs the
///   prohibition keeps it in the record backend, and the test says so out loud rather than
///   leaving it to be discovered.
///
/// A value that carries a realm is accepted when the realm is the entry's own — an
/// administrator writing a full principal is not making a mistake — and refused when it is not,
/// because constrained delegation does not cross realms.
fn delegation_acl(
    attributes: &Attributes,
    principal: &Principal,
) -> Result<Option<Vec<Principal>>> {
    let values = attributes.get(attrs::AD_ALLOWED_TO_DELEGATE_TO);
    if values.is_empty() {
        return Ok(None);
    }
    let mut out = Vec::with_capacity(values.len());
    for value in values {
        let text = std::str::from_utf8(value).map_err(|_| {
            Error::Hdb(format!(
                "{principal}: {} has a value that is not valid UTF-8, so it names no service",
                attrs::AD_ALLOWED_TO_DELEGATE_TO
            ))
        })?;
        out.push(delegation_target(text.trim(), principal)?);
    }
    Ok(Some(out))
}

/// One SPN from the delegation list, as a principal in `entry`'s realm.
fn delegation_target(text: &str, entry: &Principal) -> Result<Principal> {
    let (spn, realm) = match text.rsplit_once('@') {
        None => (text, entry.realm.as_str()),
        Some((spn, realm)) => {
            if !realm.eq_ignore_ascii_case(&entry.realm) {
                return Err(Error::Hdb(format!(
                    "{entry}: {} names a delegation target in realm {realm}, and constrained \
                     delegation does not cross realms (MS-SFU §3.1.5)",
                    attrs::AD_ALLOWED_TO_DELEGATE_TO
                )));
            }
            (spn, entry.realm.as_str())
        }
    };
    let components: Vec<String> = spn.split('/').map(str::to_string).collect();
    if components.is_empty() || components.iter().any(String::is_empty) {
        return Err(Error::Hdb(format!(
            "{entry}: {} holds {text:?}, which names no service",
            attrs::AD_ALLOWED_TO_DELEGATE_TO
        )));
    }
    Ok(Principal::new(
        crate::name::NT_PRINCIPAL,
        components,
        realm.to_string(),
    ))
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

/// Whether this entry publishes `spn`, case-insensitively.
///
/// LDAP compares `servicePrincipalName` case-insensitively and a client may ask in
/// either case, so the check does too. The octets come from the directory as it
/// stored them; a value that is not UTF-8 cannot name anything and is skipped rather
/// than turned into an error, because one broken value is not a reason to refuse a
/// ticket for a name that another value publishes.
fn names_service(attributes: &Attributes, spn: &str) -> bool {
    attributes
        .get(attrs::AD_SERVICE_PRINCIPAL_NAME)
        .iter()
        .filter_map(|value| std::str::from_utf8(value).ok())
        .any(|value| value.eq_ignore_ascii_case(spn))
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
    Principal::parse_in_realm(spn, realm).map_err(Error::from)
}

/// `hdb-pw-salt` (`lib/hdb/hdb.asn1`): the salt type of a password-derived key.
pub const SALT_TYPE_PW: u32 = 3;
/// `hdb-afs3-salt`: an AFS3 salt. Read and preserved, never produced.
pub const SALT_TYPE_AFS3: u32 = 10;

/// One `krb5Key` value, **in Heimdal's layout** (`lib/hdb/hdb.asn1`):
///
/// ```text
/// Key ::= SEQUENCE {
///     mkvno[0] INTEGER OPTIONAL,      -- the master key this key is sealed under
///     key[1]   EncryptionKey,
///     salt[2]  Salt OPTIONAL }
/// Salt ::= SEQUENCE { type[0] INTEGER, salt[1] OCTET STRING, opaque[2] OCTET STRING OPTIONAL }
/// ```
///
/// **`[0]` is `mkvno`, not the key version.** Heimdal writes this value with
/// `ASN1_MALLOC_ENCODE(Key, …)` (`hdb-ldap.c`) and takes the key's version from the separate
/// `krb5KeyVersionNumber` attribute, so a value that puts `kvno` in `[0]` is read by Heimdal as a
/// master-key number and vice versa. This crate wrote `[0] = kvno` until this was found; the reader
/// below still accepts that shape, and [`LdapHdb::migrate_key_layout`] rewrites it.
///
/// With `master`, the key material is written sealed — `encrypt(master_key, HDB_KU_MKEY, key_bytes)` —
/// and `[0]` records which master key did it. A directory is a copy of the realm's keys like any other
/// store: `krb5Key` is readable by anyone the directory lets read the attribute.
fn encode_key(
    key: &HdbKey,
    master: Option<(&dyn crate::crypto::Cipher, &crate::hdb::mkey::MasterKeys)>,
) -> Result<Vec<u8>> {
    let (material, mkvno) = match master {
        Some((cipher, keys)) => {
            let (sealed, kvno) = keys.seal(cipher, key.key.bytes())?;
            (sealed, Some(kvno))
        }
        None => (key.key.bytes().to_vec(), None),
    };
    let mut parts = Vec::new();
    // `mkvno` first, and only when the key is sealed — which is exactly when Heimdal writes it
    // (`hdb_seal_key_mkey` sets it as it seals). That is also what makes the two layouts
    // distinguishable on the way back in.
    if let Some(mkvno) = mkvno {
        parts.push(crate::der::field(0, crate::der::int(i64::from(mkvno))));
    }
    parts.push(crate::der::field(
        1,
        crate::der::seq(&[
            crate::der::field(0, crate::der::int(key.key.enctype().id() as i64)),
            crate::der::field(1, crate::der::octets(&material)),
        ]),
    ));
    if let Some(salt) = &key.salt {
        // The salt is a structure, not an octet string: `type` says how it was made, and a reader
        // that took the bare octets would lose the type and misread ours as Heimdal's key field.
        parts.push(crate::der::field(
            2,
            crate::der::seq(&[
                crate::der::field(0, crate::der::int(i64::from(SALT_TYPE_PW))),
                crate::der::field(1, crate::der::octets(salt)),
            ]),
        ));
    }
    Ok(crate::der::seq(&parts))
}

/// Which layout a `krb5Key` value was written in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyLayout {
    /// Heimdal's: `mkvno[0] OPTIONAL, key[1], salt[2] Salt`.
    Heimdal,
    /// This crate's before the layout was fixed: `kvno[0], key[1], salt[2] OCTET STRING,
    /// mkvno[3]`.
    Legacy,
}

/// The `key[1]` field of a value, and the rest of what a reader needs to tell the layouts apart.
struct KeyFields<'a> {
    material: &'a [u8],
    enctype: Enctype,
    /// `[0]`: `mkvno` in Heimdal's layout, `kvno` in ours.
    first: Option<u32>,
    /// `[2]`: a `Salt` structure in Heimdal's layout, bare octets in ours.
    salt: Option<Vec<u8>>,
    /// `[3]`: our own `mkvno` field, which Heimdal has no place for.
    legacy_mkvno: Option<u32>,
    layout: KeyLayout,
}

/// Reads the parts of a `krb5Key` value without deciding what they mean.
///
/// **The layouts are told apart by their shape, not by a version number.** There is none to use: the
/// value is an `ASN.1` `Key` in both cases. The two things that differ are `[0]` (integer in both, and
/// meaningless without knowing which) and `[2]` (`Salt` is a `SEQUENCE`; our old salt was a bare
/// `OCTET STRING`), plus our own `[3]`, which Heimdal does not write. So:
///
/// * `[3]` present → legacy, unambiguously;
/// * `[2]` a `SEQUENCE` → Heimdal, unambiguously;
/// * neither → decided by the key material: Heimdal writes `mkvno` only when it seals a key, so a
///   **plaintext** key with a `[0]` is one of ours and its `[0]` is a version number.
fn read_key<'a>(value: &'a [u8]) -> Result<KeyFields<'a>> {
    use crate::der::Reader;
    let context = "krb5Key";
    let mut r = Reader::new(value);
    let body = r.expect_in(context, crate::der::SEQUENCE)?;
    let mut f = Reader::new(body);

    let mut first = None;
    let mut material: Option<&[u8]> = None;
    let mut enctype = None;
    let mut salt = None;
    let mut salt_is_struct = false;
    let mut legacy_mkvno = None;

    while !f.is_empty() {
        let field = f
            .next_tlv(context)
            .map_err(|e| Error::Hdb(format!("{context}: {e}")))?;
        let number = field.tag & 0x1f;
        if field.tag & 0xc0 != 0x80 {
            return Err(Error::Hdb(format!(
                "{context}: field {:#04x} is not a context tag",
                field.tag
            )));
        }
        let mut inner = Reader::new(field.content);
        let value = inner
            .next_tlv(context)
            .map_err(|e| Error::Hdb(format!("{context} [{number}]: {e}")))?;
        match number {
            0 => {
                first = Some(
                    u32::try_from(
                        crate::der::as_int(context, value.content)
                            .map_err(|e| Error::Hdb(format!("{context}: {e}")))?,
                    )
                    .map_err(|_| Error::Hdb(format!("{context}: [0] does not fit in 32 bits")))?,
                )
            }
            // `[1] EncryptionKey`: `value` is already the `EncryptionKey` SEQUENCE, because a
            // constructed field's content begins with the inner value. `Fields` strips the context
            // tags of its own fields, which is the difference between `keytype [0] INTEGER` decoding
            // as 18 and decoding as 0x020112.
            1 => {
                let ef = crate::der::Fields::parse(context, value.content)?;
                let id = ef.int(0, context)? as i32;
                enctype = Some(Enctype::from_id(id).ok_or_else(|| {
                    Error::Hdb(format!("enctype {id} is not one this KDC implements"))
                })?);
                material = Some(ef.octets(1, context)?);
            }
            // `[2]`: a `Salt` structure in Heimdal's layout, bare octets in ours. `value` is the
            // SEQUENCE when it is a structure, and the tag is what tells them apart.
            2 => {
                if value.tag == crate::der::SEQUENCE {
                    salt_is_struct = true;
                    let sf = crate::der::Fields::parse(context, value.content)?;
                    // `type[0]` is read and dropped: every salt this crate writes is `hdb-pw-salt`,
                    // and the bytes are what a key was derived with.
                    salt = Some(sf.octets(1, context)?.to_vec());
                } else {
                    salt = Some(value.content.to_vec());
                }
            }
            3 => {
                legacy_mkvno = Some(
                    u32::try_from(
                        crate::der::as_int(context, value.content)
                            .map_err(|e| Error::Hdb(format!("{context}: {e}")))?,
                    )
                    .map_err(|_| Error::Hdb(format!("{context}: [3] does not fit in 32 bits")))?,
                )
            }
            // A field this crate does not know: skipped, because refusing a value over a field that
            // changes nothing here would refuse a directory another KDC wrote.
            _ => {}
        }
    }

    let enctype = enctype.ok_or_else(|| Error::Hdb(format!("{context}: no key field")))?;
    let material = material.ok_or_else(|| Error::Hdb(format!("{context}: no key material")))?;
    let sealed = !crate::hdb::mkey::is_plain_key(material, enctype);
    let layout = if legacy_mkvno.is_some() || (!salt_is_struct && salt.is_some()) {
        KeyLayout::Legacy
    } else if salt_is_struct || sealed {
        // A sealed key carries `mkvno` in `[0]`, which is Heimdal's arrangement.
        KeyLayout::Heimdal
    } else {
        // No `[2]`, no `[3]`, plaintext key with a `[0]`: ours, with a version number in `[0]`.
        match first {
            Some(_) => KeyLayout::Legacy,
            None => KeyLayout::Heimdal,
        }
    };
    Ok(KeyFields {
        material,
        enctype,
        first,
        salt,
        legacy_mkvno,
        layout,
    })
}

/// The key a `krb5Key` value holds.
///
/// `kvno` is the version from `krb5KeyVersionNumber`, which is where Heimdal keeps it. A **legacy**
/// value carries its own version in `[0]`; it is used when the attribute is absent, because an entry
/// written by us before the layout was fixed has no other source.
fn decode_key(
    value: &[u8],
    kvno: Option<u32>,
    master: Option<(&dyn crate::crypto::Cipher, &crate::hdb::mkey::MasterKeys)>,
) -> Result<HdbKey> {
    let fields = read_key(value)?;
    let plaintext = fields.material.len() == fields.enctype.key_len();
    let (mkvno, kvno) = match fields.layout {
        // Heimdal's layout has no version in the value at all — `[0]` is the master-key number, and
        // only a sealed key has one, because Heimdal writes `mkvno` as it seals.
        KeyLayout::Heimdal => (if plaintext { None } else { fields.first }, kvno),
        // In the old layout `[0]` **was** the key's own version, so it wins over the attribute: the
        // attribute is the entry's metadata, and an entry whose two disagree is an entry the caller
        // has to hear about rather than one to paper over.
        KeyLayout::Legacy => (fields.legacy_mkvno, fields.first.or(kvno)),
    };

    // A sealed blob is longer than the enctype accepts — so it is opened **before** `Key::new`,
    // which would otherwise refuse it with a length error that says nothing about what is wrong.
    let material = if crate::hdb::mkey::is_plain_key(fields.material, fields.enctype) {
        fields.material.to_vec()
    } else {
        let (cipher, keys) = master.ok_or_else(|| {
            Error::Hdb(format!(
                "a {}-octet {} key in {} is sealed under a master key{} and none was supplied",
                fields.material.len(),
                fields.enctype.name(),
                attrs::KEY,
                match mkvno {
                    Some(kvno) => format!(" ({kvno})"),
                    None => String::new(),
                }
            ))
        })?;
        keys.unseal(cipher, fields.material, mkvno, fields.enctype)?
    };
    let key = Key::new(fields.enctype, material)?;
    Ok(HdbKey {
        kvno: kvno.ok_or_else(|| {
            Error::Hdb(format!(
                "{context}: a key with no version: {} is absent and the value cannot say",
                attrs::KEY_VERSION_NUMBER,
                context = "krb5Key"
            ))
        })?,
        key,
        salt: fields.salt,
        // Cleared: the entry in memory holds plaintext, and `mkvno` describes the directory.
        mkvno: None,
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

    /// The entry whose `servicePrincipalName` holds `spn`, or `None`.
    ///
    /// A client asks for a ticket by service principal name — `cifs/host.example.com`
    /// — while a Windows directory names the account that holds it
    /// `HOST$@REALM` and keeps the name the client used in an attribute. Looking the
    /// entry up by principal alone therefore misses it, and `net ads join` cannot
    /// proceed past the first SMB ticket.
    ///
    /// The default answers `None`, which is the truth for a directory that carries no
    /// SPNs: nothing is guessed, and a realm without them behaves exactly as before.
    /// A directory that does carry them implements this as one search on
    /// `servicePrincipalName` — the index exists for it in every LDAP server.
    fn get_by_spn(&self, spn: &str) -> Result<Option<Attributes>> {
        let _ = spn;
        Ok(None)
    }

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
    /// The realm's master keys, when the directory holds sealed `krb5Key` values.
    ///
    /// `None` is the common arrangement: the directory keeps plaintext keys and protects them with its
    /// own ACL and transport. Saying so explicitly is the point — a backend that guessed would write
    /// unsealed keys while its operator believed otherwise.
    master: Option<crate::hdb::mkey::MasterKeys>,
    cipher: Arc<dyn crate::crypto::Cipher>,
}

/// The NT hash as Samba spells it: thirty-two hexadecimal digits, **upper** case.
fn nt_hash_hex(hash: &[u8; 16]) -> String {
    let mut out = String::with_capacity(32);
    for byte in hash {
        out.push_str(&format!("{byte:02X}"));
    }
    out
}

/// The inverse, refusing anything that is not exactly sixteen octets of hexadecimal.
///
/// Strict on purpose: the attribute holds a password-equivalent secret, and a value that is
/// truncated, padded or shorter than sixteen octets is a value no logon matches. Reporting it beats
/// storing a hash that will fail somewhere else.
fn nt_hash_from_hex(name: &str, text: &str) -> Result<[u8; 16]> {
    let bad = |why: &str| {
        Error::Hdb(format!(
            "{name}: {} holds {why}; a hexadecimal NT hash is 32 digits",
            attrs::SAMBA_NT_PASSWORD
        ))
    };
    if text.len() != 32 {
        return Err(bad(&format!("{} characters", text.len())));
    }
    let mut out = [0u8; 16];
    for (i, pair) in text.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        let digit = |b: u8| match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            b'A'..=b'F' => Some(b - b'A' + 10),
            _ => None,
        };
        let (hi, lo) = (digit(pair[0]), digit(pair[1]));
        match (hi, lo) {
            (Some(hi), Some(lo)) => out[i] = hi << 4 | lo,
            _ => return Err(bad("a character that is not a hexadecimal digit")),
        }
    }
    Ok(out)
}

impl LdapHdb {
    /// An `HDB` over `directory`.
    pub fn new(directory: Arc<dyn Directory>) -> Self {
        LdapHdb {
            directory,
            master: None,
            cipher: Arc::new(crate::crypto::OwnCipher),
        }
    }

    /// A backend that reads and writes `krb5Key` values sealed under `master`.
    ///
    /// Heimdal's LDAP backend does the same when it has a master key: it unseals what it reads
    /// (`hdb-ldap.c`, `hdb_unseal_key`) and seals what it writes. The reason is the directory itself —
    /// `krb5Key` is an attribute, and an account allowed to read it holds every key it can see.
    pub fn with_master_keys(
        mut self,
        master: crate::hdb::mkey::MasterKeys,
        cipher: Arc<dyn crate::crypto::Cipher>,
    ) -> Result<Self> {
        if master.is_empty() {
            return Err(Error::Hdb(
                "with_master_keys was given no master key: a directory told to seal with nothing \
                 would hold the realm's keys in the clear while its operator believed otherwise"
                    .into(),
            ));
        }
        self.master = Some(master);
        self.cipher = cipher;
        Ok(self)
    }

    /// Whether this backend seals the keys it writes.
    pub fn is_sealed(&self) -> bool {
        self.master.is_some()
    }

    /// The pair the mapping functions take.
    fn codec(&self) -> Option<(&dyn crate::crypto::Cipher, &crate::hdb::mkey::MasterKeys)> {
        self.master
            .as_ref()
            .map(|keys| (self.cipher.as_ref(), keys))
    }

    /// The directory, for an embedder that needs to reach past the mapping.
    pub fn directory(&self) -> &Arc<dyn Directory> {
        &self.directory
    }
}

impl LdapHdb {
    /// Rewrites every `krb5Key` value this crate wrote in its **old** layout into Heimdal's.
    ///
    /// The old layout put the key's version in `[0]` — the position Heimdal uses for `mkvno` — and
    /// the salt in `[2]` as a bare octet string where Heimdal expects a `Salt` structure. A directory
    /// written by an older build of this crate therefore reads wrongly on a Heimdal KDC, and this is
    /// the one-way fix.
    ///
    /// **Only the `krb5Key` values are touched.** Everything else in an entry is left exactly as the
    /// directory returned it, because re-serializing the whole entry would drop attributes this
    /// crate's mapping does not model — a directory usually has more in it than a KDC reads.
    ///
    /// Values already in Heimdal's layout are not written again, so a second run does nothing. A
    /// backend with a master key also seals what it rewrites, which is how a directory that was
    /// written in the clear ends up protected: the migration is the moment every key is in hand.
    ///
    /// Returns how many entries were rewritten, which is the number an operator wants in the log.
    pub fn migrate_key_layout(&self) -> Result<u32> {
        let mut rewritten = 0u32;
        for principal in self.directory.list()? {
            let Some(mut attributes) = self.directory.get(&principal)? else {
                // Listed and then gone: another writer removed it between the two calls, and there is
                // nothing to migrate. Not an error — a directory is not a snapshot.
                continue;
            };
            let name = principal.to_string();
            let kvno = attributes.number(attrs::KEY_VERSION_NUMBER, &name)?;
            let mut changed = false;
            let mut migrated = Vec::new();
            for value in attributes.get(attrs::KEY) {
                let fields = read_key(value)?;
                if fields.layout == KeyLayout::Heimdal {
                    migrated.push(value.clone());
                    continue;
                }
                let key = decode_key(value, kvno, self.codec())?;
                migrated.push(encode_key(&key, self.codec())?);
                changed = true;
            }
            if !changed {
                continue;
            }
            attributes.remove(attrs::KEY);
            for value in migrated {
                attributes.add(attrs::KEY, value);
            }
            self.directory.put(&principal, &attributes)?;
            rewritten += 1;
        }
        Ok(rewritten)
    }
}

impl Hdb for LdapHdb {
    fn fetch(&self, principal: &Principal) -> Result<Option<HdbEntry>> {
        match self.directory.get(principal)? {
            None => Ok(None),
            Some(attributes) => {
                let entry = from_attributes_with(&attributes, self.codec())?;
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

    fn fetch_for_service(&self, service: &Principal) -> Result<Option<HdbEntry>> {
        // By name first: a realm that keeps no SPNs, or one whose service account is
        // named exactly as clients ask, answers here and nothing else is consulted.
        if let Some(entry) = self.fetch(service)? {
            return Ok(Some(entry));
        }
        // Then by service principal name. The entry is expected to belong to a
        // *different* principal — `HOST$` holds `cifs/host` — so the check `fetch`
        // makes cannot apply; instead the store is asked to have published the name,
        // and an entry that did not would be a directory answering the wrong question.
        let Some(spn) = service_principal_name(service) else {
            return Ok(None);
        };
        let Some(attributes) = self.directory.get_by_spn(&spn)? else {
            return Ok(None);
        };
        let entry = from_attributes_with(&attributes, self.codec())?;
        if !names_service(&attributes, &spn) {
            return Err(Error::Hdb(format!(
                "{spn}: the directory answered with {}, which does not publish that                  service principal name",
                entry.principal
            )));
        }
        Ok(Some(entry))
    }

    fn store(&self, entry: HdbEntry) -> Result<()> {
        let attributes = to_attributes_with(&entry, self.codec())?;
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
            Some(attributes) => from_attributes_with(&attributes, self.codec())?,
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

    /// The NT hash travels as Samba writes it — thirty-two upper-case hexadecimal digits — and comes
    /// back as the same sixteen octets.
    ///
    /// Upper case matters: Samba writes it that way, and a comparison an operator makes between a
    /// directory and a `secretsdump` line is a text comparison. Lower case would parse equally well
    /// and would disagree with every other tool in sight.
    #[test]
    fn the_nt_hash_is_written_as_samba_spells_it() {
        let entry = entry();
        let hash = entry.nt_hash.expect("recorded from the password");
        let attributes = to_attributes(&entry);
        let written = attributes
            .first(attrs::SAMBA_NT_PASSWORD)
            .expect("the attribute is present");
        assert_eq!(written.len(), 32, "thirty-two hexadecimal digits");
        assert_eq!(
            std::str::from_utf8(written).unwrap(),
            "8CC19B6A8CFEAC299C2871C86B38DE28",
            "\"pw\" as Samba writes it: MD4 of its UTF-16LE octets, upper case. \
             Checkable with printf 'pw' | iconv -f utf-8 -t utf-16le | openssl dgst -md4 -provider legacy"
        );
        assert!(
            written
                .iter()
                .all(|b| b.is_ascii_digit() || (b'A'..=b'F').contains(b)),
            "and every digit is upper case"
        );

        // Read back, it is the same sixteen octets.
        let back = from_attributes(&attributes).expect("reads");
        assert_eq!(back.nt_hash, Some(hash));
    }

    /// A value that is not thirty-two hexadecimal digits is refused with the attribute's name,
    /// rather than stored as a hash that will fail at the first logon.
    #[test]
    fn a_malformed_nt_hash_is_refused() {
        for bad in [
            "",
            "abc",
            &"A".repeat(31),
            &"A".repeat(33),
            &format!("{}Z", "A".repeat(31)),
        ] {
            let mut attributes = to_attributes(&entry());
            attributes.set(attrs::SAMBA_NT_PASSWORD, bad.as_bytes().to_vec());
            let err = from_attributes(&attributes)
                .expect_err("a malformed hash must not read")
                .to_string();
            assert!(
                err.contains(attrs::SAMBA_NT_PASSWORD),
                "the message must name the attribute: {err}"
            );
        }
    }

    /// An entry with no hash writes no attribute: an invented hash is one no logon ever matches, and
    /// a reader that finds the attribute missing learns something true.
    #[test]
    fn an_entry_without_a_hash_writes_no_attribute() {
        let mut entry = entry();
        entry.nt_hash = None;
        let attributes = to_attributes(&entry);
        assert!(!attributes.has(attrs::SAMBA_NT_PASSWORD));
        assert_eq!(from_attributes(&attributes).unwrap().nt_hash, None);
    }

    /// A sealed directory value: no key in the clear, and the entry reads back with its key.
    ///
    /// The assertion is about the attribute bytes, not about the API. A backend that sealed on the way
    /// out and opened on the way in but stored plaintext in between would pass every round trip and
    /// protect nothing — and in a directory that matters more than in a file, because `krb5Key` is
    /// readable by anyone the ACL lets read the attribute.
    #[test]
    fn a_sealed_entry_holds_no_plaintext_key_in_the_directory() {
        use crate::crypto::{Cipher, OwnCipher};
        use crate::hdb::mkey::MasterKeys;

        let master = OwnCipher.random(Enctype::Aes256Sha1).expect("a key");
        let keys = MasterKeys::single(master.clone(), 1);
        let mut entry = HdbEntry::user(Principal::parse("alice@EXAMPLE.COM").expect("a name"));
        entry
            .add_password_key(&OwnCipher, Enctype::Aes256Sha1, b"pw", 1)
            .expect("a key");
        let plain = entry.keys[0].key.bytes().to_vec();

        let sealed_attrs = to_attributes_with(&entry, Some((&OwnCipher, &keys))).expect("mapped");
        for value in sealed_attrs.get(attrs::KEY) {
            assert!(
                !value.windows(plain.len()).any(|w| w == plain.as_slice()),
                "a key was written to {attrs} in the clear",
                attrs = attrs::KEY
            );
        }

        // Reading it back needs the master key, and the refusal names it.
        let err = from_attributes(&sealed_attrs).expect_err("sealed without a key");
        assert!(
            err.to_string().contains("sealed under a master key"),
            "{err}"
        );
        let opened = from_attributes_with(&sealed_attrs, Some((&OwnCipher, &keys)))
            .expect("the master key opens it");
        assert_eq!(opened.keys[0].key.bytes(), plain.as_slice());

        // A wrong master key is a key problem, not a record problem.
        let other = MasterKeys::single(OwnCipher.random(Enctype::Aes256Sha1).unwrap(), 1);
        let err = from_attributes_with(&sealed_attrs, Some((&OwnCipher, &other)))
            .expect_err("the wrong key");
        assert!(err.to_string().contains("does not open"), "{err}");

        // And a plaintext entry still maps: a directory written before the realm had a master key is
        // readable, and becomes sealed the next time it is written.
        let plain_attrs = to_attributes(&entry);
        let back = from_attributes_with(&plain_attrs, Some((&OwnCipher, &keys)))
            .expect("a plaintext entry reads through a sealed backend");
        assert_eq!(back.keys[0].key.bytes(), plain.as_slice());
    }

    /// The value is Heimdal's `Key` shape plus the `mkvno` this crate writes, and a value that says it
    /// is sealed but carries no `mkvno` is still attempted against the whole set — because the tag
    /// decides, and refusing on a missing number would refuse a directory another KDC wrote.
    #[test]
    fn a_sealed_value_without_a_number_is_tried_against_the_set() {
        use crate::crypto::{Cipher, Enctype, OwnCipher};
        use crate::hdb::mkey::{MasterKeys, seal_key};

        let old = OwnCipher.random(Enctype::Aes256Sha1).expect("a key");
        let new = OwnCipher.random(Enctype::Aes256Sha1).expect("a key");
        let keys = MasterKeys::from_keys([(old.clone(), 1), (new, 2)]);
        let material = seal_key(&OwnCipher, &old, &[0x5a; 32]).expect("sealed");

        // The attribute value, hand-built: kvno, the sealed material, and no `[3]`.
        let value = crate::der::seq(&[
            crate::der::field(0, crate::der::int(1)),
            crate::der::field(
                1,
                crate::der::seq(&[
                    crate::der::field(0, crate::der::int(Enctype::Aes256Sha1.id() as i64)),
                    crate::der::field(1, crate::der::octets(&material)),
                ]),
            ),
        ]);
        let opened = decode_key(&value, Some(1), Some((&OwnCipher, &keys)))
            .expect("one of the keys opens it");
        assert_eq!(opened.key.bytes(), [0x5a; 32]);
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

        // `Some([])` — "issued nothing" — has no spelling in a directory: `msDS-Supported`
        // `EncryptionTypes` has no bit for it, and writing 0 means "declared nothing", which
        // [MS-KILE] 2.2.7 reads as no restriction. It therefore degrades to `None` on a round
        // trip, and that is stated here rather than assumed: a realm that needs the
        // prohibition keeps it in the record backend.
        entry.etypes = Some(Vec::new());
        assert_eq!(
            from_attributes(&to_attributes(&entry)).unwrap().etypes,
            None,
            "a directory cannot say `issued nothing`; it reads back as no restriction"
        );
    }

    #[test]
    fn a_delegation_acl_round_trips_through_the_ad_attribute() {
        // RRL-3.27. Without this attribute an LDAP-backed realm can delegate to nobody but
        // itself, which is the same as having no S4U2Proxy at all: the whole point of a
        // service account in a directory is that an administrator can name where it may go.
        let mut entry = entry();
        entry.constrained_delegation = Some(vec![
            Principal::parse("cifs/files.example.com@EXAMPLE.COM").unwrap(),
            Principal::parse("http/web.example.com@EXAMPLE.COM").unwrap(),
        ]);
        let attributes = to_attributes(&entry);
        assert_eq!(
            attributes.get(attrs::AD_ALLOWED_TO_DELEGATE_TO).len(),
            2,
            "one value per delegation target, as AD stores them"
        );
        assert_eq!(
            attributes.first(attrs::AD_ALLOWED_TO_DELEGATE_TO),
            Some(&b"cifs/files.example.com"[..]),
            "an SPN carries no realm: the entry's own realm is what it means"
        );

        let back = from_attributes(&attributes).unwrap();
        let acl = back.constrained_delegation.expect("a list came back");
        assert_eq!(acl.len(), 2);
        assert_eq!(acl[0].components, vec!["cifs", "files.example.com"]);
        assert_eq!(acl[0].realm, "EXAMPLE.COM");
        assert_eq!(acl[1].components, vec!["http", "web.example.com"]);
    }

    #[test]
    fn a_delegation_list_of_nobody_degrades_to_absent_and_that_is_stated() {
        // `Some([])` — "to nobody" — has no spelling in a directory: `msDS-AllowedToDelegateTo`
        // holds targets, and no value means "never declared". The round trip therefore widens a
        // prohibition into a permission, and the test says so rather than leaving it to be
        // discovered: a realm that must forbid delegation keeps the entry in the record backend,
        // where an empty list survives.
        let mut entry = entry();
        entry.constrained_delegation = Some(Vec::new());
        let back = from_attributes(&to_attributes(&entry)).unwrap();
        assert_eq!(
            back.constrained_delegation, None,
            "a directory cannot say `delegates to nobody`; it reads back as `never declared`"
        );
    }

    #[test]
    fn a_delegation_target_naming_another_realm_is_refused() {
        // Constrained delegation does not cross realms (MS-SFU §3.1.5): a target in another
        // realm is a target this KDC can never issue a ticket for. Silently storing it would
        // leave an administrator believing the delegation works.
        let mut attributes = to_attributes(&entry());
        attributes.set(
            attrs::AD_ALLOWED_TO_DELEGATE_TO,
            "cifs/files.example.com@OTHER.EXAMPLE",
        );
        let err = from_attributes(&attributes).unwrap_err().to_string();
        assert!(
            err.contains("OTHER.EXAMPLE") && err.contains("realm"),
            "the refusal must name the realm it found: {err}"
        );
    }

    #[test]
    fn a_delegation_target_that_names_nothing_is_refused() {
        // An empty value, or one that is not UTF-8, would otherwise become a principal with no
        // components — a name that matches nothing and hides a typo in the directory.
        let mut attributes = to_attributes(&entry());
        attributes.set(attrs::AD_ALLOWED_TO_DELEGATE_TO, "");
        let err = from_attributes(&attributes).unwrap_err().to_string();
        assert!(err.contains("names no service"), "{err}");

        let mut attributes = to_attributes(&entry());
        attributes.set(attrs::AD_ALLOWED_TO_DELEGATE_TO, vec![0xff, 0xfe]);
        let err = from_attributes(&attributes).unwrap_err().to_string();
        assert!(err.contains("UTF-8"), "{err}");
    }

    #[test]
    fn a_realm_suffix_that_matches_the_entry_is_accepted() {
        // AD stores bare SPNs, but an administrator writing a full principal by hand is not
        // making a mistake — and refusing it would send them to a directory they just edited
        // correctly.
        let mut attributes = to_attributes(&entry());
        attributes.set(
            attrs::AD_ALLOWED_TO_DELEGATE_TO,
            "cifs/files.example.com@EXAMPLE.COM",
        );
        let back = from_attributes(&attributes).unwrap();
        let acl = back.constrained_delegation.expect("a list");
        assert_eq!(acl[0].components, vec!["cifs", "files.example.com"]);
        assert_eq!(acl[0].realm, "EXAMPLE.COM");
    }

    #[test]
    fn an_absent_delegation_attribute_stays_absent() {
        // No list is not the same as a list of nobody: `None` means "this entry never said",
        // and the KDC then allows delegation only to the service itself (MS-SFU §3.1.4).
        let entry = entry();
        assert_eq!(entry.constrained_delegation, None);
        assert_eq!(
            from_attributes(&to_attributes(&entry))
                .unwrap()
                .constrained_delegation,
            None
        );
    }

    #[test]
    fn a_zero_in_the_ad_attribute_means_no_restriction_not_none_allowed() {
        // [MS-KILE] 2.2.7 and RRL-2.26: an account whose `msDS-SupportedEncryptionTypes` is 0
        // (or absent) has declared nothing, and the KDC applies its defaults. Reading the zero
        // as "no enctypes allowed" makes every such account unusable — the ticket request is
        // refused with `KDC_ERR_ETYPE_NOSUPP` and the operator sees an account that cannot log
        // in, with nothing in the directory that looks wrong.
        let mut attributes = to_attributes(&entry());
        attributes.set(attrs::AD_SUPPORTED_ENCRYPTION_TYPES, "0");
        let back = from_attributes(&attributes).unwrap();
        assert_eq!(
            back.etypes, None,
            "zero is a declaration of nothing, not a prohibition"
        );

        // The pair: a non-zero value is a restriction and is still read as one.
        let mut attributes = to_attributes(&entry());
        attributes.set(attrs::AD_SUPPORTED_ENCRYPTION_TYPES, "16"); // 0x10, AES256-SHA1
        let back = from_attributes(&attributes).unwrap();
        assert_eq!(back.etypes, Some(vec![Enctype::Aes256Sha1]));
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

    /// A **legacy** value that carries a version newer than the attribute is refused.
    ///
    /// In Heimdal's layout the version is not in the value at all, so this contradiction cannot be
    /// expressed — and Heimdal cannot detect it either. The check stays because a directory written by
    /// an older build of this crate has values that do carry a version, and an entry whose attribute
    /// was never moved forward is an entry whose keys nothing can match. The test builds that shape by
    /// hand for exactly that reason.
    #[test]
    fn a_legacy_key_newer_than_the_declared_kvno_is_refused() {
        let mut attributes = Attributes::new();
        attributes.set(attrs::PRINCIPAL_NAME, "alice@EXAMPLE.COM");
        attributes.set(attrs::KEY_VERSION_NUMBER, "1");
        attributes.set(attrs::AD_KEY_VERSION_NUMBER, "1");
        let key = OwnCipher
            .s2k(Enctype::Aes128Sha1, b"pw", b"EXAMPLE.COMalice", None)
            .unwrap();
        // The old layout: `kvno[0]`, and the value says 2 where the attribute says 1.
        attributes.add(
            attrs::KEY,
            crate::der::seq(&[
                crate::der::field(0, crate::der::int(2)),
                crate::der::field(
                    1,
                    crate::der::seq(&[
                        crate::der::field(0, crate::der::int(Enctype::Aes128Sha1.id() as i64)),
                        crate::der::field(1, crate::der::octets(key.bytes())),
                    ]),
                ),
            ]),
        );
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
