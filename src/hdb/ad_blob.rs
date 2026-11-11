//! The Active Directory projection of an entry's keys: `supplementalCredentials`.
//!
//! # What this is for
//!
//! A directory that holds Heimdal attributes is readable by this crate and by
//! Heimdal, and by nothing else. Tools that speak to an Active Directory — an
//! audit script, `secretsdump`, a migration — look for the keys in
//! `supplementalCredentials`, and finding nothing there they report an account
//! with no keys.
//!
//! So this module writes that attribute as a **projection**: it is generated from
//! the entry, never the place a key lives, and never consulted while the entry
//! has `krb5Key`. If writing it fails, an account still logs in; only the
//! AD-shaped view of it is missing. That is the whole reason the plan refused to
//! make the AD blob the canonical form — it is written by us and read by
//! strangers, so a defect in it must not be able to cost anybody a login.
//!
//! # Reading it back
//!
//! One case does read it: an account written by an AD-shaped tool has its keys in
//! `supplementalCredentials` and nowhere else, and a KDC that refused to read that
//! could only serve directories it wrote itself. [`keys`] is the reader, and the
//! fallback is in `from_attributes` — used **only** when `krb5Key` is absent, and
//! lossy by construction: the structure has no key version, so the version comes
//! from `msDS-KeyVersionNumber`, and it has one salt for every key, so a principal
//! whose keys used different salts reads back with one of them. That is why
//! `krb5Key` stays canonical and this stays the fallback.
//!
//! # The format
//!
//! `supplementalCredentials` is a `USER_PROPERTIES` structure ([MS-SAMR]
//! §2.2.10.1) holding named properties. The one written here is
//! `Primary:Kerberos-Newer-Keys`, a `KERB_STORED_CREDENTIAL_NEW` (§2.2.10.6) whose
//! `Buffer` holds `KERB_KEY_DATA_NEW` entries (§2.2.10.7), the default salt, and
//! the key material. Offsets are from the start of the credential structure, and
//! the property value travels as the **hexadecimal text** of those octets, because
//! `USER_PROPERTY.PropertyValue` is a string.
//!
//! Three details are the kind a hand-built blob gets wrong and a reader notices:
//!
//! * `Length` counts from offset 12 up to but **not including** the final
//!   `Reserved5` octet, and when there are no properties at all the two-octet
//!   `PropertyCount` is *omitted* — so a blob with no properties is 111 octets, not
//!   113.
//! * The salt is a `defaultSalt` **and** a length, and the salt this crate keeps is
//!   per key: a principal whose keys were made with different salts has no single
//!   default. The first key's salt is written as the default and each key keeps its
//!   own because the structure has no per-key salt field — which is exactly why AD
//!   can only represent one salt, and why Heimdal's `krb5Key` is the canonical form
//!   here.
//! * `Primary:Kerberos` (the pre-Windows-2008 structure) is **not** written: it
//!   holds at most two keys and has no iteration count, so writing it for a
//!   four-enctype entry would state something false. Readers that matter read the
//!   newer property.
//!
//! # Verified against somebody else's parser
//!
//! `scripts/verify-ad-blob.sh` runs this encoder and then hands the octets to
//! **impacket**, whose `samr.USER_PROPERTIES` and `samr.KERB_STORED_CREDENTIAL_NEW`
//! are an independent implementation written from the same specification. A blob
//! this crate writes is a blob `secretsdump` can read. Without that, the only
//! evidence would be this crate agreeing with itself.

use crate::crypto::Enctype;
use crate::hdb::HdbEntry;

/// The property name an AD-shaped reader looks for.
pub const PROPERTY_KERBEROS_NEWER_KEYS: &str = "Primary:Kerberos-Newer-Keys";

/// The account's NT hash, the value a logon is checked against (MS-SAMR 2.2.10.1).
pub const PROPERTY_NT_HASH: &str = "Primary:NT";

/// `USER_PROPERTIES`'s signature octet pair ([MS-SAMR] §2.2.10.1).
const PROPERTY_SIGNATURE: u16 = 0x0050;

/// `KERB_STORED_CREDENTIAL_NEW`'s revision, the one Windows 2008 and later write.
const REVISION_NEW: u16 = 4;

/// The string-to-key iteration count this crate uses for the enctypes that have
/// one. Recorded because the structure has a field for it; the keys themselves
/// are what a reader uses.
const ITERATION_COUNT: u32 = 4096;

/// `KERB_STORED_CREDENTIAL_NEW`'s fixed part: eight 16-bit fields and two
/// 32-bit ones.
const CREDENTIAL_HEADER: usize = 24;

/// `KERB_KEY_DATA_NEW`: two 16-bit reserved fields, one 32-bit reserved, the
/// iteration count, then enctype, length and offset — six words, not four.
const KEY_DATA_NEW: usize = 24;

/// `supplemental_credentials` for `entry`.
///
/// One property, `Primary:Kerberos-Newer-Keys`, with the entry's current keys as
/// the credentials and its older ones as the old credentials — which is the
/// distinction AD draws and the reason a rotation is representable at all.
pub fn supplemental_credentials(entry: &HdbEntry) -> Vec<u8> {
    user_properties(&[(PROPERTY_KERBEROS_NEWER_KEYS, &kerberos_newer_keys(entry))])
}

/// The same structure with the account's NT hash beside its Kerberos keys.
///
/// AD keeps the hash a logon is checked against in `Primary:NT`, as the hexadecimal text of the
/// sixteen octets. Without it a machine account can be issued tickets and cannot establish a secure
/// channel: `netr_ServerAuthenticate3` derives its session key from the hash and has nothing else to
/// derive from. One blob rather than two because the attribute holds one `USER_PROPERTIES`: a second
/// write would replace the first, and the Kerberos keys are what the KDC reads.
pub fn supplemental_credentials_with_nt(entry: &HdbEntry, nt_hash: &[u8; 16]) -> Vec<u8> {
    user_properties(&[
        (PROPERTY_KERBEROS_NEWER_KEYS, &kerberos_newer_keys(entry)),
        (PROPERTY_NT_HASH, nt_hash),
    ])
}

/// `USER_PROPERTIES` carrying `properties`, in order (MS-SAMR 2.2.10.1).
///
/// `PropertyValue` is a string in the specification, and AD's string holds the hexadecimal text of
/// the octets: a reader that expects binary here finds an odd length and stops.
fn user_properties(properties: &[(&str, &[u8])]) -> Vec<u8> {
    let mut encoded = Vec::new();
    for (name, value) in properties {
        let hex = hex_lower(value);
        let name: Vec<u8> = name.encode_utf16().flat_map(u16::to_le_bytes).collect();

        encoded.extend_from_slice(&(name.len() as u16).to_le_bytes());
        encoded.extend_from_slice(&(hex.len() as u16).to_le_bytes());
        encoded.extend_from_slice(&0u16.to_le_bytes()); // Reserved
        encoded.extend_from_slice(&name);
        encoded.extend_from_slice(hex.as_bytes());
    }

    let mut out = Vec::with_capacity(112 + encoded.len());
    out.extend_from_slice(&0u32.to_le_bytes()); // Reserved1
    // Filled in below: it counts from offset 12 up to `Reserved5`, which the
    // specification writes as the structure's length *minus* that last octet and
    // minus the twelve before it.
    out.extend_from_slice(&0u32.to_le_bytes()); // Length
    out.extend_from_slice(&1u16.to_le_bytes()); // Reserved2: MUST be 1
    out.extend_from_slice(&0u16.to_le_bytes()); // Reserved3
    out.extend_from_slice(&[0u8; 96]); // Reserved4
    out.extend_from_slice(&PROPERTY_SIGNATURE.to_le_bytes());
    out.extend_from_slice(&(properties.len() as u16).to_le_bytes()); // PropertyCount
    out.extend_from_slice(&encoded);
    out.extend_from_slice(&[0u8]); // Reserved5

    let length = (out.len() - 13) as u32;
    out[4..8].copy_from_slice(&length.to_le_bytes());
    out
}

/// `USER_PROPERTIES` with no properties: 111 octets, because `PropertyCount` is
/// omitted when it would be zero.
///
/// Kept beside the encoder rather than left to a caller: the shape is surprising
/// enough that a caller who built it by analogy would write 113 octets and be
/// wrong in a way only a reader notices.
pub fn empty_supplemental_credentials() -> Vec<u8> {
    let mut out = Vec::with_capacity(111);
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&[0u8; 96]);
    out.extend_from_slice(&PROPERTY_SIGNATURE.to_le_bytes());
    out.extend_from_slice(&[0u8]);
    let length = (out.len() - 13) as u32;
    out[4..8].copy_from_slice(&length.to_le_bytes());
    out
}

/// The `KERB_STORED_CREDENTIAL_NEW` octets, before they are hex-encoded.
///
/// The structure has three places for keys — current, old, older — and this
/// crate's entries may hold more generations than that, so the projection keeps the
/// three AD can name and leaves anything beyond them out. That is the same limit AD
/// itself enforces when it prunes an account's credential history, and it is the
/// reason the blob is a projection and `krb5Key` is the record: a projection that
/// silently dropped a key it could not express would be a lie, so it drops what AD
/// drops and says so here.
pub fn kerberos_newer_keys(entry: &HdbEntry) -> Vec<u8> {
    let current = entry.kvno();
    let generation = |kvno: u32| -> Vec<&crate::hdb::HdbKey> {
        let mut keys: Vec<&crate::hdb::HdbKey> =
            entry.keys.iter().filter(|k| k.kvno == kvno).collect();
        // Deterministic order: a blob that changes byte-for-byte between two reads
        // of one entry is a blob a checksum cannot describe.
        keys.sort_by_key(|k| k.key.enctype().id());
        keys
    };
    let credentials = generation(current);
    let old = generation(current.saturating_sub(1));
    let older = generation(current.saturating_sub(2));

    // An entry whose keys are all older than its declared version — an account
    // provisioned before its first password — still has keys, and reporting none of
    // them would be a worse answer than reporting the newest as current.
    let (credentials, old, older) = if credentials.is_empty() && !old.is_empty() {
        (old, older, Vec::new())
    } else {
        (credentials, old, older)
    };

    let salt = entry
        .keys
        .first()
        .and_then(|k| k.salt.clone())
        .unwrap_or_else(|| entry.principal.default_salt());

    // `KERB_STORED_CREDENTIAL_NEW`'s fixed part: eight 16-bit fields and two
    // 32-bit ones.
    const HEADER: usize = CREDENTIAL_HEADER;
    // `KERB_KEY_DATA_NEW`: two 16-bit reserved fields, one 32-bit reserved, the
    // iteration count, then enctype, length and offset — six words, not four.
    const KEY_DATA: usize = KEY_DATA_NEW;
    let all: Vec<&crate::hdb::HdbKey> = credentials
        .iter()
        .chain(old.iter())
        .chain(older.iter())
        .copied()
        .collect();
    let arrays_len = all.len() * KEY_DATA;
    let salt_offset = HEADER + arrays_len;
    let mut next_value = salt_offset + salt.len();

    let mut key_data = Vec::with_capacity(arrays_len);
    let mut values = Vec::new();
    for key in &all {
        key_data.extend_from_slice(&0u16.to_le_bytes()); // Reserved1
        key_data.extend_from_slice(&0u16.to_le_bytes()); // Reserved2
        key_data.extend_from_slice(&0u32.to_le_bytes()); // Reserved3
        key_data.extend_from_slice(&ITERATION_COUNT.to_le_bytes());
        key_data.extend_from_slice(&(key.key.enctype().id() as u32).to_le_bytes());
        key_data.extend_from_slice(&(key.key.len() as u32).to_le_bytes());
        key_data.extend_from_slice(&(next_value as u32).to_le_bytes());
        values.extend_from_slice(key.key.bytes());
        next_value += key.key.len();
    }

    let mut out = Vec::with_capacity(next_value);
    out.extend_from_slice(&REVISION_NEW.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // Flags
    out.extend_from_slice(&(credentials.len() as u16).to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // ServiceCredentialCount
    out.extend_from_slice(&(old.len() as u16).to_le_bytes());
    out.extend_from_slice(&(older.len() as u16).to_le_bytes());
    out.extend_from_slice(&(salt.len() as u16).to_le_bytes()); // DefaultSaltLength
    out.extend_from_slice(&(salt.len() as u16).to_le_bytes()); // DefaultSaltMaximumLength
    out.extend_from_slice(&(salt_offset as u32).to_le_bytes());
    out.extend_from_slice(&ITERATION_COUNT.to_le_bytes());
    out.extend_from_slice(&key_data);
    out.extend_from_slice(&salt);
    out.extend_from_slice(&values);
    debug_assert_eq!(
        out.len(),
        next_value,
        "the offsets must describe this buffer"
    );
    out
}

/// Why a `supplementalCredentials` value could not be read.
///
/// Reading this attribute is the lossy direction, so every refusal names what is
/// wrong instead of guessing: an entry whose keys cannot be read is an entry
/// whose owner cannot log in, and a guess turns that into a mystery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdBlobError {
    /// Not a `USER_PROPERTIES`: a length, signature or count does not describe
    /// the buffer it arrived in.
    NotUserProperties,
    /// A well-formed `USER_PROPERTIES` with no `Primary:Kerberos-Newer-Keys`
    /// property — an account whose keys are not kept here at all.
    MissingProperty,
    /// The property value is not an even-length run of hexadecimal digits.
    NotHex,
    /// `KERB_STORED_CREDENTIAL_NEW` at a revision this reader does not know.
    /// Reading on would take key material from the wrong offsets.
    UnknownRevision(u16),
    /// A count, length or offset that does not describe its own buffer.
    Inconsistent,
    /// A key whose enctype this crate does not implement.
    UnknownEnctype(i32),
    /// A key whose length is not the one its enctype requires.
    BadKeyLength(i32, usize),
}

impl std::fmt::Display for AdBlobError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AdBlobError::NotUserProperties => write!(f, "not a USER_PROPERTIES structure"),
            AdBlobError::MissingProperty => {
                write!(f, "no {PROPERTY_KERBEROS_NEWER_KEYS} property")
            }
            AdBlobError::NotHex => write!(f, "the property value is not hexadecimal text"),
            AdBlobError::UnknownRevision(v) => {
                write!(f, "KERB_STORED_CREDENTIAL_NEW revision {v}, which is not 4")
            }
            AdBlobError::Inconsistent => {
                write!(f, "a count, length or offset does not describe the buffer")
            }
            AdBlobError::UnknownEnctype(id) => write!(f, "enctype {id} is not implemented here"),
            AdBlobError::BadKeyLength(id, len) => {
                write!(f, "enctype {id} cannot have a {len}-octet key")
            }
        }
    }
}

impl std::error::Error for AdBlobError {}

/// One key read out of the projection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdCredential {
    /// The enctype the blob names for this key.
    pub enctype: Enctype,
    /// The key material, as the credential structure holds it.
    pub key: Vec<u8>,
    /// The structure's *default* salt, which is the only salt AD's form has: a
    /// blob written from an entry whose keys used different salts carries one of
    /// them for all. `None` when the blob names none.
    pub salt: Option<Vec<u8>>,
}

/// The keys `supplementalCredentials` holds.
///
/// The blob carries no key version — `KERB_STORED_CREDENTIAL_NEW` has no field
/// for it — so a caller that needs one takes it from `msDS-KeyVersionNumber`,
/// which is where AD keeps it. That is [`keys`]'s second argument.
///
/// The three generations the structure has (current, old, older) all come back
/// in one list: the structure records which generation a key belongs to only by
/// the order of its counts, and an entry read back at one version has no use for
/// the distinction.
pub fn credentials(blob: &[u8]) -> Result<Vec<AdCredential>, AdBlobError> {
    let value = property_value(blob, PROPERTY_KERBEROS_NEWER_KEYS)?;
    let inner = unhex(value)?;
    if inner.len() < CREDENTIAL_HEADER {
        return Err(AdBlobError::Inconsistent);
    }
    let revision = u16_at(&inner, 0);
    if revision != REVISION_NEW {
        return Err(AdBlobError::UnknownRevision(revision));
    }
    let counts = [
        u16_at(&inner, 4) as usize,
        u16_at(&inner, 6) as usize,
        u16_at(&inner, 8) as usize,
        u16_at(&inner, 10) as usize,
    ];
    let total: usize = counts.iter().sum();
    let salt_len = u16_at(&inner, 12) as usize;
    let salt_offset = u32_at(&inner, 16) as usize;
    let end = salt_offset
        .checked_add(salt_len)
        .ok_or(AdBlobError::Inconsistent)?;
    if end > inner.len() {
        return Err(AdBlobError::Inconsistent);
    }
    let salt = if salt_len == 0 {
        None
    } else {
        Some(inner[salt_offset..end].to_vec())
    };
    let array_end = CREDENTIAL_HEADER
        .checked_add(
            total
                .checked_mul(KEY_DATA_NEW)
                .ok_or(AdBlobError::Inconsistent)?,
        )
        .ok_or(AdBlobError::Inconsistent)?;
    if array_end > inner.len() {
        return Err(AdBlobError::Inconsistent);
    }

    let mut keys = Vec::with_capacity(total);
    for i in 0..total {
        let at = CREDENTIAL_HEADER + i * KEY_DATA_NEW;
        let id = u32_at(&inner, at + 12) as i32;
        let len = u32_at(&inner, at + 16) as usize;
        let offset = u32_at(&inner, at + 20) as usize;
        let key_end = offset.checked_add(len).ok_or(AdBlobError::Inconsistent)?;
        if key_end > inner.len() {
            return Err(AdBlobError::Inconsistent);
        }
        let enctype = Enctype::from_id(id).ok_or(AdBlobError::UnknownEnctype(id))?;
        // `Key::new` is the one place that knows each enctype's length, so a
        // structure that claims an impossible length is refused here rather than
        // becoming a key nothing can ever decrypt with.
        crate::crypto::Key::new(enctype, inner[offset..key_end].to_vec())
            .map_err(|_| AdBlobError::BadKeyLength(id, len))?;
        keys.push(AdCredential {
            enctype,
            key: inner[offset..key_end].to_vec(),
            salt: salt.clone(),
        });
    }
    Ok(keys)
}

/// [`credentials`] as `HdbKey`s at `kvno`, ready to be handed to a KDC.
pub fn keys(blob: &[u8], kvno: u32) -> Result<Vec<crate::hdb::HdbKey>, AdBlobError> {
    Ok(credentials(blob)?
        .into_iter()
        .map(|c| crate::hdb::HdbKey {
            kvno,
            key: crate::crypto::Key::new(c.enctype, c.key)
                .expect("credentials() validated every key's length"),
            salt: c.salt,
        })
        .collect())
}

/// The `USER_PROPERTIES` value of the property called `name`.
fn property_value<'a>(blob: &'a [u8], name: &str) -> Result<&'a [u8], AdBlobError> {
    // The fixed part and the final `Reserved5`.
    const HEADER: usize = 110;
    if blob.len() < HEADER + 1 {
        return Err(AdBlobError::NotUserProperties);
    }
    // `Length` counts from offset 12 up to, but not including, `Reserved5`.
    if u32_at(blob, 4) as usize != blob.len() - 13 {
        return Err(AdBlobError::NotUserProperties);
    }
    if u16_at(blob, 8) != 1 || u16_at(blob, 108) != PROPERTY_SIGNATURE {
        return Err(AdBlobError::NotUserProperties);
    }
    // No `PropertyCount` field at all when there is nothing to count.
    if blob.len() == HEADER + 1 {
        return Err(AdBlobError::MissingProperty);
    }
    if blob.len() < HEADER + 3 {
        return Err(AdBlobError::NotUserProperties);
    }
    let count = u16_at(blob, HEADER) as usize;
    let end = blob.len() - 1;
    let mut at = HEADER + 2;
    for _ in 0..count {
        if at + 6 > end {
            return Err(AdBlobError::Inconsistent);
        }
        let name_len = u16_at(blob, at) as usize;
        let value_len = u16_at(blob, at + 2) as usize;
        let start = at + 6;
        let stop = start
            .checked_add(name_len)
            .and_then(|s| s.checked_add(value_len))
            .ok_or(AdBlobError::Inconsistent)?;
        if stop > end {
            return Err(AdBlobError::Inconsistent);
        }
        let raw_name = &blob[start..start + name_len];
        let value = &blob[start + name_len..stop];
        at = stop;
        if utf16(raw_name)? == name {
            return Ok(value);
        }
    }
    Err(AdBlobError::MissingProperty)
}

/// UTF-16LE text, which is how `USER_PROPERTY` spells both its name and value.
fn utf16(bytes: &[u8]) -> Result<String, AdBlobError> {
    if !bytes.len().is_multiple_of(2) {
        return Err(AdBlobError::Inconsistent);
    }
    let units: Vec<u16> = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes(*c))
        .collect();
    String::from_utf16(&units).map_err(|_| AdBlobError::Inconsistent)
}

/// Hexadecimal text back to octets: the inverse of [`hex_lower`], and as strict.
fn unhex(text: &[u8]) -> Result<Vec<u8>, AdBlobError> {
    if !text.len().is_multiple_of(2) {
        return Err(AdBlobError::NotHex);
    }
    let digit = |b: u8| -> Result<u8, AdBlobError> {
        match b {
            b'0'..=b'9' => Ok(b - b'0'),
            b'a'..=b'f' => Ok(b - b'a' + 10),
            b'A'..=b'F' => Ok(b - b'A' + 10),
            _ => Err(AdBlobError::NotHex),
        }
    };
    let mut out = Vec::with_capacity(text.len() / 2);
    for pair in text.as_chunks::<2>().0 {
        out.push(digit(pair[0])? << 4 | digit(pair[1])?);
    }
    Ok(out)
}

fn u16_at(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([bytes[at], bytes[at + 1]])
}

fn u32_at(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
}

/// Lowercase hexadecimal, which is the spelling AD uses in `PropertyValue`.
fn hex_lower(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    out
}

/// The enctypes AD's `KERBEROS_TYPE` table names, for a reader that prints them.
///
/// Not used by the encoder — the blob carries the numbers — but a log line that
/// says `aes256-cts-hmac-sha1-96` beats one that says `18`.
pub fn ad_enctype_name(enctype: Enctype) -> &'static str {
    match enctype {
        Enctype::Aes128Sha1 => "aes128-cts-hmac-sha1-96",
        Enctype::Aes256Sha1 => "aes256-cts-hmac-sha1-96",
        Enctype::Aes128Sha256 => "aes128-cts-hmac-sha256-128",
        Enctype::Aes256Sha384 => "aes256-cts-hmac-sha384-192",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::OwnCipher;
    use crate::hdb::HdbEntry;
    use crate::name::Principal;

    fn entry() -> HdbEntry {
        let mut entry = HdbEntry::user(Principal::parse("alice@EXAMPLE.COM").unwrap());
        for enctype in Enctype::ALL {
            entry
                .add_password_key(&OwnCipher, enctype, b"a password", 1)
                .unwrap();
        }
        entry
    }

    /// Reads the little-endian fields a reader would read.
    fn u16_at(bytes: &[u8], at: usize) -> u16 {
        u16::from_le_bytes([bytes[at], bytes[at + 1]])
    }
    fn u32_at(bytes: &[u8], at: usize) -> u32 {
        u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
    }

    #[test]
    fn the_envelope_is_the_shape_the_specification_describes() {
        let blob = supplemental_credentials(&entry());
        assert_eq!(u32_at(&blob, 0), 0, "Reserved1 must be zero");
        assert_eq!(u16_at(&blob, 8), 1, "Reserved2 must be 1");
        assert_eq!(u16_at(&blob, 10), 0, "Reserved3 must be zero");
        assert!(
            blob[12..108].iter().all(|b| *b == 0),
            "Reserved4 is 96 zero octets"
        );
        assert_eq!(u16_at(&blob, 108), 0x50, "PropertySignature");
        assert_eq!(u16_at(&blob, 110), 1, "one property");
        // `Length` counts from offset 12 up to the final Reserved5 octet.
        assert_eq!(
            u32_at(&blob, 4) as usize,
            blob.len() - 13,
            "the length field is not the length of the blob"
        );
        assert_eq!(*blob.last().unwrap(), 0, "Reserved5 must be zero");
    }

    #[test]
    fn an_empty_blob_is_111_octets_because_the_count_is_omitted() {
        // The one shape a caller would get wrong by analogy: with no properties
        // there is no PropertyCount field at all.
        let blob = empty_supplemental_credentials();
        assert_eq!(blob.len(), 111);
        assert_eq!(u32_at(&blob, 4) as usize, blob.len() - 13);
        assert_eq!(u16_at(&blob, 108), 0x50);
        assert_eq!(*blob.last().unwrap(), 0);
    }

    #[test]
    fn the_property_name_is_utf16_and_the_value_is_hexadecimal_text() {
        let blob = supplemental_credentials(&entry());
        let name_len = u16_at(&blob, 112) as usize;
        let value_len = u16_at(&blob, 114) as usize;
        let name: Vec<u16> = blob[118..118 + name_len]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_le_bytes(*c))
            .collect();
        assert_eq!(
            String::from_utf16(&name).unwrap(),
            PROPERTY_KERBEROS_NEWER_KEYS
        );
        let value = &blob[118 + name_len..118 + name_len + value_len];
        assert!(
            value.iter().all(|b| b.is_ascii_hexdigit()),
            "the property value is the hexadecimal text of the octets"
        );
        assert_eq!(value.len() % 2, 0);
        // Revision 4 of KERB_STORED_CREDENTIAL_NEW, decoded from the hex.
        assert_eq!(&value[..4], b"0400", "Revision 4, little-endian");
    }

    #[test]
    fn every_key_of_the_entry_reaches_the_structure() {
        let entry = entry();
        let blob = kerberos_newer_keys(&entry);
        assert_eq!(u16_at(&blob, 0), 4, "Revision");
        assert_eq!(u16_at(&blob, 4), 4, "CredentialCount: four enctypes");
        assert_eq!(u16_at(&blob, 6), 0, "no service credentials");
        assert_eq!(u16_at(&blob, 8), 0, "no old credentials at kvno 1");

        let salt_len = u16_at(&blob, 12) as usize;
        let salt_offset = u32_at(&blob, 16) as usize;
        assert!(
            blob.len() >= salt_offset + salt_len,
            "the default salt must be inside the buffer"
        );
        assert_eq!(salt_offset, 24 + 4 * 24, "the salt follows the key array");

        for i in 0..4 {
            let at = 24 + i * 24;
            let enctype = u32_at(&blob, at + 12);
            let key_len = u32_at(&blob, at + 16) as usize;
            let key_offset = u32_at(&blob, at + 20) as usize;
            let key = &blob[key_offset..key_offset + key_len];
            let held = entry
                .key_for(Enctype::from_id(enctype as i32).unwrap())
                .unwrap();
            assert_eq!(
                key,
                held.key.bytes(),
                "the key at {key_offset} must be the entry's key for enctype {enctype}"
            );
        }
    }

    #[test]
    fn a_rotation_puts_each_generation_where_ad_keeps_it() {
        let rotated = entry().rekey(&OwnCipher, b"a new password").unwrap();
        let blob = kerberos_newer_keys(&rotated);
        assert_eq!(u16_at(&blob, 4), 4, "four current keys, at the new kvno");
        assert_eq!(u16_at(&blob, 6), 0, "no service credentials");
        assert_eq!(u16_at(&blob, 8), 4, "four old ones, from the previous kvno");
        assert_eq!(u16_at(&blob, 10), 0, "and nothing two generations back yet");

        let twice = rotated.rekey(&OwnCipher, b"a third password").unwrap();
        let blob = kerberos_newer_keys(&twice);
        assert_eq!(u16_at(&blob, 4), 4, "current");
        assert_eq!(u16_at(&blob, 8), 4, "one generation back");
        assert_eq!(u16_at(&blob, 10), 4, "and two, which it can still name");
    }

    #[test]
    fn a_generation_ad_cannot_name_is_left_out_rather_than_mislabelled() {
        // Three rotations leave four generations; the structure has room for three.
        // Folding the oldest into `older` would state a generation that is not
        // there, so it is dropped — which is what AD does when it prunes.
        let mut entry = entry();
        entry.etypes = None;
        let mut rolling = entry.rekey(&OwnCipher, b"b").unwrap();
        rolling = rolling.rekey(&OwnCipher, b"c").unwrap();
        rolling = rolling.rekey(&OwnCipher, b"d").unwrap();
        assert_eq!(rolling.keys.len(), 16, "four generations of four enctypes");
        let blob = kerberos_newer_keys(&rolling);
        let named = u16_at(&blob, 4) as usize
            + u16_at(&blob, 6) as usize
            + u16_at(&blob, 8) as usize
            + u16_at(&blob, 10) as usize;
        assert_eq!(named, 12, "three generations, twelve keys, and no more");
    }

    #[test]
    fn the_blob_is_the_same_octets_on_every_call() {
        // A projection that shuffles between reads cannot be checksummed, and an
        // operator comparing two dumps would see a change that did not happen.
        let entry = entry();
        assert_eq!(
            supplemental_credentials(&entry),
            supplemental_credentials(&entry)
        );
    }

    #[test]
    fn an_entry_with_no_keys_still_produces_a_readable_structure() {
        // Not a failure: the account exists and has no keys yet, which AD can say
        // and a reader must not choke on.
        let entry = HdbEntry::user(Principal::parse("svc@EXAMPLE.COM").unwrap());
        let blob = supplemental_credentials(&entry);
        assert_eq!(u16_at(&blob, 110), 1, "the property is present");
        let inner = kerberos_newer_keys(&entry);
        assert_eq!(u16_at(&inner, 4), 0, "no credentials");
        assert_eq!(u16_at(&inner, 8), 0);
    }

    #[test]
    fn the_reader_returns_the_keys_the_writer_wrote() {
        let entry = entry();
        let blob = supplemental_credentials(&entry);
        let read = credentials(&blob).unwrap();
        assert_eq!(read.len(), 4, "one key per enctype");
        for (i, credential) in read.iter().enumerate() {
            let held = entry.key_for(credential.enctype).unwrap();
            assert_eq!(
                credential.key,
                held.key.bytes(),
                "key {i} must come back byte for byte"
            );
            assert_eq!(
                credential.salt.as_deref(),
                held.salt.as_deref(),
                "the entry's one salt is the blob's default salt"
            );
        }
    }

    #[test]
    fn a_rotation_reads_back_as_both_generations() {
        // The blob names three generations and the reader returns them in one
        // list: which is current comes from `msDS-KeyVersionNumber`, not from the
        // blob, which has no field for it.
        let rotated = entry().rekey(&OwnCipher, b"a new password").unwrap();
        let blob = supplemental_credentials(&rotated);
        let read = credentials(&blob).unwrap();
        assert_eq!(read.len(), 8, "four current and four old keys");
        let at_two = keys(&blob, 2).unwrap();
        assert!(
            at_two.iter().all(|k| k.kvno == 2),
            "the version is the caller's, since the blob cannot carry one"
        );
        assert_eq!(at_two.len(), 8);
    }

    #[test]
    fn an_entry_with_no_keys_reads_back_as_no_keys() {
        let entry = HdbEntry::user(Principal::parse("svc@EXAMPLE.COM").unwrap());
        assert!(
            credentials(&supplemental_credentials(&entry))
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn an_empty_blob_says_there_is_no_property_rather_than_no_keys() {
        // The two are different facts — "this account's keys are not here" versus
        // "this account has none" — and the reader keeps them apart.
        assert_eq!(
            credentials(&empty_supplemental_credentials()),
            Err(AdBlobError::MissingProperty)
        );
    }

    #[test]
    fn a_blob_that_is_not_user_properties_is_refused() {
        let full = supplemental_credentials(&entry());
        // Truncated: the length field no longer describes the buffer.
        assert_eq!(
            credentials(&full[..full.len() - 1]),
            Err(AdBlobError::NotUserProperties)
        );
        // Signature tampered with.
        let mut wrong = full.clone();
        wrong[108] = 0x51;
        assert_eq!(credentials(&wrong), Err(AdBlobError::NotUserProperties));
        // Shorter than the fixed part.
        assert_eq!(
            credentials(&full[..40]),
            Err(AdBlobError::NotUserProperties)
        );
    }

    #[test]
    fn a_property_value_that_is_not_hexadecimal_is_refused() {
        let mut blob = supplemental_credentials(&entry());
        let name_len = u16_at(&blob, 112) as usize;
        let value_at = 118 + name_len;
        blob[value_at] = b'z';
        assert_eq!(credentials(&blob), Err(AdBlobError::NotHex));
    }

    #[test]
    fn an_unknown_revision_is_refused_instead_of_read() {
        // Revision 3 has a different layout; reading it as revision 4 would take
        // key material from the wrong offsets and produce a key that decrypts
        // nothing, long after the reason is gone.
        let mut blob = supplemental_credentials(&entry());
        let name_len = u16_at(&blob, 112) as usize;
        let value_at = 118 + name_len;
        // First two octets of the hex text are the revision's low byte.
        blob[value_at..value_at + 4].copy_from_slice(b"0300");
        assert_eq!(credentials(&blob), Err(AdBlobError::UnknownRevision(3)));
    }

    #[test]
    fn a_key_offset_outside_the_buffer_is_refused() {
        let mut blob = supplemental_credentials(&entry());
        let name_len = u16_at(&blob, 112) as usize;
        let value_at = 118 + name_len;
        // The first `KERB_KEY_DATA_NEW` starts at octet 24 of the credential, and
        // its key offset is at +20: hex text position 2 * (24 + 20).
        let at = value_at + 2 * (CREDENTIAL_HEADER + 20);
        blob[at..at + 8].copy_from_slice(b"ffff7f00");
        assert_eq!(credentials(&blob), Err(AdBlobError::Inconsistent));
    }

    #[test]
    fn an_unknown_enctype_is_refused_by_number() {
        let mut blob = supplemental_credentials(&entry());
        let name_len = u16_at(&blob, 112) as usize;
        let value_at = 118 + name_len;
        // Enctype is at +12 of the key entry.
        let at = value_at + 2 * (CREDENTIAL_HEADER + 12);
        blob[at..at + 8].copy_from_slice(b"17000000");
        assert_eq!(credentials(&blob), Err(AdBlobError::UnknownEnctype(23)));
    }

    #[test]
    fn a_key_of_the_wrong_length_is_refused() {
        // An AES-256 key is 32 octets; a structure that says 31 must not become a
        // key that nothing can decrypt with. Which enctype the first entry holds
        // depends on the sort order, so the assertion is about the length.
        let mut blob = supplemental_credentials(&entry());
        let name_len = u16_at(&blob, 112) as usize;
        let value_at = 118 + name_len;
        let at = value_at + 2 * (CREDENTIAL_HEADER + 16);
        blob[at..at + 8].copy_from_slice(b"1f000000");
        match credentials(&blob) {
            Err(AdBlobError::BadKeyLength(_, len)) => assert_eq!(len, 31),
            other => panic!("expected a refused key length, got {other:?}"),
        }
    }

    /// The NT hash travels beside the keys, and the keys survive the company.
    ///
    /// One attribute, one `USER_PROPERTIES`: a second write would replace the first, and what it
    /// replaced is the blob the KDC reads its keys from.
    #[test]
    fn the_nt_hash_shares_the_blob_with_the_keys() {
        let cipher = OwnCipher;
        let mut entry = HdbEntry::user(
            crate::name::Principal::parse("SAMBA$@EXAMPLE.COM").expect("a principal"),
        );
        entry
            .add_password_key(&cipher, Enctype::Aes256Sha1, b"machine-password", 1)
            .expect("a key");
        let nt: [u8; 16] = std::array::from_fn(|i| i as u8 * 3);

        let blob = supplemental_credentials_with_nt(&entry, &nt);

        let hash = property_value(&blob, PROPERTY_NT_HASH).expect("the hash is there");
        assert_eq!(
            unhex(hash).expect("hex"),
            nt.to_vec(),
            "the hash reads back as itself"
        );
        assert_eq!(
            credentials(&blob).expect("the keys still read back").len(),
            1,
            "the Kerberos property is not shadowed by the second one"
        );
        assert_eq!(
            property_value(&blob, PROPERTY_KERBEROS_NEWER_KEYS).expect("the keys are there"),
            hex_lower(&kerberos_newer_keys(&entry)).as_bytes()
        );
    }

    /// The count travels where a reader looks for it, and the length is consistent with the size.
    ///
    /// Offsets rather than a sentence: the header is 108 octets, then the signature pair, then the
    /// count. A count written one field early is read as the signature, and the reader then believes
    /// the blob holds eighty properties.
    #[test]
    fn the_property_count_sits_after_the_signature() {
        let one = user_properties(&[(PROPERTY_NT_HASH, &[0xab; 16])]);
        assert_eq!(u16_at(&one, 108), PROPERTY_SIGNATURE);
        assert_eq!(u16_at(&one, 110), 1);

        let two = user_properties(&[
            (PROPERTY_KERBEROS_NEWER_KEYS, &[1, 2, 3]),
            (PROPERTY_NT_HASH, &[0xab; 16]),
        ]);
        assert_eq!(u16_at(&two, 110), 2);

        for blob in [&one, &two] {
            assert_eq!(
                u32_at(blob, 4) as usize,
                blob.len() - 13,
                "Length counts from offset 12 to the octet before Reserved5"
            );
        }
    }
}
