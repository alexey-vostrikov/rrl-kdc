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
//! the entry, never read back, and never the place a key lives. If it fails, an
//! account still logs in; only the AD-shaped view of it is missing. That is the
//! whole reason the plan refused to make the AD blob the canonical form — it is
//! written by us and read by strangers, so a defect in it must not be able to cost
//! anybody a login.
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

/// `USER_PROPERTIES`'s signature octet pair ([MS-SAMR] §2.2.10.1).
const PROPERTY_SIGNATURE: u16 = 0x0050;

/// `KERB_STORED_CREDENTIAL_NEW`'s revision, the one Windows 2008 and later write.
const REVISION_NEW: u16 = 4;

/// The string-to-key iteration count this crate uses for the enctypes that have
/// one. Recorded because the structure has a field for it; the keys themselves
/// are what a reader uses.
const ITERATION_COUNT: u32 = 4096;

/// `supplementalCredentials` for `entry`.
///
/// One property, `Primary:Kerberos-Newer-Keys`, with the entry's current keys as
/// the credentials and its older ones as the old credentials — which is the
/// distinction AD draws and the reason a rotation is representable at all.
pub fn supplemental_credentials(entry: &HdbEntry) -> Vec<u8> {
    let value = kerberos_newer_keys(entry);
    // `PropertyValue` is a string, and AD's string holds the hexadecimal text of
    // the octets. A reader that expects binary here finds an odd length and stops.
    let hex = hex_lower(&value);
    let name: Vec<u8> = PROPERTY_KERBEROS_NEWER_KEYS
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();

    let mut property = Vec::with_capacity(6 + name.len() + hex.len());
    property.extend_from_slice(&(name.len() as u16).to_le_bytes());
    property.extend_from_slice(&(hex.len() as u16).to_le_bytes());
    property.extend_from_slice(&0u16.to_le_bytes()); // Reserved
    property.extend_from_slice(&name);
    property.extend_from_slice(hex.as_bytes());

    let mut out = Vec::with_capacity(112 + property.len());
    out.extend_from_slice(&0u32.to_le_bytes()); // Reserved1
    // Filled in below: it counts from offset 12 up to `Reserved5`, which the
    // specification writes as the structure's length *minus* that last octet and
    // minus the twelve before it.
    out.extend_from_slice(&0u32.to_le_bytes()); // Length
    out.extend_from_slice(&1u16.to_le_bytes()); // Reserved2: MUST be 1
    out.extend_from_slice(&0u16.to_le_bytes()); // Reserved3
    out.extend_from_slice(&[0u8; 96]); // Reserved4
    out.extend_from_slice(&PROPERTY_SIGNATURE.to_le_bytes());
    out.extend_from_slice(&1u16.to_le_bytes()); // PropertyCount
    out.extend_from_slice(&property);
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
    const HEADER: usize = 24;
    // `KERB_KEY_DATA_NEW`: two 16-bit reserved fields, one 32-bit reserved, the
    // iteration count, then enctype, length and offset — six words, not four.
    const KEY_DATA: usize = 24;
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
}
