//! The privilege attribute certificate: what a Windows client reads out of a
//! ticket.
//!
//! Kerberos proves who the client is. A PAC also claims **what that client may
//! do** — the SIDs it holds, when the logon stops being valid — and Windows
//! services take those claims from the ticket instead of asking a directory. An
//! AD world without a PAC is an AD world where every authorisation decision has
//! to be made somewhere else, which is why this module exists at all.
//!
//! # What is here, and what is not yet
//!
//! This module writes the **envelope**: `PAC_INFO_BUFFERS` in the order the
//! specification asks for, each buffer padded to an eight-octet boundary, and the
//! two signatures (`SERVER_CHECKSUM` over the service key, `PRIVSVR_CHECKSUM`
//! over the `krbtgt` key). The envelope is the part a reader uses to find
//! anything at all, and it is the part where every hand-built blob goes wrong:
//! offsets are counted from the start of the PAC, and a buffer that is not padded
//! puts every following offset four octets off.
//!
//! The logon information itself — `KERB_VALIDATION_INFO`, an NDR-encoded
//! structure naming the account's RID and its group SIDs — is **not** built here
//! yet. That is deliberate: it cannot be built from anything this crate knows.
//! The RIDs and the domain SID belong to the directory, and inventing them would
//! produce a PAC that says a client holds SIDs that mean nothing to the server
//! reading it. [`pac`] therefore takes the buffers it is given; a caller that has
//! an identity to state is the one that must state it.
//!
//! # Why the signatures are checked here and not by the reader
//!
//! `PRIVSVR_CHECKSUM` is an HMAC under the `krbtgt` key, and the service that
//! receives the ticket does not hold that key and must never hold it. The KDC
//! signs with it; the service checks `SERVER_CHECKSUM` with its own key and trusts
//! the ticket because it trusts the KDC that issued it. That boundary is the
//! reason the two checksums have different keys at all, and it is what [`seal`]
//! implements.
//!
//! # Reference
//!
//! [MS-PAC] §2.4 (buffers), §2.8.1 (signature), [MS-KILE] §3.4.5.1 (which key
//! signs what), RFC 4757 for the RC4-HMAC checksum's salt and key derivation.

use crate::crypto::{Enctype, Key};
use crate::error::{Error, Result};

/// `PAC_LOGON_INFO` — `KERB_VALIDATION_INFO`, the buffer that names the account.
pub const PAC_LOGON_INFO: u32 = 1;

/// `PAC_CLIENT_INFO` — the client's name and the logon time, in plain text.
///
/// Type **10**, not 2: `2` is `PAC_CREDENTIALS_INFO`, the encrypted blob NTLM
/// credentials travel in. Writing this buffer under type 2 would put a plain-text
/// name where a reader expects ciphertext, and the reader would refuse the whole
/// PAC — which is exactly how this was caught, by impacket reporting no client
/// info at all.
pub const PAC_CLIENT_INFO: u32 = 10;

/// `AD-IF-RELEVANT`: the authorization-data type whose payload may be skipped by a
/// reader that does not understand it.
pub const AD_IF_RELEVANT: i64 = 1;

/// `AD-WIN2K-PAC`: the entry that carries the PAC octets.
pub const AD_WIN2K_PAC: i64 = 128;

/// `PAC_SERVER_CHECKSUM` — the signature over the service key.
pub const PAC_SERVER_CHECKSUM: u32 = 6;

/// `PAC_PRIVSVR_CHECKSUM` — the signature over the `krbtgt` key.
pub const PAC_PRIVSVR_CHECKSUM: u32 = 7;

/// `KERB_CHECKSUM_HMAC_MD5`, the signature type AD writes when the service key is
/// RC4. Its value is negative in the specification, and it travels as a 32-bit
/// signed field, which is why this is an `i32` and not a `u32`.
pub const KERB_CHECKSUM_HMAC_MD5: i32 = -138;

/// `KERB_NON_KERB_CKSUM_SALT` — the key-derivation usage for a checksum that is
/// not a Kerberos one, which is what a PAC signature is. [MS-KILE] §3.4.5.1.1
/// names it, and getting it wrong produces a signature that verifies nowhere.
pub const KERB_NON_KERB_CKSUM_SALT: u32 = 17;

use super::logon_info::{FILETIME_TICKS_PER_SECOND, FILETIME_UNIX_EPOCH_SECONDS};

/// `PAC_CLIENT_INFO`: the client's name and logon time, unencrypted ([MS-PAC]
/// §2.7.2).
///
/// This is the buffer a service reads to learn who the ticket belongs to without
/// having the client's key — it is plain text inside a PAC whose integrity
/// the signature protects. Windows writes it in every ticket, and a reader that
/// finds no `PAC_CLIENT_INFO` treats the ticket as coming from something that is
/// not a Windows KDC.
///
/// Two details are where a hand-built one goes wrong:
///
/// * `NameLength` is the length **in octets**, not in characters. A name of six
///   characters is twelve octets, and a reader that trusts a character count finds
///   half a name and a stray octet.
/// * `ClientId` is a `FILETIME` — 100-nanosecond intervals since 1601 — not a Unix
///   timestamp and not a `time_t`. Writing the Unix value puts the logon in 1601.
pub fn client_info(name: &str, logon_time: i64) -> Result<Buffer> {
    let units: Vec<u16> = name.encode_utf16().collect();
    let octets = units.len() * 2;
    // `NameLength` is a `USHORT`, and the specification has no room for a longer
    // name. Truncating instead would write a name that is not the client's, which
    // is worse than refusing.
    if octets > u16::MAX as usize {
        return Err(Error::Protocol(format!(
            "a client name of {octets} octets does not fit in PAC_CLIENT_INFO's USHORT length"
        )));
    }
    let ticks = logon_time
        .checked_mul(FILETIME_TICKS_PER_SECOND)
        .and_then(|t| t.checked_add(FILETIME_UNIX_EPOCH_SECONDS * FILETIME_TICKS_PER_SECOND))
        .ok_or_else(|| {
            Error::Protocol(format!(
                "logon time {logon_time} is not representable as FILETIME"
            ))
        })?;
    let mut data = Vec::with_capacity(10 + octets);
    data.extend_from_slice(&ticks.to_le_bytes());
    data.extend_from_slice(&(octets as u16).to_le_bytes());
    for unit in units {
        data.extend_from_slice(&unit.to_le_bytes());
    }
    Ok(Buffer::new(PAC_CLIENT_INFO, data))
}

/// The name and logon time a `PAC_CLIENT_INFO` buffer states.
///
/// The read side exists for the same reason the writer does: a value this crate
/// writes should be one this crate can read back, and the test that compares the
/// two is what makes the octet-vs-character distinction a fact rather than a
/// comment.
pub fn parse_client_info(data: &[u8]) -> Result<(String, i64)> {
    // `ClientId` (8) plus `NameLength` (2), before any name at all.
    if data.len() < 10 {
        return Err(Error::Protocol(
            "a PAC_CLIENT_INFO shorter than its fixed part".into(),
        ));
    }
    let ticks = i64::from_le_bytes(data[0..8].try_into().expect("eight octets"));
    let octets = u16::from_le_bytes(data[8..10].try_into().expect("two octets")) as usize;
    // The name must occupy exactly what the length says: a trailing NUL or a pad
    // octet is not part of it, and accepting "at least this many" would let a
    // buffer whose length is wrong read as correct.
    if data.len() != 10 + octets {
        return Err(Error::Protocol(format!(
            "PAC_CLIENT_INFO says {octets} name octets but carries {}",
            data.len() - 10
        )));
    }
    if !octets.is_multiple_of(2) {
        return Err(Error::Protocol(format!(
            "a UTF-16 name of {octets} octets is not a whole number of units"
        )));
    }
    let units: Vec<u16> = data[10..]
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u16::from_le_bytes(*pair))
        .collect();
    let name = String::from_utf16(&units)
        .map_err(|_| Error::Protocol("PAC_CLIENT_INFO: the name is not UTF-16".into()))?;
    let seconds = ticks
        .checked_div(FILETIME_TICKS_PER_SECOND)
        .and_then(|s| s.checked_sub(FILETIME_UNIX_EPOCH_SECONDS))
        .ok_or_else(|| Error::Protocol("PAC_CLIENT_INFO: a FILETIME before 1601".into()))?;
    Ok((name, seconds))
}

/// One buffer of a PAC: its type and its payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Buffer {
    /// `PAC_INFO_BUFFER.ulType`.
    pub kind: u32,
    /// `PAC_INFO_BUFFER.cbBufferSize` and the payload itself.
    pub data: Vec<u8>,
}

impl Buffer {
    /// A buffer of `kind` carrying `data`.
    pub fn new(kind: u32, data: impl Into<Vec<u8>>) -> Self {
        Buffer {
            kind,
            data: data.into(),
        }
    }
}

/// The PAC envelope: `PACTYPE` and one `PAC_INFO_BUFFER` per buffer.
///
/// Offsets are counted from the first octet of the PAC — not from the first
/// buffer, and not from the end of the header — and every payload starts on an
/// eight-octet boundary. Both facts are in [MS-PAC] §2.3 and both are the kind a
/// reader notices only as "the last buffer is garbage".
///
/// The two signature buffers must be present: [`seal`] fills them in, and a PAC
/// with a missing one is a PAC every service refuses. They are added here with
/// empty payloads, and the sizes are fixed by the checksum type.
pub fn pac(buffers: &[Buffer]) -> Vec<u8> {
    // `PACTYPE` is two `ULONG`s, and each `PAC_INFO_BUFFER` is two `ULONG`s and a
    // `ULONGLONG`.
    const HEADER: usize = 8;
    const INFO: usize = 16;
    let table_end = HEADER + INFO * buffers.len();

    let mut out = Vec::with_capacity(table_end + 64);
    out.extend_from_slice(&(buffers.len() as u32).to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes()); // Version: MUST be zero
    // The table is written first with placeholder offsets, then the payloads, and
    // the offsets are filled in once each payload's position is known — computing
    // them up front means duplicating the padding rule, which is how the two
    // copies drift apart.
    let table_at = out.len();
    out.resize(table_at + INFO * buffers.len(), 0);

    let mut offset = table_end;
    for (i, buffer) in buffers.iter().enumerate() {
        let at = table_at + i * INFO;
        out[at..at + 4].copy_from_slice(&buffer.kind.to_le_bytes());
        out[at + 4..at + 8].copy_from_slice(&(buffer.data.len() as u32).to_le_bytes());
        // `cbBufferSize` counts the payload and not the padding, but the next
        // offset is computed from the padded length: a reader that adds the size
        // without the padding lands four octets into the next header.
        out[at + 8..at + 16].copy_from_slice(&(offset as u64).to_le_bytes());
        out.extend_from_slice(&buffer.data);
        let padded = (buffer.data.len() + 7) & !7;
        out.resize(out.len() + (padded - buffer.data.len()), 0);
        offset += padded;
    }
    out
}

/// Which checksum a signature buffer carries.
///
/// Only the two the specification pairs with the keys this crate holds: the
/// RC4-HMAC one AD uses for an RC4 key, and the AES ones for an AES key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureType {
    /// `KERB_CHECKSUM_HMAC_MD5` (−138): HMAC-MD5 over the exported RC4 key, 16
    /// octets.
    HmacMd5,
    /// `HMAC_SHA1_96_AES128` (15) / `HMAC_SHA1_96_AES256` (16): 12 octets.
    HmacSha1_96Aes(Enctype),
    /// `HMAC_SHA256_128_AES128` (0x13): 16 octets. A Windows 2016 shape, and
    /// impacket's checksum table does not carry it — the id and the length come from
    /// [MS-PAC] §2.8.1, and the unit tests pin them.
    HmacSha256_128Aes,
    /// `HMAC_SHA384_192_AES256` (0x14): 24 octets, same caveat.
    HmacSha384_192Aes,
}

impl SignatureType {
    /// The signature type a key of `enctype` signs with.
    ///
    /// The PAC signature is keyed by the ticket's service key, so its type follows
    /// that key: AES-SHA1 keys get the SHA1 checksums, AES-SHA2 keys the newer ones,
    /// and an RC4 key the HMAC-MD5 one. `None` for an enctype with no PAC signature
    /// — the caller refuses rather than writing a number no reader knows.
    pub fn for_enctype(enctype: Enctype) -> Option<Self> {
        match enctype {
            Enctype::Aes128Sha1 | Enctype::Aes256Sha1 => {
                Some(SignatureType::HmacSha1_96Aes(enctype))
            }
            // The AES-SHA2 checksums are names of their own rather than a family,
            // because their numbers are not adjacent and their MAC lengths differ.
            Enctype::Aes128Sha256 => Some(SignatureType::HmacSha256_128Aes),
            Enctype::Aes256Sha384 => Some(SignatureType::HmacSha384_192Aes),
        }
    }

    /// The number the buffer records.
    pub fn id(self) -> i32 {
        match self {
            SignatureType::HmacMd5 => KERB_CHECKSUM_HMAC_MD5,
            SignatureType::HmacSha1_96Aes(Enctype::Aes128Sha1) => 15,
            SignatureType::HmacSha1_96Aes(Enctype::Aes256Sha1) => 16,
            SignatureType::HmacSha1_96Aes(_) => -1,
            SignatureType::HmacSha256_128Aes => 0x13,
            SignatureType::HmacSha384_192Aes => 0x14,
        }
    }

    /// The signature length in octets.
    ///
    /// Named `signature_len` rather than `len`: a `len` without an `is_empty` is
    /// a question nobody can answer here, since no signature type is empty.
    pub fn signature_len(self) -> usize {
        match self {
            SignatureType::HmacMd5 => 16,
            SignatureType::HmacSha1_96Aes(_) => 12,
            SignatureType::HmacSha256_128Aes => 16,
            SignatureType::HmacSha384_192Aes => 24,
        }
    }

    /// The key enctype this signature is computed with, for the AES checksums.
    ///
    /// `None` for HMAC-MD5, whose key is an RC4 key this crate does not implement;
    /// the caller that reaches it has already decided the key is RC4.
    pub fn enctype(self) -> Option<Enctype> {
        match self {
            SignatureType::HmacSha1_96Aes(enctype) => Some(enctype),
            SignatureType::HmacSha256_128Aes => Some(Enctype::Aes128Sha256),
            SignatureType::HmacSha384_192Aes => Some(Enctype::Aes256Sha384),
            SignatureType::HmacMd5 => None,
        }
    }
}

/// Signs `pac` in place: fills `PAC_SERVER_CHECKSUM` and `PAC_PRIVSVR_CHECKSUM`.
///
/// `server_key` is the key of the service the ticket is for, `kdc_key` is the
/// `krbtgt` key. Both signatures cover the whole PAC with both signature buffers
/// zeroed, which is why this cannot be done while building it: the signature is
/// over a region that contains its own (empty) slot.
pub fn seal(
    pac: &mut [u8],
    server_key: &Key,
    kdc_key: &Key,
    signature: SignatureType,
) -> Result<()> {
    if signature.id() < 0 {
        // No reader knows this type, and writing the number anyway would produce a
        // PAC whose signature nobody can verify — a ticket that fails at the
        // service, long after the reason is gone.
        return Err(Error::Crypto(format!(
            "{:?} has no PAC signature type this crate can write",
            signature
        )));
    }
    let server_at = signature_slot(pac, PAC_SERVER_CHECKSUM, signature.signature_len())?;
    let kdc_at = signature_slot(pac, PAC_PRIVSVR_CHECKSUM, signature.signature_len())?;

    for at in [server_at, kdc_at] {
        pac[at..at + 4].copy_from_slice(&signature.id().to_le_bytes());
        pac[at + 4..at + 4 + signature.signature_len()].fill(0);
    }

    let server = sign(pac, server_key, signature)?;
    let kdc = sign(pac, kdc_key, signature)?;
    pac[server_at + 4..server_at + 4 + signature.signature_len()].copy_from_slice(&server);
    pac[kdc_at + 4..kdc_at + 4 + signature.signature_len()].copy_from_slice(&kdc);
    Ok(())
}

/// The signature over `pac`, which must already have both slots zeroed.
fn sign(pac: &[u8], key: &Key, signature: SignatureType) -> Result<Vec<u8>> {
    let tag = match signature {
        SignatureType::HmacMd5 => {
            // RC4-HMAC's key derivation is its own: the "key" is the exported key
            // of an RC4 key, and the salt is the usage number as a little-endian
            // word. This is what RFC 4757 defines and what every AD writes.
            let usage = KERB_NON_KERB_CKSUM_SALT.to_le_bytes();
            hmac_md5(key.bytes(), pac, &usage)?
        }
        SignatureType::HmacSha1_96Aes(_)
        | SignatureType::HmacSha256_128Aes
        | SignatureType::HmacSha384_192Aes => {
            let expected = signature.enctype().expect("an AES signature names its key");
            if key.enctype() != expected {
                return Err(Error::Crypto(format!(
                    "a PAC signed for {expected:?} was given a {:?} key",
                    key.enctype()
                )));
            }
            let kc = crate::crypto::kdf::derive_key(
                key.enctype(),
                key.bytes(),
                KERB_NON_KERB_CKSUM_SALT,
                crate::crypto::kdf::KeyUse::Checksum,
            )?;
            let full = hmac_for(key.enctype(), &kc, pac)?;
            full[..signature.signature_len()].to_vec()
        }
    };
    if tag.len() != signature.signature_len() {
        return Err(Error::Crypto(format!(
            "a {:?} signature is {} octets, not {}",
            signature,
            tag.len(),
            signature.signature_len()
        )));
    }
    Ok(tag)
}

/// The offset of the payload of the buffer of `kind`, refusing when it is absent
/// or its size is not the one the checksum type needs.
fn signature_slot(pac: &[u8], kind: u32, len: usize) -> Result<usize> {
    let Some(buffers) = buffers_of(pac) else {
        return Err(Error::Protocol("not a PAC_INFO_BUFFER table".into()));
    };
    for (buffer_kind, size, offset) in buffers {
        if buffer_kind == kind {
            // The payload begins after `SignatureType`, which is a 32-bit field.
            let payload = offset + 4;
            if size as usize != 4 + len || payload + len > pac.len() {
                return Err(Error::Protocol(format!(
                    "PAC buffer {kind} is {size} octets, not {}",
                    4 + len
                )));
            }
            return Ok(offset);
        }
    }
    Err(Error::Protocol(format!("the PAC has no buffer {kind}")))
}

/// `(kind, cbBufferSize, offset)` for each buffer, or `None` when the table does
/// not describe the buffer it arrived in.
fn buffers_of(pac: &[u8]) -> Option<Vec<(u32, u32, usize)>> {
    if pac.len() < 8 {
        return None;
    }
    let count = u32::from_le_bytes(pac[0..4].try_into().ok()?) as usize;
    let table_end = 8usize.checked_add(count.checked_mul(16)?)?;
    if table_end > pac.len() {
        return None;
    }
    let mut buffers = Vec::with_capacity(count);
    for i in 0..count {
        let at = 8 + i * 16;
        let kind = u32::from_le_bytes(pac[at..at + 4].try_into().ok()?);
        let size = u32::from_le_bytes(pac[at + 4..at + 8].try_into().ok()?);
        let offset = u64::from_le_bytes(pac[at + 8..at + 16].try_into().ok()?);
        let offset = usize::try_from(offset).ok()?;
        if offset.checked_add(size as usize)? > pac.len() {
            return None;
        }
        buffers.push((kind, size, offset));
    }
    Some(buffers)
}

/// `KERB_CHECKSUM_HMAC_MD5` as RFC 4757 §7 defines it, which is not a plain
/// HMAC-MD5 over the message.
///
/// Two steps, and skipping either produces a signature that verifies nowhere:
/// `Ksign = HMAC-MD5(key, "signaturekey\0")`, then
/// `MD5(usage little-endian || data)` is what gets HMACed under `Ksign`. The inner
/// MD5 is there so that a signature over a long message costs one hash of it, and
/// the usage word is little-endian because that is the wire order RC4-HMAC uses
/// everywhere else.
fn hmac_md5(key: &[u8], data: &[u8], usage: &[u8; 4]) -> Result<Vec<u8>> {
    use hmac::{Hmac, KeyInit, Mac};
    use md5::{Digest, Md5};
    const SIGNATURE_KEY: &[u8] = b"signaturekey\0";
    let mut ksign = <Hmac<Md5> as KeyInit>::new_from_slice(key)
        .map_err(|_| Error::Crypto("HMAC-MD5 key".into()))?;
    ksign.update(SIGNATURE_KEY);
    let ksign = ksign.finalize().into_bytes();

    let mut inner = Md5::new();
    inner.update(usage);
    inner.update(data);
    let digest = inner.finalize();

    let mut outer = <Hmac<Md5> as KeyInit>::new_from_slice(&ksign)
        .map_err(|_| Error::Crypto("HMAC-MD5 signature key".into()))?;
    outer.update(&digest);
    Ok(outer.finalize().into_bytes().to_vec())
}

/// HMAC with the hash the enctype pairs with: SHA-1 for the two SHA1 enctypes,
/// SHA-256 for `aes128-cts-hmac-sha256-128`, SHA-384 for the 192-bit one.
///
/// The PAC signature is the full HMAC truncated to the checksum's MAC length, so the
/// hash has to match the enctype the key belongs to — an AES-SHA2 key HMACed with
/// SHA-1 gives a signature that verifies nowhere.
fn hmac_for(enctype: Enctype, key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    use hmac::{Hmac, KeyInit, Mac};
    use sha1::Sha1;
    use sha2::{Sha256, Sha384};
    Ok(match enctype {
        Enctype::Aes128Sha1 | Enctype::Aes256Sha1 => {
            let mut m = <Hmac<Sha1> as KeyInit>::new_from_slice(key)
                .map_err(|_| Error::Crypto("HMAC-SHA1 key".into()))?;
            m.update(data);
            m.finalize().into_bytes().to_vec()
        }
        Enctype::Aes128Sha256 => {
            let mut m = <Hmac<Sha256> as KeyInit>::new_from_slice(key)
                .map_err(|_| Error::Crypto("HMAC-SHA256 key".into()))?;
            m.update(data);
            m.finalize().into_bytes().to_vec()
        }
        Enctype::Aes256Sha384 => {
            let mut m = <Hmac<Sha384> as KeyInit>::new_from_slice(key)
                .map_err(|_| Error::Crypto("HMAC-SHA384 key".into()))?;
            m.update(data);
            m.finalize().into_bytes().to_vec()
        }
    })
}

/// The `authorization-data` a ticket carries a PAC in.
///
/// A PAC travels inside `AD-IF-RELEVANT` so that a KDC which does not understand
/// it can ignore it, which is the whole point of that wrapper: the octets inside
/// are opaque to everything between the KDC and the service.
pub fn authorization_data(pac: &[u8]) -> Vec<u8> {
    // `AuthorizationData ::= SEQUENCE OF SEQUENCE { ad-type [0] Int32,
    // ad-data [1] OCTET STRING }`.
    //
    // The PAC travels two levels down: `AD-IF-RELEVANT` (type 1) whose `ad-data` is
    // itself an `AuthorizationData` holding one `AD-WIN2K-PAC` (type 128) entry with
    // the octets. Both levels are load-bearing and neither is decoration — a reader
    // looks for type 1, then decodes its payload as a sequence of entries and takes
    // the PAC from the first. Writing the PAC straight into the outer entry is the
    // shape this was first written in, and impacket rejected it as a tag it did not
    // expect, which is exactly what an unexpected nesting looks like from outside.
    let inner = crate::der::seq(&[authorization_entry(AD_WIN2K_PAC, pac)]);
    crate::der::seq(&[authorization_entry(AD_IF_RELEVANT, &inner)])
}

/// One `AuthorizationData` entry: `SEQUENCE { [0] ad-type, [1] ad-data }`.
fn authorization_entry(ad_type: i64, data: &[u8]) -> Vec<u8> {
    crate::der::seq(&[
        crate::der::field(0, crate::der::int(ad_type)),
        crate::der::field(1, crate::der::octets(data)),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body(kind: u32, len: usize) -> Buffer {
        Buffer::new(kind, vec![kind as u8; len])
    }

    fn sealed() -> (Vec<u8>, Key, Key) {
        let server = Key::new(Enctype::Aes256Sha1, vec![7u8; 32]).unwrap();
        let kdc = Key::new(Enctype::Aes256Sha1, vec![9u8; 32]).unwrap();
        let mut pac = pac(&[
            body(PAC_LOGON_INFO, 100),
            // `SignatureType` (4) plus the 12-octet AES signature.
            Buffer::new(PAC_SERVER_CHECKSUM, vec![0u8; 16]),
            Buffer::new(PAC_PRIVSVR_CHECKSUM, vec![0u8; 16]),
        ]);
        let signature = SignatureType::HmacSha1_96Aes(Enctype::Aes256Sha1);
        seal(&mut pac, &server, &kdc, signature).unwrap();
        (pac, server, kdc)
    }

    #[test]
    fn the_header_counts_the_buffers_and_names_the_version() {
        let pac = pac(&[body(PAC_LOGON_INFO, 5)]);
        assert_eq!(u32::from_le_bytes(pac[0..4].try_into().unwrap()), 1);
        assert_eq!(u32::from_le_bytes(pac[4..8].try_into().unwrap()), 0);
    }

    #[test]
    fn every_payload_starts_on_an_eight_octet_boundary() {
        // A payload of 5 octets pads to 8; the next offset must reflect that.
        let pac = pac(&[body(PAC_LOGON_INFO, 5), body(PAC_CLIENT_INFO, 3)]);
        let first = u64::from_le_bytes(pac[8 + 8..8 + 16].try_into().unwrap()) as usize;
        let second = u64::from_le_bytes(pac[24 + 8..24 + 16].try_into().unwrap()) as usize;
        assert_eq!(first, 8 + 2 * 16, "the first payload follows the table");
        assert_eq!(second, first + 8, "5 octets are padded to 8, not to 5");
        assert_eq!(second % 8, 0);
    }

    #[test]
    fn a_size_does_not_count_the_padding() {
        let pac = pac(&[body(PAC_LOGON_INFO, 5)]);
        let size = u32::from_le_bytes(pac[8 + 4..8 + 8].try_into().unwrap());
        assert_eq!(
            size, 5,
            "cbBufferSize is the payload, not the padded length"
        );
    }

    #[test]
    fn sealing_fills_both_signatures_and_they_differ() {
        let (pac, _, _) = sealed();
        let buffers = buffers_of(&pac).unwrap();
        let server = buffers
            .iter()
            .find(|(kind, _, _)| *kind == PAC_SERVER_CHECKSUM)
            .unwrap();
        let kdc = buffers
            .iter()
            .find(|(kind, _, _)| *kind == PAC_PRIVSVR_CHECKSUM)
            .unwrap();
        let server_sig = &pac[server.2 + 4..server.2 + 16];
        let kdc_sig = &pac[kdc.2 + 4..kdc.2 + 16];
        assert!(
            server_sig.iter().any(|b| *b != 0),
            "the signature is written"
        );
        assert!(
            kdc_sig.iter().any(|b| *b != 0),
            "the private signature is written"
        );
        assert_ne!(
            server_sig, kdc_sig,
            "two keys mean two signatures, or one of them is not being used"
        );
    }

    #[test]
    fn the_signature_types_are_the_ones_the_specification_names() {
        let (pac, _, _) = sealed();
        let buffers = buffers_of(&pac).unwrap();
        for (kind, _, offset) in buffers {
            if kind == PAC_SERVER_CHECKSUM || kind == PAC_PRIVSVR_CHECKSUM {
                let id = i32::from_le_bytes(pac[offset..offset + 4].try_into().unwrap());
                assert_eq!(id, 16, "HMAC-SHA1-96-AES256");
            }
        }
    }

    #[test]
    fn a_changed_host_makes_the_signature_invalid() {
        // The signature is over the whole PAC, so editing any buffer breaks it —
        // which is the only property that makes it worth anything.
        let (pac, server, _) = sealed();
        let signature = SignatureType::HmacSha1_96Aes(Enctype::Aes256Sha1);
        let server_at = signature_slot(&pac, PAC_SERVER_CHECKSUM, 12).unwrap();
        let expected = pac[server_at + 4..server_at + 16].to_vec();

        let mut edited = pac.clone();
        edited[8 + 2 * 16] ^= 0xff; // one octet of the logon info
        let server_at = signature_slot(&edited, PAC_SERVER_CHECKSUM, 12).unwrap();
        edited[server_at + 4..server_at + 16].fill(0);
        let recomputed = sign(&edited, &server, signature).unwrap();
        assert_ne!(recomputed, expected);
    }

    #[test]
    fn a_pac_without_a_signature_buffer_is_refused() {
        let mut pac = pac(&[body(PAC_LOGON_INFO, 5)]);
        let server = Key::new(Enctype::Aes256Sha1, vec![7u8; 32]).unwrap();
        let err = seal(
            &mut pac,
            &server,
            &server,
            SignatureType::HmacSha1_96Aes(Enctype::Aes256Sha1),
        );
        assert!(matches!(err, Err(Error::Protocol(_))), "{err:?}");
    }

    #[test]
    fn a_signature_buffer_of_the_wrong_size_is_refused() {
        let mut pac = pac(&[
            body(PAC_LOGON_INFO, 4),
            Buffer::new(PAC_SERVER_CHECKSUM, vec![0u8; 20]),
            Buffer::new(PAC_PRIVSVR_CHECKSUM, vec![0u8; 16]),
        ]);
        let key = Key::new(Enctype::Aes256Sha1, vec![7u8; 32]).unwrap();
        let err = seal(
            &mut pac,
            &key,
            &key,
            SignatureType::HmacSha1_96Aes(Enctype::Aes256Sha1),
        );
        assert!(matches!(err, Err(Error::Protocol(_))), "{err:?}");
    }

    #[test]
    fn a_key_of_the_wrong_enctype_is_refused_rather_than_used() {
        let mut pac = pac(&[
            body(PAC_LOGON_INFO, 4),
            Buffer::new(PAC_SERVER_CHECKSUM, vec![0u8; 16]),
            Buffer::new(PAC_PRIVSVR_CHECKSUM, vec![0u8; 16]),
        ]);
        let aes128 = Key::new(Enctype::Aes128Sha1, vec![7u8; 16]).unwrap();
        let err = seal(
            &mut pac,
            &aes128,
            &aes128,
            SignatureType::HmacSha1_96Aes(Enctype::Aes256Sha1),
        );
        assert!(matches!(err, Err(Error::Crypto(_))), "{err:?}");
    }

    #[test]
    fn the_rc4_signature_matches_impackets_implementation() {
        // Two vectors computed with impacket's `_HMACMD5.checksum`, which is an
        // independent implementation of RFC 4757 §7. A plain HMAC-MD5 over
        // `usage || data` gives a different answer, which is the mistake this
        // test exists to catch.
        let key = vec![0x07u8; 16];
        let usage = KERB_NON_KERB_CKSUM_SALT.to_le_bytes();
        assert_eq!(
            hmac_md5(&key, b"abc", &usage).unwrap(),
            hex("1513dea61516575fc6535e6dc5c5ea32")
        );
        assert_eq!(
            hmac_md5(&key, b"the quick brown fox jumps over the lazy dog", &usage).unwrap(),
            hex("bae5498ab01bc241b86fa90b518a2392")
        );
    }

    fn hex(text: &str) -> Vec<u8> {
        text.as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| {
                let s = std::str::from_utf8(pair).unwrap();
                u8::from_str_radix(s, 16).unwrap()
            })
            .collect()
    }

    #[test]
    fn every_enctype_names_the_signature_that_goes_with_it() {
        // The signature is keyed by the ticket's service key, so its type follows that
        // key's enctype. The numbers are from [MS-PAC] §2.8.1 and the lengths from the
        // checksums they name — impacket's table knows only 15 and 16, which is why
        // this table is pinned here rather than checked by an outside reader.
        for (enctype, id, len) in [
            (Enctype::Aes128Sha1, 15, 12),
            (Enctype::Aes256Sha1, 16, 12),
            (Enctype::Aes128Sha256, 0x13, 16),
            (Enctype::Aes256Sha384, 0x14, 24),
        ] {
            let signature = SignatureType::for_enctype(enctype).expect("every enctype has one");
            assert_eq!(signature.id(), id, "{enctype:?}");
            assert_eq!(signature.signature_len(), len, "{enctype:?}");
            assert_eq!(signature.enctype(), Some(enctype));
        }
        assert_eq!(SignatureType::HmacMd5.id(), KERB_CHECKSUM_HMAC_MD5);
        assert_eq!(SignatureType::HmacMd5.signature_len(), 16);
        assert_eq!(
            SignatureType::HmacMd5.enctype(),
            None,
            "an RC4 key is not one of this crate's enctypes"
        );
    }

    #[test]
    fn each_signature_verifies_under_its_own_key_and_not_the_other() {
        // The four AES cases, because a SHA2 key HMACed with SHA-1 produces a
        // signature that verifies nowhere and nothing else here would notice.
        for enctype in Enctype::ALL {
            let signature = SignatureType::for_enctype(enctype).unwrap();
            let len = signature.signature_len();
            let server = Key::new(enctype, vec![0x07u8; enctype.key_len()]).unwrap();
            let kdc = Key::new(enctype, vec![0x09u8; enctype.key_len()]).unwrap();
            let mut blob = pac(&[
                body(PAC_LOGON_INFO, 24),
                Buffer::new(PAC_SERVER_CHECKSUM, vec![0u8; 4 + len]),
                Buffer::new(PAC_PRIVSVR_CHECKSUM, vec![0u8; 4 + len]),
            ]);
            seal(&mut blob, &server, &kdc, signature).unwrap();
            let buffers = buffers_of(&blob).unwrap();
            let signature_of = |kind| {
                let (_, size, offset) = *buffers.iter().find(|(k, _, _)| *k == kind).unwrap();
                assert_eq!(size as usize, 4 + len);
                blob[offset + 4..offset + size as usize].to_vec()
            };
            assert_ne!(
                signature_of(PAC_SERVER_CHECKSUM),
                signature_of(PAC_PRIVSVR_CHECKSUM)
            );
            assert_eq!(
                i32::from_le_bytes(blob[buffers[1].2..buffers[1].2 + 4].try_into().unwrap()),
                signature.id()
            );
        }
    }

    #[test]
    fn the_buffer_types_are_the_numbers_the_specification_gives() {
        // Pinned because they are wire constants, and because getting one wrong is
        // silent: a `PAC_CLIENT_INFO` written under type 2 becomes
        // `PAC_CREDENTIALS_INFO`, so a reader looks for ciphertext where a name is
        // and refuses the whole PAC. That is how this happened the first time —
        // impacket reported no client info at all, and nothing in this crate
        // noticed.
        assert_eq!(PAC_LOGON_INFO, 1);
        assert_eq!(PAC_CLIENT_INFO, 10, "2 is PAC_CREDENTIALS_INFO");
        assert_eq!(PAC_SERVER_CHECKSUM, 6);
        assert_eq!(PAC_PRIVSVR_CHECKSUM, 7);
    }

    #[test]
    fn the_client_info_name_length_counts_octets_and_not_characters() {
        // The mistake this test exists for: a six-character name is twelve octets
        // of UTF-16, and a reader that believes a character count finds half a
        // name followed by a stray octet.
        let buffer = client_info("alice", 1_700_000_000).unwrap();
        assert_eq!(buffer.kind, PAC_CLIENT_INFO);
        assert_eq!(
            u16::from_le_bytes(buffer.data[8..10].try_into().unwrap()),
            10,
            "five characters, ten octets"
        );
        assert_eq!(buffer.data.len(), 20, "8 + 2 + ten octets of name");
    }

    #[test]
    fn a_name_with_an_accent_round_trips_through_utf16() {
        // Non-ASCII is where a length computed from `str::len()` would be right by
        // accident (octets, not characters) and one computed from `chars().count()`
        // wrong; the round trip is what tells them apart.
        for name in ["alice", "алексей", "Jörg", "日本語", "a😀b"] {
            let buffer = client_info(name, 1_700_000_000).unwrap();
            let (read, _) = parse_client_info(&buffer.data).unwrap();
            assert_eq!(read, name, "{name} must come back as itself");
        }
    }

    #[test]
    fn the_client_id_is_a_filetime_and_not_a_unix_time() {
        // One second after the Unix epoch is 11644473601 seconds of FILETIME, and
        // writing the Unix value would say 1601 — the failure a reader sees as "the
        // logon happened before the operating system existed".
        let buffer = client_info("alice", 1).unwrap();
        let ticks = i64::from_le_bytes(buffer.data[0..8].try_into().unwrap());
        assert_eq!(
            ticks,
            (FILETIME_UNIX_EPOCH_SECONDS + 1) * FILETIME_TICKS_PER_SECOND
        );
        assert_eq!(
            i64::from_le_bytes(
                client_info("alice", 0).unwrap().data[0..8]
                    .try_into()
                    .unwrap()
            ),
            FILETIME_UNIX_EPOCH_SECONDS * FILETIME_TICKS_PER_SECOND,
            "the Unix epoch is 11644473600 FILETIME seconds, not zero"
        );
    }

    #[test]
    fn a_logon_time_round_trips_to_the_second() {
        for seconds in [0i64, 1_700_000_000, 2_000_000_000, 4_000_000_000] {
            let buffer = client_info("alice", seconds).unwrap();
            let (_, read) = parse_client_info(&buffer.data).unwrap();
            assert_eq!(read, seconds, "{seconds} must survive the conversion");
        }
    }

    #[test]
    fn a_client_info_of_the_wrong_shape_is_refused() {
        let good = client_info("alice", 1_700_000_000).unwrap().data;
        // Shorter than the fixed part.
        assert!(parse_client_info(&good[..9]).is_err());
        // The length says more than the buffer carries.
        assert!(parse_client_info(&good[..good.len() - 2]).is_err());
        // A trailing octet the length does not account for — a NUL terminator
        // somebody added out of habit.
        let mut padded = good.clone();
        padded.push(0);
        assert!(
            parse_client_info(&padded).is_err(),
            "the name must be exactly what the length says, not at least"
        );
        // An odd length is not a whole number of UTF-16 units.
        let mut odd = good.clone();
        odd[8..10].copy_from_slice(&9u16.to_le_bytes());
        odd.truncate(19);
        assert!(parse_client_info(&odd).is_err());
    }

    #[test]
    fn a_name_too_long_for_the_length_field_is_refused_rather_than_truncated() {
        // Truncating would write a name that is not the client's, and the ticket
        // would claim an identity nobody holds.
        let long = "a".repeat(40_000);
        assert!(client_info(&long, 1_700_000_000).is_err());
    }

    #[test]
    fn the_client_info_survives_the_envelope_and_the_signature() {
        // What a service actually does: find the buffer by type, read it, and
        // trust it because the signature verified. If the envelope's padding were
        // counted in `cbBufferSize`, the buffer read back would carry eight zero
        // octets of padding and the length check would refuse it.
        let mut blob = pac(&[
            Buffer::new(PAC_LOGON_INFO, vec![0xaa; 60]),
            client_info("alice", 1_700_000_000).unwrap(),
            Buffer::new(PAC_SERVER_CHECKSUM, vec![0u8; 16]),
            Buffer::new(PAC_PRIVSVR_CHECKSUM, vec![0u8; 16]),
        ]);
        let server = Key::new(Enctype::Aes256Sha1, vec![7u8; 32]).unwrap();
        let kdc = Key::new(Enctype::Aes256Sha1, vec![9u8; 32]).unwrap();
        seal(
            &mut blob,
            &server,
            &kdc,
            SignatureType::HmacSha1_96Aes(Enctype::Aes256Sha1),
        )
        .unwrap();

        let found = buffers_of(&blob)
            .unwrap()
            .into_iter()
            .filter(|(kind, _, _)| *kind == PAC_CLIENT_INFO)
            .map(|(_, size, offset)| blob[offset..offset + size as usize].to_vec())
            .next()
            .expect("the client info is in the envelope");
        let (name, seconds) = parse_client_info(&found).unwrap();
        assert_eq!(name, "alice");
        assert_eq!(seconds, 1_700_000_000);
    }

    #[test]
    fn the_authorization_data_wraps_the_pac_twice_as_windows_does() {
        // Two levels, and both are read by every client: an `AD-IF-RELEVANT` (type 1)
        // entry whose `ad-data` is an `AuthorizationData` with one `AD-WIN2K-PAC`
        // (type 128) entry holding the octets.
        //
        // Writing the PAC straight into the outer entry is what this crate did first,
        // and impacket refused the ticket with a tag it did not expect. Parsing the
        // DER by hand here is deliberate: the point is the shape, and a test that
        // reused the encoder's own helper would agree with whatever the encoder did.
        let pac = pac(&[body(PAC_LOGON_INFO, 8)]);
        let ad = authorization_data(&pac);

        // The outer `AuthorizationData` is a SEQUENCE OF entries, so the reader walks
        // TLVs rather than fields: `Fields` reads `[n]`-tagged members of one
        // SEQUENCE, which is the level below.
        let entry = |bytes: &[u8]| -> (i64, Vec<u8>) {
            let mut r = crate::der::Reader::new(bytes);
            let sequence = r.next_tlv("entry").unwrap();
            assert_eq!(sequence.tag, 0x30, "an entry is a SEQUENCE");
            let fields = crate::der::Fields::parse("entry", sequence.content).unwrap();
            // Each field is `[n]` wrapping the value's own tag: `[0]` holds an
            // INTEGER, `[1]` an OCTET STRING, and the octets wanted are the content
            // of that inner TLV rather than its header.
            let integer = crate::der::Reader::new(fields.bytes(0, "entry").unwrap())
                .next_tlv("ad-type")
                .unwrap();
            assert_eq!(integer.tag, 0x02, "ad-type is an INTEGER");
            let data = crate::der::Reader::new(fields.bytes(1, "entry").unwrap())
                .next_tlv("ad-data")
                .unwrap();
            assert_eq!(data.tag, 0x04, "ad-data is an OCTET STRING");
            (read_int(integer.content), data.content.to_vec())
        };

        let outer = crate::der::Reader::new(&ad)
            .next_tlv("AuthorizationData")
            .unwrap();
        assert_eq!(outer.tag, 0x30);
        let (outer_type, outer_data) = entry(outer.content);
        assert_eq!(outer_type, 1, "AD-IF-RELEVANT");

        let inner = crate::der::Reader::new(&outer_data)
            .next_tlv("IfRelevant")
            .unwrap();
        assert_eq!(inner.tag, 0x30, "the payload is an AuthorizationData");
        let (inner_type, inner_data) = entry(inner.content);
        assert_eq!(inner_type, 128, "AD-WIN2K-PAC");
        assert_eq!(
            inner_data, pac,
            "the innermost ad-data is the PAC, verbatim"
        );
    }

    /// The value of a DER INTEGER as `i64`.
    fn read_int(bytes: &[u8]) -> i64 {
        let negative = bytes[0] & 0x80 != 0;
        let mut value: i64 = if negative { -1 } else { 0 };
        for byte in bytes {
            value = (value << 8) | i64::from(*byte);
        }
        value
    }
}
