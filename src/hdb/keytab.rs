//! MIT's keytab file format.
//!
//! Reading it is how keys get into a KDC that has a database of its own: a
//! `krb5.keytab` written by MIT's `kadmin` or Heimdal's `ktutil` is the one
//! file every Kerberos installation already has. Writing it is how this crate
//! hands keys out — a service needs a keytab, not a database dump.
//!
//! The format is undocumented in the RFCs and defined only by the
//! implementations, so the details below are the ones MIT's `lib/krb5/keytab`
//! and Heimdal's `lib/krb5/keytab_file.c` agree on:
//!
//! ```text
//! file  := version entry*
//! version := 0x05 0x02            (v5.2; v5.1 has a 2-octet entry size)
//! entry := size:int32 entry-body
//! entry-body := num_components:uint16 realm:counted
//!               component:counted × num_components
//!               name_type:uint32 timestamp:uint32 vno8:uint8
//!               enctype:uint16 keylen:uint16 key:keylen
//! counted := len:uint16 octets
//! ```
//!
//! A negative `size` is a hole — an entry that was deleted without compacting
//! the file — and is skipped rather than treated as corruption, because a
//! keytab that has been edited in place has them.

use std::io::Read;
use std::path::Path;

use crate::crypto::{Enctype, Key};
use crate::error::{Error, Result};
use crate::name::Principal;

/// The 16-bit version prefix of a v5.1 keytab.
const VERSION_51: u16 = 0x0501;
/// The 16-bit version prefix of a v5.2 keytab, which this crate writes.
const VERSION_52: u16 = 0x0502;

/// One key of a keytab.
#[derive(Clone, Debug)]
pub struct KeytabEntry {
    /// The principal the key belongs to.
    pub principal: Principal,
    /// The key.
    pub key: Key,
    /// The key version.
    pub kvno: u32,
    /// The time the key was created, in seconds since the epoch.
    pub timestamp: u32,
}

/// A keytab: a bag of keys, readable and writable.
#[derive(Clone, Debug, Default)]
pub struct Keytab {
    entries: Vec<KeytabEntry>,
}

/// A byte reader that refuses to read past the buffer.
struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Cursor { data, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.pos + n > self.data.len() {
            return Err(Error::Hdb(format!(
                "keytab truncated: want {n} octets at {} of {}",
                self.pos,
                self.data.len()
            )));
        }
        let out = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(out)
    }

    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    fn u32(&mut self) -> Result<u32> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn counted(&mut self) -> Result<&'a [u8]> {
        let n = self.u16()? as usize;
        self.take(n)
    }

    fn is_empty(&self) -> bool {
        self.pos >= self.data.len()
    }
}

impl Keytab {
    /// A keytab with no entries.
    pub fn new() -> Self {
        Keytab::default()
    }

    /// Reads a keytab file.
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let mut file = std::fs::File::open(path)
            .map_err(|e| Error::Hdb(format!("cannot open {}: {e}", path.display())))?;
        let mut data = Vec::new();
        file.read_to_end(&mut data)
            .map_err(|e| Error::Hdb(format!("cannot read {}: {e}", path.display())))?;
        Self::parse(&data)
    }

    /// Parses keytab bytes.
    pub fn parse(data: &[u8]) -> Result<Self> {
        let mut c = Cursor::new(data);
        let version = c.u16()?;
        let size_len = match version {
            VERSION_52 => 4,
            VERSION_51 => 2,
            other => {
                return Err(Error::Hdb(format!(
                    "keytab version {other:#06x} is not one this crate reads (0x0501, 0x0502)"
                )));
            }
        };
        let mut entries = Vec::new();
        while !c.is_empty() {
            let raw_size = match size_len {
                4 => c.u32()? as i32,
                _ => c.u16()? as i16 as i32,
            };
            if raw_size < 0 {
                // A hole left by a deletion: skip its octets.
                c.take((-raw_size) as usize)?;
                continue;
            }
            let body = c.take(raw_size as usize)?;
            entries.push(Self::parse_entry(body)?);
        }
        Ok(Keytab { entries })
    }

    fn parse_entry(body: &[u8]) -> Result<KeytabEntry> {
        let mut c = Cursor::new(body);
        let num_components = c.u16()? as usize;
        let realm = String::from_utf8(c.counted()?.to_vec())
            .map_err(|_| Error::Hdb("keytab realm is not UTF-8".into()))?;
        let mut components = Vec::with_capacity(num_components);
        for _ in 0..num_components {
            components.push(
                String::from_utf8(c.counted()?.to_vec())
                    .map_err(|_| Error::Hdb("keytab component is not UTF-8".into()))?,
            );
        }
        if components.is_empty() {
            return Err(Error::Hdb("keytab entry has no name components".into()));
        }
        let name_type = c.u32()? as i32;
        let timestamp = c.u32()?;
        let kvno = c.u8()? as u32;
        let enctype_id = c.u16()? as i32;
        let enctype = Enctype::from_id(enctype_id).ok_or(Error::UnsupportedEnctype(enctype_id))?;
        let key_len = c.u16()? as usize;
        let key = Key::new(enctype, c.take(key_len)?)?;
        Ok(KeytabEntry {
            principal: Principal {
                name_type,
                components,
                realm,
            },
            key,
            kvno,
            timestamp,
        })
    }

    /// Writes the keytab as v5.2 bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&VERSION_52.to_be_bytes());
        for e in &self.entries {
            let mut body = Vec::new();
            body.extend_from_slice(&(e.principal.components.len() as u16).to_be_bytes());
            body.extend_from_slice(&(e.principal.realm.len() as u16).to_be_bytes());
            body.extend_from_slice(e.principal.realm.as_bytes());
            for c in &e.principal.components {
                body.extend_from_slice(&(c.len() as u16).to_be_bytes());
                body.extend_from_slice(c.as_bytes());
            }
            body.extend_from_slice(&(e.principal.name_type as u32).to_be_bytes());
            body.extend_from_slice(&e.timestamp.to_be_bytes());
            body.push(e.kvno as u8);
            body.extend_from_slice(&(e.key.enctype().id() as u16).to_be_bytes());
            body.extend_from_slice(&(e.key.len() as u16).to_be_bytes());
            body.extend_from_slice(e.key.bytes());
            out.extend_from_slice(&(body.len() as u32).to_be_bytes());
            out.extend_from_slice(&body);
        }
        out
    }

    /// Writes the keytab to a file.
    pub fn save(&self, path: impl AsRef<Path>) -> Result<()> {
        let path = path.as_ref();
        std::fs::write(path, self.to_bytes())
            .map_err(|e| Error::Hdb(format!("cannot write {}: {e}", path.display())))
    }

    /// Adds an entry.
    pub fn add(&mut self, entry: KeytabEntry) {
        self.entries.push(entry);
    }

    /// The entries, in file order.
    pub fn entries(&self) -> &[KeytabEntry] {
        &self.entries
    }

    /// Every key of `principal`, as an [`crate::hdb::HdbEntry`] holds them.
    pub fn keys_for(&self, principal: &Principal) -> Vec<&KeytabEntry> {
        self.entries
            .iter()
            .filter(|e| e.principal == *principal)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{Cipher, OwnCipher};
    use crate::hdb::{Hdb, HdbEntry, MemoryHdb};

    fn sample() -> Keytab {
        let cipher = OwnCipher;
        let mut kt = Keytab::new();
        kt.add(KeytabEntry {
            principal: Principal::parse("host/h.example.com@R").unwrap(),
            key: cipher.random(Enctype::Aes256Sha1).unwrap(),
            kvno: 3,
            timestamp: 1_700_000_000,
        });
        kt.add(KeytabEntry {
            principal: Principal::parse("host/h.example.com@R").unwrap(),
            key: cipher.random(Enctype::Aes128Sha1).unwrap(),
            kvno: 3,
            timestamp: 1_700_000_000,
        });
        kt
    }

    #[test]
    fn round_trips_through_the_file_format() {
        let kt = sample();
        let bytes = kt.to_bytes();
        assert_eq!(&bytes[..2], &[0x05, 0x02]);
        let back = Keytab::parse(&bytes).unwrap();
        assert_eq!(back.entries().len(), 2);
        assert_eq!(
            back.entries()[0].principal,
            Principal::parse("host/h.example.com@R").unwrap()
        );
        assert_eq!(back.entries()[0].kvno, 3);
        assert_eq!(back.entries()[0].key, kt.entries()[0].key);
        assert_eq!(back.entries()[1].key, kt.entries()[1].key);
    }

    #[test]
    fn reads_a_v5_1_file_with_16_bit_sizes() {
        // Build the same entry with a v5.1 header and a 16-bit length.
        let v52 = sample().to_bytes();
        let mut body = v52[6..].to_vec();
        body.truncate(u32::from_be_bytes([v52[2], v52[3], v52[4], v52[5]]) as usize);
        let mut v51 = Vec::new();
        v51.extend_from_slice(&VERSION_51.to_be_bytes());
        v51.extend_from_slice(&(body.len() as u16).to_be_bytes());
        v51.extend_from_slice(&body);
        let back = Keytab::parse(&v51).unwrap();
        assert_eq!(back.entries().len(), 1);
    }

    #[test]
    fn a_hole_is_skipped_not_refused() {
        let kt = sample();
        let second = kt.entries()[1].key.clone();
        let mut bytes = kt.to_bytes();
        // Delete the first entry by turning its size negative.
        let size = u32::from_be_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]);
        let neg = (-(size as i32)).to_be_bytes();
        bytes[2..6].copy_from_slice(&neg);
        let back = Keytab::parse(&bytes).unwrap();
        assert_eq!(back.entries().len(), 1, "the hole hides one entry");
        assert_eq!(
            back.entries()[0].key,
            second,
            "the surviving entry is the second one"
        );
    }

    #[test]
    fn a_truncated_file_is_an_error_not_a_panic() {
        let bytes = sample().to_bytes();
        for cut in 1..bytes.len().min(40) {
            let _ = Keytab::parse(&bytes[..bytes.len() - cut]);
        }
        assert!(Keytab::parse(&[0x05, 0x02, 0, 0, 0, 40]).is_err());
        assert!(Keytab::parse(&[0x05, 0x03]).is_err(), "unknown version");
    }

    #[test]
    fn a_keytab_fills_a_database() {
        let kt = sample();
        let db = MemoryHdb::new();
        let mut entry = HdbEntry::service(Principal::parse("host/h.example.com@R").unwrap());
        for e in kt.keys_for(&entry.principal) {
            entry.add_key(e.key.clone(), e.kvno, None);
        }
        db.insert(entry).unwrap();
        let fetched = db
            .fetch(&Principal::parse("host/h.example.com@R").unwrap())
            .unwrap()
            .unwrap();
        assert_eq!(fetched.keys.len(), 2);
        assert!(fetched.key_for(Enctype::Aes256Sha1).is_some());
    }
}
