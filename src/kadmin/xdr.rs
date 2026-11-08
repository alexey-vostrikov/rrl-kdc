//! XDR (RFC 4506) — the three primitives the `kadm5` protocol needs.
//!
//! Only what is used: a 4-octet unsigned, an opaque length-prefixed by it, and a
//! "null or value" boolean whose meaning is inverted (XDR's `xdr_pointer` writes
//! `TRUE` for *absent*). That last one is a real trap in this protocol: a
//! decoder that reads it as "present" finds a principal name where there is none
//! and reports a protocol error against a correct server.
//!
//! Everything is padded to four octets. A decoder that ignores the padding reads
//! the next field four octets early and produces a reply the peer cannot parse —
//! and because both sides are this crate's code in the unit tests, only a
//! third-party client finds it.

use crate::error::{Error, Result};

/// Reads XDR.
#[derive(Debug)]
pub struct Reader<'a> {
    data: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    /// A reader over `data`.
    pub fn new(data: &'a [u8]) -> Self {
        Reader { data, at: 0 }
    }

    /// How many octets are left.
    pub fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.at)
    }

    /// Whether everything was consumed. A decoder that stops early silently
    /// accepts a longer argument than it understood.
    pub fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    /// A 4-octet unsigned.
    pub fn u32(&mut self) -> Result<u32> {
        let end = self.at + 4;
        let bytes = self.data.get(self.at..end).ok_or_else(|| {
            Error::Protocol(format!(
                "XDR: wanted 4 octets at {}, {} left",
                self.at,
                self.remaining()
            ))
        })?;
        self.at = end;
        Ok(u32::from_be_bytes(bytes.try_into().expect("4 octets")))
    }

    /// A 2-octet unsigned, used by `krb5_tl_data`'s tag.
    pub fn u16(&mut self) -> Result<u16> {
        let end = self.at + 2;
        let bytes = self
            .data
            .get(self.at..end)
            .ok_or_else(|| Error::Protocol(format!("XDR: wanted 2 octets at {}", self.at)))?;
        self.at = end;
        Ok(u16::from_be_bytes(bytes.try_into().expect("2 octets")))
    }

    /// Skips one `krb5_tl_data`: a `u16` tag and an opaque.
    pub fn skip_tl_data(&mut self) -> Result<()> {
        self.u16()?;
        // The tag occupies four octets on the wire, not two: XDR pads it.
        let _ = self.u16()?;
        self.opaque()?;
        Ok(())
    }

    /// A 4-octet signed. The `kadm5` structures carry times as `int32`.
    pub fn i32(&mut self) -> Result<i32> {
        Ok(self.u32()? as i32)
    }

    /// An XDR boolean: 0 or 1, and anything else is a malformed stream rather
    /// than "true".
    pub fn bool(&mut self) -> Result<bool> {
        match self.u32()? {
            0 => Ok(false),
            1 => Ok(true),
            other => Err(Error::Protocol(format!("XDR: {other} is not a boolean"))),
        }
    }

    /// Length-prefixed opaque, padding skipped.
    pub fn opaque(&mut self) -> Result<&'a [u8]> {
        let len = self.u32()? as usize;
        let end = self.at + len;
        let bytes = self.data.get(self.at..end).ok_or_else(|| {
            Error::Protocol(format!(
                "XDR: opaque of {len} octets at {} runs past the end",
                self.at
            ))
        })?;
        // Four-octet padding, present even for a zero-length value.
        let padded = end + ((4 - (len % 4)) % 4);
        if padded > self.data.len() {
            return Err(Error::Protocol(format!(
                "XDR: opaque of {len} octets has no padding"
            )));
        }
        self.at = padded;
        Ok(bytes)
    }

    /// A NUL-terminated string, in the spelling `kadm5` uses for every name it
    /// carries: the octets end with `\0`, and an empty value means "absent".
    ///
    /// Not `string<*>`: MIT writes `xdr_string`-with-NUL here (`nullstring` in its
    /// client), so a decoder that strips no NUL leaves every principal name one
    /// octet too long and every parse fails.
    pub fn nullstring(&mut self) -> Result<Option<String>> {
        let bytes = self.opaque()?;
        match bytes.split_last() {
            None => Ok(None),
            Some((0, text)) => String::from_utf8(text.to_vec())
                .map(Some)
                .map_err(|_| Error::Protocol("XDR: a name is not UTF-8".into())),
            Some(_) => Err(Error::Protocol("XDR: a name is not NUL-terminated".into())),
        }
    }

    /// A `string<*>`: length-prefixed UTF-8.
    pub fn string(&mut self) -> Result<String> {
        let bytes = self.opaque()?;
        String::from_utf8(bytes.to_vec())
            .map_err(|_| Error::Protocol("XDR: a string is not UTF-8".into()))
    }

    /// A "may be absent" value, in XDR's `xdr_pointer` spelling: `1` means
    /// absent, `0` means a value follows.
    pub fn optional<T>(&mut self, read: impl FnOnce(&mut Self) -> Result<T>) -> Result<Option<T>> {
        if self.bool()? {
            Ok(None)
        } else {
            read(self).map(Some)
        }
    }

    /// Everything left, for a caller that has to look at the tail.
    pub fn rest(&mut self) -> &'a [u8] {
        let rest = &self.data[self.at..];
        self.at = self.data.len();
        rest
    }
}

/// Writes XDR.
#[derive(Debug, Default)]
pub struct Writer {
    bytes: Vec<u8>,
}

impl Writer {
    /// An empty writer.
    pub fn new() -> Self {
        Writer::default()
    }

    /// The octets written.
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    /// The octets written, borrowed.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// A 4-octet unsigned.
    pub fn u32(&mut self, v: u32) -> &mut Self {
        self.bytes.extend_from_slice(&v.to_be_bytes());
        self
    }

    /// A 4-octet signed.
    pub fn i32(&mut self, v: i32) -> &mut Self {
        self.bytes.extend_from_slice(&v.to_be_bytes());
        self
    }

    /// An XDR boolean.
    pub fn bool(&mut self, v: bool) -> &mut Self {
        self.u32(u32::from(v))
    }

    /// A "may be absent" marker: `1` for absent.
    pub fn absent(&mut self) -> &mut Self {
        self.u32(1)
    }

    /// A "value follows" marker: `0`, then the value.
    pub fn present(&mut self) -> &mut Self {
        self.u32(0)
    }

    /// Length-prefixed opaque with padding.
    pub fn opaque(&mut self, bytes: &[u8]) -> &mut Self {
        self.u32(bytes.len() as u32);
        self.bytes.extend_from_slice(bytes);
        let pad = (4 - (bytes.len() % 4)) % 4;
        self.bytes.extend_from_slice(&[0u8; 4][..pad]);
        self
    }

    /// A `string<*>`.
    pub fn string(&mut self, s: &str) -> &mut Self {
        self.opaque(s.as_bytes())
    }

    /// A NUL-terminated string, the spelling `kadm5` uses for names.
    pub fn nullstring(&mut self, s: Option<&str>) -> &mut Self {
        match s {
            None => self.opaque(&[]),
            Some(s) => {
                let mut bytes = s.as_bytes().to_vec();
                bytes.push(0);
                self.opaque(&bytes)
            }
        }
    }

    /// A `string<*>` that may be absent — XDR's `xdr_wrapstring` of a NULL.
    pub fn optional_string(&mut self, s: Option<&str>) -> &mut Self {
        match s {
            None => self.absent(),
            Some(s) => {
                self.present();
                self.string(s)
            }
        }
    }

    /// Raw octets, with no length prefix — for a caller assembling a structure
    /// whose parts are already encoded.
    pub fn raw(&mut self, bytes: &[u8]) -> &mut Self {
        self.bytes.extend_from_slice(bytes);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn padding_is_the_access_and_the_wire_count() {
        let mut w = Writer::new();
        w.opaque(b"abc");
        assert_eq!(
            w.bytes(),
            &[0, 0, 0, 3, b'a', b'b', b'c', 0],
            "three octets are padded to four"
        );
        let mut r = Reader::new(w.bytes());
        assert_eq!(r.opaque().unwrap(), b"abc");
        assert!(r.is_empty(), "the padding must be consumed with the value");
    }

    #[test]
    fn an_absent_value_is_a_one() {
        // `xdr_pointer` writes TRUE for absent: the inverse of every intuition.
        let mut w = Writer::new();
        w.absent();
        assert_eq!(w.bytes(), &[0, 0, 0, 1]);
        let mut r = Reader::new(w.bytes());
        assert_eq!(r.optional(|r| r.string()).unwrap(), None);

        let mut w = Writer::new();
        w.present().string("alice@EXAMPLE.COM");
        let mut r = Reader::new(w.bytes());
        assert_eq!(
            r.optional(|r| r.string()).unwrap().as_deref(),
            Some("alice@EXAMPLE.COM")
        );
    }

    #[test]
    fn a_truncated_stream_is_an_error_and_not_a_panic() {
        for broken in [
            &b""[..],
            &b"\x00\x00"[..],
            &b"\x00\x00\x00\x08abc"[..],
            &b"\x00\x00\x00\x03abc"[..],
        ] {
            let mut r = Reader::new(broken);
            assert!(r.opaque().is_err(), "{broken:?} must not decode");
        }
    }

    #[test]
    fn a_boolean_that_is_neither_is_refused() {
        let mut r = Reader::new(&[0, 0, 0, 2]);
        assert!(
            r.bool().is_err(),
            "2 is not a boolean, and reading it as true hides a bug"
        );
    }

    #[test]
    fn every_integer_round_trips_including_the_negative_ones() {
        // Times in `kadm5` are signed and an unset one is 0, but `-1` is what
        // "no expiry" means in some of the structures.
        let mut w = Writer::new();
        w.i32(-1).u32(u32::MAX).i32(1_700_000_000);
        let mut r = Reader::new(w.bytes());
        assert_eq!(r.i32().unwrap(), -1);
        assert_eq!(r.u32().unwrap(), u32::MAX);
        assert_eq!(r.i32().unwrap(), 1_700_000_000);
        assert!(r.is_empty());
    }
}
