//! DER, not BER — and only the part of DER that RFC 4120 uses.
//!
//! Kerberos ASN.1 (§5 of RFC 4120) uses single-octet tags (application tags
//! stop at 30, `KRB-ERROR`), EXPLICIT context tags and a handful of universal
//! types. A general ASN.1 library would be mostly dead weight; what is *not*
//! optional is that the encoder is DER:
//!
//! * lengths are minimal — a TGS request's checksum is computed over the exact
//!   octets of `KDC-REQ-BODY`, so a non-minimal length changes the bytes the
//!   KDC hashes and no other implementation will agree;
//! * INTEGERs are minimal two's complement;
//! * SET OF ordering is never needed here (Kerberos has no SET OF).
//!
//! Decoding is deliberately tolerant in one direction only: unknown
//! context-tagged fields are carried past, because RFC 4120 tells a KDC to
//! ignore what it does not understand (`AD-IF-RELEVANT` philosophy). What it
//! is not tolerant of is a wrong tag where a known field belongs, or a length
//! that runs past the end of the buffer.

use std::fmt;

/// Universal `INTEGER` tag.
pub const INTEGER: u8 = 0x02;
/// Universal `BIT STRING` tag — `KerberosFlags` uses it.
pub const BIT_STRING: u8 = 0x03;
/// Universal `OCTET STRING` tag.
pub const OCTET_STRING: u8 = 0x04;
/// Universal `GeneralizedTime` tag — every `KerberosTime`.
pub const GENERALIZED_TIME: u8 = 0x18;
/// Universal `GeneralString` tag — every `KerberosString`.
pub const GENERAL_STRING: u8 = 0x1b;
/// Universal constructed `SEQUENCE` tag.
pub const SEQUENCE: u8 = 0x30;

/// `OBJECT IDENTIFIER`, RFC 5280's ASN.1, which CMS and PKINIT are written in.
pub const OBJECT_IDENTIFIER: u8 = 0x06;

/// `UTCTime`, the form RFC 5280 requires for certificates dated before 2050.
pub const UTCTIME: u8 = 0x17;

/// `[APPLICATION n]`, constructed.
pub const fn app(n: u8) -> u8 {
    0x60 | n
}

/// `[n]`, context-specific, constructed — EXPLICIT, which is all Kerberos uses.
pub const fn ctx(n: u8) -> u8 {
    0xa0 | n
}

/// A DER decoding failure: what was expected, and where.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DerError {
    /// The value being parsed, for a message a human will read in a log.
    pub context: &'static str,
    /// What went wrong.
    pub detail: String,
}

impl fmt::Display for DerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.context, self.detail)
    }
}

impl std::error::Error for DerError {}

/// Result of a DER operation.
pub type Result<T> = std::result::Result<T, DerError>;

/// A failure carrying the name of the value being parsed.
pub fn err<T>(context: &'static str, detail: impl Into<String>) -> Result<T> {
    Err(DerError {
        context,
        detail: detail.into(),
    })
}

// --------------------------------------------------------------------- encode

/// DER length octets: short form below 0x80, minimal long form above.
pub fn encode_len(out: &mut Vec<u8>, len: usize) {
    if len < 0x80 {
        out.push(len as u8);
        return;
    }
    let bytes = len.to_be_bytes();
    let skip = bytes.iter().take_while(|&&b| b == 0).count();
    out.push(0x80 | (bytes.len() - skip) as u8);
    out.extend_from_slice(&bytes[skip..]);
}

/// A tag-length-value with `content` inside.
pub fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(content.len() + 6);
    out.push(tag);
    encode_len(&mut out, content.len());
    out.extend_from_slice(content);
    out
}

/// A constructed value from already-encoded children.
pub fn cons(tag: u8, parts: &[Vec<u8>]) -> Vec<u8> {
    let content: Vec<u8> = parts.concat();
    tlv(tag, &content)
}

/// A `SEQUENCE` from already-encoded children.
pub fn seq(parts: &[Vec<u8>]) -> Vec<u8> {
    cons(SEQUENCE, parts)
}

/// `[n] EXPLICIT inner` — how every field of an RFC 4120 structure is tagged.
pub fn field(n: u8, inner: Vec<u8>) -> Vec<u8> {
    cons(ctx(n), &[inner])
}

/// A minimal two's complement INTEGER.
pub fn int(v: i64) -> Vec<u8> {
    let bytes = v.to_be_bytes();
    let mut start = 0;
    // Drop redundant leading 0x00 (positive) / 0xff (negative) octets, keeping
    // the sign bit in the first remaining octet.
    while start < 7 {
        let b = bytes[start];
        let next = bytes[start + 1];
        let redundant = (b == 0x00 && next & 0x80 == 0) || (b == 0xff && next & 0x80 != 0);
        if !redundant {
            break;
        }
        start += 1;
    }
    tlv(INTEGER, &bytes[start..])
}

/// An `OCTET STRING`.
pub fn octets(b: &[u8]) -> Vec<u8> {
    tlv(OCTET_STRING, b)
}

/// `KerberosString` is a `GeneralString` (RFC 4120 §5.2.14).
pub fn general_string(s: &str) -> Vec<u8> {
    tlv(GENERAL_STRING, s.as_bytes())
}

/// A 32-bit `KerberosFlags` BIT STRING with no unused bits (RFC 4120 §5.2.8).
pub fn flags32(v: u32) -> Vec<u8> {
    let mut content = Vec::with_capacity(5);
    content.push(0); // unused bits
    content.extend_from_slice(&v.to_be_bytes());
    tlv(BIT_STRING, &content)
}

/// A `KerberosTime`: `GeneralizedTime` in `YYYYMMDDHHMMSSZ`.
pub fn time(unix: i64) -> Vec<u8> {
    tlv(
        GENERALIZED_TIME,
        crate::time::format_generalized_time(unix).as_bytes(),
    )
}

// --------------------------------------------------------------------- decode

/// One decoded TLV: its tag and its content octets.
pub struct Tlv<'a> {
    /// The identifier octet, single-octet form only.
    pub tag: u8,
    /// The content octets, without the header.
    pub content: &'a [u8],
}

/// Walks encoded values, checking lengths as it goes.
pub struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    /// A reader over one encoded value.
    pub fn new(data: &'a [u8]) -> Self {
        Reader { data, pos: 0 }
    }

    /// Whether every octet has been consumed.
    pub fn is_empty(&self) -> bool {
        self.pos >= self.data.len()
    }

    /// The octets not yet consumed.
    pub fn rest(&self) -> &'a [u8] {
        &self.data[self.pos..]
    }

    /// The next TLV, whatever its tag.
    pub fn next(&mut self, context: &'static str) -> Result<Tlv<'a>> {
        let start = self.pos;
        if start >= self.data.len() {
            return err(context, "truncated: no tag");
        }
        let tag = self.data[start];
        if tag & 0x1f == 0x1f {
            return err(context, "high-tag-number form is not used by Kerberos");
        }
        let mut p = start + 1;
        if p >= self.data.len() {
            return err(context, "truncated: no length");
        }
        let first = self.data[p];
        p += 1;
        let len = if first & 0x80 == 0 {
            first as usize
        } else {
            let n = (first & 0x7f) as usize;
            if n == 0 || n > 4 {
                return err(context, format!("bad length form: {n} octets"));
            }
            if p + n > self.data.len() {
                return err(context, "truncated: long length");
            }
            let mut v = 0usize;
            for &b in &self.data[p..p + n] {
                v = (v << 8) | b as usize;
            }
            // DER: long form only when the value does not fit in the short form.
            if v < 0x80 {
                return err(context, "non-minimal length encoding");
            }
            p += n;
            v
        };
        if p + len > self.data.len() {
            return err(
                context,
                format!("truncated: want {len} octets, have {}", self.data.len() - p),
            );
        }
        self.pos = p + len;
        Ok(Tlv {
            tag,
            content: &self.data[p..p + len],
        })
    }

    /// The next TLV, which must carry `tag`.
    pub fn expect(&mut self, context: &'static str, tag: u8) -> Result<&'a [u8]> {
        let t = self.next(context)?;
        if t.tag != tag {
            return err(
                context,
                format!("expected tag {tag:#04x}, got {:#04x}", t.tag),
            );
        }
        Ok(t.content)
    }
}

/// A decoded SEQUENCE: its context-tagged fields, by tag number.
pub struct Fields<'a> {
    items: Vec<(u8, &'a [u8])>,
}

impl<'a> Fields<'a> {
    /// Parses the *content* of a `SEQUENCE` into its `[n]` fields.
    pub fn parse(context: &'static str, content: &'a [u8]) -> Result<Self> {
        let mut r = Reader::new(content);
        let mut items = Vec::new();
        while !r.is_empty() {
            let t = r.next(context)?;
            if t.tag & 0xc0 != 0x80 {
                return err(
                    context,
                    format!("unexpected non-context tag {:#04x}", t.tag),
                );
            }
            items.push((t.tag & 0x1f, t.content));
        }
        Ok(Fields { items })
    }

    /// Parses `data` as `[APPLICATION n] SEQUENCE { ... }`.
    pub fn parse_app(context: &'static str, app_tag: u8, data: &'a [u8]) -> Result<Self> {
        let mut r = Reader::new(data);
        let inner = r.expect(context, app(app_tag))?;
        if r.rest().iter().any(|&b| b != 0) {
            return err(context, "trailing octets after the message");
        }
        let mut s = Reader::new(inner);
        let content = s.expect(context, SEQUENCE)?;
        Self::parse(context, content)
    }

    /// The raw content of field `[n]`, which must be present.
    pub fn get(&self, n: u8, context: &'static str) -> Result<&'a [u8]> {
        self.items
            .iter()
            .find(|(t, _)| *t == n)
            .map(|(_, c)| *c)
            .ok_or_else(|| DerError {
                context,
                detail: format!("missing field [{n}]"),
            })
    }

    /// The raw content of field `[n]`, if present.
    pub fn opt(&self, n: u8) -> Option<&'a [u8]> {
        self.items.iter().find(|(t, _)| *t == n).map(|(_, c)| *c)
    }

    // Typed accessors. Every field in RFC 4120 is EXPLICIT, so the value of
    // `[n]` is itself a TLV of a universal type; that inner tag is checked
    // here rather than by each caller.

    /// `[n]` as an `INTEGER`.
    pub fn int(&self, n: u8, context: &'static str) -> Result<i64> {
        let mut r = Reader::new(self.get(n, context)?);
        as_int(context, r.expect(context, INTEGER)?)
    }

    /// `[n]` as an `INTEGER`, if present.
    pub fn opt_int(&self, n: u8, context: &'static str) -> Result<Option<i64>> {
        match self.opt(n) {
            None => Ok(None),
            Some(_) => self.int(n, context).map(Some),
        }
    }

    /// `[n]` as a `UInt32`.
    pub fn u32(&self, n: u8, context: &'static str) -> Result<u32> {
        let mut r = Reader::new(self.get(n, context)?);
        as_u32(context, r.expect(context, INTEGER)?)
    }

    /// `[n]` as a `GeneralString`.
    pub fn string(&self, n: u8, context: &'static str) -> Result<String> {
        let mut r = Reader::new(self.get(n, context)?);
        as_string(context, r.expect(context, GENERAL_STRING)?)
    }

    /// `[n]` as a `GeneralString`, if present.
    pub fn opt_string(&self, n: u8, context: &'static str) -> Result<Option<String>> {
        match self.opt(n) {
            None => Ok(None),
            Some(_) => self.string(n, context).map(Some),
        }
    }

    /// `[n]` as an `OCTET STRING`'s content.
    pub fn octets(&self, n: u8, context: &'static str) -> Result<&'a [u8]> {
        let mut r = Reader::new(self.get(n, context)?);
        r.expect(context, OCTET_STRING)
    }

    /// `[n]` as an `OCTET STRING`'s content, if present.
    pub fn opt_octets(&self, n: u8, context: &'static str) -> Result<Option<&'a [u8]>> {
        match self.opt(n) {
            None => Ok(None),
            Some(_) => self.octets(n, context).map(Some),
        }
    }

    /// `[n]` as an `OBJECT IDENTIFIER`, in dotted-decimal form.
    ///
    /// PKINIT and CMS carry OIDs where RFC 4120 carries integers: content types,
    /// algorithm identifiers, the `id-pkinit-san` extension. They are read as text
    /// because the comparisons are against a fixed set, and a numeric encoding of that
    /// set would be a second place to get the arcs wrong.
    pub fn oid(&self, n: u8, context: &'static str) -> Result<String> {
        let mut r = Reader::new(self.get(n, context)?);
        decode_oid(context, r.expect(context, OBJECT_IDENTIFIER)?)
    }

    /// `[n]` as a time: `GeneralizedTime` or `UTCTime`.
    ///
    /// CMS and X.509 use both, and which one appears depends on the year and on the
    /// encoder: RFC 5280 says certificates through 2049 use `UTCTime`. Refusing one of
    /// them would reject valid certificates, so both are read here.
    pub fn time(&self, n: u8, context: &'static str) -> Result<i64> {
        let mut r = Reader::new(self.get(n, context)?);
        let tlv = r.next(context)?;
        match tlv.tag {
            GENERALIZED_TIME => {
                let text = std::str::from_utf8(tlv.content).map_err(|_| DerError {
                    context,
                    detail: "GeneralizedTime is not ASCII".into(),
                })?;
                crate::time::parse_generalized_time(text).ok_or_else(|| DerError {
                    context,
                    detail: format!("{text:?} is not a GeneralizedTime"),
                })
            }
            UTCTIME => as_utc_time(context, tlv.content),
            other => err(context, format!("tag 0x{other:02x} is not a time")),
        }
    }

    /// `[n]` as `KerberosFlags`.
    pub fn flags32(&self, n: u8, context: &'static str) -> Result<u32> {
        let mut r = Reader::new(self.get(n, context)?);
        as_flags32(context, r.expect(context, BIT_STRING)?)
    }

    /// `[n]` as `KerberosFlags`, if present.
    pub fn opt_flags32(&self, n: u8, context: &'static str) -> Result<Option<u32>> {
        match self.opt(n) {
            None => Ok(None),
            Some(_) => self.flags32(n, context).map(Some),
        }
    }

    /// The content of the `SEQUENCE` inside `[n]`.
    pub fn seq(&self, n: u8, context: &'static str) -> Result<&'a [u8]> {
        as_sequence(context, self.get(n, context)?)
    }

    /// The content of the `SEQUENCE` inside `[n]`, if present.
    pub fn opt_seq(&self, n: u8, context: &'static str) -> Result<Option<&'a [u8]>> {
        match self.opt(n) {
            None => Ok(None),
            Some(_) => self.seq(n, context).map(Some),
        }
    }

    /// The content of `[APPLICATION app_tag]` inside `[n]`.
    pub fn app(&self, n: u8, app_tag: u8, context: &'static str) -> Result<&'a [u8]> {
        let mut r = Reader::new(self.get(n, context)?);
        r.expect(context, app(app_tag))
    }

    /// The tag numbers present, in order — for diagnostics.
    pub fn tags(&self) -> Vec<u8> {
        self.items.iter().map(|(t, _)| *t).collect()
    }
}

/// Two's complement INTEGER content as `i64`.
pub fn as_int(context: &'static str, content: &[u8]) -> Result<i64> {
    if content.is_empty() || content.len() > 8 {
        return err(context, format!("INTEGER of {} octets", content.len()));
    }
    let mut v: i64 = if content[0] & 0x80 != 0 { -1 } else { 0 };
    for &b in content {
        v = (v << 8) | b as i64;
    }
    Ok(v)
}

/// INTEGER content that must be a `UInt32`.
pub fn as_u32(context: &'static str, content: &[u8]) -> Result<u32> {
    let v = as_int(context, content)?;
    u32::try_from(v).map_err(|_| DerError {
        context,
        detail: format!("value {v} out of UInt32 range"),
    })
}

/// `GeneralString` content as a UTF-8 string.
pub fn as_string(context: &'static str, content: &[u8]) -> Result<String> {
    String::from_utf8(content.to_vec()).map_err(|_| DerError {
        context,
        detail: "not UTF-8".into(),
    })
}

/// BIT STRING content as 32 flags.
pub fn as_flags32(context: &'static str, content: &[u8]) -> Result<u32> {
    // BIT STRING: first octet is the count of unused trailing bits.
    if content.len() < 2 || content.len() > 5 {
        return err(context, format!("BIT STRING of {} octets", content.len()));
    }
    let unused = content[0];
    if unused > 7 {
        return err(context, format!("BIT STRING with {unused} unused bits"));
    }
    let mut v = 0u32;
    for &b in &content[1..] {
        v = (v << 8) | b as u32;
    }
    if unused > 0 {
        v >>= unused;
    }
    Ok(v)
}

/// Strips a `SEQUENCE` tag, returning its content.
pub fn as_sequence<'a>(context: &'static str, content: &'a [u8]) -> Result<&'a [u8]> {
    let mut r = Reader::new(content);
    r.expect(context, SEQUENCE)
}

/// The elements of a `SEQUENCE OF` whose members carry `tag`.
pub fn seq_of<'a>(context: &'static str, content: &'a [u8], tag: u8) -> Result<Vec<&'a [u8]>> {
    let mut r = Reader::new(content);
    let inner = r.expect(context, SEQUENCE)?;
    let mut out = Vec::new();
    let mut s = Reader::new(inner);
    while !s.is_empty() {
        out.push(s.expect(context, tag)?);
    }
    Ok(out)
}

/// Decodes an `OBJECT IDENTIFIER`'s content into dotted-decimal form.
///
/// The first octet carries two arcs packed as `40 * arc1 + arc2`, which is why the
/// leading `2` of every OID in this file costs one octet and not two.
pub fn decode_oid(context: &'static str, content: &[u8]) -> Result<String> {
    let mut parts: Vec<u64> = Vec::new();
    let mut value: u64 = 0;
    let mut started = false;
    for (i, &b) in content.iter().enumerate() {
        if !started && b == 0x80 {
            return err(context, "OID has a redundant leading 0x80");
        }
        started = true;
        value = value
            .checked_mul(128)
            .and_then(|v| v.checked_add(u64::from(b & 0x7f)))
            .ok_or_else(|| DerError {
                context,
                detail: "OID arc overflows 64 bits".into(),
            })?;
        if b & 0x80 == 0 {
            if parts.is_empty() {
                let (first, second) = if value < 40 {
                    (0, value)
                } else if value < 80 {
                    (1, value - 40)
                } else {
                    (2, value - 80)
                };
                parts.push(first);
                parts.push(second);
            } else {
                parts.push(value);
            }
            value = 0;
            started = false;
        } else if i + 1 == content.len() {
            return err(context, "OID ends in the middle of an arc");
        }
    }
    if parts.len() < 2 {
        return err(context, "OID has fewer than two arcs");
    }
    Ok(parts
        .iter()
        .map(u64::to_string)
        .collect::<Vec<_>>()
        .join("."))
}

/// `UTCTime`: `YYMMDDHHMM[SS](Z|±hhmm)`, with the year window of RFC 5280 §4.1.2.5.1.
///
/// The window is the trap: `50` is 1950 and `49` is 2049, so a naive `2000 + yy` puts a
/// certificate issued in 1999 a century into the future, where it never expires.
pub fn as_utc_time(context: &'static str, content: &[u8]) -> Result<i64> {
    let text = std::str::from_utf8(content).map_err(|_| DerError {
        context,
        detail: "UTCTime is not ASCII".into(),
    })?;
    if text.len() < 11 {
        return err(context, format!("UTCTime {text:?} is too short"));
    }
    let digits = |a: usize, b: usize| -> Result<i64> {
        text.get(a..b)
            .and_then(|s| s.parse::<i64>().ok())
            .ok_or_else(|| DerError {
                context,
                detail: format!("UTCTime {text:?} is not numeric where digits are required"),
            })
    };
    let yy = digits(0, 2)?;
    let year = if yy >= 50 { 1900 + yy } else { 2000 + yy };
    let month = digits(2, 4)?;
    let day = digits(4, 6)?;
    let hour = digits(6, 8)?;
    let minute = digits(8, 10)?;
    // Seconds are optional: `YYMMDDHHMM` and `YYMMDDHHMMSS` are both legal. What
    // follows the ten digits decides, not the length — a five-octet zone makes
    // `…HHMM+0200` as long as `…HHMMSSZ`, so counting octets cannot tell them apart.
    let has_seconds = text
        .get(10..12)
        .is_some_and(|s| s.bytes().all(|b| b.is_ascii_digit()));
    let (second, rest) = if has_seconds {
        (digits(10, 12)?, &text[12..])
    } else {
        (0, &text[10..])
    };
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 60
    {
        return err(
            context,
            format!("UTCTime {text:?} has a field out of range"),
        );
    }
    let mut seconds = crate::time::parse_generalized_time(&format!(
        "{year:04}{month:02}{day:02}{hour:02}{minute:02}{second:02}Z"
    ))
    .ok_or_else(|| DerError {
        context,
        detail: format!("UTCTime {text:?} is not a real date"),
    })?;
    // The zone: `Z`, or an offset that has to be subtracted to reach UTC. A certificate
    // dated in local time is rare and legal, so "no zone" is not assumed to be one.
    match rest {
        "Z" | "z" => {}
        _ if rest.len() == 5 => {
            let sign = match &rest[..1] {
                "+" => 1,
                "-" => -1,
                other => return err(context, format!("UTCTime zone {other:?} is not an offset")),
            };
            let hh: i64 = rest[1..3].parse().map_err(|_| DerError {
                context,
                detail: format!("UTCTime zone {rest:?} is not numeric"),
            })?;
            let mm: i64 = rest[3..5].parse().map_err(|_| DerError {
                context,
                detail: format!("UTCTime zone {rest:?} is not numeric"),
            })?;
            seconds -= sign * (hh * 3600 + mm * 60);
        }
        other => {
            return err(
                context,
                format!("UTCTime zone {other:?} is neither Z nor an offset"),
            );
        }
    }
    Ok(seconds)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integers_are_minimal_twos_complement() {
        assert_eq!(int(0), vec![0x02, 0x01, 0x00]);
        assert_eq!(int(5), vec![0x02, 0x01, 0x05]);
        assert_eq!(int(127), vec![0x02, 0x01, 0x7f]);
        assert_eq!(int(128), vec![0x02, 0x02, 0x00, 0x80]);
        assert_eq!(int(255), vec![0x02, 0x02, 0x00, 0xff]);
        assert_eq!(int(256), vec![0x02, 0x02, 0x01, 0x00]);
        assert_eq!(int(-1), vec![0x02, 0x01, 0xff]);
        assert_eq!(int(-128), vec![0x02, 0x01, 0x80]);
        assert_eq!(int(-129), vec![0x02, 0x02, 0xff, 0x7f]);
    }

    #[test]
    fn lengths_short_and_long() {
        let mut v = Vec::new();
        encode_len(&mut v, 0x7f);
        assert_eq!(v, vec![0x7f]);
        let mut v = Vec::new();
        encode_len(&mut v, 0x80);
        assert_eq!(v, vec![0x81, 0x80]);
        let mut v = Vec::new();
        encode_len(&mut v, 0x1234);
        assert_eq!(v, vec![0x82, 0x12, 0x34]);
    }

    #[test]
    fn flags_roundtrip() {
        let encoded = flags32(0x4081_0000);
        let mut r = Reader::new(&encoded);
        let content = r.expect("flags", BIT_STRING).unwrap();
        assert_eq!(as_flags32("flags", content).unwrap(), 0x4081_0000);
    }

    #[test]
    fn non_minimal_length_is_refused() {
        // 0x81 0x05 encodes 5, which fits in the short form.
        let bad = vec![0x30, 0x81, 0x05, 0, 0, 0, 0, 0];
        let mut r = Reader::new(&bad);
        assert!(r.next("seq").is_err());
    }

    #[test]
    fn truncated_buffer_is_refused_not_panicked() {
        for cut in 0..4 {
            let good = seq(&[int(5), octets(b"hello")]);
            let mut r = Reader::new(&good[..good.len() - cut]);
            let _ = r.next("seq");
        }
    }

    #[test]
    fn fields_roundtrip_and_optional_absence() {
        let body = seq(&[field(0, flags32(0x40)), field(2, general_string("REALM"))]);
        let mut r = Reader::new(&body);
        let f = Fields::parse("body", r.expect("body", SEQUENCE).unwrap()).unwrap();
        // EXPLICIT: the value of [0] is the whole BIT STRING TLV, so the typed
        // accessor is what unwraps it.
        assert_eq!(f.flags32(0, "body").unwrap(), 0x40);
        assert_eq!(f.string(2, "body").unwrap(), "REALM");
        assert!(f.opt(5).is_none());
        assert!(f.get(5, "body").is_err());
        assert_eq!(f.tags(), vec![0, 2]);
    }

    #[test]
    fn a_wrong_inner_tag_is_reported() {
        // [0] carrying an OCTET STRING where a BIT STRING belongs.
        let body = seq(&[field(0, octets(b"nope"))]);
        let mut r = Reader::new(&body);
        let f = Fields::parse("body", r.expect("body", SEQUENCE).unwrap()).unwrap();
        assert!(f.flags32(0, "body").is_err());
    }

    #[test]
    fn oids_decode_to_the_text_that_names_them() {
        // The first two arcs are packed into one octet as `40 * a + b`, which is why
        // `1.3` costs 0x2b and not two octets. Getting this wrong shifts every arc in
        // every OID, and CMS has nothing but OIDs to steer by.
        for (content, want) in [
            (
                &[0x2b, 0x06, 0x01, 0x05, 0x02, 0x03, 0x01u8][..],
                "1.3.6.1.5.2.3.1",
            ),
            (
                &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02][..],
                "1.2.840.113549.1.7.2",
            ),
            (&[0x55, 0x1d, 0x0e][..], "2.5.29.14"),
            // An arc above 127 needs two octets, high bit first.
            (&[0x2b, 0x81, 0x00][..], "1.3.128"),
        ] {
            assert_eq!(decode_oid("test", content).unwrap(), want);
        }
    }

    #[test]
    fn a_malformed_oid_is_refused_rather_than_guessed() {
        // Truncated: the last arc's high bit says "more follows" and nothing does.
        assert!(decode_oid("test", &[0x2b, 0x86]).is_err());
        // One arc cannot make an OID: the first octet carries two.
        assert!(decode_oid("test", &[]).is_err());
        // A redundant leading 0x80 is the encoding BER allows and DER forbids.
        assert!(decode_oid("test", &[0x2b, 0x80, 0x01]).is_err());
    }

    #[test]
    fn utc_time_reads_the_century_window_the_way_rfc_5280_does() {
        // The window is the trap: `50` is 1950 and `49` is 2049. A naive `2000 + yy`
        // puts a certificate issued in 1999 a century into the future, where it never
        // expires — which is a security bug, not a parsing bug.
        assert_eq!(as_utc_time("t", b"500101000000Z").unwrap(), -631152000); // 1950-01-01
        assert_eq!(as_utc_time("t", b"490101000000Z").unwrap(), 2493072000); // 2049-01-01
        assert_eq!(as_utc_time("t", b"200101000000Z").unwrap(), 1577836800); // 2020-01-01
    }

    #[test]
    fn utc_time_applies_its_zone_offset() {
        // The same instant written in two zones: 12:00Z and 14:00+02:00.
        let utc = as_utc_time("t", b"240101120000Z").unwrap();
        let offset = as_utc_time("t", b"240101140000+0200").unwrap();
        assert_eq!(utc, offset);
        // And a negative offset goes the other way.
        assert_eq!(
            as_utc_time("t", b"240101120000-0500").unwrap(),
            utc + 5 * 3600
        );
    }

    #[test]
    fn utc_time_refuses_what_is_not_a_time() {
        assert!(as_utc_time("t", b"2401011200").is_err(), "too short");
        assert!(as_utc_time("t", b"241301120000Z").is_err(), "month 13");
        assert!(as_utc_time("t", b"240132120000Z").is_err(), "day 32");
        assert!(as_utc_time("t", b"240101250000Z").is_err(), "hour 25");
        assert!(as_utc_time("t", b"240101120000X").is_err(), "zone is not Z");
        assert!(as_utc_time("t", b"240230120000Z").is_err(), "30 February");
    }

    #[test]
    fn a_time_field_accepts_both_encodings_that_appear_in_practice() {
        // RFC 5280 requires `UTCTime` before 2050 and `GeneralizedTime` after, so a
        // reader that knows only one refuses half of the certificates in the world.
        let generalized = seq(&[field(0, time(1_700_000_000))]);
        let mut r = Reader::new(&generalized);
        let f = Fields::parse("t", r.expect("t", SEQUENCE).unwrap()).unwrap();
        assert_eq!(f.time(0, "t").unwrap(), 1_700_000_000);

        let utc = seq(&[field(0, tlv(UTCTIME, b"240101120000Z"))]);
        let mut r = Reader::new(&utc);
        let f = Fields::parse("t", r.expect("t", SEQUENCE).unwrap()).unwrap();
        assert_eq!(f.time(0, "t").unwrap(), 1704110400);

        // Anything else is not a time, and saying so is better than reading it as zero.
        let bad = seq(&[field(0, int(5))]);
        let mut r = Reader::new(&bad);
        let f = Fields::parse("t", r.expect("t", SEQUENCE).unwrap()).unwrap();
        assert!(f.time(0, "t").is_err());
    }

    #[test]
    fn an_oid_field_is_read_as_text() {
        let body = seq(&[field(
            0,
            tlv(
                OBJECT_IDENTIFIER,
                &[0x2b, 0x06, 0x01, 0x05, 0x02, 0x03, 0x01],
            ),
        )]);
        let mut r = Reader::new(&body);
        let f = Fields::parse("t", r.expect("t", SEQUENCE).unwrap()).unwrap();
        assert_eq!(f.oid(0, "t").unwrap(), "1.3.6.1.5.2.3.1");
    }
}
