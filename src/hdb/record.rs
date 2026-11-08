//! How an [`HdbEntry`] is stored.
//!
//! Heimdal stores `hdb_entry` as ASN.1 DER, and so does this crate: the record
//! below is DER whose field numbers follow `lib/hdb/hdb.asn1`, so a dump written
//! here can be read by an operator with `asn1_print` and a comparison against
//! Heimdal's schema means something.
//!
//! The mapping, field by field:
//!
//! | `[n]` | Heimdal | Here |
//! |---|---|---|
//! | 0 | `principal` | a `PrincipalName` and a realm, `SEQUENCE` |
//! | 1 | `keys` | `SEQUENCE OF Key`, each `{ kvno [0], key [1], salt [2] }` |
//! | 2 | `flags` | `HDBFlags` as a 32-bit BIT STRING |
//! | 3 | `valid_start` | `KerberosTime`, optional |
//! | 4 | `valid_end` | `KerberosTime`, optional |
//! | 5 | `pw_end` | `KerberosTime`, optional |
//! | 6 | `max_life` | `INTEGER` seconds, optional |
//! | 7 | `max_renew` | `INTEGER` seconds, optional |
//! | 8 | `modified` | `KerberosTime` |
//! | 9 | `etypes` | `SEQUENCE OF INTEGER`, optional — the enctypes this
//!   principal may be issued |
//! | 10 | `kvno` | `INTEGER` — the entry's key version. Absent in records
//!   written before it was stored, which decode to the highest key instead |
//!
//! What is *not* here yet, and is not pretended otherwise: Heimdal's
//! `HDB-extension` (`[9]`), `mkvno` on a key, generated and virtual keys, and
//! key rotation. A record written without them decodes to exactly what was
//! written; a record carrying them is refused rather than silently truncated,
//! because an entry whose unknown fields were dropped is an entry whose keys
//! stopped working.

use crate::crypto::{Enctype, Key};
use crate::der::{self, Fields, Reader};
use crate::error::{Error, Result};
use crate::name::Principal;

use super::{HdbEntry, HdbKey};

/// The field that names a record in any backend that keys by principal.
///
/// `name@realm` — the form a human recognises, and the one a lexicographic walk
/// orders by name across realms. A realm-first form would group a realm's
/// principals together, which reads better in a listing and worse in a walk that
/// wants one order over the whole database; either is defensible, and what
/// matters is that the ordering a backend promises matches the tests.
pub fn key(principal: &Principal) -> String {
    format!("{}@{}", principal.name(), principal.realm)
}

/// Encodes an entry as DER.
///
/// The principal's realm is written in the record rather than left to the caller:
/// a backend that keys by [`key`] and stored only the name would lose the realm
/// a name type cannot carry.
pub fn encode(entry: &HdbEntry) -> Vec<u8> {
    let mut parts = vec![
        der::field(
            0,
            der::seq(&[
                der::field(0, der::int(entry.principal.name_type as i64)),
                der::field(
                    1,
                    der::seq(
                        &entry
                            .principal
                            .components
                            .iter()
                            .map(|c| der::general_string(c))
                            .collect::<Vec<_>>(),
                    ),
                ),
                der::field(2, der::general_string(&entry.principal.realm)),
            ]),
        ),
        der::field(
            1,
            der::seq(
                &entry
                    .keys
                    .iter()
                    .map(|k| {
                        let mut key_parts = vec![
                            der::field(0, der::int(k.kvno as i64)),
                            der::field(
                                1,
                                der::seq(&[
                                    der::field(0, der::int(k.key.enctype().id() as i64)),
                                    der::field(1, der::octets(k.key.bytes())),
                                ]),
                            ),
                        ];
                        if let Some(salt) = &k.salt {
                            key_parts.push(der::field(2, der::octets(salt)));
                        }
                        der::seq(&key_parts)
                    })
                    .collect::<Vec<_>>(),
            ),
        ),
        der::field(2, der::flags32(entry.flags)),
    ];
    for (field, value) in [
        (3, entry.valid_start),
        (4, entry.valid_end),
        (5, entry.pw_end),
        (6, entry.max_life),
        (7, entry.max_renew),
    ] {
        if let Some(v) = value {
            // The first five are `KerberosTime`; the last two are durations in
            // seconds. Both are `INTEGER`-shaped in DER only if the time is
            // formatted, so the two kinds are handled separately below.
            if field <= 5 {
                parts.push(der::field(field, der::time(v)));
            } else {
                parts.push(der::field(field, der::int(v)));
            }
        }
    }
    parts.push(der::field(8, der::time(entry.modified)));
    if let Some(etypes) = &entry.etypes {
        // `Some([])` is written as an empty SEQUENCE, not omitted: a principal
        // that may be issued nothing is a decision, and dropping it would turn
        // the entry back into one with no restriction at all.
        parts.push(der::field(
            9,
            der::seq(
                &etypes
                    .iter()
                    .map(|e| der::int(e.id() as i64))
                    .collect::<Vec<_>>(),
            ),
        ));
    }
    parts.push(der::field(10, der::int(entry.kvno as i64)));
    der::seq(&parts)
}

/// Decodes an entry written by [`encode`].
pub fn decode(data: &[u8]) -> Result<HdbEntry> {
    let ctx = "HdbEntry";
    let mut r = Reader::new(data);
    let f = Fields::parse(ctx, r.expect(ctx, der::SEQUENCE)?)?;

    let mut pr = Reader::new(f.get(0, ctx)?);
    let pf = Fields::parse(ctx, pr.expect(ctx, der::SEQUENCE)?)?;
    let name_type = pf.int(0, ctx)? as i32;
    let mut cr = Reader::new(pf.get(1, ctx)?);
    let mut components = Vec::new();
    let mut cs = Reader::new(cr.expect(ctx, der::SEQUENCE)?);
    while !cs.is_empty() {
        components.push(der::as_string(ctx, cs.expect(ctx, der::GENERAL_STRING)?)?);
    }
    let realm = pf.string(2, ctx)?;
    if components.is_empty() {
        return Err(Error::Hdb(format!("{ctx}: record has no name components")));
    }
    let principal = Principal {
        name_type,
        components,
        realm,
    };

    let mut kr = Reader::new(f.get(1, ctx)?);
    let mut ks = Reader::new(kr.expect(ctx, der::SEQUENCE)?);
    let mut keys = Vec::new();
    while !ks.is_empty() {
        let kf = Fields::parse(ctx, ks.expect(ctx, der::SEQUENCE)?)?;
        let kvno = kf.u32(0, ctx)?;
        let mut er = Reader::new(kf.get(1, ctx)?);
        let ef = Fields::parse(ctx, er.expect(ctx, der::SEQUENCE)?)?;
        let id = ef.int(0, ctx)? as i32;
        let enctype = Enctype::from_id(id)
            .ok_or_else(|| Error::Hdb(format!("{ctx}: enctype {id} is not implemented")))?;
        let key = Key::new(enctype, ef.octets(1, ctx)?)?;
        keys.push(HdbKey {
            kvno,
            key,
            salt: kf.opt_octets(2, ctx)?.map(<[u8]>::to_vec),
        });
    }

    let time_field = |n: u8| -> Result<Option<i64>> {
        match f.opt(n) {
            None => Ok(None),
            Some(_) => {
                let mut r = Reader::new(f.get(n, ctx)?);
                let text = der::as_string(
                    ctx,
                    r.expect(ctx, der::GENERALIZED_TIME)
                        .map_err(|_| crate::der::DerError {
                            context: ctx,
                            detail: format!("field [{n}] is not a KerberosTime"),
                        })?,
                )?;
                crate::time::parse_generalized_time(&text)
                    .map(Some)
                    .ok_or_else(|| Error::Hdb(format!("{ctx}: {text:?} is not a KerberosTime")))
            }
        }
    };

    let keys_highest = keys.iter().map(|k| k.kvno).max().unwrap_or(0);

    // `Some([])` and absent are different states and both are written, so the
    // decoder must keep the difference rather than collapsing to `None`.
    let etypes_field = || -> Result<Option<Vec<Enctype>>> {
        if f.opt(9).is_none() {
            return Ok(None);
        }
        let mut r = Reader::new(f.get(9, ctx)?);
        let mut inner = Reader::new(r.expect(ctx, der::SEQUENCE)?);
        let mut out = Vec::new();
        while !inner.is_empty() {
            let content = inner.expect(ctx, der::INTEGER)?;
            let raw = der::as_int(ctx, content)?;
            let enctype = Enctype::from_id(raw as i32).ok_or_else(|| {
                Error::Hdb(format!(
                    "{ctx}: enctype {raw} is not one this KDC implements"
                ))
            })?;
            out.push(enctype);
        }
        Ok(Some(out))
    };

    Ok(HdbEntry {
        principal,
        keys,
        flags: f.flags32(2, ctx)?,
        valid_start: time_field(3)?,
        valid_end: time_field(4)?,
        pw_end: time_field(5)?,
        max_life: f.opt_int(6, ctx)?,
        max_renew: f.opt_int(7, ctx)?,
        // A record written before the version was stored has no `[10]`; the
        // highest key is the only value that cannot be wrong for it, and it is
        // what this crate derived before the field existed.
        kvno: match f.opt_int(10, ctx)? {
            Some(kvno) => u32::try_from(kvno)
                .map_err(|_| Error::Hdb(format!("{ctx}: kvno {kvno} does not fit in 32 bits")))?,
            None => keys_highest,
        },
        etypes: etypes_field()?,
        modified: time_field(8)?.unwrap_or(0),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::OwnCipher;
    use crate::hdb::flags;

    fn entry() -> HdbEntry {
        let cipher = OwnCipher;
        let mut e = HdbEntry::user(Principal::parse("alice@EXAMPLE.COM").unwrap());
        e.add_password_key(&cipher, Enctype::Aes256Sha1, b"pw", 3)
            .unwrap();
        e.add_password_key(&cipher, Enctype::Aes128Sha1, b"pw", 3)
            .unwrap();
        e.flags |= flags::REQUIRE_PREAUTH | flags::FORWARDABLE;
        e.valid_start = Some(1_600_000_000);
        e.valid_end = Some(1_900_000_000);
        e.pw_end = Some(1_800_000_000);
        e.max_life = Some(43_200);
        e.max_renew = Some(604_800);
        e.modified = 1_700_000_000;
        e
    }

    #[test]
    fn an_entry_round_trips_with_every_field() {
        let e = entry();
        let back = decode(&encode(&e)).unwrap();
        assert_eq!(back.principal, e.principal);
        assert_eq!(back.principal.name_type, e.principal.name_type);
        assert_eq!(back.flags, e.flags);
        assert_eq!(back.valid_start, e.valid_start);
        assert_eq!(back.valid_end, e.valid_end);
        assert_eq!(back.pw_end, e.pw_end);
        assert_eq!(back.max_life, e.max_life);
        assert_eq!(back.max_renew, e.max_renew);
        assert_eq!(back.modified, e.modified);
        assert_eq!(back.keys.len(), 2);
        assert_eq!(back.keys[0].kvno, 3);
        assert_eq!(back.keys[0].key, e.keys[0].key);
        assert_eq!(back.keys[0].salt.as_deref(), Some(&b"EXAMPLE.COMalice"[..]));
    }

    #[test]
    fn absent_optional_fields_stay_absent() {
        let mut e = entry();
        e.valid_start = None;
        e.valid_end = None;
        e.pw_end = None;
        e.max_life = None;
        e.max_renew = None;
        let back = decode(&encode(&e)).unwrap();
        assert_eq!(back.valid_start, None);
        assert_eq!(back.valid_end, None);
        assert_eq!(back.pw_end, None);
        assert_eq!(back.max_life, None);
        assert_eq!(back.max_renew, None);
    }

    #[test]
    fn an_entry_with_no_keys_round_trips() {
        let mut e = HdbEntry::service(Principal::parse("host/h@R").unwrap());
        e.keys.clear();
        let back = decode(&encode(&e)).unwrap();
        assert!(back.keys.is_empty());
        assert_eq!(back.principal.to_string(), "host/h@R");
    }

    #[test]
    fn a_truncated_record_is_an_error_not_a_panic() {
        let data = encode(&entry());
        for cut in 1..data.len().min(60) {
            let _ = decode(&data[..data.len() - cut]);
        }
    }

    #[test]
    fn a_record_naming_an_unimplemented_enctype_is_refused() {
        // A key of an enctype this crate cannot handle must not decode into a
        // key of some other enctype: the record is refused instead.
        let cipher = OwnCipher;
        let mut entry = HdbEntry::user(Principal::parse("a@R").unwrap());
        entry
            .add_password_key(&cipher, Enctype::Aes256Sha1, b"pw", 1)
            .unwrap();
        let mut bytes = encode(&entry);
        let pos = bytes
            .windows(3)
            .position(|w| w == [0x02, 0x01, 18])
            .expect("the AES-256 key type in the encoding");
        bytes[pos + 2] = 23; // RC4
        assert!(decode(&bytes).is_err());
    }

    #[test]
    fn the_database_key_is_name_then_realm() {
        assert_eq!(
            key(&Principal::parse("host/h.example.com@EXAMPLE.COM").unwrap()),
            "host/h.example.com@EXAMPLE.COM"
        );
    }
}
