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
//! | 13 | `extensions` | `SEQUENCE OF HDB-extension`; this crate reads and writes
//!   two of them — `allowed-to-delegate-to [2]` and `aliases [6]` — and skips the rest |
//!
//! What is *not* here yet, and is not pretended otherwise: `mkvno` on a key,
//! generated and virtual keys, key rotation, and the other `HDB-extension`s. An
//! extension this crate does not know is skipped rather than refused, because a
//! record written by a foreign tool would otherwise be unreadable for a field
//! this KDC has no use for; an entry whose *known* fields were dropped would be
//! an entry whose keys stopped working, and none are.

use crate::crypto::{Enctype, Key};
use crate::der::{self, Fields, Reader};
use crate::error::{Error, Result};
use crate::name::Principal;

use super::{Aliases, HdbEntry, HdbKey};

/// `BOOLEAN` (universal tag 1). `rrl-krb-common`'s decoder names the tags Kerberos messages use,
/// and none of them is a bare `BOOLEAN`; Heimdal's `HDB-Ext-Aliases` is the first place in this
/// crate that needs one.
const BOOLEAN: u8 = 0x01;

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
    // The plaintext path cannot fail: it seals nothing, so there is no key operation to refuse. The
    // `expect` is a statement about that, not a swallowed error — `encode_with`'s only failure is a
    // master key that cannot seal, and there is none here.
    encode_with(entry, None).expect("encoding without a master key seals nothing and cannot fail")
}

/// Encodes an entry, sealing its keys under `master` when one is given.
///
/// This is where a database's protection at rest lives: with a master key every key is written as
/// `encrypt(master_key, HDB_KU_MKEY, key_bytes)` and the record carries the `mkvno` that names it, so
/// the file is worthless without the keytab. Without one the bytes are written as they are — which is
/// what a realm that has not provisioned a master key gets, and it says so.
pub fn encode_with(
    entry: &HdbEntry,
    master: Option<(&dyn crate::crypto::Cipher, &crate::hdb::mkey::MasterKeys)>,
) -> Result<Vec<u8>> {
    // Built first, because sealing a key can fail and a record must not be half written: `parts` is
    // assembled only once every key has been dealt with.
    let mut key_values = Vec::with_capacity(entry.keys.len());
    for k in &entry.keys {
        // The bytes written are what the master key makes them: sealed when there is one, plaintext
        // otherwise. A failure to seal is a failure to write — falling back to plaintext here would
        // put a realm's keys on disk unsealed while the caller believed they were protected, and
        // nothing would say so.
        let (material, mkvno) = match master {
            Some((cipher, keys)) => {
                let (sealed, kvno) = keys.seal(cipher, k.key.bytes())?;
                (sealed, Some(kvno))
            }
            None => (k.key.bytes().to_vec(), None),
        };
        let mut key_parts = vec![
            der::field(0, der::int(k.kvno as i64)),
            der::field(
                1,
                der::seq(&[
                    der::field(0, der::int(k.key.enctype().id() as i64)),
                    der::field(1, der::octets(&material)),
                ]),
            ),
        ];
        if let Some(salt) = &k.salt {
            key_parts.push(der::field(2, der::octets(salt)));
        }
        // `mkvno [3]`: which master key this key is stored under. Written only when the key is
        // sealed, so a database with no master key keeps exactly the shape it had before this field
        // existed — an older build reads it unchanged.
        if let Some(mkvno) = mkvno {
            key_parts.push(der::field(3, der::int(i64::from(mkvno))));
        }
        key_values.push(der::seq(&key_parts));
    }

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
        der::field(1, der::seq(&key_values)),
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
    // `extensions [13] HDB-extensions`: a SEQUENCE OF `HDB-extension`, one per extension this
    // crate understands. `mandatory` is false on every one of them on purpose: a KDC that does not
    // know an extension denies what it guards (delegation, alias resolution), and denying is the
    // safe direction — marking it mandatory would make every older KDC reject the whole entry
    // instead of one thing inside it.
    let mut extensions = Vec::new();
    if let Some(acl) = &entry.constrained_delegation {
        // `data [1]` holds a CHOICE, whose `allowed-to-delegate-to [2]` alternative is
        // `SEQUENCE OF Principal`.
        extensions.push(der::seq(&[
            der::field(0, der::int(0)),
            der::field(
                1,
                der::seq(&[der::field(
                    2,
                    der::seq(&acl.iter().map(|p| p.encode_name()).collect::<Vec<_>>()),
                )]),
            ),
        ]));
    }
    if let Some(aliases) = &entry.aliases {
        // `HDB-Ext-Aliases ::= SEQUENCE { case-insensitive [0] BOOLEAN, aliases [1]
        // SEQUENCE OF Principal }`. The boolean is written even when false: it is not DEFAULT in
        // the ASN.1, so omitting it would be a different encoding of the same intent.
        extensions.push(der::seq(&[
            der::field(0, der::int(0)),
            der::field(
                1,
                der::seq(&[der::field(
                    6,
                    der::seq(&[
                        der::field(
                            0,
                            der::tlv(
                                BOOLEAN,
                                &[if aliases.case_insensitive { 0xFF } else { 0x00 }],
                            ),
                        ),
                        der::field(
                            1,
                            der::seq(
                                &aliases
                                    .names
                                    .iter()
                                    .map(|p| p.encode_name())
                                    .collect::<Vec<_>>(),
                            ),
                        ),
                    ]),
                )]),
            ),
        ]));
    }
    if let Some(policy) = &entry.policy {
        extensions.push(der::seq(&[
            der::field(0, der::int(0)),
            // `UTF8String` (tag 0x0c), which is what `hdb.asn1` says the field is — a
            // `GeneralString` here would be a different type with the same bytes.
            der::field(
                1,
                der::seq(&[der::field(12, der::tlv(0x0c, policy.as_bytes()))]),
            ),
        ]));
    }
    if !entry.strings.is_empty() {
        // `HDB-Ext-Strings`: the pairs, in the order they were set. Written as an extension
        // rather than as a field of the entry so that an entry without strings is byte-for-byte
        // what this crate wrote before strings existed.
        extensions.push(der::seq(&[
            der::field(0, der::int(0)),
            der::field(
                1,
                der::seq(&[der::field(
                    16,
                    der::seq(
                        &entry
                            .strings
                            .iter()
                            .map(|(key, value)| {
                                der::seq(&[
                                    der::field(0, der::general_string(key)),
                                    der::field(1, der::general_string(value)),
                                ])
                            })
                            .collect::<Vec<_>>(),
                    ),
                )]),
            ),
        ]));
    }
    if let Some(nt_hash) = &entry.nt_hash {
        // `NT-Hash ::= SEQUENCE { mkvno [0] INTEGER OPTIONAL, value [1] OCTET STRING }`, this
        // crate's extension 17 — Heimdal's `HDB-extension` CHOICE ends in `...`, and Heimdal has no
        // field for an NT hash at all (its `hdb.asn1` is Kerberos-only), so there is nothing of
        // Heimdal's to be compatible with here.
        //
        // `mkvno` is what makes the bytes unambiguous: present means the value is sealed under that
        // master key, absent means sixteen octets of plaintext. Deciding by length would work today
        // and break the moment an enctype's overhead made a sealed blob sixteen octets long.
        let (value, mkvno) = match master {
            Some((cipher, keys)) => {
                let (sealed, kvno) = keys.seal(cipher, nt_hash)?;
                (sealed, Some(kvno))
            }
            None => (nt_hash.to_vec(), None),
        };
        let mut fields = Vec::new();
        if let Some(mkvno) = mkvno {
            fields.push(der::field(0, der::int(i64::from(mkvno))));
        }
        fields.push(der::field(1, der::octets(&value)));
        extensions.push(der::seq(&[
            der::field(0, der::int(0)),
            der::field(1, der::seq(&[der::field(17, der::seq(&fields))])),
        ]));
    }
    if !extensions.is_empty() {
        parts.push(der::field(13, der::seq(&extensions)));
    }
    Ok(der::seq(&parts))
}

/// `Principal ::= SEQUENCE { name [0] PrincipalName, realm [1] Realm }` out of the record's `[0]`.
fn principal_from(ctx: &'static str, content: &[u8]) -> Result<Principal> {
    let pf = Fields::parse(ctx, content)?;
    let name_type = pf.int(0, ctx)? as i32;
    let mut cr = Reader::new(pf.bytes(1, ctx)?);
    let mut components = Vec::new();
    let mut cs = Reader::new(cr.expect_in(ctx, der::SEQUENCE)?);
    while !cs.is_empty() {
        components.push(der::as_string(
            ctx,
            cs.expect_in(ctx, der::GENERAL_STRING)?,
        )?);
    }
    let realm = pf.string(2, ctx)?;
    if components.is_empty() {
        return Err(Error::Hdb(format!("{ctx}: record has no name components")));
    }
    Ok(Principal {
        name_type,
        components,
        realm,
    })
}

/// Decodes an entry written by [`encode`].
///
/// A record whose keys are sealed is refused here, by name: opening one needs the master key, and
/// [`decode_with`] is what a store that has one calls.
pub fn decode(data: &[u8]) -> Result<HdbEntry> {
    decode_with(data, None)
}

/// The principal a record is stored under, without touching its keys.
///
/// A walk needs names and nothing else. Reading the keys would mean unsealing every one of them on
/// every step of a listing — and a walk over a sealed database must not need the master key at all,
/// because a slave that lists its principals is not thereby reading their keys.
pub fn principal_of(data: &[u8]) -> Result<Principal> {
    let ctx = "HdbEntry";
    let mut r = Reader::new(data);
    let f = Fields::parse(ctx, r.expect_in(ctx, der::SEQUENCE)?)?;
    let mut pr = Reader::new(f.bytes(0, ctx)?);
    principal_from(ctx, pr.expect_in(ctx, der::SEQUENCE)?)
}

/// Decodes an entry, opening whichever of its keys the record says are sealed.
pub fn decode_with(
    data: &[u8],
    master: Option<(&dyn crate::crypto::Cipher, &crate::hdb::mkey::MasterKeys)>,
) -> Result<HdbEntry> {
    let ctx = "HdbEntry";
    let mut r = Reader::new(data);
    let f = Fields::parse(ctx, r.expect_in(ctx, der::SEQUENCE)?)?;

    let mut pr = Reader::new(f.bytes(0, ctx)?);
    let principal = principal_from(ctx, pr.expect_in(ctx, der::SEQUENCE)?)?;

    let mut kr = Reader::new(f.bytes(1, ctx)?);
    let mut ks = Reader::new(kr.expect_in(ctx, der::SEQUENCE)?);
    let mut keys = Vec::new();
    while !ks.is_empty() {
        let kf = Fields::parse(ctx, ks.expect_in(ctx, der::SEQUENCE)?)?;
        let kvno = kf.u32(0, ctx)?;
        let mut er = Reader::new(kf.bytes(1, ctx)?);
        let ef = Fields::parse(ctx, er.expect_in(ctx, der::SEQUENCE)?)?;
        let id = ef.int(0, ctx)? as i32;
        let enctype = Enctype::from_id(id)
            .ok_or_else(|| Error::Hdb(format!("{ctx}: enctype {id} is not implemented")))?;
        let stored = ef.octets(1, ctx)?;
        let mkvno = kf
            .opt_int(3, ctx)?
            .map(|v| {
                u32::try_from(v)
                    .map_err(|_| Error::Hdb(format!("{ctx}: mkvno {v} does not fit in 32 bits")))
            })
            .transpose()?;
        // The key on disk may be sealed under the master key, and a sealed blob is longer than the
        // enctype accepts — so it is opened **before** `Key::new`, which would otherwise refuse it
        // with a length error that says nothing about what is actually wrong.
        let material = match mkvno {
            Some(kvno) => {
                let (cipher, master) = master.ok_or_else(|| {
                    Error::Hdb(format!(
                        "a {}-octet key for {} is sealed under master key {kvno}, and no master key \
                         was supplied",
                        stored.len(),
                        enctype.name()
                    ))
                })?;
                master.unseal(cipher, stored, Some(kvno), enctype)?
            }
            None if !crate::hdb::mkey::is_plain_key(stored, enctype) => {
                return Err(Error::Hdb(format!(
                    "a {}-octet key for {} carries no `mkvno`: it is sealed, and the record does not \
                     say which master key sealed it",
                    stored.len(),
                    enctype.name()
                )));
            }
            None => stored.to_vec(),
        };
        let key = Key::new(enctype, material)?;
        keys.push(HdbKey {
            kvno,
            key,
            salt: kf.opt_octets(2, ctx)?.map(<[u8]>::to_vec),
            // Cleared: the entry in memory holds plaintext, and `mkvno` describes what is on disk.
            // Leaving it set would let an encoder write plaintext under a "sealed" label.
            mkvno: None,
        });
    }

    let time_field = |n: u8| -> Result<Option<i64>> {
        match f.opt_bytes(n) {
            None => Ok(None),
            Some(_) => {
                let mut r = Reader::new(f.bytes(n, ctx)?);
                let text = der::as_string(
                    ctx,
                    r.expect_in(ctx, der::GENERALIZED_TIME).map_err(|_| {
                        crate::der::DerError(format!("{ctx}: field [{n}] is not a KerberosTime"))
                    })?,
                )
                .map_err(|e| Error::Hdb(e.0))?;
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
        if f.opt_bytes(9).is_none() {
            return Ok(None);
        }
        let mut r = Reader::new(f.bytes(9, ctx)?);
        let mut inner = Reader::new(r.expect_in(ctx, der::SEQUENCE)?);
        let mut out = Vec::new();
        while !inner.is_empty() {
            let content = inner.expect_in(ctx, der::INTEGER)?;
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

    // Read before the struct is built: `principal` takes ownership of the realm, and the ACL's
    // principals are named in it.
    let Extensions {
        delegation: delegation_acl,
        aliases,
        policy,
        strings,
        nt_hash,
    } = read_extensions(&f, ctx, &principal.realm, master)?;

    Ok(HdbEntry {
        principal,
        keys,
        nt_hash,
        constrained_delegation: delegation_acl,
        aliases,
        policy,
        strings,
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

/// What the record's `extensions [13]` say, for the extensions this crate understands.
///
/// Heimdal's `HDB-extension` is `{ mandatory [0] BOOLEAN, data [1] CHOICE { … } }`, and the
/// choice is numbered by what it holds: `allowed-to-delegate-to [2]`, `aliases [6]`, and a dozen
/// more this crate has no use for. Every extension is read in **one** pass, because a record can
/// carry several and returning on the first one found would silently drop the rest — which is
/// exactly what the delegation-only reader did before aliases existed.
///
/// An extension this crate does not know is skipped rather than refused, as before: a record
/// written by a foreign tool must stay readable for the fields this KDC does use.
/// What `extensions [13]` carried, in the shape the entry wants it.
struct Extensions {
    delegation: Option<Vec<Principal>>,
    aliases: Option<Aliases>,
    policy: Option<String>,
    strings: Vec<(String, String)>,
    nt_hash: Option<[u8; 16]>,
}

fn read_extensions(
    f: &Fields<'_>,
    ctx: &'static str,
    realm: &str,
    master: Option<(&dyn crate::crypto::Cipher, &crate::hdb::mkey::MasterKeys)>,
) -> Result<Extensions> {
    let mut delegation = None;
    let mut aliases = None;
    let mut policy = None;
    let mut strings = Vec::new();
    let mut nt_hash = None;
    if f.opt_bytes(13).is_none() {
        return Ok(Extensions {
            delegation: None,
            aliases: None,
            policy: None,
            strings,
            nt_hash: None,
        });
    }
    let mut r = Reader::new(f.bytes(13, ctx)?);
    let mut list = Reader::new(r.expect_in(ctx, der::SEQUENCE)?);
    while !list.is_empty() {
        let ef = Fields::parse(ctx, list.expect_in(ctx, der::SEQUENCE)?)?;
        let Some(_) = ef.opt_bytes(1) else { continue };
        let mut dr = Reader::new(ef.bytes(1, ctx)?);
        let choice = Fields::parse(ctx, dr.expect_in(ctx, der::SEQUENCE)?)?;

        if choice.opt_bytes(2).is_some() {
            let mut ar = Reader::new(choice.bytes(2, ctx)?);
            let mut acl = Reader::new(ar.expect_in(ctx, der::SEQUENCE)?);
            let mut out = Vec::new();
            while !acl.is_empty() {
                // `Principal` in `krb5.asn1` carries no realm: a delegation target is named in
                // this entry's own realm, which is also what Heimdal's ACLs mean.
                out.push(Principal::decode(
                    ctx,
                    acl.expect_in(ctx, der::SEQUENCE)?,
                    realm,
                )?);
            }
            delegation = Some(out);
        }

        if choice.opt_bytes(6).is_some() {
            // `HDB-Ext-Aliases ::= SEQUENCE { case-insensitive [0] BOOLEAN, aliases [1]
            // SEQUENCE OF Principal }`, with the principals realm-less like the ACL's.
            let mut ar = Reader::new(choice.bytes(6, ctx)?);
            let af = Fields::parse(ctx, ar.expect_in(ctx, der::SEQUENCE)?)?;
            // `opt_bytes(0)` is the content of the `[0]` wrapper, which is the `BOOLEAN` TLV
            // itself — tag and length included. Reading the first octet of that would read 0x01,
            // the boolean's tag, and call every entry case-insensitive.
            let case_insensitive = match af.opt_bytes(0) {
                Some(v) => matches!(Reader::new(v).expect_in(ctx, BOOLEAN)?, [0xFF]),
                None => false,
            };
            let mut names = Vec::new();
            if af.opt_bytes(1).is_some() {
                let mut nr = Reader::new(af.bytes(1, ctx)?);
                let mut ns = Reader::new(nr.expect_in(ctx, der::SEQUENCE)?);
                while !ns.is_empty() {
                    names.push(Principal::decode(
                        ctx,
                        ns.expect_in(ctx, der::SEQUENCE)?,
                        realm,
                    )?);
                }
            }
            aliases = Some(Aliases {
                case_insensitive,
                names,
            });
        }

        if choice.opt_bytes(12).is_some() {
            // `policy [12] UTF8String`, Heimdal's own number for the name of the policy an entry
            // is governed by — so a Heimdal KDC reading our record sees a policy it understands.
            let mut pr = Reader::new(choice.bytes(12, ctx)?);
            policy = Some(String::from_utf8_lossy(pr.expect_in(ctx, 0x0c)?).into_owned());
        }

        if choice.opt_bytes(16).is_some() {
            // This crate's own extension, `HDB-Ext-Strings`: `SEQUENCE OF SEQUENCE {
            // key [0] UTF8String, value [1] UTF8String }`. Numbered 16 because Heimdal's list
            // stops at `krb5-config [15]` and continues with `...`; an entry written here is
            // readable by Heimdal (it skips an extension it does not know) and its strings are
            // readable by this crate alone, which is the whole point of the extension being
            // optional.
            let mut sr = Reader::new(choice.bytes(16, ctx)?);
            let mut entries = Reader::new(sr.expect_in(ctx, der::SEQUENCE)?);
            while !entries.is_empty() {
                let ef = Fields::parse(ctx, entries.expect_in(ctx, der::SEQUENCE)?)?;
                let mut kr = Reader::new(ef.bytes(0, ctx)?);
                let key = kr.expect_in(ctx, der::GENERAL_STRING)?;
                let mut vr = Reader::new(ef.bytes(1, ctx)?);
                let value = vr.expect_in(ctx, der::GENERAL_STRING)?;
                strings.push((
                    String::from_utf8_lossy(key).into_owned(),
                    String::from_utf8_lossy(value).into_owned(),
                ));
            }
        }

        if choice.opt_bytes(17).is_some() {
            // This crate's extension, `NT-Hash ::= SEQUENCE { mkvno [0] INTEGER OPTIONAL,
            // value [1] OCTET STRING }`. `mkvno` says the value is sealed, and its absence says
            // sixteen plaintext octets — a distinction the record has to carry itself, because a
            // password-equivalent secret that a reader mistook for plaintext would be worse than
            // one it refused.
            let mut nr = Reader::new(choice.bytes(17, ctx)?);
            let nf = Fields::parse(ctx, nr.expect_in(ctx, der::SEQUENCE)?)?;
            let mkvno = nf.opt_int(0, ctx)?.map(|v| v as u32);
            let value = nf.octets(1, ctx)?;
            let material = match mkvno {
                Some(mkvno) => {
                    let (cipher, keys) = master.ok_or_else(|| {
                        Error::Hdb(format!(
                            "{ctx}: the NT hash is sealed under master key {mkvno} and none was \
                             supplied"
                        ))
                    })?;
                    keys.unseal_bytes(cipher, value, Some(mkvno), 16, "NT hash")?
                }
                None => value.to_vec(),
            };
            nt_hash = Some(material.as_slice().try_into().map_err(|_| {
                Error::Hdb(format!(
                    "{ctx}: an NT hash is sixteen octets, this one is {}",
                    material.len()
                ))
            })?);
        }
    }
    Ok(Extensions {
        delegation,
        aliases,
        policy,
        strings,
        nt_hash,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::OwnCipher;
    use crate::hdb::{Aliases, flags};

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

    /// The NT hash survives the record, plaintext and sealed, and the two are told apart by the
    /// record rather than by a length.
    ///
    /// A sealed hash that a reader mistook for plaintext would hand out a password-equivalent secret
    /// that is really ciphertext — and one that a reader mistook for sealed would refuse a record it
    /// could read. `mkvno` is what makes it unambiguous.
    #[test]
    fn the_nt_hash_round_trips_plain_and_sealed() {
        use crate::crypto::Cipher;
        use crate::hdb::mkey::MasterKeys;
        let e = entry();
        let hash = rrl_crypto::nt::hash_password("pw");
        assert_eq!(e.nt_hash, Some(hash), "recorded when the password was set");

        // Plaintext: sixteen octets in the extension and no `mkvno`, which is what a realm with no
        // master key gets — the same as its Kerberos keys, and just as visible in the file.
        let plain = encode(&e);
        assert_eq!(decode(&plain).unwrap().nt_hash, Some(hash));
        assert!(
            plain.windows(16).any(|w| w == hash),
            "without a master key nothing is sealed, and the record says so"
        );

        // Sealed: the same record under a master key holds no plaintext hash, and only that key
        // opens it.
        let master = OwnCipher.random(Enctype::Aes256Sha1).unwrap();
        let keys = MasterKeys::single(master, 7);
        let sealed = encode_with(&e, Some((&OwnCipher, &keys))).expect("sealed");
        assert!(
            !sealed.windows(16).any(|w| w == hash),
            "a sealed record must not carry the hash in the clear"
        );
        let back = decode_with(&sealed, Some((&OwnCipher, &keys))).expect("opened");
        assert_eq!(back.nt_hash, Some(hash), "and it comes back");

        // Without the master key the hash is refused, by name, rather than read as ciphertext.
        //
        // The keys are dropped for this: they are sealed under the same master key, and the record
        // would be refused on the first of them instead — which is correct, and would prove nothing
        // about the hash.
        let mut only_hash = e.clone();
        only_hash.keys.clear();
        let sealed_hash = encode_with(&only_hash, Some((&OwnCipher, &keys))).expect("sealed");
        assert_eq!(
            decode_with(&sealed_hash, Some((&OwnCipher, &keys)))
                .expect("opened")
                .nt_hash,
            Some(hash)
        );
        let err = decode(&sealed_hash)
            .expect_err("a sealed hash cannot be read without the master key")
            .to_string();
        assert!(err.contains("NT hash") && err.contains('7'), "{err}");
    }

    /// An entry with no NT hash writes no extension at all, so a record for a principal that never
    /// had a password is byte-for-byte what this crate wrote before the field existed.
    #[test]
    fn an_entry_without_an_nt_hash_gains_no_extension() {
        let mut e = entry();
        e.nt_hash = None;
        let without = encode(&e);
        e.nt_hash = Some([0u8; 16]);
        let with = encode(&e);
        assert!(with.len() > without.len());
        assert_eq!(decode(&without).unwrap().nt_hash, None);
    }

    /// Aliases survive the record, including the case-insensitivity switch: both are what a
    /// lookup consults, and a backend that dropped either would answer for a name nobody meant.
    #[test]
    fn aliases_round_trip_with_the_case_switch() {
        let mut e = entry();
        e.aliases = Some(Aliases {
            case_insensitive: true,
            names: vec![
                e.principal.clone(),
                Principal::parse("a.vostrikov@EXAMPLE.COM").unwrap(),
            ],
        });
        let back = decode(&encode(&e)).unwrap();
        assert!(back.matches_name(&Principal::parse("A.Vostrikov@example.com").unwrap()));
        let aliases = back.aliases.clone().expect("the extension survives");
        assert!(aliases.case_insensitive);
        assert_eq!(aliases.names.len(), 2);
        assert_eq!(aliases.names[1].to_string(), "a.vostrikov@EXAMPLE.COM");
    }

    /// The delegation list and the alias list are two extensions in one `SEQUENCE OF`, and a
    /// reader that returned on the first one it recognised dropped the other.
    #[test]
    fn delegation_and_aliases_are_both_read_from_one_record() {
        let mut e = entry();
        e.constrained_delegation = Some(vec![Principal::parse("cifs/files@EXAMPLE.COM").unwrap()]);
        e.aliases = Some(Aliases {
            case_insensitive: false,
            names: vec![Principal::parse("alias@EXAMPLE.COM").unwrap()],
        });
        let back = decode(&encode(&e)).unwrap();
        assert_eq!(
            back.constrained_delegation,
            Some(vec![Principal::parse("cifs/files@EXAMPLE.COM").unwrap()])
        );
        assert_eq!(
            back.aliases.map(|a| a.names),
            Some(vec![Principal::parse("alias@EXAMPLE.COM").unwrap()])
        );
    }

    /// String attributes round-trip, in order, and an entry without any writes no extension at all
    /// — so a record this crate wrote before strings existed still decodes to the same entry.
    #[test]
    fn string_attributes_round_trip_in_order() {
        let mut e = entry();
        e.strings = vec![
            ("kpasswd_server".into(), "kpasswd.example.com".into()),
            ("kadmin_keytab".into(), "/etc/krb5.keytab".into()),
        ];
        let back = decode(&encode(&e)).unwrap();
        assert_eq!(back.strings, e.strings);

        let plain = decode(&encode(&entry())).unwrap();
        assert!(plain.strings.is_empty());
    }

    /// A value with an octet that is not ASCII survives: these are `GeneralString`s, and a path or
    /// a hostname is not guaranteed to be ASCII by anything this crate controls.
    #[test]
    fn a_string_value_need_not_be_ascii() {
        let mut e = entry();
        e.strings = vec![("note".into(), "ключ\tзначение".into())];
        let back = decode(&encode(&e)).unwrap();
        assert_eq!(back.strings[0].1, "ключ\tзначение");
    }

    /// An entry with no aliases writes no extension, and one that writes none reads back as
    /// `None` rather than as an empty list: the two differ, because the extension also carries
    /// the case switch.
    #[test]
    fn an_entry_without_aliases_has_no_extension() {
        let back = decode(&encode(&entry())).unwrap();
        assert!(back.aliases.is_none());
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
    fn a_delegation_acl_round_trips_and_absent_stays_absent() {
        // Three states, and the difference between them is the authorization decision: no list
        // (never set), an empty list ("to nobody"), and names. Collapsing any two of them would
        // either grant delegation nobody configured or deny one that was.
        let mut e = entry();
        e.constrained_delegation = Some(vec![
            Principal::parse("cifs/files.example.com@EXAMPLE.COM").unwrap(),
            Principal::parse("http/web.example.com@EXAMPLE.COM").unwrap(),
        ]);
        let back = decode(&encode(&e)).unwrap();
        assert_eq!(
            back.constrained_delegation.as_ref().map(|v| v.len()),
            Some(2),
            "both names survive"
        );
        let acl = back.constrained_delegation.unwrap();
        assert_eq!(acl[0].components, vec!["cifs", "files.example.com"]);
        assert_eq!(acl[1].components, vec!["http", "web.example.com"]);
        assert_eq!(
            acl[0].realm, "EXAMPLE.COM",
            "named in the entry's own realm"
        );

        // An empty list is a decision, not an absence.
        e.constrained_delegation = Some(Vec::new());
        let back = decode(&encode(&e)).unwrap();
        assert_eq!(
            back.constrained_delegation,
            Some(Vec::new()),
            "`to nobody` must not become `no restriction`"
        );

        // And an entry that never had one keeps the absence.
        e.constrained_delegation = None;
        let back = decode(&encode(&e)).unwrap();
        assert_eq!(back.constrained_delegation, None);
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
