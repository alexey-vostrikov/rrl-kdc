//! Heimdal's `HDB_entry` DER: the value a propagation carries and a database stores.
//!
//! This is `lib/hdb/hdb.asn1`'s `HDB_entry`, written and read by hand — the same reason every other
//! structure in this crate is: the field numbers and the tagging are the protocol, and a derived
//! codec hides exactly the facts a reader needs to check against the ASN.1.
//!
//! ```text
//! HDB_entry ::= SEQUENCE {
//!     principal   [0] Principal OPTIONAL,
//!     kvno        [1] INTEGER,
//!     keys        [2] Keys,                 -- SEQUENCE OF Key
//!     created-by  [3] Event,
//!     modified-by [4] Event OPTIONAL,
//!     valid-start [5] KerberosTime OPTIONAL,
//!     valid-end   [6] KerberosTime OPTIONAL,
//!     pw-end      [7] KerberosTime OPTIONAL,
//!     max-life    [8] INTEGER OPTIONAL,
//!     max-renew   [9] INTEGER OPTIONAL,
//!     flags       [10] HDBFlags,            -- BIT STRING
//!     etypes      [11] HDB-EncTypeList OPTIONAL,
//!     generation  [12] GENERATION OPTIONAL,
//!     extensions  [13] HDB-extensions OPTIONAL }
//! ```
//!
//! **The numbering is not the order**, and that is the first thing a reader gets wrong: `principal`
//! is `[0]`, `kvno` is `[1]`, but the *flags* are `[10]` and sit after the times. A structure written
//! in declaration order and numbered in sequence looks right and is unreadable by Heimdal.
//!
//! **`created-by` is compulsory.** It is an `Event`: a time and, optionally, a principal. Heimdal
//! writes the entry's `modified` time there (and `modified-by` carries who, when it knows), so an
//! entry with no `modified` is written as an event at the epoch — which is what an entry created by
//! code that never recorded one has to look like.
//!
//! **Extensions are the realm's own layer**, and the ones this crate writes keep Heimdal's numbers:
//! `[2]` `allowed-to-delegate-to`, `[6]` aliases, `[12]` the policy name, `[16]` this crate's string
//! attributes. Heimdal reads what it knows and skips the rest, which is what makes `[16]` safe to
//! send it.
//!
//! What this is *not*: our own database record format ([`super::record`]), which numbers the same
//! fields differently and predates the port. The two exist side by side because switching a stored
//! format is a migration, not a refactor, and a propagation is a place where the difference is fatal
//! — Heimdal's `hprop` sends `HDB_entry`, so a slave that could only read `record` could not receive
//! anything.

use crate::crypto::{Enctype, Key};
use crate::der;
use crate::error::{Error, Result};
use crate::hdb::{HdbEntry, HdbKey, flags as entry_flags};
use crate::msg::as_time;
use crate::name::Principal;

/// The number of a context tag: `[n]` is `0xa0 | n` for the numbers this protocol uses.
///
/// A tag that is not context-class has no number here, and a caller that gets `None` skips the field
/// rather than guessing — an unknown universal tag in the middle of this structure means the octets
/// are not an `HDB_entry` at all.
fn field_number(tag: u8) -> Option<u8> {
    (tag & 0xc0 == 0x80 && tag & 0x1f < 0x1f).then_some(tag & 0x1f)
}

/// The DER of one entry, as `hdb_entry2value` produces it.
pub fn encode(entry: &HdbEntry) -> Vec<u8> {
    let mut fields = vec![
        // `principal [0] Principal OPTIONAL` — always written by us: an entry without a name is
        // legal only for compatibility with libkrb5's older dumps, and nothing this crate stores is.
        der::field(0, principal_value(&entry.principal)),
        der::field(1, der::int(entry.kvno as i64)),
        der::field(2, keys_value(&entry.keys)),
        // `created-by [3] Event`: Heimdal writes the entry's `modified` here.
        der::field(3, event_value(entry.modified, None)),
    ];

    for (number, value) in [
        (5, entry.valid_start),
        (6, entry.valid_end),
        (7, entry.pw_end),
    ] {
        if let Some(time) = value {
            fields.push(der::field(number, der::time(time)));
        }
    }
    for (number, value) in [(8, entry.max_life), (9, entry.max_renew)] {
        if let Some(seconds) = value {
            fields.push(der::field(number, der::int(seconds)));
        }
    }
    // `flags [10] HDBFlags`: a BIT STRING, which is what makes a decoder that expected an INTEGER
    // fail with "expected tag 0x02, got 0x03" — the mistake this module exists to avoid.
    fields.push(der::field(10, der::flags32(entry.flags)));
    if let Some(etypes) = &entry.etypes {
        fields.push(der::field(
            11,
            der::seq(
                &etypes
                    .iter()
                    .map(|e| der::int(e.id() as i64))
                    .collect::<Vec<_>>(),
            ),
        ));
    }
    if let Some(extensions) = extensions_value(entry) {
        fields.push(der::field(13, extensions));
    }
    der::seq(&fields)
}

/// One entry out of its DER, for a realm that stores its keys in the clear.
///
/// A sealed key is a refusal here — see [`decode_with`], which is what a realm with a master key
/// uses.
pub fn decode(data: &[u8]) -> Result<HdbEntry> {
    decode_with(data, None)
}

/// One entry out of its DER, opening sealed keys with `master`.
///
/// `master` is both the cipher and the key set, because unsealing needs both and a caller that passed
/// one without the other would be passing half an argument.
pub fn decode_with(
    data: &[u8],
    master: Option<(&dyn crate::crypto::Cipher, &crate::hdb::mkey::MasterKeys)>,
) -> Result<HdbEntry> {
    let mut r = der::Reader::new(data);
    let outer = r
        .next_tlv("HDB_entry")
        .map_err(|e| Error::Hdb(format!("HDB_entry: {e}")))?;
    if outer.tag != der::SEQUENCE {
        return Err(Error::Hdb("HDB_entry is not a SEQUENCE".into()));
    }
    let mut f = der::Reader::new(outer.content);

    // Every field is tagged, so the fields may arrive in any order — and Heimdal's own encoder emits
    // them in declaration order, which is *not* numeric order for the flags and the extensions. Each
    // is therefore collected by number rather than read positionally.
    let mut principal: Option<Principal> = None;
    let mut kvno = 0u32;
    let mut keys = Vec::new();
    let mut created_time: Option<i64> = None;
    let mut valid_start = None;
    let mut valid_end = None;
    let mut pw_end = None;
    let mut max_life = None;
    let mut max_renew = None;
    let mut entry_flags_value = 0u32;
    let mut etypes = None;
    let mut extensions: Vec<(u8, Vec<u8>)> = Vec::new();

    while !f.is_empty() {
        let field = f
            .next_tlv("HDB_entry field")
            .map_err(|e| Error::Hdb(format!("HDB_entry: {e}")))?;
        let number = match field_number(field.tag) {
            Some(n) => n,
            None => continue,
        };
        let mut inner = der::Reader::new(field.content);
        let value = inner
            .next_tlv("HDB_entry value")
            .map_err(|e| Error::Hdb(format!("HDB_entry [{number}]: {e}")))?;
        match number {
            0 => principal = Some(principal_from(value)?),
            1 => {
                kvno = u32::try_from(
                    der::as_int("kvno", value.content)
                        .map_err(|e| Error::Hdb(format!("HDB_entry: {e}")))?,
                )
                .map_err(|_| Error::Hdb("HDB_entry: kvno does not fit in 32 bits".into()))?;
            }
            2 => keys = keys_from(value, master)?,
            3 => created_time = Some(event_time(value)?),
            5 => valid_start = Some(time_from("valid-start", value)?),
            6 => valid_end = Some(time_from("valid-end", value)?),
            7 => pw_end = Some(time_from("pw-end", value)?),
            8 => {
                max_life = Some(
                    der::as_int("max-life", value.content)
                        .map_err(|e| Error::Hdb(format!("HDB_entry: {e}")))?,
                )
            }
            9 => {
                max_renew = Some(
                    der::as_int("max-renew", value.content)
                        .map_err(|e| Error::Hdb(format!("HDB_entry: {e}")))?,
                )
            }
            10 => {
                entry_flags_value = der::as_flags32("flags", value.content)
                    .map_err(|e| Error::Hdb(format!("HDB_entry: {e}")))?
            }
            11 => {
                // `etypes [11] HDB-EncTypeList ::= SEQUENCE OF INTEGER`: the list is the field's
                // content, so there is one reader and no second binding to keep in step.
                let mut er = der::Reader::new(value.content);
                let mut list = Vec::new();
                while !er.is_empty() {
                    let item = er
                        .next_tlv("etypes")
                        .map_err(|e| Error::Hdb(format!("HDB_entry etypes: {e}")))?;
                    if let Ok(id) = der::as_int("etypes", item.content)
                        && let Ok(enctype) = Enctype::from_i32(id as i32)
                    {
                        list.push(enctype);
                    }
                }
                etypes = Some(list);
            }
            // `HDB-extensions ::= SEQUENCE OF HDB-extension`: each element is a `[n]`-tagged value
            // whose number this crate reads for the ones it knows.
            13 if value.tag == der::SEQUENCE => {
                let mut er = der::Reader::new(value.content);
                while !er.is_empty() {
                    let item = er
                        .next_tlv("extension")
                        .map_err(|e| Error::Hdb(format!("HDB_entry extensions: {e}")))?;
                    extensions.push((item.tag, item.content.to_vec()));
                }
            }
            // `4` is `modified-by` (who made the change, which this crate does not model), `12` is
            // `generation` (a directory's change counter). Both are read and dropped rather than
            // refused: an entry from another KDC carries them, and refusing one over a field that
            // changes nothing here would refuse a valid database.
            _ => {}
        }
    }

    let principal = principal.ok_or_else(|| {
        Error::Hdb("HDB_entry without a principal: nothing to store it under".into())
    })?;
    let mut entry = HdbEntry::user(principal);
    entry.kvno = kvno;
    entry.keys = keys;
    entry.flags = entry_flags_value;
    entry.valid_start = valid_start;
    entry.valid_end = valid_end;
    entry.pw_end = pw_end;
    entry.max_life = max_life;
    entry.max_renew = max_renew;
    entry.etypes = etypes;
    entry.modified = created_time.unwrap_or(0);
    read_extensions(&mut entry, &extensions)?;
    Ok(entry)
}

/// `Principal ::= SEQUENCE { name [0] PrincipalName, realm [1] Realm }`.
fn principal_value(principal: &Principal) -> Vec<u8> {
    der::seq(&[
        der::field(
            0,
            der::seq(&[
                der::field(0, der::int(principal.name_type as i64)),
                der::field(
                    1,
                    der::seq(
                        &principal
                            .components
                            .iter()
                            .map(|c| der::general_string(c))
                            .collect::<Vec<_>>(),
                    ),
                ),
            ]),
        ),
        der::field(1, der::general_string(&principal.realm)),
    ])
}

fn principal_from(value: der::Tlv<'_>) -> Result<Principal> {
    let mut f = der::Reader::new(value.content);
    let name = f
        .next_tlv("name")
        .map_err(|e| Error::Hdb(format!("Principal: {e}")))?;
    let mut name_reader = der::Reader::new(name.content);
    let name = name_reader
        .next_tlv("PrincipalName")
        .map_err(|e| Error::Hdb(format!("Principal: {e}")))?;
    let mut nf = der::Reader::new(name.content);
    let name_type = nf
        .next_tlv("name-type")
        .map_err(|e| Error::Hdb(format!("PrincipalName: {e}")))?;
    let name_type = der::as_int(
        "name-type",
        der::Reader::new(name_type.content)
            .next_tlv("name-type")
            .map_err(|e| Error::Hdb(format!("PrincipalName: {e}")))?
            .content,
    )
    .map_err(|e| Error::Hdb(format!("PrincipalName: {e}")))?;
    let strings = nf
        .next_tlv("name-string")
        .map_err(|e| Error::Hdb(format!("PrincipalName: {e}")))?;
    // `name-string [1] SEQUENCE OF KerberosString`, under `EXPLICIT TAGS`: the field wraps a
    // `SEQUENCE`, whose content is the components back to back. An encoder that treated the tag as
    // implicit puts the components straight into the field, so both shapes are read — and the
    // difference matters: taking the wrapper's content as one string collapses `host/s.example.com`
    // into `host`, which is exactly what a first push from Heimdal would have stored.
    let mut sr = der::Reader::new(strings.content);
    let mut peek = der::Reader::new(strings.content);
    if let Ok(first) = peek.next_tlv("name-string")
        && first.tag == der::SEQUENCE
    {
        sr = der::Reader::new(first.content);
    }
    let mut components = Vec::new();
    while !sr.is_empty() {
        let item = sr
            .next_tlv("name-string")
            .map_err(|e| Error::Hdb(format!("PrincipalName: {e}")))?;
        let text = if item.tag == der::GENERAL_STRING {
            item.content
        } else {
            let mut ir = der::Reader::new(item.content);
            ir.next_tlv("name-string")
                .map_err(|e| Error::Hdb(format!("PrincipalName: {e}")))?
                .content
        };
        components.push(String::from_utf8_lossy(text).into_owned());
    }
    let realm = f
        .next_tlv("realm")
        .map_err(|e| Error::Hdb(format!("Principal: {e}")))?;
    // `Realm` is a `KerberosString`, which is a `GeneralString`: tagged, not bare octets.
    let realm = if realm.tag == der::GENERAL_STRING {
        String::from_utf8_lossy(realm.content).into_owned()
    } else {
        let mut rr = der::Reader::new(realm.content);
        let inner = rr
            .next_tlv("realm")
            .map_err(|e| Error::Hdb(format!("Principal realm: {e}")))?;
        String::from_utf8_lossy(inner.content).into_owned()
    };
    Ok(Principal {
        name_type: name_type as i32,
        components,
        realm,
    })
}

/// `Keys ::= SEQUENCE OF Key`, each `SEQUENCE { mkvno [0] OPT, key [1] EncryptionKey, salt [2] OPT }`.
fn keys_value(keys: &[HdbKey]) -> Vec<u8> {
    der::seq(
        &keys
            .iter()
            .map(|key| {
                let mut parts = vec![der::field(
                    1,
                    der::seq(&[
                        der::field(0, der::int(key.key.enctype().id() as i64)),
                        der::field(1, der::octets(key.key.bytes())),
                    ]),
                )];
                if let Some(salt) = &key.salt {
                    // `Salt ::= SEQUENCE { type [0] INTEGER, salt [1] OCTET STRING }`, type 3 being
                    // `hdb-pw-salt` — the salt a password-derived key used.
                    parts.push(der::field(
                        2,
                        der::seq(&[der::field(0, der::int(3)), der::field(1, der::octets(salt))]),
                    ));
                }
                der::seq(&parts)
            })
            .collect::<Vec<_>>(),
    )
}

fn keys_from(
    value: der::Tlv<'_>,
    master: Option<(&dyn crate::crypto::Cipher, &crate::hdb::mkey::MasterKeys)>,
) -> Result<Vec<HdbKey>> {
    let mut r = der::Reader::new(value.content);
    let mut keys = Vec::new();
    while !r.is_empty() {
        let item = r
            .next_tlv("Key")
            .map_err(|e| Error::Hdb(format!("Keys: {e}")))?;
        let mut kf = der::Reader::new(item.content);
        // `Key ::= SEQUENCE { mkvno [0] INTEGER OPTIONAL, key [1] EncryptionKey, salt [2] Salt OPT`:
        // the entry's own `kvno` is not in this structure at all, and the key version lives on the
        // `HDB_entry` above. `mkvno` is which master key sealed it.
        let kvno = 0u32;
        let mut mkvno: Option<u32> = None;
        let mut key: Option<Key> = None;
        let mut salt: Option<Vec<u8>> = None;
        while !kf.is_empty() {
            let field = kf
                .next_tlv("Key field")
                .map_err(|e| Error::Hdb(format!("Key: {e}")))?;
            let number = field_number(field.tag).unwrap_or(u8::MAX);
            let mut inner = der::Reader::new(field.content);
            let value = inner
                .next_tlv("Key value")
                .map_err(|e| Error::Hdb(format!("Key [{number}]: {e}")))?;
            match number {
                1 => {
                    let mut ef = der::Reader::new(value.content);
                    let etype = ef
                        .next_tlv("keytype")
                        .map_err(|e| Error::Hdb(format!("EncryptionKey: {e}")))?;
                    let etype = der::as_int(
                        "keytype",
                        der::Reader::new(etype.content)
                            .next_tlv("keytype")
                            .map_err(|e| Error::Hdb(format!("EncryptionKey: {e}")))?
                            .content,
                    )
                    .map_err(|e| Error::Hdb(format!("EncryptionKey: {e}")))?;
                    // `keyvalue [1] OCTET STRING`: the field is tagged, so the octets are one
                    // level further in than the field. Reading `bytes.content` here is the mistake
                    // that yields "a 32-octet key, got 34" — the tag and length are still in it.
                    let field = ef
                        .next_tlv("keyvalue")
                        .map_err(|e| Error::Hdb(format!("EncryptionKey: {e}")))?;
                    let mut vr = der::Reader::new(field.content);
                    let bytes = vr
                        .next_tlv("keyvalue")
                        .map_err(|e| Error::Hdb(format!("EncryptionKey: {e}")))?;
                    let enctype = Enctype::from_i32(etype as i32)
                        .map_err(|e| Error::Hdb(format!("EncryptionKey: {e}")))?;
                    // A key that is not the enctype's length is a key **sealed under a master
                    // key** — Heimdal's `hdb_seal_keys_mkey` wraps it, and an AES-256 key arrives
                    // as a confounder, the key and a tag (60 octets). Saying "takes 32, got 60"
                    // would read as corruption; this says what it actually is, and what is missing.
                    let material = if crate::hdb::mkey::is_plain_key(bytes.content, enctype) {
                        bytes.content.to_vec()
                    } else {
                        // A key sealed under the master key: `confounder + key + tag`, which for
                        // AES-256 is 60 octets where the key is 32. Heimdal's `hprop` sends exactly
                        // this when the master database is sealed, and unsealing is the only way to
                        // install such a database.
                        let (cipher, keys) = master.ok_or_else(|| {
                            Error::Hdb(format!(
                                "a {}-octet key for {}: this is a key sealed under a master key \
                                 (Heimdal's `hdb_seal_keys_mkey`), and no master key was supplied. \
                                 Either give this realm the master keytab, or push with \
                                 `hprop -D` so that the master sends the keys in the clear",
                                bytes.content.len(),
                                enctype.name()
                            ))
                        })?;
                        keys.unseal(cipher, bytes.content, mkvno, enctype)?
                    };
                    key = Some(
                        Key::new(enctype, material)
                            .map_err(|e| Error::Hdb(format!("EncryptionKey: {e}")))?,
                    );
                }
                2 => {
                    let mut sf = der::Reader::new(value.content);
                    // `type [0]` is read and dropped: this crate stores the salt and not its
                    // declared type, because every salt it writes is `hdb-pw-salt`.
                    let _ = sf.next_tlv("salt type");
                    if let Ok(bytes) = sf.next_tlv("salt") {
                        let mut br = der::Reader::new(bytes.content);
                        if let Ok(inner) = br.next_tlv("salt") {
                            salt = Some(inner.content.to_vec());
                        }
                    }
                }
                0 => {
                    mkvno = Some(
                        u32::try_from(
                            der::as_int("mkvno", value.content)
                                .map_err(|e| Error::Hdb(format!("Key mkvno: {e}")))?,
                        )
                        .map_err(|_| Error::Hdb("Key mkvno does not fit in 32 bits".into()))?,
                    )
                }
                _ => {}
            }
        }
        if let Some(key) = key {
            // `mkvno` belongs to the stored form and this codec has just unsealed the key, so the
            // entry it returns holds plaintext: a store that seals sets the field again.
            keys.push(HdbKey {
                kvno,
                key,
                salt,
                mkvno: None,
            });
        }
    }
    Ok(keys)
}

/// `Event ::= SEQUENCE { time [0] KerberosTime, principal [1] Principal OPTIONAL }`.
fn event_value(time: i64, principal: Option<&Principal>) -> Vec<u8> {
    let mut parts = vec![der::field(0, der::time(time))];
    if let Some(principal) = principal {
        parts.push(der::field(1, principal_value(principal)));
    }
    der::seq(&parts)
}

fn event_time(value: der::Tlv<'_>) -> Result<i64> {
    let mut f = der::Reader::new(value.content);
    let time = f
        .next_tlv("time")
        .map_err(|e| Error::Hdb(format!("Event: {e}")))?;
    time_from("created-by", time)
}

fn time_from(what: &'static str, value: der::Tlv<'_>) -> Result<i64> {
    // `KerberosTime` is a `GeneralizedTime`, tagged.
    let mut r = der::Reader::new(value.content);
    match r.next_tlv(what) {
        Ok(inner) if inner.tag == der::GENERALIZED_TIME => {
            as_time(what, value.content).map_err(|e| Error::Hdb(format!("HDB_entry {what}: {e}")))
        }
        _ => as_time(what, value.content).map_err(|e| Error::Hdb(format!("HDB_entry {what}: {e}"))),
    }
}

/// The extensions this crate writes, numbered as Heimdal numbers them.
fn extensions_value(entry: &HdbEntry) -> Option<Vec<u8>> {
    let mut parts: Vec<Vec<u8>> = Vec::new();
    if let Some(delegation) = &entry.constrained_delegation {
        // `HDB-Ext-Constrained-delegation-acl ::= SEQUENCE OF Principal`, in a `[2]`-tagged value.
        parts.push(der::field(
            2,
            der::seq(&delegation.iter().map(principal_value).collect::<Vec<_>>()),
        ));
    }
    if let Some(aliases) = &entry.aliases {
        // `HDB-Ext-Aliases ::= SEQUENCE { case-insensitive [0] BOOLEAN, aliases [1] SEQUENCE OF
        // Principal }`. `[1]` is written because that is where a reader looks; the case flag is
        // omitted, and `OPTIONAL` is not in the ASN.1 for it only because Heimdal always writes it —
        // a reader that required it would refuse every entry this crate sends.
        parts.push(der::field(
            6,
            der::seq(&[der::field(
                1,
                der::seq(
                    &aliases
                        .names
                        .iter()
                        .map(principal_value)
                        .collect::<Vec<_>>(),
                ),
            )]),
        ));
    }
    if let Some(policy) = &entry.policy {
        parts.push(der::field(12, der::general_string(policy)));
    }
    if parts.is_empty() {
        None
    } else {
        Some(der::seq(&parts))
    }
}

/// Reads back the extensions this crate understands, dropping the rest.
fn read_extensions(entry: &mut HdbEntry, extensions: &[(u8, Vec<u8>)]) -> Result<()> {
    for (tag, content) in extensions {
        let number = field_number(*tag);
        let content = &content[..];
        match number {
            Some(6) => {
                // `HDB-Ext-Aliases ::= SEQUENCE { case-insensitive [0] BOOLEAN, aliases [1] SEQUENCE
                // OF Principal }`. Only `[1]` is read: the case flag is a property of the directory,
                // and a name this crate stores is matched case-sensitively or not at all.
                let mut outer = der::Reader::new(content);
                let outer = outer
                    .next_tlv("aliases")
                    .map_err(|e| Error::Hdb(format!("HDB-Ext-Aliases: {e}")))?;
                let mut aliases = Vec::new();
                let mut walker = der::Reader::new(outer.content);
                while !walker.is_empty() {
                    let field = walker
                        .next_tlv("aliases field")
                        .map_err(|e| Error::Hdb(format!("HDB-Ext-Aliases: {e}")))?;
                    if field_number(field.tag) == Some(1) {
                        let mut list = der::Reader::new(field.content);
                        let list = list
                            .next_tlv("alias list")
                            .map_err(|e| Error::Hdb(format!("HDB-Ext-Aliases: {e}")))?;
                        let mut items = der::Reader::new(list.content);
                        while !items.is_empty() {
                            let item = items
                                .next_tlv("alias")
                                .map_err(|e| Error::Hdb(format!("HDB-Ext-Aliases: {e}")))?;
                            aliases.push(principal_from(item)?);
                        }
                    }
                }
                if !aliases.is_empty() {
                    entry.aliases = Some(crate::hdb::Aliases {
                        // The case flag is a directory's property and is not modelled by this
                        // crate's matcher, which compares exact names; writing `false` says so.
                        case_insensitive: false,
                        names: aliases,
                    });
                }
            }
            Some(12) => {
                let mut r = der::Reader::new(content);
                let text = r
                    .next_tlv("policy")
                    .map_err(|e| Error::Hdb(format!("HDB-Ext-Policy: {e}")))?;
                entry.policy = Some(String::from_utf8_lossy(text.content).into_owned());
            }
            // `[16]` is this crate's own string attributes, and `[2]` the delegation list. Both are
            // written by `record`'s codec with their own shapes; a propagation is not the place to
            // re-derive them, so they are left alone rather than guessed at.
            _ => {}
        }
    }
    Ok(())
}

/// Keeps the flag names in scope: an entry's flags are `HDBFlags`, and a reader should be able to see
/// which bit the code is talking about without opening another file.
const _: u32 = entry_flags::CLIENT;

#[cfg(test)]
mod tests {
    use super::*;

    fn entry() -> HdbEntry {
        let mut entry = HdbEntry::user(Principal::parse("alice@EXAMPLE.COM").expect("a principal"));
        entry.add_key(
            Key::new(Enctype::Aes256Sha1, vec![0x5a; 32]).expect("a key"),
            3,
            Some(b"EXAMPLE.COMalice".to_vec()),
        );
        entry.max_life = Some(86_400);
        entry.modified = 1_700_000_000;
        entry
    }

    /// A round trip keeps every field the codec claims to carry, including the ones whose numbers are
    /// out of order in the ASN.1 (`flags` is `[10]`, after the times).
    #[test]
    fn an_entry_round_trips() {
        let original = entry();
        let decoded = decode(&encode(&original)).expect("decodes");
        assert_eq!(decoded.principal, original.principal);
        assert_eq!(decoded.kvno, original.kvno);
        assert_eq!(decoded.flags, original.flags);
        assert_eq!(decoded.max_life, original.max_life);
        assert_eq!(decoded.modified, original.modified);
        assert_eq!(decoded.keys.len(), 1);
        assert_eq!(decoded.keys[0].key.enctype(), Enctype::Aes256Sha1);
        assert_eq!(decoded.keys[0].key.bytes(), vec![0x5a; 32]);
        assert_eq!(
            decoded.keys[0].salt.as_deref(),
            Some(&b"EXAMPLE.COMalice"[..])
        );
    }

    /// The field numbers are Heimdal's, spelled out here so that a "tidy-up" into declaration order
    /// fails: `principal` is `[0]`, `kvno` `[1]`, `keys` `[2]`, `created-by` `[3]`, `flags` `[10]`,
    /// `extensions` `[13]`.
    #[test]
    fn the_field_numbers_are_heimdals() {
        let encoded = encode(&entry());
        let mut r = der::Reader::new(&encoded);
        let body = r.next_tlv("HDB_entry").expect("a SEQUENCE");
        let mut f = der::Reader::new(body.content);
        let mut numbers = Vec::new();
        while !f.is_empty() {
            let field = f.next_tlv("field").expect("a field");
            numbers.push(field_number(field.tag).expect("a context tag"));
        }
        // `[8]` is `max-life`, which the fixture sets; `[5]`–`[7]` are absent, and `[10]` is the
        // flags — after the times, which is the ordering a reader has to expect.
        assert_eq!(numbers, vec![0, 1, 2, 3, 8, 10]);
        assert!(
            !numbers.contains(&4),
            "modified-by is optional and is not written"
        );
    }

    /// `flags` is a BIT STRING, and a decoder that expected an INTEGER there is exactly the mistake
    /// Heimdal's first push produced: "expected tag 0x02, got 0x30" came from that class of error.
    #[test]
    fn the_flags_field_is_a_bit_string() {
        let encoded = encode(&entry());
        let mut r = der::Reader::new(&encoded);
        let body = r.next_tlv("HDB_entry").expect("a SEQUENCE");
        let mut f = der::Reader::new(body.content);
        let mut seen = None;
        while !f.is_empty() {
            let field = f.next_tlv("field").expect("a field");
            if field_number(field.tag) == Some(10) {
                let mut inner = der::Reader::new(field.content);
                seen = Some(inner.next_tlv("flags").expect("the flags").tag);
            }
        }
        assert_eq!(seen, Some(der::BIT_STRING));
    }

    /// An entry with no `modified` still carries `created-by`, because the field is compulsory: an
    /// event at the epoch, which is what "nobody recorded when" looks like.
    #[test]
    fn a_missing_modification_time_is_an_event_at_the_epoch() {
        let mut entry = entry();
        entry.modified = 0;
        let decoded = decode(&encode(&entry)).expect("decodes");
        assert_eq!(decoded.modified, 0);
    }

    /// An entry from a KDC that writes the optional fields this crate does not model decodes anyway:
    /// `modified-by` and `generation` are read and dropped, not refused.
    #[test]
    fn fields_this_crate_does_not_model_are_dropped_and_not_refused() {
        let base = entry();
        // Rebuild the encoding with two extra fields in it.
        let encoded = encode(&base);
        let mut r = der::Reader::new(&encoded);
        let body = r.next_tlv("HDB_entry").expect("a SEQUENCE");
        let mut fields = body.content.to_vec();
        fields.extend(der::field(
            4,
            event_value(1_600_000_000, Some(&base.principal)),
        ));
        fields.extend(der::field(
            12,
            der::seq(&[
                der::field(0, der::time(1_699_999_999)),
                der::field(1, der::int(0)),
                der::field(2, der::int(42)),
            ]),
        ));
        // `cons` frames already-encoded parts, which is exactly what "the same fields, plus two" is.
        let decoded = decode(&der::cons(der::SEQUENCE, &[fields]))
            .expect("an entry with extra fields decodes");
        assert_eq!(decoded.principal, base.principal);
        assert_eq!(decoded.modified, base.modified);
    }

    /// A record without a principal is refused with a reason: there is nothing to store it under.
    #[test]
    fn an_entry_without_a_principal_is_refused() {
        let without = der::seq(&[
            der::field(1, der::int(1)),
            der::field(2, der::seq(&[])),
            der::field(3, event_value(0, None)),
            der::field(10, der::flags32(entry_flags::SERVER)),
        ]);
        let err = decode(&without).expect_err("no principal");
        assert!(err.to_string().contains("without a principal"), "{err}");
    }

    /// An entry whose key is sealed under the master key opens with it — and without it the refusal
    /// names the master key rather than calling the key corrupt, because those are different
    /// problems for whoever has to fix it.
    #[test]
    fn a_sealed_key_opens_with_the_master_key_and_not_without() {
        use crate::crypto::{Cipher, OwnCipher};
        use crate::hdb::mkey::{MasterKeys, seal_key};

        let master = OwnCipher.random(Enctype::Aes256Sha1).expect("a key");
        let keys = MasterKeys::single(master.clone(), 1);
        let plain = vec![0x5au8; 32];
        let sealed = seal_key(&OwnCipher, &master, &plain).expect("sealed");
        assert_eq!(sealed.len(), 60, "the size a sealed AES-256 key has");

        // Build the entry by hand: `encode` writes plain keys, which is what our own storage does.
        let principal = Principal::parse("alice@EXAMPLE.COM").expect("a name");
        let entry_der = der::seq(&[
            der::field(0, principal_value(&principal)),
            der::field(1, der::int(3)),
            der::field(
                2,
                der::seq(&[der::seq(&[
                    der::field(0, der::int(1)),
                    der::field(
                        1,
                        der::seq(&[
                            der::field(0, der::int(18)),
                            der::field(1, der::octets(&sealed)),
                        ]),
                    ),
                ])]),
            ),
            der::field(3, event_value(1_700_000_000, None)),
            der::field(10, der::flags32(entry_flags::CLIENT)),
        ]);

        let opened = decode_with(&entry_der, Some((&OwnCipher, &keys))).expect("the key opens");
        assert_eq!(opened.keys.len(), 1);
        assert_eq!(opened.keys[0].key.bytes(), plain.as_slice());
        assert_eq!(opened.keys[0].key.enctype(), Enctype::Aes256Sha1);

        // Without a master key, the refusal names it and points at `hprop -D`.
        let err = decode(&entry_der).expect_err("no master key");
        let text = err.to_string();
        assert!(text.contains("sealed under a master key"), "{text}");
        assert!(text.contains("hprop -D"), "{text}");

        // With the wrong master key: a refusal that says the key is wrong, not the record.
        let wrong = MasterKeys::single(OwnCipher.random(Enctype::Aes256Sha1).expect("a key"), 1);
        let err = decode_with(&entry_der, Some((&OwnCipher, &wrong))).expect_err("wrong key");
        assert!(err.to_string().contains("does not open"), "{err}");
    }

    /// The aliases and the policy extension survive, because a slave needs them: an entry whose alias
    /// vanished in a propagation stops answering to the name that reached it.
    #[test]
    fn aliases_and_the_policy_survive_a_round_trip() {
        let mut entry = entry();
        entry.aliases = Some(crate::hdb::Aliases {
            case_insensitive: false,
            names: vec![Principal::parse("alice@EXAMPLE.COM").expect("a name")],
        });
        entry.policy = Some("default".to_owned());
        let decoded = decode(&encode(&entry)).expect("decodes");
        assert_eq!(decoded.policy.as_deref(), Some("default"));
        assert_eq!(
            decoded.aliases.expect("aliases").names.len(),
            1,
            "the alias list is written and read"
        );
    }
}
