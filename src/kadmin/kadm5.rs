//! MIT's `kadm5` constants and structures, as `kadm5.x` and `admin.h` define them.
//!
//! The status codes are MIT's, not Kerberos': a client prints them as text, and a
//! server that invented its own numbering would leave `kadmin` saying "unknown
//! error 12345678". The offsets are from `admin.h`'s error table, which starts at
//! `KADM5_ERROR_BASE` and numbers the entries in declaration order — so the
//! constants below are positions in that table, not free choices.
//!
//! The structures are the subset this server implements. A field the server does
//! not model is still written, zeroed, because the decoder is positional: omitting
//! one shifts every field after it.

use crate::admin::Modify;
use crate::hdb::HdbEntry;
use crate::name::Principal;

use super::xdr::{Reader, Writer};

/// The RPC program number of `kadm5` — Heimdal's `KADM_SERVER`, which is what
/// `kadmin` clients use for this protocol.
pub const PROG: u32 = 2112;
/// The RPC version.
pub const VERS: u32 = 2;

/// `kadm5_init`'s version, and the one this server answers with.
pub const API_VERSION_2: u32 = 0x1234_5702;
/// The version MIT 1.18 and later ask for first.
pub const API_VERSION_4: u32 = 0x1234_5704;

/// The procedures.
pub mod proc_ {
    /// `kadm5_init`.
    pub const INIT: u32 = 13;
    /// `get_privs`.
    pub const GET_PRIVS: u32 = 12;
    /// `get_principal`.
    pub const GET_PRINCIPAL: u32 = 5;
    /// `get_principals`, a glob.
    pub const GET_PRINCS: u32 = 14;
    /// `create_principal`.
    pub const CREATE_PRINCIPAL: u32 = 1;
    /// `delete_principal`.
    pub const DELETE_PRINCIPAL: u32 = 2;
    /// `chpass_principal`.
    pub const CHPASS_PRINCIPAL: u32 = 6;
    /// `chrand_principal3`, random keys with `keepold`.
    pub const CHRAND_PRINCIPAL3: u32 = 20;
    /// `modify_principal`.
    pub const MODIFY_PRINCIPAL: u32 = 3;
    /// `rename_principal`.
    pub const RENAME_PRINCIPAL: u32 = 4;
    /// `get_strings`.
    pub const GET_STRINGS: u32 = 23;
    /// `set_string`, which with a NULL value deletes the attribute.
    pub const SET_STRING: u32 = 24;
    /// `extract_keys`: the long-term keys in the clear, for `ktadd -norandkey`.
    pub const EXTRACT_KEYS: u32 = 26;
}

pub use proc_::{
    CHPASS_PRINCIPAL, CHRAND_PRINCIPAL3, CREATE_PRINCIPAL, DELETE_PRINCIPAL, EXTRACT_KEYS,
    GET_PRINCIPAL, GET_PRINCS, GET_PRIVS, GET_STRINGS, INIT, MODIFY_PRINCIPAL, RENAME_PRINCIPAL,
    SET_STRING,
};

/// The field masks of a `kadm5_principal_ent_rec` (`kadm5/admin.h`).
///
/// The mask *is* the request: each bit says the caller means that field, and a bit this server
/// cannot honour is refused rather than ignored — an operator who typed `modprinc -fail_auth_count 3`
/// and was told "success" would believe an account had been locked out.
pub mod mask {
    /// The principal's own name.
    pub const PRINCIPAL: u32 = 0x0000_0001;
    /// `princ_expire_time`.
    pub const PRINC_EXPIRE_TIME: u32 = 0x0000_0002;
    /// `pw_expiration`.
    pub const PW_EXPIRATION: u32 = 0x0000_0004;
    /// The attribute word.
    pub const ATTRIBUTES: u32 = 0x0000_0010;
    /// `max_life`.
    pub const MAX_LIFE: u32 = 0x0000_0020;
    /// `kvno`.
    pub const KVNO: u32 = 0x0000_0100;
    /// `policy`.
    pub const POLICY: u32 = 0x0000_0800;
    /// `policy`, cleared.
    pub const POLICY_CLR: u32 = 0x0000_1000;
    /// `max_renewable_life`.
    pub const MAX_RLIFE: u32 = 0x0000_2000;

    /// The bits `modify_principal` honours here.
    pub const MODIFY_SUPPORTED: u32 =
        PRINCIPAL | PRINC_EXPIRE_TIME | PW_EXPIRATION | ATTRIBUTES | MAX_LIFE | KVNO | MAX_RLIFE;
}

/// The `KADM5_*` attribute bits of a principal (`kadm5/admin.h`).
///
/// Twelve switches. Ten map onto an `hdb` flag, two — `DISALLOW_TGT_BASED` and
/// `DISALLOW_DUP_SKEY` — describe restrictions this KDC has no setting for, and setting one is
/// refused rather than dropped. Clearing either is fine: it asks for the permissive behaviour,
/// which is what a realm without the setting already has.
pub mod attr {
    /// `DISALLOW_POSTDATED`.
    pub const DISALLOW_POSTDATED: u32 = 0x0000_0001;
    /// `DISALLOW_FORWARDABLE`.
    pub const DISALLOW_FORWARDABLE: u32 = 0x0000_0002;
    /// `DISALLOW_TGT_BASED` — not modelled.
    pub const DISALLOW_TGT_BASED: u32 = 0x0000_0004;
    /// `DISALLOW_RENEWABLE`.
    pub const DISALLOW_RENEWABLE: u32 = 0x0000_0008;
    /// `DISALLOW_PROXIABLE`.
    pub const DISALLOW_PROXIABLE: u32 = 0x0000_0010;
    /// `DISALLOW_DUP_SKEY` — not modelled.
    pub const DISALLOW_DUP_SKEY: u32 = 0x0000_0020;
    /// `DISALLOW_ALL_TIX`.
    pub const DISALLOW_ALL_TIX: u32 = 0x0000_0040;
    /// `REQUIRES_PRE_AUTH`.
    pub const REQUIRES_PRE_AUTH: u32 = 0x0000_0080;
    /// `REQUIRES_HW_AUTH`.
    pub const REQUIRES_HW_AUTH: u32 = 0x0000_0100;
    /// `DISALLOW_SVR`.
    pub const DISALLOW_SVR: u32 = 0x0000_1000;
    /// `PWCHANGE_SERVICE`.
    pub const PWCHANGE_SERVICE: u32 = 0x0000_2000;
    /// `OK_AS_DELEGATE`.
    pub const OK_AS_DELEGATE: u32 = 0x0010_0000;

    /// The two bits with no `hdb` counterpart.
    pub const UNMODELLED: u32 = DISALLOW_TGT_BASED | DISALLOW_DUP_SKEY;
}

/// The `Modify` an attribute word asks for.
///
/// A word is a *set*, not a delta: MIT's `modprinc -attrs +requires_preauth` sends a word with
/// that bit and nothing else, so every switch this server models is written from the word — the
/// absent bits become "allowed", which is what the operator asked for by leaving them out.
pub fn modify_from_attributes(word: u32) -> std::result::Result<Modify, u32> {
    if word & attr::UNMODELLED != 0 {
        return Err(BAD_MASK);
    }
    let disallowed = |bit: u32| word & bit != 0;
    Ok(Modify {
        invalid: Some(disallowed(attr::DISALLOW_ALL_TIX)),
        require_preauth: Some(disallowed(attr::REQUIRES_PRE_AUTH)),
        require_hwauth: Some(disallowed(attr::REQUIRES_HW_AUTH)),
        change_password_service: Some(disallowed(attr::PWCHANGE_SERVICE)),
        ok_as_delegate: Some(disallowed(attr::OK_AS_DELEGATE)),
        allow_server: Some(!disallowed(attr::DISALLOW_SVR)),
        forwardable: Some(!disallowed(attr::DISALLOW_FORWARDABLE)),
        proxiable: Some(!disallowed(attr::DISALLOW_PROXIABLE)),
        renewable: Some(!disallowed(attr::DISALLOW_RENEWABLE)),
        postdated: Some(!disallowed(attr::DISALLOW_POSTDATED)),
        ..Modify::default()
    })
}

/// `KADM5_ERROR_BASE`: every `kadm5` status is this plus its index in MIT's table.
const BASE: u32 = 43_787_520;

/// Success.
pub const OK: u32 = 0;
/// "Operation failed for unspecified reason".
pub const FAILURE: u32 = BASE;
/// "Operation requires 'get' privilege".
pub const AUTH_GET: u32 = BASE + 1;
/// "Operation requires 'add' privilege".
pub const AUTH_ADD: u32 = BASE + 2;
/// "Operation requires 'modify' privilege".
pub const AUTH_MODIFY: u32 = BASE + 3;
/// "Operation requires 'delete' privilege".
pub const AUTH_DELETE: u32 = BASE + 4;
/// "Insufficient authorization for operation".
pub const AUTH_INSUFFICIENT: u32 = BASE + 5;
/// "Principal or policy already exists".
pub const DUP: u32 = BASE + 7;
/// "Connection to server not initialized".
pub const NOT_INIT: u32 = BASE + 11;
/// "Principal does not exist".
pub const UNK_PRINC: u32 = BASE + 12;
/// "Invalid field mask for operation".
pub const BAD_MASK: u32 = BASE + 14;
/// "Operation requires 'list' privilege".
pub const AUTH_LIST: u32 = BASE + 44;
/// "Operation requires 'change-password' privilege".
pub const AUTH_CHANGEPW: u32 = BASE + 45;
/// "Procedure not found" — the RPC-level answer for a procedure this server does
/// not implement, reported as a `kadm5` status so the client prints something
/// useful instead of an RPC error.
pub const UNK_PROC: u32 = BASE + 6;

/// Every privilege, as `get_privs` reports them to an administrator.
pub const PRIV_ALL: u32 = 0x1f | 0x20 | 0x40;

/// The mask a `get_principal` request asks for, and the one this server answers:
/// everything it models.
const MASK_ALL: u32 = 0x41_ffff;

/// Encodes a principal entry the way `_xdr_kadm5_principal_ent_rec` lays it out.
///
/// Positional: a field this server has no value for is written as zero rather
/// than dropped, because the decoder on the other side is positional too.
pub fn encode_principal_entry(entry: &HdbEntry) -> Vec<u8> {
    let mut w = Writer::new();
    w.nullstring(Some(&entry.principal.to_string()));
    w.i32(entry.valid_end.unwrap_or(0) as i32) // princ_expire_time
        .i32(0) // last_pwd_change: not modelled
        .i32(entry.pw_end.unwrap_or(0) as i32) // pw_expiration
        .i32(entry.max_life.unwrap_or(0) as i32)
        .absent() // mod_name: NULL
        .i32(entry.modified as i32) // mod_date
        .i32(attributes_of(entry) as i32)
        .u32(entry.kvno())
        .u32(1) // mkvno
        ;
    w.nullstring(None) // policy
        .i32(0) // aux_attributes
        .i32(entry.max_renew.unwrap_or(0) as i32)
        .i32(0) // last_success
        .i32(0) // last_failed
        .u32(0) // fail_auth_count
        .i32(0) // n_key_data
        .i32(0) // n_tl_data
        // The tag-value list is a pointer (TRUE = absent), and then the key array
        // is written with its own count — so `n_key_data` above and this count are
        // two different fields, and a decoder reads both.
        .bool(true)
        .u32(0); // no key data: this server hands out metadata, not keys
    w.into_bytes()
}

/// The `kadm5` attribute bits of an entry.
///
/// The mapping is not one-to-one: Heimdal's flags and MIT's `KADM5_ATTRIBUTES`
/// describe the same switches under different names, and a few have no
/// counterpart. What has none is left unset rather than guessed at.
fn attributes_of(entry: &HdbEntry) -> u32 {
    use crate::hdb::flags as h;
    let mut attributes = 0;
    if entry.has(h::REQUIRE_PREAUTH) {
        attributes |= 0x0000_0080; // REQUIRES_PRE_AUTH
    }
    if entry.has(h::REQUIRE_HWAUTH) {
        attributes |= 0x0000_0100; // REQUIRES_HW_AUTH
    }
    if entry.has(h::REQUIRE_PWCHANGE) {
        attributes |= 0x0000_0200; // REQUIRES_PWCHANGE
    }
    if entry.has(h::OK_AS_DELEGATE) {
        attributes |= 0x0010_0000; // OK_AS_DELEGATE
    }
    if !entry.has(h::SERVER) {
        attributes |= 0x0000_1000; // DISALLOW_SVR
    }
    if entry.has(h::CHANGE_PW) {
        attributes |= 0x0000_2000; // PWCHANGE_SERVICE
    }
    // The four `DISALLOW_*` trip attributes are emitted when the flag is *absent*, which is what
    // makes the two vocabularies reversible: a principal the KDC will not issue a forwardable
    // ticket for has to look that way to `kadmin getprinc`, or the operator and the KDC disagree
    // about the same account.
    if !entry.has(h::FORWARDABLE) {
        attributes |= attr::DISALLOW_FORWARDABLE;
    }
    if !entry.has(h::PROXIABLE) {
        attributes |= attr::DISALLOW_PROXIABLE;
    }
    if !entry.has(h::RENEWABLE) {
        attributes |= attr::DISALLOW_RENEWABLE;
    }
    if !entry.has(h::POSTDATE) {
        attributes |= attr::DISALLOW_POSTDATED;
    }
    if entry.has(h::INVALID) || entry.has(h::LOCKED_OUT) {
        attributes |= 0x0000_0040; // DISALLOW_ALL_TIX
    }
    attributes
}

/// `kadm5_principal_ent_rec`, as it arrives in a `create` or `modify` request.
///
/// One decoder for both because the shape is one: MIT sends the same record and follows it with a
/// mask (and, for `create`, a password). A field this server has no column for is read and dropped
/// — the record is positional, so skipping one shifts every field after it, and a decoder that
/// guessed which ones to skip would read a principal's expiry out of its key version.
pub struct EntryRec {
    /// The name the record is about.
    pub principal: Principal,
    /// `princ_expire_time`: 0 means "never", which is MIT's spelling, not the epoch.
    pub princ_expire: i64,
    /// `pw_expiration`, 0 meaning "never".
    pub pw_expiration: i64,
    /// `max_life`.
    pub max_life: i64,
    /// `attributes`: the `KADM5_*` attribute word.
    pub attributes: u32,
    /// `kvno`.
    pub kvno: u32,
    /// `policy`.
    pub policy: Option<String>,
    /// `max_renewable_life`.
    pub max_renew: i64,
}

/// Reads `_xdr_kadm5_principal_ent_rec` from `r`.
pub fn decode_entry_rec(r: &mut Reader<'_>) -> std::result::Result<EntryRec, u32> {
    let name = r.nullstring().map_err(|_| BAD_MASK)?.ok_or(UNK_PRINC)?;
    let principal = Principal::parse(&name).map_err(|_| UNK_PRINC)?;
    let princ_expire = r.i32().map_err(|_| BAD_MASK)?;
    let _last_pwd_change = r.i32().map_err(|_| BAD_MASK)?;
    let pw_expiration = r.i32().map_err(|_| BAD_MASK)?;
    let max_life = r.i32().map_err(|_| BAD_MASK)?;
    // `mod_name` is a plain XDR bool followed by the name when present: TRUE means absent, which
    // is MIT's `xdr_nulltype` and the inverse of what the name suggests.
    if !r.bool().map_err(|_| BAD_MASK)? {
        let _ = r.nullstring().map_err(|_| BAD_MASK)?;
    }
    let _mod_date = r.i32().map_err(|_| BAD_MASK)?;
    let attributes = r.u32().map_err(|_| BAD_MASK)?;
    let kvno = r.u32().map_err(|_| BAD_MASK)?;
    let _mkvno = r.u32().map_err(|_| BAD_MASK)?;
    let policy = r.nullstring().map_err(|_| BAD_MASK)?;
    let _aux = r.u32().map_err(|_| BAD_MASK)?;
    let max_renew = r.i32().map_err(|_| BAD_MASK)?;
    let _last_success = r.i32().map_err(|_| BAD_MASK)?;
    let _last_failed = r.i32().map_err(|_| BAD_MASK)?;
    let _fail_auth = r.u32().map_err(|_| BAD_MASK)?;
    let n_keys = r.i32().map_err(|_| BAD_MASK)?;
    for _ in 0..n_keys.max(0) {
        let _ = r.u32();
        let _ = r.opaque();
        let _ = r.i32();
        let _ = r.opaque();
        let _ = r.opaque();
    }
    let n_tl = r.i32().map_err(|_| BAD_MASK)?;
    // The tag-value list is a pointer whose entries follow when it is not NULL.
    if !r.bool().map_err(|_| BAD_MASK)? {
        for _ in 0..n_tl.max(0) {
            r.skip_tl_data().map_err(|_| BAD_MASK)?;
        }
    }
    // Then the key array's own count — a second field, distinct from `n_key_data`, and reading the
    // mask here instead lands the password four octets early and silently produces a keyless
    // principal.
    let n_keys = r.u32().map_err(|_| BAD_MASK)?;
    for _ in 0..n_keys {
        let _ = r.u32().map_err(|_| BAD_MASK)?;
        let _ = r.u32().map_err(|_| BAD_MASK)?;
        let _ = r.i32().map_err(|_| BAD_MASK)?;
        let _ = r.i32().map_err(|_| BAD_MASK)?;
        let _ = r.i32().map_err(|_| BAD_MASK)?;
        let _ = r.opaque().map_err(|_| BAD_MASK)?;
        let _ = r.opaque().map_err(|_| BAD_MASK)?;
        let _ = r.opaque().map_err(|_| BAD_MASK)?;
    }
    Ok(EntryRec {
        principal,
        princ_expire: i64::from(princ_expire),
        pw_expiration: i64::from(pw_expiration),
        max_life: i64::from(max_life),
        attributes,
        kvno,
        policy,
        max_renew: i64::from(max_renew),
    })
}

/// What `create_principal` carries, as far as this server reads it.
///
/// Returns the entry fields it understood and the password. The mask tells which
/// fields the client meant; a field outside it is zero and must not be applied, or
/// `addprinc` would set an expiry the operator never asked for.
pub fn decode_create(args: &[u8]) -> std::result::Result<(HdbEntry, Vec<u8>), u32> {
    let mut r = Reader::new(args);
    let _version = r.u32().map_err(|_| BAD_MASK)?;
    let rec = decode_entry_rec(&mut r)?;
    let mask = r.u32().map_err(|_| BAD_MASK)?;
    let password = r.nullstring().map_err(|_| BAD_MASK)?;

    let mut entry = HdbEntry::user(rec.principal);
    if mask & mask::MAX_LIFE != 0 && rec.max_life != 0 {
        entry.max_life = Some(rec.max_life);
    }
    if mask & mask::MAX_RLIFE != 0 && rec.max_renew != 0 {
        entry.max_renew = Some(rec.max_renew);
    }
    if mask & mask::PRINC_EXPIRE_TIME != 0 && rec.princ_expire != 0 {
        entry.valid_end = Some(rec.princ_expire);
    }
    if mask & mask::PW_EXPIRATION != 0 && rec.pw_expiration != 0 {
        entry.pw_end = Some(rec.pw_expiration);
    }
    if mask & mask::ATTRIBUTES != 0 {
        // Only the bits this server models, and only downwards: a client that omitted
        // `REQUIRES_PRE_AUTH` gets it anyway, because a principal with a password and no
        // pre-authentication is an offline crack waiting.
        if rec.attributes & attr::DISALLOW_ALL_TIX != 0 {
            entry.flags |= crate::hdb::flags::INVALID;
        }
        if rec.attributes & attr::DISALLOW_SVR == 0 {
            entry.flags |= crate::hdb::flags::SERVER;
        }
        if rec.attributes & attr::OK_AS_DELEGATE != 0 {
            entry.flags |= crate::hdb::flags::OK_AS_DELEGATE;
        }
        if rec.attributes & attr::PWCHANGE_SERVICE != 0 {
            entry.flags |= crate::hdb::flags::CHANGE_PW;
        }
    }
    let _ = MASK_ALL;
    Ok((entry, password.unwrap_or_default().into_bytes()))
}

/// A `modify_principal` request: the entry record, the mask, and nothing else.
///
/// The mask is the request. A bit that is set names a field the caller means to change, and a bit
/// this server cannot honour is refused by name rather than ignored — an operator who typed
/// `modprinc -fail_auth_count 3` and got "success" would believe an account was locked out.
pub fn decode_modify(args: &[u8]) -> std::result::Result<(Principal, Modify), u32> {
    let mut r = Reader::new(args);
    let _version = r.u32().map_err(|_| BAD_MASK)?;
    let rec = decode_entry_rec(&mut r)?;
    let mask = r.u32().map_err(|_| BAD_MASK)?;
    if mask == 0 {
        // MIT answers `KADM5_BAD_MASK` here, and so must this: a successful no-op is a change an
        // operator believes happened.
        return Err(BAD_MASK);
    }
    // A bit this server cannot honour is refused, not dropped. Policy bits land here too while
    // policies are unmodelled: the mask names a field, and answering "success" for a field nobody
    // stored is the failure mode this refuses.
    if mask & !mask::MODIFY_SUPPORTED != 0 {
        return Err(BAD_MASK);
    }

    let mut change = Modify::default();
    if mask & mask::PRINC_EXPIRE_TIME != 0 {
        // 0 is MIT's "never", not the epoch: `modprinc -expire 0` clears the expiry.
        change.valid_end = Some((rec.princ_expire != 0).then_some(rec.princ_expire));
    }
    if mask & mask::PW_EXPIRATION != 0 {
        change.pw_end = Some((rec.pw_expiration != 0).then_some(rec.pw_expiration));
    }
    if mask & mask::MAX_LIFE != 0 {
        change.max_life = Some((rec.max_life != 0).then_some(rec.max_life));
    }
    if mask & mask::MAX_RLIFE != 0 {
        change.max_renew = Some((rec.max_renew != 0).then_some(rec.max_renew));
    }
    if mask & mask::KVNO != 0 {
        change.kvno = Some(rec.kvno);
    }
    if mask & mask::ATTRIBUTES != 0 {
        // The attribute word replaces the switches, and `..` keeps the fields the mask did not
        // name: a `modprinc -attrs` says nothing about the expiry.
        let attributes = modify_from_attributes(rec.attributes)?;
        change = Modify {
            valid_end: change.valid_end,
            pw_end: change.pw_end,
            max_life: change.max_life,
            max_renew: change.max_renew,
            kvno: change.kvno,
            ..attributes
        };
    }
    Ok((rec.principal, change))
}

/// A `rename_principal` request: the old name and the new one.
pub fn decode_rename(args: &[u8]) -> std::result::Result<(Principal, Principal), u32> {
    let mut r = Reader::new(args);
    let _version = r.u32().map_err(|_| BAD_MASK)?;
    let from = r.nullstring().map_err(|_| BAD_MASK)?.ok_or(UNK_PRINC)?;
    let to = r.nullstring().map_err(|_| BAD_MASK)?.ok_or(UNK_PRINC)?;
    Ok((
        Principal::parse(&from).map_err(|_| UNK_PRINC)?,
        Principal::parse(&to).map_err(|_| UNK_PRINC)?,
    ))
}

/// Encodes one key block for a `chrand_principal3` reply.
pub fn encode_key_block(w: &mut Writer, entry: &HdbEntry, kvno: u32) {
    // `_xdr_krb5_keyblock`: enctype, then the key as opaque data.
    let key = entry
        .keys
        .iter()
        .find(|k| k.kvno == kvno)
        .or_else(|| entry.keys.first());
    match key {
        Some(key) => {
            w.i32(key.key.enctype().id());
            w.opaque(key.key.bytes());
        }
        None => {
            w.i32(0);
            w.opaque(&[]);
        }
    }
}

/// A `set_string` request: the principal, the key, and the value or nothing.
///
/// `None` is `delstr`, not "set to NULL": MIT's protocol uses the absence of the value to mean
/// removal, and a server that stored an empty string instead would answer "set" for a request that
/// asked for a deletion.
pub fn decode_set_string(
    args: &[u8],
) -> std::result::Result<(Principal, String, Option<String>), u32> {
    let mut r = Reader::new(args);
    let _version = r.u32().map_err(|_| BAD_MASK)?;
    let name = r.nullstring().map_err(|_| BAD_MASK)?.ok_or(UNK_PRINC)?;
    let principal = Principal::parse(&name).map_err(|_| UNK_PRINC)?;
    let key = r.nullstring().map_err(|_| BAD_MASK)?.ok_or(BAD_MASK)?;
    let value = r.nullstring().map_err(|_| BAD_MASK)?;
    Ok((principal, key, value))
}

/// A `get_strings` request: just the principal.
pub fn decode_get_strings(args: &[u8]) -> std::result::Result<Principal, u32> {
    let mut r = Reader::new(args);
    let _version = r.u32().map_err(|_| BAD_MASK)?;
    let name = r.nullstring().map_err(|_| BAD_MASK)?.ok_or(UNK_PRINC)?;
    Principal::parse(&name).map_err(|_| UNK_PRINC)
}

/// The body of a `get_strings` reply: the pairs, with their count twice.
///
/// No `generic_ret` here — the dispatcher writes `api_version` and the code for every procedure.
/// The count appears twice because it is two different things that happen to have the same value:
/// an `int32` the C client prints, and the XDR array count the decoder reads before the elements.
pub fn encode_strings(strings: &[(String, String)]) -> Vec<u8> {
    let mut w = Writer::new();
    w.i32(strings.len() as i32);
    w.u32(strings.len() as u32);
    for (key, value) in strings {
        w.nullstring(Some(key)).nullstring(Some(value));
    }
    w.into_bytes()
}

/// A `extract_keys` request: the principal and the kvno, where zero means every kvno the database
/// holds.
pub fn decode_extract_keys(args: &[u8]) -> std::result::Result<(Principal, Option<u32>), u32> {
    let mut r = Reader::new(args);
    let _version = r.u32().map_err(|_| BAD_MASK)?;
    let name = r.nullstring().map_err(|_| BAD_MASK)?.ok_or(UNK_PRINC)?;
    let principal = Principal::parse(&name).map_err(|_| UNK_PRINC)?;
    // An older client sends no kvno at all, and MIT reads that as "all of them" — the same meaning
    // as an explicit zero, so the two cases collapse here.
    let kvno = r.u32().ok().filter(|k| *k != 0);
    Ok((principal, kvno))
}

/// `KRB5_KDB_SALTTYPE_NORMAL` and `KRB5_KDB_SALTTYPE_SPECIAL`, the two a key record can name.
///
/// A key with no recorded salt took the enctype's default construction, which is what `NORMAL`
/// means; one with octets was built from those octets, which is `SPECIAL`. The client that asks for
/// keys rebuilds nothing from these two fields, but a client that does reads them correctly.
const SALTTYPE_NORMAL: i32 = 0;
const SALTTYPE_SPECIAL: i32 = 4;

/// The body of an `extract_keys` reply: the key records, each with its own kvno.
///
/// The count appears once here, unlike in `get_strings`: `kadm5_key_data` is an XDR array and the
/// decoder reads the array count alone.
pub fn encode_key_data(keys: &[crate::hdb::HdbKey]) -> Vec<u8> {
    let mut w = Writer::new();
    w.u32(keys.len() as u32);
    for record in keys {
        w.u32(record.kvno);
        w.i32(record.key.enctype().id());
        w.opaque(record.key.bytes());
        match &record.salt {
            Some(salt) => w.i32(SALTTYPE_SPECIAL).opaque(salt),
            None => w.i32(SALTTYPE_NORMAL).opaque(&[]),
        };
    }
    w.into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{Enctype, OwnCipher};

    #[test]
    fn the_status_codes_are_where_mit_puts_them() {
        // Positions in `admin.h`'s table; a client prints these numbers as text,
        // so an offset error shows up as the wrong message rather than no message.
        assert_eq!(AUTH_GET - BASE, 1);
        assert_eq!(AUTH_ADD - BASE, 2);
        assert_eq!(AUTH_DELETE - BASE, 4);
        assert_eq!(DUP - BASE, 7);
        assert_eq!(UNK_PRINC - BASE, 12);
        assert_eq!(AUTH_LIST - BASE, 44);
        assert_eq!(AUTH_CHANGEPW - BASE, 45);
    }

    #[test]
    fn an_entry_is_encoded_positionally_with_the_absent_marker_for_mod_name() {
        let mut entry = HdbEntry::user(Principal::parse("alice@R").unwrap());
        entry
            .add_password_key(&OwnCipher, Enctype::Aes256Sha1, b"pw", 3)
            .unwrap();
        entry.max_life = Some(36_000);
        let bytes = encode_principal_entry(&entry);

        let mut r = Reader::new(&bytes);
        assert_eq!(
            r.nullstring().unwrap().as_deref(),
            Some("alice@R"),
            "names are NUL-terminated, not XDR strings"
        );
        assert_eq!(r.i32().unwrap(), 0, "no expiry");
        assert_eq!(r.i32().unwrap(), 0, "last_pwd_change is not modelled");
        assert_eq!(r.i32().unwrap(), 0, "no pw_expiration");
        assert_eq!(r.i32().unwrap(), 36_000, "max_life");
        assert!(r.bool().unwrap(), "mod_name is absent");
        assert_eq!(r.i32().unwrap(), 0, "mod_date");
        assert_eq!(
            r.u32().unwrap(),
            0x80 | 0x1000 | 0x1,
            "REQUIRES_PRE_AUTH, DISALLOW_SVR because a user entry is not a server, and \
             DISALLOW_POSTDATED because `HdbEntry::user` does not allow postdating"
        );
    }

    #[test]
    fn a_create_without_a_mask_field_leaves_the_defaults_alone() {
        // `addprinc` sends only what it was told; a server that applied zeroes
        // would give every principal an expiry of the epoch.
        let mut w = Writer::new();
        w.u32(API_VERSION_2);
        w.nullstring(Some("bob@R"));
        for _ in 0..4 {
            w.i32(0);
        }
        // mod_name absent (TRUE), mod_date, attributes, kvno, mkvno.
        w.bool(true).i32(0).i32(0).u32(0).u32(0);
        w.nullstring(None).i32(0); // policy, aux_attributes
        w.i32(0).i32(0).i32(0).u32(0); // max_renew, last_success, last_failed, fail_auth
        w.u32(0) // n_key_data
            .i32(0) // n_tl_data
            .bool(true) // tl_data absent
            .u32(0) // the key array's count
            .u32(0) // mask: nothing set
            .nullstring(Some("a password"));

        let (entry, password) = decode_create(w.bytes()).unwrap();
        assert_eq!(entry.principal.to_string(), "bob@R");
        assert_eq!(password, b"a password");
        assert_eq!(entry.max_life, None, "no mask bit, no value");
        assert_eq!(entry.valid_end, None);
    }

    /// The create argument as the client writes it, with `mask` and `attributes`
    /// under the caller's control.
    fn create_args(mask: u32, attributes: u32, max_life: i32, expire: i32) -> Vec<u8> {
        let mut w = Writer::new();
        w.u32(API_VERSION_2);
        w.nullstring(Some("bob@R"));
        w.i32(expire).i32(0).i32(0).i32(max_life);
        w.bool(true).i32(0).i32(attributes as i32).u32(0).u32(0);
        w.nullstring(None).i32(0);
        w.i32(0).i32(0).i32(0).u32(0);
        w.i32(0).i32(0).bool(true).u32(0);
        w.u32(mask).nullstring(Some("a password"));
        w.into_bytes()
    }

    /// A `modify` request: the same record `create` sends, then the mask and nothing else.
    fn modify_args(mask: u32, attributes: u32, max_life: i32, expire: i32) -> Vec<u8> {
        let mut w = Writer::new();
        w.u32(API_VERSION_2);
        w.nullstring(Some("bob@R"));
        w.i32(expire).i32(0).i32(0).i32(max_life);
        w.bool(true).i32(0).i32(attributes as i32).u32(0).u32(0);
        w.nullstring(None).i32(0);
        w.i32(0).i32(0).i32(0).u32(0);
        w.i32(0).i32(0).bool(true).u32(0);
        w.u32(mask);
        w.into_bytes()
    }

    /// An extract request carries a kvno, and zero means every one — the same meaning as an older
    /// client that sends no kvno at all.
    #[test]
    fn an_extract_request_reads_zero_as_all_kvnos() {
        for (written, want) in [(Some(3u32), Some(3u32)), (Some(0), None), (None, None)] {
            let mut w = Writer::new();
            w.u32(API_VERSION_2).nullstring(Some("alice@R"));
            if let Some(kvno) = written {
                w.u32(kvno);
            }
            let (principal, kvno) = decode_extract_keys(&w.into_bytes()).unwrap();
            assert_eq!(principal.to_string(), "alice@R");
            assert_eq!(kvno, want, "written {written:?}");
        }
    }

    /// The key records go out with one count and one salt type per key — the two places a decoder
    /// that assumed "count twice" (as `get_strings` has it) or "no salt" would read past.
    #[test]
    fn key_records_carry_their_kvno_enctype_and_salt() {
        use crate::crypto::{Enctype, Key};
        let keys = vec![
            crate::hdb::HdbKey {
                kvno: 2,
                key: Key::new(Enctype::Aes256Sha1, [7u8; 32]).unwrap(),
                salt: None,
            },
            crate::hdb::HdbKey {
                kvno: 2,
                key: Key::new(Enctype::Aes128Sha1, [9u8; 16]).unwrap(),
                salt: Some(b"EXAMPLE.COMalice".to_vec()),
            },
        ];
        let bytes = encode_key_data(&keys);
        let mut r = Reader::new(&bytes);
        let n = r.u32().unwrap();
        assert_eq!(n, 2, "the array count appears once");
        let first_kvno = r.u32().unwrap();
        let first_enctype = r.i32().unwrap();
        let first_key = r.opaque().unwrap().to_vec();
        let first_salttype = r.i32().unwrap();
        let first_salt = r.opaque().unwrap().to_vec();
        assert_eq!(
            (first_kvno, first_enctype),
            (2, 18),
            "aes256-cts-hmac-sha1-96"
        );
        assert_eq!(first_key, [7u8; 32]);
        assert_eq!(
            (first_salttype, first_salt.len()),
            (0, 0),
            "no salt recorded"
        );

        let _second_kvno = r.u32().unwrap();
        let second_enctype = r.i32().unwrap();
        let _second_key = r.opaque().unwrap();
        let second_salttype = r.i32().unwrap();
        let second_salt = r.opaque().unwrap().to_vec();
        assert_eq!(second_enctype, 17, "aes128-cts-hmac-sha1-96");
        assert_eq!(second_salttype, 4, "a recorded salt is SALTTYPE_SPECIAL");
        assert_eq!(second_salt, b"EXAMPLE.COMalice");
        assert!(r.rest().is_empty(), "and nothing follows the last key");
    }

    #[test]
    fn a_modify_carries_only_the_fields_its_mask_names() {
        let (principal, change) = decode_modify(&modify_args(
            mask::MAX_LIFE | mask::PRINC_EXPIRE_TIME,
            0,
            36_000,
            1_700_000_000,
        ))
        .unwrap();
        assert_eq!(principal.to_string(), "bob@R");
        assert_eq!(change.max_life, Some(Some(36_000)));
        assert_eq!(change.valid_end, Some(Some(1_700_000_000)));
        // A field the mask did not name is not a change, even though the record carries a zero
        // for it: applying that zero would clear an expiry the operator never mentioned.
        assert_eq!(change.pw_end, None);
        assert_eq!(change.max_renew, None);
        assert_eq!(change.kvno, None);
        assert!(!change.is_empty());
    }

    /// `modprinc -expire 0` means "never", not "the epoch": MIT spells the absence of an expiry as
    /// zero, and a server that stored 1970 would refuse every ticket for the principal.
    #[test]
    fn a_zero_expiry_in_a_modify_clears_it() {
        let (_, change) = decode_modify(&modify_args(mask::PRINC_EXPIRE_TIME, 0, 0, 0)).unwrap();
        assert_eq!(change.valid_end, Some(None));
    }

    /// An empty mask is an error, not a successful no-op: an operator who ran `modprinc` with no
    /// options has to be told that nothing happened.
    #[test]
    fn a_modify_with_no_fields_is_refused() {
        assert_eq!(
            decode_modify(&modify_args(0, 0, 0, 0)).unwrap_err(),
            BAD_MASK
        );
    }

    /// A mask bit this server cannot honour is refused by name rather than ignored — including the
    /// policy bits, while policies are unmodelled.
    #[test]
    fn a_mask_bit_this_server_cannot_honour_is_refused() {
        for bit in [
            mask::POLICY,
            mask::POLICY_CLR,
            0x0000_0008, // LAST_PWD_CHANGE
            0x0000_0040, // MOD_TIME
            0x0001_0000, // FAIL_AUTH_COUNT
            0x0002_0000, // KEY_DATA
        ] {
            assert_eq!(
                decode_modify(&modify_args(bit | mask::MAX_LIFE, 0, 3600, 0)).unwrap_err(),
                BAD_MASK,
                "mask bit {bit:#x} must be refused"
            );
        }
    }

    /// The attribute word is a set, and every switch this server models is written from it — the
    /// absent bits mean "allowed", which is what leaving them out asks for.
    #[test]
    fn the_attribute_word_sets_every_switch_it_models() {
        use crate::hdb::flags as h;
        let (_, change) = decode_modify(&modify_args(
            mask::ATTRIBUTES,
            attr::REQUIRES_PRE_AUTH | attr::OK_AS_DELEGATE,
            0,
            0,
        ))
        .unwrap();
        assert_eq!(change.require_preauth, Some(true));
        assert_eq!(change.ok_as_delegate, Some(true));
        assert_eq!(
            change.forwardable,
            Some(true),
            "DISALLOW_FORWARDABLE absent"
        );
        assert_eq!(change.allow_server, Some(true), "DISALLOW_SVR absent");
        assert_eq!(change.invalid, Some(false));
        assert_eq!(change.change_password_service, Some(false));

        // And with the disallow bits set, the same switches go the other way.
        let (_, change) = decode_modify(&modify_args(
            mask::ATTRIBUTES,
            attr::DISALLOW_ALL_TIX
                | attr::DISALLOW_SVR
                | attr::DISALLOW_FORWARDABLE
                | attr::PWCHANGE_SERVICE,
            0,
            0,
        ))
        .unwrap();
        assert_eq!(change.invalid, Some(true));
        assert_eq!(change.allow_server, Some(false));
        assert_eq!(change.forwardable, Some(false));
        assert_eq!(change.change_password_service, Some(true));
        assert_eq!(change.require_preauth, Some(false));
        let _ = h::SERVER;
    }

    /// The two attribute bits with no `hdb` counterpart are refused when set: dropping them would
    /// answer "success" for a restriction nobody stored.
    #[test]
    fn an_attribute_this_server_cannot_store_is_refused() {
        for bit in [attr::DISALLOW_TGT_BASED, attr::DISALLOW_DUP_SKEY] {
            assert_eq!(
                decode_modify(&modify_args(mask::ATTRIBUTES, bit, 0, 0)).unwrap_err(),
                BAD_MASK,
                "attribute {bit:#x} must be refused"
            );
        }
    }

    #[test]
    fn a_rename_carries_two_names() {
        let mut w = Writer::new();
        w.u32(API_VERSION_2);
        w.nullstring(Some("bob@R"));
        w.nullstring(Some("robert@R"));
        let (from, to) = decode_rename(&w.into_bytes()).unwrap();
        assert_eq!(from.to_string(), "bob@R");
        assert_eq!(to.to_string(), "robert@R");

        // A missing name is a malformed request, not a rename to "nothing".
        let mut w = Writer::new();
        w.u32(API_VERSION_2)
            .nullstring(Some("bob@R"))
            .nullstring(None);
        assert_eq!(decode_rename(&w.into_bytes()).unwrap_err(), UNK_PRINC);
    }

    #[test]
    fn the_mask_decides_which_fields_are_applied() {
        // `addprinc -maxlife 10h` sets the bit; `addprinc` alone does not, and a
        // server that applied zeroes would give every principal an expiry of the
        // epoch.
        let (entry, _) = decode_create(&create_args(0x00_0020, 0, 36_000, 0)).unwrap();
        assert_eq!(entry.max_life, Some(36_000));

        let (entry, _) = decode_create(&create_args(0, 0, 36_000, 0)).unwrap();
        assert_eq!(entry.max_life, None, "no mask bit, no value");
    }

    #[test]
    fn a_disallow_all_tix_attribute_makes_the_entry_invalid() {
        let (entry, _) = decode_create(&create_args(0x00_0010, 0x0000_0040, 0, 0)).unwrap();
        assert!(entry.has(crate::hdb::flags::INVALID));
    }

    #[test]
    fn an_expiry_attribute_lands_in_valid_end() {
        let (entry, _) = decode_create(&create_args(0x00_0002, 0, 0, 1_700_000_000)).unwrap();
        assert_eq!(entry.valid_end, Some(1_700_000_000));
    }

    #[test]
    fn the_attribute_bits_come_back_out_as_heimdal_flags() {
        // The mapping has to be reversible for the fields both vocabularies share,
        // or `kadmin getprinc` shows a different account from the one the KDC uses.
        use crate::hdb::flags as h;
        let mut entry = HdbEntry::user(Principal::parse("host/h@R").unwrap());
        entry.flags |= h::SERVER | h::OK_AS_DELEGATE | h::REQUIRE_PREAUTH;
        let attributes = attributes_of(&entry);
        assert_eq!(attributes & 0x0000_0080, 0x0000_0080, "REQUIRES_PRE_AUTH");
        assert_eq!(attributes & 0x0010_0000, 0x0010_0000, "OK_AS_DELEGATE");
        assert_eq!(
            attributes & 0x0000_1000,
            0,
            "a server does not DISALLOW_SVR"
        );

        entry.flags &= !h::SERVER;
        assert_eq!(
            attributes_of(&entry) & 0x0000_1000,
            0x0000_1000,
            "and a principal that is not a server does"
        );
    }

    #[test]
    fn an_unknown_name_in_a_create_is_refused_rather_than_defaulted() {
        let mut w = Writer::new();
        w.u32(API_VERSION_2);
        w.nullstring(Some("not a principal"));
        w.i32(0).i32(0).i32(0).i32(0);
        w.bool(true).i32(0).i32(0).u32(0).u32(0);
        w.nullstring(None).i32(0);
        w.i32(0).i32(0).i32(0).u32(0);
        w.i32(0).i32(0).bool(true).u32(0);
        w.u32(0).nullstring(None);
        assert_eq!(decode_create(w.bytes()).unwrap_err(), UNK_PRINC);
    }
}
