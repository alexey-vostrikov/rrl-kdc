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
}

pub use proc_::{
    CHPASS_PRINCIPAL, CHRAND_PRINCIPAL3, CREATE_PRINCIPAL, DELETE_PRINCIPAL, GET_PRINCIPAL,
    GET_PRINCS, GET_PRIVS, INIT,
};

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
    if entry.has(h::INVALID) || entry.has(h::LOCKED_OUT) {
        attributes |= 0x0000_0040; // DISALLOW_ALL_TIX
    }
    attributes
}

/// What `create_principal` carries, as far as this server reads it.
///
/// Returns the entry fields it understood and the password. The mask tells which
/// fields the client meant; a field outside it is zero and must not be applied, or
/// `addprinc` would set an expiry the operator never asked for.
pub fn decode_create(args: &[u8]) -> std::result::Result<(HdbEntry, Vec<u8>), u32> {
    let mut r = Reader::new(args);
    let _version = r.u32().map_err(|_| BAD_MASK)?;
    let name = r.nullstring().map_err(|_| BAD_MASK)?.ok_or(UNK_PRINC)?;
    let principal = Principal::parse(&name).map_err(|_| UNK_PRINC)?;
    let princ_expire = r.i32().map_err(|_| BAD_MASK)?;
    let _last_pwd_change = r.i32().map_err(|_| BAD_MASK)?;
    let pw_expiration = r.i32().map_err(|_| BAD_MASK)?;
    let max_life = r.i32().map_err(|_| BAD_MASK)?;
    // `mod_name` is a plain XDR bool followed by the name when present: TRUE
    // means absent, which is MIT's `xdr_nulltype` and the inverse of intuition.
    if !r.bool().map_err(|_| BAD_MASK)? {
        let _ = r.nullstring().map_err(|_| BAD_MASK)?;
    }
    let _mod_date = r.i32().map_err(|_| BAD_MASK)?;
    let attributes = r.u32().map_err(|_| BAD_MASK)?;
    let _kvno = r.u32().map_err(|_| BAD_MASK)?;
    let _mkvno = r.u32().map_err(|_| BAD_MASK)?;
    let _policy = r.nullstring().map_err(|_| BAD_MASK)?;
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
    // Then the key array's own count — a second field, distinct from
    // `n_key_data`, and reading the mask here instead lands the password four
    // octets early and silently produces a keyless principal.
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
    let mask = r.u32().map_err(|_| BAD_MASK)?;
    let password = r.nullstring().map_err(|_| BAD_MASK)?;
    let mut entry = HdbEntry::user(principal);
    if mask & 0x00_0020 != 0 && max_life != 0 {
        entry.max_life = Some(i64::from(max_life));
    }
    if mask & 0x00_2000 != 0 && max_renew != 0 {
        entry.max_renew = Some(i64::from(max_renew));
    }
    if mask & 0x00_0002 != 0 && princ_expire != 0 {
        entry.valid_end = Some(i64::from(princ_expire));
    }
    if mask & 0x00_0004 != 0 && pw_expiration != 0 {
        entry.pw_end = Some(i64::from(pw_expiration));
    }
    if mask & 0x00_0010 != 0 {
        // Only the bits this server models, and only downwards: a client that
        // omitted `REQUIRES_PRE_AUTH` gets it anyway, because a principal with a
        // password and no pre-authentication is an offline crack waiting.
        if attributes & 0x0000_0040 != 0 {
            entry.flags |= crate::hdb::flags::INVALID;
        }
        if attributes & 0x0000_1000 == 0 {
            entry.flags |= crate::hdb::flags::SERVER;
        }
        if attributes & 0x0010_0000 != 0 {
            entry.flags |= crate::hdb::flags::OK_AS_DELEGATE;
        }
        if attributes & 0x0000_2000 != 0 {
            entry.flags |= crate::hdb::flags::CHANGE_PW;
        }
    }
    let _ = MASK_ALL;
    Ok((entry, password.unwrap_or_default().into_bytes()))
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
            0x80 | 0x1000,
            "REQUIRES_PRE_AUTH, and DISALLOW_SVR because a user entry is not a server"
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
