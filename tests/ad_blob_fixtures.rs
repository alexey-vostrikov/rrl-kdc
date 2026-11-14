//! `supplementalCredentials` written by somebody else, read by this crate.
//!
//! The rest of `hdb::ad_blob`'s tests round-trip this crate's own encoder through its own decoder,
//! which a codec always passes. These fixtures come from a **real Samba**: `samba-tool domain
//! provision` and `samba-tool user add` wrote the attribute into a directory, and the keys in it
//! were confirmed against the same account's keytab — Samba's own string-to-key, not a reading of the
//! blob. `scripts/ad-blob-fixtures.py` produces them and refuses to write one whose halves disagree.
//!
//! What the fixtures found on arrival is the reason they were worth making: a blob Samba writes holds
//! **four** credentials for a freshly created account — `aes256-cts`, `aes128-cts`, `des-cbc-md5` and
//! `des-cbc-crc` — and this reader used to refuse the whole blob on the DES pair. Every account in an
//! AD-shaped directory was therefore unreadable. Nothing in the crate could have noticed: the encoder
//! never wrote DES, so no round-trip test had one to meet.

// `hdb::ad_blob` is the reading half of an LDAP-backed database, so it lives behind the same feature
// as the mapping that calls it.
#![cfg(feature = "hdb-ldap")]

use std::path::{Path, PathBuf};

use rrl_kdc::crypto::{Cipher, Enctype, OwnCipher};
use rrl_kdc::hdb::ad_blob::{credentials, credentials_with_skipped};

/// One fixture, as the generator wrote it.
#[derive(Debug)]
struct Fixture {
    name: String,
    blob: Vec<u8>,
    /// `(enctype, key)` for the credentials this crate implements.
    credentials: Vec<(i32, Vec<u8>)>,
    salt: Vec<u8>,
    /// Enctypes in the blob that this crate does not implement.
    skipped: Vec<i32>,
    /// The account's password, published by the generator: a throwaway in an ephemeral domain.
    password: String,
}

fn fixtures() -> Vec<Fixture> {
    let directory = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/ad_blob");
    let entries = std::fs::read_dir(&directory)
        .unwrap_or_else(|e| panic!("{}: {e}", directory.display()))
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
        .collect::<Vec<PathBuf>>();
    assert!(
        !entries.is_empty(),
        "{}: no fixtures — run `scripts/ad-blob-fixtures.py`",
        directory.display()
    );

    let mut out = Vec::new();
    for path in entries {
        let text = std::fs::read_to_string(&path).expect("a fixture is readable");
        let value: serde_json::Value =
            serde_json::from_str(&text).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        let hex = |key: &str| -> Vec<u8> {
            let text = value[key]
                .as_str()
                .unwrap_or_else(|| panic!("{}: no {key}", path.display()));
            (0..text.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("hex"))
                .collect()
        };
        let credentials = value["credentials"]
            .as_array()
            .unwrap_or_else(|| panic!("{}: no credentials", path.display()))
            .iter()
            .map(|credential| {
                let id = credential["enctype"].as_i64().expect("an enctype") as i32;
                let key = credential["key"].as_str().expect("a key");
                let key = (0..key.len())
                    .step_by(2)
                    .map(|i| u8::from_str_radix(&key[i..i + 2], 16).expect("hex"))
                    .collect::<Vec<u8>>();
                (id, key)
            })
            .collect::<Vec<_>>();
        // Text, not hex: the fixture states the salt string-to-key was given, and the reader has to
        // decode it out of the blob's UTF-16LE.
        let salt = value["credentials"]
            .as_array()
            .and_then(|c| c.first())
            .and_then(|c| c["salt"].as_str())
            .expect("a salt")
            .as_bytes()
            .to_vec();
        out.push(Fixture {
            name: value["name"].as_str().unwrap_or("?").to_owned(),
            blob: hex("blob"),
            credentials,
            salt,
            password: value["password"]
                .as_str()
                .unwrap_or_else(|| panic!("{}: no password", path.display()))
                .to_owned(),
            skipped: value["skipped_enctypes"]
                .as_array()
                .map(|list| {
                    list.iter()
                        .map(|v| v.as_i64().expect("an enctype") as i32)
                        .collect()
                })
                .unwrap_or_default(),
        });
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

/// Every key Samba wrote is read back with the enctype, the octets and the salt it has.
#[test]
fn the_keys_a_directory_wrote_are_read_back() {
    for fixture in fixtures() {
        let keys = credentials(&fixture.blob)
            .unwrap_or_else(|e| panic!("{}: a blob Samba wrote must decode: {e}", fixture.name));

        assert_eq!(
            keys.len(),
            fixture.credentials.len(),
            "{}: the credentials this crate implements",
            fixture.name
        );
        for (key, (id, octets)) in keys.iter().zip(&fixture.credentials) {
            assert_eq!(
                key.enctype.id(),
                *id,
                "{}: enctype, in the blob's order",
                fixture.name
            );
            assert_eq!(key.key, *octets, "{}: the key octets", fixture.name);
            assert_eq!(
                key.salt.as_deref(),
                Some(fixture.salt.as_slice()),
                "{}: the salt, which the structure states once for every key in it",
                fixture.name
            );
        }
    }
}

/// The DES pair a directory always writes is skipped and named, not fatal.
#[test]
fn the_des_credentials_are_skipped_and_reported() {
    for fixture in fixtures() {
        let (keys, skipped) = credentials_with_skipped(&fixture.blob)
            .unwrap_or_else(|e| panic!("{}: {e}", fixture.name));
        // As a set: the report comes out in the blob's order, which is the directory's, and pinning
        // that order here would be pinning Samba's layout rather than our reading of it.
        let mut ours = skipped.clone();
        let mut theirs = fixture.skipped.clone();
        ours.sort_unstable();
        theirs.sort_unstable();
        assert_eq!(
            ours, theirs,
            "{}: the enctypes this crate does not implement",
            fixture.name
        );
        assert!(
            skipped.contains(&1) && skipped.contains(&3),
            "{}: `des-cbc-crc` and `des-cbc-md5`, which every real blob carries: {skipped:?}",
            fixture.name
        );
        assert!(
            !keys.is_empty(),
            "{}: and the account is still readable, which is the point",
            fixture.name
        );
    }
}

/// The same blob read into `(kvno, key)` at the version the directory declares.
///
/// The version is not in the blob — `KERB_STORED_CREDENTIAL_NEW` has no field for it — so it comes
/// from `msDS-KeyVersionNumber`, and this checks that what the KDC would be handed carries it.
#[test]
fn the_keys_read_at_a_version_are_the_ones_a_ticket_needs() {
    for fixture in fixtures() {
        let keys = rrl_kdc::hdb::ad_blob::keys(&fixture.blob, 7)
            .unwrap_or_else(|e| panic!("{}: {e}", fixture.name));
        assert_eq!(keys.len(), fixture.credentials.len(), "{}", fixture.name);
        for key in &keys {
            assert_eq!(
                key.kvno, 7,
                "{}: the version the directory declares",
                fixture.name
            );
            assert_ne!(
                key.key.enctype(),
                Enctype::Rc4Hmac,
                "{}: Samba writes AES for a fresh account, so a reader that reported RC4 here would \
                 be reading the wrong octets",
                fixture.name
            );
        }
    }
}

/// The salt read out of the blob is the one the keys were derived with.
///
/// This is the assertion the other three cannot make. A salt read as raw octets would be
/// `F\0I\0X\0…` — a string with a NUL after every character — and every key derived from it would
/// differ from the keys sitting in the same blob. So: take the account's password, take the salt the
/// reader reports, run string-to-key, and require the key the blob holds. The fixture's key came from
/// Samba's own keytab, so a match means three independent things agree.
#[test]
fn the_salt_reads_as_the_string_the_keys_were_derived_with() {
    for fixture in fixtures() {
        let keys = credentials(&fixture.blob).unwrap_or_else(|e| panic!("{}: {e}", fixture.name));
        let salt = keys
            .first()
            .and_then(|k| k.salt.clone())
            .unwrap_or_else(|| panic!("{}: no salt", fixture.name));
        assert!(
            salt.iter().all(|&b| b != 0),
            "{}: a salt with NULs between the characters is the UTF-16LE encoding, not the salt: \
             {:?}",
            fixture.name,
            String::from_utf8_lossy(&salt)
        );

        let cipher = OwnCipher;
        for key in &keys {
            let derived = cipher
                .s2k(key.enctype, fixture.password.as_bytes(), &salt, None)
                .unwrap_or_else(|e| {
                    panic!("{}: string-to-key for {:?}: {e}", fixture.name, key.enctype)
                });
            assert_eq!(
                derived.bytes(),
                key.key.as_slice(),
                "{}: {:?} from the password and the salt the blob states",
                fixture.name,
                key.enctype
            );
        }
    }
}
