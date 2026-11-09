//! Writes `supplementalCredentials` blobs and what they must contain, for the
//! independent parser to check.
//!
//! `scripts/verify-ad-blob.sh` runs this and then hands the octets to impacket's
//! `samr.USER_PROPERTIES`, which is a second implementation of the same part of
//! [MS-SAMR] written by somebody else. What this example writes beside each blob is
//! the ground truth it would like to see come back: the principal and every key,
//! **by generation**, in hexadecimal.
//!
//! By generation, because that is the thing an encoder gets wrong: putting the
//! previous keys where the current ones belong produces a blob that still parses
//! and still contains every key, and it would hand an auditor yesterday's key as
//! the account's current one.
//!
//! Deliberately not a test: the check needs Python and a package this crate does
//! not depend on, so it lives in a script that says so when it cannot run, rather
//! than in a test suite that would silently skip.
//!
//! ```sh
//! scripts/verify-ad-blob.sh
//! ```

use std::path::Path;

use rust_kdc::crypto::{Enctype, OwnCipher};
use rust_kdc::hdb::HdbEntry;
use rust_kdc::hdb::ad_blob::{empty_supplemental_credentials, supplemental_credentials};
use rust_kdc::name::Principal;

fn main() -> std::io::Result<()> {
    let relative = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "target/ad-blob".to_owned());
    let out = Path::new(&relative);
    std::fs::create_dir_all(out)?;

    let mut four = HdbEntry::user(Principal::parse("alice@EXAMPLE.COM").unwrap());
    for enctype in Enctype::ALL {
        four.add_password_key(&OwnCipher, enctype, b"a password", 1)
            .unwrap();
    }
    write_entry(out, "four-enctypes", &four)?;

    // Two generations: the current keys and the ones from the previous kvno. A
    // blob that put these in one array would still parse and still hold every key.
    let rotated = four.rekey(&OwnCipher, b"a new password").unwrap();
    write_entry(out, "after-rotation", &rotated)?;

    // Three generations, which is where a reader that only knows about two starts
    // losing keys.
    let twice = rotated.rekey(&OwnCipher, b"a third password").unwrap();
    write_entry(out, "three-generations", &twice)?;

    let mut service =
        HdbEntry::service(Principal::parse("host/web.example.com@EXAMPLE.COM").unwrap());
    service
        .add_password_key(&OwnCipher, Enctype::Aes256Sha1, b"a service key", 1)
        .unwrap();
    write_entry(out, "service", &service)?;

    // A principal with no keys: its blob is one property with no credentials, and
    // must still parse. The projection is written before the first password in a
    // directory that creates the account first.
    let keyless = HdbEntry::user(Principal::parse("new@EXAMPLE.COM").unwrap());
    write_entry(out, "no-keys", &keyless)?;

    // And the structure with no properties at all — 111 octets, because
    // `PropertyCount` is omitted when it would be zero. Nothing in this crate
    // writes it for an entry; it is here so the odd shape is checked rather than
    // assumed.
    std::fs::write(
        out.join("no-properties.blob"),
        empty_supplemental_credentials(),
    )?;
    std::fs::write(
        out.join("no-properties.json"),
        "{\"principal\": null, \"kvno\": 0, \"properties\": 0}\n",
    )?;

    println!("wrote blobs to {}", out.display());
    Ok(())
}

/// Writes the blob and the facts a reader must recover from it.
fn write_entry(out: &Path, name: &str, entry: &HdbEntry) -> std::io::Result<()> {
    std::fs::write(
        out.join(format!("{name}.blob")),
        supplemental_credentials(entry),
    )?;
    let kvno = entry.kvno();
    let manifest = format!(
        "{{\"principal\": \"{}\", \"kvno\": {kvno}, \"properties\": 1, \
         \"current\": {}, \"old\": {}, \"older\": {}}}\n",
        entry.principal,
        at_kvno(&entry.keys, kvno),
        at_kvno(&entry.keys, kvno.saturating_sub(1)),
        at_kvno(&entry.keys, kvno.saturating_sub(2)),
    );
    std::fs::write(out.join(format!("{name}.json")), manifest)
}

/// The keys at one kvno, as a JSON object keyed by enctype.
fn at_kvno(keys: &[rust_kdc::hdb::HdbKey], kvno: u32) -> String {
    let mut out = String::new();
    for key in keys.iter().filter(|k| k.kvno == kvno) {
        if !out.is_empty() {
            out.push(',');
        }
        out.push_str(&format!(
            "\"{}\": \"{}\"",
            key.key.enctype().id(),
            hex(key.key.bytes())
        ));
    }
    format!("{{{out}}}")
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}
