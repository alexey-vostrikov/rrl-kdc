//! Do the two crypto implementations agree? The measurement that decides whether this crate's
//! own crypto layer is a duplicate that can go, or a difference worth keeping.
//!
//! Both sides are checked against MIT's published answers (`fixtures/mit-crypto.json`), not
//! against each other: a test that only compared them would pass if both were wrong the same
//! way, and a test that only checked one would not say whether the other could replace it.
//!
//! If this passes, `RRL-3.35` can delete `src/crypto/{kdf,nfold,aes_cts}.rs` and call the fork.

use std::fs;

use rust_kdc::crypto::{Cipher, Enctype, OwnCipher};

fn hex(s: &str) -> Vec<u8> {
    hex::decode(s).expect("a hex vector")
}

fn fixtures() -> serde_json::Value {
    serde_json::from_str(
        &fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/mit-crypto.json"
        ))
        .expect("the MIT vectors are in the tree"),
    )
    .expect("a JSON table")
}

#[test]
fn the_forks_key_opens_what_mits_vectors_encrypted() {
    let table = fixtures();
    let mut checked = 0;
    for case in table["decrypt"].as_array().expect("a list") {
        let etype = case["enctype"].as_i64().unwrap() as i32;
        let usage = case["usage"].as_u64().unwrap() as u32;
        let key = case["key"].as_str().unwrap();
        let ciphertext = case["ciphertext"].as_str().unwrap();
        let plaintext = case["plaintext"].as_str().unwrap();

        let theirs = krb5::Key::new(etype, hex(key))
            .expect("the fork takes the key")
            .decrypt(usage, &hex(ciphertext));
        assert!(
            theirs.is_ok(),
            "enctype {etype} usage {usage}: the fork could not open MIT's own ciphertext: {:?}",
            theirs.err()
        );
        assert_eq!(
            theirs.unwrap(),
            hex(plaintext),
            "enctype {etype} usage {usage}: the fork disagrees with MIT"
        );

        // And ours, on the same bytes, so a disagreement between the two is visible here rather
        // than at some later swap.
        let ours = Enctype::from_id(etype).expect("a supported enctype");
        let key = rust_kdc::crypto::Key::new(ours, hex(key)).expect("our key");
        assert_eq!(
            OwnCipher
                .decrypt(&key, usage, &hex(ciphertext))
                .expect("we open it too"),
            hex(plaintext),
            "enctype {etype} usage {usage}: we disagree with MIT"
        );
        checked += 1;
    }
    assert!(
        checked >= 18,
        "the whole table was walked, not a part: {checked}"
    );
}

#[test]
fn the_forks_checksums_match_mits_vectors() {
    let table = fixtures();
    for case in table["checksum"].as_array().expect("a list") {
        let etype = case["enctype"].as_i64().unwrap() as i32;
        let usage = case["usage"].as_u64().unwrap() as u32;
        let message = hex(case["plaintext"].as_str().unwrap());
        let expected = hex(case["checksum"].as_str().unwrap());

        let theirs = krb5::Key::new(etype, hex(case["key"].as_str().unwrap()))
            .expect("the fork takes the key")
            .checksum(usage, &message)
            .expect("the fork computes a checksum");
        assert_eq!(
            theirs, expected,
            "enctype {etype} usage {usage}: the fork disagrees"
        );
    }
}
