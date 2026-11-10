//! The single-block case of CBC-CS3: ciphertext stealing reduces to plain CBC there, and this
//! crate says so against MIT's own answer.
//!
//! An encrypted part is one block whenever the plaintext is empty, because the confounder alone
//! is 16 octets — an empty `AP-REP`, an empty `EncryptedData`, any empty plaintext with a
//! confounder. RFC 3962 §5 and the NIST SP 800-38A Addendum both reduce the construction to plain
//! CBC at one block: there is nothing to steal, so `C = E(P ⊕ IV)`.
//!
//! Worth a test of its own because a round trip cannot show it. An implementation that invents
//! its own convention for one block still decrypts back to the plaintext with its own decryptor,
//! so every round-trip test passes while the ciphertext is not the one MIT produces. Measured:
//! the `cts` crate does exactly that (`d775d376…` where MIT says `16e23934…`), which is why this
//! crate keeps its own CBC-CS3 rather than taking that dependency.
//!
//! The vector is MIT's `crypto_tests` answer for enctype 18, usage 0, empty plaintext — a third
//! party, which a comparison between two of our own implementations would not be.

use aes::cipher::{BlockCipherDecrypt, KeyInit};

use rust_kdc::crypto::aes_cts;

/// MIT's ciphertext: the encrypted part is the first 16 octets, the rest is the HMAC.
const MIT_KEY: &str = "17f275f2954f2ed1f90c377ba7f4d6a369aa0136e0bf0c927ad6133c693759a9";
const MIT_CIPHERTEXT: &str = "e5094c55ee7b38262e2b044280b069379a95bf95";

/// The same 16 octets, opened by this crate and by hand as plain CBC.
///
/// The hand computation is the point: it says the expected value follows from the definition
/// (one block ⟹ plain CBC), not from our implementation agreeing with itself.
#[test]
fn one_block_is_plain_cbc_and_this_crate_does_that() {
    let key = hex::decode(MIT_KEY).unwrap();
    let ciphertext = hex::decode(MIT_CIPHERTEXT).unwrap();
    let block = &ciphertext[..16];

    let ours = aes_cts::decrypt(&key, &[0u8; 16], block).expect("our decrypt");

    // By hand: P = D(C) ⊕ IV, with the zero IV Kerberos always uses.
    let mut expected = [0u8; 16];
    expected.copy_from_slice(block);
    aes::Aes256::new_from_slice(&key)
        .expect("a 256-bit key")
        .decrypt_block((&mut expected).into());
    assert_eq!(
        ours, expected,
        "one block must be plain CBC: our decrypt has to equal D(C) ⊕ IV"
    );

    // And the same value the `cts` crate would not produce (d775d376…, measured): the assertion
    // is written against MIT's answer, so it fails if this crate ever adopts the other
    // convention.
    assert_eq!(
        hex::encode(&ours),
        "16e239346142adf54aad6a0be853d0c8",
        "the confounder MIT encrypted for an empty plaintext"
    );
}

/// A round trip over every length above one block, so a change in the stealing path is caught.
#[test]
fn every_length_above_one_block_round_trips() {
    for key_len in [16usize, 32] {
        let key: Vec<u8> = (0..key_len).map(|i| i as u8).collect();
        for len in 17..=96usize {
            let plain: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(11)).collect();
            let sealed = aes_cts::encrypt(&key, &[0u8; 16], &plain).expect("encrypt");
            assert_eq!(sealed.len(), plain.len(), "CTS keeps the length, len {len}");
            let back = aes_cts::decrypt(&key, &[0u8; 16], &sealed).expect("decrypt");
            assert_eq!(back, plain, "round trip at len {len}, key {key_len}");
        }
    }
}
