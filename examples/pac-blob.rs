//! Prints a sealed PAC as hexadecimal, so that `scripts/verify-pac.sh` can hand
//! the same octets to impacket and compare.
//!
//! Not a test: impacket is a Python package, and a Rust test cannot call it. The
//! script is the acceptance, and it is the only evidence that this crate's PAC is
//! a PAC somebody else's parser agrees with.

use rust_heimdal_kdc::crypto::{Enctype, Key};
use rust_heimdal_kdc::kdc::pac::{
    Buffer, PAC_LOGON_INFO, PAC_PRIVSVR_CHECKSUM, PAC_SERVER_CHECKSUM, SignatureType, client_info,
    pac, seal,
};

/// A logon time the verifier can compare against: the second `2026-11-09T00:00:00Z`.
const LOGON_TIME: i64 = 1_794_182_400;

fn main() {
    // A payload with no structure of its own: what this example is about is the
    // envelope and the signatures, and a real logon info would only add noise to
    // the comparison.
    let payload: Vec<u8> = (0..100u8).collect();
    // A name with an accent, an ideograph and an emoji: the emoji is a surrogate
    // pair, so a length computed as "one octet per character" — or as "one UTF-16
    // unit per character" — shows up in the verifier rather than months later.
    let mut blob = pac(&[
        Buffer::new(PAC_LOGON_INFO, payload),
        client_info("Jörg-😀日本", LOGON_TIME).unwrap(),
        Buffer::new(PAC_SERVER_CHECKSUM, vec![0u8; 16]),
        Buffer::new(PAC_PRIVSVR_CHECKSUM, vec![0u8; 16]),
    ]);

    let server = Key::new(Enctype::Aes256Sha1, vec![0x07u8; 32]).unwrap();
    let kdc = Key::new(Enctype::Aes256Sha1, vec![0x09u8; 32]).unwrap();
    seal(
        &mut blob,
        &server,
        &kdc,
        SignatureType::HmacSha1_96Aes(Enctype::Aes256Sha1),
    )
    .unwrap();

    println!(
        "{}",
        blob.iter().map(|b| format!("{b:02x}")).collect::<String>()
    );
}
