//! Prints `KERB_VALIDATION_INFO` and a PAC carrying it, so that
//! `scripts/verify-logon-info.sh` can have impacket parse both.
//!
//! The logon information is the half of a PAC whose correctness cannot be read off
//! the code: NDR pointer arithmetic looks right either way, and only a reader that
//! did not write it can say whether a pointer lands where the structure claims.

use rust_kdc::crypto::{Enctype, Key};
use rust_kdc::kdc::logon_info::{LogonInfo, Sid, encode};
use rust_kdc::kdc::pac::{
    Buffer, PAC_LOGON_INFO, PAC_PRIVSVR_CHECKSUM, PAC_SERVER_CHECKSUM, SignatureType, pac, seal,
};

/// 2026-11-09T00:00:00Z, the same instant `examples/pac-blob.rs` uses.
const LOGON_TIME: i64 = 1_794_182_400;

fn main() {
    // A domain SID with the three words AD draws at random, an account whose RID is
    // 1105, and three groups including the two built-ins: the shape a real realm
    // has, so that a reader exercises the group array instead of a null pointer.
    let domain = Sid::parse("S-1-5-21-2415902705-1828978662-3340856871").unwrap();
    let mut info = LogonInfo::minimal("alice@EXAMPLE.COM", 1105, domain.clone(), LOGON_TIME);
    info.full_name = "Alice Example".into();
    info.group_ids = vec![
        (513, 7), // Domain Users
        (512, 7), // Domain Admins
        (1106, 7),
    ];
    info.logon_server = "DC1".into();
    info.logon_domain_name = "EXAMPLE".into();

    let validation = encode(&info).unwrap();
    println!("VALIDATION={}", hex(&validation));

    let mut blob = pac(&[
        Buffer::new(PAC_LOGON_INFO, validation),
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
    println!("PAC={}", hex(&blob));

    // Printed so the verifier compares against the source rather than against
    // whatever the buffer happens to say.
    println!("EXPECT_NAME=alice@EXAMPLE.COM");
    println!("EXPECT_FULL=Alice Example");
    println!("EXPECT_RID=1105");
    println!("EXPECT_PRIMARY=513");
    println!("EXPECT_GROUPS=513,512,1106");
    println!("EXPECT_DOMAIN={}", domain.to_text());
    println!("EXPECT_LOGON_SERVER=DC1");
    println!("EXPECT_LOGON_DOMAIN=EXAMPLE");
    println!("EXPECT_LOGON_TIME={LOGON_TIME}");
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
