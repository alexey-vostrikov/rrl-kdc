//! Print or read a `krb5Key` value, so that a second implementation can be asked about it.
//!
//! `scripts/heimdal-key-layout.sh` drives this: it asks Heimdal to decode what this prints, and asks
//! this to decode what Heimdal prints. The example exists because that check needs a program that
//! produces and consumes the value on demand; nothing in the crate wants one.
//!
//! Usage:
//!   key-value encode <enctype> <key-hex> <salt>          -> the value, hex
//!   key-value encode-sealed <enctype> <key-hex> <salt> <mkvno>
//!   key-value decode <hex>                              -> the fields

use rrl_kdc::crypto::{Cipher, Enctype, Key, OwnCipher};
use rrl_kdc::hdb::HdbKey;
use rrl_kdc::hdb::ldap::{Attributes, attrs};

fn unhex(text: &str) -> Vec<u8> {
    assert!(text.len().is_multiple_of(2), "{text:?} is not whole octets");
    (0..text.len() / 2)
        .map(|i| u8::from_str_radix(&text[2 * i..2 * i + 2], 16).expect("hex"))
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// One entry holding one key: the attribute mapping is what writes the value, so the value checked is
/// the one the crate really produces.
fn attributes(enctype: Enctype, key: &[u8], salt: &str, sealed_with: Option<u32>) -> Attributes {
    let key = Key::new(enctype, key.to_vec()).expect("a key of the right length");
    let mut entry = rrl_kdc::hdb::HdbEntry::user(
        rrl_kdc::name::Principal::parse("alice@EXAMPLE.COM").expect("a principal"),
    );
    entry.keys.push(HdbKey {
        kvno: 1,
        key,
        salt: Some(salt.as_bytes().to_vec()),
        mkvno: None,
    });
    entry.kvno = 1;
    match sealed_with {
        Some(mkvno) => {
            // A master key whose `kvno` is the number asked for: sealing with it records that number,
            // which is exactly what the check is about.
            let master = OwnCipher.random(Enctype::Aes256Sha1).expect("a key");
            let keys = rrl_kdc::hdb::mkey::MasterKeys::single(master, mkvno);
            rrl_kdc::hdb::ldap::to_attributes_with(&entry, Some((&OwnCipher, &keys)))
                .expect("mapped sealed")
        }
        None => rrl_kdc::hdb::ldap::to_attributes(&entry),
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("encode") if args.len() == 4 => {
            let enctype = Enctype::from_name(&args[1]).expect("an enctype name");
            let a = attributes(enctype, &unhex(&args[2]), &args[3], None);
            println!("{}", hex(a.first(attrs::KEY).expect("a value")));
        }
        Some("encode-sealed") if args.len() == 5 => {
            let enctype = Enctype::from_name(&args[1]).expect("an enctype name");
            let mkvno: u32 = args[4].parse().expect("a master key version");
            let a = attributes(enctype, &unhex(&args[2]), &args[3], Some(mkvno));
            println!("{}", hex(a.first(attrs::KEY).expect("a value")));
        }
        Some("decode") if args.len() == 2 => {
            let value = unhex(&args[1]);
            let mut a = Attributes::new();
            a.set(
                attrs::PRINCIPAL_NAME,
                "alice@EXAMPLE.COM".as_bytes().to_vec(),
            );
            a.set(attrs::KEY_VERSION_NUMBER, b"1".to_vec());
            a.add(attrs::KEY, value);
            match rrl_kdc::hdb::ldap::from_attributes(&a) {
                Ok(entry) => {
                    let key = &entry.keys[0];
                    println!("decoded ok");
                    println!(
                        "  kvno:    {} (from {}",
                        key.kvno,
                        attrs::KEY_VERSION_NUMBER
                    );
                    println!("           — the value itself does not carry one)");
                    println!("  enctype: {}", key.key.enctype().name());
                    println!("  keylen:  {}", key.key.len());
                    println!("  key:     {}", hex(key.key.bytes()));
                    match &key.salt {
                        Some(salt) => {
                            println!("  salt:    {}", hex(salt));
                            println!("  salt as text: {:?}", String::from_utf8_lossy(salt));
                        }
                        None => println!("  salt:    (absent)"),
                    }
                }
                Err(e) => {
                    println!("decode failed: {e}");
                    std::process::exit(1);
                }
            }
        }
        _ => {
            eprintln!("usage: key-value encode|encode-sealed|decode …");
            std::process::exit(2);
        }
    }
}
