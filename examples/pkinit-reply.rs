//! Builds a `PA-PK-AS-REP` for a test, and writes the parts to files.
//!
//! The KDC's signature has to be judged by somebody who has never seen this code, so the
//! example writes the `SignedData` on its own and `scripts/verify-pkinit-reply.sh` hands it
//! to `openssl cms -verify`. A reply this crate both produced and verified would prove only
//! that the signer and the verifier agree — the mistake that shipped two wrong `PA-DATA`
//! constants in the FAST layer.
//!
//! ```text
//! cargo run --features pkinit --example pkinit-reply -- <dir>
//! ```
//!
//! Reads `<dir>/kdc.pem` and `<dir>/kdc-key.pem` (PEM), writes:
//!
//! * `<dir>/dh-key-info.der` — the `KDCDHKeyInfo`, for `openssl asn1parse`;
//! * `<dir>/dh-signed-data.der` — the CMS `SignedData` over it;
//! * `<dir>/pk-as-rep.der` — the whole `PA-PK-AS-REP`, as the AS exchange sends it.

#[cfg(feature = "pkinit")]
fn main() {
    use rrl_kdc::kdc::pkinit::{self, reply};

    let dir = std::env::args().nth(1).unwrap_or_else(|| {
        eprintln!("usage: pkinit-reply <dir>");
        std::process::exit(2);
    });

    let cert = pem_to_der(&std::fs::read(format!("{dir}/kdc.pem")).expect("read kdc.pem"));
    let key = pem_to_der(&std::fs::read(format!("{dir}/kdc-key.pem")).expect("read kdc-key.pem"));
    let identity = reply::Identity::from_der(&cert, &key).expect("the KDC identity loads");

    // A public value of the right size for group 14: the point is the envelope, not the
    // arithmetic, which `pkinit::dh` covers with its own vectors.
    let public = [0x5au8; 256];
    let nonce = 0x5150_1234u32;

    let info = reply::kdcdh_key_info(&public, nonce);
    let signed = identity
        .signed_data(pkinit::ID_PKINIT_DH_KEY_DATA, &info)
        .expect("the KDC signs");
    let rep = reply::dh_rep_info(signed.clone());

    std::fs::write(format!("{dir}/dh-key-info.der"), &info).expect("write");
    std::fs::write(format!("{dir}/dh-signed-data.der"), &signed).expect("write");
    std::fs::write(format!("{dir}/pk-as-rep.der"), &rep).expect("write");
    println!(
        "key info {} octets, signed data {} octets, PA-PK-AS-REP {} octets",
        info.len(),
        signed.len(),
        rep.len()
    );
}

/// The DER inside a PEM file.
#[cfg(feature = "pkinit")]
fn pem_to_der(pem: &[u8]) -> Vec<u8> {
    let text = String::from_utf8_lossy(pem);
    let body: String = text
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect::<Vec<_>>()
        .join("");
    base64_decode(body.trim())
}

/// Base64, so the example needs no dependency for one fixture.
#[cfg(feature = "pkinit")]
fn base64_decode(text: &str) -> Vec<u8> {
    let table = |c: u8| -> Option<u8> {
        Some(match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        })
    };
    let mut out = Vec::new();
    let mut acc = 0u32;
    let mut bits = 0u32;
    for c in text.bytes() {
        let Some(v) = table(c) else { continue };
        acc = (acc << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    out
}

#[cfg(not(feature = "pkinit"))]
fn main() {
    eprintln!("this example needs --features pkinit");
    std::process::exit(2);
}
