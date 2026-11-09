//! Builds a `PA-PK-AS-REQ` for the PKINIT tests, with the CMS envelope made by OpenSSL.
//!
//! The split matters. The `AuthPack` is this crate's reading of RFC 4556 §3.2.1, so
//! building it here is what the KDC-under-test has to be able to read. The signature,
//! the certificate set, and the signed attributes come from `openssl cms -sign`, an
//! implementation that has never seen this code — otherwise the test would be checking
//! that the encoder and the decoder agree on a mistake.
//!
//! ```text
//! cargo run --features pkinit --example pkinit-fixture -- <dir>
//! ```
//!
//! Writes `<dir>/request-<name>.der` for each certificate in `<dir>`, plus
//! `<dir>/authpack-<name>.der` (the unsigned inner content, for diagnostics).

use std::process::Command;

use rust_heimdal_kdc::der;

/// A `KDC-REQ-BODY` as an AS-REQ carries it: the body the `paChecksum` covers.
///
/// Its contents are irrelevant to PKINIT — only its octets are, because the checksum
/// binds the signed pack to this exact request.
fn body(nonce: u32) -> Vec<u8> {
    der::seq(&[
        der::field(0, der::flags32(0x4000_0000)),
        der::field(1, der::general_string("alice")),
        der::field(2, der::general_string("EXAMPLE.COM")),
        der::field(
            3,
            der::seq(&[
                der::field(0, der::general_string("krbtgt")),
                der::field(1, der::general_string("EXAMPLE.COM")),
            ]),
        ),
        der::field(7, der::int(i64::from(nonce))),
        der::field(8, der::seq(&[der::int(18), der::int(17)])),
    ])
}

/// `AuthPack` without a public value: the RSA key transport form, which needs no DH.
fn auth_pack(body: &[u8], nonce: u32) -> Vec<u8> {
    use sha1::Digest;
    let checksum = sha1::Sha1::digest(body);
    let authenticator = der::seq(&[
        der::field(0, der::int(0)),
        der::field(1, der::time(1_700_000_000)),
        der::field(2, der::int(i64::from(nonce))),
        der::field(3, der::octets(&checksum)),
    ]);
    der::seq(&[der::field(0, authenticator)])
}

/// The `PA-PK-AS-REQ` around a `SignedData` envelope: `[0] ContentInfo`.
fn wrap(signed: &[u8]) -> Vec<u8> {
    der::seq(&[der::field(0, signed.to_vec())])
}

fn main() {
    let dir = std::env::args().nth(1).unwrap_or_else(|| {
        eprintln!("usage: pkinit-fixture <dir>");
        std::process::exit(2);
    });
    let nonce = 0x5150_1234u32;
    let body = body(nonce);
    let pack = auth_pack(&body, nonce);
    std::fs::write(format!("{dir}/authpack.der"), &pack).expect("write authpack");

    let cases = [
        "alice",
        "bob",
        "untrusted-alice",
        "expired",
        "no-pkinit-san",
        "wrong-purpose",
    ];
    for name in cases {
        let cert = format!("{dir}/{name}.pem");
        let key = format!("{dir}/{name}-key.pem");
        // `-nodetach` puts the content inside eContent rather than beside the signature,
        // which is the form RFC 4556 §3.2.1 describes and the form a KDC has to parse.
        // `-md sha256` fixes the digest; `-nosmimecap` keeps the attributes to the two
        // the standard requires.
        let out = format!("{dir}/request-{name}.der");
        let status = Command::new("openssl")
            .args([
                "cms",
                "-sign",
                "-binary",
                "-nodetach",
                "-nosmimecap",
                "-md",
                "sha256",
                // The content type MIT and Heimdal set; OpenSSL defaults to pkcs7-data,
                // and a KDC that accepted that would accept a signature over anything.
                "-econtent_type",
                "1.3.6.1.5.2.3.1",
                "-in",
                &format!("{dir}/authpack.der"),
                "-signer",
                &cert,
                "-inkey",
                &key,
                "-outform",
                "DER",
                "-out",
                &out,
            ])
            .status()
            .expect("run openssl cms");
        if !status.success() {
            panic!("openssl cms -sign failed for {name}");
        }
        let signed = std::fs::read(&out).expect("read signed request");
        std::fs::write(format!("{dir}/request-{name}-wrapped.der"), wrap(&signed))
            .expect("write wrapped request");
        println!(
            "{name}: authpack {} octets, signed {} octets, wrapped {} octets",
            pack.len(),
            signed.len(),
            wrap(&signed).len()
        );
    }

    // The body is a fixture too: the test checks that `paChecksum` covers exactly these
    // octets, and a body built independently at test time would make that check a
    // tautology.
    std::fs::write(format!("{dir}/body.der"), &body).expect("write body");
    println!("body {} octets, nonce {nonce}", body.len());
}
