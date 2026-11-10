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

use rrl_kdc::der;

/// A `KDC-REQ-BODY` as an AS-REQ carries it: the body the `paChecksum` covers.
///
/// Its contents are irrelevant to PKINIT — only its octets are, because the checksum
/// binds the signed pack to this exact request.
fn body(nonce: u32) -> Vec<u8> {
    der::seq(&[
        der::field(0, der::flags32(0x4000_0000)),
        // `cname [1] PrincipalName`: a SEQUENCE of a name type and its components, not a
        // bare string. A GeneralString here parses as nothing and the KDC refuses the body.
        der::field(
            1,
            rrl_kdc::name::Principal::parse("alice@EXAMPLE.COM")
                .expect("a principal")
                .encode_name(),
        ),
        der::field(2, der::general_string("EXAMPLE.COM")),
        // `sname [3] PrincipalName`, encoded by the crate itself: a hand-built SEQUENCE of
        // strings has no name type and does not parse as a principal.
        der::field(
            3,
            rrl_kdc::name::Principal::krbtgt("EXAMPLE.COM").encode_name(),
        ),
        // `till [5]`: required, and a request without it is not a request.
        der::field(5, der::time(1_800_003_600)),
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

    // A request in the Diffie-Hellman form, which is the one a KDC can answer: the RSA
    // transport form the cases above use carries no public value, and a KDC that implements
    // DH refuses it by name.
    //
    // The client's exponent is written beside the request, because the wiring test has to
    // derive the reply key the way the client would — that is the only check that the
    // exchange agreed on anything.
    let dh = dh_auth_pack(&body, nonce);
    std::fs::write(format!("{dir}/pkinit-authpack-dh.der"), &dh.pack).expect("write");
    std::fs::write(format!("{dir}/pkinit-client-exponent.bin"), &dh.exponent).expect("write");

    let signed_path = format!("{dir}/pkinit-as-req-signed-pa.der");
    let status = Command::new("openssl")
        .args([
            "cms",
            "-sign",
            "-binary",
            "-nodetach",
            "-nosmimecap",
            "-md",
            "sha256",
            "-econtent_type",
            "1.3.6.1.5.2.3.1",
            "-in",
            &format!("{dir}/pkinit-authpack-dh.der"),
            "-signer",
            &format!("{dir}/alice.pem"),
            "-inkey",
            &format!("{dir}/alice-key.pem"),
            "-outform",
            "DER",
            "-out",
            &signed_path,
        ])
        .status()
        .expect("run openssl cms");
    if !status.success() {
        panic!("openssl cms -sign failed for the DH request");
    }
    let signed = std::fs::read(&signed_path).expect("read signed pack");

    // `AS-REQ ::= [APPLICATION 10] KDC-REQ { pvno, msg-type, padata [3], req-body [4] }`
    let request = der::cons(
        der::app(10),
        &[der::seq(&[
            der::field(1, der::int(5)),
            der::field(2, der::int(10)),
            der::field(
                3,
                der::seq(&[pa_data(
                    crate::PKINIT_PA_PK_AS_REQ,
                    &der::seq(&[der::field(0, signed)]),
                )]),
            ),
            der::field(4, body.clone()),
        ])],
    );
    std::fs::write(format!("{dir}/pkinit-as-req.der"), &request).expect("write");
    println!(
        "PKINIT request {} octets, exponent {} octets",
        request.len(),
        dh.exponent.len()
    );
}

/// The number RFC 4556 gives `PA-PK-AS-REQ`.
const PKINIT_PA_PK_AS_REQ: i32 = 16;

/// One `PA-DATA` element.
fn pa_data(pa_type: i32, value: &[u8]) -> Vec<u8> {
    der::seq(&[
        der::field(1, der::int(i64::from(pa_type))),
        der::field(2, der::octets(value)),
    ])
}

struct DhPack {
    pack: Vec<u8>,
    exponent: Vec<u8>,
}

/// An `AuthPack` carrying a Diffie-Hellman public value in RFC 3526 group 14.
///
/// The exponent is fixed so that the test can derive the same reply key; its size is 256 bits,
/// which is what a client uses — the group's security is bounded by the subgroup, not by the
/// exponent's width.
fn dh_auth_pack(body: &[u8], nonce: u32) -> DhPack {
    use sha1::Digest;

    let group = rrl_kdc::kdc::pkinit::dh::Group::at_least(2048);
    let exponent: num_bigint::BigUint = num_bigint::BigUint::from(0x9e37_79b9_7f4a_7c15u64)
        + (num_bigint::BigUint::from(1u32) << 190);
    let ours = rrl_kdc::kdc::pkinit::dh::KeyPair::from_private(group, exponent.clone());

    let params = der::seq(&[
        der::int_bytes(&group.p().to_bytes_be()),
        der::int(2),
        der::int_bytes(&group.q().to_bytes_be()),
    ]);
    let mut bits = vec![0u8];
    bits.extend_from_slice(&ours.public_bytes());
    let spki = der::seq(&[
        der::seq(&[
            der::tlv(0x06, &[0x2a, 0x86, 0x48, 0xce, 0x3e, 0x02, 0x01]),
            params,
        ]),
        der::tlv(0x03, &bits),
    ]);

    let checksum = sha1::Sha1::digest(body);
    let pack = der::seq(&[
        der::field(
            0,
            der::seq(&[
                der::field(0, der::int(0)),
                // Inside the fixture certificates' validity window, and close enough to the
                // `till` below that a KDC at the same clock accepts both.
                der::field(1, der::time(1_799_999_990)),
                der::field(2, der::int(i64::from(nonce))),
                der::field(3, der::octets(&checksum)),
            ]),
        ),
        der::field(1, spki),
    ]);

    DhPack {
        pack,
        exponent: exponent.to_bytes_be(),
    }
}
