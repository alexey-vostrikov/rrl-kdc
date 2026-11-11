//! PKINIT over elliptic curves (RFC 5349), end to end from the KDC's side.
//!
//! The request is built here the way a client builds it — an `AuthPack` with an
//! `id-ecPublicKey` `clientPublicValue`, signed by a real certificate — because no recorded fixture
//! has one: every captured request in `tests/pkinit/` is either transport-shaped or MODP, and the
//! EC branch has no recording to lean on.
//!
//! What the test proves is the property that matters and that a unit test of the arithmetic cannot:
//! the client, using only its own secret and what came back on the wire, derives **the same reply
//! key** the KDC says it will seal the reply part with. A KDC that agreed on the wrong curve, put a
//! `SubjectPublicKeyInfo` where a point belongs, or fed the KDF a different input would fail here.

#![cfg(feature = "pkinit")]

use rrl_kdc::crypto::Enctype;
use rrl_kdc::der::{self, Reader};
use rrl_kdc::kdc::pkinit::{self, ec, reply};
use rrl_kdc::name::Principal;

const NOW: i64 = 1_800_000_000;
const NONCE: u32 = 0x5eed_1234;

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!(
        "{}/tests/pkinit/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap_or_else(|e| panic!("read {name}: {e}"))
}

fn der_of(pem: &[u8]) -> Vec<u8> {
    use base64::Engine;
    let text = String::from_utf8_lossy(pem);
    let body: String = text
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect::<Vec<_>>()
        .join("");
    base64::engine::general_purpose::STANDARD
        .decode(body.trim())
        .expect("a PEM body is base64")
}

fn p(name: &str) -> Principal {
    Principal::parse(name).unwrap()
}

/// Deterministic entropy: stateful, because `ec::KeyPair::generate` rejection-samples scalars.
fn rng() -> impl Fn(usize) -> Vec<u8> {
    let state = std::cell::Cell::new(0x9e37_79b9u32);
    move |len| {
        (0..len)
            .map(|_| {
                let mut x = state.get();
                x ^= x << 13;
                x ^= x >> 17;
                x ^= x << 5;
                state.set(x);
                (x >> 16) as u8
            })
            .collect()
    }
}

fn state() -> reply::State {
    let mut anchors = pkinit::TrustAnchors::new();
    anchors
        .add(&der_of(&fixture("ca.pem")))
        .expect("the anchor loads");
    reply::State {
        identity: reply::Identity::from_der(
            &der_of(&fixture("kdc.pem")),
            &der_of(&fixture("kdc-key.pem")),
        )
        .expect("the KDC identity loads"),
        anchors,
        policy: Default::default(),
    }
}

/// `AlgorithmIdentifier { id-ecPublicKey, namedCurve }` for `curve`.
fn ec_alg(curve: ec::Curve) -> Vec<u8> {
    der::seq(&[
        der::tlv(der::OBJECT_IDENTIFIER, &oid_content(ec::ID_EC_PUBLIC_KEY)),
        der::tlv(der::OBJECT_IDENTIFIER, &oid_content(curve.oid())),
    ])
}

/// OID content octets, so a test can name an OID it already has as text.
fn oid_content(text: &str) -> Vec<u8> {
    let parts: Vec<u64> = text.split('.').map(|p| p.parse().unwrap()).collect();
    let mut out = vec![(40 * parts[0] + parts[1]) as u8];
    for &part in &parts[2..] {
        let mut chunk = vec![(part & 0x7f) as u8];
        let mut rest = part >> 7;
        while rest > 0 {
            chunk.push(0x80 | (rest & 0x7f) as u8);
            rest >>= 7;
        }
        chunk.reverse();
        out.extend(chunk);
    }
    out
}

/// A `PA-PK-AS-REQ` whose `AuthPack` offers an EC public value on `curve`, and the client's own key
/// pair — which is what the test needs to derive the reply key independently.
fn request(curve: ec::Curve, body: &[u8]) -> (Vec<u8>, ec::KeyPair) {
    use sha1::Digest;

    let ours = ec::KeyPair::generate(curve, &rng()).expect("a client pair");
    let spki = der::seq(&[
        ec_alg(curve),
        der::tlv(0x03, &[&[0u8][..], ours.point()].concat()),
    ]);

    let checksum = sha1::Sha1::digest(body).to_vec();
    let authenticator = der::seq(&[
        der::field(0, der::int(0)),
        der::field(1, der::time(NOW)),
        der::field(2, der::int(i64::from(NONCE))),
        der::field(3, der::octets(&checksum)),
    ]);
    let auth_pack = der::seq(&[
        der::field(0, authenticator),
        der::field(1, spki), // clientPublicValue
    ]);

    let signer = reply::Identity::from_der(
        &der_of(&fixture("alice.pem")),
        &der_of(&fixture("alice-key.pem")),
    )
    .expect("the client identity loads");
    let signed = signer
        .signed_data(pkinit::ID_PKINIT_AUTH_DATA, &auth_pack)
        .expect("the client signs its AuthPack");
    (der::seq(&[der::field(0, signed)]), ours)
}

/// The KDC's point out of a `PA-PK-AS-REP`: `dhInfo [0] { dhSignedData [0] OCTET STRING }`, then
/// the `ContentInfo`, then the `SignedData`'s content, then `KDCDHKeyInfo.subjectPublicKey`.
///
/// The signature is not verified here — `tests/pkinit_reply.rs` and OpenSSL judge exactly that
/// producer — but the structure is walked with assertions, because a client walks it the same way.
fn kdc_point(pa_pk_as_rep: &[u8]) -> Vec<u8> {
    let mut r = Reader::new(pa_pk_as_rep);
    let dh_info = r.next_tlv("dhInfo").expect("a [0]");
    assert_eq!(dh_info.tag, der::ctx(0), "the reply is dhInfo [0]");
    let mut di = Reader::new(dh_info.content);
    let rep = di.next_tlv("DHRepInfo").expect("a SEQUENCE");
    let mut rf = Reader::new(rep.content);
    let signed = rf.next_tlv("dhSignedData").expect("dhSignedData [0]");
    let mut sr = Reader::new(signed.content);
    let ci_octets = sr.next_tlv("ContentInfo octets").expect("an OCTET STRING");

    let mut ci = Reader::new(ci_octets.content);
    let ci = ci.next_tlv("ContentInfo").expect("a ContentInfo");
    let mut cif = Reader::new(ci.content);
    let _oid = cif.next_tlv("contentType").expect("contentType");
    let wrapped = cif.next_tlv("signedData").expect("[0] SignedData");
    let mut wr = Reader::new(wrapped.content);
    let sd = wr.next_tlv("SignedData").expect("a SignedData");
    let mut sdf = Reader::new(sd.content);
    let _version = sdf.next_tlv("version").expect("version");
    let _digests = sdf.next_tlv("digestAlgorithms").expect("digestAlgorithms");
    let eci = sdf.next_tlv("encapContentInfo").expect("encapContentInfo");
    let mut ef = Reader::new(eci.content);
    let content_oid = ef.next_tlv("eContentType").expect("eContentType");
    assert_eq!(
        content_oid.content,
        oid_content(pkinit::ID_PKINIT_DH_KEY_DATA),
        "the signed content must be id-pkinit-DHKeyData"
    );
    let content = ef.next_tlv("eContent").expect("eContent");
    let mut cr = Reader::new(content.content);
    let octets = cr.next_tlv("KDCDHKeyInfo octets").expect("an OCTET STRING");

    let mut ki = Reader::new(octets.content);
    let info = ki.next_tlv("KDCDHKeyInfo").expect("a KDCDHKeyInfo");
    let mut kif = Reader::new(info.content);
    let public = kif
        .next_tlv("subjectPublicKey")
        .expect("subjectPublicKey [0]");
    let mut pr = Reader::new(public.content);
    let bits = pr.next_tlv("BIT STRING").expect("a BIT STRING");
    assert_eq!(bits.content[0], 0, "unused bits");
    let nonce = kif.next_tlv("nonce").expect("nonce");
    let mut nr = Reader::new(nonce.content);
    let nonce = nr.next_tlv("INTEGER").expect("an INTEGER");
    assert_eq!(
        der::as_int("nonce", nonce.content).unwrap(),
        i64::from(NONCE),
        "the KDC echoes the client's nonce"
    );
    let point = bits.content[1..].to_vec();
    assert_eq!(
        point[0], 0x04,
        "the BIT STRING holds a SEC1 point, not a SubjectPublicKeyInfo: a client parses it as a \
         point and an SPKI there fails"
    );
    point
}

/// The whole exchange, on each curve: the KDC answers, and the client derives the same reply key.
#[test]
fn an_elliptic_curve_request_is_answered_and_both_sides_derive_the_same_key() {
    for curve in [ec::Curve::P256, ec::Curve::P384, ec::Curve::P521] {
        let body = b"the KDC-REQ-BODY of an ECDH request";
        let as_req = b"the AS-REQ";
        let (pa, client) = request(curve, body);

        let answer = reply::answer(
            &state(),
            &pa,
            body,
            as_req,
            &p("alice@EXAMPLE.COM"),
            &p("krbtgt/EXAMPLE.COM@EXAMPLE.COM"),
            Enctype::Aes256Sha1,
            NOW,
            &rng(),
        )
        .unwrap_or_else(|e| panic!("{curve:?}: the KDC refused an EC request: {e}"));

        assert_eq!(
            answer.client_group_bits,
            curve.bits(),
            "{curve:?}: the reported size must be the curve's"
        );

        let point = kdc_point(&answer.pa_pk_as_rep);
        assert_eq!(
            point.len(),
            1 + 2 * curve.field_len(),
            "{curve:?}: the KDC's point is not two coordinates of the field width"
        );

        // The client's side of the agreement, from its own secret and the point on the wire.
        let z = client
            .agree(&point)
            .unwrap_or_else(|e| panic!("{curve:?}: the KDC's point is not on the curve: {e}"));
        // The reply key the client computes: no KDF was offered, so RFC 4556's `octetstring2key`.
        let key = reply::reply_key(
            &z,
            None,
            &p("alice@EXAMPLE.COM"),
            &p("krbtgt/EXAMPLE.COM@EXAMPLE.COM"),
            Enctype::Aes256Sha1,
            as_req,
            &answer.pa_pk_as_rep,
        )
        .expect("the reply key");

        assert_eq!(
            key,
            answer.reply_key.bytes(),
            "{curve:?}: the client and the KDC derived different reply keys — an exchange that \
             looks like a corrupt ticket on the wire"
        );
    }
}

/// A curve this KDC does not implement is refused by name: the request is well-formed, so reporting
/// it as malformed would send the operator looking for a parse bug.
#[test]
fn an_unknown_curve_is_refused_as_unsupported() {
    let body = b"body";
    // P-224 (`secp224r1`), which is real, old, and not one of the three.
    let ours = ec::KeyPair::generate(ec::Curve::P256, &rng()).expect("a pair");
    let alg = der::seq(&[
        der::tlv(der::OBJECT_IDENTIFIER, &oid_content(ec::ID_EC_PUBLIC_KEY)),
        der::tlv(der::OBJECT_IDENTIFIER, &oid_content("1.3.132.0.33")),
    ]);
    let spki = der::seq(&[alg, der::tlv(0x03, &[&[0u8][..], ours.point()].concat())]);
    let checksum = {
        use sha1::Digest;
        sha1::Sha1::digest(body).to_vec()
    };
    let auth_pack = der::seq(&[
        der::field(
            0,
            der::seq(&[
                der::field(0, der::int(0)),
                der::field(1, der::time(NOW)),
                der::field(2, der::int(i64::from(NONCE))),
                der::field(3, der::octets(&checksum)),
            ]),
        ),
        der::field(1, spki),
    ]);
    let signer = reply::Identity::from_der(
        &der_of(&fixture("alice.pem")),
        &der_of(&fixture("alice-key.pem")),
    )
    .expect("the client identity loads");
    let signed = signer
        .signed_data(pkinit::ID_PKINIT_AUTH_DATA, &auth_pack)
        .expect("signs");
    let pa = der::seq(&[der::field(0, signed)]);

    let err = match reply::answer(
        &state(),
        &pa,
        body,
        b"as-req",
        &p("alice@EXAMPLE.COM"),
        &p("krbtgt/EXAMPLE.COM@EXAMPLE.COM"),
        Enctype::Aes256Sha1,
        NOW,
        &rng(),
    ) {
        Err(e) => e,
        Ok(_) => panic!("secp224r1 must not be answered"),
    };
    assert!(
        matches!(err, pkinit::PkinitError::Unsupported(_)),
        "expected Unsupported for a curve this KDC does not have, got {err:?}"
    );
    assert!(err.to_string().contains("P-256"), "{err}");
}
