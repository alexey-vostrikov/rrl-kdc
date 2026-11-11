//! PKINIT's RSA key transport branch (RFC 4556 §3.2.3.2), from the KDC's side.
//!
//! The request here is built the way a client builds it: an `AuthPack` with **no**
//! `clientPublicValue`, signed by the client's certificate, wrapped in `PA-PK-AS-REQ`. What the
//! KDC answers must then open with that certificate's *private* key and carry a reply key bound to
//! the request it answers — so the test decrypts the envelope the way a client does rather than
//! asking the producer whether it liked its own output.
//!
//! The signature over the reply is not re-verified here: `tests/pkinit_reply.rs` and
//! `scripts/verify-pkinit-reply.sh` judge exactly that producer with OpenSSL, and repeating it in a
//! second shape would test the same code twice and the envelope once less.

#![cfg(feature = "pkinit")]

use rrl_kdc::crypto::Enctype;
use rrl_kdc::der::{self, Reader};
use rrl_kdc::kdc::pkinit::{self, reply};
use rrl_kdc::name::Principal;

const NOW: i64 = 1_800_000_000;
const NONCE: u32 = 0x1122_3344;
const BODY: &[u8] = b"the KDC-REQ-BODY of a request that asks for key transport";
const AS_REQ: &[u8] = b"the whole AS-REQ, which a transported ReplyKeyPack is checksummed over";

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

fn kdc_identity() -> reply::Identity {
    reply::Identity::from_der(
        &der_of(&fixture("kdc.pem")),
        &der_of(&fixture("kdc-key.pem")),
    )
    .expect("the KDC identity loads")
}

/// The client's certificate as an `Identity`: the test needs a signer, and a certificate plus its
/// key is exactly what `Identity` holds. Nothing about this makes the client a KDC — the reply is
/// signed by the KDC's own identity, and the only thing this one does is sign the request.
fn client_identity() -> reply::Identity {
    reply::Identity::from_der(
        &der_of(&fixture("alice.pem")),
        &der_of(&fixture("alice-key.pem")),
    )
    .expect("the client identity loads")
}

fn state() -> reply::State {
    let mut anchors = pkinit::TrustAnchors::new();
    anchors
        .add(&der_of(&fixture("ca.pem")))
        .expect("the anchor loads");
    reply::State {
        identity: kdc_identity(),
        anchors,
        policy: Default::default(),
    }
}

/// Deterministic bytes for the parts of the exchange that are random: an IV, a content-encryption
/// key, and the RSA padding. Reproducible so that a failure is a failure and not a different run.
fn rng() -> impl Fn(usize) -> Vec<u8> {
    // Stateful, and it has to be: `rsa`'s PKCS#1 v1.5 padding rejects zero octets and asks for
    // more bytes until none are left. A generator that answered the same sequence every call
    // would answer the same zeros forever and the loop would never end — measured: the test hung
    // for a minute before this comment existed. `Cell` keeps the closure a `Fn`, which is what
    // `reply::answer` takes.
    let state = std::cell::Cell::new(0x5au8);
    move |len| {
        (0..len)
            .map(|_| {
                let mut x = state.get() as u32;
                x ^= x << 13;
                x ^= x >> 17;
                x ^= x << 5;
                // A zero would only cost the padding loop another round, so it is mapped away.
                state.set((x as u8) | 1);
                state.get()
            })
            .collect()
    }
}

/// `AuthPack` with a `pkAuthenticator` that covers `BODY` and no `clientPublicValue` — the request
/// that asks for key transport.
fn auth_pack_without_public_value() -> Vec<u8> {
    use sha1::Digest;
    let checksum = sha1::Sha1::digest(BODY).to_vec();
    let authenticator = der::seq(&[
        der::field(0, der::int(0)),                // cusec
        der::field(1, der::time(NOW)),             // ctime
        der::field(2, der::int(i64::from(NONCE))), // nonce
        der::field(3, der::octets(&checksum)),     // paChecksum
    ]);
    der::seq(&[der::field(0, authenticator)])
}

fn request_without_public_value() -> Vec<u8> {
    let signed = client_identity()
        .signed_data(
            pkinit::ID_PKINIT_AUTH_DATA,
            &auth_pack_without_public_value(),
        )
        .expect("the client signs its AuthPack");
    // `PA-PK-AS-REQ ::= SEQUENCE { signedAuthPack [0] IMPLICIT ContentInfo }`, with the whole
    // ContentInfo inside the `[0]`.
    der::seq(&[der::field(0, signed)])
}

fn p(name: &str) -> Principal {
    Principal::parse(name).unwrap()
}

/// The envelope a client opens: the content-encryption key unwrapped with the certificate's private
/// key, then the content decrypted and unpadded.
fn open_envelope(enc_key_pack: &[u8]) -> Vec<u8> {
    use aes::cipher::{BlockCipherDecrypt, KeyInit};
    use rsa::pkcs1::DecodeRsaPrivateKey;

    // `encKeyPack [1] IMPLICIT OCTET STRING`: primitive, so the value is the octets themselves.
    let mut outer = Reader::new(enc_key_pack);
    let pack = outer.next_tlv("encKeyPack").expect("a TLV");
    assert_eq!(
        pack.tag, 0x81,
        "encKeyPack is a primitive [1]; a constructed 0xa1 is what a client cannot parse"
    );

    let mut r = Reader::new(pack.content);
    let envelope = r.next_tlv("EnvelopedData").expect("a SEQUENCE");
    assert_eq!(envelope.tag, der::SEQUENCE);

    let mut fields = Reader::new(envelope.content);
    let version = fields.next_tlv("version").expect("version");
    assert_eq!(version.content, &[0u8], "EnvelopedData version 0");

    let recipients = fields.next_tlv("recipientInfos").expect("recipientInfos");
    assert_eq!(recipients.tag, 0x31, "recipientInfos is a SET");
    let mut set = Reader::new(recipients.content);
    let ktri = set
        .next_tlv("KeyTransRecipientInfo")
        .expect("one recipient");

    let mut k = Reader::new(ktri.content);
    let _version = k.next_tlv("version").expect("version");
    let rid = k.next_tlv("rid").expect("rid");
    assert_eq!(rid.tag, der::ctx(0), "rid is [0] IssuerAndSerialNumber");
    // The recipient is the *client's* certificate: unwrapping must work with its key.
    let mut rid_inner = Reader::new(rid.content);
    let issuer_and_serial = rid_inner
        .next_tlv("IssuerAndSerialNumber")
        .expect("a SEQUENCE");
    let mut rid_seq = Reader::new(issuer_and_serial.content);
    let _issuer = rid_seq.next_tlv("issuer").expect("the issuer's Name");
    let serial = rid_seq.next_tlv("serialNumber").expect("the serial");
    // The serial is what identifies the recipient: a name alone names every certificate one CA
    // issued, and a transport key addressed to "some certificate of that CA" is addressed to
    // nobody in particular. The serial is 20 random octets, so finding it in the certificate's
    // own DER is conclusive.
    let client_cert = der_of(&fixture("alice.pem"));
    assert!(
        client_cert
            .windows(serial.content.len())
            .any(|w| w == serial.content),
        "the recipient's serial is not the signing certificate's"
    );
    let key_alg = k.next_tlv("keyEncryptionAlgorithm").expect("an algorithm");
    assert!(
        key_alg
            .content
            .windows(9)
            .any(|w| w == [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01]),
        "the key encryption algorithm is not rsaEncryption"
    );
    let wrapped = k.next_tlv("encryptedKey").expect("the wrapped key");

    // PKCS#8 is what `openssl genpkey` writes and PKCS#1 what older tools do; the identity loader
    // accepts both, so the test does too.
    use rsa::pkcs8::DecodePrivateKey;
    let key_der = der_of(&fixture("alice-key.pem"));
    let key = rsa::RsaPrivateKey::from_pkcs8_der(&key_der)
        .or_else(|_| rsa::RsaPrivateKey::from_pkcs1_der(&key_der))
        .expect("the client's private key");
    let cek = key
        .decrypt(rsa::Pkcs1v15Encrypt, wrapped.content)
        .expect("the content-encryption key unwraps with the client's key");
    assert_eq!(cek.len(), 32, "AES-256");

    let eci = fields
        .next_tlv("encryptedContentInfo")
        .expect("encryptedContentInfo");
    let mut c = Reader::new(eci.content);
    let content_type = c.next_tlv("contentType").expect("a content type");
    assert_eq!(
        content_type.content,
        [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02],
        "the content type is id-signedData: the ciphertext holds a signature, and a client \
         refuses a transported key that is not signed"
    );
    let content_alg = c
        .next_tlv("contentEncryptionAlgorithm")
        .expect("an algorithm");
    let mut alg = Reader::new(content_alg.content);
    let oid = alg.next_tlv("oid").expect("an OID");
    assert_eq!(
        oid.content,
        [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2a],
        "aes256-CBC"
    );
    let iv = alg.next_tlv("iv").expect("an IV");
    assert_eq!(iv.content.len(), 16);
    let encrypted = c.next_tlv("encryptedContent").expect("the ciphertext");
    assert_eq!(encrypted.tag, 0x80, "encryptedContent is a primitive [0]");

    let cipher = aes::Aes256::new_from_slice(&cek).expect("an AES key");
    let mut prev: [u8; 16] = iv.content.try_into().expect("16 octets");
    let mut plain = Vec::with_capacity(encrypted.content.len());
    for chunk in encrypted.content.chunks(16) {
        let mut block: [u8; 16] = chunk.try_into().expect("whole blocks");
        let ciphertext = block;
        cipher.decrypt_block((&mut block).into());
        for (byte, p) in block.iter_mut().zip(prev.iter()) {
            *byte ^= *p;
        }
        prev = ciphertext;
        plain.extend_from_slice(&block);
    }
    let pad = *plain.last().expect("padding") as usize;
    assert!((1..=16).contains(&pad), "PKCS #7 padding");
    plain.truncate(plain.len() - pad);
    plain
}

/// `ReplyKeyPack` out of the bare `SignedData` inside the envelope.
fn reply_key_pack_of(signed_data: &[u8]) -> (u8, Vec<u8>, Vec<u8>, Vec<u8>) {
    // SignedData ::= SEQUENCE { version, digestAlgorithms, encapContentInfo, [0] certs, signerInfos }
    let mut r = Reader::new(signed_data);
    let sd = r.next_tlv("SignedData").expect("SignedData");
    assert_eq!(
        sd.tag,
        der::SEQUENCE,
        "the content is a bare SignedData, not a ContentInfo"
    );
    let mut f = Reader::new(sd.content);
    let _version = f.next_tlv("version").expect("version");
    let _digests = f.next_tlv("digestAlgorithms").expect("digestAlgorithms");
    let eci = f.next_tlv("encapContentInfo").expect("encapContentInfo");
    let mut e = Reader::new(eci.content);
    let oid = e.next_tlv("contentType").expect("contentType");
    // 1.3.6.1.5.2.3.3, encoded: `43 06 01 05 02 03 03`. The neighbouring `.4` is
    // `id-pkinit-KPClientAuth`, an extended key usage — a reply signed under that OID is one a
    // client looks for in a certificate and never in a `ReplyKeyPack`.
    assert_eq!(
        oid.content,
        [0x2b, 0x06, 0x01, 0x05, 0x02, 0x03, 0x03],
        "the signed content is id-pkinit-rkeyData"
    );
    let wrapped = e.next_tlv("content").expect("content");
    let mut w = Reader::new(wrapped.content);
    let inner = w.next_tlv("octets").expect("OCTET STRING");

    let mut p = Reader::new(inner.content);
    let pack = p.next_tlv("ReplyKeyPack").expect("ReplyKeyPack");
    let mut fields = Reader::new(pack.content);

    // RFC 4556's module is `EXPLICIT TAGS`, like RFC 4120's: `[0] Int32` carries the INTEGER TLV
    // as its content, so every value here is one level deeper than an implicitly tagged field
    // would be. Decoding this the other way is what makes a reader see an enctype of 2.
    let key_field = fields.next_tlv("replyKey").expect("replyKey");
    let mut key_reader = Reader::new(key_field.content);
    let key_seq = key_reader.next_tlv("EncryptionKey").expect("EncryptionKey");
    let mut k = Reader::new(key_seq.content);
    let keytype_field = k.next_tlv("keytype").expect("keytype");
    let mut kt = Reader::new(keytype_field.content);
    let keytype = kt.next_tlv("Int32").expect("Int32");
    let keyvalue_field = k.next_tlv("keyvalue").expect("keyvalue");
    let mut kv = Reader::new(keyvalue_field.content);
    let keyvalue = kv.next_tlv("keyvalue").expect("the key's octets");

    let cksum_field = fields.next_tlv("asChecksum").expect("asChecksum");
    let mut cksum_reader = Reader::new(cksum_field.content);
    let cksum = cksum_reader.next_tlv("Checksum").expect("Checksum");
    let mut c = Reader::new(cksum.content);
    let cksumtype_field = c.next_tlv("cksumtype").expect("cksumtype");
    let mut ct = Reader::new(cksumtype_field.content);
    let cksumtype = ct.next_tlv("Int32").expect("Int32");
    let checksum_field = c.next_tlv("checksum").expect("checksum");
    let mut cs = Reader::new(checksum_field.content);
    let checksum = cs.next_tlv("checksum").expect("the checksum's octets");

    (
        keytype.content[0],
        keyvalue.content.to_vec(),
        cksumtype.content.to_vec(),
        checksum.content.to_vec(),
    )
}

#[test]
fn a_request_without_a_public_value_is_answered_by_key_transport() {
    let answer = reply::answer(
        &state(),
        &request_without_public_value(),
        BODY,
        AS_REQ,
        &p("alice@EXAMPLE.COM"),
        &p("krbtgt/EXAMPLE.COM@EXAMPLE.COM"),
        Enctype::Aes256Sha1,
        NOW,
        &rng(),
    )
    .expect("a request with no clientPublicValue is answered, not refused");

    assert_eq!(
        answer.pa_pk_as_rep[0], 0x81,
        "the reply is encKeyPack [1], not dhKeyInfo [0]"
    );
    assert_eq!(answer.client_group_bits, 0, "no group was agreed");
    assert!(
        answer.session_key.is_none(),
        "the KDC does not choose the session key here"
    );
    assert!(
        answer.pa_pkinit_kx.is_none(),
        "PA-PKINIT-KX belongs to anonymous PKINIT"
    );
}

#[test]
fn the_transported_key_opens_with_the_clients_certificate_and_is_the_reply_key() {
    let answer = reply::answer(
        &state(),
        &request_without_public_value(),
        BODY,
        AS_REQ,
        &p("alice@EXAMPLE.COM"),
        &p("krbtgt/EXAMPLE.COM@EXAMPLE.COM"),
        Enctype::Aes256Sha1,
        NOW,
        &rng(),
    )
    .expect("answered");

    let signed = open_envelope(&answer.pa_pk_as_rep);
    let (keytype, keyvalue, cksumtype, checksum) = reply_key_pack_of(&signed);

    assert_eq!(
        keytype, 18,
        "aes256-cts-hmac-sha1-96, the enctype the reply is sealed in"
    );
    assert_eq!(
        keyvalue,
        answer.reply_key.bytes(),
        "the transported key is the key the reply part is encrypted under"
    );
    // 16 is `hmac-sha1-96-aes256` (RFC 3962 §6); 15 is the aes128 variant, and a client compares
    // this number against its own enctype's and rejects the pack on a mismatch.
    assert_eq!(
        cksumtype[0], 16,
        "hmac-sha1-96-aes256, the checksum of the reply key's enctype"
    );

    // And the checksum really is over *this* AS-REQ: a pack answered for another request would
    // carry a checksum that does not verify here.
    let usage = reply::KU_PA_PK_AS_REQ.to_be_bytes();
    let expected = rrl_kdc::crypto::profile::checksum_parts(
        Enctype::Aes256Sha1,
        answer.reply_key.bytes(),
        &[&usage, AS_REQ],
    )
    .expect("the checksum");
    assert_eq!(
        checksum, expected,
        "asChecksum covers the whole AS-REQ with usage 6"
    );

    let other = rrl_kdc::crypto::profile::checksum_parts(
        Enctype::Aes256Sha1,
        answer.reply_key.bytes(),
        &[&usage, b"a different AS-REQ"],
    )
    .expect("the checksum");
    assert_ne!(
        checksum, other,
        "the checksum cannot be the same for two different requests"
    );
}

/// The reply key is the KDC's own: two answers to the same request must not hand out the same key.
#[test]
fn two_answers_carry_different_reply_keys() {
    let first = reply::answer(
        &state(),
        &request_without_public_value(),
        BODY,
        AS_REQ,
        &p("alice@EXAMPLE.COM"),
        &p("krbtgt/EXAMPLE.COM@EXAMPLE.COM"),
        Enctype::Aes256Sha1,
        NOW,
        &rng(),
    )
    .expect("answered");
    let second = reply::answer(
        &state(),
        &request_without_public_value(),
        BODY,
        AS_REQ,
        &p("alice@EXAMPLE.COM"),
        &p("krbtgt/EXAMPLE.COM@EXAMPLE.COM"),
        Enctype::Aes256Sha1,
        NOW,
        &rng(),
    )
    .expect("answered");
    // The test's generator restarts, so this compares the *cipher*'s contribution: the key must
    // come from it rather than from anything in the request.
    assert_ne!(
        first.reply_key.bytes(),
        second.reply_key.bytes(),
        "a reply key that repeats is a key every earlier client knows"
    );
}
