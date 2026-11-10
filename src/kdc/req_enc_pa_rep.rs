//! `PA-REQ-ENC-PA-REP` (RFC 6806 §11): the KDC's checksum over the request it answered.
//!
//! The value is one `Checksum` — the reply key's own checksum type, the reply key as the key,
//! and the request *as it arrived* as the data — placed in `enc-pa-rep` of the encrypted part.
//! The request flag `enc-pa-rep` (bit 15) travels with it, and the two must agree: a client reads
//! the flag to decide whether to look for the checksum, and a flag without a checksum makes it
//! reject a correct reply as `KRB5_KDCREP_MODIFIED`.
//!
//! Why it exists at all, in the words of the two clients that implement it (MIT's
//! `krb5int_fast_verify_nego` and `krb5` 1.0's `verify_enc_pa_rep`): the unprotected part of a
//! request can be rewritten in flight, and the reply travels in a key nobody else holds. A
//! checksum over the request, keyed with the reply key, is the one thing that ties the two
//! together — an attacker who alters the request cannot recompute it, and the client sees that
//! the answer is to a request it did not send.
//!
//! The second thing the client learns from the same PA-DATA is whether the KDC supports FAST
//! (the presence of `PA-FX-FAST` beside this value), and a client that does not learn that does
//! not attempt S4U at all. That is why this is a prerequisite for protocol transition rather
//! than a refinement of it.

use crate::crypto::{Cipher, Key};
use crate::der;
use crate::error::Result;

/// `PA-REQ-ENC-PA-REP`.
pub const PA_REQ_ENC_PA_REP: i32 = 149;

/// `KRB5_KU_AS_REQ`, Heimdal's `lib/krb5/krb5.h`.
pub const KU_AS_REQ: u32 = 56;
/// `KRB5_KU_TGS_REQ`, the next entry of the same table.
pub const KU_TGS_REQ: u32 = 57;

/// The `Checksum` a reply carries for `request`, keyed with `reply_key`.
///
/// `request` is the exact octets the client sent, not a re-encoding: the client verifies over
/// what it wrote, and a re-encoding that differs by one length octet produces a checksum it
/// cannot check, which it reports as a modified reply.
pub fn checksum(
    cipher: &dyn Cipher,
    reply_key: &Key,
    usage: u32,
    request: &[u8],
) -> Result<Vec<u8>> {
    let sum = cipher.checksum(reply_key, usage, request)?;
    Ok(der::seq(&[
        der::field(0, der::int(reply_key.enctype().checksum_type() as i64)),
        der::field(1, der::octets(&sum)),
    ]))
}

/// Whether a request asked for this value.
///
/// An empty `PA-REQ-ENC-PA-REP` in the request is the whole request: the client is saying "put
/// your checksum in the reply", and there is nothing to read out of it.
pub fn requested(padata: &[(i32, Vec<u8>)]) -> bool {
    padata.iter().any(|(t, _)| *t == PA_REQ_ENC_PA_REP)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{Enctype, OwnCipher};

    fn key() -> Key {
        Key::new(Enctype::Aes256Sha1, vec![0x11; 32]).unwrap()
    }

    #[test]
    fn the_checksum_is_a_type_and_a_value_the_client_can_parse() {
        let cipher = OwnCipher;
        let value = checksum(&cipher, &key(), KU_AS_REQ, b"the request").unwrap();
        let mut r = der::Reader::new(&value);
        let seq = r.expect_in("Checksum", der::SEQUENCE).unwrap();
        let f = der::Fields::parse("Checksum", seq).unwrap();
        assert_eq!(
            f.int(0, "Checksum").unwrap() as i32,
            Enctype::Aes256Sha1.checksum_type(),
            "the type must be the reply key's own, or a client refuses to check it"
        );
        let sum = f.octets(1, "Checksum").unwrap();
        cipher
            .verify_checksum(&key(), KU_AS_REQ, b"the request", sum)
            .expect("and it verifies over the request");
    }

    #[test]
    fn the_two_exchanges_use_different_key_usages() {
        // 56 and 57 are not interchangeable: a checksum under the wrong usage verifies under
        // neither, and the client reports a modified reply rather than a wrong key usage.
        let cipher = OwnCipher;
        let as_value = checksum(&cipher, &key(), KU_AS_REQ, b"req").unwrap();
        let tgs_value = checksum(&cipher, &key(), KU_TGS_REQ, b"req").unwrap();
        assert_ne!(
            as_value, tgs_value,
            "an AS checksum that equalled a TGS one would mean the usage is not in it"
        );

        let mut r = der::Reader::new(&as_value);
        let seq = r.expect_in("Checksum", der::SEQUENCE).unwrap();
        let f = der::Fields::parse("Checksum", seq).unwrap();
        let sum = f.octets(1, "Checksum").unwrap();
        assert!(
            cipher
                .verify_checksum(&key(), KU_TGS_REQ, b"req", sum)
                .is_err(),
            "the AS checksum must not verify at the TGS usage"
        );
    }

    #[test]
    fn an_empty_pa_data_is_a_request_and_a_missing_one_is_not() {
        assert!(requested(&[(PA_REQ_ENC_PA_REP, Vec::new())]));
        assert!(!requested(&[(1, Vec::new())]));
        assert!(!requested(&[]));
    }
}
