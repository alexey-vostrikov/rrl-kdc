//! RFC 4121 §4.2 per-message tokens, from the **acceptor's** side.
//!
//! A `kadmin` client authenticates with an AP-REQ and then seals every call in a
//! GSS Wrap token, because the calls carry passwords. So this module is the half
//! of RFC 4121 that the KDC's `kpasswd` path never needed: verifying a peer's MIC
//! and unsealing its Wrap tokens, and doing the same in reverse for replies.
//!
//! # The numbers are the whole trap
//!
//! RFC 4121 §2 keys every operation off the sender's role:
//!
//! ```text
//!                     MIC (04 04)          Wrap (05 04)
//!   sender acceptor    23 ACCEPTOR_SIGN     22 ACCEPTOR_SEAL
//!   sender initiator   25 INITIATOR_SIGN    24 INITIATOR_SEAL
//! ```
//!
//! An acceptor therefore *emits* with 22/23 and *verifies* with 24/25. Swapping
//! the pair round-trips perfectly against itself — both sides derive the same
//! wrong key — and fails against every real peer, which is why the two directions
//! are separate methods here rather than a flag.
//!
//! Two more traps, both of which a self-test sails past:
//!
//! * **The header travels at the END of the protected buffer.** §4.2.4 is
//!   `encrypt(plaintext | filler | header)` — data first, header last. There is no
//!   length field that would catch the other order.
//! * **A MIC token's filler is five octets, a Wrap token's is one.** Copying one
//!   header builder into the other shifts `SND_SEQ` by four octets.

use crate::crypto::{Cipher, Key, usage};
use crate::error::{Error, Result};

/// A MIC token's `TOK_ID` (RFC 4121 §4.2.6.1).
pub const TOK_ID_MIC: [u8; 2] = [0x04, 0x04];
/// A Wrap token's `TOK_ID` (RFC 4121 §4.2.6.2).
pub const TOK_ID_WRAP: [u8; 2] = [0x05, 0x04];
/// Both token classes carry a 16-octet header.
pub const HEADER_LEN: usize = 16;
/// MIC filler: five octets of `0xff` at `[3..8)`.
pub const MIC_FILLER: [u8; 5] = [0xFF; 5];
/// Wrap filler: one octet at `[3]`.
pub const WRAP_FILLER: u8 = 0xFF;
/// Bit 0 of `Flags`: the sender is the context acceptor.
pub const FLAG_SENT_BY_ACCEPTOR: u8 = 0x01;
/// Bit 1 of `Flags`: confidentiality is provided.
pub const FLAG_SEALED: u8 = 0x02;
/// Bit 2 of `Flags`: the context is keyed by an acceptor subkey.
pub const FLAG_ACCEPTOR_SUBKEY: u8 = 0x04;

/// A verified token: the sequence number it carried, and its message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Verified {
    /// `SND_SEQ` as the peer sent it. The caller must check it is the next one
    /// it expects, or a replayed token would verify.
    pub seq: u64,
    /// The plaintext, for a Wrap token; the signed message is the caller's.
    pub message: Vec<u8>,
}

/// The acceptor half of an established GSS context.
///
/// Holds the base key: the initiator's subkey when it sent one, the ticket's
/// session key otherwise. RFC 4121 §2 makes that choice on the *initiator's*
/// action, not on ours — an acceptor that asserted a subkey of its own in the
/// AP-REP would change it, and this one does not.
#[derive(Debug)]
pub struct AcceptorContext {
    cipher: std::sync::Arc<dyn Cipher>,
    key: Key,
    /// Whether the AP-REP asserted an acceptor subkey. Always false here, and
    /// kept as a field so that a token claiming one is refused with the right
    /// reason rather than an opaque MAC failure.
    acceptor_subkey: bool,
}

impl AcceptorContext {
    /// A context keyed by `key`.
    pub fn new(cipher: std::sync::Arc<dyn Cipher>, key: Key) -> Self {
        AcceptorContext {
            cipher,
            key,
            acceptor_subkey: false,
        }
    }

    /// The key per-message tokens are computed with — for tests and logs, never
    /// for printing.
    pub fn enctype(&self) -> crate::crypto::Enctype {
        self.key.enctype()
    }

    /// The checksum length this enctype's tokens carry.
    ///
    /// From the enctypes themselves, and the last one is the trap: RFC 3962's
    /// AES-SHA1 truncates its HMAC to 96 bits, RFC 8009 §6's AES-128-SHA2 to 128,
    /// and AES-256-SHA2 to **192** — not 128, because its HMAC is SHA-384.
    /// Assuming "SHA2 means 16" makes a token four octets short and the failure
    /// reads as "wrong key" rather than "wrong length".
    fn checksum_len(&self) -> usize {
        match self.key.enctype() {
            crate::crypto::Enctype::Aes128Sha1 | crate::crypto::Enctype::Aes256Sha1 => 12,
            crate::crypto::Enctype::Aes128Sha256 => 16,
            crate::crypto::Enctype::Aes256Sha384 => 24,
        }
    }

    /// The `Flags` this side sets on every token it emits.
    fn flags(&self) -> u8 {
        let mut flags = FLAG_SENT_BY_ACCEPTOR;
        if self.acceptor_subkey {
            flags |= FLAG_ACCEPTOR_SUBKEY;
        }
        flags
    }

    /// Verifies a MIC token from the initiator over `message`.
    ///
    /// Returns the sequence number the token carried: the caller is the only one
    /// who knows which number to expect, so accepting whatever arrives would make
    /// a replayed token indistinguishable from a fresh one.
    pub fn verify_mic(&self, token: &[u8], message: &[u8]) -> Result<Verified> {
        let checksum_len = self.checksum_len();
        if token.len() != HEADER_LEN + checksum_len {
            return Err(Error::Crypto(format!(
                "GSS MIC: {} octets, expected {}",
                token.len(),
                HEADER_LEN + checksum_len
            )));
        }
        if token[0..2] != TOK_ID_MIC {
            return Err(Error::Crypto(format!(
                "GSS MIC: TOK_ID {:02x}{:02x} is not a MIC token",
                token[0], token[1]
            )));
        }
        if token[3..8] != MIC_FILLER {
            return Err(Error::Crypto("GSS MIC: the filler is not five 0xff".into()));
        }
        if token[2] & FLAG_SEALED != 0 {
            return Err(Error::Crypto(
                "GSS MIC: the sealed flag is set, which RFC 4121 forbids in a MIC token".into(),
            ));
        }
        if token[2] & FLAG_SENT_BY_ACCEPTOR != 0 {
            return Err(Error::Crypto(
                "GSS MIC: the token claims to be the acceptor's, and this side is the acceptor"
                    .into(),
            ));
        }
        if token[2] & FLAG_ACCEPTOR_SUBKEY != 0 && !self.acceptor_subkey {
            return Err(Error::Crypto(
                "GSS MIC: the token claims an acceptor subkey this context never asserted".into(),
            ));
        }

        let header = &token[..HEADER_LEN];
        // RFC 4121 §4.2.4: the checksum covers the message and then the header.
        let mut signed = Vec::with_capacity(message.len() + HEADER_LEN);
        signed.extend_from_slice(message);
        signed.extend_from_slice(header);
        self.cipher.verify_checksum(
            &self.key,
            usage::INITIATOR_SIGN,
            &signed,
            &token[HEADER_LEN..],
        )?;

        Ok(Verified {
            seq: u64::from_be_bytes(header[8..16].try_into().expect("8 octets")),
            message: message.to_vec(),
        })
    }

    /// Unseals a Wrap token from the initiator.
    pub fn unwrap(&self, token: &[u8]) -> Result<Verified> {
        if token.len() < HEADER_LEN {
            return Err(Error::Crypto("GSS Wrap: shorter than its header".into()));
        }
        if token[0..2] != TOK_ID_WRAP {
            return Err(Error::Crypto(format!(
                "GSS Wrap: TOK_ID {:02x}{:02x} is not a Wrap token",
                token[0], token[1]
            )));
        }
        if token[3] != WRAP_FILLER {
            return Err(Error::Crypto("GSS Wrap: the filler is not 0xff".into()));
        }
        if token[2] & FLAG_SENT_BY_ACCEPTOR != 0 {
            return Err(Error::Crypto(
                "GSS Wrap: the token claims to be the acceptor's, and this side is the acceptor"
                    .into(),
            ));
        }
        if token[2] & FLAG_ACCEPTOR_SUBKEY != 0 && !self.acceptor_subkey {
            return Err(Error::Crypto(
                "GSS Wrap: the token claims an acceptor subkey this context never asserted".into(),
            ));
        }

        let ec = u16::from_be_bytes([token[4], token[5]]) as usize;
        let rrc = u16::from_be_bytes([token[6], token[7]]);
        let seq = u64::from_be_bytes(token[8..16].try_into().expect("8 octets"));
        let body = &token[HEADER_LEN..];
        if body.is_empty() {
            return Err(Error::Crypto("GSS Wrap: no body".into()));
        }

        // §4.2.5: the body is rotated right by RRC; undo it before decrypting.
        let rotated = rotate_left(body, rrc);
        let mut plain = self
            .cipher
            .decrypt(&self.key, usage::INITIATOR_SEAL, &rotated)?;

        // Bounds before subtraction: `ec` is the peer's number, up to 65535.
        if plain.len() < HEADER_LEN + ec {
            return Err(Error::Crypto(format!(
                "GSS Wrap: {} octets cannot hold a header and {ec} octets of filler",
                plain.len()
            )));
        }

        // The trailing header is what binds the *cleartext* header to the sealed
        // one: Flags, EC and SND_SEQ travel outside the ciphertext, and only this
        // comparison stops the peer rewriting them.
        let transmitted: [u8; HEADER_LEN] = token[..HEADER_LEN].try_into().expect("16");
        let mut expected = transmitted;
        // §4.2.4: only RRC is zeroed inside the protected header.
        expected[6] = 0;
        expected[7] = 0;
        let recovered = &plain[plain.len() - HEADER_LEN..];
        if recovered != expected {
            return Err(Error::Crypto(
                "GSS Wrap: the sealed header does not match the one on the wire".into(),
            ));
        }

        plain.truncate(plain.len() - HEADER_LEN - ec);
        Ok(Verified {
            seq,
            message: plain,
        })
    }

    /// Seals `message` in a Wrap token for the initiator.
    pub fn seal(&self, seq: u64, message: &[u8]) -> Result<Vec<u8>> {
        let header = wrap_header(self.flags() | FLAG_SEALED, 0, 0, seq);
        let mut to_encrypt = Vec::with_capacity(message.len() + HEADER_LEN);
        to_encrypt.extend_from_slice(message);
        to_encrypt.extend_from_slice(&header);
        let sealed = self
            .cipher
            .encrypt(&self.key, usage::ACCEPTOR_SEAL, &to_encrypt)?;
        let mut token = Vec::with_capacity(HEADER_LEN + sealed.len());
        token.extend_from_slice(&header);
        token.extend_from_slice(&sealed);
        Ok(token)
    }

    /// A MIC token over `message`, for the reply verifier.
    pub fn emit_mic(&self, seq: u64, message: &[u8]) -> Result<Vec<u8>> {
        let header = mic_header(self.flags(), seq);
        let mut signed = Vec::with_capacity(message.len() + HEADER_LEN);
        signed.extend_from_slice(message);
        signed.extend_from_slice(&header);
        let tag = self
            .cipher
            .checksum(&self.key, usage::ACCEPTOR_SIGN, &signed)?;
        let mut token = header.to_vec();
        token.extend_from_slice(&tag);
        Ok(token)
    }
}

/// `04 04 | Flags | FF FF FF FF FF | SND_SEQ`.
fn mic_header(flags: u8, seq: u64) -> [u8; HEADER_LEN] {
    let mut header = [0u8; HEADER_LEN];
    header[0..2].copy_from_slice(&TOK_ID_MIC);
    header[2] = flags;
    header[3..8].copy_from_slice(&MIC_FILLER);
    header[8..16].copy_from_slice(&seq.to_be_bytes());
    header
}

/// `05 04 | Flags | FF | EC | RRC | SND_SEQ` — EC and RRC big-endian, unlike the
/// little-endian fields of RFC 4121 §4.1.1.
fn wrap_header(flags: u8, ec: u16, rrc: u16, seq: u64) -> [u8; HEADER_LEN] {
    let mut header = [0u8; HEADER_LEN];
    header[0..2].copy_from_slice(&TOK_ID_WRAP);
    header[2] = flags;
    header[3] = WRAP_FILLER;
    header[4..6].copy_from_slice(&ec.to_be_bytes());
    header[6..8].copy_from_slice(&rrc.to_be_bytes());
    header[8..16].copy_from_slice(&seq.to_be_bytes());
    header
}

/// Rotates `body` left by `rrc` octets — the inverse of §4.2.5's rotation.
///
/// The modulo is not defensive tidying: RRC is a `u16`, so 65535 over an 8-octet
/// body is legal on the wire and an unreduced index would be a remotely
/// triggerable panic.
fn rotate_left(body: &[u8], rrc: u16) -> Vec<u8> {
    if body.is_empty() {
        return Vec::new();
    }
    let split = (rrc as usize) % body.len();
    let mut out = Vec::with_capacity(body.len());
    out.extend_from_slice(&body[split..]);
    out.extend_from_slice(&body[..split]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{Enctype, OwnCipher};
    use std::sync::Arc;

    fn context(enctype: Enctype) -> (AcceptorContext, Key) {
        let key = OwnCipher.random(enctype).unwrap();
        (
            AcceptorContext::new(Arc::new(OwnCipher) as Arc<dyn Cipher>, key.clone()),
            key,
        )
    }

    /// A token as an *initiator* would build it: the same functions with the other
    /// role. It exists to produce the bytes the acceptor must judge — the
    /// direction checks below are the point, not the round trip.
    fn initiator_mic(key: &Key, seq: u64, message: &[u8]) -> Vec<u8> {
        let mut header = [0u8; HEADER_LEN];
        header[0..2].copy_from_slice(&TOK_ID_MIC);
        header[2] = 0; // not sent by the acceptor
        header[3..8].copy_from_slice(&MIC_FILLER);
        header[8..16].copy_from_slice(&seq.to_be_bytes());
        let mut signed = message.to_vec();
        signed.extend_from_slice(&header);
        let tag = OwnCipher
            .checksum(key, usage::INITIATOR_SIGN, &signed)
            .unwrap();
        let mut token = header.to_vec();
        token.extend_from_slice(&tag);
        token
    }

    fn initiator_wrap(key: &Key, seq: u64, message: &[u8]) -> Vec<u8> {
        let mut header = [0u8; HEADER_LEN];
        header[0..2].copy_from_slice(&TOK_ID_WRAP);
        header[2] = FLAG_SEALED;
        header[3] = WRAP_FILLER;
        header[8..16].copy_from_slice(&seq.to_be_bytes());
        let mut to_encrypt = message.to_vec();
        to_encrypt.extend_from_slice(&header);
        let sealed = OwnCipher
            .encrypt(key, usage::INITIATOR_SEAL, &to_encrypt)
            .unwrap();
        let mut token = header.to_vec();
        token.extend_from_slice(&sealed);
        token
    }

    #[test]
    fn an_initiators_mic_verifies_and_carries_its_sequence() {
        for enctype in Enctype::ALL {
            let (context, key) = context(enctype);
            let token = initiator_mic(&key, 7, b"the call header");
            let verified = context.verify_mic(&token, b"the call header").unwrap();
            assert_eq!(verified.seq, 7, "{}", enctype.name());
        }
    }

    #[test]
    fn a_mic_over_another_message_is_refused() {
        let (context, key) = context(Enctype::Aes256Sha1);
        let token = initiator_mic(&key, 1, b"one call");
        assert!(
            context.verify_mic(&token, b"another call").is_err(),
            "the checksum binds the message, so a token cannot be moved to another call"
        );
    }

    #[test]
    fn a_reflected_mic_is_refused() {
        // The acceptor's own token replayed at it: the checksum is valid — under
        // the acceptor's usage — and only the direction bit says it is not the
        // peer's. This is what stops a reflection attack.
        let (context, _key) = context(Enctype::Aes256Sha1);
        let own = context.emit_mic(1, b"message").unwrap();
        let error = context
            .verify_mic(&own, b"message")
            .unwrap_err()
            .to_string();
        assert!(error.contains("acceptor"), "{error}");
    }

    #[test]
    fn a_token_of_the_wrong_class_is_refused() {
        let (context, key) = context(Enctype::Aes256Sha1);
        let wrap = initiator_wrap(&key, 1, b"x");
        assert!(
            context.verify_mic(&wrap, b"x").is_err(),
            "a Wrap is not a MIC"
        );
        let mic = initiator_mic(&key, 1, b"x");
        assert!(context.unwrap(&mic).is_err(), "a MIC is not a Wrap");
    }

    #[test]
    fn a_mic_with_the_wrong_filler_is_refused() {
        let (context, key) = context(Enctype::Aes256Sha1);
        let mut token = initiator_mic(&key, 1, b"x");
        token[4] = 0;
        let error = context.verify_mic(&token, b"x").unwrap_err().to_string();
        assert!(error.contains("filler"), "{error}");
    }

    #[test]
    fn a_mic_token_that_claims_to_be_sealed_is_refused() {
        // RFC 4121 §4.2.2: "SHALL NOT be set in MIC tokens".
        let (context, _key) = context(Enctype::Aes256Sha1);
        let mut token = context.emit_mic(1, b"x").unwrap();
        token[2] |= FLAG_SEALED;
        token[2] &= !FLAG_SENT_BY_ACCEPTOR;
        assert!(context.verify_mic(&token, b"x").is_err());
    }

    #[test]
    fn a_short_or_long_token_is_refused_rather_than_truncated() {
        let (context, key) = context(Enctype::Aes256Sha1);
        let token = initiator_mic(&key, 1, b"x");
        for length in [token.len() - 1, token.len() + 1, 0, 3] {
            let mut wrong = token.clone();
            wrong.resize(length, 0);
            assert!(
                context.verify_mic(&wrong, b"x").is_err(),
                "a token of {length} octets must not verify"
            );
        }
    }

    #[test]
    fn a_wrap_round_trips_and_carries_its_sequence() {
        for enctype in Enctype::ALL {
            let (context, key) = context(enctype);
            let token = initiator_wrap(&key, 42, b"an argument list");
            let opened = context.unwrap(&token).unwrap();
            assert_eq!(opened.seq, 42);
            assert_eq!(opened.message, b"an argument list");
        }
    }

    #[test]
    fn a_sealed_header_rewritten_on_the_wire_is_refused() {
        // Flags, EC and SND_SEQ travel in the clear; only the header recovered
        // from inside the ciphertext binds them. Changing the sequence outside
        // must therefore fail even though the ciphertext still decrypts.
        let (context, key) = context(Enctype::Aes256Sha1);
        let mut token = initiator_wrap(&key, 1, b"payload");
        token[15] = 2; // SND_SEQ's last octet
        assert!(
            context.unwrap(&token).is_err(),
            "a rewritten cleartext header must not unwrap"
        );
    }

    #[test]
    fn a_wrap_too_short_for_its_header_and_filler_is_refused() {
        let (context, _key) = context(Enctype::Aes256Sha1);
        assert!(context.unwrap(&[]).is_err());
        let mut token = vec![0u8; HEADER_LEN];
        token[0..2].copy_from_slice(&TOK_ID_WRAP);
        token[3] = WRAP_FILLER;
        // EC claims 60 octets of filler the body cannot hold.
        token[4] = 0;
        token[5] = 60;
        assert!(context.unwrap(&token).is_err());
    }

    #[test]
    fn the_checksum_lengths_are_the_enctypes_own() {
        // RFC 3962 truncates to 96 bits, RFC 8009 §6 to 128 and 192 — the last
        // one is not 128, and assuming it is makes every token four octets short.
        for (enctype, want) in [
            (Enctype::Aes128Sha1, 12),
            (Enctype::Aes256Sha1, 12),
            (Enctype::Aes128Sha256, 16),
            (Enctype::Aes256Sha384, 24),
        ] {
            let (context, _) = context(enctype);
            assert_eq!(context.checksum_len(), want, "{}", enctype.name());
            assert_eq!(
                context.emit_mic(1, b"x").unwrap().len(),
                HEADER_LEN + want,
                "{}",
                enctype.name()
            );
        }
    }

    #[test]
    fn a_rotation_is_undone_before_decryption() {
        // §4.2.5 rotates the body right by RRC; the sender may pick any value,
        // including one larger than the body, and an unreduced index would panic.
        for rrc in [0u16, 1, 7, 4096, u16::MAX] {
            let body = b"0123456789abcdef";
            let rotated = rotate_left(&rotate_left(body, 0), 0);
            assert_eq!(rotated, body);
            let once = rotate_left(body, rrc);
            assert_eq!(once.len(), body.len(), "rrc {rrc} keeps the length");
            let back = {
                // Undo: rotate right by the same amount, which is a left rotation
                // by the complement.
                let split = body.len() - (rrc as usize) % body.len();
                let mut out = once[split..].to_vec();
                out.extend_from_slice(&once[..split]);
                out
            };
            assert_eq!(back, body, "rrc {rrc} must be reversible");
        }
    }
}
