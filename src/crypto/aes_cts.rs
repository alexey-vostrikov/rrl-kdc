//! AES in CBC mode with ciphertext stealing, the variant Kerberos uses.
//!
//! Output length equals input length: there is no padding octet and no block
//! alignment requirement beyond "at least one block". The construction is the
//! one RFC 3962 §5 specifies (and RFC 8009 §1 names CBC-CS3): the CBC
//! ciphertext of the whole message, with the final two blocks exchanged and
//! the (now) last one truncated to the length of the ragged tail.
//!
//! Two traps, both of which produce a decryptor that only talks to itself:
//!
//! 1. **The swap happens even when the input is an exact multiple of 16.**
//!    An implementation that only steals on a ragged tail passes the 17- and
//!    31-octet vectors and fails on 32, 48, 64 — which are the shapes real
//!    Kerberos traffic takes, because the confounder is 16 octets.
//! 2. **The zero extension is internal.** The final partial block is padded
//!    with zeros to be encryptable, but those zeros are never transmitted and
//!    never MACed; recovering them on the way back (because the plaintext
//!    there was zero) is how the stolen bytes are found again.
//!
//! `chunks_exact_mut` is used rather than clippy's preferred `as_chunks_mut`
//! because the latter needs the array size as a type parameter (`U16`) for one
//! call, which buys nothing; the lint is allowed locally, at those two loops.

use aes::cipher::{Array, BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};

use crate::error::{Error, Result};

/// The AES block size.
pub const BLOCK: usize = 16;

enum Aes {
    A128(aes::Aes128),
    A256(aes::Aes256),
}

impl Aes {
    fn new(key: &[u8]) -> Result<Self> {
        match key.len() {
            16 => Ok(Aes::A128(
                aes::Aes128::new_from_slice(key)
                    .map_err(|_| Error::Crypto("AES-128 key".into()))?,
            )),
            32 => Ok(Aes::A256(
                aes::Aes256::new_from_slice(key)
                    .map_err(|_| Error::Crypto("AES-256 key".into()))?,
            )),
            n => Err(Error::Crypto(format!(
                "AES key must be 16 or 32 octets, got {n}"
            ))),
        }
    }

    fn encrypt_block(&self, block: &mut [u8; BLOCK]) {
        let ga = block.into();
        match self {
            Aes::A128(c) => c.encrypt_block(ga),
            Aes::A256(c) => c.encrypt_block(ga),
        }
    }

    fn decrypt_block(&self, block: &mut [u8; BLOCK]) {
        let ga = block.into();
        match self {
            Aes::A128(c) => c.decrypt_block(ga),
            Aes::A256(c) => c.decrypt_block(ga),
        }
    }

    fn decrypt_blocks(&self, blocks: &mut [u8]) {
        let (blocks, rest) = Array::slice_as_chunks_mut(blocks);
        debug_assert!(rest.is_empty());
        match self {
            Aes::A128(c) => c.decrypt_blocks(blocks),
            Aes::A256(c) => c.decrypt_blocks(blocks),
        }
    }
}

#[inline]
fn xor_into(dst: &mut [u8; BLOCK], src: &[u8]) {
    for (d, s) in dst.iter_mut().zip(src) {
        *d ^= *s;
    }
}

/// Encrypt `data` with AES-CBC-CTS. `iv` is the cipher state; Kerberos always
/// supplies the all-zero state (RFC 3962 §5).
pub fn encrypt(key: &[u8], iv: &[u8; BLOCK], data: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes::new(key)?;
    if data.len() < BLOCK {
        return Err(Error::Crypto(format!(
            "CTS input must be at least one block, got {} octets",
            data.len()
        )));
    }
    let mut out = data.to_vec();
    let n = out.len();

    if n == BLOCK {
        let b: &mut [u8; BLOCK] = out.as_mut_slice().try_into().expect("one block");
        xor_into(b, iv);
        cipher.encrypt_block(b);
        return Ok(out);
    }

    let d = match n % BLOCK {
        0 => BLOCK,
        r => r,
    };
    let nb = n.div_ceil(BLOCK);

    // Ordinary CBC over every full block but the final (partial) one.
    let mut prev = *iv;
    #[allow(clippy::chunks_exact_to_as_chunks)] // see the note above
    for b in out[..(nb - 1) * BLOCK].chunks_exact_mut(BLOCK) {
        let b: &mut [u8; BLOCK] = b.try_into().expect("whole block");
        xor_into(b, &prev);
        cipher.encrypt_block(b);
        prev = *b;
    }

    // The ragged tail, zero-extended for this pass only.
    let mut last = [0u8; BLOCK];
    last[..d].copy_from_slice(&out[(nb - 1) * BLOCK..]);
    xor_into(&mut last, &prev);
    cipher.encrypt_block(&mut last);

    // Exchange the final two blocks and truncate the (now) last one to d.
    out[(nb - 2) * BLOCK..(nb - 1) * BLOCK].copy_from_slice(&last);
    out[(nb - 1) * BLOCK..].copy_from_slice(&prev[..d]);
    Ok(out)
}

/// Inverse of [`encrypt`].
pub fn decrypt(key: &[u8], iv: &[u8; BLOCK], data: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes::new(key)?;
    let n = data.len();
    if n < BLOCK {
        return Err(Error::Crypto(format!(
            "CTS input must be at least one block, got {n} octets"
        )));
    }
    let mut out = data.to_vec();

    if n == BLOCK {
        let b: &mut [u8; BLOCK] = out.as_mut_slice().try_into().expect("one block");
        cipher.decrypt_block(b);
        xor_into(b, iv);
        return Ok(out);
    }

    let d = match n % BLOCK {
        0 => BLOCK,
        r => r,
    };
    let nb = n.div_ceil(BLOCK);
    let body = (nb - 2) * BLOCK;

    // Every block before the last two is plain CBC, and CBC decryption is
    // independent per block, so all of them at once; the chaining value is
    // still in `data`.
    cipher.decrypt_blocks(&mut out[..body]);
    #[allow(clippy::chunks_exact_to_as_chunks)] // see the note above
    for (i, b) in out[..body].chunks_exact_mut(BLOCK).enumerate() {
        let prev: &[u8] = if i == 0 {
            &iv[..]
        } else {
            &data[(i - 1) * BLOCK..i * BLOCK]
        };
        for (x, p) in b.iter_mut().zip(prev) {
            *x ^= p;
        }
    }

    // C_{nb-2}, or the IV when there are only two blocks.
    let mut prev = *iv;
    if nb > 2 {
        prev.copy_from_slice(&data[body - BLOCK..body]);
    }

    // The full block at `body` is C_nb; the truncated one at the tail is the
    // first d octets of C_{nb-1}.
    let mut z = [0u8; BLOCK];
    z.copy_from_slice(&data[body..body + BLOCK]);
    cipher.decrypt_block(&mut z); // z = (P_nb || 0*) XOR C_{nb-1}
    let tail = &data[body + BLOCK..];

    // The stolen octets of C_{nb-1} reappear in z, because the plaintext there
    // was the zero extension.
    let mut p_nm1 = [0u8; BLOCK];
    p_nm1[..d].copy_from_slice(tail);
    p_nm1[d..].copy_from_slice(&z[d..]);
    cipher.decrypt_block(&mut p_nm1);
    xor_into(&mut p_nm1, &prev);

    out[body..body + BLOCK].copy_from_slice(&p_nm1);
    for ((o, z), t) in out[body + BLOCK..].iter_mut().zip(z).zip(tail) {
        *o = z ^ t;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ZERO: [u8; BLOCK] = [0u8; BLOCK];

    fn key16() -> Vec<u8> {
        hex::decode("6367c48dd193d56ea7b0baad25b19455e529f5ee").unwrap()[..16].to_vec()
    }

    #[test]
    fn every_length_from_one_block_up_round_trips() {
        let k = key16();
        for n in BLOCK..=(BLOCK * 6 + 15) {
            let data: Vec<u8> = (0..n).map(|i| (i * 7 + 3) as u8).collect();
            let ct = encrypt(&k, &ZERO, &data).unwrap();
            assert_eq!(ct.len(), n, "CTS must not change the length");
            assert_ne!(ct, data);
            let pt = decrypt(&k, &ZERO, &ct).unwrap();
            assert_eq!(pt, data, "round trip at {n} octets");
        }
    }

    #[test]
    fn exact_multiple_of_the_block_is_not_plain_cbc() {
        // The trap: at 32 octets the last two blocks must still be exchanged.
        // An implementation that only steals on a ragged tail passes 17 and 31
        // octets and fails here.
        let k = key16();
        let cipher = Aes::new(&k).unwrap();
        let mut c1 = [0u8; BLOCK];
        cipher.encrypt_block(&mut c1); // CBC of two zero blocks: C1 = E(0)
        let mut c2 = [0u8; BLOCK];
        xor_into(&mut c2, &c1); // P_2 is zeros, so the input is C_1
        cipher.encrypt_block(&mut c2); // C2

        let ct = encrypt(&k, &ZERO, &[0u8; 32]).unwrap();
        assert_eq!(ct.len(), 32);
        // Transmitted layout is C_2 || C_1 when the tail fills a whole block.
        assert_eq!(&ct[..BLOCK], &c2[..], "C_n must come before C_{{n-1}}");
        assert_eq!(&ct[BLOCK..], &c1[..], "C_{{n-1}} is the truncated tail");
    }

    #[test]
    fn rejects_short_input() {
        let k = key16();
        assert!(encrypt(&k, &ZERO, &[0u8; 15]).is_err());
        assert!(decrypt(&k, &ZERO, &[0u8; 15]).is_err());
    }
}
