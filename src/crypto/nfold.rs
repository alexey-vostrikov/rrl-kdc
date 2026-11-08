//! RFC 3961 §5.1 n-fold, by the "rotate right 13 bits and add" formulation.
//!
//! n-fold maps an arbitrary octet string to exactly `n` bits by treating the
//! input as a bit stream, repeating it to `lcm(k, n)` bits, and adding the
//! repetitions modulo 2^n. It is used for the DR constant in key derivation
//! and, for AES, for nothing else — which is why an implementation that is
//! wrong here still produces *a* key, just not the key every other
//! implementation produces. The tests below are Heimdal's `n-fold-test.c`
//! vectors, which is the RFC 3961 Appendix A table plus the MIT additions.

/// n-fold `input` to `outbits` bits, returned as whole octets.
///
/// `outbits` must be a multiple of 8: every use in Kerberos folds to a key or
/// block size, and a ragged bit count would have no octet representation.
pub fn n_fold(input: &[u8], outbits: usize) -> Vec<u8> {
    assert_eq!(outbits % 8, 0, "n-fold to a whole number of octets");
    let size = outbits / 8;
    let len = input.len();
    let mut key = vec![0u8; size];
    if len == 0 || size == 0 {
        return key;
    }

    // tmp holds the not-yet-consumed tail of the running sequence followed by
    // the next rotated copy; Heimdal sizes it as 2*max(size, len) + 2*len.
    let mut tmp = vec![0u8; 2 * size.max(len) + 2 * len];
    tmp[..len].copy_from_slice(input);
    let mut rotated: Vec<u8> = input.to_vec();
    let mut l = 0usize;

    loop {
        l += len;
        while l >= size {
            add_be(&mut key, &tmp[..size]);
            l -= size;
            if l == 0 {
                break;
            }
            // memmove(tmp, tmp + size, l)
            tmp.copy_within(size..size + l, 0);
        }
        rotated = rotate_right_13(&rotated, len * 8);
        if l + len > tmp.len() {
            tmp.resize(l + len, 0);
        }
        tmp[l..l + len].copy_from_slice(&rotated);
        if l == 0 {
            break;
        }
    }
    key
}

/// Big-endian addition with end-around carry: `a += b`.
///
/// The carry out of the most significant octet is not dropped — it is added
/// back at the least significant octet and propagated. That is what both MIT's
/// `krb5int_nfold` and Heimdal's `add1` end with, and leaving it out produces
/// a result that differs only in the top octet: close enough to look like a
/// transcription error in the vectors, wrong enough that every derived key is
/// wrong.
fn add_be(a: &mut [u8], b: &[u8]) {
    debug_assert_eq!(a.len(), b.len());
    let mut carry = 0u16;
    for i in (0..a.len()).rev() {
        let x = a[i] as u16 + b[i] as u16 + carry;
        carry = x >> 8;
        a[i] = x as u8;
    }
    while carry != 0 {
        for i in (0..a.len()).rev() {
            let x = a[i] as u16 + carry;
            a[i] = x as u8;
            carry = x >> 8;
            if carry == 0 {
                break;
            }
        }
    }
}

/// Rotate a `bits`-bit string right by 13 bits, as Heimdal's `rr13` does.
///
/// 13 is used because it is coprime with 8 and with every block size in
/// Kerberos, so the rotation visits every byte position before repeating.
fn rotate_right_13(src: &[u8], bits: usize) -> Vec<u8> {
    let bytes = bits.div_ceil(8);
    let shift = 13 % bits;
    let mut dst = vec![0u8; bytes];
    for (i, out) in dst.iter_mut().enumerate() {
        // First bit position of this output byte, moved back by the rotation
        // and wrapped into range.
        let mut bb = 8 * i as isize - shift as isize;
        while bb < 0 {
            bb += bits as isize;
        }
        let bb = bb as usize;
        let (b1, s1) = (bb / 8, bb % 8);
        // Reading `8 - s1` bits would be a shift by 8 when s1 == 0; the u32
        // promotion keeps that at zero instead of panicking.
        let s2 = if bb + 8 > bytes * 8 {
            (bits + 8 - s1) % 8
        } else {
            8 - s1
        };
        let b2 = (b1 + 1) % bytes;
        *out = (((src[b1] as u32) << s1) | ((src[b2] as u32) >> s2)) as u8;
    }
    dst
}

#[cfg(test)]
mod tests {
    use super::n_fold;

    /// Heimdal `lib/krb5/n-fold-test.c`, verbatim: the second column is the
    /// output length in **octets** (`_krb5_n_fold(str, len, key, size)`,
    /// where `size` is `t->n`).
    const HEIMDAL: &[(&str, usize, &str)] = &[
        ("012345", 8, "be072631276b1955"),
        (
            "basch",
            24,
            "1aab6b42964b98b21f8cde2d2448ba3455d7862c9731643f",
        ),
        (
            "eichin",
            24,
            "65696368696e4b732b4b1b43da1a5b995a58d2c6d0d2dcca",
        ),
        (
            "sommerfeld",
            24,
            "2f7a98557c6ee4abadf4e71192dd442bd4ff5325a5def75c",
        ),
        (
            "MASSACHVSETTS INSTITVTE OF TECHNOLOGY",
            24,
            "db3b0d8f0b061e603282b308a50841229ad798fab9540c1b",
        ),
        (
            "assar@NADA.KTH.SE",
            24,
            "5c06c34d2c8905be7a51836cd6f81c4b7a9349165ab3faa9",
        ),
        (
            "testKRBTEST.MIT.EDUtestkey",
            24,
            "502cf82978e5fb1a2906bd22289156c006a0dcf5b6c2da6c",
        ),
        ("password", 7, "78a07b6caf85fa"),
        ("Rough Consensus, and Running Code", 8, "bb6ed30870b7f0e0"),
        ("password", 21, "59e4a8ca7c0385c3c37b3f6d2000247cb6e6bd5b3e"),
        (
            "MASSACHVSETTS INSTITVTE OF TECHNOLOGY",
            24,
            "db3b0d8f0b061e603282b308a50841229ad798fab9540c1b",
        ),
        // RFC 3962 §A.2, the AES string-to-key constant.
        ("kerberos", 8, "6b65726265726f73"),
    ];

    #[test]
    fn heimdal_vectors() {
        for (input, outbits, want) in HEIMDAL {
            let got = n_fold(input.as_bytes(), outbits * 8);
            assert_eq!(
                hex::encode(&got),
                *want,
                "n-fold({input:?}, {outbits} octets)"
            );
        }
    }

    #[test]
    fn folding_to_the_input_length_is_the_identity() {
        assert_eq!(n_fold(b"0123456789abcdef", 128), b"0123456789abcdef");
        assert_eq!(n_fold(b"01234567", 64), b"01234567");
    }
}
