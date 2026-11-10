//! The key exchange half of PKINIT: finite-field Diffie-Hellman and the KDF that turns
//! the shared secret into a reply key (RFC 4556 §3.2.3.1, RFC 8636 §6–8).
//!
//! Split from the trust decision on purpose. Which certificate may log in whom is a policy
//! question a realm answers in its configuration; how two parties agree on a key is a
//! question the RFC answers once. Mixed into one file, neither can be reviewed or tested
//! against its own statement.
//!
//! Only the MODP groups of RFC 3526 — 14 (2048 bits, what MIT's `pkinit_dh_min_bits`
//! defaults to) and 16 (4096) — because those are what every KDC accepts. Elliptic-curve
//! ECDH against MIT 1.22 and later is a different code path and is not here; a client that
//! offers only curves is refused by name rather than quietly given something else.
//!
//! The KDF matters more than it looks: the reply key carries the AS-REP's `enc-part`, so a
//! KDF that agrees only with itself produces a ticket nobody else can read. MIT's
//! `pkinit_kdf_test.c` vectors are in the tests for exactly that reason.

use num_bigint::BigUint;
use num_traits::Zero;

use super::PkinitError;

/// `dhpublicnumber` (ANSI X9.42), the domain-parameter OID PKINIT uses for finite-field DH.
pub const DH_PUBLIC_NUMBER: &str = "1.2.840.10046.2.1";

/// `id-pkinit-kdf-ah-sha1` (RFC 8636 §8).
pub const KDF_SHA1: &str = "1.3.6.1.5.2.3.6.1";
/// `id-pkinit-kdf-ah-sha256`.
pub const KDF_SHA256: &str = "1.3.6.1.5.2.3.6.2";
/// `id-pkinit-kdf-ah-sha512`.
pub const KDF_SHA512: &str = "1.3.6.1.5.2.3.6.3";

/// The KDFs this KDC offers, strongest first.
///
/// SHA-256 first as MIT does: the order is the KDC's preference, and a client offering
/// several expects the KDC to pick from the top. SHA-1 stays because an older client may
/// offer nothing else — a realm that refuses it stops working with every client built
/// before RFC 8636.
pub const OFFERED: [&str; 3] = [KDF_SHA256, KDF_SHA512, KDF_SHA1];

/// RFC 3526 group 14: 2048-bit MODP.
const MODP_2048: &str = concat!(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74",
    "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437",
    "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED",
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05",
    "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB",
    "9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B",
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718",
    "3995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF",
);

/// RFC 3526 group 16: 4096-bit MODP.
const MODP_4096: &str = concat!(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74",
    "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437",
    "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED",
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05",
    "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB",
    "9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B",
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718",
    "3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33",
    "A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7",
    "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864",
    "D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E2",
    "08E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D7",
    "88719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8",
    "DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2",
    "233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA9",
    "93B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199FFFFFFFFFFFFFFFF",
);

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("a hex constant"))
        .collect()
}

/// A MODP group: the safe prime `p` and generator 2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Group {
    bits: u32,
}

impl Group {
    /// The smallest group of at least `min_bits`: 4096 above 2048, else 2048.
    ///
    /// A client asking for more than group 16 gets group 16 — a KDC cannot invent a larger
    /// safe prime, and answering with a smaller one than it was asked for would be a
    /// downgrade the client never sees.
    pub fn at_least(min_bits: u32) -> Self {
        Self {
            bits: if min_bits > 2048 { 4096 } else { 2048 },
        }
    }

    /// The group whose prime these domain parameters name, if it is one of the two.
    pub fn from_domain_parameters(params: &[u8]) -> Result<Self, PkinitError> {
        let (p, g) = parse_domain_parameters(params)?;
        for bits in [2048u32, 4096] {
            let group = Self::at_least(bits);
            if group.p() == p && g == BigUint::from(2u32) {
                return Ok(group);
            }
        }
        Err(PkinitError::Unsupported(format!(
            "a {}-bit DH group that is not RFC 3526 group 14 or 16",
            p.bits()
        )))
    }

    /// The size of the group in bits.
    pub fn bits(&self) -> u32 {
        self.bits
    }

    /// The prime.
    pub fn p(&self) -> BigUint {
        BigUint::from_bytes_be(&unhex(if self.bits > 2048 {
            MODP_4096
        } else {
            MODP_2048
        }))
    }

    /// The generator, always 2 for these groups.
    pub fn g(&self) -> BigUint {
        BigUint::from(2u32)
    }

    /// `q = (p - 1) / 2`, the order of the subgroup generator 2 generates.
    ///
    /// Needed because a private exponent must be in `[1, q)` and a public value must be
    /// checked against the subgroup: a peer can send a value of small order and read the
    /// shared secret off it.
    pub fn q(&self) -> BigUint {
        (self.p() - BigUint::from(1u32)) >> 1
    }
}

/// A DH key pair: a private exponent and the public value `g^x mod p`.
#[derive(Debug, Clone)]
pub struct KeyPair {
    group: Group,
    private: BigUint,
    public: BigUint,
}

impl KeyPair {
    /// A fresh key pair in `group`, with `x` drawn from `rng`.
    ///
    /// `x` is 256 bits of randomness: half the size of the 2048-bit group, which is the
    /// same margin MIT uses, and enough that `g^x` is not recoverable by search. Drawing a
    /// full-size exponent is not better (the security is bounded by the subgroup) and
    /// makes the exponentiation slower for every login.
    pub fn generate(group: Group, rng: &dyn Fn(usize) -> Vec<u8>) -> Result<Self, PkinitError> {
        let q = group.q();
        for _ in 0..8 {
            let mut bytes = rng(32);
            if bytes.len() != 32 {
                return Err(PkinitError::Malformed(
                    "the random source returned the wrong number of octets".into(),
                ));
            }
            // Any 256-bit value is below `q` for a 2048-bit group; the reduction is here
            // so the same code is correct if the group size ever changes.
            bytes[0] |= 0x80;
            let mut private = BigUint::from_bytes_be(&bytes) % &q;
            if private.is_zero() {
                continue;
            }
            private += BigUint::from(1u32);
            let public = group.g().modpow(&private, &group.p());
            return Ok(Self {
                group,
                private,
                public,
            });
        }
        Err(PkinitError::Malformed(
            "the random source produced only zeros".into(),
        ))
    }

    /// A key pair from a known exponent, for tests that need a reproducible exchange.
    pub fn from_private(group: Group, private: BigUint) -> Self {
        let public = group.g().modpow(&private, &group.p());
        Self {
            group,
            private,
            public,
        }
    }

    /// The public value, big-endian, without leading zeros.
    pub fn public_bytes(&self) -> Vec<u8> {
        self.public.to_bytes_be()
    }

    /// The group this pair was made in.
    pub fn group(&self) -> Group {
        self.group
    }

    /// The shared secret with `peer`, as `Z` in RFC 4556 §3.2.3.1.
    ///
    /// The peer's value is checked to be in `[2, p-2]` before use. A value of `0`, `1` or
    /// `p-1` has small order and makes `Z` one of three constants: a client that accepted
    /// them would agree on a "shared secret" the attacker also knows. RFC 4556 §3.2.3.1
    /// requires this check and it is the only place where a bad value turns into a
    /// recoverable key.
    pub fn agree(&self, peer: &[u8]) -> Result<Vec<u8>, PkinitError> {
        let p = self.group.p();
        let value = BigUint::from_bytes_be(peer);
        if value < BigUint::from(2u32) || value > &p - BigUint::from(2u32) {
            return Err(PkinitError::BadSignature(
                "the peer's DH public value is outside the group".into(),
            ));
        }
        let z = value.modpow(&self.private, &p);
        if z.is_zero() {
            return Err(PkinitError::BadSignature(
                "the DH agreement produced zero".into(),
            ));
        }
        // Big-endian without leading zeros: RFC 4556 hashes `Z` as the integer's
        // representation, and a padded form would give a different key on the other side.
        Ok(z.to_bytes_be())
    }
}

/// The prime and generator of a `DomainParameters` or `DHParameter` blob.
///
/// Two encodings reach a KDC: X9.42 `DomainParameters ::= SEQUENCE { p, g, q, ... }` and
/// PKCS#3 `DHParameter ::= SEQUENCE { p, g, privateValueLength OPTIONAL }`. They agree in
/// their first two fields, so the reader takes those and ignores the rest — but it insists
/// they are INTEGERS, because a client that sent something else is not describing a group.
fn parse_domain_parameters(params: &[u8]) -> Result<(BigUint, BigUint), PkinitError> {
    let mut r = crate::der::Reader::new(params);
    let seq = r
        .next_tlv("DomainParameters")
        .map_err(|e| PkinitError::Malformed(e.to_string()))?;
    if seq.tag != crate::der::SEQUENCE {
        return Err(PkinitError::Malformed(
            "DH domain parameters are not a SEQUENCE".into(),
        ));
    }
    let mut inner = crate::der::Reader::new(seq.content);
    let p = integer(&mut inner, "p")?;
    let g = integer(&mut inner, "g")?;
    Ok((p, g))
}

fn integer(r: &mut crate::der::Reader<'_>, what: &str) -> Result<BigUint, PkinitError> {
    let tlv = r
        .next_tlv("DomainParameters")
        .map_err(|e| PkinitError::Malformed(format!("{what}: {e}")))?;
    if tlv.tag != crate::der::INTEGER {
        return Err(PkinitError::Malformed(format!(
            "DH domain parameter {what} is not an INTEGER"
        )));
    }
    let bytes = match tlv.content {
        // A leading zero is the sign octet of a positive number, not part of the value.
        [0x00, rest @ ..] => rest,
        rest => rest,
    };
    Ok(BigUint::from_bytes_be(bytes))
}

/// `KRB5PrincipalName ::= SEQUENCE { realm [0] Realm, principalName [1] PrincipalName }`
/// (RFC 4556 §3.2.2), the form the KDF binds into its context.
pub fn krb5_principal_name(p: &crate::name::Principal) -> Vec<u8> {
    crate::der::seq(&[
        crate::der::field(0, crate::der::general_string(&p.realm)),
        crate::der::field(1, p.encode_name()),
    ])
}

/// The random-to-key length of an enctype: how many octets the KDF must produce.
///
/// Every enctype this KDC issues is AES, so this is total and returns a length rather than
/// an `Option` — a realm that adds a non-AES enctype gets a compile error here instead of a
/// login that fails at the last step.
pub fn key_len(enctype: crate::crypto::Enctype) -> usize {
    use crate::crypto::Enctype::*;
    match enctype {
        Aes128Sha1 | Aes128Sha256 => 16,
        Aes256Sha1 | Aes256Sha384 => 32,
    }
}

/// RFC 8636 §6 `OtherInfo`, the context the KDF binds in.
///
/// Binding the two principals, the enctype and both messages is what stops a shared secret
/// from being replayed into a different exchange: the same `Z` under a different client or
/// a different AS-REQ gives a different key, so an attacker who captured one exchange
/// cannot make its key open another.
#[allow(clippy::too_many_arguments)]
pub fn other_info(
    kdf: &str,
    client: &crate::name::Principal,
    server: &crate::name::Principal,
    enctype: crate::crypto::Enctype,
    as_req: &[u8],
    pk_as_rep: &[u8],
) -> Vec<u8> {
    let supp = crate::der::seq(&[
        crate::der::field(0, crate::der::int(enctype.id() as i64)),
        crate::der::field(1, crate::der::octets(as_req)),
        crate::der::field(2, crate::der::octets(pk_as_rep)),
    ]);
    crate::der::seq(&[
        // `AlgorithmIdentifier ::= SEQUENCE { algorithm OID }` — no parameters, which is
        // what MIT's `pkinit_kdf_test` hashes and therefore what the vectors pin.
        crate::der::seq(&[crate::der::tlv(
            crate::der::OBJECT_IDENTIFIER,
            &encode_oid(kdf),
        )]),
        crate::der::field(0, crate::der::octets(&krb5_principal_name(client))),
        crate::der::field(1, crate::der::octets(&krb5_principal_name(server))),
        crate::der::field(2, crate::der::octets(&supp)),
    ])
}

/// An OID's content octets, the inverse of `der::decode_oid`.
fn encode_oid(text: &str) -> Vec<u8> {
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

/// Sp 800-56A's single-step KDF over the named hash: `H(counter || Z || OtherInfo)`, the
/// counter a 32-bit big-endian integer from 1, concatenated and truncated.
///
/// The counter width is four octets here and **one** in `PRF+`. Two different KDFs from
/// two different documents, and each is pinned by its own published vectors — the FAST
/// work already lost a debugging session to assuming one convention for both.
pub fn sp800_56a(kdf: &str, z: &[u8], other: &[u8], len: usize) -> Option<Vec<u8>> {
    use sha1::Digest;
    fn run<H: Digest>(z: &[u8], info: &[u8], len: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(len + 64);
        let mut counter = 1u32;
        while out.len() < len {
            let mut h = H::new();
            h.update(counter.to_be_bytes());
            h.update(z);
            h.update(info);
            out.extend_from_slice(&h.finalize());
            counter += 1;
        }
        out.truncate(len);
        out
    }
    match kdf {
        KDF_SHA1 => Some(run::<sha1::Sha1>(z, other, len)),
        KDF_SHA256 => Some(run::<sha2::Sha256>(z, other, len)),
        KDF_SHA512 => Some(run::<sha2::Sha512>(z, other, len)),
        _ => None,
    }
}

/// RFC 4556 §3.2.3.1 `octetstring2key`: SHA-1 over a one-octet counter **from zero** and
/// `Z`, truncated.
///
/// The fallback for a client that offers no KDF at all — RFC 8636 came later, and a client
/// that predates it only knows this. The counter starts at 0 here and at 1 in SP 800-56A,
/// which is the kind of one-octet difference that a self-consistent implementation never
/// notices.
pub fn octetstring2key(z: &[u8], len: usize) -> Vec<u8> {
    use sha1::Digest;
    let mut out = Vec::with_capacity(len + 20);
    let mut counter = 0u8;
    while out.len() < len {
        let mut h = sha1::Sha1::new();
        h.update([counter]);
        h.update(z);
        out.extend_from_slice(&h.finalize());
        counter = counter.wrapping_add(1);
    }
    out.truncate(len);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Enctype;
    use crate::name::Principal;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn fixed_rng(byte: u8) -> impl Fn(usize) -> Vec<u8> {
        move |n| vec![byte; n]
    }

    #[test]
    fn the_groups_are_the_ones_rfc_3526_names() {
        // The primes are the protocol: a wrong constant gives an exchange that works with
        // itself and with nothing else, and no test below would notice.
        let g14 = Group::at_least(2048);
        assert_eq!(g14.bits(), 2048);
        assert_eq!(g14.p().bits(), 2048);
        assert_eq!(g14.p().to_bytes_be()[..8], hex("FFFFFFFFFFFFFFFF")[..]);
        // 2048 bits is 256 octets, so the tail is the last eight of them.
        assert_eq!(g14.p().to_bytes_be()[248..], hex("FFFFFFFFFFFFFFFF")[..]);

        let g16 = Group::at_least(4096);
        assert_eq!(g16.bits(), 4096);
        assert_eq!(g16.p().bits(), 4096);
        assert_eq!(g16.p().to_bytes_be()[..8], hex("FFFFFFFFFFFFFFFF")[..]);

        // `q = (p-1)/2` is one bit shorter and `p = 2q + 1`, the definition of a safe prime.
        assert_eq!(
            g14.p(),
            &g14.q() * BigUint::from(2u32) + BigUint::from(1u32)
        );
    }

    #[test]
    fn a_larger_request_gets_the_larger_group_and_a_smaller_one_the_default() {
        assert_eq!(Group::at_least(1024), Group::at_least(2048));
        assert_eq!(Group::at_least(2049).bits(), 4096);
        assert_eq!(Group::at_least(8192).bits(), 4096);
    }

    #[test]
    fn two_parties_agree_on_the_same_secret() {
        let group = Group::at_least(2048);
        let a = KeyPair::generate(group, &fixed_rng(0x11)).unwrap();
        let b = KeyPair::generate(group, &fixed_rng(0x22)).unwrap();
        let z1 = a.agree(&b.public_bytes()).unwrap();
        let z2 = b.agree(&a.public_bytes()).unwrap();
        assert_eq!(z1, z2);
        assert!(!z1.is_empty());
        // And it is not the trivial secret: `g^(xy)` of two non-zero exponents is not 1.
        assert_ne!(z1, vec![1]);
    }

    #[test]
    fn a_public_value_outside_the_group_is_refused() {
        // These are the values a peer would send to force a known shared secret: `0`, `1`,
        // `p-1` and `p` all have small order or none, and `Z` becomes a constant the
        // attacker already knows.
        let group = Group::at_least(2048);
        let a = KeyPair::generate(group, &fixed_rng(0x33)).unwrap();
        let p = group.p();
        for bad in [
            BigUint::from(0u32),
            BigUint::from(1u32),
            &p - BigUint::from(1u32),
            p.clone(),
        ] {
            assert!(
                a.agree(&bad.to_bytes_be()).is_err(),
                "a value of {bad} must be refused"
            );
        }
    }

    #[test]
    fn the_same_group_is_recognised_from_its_domain_parameters() {
        // X9.42 `DomainParameters { p, g, q, ... }`: the first two fields decide the group.
        for bits in [2048u32, 4096] {
            let group = Group::at_least(bits);
            let params = crate::der::seq(&[
                crate::der::int_bytes(&group.p().to_bytes_be()),
                crate::der::int(2),
                crate::der::int_bytes(&group.q().to_bytes_be()),
            ]);
            assert_eq!(
                Group::from_domain_parameters(&params).unwrap().bits(),
                group.bits()
            );
        }
    }

    #[test]
    fn an_unknown_group_is_refused_by_size() {
        // A 512-bit prime is a legal DH group and a broken one; saying so is better than
        // agreeing with it.
        let small = crate::der::seq(&[
            crate::der::int_bytes(&[0x00, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01]),
            crate::der::int(2),
        ]);
        match Group::from_domain_parameters(&small) {
            Err(PkinitError::Unsupported(m)) => {
                assert!(m.contains("group 14 or 16"), "{m}");
                assert!(m.contains("64-bit"), "the size should be reported: {m}");
            }
            other => panic!("expected Unsupported, got {other:?}"),
        }
        // And something that is not a SEQUENCE of INTEGERS is malformed, not unsupported.
        assert!(matches!(
            Group::from_domain_parameters(&[0x30, 0x00]),
            Err(PkinitError::Malformed(_))
        ));
    }

    /// MIT's `pkinit_kdf_test.c`: 256 zero octets as `Z`, `lha@SU.SE` and
    /// `krbtgt/SU.SE@SU.SE`, a ten-octet AS-REQ of 0xAA, nine of 0xBB.
    fn mit_vector(kdf: &str, enctype: Enctype, len: usize) -> Vec<u8> {
        let client = Principal::new(1, ["lha"], "SU.SE");
        let server = Principal::new(1, ["krbtgt", "SU.SE"], "SU.SE");
        let info = other_info(kdf, &client, &server, enctype, &[0xAA; 10], &[0xBB; 9]);
        sp800_56a(kdf, &[0; 256], &info, len).unwrap()
    }

    #[test]
    fn the_kdf_matches_mits_published_vectors() {
        // These decide whether this KDC can talk to anything else. A KDF that agrees only
        // with itself produces a reply key no client can derive, and the client's report
        // is "the reply does not decrypt" — which reads like a crypto bug, not a KDF one.
        assert_eq!(
            mit_vector(KDF_SHA1, Enctype::Aes256Sha1, 32),
            hex("e6ab38c9413e035bb079201ed0b6b73d8d49a814a737c04ee6649614206f73ad")
        );
        assert_eq!(
            mit_vector(KDF_SHA256, Enctype::Aes256Sha1, 32),
            hex("77ef4e48c420ae3fec75109d7981697eed5d295c90c62564f7bfd101fa9bc1d5")
        );
    }

    #[test]
    fn an_unknown_kdf_produces_nothing_rather_than_a_guess() {
        assert!(sp800_56a("1.2.3", &[0; 8], &[], 16).is_none());
    }

    #[test]
    fn the_legacy_kdf_counts_from_zero() {
        // One octet counters, from 0 — RFC 4556 predates RFC 8636 and its counter does not
        // start where SP 800-56A's does.
        use sha1::Digest;
        let z = b"shared secret";
        let key = octetstring2key(z, 32);
        let h0 = sha1::Sha1::new()
            .chain_update([0u8])
            .chain_update(z)
            .finalize();
        let h1 = sha1::Sha1::new()
            .chain_update([1u8])
            .chain_update(z)
            .finalize();
        assert_eq!(&key[..20], h0.as_slice());
        assert_eq!(&key[20..], &h1[..12]);
    }

    #[test]
    fn the_other_info_binds_the_principals_and_the_messages() {
        // Two differences that must change the derived key: a different client and a
        // different AS-REQ. Without them a captured secret would open another exchange.
        let client = Principal::new(1, ["alice"], "EXAMPLE.COM");
        let other_client = Principal::new(1, ["bob"], "EXAMPLE.COM");
        let server = Principal::krbtgt("EXAMPLE.COM");
        let base = other_info(
            KDF_SHA256,
            &client,
            &server,
            Enctype::Aes256Sha1,
            b"req",
            b"rep",
        );
        assert_ne!(
            base,
            other_info(
                KDF_SHA256,
                &other_client,
                &server,
                Enctype::Aes256Sha1,
                b"req",
                b"rep"
            )
        );
        assert_ne!(
            base,
            other_info(
                KDF_SHA256,
                &client,
                &server,
                Enctype::Aes256Sha1,
                b"other",
                b"rep"
            )
        );
        assert_ne!(
            base,
            other_info(
                KDF_SHA256,
                &client,
                &server,
                Enctype::Aes128Sha1,
                b"req",
                b"rep"
            )
        );
        // And the same inputs give the same context, or the two sides could never agree.
        assert_eq!(
            base,
            other_info(
                KDF_SHA256,
                &client,
                &server,
                Enctype::Aes256Sha1,
                b"req",
                b"rep"
            )
        );
    }

    #[test]
    fn key_len_covers_the_enctypes_this_kdc_issues() {
        assert_eq!(key_len(Enctype::Aes128Sha1), 16);
        assert_eq!(key_len(Enctype::Aes256Sha1), 32);
        assert_eq!(key_len(Enctype::Aes128Sha256), 16);
        assert_eq!(key_len(Enctype::Aes256Sha384), 32);
    }
}
