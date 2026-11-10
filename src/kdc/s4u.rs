//! S4U2Self (MS-SFU §3.1): a service asking for a ticket in somebody else's name.
//!
//! A service that receives a request over a protocol with no Kerberos of its own (HTTP, for
//! one) still has to hand its backend a name it can check. "Protocol transition" is that:
//! the service asks this KDC for a ticket to *itself*, in the user's name, without the user's
//! password, and the KDC decides whether the service may do that at all.
//!
//! The mechanism is two `PA-DATA`s carrying the same claim, because the two specifications
//! disagree about where the checksum goes:
//!
//! * `PA-FOR-USER` (129, MS-SFU §2.2.1) — `{ name, realm, cksum, auth }`, where the checksum
//!   is HMAC-MD5 over a byte string that is *not* DER: the name type little-endian, then the
//!   components, then the realm, then the literal `Kerberos`, keyed with the `TGT`'s session
//!   key whatever its enctype. This is Heimdal's `_krb5_s4u2self_to_checksumdata` and MIT's
//!   `krb5_get_credentials_for_user`, byte for byte.
//! * `PA-S4U-X509-USER` (130, MS-SFU §2.2.2) — the same claim checksummed with the
//!   authenticator's **subkey** at usage 26, and answered by the KDC with a checksum at
//!   usage 27. This is what MIT's client actually verifies, and a reply without it makes that
//!   client refuse a correct ticket as modified.
//!
//! Both are checked when both arrive. They are one claim, and a KDC that verified only the one
//! it preferred would accept a request whose other half says something else.
//!
//! What is *not* here: S4U2Proxy. That is `super::tgs_exchange`, because it turns a ticket
//! into another ticket and needs the evidence ticket decrypted with the delegating service's
//! own key.

use crate::crypto::Key;
use crate::der::{self, Fields, Reader};
use crate::error::{Error, Result, codes};
use crate::name::Principal;

/// `PA-FOR-USER`, MS-SFU §2.2.1.
pub const PA_FOR_USER: i32 = 129;
/// `PA-S4U-X509-USER`, MS-SFU §2.2.2.
pub const PA_S4U_X509_USER: i32 = 130;
/// `KRB5_KEYUSAGE_APP_DATA_CKSUM`, which PA-FOR-USER's checksum is keyed with.
const KU_APP_DATA_CKSUM: u32 = 17;
/// `KERB_CHECKSUM_HMAC_MD5`, the only checksum MS-SFU allows for PA-FOR-USER.
const CKSUMTYPE_HMAC_MD5: i64 = -138;
/// `S4UUserID` option: the KDC's reply checksum uses `KU_S4U_X509_USER_REPLY`.
const S4U_OPTS_USE_REPLY_KEY_USAGE: u32 = 0x2000_0000;
/// `KU_S4U_X509_USER_REQUEST`: the client's checksum over `S4UUserID`.
const KU_S4U_X509_USER_REQUEST: u32 = 26;
/// `KU_S4U_X509_USER_REPLY`: the KDC's, when the client asked for it.
const KU_S4U_X509_USER_REPLY: u32 = 27;

/// `PA-FOR-USER ::= SEQUENCE { name [0], realm [1], cksum [2], auth [3] }`.
#[derive(Clone, Debug)]
pub struct ForUser {
    /// The user the service wants to act for.
    pub user: Principal,
    /// The `auth` string. MS-SFU calls it "Kerberos"; it is part of the checksummed bytes, so
    /// it is kept as it arrived rather than assumed.
    pub auth: String,
    /// The checksum, `K1 || HMAC-MD5`.
    pub checksum: Vec<u8>,
}

impl ForUser {
    /// Decodes `PA-FOR-USER`'s value.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        let seq = r.expect_in("PA-FOR-USER", der::SEQUENCE)?;
        let f = Fields::parse("PA-FOR-USER", seq)?;
        let realm = f.string(1, "PA-FOR-USER")?;
        let user = Principal::decode_field(&f, 0, "PA-FOR-USER", &realm)?;
        let auth = f.string(3, "PA-FOR-USER")?;
        let mut c = Reader::new(f.bytes(2, "PA-FOR-USER")?);
        let cseq = c.expect_in("Checksum", der::SEQUENCE)?;
        let cf = Fields::parse("Checksum", cseq)?;
        let ty = cf.int(0, "Checksum")?;
        if ty != CKSUMTYPE_HMAC_MD5 {
            return Err(Error::Protocol(format!(
                "PA-FOR-USER carries checksum type {ty}; MS-SFU §2.2.1 says \
                 KERB_CHECKSUM_HMAC_MD5 ({CKSUMTYPE_HMAC_MD5}) and nothing else, and a KDC \
                 that accepted another type would accept one it cannot key"
            )));
        }
        Ok(ForUser {
            user,
            auth,
            checksum: cf.octets(1, "Checksum")?.to_vec(),
        })
    }

    /// The byte string the checksum covers.
    ///
    /// Not DER: `int32` name type little-endian, the components with no separators or lengths,
    /// the realm, then `auth`. Heimdal's `_krb5_s4u2self_to_checksumdata` writes exactly this,
    /// and MIT's client does the same, so a KDC that DER-encoded the structure would verify
    /// nothing.
    pub fn checksummed(&self) -> Vec<u8> {
        let mut data = (self.user.name_type as u32).to_le_bytes().to_vec();
        for c in &self.user.components {
            data.extend_from_slice(c.as_bytes());
        }
        data.extend_from_slice(self.user.realm.as_bytes());
        data.extend_from_slice(self.auth.as_bytes());
        data
    }

    /// Verifies the checksum against the `TGT`'s session key.
    ///
    /// The key is used as raw bytes whatever its enctype: MS-SFU is explicit that this
    /// checksum is HMAC-MD5 "with the TGT session key", which is why an AES realm still uses
    /// MD5 here.
    pub fn verify(&self, tgt_session_key: &Key) -> Result<()> {
        let expected = hmac_md5_checksum(
            tgt_session_key.bytes(),
            KU_APP_DATA_CKSUM,
            &self.checksummed(),
        );
        if !constant_time_eq(&expected, &self.checksum) {
            return Err(Error::Kdc {
                code: codes::KRB_AP_ERR_BAD_INTEGRITY,
                text: "PA-FOR-USER: the checksum does not verify under the TGT's session key; \
                       the service is not asking about a user it holds a ticket for"
                    .into(),
            });
        }
        Ok(())
    }
}

/// `PA-S4U-X509-USER ::= SEQUENCE { user-id [0] S4UUserID, checksum [1] Checksum }`.
///
/// Named for the certificate it historically carried; in the request it is the modern half of
/// an S4U2Self claim, and the one MIT's client checks in the reply.
#[derive(Clone, Debug)]
pub struct X509User {
    /// The DER of `S4UUserID` as it arrived. The reply's checksum covers these exact octets,
    /// so they are kept rather than re-encoded: a re-encoding that differs by a single tag
    /// would produce a checksum the client cannot verify.
    pub id_der: Vec<u8>,
    /// `nonce [0]`, echoed in the reply.
    pub nonce: u32,
    /// `cname [1]`, when present.
    pub cname: Option<Principal>,
    /// `crealm [2]`.
    pub crealm: String,
    /// Whether the reply's checksum uses `KU_S4U_X509_USER_REPLY` (`options [4]`).
    pub use_reply_usage: bool,
    /// The checksum over `id_der`, keyed with the authenticator's subkey.
    pub checksum: Vec<u8>,
}

impl X509User {
    /// Decodes `PA-S4U-X509-USER`'s value.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        let seq = r.expect_in("PA-S4U-X509-USER", der::SEQUENCE)?;
        let f = Fields::parse("PA-S4U-X509-USER", seq)?;
        let id_der = f.bytes(0, "PA-S4U-X509-USER")?.to_vec();

        let mut ir = Reader::new(&id_der);
        let id = ir.expect_in("S4UUserID", der::SEQUENCE)?;
        let uf = Fields::parse("S4UUserID", id)?;
        let nonce = uf.u32(0, "S4UUserID")?;
        let crealm = uf.string(2, "S4UUserID")?;
        let cname = match uf.opt_bytes(1) {
            None => None,
            Some(_) => Some(Principal::decode_field(&uf, 1, "S4UUserID", &crealm)?),
        };
        let use_reply_usage = uf
            .opt_flags32(4, "S4UUserID")?
            .is_some_and(|o| o & S4U_OPTS_USE_REPLY_KEY_USAGE != 0);

        let mut cr = Reader::new(f.bytes(1, "PA-S4U-X509-USER")?);
        let cseq = cr.expect_in("Checksum", der::SEQUENCE)?;
        let cf = Fields::parse("Checksum", cseq)?;
        Ok(X509User {
            id_der,
            nonce,
            cname,
            crealm,
            use_reply_usage,
            checksum: cf.octets(1, "Checksum")?.to_vec(),
        })
    }

    /// The user this request names, if it names one.
    pub fn user(&self) -> Option<&Principal> {
        self.cname.as_ref()
    }

    /// Verifies the checksum against the authenticator's subkey.
    ///
    /// The subkey, not the TGT's session key: the client proves it took part in *this*
    /// exchange, not merely that it holds the ticket — which is what makes the checksum
    /// unreplayable by anyone who saw an older request.
    pub fn verify(&self, cipher: &dyn crate::crypto::Cipher, subkey: &Key) -> Result<()> {
        cipher
            .verify_checksum(
                subkey,
                KU_S4U_X509_USER_REQUEST,
                &self.id_der,
                &self.checksum,
            )
            .map_err(|e| Error::Kdc {
                code: codes::KRB_AP_ERR_BAD_INTEGRITY,
                text: format!(
                    "PA-S4U-X509-USER: the checksum does not verify under the authenticator's \
                     subkey: {e}"
                ),
            })
    }

    /// The reply's `PA-S4U-X509-USER`: the same `S4UUserID`, checksummed the other way.
    ///
    /// MS-SFU §3.1.5.2: the KDC signs the user id it actually issued a ticket for, so a client
    /// can tell a KDC that canonicalised the name from a relay that substituted it.
    pub fn reply(&self, cipher: &dyn crate::crypto::Cipher, subkey: &Key) -> Result<Vec<u8>> {
        let usage = if self.use_reply_usage {
            KU_S4U_X509_USER_REPLY
        } else {
            KU_S4U_X509_USER_REQUEST
        };
        let sum = cipher.checksum(subkey, usage, &self.id_der)?;
        let checksum = der::seq(&[
            der::field(0, der::int(subkey.enctype().checksum_type() as i64)),
            der::field(1, der::octets(&sum)),
        ]);
        Ok(der::seq(&[
            der::field(0, self.id_der.clone()),
            der::field(1, checksum),
        ]))
    }
}

/// `KERB_CHECKSUM_HMAC_MD5` over `usage || data`, with the signature key.
///
/// RFC 4757 §7.1: the key is first run through HMAC-MD5 with `"signaturekey\0"`, then the
/// checksum is `HMAC-MD5(ksign, LE32(usage) || MD5(data))`. Not RFC 3961's checksum — this is
/// the RC4-HMAC-era construction, applied here to a key of any enctype because that is what
/// MS-SFU prescribes.
pub fn hmac_md5_checksum(key: &[u8], usage: u32, data: &[u8]) -> [u8; 16] {
    let ksign = hmac_md5(key, b"signaturekey\0");
    let mut m = usage.to_le_bytes().to_vec();
    m.extend_from_slice(&md5(data));
    hmac_md5(&ksign, &m)
}

fn hmac_md5(key: &[u8], data: &[u8]) -> [u8; 16] {
    use hmac::{Hmac, KeyInit, Mac};
    use md5::Md5;
    let mut mac = Hmac::<Md5>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

fn md5(data: &[u8]) -> [u8; 16] {
    use md5::Digest;
    md5::Md5::digest(data).into()
}

/// Compares two byte strings without leaking where they differ.
///
/// A checksum comparison that returns early tells an attacker how many leading octets were
/// right, one query at a time.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Which key usage the reply checksum takes, given what the client asked for.
///
/// Exported because the smoke test and the exchange must agree about it, and a mismatch is
/// invisible: the client simply reports a modified reply.
pub fn reply_usage_for(x509: &X509User) -> u32 {
    if x509.use_reply_usage {
        KU_S4U_X509_USER_REPLY
    } else {
        KU_S4U_X509_USER_REQUEST
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{Cipher, Enctype, OwnCipher};

    fn user() -> Principal {
        Principal::parse("alice@EXAMPLE.COM").unwrap()
    }

    fn key() -> Key {
        Key::new(Enctype::Aes256Sha1, vec![0x11; 32]).unwrap()
    }

    #[test]
    fn the_checksummed_bytes_are_the_name_type_components_realm_and_auth() {
        // The layout, pinned literally: a DER encoding here would verify nothing against a
        // real client, and the two implementations that matter write this exact byte string.
        let for_user = ForUser {
            user: user(),
            auth: "Kerberos".into(),
            checksum: Vec::new(),
        };
        let mut expected = 1u32.to_le_bytes().to_vec();
        expected.extend_from_slice(b"alice");
        expected.extend_from_slice(b"EXAMPLE.COM");
        expected.extend_from_slice(b"Kerberos");
        assert_eq!(for_user.checksummed(), expected);
    }

    #[test]
    fn a_client_checksum_verifies_and_a_tampered_name_does_not() {
        // The client's side, computed the way `krb5`'s does it, and then the same request with
        // one character changed: the second has to fail, or the checksum is decoration.
        let mut for_user = ForUser {
            user: user(),
            auth: "Kerberos".into(),
            checksum: Vec::new(),
        };
        for_user.checksum =
            hmac_md5_checksum(key().bytes(), KU_APP_DATA_CKSUM, &for_user.checksummed()).to_vec();
        for_user
            .verify(&key())
            .expect("the client's checksum verifies");

        for_user.user = Principal::parse("alicf@EXAMPLE.COM").unwrap();
        let err = for_user.verify(&key()).unwrap_err().to_string();
        assert!(err.contains("does not verify"), "{err}");
    }

    #[test]
    fn the_checksum_is_keyed_with_the_tgt_session_key_and_usage_seventeen() {
        // Two ways to be wrong, and both must fail: another key, another usage. A checksum
        // that verified under any usage would be replayable from an unrelated exchange.
        let for_user = ForUser {
            user: user(),
            auth: "Kerberos".into(),
            checksum: hmac_md5_checksum(key().bytes(), KU_APP_DATA_CKSUM, &{
                let probe = ForUser {
                    user: user(),
                    auth: "Kerberos".into(),
                    checksum: Vec::new(),
                };
                probe.checksummed()
            })
            .to_vec(),
        };
        assert!(for_user.verify(&key()).is_ok());
        let other = Key::new(Enctype::Aes256Sha1, vec![0x22; 32]).unwrap();
        assert!(
            for_user.verify(&other).is_err(),
            "another key must not verify"
        );

        let mut wrong_usage = ForUser::decode(&{
            let sum = hmac_md5_checksum(key().bytes(), 18, &for_user.checksummed()).to_vec();
            encode_for_user(&user(), "Kerberos", &sum)
        })
        .unwrap();
        wrong_usage.user = user();
        assert!(
            wrong_usage.verify(&key()).is_err(),
            "the same bytes under usage 18 must not verify"
        );
    }

    #[test]
    fn a_for_user_with_another_checksum_type_is_refused_by_name() {
        let value = encode_for_user(&user(), "Kerberos", &[0u8; 16]);
        let mut patched = value.clone();
        // Flip the checksum type from -138 to 16 (CRC32) in the encoded form and check that the
        // refusal names the type rather than failing somewhere further in.
        let encoded = der::seq(&[
            der::field(0, user().encode_name()),
            der::field(1, der::general_string("EXAMPLE.COM")),
            der::field(
                2,
                der::seq(&[
                    der::field(0, der::int(16)),
                    der::field(1, der::octets(&[0u8; 4])),
                ]),
            ),
            der::field(3, der::general_string("Kerberos")),
        ]);
        patched.resize(encoded.len(), 0);
        let err = ForUser::decode(&encoded).unwrap_err().to_string();
        assert!(err.contains("KERB_CHECKSUM_HMAC_MD5"), "{err}");
    }

    #[test]
    fn the_reply_checksum_uses_the_usage_the_client_asked_for() {
        // `options [4]` bit 0x2000_0000 asks for usage 27; without it the same id is
        // checksummed at usage 26. MIT's client picks the usage from the option and refuses a
        // checksum under the other, so this decision has to be visible.
        let id = der::seq(&[
            der::field(0, der::int(7)),
            der::field(1, user().encode_name()),
            der::field(2, der::general_string("EXAMPLE.COM")),
            der::field(4, der::flags32(S4U_OPTS_USE_REPLY_KEY_USAGE)),
        ]);
        let x509 = X509User {
            id_der: id.clone(),
            nonce: 7,
            cname: Some(user()),
            crealm: "EXAMPLE.COM".into(),
            use_reply_usage: true,
            checksum: Vec::new(),
        };
        assert_eq!(reply_usage_for(&x509), KU_S4U_X509_USER_REPLY);

        let plain = X509User {
            use_reply_usage: false,
            ..x509.clone()
        };
        assert_eq!(reply_usage_for(&plain), KU_S4U_X509_USER_REQUEST);

        // And the two replies differ, which is the property the client checks.
        let cipher = OwnCipher;
        let subkey = Key::new(Enctype::Aes256Sha1, vec![0x33; 32]).unwrap();
        assert_ne!(
            plain.reply(&cipher, &subkey).unwrap(),
            x509.reply(&cipher, &subkey).unwrap()
        );
    }

    #[test]
    fn the_reply_checksum_covers_the_id_exactly_as_it_arrived() {
        // Re-encoding would be the natural way to build this reply and the wrong one: a client
        // verifies over the octets it sent, so any difference in tag or length breaks it.
        let id = der::seq(&[
            der::field(0, der::int(9)),
            der::field(1, user().encode_name()),
            der::field(2, der::general_string("EXAMPLE.COM")),
        ]);
        let x509 = X509User {
            id_der: id.clone(),
            nonce: 9,
            cname: Some(user()),
            crealm: "EXAMPLE.COM".into(),
            use_reply_usage: false,
            checksum: Vec::new(),
        };
        let cipher = OwnCipher;
        let subkey = Key::new(Enctype::Aes256Sha1, vec![0x44; 32]).unwrap();
        let reply = x509.reply(&cipher, &subkey).unwrap();

        let mut r = Reader::new(&reply);
        let seq = r.expect_in("PA-S4U-X509-USER", der::SEQUENCE).unwrap();
        let f = Fields::parse("PA-S4U-X509-USER", seq).unwrap();
        assert_eq!(f.bytes(0, "user-id").unwrap(), id.as_slice());
    }

    fn encode_for_user(user: &Principal, auth: &str, sum: &[u8]) -> Vec<u8> {
        der::seq(&[
            der::field(0, user.encode_name()),
            der::field(1, der::general_string(&user.realm)),
            der::field(
                2,
                der::seq(&[
                    der::field(0, der::int(CKSUMTYPE_HMAC_MD5)),
                    der::field(1, der::octets(sum)),
                ]),
            ),
            der::field(3, der::general_string(auth)),
        ])
    }

    #[test]
    fn the_option_bit_is_read_from_the_encoded_id_not_assumed() {
        // `options [4]` decides the usage of the reply checksum, and the two usages are not
        // interchangeable: MIT's client picks one from the bit and rejects a checksum under the
        // other. A decode that read the bit as "always set" would answer usage 27 to a client
        // asking for 26, and the client would report a modified reply.
        let without = der::seq(&[
            der::field(0, der::int(1)),
            der::field(1, user().encode_name()),
            der::field(2, der::general_string("EXAMPLE.COM")),
        ]);
        let encoded = der::seq(&[
            der::field(0, without),
            der::field(
                1,
                der::seq(&[
                    der::field(0, der::int(Enctype::Aes256Sha1.checksum_type() as i64)),
                    der::field(1, der::octets(&[0u8; 32])),
                ]),
            ),
        ]);
        let decoded = X509User::decode(&encoded).unwrap();
        assert!(!decoded.use_reply_usage, "no bit, no usage 27");
        assert_eq!(reply_usage_for(&decoded), KU_S4U_X509_USER_REQUEST);

        // And with the bit set the same decode flips it, so the bit is what is read.
        let with = der::seq(&[
            der::field(0, der::int(1)),
            der::field(1, user().encode_name()),
            der::field(2, der::general_string("EXAMPLE.COM")),
            der::field(4, der::flags32(S4U_OPTS_USE_REPLY_KEY_USAGE)),
        ]);
        let encoded = der::seq(&[
            der::field(0, with),
            der::field(
                1,
                der::seq(&[
                    der::field(0, der::int(Enctype::Aes256Sha1.checksum_type() as i64)),
                    der::field(1, der::octets(&[0u8; 32])),
                ]),
            ),
        ]);
        assert_eq!(
            reply_usage_for(&X509User::decode(&encoded).unwrap()),
            KU_S4U_X509_USER_REPLY
        );
    }

    #[test]
    fn a_decoded_x509_user_names_its_user() {
        // Heimdal accepts a request carrying only this half; a decoder that answered "nobody"
        // would make such a client unable to use S4U at all.
        let id = der::seq(&[
            der::field(0, der::int(3)),
            der::field(1, user().encode_name()),
            der::field(2, der::general_string("EXAMPLE.COM")),
        ]);
        let encoded = der::seq(&[
            der::field(0, id),
            der::field(
                1,
                der::seq(&[
                    der::field(0, der::int(Enctype::Aes256Sha1.checksum_type() as i64)),
                    der::field(1, der::octets(&[0u8; 32])),
                ]),
            ),
        ]);
        let decoded = X509User::decode(&encoded).unwrap();
        let named = decoded.user().expect("the id names a user");
        assert_eq!(named.components, vec!["alice"]);
        assert_eq!(named.realm, "EXAMPLE.COM");
    }

    #[test]
    fn a_checksum_that_differs_in_two_equal_places_is_not_equal() {
        // The comparison folds with `|`, not `^`. With `^` two identical differences cancel and
        // a tampered checksum reads as intact — the exact failure a constant-time compare exists
        // to prevent, hidden inside the constant-time code itself.
        let a = [0x00, 0x11, 0x22, 0x33];
        let mut b = a;
        b[1] ^= 0x01;
        b[3] ^= 0x01;
        assert!(
            !super::constant_time_eq(&a, &b),
            "two cancellations are still a difference"
        );

        let mut c = a;
        c[2] ^= 0x80;
        assert!(!super::constant_time_eq(&a, &c));
        assert!(super::constant_time_eq(&a, &a));
        assert!(
            !super::constant_time_eq(&a, &a[..2]),
            "a length difference is a difference"
        );
    }

    #[test]
    fn a_checksum_that_does_not_match_the_id_is_refused() {
        // Verifying the X509 half means actually verifying it: a forged id with a checksum of
        // the attacker's own making must not be accepted just because its shape is right.
        let id = der::seq(&[
            der::field(0, der::int(3)),
            der::field(1, user().encode_name()),
            der::field(2, der::general_string("EXAMPLE.COM")),
        ]);
        let subkey = Key::new(Enctype::Aes256Sha1, vec![0x55; 32]).unwrap();
        let cipher = OwnCipher;
        let x509 = X509User {
            id_der: id.clone(),
            nonce: 3,
            cname: Some(user()),
            crealm: "EXAMPLE.COM".into(),
            use_reply_usage: true,
            checksum: cipher.checksum(&subkey, 26, &id).unwrap(),
        };
        x509.verify(&cipher, &subkey)
            .expect("the honest checksum verifies");

        // The same checksum over a different id: the bytes the client signed are what count.
        let other_id = der::seq(&[
            der::field(0, der::int(3)),
            der::field(
                1,
                Principal::parse("mallory@EXAMPLE.COM")
                    .map_err(Error::from)
                    .unwrap()
                    .encode_name(),
            ),
            der::field(2, der::general_string("EXAMPLE.COM")),
        ]);
        let forged = X509User {
            id_der: other_id,
            ..x509
        };
        let err = forged.verify(&cipher, &subkey).unwrap_err().to_string();
        assert!(err.contains("does not verify"), "{err}");
    }

    #[test]
    fn an_encoded_for_user_decodes_back_to_the_same_claim() {
        let for_user = ForUser {
            user: user(),
            auth: "Kerberos".into(),
            checksum: vec![0xab; 16],
        };
        let value = encode_for_user(&for_user.user, &for_user.auth, &for_user.checksum);
        let decoded = ForUser::decode(&value).unwrap();
        assert_eq!(decoded.user.components, for_user.user.components);
        assert_eq!(decoded.user.realm, for_user.user.realm);
        assert_eq!(decoded.auth, "Kerberos");
        assert_eq!(decoded.checksum, for_user.checksum);
    }
}
