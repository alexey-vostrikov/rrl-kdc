//! The two messages RFC 3244 needs and RFC 4120 also uses elsewhere: `AP-REP`
//! and `KRB-PRIV`.
//!
//! `AP-REP` is the server's answer to an `AP-REQ`: it proves the server could
//! read the authenticator, because its `EncAPRepPart` is sealed in the ticket's
//! session key and echoes the client's clock. `KRB-PRIV` is a sealed blob with a
//! sequence number; the change-password protocol carries its request and result
//! in one.
//!
//! Both are `[APPLICATION n]`-tagged and EXPLICIT like everything else in RFC
//! 4120, and both encrypt with a usage that is not shared with any other message
//! (12 for `EncAPRepPart`, 13 for `EncKrbPrivPart`), so a reply read with the
//! wrong usage fails its integrity check rather than decrypting into nonsense.

use crate::crypto::{Key, usage};
use crate::der::{self, Fields, Reader};
use crate::error::{Error, Result};
use crate::name::Principal;

use crate::address::HostAddress;

use super::{EncryptedData, PVNO, as_time, decode_key, encode_key};

/// `AP-REP`, `[APPLICATION 15]`.
pub const AP_REP: u8 = 15;
/// `EncAPRepPart`, `[APPLICATION 27]`.
pub const ENC_AP_REP_PART: u8 = 27;
/// `KRB-PRIV`, `[APPLICATION 21]`.
pub const KRB_PRIV: u8 = 21;
/// `EncKrbPrivPart`, `[APPLICATION 28]`.
pub const ENC_KRB_PRIV_PART: u8 = 28;

/// `EncAPRepPart ::= [APPLICATION 27] SEQUENCE { ctime, cusec, subkey, seq }`.
#[derive(Clone, Debug)]
pub struct EncApRepPart {
    /// The client's `ctime`, echoed.
    pub ctime: i64,
    /// The client's `cusec`, echoed.
    pub cusec: u32,
    /// The subkey the server will use, when it offers one.
    pub subkey: Option<Key>,
    /// The sequence number, echoed.
    pub seq_number: Option<u32>,
}

impl EncApRepPart {
    /// The DER of the whole `[APPLICATION 27]` part, ready to encrypt.
    pub fn encode(&self) -> Vec<u8> {
        let mut parts = vec![
            der::field(0, der::time(self.ctime)),
            der::field(1, der::int(self.cusec as i64)),
        ];
        if let Some(subkey) = &self.subkey {
            parts.push(der::field(2, encode_key(subkey)));
        }
        if let Some(seq) = self.seq_number {
            parts.push(der::field(3, der::int(seq as i64)));
        }
        der::cons(der::app(ENC_AP_REP_PART), &[der::seq(&parts)])
    }

    /// Decodes a whole `[APPLICATION 27]` part — what a client does, and what the
    /// tests do to check the reply the KDC produced.
    pub fn decode(data: &[u8]) -> Result<Self> {
        let f = Fields::parse_app("EncAPRepPart", ENC_AP_REP_PART, data)?;
        Ok(EncApRepPart {
            ctime: as_time("EncAPRepPart.ctime", f.bytes(0, "EncAPRepPart")?)?,
            cusec: f.u32(1, "EncAPRepPart")?,
            subkey: match f.opt_bytes(2) {
                None => None,
                Some(_) => {
                    let mut r = Reader::new(f.bytes(2, "EncAPRepPart")?);
                    Some(decode_key(r.expect_in("EncAPRepPart", der::SEQUENCE)?)?)
                }
            },
            seq_number: f.opt_int(3, "EncAPRepPart")?.map(|v| v as u32),
        })
    }
}

/// `AP-REP ::= [APPLICATION 15] SEQUENCE { pvno, msg-type, enc-part }`.
#[derive(Clone, Debug)]
pub struct ApRep {
    /// The sealed `EncAPRepPart`.
    pub enc_part: EncryptedData,
}

impl ApRep {
    /// Seals `part` in `session_key` with usage 12 and renders the message.
    pub fn seal(
        cipher: &dyn crate::crypto::Cipher,
        session_key: &Key,
        part: &EncApRepPart,
    ) -> Result<Vec<u8>> {
        let enc = EncryptedData::seal(
            cipher,
            session_key,
            usage::AP_REP_ENCPART,
            None,
            &part.encode(),
        )?;
        Ok(der::cons(
            der::app(AP_REP),
            &[der::seq(&[
                der::field(0, der::int(PVNO)),
                der::field(1, der::int(AP_REP as i64)),
                der::field(2, enc.encode()),
            ])],
        ))
    }

    /// Decodes a whole `[APPLICATION 15]` message.
    pub fn decode(data: &[u8]) -> Result<Self> {
        let f = Fields::parse_app("AP-REP", AP_REP, data)?;
        let msg_type = f.int(1, "AP-REP")?;
        if msg_type != AP_REP as i64 {
            return Err(Error::Protocol(format!(
                "AP-REP msg-type is {msg_type}, expected {AP_REP}"
            )));
        }
        let mut r = Reader::new(f.bytes(2, "AP-REP")?);
        Ok(ApRep {
            enc_part: EncryptedData::decode_content(
                "AP-REP.enc-part",
                r.expect_in("AP-REP", der::SEQUENCE)?,
            )?,
        })
    }
}

/// `EncKrbPrivPart ::= [APPLICATION 28] SEQUENCE { user-data, timestamp, usec,
/// seq-number, s-address, r-address }`.
#[derive(Clone, Debug)]
pub struct EncKrbPrivPart {
    /// `user-data`: whatever the protocol carries, sealed.
    pub user_data: Vec<u8>,
    /// `timestamp`, when set.
    pub timestamp: Option<i64>,
    /// `usec`, when set.
    pub usec: Option<u32>,
    /// `seq-number`, when set.
    pub seq_number: Option<u32>,
    /// `s-address`: where the sender says it is. A server that checked this
    /// would be checking a claim, not a fact; it is echoed for the reply.
    pub s_address: Option<HostAddress>,
}

impl EncKrbPrivPart {
    /// The DER of the whole `[APPLICATION 28]` part.
    pub fn encode(&self) -> Vec<u8> {
        let mut parts = vec![der::field(0, der::octets(&self.user_data))];
        if let Some(t) = self.timestamp {
            parts.push(der::field(1, der::time(t)));
        }
        if let Some(u) = self.usec {
            parts.push(der::field(2, der::int(u as i64)));
        }
        if let Some(seq) = self.seq_number {
            parts.push(der::field(3, der::int(seq as i64)));
        }
        if let Some(addr) = &self.s_address {
            parts.push(der::field(4, addr.encode()));
        }
        der::cons(der::app(ENC_KRB_PRIV_PART), &[der::seq(&parts)])
    }

    /// Decodes a whole `[APPLICATION 28]` part.
    pub fn decode(data: &[u8]) -> Result<Self> {
        let f = Fields::parse_app("EncKrbPrivPart", ENC_KRB_PRIV_PART, data)?;
        Ok(EncKrbPrivPart {
            user_data: f.octets(0, "EncKrbPrivPart")?.to_vec(),
            timestamp: f
                .opt_bytes(1)
                .map(|_| {
                    as_time(
                        "EncKrbPrivPart.timestamp",
                        f.bytes(1, "EncKrbPrivPart").unwrap(),
                    )
                })
                .transpose()?,
            usec: f.opt_int(2, "EncKrbPrivPart")?.map(|v| v as u32),
            seq_number: f.opt_int(3, "EncKrbPrivPart")?.map(|v| v as u32),
            s_address: match f.opt_bytes(4) {
                None => None,
                Some(_) => {
                    let mut r = Reader::new(f.bytes(4, "EncKrbPrivPart")?);
                    Some(HostAddress::decode_content(
                        r.expect_in("EncKrbPrivPart", der::SEQUENCE)?,
                    )?)
                }
            },
        })
    }
}

/// Seals `data` in `key` with usage 13 and renders a `KRB-PRIV` for `seq`.
pub fn seal_krb_priv(
    cipher: &dyn crate::crypto::Cipher,
    key: &Key,
    data: &[u8],
    seq: Option<u32>,
    timestamp: i64,
) -> Result<Vec<u8>> {
    let part = EncKrbPrivPart {
        user_data: data.to_vec(),
        timestamp: Some(timestamp),
        usec: Some(0),
        seq_number: seq,
        s_address: None,
    };
    let enc = EncryptedData::seal(cipher, key, usage::KRB_PRIV_ENCPART, None, &part.encode())?;
    Ok(der::cons(
        der::app(KRB_PRIV),
        &[der::seq(&[
            der::field(0, der::int(PVNO)),
            der::field(1, der::int(KRB_PRIV as i64)),
            der::field(3, enc.encode()),
        ])],
    ))
}

/// Opens a `KRB-PRIV` in `key` and returns its `user-data` and sequence number.
pub fn open_krb_priv(
    cipher: &dyn crate::crypto::Cipher,
    key: &Key,
    message: &[u8],
) -> Result<(Vec<u8>, Option<u32>)> {
    let f = Fields::parse_app("KRB-PRIV", KRB_PRIV, message)?;
    let msg_type = f.int(1, "KRB-PRIV")?;
    if msg_type != KRB_PRIV as i64 {
        return Err(Error::Protocol(format!(
            "KRB-PRIV msg-type is {msg_type}, expected {KRB_PRIV}"
        )));
    }
    let mut r = Reader::new(f.bytes(3, "KRB-PRIV")?);
    let enc = EncryptedData::decode_content(
        "KRB-PRIV.enc-part",
        r.expect_in("KRB-PRIV", der::SEQUENCE)?,
    )?;
    let plain = cipher
        .decrypt(key, usage::KRB_PRIV_ENCPART, &enc.cipher)
        .map_err(|_| {
            Error::Protocol(
                "the KRB-PRIV does not decrypt in the subkey the authenticator carried".into(),
            )
        })?;
    let part = EncKrbPrivPart::decode(&plain)?;
    Ok((part.user_data, part.seq_number))
}

/// `ChangePasswdData ::= SEQUENCE { newpasswd [0], targname [1] OPTIONAL,
/// targrealm [2] OPTIONAL }` (RFC 3244 §2.1).
#[derive(Clone, Debug)]
pub struct ChangePasswdData {
    /// The new password.
    pub new_password: Vec<u8>,
    /// The account it is for; absent means "the client of the ticket".
    pub target: Option<Principal>,
}

impl ChangePasswdData {
    /// The DER of the `ChangePasswdData` SEQUENCE.
    pub fn encode(&self) -> Vec<u8> {
        let mut parts = vec![der::field(0, der::octets(&self.new_password))];
        if let Some(target) = &self.target {
            parts.push(der::field(1, target.encode_name()));
            parts.push(der::field(2, der::general_string(&target.realm)));
        }
        der::seq(&parts)
    }

    /// Decodes a `ChangePasswdData` SEQUENCE.
    ///
    /// The realm of the target comes from `[2]`, and the name from `[1]`; a
    /// name without a realm is refused rather than given one, because setting a
    /// password for the wrong principal is not a failure anybody can undo.
    pub fn decode(data: &[u8]) -> Result<Self> {
        let mut r = Reader::new(data);
        let f = Fields::parse(
            "ChangePasswdData",
            r.expect_in("ChangePasswdData", der::SEQUENCE)?,
        )?;
        let new_password = f.octets(0, "ChangePasswdData")?.to_vec();
        let target = match (f.opt_bytes(1), f.opt_bytes(2)) {
            (None, _) => None,
            (Some(_), None) => {
                return Err(Error::Protocol(
                    "ChangePasswdData names a target without a realm".into(),
                ));
            }
            (Some(_), Some(_)) => {
                let realm = f.string(2, "ChangePasswdData")?;
                Some(Principal::decode_field(
                    &f,
                    1,
                    "ChangePasswdData.targname",
                    &realm,
                )?)
            }
        };
        Ok(ChangePasswdData {
            new_password,
            target,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{Cipher, Enctype, OwnCipher};

    fn cipher() -> OwnCipher {
        OwnCipher
    }

    #[test]
    fn an_ap_rep_round_trips_and_echoes_the_clock() {
        let c = cipher();
        let session = c.random(Enctype::Aes256Sha1).unwrap();
        let part = EncApRepPart {
            ctime: 1_700_000_000,
            cusec: 42,
            subkey: Some(c.random(Enctype::Aes256Sha1).unwrap()),
            seq_number: Some(7),
        };
        let encoded = ApRep::seal(&c, &session, &part).unwrap();
        let back = ApRep::decode(&encoded).unwrap();
        let plain = c
            .decrypt(&session, usage::AP_REP_ENCPART, &back.enc_part.cipher)
            .unwrap();
        let part_back = EncApRepPart::decode(&plain).unwrap();
        assert_eq!(part_back.ctime, 1_700_000_000);
        assert_eq!(part_back.cusec, 42);
        assert_eq!(part_back.seq_number, Some(7));
        assert_eq!(
            part_back.subkey.unwrap().bytes(),
            part.subkey.as_ref().unwrap().bytes()
        );
    }

    #[test]
    fn a_krb_priv_round_trips_with_its_sequence_number() {
        let c = cipher();
        let key = c.random(Enctype::Aes128Sha1).unwrap();
        let msg = seal_krb_priv(&c, &key, b"a new password", Some(99), 1_700_000_000).unwrap();
        let (data, seq) = open_krb_priv(&c, &key, &msg).unwrap();
        assert_eq!(data, b"a new password");
        assert_eq!(seq, Some(99));
    }

    #[test]
    fn a_krb_priv_in_the_wrong_key_is_refused() {
        let c = cipher();
        let key = c.random(Enctype::Aes128Sha1).unwrap();
        let other = c.random(Enctype::Aes128Sha1).unwrap();
        let msg = seal_krb_priv(&c, &key, b"secret", None, 1_700_000_000).unwrap();
        assert!(open_krb_priv(&c, &other, &msg).is_err());
    }

    #[test]
    fn change_passwd_data_round_trips_with_a_target() {
        let data = ChangePasswdData {
            new_password: b"new secrets".to_vec(),
            target: Some(Principal::parse("bob@R").unwrap()),
        };
        let back = ChangePasswdData::decode(&data.encode()).unwrap();
        assert_eq!(back.new_password, b"new secrets");
        assert_eq!(back.target.unwrap().to_string(), "bob@R");
    }

    #[test]
    fn change_passwd_data_without_a_target_means_the_client() {
        let data = ChangePasswdData {
            new_password: b"pw".to_vec(),
            target: None,
        };
        let back = ChangePasswdData::decode(&data.encode()).unwrap();
        assert!(back.target.is_none());
    }

    #[test]
    fn a_target_without_a_realm_is_refused() {
        // [1] without [2]: the encoder never produces it, so it is built by hand.
        let data = der::seq(&[
            der::field(0, der::octets(b"pw")),
            der::field(1, Principal::parse("bob@R").unwrap().encode_name()),
        ]);
        assert!(ChangePasswdData::decode(&data).is_err());
    }
}
