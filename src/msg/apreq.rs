//! `AP-REQ` and `Authenticator` (RFC 4120 §5.5.1, §5.5.2).
//!
//! The KDC needs both for one thing: `PA-TGS-REQ` carries an `AP-REQ` in which
//! the client presents its TGT, and the `Authenticator` inside it is the whole
//! proof that the request came from the client the TGT names. A service needs
//! them to accept the tickets this KDC issues, which is how the tests check the
//! other direction.
//!
//! `AP-OPTIONS` is kept as a number rather than a struct because a KDC reads two
//! bits of it (`use-session-key`, `mutual-required`) and rejects nothing.

use crate::crypto::Key;
use crate::der::{self, Fields, Reader};
use crate::error::{Error, Result};
use crate::name::Principal;

use super::{EncryptedData, Ticket, as_time, decode_key, encode_key};

/// `AP-REQ`, `[APPLICATION 14]`.
pub const AP_REQ: u8 = 14;
/// `AP-REP`, `[APPLICATION 15]`.
pub const AP_REP: u8 = 15;
/// `Authenticator`, `[APPLICATION 2]`.
pub const AUTHENTICATOR: u8 = 2;

/// `APOptions` bit: the ticket should be decrypted in the session key of a TGT
/// the server holds (user-to-user).
pub const AP_OPTS_USE_SESSION_KEY: u32 = 0x4000_0000;
/// `APOptions` bit: the server must answer with an `AP-REP`.
pub const AP_OPTS_MUTUAL_REQUIRED: u32 = 0x2000_0000;

/// `AP-REQ ::= [APPLICATION 14] SEQUENCE { pvno, msg-type, ap-options, ticket,
/// authenticator }`.
#[derive(Clone, Debug)]
pub struct ApReq {
    /// `ApOptions`.
    pub ap_options: u32,
    /// The ticket, kept encoded: the KDC decrypts it through its own key, and
    /// re-encoding a decoded ticket would need every field it does not read.
    pub ticket: Vec<u8>,
    /// The encrypted `Authenticator`.
    pub authenticator: EncryptedData,
}

impl ApReq {
    /// The DER of the whole `[APPLICATION 14]` message.
    pub fn encode(&self) -> Vec<u8> {
        der::cons(
            der::app(AP_REQ),
            &[der::seq(&[
                der::field(0, der::int(super::PVNO)),
                der::field(1, der::int(AP_REQ as i64)),
                der::field(2, der::flags32(self.ap_options)),
                der::field(3, self.ticket.clone()),
                der::field(4, self.authenticator.encode()),
            ])],
        )
    }

    /// Decodes a whole `[APPLICATION 14]` message.
    pub fn decode(data: &[u8]) -> Result<Self> {
        let f = Fields::parse_app("AP-REQ", AP_REQ, data)?;
        let pvno = f.int(0, "AP-REQ")?;
        if pvno != super::PVNO {
            return Err(Error::Protocol(format!(
                "AP-REQ pvno is {pvno}, RFC 4120 says 5"
            )));
        }
        let msg_type = f.int(1, "AP-REQ")?;
        if msg_type != AP_REQ as i64 {
            return Err(Error::Protocol(format!(
                "AP-REQ msg-type is {msg_type}, expected {AP_REQ}"
            )));
        }
        let ap_options = f.flags32(2, "AP-REQ")?;
        let ticket = f.get(3, "AP-REQ")?.to_vec();
        let mut r = Reader::new(f.get(4, "AP-REQ")?);
        let authenticator = EncryptedData::decode_content(
            "AP-REQ.authenticator",
            r.expect("AP-REQ", der::SEQUENCE)?,
        )?;
        Ok(ApReq {
            ap_options,
            ticket,
            authenticator,
        })
    }

    /// The ticket this request presents.
    pub fn ticket(&self) -> Result<Ticket> {
        Ticket::decode(&self.ticket)
    }
}

/// `Authenticator ::= [APPLICATION 2] SEQUENCE { authenticator-vno, crealm,
/// cname, cksum, cusec, ctime, subkey, seq-number, authorization-data }`.
///
/// There is **no** `msg-type`: the authenticator only ever appears inside an
/// `AP-REQ`, so its type is implied, and every other field is numbered one lower
/// than it would be otherwise. Heimdal's `lib/asn1/krb5.asn1` and Devolutions'
/// `picky-krb` agree on this, and a KDC that numbers the fields as if a
/// `msg-type` were there reads `crealm` as a `PrincipalName` and refuses every
/// real client.
#[derive(Clone, Debug)]
pub struct Authenticator {
    /// The client's realm.
    pub crealm: String,
    /// The client.
    pub cname: Principal,
    /// `Checksum ::= SEQUENCE { cksumtype, checksum }` — over the request body
    /// in a `PA-TGS-REQ`, which is why it is the load-bearing field.
    pub cksum: Option<(i32, Vec<u8>)>,
    /// `cusec`.
    pub cusec: u32,
    /// `ctime`.
    pub ctime: i64,
    /// A subkey, which keys the reply in place of the ticket's session key.
    pub subkey: Option<Key>,
    /// `seq-number`.
    pub seq_number: Option<u32>,
    /// `authorization-data`, kept encoded.
    pub authorization_data: Option<Vec<u8>>,
}

impl Authenticator {
    /// The DER of the whole `[APPLICATION 2]` message.
    pub fn encode(&self) -> Vec<u8> {
        let mut parts = vec![
            der::field(0, der::int(super::PVNO)),
            der::field(1, der::general_string(&self.crealm)),
            der::field(2, self.cname.encode_name()),
        ];
        if let Some((ty, value)) = &self.cksum {
            parts.push(der::field(
                3,
                der::seq(&[
                    der::field(0, der::int(*ty as i64)),
                    der::field(1, der::octets(value)),
                ]),
            ));
        }
        parts.push(der::field(4, der::int(self.cusec as i64)));
        parts.push(der::field(5, der::time(self.ctime)));
        if let Some(subkey) = &self.subkey {
            parts.push(der::field(6, encode_key(subkey)));
        }
        if let Some(seq) = self.seq_number {
            parts.push(der::field(7, der::int(seq as i64)));
        }
        if let Some(ad) = &self.authorization_data {
            parts.push(der::field(8, ad.clone()));
        }
        der::cons(der::app(AUTHENTICATOR), &[der::seq(&parts)])
    }

    /// Decodes a whole `[APPLICATION 2]` message.
    pub fn decode(data: &[u8]) -> Result<Self> {
        let f = Fields::parse_app("Authenticator", AUTHENTICATOR, data)?;
        let crealm = f.string(1, "Authenticator")?;
        let cname = Principal::decode_field(&f, 2, "Authenticator.cname", &crealm)?;
        let cksum = match f.opt(3) {
            None => None,
            Some(_) => {
                let mut r = Reader::new(f.get(3, "Authenticator")?);
                let cf = Fields::parse("Checksum", r.expect("Authenticator", der::SEQUENCE)?)?;
                Some((
                    cf.int(0, "Checksum")? as i32,
                    cf.octets(1, "Checksum")?.to_vec(),
                ))
            }
        };
        let cusec = f.u32(4, "Authenticator")?;
        let ctime = as_time("Authenticator.ctime", f.get(5, "Authenticator")?)?;
        let subkey = match f.opt(6) {
            None => None,
            Some(_) => {
                let mut r = Reader::new(f.get(6, "Authenticator")?);
                Some(decode_key(r.expect("Authenticator", der::SEQUENCE)?)?)
            }
        };
        Ok(Authenticator {
            crealm,
            cname,
            cksum,
            cusec,
            ctime,
            subkey,
            seq_number: f.opt_int(7, "Authenticator")?.map(|v| v as u32),
            authorization_data: f.opt(8).map(<[u8]>::to_vec),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{Cipher, Enctype, OwnCipher, usage};

    fn authenticator() -> Authenticator {
        Authenticator {
            crealm: "EXAMPLE.COM".into(),
            cname: Principal::parse("alice@EXAMPLE.COM").unwrap(),
            cksum: Some((16, vec![0xaa; 12])),
            cusec: 123_456,
            ctime: 1_700_000_000,
            subkey: None,
            seq_number: None,
            authorization_data: None,
        }
    }

    #[test]
    fn authenticator_round_trips() {
        let auth = authenticator();
        let back = Authenticator::decode(&auth.encode()).unwrap();
        assert_eq!(back.crealm, auth.crealm);
        assert_eq!(back.cname, auth.cname);
        assert_eq!(back.cksum, auth.cksum);
        assert_eq!(back.ctime, auth.ctime);
        assert_eq!(back.cusec, auth.cusec);
        assert!(back.subkey.is_none());
    }

    #[test]
    fn a_subkey_survives_the_round_trip() {
        let cipher = OwnCipher;
        let mut auth = authenticator();
        auth.subkey = Some(cipher.random(Enctype::Aes256Sha1).unwrap());
        let back = Authenticator::decode(&auth.encode()).unwrap();
        assert_eq!(
            back.subkey.as_ref().unwrap().bytes(),
            auth.subkey.as_ref().unwrap().bytes()
        );
    }

    #[test]
    fn ap_req_round_trips_with_its_ticket() {
        let cipher = OwnCipher;
        let session = cipher.random(Enctype::Aes128Sha1).unwrap();
        let auth = authenticator();
        let ap_req = ApReq {
            ap_options: AP_OPTS_MUTUAL_REQUIRED,
            ticket: b"an opaque ticket".to_vec(),
            authenticator: EncryptedData::seal(
                &cipher,
                &session,
                usage::TGS_REQ_AUTH,
                None,
                &auth.encode(),
            )
            .unwrap(),
        };
        let back = ApReq::decode(&ap_req.encode()).unwrap();
        assert_eq!(back.ap_options, AP_OPTS_MUTUAL_REQUIRED);
        assert_eq!(back.ticket, ap_req.ticket);
        let plain = cipher
            .decrypt(&session, usage::TGS_REQ_AUTH, &back.authenticator.cipher)
            .unwrap();
        assert_eq!(Authenticator::decode(&plain).unwrap().cname, auth.cname);
    }

    #[test]
    fn a_wrong_ap_req_msg_type_is_refused() {
        let cipher = OwnCipher;
        let session = cipher.random(Enctype::Aes128Sha1).unwrap();
        let mut encoded = ApReq {
            ap_options: 0,
            ticket: Vec::new(),
            authenticator: EncryptedData::seal(&cipher, &session, 7, None, b"x").unwrap(),
        }
        .encode();
        // The AP-REQ's own msg-type is [1] INTEGER 14; 15 is AP-REP. The
        // encoding starts with [0] INTEGER 5 (pvno), so the window to find is
        // the one carrying 14 — finding "the first INTEGER" would change the
        // pvno and prove nothing about the msg-type.
        let pos = encoded
            .windows(3)
            .position(|w| w == [0x02, 0x01, AP_REQ])
            .expect("the msg-type INTEGER in the encoding");
        encoded[pos + 2] = AP_REP;
        assert!(ApReq::decode(&encoded).is_err());

        // ... and a wrong version is refused too, which is what tells the two
        // INTEGERs apart.
        let mut wrong_pvno = ApReq {
            ap_options: 0,
            ticket: Vec::new(),
            authenticator: EncryptedData::seal(&cipher, &session, 7, None, b"x").unwrap(),
        }
        .encode();
        let pvno = wrong_pvno
            .windows(3)
            .position(|w| w == [0x02, 0x01, 5])
            .expect("the pvno INTEGER");
        wrong_pvno[pvno + 2] = 4;
        assert!(ApReq::decode(&wrong_pvno).is_err());
    }

    /// The authenticator has no `msg-type`, and every other field is numbered
    /// one lower than it would be if it had one. This test exists because
    /// getting it wrong is invisible: the fields still parse, they just parse as
    /// each other, and every real client is refused.
    #[test]
    fn the_authenticator_carries_no_msg_type() {
        let auth = authenticator();
        let encoded = auth.encode();
        // [APPLICATION 2] SEQUENCE, then [0] pvno = 5, then [1] crealm.
        assert_eq!(encoded[0], der::app(AUTHENTICATOR));
        let mut r = Reader::new(&encoded);
        let content = r.expect("Authenticator", der::app(AUTHENTICATOR)).unwrap();
        let f = Fields::parse(
            "Authenticator",
            der::as_sequence("Authenticator", content).unwrap(),
        )
        .unwrap();
        assert_eq!(f.tags()[0], 0, "the first field is [0], the version");
        assert_eq!(
            f.int(0, "Authenticator").unwrap(),
            5,
            "[0] is the version, not a msg-type"
        );
        assert_eq!(
            f.string(1, "Authenticator").unwrap(),
            "EXAMPLE.COM",
            "[1] is the realm"
        );
        assert!(
            f.string(2, "Authenticator").is_err(),
            "[2] is a PrincipalName, not a realm"
        );
    }
}
