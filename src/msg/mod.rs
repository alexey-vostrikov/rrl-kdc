//! RFC 4120 messages, both directions: the KDC reads `KDC-REQ` and writes
//! `KDC-REP`, `EncKDCRepPart`, `Ticket`, `EncTicketPart` and `KRB-ERROR`.
//!
//! Field numbers below are the ones in RFC 4120 §5, and every one of them is
//! EXPLICIT — `[n]` wraps a whole TLV, which is why encoding goes through
//! [`der::field`] and decoding through [`crate::der::Fields`]' typed
//! accessors rather than raw octets.

pub mod apreq;
pub mod kpasswd;
pub mod req;

pub use apreq::{ApReq, Authenticator};
pub use req::{KdcReq, KdcReqBody};

use crate::crypto::{Enctype, Key};
use crate::der::{self, Fields, Reader};
use crate::error::{Error, Result};
use crate::name::Principal;

/// `pvno` of every message this crate speaks (RFC 4120 §5.3).
pub const PVNO: i64 = 5;

/// `AS-REQ` (`KDC-REQ`, msg-type 10).
pub const AS_REQ: i64 = 10;
/// `AS-REP` (`KDC-REP`, msg-type 11).
pub const AS_REP: i64 = 11;
/// `TGS-REQ` (`KDC-REQ`, msg-type 12).
pub const TGS_REQ: i64 = 12;
/// `TGS-REP` (`KDC-REP`, msg-type 13).
pub const TGS_REP: i64 = 13;
/// `EncASRepPart`, `[APPLICATION 25]`.
pub const ENC_AS_REP_PART: u8 = 25;
/// `EncTGSRepPart`, `[APPLICATION 26]`.
pub const ENC_TGS_REP_PART: u8 = 26;
/// `KRB-ERROR`, `[APPLICATION 30]`.
pub const KRB_ERROR: u8 = 30;
/// `Ticket`, `[APPLICATION 1]`.
pub const TICKET: u8 = 1;
/// `EncTicketPart`, `[APPLICATION 3]`.
pub const ENC_TICKET_PART: u8 = 3;

/// PA-DATA type `PA-TGS-REQ`.
pub const PA_TGS_REQ: i32 = 1;
/// PA-DATA type `PA-ENC-TIMESTAMP`.
pub const PA_ENC_TIMESTAMP: i32 = 2;
/// PA-DATA type `PA-PW-SALT`.
pub const PA_PW_SALT: i32 = 3;
/// PA-DATA type `PA-ETYPE-INFO2`.
pub const PA_ETYPE_INFO2: i32 = 19;
/// PA-DATA type `PA-REQ-ENC-PA-REP` (RFC 6806 §11) — informational, ignored.
pub const PA_REQ_ENC_PA_REP: i32 = 149;
/// PA-DATA type `PA-PAC-REQUEST` (MS-KILE).
pub const PA_PAC_REQUEST: i32 = 128;

/// `TicketFlags` masks (RFC 4120 §5.3), in DER bit order: bit *n* is
/// `1 << (31 - n)`.
pub mod tkt_flags {
    /// `forwardable`.
    pub const FORWARDABLE: u32 = 0x4000_0000;
    /// `forwarded`.
    pub const FORWARDED: u32 = 0x2000_0000;
    /// `proxiable`.
    pub const PROXIABLE: u32 = 0x1000_0000;
    /// `proxy`.
    pub const PROXY: u32 = 0x0800_0000;
    /// `may-postdate`.
    pub const MAY_POSTDATE: u32 = 0x0400_0000;
    /// `postdated`.
    pub const POSTDATED: u32 = 0x0200_0000;
    /// `invalid`.
    pub const INVALID: u32 = 0x0100_0000;
    /// `renewable`.
    pub const RENEWABLE: u32 = 0x0080_0000;
    /// `initial`.
    pub const INITIAL: u32 = 0x0040_0000;
    /// `pre-authent`.
    pub const PRE_AUTHENT: u32 = 0x0020_0000;
    /// `hw-authent`.
    pub const HW_AUTHENT: u32 = 0x0010_0000;
    /// `transited-policy-checked`.
    pub const TRANSITED_POLICY_CHECKED: u32 = 0x0008_0000;
    /// `ok-as-delegate`.
    pub const OK_AS_DELEGATE: u32 = 0x0004_0000;
    /// `enc-pa-rep` (RFC 6806 §11, bit 15): the KDC answers with a checksum over the request,
    /// in the encrypted part, and this says so.
    pub const ENC_PA_REP: u32 = 0x0001_0000;
    /// `anonymous` (RFC 8062 §3, bit 16): this ticket names nobody on purpose.
    ///
    /// Bit 16 in `KerberosFlags` numbering is `1 << (31 - 16)`.
    pub const ANONYMOUS: u32 = 0x0000_8000;
}

/// `KDCOptions` masks (RFC 4120 §5.4.1), in DER bit order.
pub mod kdc_options {
    /// `forwardable`.
    pub const FORWARDABLE: u32 = 0x4000_0000;
    /// `forwarded`.
    pub const FORWARDED: u32 = 0x2000_0000;
    /// `proxiable`.
    pub const PROXIABLE: u32 = 0x1000_0000;
    /// `proxy`.
    pub const PROXY: u32 = 0x0800_0000;
    /// `allow-postdate`.
    pub const ALLOW_POSTDATE: u32 = 0x0400_0000;
    /// `postdated`.
    pub const POSTDATED: u32 = 0x0200_0000;
    /// `renewable`.
    pub const RENEWABLE: u32 = 0x0100_0000;
    /// `enc-tkt-in-skey` (RFC 4120 §5.4.1, bit 28): encrypt the ticket in the
    /// session key of the ticket in `additional-tickets` — user-to-user.
    pub const ENC_TKT_IN_SKEY: u32 = 0x0000_0008;
    /// `cname-in-addl-tkt` (RFC 6806 §11, bit 14): the client comes from the ticket in
    /// `additional-tickets`, which is what S4U2Proxy asks for.
    pub const CNAME_IN_ADDL_TKT: u32 = 0x0002_0000;
    /// `renew` (bit 30): extend a renewable TGT's lifetime.
    pub const RENEW: u32 = 0x0000_0002;
    /// `validate` (bit 31): clear a postdated ticket's `INVALID` flag.
    pub const VALIDATE: u32 = 0x0000_0001;
    /// `anonymous` (RFC 8062 §3, bit 16): ask for a ticket that names nobody.
    pub const ANONYMOUS: u32 = 0x0000_8000;
    /// `canonicalize` (RFC 6806 §3).
    pub const CANONICALIZE: u32 = 0x0000_0020;
}

/// `EncryptedData ::= SEQUENCE { etype [0], kvno [1] OPTIONAL, cipher [2] }`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncryptedData {
    /// The enctype of the key that encrypted this.
    pub etype: Enctype,
    /// The key version, when the encryptor knows it.
    pub kvno: Option<u32>,
    /// The ciphertext.
    pub cipher: Vec<u8>,
}

impl EncryptedData {
    /// Encrypts `plaintext` under `key` with `usage` and records the enctype
    /// and (if given) the kvno.
    pub fn seal(
        cipher: &dyn crate::crypto::Cipher,
        key: &Key,
        usage: u32,
        kvno: Option<u32>,
        plaintext: &[u8],
    ) -> Result<Self> {
        Ok(EncryptedData {
            etype: key.enctype(),
            kvno,
            cipher: cipher.encrypt(key, usage, plaintext)?,
        })
    }

    /// The DER of the `EncryptedData` SEQUENCE, without an enclosing field.
    pub fn encode(&self) -> Vec<u8> {
        let mut parts = vec![der::field(0, der::int(self.etype.id() as i64))];
        if let Some(kvno) = self.kvno {
            parts.push(der::field(1, der::int(kvno as i64)));
        }
        parts.push(der::field(2, der::octets(&self.cipher)));
        der::seq(&parts)
    }

    /// Decodes a whole `EncryptedData` SEQUENCE, tag included — what a caller
    /// that has the DER of a field in hand wants.
    pub fn decode(context: &'static str, der: &[u8]) -> Result<Self> {
        let mut r = Reader::new(der);
        Self::decode_content(context, r.expect(context, der::SEQUENCE)?)
    }

    /// Decodes the *content* of the `EncryptedData` SEQUENCE, for callers that
    /// have already stripped the tag.
    pub fn decode_content(context: &'static str, content: &[u8]) -> Result<Self> {
        let f = Fields::parse(context, content)?;
        let etype_id = f.int(0, context)? as i32;
        let etype = Enctype::from_id(etype_id).ok_or(Error::UnsupportedEnctype(etype_id))?;
        let kvno = f.opt(1).map(|_| f.u32(1, context)).transpose()?;
        Ok(EncryptedData {
            etype,
            kvno,
            cipher: f.octets(2, context)?.to_vec(),
        })
    }
}

/// `EncryptionKey ::= SEQUENCE { keytype [0], keyvalue [1] }`.
pub fn encode_key(key: &Key) -> Vec<u8> {
    der::seq(&[
        der::field(0, der::int(key.enctype().id() as i64)),
        der::field(1, der::octets(key.bytes())),
    ])
}

/// Decodes an `EncryptionKey` from the content of its `SEQUENCE`.
pub fn decode_key(content: &[u8]) -> Result<Key> {
    let f = Fields::parse("EncryptionKey", content)?;
    let id = f.int(0, "EncryptionKey")? as i32;
    let etype = Enctype::from_id(id).ok_or(Error::UnsupportedEnctype(id))?;
    Ok(Key::new(etype, f.octets(1, "EncryptionKey")?)?)
}

/// `Ticket ::= [APPLICATION 1] SEQUENCE { tkt-vno, realm, sname, enc-part }`.
#[derive(Clone, Debug)]
pub struct Ticket {
    /// The realm of `sname`, which is the realm that issued the ticket.
    pub realm: String,
    /// The service this ticket is for.
    pub sname: Principal,
    /// The encrypted `EncTicketPart`.
    pub enc: EncryptedData,
}

impl Ticket {
    /// The DER of the whole `[APPLICATION 1]` ticket.
    pub fn encode(&self) -> Vec<u8> {
        der::cons(
            der::app(TICKET),
            &[der::seq(&[
                der::field(0, der::int(PVNO)),
                der::field(1, der::general_string(&self.realm)),
                der::field(2, self.sname.encode_name()),
                der::field(3, self.enc.encode()),
            ])],
        )
    }

    /// Decodes a whole `[APPLICATION 1]` ticket.
    pub fn decode(data: &[u8]) -> Result<Self> {
        let f = Fields::parse_app("Ticket", TICKET, data)?;
        let realm = f.string(1, "Ticket")?;
        let sname = Principal::decode_field(&f, 2, "Ticket.sname", &realm)?;
        let mut r = Reader::new(f.get(3, "Ticket")?);
        let enc =
            EncryptedData::decode_content("Ticket.enc-part", r.expect("Ticket", der::SEQUENCE)?)?;
        Ok(Ticket { realm, sname, enc })
    }
}

/// `EncTicketPart ::= [APPLICATION 3] SEQUENCE { ... }`.
#[derive(Clone, Debug)]
pub struct EncTicketPart {
    /// `TicketFlags`.
    pub flags: u32,
    /// The session key the ticket grants.
    pub session_key: Key,
    /// The client's realm.
    pub crealm: String,
    /// The client.
    pub cname: Principal,
    /// `TransitedEncoding.tr-type`; 0 is `DOMAIN-X500-COMPRESS`.
    pub transited_type: i32,
    /// `TransitedEncoding.contents`.
    pub transited: Vec<u8>,
    /// When the client authenticated.
    pub authtime: i64,
    /// When the ticket becomes valid, if not `authtime`.
    pub starttime: Option<i64>,
    /// When it stops being valid.
    pub endtime: i64,
    /// The last time it may be renewed.
    pub renew_till: Option<i64>,
    /// The addresses it is valid from — the request's, encoded as received.
    pub caddr: Option<Vec<u8>>,
    /// `AuthorizationData`, encoded as received.
    pub authorization_data: Option<Vec<u8>>,
}

impl EncTicketPart {
    /// The DER of the whole `[APPLICATION 3]` part, ready to encrypt.
    pub fn encode(&self) -> Vec<u8> {
        let mut parts = vec![
            der::field(0, der::flags32(self.flags)),
            der::field(1, encode_key(&self.session_key)),
            der::field(2, der::general_string(&self.crealm)),
            der::field(3, self.cname.encode_name()),
            der::field(
                4,
                der::seq(&[
                    der::field(0, der::int(self.transited_type as i64)),
                    der::field(1, der::octets(&self.transited)),
                ]),
            ),
            der::field(5, der::time(self.authtime)),
        ];
        if let Some(start) = self.starttime {
            parts.push(der::field(6, der::time(start)));
        }
        parts.push(der::field(7, der::time(self.endtime)));
        if let Some(renew) = self.renew_till {
            parts.push(der::field(8, der::time(renew)));
        }
        if let Some(caddr) = &self.caddr {
            // The request carried a `HostAddresses`; it is reused verbatim,
            // which is what RFC 4120 §5.4.1 means by "the addresses".
            parts.push(der::field(9, caddr.clone()));
        }
        if let Some(ad) = &self.authorization_data {
            parts.push(der::field(10, ad.clone()));
        }
        der::cons(der::app(ENC_TICKET_PART), &[der::seq(&parts)])
    }

    /// Decodes a whole `[APPLICATION 3]` part — used by the TGS exchange, and
    /// by tests that check what the KDC put in a ticket.
    pub fn decode(data: &[u8]) -> Result<Self> {
        let f = Fields::parse_app("EncTicketPart", ENC_TICKET_PART, data)?;
        let flags = f.flags32(0, "EncTicketPart")?;
        let mut r = Reader::new(f.get(1, "EncTicketPart")?);
        let session_key = decode_key(r.expect("EncTicketPart", der::SEQUENCE)?)?;
        let crealm = f.string(2, "EncTicketPart")?;
        let cname = Principal::decode_field(&f, 3, "EncTicketPart.cname", &crealm)?;
        let mut tr = Reader::new(f.get(4, "EncTicketPart")?);
        let tf = Fields::parse(
            "TransitedEncoding",
            tr.expect("TransitedEncoding", der::SEQUENCE)?,
        )?;
        let transited_type = tf.int(0, "TransitedEncoding")? as i32;
        let transited = tf.octets(1, "TransitedEncoding")?.to_vec();
        let authtime = as_time("EncTicketPart.authtime", f.get(5, "EncTicketPart")?)?;
        let starttime = f
            .opt(6)
            .map(|_| {
                as_time(
                    "EncTicketPart.starttime",
                    f.get(6, "EncTicketPart").unwrap(),
                )
            })
            .transpose()?;
        let endtime = as_time("EncTicketPart.endtime", f.get(7, "EncTicketPart")?)?;
        let renew_till = f
            .opt(8)
            .map(|_| {
                as_time(
                    "EncTicketPart.renew-till",
                    f.get(8, "EncTicketPart").unwrap(),
                )
            })
            .transpose()?;
        Ok(EncTicketPart {
            flags,
            session_key,
            crealm,
            cname,
            transited_type,
            transited,
            authtime,
            starttime,
            endtime,
            renew_till,
            caddr: f.opt(9).map(<[u8]>::to_vec),
            authorization_data: f.opt(10).map(<[u8]>::to_vec),
        })
    }
}

/// `EncKDCRepPart` — the plaintext of an `EncASRepPart` or `EncTGSRepPart`.
#[derive(Clone, Debug)]
pub struct EncKdcRepPart {
    /// The session key granted (or the ticket's, for a TGS reply).
    pub session_key: Key,
    /// `LastReq`: (lr-type, lr-value) pairs.
    pub last_req: Vec<(i32, i64)>,
    /// The request's nonce, echoed so the client can match the reply.
    pub nonce: u32,
    /// When the client's key expires.
    pub key_expiration: Option<i64>,
    /// `TicketFlags`.
    pub flags: u32,
    /// When the client authenticated.
    pub authtime: i64,
    /// When the ticket becomes valid.
    pub starttime: Option<i64>,
    /// When it stops being valid.
    pub endtime: i64,
    /// The last time it may be renewed.
    pub renew_till: Option<i64>,
    /// The realm of the service.
    pub srealm: String,
    /// The service.
    pub sname: Principal,
    /// The addresses the ticket is good from.
    pub caddr: Option<Vec<u8>>,
    /// `encrypted-pa-data [12]`: PA-DATA a client may read only after decrypting this part.
    ///
    /// RFC 6806 §11 puts `PA-REQ-ENC-PA-REP` here rather than beside the ticket, because its
    /// whole point is that an attacker who can rewrite the unprotected request cannot forge it.
    /// A value that needs the reply key to read is what makes that true.
    pub padata: Vec<(i32, Vec<u8>)>,
}

impl EncKdcRepPart {
    /// The DER of the part, wrapped in `[APPLICATION 25]` or `[APPLICATION 26]`.
    ///
    /// The tag is a parameter because the two are *not* interchangeable:
    /// RFC 4120 §5.4.2 gives an AS-REP tag 25 and a TGS-REP tag 26, and a
    /// client is entitled to reject the wrong one (Heimdal's is stricter than
    /// MIT's here, and `encode_as_rep_as_tgs_rep` exists precisely because
    /// some clients want 26 in an AS-REP).
    pub fn encode(&self, app_tag: u8) -> Vec<u8> {
        let mut parts = vec![
            der::field(0, encode_key(&self.session_key)),
            der::field(
                1,
                der::seq(
                    &self
                        .last_req
                        .iter()
                        .map(|(ty, time)| {
                            der::seq(&[
                                der::field(0, der::int(*ty as i64)),
                                der::field(1, der::time(*time)),
                            ])
                        })
                        .collect::<Vec<_>>(),
                ),
            ),
            der::field(2, der::int(self.nonce as i64)),
        ];
        if let Some(exp) = self.key_expiration {
            parts.push(der::field(3, der::time(exp)));
        }
        parts.push(der::field(4, der::flags32(self.flags)));
        parts.push(der::field(5, der::time(self.authtime)));
        if let Some(start) = self.starttime {
            parts.push(der::field(6, der::time(start)));
        }
        parts.push(der::field(7, der::time(self.endtime)));
        if let Some(renew) = self.renew_till {
            parts.push(der::field(8, der::time(renew)));
        }
        parts.push(der::field(9, der::general_string(&self.srealm)));
        parts.push(der::field(10, self.sname.encode_name()));
        if let Some(caddr) = &self.caddr {
            parts.push(der::field(11, caddr.clone()));
        }
        if !self.padata.is_empty() {
            parts.push(der::field(12, encode_pa_data(&self.padata)));
        }
        der::cons(der::app(app_tag), &[der::seq(&parts)])
    }

    /// Decodes an `EncASRepPart` / `EncTGSRepPart`: what a client does with
    /// the encrypted half, and what the tests use to check the KDC.
    pub fn decode(data: &[u8]) -> Result<Self> {
        let tag = match data.first() {
            Some(&t) if t == der::app(ENC_AS_REP_PART) || t == der::app(ENC_TGS_REP_PART) => t,
            _ => {
                return Err(Error::Protocol(
                    "enc-part is not an EncKDCRepPart (application 25 or 26)".into(),
                ));
            }
        };
        let app_tag = tag & 0x1f;
        let f = Fields::parse_app("EncKDCRepPart", app_tag, data)?;
        let mut r = Reader::new(f.get(0, "EncKDCRepPart")?);
        let session_key = decode_key(r.expect("EncKDCRepPart", der::SEQUENCE)?)?;
        let mut lr = Reader::new(f.get(1, "EncKDCRepPart")?);
        let lr_seq = lr.expect("LastReq", der::SEQUENCE)?;
        let mut lrs = Reader::new(lr_seq);
        let mut last_req = Vec::new();
        while !lrs.is_empty() {
            let e = Fields::parse("LastReq", lrs.expect("LastReq", der::SEQUENCE)?)?;
            last_req.push((
                e.int(0, "LastReq")? as i32,
                as_time("LastReq", e.get(1, "LastReq")?)?,
            ));
        }
        let nonce = f.u32(2, "EncKDCRepPart")?;
        let key_expiration = f
            .opt(3)
            .map(|_| as_time("key-expiration", f.get(3, "EncKDCRepPart").unwrap()))
            .transpose()?;
        let flags = f.flags32(4, "EncKDCRepPart")?;
        let authtime = as_time("authtime", f.get(5, "EncKDCRepPart")?)?;
        let starttime = f
            .opt(6)
            .map(|_| as_time("starttime", f.get(6, "EncKDCRepPart").unwrap()))
            .transpose()?;
        let endtime = as_time("endtime", f.get(7, "EncKDCRepPart")?)?;
        let renew_till = f
            .opt(8)
            .map(|_| as_time("renew-till", f.get(8, "EncKDCRepPart").unwrap()))
            .transpose()?;
        let srealm = f.string(9, "EncKDCRepPart")?;
        let sname = Principal::decode_field(&f, 10, "EncKDCRepPart.sname", &srealm)?;
        Ok(EncKdcRepPart {
            session_key,
            last_req,
            nonce,
            key_expiration,
            flags,
            authtime,
            starttime,
            endtime,
            renew_till,
            srealm,
            sname,
            caddr: f.opt(11).map(<[u8]>::to_vec),
            padata: match f.opt(12) {
                None => Vec::new(),
                Some(_) => {
                    let mut r = Reader::new(f.get(12, "EncKDCRepPart")?);
                    decode_pa_data("EncKDCRepPart", r.expect("EncKDCRepPart", der::SEQUENCE)?)?
                }
            },
        })
    }
}

/// `KDC-REP` — the outer body of an AS-REP or TGS-REP.
#[derive(Clone, Debug)]
pub struct KdcRep {
    /// The message type: [`AS_REP`] or [`TGS_REP`].
    pub msg_type: i64,
    /// `PA-DATA` the client needs to make sense of the reply.
    pub padata: Vec<(i32, Vec<u8>)>,
    /// The client's realm.
    pub crealm: String,
    /// The client.
    pub cname: Principal,
    /// The ticket granted.
    pub ticket: Ticket,
    /// The encrypted `EncKDCRepPart`.
    pub enc_part: EncryptedData,
}

impl KdcRep {
    /// The DER of the whole reply, `[APPLICATION 11]` or `[APPLICATION 13]`.
    pub fn encode(&self) -> Vec<u8> {
        let app_tag = if self.msg_type == AS_REP { 11 } else { 13 };
        let mut parts = vec![
            der::field(0, der::int(PVNO)),
            der::field(1, der::int(self.msg_type)),
        ];
        if !self.padata.is_empty() {
            parts.push(der::field(2, encode_pa_data(&self.padata)));
        }
        parts.push(der::field(3, der::general_string(&self.crealm)));
        parts.push(der::field(4, self.cname.encode_name()));
        parts.push(der::field(5, self.ticket.encode()));
        parts.push(der::field(6, self.enc_part.encode()));
        der::cons(der::app(app_tag), &[der::seq(&parts)])
    }
}

/// `PA-DATA ::= SEQUENCE { padata-type [1], padata-value [2] }`, as a SEQUENCE
/// OF.
pub fn encode_pa_data(items: &[(i32, Vec<u8>)]) -> Vec<u8> {
    der::seq(
        &items
            .iter()
            .map(|(ty, value)| {
                der::seq(&[
                    der::field(1, der::int(*ty as i64)),
                    der::field(2, der::octets(value)),
                ])
            })
            .collect::<Vec<_>>(),
    )
}

/// Parses a `SEQUENCE OF PA-DATA` from the content of its SEQUENCE.
pub fn decode_pa_data(context: &'static str, content: &[u8]) -> Result<Vec<(i32, Vec<u8>)>> {
    let mut r = Reader::new(content);
    let mut out = Vec::new();
    while !r.is_empty() {
        let f = Fields::parse(context, r.expect(context, der::SEQUENCE)?)?;
        out.push((f.int(1, context)? as i32, f.octets(2, context)?.to_vec()));
    }
    Ok(out)
}

/// The `PA-DATA` elements of an encoded `METHOD-DATA` SEQUENCE.
///
/// The counterpart of [`encode_pa_data`] for callers that hold the whole SEQUENCE — an error's
/// `e-data` is exactly that. [`decode_pa_data`] itself takes the content, so that a caller
/// which has already stripped the tag does not pay for a second parse.
pub fn method_data_of(der: &[u8]) -> Result<Vec<(i32, Vec<u8>)>> {
    let mut r = Reader::new(der);
    decode_pa_data("METHOD-DATA", r.expect("METHOD-DATA", der::SEQUENCE)?)
}

/// `KRB-ERROR ::= [APPLICATION 30] SEQUENCE { ... }`.
#[derive(Clone, Debug)]
pub struct KrbError {
    /// `ctime`, when the KDC echoes the client's clock.
    pub ctime: Option<i64>,
    /// `cusec`.
    pub cusec: Option<u32>,
    /// This KDC's clock.
    pub stime: i64,
    /// `stime`'s microseconds part.
    pub susec: u32,
    /// The RFC 4120 §7.5 code.
    pub code: i32,
    /// `crealm`, when the client was identified.
    pub crealm: Option<String>,
    /// `cname`, when the client was identified.
    pub cname: Option<Principal>,
    /// The realm the error is about.
    pub realm: String,
    /// The service the request named.
    pub sname: Principal,
    /// Human-readable text.
    pub e_text: Option<String>,
    /// `METHOD-DATA` for `PREAUTH_REQUIRED`, else arbitrary.
    pub e_data: Option<Vec<u8>>,
    /// `padata`, which an error carries only when RFC 6113 put it there: under FAST
    /// the real error travels as `PA-FX-ERROR` inside `PA-FX-FAST-REPLY`, and a
    /// `METHOD-DATA` in the clear alongside it would be a second, unsigned copy.
    pub padata: Vec<(i32, Vec<u8>)>,
}

impl KrbError {
    /// The DER of the whole error.
    pub fn encode(&self) -> Vec<u8> {
        let mut parts = vec![
            der::field(0, der::int(PVNO)),
            der::field(1, der::int(KRB_ERROR as i64)),
        ];
        if let Some(t) = self.ctime {
            parts.push(der::field(2, der::time(t)));
        }
        if let Some(u) = self.cusec {
            parts.push(der::field(3, der::int(u as i64)));
        }
        parts.push(der::field(4, der::time(self.stime)));
        parts.push(der::field(5, der::int(self.susec as i64)));
        parts.push(der::field(6, der::int(self.code as i64)));
        if let Some(crealm) = &self.crealm {
            parts.push(der::field(7, der::general_string(crealm)));
        }
        if let Some(cname) = &self.cname {
            parts.push(der::field(8, cname.encode_name()));
        }
        parts.push(der::field(9, der::general_string(&self.realm)));
        parts.push(der::field(10, self.sname.encode_name()));
        if let Some(t) = &self.e_text {
            parts.push(der::field(11, der::general_string(t)));
        }
        if let Some(d) = &self.e_data {
            parts.push(der::field(12, der::octets(d)));
        }
        if !self.padata.is_empty() {
            parts.push(der::field(13, encode_pa_data(&self.padata)));
        }
        der::cons(der::app(KRB_ERROR), &[der::seq(&parts)])
    }

    /// Decodes a whole `[APPLICATION 30]` error — what a client does, and what
    /// the tests do to check that the KDC answered with the right code.
    pub fn decode(data: &[u8]) -> Result<Self> {
        let f = Fields::parse_app("KRB-ERROR", KRB_ERROR, data)?;
        let ctime = f
            .opt(2)
            .map(|_| as_time("ctime", f.get(2, "KRB-ERROR").unwrap()))
            .transpose()?;
        let cusec = f.opt(3).map(|_| f.u32(3, "KRB-ERROR")).transpose()?;
        let stime = as_time("stime", f.get(4, "KRB-ERROR")?)?;
        let susec = f.u32(5, "KRB-ERROR")?;
        let code = f.int(6, "KRB-ERROR")? as i32;
        let crealm = f.opt_string(7, "KRB-ERROR")?;
        let cname = match (&crealm, f.opt(8)) {
            (Some(r), Some(_)) => Some(Principal::decode_field(&f, 8, "cname", r)?),
            _ => None,
        };
        let realm = f.string(9, "KRB-ERROR")?;
        let sname = Principal::decode_field(&f, 10, "sname", &realm)?;
        let padata = match f.opt(13) {
            None => Vec::new(),
            Some(raw) => {
                let mut r = crate::der::Reader::new(raw);
                let seq = r.next("KRB-ERROR padata")?;
                decode_pa_data("KRB-ERROR", seq.content)?
            }
        };
        Ok(KrbError {
            ctime,
            cusec,
            stime,
            susec,
            code,
            crealm,
            cname,
            realm,
            sname,
            e_text: f.opt_string(11, "KRB-ERROR")?,
            e_data: f.opt_octets(12, "KRB-ERROR")?.map(<[u8]>::to_vec),
            padata,
        })
    }

    /// `METHOD-DATA` from `e-data`, for `PREAUTH_REQUIRED`.
    pub fn method_data(&self) -> Result<Vec<(i32, Vec<u8>)>> {
        let data = self
            .e_data
            .as_deref()
            .ok_or_else(|| Error::Protocol("KRB-ERROR has no e-data".into()))?;
        let mut r = Reader::new(data);
        decode_pa_data("METHOD-DATA", r.expect("METHOD-DATA", der::SEQUENCE)?)
    }
}

/// An `ETYPE-INFO2` entry: the enctype, its salt, and any `s2kparams`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EtypeInfo2Entry {
    /// The enctype this entry describes.
    pub etype: Enctype,
    /// The salt string-to-key should use.
    pub salt: Option<Vec<u8>>,
    /// The iteration count, as four big-endian octets.
    pub s2kparams: Option<Vec<u8>>,
}

/// `ETYPE-INFO2 ::= SEQUENCE OF ETYPE-INFO2-ENTRY`.
pub fn encode_etype_info2(entries: &[EtypeInfo2Entry]) -> Vec<u8> {
    der::seq(
        &entries
            .iter()
            .map(|e| {
                let mut parts = vec![der::field(0, der::int(e.etype.id() as i64))];
                if let Some(salt) = &e.salt {
                    parts.push(der::field(
                        1,
                        der::general_string(&String::from_utf8_lossy(salt)),
                    ));
                }
                if let Some(p) = &e.s2kparams {
                    parts.push(der::field(2, der::octets(p)));
                }
                der::seq(&parts)
            })
            .collect::<Vec<_>>(),
    )
}

/// Parses `ETYPE-INFO2` — what a client does with `PREAUTH_REQUIRED`.
pub fn decode_etype_info2(data: &[u8]) -> Result<Vec<EtypeInfo2Entry>> {
    // The value is the content of an `[n]`-free SEQUENCE: strip the tag.
    let mut r = Reader::new(data);
    let content = r.expect("ETYPE-INFO2", der::SEQUENCE)?;
    let mut s = Reader::new(content);
    let mut out = Vec::new();
    while !s.is_empty() {
        let f = Fields::parse("ETYPE-INFO2-ENTRY", s.expect("ETYPE-INFO2", der::SEQUENCE)?)?;
        let id = f.int(0, "ETYPE-INFO2-ENTRY")? as i32;
        let etype = Enctype::from_id(id).ok_or(Error::UnsupportedEnctype(id))?;
        out.push(EtypeInfo2Entry {
            etype,
            salt: f
                .opt_string(1, "ETYPE-INFO2-ENTRY")?
                .map(String::into_bytes),
            s2kparams: f.opt_octets(2, "ETYPE-INFO2-ENTRY")?.map(<[u8]>::to_vec),
        });
    }
    Ok(out)
}

/// `PA-ENC-TS-ENC ::= SEQUENCE { patimestamp [0], pausec [1] OPTIONAL }`.
pub fn encode_enc_ts_enc(timestamp: i64, usec: Option<u32>) -> Vec<u8> {
    let mut parts = vec![der::field(0, der::time(timestamp))];
    if let Some(u) = usec {
        parts.push(der::field(1, der::int(u as i64)));
    }
    der::seq(&parts)
}

/// Parses `PA-ENC-TS-ENC`: (timestamp, usec).
pub fn decode_enc_ts_enc(data: &[u8]) -> Result<(i64, Option<u32>)> {
    let mut r = Reader::new(data);
    let f = Fields::parse("PA-ENC-TS-ENC", r.expect("PA-ENC-TS-ENC", der::SEQUENCE)?)?;
    let ts = as_time("PA-ENC-TS-ENC", f.get(0, "PA-ENC-TS-ENC")?)?;
    let usec = f.opt(1).map(|_| f.u32(1, "PA-ENC-TS-ENC")).transpose()?;
    Ok((ts, usec))
}

/// A `GeneralizedTime` field's value: strips the tag and parses it.
pub fn as_time(context: &'static str, content: &[u8]) -> Result<i64> {
    let mut r = Reader::new(content);
    let text = der::as_string(context, r.expect(context, der::GENERALIZED_TIME)?)?;
    crate::time::parse_generalized_time(&text)
        .ok_or_else(|| Error::Protocol(format!("{context}: {text:?} is not a KerberosTime")))
}

/// The error a request that names an unimplemented feature gets.
pub fn unsupported(what: &str) -> Error {
    Error::Protocol(format!("{what} is not implemented by this KDC"))
}

/// `KDC_ERR_WRONG_REALM`, which this crate reports for a foreign realm.
pub const WRONG_REALM: i32 = 68;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{Cipher, Enctype, OwnCipher, usage};
    use crate::error::codes;

    fn cipher() -> OwnCipher {
        OwnCipher
    }

    #[test]
    fn encrypted_data_round_trips() {
        let c = cipher();
        let key = c.random(Enctype::Aes256Sha1).unwrap();
        let ed = EncryptedData::seal(&c, &key, usage::AS_REP_ENCPART, Some(3), b"secret").unwrap();
        let back = EncryptedData::decode("ed", &ed.encode()).unwrap();
        assert_eq!(back.etype, ed.etype);
        assert_eq!(back.kvno, Some(3));
        assert_eq!(
            c.decrypt(&key, usage::AS_REP_ENCPART, &back.cipher)
                .unwrap(),
            b"secret"
        );
    }

    #[test]
    fn a_ticket_keeps_its_service_and_realm() {
        let c = cipher();
        let key = c.random(Enctype::Aes128Sha1).unwrap();
        let part = EncTicketPart {
            flags: tkt_flags::INITIAL | tkt_flags::PRE_AUTHENT,
            session_key: c.random(Enctype::Aes128Sha1).unwrap(),
            crealm: "EXAMPLE.COM".into(),
            cname: Principal::parse("alice@EXAMPLE.COM").unwrap(),
            transited_type: 0,
            transited: Vec::new(),
            authtime: 1_700_000_000,
            starttime: None,
            endtime: 1_700_003_600,
            renew_till: Some(1_700_007_200),
            caddr: None,
            authorization_data: None,
        };
        let ticket = Ticket {
            realm: "EXAMPLE.COM".into(),
            sname: Principal::krbtgt("EXAMPLE.COM"),
            enc: EncryptedData::seal(&c, &key, usage::KDC_REP_TICKET, Some(1), &part.encode())
                .unwrap(),
        };
        let decoded = Ticket::decode(&ticket.encode()).unwrap();
        assert_eq!(decoded.sname, Principal::krbtgt("EXAMPLE.COM"));
        assert_eq!(decoded.realm, "EXAMPLE.COM");

        let plain = c
            .decrypt(&key, usage::KDC_REP_TICKET, &decoded.enc.cipher)
            .unwrap();
        let part_back = EncTicketPart::decode(&plain).unwrap();
        assert_eq!(
            part_back.cname,
            Principal::parse("alice@EXAMPLE.COM").unwrap()
        );
        assert_eq!(part_back.endtime, 1_700_003_600);
        assert_eq!(part_back.renew_till, Some(1_700_007_200));
        assert_eq!(part_back.flags & tkt_flags::INITIAL, tkt_flags::INITIAL);
    }

    #[test]
    fn enc_as_rep_part_uses_tag_25_and_tgs_tag_26() {
        let c = cipher();
        let part = EncKdcRepPart {
            padata: Vec::new(),
            session_key: c.random(Enctype::Aes128Sha1).unwrap(),
            last_req: vec![(0, 0)],
            nonce: 0xdead_beef,
            key_expiration: None,
            flags: tkt_flags::INITIAL,
            authtime: 1_700_000_000,
            starttime: None,
            endtime: 1_700_003_600,
            renew_till: None,
            srealm: "R".into(),
            sname: Principal::krbtgt("R"),
            caddr: None,
        };
        let as_rep = part.encode(ENC_AS_REP_PART);
        assert_eq!(as_rep[0], der::app(25));
        assert_eq!(EncKdcRepPart::decode(&as_rep).unwrap().nonce, 0xdead_beef);
        let tgs_rep = part.encode(ENC_TGS_REP_PART);
        assert_eq!(tgs_rep[0], der::app(26));
        assert_eq!(
            EncKdcRepPart::decode(&tgs_rep).unwrap().sname,
            Principal::krbtgt("R")
        );
        // A tag neither 25 nor 26 is refused rather than guessed at.
        let mut bad = as_rep.clone();
        bad[0] = der::app(24);
        assert!(EncKdcRepPart::decode(&bad).is_err());
    }

    #[test]
    fn etype_info2_round_trips_with_salt() {
        let entries = vec![
            EtypeInfo2Entry {
                etype: Enctype::Aes256Sha1,
                salt: Some(b"EXAMPLE.COMalice".to_vec()),
                s2kparams: None,
            },
            EtypeInfo2Entry {
                etype: Enctype::Aes128Sha1,
                salt: Some(b"EXAMPLE.COMalice".to_vec()),
                s2kparams: Some(4096u32.to_be_bytes().to_vec()),
            },
        ];
        let encoded = encode_etype_info2(&entries);
        assert_eq!(decode_etype_info2(&encoded).unwrap(), entries);
    }

    #[test]
    fn enc_ts_enc_round_trips() {
        let encoded = encode_enc_ts_enc(1_700_000_000, Some(123_456));
        assert_eq!(
            decode_enc_ts_enc(&encoded).unwrap(),
            (1_700_000_000, Some(123_456))
        );
    }

    #[test]
    fn krb_error_round_trips_and_carries_method_data() {
        let method_data = encode_pa_data(&[(PA_ETYPE_INFO2, encode_etype_info2(&[]))]);
        let err = KrbError {
            ctime: None,
            cusec: None,
            stime: 1_700_000_000,
            susec: 0,
            code: codes::KDC_ERR_PREAUTH_REQUIRED,
            crealm: None,
            cname: None,
            realm: "R".into(),
            sname: Principal::krbtgt("R"),
            e_text: Some("NEEDED".into()),
            e_data: Some(method_data),
            padata: Vec::new(),
        };
        let back = KrbError::decode(&err.encode()).unwrap();
        assert_eq!(back.code, codes::KDC_ERR_PREAUTH_REQUIRED);
        assert_eq!(back.sname, Principal::krbtgt("R"));
        assert_eq!(back.e_text.as_deref(), Some("NEEDED"));
        let md = back.method_data().unwrap();
        assert_eq!(md.len(), 1);
        assert_eq!(md[0].0, PA_ETYPE_INFO2);
    }
}
