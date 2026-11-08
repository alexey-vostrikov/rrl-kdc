//! `KDC-REQ`, which is what a KDC reads: `AS-REQ` and `TGS-REQ` share the same
//! body, and the body is the only part whose exact octets matter for a
//! checksum (§5.4.1's `PA-TGS-REQ` authenticator covers it byte for byte).
//!
//! [`KdcReqBody::raw`] keeps those octets, because re-encoding a decoded body
//! is not the same thing: a client is allowed to order or pad nothing, but any
//! difference would break the checksum, so the KDC verifies over what arrived.

use crate::der::{self, Fields, Reader};
use crate::error::{Error, Result};
use crate::name::Principal;

use super::{AS_REQ, PVNO, TGS_REQ, decode_pa_data};

/// A `KDC-REQ`: an `AS-REQ` or a `TGS-REQ`.
#[derive(Clone, Debug)]
pub struct KdcReq {
    /// [`AS_REQ`] or [`TGS_REQ`].
    pub msg_type: i64,
    /// `PA-DATA`, in the order the client sent it.
    pub padata: Vec<(i32, Vec<u8>)>,
    /// The body.
    pub body: KdcReqBody,
    /// The exact octets of the `KDC-REQ-BODY` SEQUENCE, tag included — what a
    /// `PA-TGS-REQ` authenticator's checksum is computed over.
    pub raw_body: Vec<u8>,
}

/// `KDC-REQ-BODY ::= SEQUENCE { ... }`.
#[derive(Clone, Debug)]
pub struct KdcReqBody {
    /// `KDCOptions`.
    pub kdc_options: u32,
    /// The client, when the request names one.
    pub cname: Option<Principal>,
    /// The realm the request is for.
    pub realm: String,
    /// The service the ticket is wanted for.
    pub sname: Option<Principal>,
    /// `from` — when a postdated ticket should start.
    pub from: Option<i64>,
    /// `till` — when it should end. Zero means "as long as you allow".
    pub till: i64,
    /// `rtime` — the requested renewable lifetime.
    pub rtime: Option<i64>,
    /// The nonce to echo.
    pub nonce: u32,
    /// The requested enctypes, as numbers: a client may ask for ones this KDC
    /// does not implement, and that must not fail the whole request.
    pub etypes: Vec<i32>,
    /// `addresses`, kept as the `HostAddresses` SEQUENCE it arrived as.
    pub addresses: Option<Vec<u8>>,
    /// `enc-authorization-data`, kept encoded.
    pub enc_authorization_data: Option<Vec<u8>>,
    /// `additional-tickets`, kept encoded.
    pub additional_tickets: Option<Vec<u8>>,
}

impl KdcReq {
    /// Decodes a whole `[APPLICATION 10]` / `[APPLICATION 12]` request.
    ///
    /// The application tag decides which message this is: a `TGS-REQ` sent to
    /// the AS port is refused here rather than answered with something it did
    /// not ask for.
    pub fn decode(data: &[u8]) -> Result<Self> {
        let first = *data
            .first()
            .ok_or_else(|| Error::NotARequest("empty message".into()))?;
        let (app_tag, msg_type) = match first {
            0x6a => (10u8, AS_REQ),
            0x6c => (12u8, TGS_REQ),
            other => {
                return Err(Error::NotARequest(format!(
                    "application tag {other:#04x}; expected AS-REQ (0x6a) or TGS-REQ (0x6c)"
                )));
            }
        };
        let f = Fields::parse_app("KDC-REQ", app_tag, data)?;
        let pvno = f.int(1, "KDC-REQ")?;
        if pvno != PVNO {
            return Err(Error::Protocol(format!(
                "KDC-REQ pvno is {pvno}, RFC 4120 says 5"
            )));
        }
        let declared = f.int(2, "KDC-REQ")?;
        if declared != msg_type {
            return Err(Error::Protocol(format!(
                "KDC-REQ msg-type is {declared} but the application tag says {msg_type}"
            )));
        }
        let padata = match f.opt(3) {
            None => Vec::new(),
            Some(_) => {
                let mut r = Reader::new(f.get(3, "KDC-REQ")?);
                decode_pa_data("KDC-REQ", r.expect("KDC-REQ", der::SEQUENCE)?)?
            }
        };
        let raw_body = f.get(4, "KDC-REQ")?.to_vec();
        let mut r = Reader::new(&raw_body);
        let content = r.expect("KDC-REQ-BODY", der::SEQUENCE)?;
        Ok(KdcReq {
            msg_type,
            padata,
            body: KdcReqBody::decode(content)?,
            raw_body,
        })
    }

    /// The `PA-DATA` value of type `pa_type`, if the client sent one.
    pub fn padata(&self, pa_type: i32) -> Option<&[u8]> {
        self.padata
            .iter()
            .find(|(t, _)| *t == pa_type)
            .map(|(_, v)| v.as_slice())
    }
}

impl KdcReqBody {
    /// Decodes the content of a `KDC-REQ-BODY` SEQUENCE.
    pub fn decode(content: &[u8]) -> Result<Self> {
        let ctx = "KDC-REQ-BODY";
        let f = Fields::parse(ctx, content)?;
        let kdc_options = f.flags32(0, ctx)?;
        let realm = f.string(2, ctx)?;
        let cname = match f.opt(1) {
            None => None,
            Some(_) => Some(Principal::decode_field(&f, 1, ctx, &realm)?),
        };
        let sname = match f.opt(3) {
            None => None,
            Some(_) => Some(Principal::decode_field(&f, 3, ctx, &realm)?),
        };
        let from = f
            .opt(4)
            .map(|_| super::as_time(ctx, f.get(4, ctx).unwrap()))
            .transpose()?;
        let till = super::as_time(ctx, f.get(5, ctx)?)?;
        let rtime = f
            .opt(6)
            .map(|_| super::as_time(ctx, f.get(6, ctx).unwrap()))
            .transpose()?;
        let nonce = f.u32(7, ctx)?;
        let mut r = Reader::new(f.get(8, ctx)?);
        let mut s = Reader::new(r.expect(ctx, der::SEQUENCE)?);
        let mut etypes = Vec::new();
        while !s.is_empty() {
            etypes.push(der::as_int(ctx, s.expect(ctx, der::INTEGER)?)? as i32);
        }
        Ok(KdcReqBody {
            kdc_options,
            cname,
            realm,
            sname,
            from,
            till,
            rtime,
            nonce,
            etypes,
            addresses: f.get(9, ctx).ok().map(<[u8]>::to_vec),
            enc_authorization_data: f.opt(10).map(<[u8]>::to_vec),
            additional_tickets: f.opt(11).map(<[u8]>::to_vec),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::msg::{PA_ENC_TIMESTAMP, encode_pa_data, kdc_options};

    /// An AS-REQ built the way a client builds one: the shape matters, because
    /// the round trip is what the acceptance test depends on.
    fn as_req_bytes() -> Vec<u8> {
        let alice = Principal::parse("alice@R").unwrap();
        let body = der::seq(&[
            der::field(
                0,
                der::flags32(kdc_options::FORWARDABLE | kdc_options::RENEWABLE),
            ),
            der::field(1, alice.encode_name()),
            der::field(2, der::general_string("R")),
            der::field(3, Principal::krbtgt("R").encode_name()),
            der::field(5, der::time(1_700_003_600)),
            der::field(7, der::int(0x1234_5678)),
            der::field(8, der::seq(&[der::int(18), der::int(17)])),
        ]);
        der::cons(
            der::app(10),
            &[der::seq(&[
                der::field(1, der::int(5)),
                der::field(2, der::int(10)),
                der::field(3, encode_pa_data(&[(PA_ENC_TIMESTAMP, b"opaque".to_vec())])),
                der::field(4, body),
            ])],
        )
    }

    #[test]
    fn decodes_an_as_req_field_by_field() {
        let req = KdcReq::decode(&as_req_bytes()).unwrap();
        assert_eq!(req.msg_type, AS_REQ);
        assert_eq!(req.body.realm, "R");
        assert_eq!(
            req.body.cname.as_ref().unwrap().components,
            ["alice"],
            "the client must survive decoding"
        );
        assert_eq!(req.body.sname.as_ref().unwrap(), &Principal::krbtgt("R"));
        assert_eq!(req.body.nonce, 0x1234_5678);
        assert_eq!(req.body.etypes, vec![18, 17]);
        assert_eq!(req.body.till, 1_700_003_600);
        assert_ne!(req.body.kdc_options & kdc_options::FORWARDABLE, 0);
        assert_eq!(req.padata(PA_ENC_TIMESTAMP), Some(&b"opaque"[..]));
        assert!(req.padata(19).is_none());
        // The body's own octets are kept, for the TGS checksum later.
        assert_eq!(req.raw_body[0], der::SEQUENCE);
    }

    #[test]
    fn a_tgs_req_is_recognised_as_one() {
        let body = der::seq(&[
            der::field(0, der::flags32(0)),
            der::field(2, der::general_string("R")),
            der::field(3, Principal::krbtgt("R").encode_name()),
            der::field(5, der::time(1_700_003_600)),
            der::field(7, der::int(1)),
            der::field(8, der::seq(&[der::int(18)])),
        ]);
        let bytes = der::cons(
            der::app(12),
            &[der::seq(&[
                der::field(1, der::int(5)),
                der::field(2, der::int(12)),
                der::field(4, body),
            ])],
        );
        assert_eq!(KdcReq::decode(&bytes).unwrap().msg_type, TGS_REQ);
    }

    #[test]
    fn refuses_what_is_not_a_request() {
        assert!(KdcReq::decode(&[]).is_err());
        assert!(
            KdcReq::decode(&[0x6e, 0x00]).is_err(),
            "KRB-ERROR is not a request"
        );
        // pvno 4: not Kerberos 5.
        let bad = der::cons(
            der::app(10),
            &[der::seq(&[
                der::field(1, der::int(4)),
                der::field(2, der::int(10)),
            ])],
        );
        assert!(KdcReq::decode(&bad).is_err());
        // An application tag of AS-REQ carrying msg-type 12.
        let bad = der::cons(
            der::app(10),
            &[der::seq(&[
                der::field(1, der::int(5)),
                der::field(2, der::int(12)),
            ])],
        );
        assert!(KdcReq::decode(&bad).is_err());
    }

    #[test]
    fn an_unknown_enctype_in_the_list_is_not_fatal() {
        let body = der::seq(&[
            der::field(0, der::flags32(0)),
            der::field(2, der::general_string("R")),
            der::field(5, der::time(1_700_003_600)),
            der::field(7, der::int(1)),
            // 23 is RC4, which this KDC does not implement; 18 is AES-256.
            der::field(8, der::seq(&[der::int(23), der::int(18)])),
        ]);
        let bytes = der::cons(
            der::app(10),
            &[der::seq(&[
                der::field(1, der::int(5)),
                der::field(2, der::int(10)),
                der::field(4, body),
            ])],
        );
        assert_eq!(KdcReq::decode(&bytes).unwrap().body.etypes, vec![23, 18]);
    }
}
