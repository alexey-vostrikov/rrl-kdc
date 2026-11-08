//! The stand the TGS tests share: a realm, a TGT built with the knobs each case
//! needs, and the encoders that put a request on the wire.
//!
//! A TGT is built here rather than obtained from the AS exchange because each
//! case needs a *different* one — expired, not yet valid, invalid, renewable with
//! a short `renew-till` — and building it directly is the only way to hold those
//! knobs. The AS exchange has its own tests; these files are about what the TGS
//! engine does with the evidence it is handed.

#![allow(dead_code)] // each test file uses a different part of this

use std::sync::Arc;

use rust_heimdal_kdc::crypto::{Cipher, Enctype, Key, OwnCipher, usage};
use rust_heimdal_kdc::der;
use rust_heimdal_kdc::hdb::{HdbEntry, MemoryHdb};
use rust_heimdal_kdc::kdc::{Kdc, KdcConfig};
use rust_heimdal_kdc::msg::{
    self, ApReq, Authenticator, EncKdcRepPart, EncTicketPart, EncryptedData, Ticket,
    encode_pa_data, kdc_options,
};
use rust_heimdal_kdc::name::Principal;

pub const REALM: &str = "EXAMPLE.COM";
pub const SERVICE: &str = "host/server.example.com";
pub const NOW: i64 = 1_700_000_000;

pub fn alice() -> Principal {
    Principal::parse(&format!("alice@{REALM}")).unwrap()
}

pub fn service() -> Principal {
    Principal::parse(&format!("{SERVICE}@{REALM}")).unwrap()
}

/// The realm, and the `krbtgt` key the test TGTs are sealed with.
pub fn realm() -> (MemoryHdb, Key) {
    let cipher = OwnCipher;
    let db = MemoryHdb::new();
    let mut krbtgt = HdbEntry::krbtgt(REALM);
    krbtgt
        .add_password_key(&cipher, Enctype::Aes256Sha1, b"master", 1)
        .unwrap();
    let krbtgt_key = krbtgt.key_for(Enctype::Aes256Sha1).unwrap().key.clone();
    db.insert(krbtgt).unwrap();

    let mut alice_entry = HdbEntry::user(alice());
    alice_entry
        .add_password_key(&cipher, Enctype::Aes256Sha1, b"pw", 1)
        .unwrap();
    db.insert(alice_entry).unwrap();

    let mut service_entry = HdbEntry::service(service());
    service_entry
        .add_password_key(&cipher, Enctype::Aes256Sha1, b"svc", 1)
        .unwrap();
    db.insert(service_entry).unwrap();
    (db, krbtgt_key)
}

pub fn kdc() -> Kdc {
    let (db, _) = realm();
    Kdc::new(
        KdcConfig::new(REALM).unwrap(),
        Arc::new(db),
        Arc::new(OwnCipher),
    )
}

/// A TGT as the AS exchange would have issued it, with the knobs these files
/// need.
pub struct Tgt {
    pub ticket: Vec<u8>,
    pub session_key: Key,
}

/// Builds a TGT: `flags`, validity window, and an optional `renew-till`.
pub fn tgt(
    krbtgt_key: &Key,
    cname: &Principal,
    endtime: i64,
    starttime: Option<i64>,
    flags: u32,
) -> Tgt {
    tgt_with(krbtgt_key, cname, endtime, starttime, flags, None)
}

/// The same, with `renew-till`.
pub fn tgt_with(
    krbtgt_key: &Key,
    cname: &Principal,
    endtime: i64,
    starttime: Option<i64>,
    flags: u32,
    renew_till: Option<i64>,
) -> Tgt {
    let cipher = OwnCipher;
    let session_key = cipher.random(Enctype::Aes256Sha1).unwrap();
    let part = EncTicketPart {
        flags,
        session_key: session_key.clone(),
        crealm: cname.realm.clone(),
        cname: cname.clone(),
        transited_type: 0,
        transited: Vec::new(),
        authtime: NOW - 60,
        starttime,
        endtime,
        renew_till,
        caddr: None,
        authorization_data: None,
    };
    let ticket = Ticket {
        realm: REALM.into(),
        sname: Principal::krbtgt(REALM),
        enc: EncryptedData::seal(
            &cipher,
            krbtgt_key,
            usage::KDC_REP_TICKET,
            Some(1),
            &part.encode(),
        )
        .unwrap(),
    };
    Tgt {
        ticket: ticket.encode(),
        session_key,
    }
}

/// What a test can corrupt about the request it builds.
pub struct Knobs {
    /// The name in the authenticator, when it should differ from the ticket's.
    pub authenticator_cname: Option<Principal>,
    /// The `ctime` in the authenticator.
    pub authenticator_ctime: i64,
    /// Corrupt the checksum after the body is built.
    pub break_checksum: bool,
    /// Omit `PA-TGS-REQ` entirely.
    pub no_evidence: bool,
    /// Ask for a service other than [`service`]; `Some(krbtgt)` is a renewal.
    pub target: Option<Principal>,
    /// Extra `KDCOptions` for the request.
    pub options: u32,
    /// The `till` the client asks for.
    pub till: Option<i64>,
    /// The `rtime` the client asks for.
    pub rtime: Option<i64>,
}

impl Default for Knobs {
    fn default() -> Self {
        Knobs {
            authenticator_cname: None,
            authenticator_ctime: NOW,
            break_checksum: false,
            no_evidence: false,
            target: None,
            options: kdc_options::FORWARDABLE,
            till: None,
            rtime: None,
        }
    }
}

impl Knobs {
    /// A renewal: the TGT's own server, with `RENEW`.
    pub fn renew() -> Self {
        Knobs {
            target: Some(Principal::krbtgt(REALM)),
            options: kdc_options::RENEW,
            ..Knobs::default()
        }
    }

    /// A validation: the TGT's own server, with `VALIDATE`.
    pub fn validate() -> Self {
        Knobs {
            target: Some(Principal::krbtgt(REALM)),
            options: kdc_options::VALIDATE,
            ..Knobs::default()
        }
    }
}

/// A `TGS-REQ` presenting `tgt`, built as a client builds one.
pub fn tgs_req(tgt: &Tgt, knobs: Knobs) -> Vec<u8> {
    let cipher = OwnCipher;
    let target = knobs.target.clone().unwrap_or_else(service);
    let mut body_parts = vec![
        der::field(0, der::flags32(knobs.options)),
        der::field(2, der::general_string(REALM)),
        der::field(3, target.encode_name()),
        der::field(5, der::time(knobs.till.unwrap_or(NOW + 3600))),
        der::field(7, der::int(0x4242)),
        der::field(8, der::seq(&[der::int(18)])),
    ];
    if let Some(rtime) = knobs.rtime {
        body_parts.insert(4, der::field(6, der::time(rtime)));
    }
    let body = der::seq(&body_parts);

    let mut padata = Vec::new();
    if !knobs.no_evidence {
        // The checksum is over the body's exact octets, tag included — which is
        // what the KDC verifies and why the body is built before the
        // authenticator.
        let mut cksum = cipher
            .checksum(&tgt.session_key, usage::TGS_REQ_AUTH_CKSUM, &body)
            .unwrap();
        if knobs.break_checksum {
            cksum[0] ^= 0xff;
        }
        let auth = Authenticator {
            crealm: REALM.into(),
            cname: knobs.authenticator_cname.clone().unwrap_or_else(alice),
            cksum: Some((Enctype::Aes256Sha1.checksum_type(), cksum)),
            cusec: 0,
            ctime: knobs.authenticator_ctime,
            subkey: None,
            seq_number: None,
            authorization_data: None,
        };
        let ap_req = ApReq {
            ap_options: 0,
            ticket: tgt.ticket.clone(),
            authenticator: EncryptedData::seal(
                &cipher,
                &tgt.session_key,
                usage::TGS_REQ_AUTH,
                None,
                &auth.encode(),
            )
            .unwrap(),
        };
        padata.push((msg::PA_TGS_REQ, ap_req.encode()));
    }
    let mut parts = vec![der::field(1, der::int(5)), der::field(2, der::int(12))];
    if !padata.is_empty() {
        parts.push(der::field(3, encode_pa_data(&padata)));
    }
    parts.push(der::field(4, body));
    der::cons(der::app(12), &[der::seq(&parts)])
}

/// The code of a refusal; panics when the reply was not one.
pub fn code_of(reply: &[u8]) -> i32 {
    msg::KrbError::decode(reply)
        .unwrap_or_else(|e| panic!("expected KRB-ERROR, got something else: {e}"))
        .code
}

/// Reads the `EncTGSRepPart` out of a `TGS-REP`, decrypting with `key` and
/// `usage` — what a client does.
pub fn read_reply(reply: &[u8], key: &Key, usage: u32) -> EncKdcRepPart {
    let f = rust_heimdal_kdc::der::Fields::parse_app("TGS-REP", 13, reply).unwrap_or_else(|_| {
        panic!(
            "the request was refused: {:?}",
            msg::KrbError::decode(reply).map(|e| (e.code, e.e_text))
        )
    });
    let mut r = rust_heimdal_kdc::der::Reader::new(f.get(6, "TGS-REP").unwrap());
    let content = r.expect("enc-part", der::SEQUENCE).unwrap();
    let enc = EncryptedData::decode_content("enc-part", content).unwrap();
    let plain = OwnCipher
        .decrypt(key, usage, &enc.cipher)
        .expect("the reply must decrypt in the key the exchange says it used");
    EncKdcRepPart::decode(&plain).expect("the encrypted part must be an EncTGSRepPart")
}
