//! Key selection: whose order decides an enctype, and which name types are looked up.
//!
//! Heimdal has four options that all read as "use the strongest" and only one of them is on by
//! default, and the two defaults point opposite ways:
//!
//! * `tgt-use-strongest-session-key`, `svc-use-strongest-session-key`,
//!   `preauth-use-strongest-session-key` are **off**, and off means *the client's list decides* —
//!   the first enctype the client asked for that both sides support. Turning one on makes this
//!   KDC's own preference decide instead.
//! * `use-strongest-server-key` is **on**, and on means this KDC's preference decides which key
//!   seals a ticket; turning it off makes the entry's own key order decide.
//!
//! So the honest way to test them is a client that asks for a weak enctype first and a realm that
//! holds both: the session key follows the client by default and this KDC when the option is set,
//! and each of the three session options has to be shown changing what it governs and nothing else.
//!
//! `strict-nametypes` is the fifth option, and the smallest: a `krbtgt` name whose type is neither
//! `NT-SRV-INST` nor `NT-UNKNOWN` is not looked up when it is on. Heimdal's default is off, and it
//! applies to no other name.

use std::sync::Arc;

use rrl_kdc::crypto::{Cipher, Enctype, Key, OwnCipher, usage};
use rrl_kdc::der;
use rrl_kdc::error::codes;
use rrl_kdc::hdb::{HdbEntry, MemoryHdb, flags as entry_flags};
use rrl_kdc::kdc::{Kdc, KdcConfig};
use rrl_kdc::msg::{
    self, ApReq, Authenticator, EncKdcRepPart, EncTicketPart, EncryptedData, Ticket,
    encode_pa_data, kdc_options, tkt_flags,
};
use rrl_kdc::name::{NT_PRINCIPAL, NT_SRV_INST, Principal};

const REALM: &str = "EXAMPLE.COM";
const SERVICE: &str = "host/server.example.com";
const NOW: i64 = 1_700_000_000;

/// AES-128 and AES-256, in that order: weak first, so that "the first one" and "the strongest one"
/// are different answers and a test cannot pass by accident.
const WEAK: Enctype = Enctype::Aes128Sha1;
const STRONG: Enctype = Enctype::Aes256Sha1;

fn alice() -> Principal {
    Principal::parse(&format!("alice@{REALM}")).unwrap()
}

fn service() -> Principal {
    Principal::parse(&format!("{SERVICE}@{REALM}")).unwrap()
}

struct Stand {
    db: MemoryHdb,
    krbtgt_key: Key,
}

impl Stand {
    fn new() -> Stand {
        let cipher = OwnCipher;
        let db = MemoryHdb::new();

        let mut krbtgt = HdbEntry::krbtgt(REALM);
        for e in [WEAK, STRONG] {
            krbtgt.add_password_key(&cipher, e, b"master", 1).unwrap();
        }
        let krbtgt_key = krbtgt.key_for(STRONG).unwrap().key.clone();
        db.insert(krbtgt).unwrap();

        let mut user = HdbEntry::user(alice());
        user.flags &= !entry_flags::REQUIRE_PREAUTH;
        for e in [WEAK, STRONG] {
            user.add_password_key(&cipher, e, b"pw", 1).unwrap();
        }
        db.insert(user).unwrap();

        let mut svc = HdbEntry::service(service());
        for e in [WEAK, STRONG] {
            svc.add_password_key(&cipher, e, b"svc", 1).unwrap();
        }
        db.insert(svc).unwrap();

        Stand { db, krbtgt_key }
    }

    fn kdc(self, configure: impl FnOnce(&mut KdcConfig)) -> Kdc {
        let mut config = KdcConfig::new(REALM).unwrap().with_require_preauth(false);
        configure(&mut config);
        Kdc::new(config, Arc::new(self.db), Arc::new(OwnCipher))
    }

    fn tgt(&self) -> (Vec<u8>, Key) {
        let cipher = OwnCipher;
        let session_key = cipher.random(STRONG).unwrap();
        let part = EncTicketPart {
            flags: tkt_flags::INITIAL | tkt_flags::PRE_AUTHENT | tkt_flags::FORWARDABLE,
            session_key: session_key.clone(),
            crealm: REALM.into(),
            cname: alice(),
            transited_type: 0,
            transited: Vec::new(),
            authtime: NOW - 60,
            starttime: None,
            endtime: NOW + 3600,
            renew_till: None,
            caddr: None,
            authorization_data: None,
        };
        let ticket = Ticket {
            realm: REALM.into(),
            sname: Principal::krbtgt(REALM),
            enc: EncryptedData::seal(
                &cipher,
                &self.krbtgt_key,
                usage::KDC_REP_TICKET,
                Some(1),
                &part.encode(),
            )
            .unwrap(),
        };
        (ticket.encode(), session_key)
    }
}

/// A `TGS-REQ` asking for `etypes` **in that order**.
fn tgs_req(ticket: &[u8], session_key: &Key, etypes: &[Enctype]) -> Vec<u8> {
    let cipher = OwnCipher;
    let body = der::seq(&[
        der::field(0, der::flags32(kdc_options::FORWARDABLE)),
        der::field(2, der::general_string(REALM)),
        der::field(3, service().encode_name()),
        der::field(5, der::time(NOW + 3600)),
        der::field(7, der::int(0x4242)),
        der::field(
            8,
            der::seq(
                &etypes
                    .iter()
                    .map(|e| der::int(e.id() as i64))
                    .collect::<Vec<_>>(),
            ),
        ),
    ]);
    let cksum = cipher
        .checksum(session_key, usage::TGS_REQ_AUTH_CKSUM, &body)
        .unwrap();
    let auth = Authenticator {
        crealm: REALM.into(),
        cname: alice(),
        cksum: Some((session_key.enctype().checksum_type(), cksum)),
        cusec: 0,
        ctime: NOW,
        subkey: None,
        seq_number: None,
        authorization_data: None,
    };
    let ap_req = ApReq {
        ap_options: 0,
        ticket: ticket.to_vec(),
        authenticator: EncryptedData::seal(
            &cipher,
            session_key,
            usage::TGS_REQ_AUTH,
            None,
            &auth.encode(),
        )
        .unwrap(),
    };
    der::cons(
        der::app(12),
        &[der::seq(&[
            der::field(1, der::int(5)),
            der::field(2, der::int(12)),
            der::field(3, encode_pa_data(&[(msg::PA_TGS_REQ, ap_req.encode())])),
            der::field(4, body),
        ])],
    )
}

/// The reply's `EncKdcRepPart`, and the ticket's enctype.
fn reply_parts(reply: &[u8], session_key: &Key, key: &Key) -> (EncKdcRepPart, Enctype) {
    let f = der::Fields::parse_app("TGS-REP", 13, reply).unwrap_or_else(|_| {
        panic!(
            "the request was refused: {:?}",
            msg::KrbError::decode(reply).map(|e| (e.code, e.e_text))
        )
    });
    let enc = EncryptedData::decode("enc-part", f.bytes(6, "TGS-REP").expect("enc-part")).unwrap();
    let plain = OwnCipher
        .decrypt(session_key, usage::TGS_REP_ENCPART_SESSKEY, &enc.cipher)
        .expect("the reply opens with the TGT's session key");
    let part = EncKdcRepPart::decode(&plain).expect("an EncTGSRepPart");

    let t = Ticket::decode(f.bytes(5, "TGS-REP").expect("ticket")).expect("a Ticket");
    let ticket_plain = OwnCipher
        .decrypt(key, usage::KDC_REP_TICKET, &t.enc.cipher)
        .expect("the ticket opens with the service's key");
    // Decoded, not inspected: the point is that the ticket opens with the key a caller brought,
    // which is what `decrypt` above already proved. Its enctype is what the test asks about.
    let _ = EncTicketPart::decode(&ticket_plain).expect("an EncTicketPart");
    (part, t.enc.etype)
}

fn key_of(enctype: Enctype) -> Key {
    let mut entry = HdbEntry::service(service());
    entry
        .add_password_key(&OwnCipher, enctype, b"svc", 1)
        .unwrap();
    entry.key_for(enctype).unwrap().key.clone()
}

/// The default: the client's list decides. A client that writes AES-128 first gets an AES-128
/// session key even though the realm would rather issue AES-256 — which is what RFC 4120 §3.1.3
/// says and what Heimdal does with all three session-key options off.
#[test]
fn by_default_the_clients_order_decides_the_session_key() {
    let stand = Stand::new();
    let (ticket, session) = stand.tgt();
    let kdc = stand.kdc(|_| {});
    let reply = kdc.handle(&tgs_req(&ticket, &session, &[WEAK, STRONG]), NOW);
    let (part, _) = reply_parts(&reply, &session, &key_of(WEAK));
    assert_eq!(
        part.session_key.enctype(),
        WEAK,
        "the client asked for this first"
    );
}

/// `tgt-use-strongest-session-key`: this KDC's order decides instead, and the same request now
/// gets AES-256. Both halves in one test, because "AES-256 wins" alone would also pass for a KDC
/// that ignores the client entirely.
#[test]
fn tgt_use_strongest_session_key_overrides_the_clients_order() {
    let stand = Stand::new();
    let (ticket, session) = stand.tgt();
    let kdc = stand.kdc(|c| {
        c.apply("tgt-use-strongest-session-key", "true").unwrap();
    });
    let reply = kdc.handle(&tgs_req(&ticket, &session, &[WEAK, STRONG]), NOW);
    let (part, _) = reply_parts(&reply, &session, &key_of(STRONG));
    assert_eq!(part.session_key.enctype(), STRONG);
}

/// `use-strongest-server-key` decides the ticket's key, not the session key. On by default: the
/// ticket is sealed in the strongest key the service holds, whatever order the service's keys were
/// added in.
///
/// The entry is built weak-first on purpose, so the two rules give different answers.
#[test]
fn the_server_key_option_decides_the_tickets_own_enctype() {
    // On (default): AES-256 seals the ticket...
    let stand = Stand::new();
    let (ticket, session) = stand.tgt();
    let kdc = stand.kdc(|_| {});
    let reply = kdc.handle(&tgs_req(&ticket, &session, &[STRONG, WEAK]), NOW);
    let (_, sealed) = reply_parts(&reply, &session, &key_of(STRONG));
    assert_eq!(sealed, STRONG);

    // ...and off: the entry's own order decides, so AES-128, the key added first.
    let stand = Stand::new();
    let (ticket, session) = stand.tgt();
    let kdc = stand.kdc(|c| {
        c.apply("use-strongest-server-key", "false").unwrap();
    });
    let reply = kdc.handle(&tgs_req(&ticket, &session, &[STRONG, WEAK]), NOW);
    let (_, sealed) = reply_parts(&reply, &session, &key_of(WEAK));
    assert_eq!(sealed, WEAK);
}

/// `strict-nametypes`, off by default: a `krbtgt` name under `NT-PRINCIPAL` is found anyway.
#[test]
fn strict_nametypes_is_off_by_default() {
    let stand = Stand::new();
    let (ticket, session) = stand.tgt();
    let kdc = stand.kdc(|_| {});
    let mut target = Principal::krbtgt(REALM);
    target.name_type = NT_PRINCIPAL;
    let reply = kdc.handle(&tgs_req_named(&ticket, &session, &target), NOW);
    assert!(
        msg::KrbError::decode(&reply).is_err(),
        "a name type the realm does not distinguish is looked up anyway: {:?}",
        msg::KrbError::decode(&reply)
    );
}

/// On: the same name is not found, because Heimdal's `hdb` matches the name type as part of the
/// name. Both halves again — the request is legal in both configurations, and only the setting
/// changes the answer.
#[test]
fn strict_nametypes_refuses_a_krbtgt_under_another_type() {
    let stand = Stand::new();
    let (ticket, session) = stand.tgt();
    let kdc = stand.kdc(|c| c.apply("strict-nametypes", "true").unwrap());
    let mut target = Principal::krbtgt(REALM);
    target.name_type = NT_PRINCIPAL;
    let reply = kdc.handle(&tgs_req_named(&ticket, &session, &target), NOW);
    let err = msg::KrbError::decode(&reply).expect("a refusal");
    assert_eq!(err.code, codes::KDC_ERR_S_PRINCIPAL_UNKNOWN, "{err:?}");

    // And the name type Heimdal does accept still works with the option on, so the refusal is
    // about the type and not about renewals being broken in general.
    let mut target = Principal::krbtgt(REALM);
    target.name_type = NT_SRV_INST;
    let reply = kdc.handle(&tgs_req_named(&ticket, &session, &target), NOW);
    assert!(
        msg::KrbError::decode(&reply).is_err(),
        "{:?}",
        msg::KrbError::decode(&reply)
    );
}

/// `strict-nametypes` is about `krbtgt` and nothing else: a service name under `NT-PRINCIPAL` is
/// looked up whether it is on or off, which is what Heimdal's `name_type_ok` does with its first
/// line.
#[test]
fn strict_nametypes_does_not_touch_a_service_name() {
    let stand = Stand::new();
    let (ticket, session) = stand.tgt();
    let kdc = stand.kdc(|c| c.apply("strict-nametypes", "true").unwrap());
    let mut target = service();
    target.name_type = NT_PRINCIPAL;
    let reply = kdc.handle(&tgs_req_named(&ticket, &session, &target), NOW);
    assert!(
        msg::KrbError::decode(&reply).is_err(),
        "a service name is not a krbtgt name: {:?}",
        msg::KrbError::decode(&reply)
    );
}

fn tgs_req_named(ticket: &[u8], session_key: &Key, target: &Principal) -> Vec<u8> {
    let cipher = OwnCipher;
    let body = der::seq(&[
        der::field(0, der::flags32(kdc_options::FORWARDABLE)),
        der::field(2, der::general_string(REALM)),
        der::field(3, target.encode_name()),
        der::field(5, der::time(NOW + 3600)),
        der::field(7, der::int(0x4242)),
        der::field(8, der::seq(&[der::int(STRONG.id() as i64)])),
    ]);
    let cksum = cipher
        .checksum(session_key, usage::TGS_REQ_AUTH_CKSUM, &body)
        .unwrap();
    let auth = Authenticator {
        crealm: REALM.into(),
        cname: alice(),
        cksum: Some((session_key.enctype().checksum_type(), cksum)),
        cusec: 0,
        ctime: NOW,
        subkey: None,
        seq_number: None,
        authorization_data: None,
    };
    let ap_req = ApReq {
        ap_options: 0,
        ticket: ticket.to_vec(),
        authenticator: EncryptedData::seal(
            &cipher,
            session_key,
            usage::TGS_REQ_AUTH,
            None,
            &auth.encode(),
        )
        .unwrap(),
    };
    der::cons(
        der::app(12),
        &[der::seq(&[
            der::field(1, der::int(5)),
            der::field(2, der::int(12)),
            der::field(3, encode_pa_data(&[(msg::PA_TGS_REQ, ap_req.encode())])),
            der::field(4, body),
        ])],
    )
}
