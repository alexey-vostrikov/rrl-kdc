//! PAC policy: who decides whether a ticket carries one.
//!
//! Heimdal's `_kdc_include_pac_p` reads five things in an order that is not the obvious one, and
//! any of them can be the one that decides. What these tests are for is that each setting is shown
//! *changing the answer* on the same realm — a matrix where the configurations produce different
//! outcomes, so that a setting wired to nothing is visible rather than merely absent.
//!
//! `require_pac` is the one people get wrong from the name: it does not make the KDC refuse to
//! issue a ticket it cannot put a PAC in (Heimdal issues one without, and so does this). It makes a
//! *presented* TGT without a PAC count as revoked, which is a statement about what this realm
//! would have issued.

use std::sync::Arc;

use rrl_kdc::crypto::{Cipher, Enctype, Key, OwnCipher, usage};
use rrl_kdc::der;
use rrl_kdc::error::codes;
use rrl_kdc::hdb::{Hdb, HdbEntry, MemoryHdb, flags as entry_flags};
use rrl_kdc::kdc::logon_info::{Identity, PacIdentities, Sid};
use rrl_kdc::kdc::{Kdc, KdcConfig};
use rrl_kdc::msg::{
    self, ApReq, Authenticator, EncTicketPart, EncryptedData, Ticket, encode_pa_data, kdc_options,
    tkt_flags,
};
use rrl_kdc::name::Principal;

const REALM: &str = "EXAMPLE.COM";
const SERVICE: &str = "host/server.example.com";
const NOW: i64 = 1_700_000_000;

fn alice() -> Principal {
    Principal::parse(&format!("alice@{REALM}")).unwrap()
}

fn service() -> Principal {
    Principal::parse(&format!("{SERVICE}@{REALM}")).unwrap()
}

/// A directory that knows one account, so that a realm can issue PACs at all.
struct Directory;

impl PacIdentities for Directory {
    fn identity(
        &self,
        principal: &Principal,
    ) -> rrl_kdc::kdc::logon_info::PacResult<Option<Identity>> {
        Ok((*principal == alice()).then(|| Identity {
            domain: Sid::parse("S-1-5-21-100-200-300").unwrap(),
            domain_name: "EXAMPLE".into(),
            logon_server: "DC1".into(),
            user_rid: 1105,
            primary_group: 513,
            groups: vec![(513, 7)],
            full_name: "Alice Example".into(),
            user_account_control: 0x200,
            extra_sids: Vec::new(),
        }))
    }
}

/// A realm: `krbtgt`, `alice`, the service, and whichever extra entries a test adds.
struct Stand {
    db: MemoryHdb,
    krbtgt_key: Key,
}

impl Stand {
    fn new() -> Stand {
        let cipher = OwnCipher;
        let db = MemoryHdb::new();

        let mut krbtgt = HdbEntry::krbtgt(REALM);
        krbtgt
            .add_password_key(&cipher, Enctype::Aes256Sha1, b"master", 1)
            .unwrap();
        let krbtgt_key = krbtgt.key_for(Enctype::Aes256Sha1).unwrap().key.clone();
        db.insert(krbtgt).unwrap();

        let mut user = HdbEntry::user(alice());
        user.flags &= !entry_flags::REQUIRE_PREAUTH;
        user.add_password_key(&cipher, Enctype::Aes256Sha1, b"pw", 1)
            .unwrap();
        db.insert(user).unwrap();

        let mut svc = HdbEntry::service(service());
        svc.add_password_key(&cipher, Enctype::Aes256Sha1, b"svc", 1)
            .unwrap();
        db.insert(svc).unwrap();

        Stand { db, krbtgt_key }
    }

    fn flag(self, principal: Principal, flags: u32) -> Stand {
        let mut entry = self.db.fetch(&principal).unwrap().expect("the entry");
        entry.flags |= flags;
        self.db.insert(entry).unwrap();
        self
    }

    /// A cross-realm ticket-granting ticket's entry, which is what `no-auth-data-reqd` is for.
    fn with_cross_realm(self, other: &str, flags: u32) -> Stand {
        let principal = Principal::parse(&format!("krbtgt/{other}@{REALM}")).unwrap();
        let mut entry = HdbEntry::service(principal.clone());
        entry.flags |= flags;
        entry
            .add_password_key(&OwnCipher, Enctype::Aes256Sha1, b"xrealm", 1)
            .unwrap();
        self.db.insert(entry).unwrap();
        self
    }

    /// The KDC over this stand, with `configure` applied to the default configuration.
    fn kdc(self, configure: impl FnOnce(&mut KdcConfig)) -> Kdc {
        let mut config = KdcConfig::new(REALM).unwrap().with_require_preauth(false);
        configure(&mut config);
        Kdc::new(config, Arc::new(self.db), Arc::new(OwnCipher)).with_pac(Arc::new(Directory))
    }

    /// A TGT as the AS exchange would have issued it, with or without authorization data.
    ///
    /// The PAC inside is not a valid one — nothing here verifies it, and `require_pac` asks only
    /// whether authorization data carries a PAC at all. Building a signed one would need this
    /// test to reproduce the whole PAC signing path, which is what `pac_ticket.rs` is for.
    fn tgt(&self, with_pac: bool) -> (Vec<u8>, Key) {
        let cipher = OwnCipher;
        let session_key = cipher.random(Enctype::Aes256Sha1).unwrap();
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
            authorization_data: with_pac
                .then(|| rrl_kdc::kdc::pac::authorization_data(b"a PAC this test never verifies")),
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

/// A `TGS-REQ` for `target` presenting `ticket`.
fn tgs_req(
    ticket: &[u8],
    session_key: &Key,
    target: &Principal,
    extra: &[(i32, Vec<u8>)],
) -> Vec<u8> {
    let cipher = OwnCipher;
    let body = der::seq(&[
        der::field(0, der::flags32(kdc_options::FORWARDABLE)),
        der::field(2, der::general_string(REALM)),
        der::field(3, target.encode_name()),
        der::field(5, der::time(NOW + 3600)),
        der::field(7, der::int(0x4242)),
        der::field(8, der::seq(&[der::int(18)])),
    ]);
    let cksum = cipher
        .checksum(session_key, usage::TGS_REQ_AUTH_CKSUM, &body)
        .unwrap();
    let auth = Authenticator {
        crealm: REALM.into(),
        cname: alice(),
        cksum: Some((Enctype::Aes256Sha1.checksum_type(), cksum)),
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
    let mut padata = vec![(msg::PA_TGS_REQ, ap_req.encode())];
    padata.extend_from_slice(extra);
    der::cons(
        der::app(12),
        &[der::seq(&[
            der::field(1, der::int(5)),
            der::field(2, der::int(12)),
            der::field(3, encode_pa_data(&padata)),
            der::field(4, body),
        ])],
    )
}

/// The ticket from a reply, opened with `key`.
fn ticket_part(reply: &[u8], key: &Key) -> EncTicketPart {
    let f = der::Fields::parse_app("TGS-REP", 13, reply).unwrap_or_else(|_| {
        panic!(
            "the request was refused: {:?}",
            msg::KrbError::decode(reply).map(|e| (e.code, e.e_text))
        )
    });
    let t = Ticket::decode(f.bytes(5, "TGS-REP").expect("ticket")).expect("a Ticket");
    let plain = OwnCipher
        .decrypt(key, usage::KDC_REP_TICKET, &t.enc.cipher)
        .expect("the ticket opens with the service's key");
    EncTicketPart::decode(&plain).expect("an EncTicketPart")
}

/// The service's key, taken from an entry built the same way the stand builds it: the salt is the
/// entry's, not a string this test re-derives, so a change to how a salt is computed cannot make
/// these tests pass for the wrong reason.
fn service_key() -> Key {
    let mut entry = HdbEntry::service(service());
    entry
        .add_password_key(&OwnCipher, Enctype::Aes256Sha1, b"svc", 1)
        .unwrap();
    entry.key_for(Enctype::Aes256Sha1).unwrap().key.clone()
}

/// A service ticket for `service()`, under whichever configuration `configure` sets.
fn service_ticket(
    configure: impl FnOnce(&mut KdcConfig),
    extra: &[(i32, Vec<u8>)],
) -> EncTicketPart {
    let stand = Stand::new();
    let (ticket, session) = stand.tgt(true);
    let kdc = stand.kdc(configure);
    let reply = kdc.handle(&tgs_req(&ticket, &session, &service(), extra), NOW);
    ticket_part(&reply, &service_key())
}

/// The default: a realm with a directory issues a PAC, and a client that never mentions
/// `PA-PAC-REQUEST` gets one — `KRB5_PAC_WAS_GIVEN_IMPLICITLY`, the only default that keeps every
/// existing client getting the tickets it always got.
#[test]
fn a_pac_is_issued_by_default() {
    let part = service_ticket(|_| {}, &[]);
    assert!(part.authorization_data.is_some(), "no PAC by default");
}

/// `disable-pac`: the realm issues none at all.
#[test]
fn disable_pac_takes_the_pac_away() {
    let part = service_ticket(|c| c.apply("disable-pac", "true").unwrap(), &[]);
    assert!(part.authorization_data.is_none());
}

/// `auth-data-reqd` on the service beats `disable-pac`: the entry is the more specific statement,
/// which is the whole point of the flag — one service in a realm that does not issue PACs still
/// needs one.
#[test]
fn auth_data_reqd_on_the_service_beats_disable_pac() {
    let stand = Stand::new().flag(service(), entry_flags::AUTH_DATA_REQD);
    let (ticket, session) = stand.tgt(true);
    let kdc = stand.kdc(|c| c.apply("disable-pac", "true").unwrap());
    let reply = kdc.handle(&tgs_req(&ticket, &session, &service(), &[]), NOW);
    assert!(
        ticket_part(&reply, &service_key())
            .authorization_data
            .is_some(),
        "the entry asked for a PAC and the realm's default must not override it"
    );
}

/// `no-auth-data-reqd` beats `auth-data-reqd`: Heimdal checks it first, and an entry carrying both
/// is a configuration where the administrator said "no" last.
#[test]
fn no_auth_data_reqd_beats_auth_data_reqd() {
    let stand = Stand::new().flag(
        service(),
        entry_flags::NO_AUTH_DATA_REQD | entry_flags::AUTH_DATA_REQD,
    );
    let (ticket, session) = stand.tgt(true);
    let kdc = stand.kdc(|_| {});
    let reply = kdc.handle(&tgs_req(&ticket, &session, &service(), &[]), NOW);
    assert!(
        ticket_part(&reply, &service_key())
            .authorization_data
            .is_none()
    );
}

/// A client that says `include-pac = FALSE` gets no PAC, even from a realm that issues them: the
/// request is the most specific statement of all, and it can only ever take one away.
#[test]
fn a_client_may_ask_for_no_pac() {
    let stand = Stand::new();
    let (ticket, session) = stand.tgt(true);
    let kdc = stand.kdc(|_| {});
    let reject = der::seq(&[der::field(0, der::tlv(0x01, &[0x00]))]);
    let reply = kdc.handle(
        &tgs_req(
            &ticket,
            &session,
            &service(),
            &[(msg::PA_PAC_REQUEST, reject)],
        ),
        NOW,
    );
    assert!(
        ticket_part(&reply, &service_key())
            .authorization_data
            .is_none()
    );
}

/// `require-pac`: a TGT that carries no PAC is refused as revoked — and the same TGT, against the
/// same realm without the setting, is accepted. Both halves, because a test that only checked the
/// refusal would pass for a KDC that refused everything.
#[test]
fn require_pac_refuses_a_tgt_that_carries_none() {
    let stand = Stand::new();
    let (bare, session) = stand.tgt(false);
    let kdc = stand.kdc(|_| {});
    let reply = kdc.handle(&tgs_req(&bare, &session, &service(), &[]), NOW);
    assert!(
        msg::KrbError::decode(&reply).is_err(),
        "a realm without require-pac accepts it"
    );

    let stand = Stand::new();
    let (bare, session) = stand.tgt(false);
    let kdc = stand.kdc(|c| c.apply("require-pac", "true").unwrap());
    let reply = kdc.handle(&tgs_req(&bare, &session, &service(), &[]), NOW);
    let err = msg::KrbError::decode(&reply).expect("a refusal");
    assert_eq!(err.code, codes::KDC_ERR_TGT_REVOKED, "{err:?}");

    // And a TGT that does carry one passes, so the check is about the PAC and not the request.
    let stand = Stand::new();
    let (with_pac, session) = stand.tgt(true);
    let kdc = stand.kdc(|c| c.apply("require-pac", "true").unwrap());
    let reply = kdc.handle(&tgs_req(&with_pac, &session, &service(), &[]), NOW);
    assert!(
        msg::KrbError::decode(&reply).is_err(),
        "{:?}",
        msg::KrbError::decode(&reply)
    );
}

/// The root TGT carries a PAC even when its `krbtgt` entry says `no-auth-data-reqd`: a realm whose
/// ticket-granting ticket has no authorization data has nothing to revoke, and the entry flag is
/// for the cross-realm case, which the next test covers.
#[test]
fn the_root_tgt_keeps_its_pac() {
    let stand = Stand::new().flag(Principal::krbtgt(REALM), entry_flags::NO_AUTH_DATA_REQD);
    let krbtgt_key = stand.krbtgt_key.clone();
    let kdc = stand.kdc(|_| {});
    let reply = kdc.handle(
        &der::cons(
            der::app(10),
            &[der::seq(&[
                der::field(1, der::int(5)),
                der::field(2, der::int(10)),
                der::field(
                    3,
                    encode_pa_data(&[(msg::PA_ENC_TIMESTAMP, enc_timestamp())]),
                ),
                der::field(
                    4,
                    der::seq(&[
                        der::field(0, der::flags32(kdc_options::FORWARDABLE)),
                        der::field(1, alice().encode_name()),
                        der::field(2, der::general_string(REALM)),
                        der::field(3, Principal::krbtgt(REALM).encode_name()),
                        der::field(5, der::time(NOW + 3600)),
                        der::field(7, der::int(0x1234)),
                        der::field(8, der::seq(&[der::int(18)])),
                    ]),
                ),
            ])],
        ),
        NOW,
    );
    let f = der::Fields::parse_app("AS-REP", 11, &reply).unwrap_or_else(|_| {
        panic!(
            "the request was refused: {:?}",
            msg::KrbError::decode(&reply).map(|e| (e.code, e.e_text))
        )
    });
    let t = Ticket::decode(f.bytes(5, "AS-REP").expect("ticket")).expect("a Ticket");
    let plain = OwnCipher
        .decrypt(&krbtgt_key, usage::KDC_REP_TICKET, &t.enc.cipher)
        .expect("the TGT opens with krbtgt's key");
    let part = EncTicketPart::decode(&plain).expect("an EncTicketPart");
    assert!(
        part.authorization_data.is_some(),
        "the root TGT must carry a PAC whatever its entry says"
    );
}

/// A cross-realm `krbtgt/OTHER@HERE` with `no-auth-data-reqd` carries none: the PAC this realm
/// built may not be one the other realm can verify, and the entry is how an operator says so.
#[test]
fn a_cross_realm_tgt_honours_no_auth_data_reqd() {
    let stand = Stand::new().with_cross_realm("OTHER.REALM", entry_flags::NO_AUTH_DATA_REQD);
    let (ticket, session) = stand.tgt(true);
    let kdc = stand.kdc(|_| {});
    let target = Principal::parse(&format!("krbtgt/OTHER.REALM@{REALM}")).unwrap();
    let reply = kdc.handle(&tgs_req(&ticket, &session, &target, &[]), NOW);
    // The same entry the stand writes, so the salt is the entry's rather than a string derived
    // again here.
    let mut entry =
        HdbEntry::service(Principal::parse(&format!("krbtgt/OTHER.REALM@{REALM}")).unwrap());
    entry
        .add_password_key(&OwnCipher, Enctype::Aes256Sha1, b"xrealm", 1)
        .unwrap();
    let key = entry.key_for(Enctype::Aes256Sha1).unwrap().key.clone();
    assert!(ticket_part(&reply, &key).authorization_data.is_none());
}

fn enc_timestamp() -> Vec<u8> {
    let key = OwnCipher
        .s2k(
            Enctype::Aes256Sha1,
            b"pw",
            format!("{REALM}alice").as_bytes(),
            None,
        )
        .unwrap();
    EncryptedData::seal(
        &OwnCipher,
        &key,
        usage::AS_REQ_PA_ENC_TS,
        None,
        &rrl_kdc::msg::encode_enc_ts_enc(NOW, None),
    )
    .unwrap()
    .encode()
}
