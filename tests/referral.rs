//! Referrals (RFC 6806 §8): what a KDC answers when the name belongs to another realm.
//!
//! "If the canonicalize flag in the KDC options is set and the KDC doesn't find the principal
//! locally ... the KDC MAY return a cross-realm ticket-granting ticket to the next hop on the trust
//! path towards a realm that may be able to resolve the principal name." So the reply is not an
//! error and not a special message: it is an ordinary TGS-REP whose `sname` is `krbtgt/HOP@OURS`,
//! sealed in the key the two realms share, and the client walks the rest of the chain.
//!
//! These cases hold one KDC of `ADMIN.EXAMPLE.COM` and vary what it trusts, which is the whole of
//! the decision: the target's own realm when a direct trust exists, its ancestor when only the
//! parent is trusted, and nothing when the hierarchy cannot carry the request.

use std::sync::Arc;

use rrl_kdc::crypto::{Cipher, Enctype, Key, OwnCipher, usage};
use rrl_kdc::der;
use rrl_kdc::hdb::{HdbEntry, MemoryHdb};
use rrl_kdc::kdc::{Kdc, KdcConfig};
use rrl_kdc::msg::{
    self, ApReq, Authenticator, EncKdcRepPart, EncTicketPart, EncryptedData, Ticket,
    encode_pa_data, kdc_options, tkt_flags,
};
use rrl_kdc::name::Principal;

const ADMIN: &str = "ADMIN.EXAMPLE.COM";
const PARENT: &str = "EXAMPLE.COM";
const DEV: &str = "DEV.EXAMPLE.COM";
const NOW: i64 = 1_700_000_000;

fn alice() -> Principal {
    Principal::parse(&format!("alice@{ADMIN}")).unwrap()
}

fn srv(components: &[&str], realm: &str) -> Principal {
    Principal {
        name_type: rrl_kdc::name::NT_SRV_INST,
        components: components.iter().map(|c| (*c).to_owned()).collect(),
        realm: realm.to_owned(),
    }
}

/// `krbtgt/<realm>` inside this realm — the entry a trust is made of.
fn trust(realm: &str) -> Principal {
    srv(&["krbtgt", realm], ADMIN)
}

/// The realm's own database, with a trust entry for each realm named.
///
/// One key for every trust keeps the test short and costs nothing: what is under test is which
/// entry was chosen, and the reply is opened with that entry's key either way.
fn db_trusting(trusted: &[&str]) -> (MemoryHdb, Key, Key) {
    let cipher = OwnCipher;
    let db = MemoryHdb::new();

    let mut krbtgt = HdbEntry::krbtgt(ADMIN);
    krbtgt
        .add_password_key(&cipher, Enctype::Aes256Sha1, b"master", 1)
        .unwrap();
    let krbtgt_key = krbtgt.key_for(Enctype::Aes256Sha1).unwrap().key.clone();
    db.insert(krbtgt).unwrap();

    let mut user = HdbEntry::user(alice());
    user.add_password_key(&cipher, Enctype::Aes256Sha1, b"pw", 1)
        .unwrap();
    db.insert(user).unwrap();

    let shared = cipher
        .s2k(
            Enctype::Aes256Sha1,
            b"trust",
            b"shared between realms",
            None,
        )
        .unwrap();
    for realm in trusted {
        let mut entry = HdbEntry::service(trust(realm));
        entry.add_key(shared.clone(), 1, None);
        db.insert(entry).unwrap();
    }
    (db, krbtgt_key, shared)
}

fn kdc(db: MemoryHdb) -> Kdc {
    Kdc::new(
        KdcConfig::new(ADMIN).unwrap(),
        Arc::new(db),
        Arc::new(OwnCipher),
    )
}

struct Tgt {
    ticket: Vec<u8>,
    session_key: Key,
}

/// A TGT this realm issued to `client`, with `transited` as given.
fn tgt(krbtgt_key: &Key, client: &Principal, transited: &[u8]) -> Tgt {
    let cipher = OwnCipher;
    let session_key = cipher.random(Enctype::Aes256Sha1).unwrap();
    let part = EncTicketPart {
        flags: tkt_flags::FORWARDABLE | tkt_flags::PRE_AUTHENT,
        session_key: session_key.clone(),
        crealm: client.realm.clone(),
        cname: client.clone(),
        transited_type: if transited.is_empty() { 0 } else { 1 },
        transited: transited.to_vec(),
        authtime: NOW - 60,
        starttime: None,
        endtime: NOW + 3600,
        renew_till: None,
        caddr: None,
        authorization_data: None,
    };
    let ticket = Ticket {
        realm: ADMIN.into(),
        sname: Principal::krbtgt(ADMIN),
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

fn tgs_req(tgt: &Tgt, client: &Principal, target: &Principal, options: u32) -> Vec<u8> {
    let cipher = OwnCipher;
    // Field [2] is "the realm part of the server's principal identifier" (RFC 4120 §5.4.1), which
    // is what makes a request for a name in another realm expressible at all: the principal itself
    // carries no realm on the wire.
    let body = der::seq(&[
        der::field(0, der::flags32(options)),
        der::field(2, der::general_string(&target.realm)),
        der::field(3, target.encode_name()),
        der::field(5, der::time(NOW + 3600)),
        der::field(7, der::int(0x9999)),
        der::field(8, der::seq(&[der::int(18)])),
    ]);
    let cksum = cipher
        .checksum(&tgt.session_key, usage::TGS_REQ_AUTH_CKSUM, &body)
        .unwrap();
    let authenticator = Authenticator {
        crealm: client.realm.clone(),
        cname: client.clone(),
        cksum: Some((Enctype::Aes256Sha1.checksum_type(), cksum)),
        cusec: 0,
        ctime: NOW,
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
            &authenticator.encode(),
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

/// What the reply names, its encrypted part opened with the client's TGT session key.
fn reply_of(reply: &[u8], reply_key: &Key) -> (Principal, EncKdcRepPart, Ticket) {
    let f = der::Fields::parse_app("TGS-REP", 13, reply).unwrap_or_else(|_| {
        panic!(
            "expected a TGS-REP, got {:?}",
            msg::KrbError::decode(reply).map(|e| (e.code, e.e_text))
        )
    });
    let mut r = der::Reader::new(f.bytes(6, "enc-part").unwrap());
    let content = r.expect_in("enc-part", der::SEQUENCE).unwrap();
    let enc = EncryptedData::decode_content("enc-part", content).unwrap();
    // The reply's encrypted part is sealed in the reply key — the TGT's session key, or the
    // authenticator's subkey — and not in the service key; that one seals the ticket.
    let plain = OwnCipher
        .decrypt(reply_key, usage::TGS_REP_ENCPART_SESSKEY, &enc.cipher)
        .expect("the reply must open under the key the exchange says it used");
    let part = EncKdcRepPart::decode(&plain).expect("an EncTGSRepPart");
    let ticket = Ticket::decode(f.bytes(5, "ticket").unwrap()).expect("the ticket decodes");
    (ticket.sname.clone(), part, ticket)
}

/// The ticket opened with the key of the realm it was issued to — the whole point of a referral.
fn ticket_part(ticket: &Ticket, key: &Key) -> EncTicketPart {
    let plain = OwnCipher
        .decrypt(key, usage::KDC_REP_TICKET, &ticket.enc.cipher)
        .expect("the ticket must open under the trust key");
    EncTicketPart::decode(&plain).expect("an EncTicketPart")
}

#[test]
fn a_direct_trust_answers_with_the_realm_that_holds_the_name() {
    let (db, krbtgt_key, shared) = db_trusting(&[DEV]);
    let kdc = kdc(db);
    let tgt = tgt(&krbtgt_key, &alice(), b"");

    let reply = kdc.handle(
        &tgs_req(
            &tgt,
            &alice(),
            &srv(&["cifs", "files"], DEV),
            kdc_options::CANONICALIZE,
        ),
        NOW,
    );
    let (sname, part, ticket) = reply_of(&reply, &tgt.session_key);
    let inner = ticket_part(&ticket, &shared);

    assert_eq!(
        sname,
        trust(DEV),
        "the referral is a ticket to the trust entry of the realm that holds the name"
    );
    assert_eq!(part.srealm, ADMIN, "issued by this realm");
    assert_eq!(
        part.sname, sname,
        "the client compares the two before accepting"
    );
    assert_eq!(inner.cname, alice());
    assert_eq!(inner.crealm, ADMIN, "she is still in her own realm");
    assert!(
        inner.transited.is_empty(),
        "no realm has been transited yet: the client has not left"
    );
}

#[test]
fn a_trust_with_the_parent_is_a_hop_toward_the_child() {
    let (db, krbtgt_key, shared) = db_trusting(&[PARENT]);
    let kdc = kdc(db);
    let tgt = tgt(&krbtgt_key, &alice(), b"");

    let reply = kdc.handle(
        &tgs_req(
            &tgt,
            &alice(),
            &srv(&["cifs", "files"], DEV),
            kdc_options::CANONICALIZE,
        ),
        NOW,
    );
    let (sname, _, ticket) = reply_of(&reply, &tgt.session_key);
    let _ = ticket_part(&ticket, &shared);

    assert_eq!(
        sname,
        trust(PARENT),
        "the closest realm this KDC holds on the way to DEV.EXAMPLE.COM is its parent"
    );
}

#[test]
fn without_canonicalize_the_same_request_is_refused() {
    // RFC 6806 §3: the client must ask, because the reply's name differs from the request's. A KDC
    // that referred anyway would be answering a question nobody asked, and a client that did not
    // opt in may well compare the names and reject the reply.
    let (db, krbtgt_key, _) = db_trusting(&[DEV]);
    let kdc = kdc(db);
    let tgt = tgt(&krbtgt_key, &alice(), b"");

    let reply = kdc.handle(
        &tgs_req(&tgt, &alice(), &srv(&["cifs", "files"], DEV), 0),
        NOW,
    );
    let err = msg::KrbError::decode(&reply).expect("a refusal");
    assert_eq!(err.code, rrl_kdc::error::codes::KDC_ERR_S_PRINCIPAL_UNKNOWN);
    let text = err.e_text.unwrap_or_default();
    assert!(
        text.contains("not a service in this realm"),
        "the refusal should still say what was not found: {text}"
    );
}

#[test]
fn a_realm_the_hierarchy_cannot_reach_gets_no_referral() {
    let (db, krbtgt_key, _) = db_trusting(&[DEV]);
    let kdc = kdc(db);
    let tgt = tgt(&krbtgt_key, &alice(), b"");

    // `FOREIGN.REALM` shares no suffix with this realm, and no trust names it: there is no hop to
    // offer, and inventing one would send the client to a KDC that has never heard of it.
    let reply = kdc.handle(
        &tgs_req(
            &tgt,
            &alice(),
            &srv(&["cifs", "files"], "FOREIGN.REALM"),
            kdc_options::CANONICALIZE,
        ),
        NOW,
    );
    let err = msg::KrbError::decode(&reply).expect("a refusal");
    assert_eq!(err.code, rrl_kdc::error::codes::KDC_ERR_S_PRINCIPAL_UNKNOWN);
}

#[test]
fn a_referral_never_goes_back_to_the_realm_the_evidence_came_from() {
    // The client's realm is the one hop that is always wrong: a ticket back to it is a loop the
    // client can only leave by giving up. Here the only entry the hierarchy offers is exactly that
    // realm, so the answer must be a refusal rather than a referral.
    let (db, krbtgt_key, _) = db_trusting(&[PARENT]);
    let kdc = kdc(db);
    let client = Principal::parse(&format!("alice@{PARENT}")).unwrap();
    let tgt = tgt(&krbtgt_key, &client, b"");

    let reply = kdc.handle(
        &tgs_req(
            &tgt,
            &client,
            &srv(&["cifs", "files"], DEV),
            kdc_options::CANONICALIZE,
        ),
        NOW,
    );
    let err = msg::KrbError::decode(&reply).expect("a refusal, not a ticket home");
    assert_eq!(err.code, rrl_kdc::error::codes::KDC_ERR_S_PRINCIPAL_UNKNOWN);
}

#[test]
fn a_realm_already_on_the_path_is_not_offered_again() {
    // The path says `EXAMPLE.COM` was already visited. Referring there again is the same loop one
    // realm later, and the transited field that the previous KDC filled in is what makes it visible.
    let (db, krbtgt_key, _) = db_trusting(&[PARENT]);
    let kdc = kdc(db);
    let tgt = tgt(&krbtgt_key, &alice(), PARENT.as_bytes());

    let reply = kdc.handle(
        &tgs_req(
            &tgt,
            &alice(),
            &srv(&["cifs", "files"], DEV),
            kdc_options::CANONICALIZE,
        ),
        NOW,
    );
    let err = msg::KrbError::decode(&reply).expect("a refusal");
    assert_eq!(err.code, rrl_kdc::error::codes::KDC_ERR_S_PRINCIPAL_UNKNOWN);
}

#[test]
fn a_krbtgt_request_is_referred_by_its_second_component() {
    // The shape this project's own client sends: `krbtgt/DEV.EXAMPLE.COM@ADMIN.EXAMPLE.COM`, with
    // the realm of that principal in the body. The realm that decides the hop is the second
    // component; reading `sname.realm` instead would make every such request look local.
    let (db, krbtgt_key, shared) = db_trusting(&[PARENT]);
    let kdc = kdc(db);
    let tgt = tgt(&krbtgt_key, &alice(), b"");

    let reply = kdc.handle(
        &tgs_req(&tgt, &alice(), &trust(DEV), kdc_options::CANONICALIZE),
        NOW,
    );
    let (sname, _, ticket) = reply_of(&reply, &tgt.session_key);
    let _ = ticket_part(&ticket, &shared);
    assert_eq!(sname, trust(PARENT));
}

#[test]
fn a_ticket_for_this_realms_own_krbtgt_is_never_referred() {
    // A renewal or validation names `krbtgt/ADMIN.EXAMPLE.COM`: the target is this realm, and a
    // referral would be a ticket to nowhere.
    let (db, krbtgt_key, _) = db_trusting(&[PARENT]);
    let kdc = kdc(db);
    let tgt = tgt(&krbtgt_key, &alice(), b"");

    let reply = kdc.handle(
        &tgs_req(
            &tgt,
            &alice(),
            &Principal::krbtgt(ADMIN),
            kdc_options::CANONICALIZE,
        ),
        NOW,
    );
    let (sname, _, _) = reply_of(&reply, &tgt.session_key);
    assert_eq!(sname, Principal::krbtgt(ADMIN));
}
