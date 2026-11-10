//! A PAC in the ticket a client actually receives.
//!
//! `pac.rs` and `logon_info.rs` are judged byte for byte by impacket; what this file
//! checks is the wiring: that the engine puts those bytes into the ticket, signed
//! with the right keys, and that a realm without a directory still issues plain
//! Kerberos tickets.
//!
//! The request scaffolding is the same as `tgs_errors.rs`: a TGT the test builds,
//! because each case needs a different one and building it directly is the only way
//! to hold those knobs.

use std::sync::Arc;

use rust_kdc::crypto::{Cipher, Enctype, Key, OwnCipher, usage};
use rust_kdc::der;
use rust_kdc::hdb::{HdbEntry, MemoryHdb};
use rust_kdc::kdc::logon_info::{Identity, PacIdentities, Sid};
use rust_kdc::kdc::{Kdc, KdcConfig};
use rust_kdc::msg::{
    self, ApReq, Authenticator, EncTicketPart, EncryptedData, Ticket, encode_pa_data, kdc_options,
    tkt_flags,
};
use rust_kdc::name::Principal;

const REALM: &str = "EXAMPLE.COM";
const SERVICE: &str = "host/server.example.com";
const NOW: i64 = 1_700_000_000;

fn alice() -> Principal {
    Principal::parse(&format!("alice@{REALM}")).unwrap()
}

fn service() -> Principal {
    Principal::parse(&format!("{SERVICE}@{REALM}")).unwrap()
}

/// A directory that knows one account.
struct Directory {
    identity: Identity,
}

impl PacIdentities for Directory {
    fn identity(&self, principal: &Principal) -> rust_kdc::Result<Option<Identity>> {
        Ok((*principal == alice()).then(|| self.identity.clone()))
    }
}

fn identity() -> Identity {
    Identity {
        domain: Sid::parse("S-1-5-21-100-200-300").unwrap(),
        domain_name: "EXAMPLE".into(),
        logon_server: "DC1".into(),
        user_rid: 1105,
        primary_group: 513,
        groups: vec![(513, 7), (512, 7)],
        full_name: "Alice Example".into(),
        user_account_control: 0x200,
        extra_sids: Vec::new(),
    }
}

/// The realm, and the `krbtgt` key the test TGTs are sealed with.
fn realm() -> (MemoryHdb, Key) {
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

fn kdc() -> Kdc {
    let (db, _) = realm();
    Kdc::new(
        KdcConfig::new(REALM).unwrap(),
        Arc::new(db),
        Arc::new(OwnCipher),
    )
}

fn kdc_with_pac() -> Kdc {
    let (db, _) = realm();
    Kdc::new(
        KdcConfig::new(REALM).unwrap(),
        Arc::new(db),
        Arc::new(OwnCipher),
    )
    .with_pac(Arc::new(Directory {
        identity: identity(),
    }))
}

/// A TGT as the AS exchange would have issued it.
fn tgt(krbtgt_key: &Key) -> (Vec<u8>, Key) {
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
    (ticket.encode(), session_key)
}

/// A `TGS-REQ` presenting that TGT, as a client builds one.
fn tgs_req(ticket: &[u8], session_key: &Key) -> Vec<u8> {
    let cipher = OwnCipher;
    let body = der::seq(&[
        der::field(0, der::flags32(kdc_options::FORWARDABLE)),
        der::field(2, der::general_string(REALM)),
        der::field(3, service().encode_name()),
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
    let mut parts = vec![der::field(1, der::int(5)), der::field(2, der::int(12))];
    parts.push(der::field(
        3,
        encode_pa_data(&[(msg::PA_TGS_REQ, ap_req.encode())]),
    ));
    parts.push(der::field(4, body));
    der::cons(der::app(12), &[der::seq(&parts)])
}

/// The ticket from a reply, decrypted with `key`.
fn ticket_part(reply: &[u8], key: &Key) -> EncTicketPart {
    // The ticket is field [5] of the `[APPLICATION 13]` reply, and `Ticket` decodes
    // itself from the whole TLV. There is no reply decoder in the crate because
    // nothing in it needs one — a client does.
    let fields = der::Fields::parse_app("TGS-REP", 13, reply).expect("a TGS-REP");
    let ticket = Ticket::decode(fields.bytes(5, "TGS-REP").expect("the ticket")).expect("a Ticket");
    let plain = OwnCipher
        .decrypt(key, usage::KDC_REP_TICKET, &ticket.enc.cipher)
        .expect("the ticket opens with the service key");
    EncTicketPart::decode(&plain).expect("an EncTicketPart")
}

/// The PAC buffers inside an `AuthorizationData`, as `(type, payload)`.
fn pac_buffers(ad: &[u8]) -> Vec<(u32, Vec<u8>)> {
    // `AuthorizationData ::= SEQUENCE OF SEQUENCE { [0] type, [1] data }`, wrapped in
    // `AD-IF-RELEVANT`. Walking it by hand is enough here: `pac.rs` is judged by
    // impacket, and this only has to reach the octets.
    let mut out = Vec::new();
    let if_relevant = find_pac(ad).expect("the PAC is inside an AD-IF-RELEVANT");
    let count = u32::from_le_bytes(if_relevant[0..4].try_into().unwrap()) as usize;
    let mut at = 8;
    for _ in 0..count {
        let kind = u32::from_le_bytes(if_relevant[at..at + 4].try_into().unwrap());
        let size = u32::from_le_bytes(if_relevant[at + 4..at + 8].try_into().unwrap()) as usize;
        let offset = u64::from_le_bytes(if_relevant[at + 8..at + 16].try_into().unwrap()) as usize;
        out.push((kind, if_relevant[offset..offset + size].to_vec()));
        at += 16;
    }
    out
}

/// The PAC octets inside the `AuthorizationData` DER.
fn find_pac(ad: &[u8]) -> Option<&[u8]> {
    // The PAC starts where its own `PACTYPE` begins: two `ULONG`s, and the first is
    // the buffer count. Searching for the logon-info buffer's kind is not enough —
    // that octet appears everywhere — so this looks for a table whose offsets point
    // inside the buffer it is in, which is the property that makes it a PAC.
    (0..ad.len().saturating_sub(24)).find_map(|start| {
        let slice = &ad[start..];
        let count = u32::from_le_bytes(slice[0..4].try_into().ok()?) as usize;
        if count == 0 || count > 8 {
            return None;
        }
        let table_end = 8 + count * 16;
        if table_end > slice.len() {
            return None;
        }
        for i in 0..count {
            let at = 8 + i * 16;
            let size = u32::from_le_bytes(slice[at + 4..at + 8].try_into().ok()?) as usize;
            let offset = u64::from_le_bytes(slice[at + 8..at + 16].try_into().ok()?) as usize;
            if offset < table_end || offset + size > slice.len() {
                return None;
            }
        }
        Some(slice)
    })
}

/// The service's key, as `realm()` made it.
fn service_key() -> Key {
    let mut entry = HdbEntry::service(service());
    entry
        .add_password_key(&OwnCipher, Enctype::Aes256Sha1, b"svc", 1)
        .unwrap();
    entry.key_for(Enctype::Aes256Sha1).unwrap().key.clone()
}

#[test]
fn a_ticket_carries_a_pac_when_the_realm_has_a_directory() {
    let (ticket, session_key) = tgt(&realm().1);
    let reply = kdc_with_pac().handle(&tgs_req(&ticket, &session_key), NOW);
    let part = ticket_part(&reply, &service_key());
    let ad = part
        .authorization_data
        .expect("a realm with a directory puts a PAC in every ticket");
    let buffers = pac_buffers(&ad);
    let kinds: Vec<u32> = buffers.iter().map(|(kind, _)| *kind).collect();
    assert!(kinds.contains(&1), "PAC_LOGON_INFO: {kinds:?}");
    assert!(kinds.contains(&10), "PAC_CLIENT_INFO: {kinds:?}");
    assert!(kinds.contains(&6), "PAC_SERVER_CHECKSUM: {kinds:?}");
    assert!(kinds.contains(&7), "PAC_PRIVSVR_CHECKSUM: {kinds:?}");
}

#[test]
fn the_pac_states_the_identity_the_directory_gave() {
    let (ticket, session_key) = tgt(&realm().1);
    let reply = kdc_with_pac().handle(&tgs_req(&ticket, &session_key), NOW);
    let part = ticket_part(&reply, &service_key());
    let buffers = pac_buffers(&part.authorization_data.expect("a PAC"));
    let (_, logon) = buffers.iter().find(|(kind, _)| *kind == 1).unwrap();

    // `UserId` and `PrimaryGroupId` sit after six FILETIMEs and six
    // RPC_UNICODE_STRINGs, and the two `USHORT` counts.
    let user_id = u32::from_le_bytes(logon[48 + 48 + 4..48 + 48 + 8].try_into().unwrap());
    let primary = u32::from_le_bytes(logon[48 + 48 + 8..48 + 48 + 12].try_into().unwrap());
    let groups = u32::from_le_bytes(logon[48 + 48 + 12..48 + 48 + 16].try_into().unwrap());
    assert_eq!(user_id, 1105, "the RID the directory gave");
    assert_eq!(primary, 513, "`Domain Users`");
    assert_eq!(groups, 2, "the two groups the directory gave");
}

#[test]
fn both_signatures_are_keyed_by_the_keys_they_name() {
    let (ticket, session_key) = tgt(&realm().1);
    let (_, krbtgt_key) = realm();
    let reply = kdc_with_pac().handle(&tgs_req(&ticket, &session_key), NOW);
    let part = ticket_part(&reply, &service_key());
    let ad = part.authorization_data.expect("a PAC");
    let pac = find_pac(&ad).expect("the PAC octets").to_vec();
    let buffers = pac_buffers(&ad);

    // Zero the signature fields, as the signer did, then recompute.
    let mut block = pac.clone();
    for (kind, data) in &buffers {
        if *kind == 6 || *kind == 7 {
            let offset = block
                .windows(data.len())
                .position(|w| w == data.as_slice())
                .expect("the buffer is in the PAC");
            block[offset + 4..offset + data.len()].fill(0);
        }
    }
    let recompute = |key: &Key, data: &[u8]| {
        let kc = rust_kdc::crypto::kdf::derive_key(
            key.enctype(),
            key.bytes(),
            17,
            rust_kdc::crypto::kdf::KeyUse::Checksum,
        )
        .unwrap();
        use hmac::{Hmac, KeyInit, Mac};
        use sha1::Sha1;
        let mut m = <Hmac<Sha1> as KeyInit>::new_from_slice(&kc).unwrap();
        m.update(data);
        m.finalize().into_bytes()[..12].to_vec()
    };

    for (kind, data) in &buffers {
        if *kind != 6 && *kind != 7 {
            continue;
        }
        let signature = &data[4..];
        let key = if *kind == 6 {
            &service_key()
        } else {
            &krbtgt_key
        };
        assert_eq!(
            signature,
            recompute(key, &block).as_slice(),
            "buffer {kind} signs with its own key"
        );
    }
}

#[test]
fn a_realm_without_a_directory_issues_no_pac() {
    let (ticket, session_key) = tgt(&realm().1);
    let reply = kdc().handle(&tgs_req(&ticket, &session_key), NOW);
    let part = ticket_part(&reply, &service_key());
    assert!(
        part.authorization_data.is_none(),
        "plain Kerberos: nothing in the ticket claims an identity"
    );
}

#[test]
fn an_account_the_directory_does_not_know_gets_a_ticket_without_a_pac() {
    // An empty identity list is not a reason to refuse a ticket: the account is in
    // the KDC's database, and a directory that has not been filled in yet is a
    // deployment state, not an authentication failure.
    struct Empty;
    impl PacIdentities for Empty {
        fn identity(&self, _: &Principal) -> rust_kdc::Result<Option<Identity>> {
            Ok(None)
        }
    }
    let (db, _) = realm();
    let kdc = Kdc::new(
        KdcConfig::new(REALM).unwrap(),
        Arc::new(db),
        Arc::new(OwnCipher),
    )
    .with_pac(Arc::new(Empty));

    let (ticket, session_key) = tgt(&realm().1);
    let reply = kdc.handle(&tgs_req(&ticket, &session_key), NOW);
    let part = ticket_part(&reply, &service_key());
    assert!(part.authorization_data.is_none());
}
