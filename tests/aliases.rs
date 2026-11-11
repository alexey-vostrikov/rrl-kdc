//! Aliases, `force-canonicalize`, postdating and `renewable-ok` — the four things an entry says
//! about *this* ticket rather than about the realm.
//!
//! An alias is a name, not an identity: one account, several names clients may ask for, one set of
//! keys (`HDB-Ext-Aliases`). RFC 6806 §6 forbids a TGS reply from changing the name the client
//! asked for, so a ticket for an alias names the alias — unless the service's entry carries
//! Heimdal's `force-canonicalize`, which exists for the directories that publish
//! `servicePrincipalName`s and want the account they actually store back.
//!
//! Postdating and `renewable-ok` are the two flags an entry grants rather than a client asks for:
//! `may-postdate` needs both entries to allow it, and `renewable-ok` only becomes `renewable` when
//! the lifetime the client asked for could not be granted.

use std::sync::Arc;

use rrl_kdc::crypto::{Cipher, Enctype, Key, OwnCipher, usage};
use rrl_kdc::der;
use rrl_kdc::error::codes;
use rrl_kdc::hdb::{Aliases, Hdb, HdbEntry, MemoryHdb, flags as entry_flags};
use rrl_kdc::kdc::{Kdc, KdcConfig};
use rrl_kdc::msg::{
    self, ApReq, Authenticator, EncKdcRepPart, EncTicketPart, EncryptedData, Ticket,
    encode_pa_data, kdc_options, tkt_flags,
};
use rrl_kdc::name::Principal;

const REALM: &str = "EXAMPLE.COM";
const NOW: i64 = 1_700_000_000;

fn parse(name: &str) -> Principal {
    Principal::parse(&format!("{name}@{REALM}")).unwrap()
}

fn alice() -> Principal {
    parse("alice")
}

/// A realm with `krbtgt`, `alice`, and one service `service` that answers to `alias` as well.
fn realm(alias: &str, flags: u32) -> (Kdc, Key, Key) {
    let cipher = OwnCipher;
    let db = MemoryHdb::new();

    let mut krbtgt = HdbEntry::krbtgt(REALM);
    let krbtgt_key = cipher.random(Enctype::Aes256Sha1).unwrap();
    krbtgt.add_key(krbtgt_key.clone(), 1, None);
    db.insert(krbtgt).unwrap();

    let mut user = HdbEntry::user(alice());
    user.flags &= !entry_flags::REQUIRE_PREAUTH;
    user.flags |= entry_flags::POSTDATE;
    user.add_password_key(&cipher, Enctype::Aes256Sha1, b"password", 1)
        .unwrap();
    db.insert(user).unwrap();

    let mut svc = HdbEntry::service(parse("cifs/files.example.com"));
    svc.flags |= entry_flags::POSTDATE | flags;
    svc.aliases = Some(Aliases {
        case_insensitive: true,
        names: vec![
            parse("cifs/files.example.com"),
            parse(alias),
            // A second spelling of the same alias, in another case: `case-insensitive` is what
            // makes the two one name.
            parse(&alias.to_uppercase()),
        ],
    });
    let svc_key = cipher.random(Enctype::Aes256Sha1).unwrap();
    svc.add_key(svc_key.clone(), 1, None);
    db.insert(svc).unwrap();

    (
        Kdc::new(
            KdcConfig::new(REALM).unwrap().with_require_preauth(false),
            Arc::new(db),
            Arc::new(OwnCipher),
        ),
        krbtgt_key,
        svc_key,
    )
}

/// A TGT for `alice`, sealed into `krbtgt_key`, carrying `flags`.
fn tgt(krbtgt_key: &Key, flags: u32) -> (Vec<u8>, Key) {
    let cipher = OwnCipher;
    let session_key = cipher.random(Enctype::Aes256Sha1).unwrap();
    let part = EncTicketPart {
        flags,
        session_key: session_key.clone(),
        crealm: REALM.into(),
        cname: alice(),
        transited_type: 0,
        transited: Vec::new(),
        authtime: NOW - 60,
        starttime: None,
        endtime: NOW + 3600,
        renew_till: Some(NOW + 86_400),
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

/// A `TGS-REQ` for `sname` whose body carries `options` and asks to live until `till`.
fn tgs_req(
    ticket: &[u8],
    session_key: &Key,
    sname: &Principal,
    options: u32,
    till: i64,
) -> Vec<u8> {
    let cipher = OwnCipher;
    let mut body_parts = vec![
        der::field(0, der::flags32(options)),
        der::field(2, der::general_string(REALM)),
        der::field(3, sname.encode_name()),
        der::field(5, der::time(till)),
        der::field(7, der::int(0x4242)),
        der::field(8, der::seq(&[der::int(18)])),
    ];
    body_parts.insert(3, der::field(3, Principal::krbtgt(REALM).encode_name()));
    let body = der::seq(&body_parts);

    let cksum = cipher
        .checksum(session_key, usage::TGS_REQ_AUTH_CKSUM, &body)
        .unwrap();
    let authenticator = Authenticator {
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

fn read_reply(reply: &[u8], session_key: &Key) -> EncKdcRepPart {
    let f = der::Fields::parse_app("TGS-REP", 13, reply).unwrap_or_else(|_| {
        panic!(
            "the request was refused: {:?}",
            msg::KrbError::decode(reply).map(|e| (e.code, e.e_text))
        )
    });
    let enc = EncryptedData::decode("enc-part", f.bytes(6, "TGS-REP").expect("enc-part"))
        .expect("an EncryptedData");
    let plain = OwnCipher
        .decrypt(session_key, usage::TGS_REP_ENCPART_SESSKEY, &enc.cipher)
        .expect("the reply opens with the TGT's session key");
    EncKdcRepPart::decode(&plain).expect("an EncTGSRepPart")
}

/// The ticket a TGS-REP carries, opened with the service's own key: the reply's `EncKdcRepPart`
/// names the service too, but the ticket is what an acceptor reads and what a client keeps.
fn open_ticket(reply: &[u8], svc_key: &Key) -> Ticket {
    let f = der::Fields::parse_app("TGS-REP", 13, reply).expect("a TGS-REP");
    let t = Ticket::decode(f.bytes(5, "TGS-REP").expect("ticket")).expect("a Ticket");
    OwnCipher
        .decrypt(svc_key, usage::KDC_REP_TICKET, &t.enc.cipher)
        .expect("the ticket is sealed in the service's key");
    t
}

fn establish(kdc: &Kdc, req: Vec<u8>) -> Vec<u8> {
    kdc.handle(&req, NOW)
}

/// A ticket asked for by an alias names the alias.
#[test]
fn a_ticket_for_an_alias_names_the_alias() {
    let (kdc, krbtgt_key, svc_key) = realm("files.example.com", 0);
    let (ticket, session_key) = tgt(&krbtgt_key, tkt_flags::INITIAL | tkt_flags::PRE_AUTHENT);
    let reply = establish(
        &kdc,
        tgs_req(
            &ticket,
            &session_key,
            &parse("files.example.com"),
            kdc_options::FORWARDABLE,
            NOW + 600,
        ),
    );
    let part = read_reply(&reply, &session_key);
    assert_eq!(part.sname, parse("files.example.com"));
    assert_eq!(
        open_ticket(&reply, &svc_key).sname,
        parse("files.example.com")
    );
}

/// The same alias in another case: `HDB-Ext-Aliases` says `case-insensitive`, so it is the same
/// name, and the ticket carries the spelling that was asked for.
#[test]
fn a_case_insensitive_alias_is_the_same_name() {
    let (kdc, krbtgt_key, svc_key) = realm("files.example.com", 0);
    let (ticket, session_key) = tgt(&krbtgt_key, tkt_flags::INITIAL | tkt_flags::PRE_AUTHENT);
    let reply = establish(
        &kdc,
        tgs_req(
            &ticket,
            &session_key,
            &parse("FILES.Example.COM"),
            kdc_options::FORWARDABLE,
            NOW + 600,
        ),
    );
    assert_eq!(
        open_ticket(&reply, &svc_key).sname,
        parse("FILES.Example.COM"),
        "the ticket names what the client asked for, folded only for the lookup"
    );
}

/// `force-canonicalize`: the entry's own name comes back, which is what a directory that publishes
/// service names asks for so that the reply names the account it stores.
#[test]
fn force_canonicalize_returns_the_entrys_own_name() {
    let (kdc, krbtgt_key, svc_key) = realm("files.example.com", entry_flags::FORCE_CANONICALIZE);
    let (ticket, session_key) = tgt(&krbtgt_key, tkt_flags::INITIAL | tkt_flags::PRE_AUTHENT);
    let reply = establish(
        &kdc,
        tgs_req(
            &ticket,
            &session_key,
            &parse("files.example.com"),
            kdc_options::FORWARDABLE,
            NOW + 600,
        ),
    );
    let part = read_reply(&reply, &session_key);
    assert_eq!(part.sname, parse("cifs/files.example.com"));
    assert_eq!(
        open_ticket(&reply, &svc_key).sname,
        parse("cifs/files.example.com")
    );
}

/// A name no entry claims is still unknown: an alias list is not a wildcard.
#[test]
fn a_name_no_entry_claims_is_unknown() {
    let (kdc, krbtgt_key, _) = realm("files.example.com", 0);
    let (ticket, session_key) = tgt(&krbtgt_key, tkt_flags::INITIAL | tkt_flags::PRE_AUTHENT);
    let reply = establish(
        &kdc,
        tgs_req(
            &ticket,
            &session_key,
            &parse("nobody.example.com"),
            kdc_options::FORWARDABLE,
            NOW + 600,
        ),
    );
    assert_eq!(
        msg::KrbError::decode(&reply).unwrap().code,
        codes::KDC_ERR_S_PRINCIPAL_UNKNOWN
    );
}

/// The HDB itself resolves an alias, and a stored principal is never shadowed by an alias that
/// spells the same name.
#[test]
fn the_database_resolves_aliases_without_shadowing_stored_names() {
    let db = MemoryHdb::new();
    let mut svc = HdbEntry::service(parse("cifs/files.example.com"));
    svc.aliases = Some(Aliases {
        case_insensitive: false,
        names: vec![parse("files.example.com")],
    });
    db.insert(svc).unwrap();

    let found = db
        .fetch(&parse("files.example.com"))
        .unwrap()
        .expect("by alias");
    assert_eq!(found.principal, parse("cifs/files.example.com"));

    // Stored under the alias's own spelling: the entry table wins, and the alias row that pointed
    // at the other entry stops answering.
    let mut other = HdbEntry::service(parse("files.example.com"));
    other.flags |= entry_flags::OK_AS_DELEGATE;
    db.insert(other).unwrap();
    let found = db
        .fetch(&parse("files.example.com"))
        .unwrap()
        .expect("the entry");
    assert!(
        found.has(entry_flags::OK_AS_DELEGATE),
        "the stored entry, not the alias"
    );

    // Removing the entry takes its alias rows with it.
    assert!(db.remove(&parse("files.example.com")).unwrap());
    let found = db
        .fetch(&parse("files.example.com"))
        .unwrap()
        .expect("back to the alias");
    assert_eq!(found.principal, parse("cifs/files.example.com"));
}

/// The same, over the persistent backend: an alias written in one process answers in the next.
#[cfg(feature = "hdb-redb")]
#[test]
fn aliases_survive_a_reopen_and_a_rename() {
    use rrl_kdc::hdb::RedbHdb;

    let dir = std::env::temp_dir().join(format!(
        "rrl-kdc-alias-{:016x}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("hdb.redb");

    let mut svc = HdbEntry::service(parse("cifs/files.example.com"));
    svc.aliases = Some(Aliases {
        case_insensitive: false,
        names: vec![parse("files.example.com")],
    });
    {
        let db = RedbHdb::open(&path).unwrap();
        Hdb::store(&db, svc).unwrap();
    }
    let db = RedbHdb::open(&path).unwrap();
    assert_eq!(
        db.fetch(&parse("files.example.com"))
            .unwrap()
            .expect("by alias after a reopen")
            .principal,
        parse("cifs/files.example.com")
    );

    // A rename moves the alias rows with the entry, so the alias still resolves.
    Hdb::rename(
        &db,
        &parse("cifs/files.example.com"),
        &parse("smb/files.example.com"),
    )
    .unwrap();
    assert_eq!(
        db.fetch(&parse("files.example.com"))
            .unwrap()
            .expect("by alias after a rename")
            .principal,
        parse("smb/files.example.com")
    );

    std::fs::remove_dir_all(&dir).unwrap();
}

/// The service's key is what the ticket is sealed in, so an alias that resolved to the wrong entry
/// would be visible here rather than only in the name.
#[test]
fn an_alias_ticket_is_sealed_in_the_aliased_entrys_key() {
    let (kdc, krbtgt_key, svc_key) = realm("files.example.com", 0);
    let (ticket, session_key) = tgt(&krbtgt_key, tkt_flags::INITIAL | tkt_flags::PRE_AUTHENT);
    let reply = establish(
        &kdc,
        tgs_req(
            &ticket,
            &session_key,
            &parse("files.example.com"),
            kdc_options::FORWARDABLE,
            NOW + 600,
        ),
    );
    let t = open_ticket(&reply, &svc_key);
    assert_eq!(t.sname, parse("files.example.com"));
}
