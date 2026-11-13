//! A stand for `hpropd`: seeds a master realm, serves it, and receives a propagation.
//!
//! Why an example and not a test: the point of `scripts/hprop-stand.sh` is to hand a **real**
//! Heimdal `hprop` something to push to, which means three processes — a KDC, an `hpropd` and the
//! client — and a test cannot be three processes talking to a binary this repository does not build.
//!
//! Subcommands:
//!
//! ```text
//! seed  <dir>            write krb5.conf, the master's keytab and the slave's empty database
//! kdc   <dir> <addr>     serve the seeded realm
//! hpropd <db> <addr>     receive propagations into <db>
//! dump  <db>             print the principals a database holds
//! ```
//!
//! The realm is seeded with what the protocol needs and nothing else: `krbtgt`, `alice` (so that the
//! push is not a database of one entry), `hprop/HOST` (the service the master asks a ticket for) and
//! `kadmin/hprop` (the only client allowed to push).

use std::sync::Arc;

use rrl_kdc::crypto::{Cipher, Enctype, OwnCipher};
use rrl_kdc::hdb::{Hdb, HdbEntry, Keytab, MemoryHdb, keytab::KeytabEntry};
use rrl_kdc::hprop::{self, FileTarget, Hprop};
use rrl_kdc::kdc::{Kdc, KdcConfig};
use rrl_kdc::name::Principal;

const SERVICE_PASSWORD: &[u8] = b"the hprop service password";
const CLIENT_NAME: &str = "kadmin/hprop";
const MASTER_PASSWORD: &[u8] = b"the master's propagation password";
const ALICE_PASSWORD: &[u8] = b"alice's password";

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let realm = std::env::var("KDC_REALM").unwrap_or_else(|_| "EXAMPLE.COM".to_owned());
    let host = std::env::var("KDC_HOST").unwrap_or_else(|_| "kdc.example.com".to_owned());

    match args.first().map(String::as_str) {
        Some("seed") => seed(&args[1], &realm, &host).expect("the realm is seeded"),
        Some("kdc") => serve_kdc(&args[1], &args[2], &realm, &host).expect("the KDC runs"),
        Some("hpropd") => serve_hpropd(&args[1], &args[2], &realm).expect("hpropd runs"),
        Some("dump") => dump(&args[1]).expect("the database is readable"),
        Some("mkey") => write_master_key(&args[1], &realm).expect("the master key is written"),
        // The sending half: `push <dir> <addr>`. The ticket is minted here from the seeded realm,
        // because a stand that had to log in first would need a Kerberos client and the point of the
        // exercise is the propagation; a real master gets its ticket from a `kinit -k`.
        Some("push") => push(&args[1], &args[2], &realm, &host).expect("the push runs"),
        Some("seal") => seal_probe(&args[1], &args[2]).expect("the probe runs"),
        Some("unseal") => unseal_probe(&args[1], &args[2]).expect("the probe runs"),
        _ => {
            eprintln!("usage: hprop-stand seed|kdc|hpropd|dump …");
            std::process::exit(2);
        }
    }
}

/// Writes a master keytab at `<dir>/m-key`, in the form `kstash` produces: one `K/M@REALM` entry.
///
/// `kstash` prompts on a terminal for the password it derives the key from, and a container has no
/// terminal — so the stand generates the key and writes the same file shape. Heimdal reads it with
/// `-m`, and this crate reads it with `MasterKeys::from_keytab`.
fn write_master_key(dir: &str, realm: &str) -> Result<(), Box<dyn std::error::Error>> {
    let key = OwnCipher.random(Enctype::Aes256Sha1)?;
    rrl_kdc::hdb::mkey::write_keytab(format!("{dir}/m-key"), realm, &[(key, 1)])?;
    eprintln!("wrote {dir}/m-key (K/M@{realm}, kvno 1)");
    Ok(())
}

/// Prints this crate's sealing of `hex` under the master key in `path`, for comparison with
/// `docker/heimdal-hdbseal.c`. The two strings have to be equal; when they are not, the difference is
/// the usage or the derivation, and having both printed says which.
fn seal_probe(path: &str, hex: &str) -> Result<(), Box<dyn std::error::Error>> {
    let keys = rrl_kdc::hdb::mkey::MasterKeys::from_keytab(path)?;
    let mkey = keys.keys().first().ok_or("no master key")?;
    let plain: Vec<u8> = (0..hex.len() / 2)
        .map(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).expect("hex"))
        .collect();
    let sealed = rrl_kdc::hdb::mkey::seal_key(&OwnCipher, &mkey.key, &plain)?;
    println!(
        "key: {}",
        mkey.key
            .bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    );
    println!(
        "sealed ({} octets): {}",
        sealed.len(),
        sealed
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    );
    Ok(())
}

/// Opens `hex` with the master key in `path` and prints the plaintext, or the reason it did not open.
fn unseal_probe(path: &str, hex: &str) -> Result<(), Box<dyn std::error::Error>> {
    let keys = rrl_kdc::hdb::mkey::MasterKeys::from_keytab(path)?;
    let mkey = keys.keys().first().ok_or("no master key")?;
    let sealed: Vec<u8> = (0..hex.len() / 2)
        .map(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).expect("hex"))
        .collect();
    match rrl_kdc::hdb::mkey::unseal_key(&OwnCipher, &mkey.key, &sealed, Enctype::Aes256Sha1) {
        Ok(plain) => println!(
            "opened ({} octets): {}",
            plain.len(),
            plain.iter().map(|b| format!("{b:02x}")).collect::<String>()
        ),
        Err(e) => {
            println!("did not open: {e}");
            return Err(e.into());
        }
    }
    Ok(())
}

/// The realm's principals, in the order a stand provisions them.
fn entries(realm: &str, host: &str) -> Vec<HdbEntry> {
    let cipher = OwnCipher;
    let mut krbtgt = HdbEntry::krbtgt(realm);
    krbtgt.add_key(cipher.random(Enctype::Aes256Sha1).expect("a key"), 1, None);

    let mut alice = HdbEntry::user(Principal::parse(&format!("alice@{realm}")).expect("a name"));
    alice
        .add_password_key(&cipher, Enctype::Aes256Sha1, ALICE_PASSWORD, 1)
        .expect("a key");

    vec![
        krbtgt,
        alice,
        hprop::service_entry(realm, host, &cipher, SERVICE_PASSWORD).expect("the service entry"),
        hprop::master_entry(realm, &cipher, MASTER_PASSWORD).expect("the master entry"),
    ]
}

fn seed(dir: &str, realm: &str, host: &str) -> Result<(), Box<dyn std::error::Error>> {
    let db = MemoryHdb::new();
    for entry in entries(realm, host) {
        db.store(entry)?;
    }

    // `krb5.conf` in the shape Heimdal's `kinit` reads, with the KDC on the port the script serves.
    let conf = format!(
        "[libdefaults]\n default_realm = {realm}\n dns_lookup_kdc = false\n dns_lookup_realm = false\n\
         \n[realms]\n {realm} = {{\n  kdc = 127.0.0.1:18888\n }}\n\
         \n[domain_realm]\n .{host} = {realm}\n {host} = {realm}\n"
    );
    std::fs::write(format!("{dir}/krb5.conf"), conf)?;

    // The keytab `hprop` authenticates with: Heimdal's client logs in as `kadmin/hprop` (`kinit -k`
    // inside `krb5_get_init_creds_keytab`), and the ticket for `hprop/HOST` is asked for afterwards.
    let mut keytab = Keytab::new();
    let master = Principal::parse(&format!("{CLIENT_NAME}@{realm}"))?;
    let entry = db.fetch(&master)?.expect("the master was stored");
    for key in &entry.keys {
        keytab.add(KeytabEntry {
            principal: entry.principal.clone(),
            key: key.key.clone(),
            kvno: key.kvno,
            timestamp: 0,
        });
    }
    keytab.save(format!("{dir}/hprop.keytab"))?;

    // The slave's database: created empty, so that what arrives is visible as having arrived.
    let slave = format!("{dir}/slave.db");
    drop(rrl_kdc::hdb::redb_store::RedbHdb::open(&slave)?);
    eprintln!("seeded {realm} for {host}");
    Ok(())
}

fn serve_kdc(
    dir: &str,
    addr: &str,
    realm: &str,
    host: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let db = Arc::new(MemoryHdb::new());
    for entry in entries(realm, host) {
        db.store(entry)?;
    }
    let config = KdcConfig::new(realm)?;
    let kdc = Kdc::new(config, Arc::clone(&db) as Arc<dyn Hdb>, Arc::new(OwnCipher));
    eprintln!("{dir}: serving {realm} on {addr}");
    let stand = rrl_kdc::transport::serve_on(addr, kdc);
    loop {
        std::thread::sleep(std::time::Duration::from_secs(3600));
        let _ = &stand;
    }
}

/// Pushes the seeded realm into a receiver at `addr`.
///
/// The ticket for `hprop/HOST` is built here rather than obtained through an AS and a TGS exchange:
/// this binary is a stand for the propagation, and a Kerberos client is the one thing it does not
/// have. What it proves is the stream, the AP-REQ, the subkeys and the acknowledgement.
fn push(dir: &str, addr: &str, realm: &str, host: &str) -> Result<(), Box<dyn std::error::Error>> {
    use rrl_kdc::hprop::push::{Pusher, ServiceTicket};
    use rrl_kdc::msg::{EncTicketPart, EncryptedData, Ticket, tkt_flags};

    let db = MemoryHdb::new();
    for entry in entries(realm, host) {
        db.store(entry)?;
    }
    let service = Principal::parse(&format!("{}/{host}@{realm}", hprop::SERVICE))?;
    let service_key = db
        .fetch(&service)?
        .ok_or("the seeded realm has no hprop service")?
        .key_for(Enctype::Aes256Sha1)
        .ok_or("the service has no AES-256 key")?
        .key
        .clone();

    let now = hprop::now();
    let session_key = OwnCipher.random(Enctype::Aes256Sha1)?;
    let part = EncTicketPart {
        flags: tkt_flags::INITIAL | tkt_flags::PRE_AUTHENT,
        session_key: session_key.clone(),
        crealm: realm.to_owned(),
        cname: Principal::parse(&format!("{CLIENT_NAME}@{realm}"))?,
        transited_type: 0,
        transited: Vec::new(),
        authtime: now - 60,
        starttime: None,
        endtime: now + 3600,
        renew_till: None,
        caddr: None,
        authorization_data: None,
    };
    let ticket = ServiceTicket {
        ticket: Ticket {
            realm: realm.to_owned(),
            sname: service,
            enc: EncryptedData::seal(
                &OwnCipher,
                &service_key,
                rrl_kdc::crypto::usage::KDC_REP_TICKET,
                Some(1),
                &part.encode(),
            )?,
        }
        .encode(),
        session_key,
    };

    let pusher = Pusher::new(
        realm,
        Principal::parse(&format!("{CLIENT_NAME}@{realm}"))?,
        std::sync::Arc::new(OwnCipher),
    );
    let summary = pusher.push_to(addr, &db, &ticket, now)?;
    println!("pushed {} entries to {addr}", summary.entries);
    // The directory is written to by `seed`; `push` reads the same seeded realm and needs nothing
    // from it, but the argument stays so that both commands are called the same way.
    let _ = dir;
    Ok(())
}

fn serve_hpropd(db_path: &str, addr: &str, realm: &str) -> Result<(), Box<dyn std::error::Error>> {
    // The receiver authenticates the master with the same keys the master's own database holds, so
    // it seeds itself with the two principals rather than taking a keytab: a slave that cannot find
    // `kadmin/hprop` cannot tell the master from anybody else.
    let db = Arc::new(MemoryHdb::new());
    let host = std::env::var("KDC_HOST").unwrap_or_else(|_| "kdc.example.com".to_owned());
    db.store(hprop::service_entry(
        realm,
        &host,
        &OwnCipher,
        SERVICE_PASSWORD,
    )?)?;
    db.store(hprop::master_entry(realm, &OwnCipher, MASTER_PASSWORD)?)?;

    let target = FileTarget::new(db_path)?;
    // The master key, when the stand has one: a master whose database is sealed sends each key
    // encrypted under it, and a slave should store them the same way — its file is a copy of the
    // realm. One key does both jobs: opening what the master sent, and sealing what is installed.
    let mut target = target;
    let mut master = None;
    if let Ok(path) = std::env::var("HPROR_MKEY") {
        let keys = rrl_kdc::hdb::mkey::MasterKeys::from_keytab(&path)?;
        eprintln!(
            "hpropd: {} master key(s) from {path}, newest kvno {}",
            keys.keys().len(),
            keys.keys().first().map(|k| k.kvno).unwrap_or(0)
        );
        target = target.with_master_keys(Arc::new(OwnCipher), keys.clone())?;
        master = Some(Arc::new(keys));
    } else {
        eprintln!("hpropd: no HPROR_MKEY, so installed keys are stored in the clear");
    }
    let mut service = Hprop::new(
        Arc::clone(&db) as Arc<dyn Hdb>,
        Arc::new(OwnCipher),
        realm,
        Arc::new(target),
    )?;
    if let Some(keys) = master {
        service = service.with_master_keys(keys);
    }
    eprintln!("hpropd: receiving {realm} on {addr}, installing into {db_path}");
    let stand = hprop::serve_on(addr, service)?;
    // The results are printed as they arrive: this is the stand's log, and a refusal that only ever
    // lived in a `Vec` nobody read would make a failed push look like a client-side problem.
    let mut seen = 0;
    loop {
        let results = stand.results();
        while seen < results.len() {
            match &results[seen] {
                Ok(summary) => eprintln!("hpropd: installed {} entries", summary.entries),
                Err(why) => eprintln!("hpropd: refused: {why}"),
            }
            seen += 1;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

fn dump(path: &str) -> Result<(), Box<dyn std::error::Error>> {
    // A slave that was given a master key holds sealed records, and reading them without one is a
    // refusal by design (`a 60-octet key ... is sealed under master key 1`). `HPROR_MKEY` is the same
    // variable `hpropd` was told, so a dump of a sealed database takes the same argument.
    let db = match std::env::var("HPROR_MKEY") {
        Ok(keys) => rrl_kdc::hdb::redb_store::RedbHdb::open_sealed(
            path,
            rrl_kdc::hdb::mkey::MasterKeys::from_keytab(&keys)?,
            std::sync::Arc::new(OwnCipher),
        )?,
        Err(_) => rrl_kdc::hdb::redb_store::RedbHdb::open(path)?,
    };
    let mut count = 0;
    let mut next = db.first()?;
    while let Some(principal) = next {
        if let Some(entry) = db.fetch(&principal)? {
            println!(
                "{} (kvno {}, {} key{})",
                entry.principal,
                entry.kvno,
                entry.keys.len(),
                if entry.keys.len() == 1 { "" } else { "s" }
            );
            count += 1;
        }
        next = db.next(&principal)?;
    }
    println!("{count} principals");
    Ok(())
}
