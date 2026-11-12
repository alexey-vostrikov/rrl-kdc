//! A KDC for a stand: seeds a small realm, writes the keytab and `krb5.conf` a
//! client needs, and serves until killed.
//!
//! Why an example and not a test: this is the shape a *daemon* takes — an address
//! from the environment, a keytab on disk, a realm with the principals a domain
//! needs — and the crate is a library on purpose. A stand has to be able to run it
//! as a process, and `cargo run --example` is the least machinery that allows that.
//!
//! What it seeds, and why each entry exists:
//!
//! * `krbtgt/REALM` — the realm itself.
//! * `administrator` — the account a `net ads join -U administrator` authenticates
//!   as, with a password rather than a keytab.
//! * `HOSTNAME$` — the machine account. Samba names it with a trailing `$`, and a
//!   principal component may contain one; a stand that seeded `hostname` instead
//!   would fail at the first ticket for a machine that does not exist.
//! * `host/HOSTNAME`, `cifs/HOSTNAME`, `ldap/HOSTNAME` — the service principals a
//!   SMB server, an LDAP server and a machine ask tickets for. All three keys are
//!   the same, which is what one keytab with three names means.
//!
//! ```sh
//! KDC_REALM=AD.EXAMPLE.COM KDC_HOST=samba.ad.example.com \
//!   cargo run --example kdc-stand --features hdb-redb -- 0.0.0.0:88 /shared
//! ```
//!
//! # A database on disk, and whether its keys are protected
//!
//! The stand keeps its realm in memory unless told otherwise, which is what a throwaway stand wants.
//! Give it `KDC_DB` and `KDC_MKEY` and it keeps the realm in a redb file with **every key sealed
//! under the master key** — the arrangement a real deployment runs in:
//!
//! ```sh
//! KDC_DB=/shared/hdb.redb KDC_MKEY=/shared/m-key \
//!   KDC_REALM=AD.EXAMPLE.COM KDC_HOST=samba.ad.example.com \
//!   cargo run --example kdc-stand --features hdb-redb -- 0.0.0.0:88 /shared
//! ```
//!
//! `KDC_MKEY` is a keytab with a `K/M@REALM` entry, which is what `kstash` writes and what
//! `rrl_kdc::hdb::mkey::write_keytab` produces. The two variables go together: one without the other
//! stops the stand at start-up, rather than starting a KDC whose keys are on disk in the clear or
//! whose master key has nowhere to be applied.
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

use rrl_kdc::crypto::{Enctype, OwnCipher};
use rrl_kdc::hdb::{Hdb, HdbEntry, Keytab, MemoryHdb, keytab::KeytabEntry};
use rrl_kdc::kdc::logon_info::{Identity, PacIdentities, Sid};
use rrl_kdc::kdc::{Kdc, KdcConfig};
use rrl_kdc::name::Principal;
use rrl_kdc::transport::serve_on;

/// The identities a PAC states, taken from the same table that seeds the database.
///
/// A real KDC asks a directory; a stand has no directory, so the RIDs are written
/// down here and nowhere else. Keeping them in one table is the point: an RID that
/// disagreed with the principal it belongs to would produce a PAC naming somebody
/// else, and nothing in the ticket would show it.
struct StandIdentities {
    domain: Sid,
    /// NetBIOS spelling: `AD` for `AD.EXAMPLE.COM`, which is what a Windows service
    /// compares against. The DNS name there would never match.
    domain_name: String,
    logon_server: String,
    /// `principal` as a string → RID, relative to [`Self::domain`].
    rids: BTreeMap<String, u32>,
}

impl PacIdentities for StandIdentities {
    fn identity(
        &self,
        principal: &Principal,
    ) -> rrl_kdc::kdc::logon_info::PacResult<Option<Identity>> {
        let Some(rid) = self.rids.get(&principal.to_string()) else {
            // Not an error: a principal the directory has not been told about gets a
            // ticket without a PAC, which is what `TASQ-3.4`'s seam promises.
            return Ok(None);
        };
        Ok(Some(Identity {
            domain: self.domain.clone(),
            domain_name: self.domain_name.clone(),
            logon_server: self.logon_server.clone(),
            user_rid: *rid,
            // 513 `Domain Users`, the group every account in a realm is in.
            primary_group: 513,
            groups: vec![(513, 7)],
            full_name: String::new(),
            user_account_control: 0x200,
            extra_sids: Vec::new(),
        }))
    }
}

fn main() {
    let mut args = std::env::args().skip(1);
    let listen = args.next().unwrap_or_else(|| "0.0.0.0:88".to_owned());
    let out = PathBuf::from(args.next().unwrap_or_else(|| "/shared".to_owned()));

    let realm = env("KDC_REALM", "AD.EXAMPLE.COM");
    let host = env("KDC_HOST", "samba.ad.example.com");
    let admin_password = env("KDC_ADMIN_PASSWORD", "admin-Password-1");
    let service_password = env("KDC_SERVICE_PASSWORD", "service-Password-1");
    let machine_password = env("KDC_MACHINE_PASSWORD", "machine-Password-1");

    eprintln!("kdc-stand: start");
    let cipher = OwnCipher;
    // In memory, or a file with sealed keys: see this file's documentation. A configuration that
    // names one variable and not the other stops here rather than starting a KDC that is not what
    // the operator asked for.
    let db = match stand_database() {
        Ok(db) => db,
        Err(e) => {
            eprintln!("kdc-stand: {e}");
            std::process::exit(1);
        }
    };

    let mut krbtgt = HdbEntry::krbtgt(&realm);
    for enctype in Enctype::ALL {
        krbtgt
            .add_password_key(&cipher, enctype, format!("krbtgt-{realm}").as_bytes(), 1)
            .unwrap();
    }
    // The `krbtgt` key, kept so the stand can write it out for a verifier. A real
    // deployment never writes this anywhere: the key opens every ticket in the
    // realm. It exists here so that `scripts/verify-pac-live.sh` can decrypt a
    // ticket and read the PAC the KDC put in it.
    let krbtgt_key = krbtgt
        .key_for(Enctype::Aes256Sha1)
        .map(|k| k.key.bytes().to_vec())
        .expect("the krbtgt entry has an AES-256 key");
    eprintln!("kdc-stand: krbtgt seeded");
    db.store(krbtgt).expect("the krbtgt entry is stored");

    // The machine's short name, uppercased, as AD spells a computer account.
    let machine = host.split('.').next().unwrap_or(&host).to_ascii_uppercase();
    let machine_principal = Principal::parse(&format!("{machine}$@{realm}")).unwrap();
    let mut machine_entry = HdbEntry {
        principal: machine_principal.clone(),
        keys: Vec::new(),
        // Filled by `add_password_key` below, from the machine password this stand generated.
        nt_hash: None,
        kvno: 0,
        flags: rrl_kdc::hdb::flags::SERVER
            | rrl_kdc::hdb::flags::CLIENT
            | rrl_kdc::hdb::flags::REQUIRE_PREAUTH,
        valid_start: None,
        valid_end: None,
        pw_end: None,
        max_life: None,
        max_renew: None,
        etypes: None,
        modified: 0,
        constrained_delegation: None,
        aliases: None,
        policy: None,
        strings: Vec::new(),
    };
    for enctype in Enctype::ALL {
        machine_entry
            .add_password_key(&cipher, enctype, machine_password.as_bytes(), 1)
            .unwrap();
    }
    eprintln!("kdc-stand: machine seeded");
    // Cloned: the machine's keys go into the keytab as well as the database.
    db.store(machine_entry.clone())
        .expect("the machine entry is stored");

    let mut administrator =
        HdbEntry::user(Principal::parse(&format!("administrator@{realm}")).unwrap());
    administrator.flags |= rrl_kdc::hdb::flags::SERVER
        | rrl_kdc::hdb::flags::REQUIRE_PREAUTH
        | rrl_kdc::hdb::flags::OK_AS_DELEGATE
        | rrl_kdc::hdb::flags::TRUSTED_FOR_DELEGATION;
    for enctype in Enctype::ALL {
        administrator
            .add_password_key(&cipher, enctype, admin_password.as_bytes(), 1)
            .unwrap();
    }
    eprintln!("kdc-stand: administrator seeded");
    db.store(administrator)
        .expect("the administrator entry is stored");

    eprintln!("kdc-stand: services next");
    // One key, three names: what a service keytab contains when the same host runs
    // an SMB server and an LDAP server.
    let mut keytab = Keytab::new();
    for service in ["host", "cifs", "ldap"] {
        let principal = Principal::parse(&format!("{service}/{host}@{realm}")).unwrap();
        let mut entry = HdbEntry::service(principal.clone());
        for enctype in Enctype::ALL {
            entry
                .add_password_key(&cipher, enctype, service_password.as_bytes(), 1)
                .unwrap();
        }
        for key in &entry.keys {
            keytab.add(KeytabEntry {
                principal: principal.clone(),
                key: key.key.clone(),
                kvno: key.kvno,
                timestamp: 0,
            });
        }
        db.store(entry).expect("a service entry is stored");
    }
    // The machine's own keys travel too: Samba reads its password from the join,
    // but a service that has to accept a ticket for the machine needs them.
    for key in &machine_entry.keys {
        keytab.add(KeytabEntry {
            principal: machine_principal.clone(),
            key: key.key.clone(),
            kvno: key.kvno,
            timestamp: 0,
        });
    }

    eprintln!(
        "kdc-stand: seeded, writing {} keytab entries",
        keytab.entries().len()
    );
    if let Err(e) = write(out.join("service.keytab"), &keytab.to_bytes()) {
        eprintln!("kdc-stand: cannot write the keytab: {e}");
        std::process::exit(1);
    }
    let krb5_conf = format!(
        "[libdefaults]\n\
         \x20default_realm = {realm}\n\
         \x20dns_lookup_realm = false\n\
         \x20dns_lookup_kdc = false\n\
         \x20rdns = false\n\
         \x20udp_preference_limit = 1\n\
         \x20default_ccache_name = FILE:/tmp/krb5cc_%{{uid}}\n\
         \n\
         [realms]\n\
         \x20{realm} = {{\n\
         \x20 kdc = {listen_host}\n\
         \x20 admin_server = {listen_host}\n\
         \x20}}\n\
         \n\
         [domain_realm]\n\
         \x20.{lower} = {realm}\n\
         \x20{lower} = {realm}\n",
        listen_host = listen_host(&listen),
        lower = realm.to_ascii_lowercase(),
    );
    if let Err(e) = write(out.join("krb5.conf"), krb5_conf.as_bytes()) {
        eprintln!("kdc-stand: cannot write krb5.conf: {e}");
        std::process::exit(1);
    }

    println!("kdc-stand: realm {realm}, machine {machine_principal}, listening on {listen}");

    let mut config = KdcConfig::new(&realm).unwrap();
    // A domain controller answers service tickets by SPN for principals it holds,
    // and the AS has to hand out a ticket for `ldap/host` before any TGT exists —
    // that is what `net ads join -k` needs.
    config
        .apply(
            "allowed_enctypes",
            "aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96",
        )
        .unwrap();
    let kdc = Kdc::new(config, Arc::clone(&db), Arc::new(cipher));

    // A PAC only when asked for: the AD-join stand runs this example against a
    // realm whose accounts have no SIDs, and a PAC stating an invented identity
    // would be worse than none.
    let kdc = if env("KDC_PAC", "0") == "1" {
        let mut rids: BTreeMap<String, u32> = BTreeMap::new();
        // `administrator` is 500 because that is the RID AD reserves for it, and a
        // client that reads 1105 there would see a different account.
        rids.insert(format!("administrator@{realm}"), 500);
        rids.insert(machine_principal.to_string(), 1100);
        for (i, service) in ["host", "cifs", "ldap"].iter().enumerate() {
            rids.insert(format!("{service}/{host}@{realm}"), 1101 + i as u32);
        }
        let realm_name = realm
            .split('.')
            .next()
            .unwrap_or(&realm)
            .to_ascii_uppercase();
        let identities = StandIdentities {
            domain: Sid::parse(&env("KDC_DOMAIN_SID", "S-1-5-21-100-200-300")).unwrap(),
            domain_name: realm_name,
            logon_server: env("KDC_LOGON_SERVER", &instance_name(&host)),
            rids,
        };
        if let Err(e) = write(
            out.join("krbtgt.key"),
            &krbtgt_key_file(&krbtgt_key, &realm),
        ) {
            eprintln!("kdc-stand: cannot write the krbtgt key: {e}");
            std::process::exit(1);
        }
        eprintln!(
            "kdc-stand: issuing PACs, {} identities",
            identities.rids.len()
        );
        kdc.with_pac(Arc::new(identities))
    } else {
        kdc
    };

    let running = serve_on(listen.as_str(), kdc);
    println!("kdc-stand: serving on {}", running.addr());
    // Serve until the process is told to stop: a stand's KDC is a service, and a
    // library example that exits after one request would be no use to `net`.
    loop {
        std::thread::sleep(std::time::Duration::from_secs(3600));
    }
}

/// The `krbtgt` key as the stand's verifier reads it.
///
/// A file with a comment saying what it is and why it must not exist in a real
/// deployment, then the key in lowercase hex. A reader that took the comment for
/// data would fail on the parse rather than silently use the wrong bytes.
fn krbtgt_key_file(key: &[u8], realm: &str) -> Vec<u8> {
    let hex: String = key.iter().map(|b| format!("{b:02x}")).collect();
    format!(
        "# The krbtgt AES-256 key of {realm}, in hex.\n\
         #\n\
         # This key decrypts every ticket in the realm. A real deployment never writes\n\
         # it to a file, and this file exists only so that a test can open a ticket and\n\
         # read the PAC inside it. Delete it when the stand stops.\n\
         {hex}\n"
    )
    .into_bytes()
}

/// The DC's own name, as a client would write it: the host's first label, uppercased.
fn instance_name(host: &str) -> String {
    host.split('.').next().unwrap_or(host).to_ascii_uppercase()
}

/// `host:port` from a bind address, with `0.0.0.0` replaced by the loopback a
/// client on this machine can reach.
fn listen_host(listen: &str) -> String {
    match listen.rsplit_once(':') {
        Some((host, port)) => {
            let host = if host == "0.0.0.0" || host.is_empty() || host == "[::]" {
                "127.0.0.1"
            } else {
                host
            };
            format!("{host}:{port}")
        }
        None => listen.to_owned(),
    }
}

/// The realm's database: in memory, or a sealed file when the stand was given a master key.
///
/// The two environment variables are all or nothing. `KDC_DB` without `KDC_MKEY` would be a KDC whose
/// keys sit on disk in the clear — a file that forges tickets for the whole realm — and `KDC_MKEY`
/// without `KDC_DB` has no file to seal. Both are configuration mistakes that would otherwise surface
/// only as a subtlety in somebody's backup, so they stop the stand with a sentence naming the missing
/// variable. That is the project's rule: a broken configuration fails loudly instead of quietly doing
/// something else.
#[cfg(feature = "hdb-redb")]
fn stand_database() -> std::io::Result<Arc<dyn Hdb>> {
    use rrl_kdc::hdb::RedbHdb;
    use rrl_kdc::hdb::mkey::MasterKeys;

    let path = std::env::var("KDC_DB").ok();
    let keytab = std::env::var("KDC_MKEY").ok();
    match (path, keytab) {
        (None, None) => Ok(MemoryHdb::new().shared()),
        (Some(_), None) => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "KDC_DB is set and KDC_MKEY is not: the stand would write the realm's keys to disk in \
             the clear. Set KDC_MKEY to a keytab with a K/M@REALM entry, or unset KDC_DB to keep \
             the realm in memory",
        )),
        (None, Some(_)) => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "KDC_MKEY is set and KDC_DB is not: there is no file for it to seal. Set KDC_DB to the \
             database path, or unset KDC_MKEY to keep the realm in memory",
        )),
        (Some(path), Some(keytab)) => {
            let keys = MasterKeys::from_keytab(&keytab).map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("KDC_MKEY={keytab}: {e}"),
                )
            })?;
            eprintln!(
                "kdc-stand: {path}, {} master key(s) from {keytab}, newest kvno {}",
                keys.keys().len(),
                keys.keys().first().map(|k| k.kvno).unwrap_or(0)
            );
            let hdb = RedbHdb::open_sealed(&path, keys, Arc::new(OwnCipher))
                .map_err(|e| std::io::Error::other(format!("KDC_DB={path}: {e}")))?;
            Ok(Arc::new(hdb))
        }
    }
}

/// A build without the redb backend has no file to seal, and accepting variables it would ignore is
/// worse than refusing them.
#[cfg(not(feature = "hdb-redb"))]
fn stand_database() -> std::io::Result<Arc<dyn Hdb>> {
    if std::env::var("KDC_DB").is_ok() || std::env::var("KDC_MKEY").is_ok() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "KDC_DB and KDC_MKEY need the `hdb-redb` feature, and this build does not have it",
        ));
    }
    Ok(MemoryHdb::new().shared())
}

fn env(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_owned())
}

fn write(path: PathBuf, bytes: &[u8]) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&path, bytes)
}
