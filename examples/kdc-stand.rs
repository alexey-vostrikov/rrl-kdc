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
use std::path::PathBuf;
use std::sync::Arc;

use rust_heimdal_kdc::crypto::{Enctype, OwnCipher};
use rust_heimdal_kdc::hdb::{Hdb, HdbEntry, Keytab, MemoryHdb, keytab::KeytabEntry};
use rust_heimdal_kdc::kdc::{Kdc, KdcConfig};
use rust_heimdal_kdc::name::Principal;
use rust_heimdal_kdc::transport::serve_on;

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
    let db = MemoryHdb::new();

    let mut krbtgt = HdbEntry::krbtgt(&realm);
    for enctype in Enctype::ALL {
        krbtgt
            .add_password_key(&cipher, enctype, format!("krbtgt-{realm}").as_bytes(), 1)
            .unwrap();
    }
    eprintln!("kdc-stand: krbtgt seeded");
    db.insert(krbtgt).unwrap();

    // The machine's short name, uppercased, as AD spells a computer account.
    let machine = host.split('.').next().unwrap_or(&host).to_ascii_uppercase();
    let machine_principal = Principal::parse(&format!("{machine}$@{realm}")).unwrap();
    let mut machine_entry = HdbEntry {
        principal: machine_principal.clone(),
        keys: Vec::new(),
        kvno: 0,
        flags: rust_heimdal_kdc::hdb::flags::SERVER
            | rust_heimdal_kdc::hdb::flags::CLIENT
            | rust_heimdal_kdc::hdb::flags::REQUIRE_PREAUTH,
        valid_start: None,
        valid_end: None,
        pw_end: None,
        max_life: None,
        max_renew: None,
        etypes: None,
        modified: 0,
    };
    for enctype in Enctype::ALL {
        machine_entry
            .add_password_key(&cipher, enctype, machine_password.as_bytes(), 1)
            .unwrap();
    }
    eprintln!("kdc-stand: machine seeded");
    // Cloned: the machine's keys go into the keytab as well as the database.
    db.insert(machine_entry.clone()).unwrap();

    let mut administrator =
        HdbEntry::user(Principal::parse(&format!("administrator@{realm}")).unwrap());
    administrator.flags |= rust_heimdal_kdc::hdb::flags::SERVER
        | rust_heimdal_kdc::hdb::flags::REQUIRE_PREAUTH
        | rust_heimdal_kdc::hdb::flags::OK_AS_DELEGATE
        | rust_heimdal_kdc::hdb::flags::TRUSTED_FOR_DELEGATION;
    for enctype in Enctype::ALL {
        administrator
            .add_password_key(&cipher, enctype, admin_password.as_bytes(), 1)
            .unwrap();
    }
    eprintln!("kdc-stand: administrator seeded");
    db.insert(administrator).unwrap();

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
        db.insert(entry).unwrap();
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
    let kdc = Kdc::new(config, Arc::new(db) as Arc<dyn Hdb>, Arc::new(cipher));

    let running = serve_on(listen.as_str(), kdc);
    println!("kdc-stand: serving on {}", running.addr());
    // Serve until the process is told to stop: a stand's KDC is a service, and a
    // library example that exits after one request would be no use to `net`.
    loop {
        std::thread::sleep(std::time::Duration::from_secs(3600));
    }
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

fn env(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_owned())
}

fn write(path: PathBuf, bytes: &[u8]) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&path, bytes)
}
