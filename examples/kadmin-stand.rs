//! A KDC and a `kadmind` for a stand, so a **stock** `kadmin` client can be pointed at them.
//!
//! Why this exists. `tests/kadmin_live.rs` already drives the admin protocol with the `krb5` crate,
//! and that is the right judge for the wire format. What it cannot answer is whether MIT's own
//! `kadmin` — the binary every operator has — connects, because it needs what no in-process test
//! has: a `krb5.conf` on disk with `admin_server` in it, a ticket cache, and a port it can name.
//!
//! So this seeds a realm, writes both files, and serves until killed:
//!
//! ```sh
//! cargo run --example kadmin-stand -- 127.0.0.1:88 127.0.0.1:749 /shared
//! KRB5_CONFIG=/shared/krb5.conf KRB5CCNAME=FILE:/tmp/cc kadmin -p kadmin/admin -w … -q getprincs
//! ```
//!
//! The addresses are arguments rather than defaults because the stand runs unprivileged in a
//! container: 88 and 749 are what a `krb5.conf` normally says, and they are below 1024.
//!
//! What it seeds:
//!
//! * `krbtgt/REALM` — the realm itself.
//! * `kadmin/admin` — the principal `kadmin -p` logs in as. `REQUIRE_PREAUTH`, from `admin_entry`.
//! * `alice` — a user an administrator creates, reads and deletes during a run.
//!
//! The policy is `KADMIN_STAND_DENY=1`: the administrator has every right, or **none**. The second
//! shape is the one worth having: a stock client asked to do something it has no right to must print
//! MIT's `AUTH_*` message, and the only way to see that is to run it against a server that refuses.
use std::path::PathBuf;
use std::sync::Arc;

use rrl_kdc::admin::wire::{Grants, Rights};
use rrl_kdc::crypto::{Cipher, Enctype, OwnCipher};
use rrl_kdc::hdb::{Hdb, HdbEntry, MemoryHdb, flags};
use rrl_kdc::kadmin::{Kadmin, admin_entry, serve_kadmin_on};
use rrl_kdc::kdc::{Kdc, KdcConfig};
use rrl_kdc::name::Principal;
use rrl_kdc::transport::serve_on;

fn env(name: &str, default: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| default.to_owned())
}

fn main() {
    let mut args = std::env::args().skip(1);
    let kdc_addr = args.next().unwrap_or_else(|| "127.0.0.1:88".to_owned());
    let admin_addr = args.next().unwrap_or_else(|| "127.0.0.1:749".to_owned());
    let out = PathBuf::from(args.next().unwrap_or_else(|| "/shared".to_owned()));

    let realm = env("STAND_REALM", "EXAMPLE.COM");
    let admin_password = env("STAND_ADMIN_PASSWORD", "admin-Password-1");
    let alice_password = env("STAND_ALICE_PASSWORD", "alice-Password-1");
    let deny = env("STAND_DENY", "0") == "1";

    eprintln!("kadmin-stand: start, realm {realm}, denying={deny}");
    let cipher: Arc<dyn Cipher> = Arc::new(OwnCipher);
    let db = Arc::new(MemoryHdb::new());

    let mut krbtgt = HdbEntry::krbtgt(&realm);
    for enctype in Enctype::ALL {
        krbtgt
            .add_password_key(&*cipher, enctype, format!("krbtgt-{realm}").as_bytes(), 1)
            .expect("the krbtgt key");
    }
    db.store(krbtgt).expect("the krbtgt entry");

    // `admin_entry` sets `CLIENT` itself: without it this principal cannot obtain the initial
    // ticket `kadmin -p` needs, and the client stops with "KDC policy rejects request".
    let admin = admin_entry(&realm, &*cipher, admin_password.as_bytes()).expect("the admin entry");
    db.store(admin).expect("the admin entry");

    // `kadmin/<admin-server-host>`, which is the name MIT's `kadmin` asks an *initial* ticket for
    // before it talks to the admin port — `Setting initial creds service to kadmin/127.0.0.1` in its
    // trace. A realm that has only `kadmin/admin` answers that request with an unknown principal,
    // and the client stops before the first call. MIT's own `kdb5_util create` seeds this pair for
    // the same reason.
    let admin_host = admin_addr
        .rsplit_once(':')
        .map_or(admin_addr.as_str(), |(host, _)| host);
    let mut kadmin_host = HdbEntry::service(
        Principal::parse(&format!("kadmin/{admin_host}@{realm}")).expect("a name"),
    );
    for enctype in Enctype::ALL {
        kadmin_host
            .add_password_key(
                &*cipher,
                enctype,
                format!("kadmin-host-{realm}").as_bytes(),
                1,
            )
            .expect("the kadmin/host key");
    }
    db.store(kadmin_host).expect("the kadmin/host entry");

    let mut alice = HdbEntry::user(Principal::parse(&format!("alice@{realm}")).expect("a name"));
    alice.flags |= flags::REQUIRE_PREAUTH;
    for enctype in Enctype::ALL {
        alice
            .add_password_key(&*cipher, enctype, alice_password.as_bytes(), 1)
            .expect("alice's key");
    }
    db.store(alice).expect("alice's entry");

    // The two files a stock client needs, and nothing else: `krb5.conf` names the KDC and the admin
    // server, and the realm has to be spelled the same in both places.
    let conf = format!(
        "[libdefaults]\n\
         \x20default_realm = {realm}\n\
         \x20dns_lookup_realm = false\n\
         \x20dns_lookup_kdc = false\n\
         \x20rdns = false\n\
         \x20udp_preference_limit = 1\n\
         \x20default_ccache_name = FILE:/tmp/krb5cc_stand\n\
         \n\
         [realms]\n\
         \x20{realm} = {{\n\
         \x20 kdc = {kdc_addr}\n\
         \x20 admin_server = {admin_addr}\n\
         \x20}}\n"
    );
    if let Err(e) = std::fs::create_dir_all(&out) {
        eprintln!("kadmin-stand: cannot create {}: {e}", out.display());
        std::process::exit(1);
    }
    if let Err(e) = std::fs::write(out.join("krb5.conf"), conf.as_bytes()) {
        eprintln!("kadmin-stand: cannot write krb5.conf: {e}");
        std::process::exit(1);
    }
    eprintln!(
        "kadmin-stand: krb5.conf at {}",
        out.join("krb5.conf").display()
    );

    // Two engines over one database, not one engine shared: `Kdc` is not `Clone`, and the ticket a
    // `kadmin` client presents has to be issued by a KDC that sees the same principals the admin
    // server writes — so the sharing is at the database, which is where it matters.
    let config = KdcConfig::new(&realm).expect("a realm name");
    let engine = || {
        Kdc::new(
            config.clone(),
            Arc::clone(&db) as Arc<dyn Hdb>,
            Arc::clone(&cipher),
        )
    };

    let policy: Arc<dyn rrl_kdc::admin::wire::Policy> = if deny {
        Arc::new(Grants::new())
    } else {
        let actor = Principal::parse(&format!("kadmin/admin@{realm}")).expect("a name");
        Arc::new(Grants::new().grant(&actor, Rights::ALL))
    };
    let kadmin = Kadmin::new(engine(), policy).expect("a kadmind over the realm");

    let kdc_stand = serve_on(kdc_addr.clone(), engine());
    let admin_stand = serve_kadmin_on(admin_addr.clone(), kadmin).unwrap_or_else(|e| {
        eprintln!("kadmin-stand: cannot serve the admin port: {e}");
        std::process::exit(1);
    });

    println!(
        "kadmin-stand: kdc on {}, admin on {}",
        kdc_stand.addr(),
        admin_stand.addr()
    );
    println!("kadmin-stand: realm {realm}, admin password {admin_password}");

    // Until killed. A stand that exited would leave the client with a socket that closes mid-call,
    // which reads as a server fault.
    loop {
        std::thread::sleep(std::time::Duration::from_secs(3600));
    }
}
