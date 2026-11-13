//! A KDC that offers SPAKE over a fixed port, so a client from outside this process can log in.
//!
//! `tests/spake_live.rs` drives the exchange with this crate's own client. That proves the two
//! halves agree, which is exactly what a self-test cannot rule out. This example exists so a real
//! third-party client — MIT's `kinit` — can be pointed at the realm, and it is what
//! `scripts/spake-nist-stand.sh` runs.
//!
//! The realm is fixed and small on purpose: a stand is read, not configured.
//!
//! ```text
//! spake-stand 127.0.0.1:18888
//! ```
//!
//! It prints one line per mechanism decision to stderr, because the interesting failure is not
//! "the login failed" but "the client asked for P-384 and we chose P-521".

use std::sync::Arc;

use rrl_kdc::crypto::{Cipher, Enctype, OwnCipher};
use rrl_kdc::hdb::{Hdb, HdbEntry, MemoryHdb};
use rrl_kdc::kdc::spake::Spake;
use rrl_kdc::kdc::{Kdc, KdcConfig};
use rrl_kdc::name::Principal;

const REALM: &str = "SPAKE.TEST";
const PASSWORD: &str = "correct horse battery staple";

fn realm() -> Arc<dyn Hdb> {
    let cipher = OwnCipher;
    let db = MemoryHdb::new();

    let mut krbtgt = HdbEntry::krbtgt(REALM);
    for e in [Enctype::Aes256Sha1, Enctype::Aes128Sha1] {
        krbtgt
            .add_password_key(&cipher, e, b"master-key-of-the-realm", 1)
            .unwrap();
    }
    db.insert(krbtgt).unwrap();

    let mut alice = HdbEntry::user(Principal::parse(&format!("alice@{REALM}")).unwrap());
    for e in [Enctype::Aes256Sha1, Enctype::Aes128Sha1] {
        alice
            .add_password_key(&cipher, e, PASSWORD.as_bytes(), 1)
            .unwrap();
    }
    db.insert(alice).unwrap();
    Arc::new(db)
}

fn main() {
    let addr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:18888".to_owned());
    let cipher = OwnCipher;
    // The cookie is where SPAKE's state lives between the challenge and the answer. Without it a
    // second round has nothing to resume, and the exchange fails as "no challenge is outstanding".
    let cookie = cipher
        .s2k(Enctype::Aes256Sha1, b"cookie-secret", b"cookie", None)
        .unwrap();

    let kdc = Kdc::new(KdcConfig::new(REALM).unwrap(), realm(), Arc::new(OwnCipher))
        .with_cookie_key(cookie)
        .with_mechanism(Arc::new(Spake::new()));

    let running = rrl_kdc::transport::serve_on(addr.as_str(), kdc);
    eprintln!(
        "spake-stand: realm {REALM}, password {PASSWORD:?}, listening on {}",
        running.addr()
    );
    // Run until the container is torn down: the script kills it, and a KDC that exits after one
    // login cannot be used for the second (a wrong password, a different group).
    loop {
        std::thread::sleep(std::time::Duration::from_secs(3600));
    }
}
