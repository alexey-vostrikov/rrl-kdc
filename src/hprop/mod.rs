//! `hpropd`: the receiving half of Heimdal's database propagation (`kdc/hprop.c`, `kdc/hpropd.c`).
//!
//! A master KDC pushes its database to a slave over port 754: the slave authenticates the master,
//! receives one sealed HDB entry per message, and installs them **all or nothing** — a propagation
//! that dies half-way must leave the slave serving what it served before, not a mixture of two
//! databases.
//!
//! **The direction is master → slave, and the slave never asks.** That is the whole protocol: no
//! incrementality, no sequence numbers, no resumption. `hprop` walks the master's database and sends
//! every entry; the slave replaces its own. A slave that pushed back, or that accepted a stream into
//! its live database, would be a different (and worse) protocol, and neither side implements it.
//!
//! **Who may push is one principal, `kadmin/hprop@REALM`.** Heimdal checks exactly that name
//! (`kdc/hpropd.c`), and the reason it is a fixed name rather than an ACL is that the data is the
//! realm: whoever can push can set any principal's key, and an ACL that could be widened is an ACL
//! somebody would widen. A ticket for `hprop/HOST` proves the client can reach the service; the
//! client name proves it is the master.
//!
//! **All or nothing.** Entries go into a [`PropagationTarget`]'s staging area, and
//! [`PropagationTarget::commit`] runs only when the client sends the empty message that ends the
//! stream. On any error — a bad seal, a truncated stream, a refused principal — nothing is
//! committed, and the target discards what it staged. [`StagedHdb`] is the in-memory target;
//! [`FileTarget`] writes `<path>~` and renames it over `<path>`, which is Heimdal's own arrangement
//! and the only one that makes the swap atomic on a filesystem.
//!
//! **The keys arrive as they are.** Heimdal's `-E` seals them under the master key before they leave
//! the master; this crate has no master key yet (KRB-3.2), so a propagation carries plaintext keys
//! over a channel that is only as private as the seal of each message. That is stated rather than
//! implied: the stream is confidential per message, and the slave's database is not encrypted at
//! rest.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;

use crate::crypto::{Cipher, usage};
use crate::error::{Error, Result};
use crate::hdb::{Hdb, HdbEntry};
use crate::kdc::ap_req;
use crate::msg::kpasswd::{open_krb_priv_part, seal_krb_priv};
use crate::name::Principal;

pub mod push;
pub mod replica;
pub mod sendauth;

pub use sendauth::{APP_VERSION, SENDAUTH_VERSION};

/// The port `hprop` connects to (`HPROP_PORT`).
pub const PORT: u16 = 754;
/// The service name in the master's ticket: `hprop/HOST@REALM`.
pub const SERVICE: &str = "hprop";
/// The one principal allowed to push: `kadmin/hprop@REALM`.
pub const CLIENT: &str = "kadmin/hprop";

/// Where a propagation's entries go, and how they become visible.
///
/// The two calls are the protocol's two states: [`Self::store`] runs for every entry of the stream,
/// and [`Self::commit`] once, after the client has said the stream is complete. A target that
/// committed per entry would let a failed propagation become a half-updated realm.
pub trait PropagationTarget: Send + Sync + std::fmt::Debug {
    /// Stages one entry.
    fn store(&self, entry: HdbEntry) -> Result<()>;

    /// Makes everything staged so far the database readers see.
    ///
    /// Called once, and only for a stream that ended properly.
    fn commit(&self) -> Result<()>;
}

/// A target over a database in memory: what a test or a stand uses.
///
/// `commit` has nothing to install — the entries are already in the [`Hdb`] the caller supplied, and
/// the caller publishes it by handing the same `Arc` to the KDC it builds afterwards. The distinction
/// only matters for a target that has to make a swap visible, which is [`FileTarget`].
#[derive(Debug)]
pub struct StagedHdb {
    /// Where the entries are being staged. Empty until the first one arrives, which is what makes an
    /// interrupted propagation harmless: the caller's own database was never touched.
    staging: Arc<dyn Hdb>,
    /// How many entries were staged, for the summary a caller logs.
    staged: std::sync::atomic::AtomicUsize,
}

impl StagedHdb {
    /// A target that stages into `staging`, which should be empty and must not be the live database.
    pub fn new(staging: Arc<dyn Hdb>) -> StagedHdb {
        StagedHdb {
            staging,
            staged: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    /// The database the entries went into, once it is complete.
    pub fn hdb(&self) -> Arc<dyn Hdb> {
        Arc::clone(&self.staging)
    }
}

impl PropagationTarget for StagedHdb {
    fn store(&self, entry: HdbEntry) -> Result<()> {
        let principal = entry.principal.clone();
        self.staging
            .store(entry)
            .map_err(|e| Error::Hprop(format!("staging {principal}: {e}")))?;
        self.staged
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(())
    }

    fn commit(&self) -> Result<()> {
        // Nothing to install: the caller holds the same `Arc` and decides when to serve it.
        Ok(())
    }
}

/// A target over a database file: writes `<path>~` and renames it onto `<path>`.
///
/// The rename is the reason this exists. A slave that wrote into its live file would serve a mixture
/// of the old and the new database for the length of a propagation, and a crash in the middle would
/// leave that mixture permanently. Heimdal does the same `db~` → `db` swap.
#[cfg(feature = "hdb-redb")]
pub struct FileTarget {
    /// The file the propagation will replace.
    path: std::path::PathBuf,
    /// `<path>~`, where the entries go until `commit`.
    staging_path: std::path::PathBuf,
    /// The staging database, dropped before the rename so the file is closed.
    staging: std::sync::Mutex<Option<crate::hdb::redb_store::RedbHdb>>,
}

#[cfg(feature = "hdb-redb")]
impl std::fmt::Debug for FileTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileTarget")
            .field("path", &self.path)
            .field("staging_path", &self.staging_path)
            .finish()
    }
}

#[cfg(feature = "hdb-redb")]
impl FileTarget {
    /// A target that will replace `path`.
    ///
    /// The staging file is created empty and truncated, because a leftover from a previous
    /// propagation is not this one's database: keeping it would silently import entries the master
    /// has since deleted.
    pub fn new(path: impl Into<std::path::PathBuf>) -> Result<FileTarget> {
        let path = path.into();
        let staging_path = staging_path(&path);
        // Remove any leftover first: `RedbHdb::open` opens what it finds, and what it would find is
        // last time's half-written database.
        let _ = std::fs::remove_file(&staging_path);
        let staging = crate::hdb::redb_store::RedbHdb::open(&staging_path)?;
        Ok(FileTarget {
            path,
            staging_path,
            staging: std::sync::Mutex::new(Some(staging)),
        })
    }

    /// The file this target replaces.
    pub fn path(&self) -> &std::path::Path {
        &self.path
    }

    /// Stores the propagated entries **sealed** under the realm's master key.
    ///
    /// A slave's database is as valuable as its master's: a copy of it forges tickets for every
    /// principal in the realm. The staging file is re-opened sealed, so what a propagation installs is
    /// a file whose keys are `encrypt(master_key, HDB_KU_MKEY, …)` — the same form the master's own
    /// database is in.
    ///
    /// Must be called before the first entry arrives: a target that sealed halfway would leave a
    /// staging file with two kinds of record, and the point of this call is that it has one.
    pub fn with_master_keys(
        self,
        cipher: Arc<dyn Cipher>,
        keys: crate::hdb::mkey::MasterKeys,
    ) -> Result<FileTarget> {
        if keys.is_empty() {
            return Err(Error::Hprop(
                "with_master_keys was given no master key: a slave's database is the realm, and \
                 storing it in the clear is what this call exists to prevent"
                    .into(),
            ));
        }
        {
            let mut guard = self
                .staging
                .lock()
                .map_err(|_| Error::Hprop("the staging database is poisoned".into()))?;
            // Closed first: redb takes a lock on the file, and a second handle — even from the same
            // process — fails to open it.
            *guard = None;
        }
        let sealed =
            crate::hdb::redb_store::RedbHdb::open_sealed(&self.staging_path, keys, cipher)?;
        {
            let mut guard = self
                .staging
                .lock()
                .map_err(|_| Error::Hprop("the staging database is poisoned".into()))?;
            *guard = Some(sealed);
        }
        Ok(self)
    }
}

/// `<path>~`: the same shape Heimdal uses, and for the same reason — a name no running KDC opens.
#[cfg(feature = "hdb-redb")]
fn staging_path(path: &std::path::Path) -> std::path::PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push("~");
    std::path::PathBuf::from(name)
}

#[cfg(feature = "hdb-redb")]
impl PropagationTarget for FileTarget {
    fn store(&self, entry: HdbEntry) -> Result<()> {
        let principal = entry.principal.clone();
        let guard = self
            .staging
            .lock()
            .map_err(|_| Error::Hprop("the staging database is poisoned".into()))?;
        let db = guard.as_ref().ok_or_else(|| {
            Error::Hprop(
                "the propagation was already committed; a closed target takes no entries".into(),
            )
        })?;
        db.store(entry)
            .map_err(|e| Error::Hprop(format!("staging {principal}: {e}")))
    }

    fn commit(&self) -> Result<()> {
        let mut guard = self
            .staging
            .lock()
            .map_err(|_| Error::Hprop("the staging database is poisoned".into()))?;
        // Dropped before the rename: a redb file is memory-mapped and open while the object lives,
        // and renaming over a file another handle has open is the kind of thing that works on one
        // filesystem and not on the next.
        guard
            .take()
            .ok_or_else(|| Error::Hprop("the propagation was already committed".into()))?;
        std::fs::rename(&self.staging_path, &self.path).map_err(|e| {
            Error::Hprop(format!(
                "installing {} over {}: {e}",
                self.staging_path.display(),
                self.path.display()
            ))
        })
    }
}

/// What a completed propagation did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Summary {
    /// How many entries were staged and committed.
    pub entries: usize,
}

/// The receiving service.
pub struct Hprop {
    realm: String,
    /// The only client allowed to push.
    client: Principal,
    hdb: Arc<dyn Hdb>,
    cipher: Arc<dyn Cipher>,
    target: Arc<dyn PropagationTarget>,
    /// The realm's master keys, when its database stores sealed keys: without them an entry from a
    /// sealed master is refused by name rather than installed as a 60-octet "key".
    master: Option<Arc<crate::hdb::mkey::MasterKeys>>,
    max_skew: i64,
}

impl std::fmt::Debug for Hprop {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Hprop")
            .field("realm", &self.realm)
            .field("client", &self.client.to_string())
            .field("target", &self.target)
            .finish_non_exhaustive()
    }
}

impl Hprop {
    /// A service that accepts `kadmin/hprop@REALM`'s pushes into `target`.
    ///
    /// `hdb` is where the *service's own* key is read from — the `hprop/HOST` entry — and `cipher`
    /// the realm's, so that a ticket is opened with the same primitives everything else uses.
    pub fn new(
        hdb: Arc<dyn Hdb>,
        cipher: Arc<dyn Cipher>,
        realm: &str,
        target: Arc<dyn PropagationTarget>,
    ) -> Result<Hprop> {
        let client = Principal::parse(&format!("{CLIENT}@{realm}"))?;
        Ok(Hprop {
            realm: realm.to_owned(),
            client,
            hdb,
            cipher,
            target,
            master: None,
            max_skew: 300,
        })
    }

    /// The realm's master keys, so that a sealed database can be installed.
    ///
    /// A master whose database is sealed — the normal arrangement — sends each key encrypted under
    /// the master key. Without one here every entry is refused, and the refusal says so; with it the
    /// service opens each key and stores it.
    pub fn with_master_keys(mut self, keys: Arc<crate::hdb::mkey::MasterKeys>) -> Self {
        self.master = Some(keys);
        self
    }

    /// How much clock difference an authenticator may show.
    pub fn with_clock_skew(mut self, max_skew: i64) -> Self {
        self.max_skew = max_skew;
        self
    }

    /// The principal a master must be to push here.
    pub fn client(&self) -> &Principal {
        &self.client
    }

    /// Runs one propagation over `reader`/`writer`.
    ///
    /// `peer` is the address the connection came from, when it is known: a `KRB-PRIV` whose
    /// `s-address` disagrees with it is refused, which is what stops a message captured on one
    /// connection being played into another.
    pub fn handle<R: Read, W: Write>(
        &self,
        reader: &mut R,
        writer: &mut W,
        peer: Option<std::net::IpAddr>,
        now: i64,
    ) -> Result<Summary> {
        // Each step is named in the refusal: a propagation that fails has to be diagnosable from the
        // slave's log alone, and "io error" says nothing about which half of the protocol broke.
        let ap_req_bytes = sendauth::accept(reader, writer)
            .map_err(|e| Error::Hprop(format!("the sendauth handshake: {e}")))?;
        let accepted = ap_req::accept(
            self.cipher.as_ref(),
            self.hdb.as_ref(),
            &ap_req_bytes,
            SERVICE,
            &self.realm,
            now,
            self.max_skew,
        )
        .map_err(|(code, text)| Error::Hprop(format!("{text} (KDC error {code})")))?;

        // Authorization before anything is believed: the ticket proves the client can reach this
        // service, and the name proves it is the master. A refusal here answers nothing — the
        // stream ends, and nothing staged can be committed because nothing was read.
        if accepted.client != self.client {
            return Err(Error::Hprop(format!(
                "{} may not push a database: only {} may",
                accepted.client, self.client
            )));
        }

        // Mutual authentication, and the subkey that comes with it.
        //
        // Heimdal's `hprop` asks for `AP_OPTS_MUTUAL_REQUIRED | AP_OPTS_USE_SUBKEY` and then blocks
        // on an `AP-REP`, so a server that answered only the empty message would leave it waiting
        // until the socket timed out — which is exactly how this was found. The client's messages are
        // sealed in *its* subkey (from the authenticator), and ours are sealed in the subkey we
        // assert here: that is `krb5_rd_priv`'s preference (remote subkey first) and `krb5_mk_priv`'s
        // (local subkey first), and getting them the wrong way round means every entry fails its
        // integrity check while the handshake looks perfect.
        let mut read_key = accepted.session_key.clone();
        if let Some(subkey) = &accepted.authenticator.subkey {
            read_key = subkey.clone();
        }
        let mut write_key = accepted.session_key.clone();
        if accepted.ap_options & crate::msg::AP_OPTS_MUTUAL_REQUIRED != 0 {
            let ours = self
                .cipher
                .random(accepted.session_key.enctype())
                .map_err(|e| Error::Hprop(format!("a subkey for the AP-REP: {e}")))?;
            let ap_rep = crate::msg::kpasswd::ApRep::seal(
                self.cipher.as_ref(),
                &accepted.session_key,
                &crate::msg::kpasswd::EncApRepPart {
                    ctime: accepted.authenticator.ctime,
                    cusec: accepted.authenticator.cusec,
                    subkey: Some(ours.clone()),
                    seq_number: accepted.authenticator.seq_number,
                },
            )?;
            write_key = ours;
            sendauth::reply(writer, Some(&ap_rep))
                .map_err(|e| Error::Hprop(format!("answering the AP-REQ: {e}")))?;
        } else {
            sendauth::reply(writer, None)
                .map_err(|e| Error::Hprop(format!("answering the AP-REQ: {e}")))?;
        }

        let mut entries = 0usize;
        loop {
            let message = sendauth::read_message(reader)
                .map_err(|e| Error::Hprop(format!("entry {} of the stream: {e}", entries + 1)))?;
            if message.is_empty() {
                // The end of the stream. This is the only place anything becomes visible.
                self.target.commit()?;
                // Acknowledge with an empty sealed message, which is what Heimdal's receiver sends:
                // the client then knows the database was installed rather than merely received.
                let ack = seal_krb_priv(self.cipher.as_ref(), &write_key, &[], None, now)?;
                sendauth::write_message(writer, &ack)?;
                return Ok(Summary { entries });
            }

            let part = open_krb_priv_part(self.cipher.as_ref(), &read_key, &message)?;
            // The freshness check. `hprop` seals every entry with a timestamp, and without this
            // check a stream captured once could be replayed at will — including over a slave whose
            // master has been decommissioned.
            let timestamp = part
                .timestamp
                .ok_or_else(|| Error::Hprop("a propagation message carries no timestamp".into()))?;
            let skew = now.saturating_sub(timestamp);
            if skew.abs() > self.max_skew {
                return Err(Error::Hprop(format!(
                    "a propagation message is {skew}s from this slave's clock"
                )));
            }
            if let (Some(s_address), Some(peer)) = (&part.s_address, peer)
                && s_address.addr_type != 0
                && crate::address::HostAddress::from_ip(peer) != *s_address
            {
                return Err(Error::Hprop(format!(
                    "a propagation message says it came from {:?}, and this connection is from {peer}",
                    s_address.address
                )));
            }

            // Heimdal's `HDB_entry`, not this crate's own record format: `hprop` sends what
            // `hdb_entry2value` produces, and a slave that could only read `record` would receive
            // nothing at all.
            let entry = crate::hdb::value::decode_with(
                &part.user_data,
                self.master
                    .as_ref()
                    .map(|keys| (self.cipher.as_ref(), keys.as_ref())),
            )
            .map_err(|e| {
                // The first octets go into the message: an entry this codec cannot read is a
                // disagreement about a structure, and the tags are the whole evidence. A slave
                // operator with a log and no packet capture needs them.
                let head = &part.user_data[..part.user_data.len().min(96)];
                Error::Hprop(format!(
                    "entry {} of the stream: {e} (starts {:02x?}, {} octets)",
                    entries + 1,
                    head,
                    part.user_data.len()
                ))
            })?;
            self.target.store(entry)?;
            entries += 1;
        }
    }

    /// Runs one propagation over a socket.
    pub fn handle_connection(&self, stream: TcpStream, now: i64) -> Result<Summary> {
        let peer = stream.peer_addr().ok().map(|a| a.ip());
        // A read timeout, not a write one: the client may legitimately pause between entries while it
        // walks a large database, but a connection that produces nothing at all is a stuck slave
        // holding a port.
        let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(300)));
        let (mut reader, mut writer) = (stream.try_clone().map_err(Error::Io)?, stream);
        self.handle(&mut reader, &mut writer, peer, now)
    }
}

/// A source of the current time, as the service takes it: seconds since the epoch.
pub fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or_default()
}

/// A running `hpropd`, for a test or a stand.
#[derive(Debug)]
pub struct RunningHprop {
    addr: std::net::SocketAddr,
    stop: Arc<std::sync::atomic::AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
    last: Arc<std::sync::Mutex<Vec<std::result::Result<Summary, String>>>>,
}

impl RunningHprop {
    /// The address to push to, as `host:port`.
    pub fn addr(&self) -> String {
        self.addr.to_string()
    }

    /// What every finished propagation did, in the order they finished.
    ///
    /// A service has no caller to return to, so a test that wants to see a refusal needs this: the
    /// alternative is a test that cannot tell a refused push from a slow one. Failures come back as
    /// their text, because a logged reason outlives the error value and a test wants the sentence.
    pub fn results(&self) -> Vec<std::result::Result<Summary, String>> {
        self.last.lock().map(|r| r.clone()).unwrap_or_default()
    }
}

impl Drop for RunningHprop {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
        // One connection is accepted per iteration and the listener is blocking, so a connection is
        // opened to wake it. Without that, dropping a stand hangs for as long as the accept waits.
        let _ = std::net::TcpStream::connect(self.addr);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// Accepts propagations on `addr`, one connection at a time.
///
/// One at a time on purpose: two masters pushing at once would race for the target, and the protocol
/// has no notion of a master's identity beyond the client principal — which both would share.
pub fn serve_on<A: std::net::ToSocketAddrs>(addr: A, service: Hprop) -> Result<RunningHprop> {
    let listener = std::net::TcpListener::bind(addr).map_err(Error::Io)?;
    let addr = listener.local_addr().map_err(Error::Io)?;
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let last = Arc::new(std::sync::Mutex::new(Vec::new()));
    let service = Arc::new(service);
    let stop_for_thread = Arc::clone(&stop);
    let last_for_thread = Arc::clone(&last);

    let thread = std::thread::spawn(move || {
        loop {
            if stop_for_thread.load(std::sync::atomic::Ordering::Relaxed) {
                return;
            }
            match listener.accept() {
                Ok((stream, _)) => {
                    let _ = stream.set_nodelay(true);
                    let result = service
                        .handle_connection(stream, now())
                        .map_err(|e| e.to_string());
                    if let Ok(mut log) = last_for_thread.lock() {
                        log.push(result);
                    }
                }
                // Nothing waiting: yield rather than spin. A blocking accept would make `drop` wait
                // for the next connection instead of noticing the stop flag.
                Err(_) => std::thread::sleep(std::time::Duration::from_millis(20)),
            }
        }
    });

    Ok(RunningHprop {
        addr,
        stop,
        thread: Some(thread),
        last,
    })
}

/// Accepts propagations on an ephemeral loopback port.
pub fn serve_loopback(service: Hprop) -> Result<RunningHprop> {
    serve_on(("127.0.0.1", 0), service)
}

/// The `hprop/HOST` principal, as a realm provisioned by hand needs it.
///
/// No `INITIAL` flag: a master gets this ticket from its own TGT like any service ticket, which is
/// how `hprop` runs with a keytab and no password.
pub fn service_entry(
    realm: &str,
    host: &str,
    cipher: &dyn Cipher,
    password: &[u8],
) -> Result<HdbEntry> {
    let principal = Principal::parse(&format!("{SERVICE}/{host}@{realm}"))?;
    let mut entry = HdbEntry::service(principal);
    for enctype in crate::crypto::Enctype::ALL {
        entry.add_password_key(cipher, enctype, password, 1)?;
    }
    Ok(entry)
}

/// The `kadmin/hprop` principal: the master's identity, and the only one that may push.
///
/// A **client** entry, not a service one, and that is not a detail: Heimdal's `hprop` logs in as
/// `kadmin/hprop` with `kinit -k` and then asks for a service ticket *for* `hprop/HOST`. An entry
/// without `CLIENT` is refused by the AS (`KDC_ERR_POLICY`), which is exactly what the first run of
/// `scripts/hprop-stand.sh` produced — a stand is what catches that, since a unit test never asks
/// the AS for a TGT as this principal.
///
/// The keys are password-derived so that the same password can seed the master and the slave: the
/// slave may not have a keytab for the master, and after the first propagation it has the master's
/// real keys anyway.
pub fn master_entry(realm: &str, cipher: &dyn Cipher, password: &[u8]) -> Result<HdbEntry> {
    let principal = Principal::parse(&format!("{CLIENT}@{realm}"))?;
    let mut entry = HdbEntry::user(principal);
    for enctype in crate::crypto::Enctype::ALL {
        entry.add_password_key(cipher, enctype, password, 1)?;
    }
    Ok(entry)
}

/// Keeps `usage` in scope for the reader who wonders what the seal uses: `KRB-PRIV`'s enc-part.
const _: u32 = usage::KRB_PRIV_ENCPART;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{Enctype, Key, OwnCipher};
    use crate::hdb::MemoryHdb;
    use crate::msg::{ApReq, Authenticator, EncTicketPart, EncryptedData, Ticket};

    const REALM: &str = "EXAMPLE.COM";
    const NOW: i64 = 1_700_000_000;
    const HOST: &str = "kdc.example.com";

    fn p(name: &str) -> Principal {
        Principal::parse(name).expect("a principal")
    }

    /// A target that records what it was told, so a test can see the difference between "stored" and
    /// "committed" — which is the whole point of the two-call contract.
    #[derive(Debug, Default)]
    struct Recording {
        stored: std::sync::Mutex<Vec<Principal>>,
        commits: std::sync::atomic::AtomicUsize,
    }

    impl Recording {
        fn stored(&self) -> Vec<String> {
            self.stored
                .lock()
                .expect("stored")
                .iter()
                .map(|p| p.to_string())
                .collect()
        }
        fn commits(&self) -> usize {
            self.commits.load(std::sync::atomic::Ordering::Relaxed)
        }
    }

    impl PropagationTarget for Recording {
        fn store(&self, entry: HdbEntry) -> Result<()> {
            self.stored
                .lock()
                .expect("stored")
                .push(entry.principal.clone());
            Ok(())
        }
        fn commit(&self) -> Result<()> {
            self.commits
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Ok(())
        }
    }

    /// A target that fails on the second entry, to prove a broken stream commits nothing.
    #[derive(Debug, Default)]
    struct Failing {
        spec: Recording,
    }

    impl PropagationTarget for Failing {
        fn store(&self, entry: HdbEntry) -> Result<()> {
            self.spec.store(entry)?;
            if self.spec.stored().len() == 2 {
                return Err(Error::Hprop("the disk went away".into()));
            }
            Ok(())
        }
        fn commit(&self) -> Result<()> {
            self.spec.commit()
        }
    }

    /// The slave realm: an `hprop/HOST` service, the master's principal, and its service key.
    fn realm() -> (Arc<MemoryHdb>, Key) {
        let cipher = OwnCipher;
        let db = Arc::new(MemoryHdb::new());
        db.store(service_entry(REALM, HOST, &cipher, b"service password").expect("a service"))
            .expect("stored");
        db.store(master_entry(REALM, &cipher, b"master password").expect("a master"))
            .expect("stored");
        let key = db
            .fetch(&p(&format!("{SERVICE}/{HOST}@{REALM}")))
            .expect("a database")
            .expect("the service")
            .keys
            .first()
            .expect("a key")
            .key
            .clone();
        (db, key)
    }

    fn service_over(db: Arc<MemoryHdb>, target: Arc<dyn PropagationTarget>) -> Hprop {
        Hprop::new(
            Arc::clone(&db) as Arc<dyn Hdb>,
            Arc::new(OwnCipher),
            REALM,
            target,
        )
        .expect("a service")
    }

    /// The master's AP-REQ for `hprop/HOST@REALM`, and the session key its entries will be sealed in.
    ///
    /// The ticket's lifetime is derived from `at` rather than pinned to a constant, so a test over a
    /// real socket can issue one that is valid at the moment the service reads the clock.
    fn master_ap_req(service_key: &Key, client: &str, at: i64) -> (Vec<u8>, Key) {
        let cipher = OwnCipher;
        let session = cipher.random(Enctype::Aes256Sha1).expect("a session key");
        let part = EncTicketPart {
            flags: 0,
            session_key: session.clone(),
            crealm: REALM.to_owned(),
            cname: p(client),
            transited_type: 0,
            transited: Vec::new(),
            authtime: at - 60,
            starttime: None,
            endtime: at + 3600,
            renew_till: None,
            caddr: None,
            authorization_data: None,
        };
        let enc = EncryptedData::seal(
            &cipher,
            service_key,
            usage::KDC_REP_TICKET,
            None,
            &part.encode(),
        )
        .expect("the ticket seals");
        let ticket = Ticket {
            realm: REALM.to_owned(),
            sname: p(&format!("{SERVICE}/{HOST}@{REALM}")),
            enc,
        };
        let authenticator = Authenticator {
            crealm: REALM.to_owned(),
            cname: p(client),
            cksum: None,
            cusec: 0,
            ctime: at,
            subkey: None,
            seq_number: None,
            authorization_data: None,
        };
        let authenticator = EncryptedData::seal(
            &cipher,
            &session,
            usage::AP_REQ_AUTH,
            None,
            &authenticator.encode(),
        )
        .expect("the authenticator seals");
        let ap = ApReq {
            ap_options: 0,
            ticket: ticket.encode(),
            authenticator,
        };
        (ap.encode(), session)
    }

    /// What a real `hprop` writes, byte for byte, so that a pass here means the wire agrees without
    /// the client crate being present: the two version strings, the AP-REQ, the sealed entries, and
    /// the empty message that ends the stream.
    fn push(service_key: &Key, client: &str, entries: &[&str], timestamp: i64) -> (Vec<u8>, Key) {
        let (ap_req, session) = master_ap_req(
            service_key,
            client,
            if timestamp < NOW { NOW } else { timestamp },
        );
        let mut stream = Vec::new();
        for text in [SENDAUTH_VERSION, APP_VERSION] {
            let framed = [text.as_bytes(), &[0u8]].concat();
            stream.extend_from_slice(&(framed.len() as u32).to_be_bytes());
            stream.extend_from_slice(&framed);
        }
        stream.extend_from_slice(&(ap_req.len() as u32).to_be_bytes());
        stream.extend_from_slice(&ap_req);

        for name in entries {
            let mut entry = HdbEntry::user(p(name));
            entry.add_key(
                OwnCipher.random(Enctype::Aes256Sha1).expect("a key"),
                1,
                None,
            );
            let packed = crate::hdb::value::encode(&entry);
            let sealed =
                seal_krb_priv(&OwnCipher, &session, &packed, None, timestamp).expect("sealed");
            stream.extend_from_slice(&(sealed.len() as u32).to_be_bytes());
            stream.extend_from_slice(&sealed);
        }
        // The end of the stream: an empty message, framed.
        stream.extend_from_slice(&0u32.to_be_bytes());
        (stream, session)
    }

    /// Runs a push through the service and returns what it did, plus what the service wrote back.
    fn run(service: &Hprop, stream: &[u8]) -> (Result<Summary>, Vec<u8>) {
        let mut reader = std::io::Cursor::new(stream.to_vec());
        let mut writer = Vec::new();
        let result = service.handle(&mut reader, &mut writer, None, NOW);
        (result, writer)
    }

    /// The whole push: three entries arrive, one commit happens, and the acknowledgement is a sealed
    /// empty message the master can open.
    #[test]
    fn a_push_stores_every_entry_and_commits_once() {
        let (db, key) = realm();
        let target = Arc::new(Recording::default());
        let service = service_over(db, Arc::clone(&target) as Arc<dyn PropagationTarget>);
        let (stream, session) = push(
            &key,
            &format!("{CLIENT}@{REALM}"),
            &[
                &format!("alice@{REALM}"),
                &format!("bob@{REALM}"),
                &format!("host/s.example.com@{REALM}"),
            ],
            NOW,
        );

        let (result, back) = run(&service, &stream);
        assert_eq!(result.expect("the push succeeds"), Summary { entries: 3 });
        assert_eq!(
            target.stored(),
            vec![
                format!("alice@{REALM}"),
                format!("bob@{REALM}"),
                format!("host/s.example.com@{REALM}"),
            ],
            "in the order the master sent them"
        );
        assert_eq!(target.commits(), 1, "one commit, at the end");

        // The service's half of the sendauth handshake: the ok octet, the empty message after the
        // AP-REQ, then the sealed acknowledgement.
        assert_eq!(back[0], sendauth::OK);
        let after_ok = &back[1..];
        assert_eq!(
            &after_ok[..4],
            &0u32.to_be_bytes(),
            "no AP-REP was asked for"
        );
        let ack_len = u32::from_be_bytes(after_ok[4..8].try_into().expect("four octets")) as usize;
        let ack = &after_ok[8..8 + ack_len];
        let (data, _) = crate::msg::kpasswd::open_krb_priv(&OwnCipher, &session, ack)
            .expect("the acknowledgement opens in the session key");
        assert!(
            data.is_empty(),
            "the acknowledgement says nothing, it just confirms"
        );
    }

    /// A push from a principal that is not the master is refused, and **nothing** is stored or
    /// committed: authorization comes before the first entry is believed.
    #[test]
    fn a_push_from_another_principal_is_refused_and_stores_nothing() {
        let (db, key) = realm();
        let target = Arc::new(Recording::default());
        let service = service_over(db, Arc::clone(&target) as Arc<dyn PropagationTarget>);
        let (stream, _) = push(
            &key,
            &format!("alice@{REALM}"),
            &[&format!("mallory@{REALM}")],
            NOW,
        );

        let (result, _) = run(&service, &stream);
        let err = result.expect_err("only the master may push");
        assert!(err.to_string().contains("may not push a database"), "{err}");
        assert!(err.to_string().contains(&format!("{CLIENT}@")), "{err}");
        assert!(target.stored().is_empty(), "nothing may be staged");
        assert_eq!(target.commits(), 0, "and nothing may be committed");
    }

    /// A stream that stops before its empty message stores what arrived and **does not commit**: the
    /// slave keeps serving its old database, which is what all-or-nothing means.
    #[test]
    fn a_truncated_stream_commits_nothing() {
        let (db, key) = realm();
        let target = Arc::new(Recording::default());
        let service = service_over(db, Arc::clone(&target) as Arc<dyn PropagationTarget>);
        let (mut stream, _) = push(
            &key,
            &format!("{CLIENT}@{REALM}"),
            &[&format!("alice@{REALM}"), &format!("bob@{REALM}")],
            NOW,
        );
        // Drop the terminating empty message: the last four octets are its length prefix.
        stream.truncate(stream.len() - 4);

        let (result, _) = run(&service, &stream);
        let err = result.expect_err("a stream with no end is a broken stream");
        assert!(err.to_string().contains("closed the connection"), "{err}");
        assert_eq!(
            target.stored().len(),
            2,
            "both entries were staged — the target decides what to do with them"
        );
        assert_eq!(target.commits(), 0, "and none of it becomes visible");
    }

    /// A target that fails half-way does not commit either: the service stops at the first refusal
    /// rather than reading the rest of a stream it cannot store.
    #[test]
    fn a_target_that_fails_leaves_nothing_committed() {
        let (db, key) = realm();
        let target = Arc::new(Failing::default());
        let service = service_over(db, Arc::clone(&target) as Arc<dyn PropagationTarget>);
        let (stream, _) = push(
            &key,
            &format!("{CLIENT}@{REALM}"),
            &[
                &format!("alice@{REALM}"),
                &format!("bob@{REALM}"),
                &format!("carol@{REALM}"),
            ],
            NOW,
        );

        let (result, _) = run(&service, &stream);
        let err = result.expect_err("the target refused");
        assert!(err.to_string().contains("disk went away"), "{err}");
        assert_eq!(target.spec.commits(), 0);
        assert_eq!(target.spec.stored().len(), 2, "it stopped at the refusal");
    }

    /// An entry sealed with a stale timestamp is refused: a captured stream must not be replayable
    /// over a slave whose master has been decommissioned.
    #[test]
    fn a_stale_entry_is_refused() {
        let (db, key) = realm();
        let target = Arc::new(Recording::default());
        let service = service_over(db, Arc::clone(&target) as Arc<dyn PropagationTarget>);
        let (stream, _) = push(
            &key,
            &format!("{CLIENT}@{REALM}"),
            &[&format!("alice@{REALM}")],
            NOW - 3600,
        );

        let (result, _) = run(&service, &stream);
        let err = result.expect_err("an hour-old message is not fresh");
        assert!(err.to_string().contains("clock"), "{err}");
        assert!(target.stored().is_empty());
        assert_eq!(target.commits(), 0);
    }

    /// An entry that is not an HDB record is refused, and the refusal says which one: a stream of
    /// thousands where entry 4001 is corrupt has to be diagnosable.
    #[test]
    fn a_garbled_entry_is_refused_by_position() {
        let (db, key) = realm();
        let target = Arc::new(Recording::default());
        let service = service_over(db, Arc::clone(&target) as Arc<dyn PropagationTarget>);
        let (ap_req, session) = master_ap_req(&key, &format!("{CLIENT}@{REALM}"), NOW);
        let mut stream = Vec::new();
        for text in [SENDAUTH_VERSION, APP_VERSION] {
            let framed = [text.as_bytes(), &[0u8]].concat();
            stream.extend_from_slice(&(framed.len() as u32).to_be_bytes());
            stream.extend_from_slice(&framed);
        }
        stream.extend_from_slice(&(ap_req.len() as u32).to_be_bytes());
        stream.extend_from_slice(&ap_req);
        let sealed =
            seal_krb_priv(&OwnCipher, &session, b"not a record", None, NOW).expect("sealed");
        stream.extend_from_slice(&(sealed.len() as u32).to_be_bytes());
        stream.extend_from_slice(&sealed);
        stream.extend_from_slice(&0u32.to_be_bytes());

        let (result, _) = run(&service, &stream);
        let err = result.expect_err("not an HDB entry");
        assert!(err.to_string().contains("entry 1 of the stream"), "{err}");
        assert_eq!(target.commits(), 0);
    }

    /// The staging target over an `Hdb`: what a stand does, and the path the live database takes.
    #[test]
    fn the_staged_target_puts_entries_in_the_database_it_was_given() {
        let (db, key) = realm();
        let staging = Arc::new(MemoryHdb::new());
        let target = Arc::new(StagedHdb::new(Arc::clone(&staging) as Arc<dyn Hdb>));
        let service = service_over(db, Arc::clone(&target) as Arc<dyn PropagationTarget>);
        let (stream, _) = push(
            &key,
            &format!("{CLIENT}@{REALM}"),
            &[&format!("alice@{REALM}"), &format!("bob@{REALM}")],
            NOW,
        );
        run(&service, &stream).0.expect("the push succeeds");

        let alice = staging
            .fetch(&p(&format!("alice@{REALM}")))
            .expect("a database")
            .expect("alice arrived");
        assert_eq!(alice.principal.to_string(), format!("alice@{REALM}"));
        assert_eq!(alice.keys.len(), 1, "with her key");
        assert!(
            target
                .hdb()
                .fetch(&p(&format!("bob@{REALM}")))
                .unwrap()
                .is_some(),
            "bob arrived too"
        );
    }

    /// A file target can be made to seal, and refuses an empty key set: a slave that accepted a
    /// propagation into a plaintext file would hold a copy of the whole realm.
    #[cfg(feature = "hdb-redb")]
    #[test]
    fn a_file_target_seals_when_it_is_given_a_master_key() {
        use crate::crypto::OwnCipher;
        let dir = std::env::temp_dir().join(format!(
            "rrl-hprop-seal-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&dir).expect("a directory");

        // No master key: refused, because "seal" with nothing to seal with is not a mode.
        let target = FileTarget::new(dir.join("slave.db")).expect("a target");
        let err = target
            .with_master_keys(Arc::new(OwnCipher), crate::hdb::mkey::MasterKeys::none())
            .expect_err("no master key");
        assert!(err.to_string().contains("no master key"), "{err}");

        // With one: the staging database is sealed, and what it writes names the key.
        let key = OwnCipher.random(Enctype::Aes256Sha1).expect("a key");
        let master = crate::hdb::mkey::MasterKeys::single(key, 1);
        let target = FileTarget::new(dir.join("slave.db"))
            .expect("a target")
            .with_master_keys(Arc::new(OwnCipher), master.clone())
            .expect("sealed");
        let mut entry = HdbEntry::user(p(&format!("alice@{REALM}")));
        entry.add_key(
            OwnCipher.random(Enctype::Aes256Sha1).expect("a key"),
            1,
            None,
        );
        let plain = entry.keys[0].key.bytes().to_vec();
        target.store(entry).expect("staged");
        target.commit().expect("committed");

        let bytes = std::fs::read(dir.join("slave.db")).expect("the installed file");
        assert!(
            !bytes.windows(plain.len()).any(|w| w == plain.as_slice()),
            "a propagation installed a key in the clear"
        );
        let installed = crate::hdb::redb_store::RedbHdb::open_sealed(
            dir.join("slave.db"),
            master,
            Arc::new(OwnCipher),
        )
        .expect("sealed");
        let got = installed
            .fetch(&p(&format!("alice@{REALM}")))
            .expect("a fetch")
            .expect("alice");
        assert_eq!(got.keys[0].key.bytes(), plain.as_slice());

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The service name is `hprop/HOST` and the client is `kadmin/hprop`: the two names Heimdal
    /// checks, and the reason a ticket for any other service proves nothing.
    #[test]
    fn the_names_are_heimdals() {
        assert_eq!(PORT, 754);
        assert_eq!(SERVICE, "hprop");
        assert_eq!(CLIENT, "kadmin/hprop");
        assert_eq!(SENDAUTH_VERSION, "KRB5_SENDAUTH_V1.0");
        assert_eq!(APP_VERSION, "hprop-0.0");
        let (db, _) = realm();
        let service = service_over(db, Arc::new(Recording::default()));
        assert_eq!(service.client().to_string(), format!("{CLIENT}@{REALM}"));
        assert!(format!("{service:?}").contains("kadmin/hprop"));
    }

    /// The two entries a realm has to provision, and the flags that make them work.
    ///
    /// The distinction is the one that cost a stand run: the master is a **client** (it logs in with
    /// `kinit -k`), the service is a **service**, and the service is not `INITIAL` so that its ticket
    /// can be had from a TGT — which is how `hprop` runs with a keytab and no password.
    #[test]
    fn the_entries_a_realm_provisions_are_a_client_and_a_service() {
        let cipher = OwnCipher;
        let service = service_entry(REALM, HOST, &cipher, b"a password").expect("an entry");
        assert_eq!(
            service.principal.to_string(),
            format!("{SERVICE}/{HOST}@{REALM}")
        );
        assert_eq!(service.keys.len(), Enctype::ALL.len());
        assert!(service.has(crate::hdb::flags::SERVER));
        assert_eq!(
            service.flags & crate::hdb::flags::INITIAL,
            0,
            "an INITIAL service is reachable only through the AS, and hprop has a TGT"
        );

        let master = master_entry(REALM, &cipher, b"a password").expect("an entry");
        assert_eq!(master.principal.to_string(), format!("{CLIENT}@{REALM}"));
        assert!(
            master.has(crate::hdb::flags::CLIENT),
            "without CLIENT the AS refuses it with KDC_ERR_POLICY, and the master cannot log in"
        );
        assert_eq!(master.keys.len(), Enctype::ALL.len());
    }

    /// Over a real socket: the stand accepts one push, installs it, and acknowledges. This is the
    /// shape a slave actually runs in, and the only test where the service owns the connection.
    #[test]
    fn a_push_over_a_socket_is_installed() {
        let (db, key) = realm();
        let staging = Arc::new(MemoryHdb::new());
        let service = service_over(
            db,
            Arc::new(StagedHdb::new(Arc::clone(&staging) as Arc<dyn Hdb>)),
        );
        let stand = serve_loopback(service).expect("a stand");
        let (stream, _) = push(
            &key,
            &format!("{CLIENT}@{REALM}"),
            &[&format!("alice@{REALM}")],
            now(),
        );

        let mut socket = std::net::TcpStream::connect(stand.addr()).expect("connected");
        socket.write_all(&stream).expect("sent");
        socket
            .set_read_timeout(Some(std::time::Duration::from_secs(10)))
            .expect("a timeout");
        // The service answers with the ok octet, an empty message, then the acknowledgement.
        let mut back = Vec::new();
        let mut byte = [0u8; 1];
        socket.read_exact(&mut byte).expect("the ok octet");
        assert_eq!(byte[0], sendauth::OK);
        let mut len = [0u8; 4];
        socket.read_exact(&mut len).expect("the empty message");
        assert_eq!(len, [0, 0, 0, 0]);
        socket.read_exact(&mut len).expect("the acknowledgement");
        let mut ack = vec![0u8; u32::from_be_bytes(len) as usize];
        socket
            .read_exact(&mut ack)
            .expect("the acknowledgement body");
        back.extend_from_slice(&ack);
        assert!(
            !back.is_empty(),
            "the acknowledgement is a message, not a close"
        );

        assert!(
            staging
                .fetch(&p(&format!("alice@{REALM}")))
                .expect("a database")
                .is_some()
        );
        // And the stand recorded the result, which is how a test sees a failure it did not raise.
        // Polled: the handler writes its answer before it records the outcome, so a client that has
        // read the acknowledgement is still a moment ahead of the log.
        for _ in 0..100 {
            if !stand.results().is_empty() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        let results = stand.results();
        assert_eq!(results.len(), 1);
        assert_eq!(
            results[0].as_ref().expect("the push succeeded"),
            &Summary { entries: 1 }
        );
    }

    /// A connection that says nothing is a broken client, not a push of nothing: the stand records
    /// the failure rather than committing an empty database.
    #[test]
    fn a_silent_connection_installs_nothing() {
        let (db, _) = realm();
        let target = Arc::new(Recording::default());
        let service = service_over(db, Arc::clone(&target) as Arc<dyn PropagationTarget>);
        let stand = serve_loopback(service).expect("a stand");
        // Connected and closed: no version strings at all.
        drop(std::net::TcpStream::connect(stand.addr()).expect("connected"));
        for _ in 0..100 {
            if !stand.results().is_empty() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        let results = stand.results();
        assert_eq!(results.len(), 1);
        assert!(results[0].is_err());
        assert_eq!(target.commits(), 0);
    }
}
