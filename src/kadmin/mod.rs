//! `kadmind`: MIT's `kadm5` protocol over ONC RPC, authenticated by RPCSEC_GSS.
//!
//! This is the transport a stock `kadmin` speaks, and the reason it exists here is
//! that an operator with a working `kadmin` should not have to learn a second one.
//! The crate's own [`crate::admin::wire`] stays the interface an embedder uses; this
//! module is one more front end over the same `Admin`, with the same rights
//! checked in the same place.
//!
//! # What is implemented, and what is not
//!
//! Procedures: `kadm5_init`, `get_privs`, `get_principal`, `get_principals`,
//! `create_principal`, `delete_principal`, `chpass_principal`, `chrand_principal3`.
//! Policies, string attributes and `extract_keys` are not: they are the part of
//! `kadm5` this crate has no model for, and answering them with a made-up success
//! would be worse than the `KADM5_UNK_PROC` an unimplemented procedure earns.
//!
//! # The three layers, and which one is easy to get wrong
//!
//! * **ONC RPC** (RFC 5531): record marking over TCP, one call one reply. Easy.
//! * **RPCSEC_GSS** (RFC 2203): a NULLPROC carrying the AP-REQ establishes the
//!   context; every call after it is sealed in a GSS Wrap token and carries a MIC
//!   over the RPC header as its verifier. The MIC is the trap: it covers the
//!   header *as it arrived*, so the parser has to remember where the header ended.
//! * **kadm5** (XDR): the structures, and the status codes — which are MIT's, not
//!   Kerberos', and are what a client prints as an error message.
//!
//! # Authorization
//!
//! Every procedure checks a [`Right`] through the same [`Policy`] the JSON and
//! in-process front ends use. A `kadmin` client that connects as somebody with no
//! rights gets `KADM5_AUTH_*` and no data, which is the answer an operator
//! expects; a `kadmin` server that checked its own ACL instead would be a fourth
//! place where authority is decided.

pub mod gss;
pub mod kadm5;
pub mod rpc;
pub mod xdr;

use std::sync::Arc;

use crate::admin::Admin;
use crate::admin::wire::{Policy, Right};
use crate::crypto::usage;
use crate::error::{Error, Result};
use crate::hdb::HdbEntry;
use crate::kdc::Kdc;
use crate::msg::{ApReq, Authenticator, EncTicketPart};
use crate::name::Principal;

use gss::AcceptorContext;
use rpc::Call;
use xdr::{Reader, Writer};

/// The `kadmin/admin` principal of `realm` — the service a client's ticket is for.
pub fn service_principal(realm: &str) -> Result<Principal> {
    Principal::parse(&format!("kadmin/admin@{realm}")).map_err(Error::from)
}

/// Whether `candidate` names this realm's admin service: `kadmin/<anything>@<realm>`.
///
/// The second component is not checked, and deliberately: MIT's `kadmin` asks for
/// `kadmin/<admin-server-host>` while `kadmin.local` and the documented principal are `kadmin/admin`,
/// and both travel to the same server with a keytab that holds both. Only the first component and the
/// realm decide that this is the admin service rather than some other.
fn is_admin_service(candidate: &Principal, configured: &Principal) -> bool {
    candidate.realm == configured.realm
        && candidate.components.len() == configured.components.len()
        && candidate.components.first() == configured.components.first()
}

/// The `kadmin/admin` entry a realm needs, keyed with `password`.
///
/// `INITIAL` and `change-pw` are not set: a `kadmin` ticket is a *service* ticket,
/// obtained with a TGT, which is what MIT does and what makes `kadmin -p` work
/// from any host the TGT is valid on. The change-password service is a different
/// principal with different flags for exactly that reason.
///
/// `CLIENT` **is** set, and that is not a detail: `kadmin -p` with no ticket cache asks the KDC for
/// an initial ticket for this principal, and a KDC that finds only `SERVER` on the entry refuses
/// with `KDC_ERR_POLICY` — *"is not a client principal"*. An administrator who cannot obtain the
/// ticket that opens the admin port has a realm nobody can administer. Measured against MIT's
/// `kadmin`: without this flag the first thing it prints is `KDC policy rejects request while
/// initializing kadmin interface`.
pub fn admin_entry(
    realm: &str,
    cipher: &dyn crate::crypto::Cipher,
    password: &[u8],
) -> Result<HdbEntry> {
    let mut entry = HdbEntry::service(service_principal(realm)?);
    entry.flags |= crate::hdb::flags::REQUIRE_PREAUTH | crate::hdb::flags::CLIENT;
    for enctype in crate::crypto::Enctype::ALL {
        entry.add_password_key(cipher, enctype, password, 1)?;
    }
    Ok(entry)
}

/// The service: a `Kdc` for the realm, an `Admin` for the operations, and a policy
/// for who may do what.
#[derive(Debug)]
pub struct Kadmin {
    kdc: Kdc,
    admin: Admin,
    service: Principal,
}

impl Kadmin {
    /// A `kadmind` for `realm`, over `kdc`'s database.
    ///
    /// The `Admin` is built from the `Kdc` so that a ticket the KDC issues and a
    /// principal `kadmind` creates cannot come from two different databases.
    pub fn new(kdc: Kdc, policy: Arc<dyn Policy>) -> Result<Self> {
        let realm = kdc.config().realm().to_owned();
        let admin = Admin::with_defaults(realm.clone(), kdc.hdb_arc(), kdc.cipher_arc())
            .with_policy(policy);
        Ok(Kadmin {
            service: service_principal(&realm)?,
            kdc,
            admin,
        })
    }

    /// The realm being administered.
    pub fn realm(&self) -> &str {
        self.admin.realm()
    }

    /// The `Admin` behind the protocol, for a caller that wants both.
    pub fn admin(&self) -> &Admin {
        &self.admin
    }

    /// Handles one RPC call after the GSS context is established.
    ///
    /// Returns the XDR results, or a `kadm5` status the caller turns into a
    /// successful RPC reply carrying an error code — MIT's protocol reports errors
    /// in the results, not in the RPC layer, so a client can print the reason.
    fn dispatch(&self, actor: &Principal, call: &Call, args: &[u8], now: i64) -> Vec<u8> {
        let version = Reader::new(args).u32().unwrap_or(kadm5::API_VERSION_2);
        let status = self.dispatch_inner(actor, call, args, version, now);
        let mut out = Writer::new();
        out.u32(version);
        match status {
            Ok(result) => {
                out.u32(kadm5::OK);
                out.raw(&result);
            }
            Err(code) => {
                out.u32(code);
            }
        }
        out.into_bytes()
    }

    /// The procedure itself, or the `kadm5` code that refused it.
    fn dispatch_inner(
        &self,
        actor: &Principal,
        call: &Call,
        args: &[u8],
        version: u32,
        now: i64,
    ) -> std::result::Result<Vec<u8>, u32> {
        // Who is changing what: every procedure that writes an entry records the actor that the
        // GSS context authenticated and the instant this connection started. Passed in rather than
        // read here, because the clock is the server's decision, not this function's.
        let stamp = crate::admin::Stamp::by(actor, now);
        if call.prog != kadm5::PROG || call.vers != kadm5::VERS {
            return Err(kadm5::UNK_PROC);
        }
        match call.proc_ {
            kadm5::INIT => {
                // MIT's init_any: the client offers 4, then 3, then 2, and a
                // server that speaks an older one answers with
                // `KADM5_NEW_SERVER_API_VERSION` so the client steps down. This
                // server speaks 2 and accepts the rest by ignoring the fields it
                // does not know, which is what keeps `kadmin` from MIT 1.18
                // talking to it.
                Ok(Vec::new())
            }
            kadm5::GET_PRIVS => {
                // Every privilege, to every caller — which is what MIT does, and for the same
                // reason. Its `kadm5_get_privs` says so in as many words: *"this is impossible to
                // do with the current interface. For now, return all privs, which will confuse
                // some clients, but not deny any access to users of smart clients which try to
                // cache"*. The interface cannot answer it: a grant may be narrowed to particular
                // targets, and this call names none.
                //
                // This used to answer zero to a caller without `List`, and that is the failure the
                // MIT comment warns about: a client that caches `0` refuses operations it is in
                // fact allowed to perform, and the operator sees "insufficient privileges" for a
                // right the ACL had granted. Enforcement is per procedure, in `require`, and it
                // reads the policy every time — so answering generously here denies nothing.
                let _ = actor;
                let mut out = Writer::new();
                out.u32(kadm5::PRIV_ALL);
                Ok(out.into_bytes())
            }
            kadm5::GET_PRINCIPAL => {
                self.require(actor, Right::Read)?;
                let mut r = Reader::new(args);
                let _ = r.u32();
                let name = r
                    .nullstring()
                    .map_err(|_| kadm5::BAD_MASK)?
                    .ok_or(kadm5::UNK_PRINC)?;
                let principal = Principal::parse(&name).map_err(|_| kadm5::UNK_PRINC)?;
                let entry = self.admin.get(&principal).map_err(status_of)?;
                Ok(kadm5::encode_principal_entry(&entry))
            }
            kadm5::GET_PRINCS => {
                self.require(actor, Right::List)?;
                let mut r = Reader::new(args);
                let _ = r.u32();
                let glob = r
                    .nullstring()
                    .ok()
                    .flatten()
                    .unwrap_or_else(|| "*".to_owned());
                let mut names: Vec<String> = self
                    .admin
                    .list()
                    .map_err(status_of)?
                    .into_iter()
                    .map(|p| p.to_string())
                    .filter(|name| glob_matches(&glob, name))
                    .collect();
                names.sort();
                let mut out = Writer::new();
                // `n_princs` and then the array's own count: MIT's structure has
                // both, and a decoder reads both. Names are NUL-terminated.
                out.i32(names.len() as i32);
                out.u32(names.len() as u32);
                for name in &names {
                    out.nullstring(Some(name));
                }
                Ok(out.into_bytes())
            }
            kadm5::MODIFY_PRINCIPAL => {
                self.require(actor, Right::Modify)?;
                let (principal, change) = kadm5::decode_modify(args).inspect_err(|status| {
                    // The name is inside the record the decoder could not read, so all that can be
                    // said is that a modify was refused before anything was applied.
                    log_refusal(&format!("modify: the request was refused ({status})"));
                })?;
                self.admin
                    .modify_by(&principal, change, &stamp)
                    .map_err(|e| {
                        log_refusal(&format!("modify {principal}: {e}"));
                        // A value the field mask named and this server rejected — a kvno below the
                        // keys, an expiry it cannot store — is a bad mask, not a server failure: the
                        // operator named a field and gave it something it cannot hold.
                        match e {
                            crate::Error::Config(_) => kadm5::BAD_MASK,
                            other => status_of(other),
                        }
                    })?;
                Ok(Vec::new())
            }
            kadm5::RENAME_PRINCIPAL => {
                self.require(actor, Right::Modify)?;
                let (from, to) = kadm5::decode_rename(args).inspect_err(|status| {
                    log_refusal(&format!("rename: the request was refused ({status})"));
                })?;
                self.admin.rename(&from, &to).map_err(|e| {
                    log_refusal(&format!("rename {from} to {to}: {e}"));
                    status_of(e)
                })?;
                Ok(Vec::new())
            }
            kadm5::CREATE_POLICY => {
                self.require(actor, Right::Create)?;
                let (policy, mask) =
                    kadm5::decode_policy_request(args, version).inspect_err(|status| {
                        log_refusal(&format!(
                            "create_policy: the request was refused ({status})"
                        ));
                    })?;
                if !kadm5::policy_create_mask_ok(mask) {
                    return Err(kadm5::BAD_MASK);
                }
                self.admin.create_policy(policy).map_err(|e| {
                    log_refusal(&format!("create_policy: {e}"));
                    status_of(e)
                })?;
                Ok(Vec::new())
            }
            kadm5::MODIFY_POLICY => {
                self.require(actor, Right::Modify)?;
                let (policy, mask) =
                    kadm5::decode_policy_request(args, version).inspect_err(|status| {
                        log_refusal(&format!(
                            "modify_policy: the request was refused ({status})"
                        ));
                    })?;
                if !kadm5::policy_modify_mask_ok(mask) {
                    return Err(kadm5::BAD_MASK);
                }
                self.admin.modify_policy(policy).map_err(|e| {
                    log_refusal(&format!("modify_policy: {e}"));
                    status_of_policy(e)
                })?;
                Ok(Vec::new())
            }
            kadm5::DELETE_POLICY => {
                self.require(actor, Right::Delete)?;
                let name = kadm5::decode_policy_name(args).inspect_err(|status| {
                    log_refusal(&format!(
                        "delete_policy: the request was refused ({status})"
                    ));
                })?;
                let existed = self.admin.delete_policy(&name).map_err(|e| {
                    log_refusal(&format!("delete_policy {name}: {e}"));
                    match e {
                        // A policy an entry cites is a policy nobody may delete yet, and MIT has
                        // a code for exactly that state.
                        Error::Forbidden(_) => kadm5::POLICY_REF,
                        other => status_of_policy(other),
                    }
                })?;
                if !existed {
                    return Err(kadm5::UNK_POLICY);
                }
                Ok(Vec::new())
            }
            kadm5::GET_POLICY => {
                self.require(actor, Right::Read)?;
                let name = kadm5::decode_policy_name(args).inspect_err(|status| {
                    log_refusal(&format!("get_policy: the request was refused ({status})"));
                })?;
                let policy = self
                    .admin
                    .fetch_policy(&name)
                    .map_err(status_of_policy)?
                    .ok_or(kadm5::UNK_POLICY)?;
                Ok(kadm5::encode_policy(&policy, version))
            }
            kadm5::GET_POLS => {
                self.require(actor, Right::List)?;
                let mut r = Reader::new(args);
                let _ = r.u32();
                let glob = r
                    .nullstring()
                    .ok()
                    .flatten()
                    .unwrap_or_else(|| "*".to_owned());
                let names: Vec<String> = self
                    .admin
                    .policies()
                    .map_err(status_of_policy)?
                    .into_iter()
                    .filter(|name| glob_matches(&glob, name))
                    .collect();
                let mut out = Writer::new();
                // The same two counts every list in this protocol carries.
                out.i32(names.len() as i32);
                out.u32(names.len() as u32);
                for name in &names {
                    out.nullstring(Some(name));
                }
                Ok(out.into_bytes())
            }
            kadm5::EXTRACT_KEYS => {
                // A stronger right than `Keytab`: the caller keeps the keys, so this is the one
                // place where a per-realm policy has to say yes to the keys themselves.
                self.require(actor, Right::ExtractKeys)?;
                let (principal, kvno) = kadm5::decode_extract_keys(args).inspect_err(|status| {
                    log_refusal(&format!("extract_keys: the request was refused ({status})"));
                })?;
                let entry = self.admin.get(&principal).map_err(|e| {
                    log_refusal(&format!("extract_keys {principal}: {e}"));
                    status_of(e)
                })?;
                let keys: Vec<crate::hdb::HdbKey> = entry
                    .keys
                    .into_iter()
                    .filter(|k| kvno.is_none_or(|want| k.kvno == want))
                    .collect();
                // Asking for a kvno the entry does not have is not "no keys": a caller that
                // builds a keytab from an empty answer would write a keytab that authenticates
                // nothing, and would blame the service rather than the request.
                if keys.is_empty() {
                    log_refusal(&format!(
                        "extract_keys {principal}: no keys at kvno {}",
                        kvno.map(|k| k.to_string()).unwrap_or_else(|| "any".into())
                    ));
                    return Err(kadm5::UNK_PRINC);
                }
                Ok(kadm5::encode_key_data(&keys))
            }
            kadm5::GET_STRINGS => {
                self.require(actor, Right::Read)?;
                let principal = kadm5::decode_get_strings(args).inspect_err(|status| {
                    log_refusal(&format!("get_strings: the request was refused ({status})"));
                })?;
                let strings = self.admin.strings(&principal).map_err(|e| {
                    log_refusal(&format!("get_strings {principal}: {e}"));
                    status_of(e)
                })?;
                Ok(kadm5::encode_strings(&strings))
            }
            kadm5::SET_STRING => {
                self.require(actor, Right::Modify)?;
                let (principal, key, value) =
                    kadm5::decode_set_string(args).inspect_err(|status| {
                        log_refusal(&format!("set_string: the request was refused ({status})"));
                    })?;
                match value {
                    Some(value) => {
                        self.admin
                            .set_string_by(&principal, &key, &value, &stamp)
                            .map_err(|e| {
                                log_refusal(&format!("set_string {principal} {key}: {e}"));
                                match e {
                                    crate::Error::Config(_) => kadm5::BAD_MASK,
                                    other => status_of(other),
                                }
                            })?;
                    }
                    None => {
                        self.admin
                            .delete_string_by(&principal, &key, &stamp)
                            .map_err(|e| {
                                log_refusal(&format!("del_string {principal} {key}: {e}"));
                                status_of(e)
                            })?;
                    }
                }
                Ok(Vec::new())
            }
            kadm5::CREATE_PRINCIPAL => {
                self.require(actor, Right::Create)?;
                let (entry, password) = kadm5::decode_create(args)?;
                let principal = entry.principal.clone();
                let mut new = crate::admin::NewPrincipal {
                    principal,
                    password,
                    enctypes: Vec::new(),
                    role: if entry.has(crate::hdb::flags::SERVER) {
                        crate::admin::Role::Server
                    } else {
                        crate::admin::Role::Client
                    },
                };
                if !new.password.is_empty() {
                    // A password is given, so the enctypes are the KDC's.
                } else {
                    new.password = Vec::new();
                }
                self.admin.create_by(new, &stamp).map_err(|e| {
                    log_refusal(&format!("create: {e}"));
                    status_of(e)
                })?;
                Ok(Vec::new())
            }
            kadm5::DELETE_PRINCIPAL => {
                self.require(actor, Right::Delete)?;
                let mut r = Reader::new(args);
                let _ = r.u32();
                let name = r
                    .nullstring()
                    .map_err(|_| kadm5::BAD_MASK)?
                    .ok_or(kadm5::UNK_PRINC)?;
                let principal = Principal::parse(&name).map_err(|_| kadm5::UNK_PRINC)?;
                if !self.admin.delete(&principal).map_err(status_of)? {
                    return Err(kadm5::UNK_PRINC);
                }
                Ok(Vec::new())
            }
            kadm5::CHPASS_PRINCIPAL => {
                // Changing a password is its own right, and the actor is the ticket's client —
                // MIT's admin protocol never lets a caller name somebody else as the actor.
                //
                // Before the arguments are read, like every other procedure here. A check after
                // parsing answers an unprivileged caller `UNK_PRINC` or `BAD_MASK` for a name it may
                // not touch, which says whether that name exists; the refusal it is owed names the
                // right instead and says nothing about the realm.
                self.require(actor, Right::SetPassword)?;
                let mut r = Reader::new(args);
                let _ = r.u32();
                let name = r
                    .nullstring()
                    .map_err(|_| kadm5::BAD_MASK)?
                    .ok_or(kadm5::UNK_PRINC)?;
                let principal = Principal::parse(&name).map_err(|_| kadm5::UNK_PRINC)?;
                let password = r
                    .nullstring()
                    .map_err(|_| kadm5::BAD_MASK)?
                    .unwrap_or_default();
                self.admin
                    .set_password_by(&principal, password.as_bytes(), &stamp)
                    .map_err(|e| {
                        log_refusal(&format!("chpass: {e}"));
                        status_of(e)
                    })?;
                Ok(Vec::new())
            }
            kadm5::CHRAND_PRINCIPAL3 => {
                self.require(actor, Right::SetPassword)?;
                let mut r = Reader::new(args);
                let _ = r.u32();
                let name = r
                    .nullstring()
                    .map_err(|_| kadm5::BAD_MASK)?
                    .ok_or(kadm5::UNK_PRINC)?;
                let principal = Principal::parse(&name).map_err(|_| kadm5::UNK_PRINC)?;
                // Random keys: the same re-key, with a password nobody knows.
                let mut random = vec![0u8; 32];
                for chunk in random.chunks_mut(8) {
                    let key = self
                        .kdc
                        .cipher()
                        .random(crate::crypto::Enctype::Aes256Sha1)
                        .map_err(|_| kadm5::FAILURE)?;
                    chunk.copy_from_slice(&key.bytes()[..8]);
                }
                let updated = self
                    .admin
                    .set_password_by(&principal, &random, &stamp)
                    .map_err(status_of)?;
                let entry = self.admin.get(&principal).map_err(status_of)?;
                let mut out = Writer::new();
                out.u32(1);
                kadm5::encode_key_block(&mut out, &entry, updated);
                Ok(out.into_bytes())
            }
            _ => Err(kadm5::UNK_PROC),
        }
    }

    /// The `kadm5` code for "the actor may not".
    fn require(&self, actor: &Principal, right: Right) -> std::result::Result<(), u32> {
        if self.admin.policy().may(actor, right, None) {
            return Ok(());
        }
        Err(match right {
            Right::Read => kadm5::AUTH_GET,
            Right::Create => kadm5::AUTH_ADD,
            Right::Modify => kadm5::AUTH_MODIFY,
            Right::Delete => kadm5::AUTH_DELETE,
            Right::List => kadm5::AUTH_LIST,
            Right::SetPassword => kadm5::AUTH_CHANGEPW,
            _ => kadm5::AUTH_INSUFFICIENT,
        })
    }

    /// Verifies the client's AP-REQ and establishes the GSS context.
    ///
    /// Returns the client's principal, the context, and the AP-REP to send back.
    fn accept(&self, token: &[u8], now: i64) -> Result<(Principal, AcceptorContext, Vec<u8>)> {
        let ap_req_bytes = unwrap_initial_context_token(token)?;
        let ap_req = ApReq::decode(ap_req_bytes)?;
        let ticket = crate::msg::Ticket::decode(&ap_req.ticket)?;
        // The key comes from the entry the **ticket** names, not from a single pinned principal.
        //
        // That is what a keytab-based acceptor does, and MIT's `kadmin` is the reason it matters: it
        // asks the KDC for an initial ticket for `kadmin/<admin-server-host>` — its own trace says
        // `Setting initial creds service to kadmin/127.0.0.1` — so a server that accepted only
        // `kadmin/admin` refused every real client with `GSS-API error while initializing kadmin
        // interface`. A keytab for `kadmin` holds both names for exactly this reason.
        //
        // What is still refused: a ticket for a service **outside** the `kadmin` name, which is the
        // case `BADMATCH` is for.
        if !is_admin_service(&ticket.sname, &self.service) {
            return Err(Error::Kdc {
                code: crate::error::codes::KRB_AP_ERR_BADMATCH,
                text: format!(
                    "the ticket is for {}, which is not the admin service of {}",
                    ticket.sname, self.service.realm
                ),
            });
        }
        let service = self
            .kdc
            .hdb()
            .fetch(&ticket.sname)?
            .ok_or_else(|| Error::Hdb(format!("{} is not in the database", ticket.sname)))?;
        let key = service
            .key_for(ticket.enc.etype)
            .or_else(|| service.enctypes().first().and_then(|e| service.key_for(*e)))
            .ok_or_else(|| Error::Hdb(format!("{} has no usable key", self.service)))?;
        let plain =
            self.kdc
                .cipher()
                .decrypt(&key.key, usage::KDC_REP_TICKET, &ticket.enc.cipher)?;
        let enc_part: EncTicketPart = EncTicketPart::decode(&plain)?;
        if now > enc_part.endtime {
            return Err(Error::Kdc {
                code: crate::error::codes::KRB_AP_ERR_TKT_EXPIRED,
                text: "the kadmin ticket has expired".into(),
            });
        }
        let authenticator_plain = self.kdc.cipher().decrypt(
            &enc_part.session_key,
            usage::AP_REQ_AUTH,
            &ap_req.authenticator.cipher,
        )?;
        let authenticator = Authenticator::decode(&authenticator_plain)?;
        if authenticator.cname != enc_part.cname {
            return Err(Error::Kdc {
                code: crate::error::codes::KRB_AP_ERR_BADMATCH,
                text: "the authenticator names a different client than the ticket".into(),
            });
        }
        let skew = now.saturating_sub(authenticator.ctime).abs();
        if skew > self.kdc.config().clockskew() {
            return Err(Error::Skew {
                skew,
                allowed: self.kdc.config().clockskew(),
            });
        }

        // RFC 4121 §2: the per-message key is the initiator's subkey when it sent
        // one, the session key otherwise. The AP-REP does not assert an acceptor
        // subkey, so the tokens carry no `AcceptorSubkey` flag.
        let context_key = authenticator
            .subkey
            .clone()
            .unwrap_or_else(|| enc_part.session_key.clone());
        let ap_rep = crate::msg::kpasswd::ApRep::seal(
            self.kdc.cipher(),
            &enc_part.session_key,
            &crate::msg::kpasswd::EncApRepPart {
                ctime: authenticator.ctime,
                cusec: authenticator.cusec,
                subkey: None,
                seq_number: authenticator.seq_number,
            },
        )?;

        Ok((
            authenticator.cname.clone(),
            // Seeded with the number this AP-REP announces one line up: the
            // initiator counts our tokens from it, so the first one we send has
            // to be `seq_number + 1`, not zero.
            AcceptorContext::new(
                self.kdc.cipher_arc(),
                context_key,
                authenticator.seq_number.unwrap_or(0),
            ),
            // The AP-REP goes back inside the same generic wrapper the client
            // used: `[APPLICATION 0] { OID, AP-REP }`. A bare AP-REP is what this
            // server looked for on the way in and what every real client refuses
            // on the way out.
            crate::der::cons(
                crate::der::app(0),
                &[
                    crate::der::cons(0x06, &[KRB5_MECHANISM.to_vec()]),
                    // RFC 4121 §4.1.1's token identifier for an AP-REP; the
                    // wrapper carries it and a client that reads the first two
                    // octets as an identifier finds `6f 67` without one.
                    TOK_AP_REP.to_vec(),
                    ap_rep,
                ],
            ),
        ))
    }
}

/// Records why a context was refused.
///
/// To stderr, because this crate has no logger and a refusal that leaves no trace
/// is the one bug an operator cannot diagnose: the client is told
/// `GSS_S_FAILURE` and nothing else.
pub fn log_refusal(message: &str) {
    eprintln!("kadmind: {message}");
}

/// A `kadmind` listening on a loopback port, for a test or a stand.
pub struct RunningKadmin {
    addr: String,
    stop: Arc<std::sync::atomic::AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl RunningKadmin {
    /// The `host:port` to connect to.
    pub fn addr(&self) -> &str {
        &self.addr
    }

    /// The `admin_server` line a `krb5.conf` would carry.
    pub fn admin_server(&self) -> String {
        self.addr.clone()
    }

    /// Stops the listener and waits for the thread.
    pub fn stop(mut self) {
        self.shutdown();
    }

    fn shutdown(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::SeqCst);
        // The thread is blocked in `accept`; the process will not wait for it,
        // but a test that starts a second listener wants the port back.
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl std::fmt::Debug for RunningKadmin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RunningKadmin")
            .field("addr", &self.addr)
            .finish()
    }
}

impl Drop for RunningKadmin {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Starts a `kadmind` on `127.0.0.1:0` and returns the address it got.
///
/// The clock is read once, here: everything below takes the instant as a
/// parameter, so a test can hand the engine a fixed time.
pub fn serve_kadmin_loopback(kadmin: Kadmin) -> Result<RunningKadmin> {
    serve_kadmin_on(("127.0.0.1", 0), kadmin)
}

/// Starts a `kadmind` on `addr`, for a stand that has to name its port.
///
/// `admin_server` in a `krb5.conf` is a fixed `host:port`, so a client that reads one — MIT's
/// `kadmin` does — cannot be pointed at an address the server picked. `serve_kadmin_loopback` is
/// this with port zero.
pub fn serve_kadmin_on<A: std::net::ToSocketAddrs>(
    addr: A,
    kadmin: Kadmin,
) -> Result<RunningKadmin> {
    use std::net::TcpListener;

    let listener = TcpListener::bind(addr).map_err(Error::Io)?;
    listener.set_nonblocking(true).map_err(Error::Io)?;
    let addr = listener.local_addr().map_err(Error::Io)?.to_string();
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let flag = Arc::clone(&stop);

    let thread = std::thread::spawn(move || {
        let kadmin = Arc::new(kadmin);
        while !flag.load(std::sync::atomic::Ordering::SeqCst) {
            match listener.accept() {
                Ok((stream, _)) => {
                    stream.set_nonblocking(false).expect("a blocking stream");
                    let kadmin = Arc::clone(&kadmin);
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs() as i64)
                        .unwrap_or(0);
                    std::thread::spawn(move || rpc::serve_connection(stream, &kadmin, now));
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
                Err(_) => return,
            }
        }
    });

    Ok(RunningKadmin {
        addr,
        stop,
        thread: Some(thread),
    })
}

/// The Kerberos GSS mechanism's OID, `1.2.840.113554.1.2.2`, DER-encoded.
const KRB5_MECHANISM: [u8; 9] = [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02];

/// RFC 4121 §4.1.1 token identifiers inside the GSS wrapper.
pub const TOK_AP_REQ: [u8; 2] = [0x01, 0x00];
/// An AP-REP.
pub const TOK_AP_REP: [u8; 2] = [0x02, 0x00];

/// Unwraps a GSS-API `InitialContextToken`.
///
/// RFC 2743 §3.1 puts the mechanism's own token *inside* a generic wrapper:
/// `[APPLICATION 0] SEQUENCE { thisMech OID, innerContextToken }`. A server that
/// hand-parses the args as an AP-REQ sees `0x60` where it expects `0x6e` and
/// rejects every real client — the wrapper is not optional on the wire, only
/// forgettable in a test that builds the AP-REQ itself.
fn unwrap_initial_context_token(token: &[u8]) -> Result<&[u8]> {
    use crate::der::{Reader, app};
    const OID_TAG: u8 = 0x06;
    if token.first() != Some(&app(0)) {
        // Not wrapped: an implementation may hand the AP-REQ over directly, and
        // refusing it would be strictness about another layer's format.
        return Ok(token);
    }
    let mut outer = Reader::new(token);
    let body = outer.expect_in("GSS", app(0))?;
    let mut inner = Reader::new(body);
    let oid = inner.expect_in("GSS", OID_TAG)?;
    if oid != KRB5_MECHANISM {
        return Err(Error::Protocol(
            "GSS: the initial context token is for another mechanism".into(),
        ));
    }
    let mut ap_req = inner.rest();
    // RFC 4121 §4.1 prefixes the AP-REQ with a two-octet token identifier (the
    // Kerberos v5 mechanism's `TOK_ID` for an authenticator), and RFC 2743's
    // wrapper says nothing about it. Both spellings are on the wire: MIT sends
    // the identifier, Heimdal's own acceptor accepts either. Stripping it by
    // position rather than by value would eat the first two octets of a tag in
    // the other spelling, so the tag is what decides.
    if ap_req.len() > 2 && ap_req[2] == app(14) && ap_req[0] != app(14) {
        ap_req = &ap_req[2..];
    }
    if ap_req.is_empty() {
        return Err(Error::Protocol(
            "GSS: the initial context token carries no AP-REQ".into(),
        ));
    }
    Ok(ap_req)
}

/// The `kadm5` status for a crate failure.
/// The `kadm5` code for a policy refusal.
///
/// Policies answer with their own codes: `KADM5_UNK_POLICY` for a name that is not there and
/// `KADM5_DUP` for one that already is — the same `DUP` an existing principal gets, because MIT
/// keeps both in one namespace of "already taken".
fn status_of_policy(error: Error) -> u32 {
    match error {
        Error::NotFound(_) => kadm5::UNK_POLICY,
        Error::Exists(_) => kadm5::DUP,
        Error::Forbidden(_) => kadm5::POLICY_REF,
        // A policy whose own numbers contradict each other is a bad mask-bit's worth of "you
        // asked for something no record can hold".
        Error::Config(_) => kadm5::BAD_MASK,
        other => status_of(other),
    }
}

fn status_of(error: Error) -> u32 {
    match error {
        Error::NotFound(_) => kadm5::UNK_PRINC,
        Error::Exists(_) => kadm5::DUP,
        Error::Forbidden(_) => kadm5::AUTH_INSUFFICIENT,
        // The password rules are reported as the two codes an operator can act on: a length and a
        // class count are different fixes.
        Error::PasswordPolicy(crate::hdb::policy::Breach::TooShort { .. }) => {
            kadm5::PASS_Q_TOOSHORT
        }
        Error::PasswordPolicy(crate::hdb::policy::Breach::TooFewClasses { .. }) => {
            kadm5::PASS_Q_CLASS
        }
        _ => kadm5::FAILURE,
    }
}

/// MIT matches a glob against the *unparsed* name, so `*` covers the realm too.
fn glob_matches(pattern: &str, name: &str) -> bool {
    // `*` and `?` only, no classes: that is what `kadmin` documents, and a full
    // glob engine would accept patterns MIT refuses.
    let pattern: Vec<char> = pattern.chars().collect();
    let name: Vec<char> = name.chars().collect();
    let mut p = 0;
    let mut n = 0;
    let mut star: Option<(usize, usize)> = None;
    while n < name.len() {
        if p < pattern.len() && (pattern[p] == '?' || pattern[p] == name[n]) {
            p += 1;
            n += 1;
        } else if p < pattern.len() && pattern[p] == '*' {
            star = Some((p, n));
            p += 1;
        } else if let Some((sp, sn)) = star {
            p = sp + 1;
            n = sn + 1;
            star = Some((sp, sn + 1));
        } else {
            return false;
        }
    }
    while p < pattern.len() && pattern[p] == '*' {
        p += 1;
    }
    p == pattern.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_glob_covers_and_is_anchored() {
        assert!(glob_matches("*", "alice@EXAMPLE.COM"));
        assert!(glob_matches("alice*", "alice@EXAMPLE.COM"));
        assert!(glob_matches("*@EXAMPLE.COM", "alice@EXAMPLE.COM"));
        assert!(glob_matches("a?ice@EXAMPLE.COM", "alice@EXAMPLE.COM"));
        assert!(!glob_matches("bob*", "alice@EXAMPLE.COM"));
        assert!(!glob_matches("alice", "alice@EXAMPLE.COM"));
        assert!(
            !glob_matches("*@OTHER.COM", "alice@EXAMPLE.COM"),
            "a pattern that does not reach the end must not match"
        );
    }

    #[test]
    fn a_status_maps_a_missing_principal_to_unk_princ() {
        assert_eq!(status_of(Error::NotFound("x".into())), kadm5::UNK_PRINC);
        assert_eq!(status_of(Error::Exists("x".into())), kadm5::DUP);
        assert_eq!(status_of(Error::Hdb("x".into())), kadm5::FAILURE);
    }

    // --- the ACL surface: which procedure needs which right -------------------------------

    use crate::admin::wire::{Grants, Rights};
    use crate::kdc::KdcConfig;
    use crate::name::Principal;

    const ACL_REALM: &str = "EXAMPLE.COM";

    fn principal(name: &str) -> Principal {
        Principal::parse(&format!("{name}@{ACL_REALM}")).unwrap()
    }

    /// A `kadmind` over an empty realm, with `actor` holding exactly `rights`.
    fn kadmind(actor: &str, rights: Rights) -> Kadmin {
        use crate::crypto::OwnCipher;
        use crate::hdb::{HdbEntry, MemoryHdb};

        let db = MemoryHdb::new();
        let cipher = OwnCipher;
        let mut krbtgt = HdbEntry::krbtgt(ACL_REALM);
        krbtgt
            .add_password_key(&cipher, crate::crypto::Enctype::Aes256Sha1, b"master", 1)
            .unwrap();
        db.insert(krbtgt).unwrap();

        let kdc = Kdc::new(
            KdcConfig::new(ACL_REALM).unwrap(),
            std::sync::Arc::new(db),
            std::sync::Arc::new(OwnCipher),
        );
        let grants = Grants::default().grant(&principal(actor), rights);
        Kadmin::new(kdc, std::sync::Arc::new(grants)).expect("a kadmind over the realm")
    }

    /// One call, as `kadm5` receives it, returning the whole reply rather than its status.
    fn answer(kadmin: &Kadmin, actor: &str, procedure: u32, args: &[u8]) -> Vec<u8> {
        let rpc = crate::kadmin::rpc::Call {
            xid: 1,
            prog: kadm5::PROG,
            vers: kadm5::VERS,
            proc_: procedure,
            cred_flavor: 6,
            gss: None,
            verf: (0, Vec::new()),
            args: Vec::new(),
            header_len: 0,
        };
        let mut full = Vec::with_capacity(args.len() + 4);
        full.extend_from_slice(&kadm5::API_VERSION_2.to_le_bytes());
        full.extend_from_slice(args);
        kadmin.dispatch(&principal(actor), &rpc, &full, STAMP_AT)
    }

    /// The instant every call in this module's tests is stamped with.
    const STAMP_AT: i64 = 1_700_000_000;

    /// One call, as `kadm5` receives it: the version word, then whatever the procedure reads.
    fn call(kadmin: &Kadmin, actor: &str, procedure: u32, args: &[u8]) -> u32 {
        let rpc = crate::kadmin::rpc::Call {
            xid: 1,
            prog: kadm5::PROG,
            vers: kadm5::VERS,
            proc_: procedure,
            cred_flavor: 6,
            gss: None,
            verf: (0, Vec::new()),
            args: Vec::new(),
            header_len: 0,
        };
        let mut full = Vec::with_capacity(args.len() + 4);
        full.extend_from_slice(&kadm5::API_VERSION_2.to_le_bytes());
        full.extend_from_slice(args);
        let answer = kadmin.dispatch(&principal(actor), &rpc, &full, 1_700_000_000);
        // The reply is `[version][status][results…]`, and XDR is **big-endian** throughout: reading
        // it as little-endian gives a status that is the right number byte-reversed, which looks
        // like a refusal this server never sent.
        u32::from_be_bytes(answer[4..8].try_into().expect("four octets"))
    }

    /// Every procedure that reads or writes needs its own right, and the refusal names that right.
    ///
    /// The table is the point: a procedure routed to a handler with a weaker `Right` grants a
    /// privilege nobody meant to grant, and nothing about the answer would look wrong. MIT has one
    /// `AUTH_*` code per right and a client prints the one it got, so a mismatch is visible here
    /// and invisible at the wire.
    #[test]
    fn every_procedure_needs_its_own_right() {
        let actor = "admin";
        // (procedure, the right it must demand, the code when it is missing)
        let table: &[(u32, Right, u32)] = &[
            (kadm5::GET_PRINCIPAL, Right::Read, kadm5::AUTH_GET),
            (kadm5::GET_PRINCS, Right::List, kadm5::AUTH_LIST),
            (kadm5::CREATE_PRINCIPAL, Right::Create, kadm5::AUTH_ADD),
            (kadm5::MODIFY_PRINCIPAL, Right::Modify, kadm5::AUTH_MODIFY),
            (kadm5::RENAME_PRINCIPAL, Right::Modify, kadm5::AUTH_MODIFY),
            (kadm5::DELETE_PRINCIPAL, Right::Delete, kadm5::AUTH_DELETE),
            (
                kadm5::CHPASS_PRINCIPAL,
                Right::SetPassword,
                kadm5::AUTH_CHANGEPW,
            ),
            (kadm5::CREATE_POLICY, Right::Create, kadm5::AUTH_ADD),
            (kadm5::MODIFY_POLICY, Right::Modify, kadm5::AUTH_MODIFY),
            (kadm5::DELETE_POLICY, Right::Delete, kadm5::AUTH_DELETE),
            (kadm5::GET_POLICY, Right::Read, kadm5::AUTH_GET),
            (kadm5::GET_POLS, Right::List, kadm5::AUTH_LIST),
            (kadm5::GET_STRINGS, Right::Read, kadm5::AUTH_GET),
            (kadm5::SET_STRING, Right::Modify, kadm5::AUTH_MODIFY),
            (
                kadm5::EXTRACT_KEYS,
                Right::ExtractKeys,
                kadm5::AUTH_INSUFFICIENT,
            ),
        ];

        for (procedure, right, refusal) in table {
            // Without the right: refused, and with the code that names it.
            let none = kadmind(actor, Rights::NONE);
            assert_eq!(
                call(&none, actor, *procedure, &[]),
                *refusal,
                "procedure {procedure} (needs {right:?}) was not refused"
            );

            // With every right: past the check. What comes back is whatever the handler says about
            // the empty arguments — a `BAD_MASK` at worst — and never an `AUTH_*`: a refusal here
            // would mean the grant did not reach the procedure that asked for it.
            let all = kadmind(actor, Rights::ALL);
            let status = call(&all, actor, *procedure, &[]);
            assert!(
                !(kadm5::AUTH_GET..=kadm5::AUTH_INSUFFICIENT).contains(&status)
                    || status == kadm5::AUTH_INSUFFICIENT && *right == Right::ExtractKeys,
                "procedure {procedure} refused a caller holding {right:?}: {status}"
            );
        }
    }

    /// A grant of one right opens exactly one procedure.
    ///
    /// The other direction of the same table: a policy that grants `List` and nothing else must not
    /// let the same caller create, delete or read an entry.
    /// A change through `kadmind` records **who** made it, and `getprinc` reports that name.
    ///
    /// Two facts are checked and they are separate: the entry carries the modifier (a fact about the
    /// record, so a later `getprinc` or a replica sees it), and the `getprinc` reply carries it in
    /// `mod_name` (a fact about the answer, so an operator sees it). A store that recorded the
    /// subject instead of the actor would pass the first and fail nothing — the subject is what a
    /// server that inferred the modifier would report.
    #[test]
    fn a_change_records_its_author_and_getprinc_names_them() {
        use crate::crypto::{Enctype, OwnCipher};
        use crate::hdb::{Hdb, HdbEntry, MemoryHdb};
        use std::sync::Arc;

        let db = Arc::new(MemoryHdb::new());
        let mut krbtgt = HdbEntry::krbtgt(ACL_REALM);
        krbtgt
            .add_password_key(&OwnCipher, Enctype::Aes256Sha1, b"master", 1)
            .unwrap();
        db.insert(krbtgt).unwrap();
        let mut alice = HdbEntry::user(principal("alice"));
        alice
            .add_password_key(&OwnCipher, Enctype::Aes256Sha1, b"old", 1)
            .unwrap();
        db.insert(alice).unwrap();

        let kdc = Kdc::new(
            KdcConfig::new(ACL_REALM).unwrap(),
            Arc::clone(&db) as Arc<dyn Hdb>,
            Arc::new(OwnCipher),
        );
        let grants = Grants::default().grant(&principal("clerk"), Rights::ALL);
        let kadmin = Kadmin::new(kdc, Arc::new(grants)).expect("a kadmind");

        // `clerk` changes *alice's* password: the hand that acted is not the account that changed.
        let mut args = crate::kadmin::xdr::Writer::new();
        args.nullstring(Some(&principal("alice").to_string()))
            .nullstring(Some("a new password"));
        let reply = answer(&kadmin, "clerk", kadm5::CHPASS_PRINCIPAL, args.bytes());
        let status = u32::from_be_bytes(reply[4..8].try_into().expect("four octets"));
        assert_eq!(status, kadm5::OK, "the password change is allowed");

        // The record: the modifier and the instant, both from the actor's call.
        let stored = db.fetch(&principal("alice")).unwrap().expect("alice");
        assert_eq!(
            stored.modified_by.as_ref().map(ToString::to_string),
            Some(principal("clerk").to_string())
        );
        assert_eq!(stored.modified, STAMP_AT, "and when they did it");

        // The answer: `getprinc` reports the same name in `mod_name`.
        let mut get = crate::kadmin::xdr::Writer::new();
        get.nullstring(Some(&principal("alice").to_string()));
        let reply = answer(&kadmin, "clerk", kadm5::GET_PRINCIPAL, get.bytes());
        let mut r = crate::kadmin::xdr::Reader::new(&reply[8..]);
        let rec = kadm5::decode_entry_rec(&mut r).expect("an entry record");
        assert_eq!(
            rec.mod_name.as_deref(),
            Some(principal("clerk").to_string().as_str()),
            "getprinc names the administrator, not the account"
        );
        assert_eq!(rec.mod_date, STAMP_AT, "and the date it changed");
    }

    #[test]
    fn one_grant_opens_one_procedure() {
        let actor = "reader";
        let list_only = kadmind(actor, Rights::LIST);
        assert_ne!(
            call(&list_only, actor, kadm5::GET_PRINCS, &[]),
            kadm5::AUTH_LIST,
            "the granted procedure is past its check"
        );
        for (procedure, refusal) in [
            (kadm5::GET_PRINCIPAL, kadm5::AUTH_GET),
            (kadm5::CREATE_PRINCIPAL, kadm5::AUTH_ADD),
            (kadm5::DELETE_PRINCIPAL, kadm5::AUTH_DELETE),
            (kadm5::CHPASS_PRINCIPAL, kadm5::AUTH_CHANGEPW),
        ] {
            assert_eq!(
                call(&list_only, actor, procedure, &[]),
                refusal,
                "procedure {procedure} accepted a caller granted only List"
            );
        }
    }

    /// A caller with no grant at all is refused by every procedure, `init` and `get_privs` aside.
    #[test]
    fn a_caller_with_no_grant_is_refused_everywhere() {
        let actor = "nobody";
        let none = kadmind(actor, Rights::NONE);
        assert_eq!(
            call(&none, actor, kadm5::INIT, &[]),
            kadm5::OK,
            "init opens the session: the handshake is its own authentication"
        );
        for procedure in [
            kadm5::GET_PRINCIPAL,
            kadm5::GET_PRINCS,
            kadm5::CREATE_PRINCIPAL,
            kadm5::MODIFY_PRINCIPAL,
            kadm5::RENAME_PRINCIPAL,
            kadm5::DELETE_PRINCIPAL,
            kadm5::CHPASS_PRINCIPAL,
            kadm5::GET_STRINGS,
            kadm5::SET_STRING,
            kadm5::EXTRACT_KEYS,
        ] {
            let status = call(&none, actor, procedure, &[]);
            assert!(
                status != kadm5::OK,
                "procedure {procedure} answered an unprivileged caller with success"
            );
        }
    }

    /// `get_privs` reports every privilege to everyone, as MIT's does.
    ///
    /// MIT's `kadm5_get_privs` returns `~0` with the comment that the interface cannot answer the
    /// question — a grant may be narrowed to particular targets, and this call names none — and that
    /// answering generously keeps a caching client from denying operations the ACL granted.
    #[test]
    fn get_privs_reports_every_privilege_to_any_caller() {
        for rights in [Rights::NONE, Rights::LIST, Rights::ALL] {
            let kadmind = kadmind("someone", rights);
            let rpc = crate::kadmin::rpc::Call {
                xid: 1,
                prog: kadm5::PROG,
                vers: kadm5::VERS,
                proc_: kadm5::GET_PRIVS,
                cred_flavor: 6,
                gss: None,
                verf: (0, Vec::new()),
                args: Vec::new(),
                header_len: 0,
            };
            let mut args = Vec::new();
            args.extend_from_slice(&kadm5::API_VERSION_2.to_le_bytes());
            let answer = kadmind.dispatch(&principal("someone"), &rpc, &args, 1_700_000_000);
            let status = u32::from_be_bytes(answer[4..8].try_into().expect("four octets"));
            assert_eq!(status, kadm5::OK);
            let privs = u32::from_be_bytes(answer[8..12].try_into().expect("four octets"));
            assert_eq!(
                privs,
                kadm5::PRIV_ALL,
                "a caller with {rights:?} was told it has fewer privileges than MIT reports"
            );
        }
    }

    /// The acceptor is keyed on the ticket's name, within the `kadmin` service only.
    ///
    /// MIT's `kadmin` presents a ticket for `kadmin/<admin-server-host>`; `kadmin.local` and the
    /// documented name are `kadmin/admin`. Both reach the same server, and a keytab holds both — so
    /// the second component is not part of the decision, and the first one is.
    #[test]
    fn the_admin_service_is_kadmin_in_this_realm() {
        let configured = service_principal(ACL_REALM).unwrap();
        for accepted in ["kadmin/admin", "kadmin/127.0.0.1", "kadmin/dc1.example.com"] {
            assert!(
                is_admin_service(&principal(accepted), &configured),
                "{accepted} is the admin service and must be accepted"
            );
        }
        for refused in [
            // Another service entirely: a stolen service ticket must not open the admin port.
            "host/dc1.example.com",
            // Same shape, another realm.
            "kadmin/admin@OTHER.COM",
            // A one-component name is not `kadmin/<instance>`.
            "kadmin",
        ] {
            let candidate = if refused.contains('@') {
                Principal::parse(refused).unwrap()
            } else {
                principal(refused)
            };
            assert!(
                !is_admin_service(&candidate, &configured),
                "{refused} is not the admin service and must be refused"
            );
        }
    }

    #[test]
    fn the_service_principal_is_kadmin_admin() {
        assert_eq!(
            service_principal("EXAMPLE.COM").unwrap().to_string(),
            "kadmin/admin@EXAMPLE.COM"
        );
    }
}
