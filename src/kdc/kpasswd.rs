//! The change-password service, RFC 3244 §2.
//!
//! A password change starts like any other ticket request and ends like nothing
//! else in Kerberos: the client asks the AS for an *initial* ticket for
//! `kadmin/changepw` (an ordinary TGT is not enough — MIT's rule, and the reason
//! `kpasswd` does not need a TGT), presents it to port 464, and then sends a
//! sealed `KRB-PRIV` carrying the new password under a subkey it chose.
//!
//! Three things in that sequence are load-bearing and easy to get wrong:
//!
//! * **The subkey is the client's, not the ticket's.** The request is encrypted
//!   in the subkey from the authenticator, so a server that opens it with the
//!   session key decrypts nothing and reports a protocol error for a valid
//!   request.
//! * **An absent `targname` means "me".** The client may name another account
//!   (RFC 3244's set-password, an administrator's move); naming nobody is the
//!   common case and must not be read as "nobody".
//! * **Who may change whose password is the embedder's decision.** This crate
//!   asks a [`super::ChangePolicy`]; the default, [`super::SelfOnly`], allows
//!   exactly the case that needs no configuration. A KDC that ignored the target
//!   field would let any user change any password, so an unanswered request is
//!   refused rather than done.
//!
//! The reply is a `KRB-PRIV` in the same subkey whose `user-data` is the RFC 3244
//! result: a two-octet code followed by a message.

use crate::crypto::{Cipher, Key, usage};
use crate::error::{Error, Result};
use crate::hdb::{HdbEntry, flags as entry_flags};
use crate::msg::kpasswd::{ApRep, ChangePasswdData, EncApRepPart, open_krb_priv, seal_krb_priv};
use crate::msg::{ApReq, Authenticator};
use crate::name::Principal;

use super::Kdc;

/// `KRB5_KPASSWD_SUCCESS`.
pub const STATUS_SUCCESS: u16 = 0;
/// `KRB5_KPASSWD_MALFORMED`.
pub const STATUS_MALFORMED: u16 = 1;
/// `KRB5_KPASSWD_AUTHERROR`.
pub const STATUS_AUTHERROR: u16 = 3;
/// `KRB5_KPASSWD_ACCESSDENIED`.
pub const STATUS_ACCESSDENIED: u16 = 5;
/// `KRB5_KPASSWD_BAD_VERSION`.
pub const STATUS_BAD_VERSION: u16 = 6;
/// `KRB5_KPASSWD_INITIAL_FLAG_NEEDED`.
pub const STATUS_INITIAL_FLAG_NEEDED: u16 = 7;

/// The protocol version of an own-password change: `KRB5_KPASSWD_VERS_CHANGEPW`,
/// which Heimdal defines as **1** — not `0xff80`, which is the set-password
/// version. Getting these two the wrong way round means every `kpasswd` is
/// refused with `BAD_VERSION` and every set-password is accepted as a change.
pub const VERSION_CHANGE: u16 = 1;
/// `KRB5_KPASSWD_VERS_SETPW`, the RFC 3244 set-password version.
pub const VERSION_SET: u16 = 0xff80;

/// The reply the client expects: an `AP-REP`, then a sealed result.
#[derive(Debug)]
pub struct ChangeReply {
    /// The `AP-REP` proving the server read the authenticator.
    pub ap_rep: Vec<u8>,
    /// The `KRB-PRIV` carrying the result code.
    pub priv_message: Vec<u8>,
}

impl ChangeReply {
    /// Renders the reply the way RFC 3244 frames it: a two-octet total length,
    /// the version, then the `AP-REP` length and the two messages.
    pub fn encode(&self, version: u16) -> Vec<u8> {
        let total = 6 + self.ap_rep.len() + self.priv_message.len();
        let mut out = Vec::with_capacity(total);
        out.extend_from_slice(&(total as u16).to_be_bytes());
        out.extend_from_slice(&version.to_be_bytes());
        out.extend_from_slice(&(self.ap_rep.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.ap_rep);
        out.extend_from_slice(&self.priv_message);
        out
    }
}

/// The `user-data` of a result: a two-octet status and a message.
pub fn result_payload(status: u16, message: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + message.len());
    out.extend_from_slice(&status.to_be_bytes());
    out.extend_from_slice(message.as_bytes());
    out
}

impl Kdc {
    /// Handles one change-password exchange: an `AP-REQ` and a sealed request in,
    /// an `AP-REP` and a sealed result out.
    ///
    /// The whole exchange is one call because the two halves cannot be separated:
    /// the request is sealed in a subkey that arrives in the `AP-REQ`'s
    /// authenticator, so a server that kept the `AP-REQ` and answered later would
    /// have to remember that key, and remembering keys is how they leak.
    pub fn handle_kpasswd(
        &self,
        ap_req_bytes: &[u8],
        request: &[u8],
        version: u16,
        now: i64,
    ) -> Result<ChangeReply> {
        // The ticket must be for kadmin/changepw and must be ours.
        let ap_req = ApReq::decode(ap_req_bytes)?;
        let ticket = ap_req.ticket()?;
        let changepw = Principal::parse(&format!("kadmin/changepw@{}", self.config().realm()))?;
        if ticket.sname != changepw {
            return Err(Error::Kdc {
                code: crate::error::codes::KRB_AP_ERR_MODIFIED,
                text: format!(
                    "the change-password service is {changepw}, the ticket is for {}",
                    ticket.sname
                ),
            });
        }
        let entry = self
            .hdb()
            .fetch(&changepw)?
            .ok_or_else(|| Error::Hdb(format!("{changepw} is not in the database")))?;
        if !entry.has(entry_flags::CHANGE_PW) {
            return Err(Error::Kdc {
                code: crate::error::codes::KDC_ERR_POLICY,
                text: format!("{changepw} may not change passwords"),
            });
        }

        // The ticket, then the authenticator in its session key.
        let ticket_part = self.open_changepw_ticket(&ticket.enc, &entry)?;
        if now > ticket_part.endtime {
            return Err(Error::Kdc {
                code: crate::error::codes::KRB_AP_ERR_TKT_EXPIRED,
                text: "the change-password ticket has expired".into(),
            });
        }
        let authenticator = self.open_authenticator(&ap_req, &ticket_part.session_key)?;
        let skew = now.saturating_sub(authenticator.ctime);
        if skew.abs() > self.config().clockskew() {
            return Err(Error::Skew {
                skew,
                allowed: self.config().clockskew(),
            });
        }
        if authenticator.cname != ticket_part.cname {
            return Err(Error::Kdc {
                code: crate::error::codes::KRB_AP_ERR_BADMATCH,
                text: "the authenticator names a different client than the ticket".into(),
            });
        }

        // The reply is sealed in the subkey when the client offered one, and in
        // the session key otherwise — the same rule the TGS reply follows.
        let (reply_key, request_key) = match &authenticator.subkey {
            Some(subkey) => (subkey.clone(), subkey.clone()),
            None => (
                ticket_part.session_key.clone(),
                ticket_part.session_key.clone(),
            ),
        };

        let ap_rep = ApRep::seal(
            self.cipher(),
            &ticket_part.session_key,
            &EncApRepPart {
                ctime: authenticator.ctime,
                cusec: authenticator.cusec,
                // Echo the client's subkey so both sides agree on which key the
                // rest of the exchange uses.
                subkey: authenticator.subkey.clone(),
                seq_number: authenticator.seq_number,
            },
        )?;

        let (user_data, seq) = open_krb_priv(self.cipher(), &request_key, request)?;
        // RFC 3244 §2: the ticket must be initial. A service ticket for
        // kadmin/changepw that came from a TGT would let a stolen TGT change the
        // password and lock its owner out. The answer is a protocol status rather
        // than a KRB-ERROR, because at this point the exchange is sealed and the
        // client is reading a status, not a Kerberos error.
        let (status, text) = if ticket_part.flags & crate::msg::tkt_flags::INITIAL == 0 {
            (
                STATUS_INITIAL_FLAG_NEEDED,
                "the change-password ticket must be an initial one".to_owned(),
            )
        } else {
            match self.apply_change(&ticket_part.cname, version, &user_data) {
                Ok(()) => (STATUS_SUCCESS, "Password changed".to_owned()),
                Err(ChangeError::Status(status, text)) => (status, text),
                Err(ChangeError::Fatal(e)) => return Err(e),
            }
        };
        let priv_message = seal_krb_priv(
            self.cipher(),
            &reply_key,
            &result_payload(status, &text),
            seq,
            now,
        )?;

        Ok(ChangeReply {
            ap_rep,
            priv_message,
        })
    }

    /// Applies the request's new password, or says why not.
    fn apply_change(
        &self,
        client: &Principal,
        version: u16,
        user_data: &[u8],
    ) -> std::result::Result<(), ChangeError> {
        let (new_password, target) = match version {
            VERSION_CHANGE => {
                // RFC 3244 §2: a change request carries the raw password, not a
                // ChangePasswdData — the account is the ticket's client.
                (user_data.to_vec(), None)
            }
            VERSION_SET => {
                let data = ChangePasswdData::decode(user_data)
                    .map_err(|e| ChangeError::Status(STATUS_MALFORMED, e.to_string()))?;
                let target = match data.target {
                    Some(t) => t,
                    // Naming nobody means the client of the ticket: an encoder
                    // that always writes the target produces the same bytes as
                    // one that omits it only for the client's own account.
                    None => client.clone(),
                };
                (data.new_password, Some(target))
            }
            other => {
                return Err(ChangeError::Status(
                    STATUS_BAD_VERSION,
                    format!("protocol version {other:#06x} is not one this server speaks"),
                ));
            }
        };

        if new_password.is_empty() {
            return Err(ChangeError::Status(
                STATUS_MALFORMED,
                "the new password is empty".to_owned(),
            ));
        }

        // Who may change whose password is the embedder's decision, not this
        // crate's: `ChangePolicy` is asked, and `SelfOnly` — the default — allows
        // exactly the case that needs no configuration.
        let target = target.unwrap_or_else(|| client.clone());
        if !self.policy().may_change(client, &target) {
            return Err(ChangeError::Status(
                STATUS_ACCESSDENIED,
                format!("{client} may not change the password of {target}"),
            ));
        }

        let entry = self
            .hdb()
            .fetch(&target)
            .map_err(ChangeError::Fatal)?
            .ok_or_else(|| ChangeError::Status(STATUS_AUTHERROR, format!("{target} is unknown")))?;

        // One implementation of "a new password means new keys at the next kvno,
        // with the salts kept" — on the record, because the administrator's API
        // makes the same change and the two must not diverge.
        let updated = entry
            .rekey(self.cipher(), &new_password)
            .map_err(ChangeError::Fatal)?;
        self.hdb().store(updated).map_err(ChangeError::Fatal)?;
        Ok(())
    }

    /// Decrypts the change-password ticket with the service's own key.
    fn open_changepw_ticket(
        &self,
        enc: &crate::msg::EncryptedData,
        entry: &HdbEntry,
    ) -> Result<crate::msg::EncTicketPart> {
        let key = entry
            .key_for(enc.etype)
            .or_else(|| entry.enctypes().first().and_then(|e| entry.key_for(*e)));
        let key = key.ok_or_else(|| Error::Hdb("kadmin/changepw has no usable key".into()))?;
        let plain = self
            .cipher()
            .decrypt(&key.key, usage::KDC_REP_TICKET, &enc.cipher)
            .map_err(|_| Error::Kdc {
                code: crate::error::codes::KRB_AP_ERR_BAD_INTEGRITY,
                text: "the change-password ticket does not decrypt".into(),
            })?;
        crate::msg::EncTicketPart::decode(&plain)
    }

    /// Decrypts the authenticator in the ticket's session key.
    fn open_authenticator(&self, ap_req: &ApReq, session_key: &Key) -> Result<Authenticator> {
        let plain = self
            .cipher()
            .decrypt(
                session_key,
                usage::AP_REQ_AUTH,
                &ap_req.authenticator.cipher,
            )
            .map_err(|_| Error::Kdc {
                code: crate::error::codes::KRB_AP_ERR_BAD_INTEGRITY,
                text: "the authenticator does not decrypt under the ticket's session key".into(),
            })?;
        Authenticator::decode(&plain)
    }
}

/// Why a change did not happen: a status the protocol can report, or a failure
/// that means the server is broken rather than the request.
enum ChangeError {
    Status(u16, String),
    Fatal(Error),
}

impl From<Error> for ChangeError {
    fn from(e: Error) -> Self {
        ChangeError::Fatal(e)
    }
}

/// The `kadmin/changepw` principal, as a KDC provisioned by hand needs it.
pub fn changepw_entry(realm: &str, cipher: &dyn Cipher, password: &[u8]) -> Result<HdbEntry> {
    let principal = Principal::parse(&format!("kadmin/changepw@{realm}"))?;
    let mut entry = HdbEntry::service(principal);
    // `INITIAL` is what makes the AS the only way to get this ticket: the TGS
    // refuses, which is how RFC 3244's "the ticket must be initial" is enforced
    // rather than merely hoped for.
    entry.flags |= entry_flags::CHANGE_PW | entry_flags::REQUIRE_PREAUTH | entry_flags::INITIAL;
    for enctype in [
        crate::crypto::Enctype::Aes256Sha1,
        crate::crypto::Enctype::Aes128Sha1,
    ] {
        entry.add_password_key(cipher, enctype, password, 1)?;
    }
    Ok(entry)
}
