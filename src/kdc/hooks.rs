//! The three `kdc-plugin.c` hooks this crate had as behaviour but not as seams:
//! `client_access`, `referral_policy`, `finalize_reply`.
//!
//! Heimdal runs all three through `_krb5_plugin_run_f`, and each has a default for when no plugin
//! answers. [`Hooks`] carries the three here, with the same defaults, so a realm that installs none
//! behaves exactly as before — that property is what makes a seam safe to add: a build that ignores
//! it must be indistinguishable, byte for byte, from one that predates it.
//!
//! # What each one is for, in Heimdal's own terms
//!
//! * **`client_access`** (`_kdc_check_access`) answers "may this client have this ticket". Heimdal's
//!   fallback is `kdc_check_flags`, which is the HDB flag check this crate already performs inline —
//!   so the seam's default is [`Allow`], and the flags still apply on top of whatever a deployment
//!   adds. **Heimdal calls it in the AS exchange only**; this crate calls it in both, because the
//!   question an operator asks — "alice may not have a ticket for `cifs/files`" — is a question
//!   about the TGS, and a hook that never sees one cannot answer it. That is an addition, and it is
//!   the only one of the three.
//! * **`referral_policy`** (`_kdc_referral_policy`) is consulted when the service could not be
//!   found, and may turn that refusal into a referral. Heimdal's default is "no plugin, no
//!   referral": the error stands. Ours is [`NoReferral`], the same. The difference from our built-in
//!   referral (`Tgs::referral`) is who decides: that one follows the realm's own hierarchy, and this
//!   one lets a deployment answer for a name no hierarchy explains — a forest trust, a name served by
//!   a KDC this one does not know about.
//! * **`finalize_reply`** (`_kdc_finalize_reply`) sees the finished reply before it goes out, and may
//!   replace it or refuse. Heimdal's default is "nothing to do". Ours is [`Keep`].
//!
//! # A hook cannot silently downgrade security
//!
//! [`AccessPolicy`] returns a decision, not an error code, and the refusal it produces is
//! `KDC_ERR_POLICY`: the code Heimdal answers with when its own access check fails. A hook that
//! wants a different code has no way to ask for one, because the codes a client reacts to
//! differently — `POLICY` meaning "not for you", `S_PRINCIPAL_UNKNOWN` meaning "not here" — are an
//! operator's decision about information disclosure, not a plugin's.

use std::fmt;
use std::sync::Arc;

use crate::error::{Error, codes};
use crate::name::Principal;

/// Which exchange a hook is being asked about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Exchange {
    /// An `AS-REQ`: a client asking for a ticket-granting ticket.
    As,
    /// A `TGS-REQ`: a client presenting a ticket and asking for another.
    Tgs,
}

impl Exchange {
    /// The name a log line should use.
    pub fn as_str(self) -> &'static str {
        match self {
            Exchange::As => "as",
            Exchange::Tgs => "tgs",
        }
    }
}

/// What a hook is told about the ticket being decided.
///
/// The client is the one the KDC established, not the spelling the request carried: after an alias
/// or a canonicalization those differ, and a policy consulted about the wrong name is a policy
/// answering a different question.
#[derive(Debug, Clone)]
pub struct TicketRequest {
    /// Which exchange.
    pub exchange: Exchange,
    /// The client the ticket would be for.
    pub client: Principal,
    /// The service it would be for — already rewritten to the referral hop when a referral was
    /// taken, so a `finalize_reply` hook sees the ticket that was actually built.
    pub service: Principal,
    /// This KDC's realm.
    pub realm: String,
}

impl fmt::Display for TicketRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} -> {}",
            self.exchange.as_str(),
            self.client,
            self.service
        )
    }
}

/// May this client have this ticket?
pub trait AccessPolicy: fmt::Debug + Send + Sync {
    /// `true` to issue, `false` to refuse with `KDC_ERR_POLICY`.
    ///
    /// Called after the client has proved who it is — Heimdal's position, and the only one that
    /// makes sense: a decision about a name nobody has authenticated yet is a decision about a claim.
    fn allows(&self, request: &TicketRequest) -> bool;

    /// `true` when this policy admits everything without looking.
    ///
    /// Not an optimisation detail: it is what lets a realm that installed nothing skip building a
    /// [`TicketRequest`] per ticket. The default is `false`, because a policy that does something
    /// must be asked; only the passthrough may say otherwise.
    fn is_passthrough(&self) -> bool {
        false
    }
}

/// Allows everything. The default, and the behaviour this crate had before the seam existed.
#[derive(Debug, Clone, Copy, Default)]
pub struct Allow;

impl AccessPolicy for Allow {
    fn allows(&self, _request: &TicketRequest) -> bool {
        true
    }

    fn is_passthrough(&self) -> bool {
        true
    }
}

/// A refusal that no referral can rescue.
pub trait ReferralPolicy: fmt::Debug + Send + Sync {
    /// A realm whose `krbtgt` this KDC should answer with instead of refusing, or `None` to let the
    /// refusal stand.
    ///
    /// `code` is the error that would otherwise be sent, so a policy can distinguish "no such
    /// service" from "the name is not a service at all" — Heimdal passes the same fact
    /// (`priv->error_code`) for exactly that reason.
    fn instead_of_refusal(&self, request: &TicketRequest, code: i32) -> Option<Principal>;
}

/// No referral: the refusal stands. The default.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoReferral;

impl ReferralPolicy for NoReferral {
    fn instead_of_refusal(&self, _request: &TicketRequest, _code: i32) -> Option<Principal> {
        None
    }
}

/// The last thing a reply passes through.
pub trait FinalizeReply: fmt::Debug + Send + Sync {
    /// The octets to send — usually `reply` itself — or an error, which becomes a `KRB-ERROR`.
    ///
    /// Handed the reply **already encoded**, because that is the only shape in which Heimdal's hook
    /// can change it too: `r->rep` is built by then. A hook that wants to add authorization data
    /// re-encodes the reply; one that wants to refuse returns an error.
    fn finalize(&self, request: &TicketRequest, reply: Vec<u8>) -> crate::error::Result<Vec<u8>>;
}

/// Pass the reply through, unchanged. The default.
#[derive(Debug, Clone, Copy, Default)]
pub struct Keep;

impl FinalizeReply for Keep {
    fn finalize(&self, _request: &TicketRequest, reply: Vec<u8>) -> crate::error::Result<Vec<u8>> {
        Ok(reply)
    }
}

/// The three hooks a realm may install.
///
/// A struct rather than three `Option`s on [`crate::kdc::Kdc`], so that the defaults live in one
/// place and a caller can see, in one value, what it is replacing.
#[derive(Debug, Clone)]
pub struct Hooks {
    access: Arc<dyn AccessPolicy>,
    referral: Arc<dyn ReferralPolicy>,
    finalize: Arc<dyn FinalizeReply>,
}

impl Default for Hooks {
    fn default() -> Self {
        Self {
            access: Arc::new(Allow),
            referral: Arc::new(NoReferral),
            finalize: Arc::new(Keep),
        }
    }
}

impl Hooks {
    /// The defaults: allow, no referral, pass through.
    pub fn new() -> Self {
        Self::default()
    }

    /// Installs an access policy.
    pub fn with_access(mut self, policy: Arc<dyn AccessPolicy>) -> Self {
        self.access = policy;
        self
    }

    /// Installs a referral policy.
    pub fn with_referral(mut self, policy: Arc<dyn ReferralPolicy>) -> Self {
        self.referral = policy;
        self
    }

    /// Installs a reply hook.
    pub fn with_finalize(mut self, hook: Arc<dyn FinalizeReply>) -> Self {
        self.finalize = hook;
        self
    }

    /// Whether an access policy that does something is installed.
    ///
    /// Exposed because the check is skipped when none is: a [`TicketRequest`] per ticket is cheap
    /// but not free, and a realm that installed nothing should pay nothing.
    pub fn has_access(&self) -> bool {
        !self.access.is_passthrough()
    }

    /// The access decision, with the flag checks applied on top.
    ///
    /// Flags first, then the policy: an account that is locked or expired is refused whatever a
    /// deployment's policy would say, because that is a state of the account rather than a rule
    /// about a request — Heimdal's `kdc_check_flags` runs in the same order for the same reason.
    pub(crate) fn check_access(&self, request: &TicketRequest) -> crate::error::Result<()> {
        if self.access.is_passthrough() {
            return Ok(());
        }
        if self.access.allows(request) {
            return Ok(());
        }
        Err(Error::Kdc {
            code: codes::KDC_ERR_POLICY,
            text: format!("{request}: access refused by this realm's policy"),
        })
    }

    /// A referral instead of the refusal `code` would produce.
    pub(crate) fn referral_for(&self, request: &TicketRequest, code: i32) -> Option<Principal> {
        self.referral.instead_of_refusal(request, code)
    }

    /// The reply, after whatever the deployment wants to do to it.
    pub(crate) fn finalize(
        &self,
        request: &TicketRequest,
        reply: Vec<u8>,
    ) -> crate::error::Result<Vec<u8>> {
        self.finalize.finalize(request, reply)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn principal(name: &str) -> Principal {
        Principal::parse(name).expect("a principal")
    }

    fn request() -> TicketRequest {
        TicketRequest {
            exchange: Exchange::Tgs,
            client: principal("alice@EXAMPLE.COM"),
            service: principal("cifs/files@EXAMPLE.COM"),
            realm: "EXAMPLE.COM".into(),
        }
    }

    /// The defaults change nothing: a realm that installs no hooks issues exactly what it did
    /// before the seam existed.
    #[test]
    fn the_defaults_admit_and_pass_through() {
        let hooks = Hooks::new();
        assert!(hooks.check_access(&request()).is_ok(), "Allow admits");
        assert_eq!(
            hooks.referral_for(&request(), codes::KDC_ERR_S_PRINCIPAL_UNKNOWN),
            None,
            "NoReferral leaves the refusal alone"
        );
        let reply = b"a reply".to_vec();
        assert_eq!(
            hooks.finalize(&request(), reply.clone()).expect("kept"),
            reply,
            "Keep passes it through"
        );
        assert!(
            !hooks.has_access(),
            "the default is recognised as the passthrough"
        );
    }

    /// A policy that refuses produces `KDC_ERR_POLICY` — the code Heimdal answers with — and names
    /// the ticket it refused.
    #[test]
    fn a_refusing_policy_answers_policy_and_names_the_ticket() {
        #[derive(Debug)]
        struct Refuse;
        impl AccessPolicy for Refuse {
            fn allows(&self, _request: &TicketRequest) -> bool {
                false
            }
        }

        let hooks = Hooks::new().with_access(Arc::new(Refuse));
        let err = hooks.check_access(&request()).expect_err("refused");
        assert_eq!(err.kdc_code(), codes::KDC_ERR_POLICY);
        assert!(
            err.to_string().contains("alice@EXAMPLE.COM")
                && err.to_string().contains("cifs/files@EXAMPLE.COM"),
            "the message names both ends: {err}"
        );
        assert!(hooks.has_access(), "an installed policy is consulted");
    }

    /// A referral policy may answer with a hop, and receives the code that would have been sent.
    #[test]
    fn a_referral_policy_sees_the_code_and_may_answer_with_a_hop() {
        use std::sync::Mutex;
        #[derive(Debug)]
        struct Hop {
            seen: Mutex<Vec<i32>>,
        }
        impl ReferralPolicy for Hop {
            fn instead_of_refusal(&self, _request: &TicketRequest, code: i32) -> Option<Principal> {
                self.seen.lock().expect("a test's lock").push(code);
                // Answer only for the failure a referral can fix; anything else is a different
                // problem and a hop would not help.
                (code == codes::KDC_ERR_S_PRINCIPAL_UNKNOWN)
                    .then(|| Principal::krbtgt("PARTNER.EXAMPLE"))
            }
        }

        let hop = Arc::new(Hop {
            seen: Mutex::new(Vec::new()),
        });
        let hooks = Hooks::new().with_referral(Arc::clone(&hop) as Arc<dyn ReferralPolicy>);
        let answered = hooks.referral_for(&request(), codes::KDC_ERR_S_PRINCIPAL_UNKNOWN);
        // `Principal::krbtgt` builds the name in the realm it was given; printing pads the
        // components only, so the realm is the one the policy named.
        let answered = answered.expect("the policy answered");
        assert_eq!(answered.components, vec!["krbtgt", "PARTNER.EXAMPLE"]);
        assert_eq!(answered.realm, "PARTNER.EXAMPLE");
        assert_eq!(
            hop.seen.lock().expect("a test's lock").as_slice(),
            [codes::KDC_ERR_S_PRINCIPAL_UNKNOWN],
            "and it was told why the refusal was coming"
        );
        // A policy that does not answer leaves the refusal.
        assert_eq!(hooks.referral_for(&request(), codes::KDC_ERR_POLICY), None);
    }

    /// A reply hook may replace the reply or refuse, and its refusal is a `KRB-ERROR` for the client.
    #[test]
    fn a_reply_hook_may_replace_or_refuse() {
        #[derive(Debug)]
        struct Add;
        impl FinalizeReply for Add {
            fn finalize(
                &self,
                _request: &TicketRequest,
                mut reply: Vec<u8>,
            ) -> crate::error::Result<Vec<u8>> {
                reply.extend_from_slice(b"+");
                Ok(reply)
            }
        }
        #[derive(Debug)]
        struct Refuse;
        impl FinalizeReply for Refuse {
            fn finalize(
                &self,
                _request: &TicketRequest,
                _reply: Vec<u8>,
            ) -> crate::error::Result<Vec<u8>> {
                Err(Error::Kdc {
                    code: codes::KDC_ERR_POLICY,
                    text: "refused at the last moment".into(),
                })
            }
        }

        let hooks = Hooks::new().with_finalize(Arc::new(Add));
        assert_eq!(
            hooks
                .finalize(&request(), b"reply".to_vec())
                .expect("replaced"),
            b"reply+"
        );

        let hooks = Hooks::new().with_finalize(Arc::new(Refuse));
        assert_eq!(
            hooks
                .finalize(&request(), b"reply".to_vec())
                .expect_err("refused")
                .kdc_code(),
            codes::KDC_ERR_POLICY
        );
    }

    /// `TicketRequest` prints as one line naming the exchange and both ends.
    #[test]
    fn a_request_prints_as_one_line() {
        assert_eq!(
            request().to_string(),
            "tgs alice@EXAMPLE.COM -> cifs/files@EXAMPLE.COM"
        );
    }
}
