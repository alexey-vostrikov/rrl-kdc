//! Multi-round pre-authentication: the plumbing SPAKE and OTP both need.
//!
//! Every pre-authentication this crate had until now fits in one message: the client
//! proves it holds a key, the KDC checks it, done. `PA-ENC-TIMESTAMP`, `PA-ENCRYPTED-CHALLENGE`
//! and PKINIT are all like that. SPAKE (RFC 9588) and OTP (RFC 6560) are not: they take three
//! or more messages, and each one has to remember what happened in the previous one.
//!
//! Two things make that possible, and neither is a table on the KDC:
//!
//! * `KDC_ERR_MORE_PREAUTH_DATA_REQUIRED` (91, RFC 6113 §3.1) — the answer that means
//!   "not a refusal, keep going". A client reading it sends another request; a client
//!   reading `KDC_ERR_PREAUTH_FAILED` gives up. Conflating the two turns a working login
//!   into a wrong-password message.
//! * `PA-FX-COOKIE` (RFC 6113 §5.4.2.3) — where the state lives between rounds, encrypted
//!   under a realm key the client cannot read. [`crate::kdc::cookie`] has the mechanics;
//!   this module is what writes into it.
//!
//! # What a mechanism has to answer
//!
//! [`Mechanism::announce`] is what the KDC says when it asks the client to pre-authenticate:
//! usually an empty PA-DATA that just names the mechanism, but OTP's shape is a challenge
//! with a nonce, so the same hook carries content and the state behind it. [`Mechanism::round`]
//! is one exchange step: given what the last round remembered and what the client sent, it
//! either asks for more, finishes with the key that seals the reply, or refuses.
//!
//! The reply key is the mechanism's output because it is the mechanism that decides it: under
//! SPAKE the reply key is derived from the exchange rather than from the long-term key, and
//! under OTP it is the armor key. A framework that returned `()` would leave each mechanism
//! reaching into the AS path to install it, which is where the two copies of that logic would
//! start to differ.
//!
//! # Off unless asked for
//!
//! A realm with no mechanism configured offers none, and a request naming one is refused
//! **by name** rather than falling back to a password. A silent fallback is worse than a
//! refusal here: a client that asked for SPAKE and got an encrypted-timestamp challenge
//! would log in, never learn that the PAKE it relied on was absent, and keep a recorded
//! exchange that is guessable offline.

use std::sync::Arc;

use crate::crypto::{Cipher, Key};
use crate::error::Result;
use crate::name::Principal;

/// `KDC_ERR_MORE_PREAUTH_DATA_REQUIRED` (RFC 6113 §3.1).
///
/// The code that means "continue": the client sends another request, the KDC resumes from
/// the cookie. It is deliberately not `KDC_ERR_PREAUTH_FAILED` — a client that sees the
/// latter reports a bad password and stops.
pub const MORE_PREAUTH_DATA_REQUIRED: i32 = crate::error::codes::KDC_ERR_MORE_PREAUTH_DATA_REQUIRED;

/// The PA-DATA elements to advertise, and the cookie state that goes behind them.
///
/// A named type rather than a tuple spelled out at the call site: the two halves are one
/// fact — an announcement and the memory it needs — and a signature that says so is the
/// documentation a reader would otherwise have to reconstruct.
pub type Announcements = (Vec<(i32, Vec<u8>)>, Vec<u8>);

/// What the KDC announces for a mechanism that has not started yet.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Announced {
    /// The PA-DATA value to put in `METHOD-DATA`. Empty is the common case: RFC 9588 §4.1
    /// has the KDC say "I speak SPAKE" with an empty `PA-SPAKE`, and the client then sends
    /// its support message.
    pub padata: Vec<u8>,
    /// What the cookie must carry so that the client's next request can be resumed. Empty
    /// for a mechanism whose first round needs no memory.
    pub state: Vec<u8>,
}

/// One step's verdict.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Step {
    /// Another round is needed. `padata` travels to the client in `METHOD-DATA` of a
    /// `KDC_ERR_MORE_PREAUTH_DATA_REQUIRED`; `state` goes into the cookie, and comes back
    /// as the `state` argument of the next [`Mechanism::round`].
    More {
        /// The PA-DATA value for the client.
        padata: Vec<u8>,
        /// What the next round has to remember.
        state: Vec<u8>,
    },
    /// The mechanism has authenticated the client. `reply_key` is what the AS-REP's
    /// encrypted part is sealed with — under SPAKE it is derived from the exchange, under
    /// OTP it is the armor key.
    Done {
        /// The key that seals the reply.
        reply_key: Key,
        /// A PA-DATA value to carry in the reply, when the mechanism has one to send.
        padata: Option<Vec<u8>>,
    },
    /// This round did not verify. `code` is the `KDC_ERR_*` to return, so that a mechanism
    /// can say `KDC_ERR_ETYPE_NOSUPP` for a group it does not implement rather than the
    /// blanket `PREAUTH_FAILED`.
    Failed {
        /// The refusal code.
        code: i32,
        /// The `e-text`.
        text: String,
    },
}

/// Everything a mechanism may look at while deciding a round.
///
/// A struct rather than eight arguments: the set is one fact (this exchange, as the KDC
/// sees it), and clippy's argument limit is right that a mechanism reading a dozen
/// positional parameters is unreadable.
pub struct Request<'a> {
    /// Who is logging in.
    pub cname: &'a Principal,
    /// The realm being served.
    pub realm: &'a str,
    /// The `KDC-REQ-BODY` as it arrived. A mechanism that binds its exchange to the
    /// request has to hash the octets the client sent, not a re-encoding of them.
    pub body: &'a [u8],
    /// The client's long-term keys, one per usable enctype. SPAKE derives its multiplier
    /// from the key of the enctype it will use, so it needs all the candidates.
    pub longterm: &'a [Key],
    /// The armor key, when the request came inside FAST. OTP requires it.
    pub armor: Option<&'a Key>,
    /// The current time.
    pub now: i64,
    /// The cipher: randomness and the primitives a mechanism needs. It comes from the
    /// same place as everything else the KDC does, so a mechanism cannot quietly use a
    /// different source of entropy.
    pub cipher: &'a dyn Cipher,
}

/// A pre-authentication that may need more than one round.
///
/// Implementations are held by the [`crate::kdc::Kdc`] and consulted for every AS request
/// that names their PA-DATA type. Nothing else calls them, which is why the trait takes
/// the request context rather than being handed a half-parsed request by the caller.
pub trait Mechanism: Send + Sync {
    /// The `PA-DATA` type this mechanism owns, e.g. `PA-SPAKE` 151 or `PA-OTP-REQUEST` 142.
    fn pa_type(&self) -> i32;

    /// The mechanism's name, for the refusals that have to name what is not offered.
    fn name(&self) -> &'static str;

    /// What to announce when the KDC asks the client to pre-authenticate.
    ///
    /// The default is the empty PA-DATA of RFC 9588 §4.1: a value whose presence says the
    /// mechanism exists and nothing more.
    fn announce(&self, request: &Request<'_>) -> Result<Announced> {
        let _ = request;
        Ok(Announced::default())
    }

    /// One round: `state` is what the previous round left in the cookie (empty for the
    /// first), `padata` is the value the client sent for this mechanism this time.
    fn round(&self, request: &Request<'_>, state: &[u8], padata: &[u8]) -> Result<Step>;
}

/// The mechanisms a realm offers, in the order they are tried.
///
/// A `Vec` rather than a map: the set is tiny, the order is the operator's, and a request
/// naming two mechanisms is answered with the first the KDC configured rather than with
/// whichever a `HashMap` happened to yield.
#[derive(Default)]
pub struct Registry {
    mechanisms: Vec<Arc<dyn Mechanism>>,
}

impl std::fmt::Debug for Registry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list()
            .entries(self.mechanisms.iter().map(|m| m.name()))
            .finish()
    }
}

impl Registry {
    /// An empty registry: a realm that offers no multi-round pre-authentication.
    pub fn new() -> Self {
        Registry::default()
    }

    /// The same registry with `mechanism` added.
    pub fn with(mut self, mechanism: Arc<dyn Mechanism>) -> Self {
        self.mechanisms.push(mechanism);
        self
    }

    /// Whether anything is configured. A registry that is empty must not advertise
    /// anything, and must not accept a request naming a mechanism.
    pub fn is_empty(&self) -> bool {
        self.mechanisms.is_empty()
    }

    /// The configured mechanisms, for the caller that has to announce them.
    pub fn mechanisms(&self) -> &[Arc<dyn Mechanism>] {
        &self.mechanisms
    }

    /// The mechanism that owns `pa_type`, if this realm offers it.
    pub fn find(&self, pa_type: i32) -> Option<&Arc<dyn Mechanism>> {
        self.mechanisms.iter().find(|m| m.pa_type() == pa_type)
    }

    /// The mechanism to run for `padata`: the first configured one the client named.
    ///
    /// `None` when the client named none, which is not an error — it is the ordinary case
    /// of a client using a method this realm also supports.
    pub fn requested(&self, padata: &[(i32, Vec<u8>)]) -> Option<(&Arc<dyn Mechanism>, Vec<u8>)> {
        self.mechanisms.iter().find_map(|m| {
            padata
                .iter()
                .find(|(ty, _)| *ty == m.pa_type())
                .map(|(_, value)| (m, value.clone()))
        })
    }

    /// The announcement for every configured mechanism, ready for `METHOD-DATA`.
    ///
    /// Returns the PA-DATA elements and the cookie state that goes with them. Both are
    /// needed together: OTP's announcement carries a nonce, and a nonce the KDC cannot
    /// remember is an accusation, not a challenge.
    pub fn announce_all(&self, request: &Request<'_>) -> Result<Announcements> {
        let mut items = Vec::with_capacity(self.mechanisms.len());
        let mut state = Vec::new();
        for mechanism in &self.mechanisms {
            let announced = mechanism.announce(request)?;
            items.push((mechanism.pa_type(), announced.padata));
            // A mechanism that produces state is telling the KDC to remember it. Two
            // mechanisms at once is a configuration nobody has asked for yet, and
            // concatenating their states would be a protocol of our own invention — so
            // the last one to speak wins, and taking that decision here keeps it visible
            // instead of spreading it over the mechanisms.
            if !announced.state.is_empty() {
                state = announced.state;
            }
        }
        Ok((items, state))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{Enctype, OwnCipher};

    /// A mechanism that does nothing, for the registry's own tests.
    struct Named(&'static str, i32);

    impl Mechanism for Named {
        fn pa_type(&self) -> i32 {
            self.1
        }
        fn name(&self) -> &'static str {
            self.0
        }
        fn round(&self, _request: &Request<'_>, _state: &[u8], _padata: &[u8]) -> Result<Step> {
            Ok(Step::More {
                padata: Vec::new(),
                state: Vec::new(),
            })
        }
    }

    fn request_context() -> (Principal, Vec<Key>, OwnCipher) {
        let cipher = OwnCipher;
        let key = cipher
            .s2k(Enctype::Aes256Sha1, b"secret", b"salt", None)
            .unwrap();
        (
            Principal::parse("alice@EXAMPLE.COM").unwrap(),
            vec![key],
            cipher,
        )
    }

    #[test]
    fn an_empty_registry_finds_and_announces_nothing() {
        // A realm that configured no mechanism must behave as though the feature did not
        // exist: no advertisement, no match, and no panic on the empty path.
        let registry = Registry::new();
        assert!(registry.is_empty());
        assert!(registry.mechanisms().is_empty());
        assert!(registry.find(151).is_none());
        assert!(registry.requested(&[(151, vec![1, 2])]).is_none());

        let (cname, keys, cipher) = request_context();
        let context = Request {
            cname: &cname,
            realm: "EXAMPLE.COM",
            body: &[],
            longterm: &keys,
            armor: None,
            now: 1,
            cipher: &cipher,
        };
        let (items, state) = registry.announce_all(&context).unwrap();
        assert!(items.is_empty());
        assert!(state.is_empty());
    }

    #[test]
    fn a_registry_finds_the_mechanism_that_owns_the_type() {
        let registry = Registry::new()
            .with(Arc::new(Named("first", 151)))
            .with(Arc::new(Named("second", 142)));
        assert!(!registry.is_empty());
        assert_eq!(registry.mechanisms().len(), 2);
        assert_eq!(registry.find(142).map(|m| m.name()), Some("second"));
        assert!(registry.find(999).is_none());
    }

    #[test]
    fn the_first_configured_mechanism_the_client_named_is_the_one_that_runs() {
        // Order is the operator's, not a hash map's: a request naming two mechanisms has to
        // be answered by the same one every time, or two identically configured realms
        // behave differently and nobody can reproduce a report.
        let registry = Registry::new()
            .with(Arc::new(Named("first", 151)))
            .with(Arc::new(Named("second", 142)));

        let (mechanism, value) = registry
            .requested(&[(142, b"b".to_vec()), (151, b"a".to_vec())])
            .expect("a configured mechanism was named");
        assert_eq!(mechanism.name(), "first", "configuration order wins");
        assert_eq!(value, b"a", "the value is the one for *that* mechanism");
    }

    #[test]
    fn an_announcement_without_state_leaves_the_cookie_carrying_what_the_client_brought() {
        let registry = Registry::new().with(Arc::new(Named("plain", 151)));
        let (cname, keys, cipher) = request_context();
        let context = Request {
            cname: &cname,
            realm: "EXAMPLE.COM",
            body: &[],
            longterm: &keys,
            armor: None,
            now: 1,
            cipher: &cipher,
        };
        let (items, state) = registry.announce_all(&context).unwrap();
        assert_eq!(items, vec![(151, Vec::new())]);
        assert!(state.is_empty());
    }

    #[test]
    fn the_default_announcement_is_the_empty_pa_data_of_rfc_9588() {
        // §4.1: the KDC says it speaks the mechanism with an empty PA-DATA, and the client
        // answers with its support message. A default with content would be a challenge
        // invented by the framework rather than by the mechanism.
        let plain = Named("plain", 151);
        let (cname, keys, cipher) = request_context();
        let context = Request {
            cname: &cname,
            realm: "EXAMPLE.COM",
            body: &[],
            longterm: &keys,
            armor: None,
            now: 1,
            cipher: &cipher,
        };
        let announced = plain.announce(&context).unwrap();
        assert!(announced.padata.is_empty());
        assert!(announced.state.is_empty());
    }
}
