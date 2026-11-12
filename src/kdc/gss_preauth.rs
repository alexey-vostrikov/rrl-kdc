//! GSS pre-authentication: the third mechanism, after SPAKE and OTP (Heimdal's `kdc/gss_preauth.c`).
//!
//! A client proves who it is by running a GSS-API context against the KDC — Kerberos itself,
//! typically, which is how an anonymous PKINIT armor plus a GSS exchange logs a user in without a
//! password ever reaching the KDC.
//!
//! **The PA-DATA number is 655, and it is not in the IANA registry.** The registry's
//! *Pre-authentication and Typed Data* table assigns 1–166 and stops; there is no `PA-GSS-CHALLENGE`
//! and no RFC that assigns one. `655` is Heimdal's, from `lib/asn1/krb5.asn1` as
//! `KRB5-PADATA-GSS(655)`, labelled with the `krb-wg-gss-preauth` draft that was never published.
//! Using it is a deliberate interoperability decision — Heimdal is the only implementation, so its
//! number is the wire — and it is written down here because three earlier tasks in this project were
//! given a number from memory and were wrong.
//!
//! **What lives here and what does not.** The mechanism owns the *wiring*: the announcement, the
//! multi-round state in `PA-FX-COOKIE`, the check that the token is bound to this request, the reply
//! key the mechanism's contract requires, and the refusals by name. Accepting the token is a
//! [`GssAcceptor`]'s job, because that is an RFC 2743 implementation with its own key agreement —
//! and this crate deliberately does not depend on the client crate that has one. A realm that has no
//! acceptor does not offer the mechanism, and says so.

use std::fmt;
use std::sync::Arc;

use crate::crypto::Key;
use crate::error::{Error, Result};

use super::preauth::{Announced, Mechanism, Request, Step};

/// `KRB5-PADATA-GSS` (Heimdal's `lib/asn1/krb5.asn1`, `krb-wg-gss-preauth`): 655.
///
/// Not an IANA assignment; see this module's documentation.
pub const PA_GSS: i32 = 655;

/// The name a refusal uses.
pub const NAME: &str = "GSS pre-authentication";

/// Why a token was not accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GssError {
    /// The mechanism the client named is not one this realm allows.
    MechanismNotAllowed(String),
    /// The token itself was refused: a bad MIC, an expired credential, a broken context.
    Refused(String),
    /// The acceptor could not run: its own failure, not the client's.
    Unavailable(String),
}

impl fmt::Display for GssError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GssError::MechanismNotAllowed(m) => write!(
                f,
                "GSS mechanism {m} is not allowed in this realm (gss-mechanisms-allowed)"
            ),
            GssError::Refused(m) => write!(f, "the GSS token was refused: {m}"),
            GssError::Unavailable(m) => write!(f, "the GSS acceptor is unavailable: {m}"),
        }
    }
}

impl std::error::Error for GssError {}

/// What one accept step produced.
#[derive(Debug, Clone)]
pub enum GssStep {
    /// More rounds: the output token goes back to the client, and `state` travels in the cookie.
    Continue {
        /// The token to send back.
        output: Vec<u8>,
        /// What the next round needs to know.
        state: Vec<u8>,
    },
    /// The context is established.
    Done {
        /// The final token, if the mechanism has one.
        output: Vec<u8>,
        /// The context's session key, which becomes the AS reply key.
        session_key: Key,
        /// Who the token proved it was, as the acceptor names it (`alice@EXAMPLE.COM`).
        ///
        /// Compared against the client the request names, because GSS pre-authentication is
        /// authentication and not impersonation: a token that proves one identity does not
        /// authenticate a request for another (Heimdal's `_kdc_gss_check_client`).
        initiator: Option<String>,
        /// Whether the context was anonymous (`GSS_C_ANON_FLAG`).
        ///
        /// Only an anonymous *request* may use one: an anonymous token proves nothing, so
        /// accepting it for a named client would let anybody in.
        anonymous: bool,
        /// How long the context lives, in seconds, when the acceptor knows.
        ///
        /// The ticket cannot outlive the context that authenticated it (Heimdal's
        /// `_kdc_gss_endtime`); `None` and an indefinite lifetime both leave the ticket's own
        /// times alone.
        lifetime: Option<i64>,
        /// The mechanism that was used, by OID, for the log line.
        mechanism: String,
        /// A checksum over `KDC-REQ-BODY` keyed with the established context, when the mechanism
        /// produces one.
        ///
        /// Verified here rather than in the acceptor because *what* it has to cover is the KDC's
        /// business: a token accepted for one request must not be replayable into another, and only
        /// this side knows which request that is.
        body_checksum: Option<Vec<u8>>,
    },
}

/// Accepts GSS-API tokens on the KDC's behalf.
///
/// A seam, for the reason [`super::ca::CertificateAuthority`] is one: a GSS accept implementation is
/// a protocol in its own right (RFC 2743, RFC 4121, and the mechanism's own RFC), and the crate that
/// has one is the client. A realm that wants GSS pre-authentication implements this over its own
/// stack; the KDC keeps the exchange, the state and the policy.
pub trait GssAcceptor: Send + Sync + fmt::Debug {
    /// Runs one step of the context.
    ///
    /// `state` is what the previous step left (empty on the first), so an acceptor that keeps no
    /// server-side state — the only kind that survives a KDC restart — can carry its own into the
    /// cookie.
    /// `bindings` is the `KDC-REQ-BODY` as it arrived, which the acceptor is expected to check in
    /// the token's channel bindings (`application_data`): a context that is not bound to this
    /// request can be replayed into another one, and the draft that defines the mechanism puts the
    /// body there for exactly that reason (`gss-preauth`, `cb.application_data` in Heimdal's
    /// `kdc/gss_preauth.c`). An acceptor that cannot bind says so by refusing, not by ignoring the
    /// argument.
    fn step(
        &self,
        mechanism: Option<&str>,
        token: &[u8],
        state: &[u8],
        bindings: &[u8],
    ) -> std::result::Result<GssStep, GssError>;
}

/// The mechanism, as the pre-authentication framework sees it.
#[derive(Debug)]
pub struct GssPreauth {
    acceptor: Arc<dyn GssAcceptor>,
    /// The mechanism OIDs a client may name (`gss-mechanisms-allowed`). Empty means every one the
    /// acceptor knows.
    allowed: Vec<String>,
    /// Whether a mechanism whose realm is not ours may be used (`gss-cross-realm-mechanisms-allowed`).
    cross_realm_allowed: bool,
    /// This realm, for the cross-realm check.
    realm: String,
}

impl GssPreauth {
    /// The mechanism over `acceptor`, with the realm's policy.
    pub fn new(
        acceptor: Arc<dyn GssAcceptor>,
        allowed: Vec<String>,
        cross_realm_allowed: bool,
        realm: &str,
    ) -> GssPreauth {
        GssPreauth {
            acceptor,
            allowed,
            cross_realm_allowed,
            realm: realm.to_owned(),
        }
    }

    /// Whether `mechanism` may be used here.
    ///
    /// The list is by OID, and an empty list means "whatever the acceptor accepts": a realm that has
    /// not written a list has not decided, and refusing everything would make the option look like a
    /// way to turn the mechanism off — which `enable-gss-preauth` already is.
    fn mechanism_allowed(&self, mechanism: &str) -> bool {
        if self.allowed.is_empty() {
            return true;
        }
        self.allowed.iter().any(|m| m == mechanism)
    }

    /// Whether a mechanism issued in `realm` may be used here.
    ///
    /// A mechanism OID carries no realm — the *credential* does — so this is checked where the
    /// acceptor reports it: a client from another realm is exactly the case RFC 6113 §5.4.2.1
    /// describes for armor, and a realm that has not allowed it must refuse rather than accept a
    /// cross-realm identity as a local one.
    fn realm_allowed(&self, realm: Option<&str>) -> bool {
        match realm {
            None => true,
            Some(r) => self.cross_realm_allowed || r == self.realm,
        }
    }
}

impl Mechanism for GssPreauth {
    fn pa_type(&self) -> i32 {
        PA_GSS
    }

    fn name(&self) -> &'static str {
        NAME
    }

    fn round(&self, request: &Request<'_>, state: &[u8], padata: &[u8]) -> Result<Step> {
        // `PA-GSS` carries a mechanism OID (optional) and the token, inside a SEQUENCE. A client
        // that sends a bare token is understood too: the OID is what a realm policy filters on, and
        // an acceptor that knows only one mechanism does not need it.
        let Parsed {
            mechanism,
            token,
            realm: token_realm,
        } = match decode(padata) {
            Ok(parsed) => parsed,
            Err(e) => {
                return Err(Error::PreauthFailed(format!("{NAME}: {e}")));
            }
        };
        if let Some(m) = &mechanism
            && !self.mechanism_allowed(m)
        {
            return Err(Error::PreauthFailed(format!(
                "{NAME}: {}",
                GssError::MechanismNotAllowed(m.clone())
            )));
        }
        if !self.realm_allowed(token_realm.as_deref()) {
            return Err(Error::PreauthFailed(format!(
                "{NAME}: a token from {} is refused, and this realm does not allow mechanisms from \
                 another one (gss-cross-realm-mechanisms-allowed)",
                token_realm.unwrap_or_default()
            )));
        }

        match self
            .acceptor
            .step(mechanism.as_deref(), &token, state, request.body)
        {
            Ok(GssStep::Continue { output, state }) => Ok(Step::More {
                padata: encode_pa_gss(mechanism.as_deref(), &output),
                state,
            }),
            Ok(GssStep::Done {
                output,
                session_key,
                initiator,
                anonymous,
                lifetime,
                mechanism,
                body_checksum,
            }) => {
                // An anonymous context proves nothing about who is asking, so it authenticates
                // only an anonymous request (Heimdal: `GSS_C_ANON_FLAG` without
                // `_kdc_is_anon_request` is `KDC_ERR_BADOPTION`).
                if anonymous && !is_anonymous(request.cname) {
                    return Err(Error::PreauthFailed(format!(
                        "{NAME}: an anonymous context was offered for {}, which is not an \
                         anonymous request",
                        request.cname
                    )));
                }
                // Authentication, not impersonation: the identity the token proved has to be the
                // one the request asks for. Without this a token for any principal would
                // authenticate a ticket for any other.
                if let Some(initiator) = &initiator
                    && !anonymous
                    && !names_the_client(initiator, request.cname)
                {
                    return Err(Error::PreauthFailed(format!(
                        "{NAME}: the token proves {initiator}, and the request is for {}",
                        request.cname
                    )));
                }
                // The checksum binds the token to this request; without it a token captured from
                // another AS-REQ would authenticate this one. A mechanism that produces none leaves
                // the question to its own MIC, which is why this is `Option` rather than required —
                // and why the acceptor's documentation says which it produces.
                if let Some(checksum) = body_checksum {
                    let expected = crate::crypto::profile::checksum(
                        session_key.enctype(),
                        session_key.bytes(),
                        request.body,
                    )
                    .map_err(|e| Error::PreauthFailed(format!("{NAME}: the body checksum: {e}")))?;
                    if checksum != expected {
                        return Err(Error::PreauthFailed(format!(
                            "{NAME}: the token answers a different request (checksum)"
                        )));
                    }
                }
                let _ = mechanism;
                Ok(Step::Done {
                    // The GSS context's key *is* the reply key (Heimdal's `PA_REPLACE_REPLY_KEY`):
                    // the client derived it in the exchange, and deriving a second one from a
                    // long-term key would need the password this mechanism exists to avoid.
                    reply_key: session_key,
                    padata: Some(encode_pa_gss(None, &output)),
                    // The ticket cannot outlive the context, and a bounded context bounds it:
                    // `_kdc_gss_endtime` in Heimdal, for the same reason — a ticket whose
                    // authentication has expired is a ticket nobody can act on.
                    endtime_bound: lifetime.filter(|l| *l > 0),
                })
            }
            Err(GssError::Unavailable(why)) => Err(Error::PreauthFailed(format!("{NAME}: {why}"))),
            Err(e) => Err(Error::PreauthFailed(format!("{NAME}: {e}"))),
        }
    }
}

/// Whether `name` is RFC 6111's well-known anonymous principal.
///
/// Spelled out here rather than reached for: the KDC's own `is_anonymous` is private to
/// [`super::as_exchange`], and the check this mechanism makes is about the *initiator* a token
/// proved, not about the request.
fn is_anonymous(name: &crate::name::Principal) -> bool {
    name.name_type == crate::name::NT_WELLKNOWN
        && name.components.len() == 2
        && name.components[0] == "WELLKNOWN"
        && name.components[1] == "ANONYMOUS"
}

/// Whether an acceptor's `initiator` name is the principal the request asks for.
///
/// Compared as text because the acceptor's name comes from a GSS name and is not a
/// [`crate::name::Principal`]; the two spellings that reach here are `name@REALM` and a bare
/// `name`, the second being what an acceptor reports when it knows no realm.
fn names_the_client(initiator: &str, client: &crate::name::Principal) -> bool {
    let want = client.to_string();
    if initiator == want {
        return true;
    }
    // `name` without the realm: the acceptor's name, not ours to complete.
    !initiator.contains('@') && client.components.join("/") == initiator
}

/// `KRB5-PADATA-GSS`'s value: `SEQUENCE { mechanism [0] OPTIONAL, token [1], realm [2] OPTIONAL }`.
///
/// Written and read by hand because no ASN.1 module for the draft is in any released tree: the fields
/// are the three a realm needs, and the layout is documented here rather than inferred from a
/// compiler's output.
pub fn encode_pa_gss(mechanism: Option<&str>, token: &[u8]) -> Vec<u8> {
    let mut fields = Vec::new();
    if let Some(m) = mechanism {
        fields.push(crate::der::field(
            0,
            crate::der::tlv(crate::der::OBJECT_IDENTIFIER, &oid_content(m)),
        ));
    }
    fields.push(crate::der::field(1, crate::der::octets(token)));
    crate::der::seq(&fields)
}

/// A `PA-GSS` value, as far as this mechanism reads it.
struct Parsed {
    /// The mechanism OID the client named, if any.
    mechanism: Option<String>,
    /// The GSS token itself.
    token: Vec<u8>,
    /// The realm the token was issued in, when the client says.
    realm: Option<String>,
}

/// `(mechanism OID, token, realm)` out of a `PA-GSS` value.
fn decode(padata: &[u8]) -> std::result::Result<Parsed, String> {
    let mut r = crate::der::Reader::new(padata);
    let Ok(seq) = r.next_tlv("PA-GSS") else {
        // A bare token: what a client that knows only one mechanism sends.
        return Ok(Parsed {
            mechanism: None,
            token: padata.to_vec(),
            realm: None,
        });
    };
    if seq.tag != crate::der::SEQUENCE {
        return Ok(Parsed {
            mechanism: None,
            token: padata.to_vec(),
            realm: None,
        });
    }
    let mut f = crate::der::Reader::new(seq.content);
    let mut mechanism = None;
    let mut token = None;
    let mut realm = None;
    while !f.is_empty() {
        let field = f.next_tlv("field").map_err(|e| format!("PA-GSS: {e}"))?;
        let mut fr = crate::der::Reader::new(field.content);
        let inner = fr.next_tlv("value").map_err(|e| format!("PA-GSS: {e}"))?;
        match field.tag {
            t if t == crate::der::ctx(0) => {
                mechanism = Some(
                    crate::der::decode_oid("mechanism", inner.content)
                        .map_err(|e| format!("PA-GSS mechanism: {e}"))?,
                );
            }
            t if t == crate::der::ctx(1) => token = Some(inner.content.to_vec()),
            t if t == crate::der::ctx(2) => {
                realm = Some(String::from_utf8_lossy(inner.content).into_owned())
            }
            _ => {}
        }
    }
    let token = token.ok_or_else(|| "PA-GSS carries no token".to_string())?;
    Ok(Parsed {
        mechanism,
        token,
        realm,
    })
}

/// OID content octets from its dotted text.
fn oid_content(text: &str) -> Vec<u8> {
    let parts: Vec<u64> = text.split('.').map(|p| p.parse().unwrap()).collect();
    let mut out = vec![(40 * parts[0] + parts[1]) as u8];
    for &part in &parts[2..] {
        let mut chunk = vec![(part & 0x7f) as u8];
        let mut rest = part >> 7;
        while rest > 0 {
            chunk.push(0x80 | (rest & 0x7f) as u8);
            rest >>= 7;
        }
        chunk.reverse();
        out.extend(chunk);
    }
    out
}

/// The announcement: an empty `PA-GSS`, which is how a client learns the mechanism exists.
pub fn announcement() -> Announced {
    Announced::default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{Cipher, Enctype, OwnCipher};

    /// An acceptor that finishes in one round and hands back a fixed key: the mechanism's wiring,
    /// without a GSS stack.
    #[derive(Debug)]
    struct OneShot;

    impl GssAcceptor for OneShot {
        fn step(
            &self,
            mechanism: Option<&str>,
            _token: &[u8],
            _state: &[u8],
            _bindings: &[u8],
        ) -> std::result::Result<GssStep, GssError> {
            Ok(GssStep::Done {
                output: Vec::new(),
                session_key: OwnCipher.random(Enctype::Aes256Sha1).expect("a key"),
                // The initiator the token proved, which has to be the client the request names.
                initiator: Some("alice@EXAMPLE.COM".to_owned()),
                anonymous: false,
                lifetime: None,
                mechanism: mechanism.unwrap_or("1.2.840.113554.1.2.2").to_owned(),
                body_checksum: None,
            })
        }
    }

    /// An acceptor that needs two rounds, so the cookie state can be seen to work.
    #[derive(Debug)]
    struct TwoRounds;

    impl GssAcceptor for TwoRounds {
        fn step(
            &self,
            _mechanism: Option<&str>,
            token: &[u8],
            state: &[u8],
            _bindings: &[u8],
        ) -> std::result::Result<GssStep, GssError> {
            if state.is_empty() {
                return Ok(GssStep::Continue {
                    output: b"a challenge".to_vec(),
                    state: format!("carried {}", token.len()).into_bytes(),
                });
            }
            Ok(GssStep::Done {
                output: Vec::new(),
                session_key: OwnCipher.random(Enctype::Aes256Sha1).expect("a key"),
                initiator: Some("alice@EXAMPLE.COM".to_owned()),
                anonymous: false,
                lifetime: None,
                mechanism: "1.2.840.113554.1.2.2".to_owned(),
                body_checksum: None,
            })
        }
    }

    /// A request with a client and a body: what a mechanism is handed.
    static CLIENT: std::sync::OnceLock<crate::name::Principal> = std::sync::OnceLock::new();

    fn request() -> Request<'static> {
        Request {
            cname: CLIENT.get_or_init(|| {
                crate::name::Principal::parse("alice@EXAMPLE.COM").expect("a principal")
            }),
            realm: "EXAMPLE.COM",
            body: b"the KDC-REQ-BODY",
            longterm: &[],
            armor: None,
            now: 0,
            cipher: &OwnCipher,
        }
    }

    /// The type is 655, which is Heimdal's and not an IANA assignment — the one fact in this module
    /// that a reader will want to check, so it is asserted rather than trusted.
    #[test]
    fn the_pa_type_is_heimdals_655() {
        assert_eq!(PA_GSS, 655);
        assert_eq!(
            GssPreauth::new(Arc::new(OneShot), Vec::new(), false, "R").pa_type(),
            655
        );
    }

    /// A realm that names a mechanism list refuses a token for another, and the refusal names it.
    #[test]
    fn a_mechanism_outside_the_realm_list_is_refused_by_name() {
        let mechanism = GssPreauth::new(
            Arc::new(OneShot),
            vec!["1.2.840.113554.1.2.2".to_owned()],
            false,
            "EXAMPLE.COM",
        );
        let padata = encode_pa_gss(Some("1.3.6.1.5.2.5"), b"a token");
        let err = mechanism
            .round(&request(), &[], &padata)
            .expect_err("an unlisted mechanism must be refused");
        let text = err.to_string();
        assert!(text.contains("1.3.6.1.5.2.5"), "{text}");
        assert!(text.contains("gss-mechanisms-allowed"), "{text}");

        // The listed one is accepted, so the list is a filter and not a switch.
        let padata = encode_pa_gss(Some("1.2.840.113554.1.2.2"), b"a token");
        assert!(matches!(
            mechanism.round(&request(), &[], &padata).expect("accepted"),
            Step::Done { .. }
        ));
    }

    /// A token from another realm is refused unless the realm allowed cross-realm mechanisms.
    #[test]
    fn a_cross_realm_token_is_refused_unless_allowed() {
        let strict = GssPreauth::new(Arc::new(OneShot), Vec::new(), false, "EXAMPLE.COM");
        let token = {
            let mut fields = vec![crate::der::field(1, crate::der::octets(b"a token"))];
            fields.push(crate::der::field(2, crate::der::tlv(0x1b, b"OTHER.COM")));
            crate::der::seq(&fields)
        };
        let err = strict
            .round(&request(), &[], &token)
            .expect_err("a foreign realm must be refused");
        assert!(
            err.to_string()
                .contains("gss-cross-realm-mechanisms-allowed"),
            "{err}"
        );

        let permissive = GssPreauth::new(Arc::new(OneShot), Vec::new(), true, "EXAMPLE.COM");
        assert!(matches!(
            permissive.round(&request(), &[], &token).expect("allowed"),
            Step::Done { .. }
        ));
    }

    /// Two rounds: the first leaves state, which travels in the cookie and comes back — and the
    /// second round completes.
    #[test]
    fn a_two_round_mechanism_carries_its_state_in_the_cookie() {
        let mechanism = GssPreauth::new(Arc::new(TwoRounds), Vec::new(), false, "EXAMPLE.COM");
        let first = mechanism
            .round(&request(), &[], &encode_pa_gss(None, b"an initial token"))
            .expect("the first round");
        let Step::More { state, padata } = first else {
            panic!("a two-round acceptor must ask for another round");
        };
        let sent = b"an initial token";
        assert_eq!(
            state,
            format!("carried {}", sent.len()).into_bytes(),
            "the state is the acceptor's, carried verbatim"
        );
        // The second round, with what the cookie carried, completes.
        assert!(
            matches!(
                mechanism
                    .round(&request(), &state, &encode_pa_gss(None, &padata))
                    .expect("the second round"),
                Step::Done { .. }
            ),
            "a two-round acceptor finishes on the second round"
        );
    }
}
