//! kx509: a certificate for a Kerberos ticket (RFC 6717, Heimdal's `kdc/kx509.c`).
//!
//! A client that already holds a ticket asks for an X.509 certificate naming the principal that
//! ticket proves, and gets one signed by the realm's authority. It is the bridge from Kerberos to
//! everything that wants a certificate — TLS client authentication, a REST endpoint that knows only
//! X.509 — without a second credential store.
//!
//! **The message is not a KDC-REQ**, and that is why it is recognised here rather than in
//! [`super::as_exchange`]: a KDC-REQ begins with `[APPLICATION 10]` or `[APPLICATION 12]`, while a
//! kx509 request begins with the four octets `00 00 02 00` (version 2.0) followed by a DER
//! `Kx509Request`. Heimdal dispatches the same way (`kdc/process.c`, `kdc_kx509`).
//!
//! ```text
//! Kx509Request ::= SEQUENCE {
//!     authenticator  OCTET STRING,   -- an AP-REQ, or empty for an availability probe
//!     pk-hash        OCTET STRING,   -- HMAC-SHA1(session_key, version || pk-key)
//!     pk-key         OCTET STRING }  -- a Kx509CSRPlus, i.e. a CSR with proof of possession
//!
//! Kx509Response ::= SEQUENCE {
//!     error-code [0] INTEGER DEFAULT 0,
//!     hash       [1] OCTET STRING OPTIONAL,   -- HMAC-SHA1(session_key, version || errcode || cert)
//!     certificate[2] OCTET STRING OPTIONAL,
//!     e-text     [3] VisibleString OPTIONAL }
//! ```
//!
//! The MAC is HMAC-SHA1 whatever the session key's enctype is (RFC 6717 §3): the key is used as
//! octets, not through the enctype's own checksum construction. Getting that wrong produces a
//! request the KDC rejects with no explanation, because the MAC is the only authentication the
//! payload itself carries.

use std::sync::Arc;

use crate::crypto::Cipher;
use crate::crypto::usage;
use crate::error::{Error, codes};
use crate::hdb::HdbEntry;
use crate::msg::{ApReq, EncTicketPart};
use crate::name::Principal;

use super::Kdc;
use super::ca::{self, CertificateAuthority, Csr};

// The wire protocol — both directions, the framing, the two MACs and the CSR wrapper — lives in
// `rrl_krb_common::kx509`, because the client is in another crate and the MACs have no room for
// interpretation. What is here is the KDC's side of it: who may ask, what gets signed, and what the
// answer says when it cannot be. The names are re-exported so that a caller of this module does not
// have to know which crate a given constant came from.
pub use rrl_krb_common::kx509::{
    APP_CSR_PLUS, KRB_ERROR_BASE, Request, Response, STATUS_CLIENT_BAD, STATUS_SERVER_BAD, VERSION,
    csr_from_plus, hmac_sha1, plus_from_csr,
};

impl Kdc {
    /// Answers a kx509 request, or `None` when the request is not one.
    ///
    /// `None` and not an error: the same port carries KDC-REQs, and a caller that had to tell "not
    /// kx509" from "kx509 that failed" by an error type would be re-parsing the version prefix here.
    pub fn handle_kx509(&self, request: &[u8], now: i64) -> Option<Vec<u8>> {
        if !Request::claims(request) {
            return None;
        }
        Some(self.kx509_inner(request, now))
    }

    fn kx509_authority(&self) -> Option<&Arc<dyn CertificateAuthority>> {
        self.ca()
    }

    fn kx509_inner(&self, request: &[u8], now: i64) -> Vec<u8> {
        let ca = self.kx509_authority();
        let parsed = match Request::decode(request) {
            Ok(r) => r,
            Err(e) => {
                // Nothing was authenticated, so no MAC: the client can still read the code.
                return Response::error(STATUS_CLIENT_BAD, format!("{e}")).encode();
            }
        };

        // An availability probe: Heimdal's "is the service there" round, which a client sends
        // before it spends a signed CSR on it.
        if parsed.authenticator.is_empty() {
            return match ca {
                Some(_) => Response::error(
                    0,
                    format!("kx509 is available for realm {}", self.config().realm()),
                )
                .encode(),
                None => Response::error(STATUS_SERVER_BAD, "kx509 is not enabled in this realm")
                    .encode(),
            };
        }

        let Some(ca) = ca else {
            // The request was authenticated in principle but there is nothing to issue from. The
            // answer needs no MAC: it tells the client to stop, and a MAC over "server has no CA"
            // would require the session key, which would mean verifying the ticket to say that the
            // service is off.
            return Response::error(STATUS_SERVER_BAD, "kx509 is not enabled in this realm")
                .encode();
        };

        // From here on every answer is authenticated: a client that gets a MAC-less response to an
        // authenticated request cannot tell the KDC from a relay.
        let (session_key, client) = match self.kx509_authenticate(&parsed.authenticator, now) {
            Ok(pair) => pair,
            Err((code, text)) => {
                return Response::error(KRB_ERROR_BASE + code, text).encode();
            }
        };

        // The payload's own MAC, over the version and the key material — the whole reason the
        // request carries an AP-REQ at all: the ticket says who, the MAC says that whoever built
        // this payload holds the session key.
        if !parsed.verify_mac(session_key.bytes()) {
            return Response::error(
                KRB_ERROR_BASE + codes::KDC_ERR_PREAUTH_FAILED,
                "the kx509 request MAC does not verify",
            )
            .encode();
        }

        // Only the CSR form is accepted. A bare `SubjectPublicKeyInfo` would be a certificate for a
        // key nobody proved they hold — which is exactly what a CSR's signature rules out — and a
        // realm that issued one would be issuing certificates anybody could claim.
        let csr_der = match csr_from_plus(&parsed.pk_key) {
            Ok(der) => der,
            Err(e) => {
                return Response::error(STATUS_CLIENT_BAD, format!("{e}")).encode();
            }
        };
        let csr = match Csr::parse(&csr_der) {
            Ok(csr) => csr,
            Err(e) => return Response::error(STATUS_CLIENT_BAD, format!("{e}")).encode(),
        };

        let lifetime = (now, now.saturating_add(self.config().kx509_max_life()));
        let issued = ca::issue(
            &csr,
            &client,
            &client,
            lifetime,
            self.csr_authorizer(),
            ca.as_ref(),
        );
        let issued = match issued {
            Ok(issued) => issued,
            Err(e) => {
                let code = match e {
                    ca::CaError::Refused(_) => KRB_ERROR_BASE + codes::KDC_ERR_POLICY,
                    ca::CaError::Authority(_) => STATUS_SERVER_BAD,
                    _ => STATUS_CLIENT_BAD,
                };
                return Response::error(code, format!("{e}")).encode();
            }
        };

        // RFC 6717 §3: the MAC covers the certificate's DER, not the encoding of the field that
        // carries it. Feeding the OCTET STRING's own tag and length here would produce a MAC no
        // client computes — Heimdal feeds `rep->certificate->data` for the same reason.
        let mut response = Response {
            error_code: 0,
            hash: None,
            // The certificate's own DER: `encode` puts it in the field's OCTET STRING, and wrapping
            // it here would make the field carry an OCTET STRING inside an OCTET STRING.
            certificate: Some(issued.certificate),
            text: None,
        };
        // Computed from the finished response, so that the MAC covers exactly what the encoding
        // will carry: a second place that assembled the same fields could disagree with it.
        response.hash = Some(response.mac(session_key.bytes()));
        response.encode()
    }

    /// Verifies the AP-REQ and returns the ticket's session key and client.
    ///
    /// The ticket must be for this realm's kx509 service — the one principal a client is told to ask
    /// for (`kx509/host@REALM`), and asking for anything else would let a ticket for any service be
    /// traded for a certificate.
    fn kx509_authenticate(
        &self,
        ap_req_bytes: &[u8],
        now: i64,
    ) -> std::result::Result<(crate::crypto::Key, Principal), (i32, String)> {
        let ap_req = ApReq::decode(ap_req_bytes)
            .map_err(|e| (codes::KRB_AP_ERR_MODIFIED, format!("the AP-REQ: {e}")))?;
        let ticket = ap_req
            .ticket()
            .map_err(|e| (codes::KRB_AP_ERR_MODIFIED, format!("the ticket: {e}")))?;

        let service = self.config().kx509_service();
        if ticket.sname.components.first().map(|c| c.as_str()) != Some(service) {
            return Err((
                codes::KRB_AP_ERR_MODIFIED,
                format!(
                    "the ticket is for {}, and a kx509 ticket must be for {service}/…",
                    ticket.sname
                ),
            ));
        }
        if ticket.sname.realm != self.config().realm() {
            return Err((
                codes::KRB_AP_ERR_MODIFIED,
                "the kx509 ticket is for another realm".into(),
            ));
        }

        let entry = self
            .hdb()
            .fetch_for_service(&ticket.sname)
            .map_err(|e| (codes::KRB_AP_ERR_MODIFIED, format!("{e}")))?
            .ok_or_else(|| {
                (
                    codes::KDC_ERR_S_PRINCIPAL_UNKNOWN,
                    format!("{} is not in the database", ticket.sname),
                )
            })?;
        let key = entry
            .key_for(ticket.enc.etype)
            .ok_or_else(|| {
                (
                    codes::KRB_AP_ERR_BAD_INTEGRITY,
                    format!("{} has no key of the ticket's enctype", entry.principal),
                )
            })?
            .key
            .clone();

        let part = open_ticket(self.cipher(), &key, &ticket.enc)
            .map_err(|e| (codes::KRB_AP_ERR_BAD_INTEGRITY, format!("{e}")))?;
        if now > part.endtime {
            return Err((
                codes::KRB_AP_ERR_TKT_EXPIRED,
                "the kx509 ticket has expired".into(),
            ));
        }

        let plain = self
            .cipher()
            .decrypt(
                &part.session_key,
                usage::AP_REQ_AUTH,
                &ap_req.authenticator.cipher,
            )
            .map_err(|_| {
                (
                    codes::KRB_AP_ERR_BAD_INTEGRITY,
                    "the authenticator does not decrypt in the ticket's session key".into(),
                )
            })?;
        let authenticator = crate::msg::Authenticator::decode(&plain).map_err(|e| {
            (
                codes::KRB_AP_ERR_MODIFIED,
                format!("the authenticator: {e}"),
            )
        })?;

        if authenticator.cname != part.cname {
            return Err((
                codes::KRB_AP_ERR_MODIFIED,
                "the authenticator names a different client than the ticket".into(),
            ));
        }
        let skew = now.saturating_sub(authenticator.ctime);
        if skew.abs() > self.config().clockskew() {
            return Err((
                codes::KRB_AP_ERR_SKEW,
                format!("the authenticator is {skew}s from this KDC's clock"),
            ));
        }
        Ok((part.session_key, part.cname))
    }
}

/// Decrypts a service ticket.
fn open_ticket(
    cipher: &dyn Cipher,
    key: &crate::crypto::Key,
    enc: &crate::msg::EncryptedData,
) -> crate::Result<EncTicketPart> {
    let plain = cipher
        .decrypt(key, usage::KDC_REP_TICKET, &enc.cipher)
        .map_err(|_| Error::Krb(rrl_krb_common::Error::Crypto("the ticket".into())))?;
    EncTicketPart::decode(&plain).map_err(Error::from)
}

/// The CSR out of a `Kx509CSRPlus` (`[APPLICATION 35] SEQUENCE { csr OCTET STRING, ... }`).
///
/// A bare `SubjectPublicKeyInfo` is refused by name: it carries no proof of possession, and
/// [`super::ca::Csr`] exists precisely so that a certificate is never issued for a key its holder
/// has not demonstrated.
/// The service principal a realm's kx509 clients are told to ask for.
pub fn service_principal(realm: &str, host: &str) -> crate::Result<Principal> {
    Principal::parse(&format!("kx509/{host}@{realm}")).map_err(Error::from)
}

/// An HDB entry for the kx509 service, so that a test or a stand can provision one.
pub fn service_entry(
    realm: &str,
    host: &str,
    cipher: &dyn Cipher,
    password: &[u8],
) -> crate::Result<HdbEntry> {
    let principal = service_principal(realm, host)?;
    let mut entry = HdbEntry::service(principal);
    // No `INITIAL`: unlike `kadmin/changepw`, a kx509 ticket may be derived from a TGT like any
    // other service ticket, which is how a client that already has credentials gets one.
    for enctype in crate::crypto::Enctype::ALL {
        entry.add_password_key(cipher, enctype, password, 1)?;
    }
    Ok(entry)
}
