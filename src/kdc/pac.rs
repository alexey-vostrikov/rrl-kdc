//! MS-PAC, in the `rrl-krb-common` crate.
//!
//! Shared with the acceptor: the envelope, the two signatures and `PAC_CLIENT_INFO` are built here
//! and parsed there, and a PAC is only useful if the verifier reads the octets the signer wrote.
//! Two implementations of the signature are two ways to produce a PAC Windows refuses, and that
//! shows up on a domain rather than in a test.
//!
//! Re-exported rather than wrapped so that `pac::Buffer`, `pac::SignatureType` and the type codes
//! keep resolving here and are the same items on both sides.

pub use rrl_krb_common::pac::*;

/// `KRB5_PAC_WAS_REQUESTED` and `KRB5_PAC_WAS_GIVEN_IMPLICITLY` (Heimdal `krb5.h`): where the
/// claim on a PAC came from.
///
/// The two values answer different questions and are not complements. `WAS_REQUESTED`: the client
/// sent `PA-PAC-REQUEST` asking for one. `WAS_GIVEN_IMPLICITLY`: the client said nothing, so it
/// gets what every client got before the extension existed. A client that sent the extension and
/// asked for the PAC to be left out is neither, and its ticket has none.
///
/// They belong in `rrl-krb-common` beside the PAC itself; they are here for now, with the numbers
/// written out, because that repository was not named for this change.
pub(crate) const WAS_REQUESTED: u64 = 0x1;
pub(crate) const WAS_GIVEN_IMPLICITLY: u64 = 0x2;

/// Everything a PAC's issuer is given, and nothing the issuer could invent.
///
/// The shape follows MIT's `krb5_db_issue_pac` (`src/include/kdb.h`): the client, the server, the
/// time, and the keys the two checksums are made with. MIT passes them because its kdb module —
/// Samba's `samba_kdc_issue_pac` — builds and signs the PAC itself, and this trait exists so that a
/// directory can do the same here without the KDC holding any of the facts behind it.
///
/// **Both keys, not one.** The server checksum is keyed by the ticket's service key, the
/// privsvr checksum by the realm's `krbtgt` key; a PAC signed with one key twice verifies at the KDC
/// and fails at every service, which surfaces as a rejected ticket on a domain rather than as a
/// defect here.
#[derive(Debug)]
pub struct PacRequest<'a> {
    /// Whose privileges the PAC states.
    pub client: &'a crate::name::Principal,
    /// The service the ticket is for — the account whose key signs the server checksum.
    pub server: &'a crate::name::Principal,
    /// `authtime`: a logon's expiry is stated relative to it, and it is what a service compares its
    /// own clock with.
    pub authtime: i64,
    /// The signature type both checksums use, chosen by the KDC from the service key's enctype so
    /// that one type describes both.
    pub signature: SignatureType,
    /// The ticket's service key.
    pub server_key: &'a crate::crypto::Key,
    /// The realm's `krbtgt` key, for the privsvr checksum.
    pub kdc_key: &'a crate::crypto::Key,
    /// The PAC a `TGS-REQ` carried, when the incoming ticket had one.
    ///
    /// A service that receives an old PAC decides whether to keep it, replace it, or merge the two;
    /// that decision is the directory's, and passing the octets is what makes it possible at all.
    pub old_pac: Option<&'a [u8]>,
}

/// Who builds a PAC.
///
/// The seam MIT calls `issue_pac`, and the same rule applies to it: **a KDC with no issuer issues no
/// PAC**. A PAC states SIDs, RIDs and group membership, and none of those is a fact a KDC may
/// invent — a PAC with a made-up identity is worse than a ticket without one, because a service
/// trusts it.
///
/// Format and signing are not the issuer's invention either: `rrl-krb-common` holds
/// `KERB_VALIDATION_INFO`, the envelope and the two signatures, shared with the acceptor, so an
/// issuer left to write its own NDR would be a second way to produce a PAC Windows refuses.
pub trait PacIssuer: Send + Sync + std::fmt::Debug {
    /// The `AuthorizationData` this ticket should carry, or `None` for a ticket without a PAC.
    ///
    /// An `Err` is not a refusal of the login: the KDC reports it as a realm fault, because a
    /// directory that cannot state an identity is broken rather than the client being wrong. The
    /// caller converts, and the conversion is in one place.
    fn issue(&self, request: &PacRequest<'_>) -> crate::Result<Option<Vec<u8>>>;
}

/// The issuing this crate shipped before the trait existed: `PacIdentities` plus the buffer layout
/// in [`crate::kdc::pac::pac`].
///
/// Kept because it is a complete implementation for a realm whose directory is already reachable
/// through [`PacIdentities`], and because removing it would have made the seam a breaking change
/// for every embedder that had one. A deployment that keeps its identities somewhere a trait cannot
/// reach — or that needs to merge an incoming PAC the way Samba does — installs its own
/// [`PacIssuer`] instead.
pub struct IdentityIssuer {
    identities: std::sync::Arc<dyn super::logon_info::PacIdentities>,
}

// `PacIdentities` has no `Debug` bound — it is the embedder's type, and asking it to derive one for
// this crate's log line would be a requirement invented here. The trait `PacIssuer` does require
// `Debug`, because `Kdc`'s own `Debug` prints whether a PAC is issued, so the type is named without
// its contents.
impl std::fmt::Debug for IdentityIssuer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IdentityIssuer").finish_non_exhaustive()
    }
}

impl IdentityIssuer {
    /// An issuer over `identities`.
    pub fn new(identities: std::sync::Arc<dyn super::logon_info::PacIdentities>) -> IdentityIssuer {
        IdentityIssuer { identities }
    }
}

impl PacIssuer for IdentityIssuer {
    fn issue(&self, request: &PacRequest<'_>) -> crate::Result<Option<Vec<u8>>> {
        let Some(identity) = self.identities.identity(request.client)? else {
            // The directory does not know the account: a ticket without a PAC, not an empty one.
            return Ok(None);
        };
        let logon = identity.logon_info(request.client.to_string(), request.authtime);
        let mut blob = pac(&[
            Buffer::new(PAC_LOGON_INFO, super::logon_info::encode(&logon)?),
            client_info(&logon.effective_name, request.authtime)?,
            Buffer::new(
                PAC_SERVER_CHECKSUM,
                vec![0u8; request.signature.signature_len() + 4],
            ),
            Buffer::new(
                PAC_PRIVSVR_CHECKSUM,
                vec![0u8; request.signature.signature_len() + 4],
            ),
        ]);
        seal(
            &mut blob,
            request.server_key,
            request.kdc_key,
            request.signature,
        )?;
        Ok(Some(authorization_data(&blob)))
    }
}

/// Whether an `AuthorizationData` carries a PAC.
///
/// The envelope is `AD-IF-RELEVANT` (1) whose payload is another `AuthorizationData` holding
/// `AD-WIN2K-PAC` (128) — the shape [`authorization_data`] writes, and the shape Windows and MIT
/// read. Both nestings are accepted, because a ticket from another implementation may hold the PAC
/// directly in the outer sequence: `require-pac` turns the answer into a refusal, and "no PAC" has
/// to mean no PAC rather than "not the nesting this crate happens to write".
pub(crate) fn carries_pac(authorization_data: &[u8]) -> bool {
    let mut outer = crate::der::Reader::new(authorization_data);
    let Ok(content) = outer.expect_in("AuthorizationData", crate::der::SEQUENCE) else {
        return false;
    };
    scan_ad_entries(content)
}

/// One level of `AuthorizationData ::= SEQUENCE OF SEQUENCE { [0] ad-type, [1] ad-data }`.
fn scan_ad_entries(content: &[u8]) -> bool {
    let mut entries = crate::der::Reader::new(content);
    while !entries.is_empty() {
        // `next()` yields the TLV's *content*, not the TLV: asking for a `SEQUENCE` around it
        // again would consume one level that is not there and answer "no PAC" for every PAC this
        // crate writes — which is exactly what the first version of this did.
        let Ok((tag, entry)) = entries.next() else {
            return false;
        };
        if tag != crate::der::SEQUENCE {
            return false;
        }
        let Ok(fields) = crate::der::Fields::parse("AuthorizationData", entry) else {
            return false;
        };
        let (Ok(ad_type), Ok(data)) = (fields.int(0, "ad-type"), fields.octets(1, "ad-data"))
        else {
            // An entry this crate cannot read is not a PAC; the next one may be.
            continue;
        };
        if ad_type == AD_WIN2K_PAC {
            return true;
        }
        if ad_type == AD_IF_RELEVANT && carries_pac(data) {
            return true;
        }
    }
    false
}

/// The PAC inside an `AuthorizationData`, when it carries one.
///
/// The same walk as [`carries_pac`], returning the octets instead of a yes. It exists because a
/// PAC's issuer may need the one an incoming ticket carried — keeping it, merging it, or deciding
/// from it — and handing that decision an `Option<&[u8]>` is the only way it can be made. Splitting
/// the walk from the question keeps one traversal rule: two would be two ways to disagree about
/// nesting, and the disagreement would show up as "the realm dropped every PAC" rather than as a
/// parser defect.
pub fn extract_pac(authorization_data: &[u8]) -> Option<Vec<u8>> {
    let mut outer = crate::der::Reader::new(authorization_data);
    let content = outer
        .expect_in("AuthorizationData", crate::der::SEQUENCE)
        .ok()?;
    find_ad_entry(content, AD_WIN2K_PAC)
}

/// Walks one `AuthorizationData` level looking for `wanted`, descending through `AD-IF-RELEVANT`.
fn find_ad_entry(content: &[u8], wanted: i64) -> Option<Vec<u8>> {
    let mut entries = crate::der::Reader::new(content);
    while !entries.is_empty() {
        let (tag, entry) = entries.next().ok()?;
        if tag != crate::der::SEQUENCE {
            return None;
        }
        let fields = crate::der::Fields::parse("AuthorizationData", entry).ok()?;
        let (Ok(ad_type), Ok(data)) = (fields.int(0, "ad-type"), fields.octets(1, "ad-data"))
        else {
            continue;
        };
        if ad_type == wanted {
            return Some(data.to_vec());
        }
        if ad_type == AD_IF_RELEVANT {
            // `ad-data` holds the inner `AuthorizationData` **with its `SEQUENCE` tag**: the
            // envelope is written whole, so the tag has to come off before the entries can be read.
            // Recurring on the octets as they are would parse the tag as an entry and answer "no
            // PAC" for every PAC this crate writes.
            let mut inner = crate::der::Reader::new(data);
            if let Ok(content) = inner.expect_in("AuthorizationData", crate::der::SEQUENCE)
                && let Some(found) = find_ad_entry(content, wanted)
            {
                return Some(found);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The envelope this crate writes is the envelope it reads: a writer and a reader that disagree
    /// here would make `require-pac` refuse every ticket, which reads as a broken realm rather than
    /// a broken parser.
    #[test]
    fn the_pac_this_crate_writes_is_one_it_finds() {
        assert!(carries_pac(&authorization_data(b"a pac")));
    }

    /// The PAC straight in the outer sequence, which is the other nesting in the wild.
    #[test]
    fn a_pac_directly_in_the_outer_sequence_is_found_too() {
        let direct = crate::der::seq(&[crate::der::seq(&[
            crate::der::field(0, crate::der::int(AD_WIN2K_PAC)),
            crate::der::field(1, crate::der::octets(b"a pac")),
        ])]);
        assert!(carries_pac(&direct));
    }

    /// The extractor finds the same PAC the question does, and hands back its octets.
    #[test]
    fn the_pac_can_be_read_back_out() {
        assert_eq!(
            extract_pac(&authorization_data(b"a pac")).as_deref(),
            Some(&b"a pac"[..])
        );
        let direct = crate::der::seq(&[crate::der::seq(&[
            crate::der::field(0, crate::der::int(AD_WIN2K_PAC)),
            crate::der::field(1, crate::der::octets(b"another")),
        ])]);
        assert_eq!(extract_pac(&direct).as_deref(), Some(&b"another"[..]));
        assert_eq!(extract_pac(b"not DER"), None);
    }

    /// Everything else is not a PAC — including authorization data this crate cannot read, which
    /// has to answer "no" rather than refuse the request over a field it does not use.
    #[test]
    fn other_authorization_data_is_not_a_pac() {
        let md5 = crate::der::seq(&[crate::der::seq(&[
            crate::der::field(0, crate::der::int(7)),
            crate::der::field(1, crate::der::octets(b"not a pac")),
        ])]);
        assert!(!carries_pac(&md5));
        assert!(!carries_pac(b""));
        assert!(!carries_pac(&[0x30, 0x03, 0x02, 0x01, 0x01]));
    }
}
