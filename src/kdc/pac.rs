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
