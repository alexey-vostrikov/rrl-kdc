//! `TransitedEncoding`: the realms a cross-realm ticket has passed through.
//!
//! RFC 4120 §5.2.2 says a ticket carries a list of the realms traversed between the client's and
//! the server's, and that the only type defined is `DOMAIN-X500-COMPRESS` (1). RFC 4120 §3.3.3.2
//! then admits that the compression is "not fully specified", so what is implemented here is what
//! Heimdal implements (`lib/krb5/transited.c`), because a path this KDC writes has to be readable by
//! MIT and Heimdal and vice versa.
//!
//! # The format
//!
//! The contents are the realms joined by commas, with one wrinkle: a realm whose first octet is
//! `/` — an X.500-form name — is preceded by a space, so that the slash is not read as the start of
//! an abbreviation.
//!
//! Reading has to undo three abbreviations, each meaning "finish this name from the previous one":
//!
//! * a trailing `.` appends the preceding realm (`"EDU."` after `"MIT.EDU"` is `"EDU.MIT.EDU"`);
//! * a leading `/` with no space *prepends* the preceding realm (X.500 form);
//! * an empty component stands for the whole DNS hierarchy between its neighbours, which is the
//!   part that makes this scheme worth a comment calling it horrible (`"A.B.C,,C"` means
//!   `"A.B.C"`, `"B.C"`, `"C"`).
//!
//! # What this module refuses
//!
//! A path it cannot expand is an error, not a best guess: a `transited` field a verifier reads
//! differently from the way the issuer wrote it is a ticket accepted on a path it never took.
//! X.500-form hierarchies — the branch where the *next* realm starts with `/` — are refused by
//! name rather than mis-parsed; no realm this project serves uses them, and guessing would be
//! worse than a message naming what is unsupported.

use crate::error::{Error, Result};

/// `DOMAIN-X500-COMPRESS`, the only `TransitedEncoding.tr-type` RFC 4120 defines.
pub const DOMAIN_X500_COMPRESS: i32 = 1;

/// The path encoded for `TransitedEncoding.contents`.
///
/// Joins with commas and puts a space before a component that starts with `/`, which is the whole
/// of the compression on the writing side: Heimdal's `krb5_domain_x500_encode` does exactly this
/// and nothing more, because the abbreviations are a reading convenience.
pub fn encode<I, S>(realms: I) -> Vec<u8>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut out = String::new();
    for (i, realm) in realms.into_iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        if realm.as_ref().starts_with('/') {
            out.push(' ');
        }
        out.push_str(realm.as_ref());
    }
    out.into_bytes()
}

/// One component as it was written, before the abbreviations are undone.
struct Component {
    text: String,
    leading_space: bool,
    leading_slash: bool,
    trailing_dot: bool,
    empty: bool,
}

/// Splits on unescaped commas and records what each component abbreviates.
///
/// `\` escapes the next octet, which is how a realm whose name contains a comma or a backslash is
/// written. Heimdal unescapes in `make_realm`; the flags it records there are the ones expanded in
/// [`decode`].
fn split(content: &[u8]) -> Result<Vec<Component>> {
    let text =
        std::str::from_utf8(content).map_err(|_| Error::Protocol("transited: not UTF-8".into()))?;

    let mut raw = Vec::new();
    let mut current = String::new();
    let mut quoted = false;
    for ch in text.chars() {
        if quoted {
            current.push(ch);
            quoted = false;
            continue;
        }
        match ch {
            '\\' => quoted = true,
            ',' => {
                raw.push(std::mem::take(&mut current));
            }
            _ => current.push(ch),
        }
    }
    if quoted {
        return Err(Error::Protocol(
            "transited: trailing backslash escapes nothing".into(),
        ));
    }
    raw.push(current);

    Ok(raw
        .into_iter()
        .map(|mut c| {
            let leading_space = c.starts_with(' ');
            if leading_space {
                c.remove(0);
            }
            let leading_slash = c.starts_with('/');
            let trailing_dot = c.ends_with('.');
            Component {
                empty: c.is_empty(),
                text: c,
                leading_space,
                leading_slash,
                trailing_dot,
            }
        })
        .collect())
}

/// The realms `content` names, expanded, for a path from `client_realm` to `server_realm`.
///
/// The two realm arguments are needed because the first component's abbreviation refers to the
/// client's realm, and an empty component's hierarchy ends at the server's.
pub fn decode(content: &[u8], client_realm: &str, server_realm: &str) -> Result<Vec<String>> {
    if content.is_empty() {
        return Ok(Vec::new());
    }
    let components = split(content)?;
    let mut out: Vec<String> = Vec::with_capacity(components.len());

    for (i, c) in components.iter().enumerate() {
        if c.empty {
            // An empty component stands for the hierarchy between the realm before it and the one
            // after it. Walk the DNS tree and emit each level: `A.B.C` down to `C` gives `B.C`.
            let previous = out.last().map(String::as_str).unwrap_or(client_realm);
            let next = components[i + 1..]
                .iter()
                .find(|c| !c.empty)
                .map(|c| c.text.as_str())
                .unwrap_or(server_realm);
            out.extend(hierarchy(previous, next)?);
            continue;
        }

        let expanded = if c.trailing_dot {
            // `EDU.` after `MIT.EDU` is `EDU.MIT.EDU`: the name stops short, the previous realm
            // supplies the rest.
            let previous = out.last().map(String::as_str).unwrap_or(client_realm);
            let stem = c.text.trim_end_matches('.');
            let mut s = String::with_capacity(stem.len() + 1 + previous.len());
            s.push_str(stem);
            s.push('.');
            s.push_str(previous);
            s
        } else if c.leading_slash && !c.leading_space {
            // X.500 form: the previous realm is the parent.
            let previous = out.last().map(String::as_str).unwrap_or(client_realm);
            format!("{previous}{}", c.text)
        } else {
            c.text.clone()
        };

        if expanded.is_empty() {
            return Err(Error::Protocol(
                "transited: a component expanded to nothing".into(),
            ));
        }
        out.push(expanded);
    }

    Ok(out)
}

/// The realms strictly between `from` and `to` in the DNS tree, `from` excluded.
///
/// `KTH4.SE` to `SE` gives `SE`; `KTH4.SE` to `KTH4.SE` gives nothing. Heimdal's `make_path`
/// requires one name to be a suffix of the other, and answers `POLICY` when it is not — a path
/// through two unrelated realms has no spelling in this format.
fn hierarchy(from: &str, to: &str) -> Result<Vec<String>> {
    // Heimdal swaps so that `from` is the longer name.
    let (long, short) = if from.len() >= to.len() {
        (from, to)
    } else {
        (to, from)
    };

    if long == short {
        return Ok(Vec::new());
    }

    if long.ends_with(short) && short.starts_with(|c: char| c.is_ascii_alphanumeric()) {
        // DNS form: strip one label at a time until the short name is reached.
        let mut out = Vec::new();
        let mut rest = long;
        while let Some((_, tail)) = rest.split_once('.') {
            rest = tail;
            if rest == short {
                break;
            }
            out.push(rest.to_owned());
        }
        if rest != short {
            return Err(Error::Protocol(format!(
                "transited: {long} is not a parent of {short}"
            )));
        }
        return Ok(out);
    }

    Err(Error::Protocol(format!(
        "transited: no DNS hierarchy from {from} to {to}; X.500-form paths are not supported"
    )))
}

/// The path a ticket carries, given the one it was presented with.
///
/// This is Heimdal's `fix_transited_encoding` rule, and it is subtler than "append the realm":
/// the realm of the presented TGT becomes a transit realm only when it is neither the client's nor
/// the server's. A ticket a realm issues for its own service has that realm in neither list, and
/// adding it would make every ordinary ticket look like it had travelled.
pub fn with_transit(
    existing: &[u8],
    client_realm: &str,
    server_realm: &str,
    tgt_issuer: &str,
) -> Result<Vec<u8>> {
    Ok(encode(path_with_transit(
        existing,
        client_realm,
        server_realm,
        tgt_issuer,
    )?))
}

/// The same rule as [`with_transit`], but as the expanded list of realms.
///
/// Split out because the check in [`accept`] needs the realms, not their encoding: a policy that
/// compares realms has to see `EDU.MIT.EDU`, not `EDU.`.
pub fn path_with_transit(
    existing: &[u8],
    client_realm: &str,
    server_realm: &str,
    tgt_issuer: &str,
) -> Result<Vec<String>> {
    if tgt_issuer == client_realm || tgt_issuer == server_realm {
        return decode(existing, client_realm, server_realm);
    }
    let mut realms = decode(existing, client_realm, server_realm)?;
    if !realms.iter().any(|r| r == tgt_issuer) {
        realms.push(tgt_issuer.to_owned());
    }
    Ok(realms)
}

/// The realms on the DNS hierarchy between `from` and `to`, endpoints excluded.
///
/// Walks up from the client to the common suffix and then down to the server, which is the path
/// Heimdal's `hier_init`/`hier_next` walk (`lib/krb5/transited.c`): `B.EXAMPLE.COM` to
/// `OTHER.EXAMPLE.COM` gives `EXAMPLE.COM`, and `A.EXAMPLE.COM` to `B.EXAMPLE.COM` gives
/// `EXAMPLE.COM` too. A pair with no common suffix (`B.REALM.A` to `REALM.C`) has no hierarchy
/// here, and saying so is better than inventing one — an operator who has such a trust lists the
/// transit realms by hand.
pub fn hierarchical_path(from: &str, to: &str) -> Result<Vec<String>> {
    if from == to {
        return Ok(Vec::new());
    }
    let a: Vec<&str> = from.split('.').collect();
    let b: Vec<&str> = to.split('.').collect();

    // The common suffix, comparing labels from the right.
    let mut common = 0;
    while common < a.len() && common < b.len() && a[a.len() - 1 - common] == b[b.len() - 1 - common]
    {
        common += 1;
    }
    if common == 0 {
        return Err(Error::Protocol(format!(
            "transited: {from} and {to} share no realm hierarchy; list the transit realms \
             explicitly if the path is real"
        )));
    }

    let mut out = Vec::new();
    // Up from the client: `B.EXAMPLE.COM` -> `EXAMPLE.COM`.
    for take in (common..a.len()).rev() {
        let realm = a[a.len() - take..].join(".");
        if realm != from {
            out.push(realm);
        }
    }
    // Down to the server: `EXAMPLE.COM` -> `C.EXAMPLE.COM`.
    for take in (common + 1..=b.len()).rev() {
        let realm = b[b.len() - take..].join(".");
        if realm != to {
            out.push(realm);
        }
    }
    Ok(out)
}

/// Whether a cross-realm path may be accepted, given the realms an operator listed.
///
/// RFC 4120 §3.3.3: "an untrusted KDC may have fabricated the list", so each realm on the path
/// is a claim to check rather than a fact. Two sources are admissible, and the second is what
/// Heimdal falls back to when `[capaths]` has no entry for the pair:
///
/// * the realms named in the configuration, and
/// * the realms on the DNS hierarchy between the client's and the server's.
///
/// `KDC_ERR_PATH_NOT_ACCEPTED` names the realm that failed and the whole path, because an operator
/// reading only "policy rejects the path" has to guess which realm to add.
pub fn accept(
    path: &[String],
    client_realm: &str,
    server_realm: &str,
    allowed: Option<&[String]>,
) -> Result<()> {
    if path.is_empty() {
        return Ok(());
    }
    // `Err` means the two realms share no hierarchy, so nothing beyond an explicit list can be
    // admitted — the same conclusion an empty vector states, which is why this is not a `match`
    // that names the error and then discards it.
    let on_path = hierarchical_path(client_realm, server_realm).unwrap_or_default();
    for realm in path {
        let listed = allowed.is_some_and(|list| list.iter().any(|r| r == realm));
        if listed || on_path.iter().any(|r| r == realm) {
            continue;
        }
        return Err(Error::Kdc {
            code: crate::error::codes::KDC_ERR_PATH_NOT_ACCEPTED,
            text: format!(
                "the transited path from {client_realm} to {server_realm} passes through {realm}, \
                 which this realm does not accept; the path the ticket claims is [{}]",
                path.join(", ")
            ),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The writing side is the wire format, so the octets are pinned literally: a comma between
    /// realms, and a space before a component that begins with `/` (Heimdal's
    /// `krb5_domain_x500_encode`, which adds `" "` exactly for that case).
    #[test]
    fn the_encoding_is_comma_separated_with_a_space_before_a_slash() {
        assert_eq!(encode(["KTH2.SE"]), b"KTH2.SE");
        assert_eq!(encode(["KTH3.SE", "KTH2.SE"]), b"KTH3.SE,KTH2.SE");
        assert_eq!(
            encode(["KTH5.SE", "KTH4.SE", "KTH3.SE", "KTH2.SE"]),
            b"KTH5.SE,KTH4.SE,KTH3.SE,KTH2.SE"
        );
        assert_eq!(encode(["/C=SE/O=KTH"]), b" /C=SE/O=KTH");
        assert_eq!(encode(Vec::<String>::new()), b"");
    }

    /// The exact paths Heimdal's `test_x500.c` round-trips, which is the one external statement
    /// about this format that exists.
    #[test]
    fn the_paths_heimdals_test_carries_round_trip() {
        for (client, server, path) in [
            ("KTH1.SE", "KTH1.SE", vec![]),
            ("KTH1.SE", "KTH2.SE", vec![]),
            ("KTH1.SE", "KTH3.SE", vec!["KTH2.SE"]),
            ("KTH1.SE", "KTH4.SE", vec!["KTH3.SE", "KTH2.SE"]),
            ("KTH1.SE", "KTH5.SE", vec!["KTH4.SE", "KTH3.SE", "KTH2.SE"]),
        ] {
            let encoded = encode(&path);
            let decoded = decode(&encoded, client, server).expect("the path decodes");
            assert_eq!(decoded, path, "from {client} to {server}");
        }
    }

    /// A trailing dot means "the rest comes from the previous realm". Getting this backwards
    /// produces a realm name of the right shape that no KDC has ever issued.
    #[test]
    fn a_trailing_dot_completes_the_name_from_the_previous_realm() {
        assert_eq!(
            decode(b"EDU.,MIT.EDU", "MIT.EDU", "SVC.EDU").unwrap(),
            vec!["EDU.MIT.EDU", "MIT.EDU"]
        );
        // With no previous realm the client's realm supplies the rest.
        assert_eq!(
            decode(b"SUB.", "EXAMPLE.COM", "OTHER").unwrap(),
            vec!["SUB.EXAMPLE.COM"]
        );
    }

    /// A component that starts with `/` and **no space** prepends the previous realm. The space is
    /// what distinguishes the abbreviation from a literal X.500 name, and both spellings appear in
    /// the same field — so this pins them apart.
    #[test]
    fn a_leading_slash_prepends_the_previous_realm_unless_a_space_quotes_it() {
        // No space: the abbreviation, so the previous realm is prepended.
        assert_eq!(
            decode(b"C=SE,/O=KTH", "C=SE", "X").unwrap(),
            vec!["C=SE".to_owned(), "C=SE/O=KTH".to_owned()]
        );
        // With the space: a literal name, exactly as `encode` writes one.
        assert_eq!(
            decode(b"C=SE, /O=KTH", "C=SE", "X").unwrap(),
            vec!["C=SE".to_owned(), "/O=KTH".to_owned()]
        );
    }

    /// An empty component is the hierarchy between its neighbours, which is the part of the
    /// scheme that no other encoding needs.
    #[test]
    fn an_empty_component_walks_the_hierarchy() {
        assert_eq!(
            decode(b"A.B.C,,C", "CLIENT", "A.B.C").unwrap(),
            vec!["A.B.C", "B.C", "C"]
        );
        // Two empties in a row are one, per Heimdal's `make_paths`.
        assert_eq!(
            decode(b"A.B.C,,,C", "CLIENT", "A.B.C").unwrap(),
            vec!["A.B.C", "B.C", "C"]
        );
    }

    /// A path between realms that are not in one DNS hierarchy has no spelling here, and saying
    /// so is better than inventing one.
    #[test]
    fn an_impossible_hierarchy_is_refused_by_name() {
        let err = decode(b"A.X,,B.Y", "C", "C").unwrap_err().to_string();
        assert!(err.contains("no DNS hierarchy"), "{err}");
        let err = decode(b"/C=SE,,O=KTH", "C", "C").unwrap_err().to_string();
        assert!(
            !err.is_empty(),
            "an X.500 hierarchy is refused, not guessed"
        );
    }

    /// A backslash escapes the next octet, so a realm containing a comma survives the round trip.
    #[test]
    fn a_backslash_escapes_a_comma() {
        let encoded = encode(["A,B", "C"]);
        assert_eq!(
            encoded, b"A,B,C",
            "encode does not escape: the caller's job"
        );
        // Reading splits on the comma, so the escaped form is what a writer that needs a comma
        // must produce; this pins that the reader undoes it.
        assert_eq!(decode(b"A\\,B,C", "x", "y").unwrap(), vec!["A,B", "C"]);
        assert!(decode(b"A\\", "x", "y").is_err(), "a trailing escape");
    }

    /// The transit rule: only a realm that is neither the client's nor the server's is added.
    /// Heimdal's `fix_transited_encoding` compares exactly these three strings.
    #[test]
    fn only_a_third_realm_is_a_transit_realm() {
        // The TGT came from the client's realm: no transit.
        assert_eq!(
            with_transit(b"", "A", "B", "A").unwrap(),
            b"".to_vec(),
            "the client's own realm is not a transit"
        );
        // Nor is the server's.
        assert_eq!(with_transit(b"", "A", "B", "B").unwrap(), b"".to_vec());
        // A third realm is.
        assert_eq!(with_transit(b"", "A", "C", "B").unwrap(), b"B".to_vec());
        // And an existing path keeps what it had, in order.
        assert_eq!(with_transit(b"B", "A", "D", "C").unwrap(), b"B,C".to_vec());
        // A realm already on the path is not repeated.
        assert_eq!(with_transit(b"B", "A", "D", "B").unwrap(), b"B".to_vec());
    }

    /// The hierarchy walk: up from the client to the common suffix, then down to the server. Both
    /// halves matter — a path admitted by looking only upwards would accept a realm below the
    /// server's own parent.
    #[test]
    fn the_hierarchy_walks_up_and_then_down() {
        assert_eq!(
            hierarchical_path("B.EXAMPLE.COM", "OTHER.EXAMPLE.COM").unwrap(),
            vec!["EXAMPLE.COM"]
        );
        assert_eq!(
            hierarchical_path("A.B.EXAMPLE.COM", "OTHER.EXAMPLE.COM").unwrap(),
            vec!["B.EXAMPLE.COM", "EXAMPLE.COM"]
        );
        // A parent and a child are adjacent: nothing between them.
        assert_eq!(
            hierarchical_path("EXAMPLE.COM", "A.EXAMPLE.COM").unwrap(),
            Vec::<String>::new()
        );
        // The same realm has no path.
        assert_eq!(
            hierarchical_path("EXAMPLE.COM", "EXAMPLE.COM").unwrap(),
            Vec::<String>::new()
        );
        // Unrelated names have no hierarchy, and that is an error rather than an empty path: an
        // empty path would read as "acceptable".
        assert!(hierarchical_path("B.REALM.A", "REALM.C").is_err());
    }

    /// What the policy admits: realms on the hierarchy, plus the realms an operator listed. A realm
    /// that is neither is refused, and the refusal names it.
    #[test]
    fn a_path_is_accepted_only_on_the_hierarchy_or_by_name() {
        let hierarchy = vec!["EXAMPLE.COM".to_owned()];
        assert!(accept(&hierarchy, "B.EXAMPLE.COM", "OTHER.EXAMPLE.COM", None).is_ok());

        let forged = vec!["FOREIGN.REALM".to_owned()];
        let err = accept(&forged, "B.EXAMPLE.COM", "OTHER.EXAMPLE.COM", None).unwrap_err();
        assert_eq!(code_of_error(&err), 28, "KDC_ERR_PATH_NOT_ACCEPTED");
        assert!(err.to_string().contains("FOREIGN.REALM"), "{err}");

        // Listed by the operator: accepted even with no hierarchy in common.
        let listed = vec!["FOREIGN.REALM".to_owned()];
        assert!(
            accept(&forged, "B.REALM.A", "REALM.C", Some(&listed)).is_ok(),
            "an explicit list is the only way to admit a path with no DNS relationship"
        );

        // An empty path is always acceptable: a single-realm ticket has nothing to admit.
        assert!(accept(&[], "A", "B", None).is_ok());
    }

    fn code_of_error(e: &Error) -> i32 {
        match e {
            Error::Kdc { code, .. } => *code,
            other => panic!("expected a KDC error, got {other}"),
        }
    }
}
