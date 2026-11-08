//! Calendar arithmetic for `KerberosTime`.
//!
//! RFC 4120 encodes time as a `GeneralizedTime` with a `Z` suffix and no
//! fractional seconds: `YYYYMMDDHHMMSSZ`. There is no leap second in Kerberos
//! and no local timezone, so the whole job is a seconds-to-civil-date
//! conversion. It is done here, by hand, rather than pulling a date library
//! into a KDC: the algorithms are Howard Hinnant's `days_from_civil` and
//! `civil_from_days`, valid for the whole proleptic Gregorian range.

/// Days since 1970-01-01 for a civil date.
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400; // [0, 399]
    let mp = (m as i64 + 9) % 12; // March = 0
    let doy = (153 * mp + 2) / 5 + d as i64 - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    era * 146_097 + doe - 719_468
}

/// Civil date for a day count since 1970-01-01.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// `YYYYMMDDHHMMSSZ`, the only form Kerberos uses.
pub fn format_generalized_time(unix: i64) -> String {
    let days = unix.div_euclid(86_400);
    let secs = unix.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}{m:02}{d:02}{:02}{:02}{:02}Z",
        secs / 3600,
        (secs % 3600) / 60,
        secs % 60
    )
}

/// Parses `YYYYMMDDHHMMSSZ`. Rejects fractional seconds and offsets, which
/// Kerberos never produces, rather than quietly mis-reading them.
pub fn parse_generalized_time(s: &str) -> Option<i64> {
    let b = s.as_bytes();
    if b.len() != 15 || b[14] != b'Z' || !b[..14].iter().all(u8::is_ascii_digit) {
        return None;
    }
    let num = |r: std::ops::Range<usize>| -> i64 { s[r].parse().ok().unwrap_or(-1) };
    let (y, mo, d) = (num(0..4), num(4..6) as u32, num(6..8) as u32);
    let (h, mi, se) = (num(8..10), num(10..12), num(12..14));
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 || se > 60 {
        return None;
    }
    Some(days_from_civil(y, mo, d) * 86_400 + h * 3600 + mi * 60 + se)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_and_known_instants() {
        assert_eq!(format_generalized_time(0), "19700101000000Z");
        assert_eq!(format_generalized_time(1_700_000_000), "20231114221320Z");
        // 2000-02-29, the leap day that catches naive month arithmetic.
        assert_eq!(format_generalized_time(951_782_400), "20000229000000Z");
        assert_eq!(format_generalized_time(1_767_225_600), "20260101000000Z");
    }

    #[test]
    fn parses_what_it_formats() {
        for t in [0i64, 1, 951_782_400, 1_700_000_000, 4_102_444_800] {
            let s = format_generalized_time(t);
            assert_eq!(parse_generalized_time(&s), Some(t), "{s}");
        }
    }

    #[test]
    fn rejects_forms_kerberos_never_sends() {
        assert_eq!(parse_generalized_time("20231114221320.5Z"), None);
        assert_eq!(parse_generalized_time("20231114221320"), None);
        assert_eq!(parse_generalized_time("20231314221320Z"), None);
    }
}
