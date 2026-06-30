//! Date formatting from Unix epochs, with **no date crate**.
//!
//! The whole project deliberately avoids a `chrono`/`time` dependency (Termux
//! aarch64, minimal build). These helpers use Howard Hinnant's
//! civil-from-days algorithm (epoch 1970-01-01) — pure, total and
//! deterministic — so any module holding a Unix timestamp can render it
//! consistently. Previously this logic lived privately inside
//! [`crate::util::raw_archive`]; it is shared here so timestamp-bearing modules
//! (e.g. account-creation dates) format identically instead of re-deriving it.

/// Civil `(year, month [1-12], day [1-31])` for a count of days since the Unix
/// epoch (1970-01-01). Howard Hinnant's `civil_from_days` — see his
/// "chrono-Compatible Low-Level Date Algorithms". Total for all `i64` inputs.
#[must_use]
pub fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let year = if m <= 2 { y + 1 } else { y };
    (year, m as u32, d as u32)
}

/// `YYYYMMDDThhmmssZ` (UTC) for `unix_secs`. Sorts lexicographically in
/// chronological order, so a directory listing is a timeline — the form
/// [`crate::util::raw_archive`] stamps onto archived-response filenames.
#[must_use]
pub fn compact_utc(unix_secs: u64) -> String {
    let days = (unix_secs / 86_400) as i64;
    let rem = unix_secs % 86_400;
    let (hh, mi, ss) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    let (year, m, d) = civil_from_days(days);
    format!("{year:04}{m:02}{d:02}T{hh:02}{mi:02}{ss:02}Z")
}

/// `YYYY-MM-DD` (UTC date) for `unix_secs`, for human-legible account/creation
/// dates surfaced as evidence. Returns `None` for a non-positive epoch — a
/// missing or zero timestamp is not a real date and must never surface as
/// `1970-01-01`.
#[must_use]
pub fn ymd_utc(unix_secs: i64) -> Option<String> {
    if unix_secs <= 0 {
        return None;
    }
    let (year, m, d) = civil_from_days(unix_secs / 86_400);
    Some(format!("{year:04}-{m:02}-{d:02}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compact_utc_matches_known_instants() {
        assert_eq!(compact_utc(0), "19700101T000000Z");
        assert_eq!(compact_utc(1_780_726_449), "20260606T061409Z");
    }

    #[test]
    fn ymd_utc_renders_dates_and_rejects_nonpositive() {
        assert_eq!(ymd_utc(0), None, "zero epoch is not a real date");
        assert_eq!(ymd_utc(-1), None, "negative epoch rejected");
        // The famous 1e9 instant: 2001-09-09T01:46:40Z → date component.
        assert_eq!(ymd_utc(1_000_000_000).as_deref(), Some("2001-09-09"));
        // Same instant as the compact_utc test, date component only.
        assert_eq!(ymd_utc(1_780_726_449).as_deref(), Some("2026-06-06"));
    }

    #[test]
    fn civil_from_days_epoch_is_1970() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(31), (1970, 2, 1));
    }
}
