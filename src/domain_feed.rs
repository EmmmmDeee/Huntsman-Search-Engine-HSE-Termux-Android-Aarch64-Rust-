//! Constant-memory inspection of operator-supplied Domains-Monitor plain-text lists.
//!
//! A list is an observation, not an authoritative registration, ownership or
//! website-status source. This adapter is deliberately offline: the provider's
//! API embeds its token in URL paths, so a fetch must not bypass Huntsman's
//! credential-safe HTTP boundary.

use std::collections::BTreeMap;
use std::io::BufRead;

use serde::Serialize;

use crate::canonical::canonical_domain;
use crate::sha256::Sha256;

pub const SOURCE: &str = "domains-monitor.com";
pub const MAX_TARGETS: usize = 1024;
const MAX_ROW_BYTES: usize = 512;

pub const USAGE: &str = concat!(
    "domain-feed match full|dailyupdate|dailyremove FILE --as-of YYYY-MM-DD DOMAIN [DOMAIN ...]\n",
    "Read a locally supplied Domains-Monitor text list in one bounded-memory pass. ",
    "Prints JSON with SHA-256 evidence and matched domains. No HTTP calls. ",
    "No claim of domain ownership or registration availability."
);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Dataset {
    Full,
    DailyUpdate,
    DailyRemove,
}

impl Dataset {
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "full" => Some(Self::Full),
            "dailyupdate" => Some(Self::DailyUpdate),
            "dailyremove" => Some(Self::DailyRemove),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Match {
    pub domain: String,
    /// Number of times the exact canonical name occurred in the supplied file.
    pub occurrences: u64,
    /// True means "listed in this file", NOT "currently registered".
    pub listed: bool,
    /// `not_observed` applies only if every row was parsed. Invalid rows
    /// leave a non-match unresolved, never evidence of absence.
    pub status: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Report {
    pub schema_version: u32,
    pub source_claim: &'static str,
    pub source_authenticated: bool,
    pub dataset: Dataset,
    pub as_of: String,
    pub file_sha256: String,
    pub bytes_read: u64,
    pub lines_read: u64,
    pub valid_rows: u64,
    pub invalid_rows: u64,
    /// Only describes whether all supplied data rows were parsed, not the
    /// completeness of the provider's wider dataset.
    pub file_parse_complete: bool,
    pub matches: Vec<Match>,
    pub registration_status: &'static str,
    pub ownership: &'static str,
    pub site_active: &'static str,
    pub interpretation: &'static str,
}

#[derive(Default)]
struct Counts {
    lines: u64,
    valid: u64,
    invalid: u64,
    targets: BTreeMap<String, u64>,
}

fn consume_row(row: &[u8], oversized: bool, counts: &mut Counts) {
    counts.lines = counts.lines.saturating_add(1);
    if oversized {
        counts.invalid = counts.invalid.saturating_add(1);
        return;
    }
    let Ok(raw) = std::str::from_utf8(row) else {
        counts.invalid = counts.invalid.saturating_add(1);
        return;
    };
    let raw = raw.trim();
    if raw.is_empty() || raw.starts_with('#') {
        return;
    }
    // Never interpret a URL, e-mail, or delimited detailed record as a domain.
    if raw.len() > 253
        || raw.starts_with('.')
        || raw.ends_with("..")
        || raw.bytes().any(|b| {
            b.is_ascii_control() || matches!(b, b'/' | b'@' | b':' | b';' | b'?' | b'#')
        })
    {
        counts.invalid = counts.invalid.saturating_add(1);
        return;
    }
    match canonical_domain(raw) {
        Some(domain) => {
            counts.valid = counts.valid.saturating_add(1);
            if let Some(n) = counts.targets.get_mut(&domain) {
                *n = n.saturating_add(1);
            }
        }
        None => counts.invalid = counts.invalid.saturating_add(1),
    }
}

/// Validate the date that the operator attributes to a snapshot, without
/// converting it into an invented collection timestamp.
#[must_use]
pub fn valid_date(date: &str) -> bool {
    let b = date.as_bytes();
    if b.len() != 10
        || b[4] != b'-'
        || b[7] != b'-'
        || b.iter()
            .enumerate()
            .any(|(i, c)| i != 4 && i != 7 && !c.is_ascii_digit())
    {
        return false;
    }
    let Ok(year) = date[0..4].parse::<u32>() else {
        return false;
    };
    let Ok(month) = date[5..7].parse::<usize>() else {
        return false;
    };
    let Ok(day) = date[8..10].parse::<u32>() else {
        return false;
    };
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    year > 0 && (1..=12).contains(&month) && day >= 1 && day <= days[month - 1]
}

fn sha256_hex(digest: [u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(64);
    for byte in digest {
        result.push(char::from(HEX[usize::from(byte >> 4)]));
        result.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    result
}

/// Inspect the entire file, computing its raw SHA-256 while keeping no more
/// than one bounded row plus at most 1024 query names in RAM.
///
/// A match establishes only membership in the supplied file. A miss establishes
/// only absence from that file, not global absence. This intentionally does
/// not accept ZIP files: use the provider's documented `text` variant.
///
/// # Errors
/// An invalid query/date, input I/O failure or byte-counter overflow.
pub fn scan<R: BufRead>(
    mut reader: R,
    dataset: Dataset,
    as_of: &str,
    targets: &[String],
) -> Result<Report, String> {
    if !valid_date(as_of) {
        return Err("invalid --as-of date: use YYYY-MM-DD".into());
    }
    if targets.is_empty() || targets.len() > MAX_TARGETS {
        return Err(format!("expected 1..={MAX_TARGETS} domain targets"));
    }
    let mut counts = Counts::default();
    for name in targets {
        let Some(domain) = canonical_domain(name) else {
            return Err("invalid domain target".into());
        };
        counts.targets.entry(domain).or_insert(0);
    }
    let mut digest = Sha256::new();
    let mut row = Vec::with_capacity(256);
    let mut oversized = false;
    let mut bytes_read = 0_u64;
    // Archive detection must not depend on BufRead's chunk size. A reader
    // offering one byte per fill_buf must still refuse compressed input.
    let mut signature = [0_u8; 4];
    let mut signature_len = 0_usize;

    loop {
        let available = reader.fill_buf().map_err(|e| format!("feed read failed: {e}"))?;
        if available.is_empty() {
            if !row.is_empty() || oversized {
                consume_row(&row, oversized, &mut counts);
            }
            break;
        }
        let ending = available.iter().position(|b| *b == b'\n');
        let take = ending.map_or(available.len(), |n| n + 1);
        let part = &available[..take];
        if signature_len < signature.len() {
            let n = (signature.len() - signature_len).min(part.len());
            signature[signature_len..signature_len + n].copy_from_slice(&part[..n]);
            signature_len += n;
            if signature_len >= 2 && signature[..2] == [0x1f, 0x8b] {
                return Err("gzip archive supplied: use a plain-text list".into());
            }
            if signature_len == 4
                && signature[..2] == *b"PK"
                && matches!((signature[2], signature[3]), (3, 4) | (5, 6) | (7, 8))
            {
                return Err("ZIP archive supplied: use a plain-text list".into());
            }
        }
        bytes_read = bytes_read
            .checked_add(take as u64)
            .ok_or("feed byte counter overflow")?;
        digest.update(part);
        let without_lf = if ending.is_some() {
            &part[..part.len() - 1]
        } else {
            part
        };
        if !oversized {
            if row.len().saturating_add(without_lf.len()) > MAX_ROW_BYTES {
                row.clear();
                oversized = true;
            } else {
                row.extend_from_slice(without_lf);
            }
        }
        reader.consume(take);
        if ending.is_some() {
            if row.last() == Some(&b'\r') {
                row.pop();
            }
            consume_row(&row, oversized, &mut counts);
            row.clear();
            oversized = false;
        }
    }
    let file_parse_complete = counts.invalid == 0;
    let matches = counts
        .targets
        .into_iter()
        .map(|(domain, occurrences)| Match {
            domain,
            occurrences,
            listed: occurrences > 0,
            status: if occurrences > 0 {
                "present"
            } else if file_parse_complete {
                "not_observed_in_supplied_file"
            } else {
                "unresolved_due_to_invalid_rows"
            },
        })
        .collect();
    Ok(Report {
        schema_version: 1,
        source_claim: SOURCE,
        source_authenticated: false,
        dataset,
        as_of: as_of.to_owned(),
        file_sha256: sha256_hex(digest.finalize()),
        bytes_read,
        lines_read: counts.lines,
        valid_rows: counts.valid,
        invalid_rows: counts.invalid,
        file_parse_complete,
        matches,
        registration_status: "unknown",
        ownership: "unknown",
        site_active: "unknown",
        interpretation: concat!(
            "Membership of this operator-supplied file only. ",
            "Invalid rows make unmatched domains unresolved. ",
            "No claim of global coverage, live registration, availability, ",
            "ownership, or website activity."
        ),
    })
}

#[cfg(test)]
mod tests {
    use std::io::{BufReader, Cursor};

    use super::*;

    fn inspect(input: &[u8], names: &[&str]) -> Report {
        scan(
            BufReader::with_capacity(3, Cursor::new(input)),
            Dataset::Full,
            "2025-07-06",
            &names.iter().map(|n| (*n).to_owned()).collect::<Vec<_>>(),
        )
        .unwrap()
    }

    #[test]
    fn exact_membership_is_deduplicated_and_not_live_registration() {
        let report = inspect(
            b"Example.COM\r\nfoo.example.com\nexample.com\n",
            &["EXAMPLE.COM", "xample.com"],
        );
        assert_eq!(report.lines_read, 3);
        assert_eq!(report.valid_rows, 3);
        assert_eq!(report.matches[0].occurrences, 2);
        assert!(report.matches[0].listed);
        assert!(!report.matches[1].listed);
        assert_eq!(report.registration_status, "unknown");
        assert!(!report.source_authenticated);
    }

    #[test]
    fn leading_dot_is_not_silently_canonicalised_into_a_match() {
        let report = inspect(b".example.com\nexample.com\n", &["example.com"]);
        assert_eq!(report.valid_rows, 1);
        assert_eq!(report.invalid_rows, 1);
        assert_eq!(report.matches[0].occurrences, 1);
    }

    #[test]
    fn archive_detection_is_independent_of_small_read_buffers() {
        for bytes in [
            &b"PK\x03\x04payload"[..],
            &b"PK\x05\x06empty"[..],
            &b"PK\x07\x08descriptor"[..],
            &b"\x1f\x8bcompressed"[..],
        ] {
            for capacity in [1, 2, 3, 4, 7] {
                let reader = BufReader::with_capacity(capacity, Cursor::new(bytes));
                let result = scan(
                    reader,
                    Dataset::Full,
                    "2025-07-06",
                    &["example.com".into()],
                );
                assert!(result.is_err(), "magic accepted with capacity {capacity}");
            }
        }
    }

    #[test]
    fn invalid_rows_make_unmatched_domains_unresolved_not_absent() {
        let report = inspect(
            b"example.com\nhttps://another.example\n",
            &["example.com", "missing.example"],
        );
        assert!(!report.file_parse_complete);
        assert_eq!(report.invalid_rows, 1);
        assert_eq!(report.matches[0].status, "present");
        assert_eq!(
            report.matches[1].status,
            "unresolved_due_to_invalid_rows"
        );
        let clean = inspect(b"example.com\n", &["missing.example"]);
        assert!(clean.file_parse_complete);
        assert_eq!(clean.matches[0].status, "not_observed_in_supplied_file");
    }

    #[test]
    fn hashes_full_bytes_and_rejects_unstructured_rows() {
        let report = inspect(
            b"example.com\nhttps://example.com\nnone;detail\n\xff\n",
            &["example.com"],
        );
        assert_eq!(report.bytes_read, 46);
        assert_eq!(report.valid_rows, 1);
        assert_eq!(report.invalid_rows, 3);
        assert_eq!(report.file_sha256.len(), 64);
    }

    #[test]
    fn oversized_row_is_skipped_across_chunk_boundaries() {
        let mut input = vec![b'x'; 2048];
        input.extend_from_slice(b"\nexample.org");
        let r = inspect(&input, &["example.org"]);
        assert_eq!(r.lines_read, 2);
        assert_eq!(r.invalid_rows, 1);
        assert!(r.matches[0].listed);
        assert_eq!(r.bytes_read, input.len() as u64);
    }

    #[test]
    fn bogus_dates_and_bad_targets_never_scan() {
        for date in [
            "2025-02-29",
            "2025-13-01",
            "2025-00-01",
            "2025-01-00",
            "0000-01-01",
            "2025-1-01",
        ] {
            assert!(
                scan(
                    Cursor::new(b"example.com"),
                    Dataset::Full,
                    date,
                    &["example.com".into()],
                )
                .is_err()
            );
        }
        assert!(valid_date("2024-02-29"));
        assert!(
            scan(
                Cursor::new(b"example.com"),
                Dataset::Full,
                "2025-07-06",
                &["https://example.com".into()],
            )
            .is_err()
        );
        assert!(
            scan(Cursor::new(b"example.com"), Dataset::Full, "2025-07-06", &[]).is_err()
        );
    }

    #[test]
    fn exact_hash_agrees_with_known_sha256() {
        let r = inspect(b"abc\n", &["example.org"]);
        assert_eq!(
            r.file_sha256,
            "edeaaff3f1774ad2888673770c6d64097e391bc362d7d6fb34982ddf0efd18cb"
        );
    }
}
