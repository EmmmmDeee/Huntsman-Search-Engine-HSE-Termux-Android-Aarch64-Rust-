//! Canonical HUNTSMAN compatibility map for nine established security tools.
//!
//! A compatibility entry is a scoped statement of actual HUNTSMAN behavior, not
//! an implementation of the third-party program and not a claim of feature parity.
//! This module intentionally does not launch foreign executables, scan radio
//! interfaces, alter targets or bypass Android userland permissions.

use serde::Serialize;

use crate::sha256::{hex32, sha256};

/// Maximum local candidate-list size: bounded for rootless Termux.
pub const MAX_WORDLIST_BYTES: u64 = 2 * 1024 * 1024;
const MAX_CANDIDATE_BYTES: usize = 256;

/// Each entry binds a named upstream workflow to canonical HUNTSMAN owners.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct ToolCapability {
    pub id: &'static str,
    pub upstream: &'static str,
    pub category: &'static str,
    /// native_subset, existing_subset or unavailable; never full upstream parity.
    pub status: &'static str,
    pub commands: &'static [&'static str],
    pub implemented: &'static [&'static str],
    pub missing: &'static [&'static str],
    pub termux_constraint: &'static str,
}

pub const TOOLS: &[ToolCapability] = &[
    ToolCapability {
        id: "john",
        upstream: "John the Ripper",
        category: "offline_password_auditing",
        status: "native_subset",
        commands: &["security-tools sha256-audit HEX_SHA256 WORDLIST"],
        implemented: &["Bounded, offline unsalted SHA-256 candidate verification; no plaintext is printed"],
        missing: &["John format plugins", "rules, masks and advanced cracking formats"],
        termux_constraint: "CPU only; no background cracking or external binary",
    },
    ToolCapability {
        id: "hashcat",
        upstream: "Hashcat",
        category: "offline_password_auditing",
        status: "native_subset",
        commands: &["security-tools sha256-audit HEX_SHA256 WORDLIST"],
        implemented: &["Reuses the same native CPU-only SHA-256 audit engine as John"],
        missing: &["GPU acceleration", "multi-hash formats", "Hashcat rules and kernels"],
        termux_constraint: "Android Termux has no general-purpose Hashcat GPU backend",
    },
    ToolCapability {
        id: "burp",
        upstream: "Burp Suite",
        category: "web_security",
        status: "existing_subset",
        commands: &["security-tools headers HTTPS_ORIGIN", "fetch URL", "mitm audit"],
        implemented: &["Guarded HTTP requests, native security-header audit and TLS/network posture checks"],
        missing: &["Intercepting proxy", "HTTP history and replay", "active scanner"],
        termux_constraint: "No transparent proxy or platform CA installation is attempted",
    },
    ToolCapability {
        id: "sqlmap",
        upstream: "SQLmap",
        category: "web_security",
        status: "unavailable",
        commands: &[],
        implemented: &[],
        missing: &[
            "SQL injection detection",
            "DBMS fingerprinting",
            "SQLmap-compatible payloads",
        ],
        termux_constraint: "No SQL injection tests are performed by this entry",
    },
    ToolCapability {
        id: "dirb",
        upstream: "DIRB",
        category: "web_discovery",
        status: "existing_subset",
        commands: &["security-tools paths HTTPS_ORIGIN WORDLIST --authorized", "domain DOMAIN"],
        implemented: &["Anonymous, consent-gated bounded web path discovery", "Historical and indexed URL leads"],
        missing: &["Full DIRB response classifiers, recursion, extension tuning and broad wordlist parity"],
        termux_constraint: "Bounded anonymous HTTPS path probes are explicit opt-in, not broad DIRB parity"
    },
    ToolCapability {
        id: "aircrack-ng",
        upstream: "Aircrack-ng",
        category: "wireless_security",
        status: "existing_subset",
        commands: &["radar wifi --json", "mitm audit"],
        implemented: &["Read-only OS-cached Wi-Fi metadata and advisory anomaly checks"],
        missing: &[
            "Monitor-mode capture",
            "packet injection",
            "WPA key recovery",
        ],
        termux_constraint: "Raw 802.11 monitor/injection operations are not available in ordinary unprivileged Android userland",
    },
    ToolCapability {
        id: "subfinder",
        upstream: "Subfinder",
        category: "passive_dns",
        status: "existing_subset",
        commands: &["domain DOMAIN", "scan DOMAIN -k domain"],
        implemented: &[
            "Native passive subdomain sources, CT certificates, DNS and evidence pivots",
        ],
        missing: &["Subfinder provider-for-provider coverage and equivalent tuning"],
        termux_constraint: "Ordinary HTTPS/DNS only; no root required",
    },
    ToolCapability {
        id: "exiftool",
        upstream: "ExifTool",
        category: "forensics",
        status: "existing_subset",
        commands: &["exif IMAGE-FILE", "docmeta FILE"],
        implemented: &[
            "Native bounded EXIF/GPS parsing",
            "XMP and document metadata extraction",
        ],
        missing: &["Complete ExifTool format/tag catalogue", "metadata writing"],
        termux_constraint: "Local file access only; embedded location is an unverified claim",
    },
    ToolCapability {
        id: "theharvester",
        upstream: "theHarvester",
        category: "public_osint",
        status: "existing_subset",
        commands: &["domain DOMAIN", "osint lookup domain DOMAIN", "query QUERY"],
        implemented: &[
            "Public domain/email/host lead aggregation using existing source collectors",
        ],
        missing: &["Full theHarvester source parity and output-format compatibility"],
        termux_constraint: "Remote sources are subject to keys, rate limits and egress policy",
    },
];

/// JSON-stable inventory shared by CLI and authenticated HTTP.
#[derive(Debug, Serialize)]
pub struct SecurityCatalog {
    pub count: usize,
    pub tools: &'static [ToolCapability],
}

#[must_use]
pub const fn catalog() -> SecurityCatalog {
    SecurityCatalog {
        count: TOOLS.len(),
        tools: TOOLS,
    }
}

/// A bounded offline verification report. Never serializes or returns a candidate.
#[derive(Debug, PartialEq, Eq, Serialize)]
pub struct Sha256Audit {
    pub algorithm: &'static str,
    pub input_bytes: usize,
    pub lines_scanned: usize,
    pub candidates_tested: usize,
    pub overlong_or_binary_skipped: usize,
    pub matched: bool,
    pub matched_line: Option<usize>,
}

/// Verify a single **unsalted raw SHA-256 digest** against a local newline-separated
/// wordlist. No network, mutation, GPU or credential recovery logging occurs.
/// Password bytes are never copied into a report.
pub fn audit_sha256(expected_hex: &str, wordlist: &[u8]) -> Result<Sha256Audit, String> {
    if expected_hex.len() != 64 || !expected_hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("expected digest must be exactly 64 hexadecimal SHA-256 characters".into());
    }
    if wordlist.is_empty() {
        return Err("candidate wordlist must not be empty".into());
    }
    if wordlist.len() as u64 > MAX_WORDLIST_BYTES {
        return Err("candidate wordlist exceeds the 2 MiB local limit".into());
    }

    let mut report = Sha256Audit {
        algorithm: "raw_sha256_unsalted",
        input_bytes: wordlist.len(),
        lines_scanned: 0,
        candidates_tested: 0,
        overlong_or_binary_skipped: 0,
        matched: false,
        matched_line: None,
    };
    let payload = if wordlist.last() == Some(&b'\n') {
        &wordlist[..wordlist.len() - 1]
    } else {
        wordlist
    };
    for line in payload.split(|byte| *byte == b'\n') {
        report.lines_scanned += 1;
        // CRLF and LF line endings produce identical candidates, while spaces
        // remain significant password bytes.
        let candidate = if line.last() == Some(&b'\r') {
            &line[..line.len() - 1]
        } else {
            line
        };
        if candidate.len() > MAX_CANDIDATE_BYTES || candidate.contains(&0) {
            report.overlong_or_binary_skipped += 1;
            continue;
        }
        report.candidates_tested += 1;
        if hex32(&sha256(candidate)).eq_ignore_ascii_case(expected_hex) {
            report.matched = true;
            report.matched_line = Some(report.lines_scanned);
            break;
        }
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_has_nine_unique_scoped_entries() {
        let catalog = catalog();
        assert_eq!(catalog.count, 9);
        let mut ids = std::collections::BTreeSet::new();
        for tool in catalog.tools {
            assert!(ids.insert(tool.id));
            assert!(matches!(
                tool.status,
                "native_subset" | "existing_subset" | "unavailable"
            ));
            assert!(!tool.termux_constraint.is_empty());
        }
        assert_eq!(
            catalog
                .tools
                .iter()
                .filter(|tool| tool.id == "sqlmap")
                .count(),
            1
        );
    }

    #[test]
    fn sha256_matches_without_exposing_plaintext() {
        let digest = hex32(&sha256(b"known candidate"));
        let report = audit_sha256(
            &digest.to_ascii_uppercase(),
            b"wrong\r\nknown candidate\r\nunused\n",
        )
        .unwrap();
        assert!(report.matched);
        assert_eq!(report.matched_line, Some(2));
        assert_eq!(report.candidates_tested, 2);
        let printed = serde_json::to_string(&report).unwrap();
        assert!(!printed.contains("known candidate"));
        assert!(!printed.contains("wrong"));
    }

    #[test]
    fn sha256_mismatch_is_a_valid_negative_result() {
        let digest = hex32(&sha256(b"not in list"));
        let report = audit_sha256(&digest, b"first\nsecond\n").unwrap();
        assert!(!report.matched);
        assert_eq!(report.lines_scanned, 2);
        assert_eq!(report.matched_line, None);
    }

    #[test]
    fn sha256_input_is_bounded_and_strict() {
        assert!(audit_sha256("short", b"abc\n").is_err());
        assert!(audit_sha256(&"g".repeat(64), b"abc\n").is_err());
        assert!(audit_sha256(&"0".repeat(64), b"").is_err());
        assert!(
            audit_sha256(
                &"0".repeat(64),
                &vec![b'a'; MAX_WORDLIST_BYTES as usize + 1]
            )
            .is_err()
        );
    }

    #[test]
    fn sha256_preserves_spaces_and_skips_binary_lines() {
        let digest = hex32(&sha256(b"  spaced  "));
        let report = audit_sha256(&digest, b"bad\0input\n  spaced  \n").unwrap();
        assert!(report.matched);
        assert_eq!(report.overlong_or_binary_skipped, 1);
        assert_eq!(report.matched_line, Some(2));
    }
}
