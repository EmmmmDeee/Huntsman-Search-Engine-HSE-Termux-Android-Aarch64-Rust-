//! Offline source-candidate projection from Huntsman's existing APK intelligence.
//!
//! No network requests, execution, credential inference, source registration or
//! source-verification claims. The APK analyser owns extraction; this module only
//! projects its already bounded observations into stable discovery identities.

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, Ipv6Addr};

use serde::Serialize;

use crate::apk_intel;
use crate::sha256::{hex32, sha256};
use crate::validation::is_placeholder_domain;
use crate::value_syntax::{canonical_domain, is_iana_tld};

pub const SCHEMA: &str = "huntsman.source-candidates/1";
pub const MAX_CANDIDATES: usize = 512;
const MAX_URL_BYTES: usize = 2048;
const MAX_PATH_BYTES: usize = 1024;
const LIMITATIONS: &str = "Static DEX string references only; neither app network contact, source access, API method, service ownership nor intelligence accuracy is verified. Original APK analysis may omit URLs or unreadable members. Query strings and fragments are intentionally not exported. No per-string DEX byte location is claimed.";

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Candidate {
    /// SHA-256 of a domain-separated canonical endpoint string, not an identity claim.
    pub id: String,
    /// Canonical public-looking URL without query values, fragments or userinfo.
    pub endpoint: String,
    /// Unknown: a URL literal does not establish a request method.
    pub method: Option<String>,
    pub discovery: &'static str,
    pub access: &'static str,
    pub operational_status: &'static str,
    /// Several literal spellings can name the same canonical endpoint.
    pub references_in_artifact: usize,
    pub evidence: EvidenceReference,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EvidenceReference {
    pub artifact_sha256: String,
    pub artifact_type: &'static str,
    pub scope: &'static str,
    pub extractor: &'static str,
    /// No original DEX string offset is retained by the existing APK report.
    pub byte_range: Option<(usize, usize)>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CandidateReport {
    pub schema: &'static str,
    pub artifact_sha256: String,
    pub artifact_type: &'static str,
    pub urls_examined: usize,
    pub urls_rejected: usize,
    pub urls_omitted_upstream: usize,
    pub dex_strings_unread: usize,
    pub archive_members_unread: usize,
    pub candidates_omitted: usize,
    pub candidates: Vec<Candidate>,
    pub limitations: &'static str,
}

fn normalise_url(input: &str) -> Option<String> {
    if input.len() > MAX_URL_BYTES || input.bytes().any(|b| b.is_ascii_control() || b == b'\\') {
        return None;
    }
    let (scheme, rest) = if input.get(..8).is_some_and(|s| s.eq_ignore_ascii_case("https://")) {
        ("https", &input[8..])
    } else if input.get(..7).is_some_and(|s| s.eq_ignore_ascii_case("http://")) {
        ("http", &input[7..])
    } else {
        return None;
    };
    let boundary = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..boundary];
    if authority.is_empty()
        || !authority.is_ascii()
        || authority.bytes().any(|b| b == b'@' || b == b'%' || b.is_ascii_whitespace())
    {
        return None;
    }
    let (host, port) = if let Some(bracketed) = authority.strip_prefix('[') {
        let closing = bracketed.find(']')?;
        let ip: Ipv6Addr = bracketed[..closing].parse().ok()?;
        let suffix = &bracketed[closing + 1..];
        (format!("[{ip}]"), parse_port(suffix)?)
    } else {
        let (hostname, suffix) = match authority.rsplit_once(':') {
            Some((host, port)) => (host, format!(":{port}")),
            None => (authority, String::new()),
        };
        if hostname.contains(':') || hostname.is_empty() {
            return None;
        }
        let host = if let Ok(ip) = hostname.parse::<Ipv4Addr>() {
            ip.to_string()
        } else {
            let domain = canonical_domain(hostname)?;
            if is_placeholder_domain(&domain)
                || !domain.rsplit('.').next().is_some_and(is_iana_tld)
            {
                return None;
            }
            domain
        };
        (host, parse_port(&suffix)?)
    };
    let effective_port = match (scheme, port) {
        ("http", Some(80)) | ("https", Some(443)) | (_, None) => String::new(),
        (_, Some(port)) => format!(":{port}"),
    };
    let tail = &rest[boundary..];
    let path = if tail.starts_with('/') {
        let end = tail.find(['?', '#']).unwrap_or(tail.len());
        &tail[..end]
    } else {
        "/"
    };
    if path.len() > MAX_PATH_BYTES
        || path.bytes().any(|b| !b.is_ascii_graphic() || b == b'\\')
    {
        return None;
    }
    Some(format!("{scheme}://{host}{effective_port}{path}"))
}

/// Parse an explicit numeric port. Empty suffix means the URL omitted its port.
fn parse_port(suffix: &str) -> Option<Option<u16>> {
    if suffix.is_empty() {
        return Some(None);
    }
    let digits = suffix.strip_prefix(':')?;
    if digits.is_empty() || digits.len() > 5 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let port = digits.parse::<u16>().ok()?;
    (port != 0).then_some(Some(port))
}

fn from_urls(
    sha: &str,
    urls: &[String],
    urls_omitted_upstream: usize,
    dex_strings_unread: usize,
    archive_members_unread: usize,
) -> CandidateReport {
    let mut candidates: BTreeMap<String, Candidate> = BTreeMap::new();
    let mut urls_rejected = 0;
    let mut candidates_omitted = 0;
    for url in urls {
        let Some(endpoint) = normalise_url(url) else {
            urls_rejected += 1;
            continue;
        };
        if let Some(existing) = candidates.get_mut(&endpoint) {
            existing.references_in_artifact += 1;
            continue;
        }
        if candidates.len() == MAX_CANDIDATES {
            candidates_omitted += 1;
            continue;
        }
        let id = format!(
            "sha256:{}",
            hex32(&sha256(format!("hse-source-endpoint/1\\0{endpoint}").as_bytes()))
        );
        candidates.insert(
            endpoint.clone(),
            Candidate {
                id,
                endpoint,
                method: None,
                discovery: "static_reference",
                access: "unknown",
                operational_status: "not_tested",
                references_in_artifact: 1,
                evidence: EvidenceReference {
                    artifact_sha256: sha.to_owned(),
                    artifact_type: "apk",
                    scope: "dex_string_tables",
                    extractor: "apk_intel::dex::CodeUrls",
                    byte_range: None,
                },
            },
        );
    }
    CandidateReport {
        schema: SCHEMA,
        artifact_sha256: sha.to_owned(),
        artifact_type: "apk",
        urls_examined: urls.len(),
        urls_rejected,
        urls_omitted_upstream,
        dex_strings_unread,
        archive_members_unread,
        candidates_omitted,
        candidates: candidates.into_values().collect(),
        limitations: LIMITATIONS,
    }
}

/// Project an already analysed APK. Does not mutate its report or perform I/O.
#[must_use]
pub fn from_apk_report(report: &apk_intel::Report) -> CandidateReport {
    from_urls(
        &report.inventory.sha256,
        &report.analysis.code.urls,
        report.analysis.code.urls_omitted,
        report.analysis.code.strings_unread,
        report.analysis.unread.len(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn project(urls: &[&str]) -> CandidateReport {
        from_urls(
            &"a".repeat(64),
            &urls.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>(),
            0,
            0,
            0,
        )
    }

    #[test]
    fn canonical_identity_ignores_query_values_default_port_and_case_of_host() {
        let report = project(&[
            "HTTPS://API.EXAMPLE.COM:443/v1/lookup?token=PRIVATE",
            "https://api.example.com/v1/lookup?token=DIFFERENT#frag",
        ]);
        assert_eq!(report.candidates.len(), 1);
        let item = &report.candidates[0];
        assert_eq!(item.endpoint, "https://api.example.com/v1/lookup");
        assert_eq!(item.references_in_artifact, 2);
        assert_eq!(item.access, "unknown");
        assert_eq!(item.method, None);
        let json = serde_json::to_string(&report).unwrap();
        assert!(!json.contains("PRIVATE") && !json.contains("DIFFERENT"));
    }

    #[test]
    fn invalid_and_non_web_references_are_not_promoted() {
        let report = project(&[
            "https://user:pass@api.example.com/upload",
            "file:///private/notes",
            "http://api.example.com:0/path",
            "https://api.example.com\\@internal/",
            "http://api.example.com:99999/",
            "https://api.example.com:443/a",
        ]);
        assert_eq!(report.urls_rejected, 5);
        assert_eq!(report.candidates.len(), 1);
        assert_eq!(report.candidates[0].endpoint, "https://api.example.com/a");
    }

    #[test]
    fn sorting_and_identity_are_input_order_independent() {
        let a = project(&["https://z.example.com/a", "https://a.example.com/b"]);
        let b = project(&["https://a.example.com/b", "https://z.example.com/a"]);
        assert_eq!(a, b);
        assert!(a.candidates.iter().all(|c| c.evidence.byte_range.is_none()));
    }

    #[test]
    fn upstream_omissions_are_never_silent() {
        let report = from_urls(&"b".repeat(64), &[], 19, 11, 2);
        assert!(report.candidates.is_empty());
        assert_eq!(report.urls_omitted_upstream, 19);
        assert_eq!(report.dex_strings_unread, 11);
        assert_eq!(report.archive_members_unread, 2);
    }

    #[test]
    fn preserves_non_default_port_and_ipv6_without_claiming_public_access() {
        let report = project(&[
            "http://api.example.com:8080/data?key=secret",
            "https://[2001:db8::1]:8443/a",
        ]);
        assert_eq!(report.candidates.len(), 2);
        assert!(report.candidates.iter().any(|c| c.endpoint == "http://api.example.com:8080/data"));
        assert!(report.candidates.iter().any(|c| c.endpoint == "https://[2001:db8::1]:8443/a"));
        assert!(report.candidates.iter().all(|c| c.access == "unknown"));
    }
}
