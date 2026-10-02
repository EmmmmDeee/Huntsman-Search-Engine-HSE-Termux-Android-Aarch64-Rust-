//! Shared host-recon helpers behind the crate's request boundary.

use std::cmp::Ordering;

use serde::{Deserialize, Serialize};

use crate::http::{Request, append_query_param};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReconTargetKind {
    Domain,
    Url,
    Email,
    Username,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReconFinding {
    pub subject: String,
    pub confidence: f64,
}

#[must_use]
pub fn host_key(kind: ReconTargetKind, value: &str) -> Option<String> {
    match kind {
        ReconTargetKind::Domain => {
            let host = value.trim().trim_end_matches('.').to_ascii_lowercase();
            (!host.is_empty() && host.contains('.')).then_some(host)
        }
        ReconTargetKind::Url => {
            crate::circuit::host_of(value).map(|host| host.trim_matches(['[', ']']).to_string())
        }
        ReconTargetKind::Email | ReconTargetKind::Username => None,
    }
}

#[must_use]
pub fn confidence_desc_then_subject(left: &ReconFinding, right: &ReconFinding) -> Ordering {
    right
        .confidence
        .partial_cmp(&left.confidence)
        .unwrap_or(Ordering::Equal)
        .then_with(|| left.subject.cmp(&right.subject))
}

pub fn sort_by_confidence_desc(findings: &mut [ReconFinding]) {
    findings.sort_by(confidence_desc_then_subject);
}

#[must_use]
pub fn build_host_lookup_request(
    base_url: &str,
    query_param: &str,
    kind: ReconTargetKind,
    value: &str,
) -> Option<Request> {
    let host = host_key(kind, value)?;
    Some(Request::get(append_query_param(
        base_url,
        query_param,
        &host,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_key_normalises_domains_and_urls() {
        assert_eq!(
            host_key(ReconTargetKind::Domain, "Example.COM."),
            Some("example.com".to_string())
        );
        assert_eq!(
            host_key(ReconTargetKind::Url, "https://SUB.example.com/path?q=1"),
            Some("sub.example.com".to_string())
        );
        assert_eq!(host_key(ReconTargetKind::Domain, "localhost"), None);
        assert_eq!(host_key(ReconTargetKind::Email, "a@x.com"), None);
    }

    #[test]
    fn sort_is_confidence_desc_then_subject() {
        let mut findings = vec![
            ReconFinding {
                subject: "b.example.com".to_string(),
                confidence: 0.45,
            },
            ReconFinding {
                subject: "a.example.com".to_string(),
                confidence: 0.75,
            },
            ReconFinding {
                subject: "c.example.com".to_string(),
                confidence: 0.75,
            },
        ];
        sort_by_confidence_desc(&mut findings);
        assert_eq!(findings[0].subject, "a.example.com");
        assert_eq!(findings[1].subject, "c.example.com");
        assert_eq!(findings[2].subject, "b.example.com");
    }

    #[test]
    fn request_builder_targets_canonical_host() {
        let request = build_host_lookup_request(
            "https://crt.sh/",
            "q",
            ReconTargetKind::Url,
            "https://Sub.Example.com/login",
        )
        .expect("request");
        assert_eq!(request.url, "https://crt.sh/?q=sub.example.com");
    }
}
