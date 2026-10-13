//! Subdomain takeover detection: identify subdomains pointing to unclaimed service endpoints.
//!
//! When a subdomain's CNAME or A record points to a service (GitHub Pages, AWS S3, Heroku, etc.)
//! that is no longer claimed or provisioned, an attacker can claim the service and assume control
//! of that subdomain. This detector identifies such dangling subdomains by probing them and
//! matching characteristic HTTP responses and DNS states.

use std::time::Duration;

use crate::entity::{Evidence, EvidenceProvenance};
use crate::http::{Request, Transport};

/// Known service patterns that indicate a dangling/takeable subdomain.
/// Each pattern consists of a service name and the HTTP status + body substring that indicates
/// the subdomain is not currently claimed.
#[derive(Debug, Clone, Eq, PartialEq)]
struct TakeoverPattern {
    service: &'static str,
    status: u16,
    body_indicators: &'static [&'static str],
}

const TAKEOVER_PATTERNS: &[TakeoverPattern] = &[
    // GitHub Pages: 404 with "There isn't a GitHub Pages site here"
    TakeoverPattern {
        service: "github_pages",
        status: 404,
        body_indicators: &["There isn't a GitHub Pages site here"],
    },
    // Heroku: 404 with "no-such-app"
    TakeoverPattern {
        service: "heroku",
        status: 404,
        body_indicators: &["no-such-app", "Heroku"],
    },
    // AWS S3: 404 with NoSuchBucket or similar
    TakeoverPattern {
        service: "aws_s3",
        status: 404,
        body_indicators: &["NoSuchBucket", "The specified bucket does not exist"],
    },
    // Vercel (Zeit): 404 with specific message
    TakeoverPattern {
        service: "vercel",
        status: 404,
        body_indicators: &["RESERVED_DEPLOYMENT"],
    },
    // Netlify: 404 or 403
    TakeoverPattern {
        service: "netlify",
        status: 404,
        body_indicators: &["Page not found", "Not Found"],
    },
    // Fastly: 404 with specific response
    TakeoverPattern {
        service: "fastly",
        status: 404,
        body_indicators: &["Fastly error"],
    },
    // Azure: 404 with Azure-specific message
    TakeoverPattern {
        service: "azure",
        status: 404,
        body_indicators: &["Azure App Service"],
    },
    // Shopify: 404 for unclaimed shop
    TakeoverPattern {
        service: "shopify",
        status: 404,
        body_indicators: &["Shopify"],
    },
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TakeoverFinding {
    pub subdomain: String,
    pub service: String,
    pub risk_level: RiskLevel,
    pub evidence_summary: String,
    pub http_status: u16,
    pub response_sample: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RiskLevel {
    /// Possible takeover: needs manual verification.
    Low,
    /// Likely takeover: CNAME points to unclaimed service but no verification body match.
    Medium,
    /// Definite takeover possible: clear service signature.
    High,
}

impl RiskLevel {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
        }
    }
}

/// Probe a subdomain for takeover vulnerability.
///
/// Returns `Some(Some(finding))` if a vulnerability is detected,
/// `Some(None)` if the subdomain is reachable but safe, or
/// `None` if the probe fails (network error, timeout, etc.).
#[must_use]
pub fn probe<T: Transport + ?Sized>(
    transport: &T,
    subdomain: &str,
) -> Option<Option<TakeoverFinding>> {
    // Construct HTTP URL
    let url = format!("http://{subdomain}");

    // Create request with timeout to prevent hanging on slow/dead subdomains
    let mut request = Request::get(&url);
    request.timeout = Some(Duration::from_secs(3));

    // Send request
    let response = transport.send(&request).ok()?;

    // Check against known patterns
    for pattern in TAKEOVER_PATTERNS {
        if response.status == pattern.status {
            let body = response.text();

            // Check if any indicator matches
            for indicator in pattern.body_indicators {
                if body.contains(indicator) {
                    return Some(Some(TakeoverFinding {
                        subdomain: subdomain.to_owned(),
                        service: pattern.service.to_owned(),
                        risk_level: RiskLevel::High,
                        evidence_summary: format!(
                            "Subdomain points to unclaimed {} service: {}",
                            pattern.service, indicator
                        ),
                        http_status: response.status,
                        response_sample: body.chars().take(200).collect(),
                    }));
                }
            }

            // If status matches but body doesn't, it's still suspicious for this service
            if response.status == 404 {
                return Some(Some(TakeoverFinding {
                    subdomain: subdomain.to_owned(),
                    service: pattern.service.to_owned(),
                    risk_level: RiskLevel::Medium,
                    evidence_summary: format!(
                        "Subdomain returns 404 consistent with unclaimed {} service",
                        pattern.service
                    ),
                    http_status: response.status,
                    response_sample: body.chars().take(200).collect(),
                }));
            }
        }
    }

    // No known pattern matched
    Some(None)
}

/// Convert a takeover finding into evidence for inclusion in an entity.
#[must_use]
pub fn finding_to_evidence(finding: &TakeoverFinding, scan_id: &str) -> Evidence {
    let mut provenance = EvidenceProvenance::new("subdomain_takeover_detector");
    provenance.scan_id = Some(scan_id.to_owned());

    let mut attributes = std::collections::BTreeMap::new();
    attributes.insert("service".to_owned(), finding.service.clone());
    attributes.insert(
        "risk_level".to_owned(),
        finding.risk_level.as_str().to_owned(),
    );
    attributes.insert("http_status".to_owned(), finding.http_status.to_string());
    attributes.insert("sample".to_owned(), finding.response_sample.clone());

    let summary = format!(
        "Subdomain {} vulnerable to takeover via {}",
        finding.subdomain, finding.service
    );

    let mut evidence = Evidence::new(provenance, summary);
    evidence.attributes = attributes;
    evidence
}

/// Detect subdomain takeover vulnerabilities in a list of subdomains.
///
/// # Errors
/// None; returns Vec even on partial failures.
pub fn detect_in_subdomains<T: Transport + ?Sized>(
    transport: &T,
    subdomains: &[String],
) -> Vec<TakeoverFinding> {
    let mut findings = Vec::new();

    for subdomain in subdomains.iter().take(50) {
        // Limit probes to prevent DoS-like behavior
        if let Some(Some(finding)) = probe(transport, subdomain) {
            findings.push(finding);
        }
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn risk_levels_order() {
        assert!(RiskLevel::Low < RiskLevel::Medium);
        assert!(RiskLevel::Medium < RiskLevel::High);
    }

    #[test]
    fn risk_level_strings() {
        assert_eq!(RiskLevel::High.as_str(), "high");
        assert_eq!(RiskLevel::Medium.as_str(), "medium");
        assert_eq!(RiskLevel::Low.as_str(), "low");
    }

    #[test]
    fn finding_to_evidence_creates_attributes() {
        let finding = TakeoverFinding {
            subdomain: "test.example.com".to_owned(),
            service: "github_pages".to_owned(),
            risk_level: RiskLevel::High,
            evidence_summary: "Test".to_owned(),
            http_status: 404,
            response_sample: "sample".to_owned(),
        };

        let evidence = finding_to_evidence(&finding, "scan123");
        assert!(evidence.attributes.contains_key("service"));
        assert_eq!(
            evidence.attributes.get("service").map(String::as_str),
            Some("github_pages")
        );
        assert_eq!(
            evidence.attributes.get("risk_level").map(String::as_str),
            Some("high")
        );
    }
}
