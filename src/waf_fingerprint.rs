//! WAF/CDN fingerprinting: identify content delivery networks and web application firewalls.
//!
//! Analyzes HTTP response headers and status codes to detect commonly deployed WAF and CDN
//! solutions. Useful for understanding infrastructure and potential bypass vectors during
//! legitimate security assessments.

use crate::http::{Request, Transport};

/// Known WAF/CDN patterns detected by analyzing response headers and behavior.
#[derive(Debug, Clone, Eq, PartialEq)]
struct FingerprintPattern {
    name: &'static str,
    category: &'static str,
    headers: &'static [&'static str],
    header_values: &'static [&'static str],
    status_indicators: &'static [u16],
}

const FINGERPRINT_PATTERNS: &[FingerprintPattern] = &[
    // Cloudflare: Server header, cf-ray header, 1020 error pages
    FingerprintPattern {
        name: "Cloudflare",
        category: "cdn",
        headers: &["cf-ray", "cf-cache-status", "server"],
        header_values: &["cloudflare", "cf_"],
        status_indicators: &[1020, 1010],
    },
    // AWS CloudFront: Server header, X-Amz-Cf-Id header
    FingerprintPattern {
        name: "AWS CloudFront",
        category: "cdn",
        headers: &["x-amz-cf-id", "x-amz-cf-pop"],
        header_values: &["cloudfront"],
        status_indicators: &[403, 404],
    },
    // Akamai: AkamaiGHost, X-Akamai headers
    FingerprintPattern {
        name: "Akamai",
        category: "cdn",
        headers: &["x-akamai-transformed", "server"],
        header_values: &["akamaighost", "akamai"],
        status_indicators: &[403],
    },
    // Sucuri: Sucuri/CloudProxy WAF
    FingerprintPattern {
        name: "Sucuri",
        category: "waf",
        headers: &["server", "x-sucuri-id"],
        header_values: &["sucuri", "cloudproxy"],
        status_indicators: &[403],
    },
    // ModSecurity: X-ModSecurity headers
    FingerprintPattern {
        name: "ModSecurity",
        category: "waf",
        headers: &["x-modsecurity", "server"],
        header_values: &["modsecurity"],
        status_indicators: &[403, 406],
    },
    // Imperva/Incapsula: X-Iinfo, X-CDN headers
    FingerprintPattern {
        name: "Imperva/Incapsula",
        category: "waf",
        headers: &["x-iinfo", "x-cdn"],
        header_values: &["incapsula", "imperva"],
        status_indicators: &[403],
    },
    // F5 BIG-IP: Server headers, specific error pages
    FingerprintPattern {
        name: "F5 BIG-IP",
        category: "waf",
        headers: &["server"],
        header_values: &["big-ip"],
        status_indicators: &[403],
    },
    // Nginx: Server header
    FingerprintPattern {
        name: "Nginx",
        category: "webserver",
        headers: &["server"],
        header_values: &["nginx"],
        status_indicators: &[404],
    },
    // Apache: Server header
    FingerprintPattern {
        name: "Apache",
        category: "webserver",
        headers: &["server"],
        header_values: &["apache"],
        status_indicators: &[404],
    },
    // IIS: Server header, X-Powered-By
    FingerprintPattern {
        name: "Microsoft IIS",
        category: "webserver",
        headers: &["server", "x-powered-by"],
        header_values: &["iis", "microsoft-iis"],
        status_indicators: &[404],
    },
];

#[derive(Debug, Clone, PartialEq)]
pub struct FingerprintFinding {
    pub url: String,
    pub detected_service: String,
    pub category: String,
    pub headers_matched: Vec<String>,
    pub confidence: f64,
}

impl FingerprintFinding {
    #[must_use]
    pub const fn confidence_level(&self) -> &'static str {
        match self.confidence {
            x if x >= 0.9 => "high",
            x if x >= 0.7 => "medium",
            _ => "low",
        }
    }
}

/// Probe a domain/URL for WAF/CDN fingerprints via HTTP headers.
///
/// Returns `Some(findings)` if any patterns match, `None` if probe fails or no matches found.
#[must_use]
pub fn fingerprint<T: Transport + ?Sized>(
    transport: &T,
    url: &str,
) -> Option<Option<FingerprintFinding>> {
    use std::time::Duration;

    // Create request with short timeout
    let mut request = Request::get(url);
    request.timeout = Some(Duration::from_secs(5));

    let response = transport.send(&request).ok()?;

    // Check against all patterns
    for pattern in FINGERPRINT_PATTERNS {
        let mut matched_headers = Vec::new();
        let mut match_score: f64 = 0.0;

        // Check each header pattern
        for header_name in pattern.headers {
            if let Some(value) = response.header_value(header_name) {
                let lowered = value.to_lowercase();
                for header_value_pattern in pattern.header_values {
                    if lowered.contains(&header_value_pattern.to_lowercase()) {
                        matched_headers.push(format!("{header_name}: {value}"));
                        match_score += 0.4;
                        break;
                    }
                }
            }
        }

        // Check status code match
        if pattern.status_indicators.contains(&response.status) {
            match_score += 0.3;
        }

        // If we have matches, return finding
        if match_score > 0.3 && !matched_headers.is_empty() {
            let confidence = (match_score / 0.7).min(1.0_f64);
            return Some(Some(FingerprintFinding {
                url: url.to_owned(),
                detected_service: pattern.name.to_owned(),
                category: pattern.category.to_owned(),
                headers_matched: matched_headers,
                confidence,
            }));
        }
    }

    Some(None)
}

/// Fingerprint a domain and all its common subdomains/paths.
pub fn fingerprint_domain<T: Transport + ?Sized>(
    transport: &T,
    domain: &str,
) -> Vec<FingerprintFinding> {
    let mut findings = Vec::new();

    // Try root and common paths
    let urls = vec![
        format!("http://{domain}"),
        format!("https://{domain}"),
        format!("http://{domain}/robots.txt"),
        format!("https://{domain}/robots.txt"),
    ];

    for url in urls {
        if let Some(Some(finding)) = fingerprint(transport, &url) {
            findings.push(finding);
        }
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn confidence_levels_map_correctly() {
        let high = FingerprintFinding {
            url: "test".to_owned(),
            detected_service: "Cloudflare".to_owned(),
            category: "cdn".to_owned(),
            headers_matched: vec![],
            confidence: 0.95,
        };
        assert_eq!(high.confidence_level(), "high");

        let medium = FingerprintFinding {
            url: "test".to_owned(),
            detected_service: "Nginx".to_owned(),
            category: "webserver".to_owned(),
            headers_matched: vec![],
            confidence: 0.75,
        };
        assert_eq!(medium.confidence_level(), "medium");

        let low = FingerprintFinding {
            url: "test".to_owned(),
            detected_service: "Unknown".to_owned(),
            category: "other".to_owned(),
            headers_matched: vec![],
            confidence: 0.5,
        };
        assert_eq!(low.confidence_level(), "low");
    }

    #[test]
    fn patterns_are_well_formed() {
        for pattern in FINGERPRINT_PATTERNS {
            assert!(
                !pattern.headers.is_empty(),
                "Pattern {} has no headers",
                pattern.name
            );
            assert!(
                !pattern.header_values.is_empty(),
                "Pattern {} has no header values",
                pattern.name
            );
        }
    }
}
