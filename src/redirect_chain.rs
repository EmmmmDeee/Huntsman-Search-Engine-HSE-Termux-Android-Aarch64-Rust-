//! HTTP redirect chain analysis: detect redirect loops, cross-domain redirects, and anomalies.
//!
//! Follows HTTP redirect chains to identify security issues like open redirects,
//! redirect loops, suspicious cross-domain redirects, and infrastructure patterns.

use std::collections::HashSet;
use std::time::Duration;

use crate::http::{Request, Transport};

const MAX_HOPS: usize = 10;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedirectChain {
    pub start_url: String,
    pub final_url: String,
    pub hops: Vec<RedirectHop>,
    pub anomaly: Option<RedirectAnomaly>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedirectHop {
    pub source_url: String,
    pub status_code: u16,
    pub target_url: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedirectAnomaly {
    /// Redirect loop detected (same URL appears twice)
    Loop,
    /// Exceeds max hops limit
    DepthExceeded,
    /// Redirects to external domain
    CrossDomainRedirect,
    /// Status code indicates client error before redirect
    ClientError,
    /// Suspicious redirect pattern detected
    Suspicious,
}

impl RedirectAnomaly {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Loop => "redirect_loop",
            Self::DepthExceeded => "depth_exceeded",
            Self::CrossDomainRedirect => "cross_domain_redirect",
            Self::ClientError => "client_error",
            Self::Suspicious => "suspicious",
        }
    }
}

/// Extract domain from a URL for comparison.
fn extract_domain(url: &str) -> Option<String> {
    url.split("://")
        .nth(1)
        .and_then(|rest| rest.split('/').next())
        .map(str::to_lowercase)
}

/// Base for resolving a relative reference: the URL with its last path segment removed.
fn relative_base(url: &str) -> Option<String> {
    let authority_start = url.find("://")? + 3;
    let base_len = url[authority_start..]
        .rfind('/')
        .map_or(url.len(), |i| authority_start + i);
    Some(url[..base_len].to_owned())
}

/// Follow redirect chain for a URL, up to `MAX_HOPS`.
#[must_use]
pub fn follow_redirects<T: Transport + ?Sized>(
    transport: &T,
    start_url: &str,
) -> Option<RedirectChain> {
    let mut hops = Vec::new();
    let mut current_url = start_url.to_string();
    let mut seen_urls = HashSet::new();
    let mut anomaly = None;

    let start_domain = extract_domain(start_url)?;

    for _ in 0..MAX_HOPS {
        // Check for loops
        if seen_urls.contains(&current_url) {
            anomaly = Some(RedirectAnomaly::Loop);
            break;
        }
        seen_urls.insert(current_url.clone());

        // Make request
        let mut request = Request::get(&current_url);
        request.timeout = Some(Duration::from_secs(3));

        let response = transport.send(&request).ok()?;

        // Check for non-3xx status codes
        if response.status < 300 || response.status >= 400 {
            if response.status >= 400 {
                anomaly = Some(RedirectAnomaly::ClientError);
            }
            // Not a redirect, chain ends
            let final_url = current_url.clone();
            return Some(RedirectChain {
                start_url: start_url.to_string(),
                final_url,
                hops,
                anomaly,
            });
        }

        // Get Location header
        let Some(location) = response.header_value("location").map(str::to_owned) else {
            // Redirect without Location header
            return Some(RedirectChain {
                start_url: start_url.to_string(),
                final_url: current_url,
                hops,
                anomaly: Some(RedirectAnomaly::Suspicious),
            });
        };

        // Resolve relative URLs
        let target_url = if location.starts_with("http://") || location.starts_with("https://") {
            location.clone()
        } else if location.starts_with('/') {
            let domain = extract_domain(&current_url)?;
            let scheme = if current_url.starts_with("https") {
                "https"
            } else {
                "http"
            };
            format!("{scheme}://{domain}{location}")
        } else {
            let base = relative_base(&current_url)?;
            format!("{base}/{location}")
        };

        // Check for cross-domain redirects
        if let Some(target_domain) = extract_domain(&target_url) {
            if target_domain != start_domain && anomaly.is_none() {
                anomaly = Some(RedirectAnomaly::CrossDomainRedirect);
            }
        }

        hops.push(RedirectHop {
            source_url: current_url.clone(),
            status_code: response.status,
            target_url: target_url.clone(),
        });

        current_url = target_url;
    }

    // Exceeded max hops
    if anomaly.is_none() {
        anomaly = Some(RedirectAnomaly::DepthExceeded);
    }

    Some(RedirectChain {
        start_url: start_url.to_string(),
        final_url: current_url,
        hops,
        anomaly,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_domain_parses_urls_correctly() {
        assert_eq!(
            extract_domain("https://example.com/path"),
            Some("example.com".to_string())
        );
        assert_eq!(
            extract_domain("http://sub.example.com:8080/path"),
            Some("sub.example.com:8080".to_string())
        );
        assert_eq!(extract_domain("invalid"), None);
    }

    #[test]
    fn redirect_anomaly_strings_are_consistent() {
        assert_eq!(RedirectAnomaly::Loop.as_str(), "redirect_loop");
        assert_eq!(RedirectAnomaly::DepthExceeded.as_str(), "depth_exceeded");
        assert_eq!(
            RedirectAnomaly::CrossDomainRedirect.as_str(),
            "cross_domain_redirect"
        );
        assert_eq!(RedirectAnomaly::ClientError.as_str(), "client_error");
        assert_eq!(RedirectAnomaly::Suspicious.as_str(), "suspicious");
    }

    #[test]
    fn relative_base_strips_only_the_last_path_segment() {
        assert_eq!(
            relative_base("https://example.com/a/b"),
            Some("https://example.com/a".to_string())
        );
        assert_eq!(
            relative_base("https://example.com/"),
            Some("https://example.com".to_string())
        );
        assert_eq!(
            relative_base("https://example.com"),
            Some("https://example.com".to_string())
        );
        assert_eq!(relative_base("invalid"), None);
    }
}
