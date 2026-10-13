//! HTTP redirect chain analysis: detect redirect loops, cross-domain redirects, and anomalies.
//!
//! Follows HTTP redirect chains to identify security issues like open redirects,
//! redirect loops, suspicious cross-domain redirects, and infrastructure patterns.
//! The transport never follows redirects itself, so every hop is observed here.

use std::collections::HashSet;
use std::time::Duration;

use crate::http::{Request, Transport, parse_http_uri, resolve_location};

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
    /// Redirect without a usable `Location` (absent, or not an http(s) URL)
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

/// Lower-cased host of an absolute http(s) URL, without the port.
#[must_use]
pub fn host_of(url: &str) -> Option<String> {
    parse_http_uri(url)
        .ok()?
        .host()
        .map(str::to_ascii_lowercase)
}

/// Follow the redirect chain from `start_url`, up to `MAX_HOPS`.
///
/// `None` when `start_url` is not an absolute http(s) URL or the first request
/// obtains no response at all.
#[must_use]
pub fn follow_redirects<T: Transport + ?Sized>(
    transport: &T,
    start_url: &str,
) -> Option<RedirectChain> {
    let start_host = host_of(start_url)?;
    let mut hops = Vec::new();
    let mut current_url = start_url.to_owned();
    let mut seen_urls = HashSet::new();
    let mut anomaly = None;

    let finish = |final_url: String, hops, anomaly| {
        Some(RedirectChain {
            start_url: start_url.to_owned(),
            final_url,
            hops,
            anomaly,
        })
    };

    for _ in 0..MAX_HOPS {
        if !seen_urls.insert(current_url.clone()) {
            return finish(current_url, hops, Some(RedirectAnomaly::Loop));
        }

        let mut request = Request::get(&current_url);
        request.timeout = Some(Duration::from_secs(3));
        let response = transport.send(&request).ok()?;

        if !(300..400).contains(&response.status) {
            if response.status >= 400 {
                anomaly = Some(RedirectAnomaly::ClientError);
            }
            return finish(current_url, hops, anomaly);
        }

        let Some(location) = response.header_value("location") else {
            return finish(current_url, hops, Some(RedirectAnomaly::Suspicious));
        };
        let Ok(target_url) = resolve_location(&current_url, location) else {
            return finish(current_url, hops, Some(RedirectAnomaly::Suspicious));
        };

        if anomaly.is_none() && host_of(&target_url).as_deref() != Some(start_host.as_str()) {
            anomaly = Some(RedirectAnomaly::CrossDomainRedirect);
        }

        hops.push(RedirectHop {
            source_url: current_url,
            status_code: response.status,
            target_url: target_url.clone(),
        });
        current_url = target_url;
    }

    finish(
        current_url,
        hops,
        anomaly.or(Some(RedirectAnomaly::DepthExceeded)),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::{Response, TransportFailure};

    /// Answers each listed URL with its status and `Location`; any other URL is a 200.
    struct Hops(Vec<(String, u16, Option<String>)>);

    impl Hops {
        fn new(rows: &[(&str, u16, Option<&str>)]) -> Self {
            Self(
                rows.iter()
                    .map(|(u, s, l)| ((*u).to_owned(), *s, l.map(str::to_owned)))
                    .collect(),
            )
        }
    }

    impl Transport for Hops {
        fn send(&self, request: &Request) -> Result<Response, TransportFailure> {
            let (status, location) = self
                .0
                .iter()
                .find(|(url, _, _)| *url == request.url)
                .map_or((200, None), |(_, s, l)| (*s, l.clone()));
            Ok(Response {
                status,
                headers: location
                    .map(|l| vec![("Location".to_owned(), l)])
                    .unwrap_or_default(),
                body: Vec::new(),
                truncated: false,
            })
        }
    }

    fn chain(rows: &[(&str, u16, Option<&str>)], start: &str) -> RedirectChain {
        follow_redirects(&Hops::new(rows), start).expect("start url is absolute http(s)")
    }

    #[test]
    fn host_of_drops_port_and_case_and_rejects_non_urls() {
        assert_eq!(
            host_of("https://Example.com/path"),
            Some("example.com".to_string())
        );
        assert_eq!(
            host_of("http://sub.example.com:8080/path"),
            Some("sub.example.com".to_string())
        );
        assert_eq!(host_of("invalid"), None);
        assert_eq!(host_of("ftp://example.com/"), None);
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
    fn a_relative_location_resolves_against_the_directory_not_the_last_segment() {
        let got = chain(
            &[("https://example.com/a/b", 302, Some("c"))],
            "https://example.com/a/b",
        );
        assert_eq!(got.final_url, "https://example.com/a/c");
        assert_eq!(got.hops.len(), 1);
        assert_eq!(got.hops[0].status_code, 302);
        assert_eq!(got.anomaly, None);
    }

    #[test]
    fn absolute_path_then_protocol_relative_location_crosses_domains() {
        let got = chain(
            &[
                ("http://example.com", 301, Some("/x")),
                ("http://example.com/x", 302, Some("//cdn.example.net/y")),
            ],
            "http://example.com",
        );
        assert_eq!(got.final_url, "http://cdn.example.net/y");
        assert_eq!(got.hops.len(), 2);
        assert_eq!(got.hops[0].target_url, "http://example.com/x");
        assert_eq!(got.anomaly, Some(RedirectAnomaly::CrossDomainRedirect));
    }

    #[test]
    fn a_scheme_upgrade_on_the_same_host_is_not_cross_domain() {
        let got = chain(
            &[("http://example.com", 301, Some("https://example.com/"))],
            "http://example.com",
        );
        assert_eq!(got.final_url, "https://example.com/");
        assert_eq!(got.anomaly, None);
    }

    #[test]
    fn a_loop_stops_at_the_repeated_url() {
        let got = chain(
            &[
                ("https://example.com/a", 302, Some("/b")),
                ("https://example.com/b", 302, Some("/a")),
            ],
            "https://example.com/a",
        );
        assert_eq!(got.anomaly, Some(RedirectAnomaly::Loop));
        assert_eq!(got.hops.len(), 2);
        assert_eq!(got.final_url, "https://example.com/a");
    }

    #[test]
    fn a_redirect_without_a_usable_location_is_suspicious() {
        let absent = chain(&[("https://example.com", 302, None)], "https://example.com");
        assert_eq!(absent.anomaly, Some(RedirectAnomaly::Suspicious));
        assert!(absent.hops.is_empty());

        let script = chain(
            &[("https://example.com", 302, Some("javascript:alert(1)"))],
            "https://example.com",
        );
        assert_eq!(script.anomaly, Some(RedirectAnomaly::Suspicious));
        assert!(script.hops.is_empty());
    }

    #[test]
    fn a_client_error_ends_the_chain_as_client_error() {
        let got = chain(
            &[
                ("https://example.com", 301, Some("/gone")),
                ("https://example.com/gone", 404, None),
            ],
            "https://example.com",
        );
        assert_eq!(got.anomaly, Some(RedirectAnomaly::ClientError));
        assert_eq!(got.hops.len(), 1);
    }

    #[test]
    fn a_chain_longer_than_max_hops_is_depth_exceeded() {
        let rows: Vec<(String, u16, Option<String>)> = (0..=MAX_HOPS)
            .map(|i| {
                (
                    format!("https://example.com/{i}"),
                    302,
                    Some(format!("/{}", i + 1)),
                )
            })
            .collect();
        let got = follow_redirects(&Hops(rows), "https://example.com/0").expect("absolute");
        assert_eq!(got.anomaly, Some(RedirectAnomaly::DepthExceeded));
        assert_eq!(got.hops.len(), MAX_HOPS);
    }

    #[test]
    fn a_non_http_start_url_is_none() {
        assert_eq!(follow_redirects(&Hops::new(&[]), "example.com"), None);
    }
}
