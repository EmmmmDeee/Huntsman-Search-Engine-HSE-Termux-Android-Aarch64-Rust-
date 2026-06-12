//! WAF/CDN detection — fingerprint web application firewalls and CDNs
//! from HTTP response headers.
//!
//! Identifies Cloudflare, Akamai, AWS CloudFront, Fastly, Sucuri,
//! Imperva/Incapsula, and other WAF/CDN providers by inspecting
//! response headers (Server, X-Powered-By, Via, CF-RAY, etc.).
//!
//! No API key required. Single HEAD request per domain.

use async_trait::async_trait;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::RequestBuilderExt;

const SRC: &str = "waf_detect";

pub struct WafDetect;

#[async_trait]
impl Module for WafDetect {
    fn name(&self) -> &'static str {
        SRC
    }
    fn description(&self) -> &'static str {
        "Detect WAF/CDN providers from HTTP response header fingerprints"
    }
    fn priority(&self) -> u8 {
        30
    }
    fn max_timeout_ms(&self) -> u64 {
        6_000
    }
    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Domain | TargetKind::Url)
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Web
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        // Fingerprints WAFs (network security appliances) and CDNs from HTTP
        // headers — ATT&CK Network Security Appliances (T1590.006) and CDNs
        // (T1596.004), not the Web category default. Both are free/keyless.
        &["T1590.006", "T1596.004"]
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[EntityKind::Domain];
        KINDS
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let mut result = ModuleResult::new();

        let url = match target.kind {
            TargetKind::Url => target.value.clone(),
            TargetKind::Domain => format!("https://{}", target.value.trim()),
            _ => return Ok(result),
        };

        let resp = ctx.http.head(&url).send_tagged(SRC).await?;

        let headers = resp.headers();
        // Run every fingerprint predicate over the response headers and keep the
        // providers whose check fired — one functional pass, no intermediate
        // accumulator.
        let providers: Vec<&str> = FINGERPRINTS
            .iter()
            .filter(|(check_fn, _)| check_fn(headers))
            .map(|(_, provider)| *provider)
            .collect();

        if providers.is_empty() {
            return Ok(result);
        }
        // Emit the finding against the HOST, not the raw target value: for a
        // `Url` target `target.value` is the full URL (`https://host/path`),
        // which must never be stored as a `Domain` entity value (it would be a
        // malformed domain — the bug that surfaced `domain https://…/path`).
        let host = crate::util::url_util::host_from_url(&url)
            .unwrap_or_else(|| target.value.trim().to_string());
        let mut e = Entity::new(EntityKind::Domain, &host, 0.85, &ctx.scan_id);
        for provider in &providers {
            e.tag(format!("waf:{provider}"));
        }
        e.tag("waf-detected");
        e.add_evidence(
            Evidence::new(SRC, format!("WAF/CDN detected: {}", providers.join(", ")))
                .with_attr("providers", providers.join(", "))
                .with_attr(
                    "server",
                    headers
                        .get("server")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or(""),
                ),
        );
        result.push(e);

        Ok(result)
    }
}

type HeaderCheck = fn(&reqwest::header::HeaderMap) -> bool;

fn has_cloudflare(h: &reqwest::header::HeaderMap) -> bool {
    h.contains_key("cf-ray")
        || h.get("server")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|s| s.contains("cloudflare"))
}

fn has_akamai(h: &reqwest::header::HeaderMap) -> bool {
    h.contains_key("x-akamai-transformed")
        || h.get("server")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|s| s.contains("AkamaiGHost"))
}

fn has_cloudfront(h: &reqwest::header::HeaderMap) -> bool {
    h.contains_key("x-amz-cf-id") || h.contains_key("x-amz-cf-pop")
}

fn has_fastly(h: &reqwest::header::HeaderMap) -> bool {
    h.contains_key("x-fastly-request-id")
        || h.get("via")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|s| s.contains("varnish"))
}

fn has_sucuri(h: &reqwest::header::HeaderMap) -> bool {
    h.contains_key("x-sucuri-id")
        || h.get("server")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|s| s.contains("Sucuri"))
}

fn has_incapsula(h: &reqwest::header::HeaderMap) -> bool {
    h.contains_key("x-iinfo")
        || h.get("x-cdn")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|s| s.contains("Incapsula"))
}

fn has_ddos_guard(h: &reqwest::header::HeaderMap) -> bool {
    h.get("server")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|s| s.contains("ddos-guard"))
}

fn has_stackpath(h: &reqwest::header::HeaderMap) -> bool {
    h.contains_key("x-sp-url") || h.contains_key("x-sp-waf")
}

const FINGERPRINTS: &[(HeaderCheck, &str)] = &[
    (has_cloudflare, "Cloudflare"),
    (has_akamai, "Akamai"),
    (has_cloudfront, "CloudFront"),
    (has_fastly, "Fastly"),
    (has_sucuri, "Sucuri"),
    (has_incapsula, "Imperva/Incapsula"),
    (has_ddos_guard, "DDoS-Guard"),
    (has_stackpath, "StackPath"),
];

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::header::{HeaderMap, HeaderValue};

    #[test]
    fn detect_cloudflare() {
        let mut h = HeaderMap::new();
        h.insert("cf-ray", HeaderValue::from_static("abc123"));
        assert!(has_cloudflare(&h));
    }

    #[test]
    fn detect_cloudfront() {
        let mut h = HeaderMap::new();
        h.insert("x-amz-cf-id", HeaderValue::from_static("xyz"));
        assert!(has_cloudfront(&h));
    }

    #[test]
    fn no_waf_detected() {
        let h = HeaderMap::new();
        assert!(!has_cloudflare(&h));
        assert!(!has_akamai(&h));
        assert!(!has_cloudfront(&h));
    }

    #[test]
    fn fingerprint_table_non_empty() {
        assert!(FINGERPRINTS.len() >= 8);
    }

    #[tokio::test]
    async fn module_metadata() {
        let m = WafDetect;
        assert!(m.accepts(&Target::new(TargetKind::Domain, "example.com")));
        assert!(m.accepts(&Target::new(TargetKind::Url, "https://example.com")));
        assert!(!m.accepts(&Target::new(TargetKind::Email, "x@y.com")));
    }
}
