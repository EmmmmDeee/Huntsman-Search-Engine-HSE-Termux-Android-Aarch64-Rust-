//! HTTP server fingerprint via a single HEAD request.
//!
//! Captures the response headers that reliably identify the running
//! stack — `Server`, `X-Powered-By`, `X-Generator`, etc. — plus the
//! security-posture headers (`X-Frame-Options`, `Content-Security-Policy`,
//! `Strict-Transport-Security`, `X-AspNet-Version`).
//!
//! Tries HTTPS first, falls back to plain HTTP. Even 4xx/5xx responses
//! leak useful headers so we only abort if the host refuses both
//! schemes outright.
//!
//! Tagged outputs (`nginx`, `apache`, `iis`, `cloudflare`, `wordpress`)
//! let the Browse tab filter on stack family.

use async_trait::async_trait;

use crate::core::{
    entity::{Entity, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};

const SRC: &str = "webserver_banner";

pub struct WebserverBanner;

/// Headers we surface as evidence. Lower-case because `reqwest`
/// canonicalises header names that way internally.
const FINGERPRINT_HEADERS: &[&str] = &[
    "server",
    "x-powered-by",
    "x-generator",
    "x-aspnet-version",
    "x-aspnetmvc-version",
    "x-frame-options",
    "content-security-policy",
    "strict-transport-security",
    "via",
    "cf-ray",
    "x-amz-cf-id",
    "x-served-by",
    "x-cache",
];

#[async_trait]
impl Module for WebserverBanner {
    fn name(&self) -> &'static str {
        "webserver_banner"
    }

    fn description(&self) -> &'static str {
        "HTTP header fingerprinting and tech stack detection"
    }

    fn priority(&self) -> u8 {
        36
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(
            t.kind,
            TargetKind::Domain | TargetKind::IpAddress | TargetKind::Url
        )
    }

    fn max_timeout_ms(&self) -> u64 {
        // Two HEAD attempts (HTTPS → HTTP fallback). Each on a fresh
        // socket if the connection pool is empty.
        6_000
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Web
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let (host, port) = match target.kind {
            TargetKind::Url => match url::Url::parse(target.value.trim()) {
                Ok(u) => (u.host_str().unwrap_or("").to_string(), u.port()),
                Err(_) => return Ok(ModuleResult::new()),
            },
            _ => (target.value.trim().to_string(), None),
        };
        if host.is_empty() || host.contains('/') {
            return Ok(ModuleResult::new());
        }

        let port_suffix = port.map_or(String::new(), |p| format!(":{p}"));
        for scheme in ["https", "http"] {
            let url = format!("{scheme}://{host}{port_suffix}/");
            let Ok(resp) = ctx.http.head(&url).send().await else {
                continue;
            };
            let status = resp.status();
            let captured = capture_headers(resp.headers());
            for (_, v) in resp.headers() {
                if let Ok(val) = v.to_str() {
                    crate::util::http::scan_for_api_keys_with_source(val, "http_header");
                }
            }
            if captured.is_empty() {
                continue;
            }

            let mut entity = target.to_entity(0.85, &ctx.scan_id);
            entity.tag(crate::core::tags::WEB);
            apply_stack_tags(&mut entity, &captured);

            let mut ev = Evidence::new(SRC, format!("HTTP headers from {scheme} HEAD of {host}"))
                .with_attr("scheme", scheme)
                .with_attr("status", status.as_u16().to_string());
            for (h, v) in &captured {
                // Clip individual values so a verbose CSP doesn't bloat
                // the evidence row past sanity.
                let clipped: String = v.chars().take(240).collect();
                ev = ev.with_attr(h.as_str(), clipped);
            }
            entity.add_evidence(ev);

            let mut result = ModuleResult::new();
            result.push(entity);
            return Ok(result);
        }
        Ok(ModuleResult::new())
    }
}

fn capture_headers(h: &reqwest::header::HeaderMap) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::with_capacity(FINGERPRINT_HEADERS.len());
    for name in FINGERPRINT_HEADERS {
        if let Some(v) = h.get(*name)
            && let Ok(s) = v.to_str()
            && !s.is_empty()
        {
            out.push(((*name).to_string(), s.to_string()));
        }
    }
    out
}

fn apply_stack_tags(e: &mut Entity, headers: &[(String, String)]) {
    let mut blob = String::with_capacity(headers.iter().map(|(_, v)| v.len() + 1).sum());
    for (i, (_, v)) in headers.iter().enumerate() {
        if i > 0 {
            blob.push('|');
        }
        for c in v.chars() {
            blob.push(c.to_ascii_lowercase());
        }
    }
    let names: Vec<&str> = headers.iter().map(|(n, _)| n.as_str()).collect();
    if blob.contains("nginx") {
        e.tag("nginx");
    }
    if blob.contains("apache") {
        e.tag("apache");
    }
    if blob.contains("microsoft-iis") || blob.contains("iis/") {
        e.tag("iis");
    }
    if blob.contains("cloudflare") || names.contains(&"cf-ray") {
        e.tag("cloudflare");
    }
    if names.contains(&"x-amz-cf-id") {
        e.tag("aws-cloudfront");
    }
    if names.contains(&"x-served-by") || names.contains(&"x-cache") {
        e.tag("fastly");
    }
    if blob.contains("wordpress") {
        e.tag("wordpress");
    }
    if blob.contains("drupal") {
        e.tag("drupal");
    }
    if blob.contains("php") {
        e.tag("php");
    }
    if blob.contains("aspnet") || names.contains(&"x-aspnet-version") {
        e.tag("aspnet");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::entity::EntityKind;

    #[test]
    fn accepts_domain_ip_and_url() {
        let m = WebserverBanner;
        assert!(m.accepts(&Target::new(TargetKind::Domain, "x")));
        assert!(m.accepts(&Target::new(TargetKind::IpAddress, "1.1.1.1")));
        assert!(m.accepts(&Target::new(TargetKind::Url, "https://example.com/path")));
        assert!(!m.accepts(&Target::new(TargetKind::Email, "a@b")));
    }

    #[test]
    fn apply_stack_tags_recognises_common_stacks() {
        let mut e = Entity::new(EntityKind::Domain, "x.com", 0.5, "s");
        apply_stack_tags(
            &mut e,
            &[
                ("server".into(), "nginx/1.18.0".into()),
                ("x-powered-by".into(), "PHP/8.1.0".into()),
            ],
        );
        assert!(e.has_tag("nginx"));
        assert!(e.has_tag("php"));
        assert!(!e.has_tag("iis"));
    }

    #[test]
    fn apply_stack_tags_recognises_cdns() {
        let mut e = Entity::new(EntityKind::Domain, "x.com", 0.5, "s");
        apply_stack_tags(&mut e, &[("cf-ray".into(), "1234abcd".into())]);
        assert!(e.has_tag("cloudflare"));
    }
}
