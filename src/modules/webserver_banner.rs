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
    entity::{Entity, EntityKind, Evidence},
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

    fn produces(&self) -> &'static [EntityKind] {
        // Re-emits the target (Domain / IpAddress / Url) enriched with banner
        // evidence via `to_entity`.
        const KINDS: &[EntityKind] = &[EntityKind::Domain, EntityKind::IpAddress, EntityKind::Url];
        KINDS
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let Some((host, port)) = extract_host_port(target.kind, &target.value) else {
            return Ok(ModuleResult::new());
        };

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

/// Resolve a target to the `(host, optional port)` to probe. **Pure** (no
/// network/IO): a `Url` is parsed and its host + explicit port taken; any other
/// kind is used verbatim. Returns `None` for an unparseable URL or a host that is
/// empty or path-shaped (contains `/`), the cases where there is nothing to HEAD.
fn extract_host_port(kind: TargetKind, value: &str) -> Option<(String, Option<u16>)> {
    let (host, port) = match kind {
        TargetKind::Url => {
            let u = url::Url::parse(value.trim()).ok()?;
            (u.host_str().unwrap_or("").to_string(), u.port())
        }
        _ => (value.trim().to_string(), None),
    };
    if host.is_empty() || host.contains('/') {
        return None;
    }
    Some((host, port))
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

    fn tags_for(headers: &[(&str, &str)]) -> Entity {
        let mut e = Entity::new(EntityKind::Domain, "x.com", 0.5, "s");
        let owned: Vec<(String, String)> = headers
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect();
        apply_stack_tags(&mut e, &owned);
        e
    }

    #[test]
    fn apply_stack_tags_covers_full_signature_set() {
        // IIS via Server value, ASP.NET via header name.
        let e = tags_for(&[
            ("server", "Microsoft-IIS/10.0"),
            ("x-aspnet-version", "4.0.30319"),
        ]);
        assert!(e.has_tag("iis") && e.has_tag("aspnet"));

        // Cloudflare via Server value (not just cf-ray).
        assert!(tags_for(&[("server", "cloudflare")]).has_tag("cloudflare"));
        // AWS CloudFront + Fastly are header-name driven.
        assert!(tags_for(&[("x-amz-cf-id", "abc")]).has_tag("aws-cloudfront"));
        assert!(tags_for(&[("x-served-by", "cache-syd")]).has_tag("fastly"));
        assert!(tags_for(&[("x-cache", "HIT")]).has_tag("fastly"));
        // CMS fingerprints in any header value.
        assert!(tags_for(&[("x-generator", "WordPress 6.5")]).has_tag("wordpress"));
        assert!(tags_for(&[("x-generator", "Drupal 10 (https://drupal.org)")]).has_tag("drupal"));
        // Apache.
        assert!(tags_for(&[("server", "Apache/2.4.52")]).has_tag("apache"));
    }

    #[test]
    fn apply_stack_tags_is_case_insensitive_and_quiet_on_unknown() {
        assert!(tags_for(&[("server", "NGINX/1.25")]).has_tag("nginx"));
        // An unrecognised stack raises none of the family tags.
        let e = tags_for(&[("server", "GoatServer/1.0")]);
        for t in ["nginx", "apache", "iis", "cloudflare", "wordpress", "php"] {
            assert!(!e.has_tag(t), "unexpected tag {t}");
        }
    }

    #[test]
    fn capture_headers_keeps_only_fingerprint_headers_nonempty() {
        use reqwest::header::{HeaderMap, HeaderValue};
        let mut h = HeaderMap::new();
        h.insert("server", HeaderValue::from_static("nginx"));
        h.insert("content-type", HeaderValue::from_static("text/html")); // not fingerprint
        h.insert("x-powered-by", HeaderValue::from_static("")); // empty → dropped
        let got = capture_headers(&h);
        assert_eq!(got, vec![("server".to_string(), "nginx".to_string())]);
    }

    #[test]
    fn extract_host_port_handles_url_domain_and_rejects_junk() {
        // URL with explicit port.
        assert_eq!(
            extract_host_port(TargetKind::Url, "https://example.com:8443/a"),
            Some(("example.com".to_string(), Some(8443)))
        );
        // URL without explicit port → None port.
        assert_eq!(
            extract_host_port(TargetKind::Url, "http://host.org/"),
            Some(("host.org".to_string(), None))
        );
        // Bare domain.
        assert_eq!(
            extract_host_port(TargetKind::Domain, "  example.com "),
            Some(("example.com".to_string(), None))
        );
        // Unparseable URL and a path-shaped domain → nothing to probe.
        assert_eq!(extract_host_port(TargetKind::Url, "not a url"), None);
        assert_eq!(extract_host_port(TargetKind::Domain, "x.com/path"), None);
        assert_eq!(extract_host_port(TargetKind::Domain, "  "), None);
    }
}
