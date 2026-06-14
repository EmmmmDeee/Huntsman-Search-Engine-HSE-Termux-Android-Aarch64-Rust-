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
            // Surface any API keys leaked in response headers (credentials are
            // high-value seeds) before deciding whether the banner is useful.
            resp.headers()
                .values()
                .filter_map(|v| v.to_str().ok())
                .for_each(|val| {
                    crate::util::http::scan_for_api_keys_with_source(val, "http_header")
                });
            if captured.is_empty() {
                continue;
            }

            let mut entity = target.to_entity(0.85, &ctx.scan_id);
            entity.tag(crate::core::tags::WEB);
            apply_stack_tags(&mut entity, &captured);

            // Fold each captured header into the evidence, clipping individual
            // values so a verbose CSP doesn't bloat the row past sanity.
            let ev = captured.iter().fold(
                Evidence::new(SRC, format!("HTTP headers from {scheme} HEAD of {host}"))
                    .with_attr("scheme", scheme)
                    .with_attr("status", status.as_u16().to_string()),
                |ev, (h, v)| ev.with_attr(h.as_str(), v.chars().take(240).collect::<String>()),
            );
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
    FINGERPRINT_HEADERS
        .iter()
        .filter_map(|name| {
            let s = h.get(*name)?.to_str().ok()?;
            (!s.is_empty()).then(|| ((*name).to_string(), s.to_string()))
        })
        .collect()
}

fn apply_stack_tags(e: &mut Entity, headers: &[(String, String)]) {
    // Lower-case every header value and join them into one searchable blob.
    let blob: String = headers
        .iter()
        .map(|(_, v)| v.to_ascii_lowercase())
        .collect::<Vec<_>>()
        .join("|");
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
    include!("tests.rs");
}
