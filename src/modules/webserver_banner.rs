use async_trait::async_trait;

use crate::core::{
    entity::{Entity, Evidence},
    error::Result,
    module::{Module, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};

pub struct WebserverBanner;

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
        matches!(t.kind, TargetKind::Domain)
    }

    fn max_timeout_ms(&self) -> u64 {
        6_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let domain = target.value.trim();
        if domain.is_empty() || domain.contains('/') {
            return Ok(ModuleResult::new());
        }

        for scheme in ["https", "http"] {
            let url = format!("{scheme}://{domain}/");
            let Ok(resp) = ctx.http.head(&url).send().await else {
                continue;
            };
            let status = resp.status();
            let captured = capture_headers(resp.headers());
            if captured.is_empty() {
                continue;
            }

            let mut entity = target.to_entity(0.85, &ctx.scan_id);
            entity.tag(crate::core::tags::WEB);
            apply_stack_tags(&mut entity, &captured);

            let mut ev = Evidence::new(
                "webserver_banner",
                format!("HTTP headers from {scheme} HEAD of {domain}"),
            )
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
    e.tag_if(blob.contains("nginx"), "nginx");
    e.tag_if(blob.contains("apache"), "apache");
    e.tag_if(
        blob.contains("microsoft-iis") || blob.contains("iis/"),
        "iis",
    );
    e.tag_if(
        blob.contains("cloudflare") || names.contains(&"cf-ray"),
        "cloudflare",
    );
    e.tag_if(names.contains(&"x-amz-cf-id"), "aws-cloudfront");
    e.tag_if(
        names.contains(&"x-served-by") || names.contains(&"x-cache"),
        "fastly",
    );
    e.tag_if(blob.contains("wordpress"), "wordpress");
    e.tag_if(blob.contains("drupal"), "drupal");
    e.tag_if(blob.contains("php"), "php");
    e.tag_if(
        blob.contains("aspnet") || names.contains(&"x-aspnet-version"),
        "aspnet",
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::entity::EntityKind;

    #[test]
    fn accepts_only_domain() {
        let m = WebserverBanner;
        assert!(m.accepts(&Target::new(TargetKind::Domain, "x")));
        assert!(!m.accepts(&Target::new(TargetKind::IpAddress, "1.1.1.1")));
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
