//! Subdomain takeover detection — check if CNAME targets point to
//! unclaimed cloud services (S3, Azure, Heroku, GitHub Pages, etc.).
//!
//! When a subdomain has a CNAME pointing to a cloud provider but the
//! underlying resource is unclaimed, an attacker can register it and
//! serve content on the victim's subdomain. This module checks DNS
//! CNAME records against known vulnerable fingerprints.
//!
//! No API key required. Uses DNS resolution + HTTP fingerprint check.

use async_trait::async_trait;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};

const SRC: &str = "subdomain_takeover";

pub struct SubdomainTakeover;

/// One takeover fingerprint: the CNAME substring that points at a cloud
/// provider, the human-readable service name, and the HTTP body marker that
/// proves the resource is unclaimed (`None` ⇒ prove via NXDOMAIN instead).
type Fingerprint = (&'static str, &'static str, Option<&'static str>);

/// The fingerprints whose CNAME pattern is a substring of `cname_target`, in
/// table order. **Pure** — the pattern-matching half of detection, split out so
/// the "which providers does this CNAME implicate" logic is testable without
/// DNS or HTTP. The caller still runs each candidate's (network) claim check.
fn matching_fingerprints(cname_target: &str) -> impl Iterator<Item = &'static Fingerprint> {
    TAKEOVER_FINGERPRINTS
        .iter()
        .filter(move |(pattern, _, _)| cname_target.contains(pattern))
}

/// Build the vulnerable-subdomain entity once a dangling CNAME has been
/// confirmed claimable. **Pure** (no network), so the
/// CNAME→tag→evidence mapping is unit-testable directly.
///
/// Emits a single `Domain` entity for `domain` tagged `vulnerable` +
/// `subdomain-takeover` + `takeover:<service>`, carrying the CNAME target and
/// service as evidence. A blank `service` adds no `takeover:` tag and no
/// `service` attr; a blank `cname_target` adds no `cname_target` attr.
fn build_entities(domain: &str, cname_target: &str, service: &str, scan_id: &str) -> Vec<Entity> {
    let mut e = Entity::new(EntityKind::Domain, domain, 0.90, scan_id);
    e.tag(crate::core::tags::VULNERABLE);
    e.tag("subdomain-takeover");
    if !service.is_empty() {
        e.tag(format!("takeover:{service}"));
    }
    let mut ev = Evidence::new(
        SRC,
        format!("CNAME {domain} points to {cname_target} — {service} may be claimable"),
    );
    if !cname_target.is_empty() {
        ev = ev.with_attr("cname_target", cname_target);
    }
    if !service.is_empty() {
        ev = ev.with_attr("service", service);
    }
    e.add_evidence(ev);
    vec![e]
}

#[async_trait]
impl Module for SubdomainTakeover {
    fn name(&self) -> &'static str {
        SRC
    }
    fn description(&self) -> &'static str {
        "Detect subdomain takeover via dangling CNAME fingerprinting"
    }
    fn priority(&self) -> u8 {
        40
    }
    fn max_timeout_ms(&self) -> u64 {
        8_000
    }
    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Domain)
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::DnsRecon
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        // Subdomain/domain-property inspection — ATT&CK Domain Properties (T1590.001).
        &["T1590.001"]
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[EntityKind::Domain];
        KINDS
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let mut result = ModuleResult::new();
        let domain = target.value.clone();

        if domain.is_empty() || !domain.contains('.') {
            return Ok(result);
        }

        let resolver = crate::util::dns::shared_resolver();
        // Resolve the CNAME chain and take the first CNAME answer, normalised to
        // a trailing-dot-free lower-case host. A lookup error (NXDOMAIN, no
        // CNAME) collapses to `None` and short-circuits below.
        let cname = resolver
            .lookup(&domain, hickory_resolver::proto::rr::RecordType::CNAME)
            .await
            .ok()
            .and_then(|lookup| {
                lookup.answers().iter().find_map(|record| {
                    if let hickory_resolver::proto::rr::RData::CNAME(ref c) = record.data {
                        Some(c.0.to_ascii().trim_end_matches('.').to_lowercase())
                    } else {
                        None
                    }
                })
            });

        let Some(cname_target) = cname else {
            return Ok(result);
        };

        for &(_, service, fingerprint_path) in matching_fingerprints(&cname_target) {
            let vulnerable = if let Some(path) = fingerprint_path {
                check_http_fingerprint(&ctx.http, &domain, path).await
            } else {
                check_nxdomain(&cname_target).await
            };

            if vulnerable {
                result.extend(build_entities(
                    &domain,
                    &cname_target,
                    service,
                    &ctx.scan_id,
                ));
                break;
            }
        }

        Ok(result)
    }
}

async fn check_nxdomain(cname_target: &str) -> bool {
    let resolver = crate::util::dns::shared_resolver();
    resolver.lookup_ip(cname_target).await.is_err()
}

async fn check_http_fingerprint(http: &reqwest::Client, domain: &str, fingerprint: &str) -> bool {
    let url = format!("http://{domain}");
    match tokio::time::timeout(std::time::Duration::from_secs(5), http.get(&url).send()).await {
        Ok(Ok(resp)) => {
            if let Some(body) = crate::util::http::read_body_capped(resp, 256 * 1024).await {
                body.contains(fingerprint)
            } else {
                false
            }
        }
        _ => false,
    }
}

const TAKEOVER_FINGERPRINTS: &[(&str, &str, Option<&str>)] = &[
    // (CNAME pattern, service name, HTTP body fingerprint or None for NXDOMAIN check)
    ("s3.amazonaws.com", "AWS S3", Some("NoSuchBucket")),
    ("s3-website", "AWS S3 Website", Some("NoSuchBucket")),
    (".herokuapp.com", "Heroku", Some("no-such-app")),
    (".herokudns.com", "Heroku DNS", Some("no-such-app")),
    (
        "github.io",
        "GitHub Pages",
        Some("There isn't a GitHub Pages site here"),
    ),
    (
        ".azurewebsites.net",
        "Azure App Service",
        Some("404 Web Site not found"),
    ),
    (".cloudapp.net", "Azure Cloud", None),
    (
        ".trafficmanager.net",
        "Azure Traffic Manager",
        Some("404 Web Site not found"),
    ),
    (".blob.core.windows.net", "Azure Blob", Some("BlobNotFound")),
    (".cloudfront.net", "AWS CloudFront", Some("Bad request")),
    (".elasticbeanstalk.com", "AWS Elastic Beanstalk", None),
    (".ghost.io", "Ghost", Some("404 error")),
    (
        ".myshopify.com",
        "Shopify",
        Some("Sorry, this shop is currently unavailable"),
    ),
    (".surge.sh", "Surge.sh", Some("project not found")),
    (".bitbucket.io", "Bitbucket", Some("Repository not found")),
    (".netlify.app", "Netlify", Some("Not Found")),
    (".netlify.com", "Netlify", Some("Not Found")),
    (".pantheonsite.io", "Pantheon", Some("404 error")),
    (
        ".wordpress.com",
        "WordPress",
        Some("Do you want to register"),
    ),
    (".tumblr.com", "Tumblr", Some("There's nothing here")),
    (".fly.dev", "Fly.io", None),
    (".vercel.app", "Vercel", Some("404")),
    (".render.com", "Render", Some("not found")),
    (".pages.dev", "Cloudflare Pages", None),
];

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
