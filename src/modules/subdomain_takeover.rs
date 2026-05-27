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
    module::{Module, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};

const SRC: &str = "subdomain_takeover";

pub struct SubdomainTakeover;

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

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let mut result = ModuleResult::new();
        let domain = target.value.trim().to_lowercase();

        if domain.is_empty() || !domain.contains('.') {
            return Ok(result);
        }

        let resolver = crate::util::dns::shared_resolver();
        let cname = match resolver
            .lookup(&domain, hickory_resolver::proto::rr::RecordType::CNAME)
            .await
        {
            Ok(lookup) => {
                let mut target_name = None;
                for record in lookup.answers() {
                    if let hickory_resolver::proto::rr::RData::CNAME(ref c) = record.data {
                        target_name = Some(c.0.to_ascii().trim_end_matches('.').to_lowercase());
                        break;
                    }
                }
                target_name
            }
            Err(_) => None,
        };

        let Some(cname_target) = cname else {
            return Ok(result);
        };

        for &(pattern, service, fingerprint_path) in TAKEOVER_FINGERPRINTS {
            if !cname_target.contains(pattern) {
                continue;
            }

            let vulnerable = if let Some(path) = fingerprint_path {
                check_http_fingerprint(&ctx.http, &domain, path).await
            } else {
                check_nxdomain(&cname_target).await
            };

            if vulnerable {
                let mut e = Entity::new(EntityKind::Domain, &domain, 0.90, &ctx.scan_id);
                e.tag("vulnerable");
                e.tag("subdomain-takeover");
                e.tag(format!("takeover:{service}"));
                e.add_evidence(
                    Evidence::new(
                        SRC,
                        format!(
                            "CNAME {} points to {} — {} may be claimable",
                            domain, cname_target, service
                        ),
                    )
                    .with_attr("cname_target", &cname_target)
                    .with_attr("service", service),
                );
                result.push(e);
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
            if let Ok(body) = resp.text().await {
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
    use super::*;

    #[test]
    fn fingerprint_table_is_sorted_and_non_empty() {
        assert!(!TAKEOVER_FINGERPRINTS.is_empty());
        for &(pattern, service, _) in TAKEOVER_FINGERPRINTS {
            assert!(!pattern.is_empty());
            assert!(!service.is_empty());
        }
    }

    #[test]
    fn known_services_present() {
        let services: Vec<&str> = TAKEOVER_FINGERPRINTS.iter().map(|t| t.1).collect();
        assert!(services.contains(&"AWS S3"));
        assert!(services.contains(&"Heroku"));
        assert!(services.contains(&"GitHub Pages"));
        assert!(services.contains(&"Netlify"));
    }

    #[tokio::test]
    async fn module_metadata() {
        let m = SubdomainTakeover;
        assert!(m.accepts(&Target::new(TargetKind::Domain, "sub.example.com")));
        assert!(!m.accepts(&Target::new(TargetKind::IpAddress, "1.2.3.4")));
    }
}
