//! Subdomain brute-force against a bounded common-name dictionary.
//!
//! Runs ~60 candidate sub-labels (`www`, `mail`, `api`, `dev`, `staging`,
//! …) as A/AAAA lookups against the shared resolver, bounded to 12 in
//! flight at a time so Termux's cellular link doesn't drown.
//!
//! Tighter than `crtsh` (CT-log scrape — historical, may include dead
//! names) and complementary to `dns_resolver` (one parent record, not
//! enumeration). The dictionary is intentionally small — anything
//! larger belongs behind a dedicated module with a wordlist file.

use std::sync::{Arc, OnceLock};

use async_trait::async_trait;
use hickory_resolver::{
    TokioResolver,
    config::{CLOUDFLARE, ResolverConfig},
    net::runtime::TokioRuntimeProvider,
};
use tokio::sync::Semaphore;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};

fn shared_resolver() -> &'static TokioResolver {
    static R: OnceLock<TokioResolver> = OnceLock::new();
    R.get_or_init(|| {
        TokioResolver::builder_with_config(
            ResolverConfig::udp_and_tcp(&CLOUDFLARE),
            TokioRuntimeProvider::default(),
        )
        .build()
        .expect("hardcoded Cloudflare resolver config must build")
    })
}

/// Curated set — covers ~99% of the public-facing subdomains operators
/// actually want to discover. Ordered roughly by frequency so cancellation
/// during a partial run still surfaces the highest-value names first.
const SUBDOMAINS: &[&str] = &[
    "www",
    "mail",
    "smtp",
    "imap",
    "pop",
    "pop3",
    "webmail",
    "ns",
    "ns1",
    "ns2",
    "ns3",
    "mx",
    "mx1",
    "ftp",
    "admin",
    "blog",
    "api",
    "dev",
    "staging",
    "stage",
    "test",
    "beta",
    "alpha",
    "qa",
    "secure",
    "vpn",
    "cdn",
    "static",
    "assets",
    "media",
    "img",
    "images",
    "docs",
    "support",
    "help",
    "status",
    "shop",
    "store",
    "portal",
    "app",
    "apps",
    "my",
    "login",
    "auth",
    "sso",
    "files",
    "upload",
    "download",
    "backup",
    "git",
    "gitlab",
    "github",
    "jira",
    "wiki",
    "forum",
    "community",
    "old",
    "new",
    "m",
    "mobile",
    "internal",
    "prod",
    "production",
    "cpanel",
    "autodiscover",
    "autoconfig",
    "webdisk",
];

const MAX_CONCURRENT: usize = 12;

pub struct DnsBrute;

#[async_trait]
impl Module for DnsBrute {
    fn name(&self) -> &'static str {
        "dns_brute"
    }

    fn priority(&self) -> u8 {
        22
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Domain)
    }

    fn max_timeout_ms(&self) -> u64 {
        // 67 lookups bounded to MAX_CONCURRENT; the shared resolver
        // keeps most hits warm, but a slow upstream can drag.
        15_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let parent = target.value.trim().trim_end_matches('.').to_lowercase();
        if parent.is_empty() || parent.contains('/') || parent.contains(' ') {
            return Ok(ModuleResult::new());
        }

        let resolver = shared_resolver();
        let sem = Arc::new(Semaphore::new(MAX_CONCURRENT));
        let mut set = tokio::task::JoinSet::new();

        for sub in SUBDOMAINS {
            // Skip if the sub-label happens to already be part of the
            // input domain (defensive — avoids generating `www.www.x.com`).
            if parent.starts_with(&format!("{sub}.")) {
                continue;
            }
            let host = format!("{sub}.{parent}");
            let sem = Arc::clone(&sem);
            set.spawn(async move {
                let _permit = sem.acquire_owned().await.ok()?;
                if resolver.lookup_ip(host.as_str()).await.is_ok() {
                    Some(host)
                } else {
                    None
                }
            });
        }

        let mut result = ModuleResult::new();
        while let Some(joined) = set.join_next().await {
            let Ok(Some(host)) = joined else { continue };
            let mut e = Entity::new(EntityKind::Domain, &host, 0.85, &ctx.scan_id);
            e.tag("subdomain");
            e.tag("dns-brute");
            e.add_evidence(
                Evidence::new(
                    "dns_brute",
                    format!("Subdomain {host} resolves to one or more A/AAAA records"),
                )
                .with_attr("parent_domain", &parent)
                .with_attr("method", "common-name-dictionary")
                .with_attr("dictionary_size", SUBDOMAINS.len().to_string()),
            );
            result.push(e);
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_only_domain() {
        let m = DnsBrute;
        assert!(m.accepts(&Target::new(TargetKind::Domain, "x")));
        assert!(!m.accepts(&Target::new(TargetKind::IpAddress, "1.1.1.1")));
    }

    #[test]
    fn dictionary_is_unique_and_lowercase() {
        let mut sorted: Vec<&&str> = SUBDOMAINS.iter().collect();
        sorted.sort();
        let mut deduped = sorted.clone();
        deduped.dedup();
        assert_eq!(sorted.len(), deduped.len(), "dictionary has duplicates");
        for s in SUBDOMAINS {
            assert!(
                s.chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()),
                "non-lowercase entry: {s}"
            );
            assert!(
                !s.is_empty() && !s.contains('.'),
                "subdomains must be single label without dots: {s}"
            );
        }
    }
}
