//! Anubis (jldc.me) — free, key-less passive-DNS subdomain aggregator.
//!
//! Endpoint: `GET https://jldc.me/anubis/subdomains/{domain}`
//! Auth: None — anonymous and free (rate-limited; a failure surfaces as a module
//! error and the engine moves on, like any other free source).
//!
//! Anubis draws subdomains from an aggregated passive-DNS corpus that is distinct
//! from Certificate Transparency ([`crate::modules::crtsh`] /
//! [`crate::modules::certspotter`]) and from HackerTarget's `hostsearch` — it
//! surfaces names that were RESOLVED historically but may never have appeared in
//! a public certificate. Running it alongside those sources maximises the
//! attack-surface recall from one apex seed with zero operator configuration
//! (the autonomy win: no API key to provision). It is a recognised
//! subfinder/amass source (`jldc`).

use async_trait::async_trait;
use std::collections::HashSet;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
    tags,
};
use crate::util::http::urlencode;

const SRC: &str = "anubis";

/// Map the Anubis subdomain list to deduplicated `Domain` entities. **Pure** (no
/// network/IO): skips blanks/wildcards/non-hosts, dedups, classifies a name as a
/// subdomain of `domain_base` (case-folded) for a confidence boost, and returns
/// EVERY distinct entity, confidence-descending (uid-tie-broken) — no per-module
/// cap, because each subdomain is a real BFS pivot and the frontier budget is the
/// engine's, not this leaf module's (mirrors `crtsh`/`certspotter`).
fn build_entities(names: &[String], domain_base: &str, scan_id: &str) -> Vec<Entity> {
    let base = domain_base.trim().trim_end_matches('.').to_lowercase();
    let dot_base = format!(".{base}");
    let mut seen: HashSet<String> = HashSet::new();

    let mut out: Vec<Entity> = names
        .iter()
        .filter_map(|raw| {
            let name = raw.trim().trim_end_matches('.').to_lowercase();
            if name.is_empty() || name.starts_with('*') || !name.contains('.') {
                return None;
            }
            if !seen.insert(name.clone()) {
                return None;
            }
            let is_sub = name == base || name.ends_with(&dot_base);
            // Off-base names are rare here (Anubis is keyed on the apex) but a
            // corrupt entry is retained as a low-confidence lead rather than
            // asserted as the subject's subdomain.
            let conf = if is_sub { 0.72 } else { 0.40 };
            let mut e = Entity::new(EntityKind::Domain, &name, conf, scan_id);
            e.tag(SRC);
            e.tag("passive-dns");
            if is_sub {
                e.tag(tags::SUBDOMAIN);
            }
            e.add_evidence(Evidence::new(
                SRC,
                "Passive-DNS subdomain (Anubis / jldc.me)",
            ));
            Some(e)
        })
        .collect();

    // Deterministic confidence-descending emission order (shared with the other
    // host-recon collectors). No truncation.
    crate::util::recon::sort_by_confidence_desc(&mut out);
    out
}

pub struct Anubis;

#[async_trait]
impl Module for Anubis {
    fn name(&self) -> &'static str {
        "anubis"
    }

    fn description(&self) -> &'static str {
        "Passive-DNS subdomain aggregation via Anubis/jldc.me (free, no key)"
    }

    fn priority(&self) -> u8 {
        // Alongside the two CT sources (crtsh 29 / certspotter 28); order is
        // immaterial to the union the engine dedups, but a stable value keeps
        // dispatch deterministic.
        27
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Domain | TargetKind::Url)
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::DnsRecon
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        // Search Open Technical Databases: DNS/Passive DNS (T1596.001).
        &["T1596.001"]
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[EntityKind::Domain];
        KINDS
    }

    fn max_timeout_ms(&self) -> u64 {
        8_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let Some(host) = crate::util::recon::host_key(target.kind, &target.value) else {
            return Ok(ModuleResult::new());
        };

        let url = format!("https://jldc.me/anubis/subdomains/{}", urlencode(&host));

        // Shared `fetch_json` (curl/OpenSSL fallback + circuit breaker every
        // keyless source gets on Termux/DC IPs). The endpoint answers a JSON array
        // of subdomain strings, or `null` when it indexes none — decoded through
        // `Option` so a null body is a clean empty result, not a hard error.
        let names: Option<Vec<String>> =
            crate::util::http::fetch_json(&ctx.http, SRC, &url).await?;
        let names = names.unwrap_or_default();

        let mut result = ModuleResult::new();
        result.entities = build_entities(&names, &host, &ctx.scan_id);
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
