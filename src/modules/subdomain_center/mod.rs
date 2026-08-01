//! subdomain.center — free, keyless subdomain enumeration.
//!
//! Endpoint: `GET https://api.subdomain.center/?domain={domain}` — returns a bare
//! JSON array of subdomain FQDNs the service has aggregated from certificate
//! transparency and passive sources. No key, one request per domain,
//! Termux-friendly.
//!
//! It is *additive* alongside the tree's existing subdomain sources (`crtsh`,
//! `certspotter`, `anubis`, `hackertarget`, `mnemonic_pdns`): subdomain.center
//! aggregates a distinct corpus, so it surfaces names the CT-only sources miss —
//! the multi-independent-corpus rule HSE applies everywhere (the `geocode` +
//! `photon`, `beacondb` + `mylnikov` precedents).
//!
//! Every returned name is validated to be a real subdomain of the queried domain
//! before it is emitted, so aggregation noise (an unrelated host, a wildcard, the
//! apex itself) is dropped rather than surfaced as a finding. The response → entity
//! mapping is a pure function, unit-tested against a captured-shape fixture.

use std::collections::HashSet;

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    confidence,
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
    tags,
};
use crate::util::http::{fetch_json_or_404, urlencode};

const SRC: &str = "subdomain_center";
const BASE: &str = "https://api.subdomain.center/";

pub struct SubdomainCenter;

/// The API answers with a bare JSON array of FQDN strings; a transparent
/// newtype keeps the `Deserialize` obvious at the call site.
#[derive(Deserialize)]
struct SubdomainList(Vec<String>);

/// Map the aggregated subdomain list to `Domain` entities. **Pure** (no network).
///
/// Each name is trimmed, lower-cased, wildcard-defanged (`*.`) and root-dot
/// stripped, then kept only if it is a real subdomain of `domain` (never the apex
/// itself, never an unrelated host the aggregator returned as noise). Results are
/// de-duplicated within the response. Confirmed subdomains are emitted at
/// [`confidence::VERY_HIGH`] — an observed, corroboratable CT/passive name.
fn build_entities(subs: &[String], domain: &str, scan_id: &str) -> Vec<Entity> {
    let domain_l = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    let mut seen: HashSet<String> = HashSet::new();
    let mut out = Vec::new();

    for raw in subs {
        let host = raw
            .trim()
            .trim_end_matches('.')
            .trim_start_matches("*.")
            .to_ascii_lowercase();
        if host.is_empty() || !host.contains('.') || host == domain_l {
            continue;
        }
        // Drop anything the aggregator returned that is not actually under the
        // queried domain — never emit an unrelated host as a "subdomain".
        if !crate::util::domains::is_or_subdomain_of(&host, &domain_l) {
            continue;
        }
        if !seen.insert(host.clone()) {
            continue;
        }
        let mut e = Entity::new(EntityKind::Domain, &host, confidence::VERY_HIGH, scan_id);
        e.tag(SRC);
        e.tag(tags::SUBDOMAIN);
        e.add_evidence(Evidence::new(
            SRC,
            format!("Subdomain of {domain_l} (subdomain.center aggregation)"),
        ));
        out.push(e);
    }

    out
}

#[async_trait]
impl Module for SubdomainCenter {
    fn name(&self) -> &'static str {
        "subdomain_center"
    }

    fn description(&self) -> &'static str {
        "subdomain.center (free) — keyless subdomain enumeration from an aggregated CT/passive corpus"
    }

    fn priority(&self) -> u8 {
        24
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Domain | TargetKind::Url)
    }

    fn max_timeout_ms(&self) -> u64 {
        12_000
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::DnsRecon
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        // Querying an aggregated open subdomain corpus is ATT&CK Search Open
        // Technical Databases: DNS/Passive DNS.
        &["T1596.001"]
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[EntityKind::Domain];
        KINDS
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let domain = match target.kind {
            TargetKind::Domain => target.value.trim().to_string(),
            TargetKind::Url => match crate::util::url_util::host_from_url(&target.value) {
                Some(h) => h,
                None => return Ok(ModuleResult::new()),
            },
            _ => return Ok(ModuleResult::new()),
        };
        if domain.is_empty() {
            return Ok(ModuleResult::new());
        }

        let url = format!("{BASE}?domain={}", urlencode(&domain));
        // 404 → clean "no data for this domain"; other non-2xx surfaces as an
        // error the operator and circuit breaker can react to.
        let Some(SubdomainList(subs)) = fetch_json_or_404(&ctx.http, SRC, &url).await? else {
            return Ok(ModuleResult::new());
        };

        let mut result = ModuleResult::new();
        result.extend(build_entities(&subs, &domain, &ctx.scan_id));
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
