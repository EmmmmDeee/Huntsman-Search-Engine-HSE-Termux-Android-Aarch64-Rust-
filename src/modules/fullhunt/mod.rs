//! FullHunt attack-surface management — subdomain / asset discovery for a
//! domain. Key-gated; FullHunt's API Console has a genuine Free plan (10
//! credits/month, evaluation use) above which usage is credit-metered.
//!
//! Endpoint: `GET https://fullhunt.io/api/v1/intel/domain?domain={domain}`
//! ("Data Intelligence APIs" — documented as "Get all subdomains associated
//! with the given domain").
//! Auth:     `X-API-KEY: <key>` request header — the same header this repo's
//! already-verified auth-check probe uses against
//! `GET https://fullhunt.io/api/v1/auth/status` (`util::service_defs`'s
//! `fullhunt` def).
//!
//! # Documentation provenance
//!
//! Confirmed live against FullHunt's current documentation site
//! (`docs.fullhunt.io` — `api-docs.fullhunt.io` 301-redirects there):
//!   * `https://docs.fullhunt.io/docs/data-intelligence-apis` — the endpoint
//!     table (`GET /api/v1/intel/domain`, `X-API-KEY` header, 60 req/min) plus
//!     a full worked example:
//!     ```json
//!     {
//!       "query": {"domain": "kaspersky.com"},
//!       "results": [
//!         {"asn": 0, "dns_ptr": null, "domain": "kaspersky.com",
//!          "host": "08.kaspersky.com", "ip_address": "", "organization": ""}
//!       ],
//!       "total_pages": 10000,
//!       "total_query_results": 10000
//!     }
//!     ```
//!     `asn: 0`, `ip_address: ""` and `organization: ""` are that page's own
//!     documented "field present but nothing known" shape — treated as absent
//!     below, exactly as `censys` treats a `0`/absent ASN and an empty geo field.
//!   * `https://docs.fullhunt.io/docs/errors` — the status-code table:
//!     `401`/`403` = bad/expired/unauthorized key, `404` = "querying for a
//!     domain or host that does not exist" (a clean miss, not a failure),
//!     `429` = rate limit exceeded.
//!   * `https://docs.fullhunt.io/docs/rate-limiting` — 60 requests/minute,
//!     `429` with `X-RateLimit-*` headers.
//!   * `https://fullhunt.io/pricing/console/` — the API Console's Free plan
//!     (10 credits/month) grants Data Intelligence API access, above which
//!     usage is paid/credit-metered — the free-to-register tier that makes
//!     this `ModuleCost::KeyGated` rather than `Paid`.
//!
//! This module deliberately fetches only the first (default) page: the
//! documented example shows `total_pages` can run into the thousands for a
//! large domain, and FullHunt's own community-tier cap (~100 results) means a
//! full-pagination crawl would very quickly exhaust the Free plan's monthly
//! credit budget for one target. A smaller, verified single-page slice beats
//! guessing at an unconfirmed pagination query-parameter contract.
//!
//! Response → entity mapping is a pure function ([`build_entities`]),
//! unit-tested against the captured-shape fixture above.

use std::collections::HashSet;

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    confidence,
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
    tags,
};
use crate::util::domains::is_proper_subdomain_of;
use crate::util::http::{json_decode, keyed_cascade, urlencode};

const KEY_ENV: &str = "HUNTSMAN_FULLHUNT_KEY";
const SRC: &str = "fullhunt";

/// One row of `results[]` — a discovered host under the queried domain, plus
/// whatever infra attribution FullHunt has cached for it.
#[derive(Deserialize)]
struct HostRecord {
    #[serde(default)]
    host: Option<String>,
    #[serde(default)]
    ip_address: Option<String>,
    #[serde(default)]
    asn: Option<i64>,
    #[serde(default)]
    organization: Option<String>,
    #[serde(default)]
    dns_ptr: Option<Vec<String>>,
}

#[derive(Deserialize)]
struct DomainResp {
    #[serde(default)]
    results: Vec<HostRecord>,
    /// FullHunt's own reported total match count — can exceed `results.len()`
    /// (the endpoint pages), so this is carried onto every entity as honest
    /// context rather than the caller inferring "found everything" from a
    /// single page's length.
    #[serde(default)]
    total_query_results: Option<u64>,
}

/// Cap on `dns_ptr` names turned into `Domain` pivots per host record. The
/// field is untrusted external data; a hostile or misconfigured record's
/// length must not translate into unbounded entity fan-out for one host.
const MAX_PTR_PER_HOST: usize = 5;

/// Build the discovered-asset entities from a decoded `/intel/domain`
/// response. **Pure** (no network/IO), so unit-tested directly off JSON
/// fixtures.
///
/// | source                                    | output                                |
/// |--------------------------------------------|---------------------------------------|
/// | `results[].host` (proper subdomain of `domain`) | `Domain` (+ `fullhunt`/`subdomain`)   |
/// | `results[].ip_address` (valid, non-empty) | `IpAddress` (+ `fullhunt`), deduped    |
/// | `results[].asn` (`> 0`)                   | `Asn` (`AS<n>`, + `fullhunt`), deduped  |
/// | `results[].organization` (non-blank)      | `Organisation` (+ `fullhunt`), deduped  |
/// | `results[].dns_ptr[]` (real hostname)     | `Domain` pivot (+ `fullhunt`/`ptr`)     |
///
/// A `host` that is not a proper subdomain of the queried `domain` — the apex
/// echoed back, or (defensively) an unrelated name — is skipped entirely,
/// including its infra attribution: only a confirmed new asset earns a
/// pivot. `asn: 0`, an empty `ip_address`, and an empty `organization` are
/// FullHunt's own "nothing known" sentinels (see the module doc's captured
/// example) and are treated as absent, not emitted as findings.
fn build_entities(body: &DomainResp, domain: &str, scan_id: &str) -> Vec<Entity> {
    let domain_lc = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    let total = body
        .total_query_results
        .unwrap_or(body.results.len() as u64)
        .to_string();

    let mut out = Vec::new();
    let mut seen_ips: HashSet<String> = HashSet::new();
    let mut seen_asns: HashSet<i64> = HashSet::new();
    let mut seen_orgs: HashSet<String> = HashSet::new();
    let mut seen_ptrs: HashSet<String> = HashSet::new();

    for rec in &body.results {
        let Some(host) = rec
            .host
            .as_deref()
            .map(|h| h.trim().trim_end_matches('.').to_ascii_lowercase())
            .filter(|h| is_proper_subdomain_of(h, &domain_lc))
        else {
            continue;
        };

        let ip = rec
            .ip_address
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty());
        let asn = rec.asn.filter(|n| *n > 0);
        let org = rec
            .organization
            .as_deref()
            .map(str::trim)
            .filter(|s| s.len() >= 2);

        // ── Discovered subdomain/asset ───────────────────────────
        let mut e = Entity::new(EntityKind::Domain, &host, confidence::EXPERT, scan_id);
        e.tag(SRC);
        e.tag(tags::SUBDOMAIN);
        let mut ev = Evidence::new(
            SRC,
            format!("FullHunt attack-surface asset under {domain_lc}"),
        )
        .with_attr("parent_domain", &domain_lc)
        .with_attr("total_query_results", &total);
        if let Some(ip) = ip {
            ev = ev.with_attr("ip_address", ip);
        }
        if let Some(asn) = asn {
            ev = ev.with_attr("asn", format!("AS{asn}"));
        }
        if let Some(org) = org {
            ev = ev.with_attr("organization", org);
        }
        e.add_evidence(ev);
        out.push(e);

        // ── Resolved IP as its own asset ──────────────────────────
        if let Some(ip) = ip
            && ip.parse::<std::net::IpAddr>().is_ok()
            && seen_ips.insert(ip.to_string())
        {
            let mut ie = Entity::new(EntityKind::IpAddress, ip, confidence::HIGH, scan_id);
            ie.tag(SRC);
            ie.add_evidence(
                Evidence::new(SRC, format!("Resolved IP for {host} (FullHunt)"))
                    .with_attr("host", &host),
            );
            out.push(ie);
        }

        // ── Announcing ASN ────────────────────────────────────────
        if let Some(asn) = asn
            && seen_asns.insert(asn)
        {
            let asn_str = format!("AS{asn}");
            let mut ae = Entity::new(
                EntityKind::Asn,
                &asn_str,
                confidence::HIGH_PLUSPLUS,
                scan_id,
            );
            ae.tag(SRC);
            ae.add_evidence(Evidence::new(SRC, format!("Announcing ASN for {host}")));
            out.push(ae);
        }

        // ── Network-operator Organisation ─────────────────────────
        if let Some(org) = org
            && seen_orgs.insert(org.to_string())
        {
            let mut oe = Entity::new(EntityKind::Organisation, org, confidence::HIGH, scan_id);
            oe.tag(SRC);
            oe.add_evidence(Evidence::new(SRC, format!("Network operator for {host}")));
            out.push(oe);
        }

        // ── Reverse-DNS PTR pivots ─────────────────────────────────
        if let Some(ptrs) = &rec.dns_ptr {
            for raw in ptrs.iter().take(MAX_PTR_PER_HOST) {
                let ptr = raw.trim().trim_end_matches('.').to_ascii_lowercase();
                if ptr.is_empty()
                    || !ptr.contains('.')
                    || ptr.parse::<std::net::IpAddr>().is_ok()
                    || ptr.contains(char::is_whitespace)
                    || !seen_ptrs.insert(ptr.clone())
                {
                    continue;
                }
                let mut pe = Entity::new(EntityKind::Domain, &ptr, confidence::ATTRIBUTED, scan_id);
                pe.tag(SRC);
                pe.tag(tags::PTR);
                pe.add_evidence(
                    Evidence::new(SRC, format!("Reverse-DNS host for {host}"))
                        .with_attr("host", &host),
                );
                out.push(pe);
            }
        }
    }

    out
}

pub struct FullHunt;

#[async_trait]
impl Module for FullHunt {
    fn name(&self) -> &'static str {
        "fullhunt"
    }
    fn description(&self) -> &'static str {
        "FullHunt attack-surface intel — enumerates subdomains and their resolved IP/ASN/org attribution"
    }
    fn priority(&self) -> u8 {
        55
    }

    fn cost(&self) -> ModuleCost {
        ModuleCost::KeyGated
    }
    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Domain)
    }
    fn max_timeout_ms(&self) -> u64 {
        10_000
    }
    fn cache_ttl_secs(&self) -> u64 {
        // Attack-surface / subdomain data is stable within a day, and the Free
        // plan's 10 credits/month makes re-querying the same domain within a
        // scan session wasteful — the same "IP intel: 24h" bracket
        // `censys`/`binaryedge` already cache under for the identical reason
        // (finite paid/metered query allowance).
        86_400
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Infrastructure
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        // Infrastructure default (T1590.005 IP Addresses, T1596.005 Search
        // Open Technical Databases: Scan Databases — FullHunt's own attack-
        // surface corpus) plus, since this endpoint's whole purpose is
        // subdomain enumeration, T1596.001 Search Open Technical Databases:
        // DNS/Passive DNS (the DnsRecon-category technique), and T1591.002
        // Business Relationships for the network-operator Organisation pivot
        // — mirrors `censys`'s identical ASN→Organisation attribution.
        // Superset of the category default — coverage cannot regress.
        &["T1590.005", "T1591.002", "T1596.001", "T1596.005"]
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[
            EntityKind::Domain,
            EntityKind::IpAddress,
            EntityKind::Asn,
            EntityKind::Organisation,
        ];
        KINDS
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let initial_key = match ctx.key_opt(KEY_ENV) {
            Some(k) => k,
            None => return Ok(ModuleResult::new()),
        };
        let domain = target
            .value
            .trim()
            .trim_end_matches('.')
            .to_ascii_lowercase();
        if domain.is_empty() {
            return Ok(ModuleResult::new());
        }

        let url = format!(
            "https://fullhunt.io/api/v1/intel/domain?domain={}",
            urlencode(&domain)
        );
        // Key cascade via the shared primitive: on a terminal key/quota
        // failure (401/403/429), rotate to the next untried usable pooled key
        // so one call spends every credential the pool holds.
        // `absent_statuses: &[404]` — FullHunt's documented "querying for a
        // domain or host that does not exist" response, a clean miss rather
        // than an error.
        let Some(resp) = keyed_cascade(ctx, SRC, initial_key, &[404], |key| {
            ctx.http
                .get(&url)
                .header("X-API-KEY", key)
                .header("Accept", "application/json")
        })
        .await?
        else {
            return Ok(ModuleResult::new());
        };
        let body: DomainResp = json_decode(SRC, resp).await?;
        if body.results.is_empty() {
            return Ok(ModuleResult::new());
        }

        let mut result = ModuleResult::new();
        result.extend(build_entities(&body, &domain, &ctx.scan_id));
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
