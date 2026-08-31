//! URLScan.io domain intelligence — recent scans, resolved IPs, and verdicts.
//!
//! Endpoint: `GET https://urlscan.io/api/v1/search/?q=domain:{domain}&size=100`
//!           `GET https://urlscan.io/api/v1/search/?q=page.url:{url}&size=100`
//!
//! No API key required for the search endpoint. Anonymous queries are
//! rate-limited to ~100/min by URLScan.io; an optional pooled `HUNTSMAN_URLSCAN_KEY`
//! (sent as the `API-Key` header) raises that limit for large fan-outs. The
//! page size is the keyless per-page maximum (100). The response carries per-scan
//! metadata (page URL, domain, resolved IP, country, server header) and
//! community/engine verdicts. We surface aggregate intel (scan count,
//! unique IPs, countries, server types) and tag the target as
//! "urlscan-malicious" when any verdict flags it.

use std::collections::BTreeSet;

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    confidence,
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::{fetch_json, fetch_keyed_json, urlencode};

const SRC: &str = "urlscan";
/// Optional URLScan.io API key. The search endpoint works keyless (~100/min),
/// but a pooled key raises the rate limit and result quota — worthwhile once a
/// scan fans out across many domains/IPs. Sent as URLScan's `API-Key` header.
const KEY_ENV: &str = "HUNTSMAN_URLSCAN_KEY";
const KEY_HEADER: &str = "API-Key";

/// URLScan.io search page size. Requested at the API's keyless per-page maximum
/// (100, verified live — larger values are silently capped to 100): the search
/// is ONE request regardless, so asking for 100 instead of 10 surfaces up to
/// 10× more resolved IPs / hosting domains / scanned URLs at no extra
/// request or rate-limit cost. The whole-corpus `total` is still reported
/// separately, so a target scanned more than 100 times is not understated.
const PAGE_SIZE: u32 = 100;

/// Build the URLScan.io search URL for a target. **Pure** so the query shape
/// (field selector + page size) is unit-tested without a live endpoint. Returns
/// `None` for a kind URLScan cannot be keyed on.
fn build_query(kind: TargetKind, value: &str) -> Option<String> {
    let field = match kind {
        TargetKind::Domain => "domain",
        TargetKind::Url => "page.url",
        TargetKind::IpAddress => "page.ip",
        _ => return None,
    };
    Some(format!(
        "https://urlscan.io/api/v1/search/?q={field}:\"{}\"&size={PAGE_SIZE}",
        urlencode(value)
    ))
}

/// URLScan search fetch with URLScan's *optional-key* auth. With a pooled
/// [`KEY_ENV`] key the request carries the `API-Key` header via the shared
/// keyed-fetch helper (401/403/429 burn the key); without one it falls back to
/// the exact keyless `fetch_json` path, so the free tier is unchanged. A keyless
/// search always returns a body (`Some`), never `None`.
async fn urlscan_fetch(ctx: &ModuleContext, url: &str) -> Result<Option<SearchResp>> {
    if ctx.key_opt(KEY_ENV).is_some() {
        fetch_keyed_json(ctx, SRC, url, KEY_ENV, KEY_HEADER).await
    } else {
        fetch_json(&ctx.http, SRC, url).await.map(Some)
    }
}

pub struct UrlScan;

// ─── Response types ─────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct SearchResp {
    #[serde(default)]
    results: Vec<ScanResult>,
    /// URLScan.io's true match count. The query caps `results` to one page
    /// (`size=5`/`10`), so a heavily-scanned target's real footprint exceeds
    /// what's returned — this is the field that lets the module report the
    /// true total instead of fabricating one from the truncated page (the
    /// same bug class already fixed in `netlas`/`psbdmp`/`pypi_user`/
    /// `rubygems_user`). Absent on some older API responses, so it's
    /// optional and falls back to the page length — mirrors `dehashed`'s
    /// identical `total`-with-fallback pattern.
    #[serde(default)]
    total: Option<u64>,
}

#[derive(Deserialize)]
struct ScanResult {
    #[serde(default)]
    page: Option<PageInfo>,
    #[serde(default)]
    verdicts: Option<Verdicts>,
}

#[derive(Deserialize)]
struct PageInfo {
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    domain: Option<String>,
    #[serde(default)]
    ip: Option<String>,
    #[serde(default)]
    country: Option<String>,
    #[serde(default)]
    server: Option<String>,
    /// The announcing ASN of the scanned page's IP (`"AS13335"`) — the hosting
    /// network operator, a pivot the module used to discard.
    #[serde(default)]
    asn: Option<String>,
    /// The reverse-DNS (PTR) hostname of the page IP — a domain edge distinct
    /// from `domain` (which is the requested host, not the resolved PTR).
    #[serde(default)]
    ptr: Option<String>,
}

#[derive(Deserialize)]
struct Verdicts {
    #[serde(default)]
    malicious: Option<bool>,
}

// ─── Module impl ────────────────────────────────────────────────────────────

#[async_trait]
impl Module for UrlScan {
    fn name(&self) -> &'static str {
        "urlscan"
    }

    fn description(&self) -> &'static str {
        "URLScan.io domain recon — surfaces recent scans, resolved IPs, and verdicts"
    }

    fn priority(&self) -> u8 {
        15
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(
            t.kind,
            TargetKind::Domain | TargetKind::Url | TargetKind::IpAddress
        )
    }

    fn max_timeout_ms(&self) -> u64 {
        8_000
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Infrastructure
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        // URLScan.io is a genuine scan database (T1596.005) and surfaces IP
        // addresses (T1590.005). Scan results also carry the hosting country,
        // emitted as an Address entity → T1591.001 Physical Locations, which
        // the Infrastructure default omits.
        &["T1590.005", "T1591.001", "T1596.005"]
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[
            EntityKind::IpAddress,
            EntityKind::Address,
            EntityKind::Coordinates,
            // Domains/subdomains seen hosting the target + the scanned URLs —
            // attack-surface pivots the module used to discard.
            EntityKind::Domain,
            EntityKind::Url,
            // Announcing ASN of the scanned pages' IPs.
            EntityKind::Asn,
        ];
        KINDS
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let Some(query) = build_query(target.kind, &target.value) else {
            return Ok(ModuleResult::new());
        };

        let Some(data) = urlscan_fetch(ctx, &query).await? else {
            return Ok(ModuleResult::new());
        };

        if data.results.is_empty() {
            return Ok(ModuleResult::new());
        }

        // True total, not the page-capped count: `data.total` (when present)
        // reflects URLScan.io's whole match count, so it doesn't understate
        // a heavily-scanned target's real footprint the way `results.len()`
        // (the current page) would.
        let total_matches = data.total.unwrap_or(data.results.len() as u64);
        let intel = summarize(&data.results);

        let entity = build_target_entity(target, &intel, total_matches, &ctx.scan_id);
        let mut result = ModuleResult::new();
        result.push(entity);
        result.extend(child_entities(&intel, &target.value, &ctx.scan_id));
        Ok(result)
    }
}

/// Build the target entity + aggregate evidence. **Pure** (no IO), so the
/// true-total-vs-shown distinction is unit-tested directly without a live
/// URLScan.io response.
fn build_target_entity(
    target: &Target,
    intel: &UrlScanIntel,
    total_matches: u64,
    scan_id: &str,
) -> Entity {
    let confidence = if intel.any_malicious {
        confidence::EXPERT
    } else {
        confidence::HIGH_PLUS
    };
    let mut entity = target.to_entity(confidence, scan_id);
    entity.tag("urlscan");
    if intel.any_malicious {
        entity.tag("urlscan-malicious");
    }

    let mut ev = Evidence::new(
        SRC,
        format!(
            "URLScan.io: {} scan(s) total ({} shown), {} unique IP(s)",
            total_matches,
            intel.scan_count,
            intel.unique_ips.len()
        ),
    )
    .with_attr("scan_count", total_matches.to_string())
    .with_attr("scans_shown", intel.scan_count.to_string())
    .with_attr("unique_ips", intel.unique_ips.len().to_string());
    if !intel.countries.is_empty() {
        let list: Vec<&str> = intel.countries.iter().map(String::as_str).collect();
        ev = ev.with_attr("countries", list.join(", "));
    }
    if !intel.servers.is_empty() {
        // Full-fidelity policy: every distinct server string observed.
        let list: Vec<&str> = intel.servers.iter().map(String::as_str).collect();
        ev = ev.with_attr("servers", list.join(", "));
    }
    if intel.any_malicious {
        ev = ev.with_attr("malicious_verdict", "true");
    }
    entity.add_evidence(ev);
    entity
}

/// Aggregated, deduplicated intel across a URLScan.io search response. **Pure.**
struct UrlScanIntel {
    unique_ips: BTreeSet<String>,
    countries: BTreeSet<String>,
    servers: BTreeSet<String>,
    /// Domains/subdomains the scans resolved for the target.
    domains: BTreeSet<String>,
    /// Distinct scanned page URLs.
    urls: BTreeSet<String>,
    /// Announcing ASNs (`"AS13335"`) of the scanned pages' IPs.
    asns: BTreeSet<String>,
    /// Reverse-DNS (PTR) hostnames of the scanned pages' IPs.
    ptrs: BTreeSet<String>,
    scan_count: usize,
    any_malicious: bool,
}

/// Reduce a search response to its deduplicated fields. **Pure** (no IO).
fn summarize(results: &[ScanResult]) -> UrlScanIntel {
    let field = |f: fn(&PageInfo) -> Option<&str>| -> BTreeSet<String> {
        results
            .iter()
            .filter_map(|e| e.page.as_ref())
            .filter_map(f)
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(String::from)
            .collect()
    };
    UrlScanIntel {
        unique_ips: field(|p| p.ip.as_deref()),
        countries: field(|p| p.country.as_deref()),
        servers: field(|p| p.server.as_deref()),
        domains: field(|p| p.domain.as_deref()),
        urls: field(|p| p.url.as_deref()),
        asns: field(|p| p.asn.as_deref()),
        ptrs: field(|p| p.ptr.as_deref()),
        scan_count: results.len(),
        any_malicious: results
            .iter()
            .filter_map(|e| e.verdicts.as_ref())
            .any(|v| v.malicious == Some(true)),
    }
}

/// Child entities for a URLScan.io result: the resolved IPs, hosting countries,
/// associated domains/subdomains, scanned URLs, announcing ASNs, and reverse-DNS
/// (PTR) hosts. **Pure** (no IO) so the dedup, validity gates and target-echo
/// suppression are unit-tested directly.
fn child_entities(intel: &UrlScanIntel, target_value: &str, scan_id: &str) -> Vec<Entity> {
    let mut out: Vec<Entity> = Vec::new();
    let target_lc = target_value.trim().to_ascii_lowercase();

    // Resolved IPs (valid v4/v6 only).
    out.extend(
        intel
            .unique_ips
            .iter()
            .filter(|ip| ip.parse::<std::net::IpAddr>().is_ok())
            .map(|ip| {
                let mut e = Entity::new(EntityKind::IpAddress, ip, confidence::HIGH, scan_id);
                e.tag("urlscan");
                e.add_evidence(Evidence::new(
                    SRC,
                    format!("Resolved IP seen in URLScan.io scans of {target_value}"),
                ));
                e
            }),
    );

    // Hosting countries → geo-hint Address + optional Coordinates.
    out.extend(intel.countries.iter().flat_map(|country| {
        let mut e = Entity::new(EntityKind::Address, country, confidence::MEDIUM, scan_id);
        e.tag("urlscan");
        e.tag("geoint");
        e.add_evidence(Evidence::new(
            SRC,
            format!("Hosting country from URLScan.io scans of {target_value}"),
        ));
        let coord = crate::util::city_coords::city_coords(country).map(|(lat, lon)| {
            let coord_val = format!("{lat:.4},{lon:.4}");
            let mut c = Entity::new(
                EntityKind::Coordinates,
                &coord_val,
                confidence::LOW,
                scan_id,
            );
            c.tag("urlscan");
            c.tag("addr-derived");
            c.tag("geoint");
            c.add_evidence(Evidence::new(
                SRC,
                format!("Geocode of hosting country '{country}' for {target_value}"),
            ));
            c
        });
        let mut v = vec![e];
        v.extend(coord);
        v
    }));

    // Associated domains/subdomains (drop the seed echo + dotless junk).
    out.extend(
        intel
            .domains
            .iter()
            .filter(|d| d.contains('.') && d.to_ascii_lowercase() != target_lc)
            .map(|d| {
                let mut e = Entity::new(EntityKind::Domain, d, confidence::MEDIUM_HIGH, scan_id);
                e.tag("urlscan");
                e.tag("resolved-domain");
                e.add_evidence(Evidence::new(
                    SRC,
                    format!("Domain seen in URLScan.io scans of {target_value}"),
                ));
                e
            }),
    );

    // Scanned page URLs → attack-surface pivots. Full-fidelity policy: every URL
    // urlscan observed for the target page becomes a pivot, never a capped subset
    // (the set is bounded by urlscan's own per-scan response).
    out.extend(intel.urls.iter().filter(|u| u.len() >= 4).map(|u| {
        let mut e = Entity::new(EntityKind::Url, u, confidence::MEDIUM, scan_id);
        e.tag("urlscan");
        e.add_evidence(Evidence::new(
            SRC,
            format!("Page scanned by URLScan.io for {target_value}"),
        ));
        e
    }));

    // Announcing ASNs of the scanned pages' IPs (`"AS13335"`). Validate the
    // `AS<digits>` shape so a malformed/empty field never becomes a junk pivot,
    // and re-emit canonically (`AS` + digits) regardless of source casing.
    out.extend(
        intel
            .asns
            .iter()
            .filter_map(|a| {
                a.strip_prefix("AS")
                    .or_else(|| a.strip_prefix("as"))
                    .filter(|d| !d.is_empty() && d.bytes().all(|b| b.is_ascii_digit()))
            })
            .map(|digits| {
                let asn = format!("AS{digits}");
                let mut e = Entity::new(EntityKind::Asn, &asn, confidence::MEDIUM_HIGH, scan_id);
                e.tag("urlscan");
                e.add_evidence(Evidence::new(
                    SRC,
                    format!("Announcing ASN seen in URLScan.io scans of {target_value}"),
                ));
                e
            }),
    );

    // Reverse-DNS (PTR) hostnames → Domain pivots, held to the same validity gate
    // as resolved domains (dotted, non-IP, not the seed echo).
    out.extend(
        intel
            .ptrs
            .iter()
            .map(|p| p.trim().trim_end_matches('.'))
            .filter(|p| {
                p.contains('.')
                    && p.parse::<std::net::IpAddr>().is_err()
                    && p.to_ascii_lowercase() != target_lc
            })
            .map(|p| {
                let mut e = Entity::new(EntityKind::Domain, p, confidence::MEDIUM_HIGH, scan_id);
                e.tag("urlscan");
                e.tag("ptr");
                e.add_evidence(Evidence::new(
                    SRC,
                    format!("Reverse-DNS host seen in URLScan.io scans of {target_value}"),
                ));
                e
            }),
    );

    out
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
