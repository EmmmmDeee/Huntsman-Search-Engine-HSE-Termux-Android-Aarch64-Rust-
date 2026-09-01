//! Common Crawl module — a **domain**'s URLs from the open web crawl index.
//!
//! Ported from the sibling `Huntsman-` repository during consolidation. The
//! parsing judgement — the two-step index-discovery-then-query flow,
//! per-line skip-on-parse-failure (the index occasionally emits a
//! non-record line), case-insensitive dedup, and the emission cap — is the
//! part worth carrying over verbatim; the trait wrapper is rewritten
//! against this crate's `Module` contract (`accepts`/`process`/`produces`),
//! which the source repository's simpler `is_enabled`/`execute` shape has
//! no equivalent of.
//!
//! Common Crawl publishes a keyless CDX index of billions of pages. This
//! module first reads `collinfo.json` to discover the latest index's
//! `cdx-api` URL (so it never goes stale on a hard-coded collection id),
//! then queries that index for the domain.
//!
//! Endpoints:
//!   `GET https://index.commoncrawl.org/collinfo.json` →
//!     `[{ "cdx-api": "https://index.commoncrawl.org/CC-MAIN-…-index" }]`
//!   `GET <cdx-api>?url=<domain>&output=json&limit=100` → JSON-lines, one
//!     `{ "url": "…" }` record per line.
//!
//! Keyless — not key-gated, and deliberately not added to any key-gate
//! table.
//!
//! What it deliberately does NOT do: it does not follow or fetch any of the
//! discovered URLs. A URL appearing in the archive is reported as a lead —
//! a page Common Crawl observed for this domain at some point in the past —
//! not confirmed live content, hence the point-in-time-snapshot confidence
//! (see [`URL_CONFIDENCE`]).

use async_trait::async_trait;
use serde::Deserialize;
use std::collections::HashSet;

use crate::core::{
    confidence,
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::{
    RequestBuilderExt, UA_OSINT, json_decode, ok_or_absent, read_text, urlencode,
};

const SRC: &str = "commoncrawl";

/// Cap on URLs emitted for one domain. A large or long-lived site can have
/// thousands of pages indexed across crawl snapshots; past a few dozen the
/// marginal lead is worthless and the frontier cost is not — the same
/// reasoning `bitcoin::MAX_COSPEND_ADDRESSES` applies to its co-spend set.
const CAP: usize = 50;

/// Confidence for a URL indexed in the Common Crawl archive. These are real
/// observed web pages, but represent a point-in-time snapshot rather than
/// confirmed-live content, so this sits at [`confidence::MEDIUM_PLUS`] —
/// carried over unchanged from the source module's calibration (was a bare
/// `0.60` there).
const URL_CONFIDENCE: f64 = confidence::MEDIUM_PLUS;

#[derive(Debug, Deserialize)]
struct CollInfo {
    #[serde(rename = "cdx-api", default)]
    cdx_api: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CcRecord {
    #[serde(default)]
    url: Option<String>,
}

/// Build the CDX query URL for `domain`. **Pure**, so the matchType behavior
/// is unit-testable without a live server.
///
/// The CDX-Server API's `matchType` defaults to `exact` when omitted: a bare
/// `url=<domain>` matches only that literal URL string across snapshot
/// dates, not the domain's pages — silently defeating this module's entire
/// purpose ("a domain's URLs") with no error, just a near-empty result.
/// `url=*.{domain}` triggers CDX `matchType=domain` (the domain + every
/// subdomain, all their paths) without needing a separate query parameter —
/// the same proven pattern `wayback`'s own CDX domain-match pass uses.
fn cdx_query_url(cdx_api: &str, domain: &str) -> String {
    format!(
        "{cdx_api}?url=*.{}&output=json&limit=100",
        urlencode(domain)
    )
}

/// Pure projection of the CDX index's JSON-lines body into `Url` entities.
///
/// Lines that fail to parse are skipped rather than failing the whole
/// module — the index occasionally emits a non-record line, and one bad
/// line must not discard every genuine URL before or after it. Deduplicated
/// case-insensitively on the raw URL string (Common Crawl can repeat the
/// same page across multiple snapshot dates) and capped at [`CAP`]. Pure
/// and network-free, so unit-testable directly with no HTTP.
fn build_entities(body: &str, scan_id: &str) -> Vec<Entity> {
    let mut out = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Ok(rec) = serde_json::from_str::<CcRecord>(line) else {
            continue;
        };
        let Some(u) = rec.url else { continue };
        let u = u.trim().to_string();
        if u.is_empty() || !seen.insert(u.to_lowercase()) {
            continue;
        }
        let mut e = Entity::new(EntityKind::Url, &u, URL_CONFIDENCE, scan_id);
        e.tag("commoncrawl");
        e.tag("archive");
        e.add_evidence(Evidence::new(SRC, format!("Indexed by Common Crawl: {u}")));
        out.push(e);
        if out.len() >= CAP {
            break;
        }
    }
    out
}

/// Common Crawl domain URL discovery — see the module docs for the
/// index-discovery-then-query flow and what it deliberately does not do.
pub struct CommonCrawl;

#[async_trait]
impl Module for CommonCrawl {
    fn name(&self) -> &'static str {
        "commoncrawl"
    }

    fn description(&self) -> &'static str {
        "Common Crawl open web index (keyless) — discovers URLs for a domain crawled into the public CDX archive"
    }

    fn priority(&self) -> u8 {
        45
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Domain)
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Web
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        // Common Crawl is a third-party pre-crawled ARCHIVE database, not the
        // victim's own site (`Web`'s default T1594) and not a live scraper
        // (`T1592.002`) — it is closer to querying Shodan/Censys, which
        // `Infrastructure` maps to T1596.005 "Search Open Technical
        // Databases: Scan Databases". Overridden for the same reason
        // `hackertarget`/`bitcoin` override their category's default.
        &["T1596.005"]
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[EntityKind::Url];
        KINDS
    }

    fn max_timeout_ms(&self) -> u64 {
        10_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let domain = target.value.trim();
        if domain.is_empty() {
            return Ok(ModuleResult::new());
        }

        // 1) Discover the latest index's `cdx-api` endpoint, so the module
        // never goes stale on a hard-coded collection id. A genuine 404 here
        // is "no index, no results" — but a throttle, block, or upstream
        // outage must surface as a typed `Err` per the fail-closed
        // invariant, not collapse into that same "no results" outcome.
        let resp = ctx
            .http
            .get("https://index.commoncrawl.org/collinfo.json")
            .header("User-Agent", UA_OSINT)
            .send_tagged(SRC)
            .await?;
        let Some(resp) = ok_or_absent(SRC, resp, &[404]).await? else {
            return Ok(ModuleResult::new());
        };
        let coll: Vec<CollInfo> = json_decode(SRC, resp).await?;
        let Some(cdx_api) = coll.into_iter().find_map(|c| c.cdx_api) else {
            return Ok(ModuleResult::new());
        };

        // 2) Query that index for the domain. Same fail-closed treatment: a
        // 404 is a clean miss, anything else non-2xx is a typed `Err`.
        let url = cdx_query_url(&cdx_api, domain);
        let resp = ctx
            .http
            .get(&url)
            .header("User-Agent", UA_OSINT)
            .send_tagged(SRC)
            .await?;
        let Some(resp) = ok_or_absent(SRC, resp, &[404]).await? else {
            return Ok(ModuleResult::new());
        };
        let body = read_text(SRC, resp).await?;

        let mut result = ModuleResult::new();
        result.entities = build_entities(&body, &ctx.scan_id);
        Ok(result)
    }
}

#[cfg(test)]
mod tests;
