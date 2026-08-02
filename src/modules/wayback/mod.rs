//! Wayback Machine CDX API — historical snapshots of a domain, plus
//! historical contact extraction from archived pages.
//!
//! Free, no key. Three CDX queries are issued:
//!
//! 1. **Snapshot summary** (`fl=timestamp,statuscode`, `collapse=urlkey`,
//!    `limit=1000`) — records the archived-URL count and the
//!    first/last-seen timestamps. Used by the AU-010 infrastructure
//!    consensus rule and the age-confidence heuristic.
//!
//! 2. **Contact mining** (`fl=timestamp,original`, `collapse=urlkey`,
//!    `limit=500`) — finds archived pages whose paths contain a
//!    contact-adjacent keyword (contact, about, team, staff, imprint…),
//!    fetches each raw snapshot HTML (capped at 32 KB), and extracts
//!    email addresses, phone numbers, **and any leaked API key/credential**
//!    (via the universal `found_keys`/`key_harvest` classifier — the same
//!    one `web_crawler`/`username_search` run over their own fetched
//!    bodies). This recovers secrets that have since been scrubbed from the
//!    live site but persist in an archived snapshot — the same technique
//!    that drives many authoritative OSINT investigations (Theranos,
//!    Wirecard, OCCRP shell companies) where the current site shows
//!    different or no contacts but earlier versions are preserved in
//!    the archive, applied here to credentials instead of just contacts.
//!
//! 3. **Historical subdomain recovery** (`url=*.{domain}`, `fl=original`,
//!    `collapse=urlkey`) — the CDX domain-match pass. Reduces every archived
//!    URL to its host and emits the distinct DECOMMISSIONED subdomains no live
//!    CT/DNS source will ever return (they no longer resolve) as `Domain`
//!    pivots tagged `archived`/`wayback-historical`. No page fetches.

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    confidence,
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::freq::top_n;
use crate::util::http::RequestBuilderExt;
use crate::util::http::{fetch_json, read_body_capped, urlencode};

const SRC: &str = "wayback";

/// Maximum archived contact-page snapshots to fetch per scan.
/// Each fetch is one network round-trip to archive.org.
const MAX_CONTACT_SNAPSHOTS: usize = 10;

/// Cap on historical subdomains surfaced from the CDX domain-match pass. A
/// long-lived domain can accrue hundreds of archived hostnames; this bounds
/// graph expansion while still recovering the salient decommissioned names.
const MAX_HISTORICAL_SUBDOMAINS: usize = 60;

/// Body read cap per snapshot fetch. 32 KB is more than enough for a
/// contact page; anything larger is almost certainly a binary or video.
const SNAPSHOT_BODY_CAP: usize = 32 * 1024;

/// Inter-snapshot delay — archive.org asks for ≤4 req/s.
const INTER_SNAPSHOT_MS: u64 = 300;

/// Path-level keywords that suggest a URL hosts contact/team information.
const CONTACT_PATH_KEYWORDS: &[&str] = &[
    "contact",
    "about",
    "team",
    "staff",
    "imprint",
    "impressum",
    "reach",
    "support",
    "people",
];

pub struct Wayback;

/// CDX API returns a 2-D array; first row is the column header, the
/// rest are data rows.
#[derive(Deserialize)]
struct Row(Vec<String>);

/// Reduce a target to the bare lowercase host the CDX query keys on. **Pure**:
/// a `Url` is stripped of its scheme, path and port; anything else is just
/// trimmed and lowercased. Returns `""` when nothing host-like remains.
fn extract_domain(kind: TargetKind, value: &str) -> String {
    match kind {
        TargetKind::Url => crate::util::url_util::host_only(value).to_lowercase(),
        _ => value.trim().to_lowercase(),
    }
}

/// Build the archive entity from CDX rows. **Pure** (no network/IO). The first
/// row is the CDX column header, so a response of `rows.len() <= 1` means the
/// domain is unarchived → `None`. Otherwise the data rows (timestamp-sorted
/// ascending) yield the snapshot count, the earliest/most-recent bookend
/// timestamps (raw + ISO), and the HTTP status-code distribution.
fn build_entity(kind: EntityKind, value: &str, rows: &[Row], scan_id: &str) -> Option<Entity> {
    if rows.len() <= 1 {
        return None;
    }
    let count = rows.len() - 1;
    let first_ts = rows.get(1).and_then(|r| r.0.first());
    let last_ts = rows.last().and_then(|r| r.0.first());

    let status_dist = top_n(
        rows[1..]
            .iter()
            .filter_map(|r| r.0.get(1).map(String::as_str)),
        10,
    );

    let mut entity = Entity::new(kind, value, confidence::HIGH_PLUSPLUS, scan_id);
    entity.tag("archived");
    let mut ev = Evidence::new(
        SRC,
        format!("Wayback Machine: {count} archived snapshot(s)"),
    )
    .with_attr("snapshot_count", count.to_string())
    .with_attr("cdx_query_limit", "1000");
    if let Some(t) = first_ts {
        ev = ev
            .with_attr("first_seen", t.as_str())
            .with_attr("first_seen_iso", iso_from_cdx(t));
    }
    if let Some(t) = last_ts {
        ev = ev
            .with_attr("last_seen", t.as_str())
            .with_attr("last_seen_iso", iso_from_cdx(t));
    }
    if !status_dist.is_empty() {
        ev = ev.with_attr("status_distribution", &status_dist);
    }
    entity.add_evidence(ev);
    Some(entity)
}

/// Recover historical subdomains of `domain` from a CDX domain-match response
/// (`fl=original`). **Pure** (no network/IO): each row's original URL is reduced
/// to its host, kept only when it is a real subdomain of `domain` (the apex echo
/// is dropped), then deduplicated and sorted (BTreeSet) so the output is stable
/// across runs, and capped at [`MAX_HISTORICAL_SUBDOMAINS`].
///
/// Live CT/DNS sources only return names that still resolve; the Wayback
/// domain-match is the canonical way to recover DECOMMISSIONED subdomains no
/// live source will ever surface — sourced from real archived hostnames, never
/// synthesised. The first row is the CDX column header and is skipped.
fn historical_subdomains(rows: &[Row], domain: &str, scan_id: &str) -> Vec<Entity> {
    let domain = domain.trim().to_lowercase();
    if domain.is_empty() {
        return Vec::new();
    }
    let suffix = format!(".{domain}");
    let hosts: std::collections::BTreeSet<String> = rows
        .iter()
        .skip(1) // CDX column header
        .filter_map(|r| r.0.first())
        .filter_map(|orig| crate::util::url_util::host_from_url(orig))
        // A real subdomain of the seed — never the apex echo, never an
        // unrelated host the query might return.
        .filter(|h| h != &domain && h.ends_with(&suffix))
        .collect();

    hosts
        .into_iter()
        .take(MAX_HISTORICAL_SUBDOMAINS)
        .map(|host| {
            let mut e = Entity::new(EntityKind::Domain, &host, confidence::MEDIUM_HIGH, scan_id);
            e.tag("archived");
            e.tag("wayback-historical");
            e.add_evidence(Evidence::new(
                SRC,
                format!("Historical subdomain of {domain} recovered from the Wayback CDX archive"),
            ));
            e
        })
        .collect()
}

/// True when `url` contains a path keyword associated with contact / team
/// information pages (case-insensitive).
fn is_contact_path(url: &str) -> bool {
    let lower = url.to_lowercase();
    // Check only the path portion — not the domain — so a domain like
    // `contact-center.com` does not match every URL on that host.
    let path_start = lower.find("://").map_or(0, |p| p + 3);
    let path = lower[path_start..]
        .find('/')
        .map_or(lower.as_str(), |p| &lower[path_start + p..]);
    CONTACT_PATH_KEYWORDS.iter().any(|kw| path.contains(kw))
}

/// Construct the Wayback raw-content URL for a given snapshot. The `id_`
/// modifier tells the Wayback Machine to return the unmodified original
/// response without banner injection or URL rewriting.
fn archive_url(timestamp: &str, original: &str) -> String {
    format!("https://web.archive.org/web/{timestamp}id_/{original}")
}

/// Scan an already-fetched archived-page body for a leaked API key via the
/// universal `found_keys`/`key_harvest` classifier — the same one
/// `web_crawler`/`username_search` run over their own fetched bodies — and
/// pool any poolable hit. No network I/O of its own (the body is already in
/// memory), so this is exercised directly by tests without mocking HTTP.
fn mine_keys_from_body(
    pool: &crate::util::key_pool::KeyPool,
    body: &str,
    domain: &str,
    ts_iso: &str,
    original_url: &str,
) {
    use crate::util::found_keys::{MAX_TOKEN, key_tokens};
    use crate::util::key_harvest::identify_api_key;

    for token in key_tokens(body, MAX_TOKEN) {
        if let Some((service, key_val)) = identify_api_key(token) {
            let mut entry = crate::util::key_pool::KeyEntry::new(key_val);
            entry.notes = Some(format!("Wayback archive ({ts_iso}) — {original_url}"));
            entry.status = crate::util::key_pool::KeyStatus::Untested;
            entry.discovered_at = Some(crate::core::entity::unix_now());
            entry.discovered_by = Some(format!("wayback:{domain}"));
            if pool.add(service, entry) {
                tracing::info!(
                    service,
                    domain,
                    snapshot = %ts_iso,
                    "API key discovered in archived page (wayback)"
                );
            }
        }
    }
}

/// Build the `Url` entity for a freshly-discovered archived contact-adjacent
/// page, or `None` when `original_url` was already emitted this scan
/// (dedup tracked via `seen_urls`). Confidence is modest (confidence::MEDIUM_HIGH) — this only
/// proves the page was once archived, not that it is live today. **Pure**
/// (no network/IO), so — like `mine_keys_from_body` — it is exercised
/// directly by tests without mocking HTTP.
fn mine_url_entity(
    seen_urls: &mut std::collections::HashSet<String>,
    original_url: &str,
    fetch_url: &str,
    ts_iso: &str,
    scan_id: &str,
) -> Option<Entity> {
    if !seen_urls.insert(original_url.to_string()) {
        return None;
    }
    let mut u = Entity::new(
        EntityKind::Url,
        original_url,
        confidence::MEDIUM_HIGH,
        scan_id,
    );
    u.tag("wayback-historical");
    u.tag(crate::core::tags::SEARCH_DISCOVERED);
    let ev = Evidence::new(
        SRC,
        format!(
            "[wayback] contact-adjacent page discovered via archived snapshot — {original_url}"
        ),
    )
    .with_attr("archive_url", fetch_url)
    .with_attr("snapshot_timestamp_iso", ts_iso);
    u.add_evidence(ev);
    Some(u)
}

/// Fetch archived contact-adjacent pages for `domain` and extract
/// historical email addresses and phone numbers with temporal metadata.
/// Also runs every fetched body through the universal key-harvest
/// classifier — any poolable API key it finds goes straight into
/// `key_pool` (no separate entity/fetch; matches the `web_crawler`/
/// `username_search` treatment of their own fetched bodies).
///
/// Returns an empty vec both when the CDX query fails and when no contact
/// pages are archived — failures here must not abort the main snapshot query,
/// which has already produced its own evidence by this point. The two cases
/// share a return value by design, so the failing one is logged to keep them
/// distinguishable in diagnostics.
async fn mine_contacts(domain: &str, scan_id: &str, ctx: &ModuleContext) -> Vec<Entity> {
    let cdx_url = format!(
        "https://web.archive.org/cdx/search/cdx?url={}/*&output=json\
         &fl=timestamp,original&filter=statuscode:200\
         &limit=500&collapse=urlkey",
        urlencode(domain)
    );

    let rows: Vec<Row> = match fetch_json(&ctx.http, SRC, &cdx_url).await {
        Ok(r) => r,
        // Deliberately still an empty vec — see the doc above; a failure here
        // must not discard the primary snapshot findings. But it is logged so
        // an outage stays distinguishable from "no contact pages archived",
        // which is the same empty return value.
        Err(e) => {
            tracing::debug!(
                module = SRC,
                domain,
                error = %e,
                "wayback: contact-mining CDX query failed; continuing without contact enrichment"
            );
            return Vec::new();
        }
    };

    // Skip header row, filter to contact-adjacent paths, take the cap.
    let contact_snapshots: Vec<(String, String)> = rows
        .iter()
        .skip(1)
        .filter_map(|r| {
            let ts = r.0.first()?.clone();
            let orig = r.0.get(1)?.clone();
            if is_contact_path(&orig) {
                Some((ts, orig))
            } else {
                None
            }
        })
        .take(MAX_CONTACT_SNAPSHOTS)
        .collect();

    if contact_snapshots.is_empty() {
        return Vec::new();
    }

    let mut entities: Vec<Entity> = Vec::new();
    let mut seen_emails: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut seen_phones: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut seen_urls: std::collections::HashSet<String> = std::collections::HashSet::new();
    let key_pool = crate::util::key_pool::global_pool();

    for (timestamp, original_url) in &contact_snapshots {
        if ctx.cancel.is_cancelled() {
            break;
        }

        let fetch_url = archive_url(timestamp, original_url);
        let resp = match ctx.http.get(&fetch_url).send_tagged(SRC).await {
            Ok(r) => r,
            Err(_) => {
                tokio::time::sleep(std::time::Duration::from_millis(INTER_SNAPSHOT_MS)).await;
                continue;
            }
        };
        if !resp.status().is_success() {
            tokio::time::sleep(std::time::Duration::from_millis(INTER_SNAPSHOT_MS)).await;
            continue;
        }
        let Some(body) = read_body_capped(resp, SNAPSHOT_BODY_CAP).await else {
            tokio::time::sleep(std::time::Duration::from_millis(INTER_SNAPSHOT_MS)).await;
            continue;
        };

        let ts_iso = iso_from_cdx(timestamp);

        if let Some(u) = mine_url_entity(&mut seen_urls, original_url, &fetch_url, &ts_iso, scan_id)
        {
            entities.push(u);
        }

        for email in crate::util::extract::page_emails(&body) {
            if crate::util::domains::is_infrastructure_email(&email) {
                continue;
            }
            if seen_emails.insert(email.clone()) {
                let mut e = Entity::new(EntityKind::Email, &email, confidence::HIGH_PLUS, scan_id);
                e.tag("wayback-historical");
                e.tag(crate::core::tags::SEARCH_DISCOVERED);
                let ev = Evidence::new(
                    SRC,
                    format!("[wayback] email `{email}` from archived page — {original_url}"),
                )
                .with_attr("archive_url", &fetch_url)
                .with_attr("original_url", original_url.as_str())
                .with_attr("snapshot_timestamp_iso", ts_iso.as_str());
                e.add_evidence(ev);
                entities.push(e);
            }
        }

        for phone in crate::util::extract::phones(&body) {
            if seen_phones.insert(phone.clone()) {
                let mut e = Entity::new(EntityKind::Phone, &phone, confidence::HIGH, scan_id);
                e.tag("wayback-historical");
                e.tag(crate::core::tags::SEARCH_DISCOVERED);
                let ev = Evidence::new(
                    SRC,
                    format!("[wayback] phone `{phone}` from archived page — {original_url}"),
                )
                .with_attr("archive_url", &fetch_url)
                .with_attr("original_url", original_url.as_str())
                .with_attr("snapshot_timestamp_iso", ts_iso.as_str());
                e.add_evidence(ev);
                entities.push(e);
            }
        }

        // An archived page can carry an API key/credential the LIVE site has
        // since removed — the same "secrets outlive the fix" pattern this
        // module already mines contacts for, applied to bytes already in
        // memory (no extra fetch).
        mine_keys_from_body(&key_pool, &body, domain, &ts_iso, original_url);

        tokio::time::sleep(std::time::Duration::from_millis(INTER_SNAPSHOT_MS)).await;
    }

    entities
}

#[async_trait]
impl Module for Wayback {
    fn name(&self) -> &'static str {
        "wayback"
    }

    fn description(&self) -> &'static str {
        "Internet Archive Wayback Machine recon — enumerates snapshot history and extracts historical contact intel"
    }

    fn priority(&self) -> u8 {
        38
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Domain | TargetKind::Url)
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Web
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        // T1596 — Search Open Technical Databases (Wayback Machine is a public
        // web archive, an open technical database). T1589.002 — Email Addresses
        // (contact mining extracts email addresses from archived pages).
        // Superset of the Web default ["T1594", "T1592.002"].
        &["T1596", "T1589.002"]
    }

    fn produces(&self) -> &'static [crate::core::entity::EntityKind] {
        use crate::core::entity::EntityKind;
        const KINDS: &[EntityKind] = &[
            EntityKind::Domain,
            EntityKind::Url,
            EntityKind::Email,
            EntityKind::Phone,
        ];
        KINDS
    }

    fn max_timeout_ms(&self) -> u64 {
        // Three CDX queries (snapshot summary, contact mining, subdomain
        // domain-match) + up to MAX_CONTACT_SNAPSHOTS page fetches with
        // INTER_SNAPSHOT_MS gaps: conservatively 10 × (300ms + 2s latency) = 23s
        // plus the extra fetch-free CDX GET. 30s gives headroom for slow archive
        // responses.
        30_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let domain = extract_domain(target.kind, &target.value);
        if domain.is_empty() {
            return Ok(ModuleResult::new());
        }

        // ── Pass 1: snapshot count + metadata ────────────────────────────────
        let url = format!(
            "https://web.archive.org/cdx/search/cdx?url={}/*&output=json&fl=timestamp,statuscode&limit=1000&collapse=urlkey",
            urlencode(&domain)
        );
        let rows: Vec<Row> = fetch_json(&ctx.http, SRC, &url).await?;

        let mut result = ModuleResult::new();
        if let Some(e) = build_entity(
            target.kind.to_entity_kind(),
            &target.value,
            &rows,
            &ctx.scan_id,
        ) {
            result.push(e);
        }

        // ── Pass 2: mine historical contacts from archived pages ──────────────
        if !ctx.cancel.is_cancelled() {
            for e in mine_contacts(&domain, &ctx.scan_id, ctx).await {
                result.push(e);
            }
        }

        // ── Pass 3: recover DECOMMISSIONED subdomains via CDX domain-match ─────
        // `url=*.{domain}` triggers CDX matchType=domain (the domain + every
        // archived subdomain). No page fetches — just the archived hostname list
        // — so this is the cheap, high-value attack-surface pass that live CT/DNS
        // sources structurally cannot provide.
        if !ctx.cancel.is_cancelled() {
            let sub_url = format!(
                "https://web.archive.org/cdx/search/cdx?url=*.{}&output=json&fl=original&collapse=urlkey&limit=5000",
                urlencode(&domain)
            );
            if let Ok(sub_rows) = fetch_json::<Vec<Row>>(&ctx.http, SRC, &sub_url).await {
                for e in historical_subdomains(&sub_rows, &domain, &ctx.scan_id) {
                    result.push(e);
                }
            }
        }

        Ok(result)
    }
}

/// Convert a CDX timestamp `20140912153012` → `2014-09-12 15:30:12 UTC`
/// for human readability. Falls back to the raw string on parse error.
fn iso_from_cdx(ts: &str) -> String {
    if ts.len() != 14 || !ts.chars().all(|c| c.is_ascii_digit()) {
        return ts.to_string();
    }
    format!(
        "{}-{}-{} {}:{}:{} UTC",
        &ts[0..4],
        &ts[4..6],
        &ts[6..8],
        &ts[8..10],
        &ts[10..12],
        &ts[12..14],
    )
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
