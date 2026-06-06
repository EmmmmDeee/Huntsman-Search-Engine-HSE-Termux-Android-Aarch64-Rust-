//! Wayback Machine CDX API — historical snapshots of a domain.
//!
//! Free, no key. Endpoint:
//!   `https://web.archive.org/cdx/search/cdx?url={domain}/*&output=json
//!    &fl=timestamp,statuscode&limit=1000&collapse=urlkey`
//!
//! Returns the count of distinct historical URLs the Wayback Machine
//! holds for the target domain, plus the first-seen and last-seen
//! timestamps. Useful for:
//!   * Confirming a domain isn't newly-registered (low snapshot count
//!     + recent first-seen = suspicious).
//!   * AU-010 infrastructure consensus — another independent source
//!     confirming the domain existed.

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::freq::top_n;
use crate::util::http::{fetch_json, urlencode};

const SRC: &str = "wayback";

pub struct Wayback;

/// CDX API returns a 2-D array; first row is the column header, the
/// rest are data rows. We only request `timestamp,statuscode`, so each
/// data row is exactly two elements.
#[derive(Deserialize)]
struct Row(Vec<String>);

/// Reduce a target to the bare lowercase host the CDX query keys on. **Pure**:
/// a `Url` is stripped of its scheme, path and port; anything else is just
/// trimmed and lowercased. Returns `""` when nothing host-like remains.
fn extract_domain(kind: TargetKind, value: &str) -> String {
    let trimmed = value.trim();
    match kind {
        TargetKind::Url => trimmed
            .strip_prefix("https://")
            .or_else(|| trimmed.strip_prefix("http://"))
            .unwrap_or(trimmed)
            .split('/')
            .next()
            .unwrap_or("")
            .split(':')
            .next()
            .unwrap_or("")
            .to_lowercase(),
        _ => trimmed.to_lowercase(),
    }
}

/// Build the archive entity from CDX rows. **Pure** (no network/IO). The first
/// row is the CDX column header, so a response of `rows.len() <= 1` means the
/// domain is unarchived → `None`. Otherwise the data rows (timestamp-sorted
/// ascending) yield the snapshot count, the earliest/most-recent bookend
/// timestamps (raw + ISO), and the HTTP status-code distribution.
fn build_entity(kind: EntityKind, value: &str, rows: &[Row], scan_id: &str) -> Option<Entity> {
    if rows.len() <= 1 {
        // Domain not archived — not necessarily suspicious (private sites are
        // routinely excluded), just no findings.
        return None;
    }
    let count = rows.len() - 1; // exclude header row
    // CDX rows come timestamp-sorted ascending. Second row = earliest snapshot
    // (first is header), last row = most recent.
    let first_ts = rows.get(1).and_then(|r| r.0.first());
    let last_ts = rows.last().and_then(|r| r.0.first());

    // Status codes live at index 1 of each data row (fl=timestamp,statuscode).
    let status_dist = top_n(
        rows[1..]
            .iter()
            .filter_map(|r| r.0.get(1).map(String::as_str)),
        10,
    );

    let mut entity = Entity::new(kind, value, 0.80, scan_id);
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

#[async_trait]
impl Module for Wayback {
    fn name(&self) -> &'static str {
        "wayback"
    }

    fn description(&self) -> &'static str {
        "Internet Archive Wayback Machine history lookup"
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

    fn max_timeout_ms(&self) -> u64 {
        // Single network request with no per-request timeout; the 3s default
        // would kill a slow-but-connected response as a spurious "timeout".
        10_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let domain = extract_domain(target.kind, &target.value);
        if domain.is_empty() {
            return Ok(ModuleResult::new());
        }

        // collapse=urlkey deduplicates same-URL snapshots; limit=1000
        // caps response size for very old domains (some have millions
        // of snapshots — we just need the count and bookends).
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
    use super::*;

    #[test]
    fn accepts_domain_and_url() {
        let m = Wayback;
        assert!(m.accepts(&Target::new(TargetKind::Domain, "example.com")));
        assert!(m.accepts(&Target::new(TargetKind::Url, "https://example.com/p")));
        assert!(!m.accepts(&Target::new(TargetKind::IpAddress, "1.1.1.1")));
    }

    #[test]
    fn iso_conversion() {
        assert_eq!(iso_from_cdx("20140912153012"), "2014-09-12 15:30:12 UTC");
        assert_eq!(iso_from_cdx("not-a-timestamp"), "not-a-timestamp");
        assert_eq!(iso_from_cdx("12345"), "12345");
    }

    #[test]
    fn extract_domain_strips_scheme_path_port_and_lowercases() {
        assert_eq!(
            extract_domain(TargetKind::Url, "https://Example.COM:8443/a/b?x=1"),
            "example.com"
        );
        assert_eq!(
            extract_domain(TargetKind::Url, "http://sub.host.org/"),
            "sub.host.org"
        );
        // Non-URL kinds are just trimmed + lowercased.
        assert_eq!(
            extract_domain(TargetKind::Domain, "  Example.com "),
            "example.com"
        );
        assert_eq!(extract_domain(TargetKind::Domain, ""), "");
    }

    fn row(cells: &[&str]) -> Row {
        Row(cells.iter().map(|s| s.to_string()).collect())
    }

    fn attr<'a>(e: &'a Entity, k: &str) -> Option<&'a str> {
        e.evidence[0].attributes.get(k).map(String::as_str)
    }

    #[test]
    fn header_only_or_empty_response_yields_no_entity() {
        assert!(build_entity(EntityKind::Domain, "x.com", &[], "s").is_none());
        // Header row only — domain unarchived.
        let header = [row(&["timestamp", "statuscode"])];
        assert!(build_entity(EntityKind::Domain, "x.com", &header, "s").is_none());
    }

    #[test]
    fn counts_snapshots_and_picks_bookend_timestamps() {
        let rows = [
            row(&["timestamp", "statuscode"]), // header
            row(&["20140912153012", "200"]),   // earliest
            row(&["20160101000000", "301"]),
            row(&["20200722120000", "200"]), // most recent
        ];
        let e = build_entity(EntityKind::Domain, "example.com", &rows, "s").unwrap();
        assert_eq!(e.kind, EntityKind::Domain);
        assert!(e.has_tag("archived"));
        assert!((e.confidence - 0.80).abs() < 1e-9);
        assert_eq!(attr(&e, "snapshot_count"), Some("3")); // header excluded
        assert_eq!(attr(&e, "first_seen"), Some("20140912153012"));
        assert_eq!(attr(&e, "first_seen_iso"), Some("2014-09-12 15:30:12 UTC"));
        assert_eq!(attr(&e, "last_seen"), Some("20200722120000"));
        assert_eq!(attr(&e, "last_seen_iso"), Some("2020-07-22 12:00:00 UTC"));
        // 200 appears twice, 301 once → ranked by frequency.
        assert_eq!(attr(&e, "status_distribution"), Some("200×2, 301×1"));
    }
}
