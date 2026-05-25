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
    module::{Module, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::{fetch_json, urlencode};

pub struct Wayback;

/// CDX API returns a 2-D array; first row is the column header, the
/// rest are data rows. We only request `timestamp,statuscode`, so each
/// data row is exactly two elements.
#[derive(Deserialize)]
struct Row(Vec<String>);

#[async_trait]
impl Module for Wayback {
    fn name(&self) -> &'static str {
        "wayback"
    }

    fn priority(&self) -> u8 {
        38
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Domain)
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let domain = target.value.trim().to_lowercase();
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

        let rows: Vec<Row> = fetch_json(&ctx.http, "wayback", &url).await?;

        // First row is the column header; skip it. Avoid collecting into
        // an intermediate Vec — we only need the count and bookend timestamps.
        if rows.len() <= 1 {
            // Domain not archived — not necessarily suspicious (private
            // sites are routinely excluded), just no findings.
            return Ok(ModuleResult::new());
        }

        let count = rows.len() - 1; // exclude header row
        // CDX rows come timestamp-sorted ascending. Second row = earliest
        // snapshot (first is header), last row = most recent.
        let first_ts = rows.get(1).and_then(|r| r.0.first());
        let last_ts = rows.last().and_then(|r| r.0.first());

        let mut entity = Entity::new(EntityKind::Domain, &domain, 0.80, &ctx.scan_id);
        entity.tag("archived");
        let mut ev = Evidence::new(
            "wayback",
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
        entity.add_evidence(ev);

        let mut result = ModuleResult::new();
        result.push(entity);
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
    fn accepts_only_domain() {
        let m = Wayback;
        assert!(m.accepts(&Target::new(TargetKind::Domain, "example.com")));
        assert!(!m.accepts(&Target::new(TargetKind::IpAddress, "1.1.1.1")));
    }

    #[test]
    fn iso_conversion() {
        assert_eq!(iso_from_cdx("20140912153012"), "2014-09-12 15:30:12 UTC");
        assert_eq!(iso_from_cdx("not-a-timestamp"), "not-a-timestamp");
        assert_eq!(iso_from_cdx("12345"), "12345");
    }
}
