//! IP Australia Trade Marks Register — Australian federal intellectual property
//! register of all trade mark applications, registrations and lapsed marks.
//!
//! Free, keyless. Scrapes the IP Australia trade marks quick-search page:
//! <https://search.ipaustralia.gov.au/trademarks/search/quick>
//!
//! Accepts `FullName` and `Organisation` targets.
//!
//! Emits
//! -----
//! * `Organisation` — the trade mark owner (corporate or individual registrant).
//! * `Address`      — the owner's registered address as published in the register.
//!
//! Confidence
//! ----------
//! * Organisation (registered trade mark owner): 0.78
//! * Address (owner address from IP Australia register): 0.65
//!
//! MITRE ATT&CK
//! ------------
//! * T1591.002 — Business Relationships (trademark → corporate identity)
//! * T1591.001 — Determine Physical Locations (owner registered address)

use async_trait::async_trait;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::html::strip_html;
use crate::util::http::{RequestBuilderExt, UA_BROWSER, read_body_capped};

#[cfg(test)]
mod tests;

pub(super) const SRC: &str = "ip_australia";

/// IP Australia trade marks quick search URL.
const SEARCH_URL: &str = "https://search.ipaustralia.gov.au/trademarks/search/quick";

/// Maximum trade marks processed per search.
const MAX_RESULTS: usize = 20;

const ORG_CONF: f64 = 0.78;
const ADDR_CONF: f64 = 0.65;

/// Australian state/territory abbreviations for address extraction.
const AU_STATES: &[&str] = &["NSW", "VIC", "QLD", "SA", "WA", "TAS", "NT", "ACT"];

pub struct IpAustralia;

// ── Parsing ──────────────────────────────────────────────────────────────────

/// Trade mark status keywords → canonical tag suffix.
const TM_STATUS: &[(&str, &str)] = &[
    ("registered", "registered"),
    ("pending", "pending"),
    ("lapsed", "lapsed"),
    ("removed", "removed"),
    ("opposed", "opposed"),
    ("refused", "refused"),
    ("expired", "expired"),
    ("abandoned", "abandoned"),
    ("accepted", "accepted"),
    ("filed", "filed"),
];

/// Parse the stripped text of an IP Australia trade marks search result page.
///
/// Strategy: scan lines for "owner" or "applicant" anchor words, then examine
/// the surrounding ±5-line window for query-matching organisation names,
/// status keywords, and address localities.
pub(super) fn parse_trademark_html(html: &str, query: &str, scan_id: &str) -> Vec<Entity> {
    let text = strip_html(html);
    let query_lc = query.to_ascii_lowercase();

    let lines: Vec<&str> = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();

    let mut out: Vec<Entity> = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut count = 0;
    let mut i = 0;

    while i < lines.len() && count < MAX_RESULTS {
        let line_lc = lines[i].to_ascii_lowercase();

        // Anchor on "owner" or "applicant" labels used in the IP Australia search results.
        if !line_lc.contains("owner") && !line_lc.contains("applicant") {
            i += 1;
            continue;
        }

        let w_start = i.saturating_sub(5);
        let w_end = (i + 6).min(lines.len());
        let window = &lines[w_start..w_end];

        // Find a name line overlapping with at least one query token (≥3 chars).
        let name_line: Option<&str> = window.iter().copied().find(|l| {
            let ll = l.to_ascii_lowercase();
            l.len() >= 4
                && l.len() <= 100
                && query_lc
                    .split_whitespace()
                    .any(|tok| tok.len() >= 3 && ll.contains(tok))
                // Reject pure keyword / navigation lines.
                && !ll.contains("owner")
                && !ll.contains("applicant")
                && !ll.contains("search")
                && !ll.contains("result")
                && !TM_STATUS.iter().any(|(kw, _)| ll == *kw)
        });

        let Some(name) = name_line else {
            i += 1;
            continue;
        };

        // Status: find matching keyword in window.
        let status_tag: &str = window
            .iter()
            .find_map(|&l| {
                let ll = l.to_ascii_lowercase();
                TM_STATUS
                    .iter()
                    .find(|(kw, _)| ll == *kw || ll.contains(kw))
                    .map(|(_, t)| *t)
            })
            .unwrap_or("filed");

        // Address: line containing an AU state abbreviation.
        let locality: Option<String> = window.iter().find_map(|&l| {
            let state = AU_STATES
                .iter()
                .find(|&&s| l.contains(s) && l.len() <= 60)?;
            let idx = l.find(state)?;
            let suburb_raw = l[..idx].trim().trim_end_matches(',').trim();
            if suburb_raw.is_empty() || suburb_raw.len() > 40 {
                return None;
            }
            let after = l[idx + state.len()..].trim();
            if let Some(pc) = after.split_whitespace().next()
                && pc.len() == 4
                && pc.chars().all(|c| c.is_ascii_digit())
                && pc.parse::<u32>().is_ok_and(|n| (2000..=7999).contains(&n))
            {
                return Some(format!("{suburb_raw}, {state} {pc}"));
            }
            Some(format!("{suburb_raw}, {state}"))
        });

        let key = format!("{}|{status_tag}", name.to_ascii_lowercase());
        if !seen.insert(key) {
            i += 1;
            continue;
        }

        let tm_status_tag = format!("trademark-status:{status_tag}");

        let mut ev = Evidence::new(
            SRC,
            format!("IP Australia Trade Marks: {name} — {status_tag}"),
        )
        .with_attr("source", "ip_australia")
        .with_attr("trademark_status", status_tag);
        if let Some(ref loc) = locality {
            ev = ev.with_attr("address", loc.as_str());
        }

        let mut org = Entity::new(EntityKind::Organisation, name, ORG_CONF, scan_id);
        org.tag(SRC);
        org.tag("ip-australia");
        org.tag("trademark");
        org.tag("country:AU");
        org.tag(tm_status_tag.as_str());
        org.add_evidence(ev);
        out.push(org);

        if let Some(ref locality) = locality {
            let addr_key = format!("addr|{locality}");
            if seen.insert(addr_key) {
                let mut addr =
                    Entity::new(EntityKind::Address, locality.as_str(), ADDR_CONF, scan_id);
                addr.tag(SRC);
                addr.tag("ip-australia");
                addr.tag("country:AU");
                if let Some(st) = AU_STATES.iter().find(|&&s| locality.contains(s)) {
                    addr.tag(format!("au-state:{st}"));
                }
                addr.add_evidence(
                    Evidence::new(SRC, format!("IP Australia registered address for {name}"))
                        .with_attr("source", "ip_australia")
                        .with_attr("owner", name),
                );
                out.push(addr);
            }
        }

        count += 1;
        i += 1;
    }

    out
}

// ── Module impl ───────────────────────────────────────────────────────────────

#[async_trait]
impl Module for IpAustralia {
    fn name(&self) -> &'static str {
        SRC
    }

    fn description(&self) -> &'static str {
        "IP Australia Trade Marks Register — trademark owner identity and address (free, keyless)"
    }

    fn priority(&self) -> u8 {
        // Corporate IP intelligence; lower priority than personnel registers.
        75
    }

    fn cost(&self) -> ModuleCost {
        ModuleCost::Free
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::FullName | TargetKind::Organisation)
            && t.value.trim().len() >= 3
    }

    fn is_passive(&self) -> bool {
        false
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Corporate
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        &["T1591.002", "T1591.001"]
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[EntityKind::Organisation, EntityKind::Address];
        KINDS
    }

    fn max_timeout_ms(&self) -> u64 {
        15_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let query = target.value.trim();

        let url = format!(
            "{}?q={}&n=20",
            SEARCH_URL,
            crate::util::http::urlencode(query),
        );

        let Ok(resp) = ctx
            .http
            .get(&url)
            .header("Accept", "text/html,application/xhtml+xml")
            .header("User-Agent", UA_BROWSER)
            .send_tagged(SRC)
            .await
        else {
            return Ok(ModuleResult::new());
        };

        if !resp.status().is_success() {
            return Ok(ModuleResult::new());
        }

        let Some(html) = read_body_capped(resp, 1_000_000).await else {
            return Ok(ModuleResult::new());
        };

        let entities = parse_trademark_html(&html, query, &ctx.scan_id);
        let mut result = ModuleResult::new();
        result.extend(entities);
        Ok(result)
    }
}
