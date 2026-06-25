//! AFSA National Personal Insolvency Index (NPII) — public register of
//! bankruptcy, debt agreements and personal insolvency agreements in Australia.
//!
//! Free, keyless. Scrapes the AFSA NPII online search:
//! <https://www.afsa.gov.au/online-services/bankruptcy-register-search>
//!
//! Accepts `FullName` targets only (at minimum first + last name tokens).
//!
//! Emits
//! -----
//! * `Person`  — confirmed or former insolvent, tagged with administration type
//!   (`insolvency:bankruptcy`, `insolvency:debt-agreement`, `insolvency:pia`)
//!   and current status (`insolvency:current`, `insolvency:former`, …).
//! * `Address` — registered suburb + state as published in the NPII (locality
//!   only; no street address is published in the public register).
//!
//! Confidence
//! ----------
//! * Person (exact name in federal register): 0.82
//! * Address (as-registered suburb/state): 0.65
//!
//! MITRE ATT&CK
//! ------------
//! * T1591.001 — Determine Physical Locations (suburb + state from NPII)
//! * T1589.003 — Employee Names (legal name confirmed in federal register)

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

pub(super) const SRC: &str = "afsa_insolvency";

/// AFSA NPII search base URL.
/// Uses Rails Ransack query params: `search[name_cont]=<name>`.
const SEARCH_URL: &str = "https://www.afsa.gov.au/online-services/bankruptcy-register-search";

/// Maximum records turned into entities per search — prevents graph flooding
/// on a common surname.
const MAX_RESULTS: usize = 20;

const PERSON_CONF: f64 = 0.82;
const ADDR_CONF: f64 = 0.65;

pub struct AfsaInsolvency;

// ── Parsing ──────────────────────────────────────────────────────────────────

/// Administration type keywords → canonical tag.
const ADMIN_TYPES: &[(&str, &str)] = &[
    ("bankruptcy", "insolvency:bankruptcy"),
    ("sequestration order", "insolvency:bankruptcy"),
    ("debt agreement", "insolvency:debt-agreement"),
    ("personal insolvency agreement", "insolvency:pia"),
    ("part x", "insolvency:part-x"),
    ("deceased estate", "insolvency:deceased-estate"),
];

/// Status keywords → canonical tag.
const STATUS_KW: &[(&str, &str)] = &[
    ("current", "insolvency:current"),
    ("annulled", "insolvency:annulled"),
    ("discharged", "insolvency:former"),
    ("completed", "insolvency:former"),
    ("terminated", "insolvency:terminated"),
    ("revoked", "insolvency:revoked"),
];

/// Australian state/territory abbreviations used in address extraction.
const AU_STATES: &[&str] = &["NSW", "VIC", "QLD", "SA", "WA", "TAS", "NT", "ACT"];

/// Parse the stripped text of an AFSA NPII result page.
///
/// Strategy: scan text lines for administration-type keywords; when found,
/// search the surrounding ±5-line window for a name that overlaps with the
/// query and for a suburb/state locality. Pure function — no I/O.
pub(super) fn parse_npii_html(html: &str, query_name: &str, scan_id: &str) -> Vec<Entity> {
    let text = strip_html(html);
    let query_lc = query_name.to_ascii_lowercase();

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

        let Some((_, admin_tag)) = ADMIN_TYPES.iter().find(|(kw, _)| line_lc.contains(kw)) else {
            i += 1;
            continue;
        };

        let w_start = i.saturating_sub(5);
        let w_end = (i + 6).min(lines.len());
        let window = &lines[w_start..w_end];

        // Find the most plausible name in the window — a short line that
        // contains at least one query token (≥3 chars), is purely alphabetic +
        // spaces/hyphens/apostrophes, and doesn't look like a header or status word.
        let name_line: Option<&str> = window.iter().copied().find(|l| {
            let ll = l.to_ascii_lowercase();
            l.len() >= 4
                && l.len() <= 80
                && query_lc
                    .split_whitespace()
                    .any(|tok| tok.len() >= 3 && ll.contains(tok))
                && l.chars()
                    .all(|c| c.is_alphabetic() || matches!(c, ' ' | '-' | '\'' | ','))
                // Don't misread keyword lines as names.
                && ADMIN_TYPES.iter().all(|(kw, _)| !ll.contains(kw))
                && STATUS_KW.iter().all(|(kw, _)| !ll.contains(kw))
        });

        let Some(name) = name_line else {
            i += 1;
            continue;
        };

        // Status.
        let status_tag: &str = window
            .iter()
            .find_map(|&l| {
                let ll = l.to_ascii_lowercase();
                STATUS_KW
                    .iter()
                    .find(|(kw, _)| ll.contains(kw))
                    .map(|(_, t)| *t)
            })
            .unwrap_or("insolvency:current");

        // Suburb + state locality.
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

        // Dedup by (name, admin_tag).
        let key = format!("{}|{admin_tag}", name.to_ascii_lowercase());
        if !seen.insert(key) {
            i += 1;
            continue;
        }

        let admin_label = admin_tag.trim_start_matches("insolvency:");

        let mut ev = Evidence::new(
            SRC,
            format!("AFSA NPII: {name} — {admin_label} ({status_tag})"),
        )
        .with_attr("source", "afsa_npii")
        .with_attr("administration_type", admin_label)
        .with_attr("status", status_tag);
        if let Some(ref loc) = locality {
            ev = ev.with_attr("suburb_state", loc.as_str());
        }

        let mut person = Entity::new(EntityKind::Person, name, PERSON_CONF, scan_id);
        person.tag(SRC);
        person.tag("afsa-npii");
        person.tag("country:AU");
        person.tag(*admin_tag);
        person.tag(status_tag);
        person.add_evidence(ev);
        out.push(person);

        if let Some(ref locality) = locality {
            let mut addr = Entity::new(EntityKind::Address, locality.as_str(), ADDR_CONF, scan_id);
            addr.tag(SRC);
            addr.tag("afsa-npii");
            addr.tag("country:AU");
            if let Some(st) = AU_STATES.iter().find(|&&s| locality.contains(s)) {
                addr.tag(format!("au-state:{st}"));
            }
            addr.add_evidence(
                Evidence::new(SRC, format!("AFSA NPII registered locality for {name}"))
                    .with_attr("source", "afsa_npii")
                    .with_attr("name", name),
            );
            out.push(addr);
        }

        count += 1;
        i += 1;
    }

    out
}

// ── Module impl ───────────────────────────────────────────────────────────────

#[async_trait]
impl Module for AfsaInsolvency {
    fn name(&self) -> &'static str {
        SRC
    }

    fn description(&self) -> &'static str {
        "AFSA National Personal Insolvency Index — bankruptcy, debt agreements and PIAs (free, keyless)"
    }

    fn priority(&self) -> u8 {
        // Government / public-records band (110-118); high-signal people pivot.
        116
    }

    fn cost(&self) -> ModuleCost {
        ModuleCost::Free
    }

    fn accepts(&self, t: &Target) -> bool {
        // FullName only; require at least first + last name tokens.
        t.kind == TargetKind::FullName && t.value.trim().contains(' ')
    }

    fn is_passive(&self) -> bool {
        false
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Corporate
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        &["T1591.001", "T1589.003"]
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[EntityKind::Person, EntityKind::Address];
        KINDS
    }

    fn max_timeout_ms(&self) -> u64 {
        18_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let full_name = target.value.trim();

        let url = format!(
            "{}?search%5Bname_cont%5D={}",
            SEARCH_URL,
            crate::util::http::urlencode(full_name),
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

        let entities = parse_npii_html(&html, full_name, &ctx.scan_id);
        let mut result = ModuleResult::new();
        result.extend(entities);
        Ok(result)
    }
}
