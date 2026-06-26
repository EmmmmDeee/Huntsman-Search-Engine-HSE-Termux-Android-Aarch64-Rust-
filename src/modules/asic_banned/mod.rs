//! ASIC Banned and Disqualified Persons register — federal enforcement records
//! for individuals formally banned or disqualified by the Australian Securities
//! and Investments Commission.
//!
//! Free, keyless. Scrapes the ASIC banned & disqualified persons public search:
//! <https://asic.gov.au/online-services/search-asic-s-registers/banned-and-disqualified/>
//!
//! Accepts `FullName` targets (first + last name) and `Organisation` targets.
//!
//! Emits
//! -----
//! * `Person`  — a formally banned or disqualified individual, tagged with ban
//!   type (`asic:banned-financial`, `asic:banned-credit`, `asic:disqualified`)
//!   and permanence (`asic:permanent`, `asic:temporary`).
//!
//! Confidence
//! ----------
//! * Person (exact name in ASIC federal enforcement register): 0.88
//!
//! MITRE ATT&CK
//! ------------
//! * T1591.001 — Determine Physical Locations
//! * T1589.003 — Employee Names (legal name confirmed in ASIC enforcement register)

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

pub(super) const SRC: &str = "asic_banned";

/// ASIC banned & disqualified persons search base URL (GET with name + action).
const SEARCH_URL: &str =
    "https://asic.gov.au/online-services/search-asic-s-registers/banned-and-disqualified/";

/// Maximum persons emitted per search to prevent graph flooding.
const MAX_RESULTS: usize = 20;

const PERSON_CONF: f64 = 0.88;

pub struct AsicBanned;

// ── Parsing ──────────────────────────────────────────────────────────────────

/// Ban reason keywords → canonical tag suffix.
const BAN_TYPES: &[(&str, &str)] = &[
    (
        "banned from providing financial services",
        "banned-financial",
    ),
    ("banned from providing credit assistance", "banned-credit"),
    ("banned from engaging in credit activities", "banned-credit"),
    ("disqualified from managing corporations", "disqualified"),
    ("disqualified from managing a corporation", "disqualified"),
    (
        "suspended from providing financial services",
        "suspended-financial",
    ),
    ("suspended from providing credit", "suspended-credit"),
    ("banned from acting as", "banned-financial"),
    ("banned from", "banned-financial"),
    ("disqualified", "disqualified"),
];

/// Duration indicators → permanence tag.
const PERMANENT_KW: &[&str] = &["permanently", "n/a", "indefinite", "permanent"];

/// Parse the stripped text of an ASIC banned register result page.
///
/// Strategy: scan lines for ban-reason keywords; when found, examine the
/// surrounding ±6-line window for a name that overlaps with the query
/// tokens. Pure function — no I/O.
pub(super) fn parse_banned_html(html: &str, query: &str, scan_id: &str) -> Vec<Entity> {
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

        let Some((_, ban_suffix)) = BAN_TYPES.iter().find(|(kw, _)| line_lc.contains(kw)) else {
            i += 1;
            continue;
        };

        let w_start = i.saturating_sub(6);
        let w_end = (i + 7).min(lines.len());
        let window = &lines[w_start..w_end];

        // Find most plausible name: a short line overlapping with at least one
        // query token (≥3 chars), purely alphabetic + spaces/hyphens/commas.
        let name_line: Option<&str> = window.iter().copied().find(|l| {
            let ll = l.to_ascii_lowercase();
            l.len() >= 4
                && l.len() <= 80
                && query_lc
                    .split_whitespace()
                    .any(|tok| tok.len() >= 3 && ll.contains(tok))
                && l.chars()
                    .all(|c| c.is_alphabetic() || matches!(c, ' ' | '-' | '\'' | ','))
                && BAN_TYPES.iter().all(|(kw, _)| !ll.contains(kw))
        });

        let Some(name) = name_line else {
            i += 1;
            continue;
        };

        // Permanence: does any window line contain a permanence keyword?
        let is_permanent = window.iter().any(|&l| {
            let ll = l.to_ascii_lowercase();
            PERMANENT_KW.iter().any(|kw| ll.contains(kw))
        });
        let permanence_tag = if is_permanent {
            "asic:permanent"
        } else {
            "asic:temporary"
        };

        let key = format!("{}|{ban_suffix}", name.to_ascii_lowercase());
        if !seen.insert(key) {
            i += 1;
            continue;
        }

        let ban_tag = format!("asic:{ban_suffix}");
        let ev = Evidence::new(
            SRC,
            format!("ASIC Banned Register: {name} — {ban_suffix} ({permanence_tag})"),
        )
        .with_attr("source", "asic_banned_register")
        .with_attr("ban_type", *ban_suffix)
        .with_attr("permanence", permanence_tag);

        let mut person = Entity::new(EntityKind::Person, name, PERSON_CONF, scan_id);
        person.tag(SRC);
        person.tag("asic-banned");
        person.tag("country:AU");
        person.tag(ban_tag.as_str());
        person.tag(permanence_tag);
        person.add_evidence(ev);
        out.push(person);

        count += 1;
        i += 1;
    }

    out
}

// ── Module impl ───────────────────────────────────────────────────────────────

#[async_trait]
impl Module for AsicBanned {
    fn name(&self) -> &'static str {
        SRC
    }

    fn description(&self) -> &'static str {
        "ASIC Banned and Disqualified Persons register — federal enforcement records (free, keyless)"
    }

    fn priority(&self) -> u8 {
        // Federal enforcement register; very high-signal people finding.
        110
    }

    fn cost(&self) -> ModuleCost {
        ModuleCost::Free
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::FullName | TargetKind::Organisation)
            && t.value.trim().contains(' ')
    }

    fn is_passive(&self) -> bool {
        false
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::People
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        &["T1591.001", "T1589.003"]
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[EntityKind::Person];
        KINDS
    }

    fn max_timeout_ms(&self) -> u64 {
        18_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let query = target.value.trim();

        let url = format!(
            "{}?name={}&action_doSearch=Search",
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

        let entities = parse_banned_html(&html, query, &ctx.scan_id);
        let mut result = ModuleResult::new();
        result.extend(entities);
        Ok(result)
    }
}
