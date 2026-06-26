//! ASIC Financial Services Register (FSR) — Australia's central register of
//! authorised financial services licensees, credit licensees, financial
//! advisers and credit representatives.
//!
//! Free, keyless. Queries the ASIC Connect Online professional-registers search:
//! <https://asic.gov.au/online-services/search-asic-s-registers/professional-registers/>
//!
//! Accepts `FullName` targets (first + last name) and `Organisation` targets.
//!
//! Emits
//! -----
//! * `Person`       — a named financial adviser or credit representative.
//! * `Organisation` — an AFS or credit licensee company.
//! * `Address`      — the registered principal business address from the FSR.
//!
//! Confidence
//! ----------
//! * Person (named individual in ASIC FSR): 0.83
//! * Organisation (AFS/credit licensee): 0.80
//! * Address (principal business address): 0.68
//!
//! MITRE ATT&CK
//! ------------
//! * T1591.001 — Determine Physical Locations (registered address)
//! * T1591.002 — Business Relationships (licensee ↔ adviser link)
//! * T1589.003 — Employee Names (confirmed individual in ASIC register)

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

pub(super) const SRC: &str = "asic_fsr";

/// ASIC professional registers search URL.
const SEARCH_URL: &str =
    "https://asic.gov.au/online-services/search-asic-s-registers/professional-registers/";

/// Maximum result sets processed per search.
const MAX_RESULTS: usize = 20;

const PERSON_CONF: f64 = 0.83;
const ORG_CONF: f64 = 0.80;
const ADDR_CONF: f64 = 0.68;

/// Australian state/territory abbreviations for address extraction.
const AU_STATES: &[&str] = &["NSW", "VIC", "QLD", "SA", "WA", "TAS", "NT", "ACT"];

pub struct AsicFsr;

// ── Parsing ──────────────────────────────────────────────────────────────────

/// Register type keywords → canonical tag suffix.
const REGISTER_TYPES: &[(&str, &str)] = &[
    ("australian financial services licensee", "afs-licensee"),
    ("afs licensee", "afs-licensee"),
    ("financial services licensee", "afs-licensee"),
    ("australian credit licensee", "credit-licensee"),
    ("credit licensee", "credit-licensee"),
    ("financial adviser", "financial-adviser"),
    ("financial advisor", "financial-adviser"),
    ("credit representative", "credit-representative"),
    ("authorised representative", "authorised-representative"),
    ("responsible manager", "responsible-manager"),
];

/// Parse the stripped text of an ASIC FSR result page.
///
/// Strategy: scan lines for register-type keywords; when found, examine the
/// surrounding ±6-line window for a name that overlaps with query tokens,
/// a company name, and an address locality.
pub(super) fn parse_fsr_html(html: &str, query: &str, scan_id: &str) -> Vec<Entity> {
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

        let Some((_, reg_suffix)) = REGISTER_TYPES.iter().find(|(kw, _)| line_lc.contains(kw))
        else {
            i += 1;
            continue;
        };

        let w_start = i.saturating_sub(6);
        let w_end = (i + 7).min(lines.len());
        let window = &lines[w_start..w_end];

        let is_individual_reg = matches!(
            *reg_suffix,
            "financial-adviser" | "credit-representative" | "authorised-representative"
        );

        // Find name: line overlapping with query tokens, alphabetic chars only.
        let name_line: Option<&str> = window.iter().copied().find(|l| {
            let ll = l.to_ascii_lowercase();
            l.len() >= 4
                && l.len() <= 80
                && query_lc
                    .split_whitespace()
                    .any(|tok| tok.len() >= 3 && ll.contains(tok))
                && l.chars()
                    .all(|c| c.is_alphabetic() || matches!(c, ' ' | '-' | '\'' | ','))
                && REGISTER_TYPES.iter().all(|(kw, _)| !ll.contains(kw))
        });

        let Some(name) = name_line else {
            i += 1;
            continue;
        };

        let key = format!("{}|{reg_suffix}", name.to_ascii_lowercase());
        if !seen.insert(key) {
            i += 1;
            continue;
        }

        // Locality: find a line containing an AU state abbreviation.
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

        let reg_tag = format!("asic-fsr:{reg_suffix}");
        let ev_desc = format!("ASIC FSR: {name} — {reg_suffix}");

        if is_individual_reg {
            let mut ev = Evidence::new(SRC, ev_desc)
                .with_attr("source", "asic_fsr")
                .with_attr("register_type", *reg_suffix);
            if let Some(ref loc) = locality {
                ev = ev.with_attr("address", loc.as_str());
            }

            let mut person = Entity::new(EntityKind::Person, name, PERSON_CONF, scan_id);
            person.tag(SRC);
            person.tag("asic-fsr");
            person.tag("country:AU");
            person.tag(reg_tag.as_str());
            person.add_evidence(ev);
            out.push(person);
        } else {
            let mut ev = Evidence::new(SRC, ev_desc)
                .with_attr("source", "asic_fsr")
                .with_attr("register_type", *reg_suffix);
            if let Some(ref loc) = locality {
                ev = ev.with_attr("address", loc.as_str());
            }

            let mut org = Entity::new(EntityKind::Organisation, name, ORG_CONF, scan_id);
            org.tag(SRC);
            org.tag("asic-fsr");
            org.tag("country:AU");
            org.tag(reg_tag.as_str());
            org.add_evidence(ev);
            out.push(org);
        }

        if let Some(ref locality) = locality {
            let loc_key = format!("addr|{locality}");
            if seen.insert(loc_key) {
                let mut addr =
                    Entity::new(EntityKind::Address, locality.as_str(), ADDR_CONF, scan_id);
                addr.tag(SRC);
                addr.tag("asic-fsr");
                addr.tag("country:AU");
                if let Some(st) = AU_STATES.iter().find(|&&s| locality.contains(s)) {
                    addr.tag(format!("au-state:{st}"));
                }
                addr.add_evidence(
                    Evidence::new(SRC, format!("ASIC FSR registered address for {name}"))
                        .with_attr("source", "asic_fsr")
                        .with_attr("name", name),
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
impl Module for AsicFsr {
    fn name(&self) -> &'static str {
        SRC
    }

    fn description(&self) -> &'static str {
        "ASIC Financial Services Register — AFS/credit licensees, advisers and representatives (free, keyless)"
    }

    fn priority(&self) -> u8 {
        // Government professional-licencing register; high-signal for financial-sector people.
        106
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
        &["T1591.001", "T1591.002", "T1589.003"]
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[
            EntityKind::Person,
            EntityKind::Organisation,
            EntityKind::Address,
        ];
        KINDS
    }

    fn max_timeout_ms(&self) -> u64 {
        18_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let query = target.value.trim();

        let url = format!(
            "{}?query={}&action_doSearch=Search",
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

        let entities = parse_fsr_html(&html, query, &ctx.scan_id);
        let mut result = ModuleResult::new();
        result.extend(entities);
        Ok(result)
    }
}
