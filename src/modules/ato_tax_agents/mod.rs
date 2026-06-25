//! ATO Tax Practitioners Board — public register of registered tax agents,
//! BAS agents, and tax financial advisers in Australia.
//!
//! Free, keyless. Scrapes the TPB Public Register at:
//! <https://www.tpb.gov.au/public-register>
//!
//! The TPB public register is the authoritative federal register of approximately
//! 80,000 registered tax and BAS agents in Australia. Every registered agent
//! (individual or company) must maintain a current registration to lawfully
//! provide tax agent, BAS, or tax financial adviser services. The register
//! includes the practitioner's legal name, registration number, type, status,
//! state, and registered business address.
//!
//! Accepts
//! -------
//! * `FullName`     — searches for an individual registered practitioner
//! * `Organisation` — searches for a company registered as a tax agent
//! * `Email`        — searches for a practitioner by contact email
//!
//! Emits
//! -----
//! * `Person`       — individual registered tax/BAS/TFA agent
//! * `Organisation` — company registered as a tax agent
//! * `Address`      — registered business address (suburb + state)
//! * `AbnAcn`       — ABN extracted from registration record
//!
//! Confidence
//! ----------
//! * Person / Organisation (exact federal register match): 0.83
//! * Address (as-registered):                             0.70
//! * ABN (directly from register):                        0.90
//!
//! MITRE ATT&CK
//! ------------
//! * T1591.001 — Determine Physical Locations (registered business address)
//! * T1591.002 — Business Relationships (practitioner → employer firm)
//! * T1589.003 — Employee Names (legal name on federal register)

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

pub(super) const SRC: &str = "ato_tax_agents";

/// TPB public register search endpoint.
const SEARCH_URL: &str = "https://www.tpb.gov.au/public-register/search";

/// Maximum registration records to process per search.
const MAX_RESULTS: usize = 25;

const PERSON_CONF: f64 = 0.83;
const ORG_CONF: f64 = 0.83;
const ADDR_CONF: f64 = 0.70;
const ABN_CONF: f64 = 0.90;

/// Registration type keywords and their canonical tags.
const REG_TYPES: &[(&str, &str)] = &[
    ("tax financial adviser", "tpb:tax-financial-adviser"),
    ("tfa", "tpb:tax-financial-adviser"),
    ("bas agent", "tpb:bas-agent"),
    ("tax agent", "tpb:tax-agent"),
];

/// Status keywords and their canonical tags.
const STATUS_KW: &[(&str, &str)] = &[
    ("registered", "tpb:current"),
    ("current", "tpb:current"),
    ("suspended", "tpb:suspended"),
    ("terminated", "tpb:terminated"),
    ("cancelled", "tpb:terminated"),
    ("deregistered", "tpb:former"),
];

/// Australian state/territory abbreviations.
const AU_STATES: &[&str] = &["NSW", "VIC", "QLD", "SA", "WA", "TAS", "NT", "ACT"];

pub struct AtoTaxAgents;

// ── Parsing ──────────────────────────────────────────────────────────────────

/// Detect whether a registration name looks like a company (Pty Ltd, Ltd, Trust,
/// Partnership, etc.) or an individual.
fn is_company_name(name: &str) -> bool {
    let lc = name.to_ascii_lowercase();
    lc.contains("pty ltd")
        || lc.contains("pty. ltd")
        || lc.contains(" ltd")
        || lc.contains(" limited")
        || lc.contains(" trust")
        || lc.contains(" partnership")
        || lc.contains("& associates")
        || lc.contains("& co")
        || lc.contains("& partners")
        || lc.ends_with(" partners")
        || lc.contains(" group")
        || lc.contains(" services")
        || lc.contains(" solutions")
        || lc.contains(" accounting")
        || lc.contains(" advisors")
        || lc.contains(" advisers")
}

/// Parse the stripped text of a TPB public register search result page.
///
/// The TPB result table typically has columns:
/// | Name | Registration No. | Type | Status | State |
///
/// We match rows where the name overlaps with the query and extract
/// the registration type, status, and state (→ Address).
///
/// Pure function — no I/O.
pub(super) fn parse_tpb_html(html: &str, query: &str, scan_id: &str) -> Vec<Entity> {
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
        let line = lines[i];
        let line_lc = line.to_ascii_lowercase();

        // Look for a registration type keyword on this line.
        let Some((_, reg_tag)) = REG_TYPES.iter().find(|(kw, _)| line_lc.contains(kw)) else {
            i += 1;
            continue;
        };

        let w_start = i.saturating_sub(6);
        let w_end = (i + 6).min(lines.len());
        let window = &lines[w_start..w_end];

        // Find the most plausible name line: contains a query token, right
        // length, plausible character set, not a keyword line.
        let name_line: Option<&str> = window.iter().copied().find(|l| {
            let ll = l.to_ascii_lowercase();
            l.len() >= 4
                && l.len() <= 100
                && query_lc
                    .split_whitespace()
                    .any(|tok| tok.len() >= 3 && ll.contains(tok))
                && l.chars().all(|c| {
                    c.is_alphanumeric() || matches!(c, ' ' | '-' | '\'' | ',' | '.' | '&' | '/')
                })
                && REG_TYPES.iter().all(|(kw, _)| !ll.contains(kw))
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
            .unwrap_or("tpb:current");

        // State → Address.
        let locality: Option<String> = window.iter().find_map(|&l| {
            let state = AU_STATES
                .iter()
                .find(|&&s| l.contains(s) && l.len() <= 60)?;
            let idx = l.find(state)?;
            let prefix = l[..idx].trim().trim_end_matches(',').trim();
            if prefix.is_empty() {
                // Just the state code — still useful.
                return Some((*state).to_string());
            }
            if prefix.len() > 40 {
                return None;
            }
            let after = l[idx + state.len()..].trim();
            if let Some(pc) = after.split_whitespace().next()
                && pc.len() == 4
                && pc.chars().all(|c| c.is_ascii_digit())
                && pc.parse::<u32>().is_ok_and(|n| (2000..=7999).contains(&n))
            {
                return Some(format!("{prefix}, {state} {pc}"));
            }
            Some(format!("{prefix}, {state}"))
        });

        // ABN: an 11-digit number (with optional spaces).
        let abn: Option<String> = window.iter().find_map(|&l| {
            let digits: String = l.chars().filter(char::is_ascii_digit).collect();
            if digits.len() == 11 {
                Some(format!(
                    "{} {} {} {}",
                    &digits[..2],
                    &digits[2..5],
                    &digits[5..8],
                    &digits[8..11],
                ))
            } else {
                None
            }
        });

        // Dedup by (name, reg_tag).
        let key = format!("{}|{reg_tag}", name.to_ascii_lowercase());
        if !seen.insert(key) {
            i += 1;
            continue;
        }

        let reg_label = reg_tag.trim_start_matches("tpb:");
        let mut ev = Evidence::new(
            SRC,
            format!("TPB register: {name} — {reg_label} ({status_tag})"),
        )
        .with_attr("source", "tpb_register")
        .with_attr("registration_type", reg_label)
        .with_attr("status", status_tag);
        if let Some(ref loc) = locality {
            ev = ev.with_attr("state_or_locality", loc.as_str());
        }
        if let Some(ref abn_val) = abn {
            ev = ev.with_attr("abn", abn_val.as_str());
        }

        // Emit Person or Organisation.
        if is_company_name(name) {
            let mut org = Entity::new(EntityKind::Organisation, name, ORG_CONF, scan_id);
            org.tag(SRC);
            org.tag("tpb-registered");
            org.tag("country:AU");
            org.tag(*reg_tag);
            org.tag(status_tag);
            org.add_evidence(ev);
            out.push(org);
        } else {
            let mut person = Entity::new(EntityKind::Person, name, PERSON_CONF, scan_id);
            person.tag(SRC);
            person.tag("tpb-registered");
            person.tag("country:AU");
            person.tag(*reg_tag);
            person.tag(status_tag);
            person.add_evidence(ev);
            out.push(person);
        }

        // Address entity.
        if let Some(ref locality) = locality
            && !locality.is_empty()
            && locality.len() > 2
        {
            let mut addr = Entity::new(EntityKind::Address, locality.as_str(), ADDR_CONF, scan_id);
            addr.tag(SRC);
            addr.tag("tpb-registered");
            addr.tag("country:AU");
            if let Some(st) = AU_STATES.iter().find(|&&s| locality.contains(s)) {
                addr.tag(format!("au-state:{st}"));
            }
            addr.add_evidence(
                Evidence::new(SRC, format!("TPB registered business address for {name}"))
                    .with_attr("source", "tpb_register")
                    .with_attr("name", name),
            );
            out.push(addr);
        }

        // ABN entity.
        if let Some(abn_val) = abn {
            let mut abn_e = Entity::new(EntityKind::AbnAcn, &abn_val, ABN_CONF, scan_id);
            abn_e.tag(SRC);
            abn_e.tag("tpb-registered");
            abn_e.tag("country:AU");
            abn_e.add_evidence(
                Evidence::new(SRC, format!("ABN from TPB register entry for {name}"))
                    .with_attr("source", "tpb_register")
                    .with_attr("holder", name),
            );
            out.push(abn_e);
        }

        count += 1;
        i += 1;
    }

    out
}

// ── Module impl ───────────────────────────────────────────────────────────────

#[async_trait]
impl Module for AtoTaxAgents {
    fn name(&self) -> &'static str {
        SRC
    }

    fn description(&self) -> &'static str {
        "Tax Practitioners Board public register — registered tax agents, BAS agents and tax financial advisers (free, keyless)"
    }

    fn priority(&self) -> u8 {
        // Government / public-records band — alongside the other AU gov registers.
        113
    }

    fn cost(&self) -> ModuleCost {
        ModuleCost::Free
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(
            t.kind,
            TargetKind::FullName | TargetKind::Organisation | TargetKind::Email
        ) && !t.value.trim().is_empty()
    }

    fn is_passive(&self) -> bool {
        false
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Corporate
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        &["T1591.001", "T1591.002", "T1589.003"]
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[
            EntityKind::Person,
            EntityKind::Organisation,
            EntityKind::Address,
            EntityKind::AbnAcn,
        ];
        KINDS
    }

    fn max_timeout_ms(&self) -> u64 {
        18_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let query = target.value.trim();

        // TPB search by name (applies to all accepted target kinds).
        let url = format!(
            "{}?name={}",
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

        let entities = parse_tpb_html(&html, query, &ctx.scan_id);
        let mut result = ModuleResult::new();
        result.extend(entities);
        Ok(result)
    }
}
