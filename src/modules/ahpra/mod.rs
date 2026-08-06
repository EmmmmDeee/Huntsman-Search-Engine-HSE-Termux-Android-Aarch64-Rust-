//! AHPRA (Australian Health Practitioner Regulation Agency) register scrape.
//! Free HTML scrape; no key required.
//!
//! Endpoint: `GET https://www.ahpra.gov.au/Registration/Registers-of-Practitioners.aspx`
//! Query params: Spousesurname={name} or Organisation={org}

#[cfg(test)]
mod tests;

use async_trait::async_trait;

use crate::core::{
    confidence,
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::RequestBuilderExt;

const SRC: &str = "ahpra";

pub struct Ahpra;

/// Scrape the AHPRA register search-results table into
/// `(name, profession, registration_number)` rows.
///
/// A dependency-free `<tr>`/`<td>` walk (no scraper crate, in keeping with the
/// lean Termux build): each cell's text is taken via
/// [`strip_tags_plain`](crate::util::html::strip_tags_plain) and rows
/// with at least three cells are kept. The header row (`Name`/`Practitioner`)
/// and nameless rows are dropped, so the result is data-only. Pure given
/// `html` — unit-testable against a captured response.
pub(super) fn parse_ahpra_html(html: &str) -> Vec<(String, String, String)> {
    // Returns Vec<(name, profession, registration_number)>. The `<tr>`/`<td>`
    // table walk is shared via `util::html::table_rows`; this keeps only the
    // AHPRA-specific column mapping and header/nameless-row drop.
    let mut results = Vec::new();
    for cells in crate::util::html::table_rows(html) {
        if cells.len() >= 3 {
            let name = cells[0].clone();
            let profession = cells[1].clone();
            let reg_no = cells[2].clone();
            if !name.is_empty() && name != "Name" && name != "Practitioner" {
                results.push((name, profession, reg_no));
            }
        }
    }
    results
}

/// Remove HTML tags from a table cell, returning its visible text — a
/// single-pass character filter that drops everything between `<` and `>`.
/// Sufficient for the flat, well-formed AHPRA cells; the caller trims.

#[async_trait]
impl Module for Ahpra {
    fn name(&self) -> &'static str {
        "ahpra"
    }

    fn description(&self) -> &'static str {
        "AHPRA practitioner-register recon — enumerates registered health practitioners by name or organisation"
    }

    fn priority(&self) -> u8 {
        86
    }

    fn cost(&self) -> ModuleCost {
        ModuleCost::Free
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::FullName | TargetKind::Organisation)
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::People
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[EntityKind::Person];
        KINDS
    }

    fn max_timeout_ms(&self) -> u64 {
        12_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let value = target.value.trim();
        let param = match target.kind {
            TargetKind::Organisation => {
                format!("Organisation={}", crate::util::http::urlencode(value))
            }
            _ => format!("Spousesurname={}", crate::util::http::urlencode(value)),
        };
        let url = format!(
            "https://www.ahpra.gov.au/Registration/Registers-of-Practitioners.aspx?{param}"
        );

        let resp = ctx.http.get(&url).send_tagged(SRC).await?;
        if !resp.status().is_success() {
            return Ok(ModuleResult::new());
        }
        let html = match crate::util::http::read_body_capped(resp, 512 * 1024).await {
            Some(s) => s,
            None => return Ok(ModuleResult::new()),
        };

        let practitioners = parse_ahpra_html(&html);
        let mut result = ModuleResult::new();
        result.extend(build_practitioner_entities(&practitioners, &ctx.scan_id));

        Ok(result)
    }
}

/// One `Person` entity per parsed practitioner — EVERY row, no cap. The HTML body
/// is already size-bounded by `read_body_capped` (the real resource limit), so
/// capping here would silently drop practitioners 21..N of a common-surname
/// register search (Smith/Nguyen/Lee return many). Pure and testable.
pub(super) fn build_practitioner_entities(
    practitioners: &[(String, String, String)],
    scan_id: &str,
) -> Vec<Entity> {
    let mut out = Vec::with_capacity(practitioners.len());
    for (name, profession, reg_no) in practitioners {
        let mut person = Entity::new(EntityKind::Person, name, confidence::HIGH_PLUS, scan_id);
        person.tag("ahpra");
        person.tag("health-practitioner");
        if !profession.is_empty() {
            person.tag(format!(
                "profession:{}",
                profession.to_lowercase().replace(' ', "-")
            ));
        }
        person.add_evidence(
            Evidence::new(SRC, format!("AHPRA registered practitioner: {name}"))
                .with_attr("profession", profession)
                .with_attr("registration_number", reg_no)
                .with_attr("source", "ahpra.gov.au"),
        );
        out.push(person);
    }
    out
}
