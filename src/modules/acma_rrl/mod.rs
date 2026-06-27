//! ACMA Radiocommunications Register lookup.
//! Free; no key required.
//!
//! Endpoint: `GET https://web.acma.gov.au/rrl/licence_search.do?submit=Search&clientName={name}`
//! Also supports: clientAbn={abn}, latitude={lat}&longitude={lon}&radius={km}

#[cfg(test)]
mod tests;

use async_trait::async_trait;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::RequestBuilderExt;

const SRC: &str = "acma_rrl";

pub struct AcmaRrl;

/// Scrape the ACMA RRL search-results table into
/// `(licensee_name, licence_number, service)` rows.
///
/// A deliberately dependency-free HTML walk (no scraper/html5ever crate, in
/// keeping with the lean Termux build): it splits on `<tr>`/`</tr>`, pulls each
/// `<td>` via [`strip_html_tags`], and keeps rows with at least three cells.
/// The header row (`Licensee`) and rows missing a name or licence number are
/// dropped, so the result is data-only. Pure given `html` — unit-testable
/// against a captured response without a network round-trip.
pub(super) fn parse_acma_html(html: &str) -> Vec<(String, String, String)> {
    // Returns Vec<(licensee_name, licence_number, service)>
    let mut results = Vec::new();
    let mut remaining = html;
    while let Some(row_start) = remaining.find("<tr") {
        remaining = &remaining[row_start + 3..];
        let Some(row_end) = remaining.find("</tr>") else {
            break;
        };
        let row = &remaining[..row_end];
        remaining = &remaining[row_end + 5..];

        let cells: Vec<String> = {
            let mut cells = Vec::new();
            let mut r = row;
            while let Some(td_start) = r.find("<td") {
                r = &r[td_start..];
                let Some(td_content_start) = r.find('>') else {
                    break;
                };
                r = &r[td_content_start + 1..];
                let Some(td_end) = r.find("</td>") else { break };
                let cell = &r[..td_end];
                cells.push(strip_html_tags(cell).trim().to_string());
                r = &r[td_end + 5..];
            }
            cells
        };

        if cells.len() >= 3 {
            let name = cells[0].clone();
            let lic_no = cells[1].clone();
            let service = cells[2].clone();
            if !name.is_empty() && name != "Licensee" && !lic_no.is_empty() {
                results.push((name, lic_no, service));
            }
        }
    }
    results
}

/// Pull the licensee's ABN out of the RRL detail HTML, if present.
///
/// Finds the `ABN:</…>` label cell, takes the digits from the following table
/// cell, and returns them only when exactly 11 — the strict ABN length — so a
/// stray or malformed number is rejected rather than emitted as a bogus
/// `AbnAcn`. `None` when no ABN label is present (the common case for an
/// individual licensee).
pub(super) fn extract_abn_from_html(html: &str) -> Option<String> {
    let marker = "ABN:</";
    let pos = html.find(marker)?;
    let after = &html[pos + marker.len()..];
    let td_end = after.find("</td>")?;
    let raw = &after[..td_end];
    let abn: String = raw.chars().filter(char::is_ascii_digit).collect();
    if abn.len() == 11 { Some(abn) } else { None }
}

/// Remove HTML tags from a table cell, returning its visible text.
///
/// A single-pass character filter that drops everything between `<` and `>`.
/// Sufficient for the flat, well-formed RRL cells (no nested-bracket or
/// entity-decoding concerns here); the caller trims the result.
fn strip_html_tags(html: &str) -> String {
    let mut out = String::with_capacity(html.len());
    let mut in_tag = false;
    for c in html.chars() {
        match c {
            '<' => {
                in_tag = true;
            }
            '>' => {
                in_tag = false;
            }
            _ if !in_tag => {
                out.push(c);
            }
            _ => {}
        }
    }
    out
}

#[async_trait]
impl Module for AcmaRrl {
    fn name(&self) -> &'static str {
        "acma_rrl"
    }

    fn description(&self) -> &'static str {
        "ACMA Radiocommunications Register: licence holders by organisation name, ABN, or coordinates"
    }

    fn priority(&self) -> u8 {
        48
    }

    fn cost(&self) -> ModuleCost {
        ModuleCost::Free
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(
            t.kind,
            TargetKind::Organisation | TargetKind::AbnAcn | TargetKind::Coordinates
        )
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Corporate
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        &["T1591.001", "T1591.002"]
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[EntityKind::Organisation, EntityKind::AbnAcn];
        KINDS
    }

    fn max_timeout_ms(&self) -> u64 {
        10_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let value = target.value.trim();
        let param = match target.kind {
            TargetKind::AbnAcn => format!("clientAbn={}", crate::util::http::urlencode(value)),
            TargetKind::Coordinates => {
                // Expect "lat,lon" format
                let parts: Vec<&str> = value.splitn(2, ',').collect();
                if parts.len() != 2 {
                    return Ok(ModuleResult::new());
                }
                let lat = parts[0].trim();
                let lon = parts[1].trim();
                format!("latitude={lat}&longitude={lon}&radius=10&submit=Search")
            }
            _ => format!("clientName={}", crate::util::http::urlencode(value)),
        };
        let url = format!("https://web.acma.gov.au/rrl/licence_search.do?submit=Search&{param}");

        let resp = ctx
            .http
            .get(&url)
            .header("Accept", "text/html,application/xhtml+xml")
            .send_tagged(SRC)
            .await?;

        if !resp.status().is_success() {
            return Ok(ModuleResult::new());
        }
        let html = match crate::util::http::read_body_capped(resp, 512 * 1024).await {
            Some(s) => s,
            None => return Ok(ModuleResult::new()),
        };

        let licences = parse_acma_html(&html);
        let mut result = ModuleResult::new();

        for (name, lic_no, service) in licences.iter().take(20) {
            let mut org = Entity::new(EntityKind::Organisation, name, 0.65, &ctx.scan_id);
            org.tag("acma");
            org.tag("radiocommunications-licensee");
            if !service.is_empty() {
                org.tag(format!(
                    "service:{}",
                    service.to_lowercase().replace(' ', "-")
                ));
            }
            org.add_evidence(
                Evidence::new(SRC, format!("ACMA RRL licence {lic_no} held by {name}"))
                    .with_attr("licence_number", lic_no)
                    .with_attr("service_type", service)
                    .with_attr("source", "acma.gov.au"),
            );

            // If there's an ABN in the HTML, emit it too
            if let Some(abn) = extract_abn_from_html(&html) {
                let mut abn_entity = Entity::new(EntityKind::AbnAcn, &abn, 0.70, &ctx.scan_id);
                abn_entity.tag("acma");
                abn_entity
                    .add_evidence(Evidence::new(SRC, format!("ABN for {name} from ACMA RRL")));
                result.push(abn_entity);
            }

            result.push(org);
        }

        Ok(result)
    }
}
