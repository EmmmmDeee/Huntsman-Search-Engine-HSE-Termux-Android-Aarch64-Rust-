//! AHPRA (Australian Health Practitioner Regulation Agency) register scrape.
//! Free HTML scrape; no key required.
//!
//! Endpoint: `GET https://www.ahpra.gov.au/Registration/Registers-of-Practitioners.aspx`
//! Query params: Spousesurname={name} or Organisation={org}

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

const SRC: &str = "ahpra";

pub struct Ahpra;

pub(super) fn parse_ahpra_html(html: &str) -> Vec<(String, String, String)> {
    // Returns Vec<(name, profession, registration_number)>
    // Parse simple table rows from AHPRA search results HTML.
    let mut results = Vec::new();
    let mut remaining = html;
    while let Some(row_start) = remaining.find("<tr") {
        remaining = &remaining[row_start + 3..];
        let Some(row_end) = remaining.find("</tr>") else {
            break;
        };
        let row = &remaining[..row_end];
        remaining = &remaining[row_end + 5..];

        // Extract text from td cells.
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
                // Strip remaining HTML tags.
                let text = strip_tags(cell);
                cells.push(text.trim().to_string());
                r = &r[td_end + 5..];
            }
            cells
        };

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

fn strip_tags(html: &str) -> String {
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
impl Module for Ahpra {
    fn name(&self) -> &'static str {
        "ahpra"
    }

    fn description(&self) -> &'static str {
        "AHPRA practitioner register: registered health practitioners by name or organisation"
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
        const KINDS: &[EntityKind] = &[EntityKind::Person, EntityKind::Organisation];
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

        for (name, profession, reg_no) in practitioners.iter().take(20) {
            let mut person = Entity::new(EntityKind::Person, name, 0.70, &ctx.scan_id);
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
            result.push(person);
        }

        Ok(result)
    }
}
