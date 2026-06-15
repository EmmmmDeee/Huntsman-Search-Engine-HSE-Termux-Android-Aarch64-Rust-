//! Australian court records search via AustLII (free, public).
//!
//! AustLII (Australasian Legal Information Institute) is the primary
//! free-access repository of Australian legal judgments and tribunal
//! decisions. It indexes decisions from all Australian federal and
//! state courts, AAT, ACAT, NCAT, VCAT, QCAT, SACAT, and more.
//!
//! This module queries the AustLII full-text search for a name or
//! organisation and extracts case references and their URLs. Case
//! appearance confirms a legal presence and can surface addresses,
//! associated names, and organisational relationships from judgment text.
//!
//! Sources:
//!   AustLII search: `https://www.austlii.edu.au/cgi-bin/sinosrch.cgi`
//!
//! Entities produced:
//!   - `Url` → AustLII case document URL
//!
//! MITRE ATT&CK:
//!   - T1591.001 — Gather Victim Org Information: Determine Physical Locations
//!   - T1589.003 — Gather Victim Identity Information: Employee Names

mod parse;

#[cfg(test)]
mod tests;

use async_trait::async_trait;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::{RequestBuilderExt, urlencode};

const SRC: &str = "au_court_records";
const AUSTLII_SEARCH: &str = "https://www.austlii.edu.au/cgi-bin/sinosrch.cgi";

pub struct AuCourtRecords;

#[async_trait]
impl Module for AuCourtRecords {
    fn name(&self) -> &'static str {
        "au_court_records"
    }

    fn description(&self) -> &'static str {
        "Australian court record search via AustLII — case appearances by name or organisation"
    }

    fn priority(&self) -> u8 {
        46
    }

    fn is_passive(&self) -> bool {
        true
    }

    fn cost(&self) -> ModuleCost {
        ModuleCost::Free
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::FullName | TargetKind::Organisation)
    }

    fn max_timeout_ms(&self) -> u64 {
        15_000
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Corporate
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        &["T1591.001", "T1589.003"]
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[EntityKind::Url];
        KINDS
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let query = format!("\"{}\"", target.value);
        let encoded = urlencode(&query);

        // AustLII sinotype search restricted to AU cases
        let url = format!(
            "{AUSTLII_SEARCH}?method=boolean&query={encoded}&mask_path=au%2Fcases&results=20"
        );

        let resp = ctx
            .http
            .get(&url)
            .header("Accept", "text/html")
            .send_tagged(SRC)
            .await?;

        if !resp.status().is_success() {
            return Ok(ModuleResult::new());
        }

        let html = resp.text().await.unwrap_or_default();
        let hits = parse::extract_case_links(&html);

        if hits.is_empty() {
            return Ok(ModuleResult::new());
        }

        let mut result = ModuleResult::with_capacity(hits.len());
        for (case_url, title) in hits.iter().take(10) {
            let mut e = Entity::new(EntityKind::Url, case_url, 0.65, &ctx.scan_id);
            e.tag("court-record");
            e.tag("austlii");
            e.tag("au-legal");
            e.add_evidence(
                Evidence::new(SRC, format!("AustLII case: {title}"))
                    .with_attr("case_title", title)
                    .with_attr("case_url", case_url)
                    .with_attr("source", "austlii.edu.au")
                    .with_attr("query", &query),
            );
            result.push(e);
        }

        Ok(result)
    }
}
