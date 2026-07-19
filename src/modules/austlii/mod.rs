//! AustLII (Australian Legal Information Institute) court and legislation search.
//! Free HTML scrape; no key required.
//!
//! Endpoint: `GET https://www.austlii.edu.au/cgi-bin/sinosrch.cgi`
//! Returns case/legislation document references for a name or organisation query.

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

const SRC: &str = "austlii";
const SEARCH_URL: &str = "https://www.austlii.edu.au/cgi-bin/sinosrch.cgi";

/// Cap on AustLII document references surfaced — matched to the `results=` the
/// request asks for, so every fetched court-judgment / legislation reference
/// becomes a `Url` (no-omission directive). Previously the request asked for 20
/// but only the first 10 were emitted, silently dropping up to half a subject's
/// AU legal-record hits.
const MAX_DOCS: usize = 20;

pub struct AustLii;

/// Extract legal-document hyperlinks from an AustLII search-results page.
/// Returns `Vec<(url, title)>` for `/au/cases/`, `/au/legis/`, and
/// `/au/journals/` paths only.
pub(super) fn extract_case_links(html: &str) -> Vec<(String, String)> {
    let mut results = Vec::new();
    let mut remaining = html;

    while let Some(pos) = remaining.find("href=\"") {
        remaining = &remaining[pos + 6..];
        let Some(end) = remaining.find('"') else {
            break;
        };
        let href = &remaining[..end];
        remaining = &remaining[end..];

        if !href.contains("/au/cases/")
            && !href.contains("/au/legis/")
            && !href.contains("/au/journals/")
        {
            continue;
        }

        let url = if href.starts_with("http") {
            href.to_string()
        } else {
            format!("https://www.austlii.edu.au{href}")
        };

        let Some(gt) = remaining.find('>') else {
            continue;
        };
        let after = &remaining[gt + 1..];
        let Some(lt) = after.find('<') else {
            continue;
        };
        let title = crate::util::html::strip_html(&after[..lt])
            .trim()
            .to_string();

        if !url.is_empty() && !title.is_empty() {
            results.push((url, title));
        }
    }
    results
}

#[async_trait]
impl Module for AustLii {
    fn name(&self) -> &'static str {
        "austlii"
    }

    fn description(&self) -> &'static str {
        "AustLII recon — surfaces Australian court judgments and legislation references tied to a name or organisation"
    }

    fn priority(&self) -> u8 {
        55
    }

    fn cost(&self) -> ModuleCost {
        ModuleCost::Free
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::FullName | TargetKind::Organisation)
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Corporate
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[EntityKind::Url, EntityKind::Organisation];
        KINDS
    }

    fn max_timeout_ms(&self) -> u64 {
        10_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let query = crate::util::http::urlencode(target.value.trim());
        let url = format!(
            "{SEARCH_URL}?query={query}&method=auto&results={MAX_DOCS}&filter=results&format=html"
        );

        let resp = ctx.http.get(&url).send_tagged(SRC).await?;
        if !resp.status().is_success() {
            return Ok(ModuleResult::new());
        }

        let html = match crate::util::http::read_body_capped(resp, 512 * 1024).await {
            Some(s) => s,
            None => return Ok(ModuleResult::new()),
        };

        let links = extract_case_links(&html);
        if links.is_empty() {
            return Ok(ModuleResult::new());
        }

        Ok(build_entities(&links, target, &ctx.scan_id))
    }
}

/// Map the extracted AustLII document links to entities. **Pure** (no network):
/// each link (up to [`MAX_DOCS`], matched to the request's `results=`) becomes a
/// `court-judgment` `Url`, and an Organisation target with ≥2 references also
/// gets a `legal-record` Organisation summary. Split out of `process` so the
/// no-omission cap is unit-testable without a network round-trip.
fn build_entities(links: &[(String, String)], target: &Target, scan_id: &str) -> ModuleResult {
    let mut result = ModuleResult::new();

    for (doc_url, title) in links.iter().take(MAX_DOCS) {
        let mut url_ent = Entity::new(EntityKind::Url, doc_url, confidence::HIGH_PLUS, scan_id);
        url_ent.tag("court-judgment");
        url_ent.tag("austlii");
        url_ent.add_evidence(
            Evidence::new(SRC, format!("AustLII document: {title}"))
                .with_attr("title", title)
                .with_attr("source", "austlii.edu.au"),
        );
        result.push(url_ent);
    }

    if links.len() >= 2 && matches!(target.kind, TargetKind::Organisation) {
        let mut org = Entity::new(
            EntityKind::Organisation,
            target.value.trim(),
            confidence::MEDIUM_HIGH,
            scan_id,
        );
        org.tag("legal-record");
        org.tag("austlii");
        org.add_evidence(
            Evidence::new(
                SRC,
                format!(
                    "AustLII: {} legal document references found",
                    links.len().min(MAX_DOCS)
                ),
            )
            .with_attr("source", "austlii.edu.au"),
        );
        result.push(org);
    }

    result
}
