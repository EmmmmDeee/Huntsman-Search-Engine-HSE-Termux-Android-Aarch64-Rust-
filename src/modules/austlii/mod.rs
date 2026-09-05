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

    fn attack_techniques(&self) -> &'static [&'static str] {
        // process()/build_entities() only ever emit a court-judgment Url (raw
        // case/legislation title, no personnel parsing) and, for Organisation
        // targets, a generic legal-record count Organisation entity — no
        // officer name/title/role extraction anywhere, so drop the Corporate
        // default's T1591.004 (cf. acnc_charities). T1591.002 stands in for
        // the litigation/legislative footprint the "legal-record" entity captures.
        &["T1591.002"]
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
        // NOT `ok_or_absent(.., &[404])`: `SEARCH_URL` is a FIXED endpoint path,
        // not a per-subject resource, so a 404 here means the endpoint moved or
        // the CGI was withdrawn — never "this subject has no legal records".
        // Treating it as a clean miss made an AustLII outage indistinguishable
        // from a subject with a clean record, silently and on every scan.
        // `&[]`, not `&[404]`: AustLII signals "no results" in the body of a
        // 200 (an empty results table), so per `ok_or_absent`'s own contract
        // every non-2xx here is a failure.
        let Some(resp) = crate::util::http::ok_or_absent(SRC, resp, &[]).await? else {
            return Ok(ModuleResult::new());
        };

        // "No AustLII legal records for this subject" is a negative claim an
        // analyst acts on; a connection reset mid-body must not manufacture one.
        let html = crate::util::http::read_body_capped_or_fail(SRC, resp, 512 * 1024).await?;

        let links = extract_case_links(&html);
        if links.is_empty() {
            return Ok(ModuleResult::new());
        }

        Ok(build_entities(&links, target, &ctx.scan_id))
    }
}

/// Map the extracted AustLII document links to entities. **Pure** (no network):
/// each link (up to [`MAX_DOCS`], matched to the request's `results=`) becomes a
/// `court-judgment` `Url`, and an Organisation target with ≥2 title-relevant
/// references also gets a `legal-record` Organisation summary. Split out of
/// `process` so the no-omission cap is unit-testable without a network
/// round-trip.
///
/// `sinosrch.cgi` is a full-text search across AustLII's entire corpus, not a
/// party-name-scoped lookup — a judgment's title is the only text available
/// here, and it routinely mentions people who are not litigants (witnesses,
/// barristers, cited third parties). Relevance therefore demands that the title
/// name the WHOLE subject ([`whole_word_token_match`](crate::util::str_util::whole_word_token_match)
/// — every query token present as a whole word), not merely SHARE a token: a
/// case title carries the corporate legal form (`Pty`, `Ltd`) of half the
/// companies on the register, and a person's given or family name alone is what
/// every namesake's matter looks like ("Smith v The Queen"). A hit that clears
/// that bar is the subject's own record; one that does not is still real
/// evidence (AustLII's own ranking surfaced it), just weaker — so it is kept, at
/// a lower confidence and flagged `needs-identity-verification`, rather than
/// dropped or trusted equally.
///
/// Every emitted `Url` also carries [`tags::SOURCE_DOCUMENT`](crate::core::tags::SOURCE_DOCUMENT):
/// a judgment names the judge, counsel, witnesses and the opposing party, so the
/// engine must deliver the document to be read, never mine it for seeds. The tag
/// is the structural stop the expansion loop honours.
fn build_entities(links: &[(String, String)], target: &Target, scan_id: &str) -> ModuleResult {
    let mut result = ModuleResult::new();
    let query = target.value.trim();
    let mut title_matches = 0usize;

    for (doc_url, title) in links.iter().take(MAX_DOCS) {
        // Whole-name match, not any-token: a shared legal-form word (`Pty`,
        // `Ltd`) or a lone given/family name does not make a full-text hit the
        // subject's own case — it is exactly the namesake the caution warns of.
        let relevant = crate::util::str_util::whole_word_token_match(title, query);
        if relevant {
            title_matches += 1;
        }
        let conf = if relevant {
            confidence::HIGH_PLUS
        } else {
            confidence::LOW_MEDIUM
        };
        let mut url_ent = Entity::new(EntityKind::Url, doc_url, conf, scan_id);
        url_ent.tag("court-judgment");
        url_ent.tag("austlii");
        // A court document names third parties by its nature; record it as
        // evidence to read, never pivot into the strangers it lists.
        url_ent.tag(crate::core::tags::SOURCE_DOCUMENT);
        let mut ev = Evidence::new(SRC, format!("AustLII document: {title}"))
            .with_attr("title", title)
            .with_attr("source", "austlii.edu.au");
        if !relevant {
            url_ent.tag("needs-identity-verification");
            ev = ev.with_attr(
                "caution",
                "Full-text search hit — the query may appear only in the document \
                 body (e.g. a witness, cited party, or barrister) rather than the \
                 title naming a litigant; verify before treating this as the \
                 subject's own case.",
            );
        }
        url_ent.add_evidence(ev);
        result.push(url_ent);
    }

    if title_matches >= 2 && matches!(target.kind, TargetKind::Organisation) {
        let mut org = Entity::new(
            EntityKind::Organisation,
            query,
            confidence::MEDIUM_HIGH,
            scan_id,
        );
        org.tag("legal-record");
        org.tag("austlii");
        org.add_evidence(
            Evidence::new(
                SRC,
                format!("AustLII: {title_matches} legal document references found"),
            )
            .with_attr("source", "austlii.edu.au"),
        );
        result.push(org);
    }

    result
}
