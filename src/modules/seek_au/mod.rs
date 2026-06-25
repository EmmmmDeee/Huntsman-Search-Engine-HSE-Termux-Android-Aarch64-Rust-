//! Seek.com.au — Australia's largest employment marketplace.
//!
//! Free, keyless. Scrapes public search results and JSON-LD job posting data.
//!
//! Accepts
//! -------
//! * `Organisation` — searches for job listings by the organisation; extracts
//!   office location, contact email, and types of roles hired.
//! * `FullName` — searches for the person as an employer/contact in listings;
//!   also discovers employer organisations and their locations.
//!
//! Emits
//! -----
//! * `Organisation` — employer found in one or more Seek listings
//! * `Address`      — office/work location (suburb + state) from listing
//! * `Email`        — contact email found in listing text
//! * `Url`          — Seek listing URL
//!
//! Confidence
//! ----------
//! * Organisation (Seek verified employer account): 0.72
//! * Address (listing location, as-posted):         0.60
//! * Email (in-listing contact):                    0.52
//! * Url (listing page):                            0.65
//!
//! MITRE ATT&CK
//! ------------
//! * T1591.001 — Determine Physical Locations (office/work location in listings)
//! * T1591.002 — Business Relationships (employer-employee, role functions)
//! * T1591.004 — Identify Roles (job titles + functions advertised)

use async_trait::async_trait;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::extract::page_emails;
use crate::util::html::strip_html;
use crate::util::http::{RequestBuilderExt, UA_BROWSER, read_body_capped};

#[cfg(test)]
mod tests;

pub(super) const SRC: &str = "seek_au";

const SEARCH_BASE: &str = "https://www.seek.com.au/jobs";

const MAX_LISTINGS: usize = 15;

const ORG_CONF: f64 = 0.72;
const ADDR_CONF: f64 = 0.60;
const EMAIL_CONF: f64 = 0.52;
const URL_CONF: f64 = 0.65;

/// Australian state/territory abbreviations for location extraction.
const AU_STATES: &[&str] = &["NSW", "VIC", "QLD", "SA", "WA", "TAS", "NT", "ACT"];

pub struct SeekAu;

// ── Parsing ──────────────────────────────────────────────────────────────────

/// Parse Seek job search HTML for employer, location, email, and URL entities.
///
/// Seek embeds structured `application/ld+json` `JobPosting` objects in
/// search-result pages — these are the primary parse target. The plain-text
/// fallback covers pages that don't include JSON-LD.
///
/// Pure function — no I/O.
pub(super) fn parse_seek_html(html: &str, query: &str, scan_id: &str) -> Vec<Entity> {
    let mut out = Vec::new();
    let query_lc = query.to_ascii_lowercase();

    // ── JSON-LD JobPosting extraction ───────────────────────────────────────
    // Seek embeds one or more <script type="application/ld+json"> blocks with
    // JobPosting structured data.  Extract each block and pull out:
    //   hiringOrganization.name, jobLocation.address.addressLocality,
    //   jobLocation.address.addressRegion, url, applicationContact.email
    let mut listing_count = 0;
    let mut seen_orgs: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut seen_addrs: std::collections::HashSet<String> = std::collections::HashSet::new();

    let bytes = html.as_bytes();
    let mut pos = 0;
    while pos < bytes.len() && listing_count < MAX_LISTINGS {
        // Find <script type="application/ld+json">
        let Some(rel) = html[pos..].find(r#"application/ld+json"#) else {
            break;
        };
        let tag_start = pos + rel;
        // Advance to the content between > and </script>
        let Some(content_start) = html[tag_start..].find('>') else {
            pos = tag_start + 1;
            continue;
        };
        let content_start = tag_start + content_start + 1;
        let Some(content_end) = html[content_start..].find("</script>") else {
            pos = content_start;
            continue;
        };
        let json_str = html[content_start..content_start + content_end].trim();
        pos = content_start + content_end + 9; // past </script>

        if !json_str.contains("JobPosting") {
            continue;
        }

        // Parse the JSON blob — tolerant extraction via string search rather
        // than full parse (avoids pulling in serde_json in a module that
        // doesn't otherwise need it; also tolerant of partial or embedded blobs).
        let employer = extract_json_string(json_str, "name")
            .or_else(|| extract_json_string(json_str, "hiringOrganization"));

        let locality = extract_json_string(json_str, "addressLocality");
        let region = extract_json_string(json_str, "addressRegion");
        let listing_url = extract_json_string(json_str, "url");

        // Only process listings relevant to the query.
        let context_lc = json_str.to_ascii_lowercase();
        let relevant = query_lc
            .split_whitespace()
            .any(|tok| tok.len() >= 3 && context_lc.contains(tok));
        if !relevant {
            continue;
        }

        // Emit Organisation entity.
        if let Some(ref emp) = employer {
            let emp_lc = emp.to_ascii_lowercase();
            if seen_orgs.insert(emp_lc) {
                let mut org =
                    Entity::new(EntityKind::Organisation, emp.as_str(), ORG_CONF, scan_id);
                org.tag(SRC);
                org.tag("seek-employer");
                org.tag("country:AU");
                org.add_evidence(
                    Evidence::new(SRC, format!("Seek.com.au employer listing for '{query}'"))
                        .with_attr("source", "seek_au")
                        .with_attr("query", query),
                );
                out.push(org);
            }
        }

        // Emit Address entity.
        if let (Some(loc), Some(reg)) = (&locality, &region) {
            let au_region = AU_STATES
                .iter()
                .find(|&&s| reg.eq_ignore_ascii_case(s) || reg.contains(s))
                .copied()
                .unwrap_or(reg.as_str());
            let addr_str = format!("{loc}, {au_region}");
            if seen_addrs.insert(addr_str.clone()) {
                let mut addr = Entity::new(EntityKind::Address, &addr_str, ADDR_CONF, scan_id);
                addr.tag(SRC);
                addr.tag("seek-location");
                addr.tag("job-listing");
                addr.tag("country:AU");
                if let Some(st) = AU_STATES.iter().find(|&&s| addr_str.contains(s)) {
                    addr.tag(format!("au-state:{st}"));
                }
                let ev_desc = employer.as_deref().map_or_else(
                    || format!("Seek listing location for query '{query}'"),
                    |e| format!("Seek listing location for employer '{e}'"),
                );
                addr.add_evidence(
                    Evidence::new(SRC, ev_desc)
                        .with_attr("source", "seek_au")
                        .with_attr("locality", loc.as_str())
                        .with_attr("region", reg.as_str()),
                );
                out.push(addr);
            }
        } else if let Some(ref loc) = locality {
            // Only locality, no region — still useful.
            if seen_addrs.insert(loc.clone()) {
                let mut addr =
                    Entity::new(EntityKind::Address, loc.as_str(), ADDR_CONF - 0.05, scan_id);
                addr.tag(SRC);
                addr.tag("seek-location");
                addr.tag("job-listing");
                addr.tag("country:AU");
                addr.add_evidence(
                    Evidence::new(SRC, format!("Seek listing locality for query '{query}'"))
                        .with_attr("source", "seek_au")
                        .with_attr("locality", loc.as_str()),
                );
                out.push(addr);
            }
        }

        // Emit Url entity for listing page.
        if let Some(ref url) = listing_url
            && url.contains("seek.com.au")
        {
            let mut ue = Entity::new(EntityKind::Url, url.as_str(), URL_CONF, scan_id);
            ue.tag(SRC);
            ue.tag("seek-listing");
            ue.tag("job-listing");
            ue.tag("country:AU");
            ue.add_evidence(
                Evidence::new(SRC, format!("Seek listing URL for query '{query}'"))
                    .with_attr("source", "seek_au"),
            );
            out.push(ue);
        }

        // Extract emails from the JSON-LD description (not visible in body after strip_html).
        for email in page_emails(json_str) {
            if !email.to_ascii_lowercase().ends_with("@seek.com.au") {
                let mut e = Entity::new(EntityKind::Email, &email, EMAIL_CONF, scan_id);
                e.tag(SRC);
                e.tag("seek-contact");
                e.tag("job-listing");
                e.add_evidence(
                    Evidence::new(
                        SRC,
                        format!("Contact email found in Seek listing for '{query}'"),
                    )
                    .with_attr("source", "seek_au"),
                );
                out.push(e);
            }
        }

        listing_count += 1;
    }

    // ── Plain-text fallback: email extraction ───────────────────────────────
    // Mine any contact emails visible in the HTML — sometimes listed directly
    // in ad text when the employer allows direct applications.
    let stripped = strip_html(html);
    for email in page_emails(&stripped) {
        // Filter out Seek's own domain emails (noreply@seek.com.au etc.).
        if email.to_ascii_lowercase().ends_with("@seek.com.au") {
            continue;
        }
        let mut e = Entity::new(EntityKind::Email, &email, EMAIL_CONF, scan_id);
        e.tag(SRC);
        e.tag("seek-contact");
        e.tag("job-listing");
        e.add_evidence(
            Evidence::new(
                SRC,
                format!("Contact email found in Seek listing for '{query}'"),
            )
            .with_attr("source", "seek_au"),
        );
        out.push(e);
    }

    out
}

/// Extract the string value of a JSON key from a raw JSON string.
/// Searches for `"key":"value"` or `"key": "value"` — lightweight, no full parse.
fn extract_json_string(json: &str, key: &str) -> Option<String> {
    let needle = format!("\"{key}\"");
    let pos = json.find(&needle)?;
    let after = json[pos + needle.len()..].trim_start();
    let after = after.strip_prefix(':')?.trim_start();
    let after = after.strip_prefix('"')?;
    let end = after.find('"')?;
    let value = &after[..end];
    if value.is_empty() {
        return None;
    }
    // Un-escape common JSON escape sequences.
    Some(
        value
            .replace("\\\"", "\"")
            .replace("\\/", "/")
            .replace("\\n", " "),
    )
}

// ── Module impl ───────────────────────────────────────────────────────────────

#[async_trait]
impl Module for SeekAu {
    fn name(&self) -> &'static str {
        SRC
    }

    fn description(&self) -> &'static str {
        "Seek.com.au — employer intelligence, office locations and contacts from Australian job listings (free, keyless)"
    }

    fn priority(&self) -> u8 {
        // People / Corporate band — slightly below the government registers
        // (110+) but above the generic free modules.
        95
    }

    fn cost(&self) -> ModuleCost {
        ModuleCost::Free
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Organisation | TargetKind::FullName)
            && !t.value.trim().is_empty()
    }

    fn is_passive(&self) -> bool {
        false
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::People
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        &["T1591.001", "T1591.002", "T1591.004"]
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[
            EntityKind::Organisation,
            EntityKind::Address,
            EntityKind::Email,
            EntityKind::Url,
        ];
        KINDS
    }

    fn max_timeout_ms(&self) -> u64 {
        15_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let query = target.value.trim();

        let url = format!(
            "{}?keywords={}&where=All+Australia",
            SEARCH_BASE,
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

        let Some(html) = read_body_capped(resp, 2_000_000).await else {
            return Ok(ModuleResult::new());
        };

        let entities = parse_seek_html(&html, query, &ctx.scan_id);

        // Dedup by (kind, value).
        let mut result = ModuleResult::new();
        let mut seen_kv: std::collections::HashSet<(String, String)> =
            std::collections::HashSet::new();
        for e in entities {
            if seen_kv.insert((format!("{:?}", e.kind), e.value.clone())) {
                result.push(e);
            }
        }

        Ok(result)
    }
}
