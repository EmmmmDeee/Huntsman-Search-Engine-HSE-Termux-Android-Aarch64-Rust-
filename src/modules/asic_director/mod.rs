//! ASIC company directors lookup — Australian Securities & Investments Commission.
//!
//! Endpoint: `https://connectonline.asic.gov.au/RegistrySearch/faces/landing/SearchRegisters.jspx`
//! (public, free, no API key — HTML scrape of the public search interface)
//!
//! For a `FullName` seed, searches ASIC's public company registers for director
//! appointments. When a match is found it fans out:
//!
//!   * `Organisation` — the registered company name (confirms employment/role pivot)
//!   * `AbnAcn` — the ACN of the company (feeds `abn_lookup` for address/coords)
//!   * `Address` — registered office address from the director record where present
//!
//! MITRE ATT&CK:
//!   * T1591.002 — Business Relationships (director → company affiliation)
//!   * T1591.004 — Identify Roles (confirms director role)
//!   * T1591.001 — Determine Physical Locations (registered office address)
//!
//! Confidence model:
//!   * Exact name match in ASIC register: 0.80 (official govt source)
//!   * ACN emitted for downstream abn_lookup: 0.82
//!   * Address from registered office: 0.72
//!
//! Note: ASIC Connect Online is rate-limited by IP. This module uses a light
//! scraping strategy with a single polite request per scan. The ABN/ACN pivot
//! via `abn_lookup` then enriches the full company record including HQ address
//! and geolocation — making this the highest-confidence AU geo pivot after a
//! FullName seed.
//!
//! `process()` distinguishes "the request never actually got a readable
//! response" (a real `Error::module` failure, surfaced to the operator and to
//! the T2.7 scraper-health signal) from "ASIC Connect Online answered but had
//! no director record matching this name" (the ordinary, honest empty
//! success) — see [`request_failed`].

use async_trait::async_trait;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::{Error, Result},
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::RequestBuilderExt;

const SRC: &str = "asic_director";

pub struct AsicDirector;

/// Strip HTML tags and decode basic HTML entities. Pure.
fn clean_html(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut in_tag = false;
    let chars: Vec<char> = s.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        match chars[i] {
            '<' => in_tag = true,
            '>' => in_tag = false,
            '&' if !in_tag => {
                // Decode &amp; &lt; &gt; &nbsp;
                let rest: String = chars[i..].iter().collect();
                if rest.starts_with("&amp;") {
                    out.push('&');
                    i += 5;
                    continue;
                } else if rest.starts_with("&lt;") {
                    out.push('<');
                    i += 4;
                    continue;
                } else if rest.starts_with("&gt;") {
                    out.push('>');
                    i += 4;
                    continue;
                } else if rest.starts_with("&nbsp;") {
                    out.push(' ');
                    i += 6;
                    continue;
                } else {
                    out.push('&');
                }
            }
            c if !in_tag => out.push(c),
            _ => {}
        }
        i += 1;
    }
    out
}

/// Entities built from a single ASIC search result block. Pure.
fn build_director_entities(
    company_name: &str,
    acn: &str,
    full_name: &str,
    address: Option<&str>,
    scan_id: &str,
) -> Vec<Entity> {
    let mut out = Vec::new();
    if company_name.is_empty() {
        return out;
    }

    let ev_base = Evidence::new(
        SRC,
        format!("ASIC director record: {full_name} → {company_name}"),
    )
    .with_attr("director_name", full_name)
    .with_attr("company_name", company_name)
    .with_attr("register", "ASIC");

    // Organisation entity.
    let mut org = Entity::new(EntityKind::Organisation, company_name, 0.80, scan_id);
    org.tag(SRC);
    org.tag("asic");
    org.tag("au-company");
    org.tag("country:AU");
    let mut org_ev = ev_base.clone();
    if !acn.is_empty() {
        org_ev = org_ev.with_attr("acn", acn);
    }
    org.add_evidence(org_ev);
    out.push(org);

    // ACN entity → feeds abn_lookup for full address/coords.
    if !acn.is_empty() {
        let acn_clean: String = acn.chars().filter(char::is_ascii_digit).collect();
        if acn_clean.len() == 9 {
            let mut acn_e = Entity::new(EntityKind::AbnAcn, &acn_clean, 0.82, scan_id);
            acn_e.tag(SRC);
            acn_e.tag("asic");
            acn_e.tag("acn");
            acn_e.tag("country:AU");
            acn_e.add_evidence(
                ev_base
                    .clone()
                    .with_attr("acn", &acn_clean)
                    .with_attr("type", "ACN"),
            );
            out.push(acn_e);
        }
    }

    // Address from registered office.
    if let Some(addr) = address.filter(|s| !s.trim().is_empty()) {
        let mut ae = Entity::new(EntityKind::Address, addr, 0.72, scan_id);
        ae.tag(SRC);
        ae.tag("asic");
        ae.tag("registered-office");
        ae.tag("country:AU");
        if let Some(st) = crate::util::address_au::state_code(addr) {
            ae.tag(format!("au-state:{st}"));
        }
        ae.add_evidence(ev_base.clone().with_attr("registered_office", addr));
        out.push(ae);
        if let Some((lat, lon)) = crate::util::city_coords::city_coords(addr) {
            let coord_val = format!("{lat:.4},{lon:.4}");
            let mut c = Entity::new(EntityKind::Coordinates, &coord_val, 0.62, scan_id);
            c.tag(SRC);
            c.tag("addr-derived");
            c.tag("geoint");
            c.tag("country:AU");
            c.add_evidence(ev_base.with_attr("registered_office", addr));
            out.push(c);
        }
    }

    out
}

/// Parse ASIC Connect Online HTML search result for director name matches.
/// Returns `(company_name, acn, registered_office_address)` tuples. Pure.
fn parse_asic_html(html: &str, full_name: &str) -> Vec<(String, String, Option<String>)> {
    let name_lc = full_name.to_lowercase();
    // ASIC result rows contain: Company Name | ACN | Address | Role | Status.
    // Keep lines where every name token appears, then extract company/ACN/address.
    clean_html(html)
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .filter(|line| {
            let line_lc = line.to_lowercase();
            name_lc.split_whitespace().all(|tok| line_lc.contains(tok))
        })
        .filter_map(|line| {
            let acn = extract_acn(line).unwrap_or_default();
            let company = extract_company_name(line, &acn);
            if company.len() < 3 {
                return None;
            }
            Some((company, acn, extract_au_address(line)))
        })
        .collect()
}

/// Extract the first 9-digit ACN-like sequence from text. Pure.
fn extract_acn(text: &str) -> Option<String> {
    let digits_only: String = text.chars().filter(char::is_ascii_digit).collect();
    (digits_only.len() >= 9).then(|| digits_only[..9].to_string())
}

/// Rough company name extraction: text before the first digit run. Pure.
fn extract_company_name(line: &str, acn: &str) -> String {
    // The company name is the text before the ACN. Splitting on the *normalised*
    // digits-only `acn` ("123456789") misses the canonical space-grouped display
    // form ("123 456 789") — which left the ENTIRE row as the company value — so
    // fall back to cutting at the first digit of the trailing registration number.
    let name = if acn.is_empty() {
        line
    } else if let Some(i) = line.find(acn) {
        &line[..i]
    } else if let Some(i) = line.find(|c: char| c.is_ascii_digit()) {
        &line[..i]
    } else {
        line
    };
    // Clean up and trim punctuation.
    name.trim()
        .trim_end_matches(|c: char| !c.is_alphanumeric())
        .to_string()
}

/// Extract an AU address pattern (state + postcode) from a text line. Pure.
fn extract_au_address(text: &str) -> Option<String> {
    // Look for AU state abbreviation followed by a 4-digit postcode.
    let tokens: Vec<&str> = text.split_whitespace().collect();
    tokens.iter().enumerate().find_map(|(i, tok)| {
        crate::util::address_au::state_code(tok)?;
        let next = *tokens.get(i + 1)?;
        if next.len() == 4
            && next.chars().all(|c| c.is_ascii_digit())
            && next
                .parse::<u32>()
                .is_ok_and(|n| (2000..=7999).contains(&n))
        {
            // Build a context: up to 4 tokens before + state + postcode.
            let start = i.saturating_sub(4);
            Some(tokens[start..=(i + 1)].join(" "))
        } else {
            None
        }
    })
}

#[async_trait]
impl Module for AsicDirector {
    fn name(&self) -> &'static str {
        SRC
    }

    fn description(&self) -> &'static str {
        "ASIC company directors register — find director appointments for a full name and pivot to company ACN/address"
    }

    fn priority(&self) -> u8 {
        89
    }

    fn accepts(&self, t: &Target) -> bool {
        t.kind == TargetKind::FullName && t.value.trim().contains(' ')
    }

    /// `accepts()` value-gates (a name must have ≥2 tokens), so the default
    /// probe-based `consumes()` is empty — which would leave this module out of
    /// the FullName dispatch bucket and silently never run. Declare the kind
    /// explicitly; the engine still re-applies `accepts()` to each real target
    /// at dispatch, so the multi-word value filter is preserved.
    fn consumes(&self) -> Vec<TargetKind> {
        vec![TargetKind::FullName]
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Corporate
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        &["T1591.002", "T1591.004", "T1591.001"]
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[
            EntityKind::Organisation,
            EntityKind::AbnAcn,
            EntityKind::Address,
            EntityKind::Coordinates,
        ];
        KINDS
    }

    fn max_timeout_ms(&self) -> u64 {
        15_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let full_name = target.value.trim();
        // ASIC Connect Online public person search (name search).
        let url = format!(
            "https://connectonline.asic.gov.au/RegistrySearch/faces/landing/SearchRegisters.jspx?searchText={}&searchType=OrgAndBus",
            crate::util::http::urlencode(full_name),
        );

        let mut html_read_ok = false;
        let mut result = ModuleResult::new();

        if let Ok(resp) = ctx
            .http
            .get(&url)
            .header("User-Agent", crate::util::http::UA_BROWSER)
            .header("Accept", "text/html,application/xhtml+xml")
            .send_tagged(SRC)
            .await
            && resp.status().is_success()
            && let Some(html) = crate::util::http::read_body_capped(resp, 1_000_000).await
        {
            html_read_ok = true;
            result.extend(parse_asic_html(&html, full_name).into_iter().flat_map(
                |(company, acn, address)| {
                    build_director_entities(
                        &company,
                        &acn,
                        full_name,
                        address.as_deref(),
                        &ctx.scan_id,
                    )
                },
            ));
        }

        if request_failed(html_read_ok, !result.entities.is_empty()) {
            return Err(Error::module(
                SRC,
                "ASIC Connect Online request failed at the transport level, returned a \
                 non-success HTTP status, or its response body was unreadable — not \"no \
                 director records for this name\"",
            ));
        }

        Ok(result)
    }
}

/// Whether `process()`'s single ASIC Connect Online request should be
/// surfaced as a real `Error::module` failure rather than its ordinary empty
/// success. True precisely when the request never produced a readable HTML
/// body (`html_read_ok` false — a transport error, non-success HTTP status,
/// or an oversized/undecodable body) AND nothing was found
/// (`found_any_entity` false). A request that read successfully but simply
/// matched no director record for this name is not a failure — only "ASIC
/// Connect Online never actually answered this scan" is. Mirrors
/// `au_property`'s `all_legs_unreachable` for this module's single-request
/// case (T2.120: "same defect class already fixed the same day for sibling
/// `au_property` — `asic_director` was missed"); pure and free of
/// `ModuleContext`/network so it is unit-testable without a live server —
/// see `tests::request_failed_*`.
#[must_use]
fn request_failed(html_read_ok: bool, found_any_entity: bool) -> bool {
    !html_read_ok && !found_any_entity
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
