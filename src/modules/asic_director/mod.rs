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
//!   * Whole-word all-tokens name match in ASIC register: confidence::HIGH_PLUSPLUS
//!     (official govt source — the previous "exact match" description overclaimed:
//!     the row-scanning match is name-text-only, so two different real directors
//!     sharing a full name are indistinguishable to it)
//!   * ACN emitted for downstream abn_lookup: 0.82
//!   * Address from registered office: 0.72
//!
//! **Live status (2026-08-04):** a direct request to the endpoint above
//! returns `403` — including with a full browser `User-Agent` header — which
//! is an anti-bot/WAF (or JS-challenge) block, NOT the plain IP rate-limiting
//! this doc previously assumed. A rate limit would show as an eventual `429`
//! or a delayed `200`; an immediate, UA-independent `403` on every request
//! means no plain HTTP client (this module's `reqwest`/`curl` transport
//! included) can currently pass it without a headless-browser-class
//! workaround. Confirmed live from a non-residential IP; not yet confirmed
//! whether a Termux/mobile-carrier IP fares differently. No fix attempted
//! here — this is the module's next candidate work, the same
//! "confirmed-dead-endpoint, no rewrite yet" pattern already documented for
//! `au_property`'s three legs.
//!
//! This module uses a light scraping strategy with a single polite request
//! per scan. The ABN/ACN pivot via `abn_lookup` then enriches the full
//! company record including HQ address and geolocation — making this the
//! highest-confidence AU geo pivot after a FullName seed, when reachable.
//!
//! `process()` distinguishes "the request never actually got a readable
//! response" (a real `Error::module` failure, surfaced to the operator and to
//! the T2.7 scraper-health signal) from "ASIC Connect Online answered but had
//! no director record matching this name" (the ordinary, honest empty
//! success) — see [`request_failed`].

use async_trait::async_trait;

use crate::core::{
    confidence,
    entity::{Entity, EntityKind, Evidence},
    error::{Error, Result},
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::RequestBuilderExt;

const SRC: &str = "asic_director";

pub struct AsicDirector;

/// Strip HTML tags and decode entities, via the crate's shared helpers. Pure.
///
/// Was a hand-rolled `in_tag` loop with inline entity decoding, carrying two
/// defects the shared pair does not.
///
/// **It was quadratic.** Every `&` rebuilt the entire remainder of the document
/// into a fresh `String` purely to test it with `starts_with`, so cost grew with
/// (ampersand count x document length) — and an ASIC result table carries one
/// `&amp;` per company row, the worst case for exactly this shape. Measured on a
/// synthetic table of that shape: 8 KB took 1.59 ms and 128 KB took 395 ms, time
/// quadrupling per doubling, against 239 us for a linear scan of the same 128 KB.
/// On the Termux aarch64 target that is a module that returns nothing because it
/// spent its time budget parsing rather than fetching.
///
/// **It decoded four entities.** `&amp;`, `&lt;`, `&gt;` and `&nbsp;` only — so a
/// director named `O&#39;Brien`, a numeric reference and an unremarkable
/// Australian surname, reached the graph with the escape still in it, as did
/// every `&quot;`. [`crate::util::html::decode_entities`] covers the full named
/// set plus every decimal and hex character reference.
///
/// Deliberately [`strip_tags_plain`](crate::util::html::strip_tags_plain) rather
/// than [`strip_html`](crate::util::html::strip_html): `strip_html` substitutes a
/// space for each tag, and this output is consumed line-by-line by
/// [`extract_company_name`], so that would push a space into the middle of
/// extracted company names. Dropping tags outright preserves the previous
/// behaviour exactly. Tags come off before entities are decoded, so a decoded
/// `<` can never be re-read as the start of a tag.
fn clean_html(s: &str) -> String {
    crate::util::html::decode_entities(&crate::util::html::strip_tags_plain(s))
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
    let mut org = Entity::new(
        EntityKind::Organisation,
        company_name,
        confidence::HIGH_PLUSPLUS,
        scan_id,
    );
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
        let acn_clean = crate::util::str_util::ascii_digits(acn);
        // Checksum-validate before trusting it, exactly like every other
        // caller in this codebase that mints an ACN-shaped value
        // (au_business_id, the search_engines extractor,
        // core::correlator::rules::org, core::scan's TargetKind inference).
        // extract_acn() collects every digit anywhere in the row rather than
        // a run anchored on the "ACN" label, so a company name that itself
        // contains digits ("7-Eleven Stores Pty Ltd", "1300 Smiles Limited")
        // glues those leading digits onto the real ACN's stream, producing a
        // fabricated 9-digit value. Length alone can't catch that — the
        // corruption preserves the count — but the checksum almost always
        // will, so this is the honest floor against shipping a corrupted
        // value to the live ASIC ABN Lookup API as a "confirmed" pivot.
        if acn_clean.len() == 9 && crate::util::abn::is_valid_acn(&acn_clean) {
            let mut acn_e = Entity::new(
                EntityKind::AbnAcn,
                &acn_clean,
                confidence::CORROBORATED,
                scan_id,
            );
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
        let mut ae = Entity::new(EntityKind::Address, addr, confidence::ATTRIBUTED, scan_id);
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
            let mut c = Entity::new(
                EntityKind::Coordinates,
                &coord_val,
                confidence::NOTABLE,
                scan_id,
            );
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
    // ASIC result rows contain: Company Name | ACN | Address | Role | Status.
    // Keep lines where every whole-word name token appears somewhere in the
    // row, then extract company/ACN/address. Whole-word, not substring — a
    // raw `.contains()` check let a short token land inside an unrelated
    // word anywhere in the row (company name, address, ...), matching a
    // completely different director's row and attributing their company/
    // ACN/address to the queried name.
    clean_html(html)
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .filter(|line| crate::util::str_util::whole_word_token_match(line, full_name))
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
    let digits_only = crate::util::str_util::ascii_digits(text);
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
        "ASIC company-directors recon — surfaces director appointments for a full name and pivots to company ACN/address"
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
