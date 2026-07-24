//! Australian people-finder — True People Search AU.
//!
//! Scrapes the public search results page for a full-name seed (optionally
//! location-qualified) and extracts names, addresses, phone numbers, and
//! suburb/state data as structured entities.
//!
//! Sources (keyless, free):
//!   * True People Search AU — `https://www.truepeoplesearch.com.au/results?name={Full+Name}`
//!
//! No White Pages AU leg: `whitepages.com.au/residential/search/{name}` is
//! retired — live-confirmed (2026-07-13) via three real `GET` requests (a
//! nonsense name, the common real name "John Smith", and the bare
//! `/residential/search/` root), every one returning a generic HTTP 404
//! rather than a query-specific result. The site's own markup confirms
//! this isn't transient: it now serves a Nuxt.js client-rendered SPA (no
//! server-rendered search form at all), so the legacy path this module
//! queried no longer exists in any form. Repointing to whatever data API
//! the SPA now calls client-side is a distinct future capability (not
//! confirmed reachable/stable from a quick static check), not a same-shape
//! endpoint repair, so the dead dispatch was removed rather than left to
//! silently pay a wasted request/timeout cost on every scan — `process()`
//! already gated the parse on `resp.status().is_success()`, so this never
//! risked misparsing the 404 page, only ever contributed nothing. The
//! `parse_whitepages_html` parser (and its `clean_au_locality` helper) were
//! removed along with the dispatch, not kept dormant: they parse the
//! retired server-rendered HTML shape specifically, which a future SPA-API
//! repoint would need an entirely new parser for anyway (a different data
//! shape, not a revived old one).
//!
//! MITRE ATT&CK:
//!   * T1591.001 — Determine Physical Locations (residential address + suburb)
//!   * T1589.002 — Email Addresses (contact details where listed)
//!   * T1589.003 — Employee Names (confirms legal name, nickname variants)
//!
//! Confidence model:
//!   * Address with suburb + state: confidence::MEDIUM_HIGH (single-source, AU register quality)
//!   * Phone number: confidence::MEDIUM (listed, unverified)
//!   * Name variant confirmation: confidence::MEDIUM_PLUS (exact match in directory)
//!
//! Orthogonal to `au_unclaimed` and `abn_lookup` — those mine business/govt
//! registers; this mines residential directories. Together they triangulate
//! physical location from three independent source classes (TA0043 technique
//! diversity principle).
//!
//! It also extracts the **relatives / associates** these directories list
//! ([`parse_relatives`]) as Person entities bound to the subject by `related_to`
//! — a second, independent FAMILY angle alongside the government registers, so
//! the relation layer forms a *reliable* family link (two sources, plus surname
//! kinship) rather than a single-source candidate.

#[cfg(test)]
mod tests;

use std::sync::LazyLock;

use async_trait::async_trait;
use regex::Regex;

use crate::core::{
    confidence,
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::extract::page_emails;
use crate::util::html::strip_html;
use crate::util::http::{RequestBuilderExt, read_body_capped};

pub(crate) const SRC: &str = "au_people";

pub struct AuPeople;

/// Split a full name into first/last for URL construction. Returns `(first, last)`
/// where `last` is every token after the first. Pure.
pub(super) fn split_name(full: &str) -> (&str, &str) {
    let trimmed = full.trim();
    if let Some(pos) = trimmed.find(' ') {
        (&trimmed[..pos], trimmed[pos + 1..].trim_start())
    } else {
        (trimmed, "")
    }
}

/// Extract au-state tag from suburb/state text. Pure.
pub(super) fn state_tag_from_text(text: &str) -> Option<String> {
    crate::util::address_au::state_code(text).map(|s| format!("au-state:{s}"))
}

/// Parse True People Search AU HTML for name-confirmed address and phone entities.
/// Uses a simpler heuristic — TPS structures results as JSON-LD or visible text blocks. Pure.
pub(super) fn parse_tps_html(html: &str, full_name: &str, scan_id: &str) -> Vec<Entity> {
    let mut out = Vec::new();
    let stripped = strip_html(html);

    // TPS embeds addresses as "Suburb, STATE POSTCODE" patterns.
    // Use a simple line-by-line scan for lines that look like AU addresses.
    out.extend(
        stripped
            .lines()
            .map(str::trim)
            .filter(|&line| (6..=120).contains(&line.len()))
            // Must name an AU state abbreviation and carry a 4-digit AU postcode.
            .filter(|&line| crate::util::address_au::state_code(line).is_some())
            .filter(|&line| {
                line.split_whitespace().any(|tok| {
                    tok.len() == 4
                        && tok.chars().all(|c| c.is_ascii_digit())
                        && tok.parse::<u32>().is_ok_and(|n| (2000..=7999).contains(&n))
                })
            })
            .map(|line| {
                let mut ae = Entity::new(EntityKind::Address, line, 0.52, scan_id);
                ae.tag(SRC);
                ae.tag("au-directory");
                ae.tag("tps-au");
                ae.tag("country:AU");
                if let Some(st) = state_tag_from_text(line) {
                    ae.tag(st);
                }
                ae.add_evidence(
                    Evidence::new(
                        SRC,
                        format!(
                            "Address listed on the True People Search AU results page for {full_name} (attribution unconfirmed)"
                        ),
                    )
                    .with_attr("line", line)
                    .with_attr("source", "tps_au"),
                );
                // A TPS results page lists the subject ALONGSIDE relatives,
                // associates, and unrelated same-name people, and this line scan
                // cannot tell whose address a line is. Emitting each as a CONFIRMED
                // subject Address (0.52, above the 0.50 floor) fabricated a residency
                // — and an `au-state:` jurisdiction — for strangers, polluting the AU
                // residency verdict (AU-090/091/092/098). Demote to a candidate lead:
                // retained for the Network/full views, excluded from the confirmed
                // graph, correlator, and residency consensus. The subject's real
                // address is confirmed by the name-matched sources
                // (au_property/au_unclaimed), not this unattributed line scan.
                ae.demote_to_candidate();
                ae
            }),
    );
    // Geocode TPS address lines to Coordinates.
    let tps_coords: Vec<_> = out
        .iter()
        .filter(|e| e.kind == EntityKind::Address && e.tags.iter().any(|t| t == "tps-au"))
        .filter_map(|e| {
            let (lat, lon) = crate::util::city_coords::city_coords(&e.value)?;
            let coord_val = format!("{lat:.4},{lon:.4}");
            let mut c = Entity::new(EntityKind::Coordinates, &coord_val, 0.42, scan_id);
            c.tag(SRC);
            c.tag("addr-derived");
            c.tag("geoint");
            c.tag("country:AU");
            c.add_evidence(Evidence::new(
                SRC,
                format!(
                    "Geocode of an address listed on the True People Search AU results page for {full_name} (attribution unconfirmed)"
                ),
            ));
            // Derived from an unconfirmed TPS address (see the parse above) — carry
            // the same candidate quarantine so an unattributed line can't seed a
            // confirmed coordinate that feeds the geo footprint.
            c.demote_to_candidate();
            Some(c)
        })
        .collect();
    out.extend(tps_coords);

    // Mine emails.
    out.extend(page_emails(&stripped).into_iter().map(|email| {
        let mut e = Entity::new(EntityKind::Email, &email, confidence::LOW_MEDIUM, scan_id);
        e.tag(SRC);
        e.tag("au-directory");
        e.tag("tps-au");
        e.add_evidence(
            Evidence::new(SRC, format!("TPS AU contact email for {full_name}"))
                .with_attr("source", "tps_au"),
        );
        e
    }));

    out
}

/// Relationship-section markers AU people-search pages use to list a person's
/// relatives and associates (True People Search AU; "people you may know"). The
/// names that follow are the family/associate angle this module adds.
static RELATIVES_SECTION_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?is)(?:possible relatives|relatives|possible associates|known associates|associates|related to|lives with|household members?|also known as)\b(.{0,300})",
    )
    .expect("constant relatives-section regex")
});

/// Extract the relatives/associates a people-search page lists as Person
/// entities bound to the subject by a `related_to` attribute (so the relation
/// layer links them, and surname kinship corroborates).
///
/// Deliberately CONSERVATIVE for reliability: within a relationship section it
/// keeps only well-formed capitalised name runs **ending in the subject's
/// surname** — the family the operator is after — which also rejects the page
/// chrome ("View Profile", "Background Check", suburb names). Each is emitted
/// below the confidence::MEDIUM expansion floor (confidence::LOW_MEDIUM) so a relative is recorded and linked
/// but never auto-pivoted into its own sub-scan. Pure.
pub(super) fn parse_relatives(html: &str, full_name: &str, scan_id: &str) -> Vec<Entity> {
    let text = strip_html(html);
    let full = full_name.trim();
    let surname_lc = match full.rsplit(' ').next() {
        Some(s) if s.chars().filter(|c| c.is_alphabetic()).count() >= 2 => s.to_lowercase(),
        _ => return Vec::new(),
    };
    let subject_lc = full.to_lowercase();
    // Capitalised page chrome that sits adjacent to names on people-search
    // results and would otherwise be mis-read as a given name ("View **Profile**
    // Helene Moreau"). A given-name token must not be one of these.
    const CHROME: &[&str] = &[
        "view",
        "profile",
        "background",
        "check",
        "search",
        "report",
        "address",
        "phone",
        "age",
        "record",
        "records",
        "details",
        "more",
        "see",
        "full",
        "results",
        "result",
        "public",
        "people",
        "find",
        "lookup",
        "contact",
        "email",
        "relatives",
        "associates",
        "possible",
        "known",
        "related",
        "lives",
        "household",
        "also",
        "aka",
        "name",
        "names",
        "mobile",
        "landline",
        "current",
        "former",
        "city",
        "state",
        "suburb",
        "this",
        "person",
        "and",
        "the",
        "with",
    ];
    let strip_punct = |w: &str| w.trim_matches(|c: char| !c.is_alphabetic()).to_lowercase();
    let is_name_token = |t: &str| {
        let tl = strip_punct(t);
        t.chars().next().is_some_and(char::is_uppercase)
            && t.len() <= 20
            && t.chars()
                .all(|c| c.is_alphabetic() || matches!(c, '.' | '\'' | '-'))
            && !CHROME.contains(&tl.as_str())
    };

    let mut out = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    for sec in RELATIVES_SECTION_RE.captures_iter(&text) {
        let Some(window) = sec.get(1) else { continue };
        let words: Vec<&str> = window.as_str().split_whitespace().collect();
        for (i, w) in words.iter().enumerate() {
            if strip_punct(w) != surname_lc {
                continue;
            }
            // Walk back over up to two immediately-preceding name tokens (given
            // name + optional middle name/initial); stop at the first non-name.
            let mut given: Vec<&str> = Vec::new();
            for j in (0..i).rev() {
                if given.len() >= 2 || !is_name_token(words[j]) {
                    break;
                }
                given.push(words[j]);
            }
            if given.is_empty() {
                continue;
            }
            given.reverse();
            let raw = format!(
                "{} {}",
                given.join(" "),
                w.trim_matches(|c: char| !c.is_alphabetic())
            );
            let name = crate::util::str_util::title_case(&raw);
            let name_lc = name.to_lowercase();
            if name.len() < 5 || name_lc == subject_lc || !seen.insert(name_lc) {
                continue;
            }
            let mut e = Entity::new(EntityKind::Person, &name, confidence::LOW_MEDIUM, scan_id);
            e.tag(SRC);
            e.tag("au-directory");
            e.tag("relatives");
            e.tag("family-candidate");
            e.tag("country:AU");
            e.add_evidence(
                Evidence::new(
                    SRC,
                    format!("AU residential directory lists {name} as a relative of {full}"),
                )
                .with_attr("relationship", "relative")
                .with_attr("related_to", full)
                .with_attr("source", "au_people_relatives"),
            );
            out.push(e);
        }
    }
    out
}

/// Deduplicate entities by (kind, value), GREATEST-merging duplicates into the
/// first occurrence rather than discarding them. Pure; order-preserving.
///
/// This module accumulates results from two independent AU directories (White
/// Pages AU + True People Search AU, plus a relatives pass over each). The SAME
/// address or phone is frequently listed by both — each source emits an entity
/// with the same normalised `(kind, value)`, hence the same UID, but carrying
/// its own distinct evidence. Simply keeping the first and dropping the rest
/// (the previous behaviour) silently discarded the second directory's
/// independent confirmation *at the module boundary*, before the engine's own
/// UID-merge could ever see it — throwing away exactly the cross-source
/// corroboration that makes a people-finder hit trustworthy. Folding duplicates
/// through [`Entity::merge`] (GREATEST-semantics: max confidence, summed
/// corroboration, unioned + de-duplicated evidence and tags) means a fact both
/// directories agree on now reads as corroborated. `merge` is commutative in the
/// folded signal, so the result is independent of input order (only the surviving
/// slot's position follows first-occurrence order).
pub(super) fn dedup_by_kind_value(entities: &mut Vec<Entity>) {
    use std::collections::HashMap;
    let mut index: HashMap<(EntityKind, String), usize> = HashMap::new();
    let mut deduped: Vec<Entity> = Vec::with_capacity(entities.len());
    for e in entities.drain(..) {
        let key = (e.kind.clone(), e.value.clone());
        match index.get(&key) {
            Some(&i) => deduped[i].merge(e),
            None => {
                index.insert(key, deduped.len());
                deduped.push(e);
            }
        }
    }
    *entities = deduped;
}

#[async_trait]
impl Module for AuPeople {
    fn name(&self) -> &'static str {
        SRC
    }

    fn description(&self) -> &'static str {
        "Australian people-finder — sweeps White Pages AU + True People Search AU to confirm a name against residential address and phone"
    }

    fn priority(&self) -> u8 {
        88
    }

    fn accepts(&self, t: &Target) -> bool {
        if t.kind != TargetKind::FullName {
            return false;
        }
        // Require at least two tokens (first + last name).
        t.value.trim().contains(' ')
    }

    /// `accepts()` value-gates (a name must have ≥2 tokens), so the default
    /// probe-based `consumes()` is empty — which would leave this module out of
    /// the FullName dispatch bucket and silently never run. Declare the kind
    /// explicitly; the per-target `accepts()` re-check at dispatch preserves the
    /// multi-word value filter.
    fn consumes(&self) -> Vec<TargetKind> {
        vec![TargetKind::FullName]
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::People
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        &["T1591.001", "T1589.002", "T1589.003"]
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[
            EntityKind::Address,
            EntityKind::Phone,
            EntityKind::Email,
            EntityKind::Person,
            EntityKind::Coordinates,
        ];
        KINDS
    }

    fn max_timeout_ms(&self) -> u64 {
        // One remaining lookup (TPS AU) now that the retired White Pages
        // AU leg is gone — was 12,000 for the two sequential calls.
        6_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let full_name = target.value.trim();
        let (first, last) = split_name(full_name);
        if first.is_empty() || last.is_empty() {
            return Ok(ModuleResult::new());
        }

        let mut result = ModuleResult::new();

        // No White Pages AU leg: see the module doc comment — the endpoint
        // this used to query is retired (confirmed 404 for any name).

        // True People Search AU.
        let tps_url = format!(
            "https://www.truepeoplesearch.com.au/results?name={}",
            crate::util::http::urlencode(full_name),
        );
        if let Ok(resp) = ctx
            .http
            .get(&tps_url)
            .header("Accept", "text/html,application/xhtml+xml")
            .header("User-Agent", crate::util::http::UA_BROWSER)
            .send_tagged(SRC)
            .await
            && resp.status().is_success()
            && let Some(html) = read_body_capped(resp, 1_000_000).await
        {
            result.extend(parse_tps_html(&html, full_name, &ctx.scan_id));
            result.extend(parse_relatives(&html, full_name, &ctx.scan_id));
        }

        // Emit a Person anchor for the name if we got any results — confirms
        // the name exists in AU residential directories.
        if !result.entities.is_empty() {
            let mut person = Entity::new(EntityKind::Person, full_name, 0.62, &ctx.scan_id);
            person.tag(SRC);
            person.tag("au-directory");
            person.tag("confirmed-in-directory");
            person.add_evidence(
                Evidence::new(
                    SRC,
                    format!("Name '{full_name}' found in AU residential directory"),
                )
                .with_attr("source", "tps_au"),
            );
            result.push(person);
        }

        dedup_by_kind_value(&mut result.entities);
        Ok(result)
    }
}
