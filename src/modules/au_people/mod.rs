//! Australian people-finder — White Pages AU + True People Search AU.
//!
//! Scrapes the public search results pages for a full-name seed (optionally
//! location-qualified) and extracts names, addresses, phone numbers, and
//! suburb/state data as structured entities.
//!
//! Sources (both keyless, free):
//!   * White Pages AU — `https://www.whitepages.com.au/residential/search/{FirstName}+{LastName}`
//!   * True People Search AU — `https://www.truepeoplesearch.com.au/results?name={Full+Name}`
//!
//! MITRE ATT&CK:
//!   * T1591.001 — Determine Physical Locations (residential address + suburb)
//!   * T1589.002 — Email Addresses (contact details where listed)
//!   * T1589.003 — Employee Names (confirms legal name, nickname variants)
//!
//! Confidence model:
//!   * Address with suburb + state: 0.55 (single-source, AU register quality)
//!   * Phone number: 0.50 (listed, unverified)
//!   * Name variant confirmation: 0.60 (exact match in directory)
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

/// Isolate the canonical `Suburb, STATE POSTCODE` locality from a noisy
/// directory window. **Pure.**
///
/// The White Pages parser grabs a ±60-char byte window around each postcode,
/// which captures page chrome adjacent to the address — breadcrumb labels
/// ("Australian Suburbs"), section headings, "profile"/"results" boilerplate.
/// Emitting the raw window as the Address value produced malformed entities
/// like `"Australian SuburbsWoronora, NSW 2232"` (observed live: it then became
/// a re-scan seed, wasting classifier/search/geocode dispatches on garbage).
///
/// This keeps only the 1-3 capitalised words immediately before the
/// `STATE POSTCODE` tail and drops a leading directory-chrome stop-word so a
/// genuine multi-word suburb ("Gold Coast", "St Kilda") survives while
/// "Australian Suburbs Woronora" collapses to "Woronora". Returns `None` when
/// the window holds no recognisable `Suburb STATE POSTCODE` shape.
pub(super) fn clean_au_locality(window: &str) -> Option<String> {
    static LOCALITY_RE: LazyLock<Regex> = LazyLock::new(|| {
        // 1-3 capitalised words, optional comma, AU state, 4-digit postcode.
        Regex::new(
            r"([A-Z][A-Za-z'.\-]+(?:\s+[A-Z][A-Za-z'.\-]+){0,2}),?\s+(NSW|VIC|QLD|SA|WA|TAS|NT|ACT)\s+(\d{4})\b",
        )
        .expect("constant AU locality regex")
    });
    // Words that head page chrome but never a real AU suburb — stripped from the
    // front of the captured suburb run (data-driven from live scan artifacts).
    const CHROME_WORDS: &[&str] = &[
        "Australian",
        "Suburbs",
        "Suburb",
        "Profile",
        "Profiles",
        "Results",
        "Result",
        "Search",
        "Background",
        "View",
        "Address",
        "Addresses",
        "Location",
        "Locations",
        "Home",
        "Find",
        "People",
        "Name",
        "Names",
        "Phone",
    ];
    // The window can hold several matches (e.g. a breadcrumb postcode then the
    // result's own); the LAST is the one adjacent to the postcode we scanned.
    let caps = LOCALITY_RE.captures_iter(window).last()?;
    let suburb_raw = caps.get(1)?.as_str();
    let state = caps.get(2)?.as_str();
    let postcode = caps.get(3)?.as_str();

    // Drop leading chrome words; keep the trailing real suburb tokens.
    let mut words: Vec<&str> = suburb_raw.split_whitespace().collect();
    while words.len() > 1 && CHROME_WORDS.contains(&words[0]) {
        words.remove(0);
    }
    // A suburb that is ONLY a chrome word is not a real locality.
    if words.len() == 1 && CHROME_WORDS.contains(&words[0]) {
        return None;
    }
    let suburb = words.join(" ");
    if suburb.is_empty() {
        return None;
    }
    Some(format!("{suburb}, {state} {postcode}"))
}

/// Parse White Pages AU result HTML for address/phone/name entries.
/// Looks for structured microdata and text patterns. Pure.
pub(super) fn parse_whitepages_html(html: &str, full_name: &str, scan_id: &str) -> Vec<Entity> {
    let mut out = Vec::new();
    let name_lc = full_name.to_lowercase();

    // White Pages AU structures results as repeated blocks containing suburb, state, phone.
    // We scan for AU postcode patterns (4 digits) surrounded by suburb/state context.
    let bytes = html.as_bytes();
    let len = bytes.len();
    let mut i = 0;

    // Look for phone number patterns: (0X) XXXX XXXX or 04XX XXX XXX
    let mut seen_phones: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut seen_addresses: std::collections::HashSet<String> = std::collections::HashSet::new();

    // Extract phone numbers via extract::phones (E.164 +61 format) — but White Pages
    // uses local AU format so we also scan for 10-digit AU mobile/landline patterns.
    // AU mobile: 04XX XXX XXX; Landline: (0X) XXXX XXXX
    while i < len {
        // Scan for "04" prefix mobile numbers in text.
        if i + 10 < len
            && bytes[i] == b'0'
            && bytes[i + 1] == b'4'
            && bytes[i..i + 2]
                .iter()
                .all(|b| b.is_ascii_digit() || *b == b'0' || *b == b'4')
        {
            let start = i;
            let mut digits = 0u32;
            let mut j = i;
            while j < len && (bytes[j].is_ascii_digit() || bytes[j] == b' ') && digits <= 10 {
                if bytes[j].is_ascii_digit() {
                    digits += 1;
                }
                j += 1;
            }
            if digits == 10 {
                let raw: String = html[start..j]
                    .chars()
                    .filter(char::is_ascii_digit)
                    .collect();
                // Convert local AU 04XX → E.164 +614XX
                if raw.starts_with('0') {
                    let e164 = format!("+61{}", raw.strip_prefix('0').unwrap_or(&raw));
                    if seen_phones.insert(e164.clone()) {
                        let mut e = Entity::new(EntityKind::Phone, &e164, 0.50, scan_id);
                        e.tag(SRC);
                        e.tag("au-directory");
                        e.tag("whitepages");
                        e.tag("country:AU");
                        e.add_evidence(
                            Evidence::new(SRC, format!("White Pages AU phone for {full_name}"))
                                .with_attr("raw", &raw)
                                .with_attr("source", "whitepages_au"),
                        );
                        out.push(e);
                    }
                }
            }
            i = j;
            continue;
        }

        // Scan for 4-digit AU postcodes in text context — build Address entities.
        if i + 4 <= len
            && bytes[i].is_ascii_digit()
            && bytes[i + 1].is_ascii_digit()
            && bytes[i + 2].is_ascii_digit()
            && bytes[i + 3].is_ascii_digit()
            && (i == 0 || !bytes[i - 1].is_ascii_digit())
            && (i + 4 >= len || !bytes[i + 4].is_ascii_digit())
        {
            let postcode = &html[i..i + 4];
            // Only process valid AU postcode ranges (2000-7999).
            if let Ok(pc) = postcode.parse::<u32>()
                && (2000..=7999).contains(&pc)
            {
                // Grab a ~120-char window around the postcode for suburb/state
                // context. `i±60` are arbitrary byte offsets into untrusted
                // response HTML; a raw `&html[..]` panics when one lands inside a
                // multibyte character (accented suburb names, typographic quotes,
                // NBSP — all common in real pages), so clamp to char boundaries.
                let context =
                    crate::util::str_util::char_window(html, i.saturating_sub(60), i + 64);
                // Strip HTML tags from context.
                let stripped = strip_html(context);
                let trimmed = stripped.trim().replace("  ", " ");
                // Isolate the canonical `Suburb, STATE POSTCODE` locality from the
                // noisy window — the raw window carries page chrome adjacent to the
                // postcode (breadcrumb labels, headings) that must not become part
                // of the Address value. Skip the postcode entirely if no clean
                // locality is recoverable.
                let Some(locality) = clean_au_locality(&trimmed) else {
                    i += 4;
                    continue;
                };
                if !seen_addresses.insert(locality.clone()) {
                    i += 4;
                    continue;
                }
                {
                    // Does the seed name appear in the HTML up to just past the
                    // postcode? `i + 64` is a byte offset into untrusted HTML, so
                    // clamp it to a char boundary (raw `html[..i+64]` panics on
                    // multibyte content); lower-case the window once, not per token.
                    let window_lc =
                        crate::util::str_util::truncate_safe(html, i + 64).to_lowercase();
                    let addr_conf = if name_lc
                        .split_whitespace()
                        .all(|tok| window_lc.contains(tok))
                    {
                        0.55
                    } else {
                        0.42
                    };
                    let mut ae = Entity::new(EntityKind::Address, &locality, addr_conf, scan_id);
                    ae.tag(SRC);
                    ae.tag("au-directory");
                    ae.tag("whitepages");
                    ae.tag("country:AU");
                    if let Some(st) = state_tag_from_text(&locality) {
                        ae.tag(st);
                    }
                    ae.add_evidence(
                        Evidence::new(
                            SRC,
                            format!("White Pages AU address context for {full_name}"),
                        )
                        .with_attr("postcode", postcode)
                        // Preserve the raw window for provenance/audit.
                        .with_attr("context", &trimmed),
                    );
                    if let Some((lat, lon)) = crate::util::city_coords::city_coords(&locality) {
                        let coord_val = format!("{lat:.4},{lon:.4}");
                        let mut c = Entity::new(
                            EntityKind::Coordinates,
                            &coord_val,
                            addr_conf - 0.10,
                            scan_id,
                        );
                        c.tag(SRC);
                        c.tag("addr-derived");
                        c.tag("geoint");
                        c.tag("country:AU");
                        c.add_evidence(Evidence::new(
                            SRC,
                            format!("Geocode of White Pages AU address for {full_name}"),
                        ));
                        out.push(c);
                    }
                    out.push(ae);
                }
            }
            i += 4;
            continue;
        }

        i += 1;
    }

    // Mine any email addresses visible in the HTML.
    out.extend(page_emails(html).into_iter().map(|email| {
        let mut e = Entity::new(EntityKind::Email, &email, 0.45, scan_id);
        e.tag(SRC);
        e.tag("au-directory");
        e.tag("whitepages");
        e.add_evidence(
            Evidence::new(SRC, format!("White Pages AU contact email for {full_name}"))
                .with_attr("source", "whitepages_au"),
        );
        e
    }));

    out
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
                        format!("True People Search AU address for {full_name}"),
                    )
                    .with_attr("line", line)
                    .with_attr("source", "tps_au"),
                );
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
                format!("Geocode of True People Search AU address for {full_name}"),
            ));
            Some(c)
        })
        .collect();
    out.extend(tps_coords);

    // Mine emails.
    out.extend(page_emails(&stripped).into_iter().map(|email| {
        let mut e = Entity::new(EntityKind::Email, &email, 0.45, scan_id);
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
/// below the 0.50 expansion floor (0.45) so a relative is recorded and linked
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
            let mut e = Entity::new(EntityKind::Person, &name, 0.45, scan_id);
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

/// Deduplicate entities by (kind, value) from a mutable result. Pure.
pub(super) fn dedup_by_kind_value(entities: &mut Vec<Entity>) {
    let mut seen = std::collections::HashSet::new();
    entities.retain(|e| seen.insert((e.kind.clone(), e.value.clone())));
}

#[async_trait]
impl Module for AuPeople {
    fn name(&self) -> &'static str {
        SRC
    }

    fn description(&self) -> &'static str {
        "Australian people-finder — White Pages AU + True People Search AU for residential address, phone and name confirmation"
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
        12_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let full_name = target.value.trim();
        let (first, last) = split_name(full_name);
        if first.is_empty() || last.is_empty() {
            return Ok(ModuleResult::new());
        }

        let mut result = ModuleResult::new();

        // White Pages AU search.
        let wp_url = format!(
            "https://www.whitepages.com.au/residential/search/{}+{}",
            crate::util::http::urlencode(first),
            crate::util::http::urlencode(last),
        );
        if let Ok(resp) = ctx
            .http
            .get(&wp_url)
            .header("Accept", "text/html,application/xhtml+xml")
            .header("User-Agent", crate::util::http::UA_BROWSER)
            .send_tagged(SRC)
            .await
            && resp.status().is_success()
            && let Some(html) = read_body_capped(resp, 1_000_000).await
        {
            result.extend(parse_whitepages_html(&html, full_name, &ctx.scan_id));
            result.extend(parse_relatives(&html, full_name, &ctx.scan_id));
        }

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
                .with_attr("source", "whitepages_au+tps_au"),
            );
            result.push(person);
        }

        dedup_by_kind_value(&mut result.entities);
        Ok(result)
    }
}
