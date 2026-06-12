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
//! Orthogonal to `qld_unclaimed` and `abn_lookup` — those mine business/govt
//! registers; this mines residential directories. Together they triangulate
//! physical location from three independent source classes (TA0043 technique
//! diversity principle).

use async_trait::async_trait;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::extract::page_emails;
use crate::util::http::RequestBuilderExt;

const SRC: &str = "au_people";

pub struct AuPeople;

/// Split a full name into first/last for URL construction. Returns `(first, last)`
/// where `last` is every token after the first. Pure.
fn split_name(full: &str) -> (&str, &str) {
    let trimmed = full.trim();
    if let Some(pos) = trimmed.find(' ') {
        (&trimmed[..pos], trimmed[pos + 1..].trim_start())
    } else {
        (trimmed, "")
    }
}

/// Extract au-state tag from suburb/state text. Pure.
fn state_tag_from_text(text: &str) -> Option<String> {
    crate::util::address_au::state_code(text).map(|s| format!("au-state:{s}"))
}

/// Parse White Pages AU result HTML for address/phone/name entries.
/// Looks for structured microdata and text patterns. Pure.
fn parse_whitepages_html(html: &str, full_name: &str, scan_id: &str) -> Vec<Entity> {
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
                    .filter(|c| c.is_ascii_digit())
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
                // Grab surrounding 120-char window for suburb/state context.
                let ctx_start = i.saturating_sub(60);
                let ctx_end = (i + 64).min(len);
                let context = &html[ctx_start..ctx_end];
                // Strip HTML tags from context.
                let stripped = strip_html_tags(context);
                let trimmed = stripped.trim().replace("  ", " ");
                if !trimmed.is_empty()
                    && trimmed.len() > 5
                    && !seen_addresses.insert(trimmed.clone())
                {
                    i += 4;
                    continue;
                }
                if !trimmed.is_empty() && trimmed.len() > 5 {
                    let addr_conf = if name_lc
                        .split_whitespace()
                        .all(|tok| html[..ctx_end].to_lowercase().contains(tok))
                    {
                        0.55
                    } else {
                        0.42
                    };
                    let mut ae = Entity::new(EntityKind::Address, &trimmed, addr_conf, scan_id);
                    ae.tag(SRC);
                    ae.tag("au-directory");
                    ae.tag("whitepages");
                    ae.tag("country:AU");
                    if let Some(st) = state_tag_from_text(&trimmed) {
                        ae.tag(st);
                    }
                    ae.add_evidence(
                        Evidence::new(
                            SRC,
                            format!("White Pages AU address context for {full_name}"),
                        )
                        .with_attr("postcode", postcode)
                        .with_attr("context", &trimmed),
                    );
                    out.push(ae);
                }
            }
            i += 4;
            continue;
        }

        i += 1;
    }

    // Mine any email addresses visible in the HTML.
    for email in page_emails(html) {
        let mut e = Entity::new(EntityKind::Email, &email, 0.45, scan_id);
        e.tag(SRC);
        e.tag("au-directory");
        e.tag("whitepages");
        e.add_evidence(
            Evidence::new(SRC, format!("White Pages AU contact email for {full_name}"))
                .with_attr("source", "whitepages_au"),
        );
        out.push(e);
    }

    out
}

/// Strip HTML tags from a string slice, replacing each tag with a space. Pure.
fn strip_html_tags(html: &str) -> String {
    let mut out = String::with_capacity(html.len());
    let mut in_tag = false;
    for ch in html.chars() {
        match ch {
            '<' => {
                in_tag = true;
                // Replace the tag with a space so adjacent text stays separated.
                if !out.ends_with(' ') {
                    out.push(' ');
                }
            }
            '>' => in_tag = false,
            _ if !in_tag => out.push(ch),
            _ => {}
        }
    }
    out
}

/// Parse True People Search AU HTML for name-confirmed address and phone entities.
/// Uses a simpler heuristic — TPS structures results as JSON-LD or visible text blocks. Pure.
fn parse_tps_html(html: &str, full_name: &str, scan_id: &str) -> Vec<Entity> {
    let mut out = Vec::new();
    let stripped = strip_html_tags(html);

    // TPS embeds addresses as "Suburb, STATE POSTCODE" patterns.
    // Use a simple line-by-line scan for lines that look like AU addresses.
    for line in stripped.lines() {
        let line = line.trim();
        if line.len() < 6 || line.len() > 120 {
            continue;
        }
        // Must contain at least one word that is an AU state abbreviation.
        if crate::util::address_au::state_code(line).is_none() {
            continue;
        }
        // Must contain a 4-digit AU postcode.
        let has_postcode = line.split_whitespace().any(|tok| {
            tok.len() == 4
                && tok.chars().all(|c| c.is_ascii_digit())
                && tok.parse::<u32>().is_ok_and(|n| (2000..=7999).contains(&n))
        });
        if !has_postcode {
            continue;
        }

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
        out.push(ae);
    }

    // Mine emails.
    for email in page_emails(&stripped) {
        let mut e = Entity::new(EntityKind::Email, &email, 0.45, scan_id);
        e.tag(SRC);
        e.tag("au-directory");
        e.tag("tps-au");
        e.add_evidence(
            Evidence::new(SRC, format!("TPS AU contact email for {full_name}"))
                .with_attr("source", "tps_au"),
        );
        out.push(e);
    }

    out
}

/// Deduplicate entities by (kind, value) from a mutable result. Pure.
fn dedup_by_kind_value(entities: &mut Vec<Entity>) {
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
            .header(
                "User-Agent",
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            )
            .send_tagged(SRC)
            .await
            && resp.status().is_success()
            && let Ok(html) = resp.text().await
        {
            let mut ents = parse_whitepages_html(&html, full_name, &ctx.scan_id);
            for e in ents.drain(..) {
                result.push(e);
            }
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
            .header(
                "User-Agent",
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            )
            .send_tagged(SRC)
            .await
            && resp.status().is_success()
            && let Ok(html) = resp.text().await
        {
            let mut ents = parse_tps_html(&html, full_name, &ctx.scan_id);
            for e in ents.drain(..) {
                result.push(e);
            }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_two_token_fullname_only() {
        let m = AuPeople;
        assert!(m.accepts(&Target::new(TargetKind::FullName, "Haigen Bamford")));
        assert!(!m.accepts(&Target::new(TargetKind::FullName, "Haigen"))); // single token
        assert!(!m.accepts(&Target::new(TargetKind::Email, "a@b.com")));
        assert!(!m.accepts(&Target::new(TargetKind::Username, "haigen")));
    }

    #[test]
    fn module_metadata() {
        let m = AuPeople;
        assert_eq!(m.name(), "au_people");
        assert!(m.attack_techniques().contains(&"T1591.001"));
        assert!(m.attack_techniques().contains(&"T1589.003"));
    }

    #[test]
    fn split_name_standard() {
        assert_eq!(split_name("Haigen Bamford"), ("Haigen", "Bamford"));
        assert_eq!(split_name("Mary Jane Watson"), ("Mary", "Jane Watson"));
        assert_eq!(split_name("Solo"), ("Solo", ""));
    }

    #[test]
    fn strip_html_tags_removes_markup() {
        // Tags are replaced by spaces; adjacent content stays separated.
        let r = strip_html_tags("<b>Sydney</b>, <span>NSW</span> 2000");
        assert!(r.contains("Sydney") && r.contains("NSW") && r.contains("2000"));
        assert_eq!(strip_html_tags("plain text"), "plain text");
    }

    #[test]
    fn parse_tps_html_extracts_au_address() {
        let html =
            "<div>Results for Test Person</div><p>Bondi Beach, NSW 2026</p><p>Other line</p>";
        let ents = parse_tps_html(html, "Test Person", "s");
        assert!(
            ents.iter().any(|e| e.kind == EntityKind::Address
                && e.value.contains("NSW")
                && e.has_tag("au-state:NSW")),
            "should extract NSW address"
        );
    }

    #[test]
    fn parse_tps_html_skips_non_au_lines() {
        // No AU state abbreviation or postcode → nothing emitted.
        let html = "<p>London, UK</p><p>New York, NY 10001</p>";
        let ents = parse_tps_html(html, "Test Person", "s");
        assert!(
            ents.iter().all(|e| e.kind != EntityKind::Address),
            "non-AU addresses should not be emitted"
        );
    }

    #[test]
    fn dedup_removes_same_kind_value() {
        let mut ents = vec![
            Entity::new(EntityKind::Address, "Sydney NSW 2000", 0.5, "s"),
            Entity::new(EntityKind::Address, "Sydney NSW 2000", 0.6, "s"),
            Entity::new(EntityKind::Email, "a@b.com", 0.5, "s"),
        ];
        dedup_by_kind_value(&mut ents);
        assert_eq!(ents.len(), 2);
    }

    #[test]
    fn state_tag_from_text_recognises_au_states() {
        assert_eq!(
            state_tag_from_text("Bondi Beach NSW 2026"),
            Some("au-state:NSW".into())
        );
        assert_eq!(
            state_tag_from_text("Melbourne VIC 3000"),
            Some("au-state:VIC".into())
        );
        assert!(state_tag_from_text("London UK").is_none());
    }
}
