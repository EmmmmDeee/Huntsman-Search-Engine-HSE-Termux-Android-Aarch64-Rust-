//! Employer / business address pivot.
//!
//! Given an Email target with a non-freemail domain, OR a Domain target,
//! this module fetches the public homepage and the canonical contact
//! pages (`/contact`, `/contact-us`, `/about`, `/about-us`, `/team`,
//! `/our-team`), strips HTML, and extracts:
//!
//!  - Australian-format business addresses (Level/Suite/Unit + Street +
//!    Suburb + State + Postcode) → Address entities
//!  - AU phone numbers (E.164 normalised) → Phone entities
//!  - Email addresses on the same domain → Email entities
//!  - Linked external profile URLs (LinkedIn, Facebook, Instagram,
//!    LinkedIn pages) → Url entities
//!
//! This is the OSINT→Geolocation bridge for professional subjects:
//! once a subject's employer-domain email surfaces, the employer's
//! commercial address is one round-trip away.
//!
//! Free, no API key required. Uses curl for resilience against
//! aggressive TLS fingerprinting.

use async_trait::async_trait;
use std::collections::HashSet;
use std::sync::OnceLock;

use regex::Regex;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::address_au;
use crate::util::curl;
use crate::util::domains::{is_freemail, is_social_platform};
use crate::util::html::strip_html;

const SRC: &str = "employer_pivot";

pub struct EmployerPivot;

#[async_trait]
impl Module for EmployerPivot {
    fn name(&self) -> &'static str {
        SRC
    }

    fn description(&self) -> &'static str {
        "Pivot from employer-domain email or domain to business address via contact pages"
    }

    fn priority(&self) -> u8 {
        92
    }

    fn is_passive(&self) -> bool {
        false
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Email | TargetKind::Domain)
    }

    fn max_timeout_ms(&self) -> u64 {
        12_000
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::People
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[
            EntityKind::Address,
            EntityKind::Phone,
            EntityKind::Email,
            EntityKind::Url,
        ];
        KINDS
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let mut result = ModuleResult::new();
        let Some(domain) = domain_for_target(target) else {
            return Ok(result);
        };
        if is_freemail(&domain) || is_social_platform(&domain) {
            return Ok(result);
        }

        let paths = [
            "/",
            "/contact",
            "/contact-us",
            "/contact_us",
            "/about",
            "/about-us",
            "/our-team",
            "/team",
        ];

        let mut all_text = String::new();
        let mut visited: Vec<String> = Vec::new();
        for path in paths {
            let url = format!("https://{}{}", domain, path);
            // The host is an attacker-influenceable discovered domain, so fetch
            // through the SSRF-guarded reqwest client (private-IP-filtering DNS
            // resolver + redirect policy cover the initial request AND every
            // redirect hop) rather than the curl fallback. Keep the desktop UA.
            let fetched = match ctx
                .http
                .get(&url)
                .header(reqwest::header::USER_AGENT, curl::UA_DESKTOP)
                .timeout(std::time::Duration::from_millis(6_000))
                .send()
                .await
            {
                Ok(resp) if resp.status().is_success() => {
                    crate::util::http::read_body_capped(resp, 512 * 1024).await
                }
                _ => None,
            };
            if let Some(html) = fetched {
                if html.len() < 200 {
                    continue;
                }
                visited.push(url.clone());
                all_text.push_str(&strip_html(&html));
                all_text.push('\n');
                if visited.len() >= 4 {
                    break;
                }
            }
        }
        if all_text.is_empty() {
            return Ok(result);
        }

        // ── Addresses ────────────────────────────────────────────────
        let mut seen_addr: HashSet<String> = HashSet::new();
        for addr in address_au::extract_all(&all_text) {
            let canon = canonical_address(&addr);
            if !seen_addr.insert(canon.clone()) {
                continue;
            }
            let mut e = Entity::new(EntityKind::Address, &canon, addr.confidence(), &ctx.scan_id);
            e.tag("business");
            e.tag("employer-pivot");
            e.tag("country:AU");
            e.tag(format!("state:{}", addr.state));
            e.tag(format!("postcode:{}", addr.postcode));
            let mut ev = Evidence::new(
                SRC,
                format!("Business address extracted from {} contact pages", domain),
            )
            .with_attr("addr_country", "Australia")
            .with_attr("addr_iso", "AU")
            .with_attr("addr_state", &addr.state)
            .with_attr("addr_city", &addr.suburb)
            .with_attr("addr_postal", &addr.postcode)
            .with_attr("street_number", &addr.street_number)
            .with_attr("street", &addr.street);
            if let Some(lvl) = addr.level.as_deref() {
                ev = ev.with_attr("level", lvl);
            }
            if let Some(unit) = addr.unit.as_deref() {
                ev = ev.with_attr("unit", unit);
            }
            ev = ev.with_attr("employer_domain", &domain);
            ev = ev.with_attr("source_urls", visited.join(" | "));
            e.add_evidence(ev);
            result.push(e);
        }

        // ── Phones ──────────────────────────────────────────────────
        let mut seen_phone: HashSet<String> = HashSet::new();
        for ph in address_au::extract_phones(&all_text) {
            if !seen_phone.insert(ph.clone()) {
                continue;
            }
            let mut e = Entity::new(EntityKind::Phone, &ph, 0.65, &ctx.scan_id);
            e.tag("business");
            e.tag("employer-pivot");
            e.tag("country:AU");
            e.add_evidence(
                Evidence::new(SRC, format!("Business phone from {}", domain))
                    .with_attr("employer_domain", &domain)
                    .with_attr("e164", &ph),
            );
            result.push(e);
        }

        // ── Same-domain emails ──────────────────────────────────────
        let mut seen_email: HashSet<String> = HashSet::new();
        for em in extract_emails(&all_text, &domain) {
            if !seen_email.insert(em.clone()) {
                continue;
            }
            let mut e = Entity::new(EntityKind::Email, &em, 0.70, &ctx.scan_id);
            e.tag("business");
            e.tag("employer-pivot");
            e.add_evidence(
                Evidence::new(SRC, format!("Employer email from {} site", domain))
                    .with_attr("employer_domain", &domain),
            );
            result.push(e);
        }

        // ── Linked profile URLs ─────────────────────────────────────
        let mut seen_url: HashSet<String> = HashSet::new();
        for url in extract_profile_urls(&all_text) {
            if !seen_url.insert(url.clone()) {
                continue;
            }
            let mut e = Entity::new(EntityKind::Url, &url, 0.55, &ctx.scan_id);
            e.tag("employer-pivot");
            e.tag("social-profile");
            e.add_evidence(
                Evidence::new(SRC, format!("Linked profile from {} site", domain))
                    .with_attr("employer_domain", &domain)
                    .with_attr("profile_url", &url),
            );
            result.push(e);
        }

        Ok(result)
    }
}

fn domain_for_target(t: &Target) -> Option<String> {
    // Email and Domain are normalised identically — trimmed + lowercased — and a
    // blank result is rejected. The old Email arm skipped the trim and could
    // return an empty string for a value like `user@`, which then built
    // malformed fetch URLs (`https://example.com /contact`, `https:///contact`).
    let raw = match t.kind {
        TargetKind::Email => t.value.rsplit_once('@').map(|(_, d)| d),
        TargetKind::Domain => Some(t.value.as_str()),
        _ => None,
    }?;
    let domain = raw.trim().to_lowercase();
    (!domain.is_empty()).then_some(domain)
}

fn extract_emails(text: &str, employer_domain: &str) -> Vec<String> {
    static R: OnceLock<Regex> = OnceLock::new();
    let re =
        R.get_or_init(|| Regex::new(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}").unwrap());
    let mut out = Vec::new();
    for m in re.find_iter(text) {
        let s = m.as_str().to_lowercase();
        if let Some((_, d)) = s.rsplit_once('@')
            && d == employer_domain
        {
            out.push(s);
        }
    }
    out
}

fn extract_profile_urls(text: &str) -> Vec<String> {
    static R: OnceLock<Regex> = OnceLock::new();
    let re = R.get_or_init(|| {
        Regex::new(
            r"https?://(?:www\.)?(?:linkedin\.com|facebook\.com|instagram\.com|twitter\.com|x\.com|youtube\.com)/[A-Za-z0-9_./@\-]+"
        ).unwrap()
    });
    re.find_iter(text)
        .map(|m| m.as_str().trim_end_matches(['/', '.', ',']).to_string())
        .collect()
}

fn canonical_address(a: &address_au::AuAddress) -> String {
    let mut s = String::new();
    if let Some(lvl) = a.level.as_deref() {
        s.push_str(lvl);
        s.push_str(", ");
    }
    if let Some(u) = a.unit.as_deref() {
        s.push_str(u);
        s.push('/');
    }
    s.push_str(&a.street_number);
    s.push(' ');
    s.push_str(&a.street);
    s.push_str(", ");
    s.push_str(&a.suburb);
    s.push(' ');
    s.push_str(&a.state);
    s.push(' ');
    s.push_str(&a.postcode);
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_same_domain_emails_only() {
        let text = "Contact info@acme.com or sales@acme.com but ignore noise@example.com";
        let v = extract_emails(text, "acme.com");
        assert!(v.contains(&"info@acme.com".to_string()));
        assert!(v.contains(&"sales@acme.com".to_string()));
        assert!(!v.iter().any(|e| e.ends_with("@example.com")));
    }

    #[test]
    fn domain_for_email_is_trimmed_and_lowercased() {
        let t = Target::new(TargetKind::Email, "Person@Example.COM");
        assert_eq!(domain_for_target(&t).as_deref(), Some("example.com"));
        // Leading/trailing whitespace around the domain part is stripped — the
        // bug the old Email arm left in (it lacked the Domain arm's trim()).
        let spaced = Target::new(TargetKind::Email, "p@ Example.com ");
        assert_eq!(domain_for_target(&spaced).as_deref(), Some("example.com"));
    }

    #[test]
    fn domain_for_email_rejects_empty_or_missing_domain() {
        // `user@` has no domain part → None (previously Some("") → malformed URLs).
        assert_eq!(
            domain_for_target(&Target::new(TargetKind::Email, "user@")),
            None
        );
        // No `@` at all → None.
        assert_eq!(
            domain_for_target(&Target::new(TargetKind::Email, "notanemail")),
            None
        );
    }

    #[test]
    fn domain_for_domain_target_trims_and_lowercases() {
        let t = Target::new(TargetKind::Domain, "  ACME.com  ");
        assert_eq!(domain_for_target(&t).as_deref(), Some("acme.com"));
    }

    #[test]
    fn domain_for_unsupported_kind_is_none() {
        assert_eq!(
            domain_for_target(&Target::new(TargetKind::IpAddress, "1.2.3.4")),
            None
        );
    }

    #[test]
    fn profile_urls_match_known_platforms_and_trim_trailing_punctuation() {
        let text = "see https://www.linkedin.com/in/jane-doe/ and \
                    https://twitter.com/acme, plus https://example.com/x ignored";
        let urls = extract_profile_urls(text);
        // Trailing '/' is trimmed; the comma is never part of the path class.
        assert!(urls.contains(&"https://www.linkedin.com/in/jane-doe".to_string()));
        assert!(urls.contains(&"https://twitter.com/acme".to_string()));
        // A non-listed domain is not a profile link.
        assert!(!urls.iter().any(|u| u.contains("example.com")));
    }

    #[test]
    fn canonical_address_includes_level_and_unit_when_present() {
        let a = address_au::AuAddress {
            full: "ignored".into(),
            level: Some("Level 5".into()),
            unit: Some("12".into()),
            street_number: "100".into(),
            street: "King St".into(),
            suburb: "Sydney".into(),
            state: "NSW".into(),
            postcode: "2000".into(),
        };
        assert_eq!(
            canonical_address(&a),
            "Level 5, 12/100 King St, Sydney NSW 2000"
        );
    }

    #[test]
    fn canonical_address_omits_absent_optional_parts() {
        let a = address_au::AuAddress {
            full: "ignored".into(),
            level: None,
            unit: None,
            street_number: "1".into(),
            street: "Main Rd".into(),
            suburb: "Perth".into(),
            state: "WA".into(),
            postcode: "6000".into(),
        };
        assert_eq!(canonical_address(&a), "1 Main Rd, Perth WA 6000");
    }
}
