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
//!  - Microsoft 365 tenant ID (via OpenID Connect discovery endpoint) →
//!    Domain entity tagged `m365` with `m365_tenant_id` evidence attribute.
//!    Fires when the domain has an active Azure AD / Entra ID tenant.
//!    Technique: T1590.001 (Gather Victim Network Information: IP Addresses) —
//!    tenant IDs expose cloud-infrastructure provider relationships.
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
use crate::util::jsonld;

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
        18_000
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::People
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        // Contact-page scraping → T1591.001 (Gather Victim Org Info: Determine
        // Physical Locations). M365 tenant discovery → T1590.001 (Gather Victim
        // Network Information: IP Addresses / cloud infrastructure).
        &["T1591.001", "T1590.001"]
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[
            EntityKind::Address,
            EntityKind::Phone,
            EntityKind::Email,
            EntityKind::Person,
            EntityKind::Organisation,
            EntityKind::Url,
            EntityKind::Domain,
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
        // JSON-LD blocks extracted from raw HTML before tag-stripping discards
        // <script> elements. Schema.org structured data (RealEstateAgent, Person,
        // Organization, ContactPoint) carries higher confidence than regex fallback.
        let mut all_jsonld: Vec<serde_json::Value> = Vec::new();
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
                // Extract JSON-LD before strip_html removes <script> blocks.
                all_jsonld.extend(jsonld::extract_jsonld_blocks(&html));
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
            e.tag(crate::core::tags::AU_RELEVANT);
            // Canonical au-state tag for correlator compatibility (AU-056).
            if let Some(st) = crate::core::tags::au_state_tag(&addr.state) {
                e.tag(st);
            }
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

        // ── Phones (Schema.org JSON-LD first, regex fallback) ───────
        // Structured-data phones (conf 0.80) are inserted before the regex
        // pass so the seen_phone gate prevents the same number being re-added
        // at lower confidence by the plain-text extractor.
        let mut seen_phone: HashSet<String> = HashSet::new();
        let schema_phone_types = [
            "person",
            "realestateagent",
            "agent",
            "contactpoint",
            "localbusiness",
            "organization",
        ];
        for type_name in &schema_phone_types {
            for block in jsonld::blocks_of_type(&all_jsonld, type_name) {
                for raw in jsonld::field_strings(block, "telephone") {
                    let Some(ph) = normalise_phone_au(&raw) else {
                        continue;
                    };
                    if !seen_phone.insert(ph.clone()) {
                        continue;
                    }
                    let mut e = Entity::new(EntityKind::Phone, &ph, 0.80, &ctx.scan_id);
                    e.tag("business");
                    e.tag("employer-pivot");
                    e.tag("schema-org");
                    e.tag("country:AU");
                    let mut ev = Evidence::new(
                        SRC,
                        format!("Phone from Schema.org {} on {}", type_name, domain),
                    )
                    .with_attr("schema_type", *type_name)
                    .with_attr("employer_domain", &domain)
                    .with_attr("source_urls", visited.join(" | "))
                    .with_attr("e164", &ph);
                    if let Some(contact_name) = jsonld::field_str(block, "name") {
                        ev = ev.with_attr("contact_name", &contact_name);
                    }
                    e.add_evidence(ev);
                    result.push(e);
                }
            }
        }
        // Regex fallback: adds any phones present in plain text but absent from JSON-LD.
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

        // ── Same-domain emails (Schema.org JSON-LD first, regex fallback) ──
        let mut seen_email: HashSet<String> = HashSet::new();
        let schema_email_types = [
            "person",
            "realestateagent",
            "agent",
            "contactpoint",
            "localbusiness",
        ];
        for type_name in &schema_email_types {
            for block in jsonld::blocks_of_type(&all_jsonld, type_name) {
                for raw in jsonld::field_strings(block, "email") {
                    let em = raw.to_lowercase();
                    if em.is_empty() || !seen_email.insert(em.clone()) {
                        continue;
                    }
                    let mut e = Entity::new(EntityKind::Email, &em, 0.80, &ctx.scan_id);
                    e.tag("business");
                    e.tag("employer-pivot");
                    e.tag("schema-org");
                    let mut ev = Evidence::new(
                        SRC,
                        format!("Email from Schema.org {} on {}", type_name, domain),
                    )
                    .with_attr("schema_type", *type_name)
                    .with_attr("employer_domain", &domain);
                    if let Some(contact_name) = jsonld::field_str(block, "name") {
                        ev = ev.with_attr("contact_name", &contact_name);
                    }
                    e.add_evidence(ev);
                    result.push(e);
                }
            }
        }
        // Regex fallback: same-domain emails in plain text not already found via JSON-LD.
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

        // ── Person entities from Schema.org ─────────────────────────
        // RealEstateAgent / Person / Agent blocks expose name + jobTitle +
        // worksFor — the highest-confidence identity signal from a corporate site.
        let mut seen_person: HashSet<String> = HashSet::new();
        let schema_person_types = ["person", "realestateagent", "agent"];
        for type_name in &schema_person_types {
            for block in jsonld::blocks_of_type(&all_jsonld, type_name) {
                let Some(name) = jsonld::field_str(block, "name") else {
                    continue;
                };
                let name_key = name.to_lowercase();
                if !seen_person.insert(name_key) {
                    continue;
                }
                let mut e = Entity::new(EntityKind::Person, &name, 0.75, &ctx.scan_id);
                e.tag("employer-pivot");
                e.tag("schema-org");
                let mut ev = Evidence::new(
                    SRC,
                    format!("Person from Schema.org {} on {}", type_name, domain),
                )
                .with_attr("schema_type", *type_name)
                .with_attr("employer_domain", &domain)
                .with_attr("source_urls", visited.join(" | "));
                if let Some(title) = jsonld::field_str(block, "jobTitle") {
                    e.tag(format!(
                        "jobtitle:{}",
                        title.to_lowercase().replace(' ', "-")
                    ));
                    ev = ev.with_attr("job_title", &title);
                }
                if let Some(works_for) = jsonld::field_str_nested(block, "worksFor", "name")
                    .or_else(|| jsonld::field_str(block, "worksFor"))
                {
                    ev = ev.with_attr("works_for", &works_for);
                }
                e.add_evidence(ev);
                result.push(e);
            }
        }

        // ── Organisation from Schema.org ─────────────────────────────
        let mut seen_org: HashSet<String> = HashSet::new();
        for type_name in &["organization", "localbusiness", "realestateagency"] {
            for block in jsonld::blocks_of_type(&all_jsonld, type_name) {
                let Some(name) = jsonld::field_str(block, "name") else {
                    continue;
                };
                if !seen_org.insert(name.to_lowercase()) {
                    continue;
                }
                let mut e = Entity::new(EntityKind::Organisation, &name, 0.70, &ctx.scan_id);
                e.tag("employer-pivot");
                e.tag("schema-org");
                let mut ev = Evidence::new(
                    SRC,
                    format!("Organisation from Schema.org {} on {}", type_name, domain),
                )
                .with_attr("schema_type", *type_name)
                .with_attr("employer_domain", &domain);
                if let Some(org_url) = jsonld::field_str(block, "url") {
                    ev = ev.with_attr("org_url", &org_url);
                }
                e.add_evidence(ev);
                result.push(e);
            }
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

        // ── Microsoft 365 tenant discovery ──────────────────────────
        // Queries the Azure AD OpenID Connect discovery endpoint. A successful
        // response confirms the domain has an active Entra ID / M365 tenant and
        // discloses the tenant UUID — useful for cloud-infrastructure attribution
        // (T1590.001). No auth required; the endpoint is public.
        if let Some(tenant_id) = fetch_m365_tenant_id(&domain, ctx).await {
            let mut e = Entity::new(EntityKind::Domain, &domain, 0.75, &ctx.scan_id);
            e.tag("m365");
            e.tag("employer-pivot");
            e.add_evidence(
                Evidence::new(SRC, format!("Microsoft 365 tenant for {domain}"))
                    .with_attr("m365_tenant_id", &tenant_id)
                    .with_attr("employer_domain", &domain)
                    .with_attr("method", "oidc-discovery"),
            );
            result.push(e);
        }

        Ok(result)
    }
}

fn domain_for_target(t: &Target) -> Option<String> {
    match t.kind {
        TargetKind::Email => t.value.rsplit_once('@').map(|(_, d)| d.to_lowercase()),
        TargetKind::Domain => Some(t.value.trim().to_lowercase()),
        _ => None,
    }
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

/// Fetches the Microsoft 365 / Azure AD tenant UUID for a domain by probing
/// the OpenID Connect discovery endpoint. Returns `Some(tenant_id)` when the
/// domain has an active Entra ID tenant; `None` for non-M365 domains or on
/// any network / parse error. The UUID is extracted from the `issuer` field:
/// `https://sts.windows.net/{tenant_id}/`.
async fn fetch_m365_tenant_id(domain: &str, ctx: &ModuleContext) -> Option<String> {
    let url = format!(
        "https://login.microsoftonline.com/{}/.well-known/openid-configuration",
        domain
    );
    let body = ctx
        .http
        .get(&url)
        .timeout(std::time::Duration::from_millis(5_000))
        .send()
        .await
        .ok()?
        .text()
        .await
        .ok()?;
    // Issuer format: "https://sts.windows.net/{uuid}/"
    let issuer = body.split('"').skip_while(|&s| s != "issuer").nth(2)?; // key → ":" → value
    let tenant_id = issuer
        .trim_start_matches("https://sts.windows.net/")
        .trim_end_matches('/');
    // Validate: must be a 36-char UUID (8-4-4-4-12 hex with hyphens)
    if tenant_id.len() == 36 && tenant_id.chars().all(|c| c.is_ascii_hexdigit() || c == '-') {
        Some(tenant_id.to_string())
    } else {
        None
    }
}

/// Normalise a raw phone string to E.164 AU format (`+61xxxxxxxxx`).
/// Returns `None` for strings that do not look like a valid AU number.
fn normalise_phone_au(raw: &str) -> Option<String> {
    let digits: String = raw.chars().filter(|c| c.is_ascii_digit()).collect();
    match digits.len() {
        10 if digits.starts_with('0') => Some(format!("+61{}", &digits[1..])),
        11 if digits.starts_with("61") => Some(format!("+{digits}")),
        12 if digits.starts_with("061") => Some(format!("+{}", &digits[1..])),
        _ => None,
    }
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
}
