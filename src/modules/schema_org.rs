//! Schema.org / JSON-LD structured-data module.
//!
//! Fetches a target domain's homepage and up to three canonical content pages
//! (`/`, `/about`, `/contact`, `/our-team`, `/team`) and lifts all JSON-LD
//! structured-data blocks. Rather than regex-scraping rendered plain text, this
//! module extracts deliberately-published Schema.org markup:
//!
//!  - `Person` / `RealEstateAgent` / `Agent` → Person + Phone + Email entities
//!  - `Organization` / `LocalBusiness`       → Organisation + Phone + Address
//!  - `ContactPoint`                         → Phone + Email
//!  - `PostalAddress`                        → Address (AU-formatted)
//!
//! Structured data carries higher confidence than regex-based fallback because
//! it represents deliberately published machine-readable markup.
//!
//! Techniques: T1591.001 (Gather Victim Org Info: Determine Physical Locations),
//!             T1589.003 (Gather Victim Identity Information: Employee Names).
//!
//! Free, no API key required. Uses the SSRF-guarded reqwest client.

use async_trait::async_trait;
use std::collections::HashSet;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::address_au;
use crate::util::curl;
use crate::util::domains::{is_freemail, is_social_platform};
use crate::util::jsonld;

const SRC: &str = "schema_org";

pub struct SchemaOrg;

#[async_trait]
impl Module for SchemaOrg {
    fn name(&self) -> &'static str {
        SRC
    }

    fn description(&self) -> &'static str {
        "Extract Schema.org / JSON-LD structured entities from employer and profile pages"
    }

    fn priority(&self) -> u8 {
        88
    }

    fn is_passive(&self) -> bool {
        false
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(
            t.kind,
            TargetKind::Domain | TargetKind::Email | TargetKind::Url
        )
    }

    fn max_timeout_ms(&self) -> u64 {
        22_000
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::People
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        &["T1591.001", "T1589.003"]
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[
            EntityKind::Person,
            EntityKind::Phone,
            EntityKind::Email,
            EntityKind::Address,
            EntityKind::Organisation,
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
            "/about",
            "/about-us",
            "/contact",
            "/contact-us",
            "/our-team",
            "/team",
        ];

        let mut all_blocks: Vec<serde_json::Value> = Vec::new();
        let mut source_urls: Vec<String> = Vec::new();

        for path in paths {
            let url = format!("https://{}{}", domain, path);
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
                let blocks = jsonld::extract_jsonld_blocks(&html);
                if !blocks.is_empty() {
                    source_urls.push(url.clone());
                    all_blocks.extend(blocks);
                }
                if source_urls.len() >= 4 {
                    break;
                }
            }
        }

        if all_blocks.is_empty() {
            return Ok(result);
        }

        let src_attr = source_urls.join(" | ");

        // ── Phones ────────────────────────────────────────────────────
        let phone_types = [
            "person",
            "realestateagent",
            "agent",
            "contactpoint",
            "localbusiness",
            "organization",
        ];
        let mut seen_phone: HashSet<String> = HashSet::new();
        for type_name in &phone_types {
            for block in jsonld::blocks_of_type(&all_blocks, type_name) {
                for raw in jsonld::field_strings(block, "telephone") {
                    let Some(ph) = normalise_phone_au(&raw) else {
                        continue;
                    };
                    if !seen_phone.insert(ph.clone()) {
                        continue;
                    }
                    let mut e = Entity::new(EntityKind::Phone, &ph, 0.80, &ctx.scan_id);
                    e.tag("schema-org");
                    e.tag("structured-data");
                    if let Some(name) = jsonld::field_str(block, "name") {
                        e.tag(format!("contact:{}", name.to_lowercase().replace(' ', "-")));
                    }
                    e.add_evidence(
                        Evidence::new(
                            SRC,
                            format!("Phone from Schema.org {} on {}", type_name, domain),
                        )
                        .with_attr("schema_type", *type_name)
                        .with_attr("employer_domain", &domain)
                        .with_attr("source_urls", &src_attr)
                        .with_attr("e164", &ph),
                    );
                    result.push(e);
                }
            }
        }

        // ── Emails ────────────────────────────────────────────────────
        let email_types = ["person", "realestateagent", "agent", "contactpoint"];
        let mut seen_email: HashSet<String> = HashSet::new();
        for type_name in &email_types {
            for block in jsonld::blocks_of_type(&all_blocks, type_name) {
                for raw in jsonld::field_strings(block, "email") {
                    let em = raw.to_lowercase();
                    if em.is_empty() || !seen_email.insert(em.clone()) {
                        continue;
                    }
                    let mut e = Entity::new(EntityKind::Email, &em, 0.75, &ctx.scan_id);
                    e.tag("schema-org");
                    e.tag("structured-data");
                    let mut ev = Evidence::new(
                        SRC,
                        format!("Email from Schema.org {} on {}", type_name, domain),
                    )
                    .with_attr("schema_type", *type_name)
                    .with_attr("employer_domain", &domain);
                    if let Some(name) = jsonld::field_str(block, "name") {
                        ev = ev.with_attr("contact_name", &name);
                    }
                    e.add_evidence(ev);
                    result.push(e);
                }
            }
        }

        // ── Person / Agent entities ────────────────────────────────────
        let person_types = ["person", "realestateagent", "agent"];
        let mut seen_person: HashSet<String> = HashSet::new();
        for type_name in &person_types {
            for block in jsonld::blocks_of_type(&all_blocks, type_name) {
                let Some(name) = jsonld::field_str(block, "name") else {
                    continue;
                };
                if !seen_person.insert(name.to_lowercase()) {
                    continue;
                }
                let mut e = Entity::new(EntityKind::Person, &name, 0.75, &ctx.scan_id);
                e.tag("schema-org");
                e.tag("structured-data");
                let mut ev = Evidence::new(
                    SRC,
                    format!("Person from Schema.org {} on {}", type_name, domain),
                )
                .with_attr("schema_type", *type_name)
                .with_attr("employer_domain", &domain)
                .with_attr("source_urls", &src_attr);
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

        // ── Addresses (PostalAddress + embedded in LocalBusiness) ──────
        let addr_parent_types = [
            "postaladdress",
            "localbusiness",
            "organization",
            "realestateagent",
        ];
        let mut seen_addr: HashSet<String> = HashSet::new();
        for type_name in &addr_parent_types {
            for block in jsonld::blocks_of_type(&all_blocks, type_name) {
                // PostalAddress may be the block itself or nested under "address".
                let addr_node: &serde_json::Value = if *type_name == "postaladdress" {
                    block
                } else if let Some(a) = block.get("address") {
                    a
                } else {
                    continue;
                };
                let street = jsonld::field_str(addr_node, "streetAddress");
                let suburb = jsonld::field_str(addr_node, "addressLocality");
                let region = jsonld::field_str(addr_node, "addressRegion");
                let postcode = jsonld::field_str(addr_node, "postalCode");
                let country = jsonld::field_str(addr_node, "addressCountry");
                let (Some(st), Some(su), Some(re), Some(pc)) = (street, suburb, region, postcode)
                else {
                    continue;
                };
                let is_au = country.as_deref().is_none_or(|c| {
                    let u = c.to_uppercase();
                    u == "AU" || u == "AUSTRALIA"
                });
                if !is_au {
                    continue;
                }
                let state = re.to_uppercase();
                let canonical = format!("{st}, {su} {state} {pc}");
                if !seen_addr.insert(canonical.clone()) {
                    continue;
                }
                // Feed through the AU address parser for confidence + tag enrichment.
                let conf = if address_au::extract_all(&canonical).is_empty() {
                    0.75_f64
                } else {
                    0.85_f64
                };
                let mut e = Entity::new(EntityKind::Address, &canonical, conf, &ctx.scan_id);
                e.tag("schema-org");
                e.tag("structured-data");
                e.tag("country:AU");
                e.tag(format!("state:{state}"));
                e.tag(format!("postcode:{pc}"));
                e.add_evidence(
                    Evidence::new(
                        SRC,
                        format!("Address from Schema.org {} on {}", type_name, domain),
                    )
                    .with_attr("schema_type", *type_name)
                    .with_attr("addr_country", "Australia")
                    .with_attr("addr_iso", "AU")
                    .with_attr("addr_state", &state)
                    .with_attr("addr_city", &su)
                    .with_attr("addr_postal", &pc)
                    .with_attr("street", &st)
                    .with_attr("employer_domain", &domain)
                    .with_attr("source_urls", &src_attr),
                );
                result.push(e);
            }
        }

        // ── Organisation ──────────────────────────────────────────────
        let org_types = ["organization", "localbusiness", "realestateagency"];
        let mut seen_org: HashSet<String> = HashSet::new();
        for type_name in &org_types {
            for block in jsonld::blocks_of_type(&all_blocks, type_name) {
                let Some(name) = jsonld::field_str(block, "name") else {
                    continue;
                };
                if !seen_org.insert(name.to_lowercase()) {
                    continue;
                }
                let mut e = Entity::new(EntityKind::Organisation, &name, 0.70, &ctx.scan_id);
                e.tag("schema-org");
                e.tag("structured-data");
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

        // ── Linked URLs (sameAs, url fields on any block) ─────────────
        let mut seen_url: HashSet<String> = HashSet::new();
        for block in &all_blocks {
            for field in &["sameAs", "url"] {
                for u in jsonld::field_strings(block, field) {
                    if !u.starts_with("http") || !seen_url.insert(u.clone()) {
                        continue;
                    }
                    let mut e = Entity::new(EntityKind::Url, &u, 0.60, &ctx.scan_id);
                    e.tag("schema-org");
                    e.tag("structured-data");
                    e.add_evidence(
                        Evidence::new(SRC, format!("URL from Schema.org sameAs/url on {}", domain))
                            .with_attr("employer_domain", &domain),
                    );
                    result.push(e);
                }
            }
        }

        Ok(result)
    }
}

fn domain_for_target(t: &Target) -> Option<String> {
    match t.kind {
        TargetKind::Email => t.value.rsplit_once('@').map(|(_, d)| d.to_lowercase()),
        TargetKind::Domain => Some(t.value.trim().to_lowercase()),
        TargetKind::Url => t
            .value
            .trim_start_matches("https://")
            .trim_start_matches("http://")
            .split('/')
            .next()
            .map(|h| h.split(':').next().unwrap_or(h).to_lowercase()),
        _ => None,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalises_au_mobile() {
        assert_eq!(
            normalise_phone_au("0400 681 011"),
            Some("+61400681011".to_string())
        );
        assert_eq!(
            normalise_phone_au("+61 400 681 011"),
            Some("+61400681011".to_string())
        );
    }

    #[test]
    fn rejects_non_au_phone() {
        assert_eq!(normalise_phone_au("1234"), None);
        assert_eq!(normalise_phone_au("+1 800 555 1234"), None);
    }
}
