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
//!
//! [`should_skip_pivot`] bails out before any fetch on a domain that is
//! consumer freemail, a social platform, or CDN/registrar/cloud/ESP
//! infrastructure (a nameserver — `rdap_domain`/`whois` both surface a
//! domain's own nameservers as first-class `Domain` entities — or a WHOIS
//! abuse desk), or on an `Email` target with a role/automation local-part —
//! none of these is the subject's own employer.

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
use crate::util::domains::{
    is_freemail, is_infra_provider_domain, is_infrastructure_email, is_social_platform,
};
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

    fn attack_techniques(&self) -> &'static [&'static str] {
        // Mining an employer site yields the org's physical address, phone and
        // linked corporate profiles — ATT&CK Gather Victim Org Information:
        // Determine Physical Locations (T1591.001) + Business Relationships
        // (T1591.002), more precise than the People-category default.
        &["T1591.001", "T1591.002"]
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[
            EntityKind::Address,
            EntityKind::Coordinates,
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
        if should_skip_pivot(target, &domain) {
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
        // Track whether the base homepage is reachable — if the root path fails
        // (DC IP blocked, domain dead, etc.) no sub-path will succeed either.
        // Live scan: 136 employer_pivot dispatches at 12 s each = 27 min wasted
        // on unreachable domains; bail after the first failure.
        let mut homepage_ok = false;
        for path in paths {
            // Sub-paths are only useful when the homepage was reachable.
            if path != "/" && !homepage_ok {
                break;
            }
            let url = format!("https://{domain}{path}");
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
                    if path == "/" {
                        homepage_ok = true;
                    }
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
        result.extend(
            address_au::extract_all(&all_text)
                .into_iter()
                .filter_map(|addr| {
                    let canon = canonical_address(&addr);
                    if !seen_addr.insert(canon.clone()) {
                        return None;
                    }
                    let mut e =
                        Entity::new(EntityKind::Address, &canon, addr.confidence(), &ctx.scan_id);
                    e.tag("business");
                    e.tag("employer-pivot");
                    e.tag("country:AU");
                    e.tag(format!("state:{}", addr.state));
                    e.tag(format!("postcode:{}", addr.postcode));
                    let mut ev = Evidence::new(
                        SRC,
                        format!("Business address extracted from {domain} contact pages"),
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
                    let coord = crate::util::city_coords::city_coords(&canon).map(|(lat, lon)| {
                        let coord_val = format!("{lat:.4},{lon:.4}");
                        let mut c = Entity::new(
                            EntityKind::Coordinates,
                            &coord_val,
                            addr.confidence() - 0.10,
                            &ctx.scan_id,
                        );
                        c.tag("addr-derived");
                        c.tag("geoint");
                        c.tag("country:AU");
                        c.tag("employer-pivot");
                        c.add_evidence(Evidence::new(
                            SRC,
                            format!("Geocode of business address from {domain}"),
                        ));
                        c
                    });
                    Some((e, coord))
                })
                .flat_map(|(e, coord)| {
                    let mut v = vec![e];
                    v.extend(coord);
                    v
                }),
        );

        // ── Phones ──────────────────────────────────────────────────
        let mut seen_phone: HashSet<String> = HashSet::new();
        result.extend(
            address_au::extract_phones(&all_text)
                .into_iter()
                .filter_map(|ph| {
                    if !seen_phone.insert(ph.clone()) {
                        return None;
                    }
                    let mut e = Entity::new(EntityKind::Phone, &ph, 0.65, &ctx.scan_id);
                    e.tag("business");
                    e.tag("employer-pivot");
                    e.tag("country:AU");
                    e.add_evidence(
                        Evidence::new(SRC, format!("Business phone from {domain}"))
                            .with_attr("employer_domain", &domain)
                            .with_attr("e164", &ph),
                    );
                    Some(e)
                }),
        );

        // ── Same-domain emails ──────────────────────────────────────
        let mut seen_email: HashSet<String> = HashSet::new();
        result.extend(
            extract_emails(&all_text, &domain)
                .into_iter()
                .filter_map(|em| {
                    if !seen_email.insert(em.clone()) {
                        return None;
                    }
                    let mut e = Entity::new(EntityKind::Email, &em, 0.70, &ctx.scan_id);
                    e.tag("business");
                    e.tag("employer-pivot");
                    e.add_evidence(
                        Evidence::new(SRC, format!("Employer email from {domain} site"))
                            .with_attr("employer_domain", &domain),
                    );
                    Some(e)
                }),
        );

        // ── Linked profile URLs ─────────────────────────────────────
        let mut seen_url: HashSet<String> = HashSet::new();
        result.extend(
            extract_profile_urls(&all_text)
                .into_iter()
                .filter_map(|url| {
                    if !seen_url.insert(url.clone()) {
                        return None;
                    }
                    let mut e = Entity::new(EntityKind::Url, &url, 0.55, &ctx.scan_id);
                    e.tag("employer-pivot");
                    e.tag("social-profile");
                    e.add_evidence(
                        Evidence::new(SRC, format!("Linked profile from {domain} site"))
                            .with_attr("employer_domain", &domain)
                            .with_attr("profile_url", &url),
                    );
                    Some(e)
                }),
        );

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
    // Canonical email matcher (util::extract::EMAIL_RE) — same pattern this
    // module open-coded; keep the per-call domain filter (no dedup here).
    crate::util::extract::EMAIL_RE
        .find_iter(text)
        .map(|m| m.as_str().to_lowercase())
        .filter(|s| {
            s.rsplit_once('@')
                .is_some_and(|(_, d)| d == employer_domain)
        })
        .collect()
}

fn extract_profile_urls(text: &str) -> Vec<String> {
    static R: OnceLock<Regex> = OnceLock::new();
    let re = R.get_or_init(|| {
        Regex::new(
            r"https?://(?:www\.)?(?:linkedin\.com|facebook\.com|instagram\.com|twitter\.com|x\.com|youtube\.com)/[A-Za-z0-9_./@\-]+"
        ).expect("constant social profile-url regex")
    });
    re.find_iter(text)
        .map(|m| m.as_str().trim_end_matches(['/', '.', ',']).to_string())
        .collect()
}

/// Whether `target` (with its already-derived `domain`) must be skipped
/// before any network fetch.
///
/// Two independent guards, both against attributing an infrastructure
/// provider's — not the subject's — contact details:
///
/// 1. The domain itself is a consumer freemail/social-platform host (not a
///    business), or a CDN/registrar/cloud/ESP infrastructure provider
///    ([`is_infra_provider_domain`]). Applies to BOTH target kinds this
///    module accepts: a bare `Domain` target can itself be a nameserver —
///    `rdap_domain`/`whois` both surface a domain's own nameservers as
///    first-class `Domain` entities (`ns1.cloudflare.com`), which without
///    this check would scrape Cloudflare's own contact page and attribute it
///    to the scan subject.
/// 2. For an `Email` target specifically, a role/automation local-part on an
///    otherwise-plausible domain ([`is_infrastructure_email`]: `dns@`,
///    `noc@`, `hostmaster@`, …) — RFC 2142 / conventional zone-abuse
///    contacts, not real employees. Without this, a SOA RNAME address
///    (emitted by `dns_intel`) scrapes the registrar's corporate contact
///    pages (observed: `dns@cloudflare.com` → Cloudflare Sydney HQ).
fn should_skip_pivot(target: &Target, domain: &str) -> bool {
    if is_freemail(domain) || is_social_platform(domain) || is_infra_provider_domain(domain) {
        return true;
    }
    target.kind == TargetKind::Email && is_infrastructure_email(&target.value)
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
    include!("tests.rs");
}
