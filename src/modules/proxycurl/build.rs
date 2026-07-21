//! Pure entity-building logic: maps a parsed [`LinkedInProfile`] to the full
//! set of output entities. No network I/O — all field→entity mapping lives here
//! so it is unit-tested without a live API.

use std::collections::HashSet;

use crate::core::{
    confidence,
    entity::{Entity, EntityKind, Evidence},
    module::ModuleResult,
    scan::Target,
};
use crate::util::domains::is_freemail;

use super::types::{Certification, DateField, Education, LinkedInProfile};
use super::{MAX_EXPERIENCES, MAX_LISTED, SRC};

use crate::util::str_util::nonempty;

/// The registrable-ish domain of an email's local@domain, lowercased.
pub(super) fn email_domain(email: &str) -> Option<String> {
    let domain = email.rsplit_once('@')?.1.trim().to_lowercase();
    (domain.contains('.') && domain.len() >= 4).then_some(domain)
}

/// Build all entities from a parsed profile. **Pure** (no network / IO / clock)
/// so every field→entity mapping and confidence is unit-tested directly.
///
/// Confidences encode source authority: a named LinkedIn profile is strong
/// (confidence::HIGH_PLUSPLUS_PLUS); a personal email is strong (confidence::HIGH_PLUSPLUS); a domain *derived* from that email
/// is weaker (0.68); a self-reported location is soft (confidence::MEDIUM_PLUS).
pub(super) fn build_entities(
    profile: &LinkedInProfile,
    target: &Target,
    scan_id: &str,
) -> ModuleResult {
    let mut result = ModuleResult::new();

    // ── Person (the anchor) ───────────────────────────────────────────────
    if let Some(name) = profile.display_name() {
        let mut pe = Entity::new(
            EntityKind::Person,
            &name,
            confidence::HIGH_PLUSPLUS_PLUS,
            scan_id,
        );
        pe.tag("proxycurl");
        pe.tag("linkedin");
        let mut ev = Evidence::new(SRC, format!("LinkedIn profile: {name}"))
            .with_attr("target", &target.value);
        if let Some(h) = nonempty(&profile.headline) {
            ev = ev.with_attr("headline", h);
        }
        if let Some(occ) = nonempty(&profile.occupation) {
            ev = ev.with_attr("occupation", occ);
        }
        if let Some(pid) = nonempty(&profile.public_identifier) {
            ev = ev.with_attr("linkedin_id", pid);
        }
        if let Some(c) = profile.connections {
            ev = ev.with_attr("connections", c.to_string());
        }
        if let Some(summary) = nonempty(&profile.summary) {
            // Full-fidelity policy: the professional bio is stored verbatim, never
            // capped — the operator sees the authentic discovered text in full.
            ev = ev.with_attr("summary", summary);
        }
        let current: Vec<&str> = profile
            .experiences
            .iter()
            .filter(|e| e.ends_at.is_none())
            .filter_map(|e| nonempty(&e.company))
            .take(MAX_LISTED)
            .collect();
        if !current.is_empty() {
            ev = ev.with_attr("current_companies", current.join(", "));
        }
        if !profile.experiences.is_empty() {
            ev = ev.with_attr("experience_count", profile.experiences.len().to_string());
        }
        let schools: Vec<String> = profile
            .education
            .iter()
            .filter_map(Education::describe)
            .take(MAX_LISTED)
            .collect();
        if !schools.is_empty() {
            ev = ev.with_attr("education", schools.join("; "));
        }
        let certs: Vec<String> = profile
            .certifications
            .iter()
            .filter_map(Certification::describe)
            .take(MAX_LISTED)
            .collect();
        if !certs.is_empty() {
            ev = ev.with_attr("certifications", certs.join("; "));
        }
        pe.add_evidence(ev);
        result.push(pe);
    }

    // ── LinkedIn vanity handle → Username pivot ───────────────────────────
    // The `public_identifier` (the `/in/{slug}` handle) is a stable, cross-
    // platform identity anchor in its own right — not merely a Person attribute
    // — so mint it as a platform-prefixed Username the way the other social
    // modules do, letting BFS pivot on the handle across sites.
    if let Some(pid) = nonempty(&profile.public_identifier) {
        let mut ue = Entity::new(
            EntityKind::Username,
            format!("linkedin:{pid}"),
            0.80,
            scan_id,
        );
        ue.tag("proxycurl");
        ue.tag("linkedin");
        ue.add_evidence(
            Evidence::new(SRC, format!("LinkedIn vanity handle: {pid}"))
                .with_attr("target", &target.value),
        );
        result.push(ue);
    }

    // ── Address (needs ≥2 of city/state/country to be meaningful) ─────────
    let loc_parts: Vec<&str> = [
        nonempty(&profile.city),
        nonempty(&profile.state),
        nonempty(&profile.country_full_name),
    ]
    .into_iter()
    .flatten()
    .collect();
    if loc_parts.len() >= 2 {
        let location = loc_parts.join(", ");
        let mut ae = Entity::new(
            EntityKind::Address,
            &location,
            confidence::MEDIUM_PLUS,
            scan_id,
        );
        ae.tag("proxycurl");
        ae.tag("linkedin");
        ae.tag("geoint");
        if let Some(cc) = nonempty(&profile.country) {
            ae.tag(format!("country:{}", cc.to_uppercase()));
        }
        if let Some(state_str) = nonempty(&profile.state)
            && let Some(sc) = crate::util::address_au::state_code(state_str)
        {
            ae.tag(format!("au-state:{sc}"));
            ae.tag("country:AU");
        }
        ae.add_evidence(Evidence::new(SRC, format!("LinkedIn location: {location}")));
        result.push(ae);

        if let Some((lat, lon)) = crate::util::city_coords::city_coords(&location) {
            let coord_val = format!("{lat:.4},{lon:.4}");
            let mut c = Entity::new(EntityKind::Coordinates, &coord_val, 0.52, scan_id);
            c.tag("proxycurl");
            c.tag("linkedin");
            c.tag("addr-derived");
            c.tag("geoint");
            if let Some(cc) = nonempty(&profile.country) {
                c.tag(format!("country:{}", cc.to_uppercase()));
            }
            if let Some(state_str) = nonempty(&profile.state)
                && let Some(sc) = crate::util::address_au::state_code(state_str)
            {
                c.tag(format!("au-state:{sc}"));
                c.tag("country:AU");
            }
            c.add_evidence(Evidence::new(
                SRC,
                format!("Inline geocode of LinkedIn location '{location}' → {coord_val}"),
            ));
            result.push(c);
        }
    }

    // ── Emails + their (non-freemail) domains — single deduped pass ────────
    let mut seen_emails = HashSet::new();
    let mut seen_domains = HashSet::new();
    for email in profile
        .personal_emails
        .iter()
        .map(|e| e.trim())
        .filter(|e| crate::util::extract::looks_like_email(e))
    {
        // Dedup case-insensitively, then cap the DISTINCT addresses.
        if !seen_emails.insert(email.to_lowercase()) {
            continue;
        }
        let mut ee = Entity::new(EntityKind::Email, email, confidence::HIGH_PLUSPLUS, scan_id);
        ee.tag("proxycurl");
        ee.tag("linkedin");
        ee.add_evidence(Evidence::new(SRC, "Personal email from LinkedIn"));
        result.push(ee);

        if let Some(domain) = email_domain(email)
            && !is_freemail(&domain)
            && seen_domains.insert(domain.clone())
        {
            let mut de = Entity::new(EntityKind::Domain, &domain, 0.68, scan_id);
            de.tag("proxycurl");
            de.tag("linkedin");
            de.tag("derived");
            de.add_evidence(Evidence::new(SRC, "Email domain from LinkedIn profile"));
            result.push(de);
        }
    }

    // ── Phones ────────────────────────────────────────────────────────────
    result.extend(
        profile
            .personal_numbers
            .iter()
            .map(|p| p.trim())
            .filter(|p| p.len() >= 7)
            .map(|phone| {
                let mut phe = Entity::new(EntityKind::Phone, phone, confidence::VERY_HIGH, scan_id);
                phe.tag("proxycurl");
                phe.tag("linkedin");
                phe.add_evidence(Evidence::new(SRC, "Phone from LinkedIn"));
                phe
            }),
    );

    // ── Organisations (employers) — title, dates, and job location ────────
    result.extend(
        profile
            .experiences
            .iter()
            .take(MAX_EXPERIENCES)
            .filter_map(|exp| {
                let company = nonempty(&exp.company).filter(|c| c.chars().count() >= 2)?;
                let mut oe =
                    Entity::new(EntityKind::Organisation, company, confidence::HIGH, scan_id);
                oe.tag("proxycurl");
                oe.tag("linkedin");
                let mut ev = Evidence::new(SRC, format!("Employer: {company}"));
                if let Some(title) = nonempty(&exp.title) {
                    ev = ev.with_attr("title", title);
                }
                if let Some(loc) = nonempty(&exp.location) {
                    ev = ev.with_attr("location", loc);
                }
                if let Some(start) = exp.starts_at.as_ref().map(DateField::to_string_approx)
                    && !start.is_empty()
                {
                    ev = ev.with_attr("start_date", start);
                }
                match exp.ends_at.as_ref().map(DateField::to_string_approx) {
                    Some(end) if !end.is_empty() => ev = ev.with_attr("end_date", end),
                    _ => oe.tag("current-employer"),
                }
                oe.add_evidence(ev);
                Some(oe)
            }),
    );

    // ── Organisations (alma maters) — degree and field of study ───────────
    // Lower confidence than the employer loop above: a school attended in the
    // past is a weaker "current relationship" signal than a listed employer.
    result.extend(profile.education.iter().take(MAX_LISTED).filter_map(|edu| {
        let school = nonempty(&edu.school).filter(|s| s.chars().count() >= 2)?;
        let mut oe = Entity::new(
            EntityKind::Organisation,
            school,
            confidence::MEDIUM_HIGH,
            scan_id,
        );
        oe.tag("proxycurl");
        oe.tag("linkedin");
        oe.tag("education");
        let mut ev = Evidence::new(SRC, format!("Educational institution: {school}"));
        if let Some(degree) = nonempty(&edu.degree_name) {
            ev = ev.with_attr("degree", degree);
        }
        if let Some(field) = nonempty(&edu.field_of_study) {
            ev = ev.with_attr("field_of_study", field);
        }
        oe.add_evidence(ev);
        Some(oe)
    }));

    // ── Personal website URL ──────────────────────────────────────────────
    if let Some(url) = profile
        .website_url
        .as_deref()
        .map(str::trim)
        .filter(|u| u.starts_with("http://") || u.starts_with("https://"))
    {
        let mut ue = Entity::new(EntityKind::Url, url, 0.72, scan_id);
        ue.tag("proxycurl");
        ue.tag("linkedin");
        ue.add_evidence(Evidence::new(SRC, "Website URL from LinkedIn profile"));
        result.push(ue);
        // Also surface the host as a Domain pivot.
        if let Some(host) = crate::util::url_util::host_from_url(url)
            && !host.eq_ignore_ascii_case("linkedin.com")
            && !host.eq_ignore_ascii_case("lnkd.in")
        {
            let mut de = Entity::new(EntityKind::Domain, &host, 0.68, scan_id);
            de.tag("proxycurl");
            de.tag("linkedin");
            de.tag("derived");
            de.add_evidence(Evidence::new(SRC, "Website domain from LinkedIn profile"));
            result.push(de);
        }
    }

    result
}
