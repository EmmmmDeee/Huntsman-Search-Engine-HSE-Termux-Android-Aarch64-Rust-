//! Pure entity-building functions for SEON email and phone enrichment.
//!
//! These functions are free of HTTP transport and are unit-tested directly.

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    scan::Target,
    tags,
};
use crate::util::str_util::nonempty;

use super::{
    HIGH_RISK_SCORE, SRC,
    types::{AccountPresence, Breach, DomainRegistration, SeonEmailData, SeonPhoneData},
};

/// A registrant-PII string that's a redaction/privacy-service placeholder
/// rather than real data — the same class of guard `whois`'s registrant
/// extraction already applies, reused here so a masked WHOIS-privacy domain
/// registration doesn't mint a fake `John Doe`/`Privacy Inc` node.
fn is_redacted(s: &str) -> bool {
    let l = s.to_lowercase();
    l.contains("privacy") || l.contains("redacted") || l.contains("data protected")
}

/// The platforms a presence map reports as `registered: true`, in declared order.
pub(super) fn registered_accounts<'a>(
    pairs: &[(&'static str, &'a Option<AccountPresence>)],
) -> Vec<(&'static str, &'a AccountPresence)> {
    pairs
        .iter()
        .filter_map(|(name, opt)| {
            opt.as_ref()
                .filter(|p| p.registered == Some(true))
                .map(|p| (*name, p))
        })
        .collect()
}

/// A `Url` entity for a social/messaging profile discovered via SEON — the lead
/// the old code dropped on the floor.
pub(super) fn profile_url_entity(platform: &str, url: &str, who: &str, scan_id: &str) -> Entity {
    let mut e = Entity::new(EntityKind::Url, url, 0.70, scan_id);
    e.tag("seon");
    e.tag("social-profile");
    e.tag(format!("platform:{platform}"));
    e.add_evidence(Evidence::new(
        SRC,
        format!("{platform} profile via SEON for {who}"),
    ));
    e
}

/// Build entities from a SEON **email** enrichment: the enriched email itself
/// (fraud score, deliverability, domain quality, platform-registration
/// summary), a `Domain` per breach it appears in (mirroring `hibp`'s
/// breach→Domain pattern, `breach_date`-stamped for AU-019 clustering), and
/// WHOIS-style registrant PII (`Domain`/`Person`/`Organisation`/`Address`/
/// `Phone`) for every domain SEON associates with this email — mirroring
/// `whois`'s registrant extraction, since SEON's `associated_domain_
/// registrations` is the same kind of data. Pure — unit-tested without a
/// live API.
pub(super) fn build_email_entities(
    target: &Target,
    data: &SeonEmailData,
    scan_id: &str,
) -> Vec<Entity> {
    let email = target.value.trim();
    let mut out = Vec::new();
    let mut entity = target.to_entity(0.88, scan_id);
    entity.tag("seon");

    let mut ev = Evidence::new(SRC, format!("SEON email enrichment for {email}"));
    if let Some(score) = data
        .risk_scores
        .as_ref()
        .and_then(|r| r.global_network_score)
    {
        ev = ev.with_attr("fraud_score", format!("{score:.1}"));
        if score >= HIGH_RISK_SCORE {
            entity.tag("high-risk");
        }
    }
    if let Some(ed) = &data.email_details {
        if let Some(d) = ed.deliverable {
            ev = ev.with_attr("deliverable", d.to_string());
        }
        if ed.full_inbox == Some(true) {
            ev = ev.with_attr("full_inbox", "true");
        }
        if ed.valid_format == Some(false) {
            ev = ev.with_attr("valid_format", "false");
        }
        if let Some(months) = ed.minimum_age_months {
            ev = ev.with_attr("minimum_age_months", months.to_string());
        }
        if let Some(d) = nonempty(&ed.earliest_profile_date) {
            ev = ev.with_attr("earliest_profile_date", d);
        }
    }
    if let Some(dd) = &data.email_domain_details {
        if let Some(d) = nonempty(&dd.domain) {
            ev = ev.with_attr("domain", d);
        }
        if dd.registered == Some(true) {
            ev = ev.with_attr("domain_registered", "true");
        }
        if dd.custom == Some(true) {
            ev = ev.with_attr("custom_domain", "true");
            entity.tag("custom-domain");
        }
        if dd.disposable == Some(true) {
            entity.tag("disposable");
            ev = ev.with_attr("disposable", "true");
        }
        if dd.free == Some(true) {
            entity.tag("freemail");
            ev = ev.with_attr("freemail", "true");
        }
        if dd.suspicious_tld == Some(true) {
            entity.tag("suspicious-tld");
            ev = ev.with_attr("suspicious_tld", "true");
        }
        if dd.valid_mx == Some(false) {
            ev = ev.with_attr("valid_mx", "false");
        }
        if dd.website_exists == Some(true)
            && let Some(reg) = nonempty(&dd.registered_to)
        {
            ev = ev.with_attr("domain_registered_to", reg);
        }
        if let Some(r) = nonempty(&dd.registrar_name) {
            ev = ev.with_attr("domain_registrar", r);
        }
        if let Some(c) = nonempty(&dd.created) {
            ev = ev.with_attr("domain_created", c);
        }
    }
    if let Some(fh) = &data.seon_fraud_history
        && fh.hits.unwrap_or(0) > 0
    {
        entity.tag("fraud-history");
        ev = ev.with_attr("fraud_hits", fh.hits.unwrap_or(0).to_string());
        if let Some(ch) = fh.customer_hits {
            ev = ev.with_attr("fraud_customer_hits", ch.to_string());
        }
        if let Some(dh) = fh.fraudulent_decline_hits
            && dh > 0
        {
            entity.tag("fraudulent-decline-history");
            ev = ev.with_attr("fraud_decline_hits", dh.to_string());
        }
        if let Some(d) = fh.first_seen.and_then(crate::util::timefmt::ymd_utc) {
            ev = ev.with_attr("fraud_first_seen", d);
        }
        if let Some(d) = fh.last_seen.and_then(crate::util::timefmt::ymd_utc) {
            ev = ev.with_attr("fraud_last_seen", d);
        }
    }

    // Platform-registration summary — SEON's v3 schema only returns
    // CATEGORY-LEVEL counts (`account_aggregates`), not per-platform names or
    // profile links, so unlike the pre-v3 shape this cannot mint individual
    // `Url`/`Person` leads per platform (that data no longer exists in the
    // API at all — see `types.rs`'s `SeonEmailData` doc comment).
    if let Some(agg) = &data.account_aggregates {
        if let Some(total) = agg.total_registration {
            ev = ev.with_attr("platform_registrations", total.to_string());
        }
        if let Some(b) = agg.business.as_ref().and_then(|g| g.total_registration) {
            ev = ev.with_attr("business_platform_registrations", b.to_string());
        }
        if let Some(p) = agg.personal.as_ref().and_then(|g| g.total_registration) {
            ev = ev.with_attr("personal_platform_registrations", p.to_string());
        }
        // Sorted into ONE list (not business-categories-then-personal-
        // categories) so an operator scanning for a specific category
        // doesn't need to know which group it falls under. The SAME
        // category name can legitimately appear in BOTH `business` and
        // `personal` with DIFFERENT counts (SEON's own example response
        // shows `technology` under both, e.g. business 11/34 vs personal
        // 2/7) — collapsing them into one map keyed on name alone would
        // silently drop one group's count, so the group is folded into the
        // label itself (`technology[business]`/`technology[personal]`)
        // rather than deduped away. Sorting the formatted `(String, u32,
        // u32)` tuples (not a `BTreeMap`, which would need the group in the
        // key anyway) keeps this deterministic without re-deriving a
        // comparator; same-name categories from different groups sort
        // adjacently since they share the label prefix.
        let mut registered_categories: Vec<(String, u32, u32)> =
            [("business", &agg.business), ("personal", &agg.personal)]
                .into_iter()
                .filter_map(|(group, g)| g.as_ref().map(|g| (group, g)))
                .flat_map(|(group, g)| g.categories.iter().map(move |(name, c)| (group, name, c)))
                .filter(|(_, _, c)| c.registered.unwrap_or(0) > 0)
                .map(|(group, name, c)| {
                    (
                        format!("{name}[{group}]"),
                        c.registered.unwrap_or(0),
                        c.checked.unwrap_or(0),
                    )
                })
                .collect();
        registered_categories.sort();
        let registered_categories: Vec<String> = registered_categories
            .into_iter()
            .map(|(label, registered, checked)| format!("{label}:{registered}/{checked}"))
            .collect();
        if !registered_categories.is_empty() {
            ev = ev.with_attr("platform_categories", registered_categories.join(", "));
        }
    }
    if let Some(bd) = &data.breach_details {
        if let Some(n) = bd.number_of_breaches {
            ev = ev.with_attr("breach_count", n.to_string());
        }
        if bd.haveibeenpwned_listed == Some(true) {
            entity.tag(tags::BREACH);
            ev = ev.with_attr("haveibeenpwned_listed", "true");
        }
    }
    entity.add_evidence(ev);
    out.push(entity);

    // Breach domains — the same "Domain per breach, breach_date-stamped"
    // pattern `hibp`/`dehashed` already use, so a SEON-sourced breach hit
    // can date-cluster with the same breach surfaced by another module
    // (AU-019).
    out.extend(
        data.breach_details
            .iter()
            .flat_map(|b| &b.breaches)
            .filter_map(|breach| breach_domain_entity(breach, scan_id)),
    );

    // WHOIS-style registrant PII for every domain SEON associates with this
    // email — the richest new signal this fix recovers.
    out.extend(
        data.associated_domain_registrations
            .iter()
            .flat_map(|a| &a.domains)
            .flat_map(|reg| domain_registration_entities(reg, email, scan_id)),
    );

    out
}

/// A `Domain` entity for one SEON-reported breach, `breach_date`-stamped so
/// it date-clusters with the same breach if another module also surfaces it.
/// Mirrors `hibp::breach_evidence`'s Domain-per-breach pattern. Returns
/// `None` when the breach carries no usable domain (SEON's own example shows
/// every real breach entry does, but a defensive `None` costs nothing).
fn breach_domain_entity(breach: &Breach, scan_id: &str) -> Option<Entity> {
    let domain = breach.domain.as_deref().filter(|d| d.contains('.'))?;
    let mut de = Entity::new(EntityKind::Domain, domain, 0.55, scan_id);
    de.tag(tags::BREACH);
    de.tag("seon");
    de.tag(tags::BREACH_DERIVED);
    let mut ev = Evidence::new(
        SRC,
        format!(
            "Breach '{}' ({})",
            breach.name.as_deref().unwrap_or(domain),
            breach.date.as_deref().unwrap_or("unknown date"),
        ),
    );
    if let Some(name) = nonempty(&breach.name) {
        ev = ev.with_attr("breach_name", name);
    }
    if let Some(date) = nonempty(&breach.date) {
        ev = ev.with_attr("breach_date", date);
    }
    de.add_evidence(ev);
    Some(de)
}

/// `Domain`/`Person`/`Organisation`/`Address`/`Phone` entities for one
/// SEON-reported associated domain registration — WHOIS-style registrant
/// data, so this mirrors `whois`'s registrant extraction (same confidence,
/// same redaction/privacy-placeholder guard) rather than inventing a new
/// pattern.
fn domain_registration_entities(reg: &DomainRegistration, who: &str, scan_id: &str) -> Vec<Entity> {
    let mut out = Vec::new();
    let ev = || {
        Evidence::new(
            SRC,
            format!("SEON associated domain registration for {who}"),
        )
    };

    if let Some(domain) = nonempty(&reg.domain_name) {
        let mut de = Entity::new(EntityKind::Domain, domain, 0.60, scan_id);
        de.tag("seon");
        de.tag(tags::REGISTRANT);
        de.add_evidence(ev());
        out.push(de);
    }
    if let Some(name) =
        nonempty(&reg.full_name).filter(|n| n.len() >= 4 && n.contains(' ') && !is_redacted(n))
    {
        let mut pe = Entity::new(EntityKind::Person, name, 0.72, scan_id);
        pe.tag("seon");
        pe.tag(tags::REGISTRANT);
        pe.add_evidence(ev());
        out.push(pe);
    }
    if let Some(org) = nonempty(&reg.company_name).filter(|n| n.len() >= 3 && !is_redacted(n)) {
        let mut oe = Entity::new(EntityKind::Organisation, org, 0.72, scan_id);
        oe.tag("seon");
        oe.tag(tags::REGISTRANT);
        oe.add_evidence(ev());
        out.push(oe);
    }
    if let Some(phone) = nonempty(&reg.phone_number).filter(|p| !is_redacted(p)) {
        let mut phe = Entity::new(EntityKind::Phone, phone, 0.65, scan_id);
        phe.tag("seon");
        phe.tag(tags::REGISTRANT);
        phe.add_evidence(ev());
        out.push(phe);
    }
    let addr_parts: Vec<&str> = [
        reg.mailing_address.as_deref(),
        reg.city_name.as_deref(),
        reg.state_name.as_deref(),
        reg.zip_code.as_deref(),
        reg.country_code.as_deref(),
    ]
    .into_iter()
    .flatten()
    .map(str::trim)
    .filter(|s| !s.is_empty() && !is_redacted(s) && !s.eq_ignore_ascii_case("n/a"))
    .collect();
    if addr_parts.len() >= 2 {
        let composed = addr_parts.join(", ");
        let mut ae = Entity::new(EntityKind::Address, composed, 0.60, scan_id);
        ae.tag("seon");
        ae.tag(tags::REGISTRANT);
        ae.add_evidence(ev());
        out.push(ae);
    }

    out
}

/// Build entities from a SEON **phone** enrichment: the enriched phone (carrier,
/// line type, geo) plus a `Url` for any messaging-app profile link. Pure.
pub(super) fn build_phone_entities(
    target: &Target,
    data: &SeonPhoneData,
    scan_id: &str,
) -> Vec<Entity> {
    let phone = target.value.trim();
    let mut out = Vec::new();
    let mut entity = target.to_entity(0.88, scan_id);
    entity.tag("seon");

    let mut ev = Evidence::new(SRC, format!("SEON phone enrichment for {phone}"));
    if let Some(score) = data.score {
        ev = ev.with_attr("fraud_score", format!("{score:.1}"));
        if score >= HIGH_RISK_SCORE {
            entity.tag("high-risk");
        }
    }
    if let Some(v) = data.valid {
        ev = ev.with_attr("valid", v.to_string());
    }
    if let Some(c) = nonempty(&data.carrier) {
        ev = ev.with_attr("carrier", c);
    }
    if let Some(c) = nonempty(&data.country) {
        ev = ev.with_attr("country", c);
    }
    if let Some(cc) = nonempty(&data.country_code) {
        ev = ev.with_attr("country_code", cc);
        entity.tag(format!("country:{}", cc.to_uppercase()));
    }
    if let Some(lt) = nonempty(&data.line_type) {
        ev = ev.with_attr("line_type", lt);
        entity.tag(format!("line:{lt}"));
    }

    let registered = data
        .account_details
        .as_ref()
        .map(|a| {
            registered_accounts(&[
                ("whatsapp", &a.whatsapp),
                ("viber", &a.viber),
                ("telegram", &a.telegram),
            ])
        })
        .unwrap_or_default();
    if !registered.is_empty() {
        let names: Vec<&str> = registered.iter().map(|(n, _)| *n).collect();
        ev = ev.with_attr("messaging_platforms", names.join(","));
    }
    entity.add_evidence(ev);
    out.push(entity);

    out.extend(registered.iter().filter_map(|(platform, p)| {
        nonempty(&p.url).map(|url| profile_url_entity(platform, url, phone, scan_id))
    }));

    out
}
