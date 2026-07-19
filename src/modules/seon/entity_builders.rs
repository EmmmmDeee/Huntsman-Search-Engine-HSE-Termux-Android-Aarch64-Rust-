//! Pure entity-building functions for SEON email and phone enrichment.
//!
//! These functions are free of HTTP transport and are unit-tested directly.

use crate::core::{
    confidence,
    entity::{Entity, EntityKind, Evidence},
    scan::Target,
    tags,
};
use crate::util::str_util::nonempty;

use super::{
    HIGH_RISK_SCORE, SRC,
    types::{
        AccountAggregates, Breach, CnamDetails, DomainRegistration, EmailDomainDetails, RiskScores,
        SeonEmailData, SeonFraudHistory, SeonPhoneData,
    },
};

/// A registrant-PII string that's a redaction/privacy-service placeholder
/// rather than real data — the same class of guard `whois`'s registrant
/// extraction already applies, reused here so a masked WHOIS-privacy domain
/// registration doesn't mint a fake `John Doe`/`Privacy Inc` node.
fn is_redacted(s: &str) -> bool {
    let l = s.to_lowercase();
    l.contains("privacy") || l.contains("redacted") || l.contains("data protected")
}

/// Fraud score evidence + high-risk tagging — identical on both SEON paths
/// (`risk_scores.global_network_score` is the same field shared by
/// `email-api/v3` and `phone-api/v2`).
fn apply_risk_score(entity: &mut Entity, mut ev: Evidence, risk: &RiskScores) -> Evidence {
    if let Some(score) = risk.global_network_score {
        ev = ev.with_attr("fraud_score", format!("{score:.1}"));
        if score >= HIGH_RISK_SCORE {
            entity.tag("high-risk");
        }
    }
    ev
}

/// Consortium fraud-history evidence + tagging — identical on both SEON
/// paths (`seon_fraud_history` is the same field shared by both endpoints).
fn apply_fraud_history(entity: &mut Entity, mut ev: Evidence, fh: &SeonFraudHistory) -> Evidence {
    if fh.hits.unwrap_or(0) > 0 {
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
    ev
}

/// Platform-registration category summary evidence — identical on both SEON
/// paths (`account_aggregates` is the same field shared by both endpoints).
/// Sorted into one list (not business-categories-then-personal-categories)
/// so an operator scanning for a specific category doesn't need to know
/// which group it falls under. The same category name can legitimately
/// appear in BOTH `business` and `personal` with different counts (SEON's
/// own example response shows `technology` under both) — collapsing them
/// into one map keyed on name alone would silently drop one group's count,
/// so the group is folded into the label itself (`technology[business]`/
/// `technology[personal]`) rather than deduped away.
fn apply_account_aggregates(mut ev: Evidence, agg: &AccountAggregates) -> Evidence {
    if let Some(total) = agg.total_registration {
        ev = ev.with_attr("platform_registrations", total.to_string());
    }
    if let Some(b) = agg.business.as_ref().and_then(|g| g.total_registration) {
        ev = ev.with_attr("business_platform_registrations", b.to_string());
    }
    if let Some(p) = agg.personal.as_ref().and_then(|g| g.total_registration) {
        ev = ev.with_attr("personal_platform_registrations", p.to_string());
    }
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
    ev
}

/// A PSTN-subscriber `Person` from SEON's CNAM lookup — mirrors
/// `hlr_cnam::build_cnam_person`'s identical pattern (same confidence, same
/// minimal-length filter): this is the same Caller-ID-Name signal via a
/// different provider, so it earns the same treatment rather than a new one.
fn cnam_person_entity(cnam: &CnamDetails, phone: &str, scan_id: &str) -> Option<Entity> {
    let name = nonempty(&cnam.name).filter(|n| n.len() >= 2)?;
    let mut person = Entity::new(EntityKind::Person, name, confidence::MEDIUM_HIGH, scan_id);
    person.tag("seon");
    person.tag("cnam");
    person.tag("pstn-subscriber");
    person.add_evidence(
        Evidence::new(SRC, format!("CNAM subscriber name for {phone}"))
            .with_attr("cnam_name", name),
    );
    Some(person)
}

/// A carrier/network `Organisation` pivot from SEON's provider lookup —
/// mirrors `hlr_cnam::build_hlr_entities`'s identical carrier-Organisation
/// pattern (same confidence, same minimal-length filter).
fn carrier_entity(carrier: &str, phone: &str, scan_id: &str) -> Option<Entity> {
    let carrier = carrier.trim();
    if carrier.len() < 2 {
        return None;
    }
    let mut oe = Entity::new(EntityKind::Organisation, carrier, 0.62, scan_id);
    oe.tag("seon");
    oe.tag("carrier");
    oe.add_evidence(
        Evidence::new(SRC, format!("Carrier/network for {phone} per SEON"))
            .with_attr("phone", phone),
    );
    Some(oe)
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
    let mut entity = target.to_entity(confidence::EXPERT, scan_id);
    entity.tag("seon");

    let mut ev = Evidence::new(SRC, format!("SEON email enrichment for {email}"));
    if let Some(risk) = &data.risk_scores {
        ev = apply_risk_score(&mut entity, ev, risk);
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
    if let Some(fh) = &data.seon_fraud_history {
        ev = apply_fraud_history(&mut entity, ev, fh);
    }

    // Platform-registration summary — SEON's v3 schema only returns
    // CATEGORY-LEVEL counts (`account_aggregates`), not per-platform names or
    // profile links, so unlike the pre-v3 shape this cannot mint individual
    // `Url`/`Person` leads per platform (that data no longer exists in the
    // API at all — see `types.rs`'s `SeonEmailData` doc comment).
    if let Some(agg) = &data.account_aggregates {
        ev = apply_account_aggregates(ev, agg);
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

    // The enriched email's own domain as a first-class Domain pivot — SEON
    // parses it (`email_domain_details.domain`) but it was previously only
    // ever attached as an evidence attribute on the Email entity above.
    out.extend(
        data.email_domain_details
            .as_ref()
            .and_then(|dd| email_domain_entity(dd, scan_id)),
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
    let mut de = Entity::new(EntityKind::Domain, domain, confidence::MEDIUM_HIGH, scan_id);
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
        let mut de = Entity::new(EntityKind::Domain, domain, confidence::MEDIUM_PLUS, scan_id);
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
        let mut phe = Entity::new(EntityKind::Phone, phone, confidence::HIGH, scan_id);
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
        let mut ae = Entity::new(
            EntityKind::Address,
            composed,
            confidence::MEDIUM_PLUS,
            scan_id,
        );
        ae.tag("seon");
        ae.tag(tags::REGISTRANT);
        ae.add_evidence(ev());
        out.push(ae);
    }

    out
}

/// A `Domain` entity for the enriched email's own domain
/// (`email_domain_details.domain`) — mirrors `breach_domain_entity`'s and
/// `domain_registration_entities`' identical string-to-`Domain` pattern.
/// Guarded against freemail/disposable domains (`free`/`disposable`) so a
/// shared provider like Gmail or a throwaway domain isn't minted as a
/// first-class pivot node alongside the genuinely email-specific ones.
fn email_domain_entity(dd: &EmailDomainDetails, scan_id: &str) -> Option<Entity> {
    let domain = nonempty(&dd.domain)?;
    if dd.free == Some(true) || dd.disposable == Some(true) {
        return None;
    }
    let mut de = Entity::new(EntityKind::Domain, domain, confidence::MEDIUM_PLUS, scan_id);
    de.tag("seon");
    let mut ev = Evidence::new(SRC, format!("SEON email domain details for {domain}"));
    if let Some(r) = dd.registered {
        ev = ev.with_attr("registered", r.to_string());
    }
    if let Some(r) = nonempty(&dd.registrar_name) {
        ev = ev.with_attr("registrar_name", r);
    }
    if let Some(c) = nonempty(&dd.created) {
        ev = ev.with_attr("created", c);
    }
    if let Some(v) = dd.valid_mx {
        ev = ev.with_attr("valid_mx", v.to_string());
    }
    if let Some(w) = dd.website_exists {
        ev = ev.with_attr("website_exists", w.to_string());
    }
    de.add_evidence(ev);
    Some(de)
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
    let mut entity = target.to_entity(confidence::EXPERT, scan_id);
    entity.tag("seon");

    let mut ev = Evidence::new(SRC, format!("SEON phone enrichment for {phone}"));
    if let Some(risk) = &data.risk_scores {
        ev = apply_risk_score(&mut entity, ev, risk);
    }
    if let Some(pcd) = &data.provider_carrier_details {
        if let Some(v) = pcd.phone_is_valid {
            ev = ev.with_attr("valid", v.to_string());
        }
        if let Some(c) = nonempty(&pcd.carrier) {
            ev = ev.with_attr("carrier", c);
        }
        if let Some(c) = nonempty(&pcd.country) {
            ev = ev.with_attr("country", c);
            entity.tag(format!("country:{c}"));
        }
        if pcd.disposable == Some(true) {
            entity.tag("disposable");
            ev = ev.with_attr("disposable", "true");
        }
        if let Some(lt) = nonempty(&pcd.line_type) {
            ev = ev.with_attr("line_type", lt);
            entity.tag(format!("line:{lt}"));
        }
    }
    if let Some(hlr) = &data.hlr_details {
        if let Some(s) = nonempty(&hlr.status) {
            ev = ev.with_attr("hlr_status", s);
        }
        if let Some(imsi) = nonempty(&hlr.imsi) {
            ev = ev.with_attr("imsi", imsi);
        }
        if let Some(msc) = nonempty(&hlr.serving_msc) {
            ev = ev.with_attr("serving_msc", msc);
        }
        if let Some(c) = nonempty(&hlr.original_carrier) {
            ev = ev.with_attr("ported_from_carrier", c);
        }
        if let Some(c) = nonempty(&hlr.ported_carrier) {
            ev = ev.with_attr("ported_carrier", c);
            entity.tag("ported");
        }
        if let Some(c) = nonempty(&hlr.roaming_carrier) {
            ev = ev.with_attr("roaming_carrier", c);
            entity.tag("roaming");
        }
    }
    if let Some(fh) = &data.seon_fraud_history {
        ev = apply_fraud_history(&mut entity, ev, fh);
    }
    if let Some(agg) = &data.account_aggregates {
        ev = apply_account_aggregates(ev, agg);
    }
    entity.add_evidence(ev);
    out.push(entity);

    // Carrier/network → Organisation pivot (consistent with hlr_cnam/ip2location/ipquery).
    out.extend(
        data.provider_carrier_details
            .as_ref()
            .and_then(|pcd| nonempty(&pcd.carrier))
            .and_then(|c| carrier_entity(c, phone, scan_id)),
    );

    // HLR-reported ported-to carrier → a second Organisation pivot, distinct
    // from the provider-reported carrier above — a number ported to a new
    // network is a genuinely different Organisation, not a duplicate. Must
    // stay AFTER the provider_carrier_details push above so any caller that
    // finds the first Organisation still gets the provider-reported one.
    out.extend(
        data.hlr_details
            .as_ref()
            .and_then(|h| nonempty(&h.ported_carrier))
            .and_then(|c| carrier_entity(c, phone, scan_id))
            .map(|mut oe| {
                oe.tag("ported-carrier");
                oe
            }),
    );

    // CNAM Caller-ID-Name → Person pivot (consistent with hlr_cnam).
    out.extend(
        data.cnam_details
            .as_ref()
            .and_then(|cnam| cnam_person_entity(cnam, phone, scan_id)),
    );

    out
}
