//! Pure entity-building functions for SEON email and phone enrichment.
//!
//! These functions are free of HTTP transport and are unit-tested directly.

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    scan::Target,
};
use crate::util::str_util::nonempty;

use super::{
    types::{AccountPresence, SeonEmailData, SeonPhoneData},
    HIGH_RISK_SCORE, PERSON_PLATFORMS, SRC,
};

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

/// Build entities from a SEON **email** enrichment: the enriched email itself,
/// a `Person` lead from the best-named platform, and a `Url` for every platform
/// that reported a profile link. Pure — unit-tested without a live API.
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
    if let Some(score) = data.score {
        ev = ev.with_attr("fraud_score", format!("{score:.1}"));
        if score >= HIGH_RISK_SCORE {
            entity.tag("high-risk");
        }
    }
    if let Some(d) = data.deliverable {
        ev = ev.with_attr("deliverable", d.to_string());
    }
    if let Some(dd) = &data.domain_details {
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
    }

    let registered = data
        .account_details
        .as_ref()
        .map(|a| {
            registered_accounts(&[
                ("facebook", &a.facebook),
                ("twitter", &a.twitter),
                ("linkedin", &a.linkedin),
                ("instagram", &a.instagram),
                ("github", &a.github),
                ("google", &a.google),
                ("apple", &a.apple),
                ("microsoft", &a.microsoft),
                ("spotify", &a.spotify),
                ("skype", &a.skype),
            ])
        })
        .unwrap_or_default();

    if !registered.is_empty() {
        let names: Vec<&str> = registered.iter().map(|(n, _)| *n).collect();
        ev = ev.with_attr("platforms_registered", names.join(","));
        ev = ev.with_attr("platform_count", names.len().to_string());
    }
    entity.add_evidence(ev);
    out.push(entity);

    // One Person from the best-named identity platform.
    if let Some((platform, name)) = registered.iter().find_map(|(plat, p)| {
        nonempty(&p.name)
            .filter(|n| PERSON_PLATFORMS.contains(plat) && n.len() >= 3 && n.contains(' '))
            .map(|n| (*plat, n))
    }) {
        let mut pe = Entity::new(EntityKind::Person, name, 0.65, scan_id);
        pe.tag("seon");
        pe.tag(format!("platform:{platform}"));
        pe.add_evidence(Evidence::new(
            SRC,
            format!("Name from {platform} via SEON for {email}"),
        ));
        out.push(pe);
    }

    // A Url for every platform that reported a profile link.
    out.extend(registered.iter().filter_map(|(platform, p)| {
        nonempty(&p.url).map(|url| profile_url_entity(platform, url, email, scan_id))
    }));

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
