//! AU correlation rules — org family. See `super` (rules/mod.rs) for the
//! shared helpers; every rule reaches them through `use super::*`.

use super::*;

pub(in crate::core::correlator) fn rule_au_012_identity_linked_domain(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    let username_uids: Vec<String> = entities
        .iter()
        .filter(|e| e.kind == EntityKind::Username)
        .map(|u| u.uid.clone())
        .collect();
    if username_uids.is_empty() {
        return Vec::new();
    }
    entities
        .iter()
        .filter(|e| {
            matches!(e.kind, EntityKind::Url | EntityKind::Domain) && e.has_tag("personal-site")
        })
        .map(|d| {
            let mut uids = Vec::with_capacity(1 + username_uids.len());
            uids.push(d.uid.clone());
            uids.extend(username_uids.iter().cloned());
            Correlation {
                rule_id: "AU-012".into(),
                rule_name: "Identity-linked site".into(),
                severity: Severity::Medium,
                description: format!(
                    "Personal site '{}' co-occurs with {} username(s) in scan",
                    d.value,
                    username_uids.len()
                ),
                entity_uids: uids,
                scan_id: scan_id.into(),
                ts,
                rank: 0.0,
            }
        })
        .collect()
}

pub(in crate::core::correlator) fn rule_au_022_organisation_with_breach(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    let orgs: Vec<&Entity> = entities
        .iter()
        .filter(|e| e.kind == EntityKind::Organisation && e.confidence >= 0.60)
        .collect();
    if orgs.is_empty() {
        return Vec::new();
    }
    let breach_entities: Vec<&Entity> = entities.iter().filter(|e| e.has_tag("breach")).collect();
    if breach_entities.is_empty() {
        return Vec::new();
    }
    let mut uids: Vec<String> = orgs.iter().map(|e| e.uid.clone()).collect();
    // Full member set (no `take` cap): the live and finalise passes must yield the
    // same uid SET so storage's containment-dedup folds them. A `take(5)` of the
    // HashMap-ordered breach list gave disjoint 5-samples across passes that
    // persisted as duplicate AU-022 rows — the same defect (and fix) as AU-018.
    uids.extend(breach_entities.iter().map(|e| e.uid.clone()));
    vec![Correlation::new(
        "AU-022",
        "Organisation linked to breach data",
        Severity::High,
        format!(
            "{} organisation(s) co-located with {} breach entities",
            orgs.len(),
            breach_entities.len()
        ),
        uids,
        scan_id,
        ts,
    )]
}

pub(in crate::core::correlator) fn rule_au_024_email_fraud_signal(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    entities
        .iter()
        .filter(|e| e.kind == EntityKind::Email)
        .filter_map(|e| {
            // Classify each tag class once, then reuse the booleans for the
            // ≥2-signal gate, the signal labels and (implicitly) the count —
            // instead of re-scanning the tag list up to seven times per email.
            let fraud = e.has_tag("suspicious") || e.has_tag("high-risk");
            let breach = e.has_tag("breach");
            let disposable = e.has_tag("disposable");
            if u32::from(fraud) + u32::from(breach) + u32::from(disposable) < 2 {
                return None;
            }
            let mut signals: Vec<&str> = Vec::new();
            if fraud {
                signals.push("fraud-flagged");
            }
            if breach {
                signals.push("breach-exposed");
            }
            if disposable {
                signals.push("disposable");
            }
            Some(Correlation::new(
                "AU-024",
                "Multi-signal email fraud indicator",
                Severity::High,
                format!(
                    "Email '{}' has converging risk signals: {}",
                    e.value,
                    signals.join(" + ")
                ),
                vec![e.uid.clone()],
                scan_id,
                ts,
            ))
        })
        .collect()
}

pub(in crate::core::correlator) fn rule_au_025_corporate_identity_link(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    let orgs: Vec<&Entity> = entities
        .iter()
        .filter(|e| e.kind == EntityKind::Organisation && e.has_tag("opencorporates"))
        .collect();
    if orgs.is_empty() {
        return Vec::new();
    }
    let persons: Vec<&Entity> = entities
        .iter()
        .filter(|e| e.kind == EntityKind::Person && e.confidence >= 0.60)
        .collect();
    if persons.is_empty() {
        return Vec::new();
    }
    let mut uids: Vec<String> = orgs.iter().map(|o| o.uid.clone()).collect();
    // Full member set (no `take` cap) so the live/finalise uid SETs match and
    // containment-dedup folds them, as in AU-018/AU-022 — a HashMap-ordered
    // `take(5)` sample otherwise persists as duplicate AU-025 rows.
    uids.extend(persons.iter().map(|p| p.uid.clone()));
    vec![Correlation::new(
        "AU-025",
        "Corporate registry linked to identity",
        Severity::Medium,
        format!(
            "{} registered company/ies co-located with {} person entities",
            orgs.len(),
            persons.len()
        ),
        uids,
        scan_id,
        ts,
    )]
}

/// AU-033 — Australian business identity. Links an ABN/ACN registration to the
/// registered organisation(s) it belongs to when both are present from an
/// Australian registry (`abn_lookup` → `abr`, `opencorporates`, `acnc_charities`
/// → `acnc`, `gleif_lei` → `gleif`). Surfaces the
/// ABN/ACN ↔ Organisation chain those modules produce but no prior rule joined
/// (AU-025 covers Organisation ↔ Person). Organisations are gated on a registry
/// tag so unrelated `Organisation` names (e.g. from search_engines) don't link.
pub(in crate::core::correlator) fn rule_au_033_abn_organisation_link(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    let abns: Vec<&Entity> = entities
        .iter()
        .filter(|e| e.kind == EntityKind::AbnAcn)
        .collect();
    if abns.is_empty() {
        return Vec::new();
    }
    let orgs: Vec<&Entity> = entities
        .iter()
        .filter(|e| {
            e.kind == EntityKind::Organisation
                && (e.has_tag("abr")
                    || e.has_tag("opencorporates")
                    || e.has_tag("acnc")
                    || e.has_tag("gleif"))
        })
        .collect();
    if orgs.is_empty() {
        return Vec::new();
    }
    let mut uids: Vec<String> = abns.iter().map(|a| a.uid.clone()).collect();
    uids.extend(orgs.iter().map(|o| o.uid.clone()));
    vec![Correlation::new(
        "AU-033",
        "Australian business identity (ABN/ACN \u{2194} organisation)",
        Severity::Medium,
        format!(
            "{} ABN/ACN registration(s) linked to {} registered organisation(s) \
             via the Australian Business Register / corporate registries",
            abns.len(),
            orgs.len()
        ),
        uids,
        scan_id,
        ts,
    )]
}

/// Delegates to [`crate::util::domains::is_proxy_registrant`] — single source
/// of truth for the privacy-proxy / WHOIS-redaction exclusion used by both
/// AU-061 and `core::relation::builders::derive_co_ownership`.
fn is_proxy_registrant(value: &str, is_email: bool) -> bool {
    crate::util::domains::is_proxy_registrant(value, is_email)
}

/// AU-061 — Shared-registrant domain co-ownership.
///
/// Groups the `RegisteredBy` edges (Domain → registrant Organisation/Email,
/// derived from WHOIS/RDAP by `relation::builders::derive_registration`) by
/// registrant. When ≥2 DISTINCT domains share one genuine registrant they are
/// very likely controlled by a single operator — the canonical WHOIS pivot for
/// mapping an actor's domain estate.
///
/// This is the ownership counterpart to AU-044 (shared web-analytics id): both
/// assert "different web properties, one operator". Unlike a shared hosting IP
/// (millions of unrelated sites behind one CDN edge — AU-031 treats that as
/// noise to *suppress*), a shared registrant is a strong ownership signal
/// because the registrant is the party that contractually holds the domains.
///
/// False-positive guard: privacy-proxy / redacted registrants (see
/// [`is_proxy_registrant`]) are shared across millions of domains and are
/// EXCLUDED — only a real registrant identity links the estate. Severity High,
/// matching AU-044's shared-ownership tier. Deterministic: registrants iterated
/// in uid order, member domains sorted by uid.
pub(in crate::core::correlator) fn rule_au_061_shared_registrant(
    entities: &[Entity],
    relations: &[Relation],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    // uid → entity, for endpoint lookup.
    let by_uid: HashMap<&str, &Entity> = entities.iter().map(|e| (e.uid.as_str(), e)).collect();

    // registrant uid → distinct domain uids registered by it (insertion order
    // preserved for determinism; sorted before emission).
    let mut groups: HashMap<&str, Vec<&str>> = HashMap::new();
    for r in relations
        .iter()
        .filter(|r| r.kind == RelationKind::RegisteredBy)
    {
        let (Some(dom), Some(reg)) = (
            by_uid.get(r.from_uid.as_str()),
            by_uid.get(r.to_uid.as_str()),
        ) else {
            continue;
        };
        // `RegisteredBy` is Domain → Organisation/Email by construction; assert
        // the endpoint kinds so a malformed edge can't group non-domains.
        if dom.kind != EntityKind::Domain
            || !matches!(reg.kind, EntityKind::Organisation | EntityKind::Email)
        {
            continue;
        }
        if is_proxy_registrant(&reg.value, reg.kind == EntityKind::Email) {
            continue;
        }
        let members = groups.entry(r.to_uid.as_str()).or_default();
        if !members.contains(&r.from_uid.as_str()) {
            members.push(r.from_uid.as_str());
        }
    }

    // Stable iteration order: registrants by uid.
    let mut registrant_uids: Vec<&str> = groups.keys().copied().collect();
    registrant_uids.sort_unstable();

    let mut out = Vec::new();
    for reg_uid in registrant_uids {
        let Some(mut domains) = groups.remove(reg_uid) else {
            continue;
        };
        if domains.len() < 2 {
            continue;
        }
        domains.sort_unstable();
        let reg = by_uid.get(reg_uid).copied();
        let reg_label = reg.map_or("registrant", |e| e.value.as_str());
        let reg_kind = match reg.map(|e| &e.kind) {
            Some(EntityKind::Email) => "registrant email",
            _ => "registrant organisation",
        };
        let domain_values: Vec<&str> = domains
            .iter()
            .filter_map(|u| by_uid.get(u).map(|e| e.value.as_str()))
            .collect();

        let mut uids: Vec<String> = Vec::with_capacity(domains.len() + 1);
        uids.push(reg_uid.to_string());
        uids.extend(domains.iter().map(|u| (*u).to_string()));

        out.push(Correlation::new(
            "AU-061",
            "Shared registrant (domain co-ownership)",
            Severity::High,
            format!(
                "{} domains share the {} '{}' — a common WHOIS registrant indicates \
                 the domains are controlled by one operator: {}",
                domains.len(),
                reg_kind,
                reg_label,
                domain_values.join(", ")
            ),
            uids,
            scan_id,
            ts,
        ));
    }
    out
}

/// Upper bound on DISTINCT registrable domains sharing one dedicated IP for
/// AU-062 to read the co-tenancy as probable co-ownership rather than shared
/// hosting. A real operator estate is a handful of sites; a single IP serving
/// many *distinct* sites is a reseller / shared-hosting box — the high-fan-out
/// shared-infra case AU-031 already aggregates as noise.
const MAX_CO_HOSTED_REGISTRABLE: usize = 5;

/// AU-062 — Shared dedicated-IP domain co-hosting (probable co-ownership).
///
/// Groups the `ResolvesTo` edges (Domain → IpAddress, from DNS) by IP. When a
/// SMALL set of ≥2 DISTINCT registrable domains resolve to one DEDICATED IP they
/// are probably co-owned — the reverse-IP clustering pivot for an actor's estate.
///
/// This is the IP counterpart to AU-061 (shared registrant) at LOWER severity
/// (Medium vs High): a dedicated IP can still host a few unrelated small sites,
/// whereas a registrant contractually holds the domains. The finding is framed
/// as a lead to verify (against registrant / page content), not a conclusion.
///
/// Three false-positive guards, each removing a distinct noise class:
/// 1. **CDN / anycast edges** (`is_cdn_edge_ip`) and **non-routable** IPs
///    (`is_non_routable_ip`) are excluded — a Cloudflare edge fronting millions
///    of unrelated sites is co-tenancy, not co-ownership (the class AU-031
///    suppresses).
/// 2. **Distinct registrable domains** (`registrable_domain`) — the membership
///    must span ≥2 different eTLD+1s, so a single site's own subdomains
///    (`www`/`api`/`blog.example.com` all on its origin IP) is co-*residence*,
///    not co-ownership, and does NOT fire.
/// 3. **Fan-out cap** (`MAX_CO_HOSTED_REGISTRABLE`) — many distinct sites on one
///    IP reads as shared hosting and is skipped.
///
/// Severity Medium. Deterministic: IPs iterated in uid order, member domains and
/// the named registrable set sorted.
pub(in crate::core::correlator) fn rule_au_062_shared_hosting_ip(
    entities: &[Entity],
    relations: &[Relation],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    let by_uid: HashMap<&str, &Entity> = entities.iter().map(|e| (e.uid.as_str(), e)).collect();

    // IP uid → distinct domain uids resolving to it (insertion order preserved).
    let mut groups: HashMap<&str, Vec<&str>> = HashMap::new();
    for r in relations
        .iter()
        .filter(|r| r.kind == RelationKind::ResolvesTo)
    {
        let (Some(dom), Some(ip)) = (
            by_uid.get(r.from_uid.as_str()),
            by_uid.get(r.to_uid.as_str()),
        ) else {
            continue;
        };
        if dom.kind != EntityKind::Domain || ip.kind != EntityKind::IpAddress {
            continue;
        }
        // Guard 1: exclude CDN/anycast edges and non-routable IPs.
        if crate::core::validation::is_cdn_edge_ip(&ip.value)
            || crate::core::validation::is_non_routable_ip(&ip.value)
        {
            continue;
        }
        let members = groups.entry(r.to_uid.as_str()).or_default();
        if !members.contains(&r.from_uid.as_str()) {
            members.push(r.from_uid.as_str());
        }
    }

    let mut ip_uids: Vec<&str> = groups.keys().copied().collect();
    ip_uids.sort_unstable();

    let mut out = Vec::new();
    for ip_uid in ip_uids {
        let Some(mut domains) = groups.remove(ip_uid) else {
            continue;
        };
        domains.sort_unstable();

        // Guard 2: count DISTINCT registrable domains; a single site's own
        // subdomains collapse to one eTLD+1 and must not fire.
        let mut registrables: Vec<String> = domains
            .iter()
            .filter_map(|u| by_uid.get(u))
            .filter_map(|e| crate::util::domains::registrable_domain(&e.value))
            .collect();
        registrables.sort_unstable();
        registrables.dedup();

        // Guard 3: ≥2 distinct sites, but skip shared-hosting fan-out.
        if registrables.len() < 2 || registrables.len() > MAX_CO_HOSTED_REGISTRABLE {
            continue;
        }

        let ip_label = by_uid.get(ip_uid).map_or("ip", |e| e.value.as_str());
        let mut uids: Vec<String> = Vec::with_capacity(domains.len() + 1);
        uids.push(ip_uid.to_string());
        uids.extend(domains.iter().map(|u| (*u).to_string()));

        out.push(Correlation::new(
            "AU-062",
            "Co-hosted on dedicated IP (probable co-ownership)",
            Severity::Medium,
            format!(
                "{} distinct sites resolve to the same dedicated IP {} — small-set \
                 co-hosting on a non-CDN address is a lead that the domains share an \
                 operator (verify against registrant / content): {}",
                registrables.len(),
                ip_label,
                registrables.join(", ")
            ),
            uids,
            scan_id,
            ts,
        ));
    }
    out
}
