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
    let orgs: Vec<&Entity> = entities_of_kind(entities, EntityKind::Organisation)
        .into_iter()
        .filter(|e| e.confidence >= 0.60)
        .collect();
    let breach_entities: Vec<&Entity> = entities.iter().filter(|e| e.has_tag("breach")).collect();
    if orgs.is_empty() || breach_entities.is_empty() {
        return Vec::new();
    }
    let mut uids: Vec<String> = orgs.iter().map(|e| e.uid.clone()).collect();
    uids.extend(breach_entities.iter().take(5).map(|e| e.uid.clone()));
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
        .filter(|e| {
            let s = e.has_tag("suspicious") || e.has_tag("high-risk");
            let b = e.has_tag("breach");
            let d = e.has_tag("disposable");
            u32::from(s) + u32::from(b) + u32::from(d) >= 2
        })
        .map(|e| {
            let mut signals: Vec<&str> = Vec::new();
            if e.has_tag("suspicious") || e.has_tag("high-risk") {
                signals.push("fraud-flagged");
            }
            if e.has_tag("breach") {
                signals.push("breach-exposed");
            }
            if e.has_tag("disposable") {
                signals.push("disposable");
            }
            Correlation::new(
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
            )
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
    let persons: Vec<&Entity> = entities
        .iter()
        .filter(|e| e.kind == EntityKind::Person && e.confidence >= 0.60)
        .collect();
    if orgs.is_empty() || persons.is_empty() {
        return Vec::new();
    }
    let mut uids: Vec<String> = orgs.iter().map(|o| o.uid.clone()).collect();
    uids.extend(persons.iter().take(5).map(|p| p.uid.clone()));
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
    if abns.is_empty() || orgs.is_empty() {
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

/// AU-058 — Microsoft 365 tenant attribution.
///
/// Fires when at least one domain entity carries the `m365` tag (injected by
/// `employer_pivot` after a successful Azure AD / Entra ID OpenID-Connect
/// discovery). The presence of an active M365 tenant confirms the organisation
/// uses Microsoft-hosted email and cloud services, strengthening the link
/// between the discovered email address and the corporate infrastructure.
///
/// Technique: T1590.001 — Gather Victim Network Information: IP Addresses /
/// Cloud infrastructure attribution.
///
/// Severity: Low — informational. Confirms cloud platform, not a threat signal.
pub(in crate::core::correlator) fn rule_au_058_m365_tenant_attribution(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    let m365_domains: Vec<&Entity> = entities
        .iter()
        .filter(|e| e.kind == EntityKind::Domain && e.has_tag("m365"))
        .collect();
    if m365_domains.is_empty() {
        return Vec::new();
    }
    // Require at least one identity anchor (person, email, or username) to
    // avoid firing on infrastructure-only scans.
    let has_anchor = entities.iter().any(|e| {
        matches!(
            e.kind,
            EntityKind::Person | EntityKind::Email | EntityKind::Username
        )
    });
    if !has_anchor {
        return Vec::new();
    }
    let mut uids: Vec<String> = m365_domains.iter().map(|d| d.uid.clone()).collect();
    // Include any email entities to link the tenant discovery to the subject.
    uids.extend(
        entities
            .iter()
            .filter(|e| e.kind == EntityKind::Email)
            .map(|e| e.uid.clone()),
    );
    uids.sort_unstable();
    uids.dedup();
    vec![Correlation::new(
        "AU-058",
        "Microsoft 365 tenant attribution",
        Severity::Low,
        format!(
            "{} domain(s) confirmed with active Microsoft 365 / Entra ID tenant; \
             email address(es) are Microsoft-hosted (T1590.001 cloud infrastructure)",
            m365_domains.len()
        ),
        uids,
        scan_id,
        ts,
    )]
}
