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
