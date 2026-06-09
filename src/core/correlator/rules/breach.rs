//! AU correlation rules — breach family. See `super` (rules/mod.rs) for the
//! shared helpers; every rule reaches them through `use super::*`.

use super::*;

pub(in crate::core::correlator) fn rule_au_001_multi_breach(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    const BREACH_SOURCES: &[&str] = &[
        "hudsonrock",
        "xposed_or_not",
        "breach_directory",
        "dehashed",
        "hibp",
        "oathnet_pro",
        "emailrep",
        // NOTE: the generic `search_engines` source is deliberately NOT listed.
        // A web-search hit is not breach corroboration, and counting it would let
        // one real breach + one search result fire a false Critical. (An earlier
        // `search_engines:oathnet` entry was dead — the module emits the plain
        // `search_engines` source — so it was removed rather than "fixed" to
        // `search_engines`, which would introduce exactly that false positive.)
    ];
    let mut out = Vec::new();
    for e in entities_of_kind(entities, EntityKind::Email) {
        let sources = tagged_matching_sources(e, BREACH_SOURCES);
        if sources.len() >= 2 {
            let mut names: Vec<&str> = sources.into_iter().collect();
            names.sort_unstable();
            out.push(Correlation::new(
                "AU-001",
                "Multi-source breach corroboration",
                Severity::Critical,
                format!(
                    "{} found in {} breach sources: {}",
                    e.value,
                    names.len(),
                    names.join(", ")
                ),
                vec![e.uid.clone()],
                scan_id,
                ts,
            ));
        }
    }
    out
}

pub(in crate::core::correlator) fn rule_au_009_stealer_log(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    entities
        .iter()
        .filter(|e| e.kind == EntityKind::Email && e.has_tag("stealer-log"))
        .map(|e| Correlation {
            rule_id: "AU-009".into(),
            rule_name: "Stealer-log compromise".into(),
            severity: Severity::High,
            description: format!("Email {} observed in info-stealer log dumps", e.value),
            entity_uids: vec![e.uid.clone()],
            scan_id: scan_id.into(),
            ts,
            rank: 0.0,
        })
        .collect()
}

pub(in crate::core::correlator) fn rule_au_019_temporal_breach_cluster(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    let mut breach_dates: Vec<(&Entity, &str)> = Vec::new();
    for e in entities {
        if !e.has_tag("breach") {
            continue;
        }
        for ev in &e.evidence {
            for field in ["breach_date", "not_before", "earliest_record", "date"] {
                if let Some(d) = ev.attributes.get(field)
                    && let Some(day) = d.get(..10)
                {
                    breach_dates.push((e, day));
                }
            }
        }
    }
    if breach_dates.len() < 3 {
        return Vec::new();
    }
    breach_dates.sort_by_key(|(_, d)| *d);
    let mut clusters: Vec<Vec<String>> = Vec::new();
    let mut current: Vec<String> = vec![breach_dates[0].0.uid.clone()];
    // Anchor the window to the cluster's FIRST (earliest, since sorted) date, not
    // a rolling previous date. A rolling gap chains — Jan 1 / Jan 30 / Feb 28 /
    // Mar 30 are each ≤30 days apart and would collapse into one 88-day "cluster",
    // contradicting the "within 30 days" claim. Anchoring bounds every cluster to
    // a genuine ≤30-day span (a real coordinated-compromise window).
    let mut anchor = breach_dates[0].1;
    for &(e, d) in &breach_dates[1..] {
        if date_diff_days(anchor, d) <= 30 {
            if !current.contains(&e.uid) {
                current.push(e.uid.clone());
            }
        } else {
            if current.len() >= 3 {
                clusters.push(current);
            }
            current = vec![e.uid.clone()];
            anchor = d;
        }
    }
    if current.len() >= 3 {
        clusters.push(current);
    }
    clusters
        .into_iter()
        .map(|uids| Correlation {
            rule_id: "AU-019".into(),
            rule_name: "Temporal breach cluster".into(),
            severity: Severity::High,
            description: format!(
                "{} breach entities clustered within 30 days — potential coordinated compromise",
                uids.len()
            ),
            entity_uids: uids,
            scan_id: scan_id.into(),
            ts,
            rank: 0.0,
        })
        .collect()
}

pub(in crate::core::correlator) fn rule_au_021_api_key_exposure(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    entities
        .iter()
        .filter(|e| e.kind == EntityKind::ApiKey)
        .map(|e| {
            Correlation::new(
                "AU-021",
                "API key exposure",
                Severity::Critical,
                format!("API key '{}' discovered in breach/stealer data", e.value),
                vec![e.uid.clone()],
                scan_id,
                ts,
            )
        })
        .collect()
}

/// AU-037 — Plaintext credential exposure.
///
/// The single most actionable OSINT finding: an actual leaked secret. The
/// breach/stealer modules surface the canonical secret as a first-class
/// `Password` / `Credential` entity (distinct from `ApiKey`, which AU-021
/// covers), but nothing previously synthesised them into an alert. This fires
/// CRITICAL when any are present, links the secret entities (capped) plus the
/// exposed identity (emails/usernames) so the operator sees *whose* credentials
/// leaked, and reports only COUNTS — the raw secret values stay in the entities
/// (full-fidelity policy) and are never copied into correlation text.
pub(in crate::core::correlator) fn rule_au_037_credential_exposure(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    let secrets: Vec<&Entity> = entities
        .iter()
        .filter(|e| matches!(e.kind, EntityKind::Password | EntityKind::Credential))
        .collect();
    if secrets.is_empty() {
        return Vec::new();
    }
    let passwords = secrets
        .iter()
        .filter(|e| e.kind == EntityKind::Password)
        .count();
    let credentials = secrets.len() - passwords;

    // Affected secrets first (capped), then the identity they pertain to.
    let mut uids: Vec<String> = secrets.iter().take(20).map(|e| e.uid.clone()).collect();
    uids.extend(
        entities
            .iter()
            .filter(|e| matches!(e.kind, EntityKind::Email | EntityKind::Username))
            .take(5)
            .map(|e| e.uid.clone()),
    );

    let mut parts = Vec::new();
    if passwords > 0 {
        parts.push(format!(
            "{passwords} plaintext password{}",
            if passwords == 1 { "" } else { "s" }
        ));
    }
    if credentials > 0 {
        parts.push(format!(
            "{credentials} credential record{}",
            if credentials == 1 { "" } else { "s" }
        ));
    }
    vec![Correlation::new(
        "AU-037",
        "Plaintext credential exposure",
        Severity::Critical,
        format!(
            "{} exposed in breach/stealer data — the affected identity's secret(s) are directly recoverable",
            parts.join(" and ")
        ),
        uids,
        scan_id,
        ts,
    )]
}

/// AU-043 — the subject's data appears in one or more public pastes (`psbdmp`):
/// a public-exposure signal that corroborates breach findings. `Medium`. One
/// grouped firing over all paste URLs.
pub(in crate::core::correlator) fn rule_au_043_paste_exposure(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    let pastes: Vec<&Entity> = entities
        .iter()
        .filter(|e| e.kind == EntityKind::Url && e.has_tag(crate::core::tags::PASTE_EXPOSED))
        .collect();
    if pastes.is_empty() {
        return Vec::new();
    }
    let uids: Vec<String> = pastes.iter().map(|e| e.uid.clone()).collect();
    vec![Correlation::new(
        "AU-043",
        "Public paste exposure",
        Severity::Medium,
        format!("Subject data found in {} public paste(s)", pastes.len()),
        uids,
        scan_id,
        ts,
    )]
}
