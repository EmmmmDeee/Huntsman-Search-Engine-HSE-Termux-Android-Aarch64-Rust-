//! AU correlation rules — identity cluster and cross-source corroboration family.
//! See `super::super` (rules/mod.rs) for the shared helpers; all reach them via
//! `use super::*` → `identity/mod.rs` → `use super::*` → `rules/mod.rs`.

use super::*;

/// True when a Username value is a usable identity anchor: long enough and not a
/// generic / role / extraction-noise token. Mirrors the AU-034 handle gate
/// (`account.rs`) so the whole identity-cluster family treats junk handles
/// (`from`, `dns`, role mailboxes) consistently — they must never seed a
/// "confirmed identity" correlation. A live person-scan fired AU-045 on `from`
/// and `dns` (mis-extracted as usernames, "confirmed" across two source
/// families); those are parser artifacts, not aliases.
fn is_anchorable_handle(value: &str) -> bool {
    const MIN_HANDLE_LEN: usize = 4;
    let handle = canonical_handle(value);
    handle.len() >= MIN_HANDLE_LEN && !is_generic_handle(&handle)
}

pub(in crate::core::correlator) fn rule_au_002_identity_cluster(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    // A confidence floor on top of the upstream candidate-exclusion: a genuine
    // identity cluster is built from corroborated entities, not weak guesses.
    const MIN_CONF: f64 = 0.50;
    // One person does not own dozens of distinct emails or phones — that many
    // is the signature of a breach dump spanning many people. Refuse to fuse it
    // into a CRITICAL "one identity" correlation (the exact failure that fused
    // 179 strangers from a name search). Candidate-exclusion makes this rare;
    // this is the backstop for any non-candidate bulk source.
    const MAX_PER_KIND: usize = 25;
    let of_kind = |k| -> Vec<&Entity> {
        entities_of_kind(entities, k)
            .into_iter()
            .filter(|e| e.confidence >= MIN_CONF)
            .collect()
    };
    let emails = of_kind(EntityKind::Email);
    let usernames = of_kind(EntityKind::Username);
    let phones = of_kind(EntityKind::Phone);

    if emails.is_empty() || usernames.is_empty() || phones.is_empty() {
        return Vec::new();
    }
    if emails.len() > MAX_PER_KIND || usernames.len() > MAX_PER_KIND || phones.len() > MAX_PER_KIND
    {
        return Vec::new();
    }

    let mut uids: Vec<String> = emails.iter().map(|e| e.uid.clone()).collect();
    uids.extend(usernames.iter().map(|e| e.uid.clone()));
    uids.extend(phones.iter().map(|e| e.uid.clone()));

    vec![Correlation {
        rule_id: "AU-002".into(),
        rule_name: "Identity cluster".into(),
        severity: Severity::Critical,
        description: format!(
            "Email + Username + Phone co-located: {} email(s), {} username(s), {} phone(s)",
            emails.len(),
            usernames.len(),
            phones.len()
        ),
        entity_uids: uids,
        scan_id: scan_id.into(),
        ts,
        rank: 0.0,
    }]
}

/// AU-045 — Multi-service identity confirmation.
///
/// An identity value (email / username / person) whose corroborating sources
/// span **two or more distinct service families** (breach, social, presence,
/// search, email-intel, identity-registry, infra) is independently confirmed
/// across the system, not merely echoed by one kind of provider. This is the
/// strongest honest signal for an alias investigation and the explicit
/// cross-service cross-reference the operator program asks for: it differs from
/// AU-003 (which counts distinct sources regardless of kind) by requiring
/// *diversity of provider family* — a handle confirmed by GitHub AND a breach DB
/// AND a search engine is far stronger evidence of a real identity than three
/// breach DBs that may all quote one leaked record. Directly counters the
/// single-source fragility a result-matrix analysis surfaced: it rewards genuine
/// cross-provider agreement and makes it a first-class, ranked finding.
pub(in crate::core::correlator) fn rule_au_045_multi_service_identity(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    use std::collections::BTreeSet;
    const MIN_FAMILIES: usize = 2;
    entities
        .iter()
        .filter(|e| match e.kind {
            // Only a real handle anchors an identity. Junk handles (`from`,
            // `dns`) and role desks (`abuse@…`) are confirmed across families as
            // a matter of course and must not be promoted to "confirmed
            // identity" — the exact false signal a live person-scan produced.
            EntityKind::Username => is_anchorable_handle(&e.value),
            EntityKind::Email => !crate::core::validation::is_role_mailbox(&e.value),
            EntityKind::Person => true,
            _ => false,
        })
        .filter_map(|e| {
            // Distinct provider families across this entity's corroborating
            // sources, ignoring the unclassified `other` bucket so a stray
            // unknown source can't fabricate diversity.
            let families: BTreeSet<&'static str> = e
                .corroborating_sources()
                .iter()
                .map(|s| source_family(s))
                .filter(|f| *f != "other")
                .collect();
            if families.len() < MIN_FAMILIES {
                return None;
            }
            let listed: Vec<&str> = families.iter().copied().collect();
            Some(Correlation {
                rule_id: "AU-045".into(),
                rule_name: "Multi-service identity confirmation".into(),
                severity: Severity::High,
                description: format!(
                    "{} '{}' independently confirmed across {} service families: {}",
                    e.kind,
                    e.value,
                    listed.len(),
                    listed.join(", ")
                ),
                entity_uids: vec![e.uid.clone()],
                scan_id: scan_id.into(),
                ts,
                rank: 0.0,
            })
        })
        .collect()
}

/// AU-046 — Cross-platform identity resolution.
///
/// The investigative payoff of the keyless account modules: when an alias
/// (a Username confirmed across **≥2 distinct platform families** — code/forum/
/// social/presence) has also yielded real-world identifiers (an Email or Person)
/// *from those platform accounts*, the handle is no longer just "present on N
/// sites" — it is **resolved to an identity**. This links the alias to the
/// email(s)/person(s) its GitHub/npm/Reddit/Keybase profiles expose, producing
/// the individualised, subject-as-hub result an alias investigation is for.
///
/// Distinct from AU-045 (which only confirms the handle exists across families)
/// and AU-002 (which needs email+username+phone all present): AU-046 is the
/// *handle → identity* edge, drawn only from identifiers a platform account
/// itself published, so it can't fuse unrelated breach-dump strangers.
pub(in crate::core::correlator) fn rule_au_046_cross_platform_identity_resolution(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    use std::collections::BTreeSet;
    // Platform-account provider families — the ones where a confirmed handle is
    // an account a person controls (not infra/breach corpora).
    let is_platform = |f: &str| matches!(f, "code" | "forum" | "social" | "presence");
    let platform_families = |e: &Entity| -> BTreeSet<&'static str> {
        e.corroborating_sources()
            .iter()
            .map(|s| source_family(s))
            .filter(|f| is_platform(f))
            .collect()
    };

    // The alias: a username controlled across ≥2 distinct platform families.
    // Compute each alias's family set ONCE here and carry it forward, rather
    // than recomputing `platform_families` (a full corroborating-sources scan)
    // a second time in the emit loop below.
    let aliases: Vec<(&Entity, BTreeSet<&'static str>)> = entities
        .iter()
        .filter(|e| e.kind == EntityKind::Username && is_anchorable_handle(&e.value))
        .filter_map(|e| {
            let fams = platform_families(e);
            (fams.len() >= 2).then_some((e, fams))
        })
        .collect();
    if aliases.is_empty() {
        return Vec::new();
    }

    // Real-world identifiers the platform accounts themselves exposed, each
    // carried with the PLATFORM sources that published it. Pairing on shared
    // source is what makes the resolution per-alias rather than global: only an
    // account that exposed BOTH the handle and the identifier links them.
    fn platform_sources(e: &Entity) -> BTreeSet<&str> {
        e.corroborating_sources()
            .into_iter()
            .filter(|&s| matches!(source_family(s), "code" | "forum" | "social" | "presence"))
            .collect()
    }
    let resolved: Vec<(&Entity, BTreeSet<&str>)> = entities
        .iter()
        .filter(|e| matches!(e.kind, EntityKind::Email | EntityKind::Person))
        .filter_map(|e| {
            let srcs = platform_sources(e);
            (!srcs.is_empty()).then_some((e, srcs))
        })
        .collect();
    if resolved.is_empty() {
        return Vec::new();
    }

    aliases
        .iter()
        .filter_map(|(alias, fams)| {
            // Link ONLY to identifiers that share a publishing source with THIS
            // alias — the same platform account exposed both. A platform-sourced
            // identifier with no shared account is an unrelated stranger and is
            // not fused. (Fixes the prior behaviour, which extended EVERY
            // platform-sourced identifier onto EVERY alias, regardless of account
            // — the exact fusion this rule's doc promises it avoids.)
            let alias_srcs = platform_sources(alias);
            let linked: Vec<&Entity> = resolved
                .iter()
                .filter(|(_, srcs)| !srcs.is_disjoint(&alias_srcs))
                .map(|(e, _)| *e)
                .collect();
            if linked.is_empty() {
                return None;
            }
            let fam_list: Vec<&str> = fams.iter().copied().collect();
            let mut uids = vec![alias.uid.clone()];
            uids.extend(linked.iter().map(|e| e.uid.clone()));
            Some(Correlation {
                rule_id: "AU-046".into(),
                rule_name: "Cross-platform identity resolution".into(),
                severity: Severity::High,
                description: format!(
                    "Alias '{}' (confirmed across {}: {}) resolves to {} real-world identifier(s) its platform accounts published",
                    alias.value,
                    fam_list.len(),
                    fam_list.join(", "),
                    linked.len()
                ),
                entity_uids: uids,
                scan_id: scan_id.into(),
                ts,
                rank: 0.0,
            })
        })
        .collect()
}

pub(in crate::core::correlator) fn rule_au_003_high_corroboration(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    // Thresholds are on DISTINCT corroborating sources (source_count), not the
    // summed observation-magnitude field. Calibrated for real distinct-source
    // counts: infra entities (domain/url/ip) reach high agreement easily across
    // resolver/cert/whois/geo modules, so they need 3; identity entities
    // (email/person/username/phone) are strong at 2 distinct independent
    // sources. The old thresholds (5/4/3) were tuned to the inflated summed
    // counter and effectively never fired on honest distinct-source counts.
    let min_sources = |kind: &crate::core::entity::EntityKind| -> u32 {
        match kind {
            EntityKind::Domain | EntityKind::Url | EntityKind::IpAddress => 3,
            _ => 2,
        }
    };
    entities
        .iter()
        .filter_map(|e| {
            // Compute the distinct-source count ONCE and reuse it for the gate,
            // the message, AND the C_eff. `source_count()` re-scans the whole
            // evidence chain (O(k²)) on every call; the prior form paid for it
            // twice — the explicit count here plus a second scan inside
            // `c_effective()` — so the C_eff now flows through
            // `c_effective_with_source_count(sources)` to keep it to one scan.
            let sources = e.source_count();
            if sources < min_sources(&e.kind) {
                return None;
            }
            Some(Correlation {
                rule_id: "AU-003".into(),
                rule_name: "High cross-source corroboration".into(),
                severity: Severity::Medium,
                description: format!(
                    "{} entity '{}' corroborated by {} independent source(s) (C_eff={:.3})",
                    e.kind,
                    e.value,
                    sources,
                    e.c_effective_with_source_count(sources)
                ),
                entity_uids: vec![e.uid.clone()],
                scan_id: scan_id.into(),
                ts,
                rank: 0.0,
            })
        })
        .collect()
}

pub(in crate::core::correlator) fn rule_au_020_person_entity_cluster(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    let persons: Vec<&Entity> = entities_of_kind(entities, EntityKind::Person)
        .into_iter()
        .filter(|e| e.confidence >= 0.50)
        .collect();
    if persons.len() < 2 {
        return Vec::new();
    }
    let uids: Vec<String> = persons.iter().map(|e| e.uid.clone()).collect();
    vec![Correlation::new(
        "AU-020",
        "Multiple person entities",
        Severity::Medium,
        format!(
            "{} person entities discovered — potential identity disambiguation needed",
            persons.len()
        ),
        uids,
        scan_id,
        ts,
    )]
}

pub(in crate::core::correlator) fn rule_au_023_cross_platform_identity(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    const IDENTITY_SOURCES: &[&str] = &[
        "keybase",
        "github_user",
        "proxycurl",
        "epieos",
        "seon",
        "contact_enrich",
    ];
    let mut out = Vec::new();
    for e in entities_of_kind(entities, EntityKind::Person)
        .into_iter()
        .filter(|e| e.confidence >= 0.60)
    {
        let sources = tagged_matching_sources(e, IDENTITY_SOURCES);
        if sources.len() >= 2 {
            let mut names: Vec<&str> = sources.into_iter().collect();
            names.sort_unstable();
            out.push(Correlation::new(
                "AU-023",
                "Cross-platform identity convergence",
                Severity::High,
                format!(
                    "Person '{}' confirmed by {} independent identity source(s): {}",
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
