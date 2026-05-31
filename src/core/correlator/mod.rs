// Correlator — rule-based cross-correlation analysis.
//
// Two entry points share the same deterministic rule set:
//
//   * [`Correlator::run`] — the authoritative finalise-time pass. Loads the
//     scan's persisted entities *and* the typed relation edges, evaluates
//     both the entity rules and the graph-aware relation rules, and persists
//     every firing.
//   * [`correlate_entities`] — a live, in-memory pass the engine invokes
//     during ingestion (after the seed round and after each expansion round)
//     so high-confidence correlations stream out as the graph grows rather
//     than only after the scan finishes. Entity rules only — relation rules
//     need the persisted edge set, so they stay in `run`.
//
// Each firing rule produces a [`Correlation`] record persisted alongside the
// scan and emitted on the event bus. Rules are deterministic — no LLMs,
// no fuzzy matching.

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tracing::debug;

use crate::core::entity::Entity;
use crate::core::error::Result;
use crate::core::port::StoragePort;
use crate::core::relation::Relation;

// ─── Severity ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_canonical(&self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }

    /// Ordinal weight for ranking. Higher = more severe. Used as the severity
    /// factor in a correlation's rank score (`weight × max child C_eff`).
    pub fn weight(&self) -> f64 {
        match self {
            Self::Low => 1.0,
            Self::Medium => 2.0,
            Self::High => 3.0,
            Self::Critical => 4.0,
        }
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Low => write!(f, "LOW"),
            Self::Medium => write!(f, "MEDIUM"),
            Self::High => write!(f, "HIGH"),
            Self::Critical => write!(f, "CRITICAL"),
        }
    }
}

// ─── Correlation ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Correlation {
    pub rule_id: String,
    pub rule_name: String,
    pub severity: Severity,
    pub description: String,
    pub entity_uids: Vec<String>,
    pub scan_id: String,
    pub ts: u64,
    /// Ranking score = `severity.weight() × max(C_eff)` over the child
    /// entities. Computed once in `Correlator::run` after the rules fire (the
    /// rules themselves don't have the entity C_eff map handy) and used to
    /// order the Correlations view highest-value-first. `#[serde(default)]`
    /// keeps correlation rows persisted before this field existed readable
    /// (they deserialize with rank 0.0 and simply sort last).
    #[serde(default)]
    pub rank: f64,
}

/// Compute `severity.weight() × max(C_eff)` over the child entities of each
/// correlation, write it into `rank`, and sort the slice rank-descending with
/// a stable severity/rule_id tie-break. Shared by both the finalize pass
/// (`Correlator::run`) and the live incremental pass (engine) so a correlation
/// carries the same rank whether it was streamed mid-scan or produced at the
/// end. `ceff` maps entity uid → c_effective().
pub fn rank_and_sort(corrs: &mut [Correlation], ceff: &std::collections::HashMap<String, f64>) {
    for c in corrs.iter_mut() {
        let max_child = c
            .entity_uids
            .iter()
            .filter_map(|uid| ceff.get(uid).copied())
            .fold(0.0_f64, f64::max);
        c.rank = c.severity.weight() * max_child;
    }
    corrs.sort_by(|a, b| {
        b.rank
            .partial_cmp(&a.rank)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then(b.severity.cmp(&a.severity))
            .then(a.rule_id.cmp(&b.rule_id))
    });
}

impl Correlation {
    pub(crate) fn new(
        rule_id: &str,
        rule_name: &str,
        severity: Severity,
        description: String,
        entity_uids: Vec<String>,
        scan_id: &str,
        ts: u64,
    ) -> Self {
        Self {
            rule_id: rule_id.into(),
            rule_name: rule_name.into(),
            severity,
            description,
            entity_uids,
            scan_id: scan_id.into(),
            ts,
            rank: 0.0,
        }
    }
}

// ─── Correlator ────────────────────────────────────────────────────────────

pub struct Correlator {
    store: Arc<dyn StoragePort>,
}

impl Correlator {
    pub fn new(store: Arc<dyn StoragePort>) -> Self {
        Self { store }
    }

    pub fn run(&self, scan_id: &str) -> Result<Vec<Correlation>> {
        let entities = self.store.entities_for_scan(scan_id)?;
        if entities.is_empty() {
            return Ok(Vec::new());
        }
        let mut firings = evaluate_rules(&entities, scan_id);

        // Graph-aware pass: rules that need the typed relation edges (the
        // attribution graph), not just the flat entity list. Relations are
        // persisted by `finalise_scan` before the correlator runs.
        let relations = self.store.relations_for_scan(scan_id)?;
        if !relations.is_empty() {
            let now = crate::core::entity::unix_now();
            firings.extend(evaluate_relation_rules(&entities, &relations, scan_id, now));
        }

        // Rank each firing by severity × highest child C_eff and sort
        // (shared with the live incremental pass so ranks are consistent).
        let ceff: std::collections::HashMap<String, f64> = entities
            .iter()
            .map(|e| (e.uid.clone(), e.c_effective()))
            .collect();
        rank_and_sort(&mut firings, &ceff);

        for c in &firings {
            self.store.upsert_correlation(c)?;
        }
        debug!(scan_id, fired = firings.len(), "correlator done");
        Ok(firings)
    }
}

// ─── Rules ─────────────────────────────────────────────────────────────────

type RuleFn = fn(&[Entity], &str, u64) -> Vec<Correlation>;

mod rules;
use rules::*;

const RULES: &[RuleFn] = &[
    rule_au_001_multi_breach,
    rule_au_002_identity_cluster,
    rule_au_003_high_corroboration,
    rule_au_004_malicious_infrastructure,
    rule_au_005_anonymous_network,
    rule_au_006_proxy_vpn,
    rule_au_007_high_risk_reputation,
    rule_au_008_exposed_service,
    rule_au_009_stealer_log,
    rule_au_010_infra_consensus,
    rule_au_011_cross_platform_username,
    rule_au_012_identity_linked_domain,
    rule_au_013_local_network_discovery,
    rule_au_014_geo_cluster,
    rule_au_015_threat_intel_hit,
    rule_au_016_breach_ip_geo_chain,
    rule_au_017_multi_geo_convergence,
    rule_au_018_email_address_colocation,
    rule_au_019_temporal_breach_cluster,
    rule_au_020_person_entity_cluster,
    rule_au_021_api_key_exposure,
    rule_au_022_organisation_with_breach,
    rule_au_023_cross_platform_identity,
    rule_au_024_email_fraud_signal,
    rule_au_025_corporate_identity_link,
    rule_au_026_validated_address,
    rule_au_027_address_coordinates_chain,
    rule_au_028_subdomain_takeover_risk,
    rule_au_029_cloud_storage_exposure,
    rule_au_030_geo_convergence_score,
    rule_au_033_abn_organisation_link,
];

fn evaluate_rules(entities: &[Entity], scan_id: &str) -> Vec<Correlation> {
    let now = crate::core::entity::unix_now();
    let mut out = Vec::new();
    for rule in RULES {
        out.extend(rule(entities, scan_id, now));
    }
    out
}

/// Evaluate the entity-only rules against an in-memory entity slice.
///
/// This is the live-ingestion entry point: the engine calls it against the
/// working entity map after each dispatch round so correlations stream out
/// during the scan, with no store round-trip. The graph-aware relation rules
/// are intentionally excluded here — they need the persisted edge set, which
/// only exists once [`Correlator::run`] derives it at finalise.
pub(crate) fn correlate_entities(entities: &[Entity], scan_id: &str) -> Vec<Correlation> {
    evaluate_rules(entities, scan_id)
}

// ─── Graph-aware rules ───────────────────────────────────────────────────────
// Rules that consume the typed `Relation` edge set in addition to entities.
// Kept separate from `RULES` so the 30 entity-only rules need no signature
// change.

type RelationRuleFn = fn(&[Entity], &[Relation], &str, u64) -> Vec<Correlation>;

const RELATION_RULES: &[RelationRuleFn] = &[
    rule_au_031_malicious_adjacency,
    rule_au_032_colocation_cluster,
];

fn evaluate_relation_rules(
    entities: &[Entity],
    relations: &[Relation],
    scan_id: &str,
    now: u64,
) -> Vec<Correlation> {
    let mut out = Vec::new();
    for rule in RELATION_RULES {
        out.extend(rule(entities, relations, scan_id, now));
    }
    out
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;
    use crate::core::entity::{Entity, EntityKind, Evidence};

    // ── Severity::as_canonical ──────────────────────────────────────────

    #[test]
    fn as_canonical_returns_lowercase() {
        assert_eq!(Severity::Low.as_canonical(), "low");
        assert_eq!(Severity::Medium.as_canonical(), "medium");
        assert_eq!(Severity::High.as_canonical(), "high");
        assert_eq!(Severity::Critical.as_canonical(), "critical");
    }

    // ── Severity::weight + rank ordering ────────────────────────────────

    #[test]
    fn severity_weight_is_monotonic() {
        assert!(Severity::Low.weight() < Severity::Medium.weight());
        assert!(Severity::Medium.weight() < Severity::High.weight());
        assert!(Severity::High.weight() < Severity::Critical.weight());
    }

    #[test]
    fn run_ranks_by_severity_times_max_child_ceff() {
        use crate::core::test_support::InMemoryStore;
        use std::sync::Arc;

        // Build a scan where:
        //  - a HIGH-severity rule will fire over a strongly-corroborated entity
        //    (high C_eff), and
        //  - a CRITICAL-severity rule will fire over a weakly-corroborated one
        //    (low C_eff),
        // so that severity-alone ordering (critical first) and
        // severity×C_eff ordering disagree — proving the rank is C_eff-scaled.
        //
        // AU-021 (API key exposure) is Critical and fires on any ApiKey entity.
        // AU-003 (cross-source corroboration) is Medium and fires on an entity
        // with >=2 distinct sources. We give the ApiKey a LOW C_eff (single
        // source, low base confidence) and the corroborated email a HIGH C_eff
        // (3 distinct sources, high base confidence). The Medium hit on the
        // high-C_eff entity must outrank the Critical hit on the low-C_eff one
        // once C_eff dominates the severity gap.
        let store: Arc<dyn StoragePort> = Arc::new(InMemoryStore::new());
        let sid = "rank-test";

        let mut weak_key = Entity::new(EntityKind::ApiKey, "AKIAWEAK", 0.20, sid);
        weak_key.add_evidence(Evidence::new("key_harvest", "found once"));

        let mut strong_email = Entity::new(EntityKind::Email, "a@b.com", 0.95, sid);
        for src in ["hibp", "dehashed", "search_engines"] {
            strong_email.add_evidence(Evidence::new(src, "seen"));
        }

        store.upsert_entity(&weak_key).unwrap();
        store.upsert_entity(&strong_email).unwrap();

        let corr = Correlator::new(Arc::clone(&store));
        let hits = corr.run(sid).unwrap();

        // Both rules fired.
        let key_hit = hits.iter().find(|c| c.rule_id == "AU-021").unwrap();
        let email_hit = hits.iter().find(|c| c.rule_id == "AU-003").unwrap();

        // Critical×low-C_eff vs Medium×high-C_eff: 4×~0.20 = 0.8 vs 2×~0.99 ≈ 1.98.
        assert!(
            email_hit.rank > key_hit.rank,
            "C_eff-scaled rank must put the strongly-corroborated Medium hit \
             (rank {:.3}) above the weak Critical hit (rank {:.3})",
            email_hit.rank,
            key_hit.rank,
        );
        // And the returned Vec is sorted by rank desc.
        assert!(
            hits.windows(2).all(|w| w[0].rank >= w[1].rank),
            "correlations must be returned in rank-descending order"
        );
        // Rank is severity.weight × max child C_eff (sanity on the key hit).
        let expected_key_rank = Severity::Critical.weight() * weak_key.c_effective();
        assert!((key_hit.rank - expected_key_rank).abs() < 1e-9);
    }

    // ── Severity Display ────────────────────────────────────────────────

    #[test]
    fn display_returns_uppercase() {
        assert_eq!(Severity::Low.to_string(), "LOW");
        assert_eq!(Severity::Medium.to_string(), "MEDIUM");
        assert_eq!(Severity::High.to_string(), "HIGH");
        assert_eq!(Severity::Critical.to_string(), "CRITICAL");
    }

    // ── Severity ordering ───────────────────────────────────────────────

    #[test]
    fn severity_ordering() {
        assert!(Severity::Low < Severity::Medium);
        assert!(Severity::Medium < Severity::High);
        assert!(Severity::High < Severity::Critical);
    }

    // ── Severity serde ──────────────────────────────────────────────────

    #[test]
    fn severity_json_round_trip() {
        for (variant, expected_str) in [
            (Severity::Low, "\"low\""),
            (Severity::Medium, "\"medium\""),
            (Severity::High, "\"high\""),
            (Severity::Critical, "\"critical\""),
        ] {
            let json = serde_json::to_string(&variant).unwrap();
            assert_eq!(json, expected_str);
            let back: Severity = serde_json::from_str(&json).unwrap();
            assert_eq!(back, variant);
        }
    }

    // ── Correlation::new ────────────────────────────────────────────────

    #[test]
    fn correlation_new_sets_all_fields() {
        let uids = vec!["uid-a".to_string(), "uid-b".to_string()];
        let c = Correlation::new(
            "R001",
            "test rule",
            Severity::High,
            "something suspicious".to_string(),
            uids.clone(),
            "scan-1",
            1700000000,
        );

        assert_eq!(c.rule_id, "R001");
        assert_eq!(c.rule_name, "test rule");
        assert_eq!(c.severity, Severity::High);
        assert_eq!(c.description, "something suspicious");
        assert_eq!(c.entity_uids, uids);
        assert_eq!(c.scan_id, "scan-1");
        assert_eq!(c.ts, 1700000000);
    }

    // ── Correlation serde round-trip ────────────────────────────────────

    #[test]
    fn correlation_json_round_trip() {
        let original = Correlation::new(
            "R002",
            "exposed creds",
            Severity::Critical,
            "credentials found in breach db".to_string(),
            vec!["uid-x".to_string()],
            "scan-99",
            1700000001,
        );

        let json = serde_json::to_string(&original).unwrap();
        let back: Correlation = serde_json::from_str(&json).unwrap();

        assert_eq!(back.rule_id, original.rule_id);
        assert_eq!(back.rule_name, original.rule_name);
        assert_eq!(back.severity, original.severity);
        assert_eq!(back.description, original.description);
        assert_eq!(back.entity_uids, original.entity_uids);
        assert_eq!(back.scan_id, original.scan_id);
        assert_eq!(back.ts, original.ts);
    }

    // ── Rule test helpers ───────────────────────────────────────────────

    fn email(value: &str, sources: &[&str]) -> Entity {
        let mut e = Entity::new(EntityKind::Email, value, 0.9, "scan-test");
        for src in sources {
            e.add_evidence(Evidence::new(*src, "test"));
        }
        e
    }

    fn domain(value: &str, sources: &[&str]) -> Entity {
        let mut e = Entity::new(EntityKind::Domain, value, 0.9, "scan-test");
        for src in sources {
            e.add_evidence(Evidence::new(*src, "test"));
        }
        e
    }

    #[test]
    fn au033_links_abn_to_registry_organisation() {
        let entities = vec![
            tagged(EntityKind::AbnAcn, "51824753556", &["abr"]),
            tagged(
                EntityKind::Organisation,
                "Example Pty Ltd",
                &["abr", "australian"],
            ),
        ];
        let r = rule_au_033_abn_organisation_link(&entities, "scan-test", 0);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].rule_id, "AU-033");
        assert_eq!(r[0].entity_uids.len(), 2);
    }

    #[test]
    fn au033_no_fire_without_registry_org_or_abn() {
        // ABN + a non-registry Organisation (e.g. a search_engines org name)
        // must NOT link — avoids joining unrelated company names.
        let mixed = vec![
            tagged(EntityKind::AbnAcn, "51824753556", &["abr"]),
            Entity::new(EntityKind::Organisation, "Some Other Co", 0.9, "scan-test"),
        ];
        assert!(rule_au_033_abn_organisation_link(&mixed, "scan-test", 0).is_empty());
        // A registry org with no ABN present also does not fire.
        let only_org = vec![tagged(
            EntityKind::Organisation,
            "Example Pty Ltd",
            &["opencorporates"],
        )];
        assert!(rule_au_033_abn_organisation_link(&only_org, "scan-test", 0).is_empty());
    }

    fn tagged(kind: EntityKind, value: &str, tags: &[&str]) -> Entity {
        let mut e = Entity::new(kind, value, 0.9, "scan-test");
        for t in tags {
            e.tag(*t);
        }
        e
    }

    fn username_summary(value: &str, count: u64, platforms: &str) -> Entity {
        let mut e = Entity::new(EntityKind::Username, value, 0.95, "scan-test");
        e.tag("multi-platform");
        e.add_evidence(
            Evidence::new("username_search", "summary")
                .with_attr("platforms_count", count.to_string())
                .with_attr("platforms", platforms),
        );
        e
    }

    // ── AU-001 ──────────────────────────────────────────────────────────

    #[test]
    fn au001_fires_at_two_breach_sources() {
        let e = email("x@y.com", &["hudsonrock", "breach_directory"]);
        let r = rule_au_001_multi_breach(&[e], "s1", 0);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].rule_id, "AU-001");
        assert_eq!(r[0].severity, Severity::Critical);
    }

    #[test]
    fn au001_no_fire_at_one_source() {
        let e = email("x@y.com", &["hudsonrock"]);
        assert!(rule_au_001_multi_breach(&[e], "s1", 0).is_empty());
    }

    #[test]
    fn au001_ignores_non_breach_sources() {
        let e = email("x@y.com", &["crtsh", "dns_resolver"]);
        assert!(rule_au_001_multi_breach(&[e], "s1", 0).is_empty());
    }

    // ── AU-002 ──────────────────────────────────────────────────────────

    #[test]
    fn au002_fires_with_all_three_kinds() {
        let entities = vec![
            Entity::new(EntityKind::Email, "x@y.com", 0.9, "s"),
            Entity::new(EntityKind::Username, "xuser", 0.8, "s"),
            Entity::new(EntityKind::Phone, "+61400000000", 0.8, "s"),
        ];
        let r = rule_au_002_identity_cluster(&entities, "s", 0);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].rule_id, "AU-002");
        assert_eq!(r[0].entity_uids.len(), 3);
    }

    #[test]
    fn au002_no_fire_missing_kind() {
        let entities = vec![
            Entity::new(EntityKind::Email, "x@y.com", 0.9, "s"),
            Entity::new(EntityKind::Username, "xuser", 0.8, "s"),
        ];
        assert!(rule_au_002_identity_cluster(&entities, "s", 0).is_empty());
    }

    // ── AU-003 ──────────────────────────────────────────────────────────

    #[test]
    fn au003_fires_at_kind_specific_thresholds() {
        // Thresholds are now on DISTINCT sources: identity (email) >= 2,
        // infra (domain) >= 3. These fixtures set corroboration with no
        // evidence, so source_count() falls back to the field value.
        let mut email = Entity::new(EntityKind::Email, "x@y.com", 0.9, "s");
        email.corroboration = 2;
        let r = rule_au_003_high_corroboration(&[email], "s", 0);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].rule_id, "AU-003");
        assert!(
            r[0].description.contains("2 independent source"),
            "description must report the true distinct-source count: {}",
            r[0].description
        );

        let mut domain = Entity::new(EntityKind::Domain, "x.com", 0.9, "s");
        domain.corroboration = 3;
        let r = rule_au_003_high_corroboration(&[domain], "s", 0);
        assert_eq!(r.len(), 1);
    }

    #[test]
    fn au003_no_fire_below_threshold() {
        // Email below 2 distinct sources, domain below 3 → no fire.
        let mut e = Entity::new(EntityKind::Email, "x@y.com", 0.9, "s");
        e.corroboration = 1;
        assert!(rule_au_003_high_corroboration(&[e], "s", 0).is_empty());

        let mut d = Entity::new(EntityKind::Domain, "x.com", 0.9, "s");
        d.corroboration = 2;
        assert!(rule_au_003_high_corroboration(&[d], "s", 0).is_empty());
    }

    #[test]
    fn au003_uses_distinct_sources_not_summed_corroboration() {
        // THE FIX in correlator terms: an email with summed corroboration=8
        // but only 1 distinct evidence source must NOT fire AU-003 (it is not
        // cross-corroborated), and an email with 2 distinct sources must fire
        // regardless of the summed field.
        let mut single = Entity::new(EntityKind::Email, "a@b.com", 0.9, "s");
        single.corroboration = 8;
        single.add_evidence(crate::core::entity::Evidence::new("oathnet_pro", "8 rows"));
        assert!(
            rule_au_003_high_corroboration(&[single], "s", 0).is_empty(),
            "single-source entity must not fire AU-003 despite inflated corroboration"
        );

        let mut multi = Entity::new(EntityKind::Email, "a@b.com", 0.9, "s");
        multi.corroboration = 2;
        multi.add_evidence(crate::core::entity::Evidence::new("hibp", "breach"));
        multi.add_evidence(crate::core::entity::Evidence::new("dehashed", "breach"));
        assert_eq!(
            rule_au_003_high_corroboration(&[multi], "s", 0).len(),
            1,
            "two distinct sources must fire AU-003"
        );
    }

    // ── AU-004 ──────────────────────────────────────────────────────────

    #[test]
    fn au004_fires_on_malicious_domain() {
        let e = tagged(EntityKind::Domain, "evil.example", &["malicious"]);
        let r = rule_au_004_malicious_infrastructure(&[e], "s", 0);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].severity, Severity::Critical);
    }

    #[test]
    fn au004_no_fire_without_tag() {
        let e = tagged(EntityKind::Domain, "ok.example", &[]);
        assert!(rule_au_004_malicious_infrastructure(&[e], "s", 0).is_empty());
    }

    // ── AU-005 ──────────────────────────────────────────────────────────

    #[test]
    fn au005_fires_on_tor_exit() {
        let e = tagged(EntityKind::IpAddress, "1.1.1.1", &["tor-exit"]);
        let r = rule_au_005_anonymous_network(&[e], "s", 0);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].severity, Severity::High);
    }

    // ── AU-006 ──────────────────────────────────────────────────────────

    #[test]
    fn au006_fires_on_vpn_but_not_tor() {
        let vpn_ip = tagged(EntityKind::IpAddress, "2.2.2.2", &["vpn"]);
        let tor_ip = tagged(EntityKind::IpAddress, "3.3.3.3", &["tor-exit", "vpn"]);
        let r = rule_au_006_proxy_vpn(&[vpn_ip, tor_ip], "s", 0);
        assert_eq!(r.len(), 1);
        assert!(r[0].description.contains("2.2.2.2"));
    }

    #[test]
    fn au006_excludes_all_anon_tags_not_just_tor_exit() {
        let tor_short = tagged(EntityKind::IpAddress, "4.4.4.4", &["tor", "vpn"]);
        let anon_net = tagged(
            EntityKind::IpAddress,
            "5.5.5.5",
            &["anonymous-network", "vpn"],
        );
        let anon_vpn = tagged(EntityKind::IpAddress, "6.6.6.6", &["anonymous-vpn", "vpn"]);
        assert!(rule_au_006_proxy_vpn(&[tor_short], "s", 0).is_empty());
        assert!(rule_au_006_proxy_vpn(&[anon_net], "s", 0).is_empty());
        assert!(rule_au_006_proxy_vpn(&[anon_vpn], "s", 0).is_empty());
    }

    // ── AU-007 ──────────────────────────────────────────────────────────

    #[test]
    fn au007_fires_on_high_risk() {
        let e = tagged(EntityKind::IpAddress, "4.4.4.4", &["high-risk", "scanner"]);
        let r = rule_au_007_high_risk_reputation(&[e], "s", 0);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].severity, Severity::High);
    }

    // ── AU-008 ──────────────────────────────────────────────────────────

    #[test]
    fn au008_fires_on_vulnerable_tag() {
        let e = tagged(EntityKind::Domain, "vuln.example", &["vulnerable"]);
        let r = rule_au_008_exposed_service(&[e], "s", 0);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].rule_id, "AU-008");
    }

    // ── AU-009 ──────────────────────────────────────────────────────────

    #[test]
    fn au009_fires_on_stealer_log() {
        let e = tagged(EntityKind::Email, "x@y.com", &["stealer-log"]);
        let r = rule_au_009_stealer_log(&[e], "s", 0);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].severity, Severity::High);
    }

    // ── AU-010 ──────────────────────────────────────────────────────────

    #[test]
    fn au010_fires_at_three_sources_on_domain() {
        let e = domain("x.com", &["crtsh", "dns_resolver", "hudsonrock"]);
        let r = rule_au_010_infra_consensus(&[e], "s", 0);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].rule_id, "AU-010");
    }

    #[test]
    fn au010_no_fire_at_two_sources() {
        let e = domain("x.com", &["crtsh", "dns_resolver"]);
        assert!(rule_au_010_infra_consensus(&[e], "s", 0).is_empty());
    }

    #[test]
    fn au010_ignores_non_infrastructure_kinds() {
        let e = email("x@y.com", &["a", "b", "c"]);
        assert!(rule_au_010_infra_consensus(&[e], "s", 0).is_empty());
    }

    // ── AU-011 ──────────────────────────────────────────────────────────

    #[test]
    fn au011_fires_on_three_platforms() {
        let e = username_summary("alice", 3, "github, reddit, twitter");
        let r = rule_au_011_cross_platform_username(&[e], "s", 0);
        assert_eq!(r.len(), 1);
        assert!(r[0].description.contains("3 platforms"));
        assert!(r[0].description.contains("github"));
    }

    #[test]
    fn au011_no_fire_on_two_platforms() {
        let e = username_summary("alice", 2, "github, reddit");
        assert!(rule_au_011_cross_platform_username(&[e], "s", 0).is_empty());
    }

    // ── AU-012 ──────────────────────────────────────────────────────────

    #[test]
    fn au012_fires_when_username_and_personal_site_url_present() {
        let entities = vec![
            tagged(EntityKind::Username, "alice", &[]),
            tagged(
                EntityKind::Url,
                "https://alice.example/",
                &["personal-site"],
            ),
        ];
        let r = rule_au_012_identity_linked_domain(&entities, "s", 0);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].entity_uids.len(), 2);
        assert!(r[0].description.contains("co-occurs"));
    }

    #[test]
    fn au012_also_fires_on_personal_site_domain() {
        let entities = vec![
            tagged(EntityKind::Username, "alice", &[]),
            tagged(EntityKind::Domain, "alice.example", &["personal-site"]),
        ];
        let r = rule_au_012_identity_linked_domain(&entities, "s", 0);
        assert_eq!(r.len(), 1);
    }

    #[test]
    fn au012_no_fire_without_username() {
        let entities = vec![tagged(
            EntityKind::Url,
            "https://alice.example/",
            &["personal-site"],
        )];
        assert!(rule_au_012_identity_linked_domain(&entities, "s", 0).is_empty());
    }

    // ── AU-013 ──────────────────────────────────────────────────────────

    #[test]
    fn au013_fires_on_two_lan_entities() {
        let entities = vec![
            tagged(EntityKind::IpAddress, "192.168.1.1", &["local-arp"]),
            tagged(EntityKind::MacAddress, "aa:bb:cc:dd:ee:ff", &["local-arp"]),
        ];
        let r = rule_au_013_local_network_discovery(&entities, "s", 0);
        assert_eq!(r.len(), 1);
    }

    #[test]
    fn au013_no_fire_on_one_lan_entity() {
        let entities = vec![tagged(EntityKind::IpAddress, "192.168.1.1", &["local-arp"])];
        assert!(rule_au_013_local_network_discovery(&entities, "s", 0).is_empty());
    }

    // ── AU-014 ──────────────────────────────────────────────────────────

    #[test]
    fn au014_fires_on_two_geo_sources() {
        let mut e = Entity::new(EntityKind::Coordinates, "0,0", 0.9, "s");
        e.add_evidence(Evidence::new("wigle", "test"));
        e.add_evidence(Evidence::new("device_sensors", "test"));
        let r = rule_au_014_geo_cluster(&[e], "s", 0);
        assert_eq!(r.len(), 1);
    }

    // ── AU-015 ──────────────────────────────────────────────────────────

    #[test]
    fn au015_fires_on_threat_intel_tag() {
        let e = tagged(
            EntityKind::Domain,
            "bad.example",
            &["threat-intel", "ti:malware"],
        );
        let r = rule_au_015_threat_intel_hit(&[e], "s", 0);
        assert_eq!(r.len(), 1);
        assert!(r[0].description.contains("malware"));
    }

    #[test]
    fn au015_attribution_names_evidence_source_not_otx() {
        let mut e = Entity::new(EntityKind::Domain, "bad.example", 0.9, "s");
        e.tag("threat-intel");
        e.add_evidence(Evidence::new("threatfox", "t"));
        let r = rule_au_015_threat_intel_hit(&[e], "s", 0);
        assert_eq!(r.len(), 1);
        assert!(r[0].description.contains("threatfox"));
        assert!(!r[0].description.contains("OTX"));
    }

    #[test]
    fn au015_attribution_excludes_non_ti_evidence() {
        let mut e = Entity::new(EntityKind::Domain, "bad.example", 0.9, "s");
        e.tag("threat-intel");
        e.add_evidence(Evidence::new("ip_reputation", "ti-hit"));
        e.add_evidence(Evidence::new("whois", "registry-data"));
        e.add_evidence(Evidence::new("dns_resolver", "a-record"));
        let r = rule_au_015_threat_intel_hit(&[e], "s", 0);
        assert_eq!(r.len(), 1);
        assert!(r[0].description.contains("ip_reputation"));
        assert!(!r[0].description.contains("whois"));
        assert!(!r[0].description.contains("dns_resolver"));
    }

    #[test]
    fn au015_attribution_falls_back_when_source_unknown() {
        let e = tagged(EntityKind::Domain, "bad.example", &["threat-intel"]);
        let r = rule_au_015_threat_intel_hit(&[e], "s", 0);
        assert_eq!(r.len(), 1);
        assert!(r[0].description.contains("curated threat-intel feed"));
    }

    // ── Cross-cutting ───────────────────────────────────────────────────

    #[test]
    fn severity_orders_correctly() {
        assert!(Severity::Low < Severity::Medium);
        assert!(Severity::Medium < Severity::High);
        assert!(Severity::High < Severity::Critical);
    }

    #[test]
    fn evaluate_rules_fires_expected_subset() {
        let mut email = Entity::new(EntityKind::Email, "x@y.com", 0.9, "s");
        email.add_evidence(Evidence::new("hudsonrock", "t"));
        email.add_evidence(Evidence::new("xposed_or_not", "t"));
        email.tag("stealer-log");
        let domain = tagged(
            EntityKind::Domain,
            "evil.example",
            &["malicious", "vulnerable", "threat-intel"],
        );
        let ip = tagged(EntityKind::IpAddress, "1.1.1.1", &["tor-exit"]);
        let firings = evaluate_rules(&[email, domain, ip], "s");
        let ids: HashSet<&str> = firings.iter().map(|c| c.rule_id.as_str()).collect();
        for expected in &["AU-001", "AU-004", "AU-005", "AU-008", "AU-009", "AU-015"] {
            assert!(
                ids.contains(expected),
                "expected {expected} in firings, got {ids:?}"
            );
        }
    }

    #[test]
    fn rule_016_breach_ip_geo_chain_fires() {
        let mut ip = Entity::new(EntityKind::IpAddress, "101.169.42.148", 0.72, "s");
        ip.tag("breach");
        let mut coord = Entity::new(EntityKind::Coordinates, "-27.5567,152.2767", 0.65, "s");
        coord.add_evidence(Evidence::new(
            "ip_geo",
            "Geolocation for 101.169.42.148: Gatton, QLD",
        ));
        let firings = rule_au_016_breach_ip_geo_chain(&[ip, coord], "s", 0);
        assert_eq!(firings.len(), 1);
        assert_eq!(firings[0].rule_id, "AU-016");
    }

    #[test]
    fn rule_016_no_fire_without_breach_tag() {
        let ip = Entity::new(EntityKind::IpAddress, "1.2.3.4", 0.72, "s");
        let coord = Entity::new(EntityKind::Coordinates, "1.0,2.0", 0.65, "s");
        let firings = rule_au_016_breach_ip_geo_chain(&[ip, coord], "s", 0);
        assert!(firings.is_empty());
    }

    #[test]
    fn rule_017_multi_geo_convergence_fires() {
        let c1 = Entity::new(EntityKind::Coordinates, "-27.55,152.27", 0.60, "s");
        let c2 = Entity::new(EntityKind::Coordinates, "-27.60,152.30", 0.65, "s");
        let firings = rule_au_017_multi_geo_convergence(&[c1, c2], "s", 0);
        assert_eq!(firings.len(), 1);
        assert_eq!(firings[0].rule_id, "AU-017");
        assert!(firings[0].description.contains("converge"));
    }

    #[test]
    fn rule_017_no_fire_for_distant_coords() {
        let c1 = Entity::new(EntityKind::Coordinates, "-27.55,152.27", 0.60, "s");
        let c2 = Entity::new(EntityKind::Coordinates, "-33.86,151.20", 0.65, "s");
        let firings = rule_au_017_multi_geo_convergence(&[c1, c2], "s", 0);
        assert!(firings.is_empty());
    }

    // ── AU-031 (graph-aware: relation edges) ────────────────────────────

    #[test]
    fn au031_fires_on_edge_to_malicious_node() {
        use crate::core::relation::{Relation, RelationKind};
        let bad = tagged(EntityKind::Domain, "evil.example", &["malicious"]);
        let benign = tagged(EntityKind::Domain, "blog.evil.example", &[]);
        let rel = Relation::new(
            benign.uid.clone(),
            bad.uid.clone(),
            RelationKind::SubdomainOf,
            0.8,
            "s",
        );
        let r = rule_au_031_malicious_adjacency(&[bad.clone(), benign.clone()], &[rel], "s", 0);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].rule_id, "AU-031");
        assert_eq!(r[0].severity, Severity::High);
        assert!(r[0].entity_uids.contains(&benign.uid));
        assert!(r[0].entity_uids.contains(&bad.uid));
        assert!(r[0].description.contains("blog.evil.example"));
        assert!(r[0].description.contains("malicious"));
    }

    #[test]
    fn au031_no_fire_when_neither_endpoint_flagged() {
        use crate::core::relation::{Relation, RelationKind};
        let a = tagged(EntityKind::Domain, "a.example", &[]);
        let b = tagged(EntityKind::Domain, "example", &[]);
        let rel = Relation::new(
            a.uid.clone(),
            b.uid.clone(),
            RelationKind::SubdomainOf,
            0.8,
            "s",
        );
        assert!(rule_au_031_malicious_adjacency(&[a, b], &[rel], "s", 0).is_empty());
    }

    #[test]
    fn au031_no_fire_when_both_endpoints_flagged() {
        use crate::core::relation::{Relation, RelationKind};
        let a = tagged(EntityKind::Domain, "evil.example", &["malicious"]);
        let b = tagged(EntityKind::Domain, "bad.example", &["threat-intel"]);
        let rel = Relation::new(
            a.uid.clone(),
            b.uid.clone(),
            RelationKind::CoLocatedWith,
            0.8,
            "s",
        );
        assert!(rule_au_031_malicious_adjacency(&[a, b], &[rel], "s", 0).is_empty());
    }

    #[test]
    fn au031_skips_edges_with_missing_endpoints() {
        use crate::core::relation::{Relation, RelationKind};
        // Edge references a uid not in the entity set → no fire, no panic.
        let bad = tagged(EntityKind::Domain, "evil.example", &["malicious"]);
        let rel = Relation::new(
            "ghost-uid",
            bad.uid.clone(),
            RelationKind::DerivedFrom,
            0.8,
            "s",
        );
        assert!(rule_au_031_malicious_adjacency(&[bad], &[rel], "s", 0).is_empty());
    }

    // ── AU-032 (graph-aware: co-location cluster) ───────────────────────

    #[test]
    fn au032_fires_on_three_node_colocation_cluster() {
        use crate::core::relation::{Relation, RelationKind};
        let c1 = Entity::new(EntityKind::Coordinates, "-27.470000,153.020000", 0.9, "s");
        let c2 = Entity::new(EntityKind::Coordinates, "-27.470500,153.020500", 0.8, "s");
        let c3 = Entity::new(EntityKind::Coordinates, "-27.471000,153.021000", 0.7, "s");
        // Chain c1–c2–c3 → one connected component of 3.
        let rels = vec![
            Relation::new(
                c1.uid.clone(),
                c2.uid.clone(),
                RelationKind::CoLocatedWith,
                0.9,
                "s",
            ),
            Relation::new(
                c2.uid.clone(),
                c3.uid.clone(),
                RelationKind::CoLocatedWith,
                0.9,
                "s",
            ),
        ];
        let r = rule_au_032_colocation_cluster(&[c1, c2, c3], &rels, "s", 0);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].rule_id, "AU-032");
        assert_eq!(r[0].severity, Severity::Medium);
        assert_eq!(r[0].entity_uids.len(), 3);
        assert!(r[0].description.contains("3 coordinates"));
    }

    #[test]
    fn au032_no_fire_on_pair() {
        use crate::core::relation::{Relation, RelationKind};
        let c1 = Entity::new(EntityKind::Coordinates, "-27.470000,153.020000", 0.9, "s");
        let c2 = Entity::new(EntityKind::Coordinates, "-27.470500,153.020500", 0.8, "s");
        let rels = vec![Relation::new(
            c1.uid.clone(),
            c2.uid.clone(),
            RelationKind::CoLocatedWith,
            0.9,
            "s",
        )];
        assert!(rule_au_032_colocation_cluster(&[c1, c2], &rels, "s", 0).is_empty());
    }

    #[test]
    fn au032_ignores_non_colocation_edges() {
        use crate::core::relation::{Relation, RelationKind};
        // Three domains chained by SubdomainOf — not co-location → no cluster.
        let a = Entity::new(EntityKind::Domain, "a.b.c.com", 0.9, "s");
        let b = Entity::new(EntityKind::Domain, "b.c.com", 0.9, "s");
        let c = Entity::new(EntityKind::Domain, "c.com", 0.9, "s");
        let rels = vec![
            Relation::new(
                a.uid.clone(),
                b.uid.clone(),
                RelationKind::SubdomainOf,
                0.9,
                "s",
            ),
            Relation::new(
                b.uid.clone(),
                c.uid.clone(),
                RelationKind::SubdomainOf,
                0.9,
                "s",
            ),
        ];
        assert!(rule_au_032_colocation_cluster(&[a, b, c], &rels, "s", 0).is_empty());
    }
}
