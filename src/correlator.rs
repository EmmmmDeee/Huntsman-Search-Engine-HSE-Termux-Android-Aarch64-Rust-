use std::cell::RefCell;
use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::canonical::canonical_handle;
use crate::entity::Entity;
use crate::relation::Relation;
use crate::tags;

mod rules;

pub use rules::{
    text_mentions_ip, source_family, date_diff_days, tagged_matching_sources, rule_au_001_multi_breach, rule_au_002_identity_cluster, rule_au_003_high_corroboration, rule_au_019_temporal_breach_cluster, rule_au_021_api_key_exposure, rule_au_060_transitive_identity_closure, rule_au_062_multipath_corroboration, rule_au_063_corroboration_gap, rule_au_070_connection_broker, rule_au_071_robust_identity_cluster, rule_au_109_shared_registrant, rule_au_110_shared_hosting_ip,
};

pub struct RuleContext<'a> {
    entities: &'a [Entity],
    relations: &'a [Relation],
    by_uid: RefCell<Option<HashMap<&'a str, &'a Entity>>>,
    by_canonical_handle: RefCell<Option<HashMap<String, Vec<&'a Entity>>>>,
}

impl<'a> RuleContext<'a> {
    #[must_use]
    pub fn new(entities: &'a [Entity], relations: &'a [Relation]) -> Self {
        Self {
            entities,
            relations,
            by_uid: RefCell::new(None),
            by_canonical_handle: RefCell::new(None),
        }
    }

    #[must_use]
    pub fn entities(&self) -> &'a [Entity] {
        self.entities
    }

    #[must_use]
    pub fn relations(&self) -> &'a [Relation] {
        self.relations
    }

    pub fn by_uid(&self) -> std::cell::Ref<'_, HashMap<&'a str, &'a Entity>> {
        if self.by_uid.borrow().is_none() {
            *self.by_uid.borrow_mut() = Some(
                self.entities
                    .iter()
                    .map(|entity| (entity.uid.as_str(), entity))
                    .collect(),
            );
        }
        std::cell::Ref::map(self.by_uid.borrow(), |map| {
            map.as_ref().expect("cache initialised")
        })
    }

    pub fn by_canonical_handle(&self) -> std::cell::Ref<'_, HashMap<String, Vec<&'a Entity>>> {
        if self.by_canonical_handle.borrow().is_none() {
            let mut map = HashMap::<String, Vec<&Entity>>::new();
            for entity in self.entities {
                if let Some(handle) = canonical_handle(&entity.value) {
                    map.entry(handle).or_default().push(entity);
                }
            }
            *self.by_canonical_handle.borrow_mut() = Some(map);
        }
        std::cell::Ref::map(self.by_canonical_handle.borrow(), |map| {
            map.as_ref().expect("cache initialised")
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    #[must_use]
    pub const fn as_canonical(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }

    #[must_use]
    pub const fn weight(self) -> f64 {
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
        f.write_str(self.as_canonical())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Correlation {
    pub rule_id: String,
    pub rule_name: String,
    pub severity: Severity,
    pub description: String,
    pub entity_uids: Vec<String>,
    pub scan_id: String,
    pub ts: u64,
    #[serde(default)]
    pub rank: f64,
}

impl Correlation {
    #[must_use]
    pub fn new(
        rule_id: &str,
        rule_name: &str,
        severity: Severity,
        description: impl Into<String>,
        entity_uids: Vec<String>,
        scan_id: &str,
        ts: u64,
    ) -> Self {
        Self {
            rule_id: rule_id.into(),
            rule_name: rule_name.into(),
            severity,
            description: description.into(),
            entity_uids,
            scan_id: scan_id.into(),
            ts,
            rank: 0.0,
        }
    }
}

pub trait Rule: Sync {
    fn id(&self) -> &'static str;
    fn name(&self) -> &'static str;
    fn severity(&self) -> Severity;
    fn run(&self, context: &RuleContext<'_>, scan_id: &str, now: u64) -> Vec<Correlation>;
}

struct FnRule {
    id: &'static str,
    name: &'static str,
    severity: Severity,
    runner: fn(&RuleContext<'_>, &str, u64) -> Vec<Correlation>,
}

impl Rule for FnRule {
    fn id(&self) -> &'static str {
        self.id
    }

    fn name(&self) -> &'static str {
        self.name
    }

    fn severity(&self) -> Severity {
        self.severity
    }

    fn run(&self, context: &RuleContext<'_>, scan_id: &str, now: u64) -> Vec<Correlation> {
        (self.runner)(context, scan_id, now)
    }
}

static AU_001: FnRule = FnRule {
    id: "AU-001",
    name: "multi_breach",
    severity: Severity::High,
    runner: rule_au_001_multi_breach,
};
static AU_002: FnRule = FnRule {
    id: "AU-002",
    name: "identity_cluster",
    severity: Severity::Critical,
    runner: rule_au_002_identity_cluster,
};
static AU_003: FnRule = FnRule {
    id: "AU-003",
    name: "high_corroboration",
    severity: Severity::Medium,
    runner: rule_au_003_high_corroboration,
};
static AU_019: FnRule = FnRule {
    id: "AU-019",
    name: "temporal_breach_cluster",
    severity: Severity::High,
    runner: rule_au_019_temporal_breach_cluster,
};
static AU_021: FnRule = FnRule {
    id: "AU-021",
    name: "api_key_exposure",
    severity: Severity::Critical,
    runner: rule_au_021_api_key_exposure,
};
static AU_060: FnRule = FnRule {
    id: "AU-060",
    name: "transitive_identity_closure",
    severity: Severity::High,
    runner: rule_au_060_transitive_identity_closure,
};
static AU_062: FnRule = FnRule {
    id: "AU-062",
    name: "multipath_corroboration",
    severity: Severity::High,
    runner: rule_au_062_multipath_corroboration,
};
static AU_063: FnRule = FnRule {
    id: "AU-063",
    name: "corroboration_gap",
    severity: Severity::Low,
    runner: rule_au_063_corroboration_gap,
};
static AU_070: FnRule = FnRule {
    id: "AU-070",
    name: "connection_broker",
    severity: Severity::Medium,
    runner: rule_au_070_connection_broker,
};
static AU_071: FnRule = FnRule {
    id: "AU-071",
    name: "robust_identity_cluster",
    severity: Severity::High,
    runner: rule_au_071_robust_identity_cluster,
};
static AU_109: FnRule = FnRule {
    id: "AU-109",
    name: "shared_registrant",
    severity: Severity::Medium,
    runner: rule_au_109_shared_registrant,
};
static AU_110: FnRule = FnRule {
    id: "AU-110",
    name: "shared_hosting_ip",
    severity: Severity::Medium,
    runner: rule_au_110_shared_hosting_ip,
};

static REGISTRY: [&dyn Rule; 12] = [
    &AU_001, &AU_002, &AU_003, &AU_019, &AU_021, &AU_060, &AU_062, &AU_063, &AU_070, &AU_071,
    &AU_109, &AU_110,
];

#[must_use]
pub fn registry() -> &'static [&'static dyn Rule] {
    &REGISTRY
}

pub struct Correlator;

impl Correlator {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    #[must_use]
    pub fn run_on(
        &self,
        entities: &[Entity],
        relations: &[Relation],
        scan_id: &str,
    ) -> Vec<Correlation> {
        evaluate_rules(entities, relations, scan_id)
    }
}

impl Default for Correlator {
    fn default() -> Self {
        Self::new()
    }
}

pub fn rank_and_sort(correlations: &mut [Correlation], entities: &[Entity]) {
    let ceff = entities
        .iter()
        .map(|entity| (entity.uid.clone(), entity.c_effective()))
        .collect::<HashMap<_, _>>();
    for correlation in correlations.iter_mut() {
        let max_child = correlation
            .entity_uids
            .iter()
            .filter_map(|uid| ceff.get(uid).copied())
            .fold(0.0_f64, f64::max);
        correlation.rank = correlation.severity.weight() * max_child;
    }
    correlations.sort_by(|left, right| {
        right
            .rank
            .partial_cmp(&left.rank)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then(right.severity.cmp(&left.severity))
            .then(left.rule_id.cmp(&right.rule_id))
            .then(left.entity_uids.cmp(&right.entity_uids))
    });
}

#[must_use]
pub fn confirmed_only(entities: &[Entity]) -> Vec<Entity> {
    entities
        .iter()
        .filter(|entity| !entity.has_tag(tags::CANDIDATE))
        .cloned()
        .collect()
}

#[must_use]
pub fn evaluate_rules(
    entities: &[Entity],
    relations: &[Relation],
    scan_id: &str,
) -> Vec<Correlation> {
    let confirmed = confirmed_only(entities);
    let context = RuleContext::new(&confirmed, relations);
    let now = crate::entity::unix_now();
    let mut out = Vec::new();
    for rule in registry() {
        out.extend(rule.run(&context, scan_id, now));
    }
    rank_and_sort(&mut out, &confirmed);
    out
}

#[must_use]
pub fn correlate_entities(entities: &[Entity], scan_id: &str) -> Vec<Correlation> {
    evaluate_rules(entities, &[], scan_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entity::{EntityKind, Evidence, EvidenceProvenance};
    use crate::relation::RelationKind;

    fn evidence(source: &str, summary: &str) -> Evidence {
        Evidence::new(EvidenceProvenance::new(source), summary)
    }

    fn ent(kind: EntityKind, value: &str, conf: f64, src: &str, candidate: bool) -> Entity {
        let mut entity = Entity::new(kind, value, conf, "scan");
        entity.add_evidence(evidence(src, "x"));
        if candidate {
            entity.tag(tags::CANDIDATE);
        }
        entity
    }

    #[test]
    fn rule_context_by_uid_indexes_every_entity_and_caches() {
        let entities = vec![
            ent(EntityKind::Email, "a@example.com", 0.9, "src-a", false),
            ent(EntityKind::Username, "alice", 0.8, "src-b", false),
            ent(EntityKind::Domain, "example.com", 0.7, "src-c", false),
        ];
        let ctx = RuleContext::new(&entities, &[]);
        let by_uid = ctx.by_uid();
        assert_eq!(by_uid.len(), entities.len());
        for entity in &entities {
            let got = by_uid.get(entity.uid.as_str()).unwrap();
            assert_eq!(got.uid, entity.uid);
        }
        drop(by_uid);
        assert_eq!(ctx.by_uid().len(), entities.len());
    }

    #[test]
    fn temporal_breach_cluster_survives_non_ascii_breach_date() {
        let mk = |value: &str, date: &str| {
            let mut entity = Entity::new(EntityKind::Email, value, 0.8, "scan");
            entity.tag(tags::BREACH);
            entity.add_evidence(evidence("hibp", "breach").with_attr("breach_date", date));
            entity
        };
        let entities = vec![
            mk("a@x.com", "2024-01-0€9"),
            mk("b@x.com", "2024-01-15"),
            mk("c@x.com", "2024-02-10"),
        ];
        let _ = rule_au_019_temporal_breach_cluster(&RuleContext::new(&entities, &[]), "scan", 0);
    }

    #[test]
    fn temporal_breach_cluster_window_is_anchored_not_rolling() {
        let mk = |value: &str, date: &str| {
            let mut entity = Entity::new(EntityKind::Email, value, 0.8, "scan");
            entity.tag(tags::BREACH);
            entity.add_evidence(evidence("hibp", "breach").with_attr("breach_date", date));
            entity
        };
        let tight = vec![
            mk("a@x.com", "2024-01-01"),
            mk("b@x.com", "2024-01-10"),
            mk("c@x.com", "2024-01-20"),
        ];
        let result = rule_au_019_temporal_breach_cluster(&RuleContext::new(&tight, &[]), "scan", 0);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].entity_uids.len(), 3);
        let chained = vec![
            mk("a@x.com", "2024-01-01"),
            mk("b@x.com", "2024-01-30"),
            mk("c@x.com", "2024-02-28"),
            mk("d@x.com", "2024-03-30"),
        ];
        let chained_result =
            rule_au_019_temporal_breach_cluster(&RuleContext::new(&chained, &[]), "scan", 0);
        assert!(chained_result.is_empty(), "{chained_result:?}");
    }

    #[test]
    fn candidates_are_excluded_from_correlation() {
        let mut entities = vec![
            ent(EntityKind::Email, "me@real.com", 0.85, "oathnet_pro", false),
            ent(EntityKind::Username, "me", 0.7, "oathnet_pro", false),
            ent(EntityKind::Phone, "15551112222", 0.7, "oathnet_pro", false),
        ];
        for i in 0..40 {
            entities.push(ent(
                EntityKind::Email,
                &format!("stranger{i}@bank.com"),
                0.25,
                "oathnet_pro",
                true,
            ));
        }
        let firings = evaluate_rules(&entities, &[], "scan");
        let candidate_uids = entities
            .iter()
            .filter(|entity| entity.has_tag(tags::CANDIDATE))
            .map(|entity| entity.uid.as_str())
            .collect::<std::collections::HashSet<_>>();
        for correlation in &firings {
            for uid in &correlation.entity_uids {
                assert!(!candidate_uids.contains(uid.as_str()));
            }
        }
        let au002 = firings
            .iter()
            .find(|correlation| correlation.rule_id == "AU-002")
            .unwrap();
        assert!(au002.description.contains("1 email(s)"));
    }

    #[test]
    fn au002_refuses_to_fuse_an_implausible_identity_dump() {
        let mut big = vec![
            ent(EntityKind::Username, "u", 0.7, "s", false),
            ent(EntityKind::Phone, "15551112222", 0.7, "s", false),
        ];
        for i in 0..30 {
            big.push(ent(
                EntityKind::Email,
                &format!("e{i}@x.com"),
                0.7,
                "s",
                false,
            ));
        }
        let findings = rule_au_002_identity_cluster(&RuleContext::new(&big, &[]), "scan", 0);
        assert!(findings.is_empty(), "{findings:?}");
        let small = vec![
            ent(EntityKind::Email, "me@x.com", 0.85, "s", false),
            ent(EntityKind::Username, "me", 0.7, "s", false),
            ent(EntityKind::Phone, "15551112222", 0.7, "s", false),
        ];
        assert_eq!(
            rule_au_002_identity_cluster(&RuleContext::new(&small, &[]), "scan", 0).len(),
            1
        );
        let weak = vec![
            ent(EntityKind::Email, "me@x.com", 0.3, "s", false),
            ent(EntityKind::Username, "me", 0.3, "s", false),
            ent(EntityKind::Phone, "15551112222", 0.3, "s", false),
        ];
        let findings = rule_au_002_identity_cluster(&RuleContext::new(&weak, &[]), "scan", 0);
        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn helper_behaviour_matches_legacy_oracles() {
        assert!(text_mentions_ip("seen at 1.2.3.4: Brisbane", "1.2.3.4"));
        assert!(text_mentions_ip("via [2001:db8::1]:443", "2001:db8::1"));
        assert!(!text_mentions_ip("host 1.2.3.45 responded", "1.2.3.4"));
        assert!(!text_mentions_ip("aé1", "é"));
        assert_eq!(source_family("ip2location"), "infra");
        assert_eq!(source_family("hibp"), "breach");
        assert_eq!(source_family("github_user"), "code");
        assert_eq!(date_diff_days("2024-06-15", "2024-06-15"), 0);
        assert!(crate::relation::is_generic_handle("support"));
        assert!(!crate::relation::is_generic_handle("adalovelace"));
    }

    #[test]
    fn run_ranks_by_severity_times_max_child_ceff() {
        let mut weak_key = Entity::new(EntityKind::ApiKey, "AKIAWEAK", 0.20, "scan");
        weak_key.add_evidence(evidence("key_harvest", "found once"));
        let mut strong_email = Entity::new(EntityKind::Email, "a@b.com", 0.95, "scan");
        for source in ["hibp", "dehashed", "search_engines"] {
            strong_email.add_evidence(evidence(source, "seen"));
        }
        let results = evaluate_rules(&[weak_key, strong_email], &[], "scan");
        assert_eq!(results[0].rule_id, "AU-003");
        assert!(
            results
                .iter()
                .any(|correlation| correlation.rule_id == "AU-021")
        );
    }

    #[test]
    fn relation_rules_cover_core_graph_patterns() {
        let entities = vec![
            ent(EntityKind::Email, "a@example.com", 0.9, "hibp", false),
            ent(EntityKind::Username, "alice", 0.8, "github_user", false),
            ent(EntityKind::Phone, "15551112222", 0.8, "name_intel", false),
            ent(EntityKind::Domain, "a.example.com", 0.8, "whois", false),
            ent(EntityKind::Domain, "b.example.com", 0.8, "whois", false),
            ent(EntityKind::IpAddress, "1.2.3.4", 0.8, "dns_intel", false),
        ];
        let relations = vec![
            Relation::new(
                &entities[0].uid,
                &entities[1].uid,
                RelationKind::AliasOf,
                0.8,
                "scan",
            ),
            Relation::new(
                &entities[1].uid,
                &entities[2].uid,
                RelationKind::IdentifiedBy,
                0.8,
                "scan",
            ),
            Relation::new(
                &entities[0].uid,
                &entities[2].uid,
                RelationKind::SameIdentity,
                0.7,
                "scan",
            ),
            Relation::new(
                &entities[3].uid,
                &entities[5].uid,
                RelationKind::ResolvesTo,
                0.8,
                "scan",
            ),
            Relation::new(
                &entities[4].uid,
                &entities[5].uid,
                RelationKind::ResolvesTo,
                0.8,
                "scan",
            ),
            Relation::new(
                &entities[3].uid,
                &entities[1].uid,
                RelationKind::RegisteredBy,
                0.8,
                "scan",
            ),
            Relation::new(
                &entities[4].uid,
                &entities[1].uid,
                RelationKind::RegisteredBy,
                0.8,
                "scan",
            ),
        ];
        let results = evaluate_rules(&entities, &relations, "scan");
        assert!(
            results
                .iter()
                .any(|correlation| correlation.rule_id == "AU-060")
        );
        assert!(
            results
                .iter()
                .any(|correlation| correlation.rule_id == "AU-062")
        );
        assert!(
            results
                .iter()
                .any(|correlation| correlation.rule_id == "AU-109")
        );
        assert!(
            results
                .iter()
                .any(|correlation| correlation.rule_id == "AU-110")
        );
    }
}
