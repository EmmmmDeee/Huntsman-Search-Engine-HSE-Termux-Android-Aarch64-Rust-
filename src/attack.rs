use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

pub use crate::attack_catalog::{ENTERPRISE, TACTICS};
use crate::dependency::ModuleCategory;
use crate::entity::{Entity, EntityKind};
use crate::graph::{EntityRelation, RelationKind};

/// Version of the broad static Enterprise catalogue in `attack_catalog.rs`.
///
/// The reconstruction only claims current-version fidelity for TA0043; do not
/// relabel this broader v17.1 catalogue as v19.2 without regenerating all of it.
pub const ATTACK_VERSION: &str = "17.1";
/// Current MITRE ATT&CK version used by the TA0043 Reconnaissance view.
pub const RECONNAISSANCE_VERSION: &str = "19.2";
pub const TACTIC_ID: &str = "TA0043";
pub const TACTIC_NAME: &str = "Reconnaissance";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Tactic {
    pub id: &'static str,
    pub shortname: &'static str,
    pub name: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Technique {
    pub id: &'static str,
    pub name: &'static str,
    pub is_subtechnique: bool,
    pub tactics: &'static [&'static str],
}

/// TA0043 additions after the repository's broad v17.1 catalogue was pinned.
/// Keeping the overlay explicit avoids falsely claiming that every non-Recon
/// Enterprise object has been regenerated to v19.2.
const RECONNAISSANCE_V19_2_ADDITIONS: &[Technique] = &[
    Technique {
        id: "T1681",
        name: "Search Threat Vendor Data",
        is_subtechnique: false,
        tactics: &["reconnaissance"],
    },
    Technique {
        id: "T1682",
        name: "Query Public AI Services",
        is_subtechnique: false,
        tactics: &["reconnaissance"],
    },
];

const INTENTIONAL_EXCLUSION_IDS: &[&str] =
    &["T1598.001", "T1598.002", "T1598.003", "T1598.004", "T1682"];

fn major(version: &'static str) -> &'static str {
    match version.split_once('.') {
        Some((value, _)) => value,
        None => version,
    }
}

#[must_use]
pub fn attack_spec_major() -> &'static str {
    major(ATTACK_VERSION)
}

#[must_use]
pub fn reconnaissance_spec_major() -> &'static str {
    major(RECONNAISSANCE_VERSION)
}

#[must_use]
pub fn technique(id: &str) -> Option<&'static Technique> {
    ENTERPRISE
        .iter()
        .chain(RECONNAISSANCE_V19_2_ADDITIONS.iter())
        .find(|item| item.id == id)
}

#[must_use]
pub fn tactic(id_or_shortname: &str) -> Option<&'static Tactic> {
    TACTICS
        .iter()
        .find(|item| item.id == id_or_shortname || item.shortname == id_or_shortname)
}

#[must_use]
pub fn techniques_for_tactic(shortname: &str) -> Vec<&'static Technique> {
    ENTERPRISE
        .iter()
        .chain(RECONNAISSANCE_V19_2_ADDITIONS.iter())
        .filter(|item| item.tactics.contains(&shortname))
        .collect()
}

#[must_use]
pub fn reconnaissance() -> Vec<&'static Technique> {
    techniques_for_tactic("reconnaissance")
}

#[must_use]
pub fn reconnaissance_families() -> Vec<&'static Technique> {
    reconnaissance()
        .into_iter()
        .filter(|item| !item.is_subtechnique)
        .collect()
}

fn belongs_to_family(item: &Technique, family: &Technique) -> bool {
    item.id == family.id
        || item
            .id
            .strip_prefix(family.id)
            .is_some_and(|rest| rest.starts_with('.'))
}

#[must_use]
pub fn reconnaissance_leaves() -> Vec<&'static Technique> {
    let recon = reconnaissance();
    recon
        .iter()
        .copied()
        .filter(|item| {
            item.is_subtechnique
                || !recon.iter().any(|candidate| {
                    candidate.is_subtechnique && belongs_to_family(candidate, item)
                })
        })
        .collect()
}

#[must_use]
pub fn intentional_exclusions() -> Vec<&'static Technique> {
    reconnaissance_leaves()
        .into_iter()
        .filter(|item| INTENTIONAL_EXCLUSION_IDS.contains(&item.id))
        .collect()
}

#[must_use]
pub fn uncovered(is_covered: impl Fn(&str) -> bool) -> Vec<&'static Technique> {
    reconnaissance_leaves()
        .into_iter()
        .filter(|item| !INTENTIONAL_EXCLUSION_IDS.contains(&item.id))
        .filter(|item| !is_covered(item.id))
        .collect()
}

#[must_use]
pub fn techniques_for_category(category: ModuleCategory) -> &'static [&'static str] {
    match category {
        ModuleCategory::DnsRecon => &[
            "T1590.001",
            "T1590.002",
            "T1596.001",
            "T1596.002",
            "T1596.003",
        ],
        ModuleCategory::Breach => &["T1589.001", "T1589.002"],
        ModuleCategory::Infrastructure => &["T1590.005", "T1596.005"],
        ModuleCategory::Search => &["T1593.002"],
        ModuleCategory::Social => &["T1593.001", "T1589.003"],
        ModuleCategory::Email => &["T1589.002"],
        ModuleCategory::Phone => &["T1589"],
        ModuleCategory::Corporate => &["T1591.002", "T1591.004"],
        // A generic "Threat" category cannot distinguish private victim-data
        // research (T1597.001) from searching open/closed vendor reporting
        // about adversary activity (T1681). Concrete collectors must bind an
        // exact technique instead of inheriting a false default.
        ModuleCategory::Threat => &[],
        ModuleCategory::Sensor => &["T1592"],
        ModuleCategory::People => &["T1589.003", "T1591.004"],
        ModuleCategory::Web => &["T1594", "T1592.002"],
        ModuleCategory::Geo => &["T1591.001"],
        ModuleCategory::Other => &[],
    }
}

#[must_use]
pub fn techniques_for_entity_kind(kind: &EntityKind) -> &'static [&'static str] {
    match kind {
        EntityKind::Person => &["T1589", "T1589.003", "T1591"],
        EntityKind::Organisation => &["T1591"],
        EntityKind::Email => &["T1589.002"],
        EntityKind::Phone | EntityKind::CryptoAddress => &["T1589"],
        EntityKind::Username => &["T1593.001", "T1589.003"],
        EntityKind::Credential | EntityKind::ApiKey => &["T1589.001"],
        EntityKind::IpAddress => &["T1590.005"],
        EntityKind::Domain => &["T1590.001", "T1596.002", "T1593.002", "T1594"],
        EntityKind::Url => &["T1594"],
        EntityKind::Asn => &["T1590.004"],
        EntityKind::Address | EntityKind::Coordinates => &["T1591.001"],
        EntityKind::AbnAcn => &["T1591.002", "T1591.004"],
        EntityKind::MacAddress | EntityKind::DeviceId | EntityKind::Ssid | EntityKind::Document => {
            &["T1592"]
        }
        EntityKind::TrackingId => &["T1593.002", "T1591"],
        EntityKind::Other => &[],
    }
}

#[must_use]
pub fn techniques_for_relation_kind(kind: RelationKind) -> &'static [&'static str] {
    match kind {
        RelationKind::LocatedAt => &["T1591.001"],
        RelationKind::AssociatedWith => &["T1589"],
        RelationKind::AliasOf => &["T1589.003", "T1593.001"],
        RelationKind::Owns => &["T1591.002"],
        RelationKind::MemberOf => &["T1591"],
        RelationKind::MentionedWith => &["T1594"],
        RelationKind::ExposedWith => &["T1589.001"],
        RelationKind::Uses
        | RelationKind::Supports
        | RelationKind::Contradicts
        | RelationKind::SameAs => &[],
    }
}

pub fn fold_relation_techniques(
    exercised: &mut BTreeMap<String, usize>,
    relations: &[EntityRelation],
) {
    for relation in relations {
        for id in techniques_for_relation_kind(relation.kind) {
            *exercised.entry((*id).to_owned()).or_insert(0) += 1;
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CoveredTechnique {
    #[serde(flatten)]
    pub technique: Technique,
    pub entity_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TechniqueByEntityType {
    #[serde(flatten)]
    pub technique: Technique,
    pub by_entity_type: BTreeMap<String, usize>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FamilyCoverage {
    #[serde(flatten)]
    pub technique: Technique,
    /// Evidence directly attached to the parent technique. This reaches the
    /// family but never substitutes for a more specific child capability.
    pub direct_count: usize,
    pub covered_leaf_count: usize,
    pub gap_leaf_count: usize,
    pub excluded_leaf_count: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Coverage {
    pub tactic_id: &'static str,
    pub tactic_name: &'static str,
    pub attack_version: &'static str,
    /// Covered actionable leaves only; parent families are represented in
    /// `family_rollups` and never double-counted here.
    pub covered: Vec<CoveredTechnique>,
    /// Applicable actionable leaves with no supplied capability evidence.
    pub uncovered: Vec<&'static Technique>,
    /// Deliberate product-scope exclusions, kept separate from engineering gaps.
    pub intentional_exclusions: Vec<&'static Technique>,
    pub family_rollups: Vec<FamilyCoverage>,
    pub catalog_leaf_count: usize,
    pub applicable_leaf_count: usize,
    /// `covered / applicable_leaf_count`; this is structural capability
    /// coverage, not detection effectiveness or evidence quality.
    pub coverage_fraction: f64,
}

#[allow(clippy::cast_precision_loss)]
fn ratio(numerator: usize, denominator: usize) -> f64 {
    if denominator == 0 {
        0.0
    } else {
        numerator as f64 / denominator as f64
    }
}

#[must_use]
pub fn coverage(exercised: &BTreeMap<String, usize>) -> Coverage {
    let leaves = reconnaissance_leaves();
    let intentional_exclusions: Vec<&Technique> = leaves
        .iter()
        .copied()
        .filter(|item| INTENTIONAL_EXCLUSION_IDS.contains(&item.id))
        .collect();
    let covered: Vec<CoveredTechnique> = leaves
        .iter()
        .filter(|item| !INTENTIONAL_EXCLUSION_IDS.contains(&item.id))
        .filter_map(|item| {
            exercised
                .get(item.id)
                .map(|&entity_count| CoveredTechnique {
                    technique: **item,
                    entity_count,
                })
        })
        .collect();
    let uncovered: Vec<&Technique> = leaves
        .iter()
        .copied()
        .filter(|item| !INTENTIONAL_EXCLUSION_IDS.contains(&item.id))
        .filter(|item| !exercised.contains_key(item.id))
        .collect();

    let covered_ids: BTreeSet<&str> = covered.iter().map(|item| item.technique.id).collect();
    let uncovered_ids: BTreeSet<&str> = uncovered.iter().map(|item| item.id).collect();
    let excluded_ids: BTreeSet<&str> = intentional_exclusions.iter().map(|item| item.id).collect();
    let family_rollups = reconnaissance_families()
        .into_iter()
        .map(|family| {
            let family_leaves: Vec<&Technique> = leaves
                .iter()
                .copied()
                .filter(|leaf| belongs_to_family(leaf, family))
                .collect();
            FamilyCoverage {
                technique: *family,
                direct_count: exercised.get(family.id).copied().unwrap_or(0),
                covered_leaf_count: family_leaves
                    .iter()
                    .filter(|leaf| covered_ids.contains(leaf.id))
                    .count(),
                gap_leaf_count: family_leaves
                    .iter()
                    .filter(|leaf| uncovered_ids.contains(leaf.id))
                    .count(),
                excluded_leaf_count: family_leaves
                    .iter()
                    .filter(|leaf| excluded_ids.contains(leaf.id))
                    .count(),
            }
        })
        .collect();
    let catalog_leaf_count = leaves.len();
    let applicable_leaf_count = catalog_leaf_count.saturating_sub(intentional_exclusions.len());

    Coverage {
        tactic_id: TACTIC_ID,
        tactic_name: TACTIC_NAME,
        attack_version: RECONNAISSANCE_VERSION,
        coverage_fraction: ratio(covered.len(), applicable_leaf_count),
        covered,
        uncovered,
        intentional_exclusions,
        family_rollups,
        catalog_leaf_count,
        applicable_leaf_count,
    }
}

#[cfg(test)]
const MAPPED_ENTITY_KINDS: &[EntityKind] = &[
    EntityKind::Person,
    EntityKind::Email,
    EntityKind::Phone,
    EntityKind::Username,
    EntityKind::Credential,
    EntityKind::ApiKey,
    EntityKind::IpAddress,
    EntityKind::Domain,
    EntityKind::Url,
    EntityKind::Asn,
    EntityKind::Address,
    EntityKind::Coordinates,
    EntityKind::Organisation,
    EntityKind::AbnAcn,
    EntityKind::MacAddress,
    EntityKind::DeviceId,
    EntityKind::Ssid,
    EntityKind::TrackingId,
    EntityKind::CryptoAddress,
    EntityKind::Document,
];

#[cfg(test)]
const ALL_RELATION_KINDS: &[RelationKind] = &[
    RelationKind::AliasOf,
    RelationKind::LocatedAt,
    RelationKind::AssociatedWith,
    RelationKind::SameAs,
    RelationKind::MemberOf,
    RelationKind::Uses,
    RelationKind::Owns,
    RelationKind::MentionedWith,
    RelationKind::ExposedWith,
    RelationKind::Supports,
    RelationKind::Contradicts,
];

/// Structural capability from an explicit set of reachable module bindings.
///
/// Entity/relation ontology mappings are deliberately *not* folded in here:
/// knowing how an entity kind maps to ATT&CK does not prove that a reachable
/// collector currently implements that behavior.
#[must_use]
pub fn static_reconnaissance_coverage<'a>(
    module_technique_ids: impl IntoIterator<Item = &'a str>,
) -> Coverage {
    let mut counts = BTreeMap::new();
    for id in module_technique_ids {
        *counts.entry(id.to_owned()).or_insert(0) += 1;
    }
    coverage(&counts)
}

#[must_use]
pub fn coverage_by_entity_type(
    entity_techniques: &[(String, String)],
) -> Vec<TechniqueByEntityType> {
    let mut by_technique: BTreeMap<String, BTreeMap<String, usize>> = BTreeMap::new();
    for (kind, tech_id) in entity_techniques {
        by_technique
            .entry(tech_id.clone())
            .or_default()
            .entry(kind.clone())
            .and_modify(|count| *count += 1)
            .or_insert(1);
    }
    reconnaissance_leaves()
        .iter()
        .filter_map(|item| {
            by_technique
                .remove(item.id)
                .map(|by_entity_type| TechniqueByEntityType {
                    technique: **item,
                    by_entity_type,
                })
        })
        .collect()
}

#[must_use]
pub fn techniques_from_entities(entities: &[&Entity]) -> Vec<String> {
    let mut out = BTreeSet::new();
    for entity in entities {
        for tag in &entity.tags {
            if let Some(id) = tag.strip_prefix("attack:") {
                out.insert(id.to_owned());
            }
        }
    }
    out.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_id(id: &str) -> (u32, i64) {
        let core = id.trim_start_matches('T');
        match core.split_once('.') {
            Some((base, sub)) => (
                base.parse().expect("base id parses"),
                sub.parse().expect("sub id parses"),
            ),
            None => (core.parse().expect("id parses"), -1),
        }
    }

    #[test]
    fn base_catalogue_is_well_formed_sorted_and_unique() {
        for item in ENTERPRISE {
            assert!(item.id.starts_with('T'));
            let core = item.id.trim_start_matches('T');
            let (base, sub) = match core.split_once('.') {
                Some((base, sub)) => (base, Some(sub)),
                None => (core, None),
            };
            assert_eq!(sub.is_some(), item.is_subtechnique, "{}", item.id);
            assert_eq!(base.len(), 4, "{}", item.id);
            assert!(base.bytes().all(|byte| byte.is_ascii_digit()));
            if let Some(sub) = sub {
                assert_eq!(sub.len(), 3, "{}", item.id);
                assert!(sub.bytes().all(|byte| byte.is_ascii_digit()));
            }
            assert!(!item.name.is_empty(), "{} has no name", item.id);
            assert!(!item.tactics.is_empty(), "{} has no tactic", item.id);
            for shortname in item.tactics {
                assert!(TACTICS.iter().any(|tac| tac.shortname == *shortname));
            }
        }
        let ids: Vec<&str> = ENTERPRISE.iter().map(|item| item.id).collect();
        let mut sorted = ids.clone();
        sorted.sort_by_key(|id| parse_id(id));
        assert_eq!(ids, sorted);
        let unique: BTreeSet<&str> = ids.iter().copied().collect();
        assert_eq!(unique.len(), ids.len());
        let bases: BTreeSet<u32> = ENTERPRISE
            .iter()
            .filter(|item| !item.is_subtechnique)
            .map(|item| parse_id(item.id).0)
            .collect();
        for item in ENTERPRISE.iter().filter(|item| item.is_subtechnique) {
            assert!(bases.contains(&parse_id(item.id).0), "{}", item.id);
        }
    }

    #[test]
    fn pinned_base_tactics_remain_self_consistent() {
        assert_eq!(ATTACK_VERSION, "17.1");
        assert_eq!(TACTICS.len(), 14);
        assert_eq!(TACTIC_ID, "TA0043");
        assert_eq!(TACTIC_NAME, "Reconnaissance");
        assert_eq!(tactic(TACTIC_ID).map(|item| item.name), Some(TACTIC_NAME));
    }

    #[test]
    fn reconnaissance_slice_is_v19_2() {
        assert_eq!(RECONNAISSANCE_VERSION, "19.2");
        assert_eq!(reconnaissance().len(), 46);
        assert_eq!(reconnaissance_families().len(), 12);
        assert_eq!(reconnaissance_leaves().len(), 37);
        for id in ["T1681", "T1682"] {
            let item = technique(id).expect("v19.2 recon addition");
            assert!(item.tactics.contains(&"reconnaissance"));
        }
    }

    #[test]
    fn category_entity_and_relation_mappings_point_to_catalogued_recon_ids() {
        for category in [
            ModuleCategory::DnsRecon,
            ModuleCategory::Breach,
            ModuleCategory::Infrastructure,
            ModuleCategory::Search,
            ModuleCategory::Social,
            ModuleCategory::Email,
            ModuleCategory::Phone,
            ModuleCategory::Corporate,
            ModuleCategory::Threat,
            ModuleCategory::Sensor,
            ModuleCategory::People,
            ModuleCategory::Web,
            ModuleCategory::Geo,
            ModuleCategory::Other,
        ] {
            for id in techniques_for_category(category) {
                let item = technique(id).expect("category id exists");
                assert!(item.tactics.contains(&"reconnaissance"));
            }
        }
        assert!(techniques_for_category(ModuleCategory::Threat).is_empty());
        for kind in MAPPED_ENTITY_KINDS {
            for id in techniques_for_entity_kind(kind) {
                let item = technique(id).expect("entity id exists");
                assert!(item.tactics.contains(&"reconnaissance"));
            }
        }
        for &kind in ALL_RELATION_KINDS {
            for id in techniques_for_relation_kind(kind) {
                let item = technique(id).expect("relation id exists");
                assert!(item.tactics.contains(&"reconnaissance"));
            }
        }
    }

    #[test]
    fn coverage_uses_leaves_and_separates_exclusions() {
        let exercised = BTreeMap::from([
            ("T1596.002".to_owned(), 5_usize),
            ("T1589.002".to_owned(), 2_usize),
            ("T1589".to_owned(), 9_usize),
            ("T9999".to_owned(), 99_usize),
        ]);
        let cov = coverage(&exercised);
        assert_eq!(cov.tactic_id, TACTIC_ID);
        assert_eq!(cov.attack_version, RECONNAISSANCE_VERSION);
        assert_eq!(cov.catalog_leaf_count, 37);
        assert_eq!(cov.applicable_leaf_count, 32);
        assert_eq!(cov.covered.len(), 2);
        assert_eq!(cov.uncovered.len(), 30);
        assert_eq!(cov.intentional_exclusions.len(), 5);
        assert_eq!(cov.covered[0].technique.id, "T1589.002");
        assert_eq!(cov.covered[1].technique.id, "T1596.002");
        assert_eq!(cov.covered[1].entity_count, 5);
        assert!(!cov.covered.iter().any(|item| item.technique.id == "T1589"));
        assert!(cov.uncovered.iter().any(|item| item.id == "T1681"));
        assert!(!cov.uncovered.iter().any(|item| item.id == "T1682"));
    }

    #[test]
    fn relation_fold_counts_edges() {
        let relations = vec![
            EntityRelation::new("a", "b", RelationKind::MemberOf, 0.9),
            EntityRelation::new("c", "d", RelationKind::MemberOf, 0.9),
            EntityRelation::new("e", "f", RelationKind::Owns, 0.9),
            EntityRelation::new("g", "h", RelationKind::Uses, 0.9),
        ];
        let mut exercised = BTreeMap::from([("T1591".to_owned(), 2_usize)]);
        fold_relation_techniques(&mut exercised, &relations);
        assert_eq!(exercised.get("T1591"), Some(&4));
        assert_eq!(exercised.get("T1591.002"), Some(&1));
        assert_eq!(exercised.len(), 2);
    }

    #[test]
    fn structural_coverage_requires_explicit_reachable_bindings() {
        let empty = static_reconnaissance_coverage(std::iter::empty::<&str>());
        assert!(empty.covered.is_empty());
        assert_eq!(empty.uncovered.len(), 32);

        let cov = static_reconnaissance_coverage(["T1595.001", "T1596.002", "T1589.001"]);
        let covered: BTreeSet<&str> = cov.covered.iter().map(|item| item.technique.id).collect();
        assert_eq!(
            covered,
            BTreeSet::from(["T1589.001", "T1595.001", "T1596.002"])
        );
        assert_eq!(cov.coverage_fraction, 3.0 / 32.0);
    }

    #[test]
    fn techniques_from_entities_extracts_sorted_unique_attack_tags() {
        let mut a = Entity::new(EntityKind::Email, "test1@example.com", 0.8, "s");
        a.tag("attack:T1589.002");
        a.tag("attack:T1593.002");
        let mut b = Entity::new(EntityKind::Username, "testuser", 0.7, "s");
        b.tag("attack:T1589.002");
        b.tag("attack:T1593.001");
        b.tag("sector:tech");
        let ids = techniques_from_entities(&[&a, &b]);
        assert_eq!(ids, vec!["T1589.002", "T1593.001", "T1593.002"]);
    }

    #[test]
    fn coverage_by_entity_type_aggregates_leaf_techniques_only() {
        let rows = vec![
            ("Person".to_owned(), "T1589".to_owned()),
            ("Email".to_owned(), "T1589.002".to_owned()),
            ("Email".to_owned(), "T1589.002".to_owned()),
            ("Username".to_owned(), "T1593.001".to_owned()),
        ];
        let by_type = coverage_by_entity_type(&rows);
        assert_eq!(by_type.len(), 2);
        assert_eq!(by_type[0].technique.id, "T1589.002");
        assert_eq!(by_type[1].technique.id, "T1593.001");
        assert_eq!(by_type[0].by_entity_type.get("Email"), Some(&2));
    }
}
