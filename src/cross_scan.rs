//! Cross-scan bridge analysis with injected storage boundaries.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use serde::{Deserialize, Serialize};

use crate::entity::{Entity, EntityKind};
use crate::error::Error;
use crate::tags;

const DEFAULT_MAX_FRONTIER: usize = 128;
const DEFAULT_MAX_VISITED: usize = 512;

/// Storage boundary for history-aware bridge lookups.
pub trait CrossScanStore {
    /// # Errors
    /// Returns storage-layer lookup failures.
    fn entities_for_scan(&self, scan_id: &str) -> Result<Vec<Entity>, Error>;

    /// # Errors
    /// Returns storage-layer lookup failures.
    fn scan_ids_for_entity(&self, entity_uid: &str) -> Result<Vec<String>, Error>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum BridgeTier {
    Direct,
    Alias,
    Related,
}

impl BridgeTier {
    #[must_use]
    pub fn is_stronger_than(self, other: Self) -> bool {
        self < other
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BridgedEntity {
    pub entity: Entity,
    pub tier: BridgeTier,
    pub overlapping_scans: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransitiveLink {
    pub origin_scan_id: String,
    pub via_entity_uid: String,
    pub target_scan_id: String,
    pub depth: usize,
    pub tier: BridgeTier,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum CrossScanCategory {
    None,
    Historical { matches: Vec<BridgedEntity> },
    Relation { matches: Vec<BridgedEntity> },
    Transitive { links: Vec<TransitiveLink> },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrossScanOptions {
    pub max_frontier: usize,
    pub max_visited: usize,
}

impl Default for CrossScanOptions {
    fn default() -> Self {
        Self {
            max_frontier: DEFAULT_MAX_FRONTIER,
            max_visited: DEFAULT_MAX_VISITED,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrossScanRecord {
    pub uid: String,
    pub value: String,
    pub kind: String,
    pub scan_ids: Vec<String>,
    pub sightings: usize,
}

#[must_use]
pub fn build_cross_scan_history(entities: &[Entity]) -> Vec<CrossScanRecord> {
    let mut buckets = BTreeMap::<String, (String, String, BTreeSet<String>)>::new();
    for entity in entities {
        let entry = buckets.entry(entity.uid.clone()).or_insert_with(|| {
            (
                entity.value.clone(),
                entity.kind.to_string(),
                BTreeSet::new(),
            )
        });
        if !entity.scan_id.is_empty() {
            entry.2.insert(entity.scan_id.clone());
        }
        for evidence in &entity.evidence {
            if let Some(scan_id) = &evidence.provenance.scan_id {
                entry.2.insert(scan_id.clone());
            }
        }
    }
    let mut records = buckets
        .into_iter()
        .map(|(uid, (value, kind, scan_ids))| CrossScanRecord {
            uid,
            value,
            kind,
            sightings: scan_ids.len(),
            scan_ids: scan_ids.into_iter().collect(),
        })
        .collect::<Vec<_>>();
    records.sort_by(|left, right| {
        right
            .sightings
            .cmp(&left.sightings)
            .then_with(|| left.uid.cmp(&right.uid))
    });
    records
}

/// Classifies a scan using stored cross-scan history.
///
/// # Errors
/// Returns storage-layer lookup failures.
pub fn category_for_scan<S: CrossScanStore>(
    store: &S,
    scan_id: &str,
) -> Result<CrossScanCategory, Error> {
    category_for_scan_with(store, scan_id, CrossScanOptions::default())
}

/// Classifies a scan using stored history and explicit traversal limits.
///
/// # Errors
/// Returns storage-layer lookup failures.
pub fn category_for_scan_with<S: CrossScanStore>(
    store: &S,
    scan_id: &str,
    options: CrossScanOptions,
) -> Result<CrossScanCategory, Error> {
    let entities = store.entities_for_scan(scan_id)?;
    category_from_entities(store, scan_id, &entities, options)
}

/// Resolves the strongest cross-scan category from an in-memory entity batch.
///
/// # Errors
/// Returns storage-layer lookup failures.
pub fn category_from_entities<S: CrossScanStore>(
    store: &S,
    scan_id: &str,
    entities: &[Entity],
    options: CrossScanOptions,
) -> Result<CrossScanCategory, Error> {
    let direct = collect_direct_bridges(store, scan_id, entities)?;
    if direct.is_empty() {
        return Ok(CrossScanCategory::None);
    }

    let strongest = direct
        .iter()
        .map(|bridge| bridge.tier)
        .min()
        .unwrap_or(BridgeTier::Related);
    let strongest_matches = direct
        .iter()
        .filter(|bridge| bridge.tier == strongest)
        .cloned()
        .collect::<Vec<_>>();

    match strongest {
        BridgeTier::Direct | BridgeTier::Alias => Ok(CrossScanCategory::Historical {
            matches: strongest_matches,
        }),
        BridgeTier::Related => {
            let links = transitive_closure(store, scan_id, &strongest_matches, options)?;
            if links.is_empty() {
                Ok(CrossScanCategory::Relation {
                    matches: strongest_matches,
                })
            } else {
                Ok(CrossScanCategory::Transitive { links })
            }
        }
    }
}

/// Looks for directly recurring entities in prior scans.
///
/// # Errors
/// Returns storage-layer lookup failures.
pub fn collect_direct_bridges<S: CrossScanStore>(
    store: &S,
    current_scan_id: &str,
    entities: &[Entity],
) -> Result<Vec<BridgedEntity>, Error> {
    let mut matches = Vec::new();
    for entity in entities {
        if !is_bridgeable(entity) {
            continue;
        }
        let historical = overlapping_scans(store, current_scan_id, entity)?;
        if historical.is_empty() {
            continue;
        }
        matches.push(BridgedEntity {
            entity: entity.clone(),
            tier: bridge_tier(entity),
            overlapping_scans: historical,
        });
    }
    matches.sort_by(|left, right| {
        left.tier
            .cmp(&right.tier)
            .then_with(|| {
                right
                    .overlapping_scans
                    .len()
                    .cmp(&left.overlapping_scans.len())
            })
            .then_with(|| left.entity.uid.cmp(&right.entity.uid))
    });
    Ok(matches)
}

/// Expands weak bridges through related scans up to the configured limits.
///
/// # Errors
/// Returns storage-layer lookup failures.
pub fn transitive_closure<S: CrossScanStore>(
    store: &S,
    origin_scan_id: &str,
    seeds: &[BridgedEntity],
    options: CrossScanOptions,
) -> Result<Vec<TransitiveLink>, Error> {
    let mut queue = VecDeque::new();
    let mut visited_scans = BTreeSet::from([origin_scan_id.to_string()]);
    let mut seen_edges = BTreeSet::new();
    let mut links = Vec::new();

    for seed in seeds {
        for scan_id in &seed.overlapping_scans {
            if scan_id == origin_scan_id || !visited_scans.insert(scan_id.clone()) {
                continue;
            }
            queue.push_back((scan_id.clone(), seed.entity.uid.clone(), 1usize, seed.tier));
        }
    }

    while let Some((scan_id, via_entity_uid, depth, tier)) = queue.pop_front() {
        if links.len() >= options.max_frontier || visited_scans.len() > options.max_visited {
            break;
        }
        let edge_key = (
            origin_scan_id.to_string(),
            via_entity_uid.clone(),
            scan_id.clone(),
        );
        if !seen_edges.insert(edge_key) {
            continue;
        }
        links.push(TransitiveLink {
            origin_scan_id: origin_scan_id.to_string(),
            via_entity_uid: via_entity_uid.clone(),
            target_scan_id: scan_id.clone(),
            depth,
            tier,
        });

        if depth >= 2 {
            continue;
        }

        for entity in store.entities_for_scan(&scan_id)? {
            if !is_bridgeable(&entity) {
                continue;
            }
            for neighbor in overlapping_scans(store, &scan_id, &entity)? {
                if neighbor == origin_scan_id || !visited_scans.insert(neighbor.clone()) {
                    continue;
                }
                queue.push_back((neighbor, entity.uid.clone(), depth + 1, BridgeTier::Related));
            }
        }
    }

    links.sort_by(|left, right| {
        left.depth
            .cmp(&right.depth)
            .then_with(|| left.target_scan_id.cmp(&right.target_scan_id))
            .then_with(|| left.via_entity_uid.cmp(&right.via_entity_uid))
    });
    Ok(links)
}

#[must_use]
pub fn alias_handles(email: &str) -> Vec<String> {
    let local = email.split('@').next().unwrap_or(email).trim();
    if local.is_empty() {
        return Vec::new();
    }
    let base = local.split('+').next().unwrap_or(local);
    if !is_anchorable_handle(base) {
        return Vec::new();
    }
    let mut handles = BTreeSet::from([base.to_ascii_lowercase()]);
    if let Some(canonical) = crate::canonical::canonical_handle(base) {
        if canonical.len() >= 3 {
            handles.insert(canonical);
        }
    }
    handles.into_iter().collect()
}

#[must_use]
pub fn bridge_tier(entity: &Entity) -> BridgeTier {
    match entity.kind {
        EntityKind::Email | EntityKind::Phone | EntityKind::Username => BridgeTier::Direct,
        EntityKind::Person | EntityKind::Organisation => BridgeTier::Alias,
        _ => BridgeTier::Related,
    }
}

#[must_use]
pub fn is_bridgeable(entity: &Entity) -> bool {
    if entity.value.trim().is_empty() || entity.scan_id.trim().is_empty() {
        return false;
    }
    if entity
        .tags
        .iter()
        .any(|tag| tag == tags::CANDIDATE || tag == "quarantined" || tag == "promoted")
    {
        return false;
    }
    if entity.confidence < 0.45 {
        return false;
    }
    match entity.kind {
        EntityKind::Person
        | EntityKind::Organisation
        | EntityKind::Coordinates
        | EntityKind::Address => false,
        EntityKind::Username => crate::canonical::canonical_handle(&entity.value)
            .is_some_and(|canonical| canonical.len() >= 3),
        EntityKind::Email => !alias_handles(&entity.value).is_empty() || entity.value.contains('@'),
        _ => true,
    }
}

fn overlapping_scans<S: CrossScanStore>(
    store: &S,
    current_scan_id: &str,
    entity: &Entity,
) -> Result<Vec<String>, Error> {
    let scan_ids = store.scan_ids_for_entity(&entity.uid)?;
    let mut overlaps = BTreeSet::new();
    for scan_id in scan_ids {
        if scan_id != current_scan_id {
            overlaps.insert(scan_id);
        }
    }
    Ok(overlaps.into_iter().collect())
}

fn is_anchorable_handle(local: &str) -> bool {
    let detagged = local.split('+').next().unwrap_or(local);
    let base = detagged
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .map(|c| c.to_ascii_lowercase())
        .collect::<String>();
    if base.len() < 3 {
        return false;
    }
    !matches!(
        base.as_str(),
        "admin"
            | "administrator"
            | "info"
            | "support"
            | "help"
            | "helpdesk"
            | "contact"
            | "sales"
            | "abuse"
            | "postmaster"
            | "hostmaster"
            | "webmaster"
            | "noreply"
            | "donotreply"
            | "dns"
            | "root"
            | "mail"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    use crate::entity::{Entity, EntityKind, Evidence, EvidenceProvenance};

    #[derive(Default)]
    struct FakeStore {
        by_scan: BTreeMap<String, Vec<Entity>>,
        by_uid: BTreeMap<String, Vec<String>>,
    }

    impl FakeStore {
        fn insert(&mut self, entity: Entity) {
            self.by_uid
                .entry(entity.uid.clone())
                .or_default()
                .push(entity.scan_id.clone());
            self.by_scan
                .entry(entity.scan_id.clone())
                .or_default()
                .push(entity);
        }
    }

    impl CrossScanStore for FakeStore {
        fn entities_for_scan(&self, scan_id: &str) -> Result<Vec<Entity>, Error> {
            Ok(self.by_scan.get(scan_id).cloned().unwrap_or_default())
        }

        fn scan_ids_for_entity(&self, entity_uid: &str) -> Result<Vec<String>, Error> {
            Ok(self.by_uid.get(entity_uid).cloned().unwrap_or_default())
        }
    }

    fn entity(kind: EntityKind, value: &str, confidence: f64, scan_id: &str) -> Entity {
        Entity::builder(kind, value, confidence, scan_id).build()
    }

    #[test]
    fn history_collects_unique_scan_ids() {
        let entity = Entity::builder(EntityKind::Email, "ada@example.com", 0.8, "scan-a")
            .evidence(Evidence::new(
                EvidenceProvenance::for_scan("hibp", "scan-b"),
                "row",
            ))
            .build();
        let history = build_cross_scan_history(&[entity]);
        assert_eq!(history[0].sightings, 2);
    }

    #[test]
    fn alias_handles_strip_plus_tags_and_punctuation() {
        let handles = alias_handles("Ada.Lovelace+ops@example.com");
        assert_eq!(
            handles,
            vec!["ada.lovelace".to_string(), "adalovelace".to_string()]
        );
        assert!(alias_handles("support@example.com").is_empty());
    }

    #[test]
    fn direct_bridges_produce_historical_category() {
        let mut store = FakeStore::default();
        store.insert(entity(EntityKind::Email, "ada@example.com", 0.9, "scan-a"));
        store.insert(entity(EntityKind::Email, "ada@example.com", 0.9, "scan-b"));

        let current = store.entities_for_scan("scan-a").unwrap();
        let category =
            category_from_entities(&store, "scan-a", &current, CrossScanOptions::default())
                .unwrap();
        match category {
            CrossScanCategory::Historical { matches } => {
                assert_eq!(matches.len(), 1);
                assert_eq!(matches[0].overlapping_scans, vec!["scan-b".to_string()]);
            }
            other => panic!("expected historical bridge, got {other:?}"),
        }
    }

    #[test]
    fn related_entities_walk_transitively() {
        let mut store = FakeStore::default();
        store.insert(entity(EntityKind::IpAddress, "1.1.1.1", 0.9, "scan-a"));
        store.insert(entity(EntityKind::IpAddress, "1.1.1.1", 0.9, "scan-b"));
        store.insert(entity(EntityKind::IpAddress, "2.2.2.2", 0.9, "scan-b"));
        store.insert(entity(EntityKind::IpAddress, "2.2.2.2", 0.9, "scan-c"));

        let current = store.entities_for_scan("scan-a").unwrap();
        let category =
            category_from_entities(&store, "scan-a", &current, CrossScanOptions::default())
                .unwrap();
        match category {
            CrossScanCategory::Transitive { links } => {
                assert_eq!(links[0].target_scan_id, "scan-b");
                assert_eq!(links[0].depth, 1);
                assert!(
                    links
                        .iter()
                        .any(|link| link.target_scan_id == "scan-c" && link.depth == 2)
                );
            }
            other => panic!("expected transitive bridge, got {other:?}"),
        }
    }

    #[test]
    fn candidate_entities_do_not_bridge() {
        let mut store = FakeStore::default();
        store.insert(
            Entity::builder(EntityKind::Email, "ada@example.com", 0.9, "scan-a")
                .tag(tags::CANDIDATE)
                .build(),
        );
        store.insert(entity(EntityKind::Email, "ada@example.com", 0.9, "scan-b"));

        let current = store.entities_for_scan("scan-a").unwrap();
        let category =
            category_from_entities(&store, "scan-a", &current, CrossScanOptions::default())
                .unwrap();
        assert_eq!(category, CrossScanCategory::None);
    }
}
