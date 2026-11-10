//! Cross-scan bridge analysis with injected storage boundaries.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use serde::{Deserialize, Serialize};

use crate::entity::{Entity, EntityKind, Evidence};
use crate::error::Error;
use crate::tags;

const DEFAULT_MAX_FRONTIER: usize = 128;
const DEFAULT_MAX_VISITED: usize = 512;

/// Storage boundary for history-aware bridge lookups.
pub trait CrossScanStore {
    /// # Errors
    /// Returns storage-layer lookup failures.
    fn entities_for_scan(&self, scan_id: &str) -> Result<Vec<Entity>, Error>;

    /// Return only scan ids with at least one bridge-eligible observation of this UID.
    /// Raw history may retain additional candidate/weak observations separately.
    ///
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

impl BridgeTier {}

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
    // Pages may repeat an entity UID in one scan. It is one cross-scan link, not
    // independent corroboration. Merge only the derived bridge view; do not
    // alter the store's original entity records or source evidence.
    let mut by_uid = BTreeMap::<String, BridgedEntity>::new();
    for entity in entities {
        // Check before merging: a quarantined candidate must never contaminate
        // an independently bridgeable observation of the same identity.
        if entity.scan_id != current_scan_id || !is_bridgeable(entity) {
            continue;
        }
        if let Some(existing) = by_uid.get_mut(&entity.uid) {
            // Absorb the distinct source evidence, but not an extra unsupported
            // corroboration simply because the same page yielded the UID twice.
            let corroboration = existing.entity.corroboration.max(entity.corroboration);
            existing.entity.absorb(entity.clone());
            existing.entity.corroboration = corroboration;
            continue;
        }
        let historical = overlapping_scans(store, current_scan_id, entity)?;
        if historical.is_empty() {
            continue;
        }
        by_uid.insert(entity.uid.clone(), BridgedEntity {
            entity: entity.clone(),
            tier: bridge_tier(entity),
            overlapping_scans: historical,
        });
    }
    let mut matches: Vec<_> = by_uid.into_values().collect();
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
/// Visits are reserved before insertion into the queue: high-fan-out seeds
/// cannot exhaust the frontier or visit budget before results are emitted.
/// Incompleteness is represented conservatively by the bounded returned set;
/// this function does not imply that unvisited scans were checked.
///
/// # Errors
/// Returns storage-layer lookup failures for scans that were actually visited.
pub fn transitive_closure<S: CrossScanStore>(
    store: &S,
    origin_scan_id: &str,
    seeds: &[BridgedEntity],
    options: CrossScanOptions,
) -> Result<Vec<TransitiveLink>, Error> {
    if options.max_frontier == 0 || options.max_visited <= 1 {
        return Ok(Vec::new());
    }

    let mut queue = VecDeque::new();
    let mut visited_scans = BTreeSet::from([origin_scan_id.to_owned()]);
    let mut links = Vec::new();

    // A discovered scan reserves both one visited slot and one output slot.
    // The origin is counted in max_visited but never becomes a link.
    for seed in seeds {
        // Direct callers must not turn a foreign scan's retained row into an
        // observation by the origin scan.
        if seed.entity.scan_id != origin_scan_id || !is_bridgeable(&seed.entity) {
            continue;
        }
        // BridgedEntity is public and deserializable: supplied neighbours and
        // tier are claims, not evidence. Revalidate against the store before
        // reserving a frontier slot, even for direct API callers.
        let verified_scans = overlapping_scans(store, origin_scan_id, &seed.entity)?;
        let verified_tier = bridge_tier(&seed.entity);
        for scan_id in &seed.overlapping_scans {
            if verified_scans.binary_search(scan_id).is_err() {
                continue;
            }
            if visited_scans.len() >= options.max_visited
                || visited_scans.len() > options.max_frontier
            {
                break;
            }
            if visited_scans.insert(scan_id.clone()) {
                queue.push_back((
                    scan_id.clone(),
                    seed.entity.uid.clone(),
                    1usize,
                    verified_tier,
                ));
            }
        }
    }

    while let Some((scan_id, via_entity_uid, depth, tier)) = queue.pop_front() {
        links.push(TransitiveLink {
            origin_scan_id: origin_scan_id.to_owned(),
            via_entity_uid,
            target_scan_id: scan_id.clone(),
            depth,
            tier,
        });

        if depth >= 2
            || visited_scans.len() >= options.max_visited
            || visited_scans.len() > options.max_frontier
        {
            continue;
        }
        for entity in store.entities_for_scan(&scan_id)? {
            // A copied row stored in this scan is not a new observation that
            // can justify a transitive hop to another scan.
            if entity.scan_id != scan_id || !is_bridgeable(&entity) {
                continue;
            }
            for neighbor in overlapping_scans(store, &scan_id, &entity)? {
                if visited_scans.len() >= options.max_visited
                    || visited_scans.len() > options.max_frontier
                {
                    break;
                }
                if visited_scans.insert(neighbor.clone()) {
                    queue.push_back((neighbor, entity.uid.clone(), depth + 1, BridgeTier::Related));
                }
            }
            if visited_scans.len() >= options.max_visited
                || visited_scans.len() > options.max_frontier
            {
                break;
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
    // Persisted entity IDs are input data, not authority. A stale or forged UID
    // must not join unrelated kinds/values across scans. Retain the original
    // record in raw history; only exclude it from the derived bridge view.
    if entity.uid != crate::entity::derive_uid(&entity.kind, &entity.value) {
        return false;
    }
    if entity
        .tags
        .iter()
        .any(|tag| tag == tags::CANDIDATE || tag == "quarantined" || tag == "promoted")
    {
        return false;
    }
    // A finding must reach 0.45 to bridge. An operator's seed is the query itself, which every
    // seed carries at 0.25, so the seed bridges on its value and a weak finding still does not.
    if entity.confidence < 0.45 && !entity.evidence.iter().any(Evidence::is_operator_seed) {
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
        // Thousands of unrelated networks broadcast `xfinitywifi` or `NETGEAR-Guest`; sharing one
        // says nothing about who runs either network, so it never joins two scans.
        EntityKind::Ssid => !crate::value_syntax::is_generic_ssid(&entity.value),
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
            if is_bridgeable(&entity) {
                self.by_uid
                    .entry(entity.uid.clone())
                    .or_default()
                    .push(entity.scan_id.clone());
            }
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
        let handles = alias_handles("support@example.com");
        assert!(handles.is_empty(), "{handles:?}");
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
    fn repeated_uid_is_one_bridge_with_all_independent_evidence_retained() {
        let mut store = FakeStore::default();
        let mut first = entity(EntityKind::Email, "ada@example.com", 0.6, "scan-a");
        first.add_evidence(Evidence::new(
            EvidenceProvenance::for_scan("hibp", "scan-a"),
            "first source record",
        ));
        let mut second = entity(EntityKind::Email, "ada@example.com", 0.9, "scan-a");
        second.add_evidence(Evidence::new(
            EvidenceProvenance::for_scan("dehashed", "scan-a"),
            "second source record",
        ));
        store.insert(first);
        store.insert(second);
        store.insert(entity(EntityKind::Email, "ada@example.com", 0.8, "scan-b"));

        let original = store.entities_for_scan("scan-a").unwrap();
        assert_eq!(original.len(), 2, "raw history must not be deduplicated");
        let bridges = collect_direct_bridges(&store, "scan-a", &original).unwrap();
        assert_eq!(bridges.len(), 1, "one UID is one cross-scan bridge");
        assert_eq!(bridges[0].overlapping_scans, vec!["scan-b".to_string()]);
        assert_eq!(bridges[0].entity.confidence, 0.9);
        assert_eq!(bridges[0].entity.evidence.len(), 2);
        let sources: BTreeSet<_> = bridges[0]
            .entity
            .evidence
            .iter()
            .map(|evidence| evidence.provenance.source.as_str())
            .collect();
        assert_eq!(sources, BTreeSet::from(["hibp", "dehashed"]));
        assert_eq!(store.entities_for_scan("scan-a").unwrap(), original);

        let category =
            category_from_entities(&store, "scan-a", &original, CrossScanOptions::default())
                .unwrap();
        let CrossScanCategory::Historical { matches } = category else {
            panic!("expected one historical bridge, got {category:?}");
        };
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].entity.evidence.len(), 2);
    }

    #[test]
    fn repeated_evidence_free_rows_do_not_inflate_corroboration() {
        let mut store = FakeStore::default();
        store.insert(entity(EntityKind::Email, "ada@example.com", 0.8, "scan-a"));
        store.insert(entity(EntityKind::Email, "ada@example.com", 0.8, "scan-a"));
        store.insert(entity(EntityKind::Email, "ada@example.com", 0.8, "scan-b"));

        let original = store.entities_for_scan("scan-a").unwrap();
        assert_eq!(original.len(), 2);
        let bridges = collect_direct_bridges(&store, "scan-a", &original).unwrap();
        assert_eq!(bridges.len(), 1);
        assert_eq!(bridges[0].entity.corroboration, 1);
        assert_eq!(bridges[0].entity.source_count(), 1);
        assert_eq!(store.entities_for_scan("scan-a").unwrap(), original);
    }

    #[test]
    fn a_quarantined_duplicate_does_not_contaminate_the_valid_bridge() {
        let mut store = FakeStore::default();
        let mut candidate = entity(EntityKind::Email, "ada@example.com", 0.9, "scan-a");
        candidate.tag(tags::CANDIDATE);
        candidate.add_evidence(Evidence::new(
            EvidenceProvenance::for_scan("unconfirmed", "scan-a"),
            "not an admitted bridge",
        ));
        let mut observed = entity(EntityKind::Email, "ada@example.com", 0.8, "scan-a");
        observed.add_evidence(Evidence::new(
            EvidenceProvenance::for_scan("observed", "scan-a"),
            "admitted source",
        ));
        store.insert(candidate);
        store.insert(observed);
        store.insert(entity(EntityKind::Email, "ada@example.com", 0.8, "scan-b"));

        let original = store.entities_for_scan("scan-a").unwrap();
        let bridges = collect_direct_bridges(&store, "scan-a", &original).unwrap();
        assert_eq!(bridges.len(), 1);
        assert!(is_bridgeable(&bridges[0].entity));
        assert_eq!(bridges[0].entity.evidence.len(), 1);
        assert_eq!(bridges[0].entity.evidence[0].provenance.source, "observed");
        assert_eq!(store.entities_for_scan("scan-a").unwrap(), original);
    }

    #[test]
    fn forged_uid_never_creates_a_cross_scan_bridge() {
        let mut store = FakeStore::default();
        let current = entity(EntityKind::Email, "ada@example.com", 0.9, "scan-a");

        // The UID belongs to Ada's email, but the retained row claims a
        // different email. A deserialized artifact can carry this mismatch.
        let mut mismatched_value = entity(EntityKind::Email, "bob@example.com", 0.9, "scan-b");
        mismatched_value.uid.clone_from(&current.uid);
        assert!(
            !is_bridgeable(&mismatched_value),
            "a forged UID must not pass the evidence bridge gate"
        );

        // A different kind of entity cannot impersonate the same UID either.
        let mut mismatched_kind = entity(EntityKind::Username, "ada", 0.9, "scan-d");
        mismatched_kind.uid.clone_from(&current.uid);
        assert!(!is_bridgeable(&mismatched_kind));

        store.insert(current.clone());
        store.insert(mismatched_value);
        store.insert(mismatched_kind);
        let original = store.entities_for_scan("scan-a").unwrap();
        assert_eq!(
            category_from_entities(&store, "scan-a", &original, CrossScanOptions::default())
                .unwrap(),
            CrossScanCategory::None,
        );

        store.insert(entity(EntityKind::Email, "ada@example.com", 0.9, "scan-c"));
        match category_from_entities(&store, "scan-a", &original, CrossScanOptions::default())
            .unwrap()
        {
            CrossScanCategory::Historical { matches } => {
                assert_eq!(matches.len(), 1);
                assert_eq!(matches[0].overlapping_scans, vec!["scan-c".to_owned()]);
            }
            other => panic!("expected only the legitimate observation, got {other:?}"),
        }
    }

    #[test]
    fn copied_row_cannot_impersonate_the_current_scans_observation() {
        let mut store = FakeStore::default();
        let original = entity(EntityKind::Email, "ada@example.com", 0.9, "scan-original");
        store.insert(original.clone());

        // A saved scan can contain a retained entity from a different scan.
        // Its UID is valid, but it is not an observation by scan-copied.
        let copied = original.clone();
        assert_eq!(
            category_from_entities(
                &store,
                "scan-copied",
                &[copied.clone()],
                CrossScanOptions::default(),
            )
            .unwrap(),
            CrossScanCategory::None,
        );
        assert_eq!(copied.scan_id, "scan-original");

        store.insert(entity(
            EntityKind::Email,
            "ada@example.com",
            0.9,
            "scan-copied",
        ));
        let actual = store.entities_for_scan("scan-copied").unwrap();
        match category_from_entities(&store, "scan-copied", &actual, CrossScanOptions::default())
            .unwrap()
        {
            CrossScanCategory::Historical { matches } => {
                assert_eq!(matches.len(), 1);
                assert_eq!(
                    matches[0].overlapping_scans,
                    vec!["scan-original".to_owned()],
                );
            }
            other => panic!("expected only the real current observation, got {other:?}"),
        }
    }

    #[test]
    fn copied_intermediate_row_cannot_invent_a_transitive_path() {
        let mut store = FakeStore::default();
        store.insert(entity(EntityKind::IpAddress, "198.51.100.1", 0.9, "scan-a"));
        store.insert(entity(EntityKind::IpAddress, "198.51.100.1", 0.9, "scan-b"));
        let copied = entity(EntityKind::IpAddress, "198.51.100.2", 0.9, "scan-c");
        store.insert(copied.clone());
        store
            .by_scan
            .entry("scan-b".to_owned())
            .or_default()
            .push(copied.clone());

        let first = store.entities_for_scan("scan-a").unwrap();
        let category =
            category_from_entities(&store, "scan-a", &first, CrossScanOptions::default()).unwrap();
        let CrossScanCategory::Transitive { links } = category else {
            panic!("expected only the direct scan-b path, got {category:?}");
        };
        assert_eq!(links.len(), 1, "{links:?}");
        assert_eq!(links[0].target_scan_id, "scan-b");
        assert_eq!(links[0].depth, 1);
        assert_eq!(store.entities_for_scan("scan-b").unwrap().len(), 2);

        // The identical value really observed by scan-b admits the second hop.
        store.insert(entity(EntityKind::IpAddress, "198.51.100.2", 0.9, "scan-b"));
        let category =
            category_from_entities(&store, "scan-a", &first, CrossScanOptions::default()).unwrap();
        let CrossScanCategory::Transitive { links } = category else {
            panic!("expected a genuine second hop, got {category:?}");
        };
        assert!(links.iter().any(|link| {
            link.target_scan_id == "scan-c" && link.depth == 2
        }));
        assert!(store
            .entities_for_scan("scan-b")
            .unwrap()
            .iter()
            .any(|item| item == &copied));
    }

    #[test]
    fn direct_transitive_api_refuses_a_seed_owned_by_another_scan() {
        let mut store = FakeStore::default();
        let origin = entity(EntityKind::IpAddress, "198.51.100.8", 0.9, "scan-origin");
        let other = entity(EntityKind::IpAddress, "198.51.100.8", 0.9, "scan-other");
        store.insert(origin.clone());
        store.insert(other.clone());

        let copied_seed = BridgedEntity {
            entity: other,
            tier: BridgeTier::Related,
            overlapping_scans: vec!["scan-other".to_owned()],
        };
        assert!(
            transitive_closure(
                &store,
                "scan-origin",
                &[copied_seed],
                CrossScanOptions::default(),
            )
            .unwrap()
            .is_empty(),
            "the public traversal API must check seed ownership",
        );

        let genuine_seed = BridgedEntity {
            entity: origin,
            tier: BridgeTier::Related,
            overlapping_scans: vec!["scan-other".to_owned()],
        };
        let links = transitive_closure(
            &store,
            "scan-origin",
            &[genuine_seed],
            CrossScanOptions::default(),
        )
        .unwrap();
        assert_eq!(links.len(), 1);
        assert_eq!(links[0].target_scan_id, "scan-other");
        assert_eq!(links[0].depth, 1);
        assert_eq!(store.entities_for_scan("scan-other").unwrap().len(), 1);
    }

    #[test]
    fn public_transitive_api_rejects_invented_neighbors_and_tier() {
        let mut store = FakeStore::default();
        let origin = entity(EntityKind::IpAddress, "198.51.100.8", 0.9, "scan-origin");
        store.insert(origin.clone());
        store.insert(entity(
            EntityKind::IpAddress,
            "198.51.100.8",
            0.9,
            "scan-real",
        ));
        store.insert(entity(
            EntityKind::IpAddress,
            "198.51.100.9",
            0.9,
            "scan-unrelated",
        ));
        let before = store.entities_for_scan("scan-origin").unwrap();
        let claimed = BridgedEntity {
            entity: origin.clone(),
            // A public API caller can forge both the claimed tier and neighbors.
            tier: BridgeTier::Direct,
            overlapping_scans: vec![
                "scan-unrelated".to_owned(),
                "scan-real".to_owned(),
                "scan-absent".to_owned(),
            ],
        };
        let links = transitive_closure(
            &store,
            "scan-origin",
            &[claimed],
            CrossScanOptions::default(),
        )
        .unwrap();
        assert_eq!(links.len(), 1, "unverified neighbors must be excluded");
        assert_eq!(links[0].target_scan_id, "scan-real");
        assert_eq!(links[0].depth, 1);
        assert_eq!(links[0].tier, BridgeTier::Related);

        let unsupported_only = BridgedEntity {
            entity: origin,
            tier: BridgeTier::Related,
            overlapping_scans: vec!["scan-absent".to_owned()],
        };
        assert!(
            transitive_closure(
                &store,
                "scan-origin",
                &[unsupported_only],
                CrossScanOptions::default(),
            )
            .unwrap()
            .is_empty(),
        );
        assert_eq!(store.entities_for_scan("scan-origin").unwrap(), before);
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
    fn a_generic_ssid_never_bridges_scans_and_a_distinctive_one_does() {
        for generic in ["xfinitywifi", "NETGEAR-Guest", "Free Public WiFi"] {
            let mut store = FakeStore::default();
            store.insert(entity(EntityKind::Ssid, generic, 0.8, "scan-a"));
            store.insert(entity(EntityKind::Ssid, generic, 0.8, "scan-b"));
            let current = store.entities_for_scan("scan-a").unwrap();
            let category =
                category_from_entities(&store, "scan-a", &current, CrossScanOptions::default())
                    .unwrap();
            assert_eq!(category, CrossScanCategory::None, "{generic}");
        }

        let mut store = FakeStore::default();
        store.insert(entity(EntityKind::Ssid, "Lovelace-House", 0.8, "scan-a"));
        store.insert(entity(EntityKind::Ssid, "Lovelace-House", 0.8, "scan-b"));
        let current = store.entities_for_scan("scan-a").unwrap();
        let category =
            category_from_entities(&store, "scan-a", &current, CrossScanOptions::default())
                .unwrap();
        assert_ne!(category, CrossScanCategory::None);
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

    #[test]
    fn a_large_seed_fanout_never_exceeds_either_budget() {
        let mut store = FakeStore::default();
        let shared = entity(EntityKind::IpAddress, "203.0.113.10", 0.9, "origin");
        store.insert(shared.clone());
        for number in 0..250 {
            store.insert(entity(
                EntityKind::IpAddress,
                "203.0.113.10",
                0.9,
                &format!("scan-{number:03}"),
            ));
        }
        let seeds = collect_direct_bridges(&store, "origin", &[shared]).unwrap();
        let small = transitive_closure(
            &store,
            "origin",
            &seeds,
            CrossScanOptions {
                max_frontier: 7,
                max_visited: 4,
            },
        )
        .unwrap();
        assert_eq!(small.len(), 3);
        assert_eq!(
            small
                .iter()
                .map(|link| link.target_scan_id.as_str())
                .collect::<Vec<_>>(),
            ["scan-000", "scan-001", "scan-002"],
        );
        let frontier_limited = transitive_closure(
            &store,
            "origin",
            &seeds,
            CrossScanOptions {
                max_frontier: 2,
                max_visited: 100,
            },
        )
        .unwrap();
        assert_eq!(frontier_limited.len(), 2);
    }

    #[test]
    fn zero_budget_never_claims_any_cross_scan_links() {
        let mut store = FakeStore::default();
        store.insert(entity(EntityKind::IpAddress, "203.0.113.20", 0.9, "origin"));
        store.insert(entity(EntityKind::IpAddress, "203.0.113.20", 0.9, "other"));
        let seeds = collect_direct_bridges(
            &store,
            "origin",
            &store.entities_for_scan("origin").unwrap(),
        )
        .unwrap();
        for options in [
            CrossScanOptions {
                max_frontier: 0,
                max_visited: 100,
            },
            CrossScanOptions {
                max_frontier: 100,
                max_visited: 1,
            },
            CrossScanOptions {
                max_frontier: 100,
                max_visited: 0,
            },
        ] {
            assert!(
                transitive_closure(&store, "origin", &seeds, options)
                    .unwrap()
                    .is_empty()
            );
        }
    }

    #[test]
    fn budgets_still_allow_second_hop_when_slots_remain() {
        let mut store = FakeStore::default();
        store.insert(entity(EntityKind::IpAddress, "198.51.100.1", 0.9, "scan-a"));
        store.insert(entity(EntityKind::IpAddress, "198.51.100.1", 0.9, "scan-b"));
        store.insert(entity(EntityKind::IpAddress, "198.51.100.2", 0.9, "scan-b"));
        store.insert(entity(EntityKind::IpAddress, "198.51.100.2", 0.9, "scan-c"));
        let seeds = collect_direct_bridges(
            &store,
            "scan-a",
            &store.entities_for_scan("scan-a").unwrap(),
        )
        .unwrap();
        let links = transitive_closure(
            &store,
            "scan-a",
            &seeds,
            CrossScanOptions {
                max_frontier: 2,
                max_visited: 3,
            },
        )
        .unwrap();
        assert_eq!(links.len(), 2);
        assert_eq!(
            (links[0].target_scan_id.as_str(), links[0].depth),
            ("scan-b", 1)
        );
        assert_eq!(
            (links[1].target_scan_id.as_str(), links[1].depth),
            ("scan-c", 2)
        );
    }
}
