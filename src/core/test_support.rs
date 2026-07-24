//! Test-only support: an in-memory [`StoragePort`] and deterministic mock
//! modules used to prove engine properties (bounded best-first halting,
//! over-budget early stop) without touching SQLite or the network.
//!
//! Compiled only under `#[cfg(test)]` — never part of the shipped binary.

use std::collections::HashMap;

use parking_lot::Mutex;

use crate::core::correlator::Correlation;
use crate::core::entity::Entity;
use crate::core::error::Result;
use crate::core::event::Event;
use crate::core::port::StoragePort;
use crate::core::relation::Relation;
use crate::core::scan::Scan;

/// Fully in-memory [`StoragePort`]. Pure HashMap/Vec state behind a single
/// `parking_lot::Mutex`, so engine tests are deterministic, allocation-bounded,
/// and never spawn a SQLite connection. Mirrors the GREATEST-merge contract of
/// the real store closely enough for halting/budget assertions: `upsert_entity`
/// keeps the higher-confidence copy on UID collision.
///
/// It also mirrors the real store's `entity_observations` table (see
/// [`Inner::observations`]) — without it, an entity recorded by three scans
/// collapsed to whichever scan happened to insert it first, and every
/// cross-scan property (history bridging, enrichment leverage, transitive
/// closure) was untestable against this port because it could only ever answer
/// "one scan".
#[derive(Default)]
pub struct InMemoryStore {
    inner: Mutex<Inner>,
}

#[derive(Default)]
struct Inner {
    scans: HashMap<String, Scan>,
    entities: HashMap<String, Entity>,
    /// The `entity_observations` join table: entity uid → every `(scan_id,
    /// observed_at)` that recorded it, deduplicated on `(uid, scan_id)` exactly
    /// as the real store's `INSERT OR IGNORE` does.
    ///
    /// This is what makes an entity's *identity* (the uid) independent of the
    /// scan that first saw it. `Entity::scan_id` is only the originating scan;
    /// membership of a scan is this ledger, and reads must go through it.
    observations: HashMap<String, Vec<(String, u64)>>,
    correlations: Vec<Correlation>,
    relations: Vec<Relation>,
    events: Vec<Event>,
}

impl InMemoryStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Total entities currently held — the post-scan "what got persisted"
    /// count the halting test asserts against.
    pub fn entity_count(&self) -> usize {
        self.inner.lock().entities.len()
    }
}

impl StoragePort for InMemoryStore {
    fn upsert_scan(&self, scan: &Scan) -> Result<()> {
        self.inner
            .lock()
            .scans
            .insert(scan.id.clone(), scan.clone());
        Ok(())
    }

    fn get_scan(&self, id: &str) -> Result<Option<Scan>> {
        Ok(self.inner.lock().scans.get(id).cloned())
    }

    fn list_scans(&self, limit: usize) -> Result<Vec<Scan>> {
        // Mirror Store::list_scans — newest-first by started_at — so the
        // in-memory port is deterministic and matches production ordering
        // (HashMap iteration order is otherwise arbitrary across runs).
        let mut scans: Vec<Scan> = self.inner.lock().scans.values().cloned().collect();
        // newest-first by started_at (Reverse for descending key sort)
        scans.sort_by_key(|s| std::cmp::Reverse(s.started_at));
        scans.truncate(limit);
        Ok(scans)
    }

    fn radar_history(&self, limit: usize) -> Result<Vec<Scan>> {
        // Mirror Store::radar_history's sentinel filter exactly, via the same
        // canonical predicate (`core::scan::is_radar_sentinel`) so this mock
        // can't silently drift from the real implementation.
        let mut scans: Vec<Scan> = self
            .inner
            .lock()
            .scans
            .values()
            .filter(|s| crate::core::scan::is_radar_sentinel(s.target.kind, &s.target.value))
            .cloned()
            .collect();
        scans.sort_by_key(|s| std::cmp::Reverse(s.started_at));
        scans.truncate(limit);
        Ok(scans)
    }

    fn delete_scan(&self, scan_id: &str) -> Result<bool> {
        Ok(self.inner.lock().scans.remove(scan_id).is_some())
    }

    fn upsert_entity(&self, entity: &Entity) -> Result<()> {
        let mut g = self.inner.lock();
        // Record the observation first, mirroring the real store's
        // `INSERT OR IGNORE INTO entity_observations` — one row per distinct
        // (uid, scan_id), so re-upserting within a scan does not inflate the
        // cross-scan degree.
        let obs = g.observations.entry(entity.uid.clone()).or_default();
        if !obs.iter().any(|(s, _)| *s == entity.scan_id) {
            obs.push((entity.scan_id.clone(), entity.observed_at));
        }
        match g.entities.get_mut(&entity.uid) {
            // Mirror the real store's GREATEST-merge contract exactly: on UID
            // collision, MERGE (max confidence, accumulate corroboration,
            // append evidence, union tags) rather than keep-or-overwrite. The
            // prior keep-stronger/overwrite logic silently discarded new
            // evidence/tags/corroboration, diverging from production and
            // undermining tests that assert merge semantics.
            Some(existing) => existing.merge(entity.clone()),
            None => {
                g.entities.insert(entity.uid.clone(), entity.clone());
            }
        }
        Ok(())
    }

    fn upsert_entities_batch(&self, entities: &[Entity]) -> Result<usize> {
        for e in entities {
            self.upsert_entity(e)?;
        }
        Ok(entities.len())
    }

    fn entities_for_scan(&self, scan_id: &str) -> Result<Vec<Entity>> {
        // Mirror Store::entities_for_scan: JOIN through entity_observations, NOT
        // a filter on `Entity::scan_id`. A merged entity keeps the originating
        // scan's id in that field, so filtering on it hid the entity from every
        // later scan that also observed it.
        let g = self.inner.lock();
        let mut ents: Vec<Entity> = g
            .entities
            .values()
            .filter(|e| {
                g.observations
                    .get(&e.uid)
                    .is_some_and(|obs| obs.iter().any(|(s, _)| s == scan_id))
            })
            .cloned()
            .collect();
        // Confidence desc, uid asc — the real store's ORDER BY, so ties are
        // deterministic across runs.
        ents.sort_by(|a, b| {
            b.confidence
                .partial_cmp(&a.confidence)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.uid.cmp(&b.uid))
        });
        Ok(ents)
    }

    fn entities_filtered(
        &self,
        scan_id: &str,
        kind: Option<&str>,
        min_confidence: Option<f64>,
        value_contains: Option<&str>,
    ) -> Result<Vec<Entity>> {
        Ok(self
            .inner
            .lock()
            .entities
            .values()
            .filter(|e| e.scan_id == scan_id)
            .filter(|e| kind.is_none_or(|k| e.kind.to_string() == k))
            .filter(|e| min_confidence.is_none_or(|m| e.confidence >= m))
            .filter(|e| value_contains.is_none_or(|v| e.value.contains(v)))
            .cloned()
            .collect())
    }

    fn entity_facets(&self, scan_id: &str) -> Result<Vec<(String, u64)>> {
        let mut counts: HashMap<String, u64> = HashMap::new();
        for e in self
            .inner
            .lock()
            .entities
            .values()
            .filter(|e| e.scan_id == scan_id)
        {
            *counts.entry(e.kind.to_string()).or_insert(0) += 1;
        }
        // Mirror Store::entity_facets (COUNT desc) for deterministic ordering.
        let mut facets: Vec<(String, u64)> = counts.into_iter().collect();
        facets.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        Ok(facets)
    }

    fn get_entity(&self, uid: &str) -> Result<Option<Entity>> {
        Ok(self.inner.lock().entities.get(uid).cloned())
    }

    fn search_entities(&self, query: &str, limit: usize) -> Result<Vec<Entity>> {
        Ok(self
            .inner
            .lock()
            .entities
            .values()
            .filter(|e| e.value.contains(query))
            .take(limit)
            .cloned()
            .collect())
    }

    fn scan_ids_for_entity(&self, entity_uid: &str) -> Result<Vec<String>> {
        // Real store: ORDER BY observed_at DESC, scan_id DESC.
        let g = self.inner.lock();
        let mut obs = g.observations.get(entity_uid).cloned().unwrap_or_default();
        obs.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| b.0.cmp(&a.0)));
        Ok(obs.into_iter().map(|(s, _)| s).collect())
    }

    fn observation_count(&self, entity_uid: &str) -> Result<usize> {
        // Real store: COUNT(*) FROM entity_observations — the number of distinct
        // scans that recorded the entity, which is not the same thing as its
        // accumulated corroboration (distinct *sources* within a scan).
        Ok(self
            .inner
            .lock()
            .observations
            .get(entity_uid)
            .map_or(0, Vec::len))
    }

    fn upsert_correlation(&self, c: &Correlation) -> Result<()> {
        self.inner.lock().correlations.push(c.clone());
        Ok(())
    }

    fn correlations_for_scan(&self, scan_id: &str) -> Result<Vec<Correlation>> {
        Ok(self
            .inner
            .lock()
            .correlations
            .iter()
            .filter(|c| c.scan_id == scan_id)
            .cloned()
            .collect())
    }

    fn upsert_relation(&self, r: &Relation) -> Result<()> {
        self.inner.lock().relations.push(r.clone());
        Ok(())
    }

    fn relations_for_scan(&self, scan_id: &str) -> Result<Vec<Relation>> {
        Ok(self
            .inner
            .lock()
            .relations
            .iter()
            .filter(|r| r.scan_id == scan_id)
            .cloned()
            .collect())
    }

    fn insert_event(&self, event: &Event) -> Result<()> {
        self.inner.lock().events.push(event.clone());
        Ok(())
    }

    fn events_for_scan(&self, scan_id: &str) -> Result<Vec<Event>> {
        Ok(self
            .inner
            .lock()
            .events
            .iter()
            .filter(|e| e.scan_id == scan_id)
            .cloned()
            .collect())
    }
}
