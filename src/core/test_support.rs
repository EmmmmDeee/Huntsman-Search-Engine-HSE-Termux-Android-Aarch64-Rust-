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
    /// observed_at, copy)` that recorded it, one per `(uid, scan_id)` exactly
    /// as the real store's primary key keeps it.
    ///
    /// This is what makes an entity's *identity* (the uid) independent of the
    /// scan that first saw it. `Entity::scan_id` is only the originating scan;
    /// membership of a scan is this ledger, and reads must go through it.
    ///
    /// `copy` mirrors the real row's `data_json`: that scan's OWN view of the
    /// entity, folded only from its own upserts. Per-scan reads return it; the
    /// shared `entities` entry folds in every scan that ever saw the uid, and
    /// returning that exported other subjects' evidence (REQ-STORAGE-005).
    observations: HashMap<String, Vec<(String, u64, Entity)>>,
    correlations: Vec<Correlation>,
    relations: Vec<Relation>,
    events: Vec<Event>,
    /// Mirrors the real store's `raw_archive` table (inter-scan entity
    /// cache): key → `(archived_at, ttl_secs, result)`. Without this, the
    /// trait's default no-op `archive_module_result`/`lookup_module_result_fresh`
    /// made a cache HIT untestable against this port — every lookup silently
    /// returned `None` regardless of what was archived, so no dispatch-level
    /// test could ever exercise the module-skip-on-cache-hit path.
    raw_archive: HashMap<String, (u64, u64, crate::core::port::CachedModuleResult)>,
}

impl Inner {
    /// Every entity `scan_id` observed, as that scan's own copy — the double's
    /// `SELECT COALESCE(o.data_json, e.data_json) … JOIN entity_observations o`.
    fn scan_copies(&self, scan_id: &str) -> impl Iterator<Item = &Entity> {
        self.observations
            .values()
            .flatten()
            .filter(move |(s, _, _)| s == scan_id)
            .map(|(_, _, copy)| copy)
    }
}

/// Confidence desc, uid asc — the real store's `ORDER BY` for per-scan reads,
/// so ties are deterministic across runs.
fn sort_like_store(ents: &mut [Entity]) {
    ents.sort_by(|a, b| {
        b.confidence
            .partial_cmp(&a.confidence)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.uid.cmp(&b.uid))
    });
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
        // `entity_observations` upsert — one row per distinct (uid, scan_id), so
        // re-upserting within a scan does not inflate the cross-scan degree.
        // A re-upsert folds into THAT scan's copy by the real store's same-scan
        // rules (merge, GREATEST corroboration, canonical order); a new scan
        // starts its copy from the incoming entity alone.
        let obs = g.observations.entry(entity.uid.clone()).or_default();
        match obs.iter_mut().find(|(s, _, _)| *s == entity.scan_id) {
            Some((_, _, copy)) => {
                let (stored_corr, incoming_corr) = (copy.corroboration, entity.corroboration);
                copy.merge(entity.clone());
                copy.corroboration = stored_corr.max(incoming_corr).max(1);
                copy.canonicalize_order();
            }
            None => obs.push((entity.scan_id.clone(), entity.observed_at, entity.clone())),
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
        // later scan that also observed it. And return the scan's own copy, not
        // the shared entry, which carries every other scan's evidence too.
        let mut ents: Vec<Entity> = self.inner.lock().scan_copies(scan_id).cloned().collect();
        sort_like_store(&mut ents);
        Ok(ents)
    }

    fn detach_scan_observations(&self, scan_id: &str, entity_uids: &[String]) -> Result<usize> {
        // Mirror Store::detach_scan_observations so engine finalise-fold tests
        // exercise the real detach (and its orphan cleanup) instead of the
        // trait's no-op default — otherwise a fold's victim stays visible under
        // the in-memory path and a detach regression passes untested here.
        // Drop each named uid's `(scan_id, _)` observation; when nothing observes
        // the uid anymore, delete its entity row too (the fully-absorbed victim).
        let mut g = self.inner.lock();
        let mut removed = 0usize;
        for uid in entity_uids {
            let now_empty = if let Some(obs) = g.observations.get_mut(uid) {
                let before = obs.len();
                obs.retain(|(s, _, _)| s != scan_id);
                removed += before - obs.len();
                obs.is_empty()
            } else {
                false
            };
            if now_empty {
                g.observations.remove(uid);
                g.entities.remove(uid);
            }
        }
        Ok(removed)
    }

    fn entities_filtered(
        &self,
        scan_id: &str,
        kind: Option<&str>,
        min_confidence: Option<f64>,
        value_contains: Option<&str>,
    ) -> Result<Vec<Entity>> {
        // Mirror Store::entities_filtered: the scan's own copies, filtered on
        // the copy's fields and ordered like the real store's ORDER BY.
        let mut ents: Vec<Entity> = self
            .inner
            .lock()
            .scan_copies(scan_id)
            .filter(|e| kind.is_none_or(|k| e.kind.to_string() == k))
            .filter(|e| min_confidence.is_none_or(|m| e.confidence >= m))
            .filter(|e| value_contains.is_none_or(|v| e.value.contains(v)))
            .cloned()
            .collect();
        sort_like_store(&mut ents);
        Ok(ents)
    }

    fn entity_facets(&self, scan_id: &str) -> Result<Vec<(String, u64)>> {
        let mut counts: HashMap<String, u64> = HashMap::new();
        for e in self.inner.lock().scan_copies(scan_id) {
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
        let mut obs: Vec<(String, u64)> = g
            .observations
            .get(entity_uid)
            .into_iter()
            .flatten()
            .map(|(s, t, _)| (s.clone(), *t))
            .collect();
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

    fn archive_module_result(
        &self,
        key: &str,
        ttl_secs: u64,
        entities: &[Entity],
        truncation: Option<&str>,
    ) -> Result<()> {
        // Mirror `Store::archive_module_result`: `INSERT OR REPLACE` keyed on
        // `key`, timestamped `archived_at = now()`.
        self.inner.lock().raw_archive.insert(
            key.to_string(),
            (
                crate::core::entity::unix_now(),
                ttl_secs,
                crate::core::port::CachedModuleResult {
                    entities: entities.to_vec(),
                    truncation: truncation.map(str::to_string),
                },
            ),
        );
        Ok(())
    }

    fn lookup_module_result_fresh(
        &self,
        key: &str,
    ) -> Result<Option<crate::core::port::CachedModuleResult>> {
        // Mirror `Store::lookup_module_result_fresh`'s freshness predicate
        // exactly: `archived_at + ttl_secs > now()`, so `ttl_secs == 0`
        // expires immediately, matching the real store's tested behavior.
        let now = crate::core::entity::unix_now();
        Ok(self
            .inner
            .lock()
            .raw_archive
            .get(key)
            .filter(|(archived_at, ttl_secs, _)| archived_at + ttl_secs > now)
            .map(|(_, _, result)| result.clone()))
    }
}

/// A bare engine event on scan `scan-1` at t=0, for tests that only care
/// about the kind — the coverage aggregation and the ledger both read events
/// this way, so the fixture lives here rather than in either test module.
#[must_use]
pub fn module_event(kind: crate::core::event::EventKind) -> Event {
    Event {
        scan_id: "scan-1".to_string(),
        ts: 0,
        kind,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::entity::{EntityKind, Evidence};

    /// The double keeps the real store's per-scan semantics (REQ-STORAGE-005,
    /// `storage::tests::a_scan_reads_only_its_own_copy_of_an_entity_other_scans_also_observed`):
    /// a per-scan read returns that scan's own copy, and `get_entity` the merge.
    #[test]
    fn per_scan_reads_return_the_scans_own_copy_not_the_shared_entry() {
        let store = InMemoryStore::new();
        let org = |scan: &str, owner: &str, generation: u32| {
            let mut e = Entity::new(EntityKind::Organisation, "AGL SALES PTY LIMITED", 0.8, scan);
            e.generation = generation;
            e.add_evidence(
                Evidence::new("qld_unclaimed", "record").with_attr("paid_to_owner", owner),
            );
            e
        };
        let knight = org("scan-knight", "CATHY KNIGHT", 0);
        let thorpe = org("scan-thorpe", "Deanna Marie Thorpe", 2);
        store.upsert_entity(&knight).expect("should succeed");
        store.upsert_entity(&thorpe).expect("should succeed");
        store
            .upsert_entity(&thorpe)
            .expect("a same-scan re-persist");

        let owner = |e: &Entity| e.evidence[0].attributes["paid_to_owner"].clone();
        for (scan, want, generation) in [
            ("scan-thorpe", "Deanna Marie Thorpe", 2),
            ("scan-knight", "CATHY KNIGHT", 0),
        ] {
            for got in [
                store.entities_for_scan(scan).expect("should succeed"),
                store
                    .entities_filtered(scan, None, None, None)
                    .expect("should succeed"),
            ] {
                assert_eq!(got.len(), 1, "{scan}");
                assert_eq!(owner(&got[0]), want, "{scan} reads only its own record");
                assert_eq!((got[0].generation, got[0].corroboration), (generation, 1));
            }
        }
        let shared = store
            .get_entity(&thorpe.uid)
            .expect("should succeed")
            .expect("row");
        assert_eq!(owner(&shared), "CATHY KNIGHT; Deanna Marie Thorpe");
    }
}
