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
    /// What the store held at the moment each scan's row FIRST turned
    /// terminal — see [`TerminalWitness`].
    terminal_witnesses: Vec<TerminalWitness>,
    /// A subscription to the engine's live event bus, when a test attached one
    /// ([`InMemoryStore::watch_bus`]): read at the terminal write, so a
    /// witness records whether SSE subscribers had ALREADY been told the scan
    /// completed.
    bus: Option<tokio::sync::broadcast::Receiver<Event>>,
}

/// A snapshot the in-memory store takes when a scan's stored status first
/// becomes terminal: what an export reading the store at that instant would
/// have seen. The engine's lifecycle invariant is that a scan reads terminal
/// only once everything its exports read is durable, so these let a test
/// check it at the storage boundary rather than after the fact.
#[derive(Debug, Clone)]
pub struct TerminalWitness {
    pub scan_id: String,
    pub status: crate::core::scan::ScanStatus,
    /// Correlations stored for the scan at that instant.
    pub correlations: usize,
    /// Relations stored for the scan at that instant.
    pub relations: usize,
    /// Whether the scan's `ScanComplete` event was already stored.
    pub completion_event: bool,
    /// Whether the scan's `ScanComplete` had already been BROADCAST to live
    /// subscribers — only recorded when a bus is watched
    /// ([`InMemoryStore::watch_bus`]); `false` otherwise.
    pub completion_broadcast: bool,
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

    /// Every [`TerminalWitness`] taken so far, in order.
    pub fn terminal_witnesses(&self) -> Vec<TerminalWitness> {
        self.inner.lock().terminal_witnesses.clone()
    }

    /// Watch the engine's live event bus: a broadcast is synchronous, so the
    /// events queued on `rx` when a row first turns terminal are exactly the
    /// ones subscribers had been sent by then.
    pub fn watch_bus(&self, rx: tokio::sync::broadcast::Receiver<Event>) {
        self.inner.lock().bus = Some(rx);
    }
}

impl StoragePort for InMemoryStore {
    fn upsert_scan(&self, scan: &Scan) -> Result<()> {
        let mut inner = self.inner.lock();
        let was_terminal = inner
            .scans
            .get(&scan.id)
            .is_some_and(|prev| prev.status.is_terminal());
        if scan.status.is_terminal() && !was_terminal {
            let mut completion_broadcast = false;
            if let Some(rx) = inner.bus.as_mut() {
                while let Ok(ev) = rx.try_recv() {
                    completion_broadcast |= ev.scan_id == scan.id
                        && matches!(ev.kind, crate::core::event::EventKind::ScanComplete { .. });
                }
            }
            let witness = TerminalWitness {
                completion_broadcast,
                scan_id: scan.id.clone(),
                status: scan.status,
                correlations: inner
                    .correlations
                    .iter()
                    .filter(|c| c.scan_id == scan.id)
                    .count(),
                relations: inner
                    .relations
                    .iter()
                    .filter(|r| r.scan_id == scan.id)
                    .count(),
                completion_event: inner.events.iter().any(|e| {
                    e.scan_id == scan.id
                        && matches!(e.kind, crate::core::event::EventKind::ScanComplete { .. })
                }),
            };
            inner.terminal_witnesses.push(witness);
        }
        inner.scans.insert(scan.id.clone(), scan.clone());
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

/// A [`StoragePort`] that forwards every call to `inner` but fails the calls a
/// test names — the store failing partway through a finalise (a full disk, a
/// locked database) that [`crate::core::scan::FinaliseTally`] exists to
/// record. Relation and entity writes refuse both the batch and the per-item
/// fallback, so the fallback path is exercised and every item is counted. A
/// relation READ can be refused or made to panic, which is how the correlator
/// pass (and the route and boost passes that read the graph) fail outright.
/// Every other method forwards, including the optional ones, so the wrapped
/// store behaves exactly as it would alone. Shared by the engine,
/// `app::persist` and web-upload tests so all three finalise paths are proved
/// against the same failure.
#[derive(Default)]
pub struct RefusingStore {
    inner: Option<std::sync::Arc<dyn StoragePort>>,
    refuse_relations: bool,
    refuse_correlations: bool,
    refuse_relation_reads: bool,
    panic_on_relation_reads: bool,
    refuse_detach: bool,
    refuse_entity_writes: bool,
    refuse_template_counts: bool,
}

/// The error text [`RefusingStore`] returns for a refused relation write.
pub const REFUSED_RELATION: &str = "injected relation write failure";
/// The error text [`RefusingStore`] returns for a refused correlation write.
pub const REFUSED_CORRELATION: &str = "injected correlation write failure";
/// The error text [`RefusingStore`] returns for a refused relation read.
pub const REFUSED_RELATION_READ: &str = "injected relation read failure";
/// The error text [`RefusingStore`] returns for a refused observation detach.
pub const REFUSED_DETACH: &str = "injected detach failure";
/// The error text [`RefusingStore`] returns for a refused entity write.
pub const REFUSED_ENTITY: &str = "injected entity write failure";
/// The error text [`RefusingStore`] returns for a refused route-count read.
pub const REFUSED_TEMPLATE_COUNT: &str = "injected template count failure";

fn injected(text: &str) -> crate::core::error::Error {
    crate::core::error::Error::Other(text.to_string())
}

impl RefusingStore {
    /// Wrap `inner`, refusing nothing yet.
    pub fn new(inner: std::sync::Arc<dyn StoragePort>) -> Self {
        Self {
            inner: Some(inner),
            ..Self::default()
        }
    }

    fn inner(&self) -> &dyn StoragePort {
        self.inner
            .as_deref()
            .expect("RefusingStore::new sets the inner store")
    }

    /// Refuse every read of a scan's relations.
    #[must_use]
    pub fn refusing_relation_reads(mut self) -> Self {
        self.refuse_relation_reads = true;
        self
    }

    /// Panic on every read of a scan's relations — with a payload carrying a
    /// run-specific address, so a test can prove the payload never reaches
    /// the scan record.
    #[must_use]
    pub fn panicking_on_relation_reads(mut self) -> Self {
        self.panic_on_relation_reads = true;
        self
    }

    /// Refuse every detach of a scan's observations.
    #[must_use]
    pub fn refusing_detach(mut self) -> Self {
        self.refuse_detach = true;
        self
    }

    /// Refuse every entity write, batch and single.
    #[must_use]
    pub fn refusing_entity_writes(mut self) -> Self {
        self.refuse_entity_writes = true;
        self
    }

    /// Refuse every cross-scan route-count read.
    #[must_use]
    pub fn refusing_template_counts(mut self) -> Self {
        self.refuse_template_counts = true;
        self
    }

    /// Refuse every relation write.
    #[must_use]
    pub fn refusing_relations(mut self) -> Self {
        self.refuse_relations = true;
        self
    }

    /// Refuse every correlation write.
    #[must_use]
    pub fn refusing_correlations(mut self) -> Self {
        self.refuse_correlations = true;
        self
    }
}

impl StoragePort for RefusingStore {
    fn upsert_scan(&self, scan: &Scan) -> Result<()> {
        self.inner().upsert_scan(scan)
    }
    fn get_scan(&self, id: &str) -> Result<Option<Scan>> {
        self.inner().get_scan(id)
    }
    fn list_scans(&self, limit: usize) -> Result<Vec<Scan>> {
        self.inner().list_scans(limit)
    }
    fn radar_history(&self, limit: usize) -> Result<Vec<Scan>> {
        self.inner().radar_history(limit)
    }
    fn delete_scan(&self, scan_id: &str) -> Result<bool> {
        self.inner().delete_scan(scan_id)
    }
    fn upsert_entity(&self, entity: &Entity) -> Result<()> {
        if self.refuse_entity_writes {
            return Err(injected(REFUSED_ENTITY));
        }
        self.inner().upsert_entity(entity)
    }
    fn upsert_entities_batch(&self, entities: &[Entity]) -> Result<usize> {
        if self.refuse_entity_writes {
            return Err(injected(REFUSED_ENTITY));
        }
        self.inner().upsert_entities_batch(entities)
    }
    fn entities_for_scan(&self, scan_id: &str) -> Result<Vec<Entity>> {
        self.inner().entities_for_scan(scan_id)
    }
    fn entities_filtered(
        &self,
        scan_id: &str,
        kind: Option<&str>,
        min_confidence: Option<f64>,
        value_contains: Option<&str>,
    ) -> Result<Vec<Entity>> {
        self.inner()
            .entities_filtered(scan_id, kind, min_confidence, value_contains)
    }
    fn entity_facets(&self, scan_id: &str) -> Result<Vec<(String, u64)>> {
        self.inner().entity_facets(scan_id)
    }
    fn get_entity(&self, uid: &str) -> Result<Option<Entity>> {
        self.inner().get_entity(uid)
    }
    fn search_entities(&self, query: &str, limit: usize) -> Result<Vec<Entity>> {
        self.inner().search_entities(query, limit)
    }
    fn scan_ids_for_entity(&self, entity_uid: &str) -> Result<Vec<String>> {
        self.inner().scan_ids_for_entity(entity_uid)
    }
    fn observation_count(&self, entity_uid: &str) -> Result<usize> {
        self.inner().observation_count(entity_uid)
    }
    fn detach_scan_observations(&self, scan_id: &str, entity_uids: &[String]) -> Result<usize> {
        if self.refuse_detach {
            return Err(injected(REFUSED_DETACH));
        }
        self.inner().detach_scan_observations(scan_id, entity_uids)
    }
    fn upsert_correlation(&self, c: &Correlation) -> Result<()> {
        if self.refuse_correlations {
            return Err(injected(REFUSED_CORRELATION));
        }
        self.inner().upsert_correlation(c)
    }
    fn correlations_for_scan(&self, scan_id: &str) -> Result<Vec<Correlation>> {
        self.inner().correlations_for_scan(scan_id)
    }
    fn upsert_relation(&self, r: &Relation) -> Result<()> {
        if self.refuse_relations {
            return Err(injected(REFUSED_RELATION));
        }
        self.inner().upsert_relation(r)
    }
    fn upsert_relations_batch(&self, rels: &[Relation]) -> Result<usize> {
        if self.refuse_relations {
            return Err(injected(REFUSED_RELATION));
        }
        self.inner().upsert_relations_batch(rels)
    }
    fn relations_for_scan(&self, scan_id: &str) -> Result<Vec<Relation>> {
        if self.panic_on_relation_reads {
            let local = 0u8;
            panic!("injected relation read panic at {:p}", &local);
        }
        if self.refuse_relation_reads {
            return Err(injected(REFUSED_RELATION_READ));
        }
        self.inner().relations_for_scan(scan_id)
    }
    fn insert_event(&self, event: &Event) -> Result<()> {
        self.inner().insert_event(event)
    }
    fn insert_events_batch(&self, events: &[Event]) -> Result<usize> {
        self.inner().insert_events_batch(events)
    }
    fn events_for_scan(&self, scan_id: &str) -> Result<Vec<Event>> {
        self.inner().events_for_scan(scan_id)
    }
    fn delete_events_for_scan(&self, scan_id: &str) -> Result<()> {
        self.inner().delete_events_for_scan(scan_id)
    }
    fn recent_module_outcome_events(&self, limit: usize) -> Result<Vec<Event>> {
        self.inner().recent_module_outcome_events(limit)
    }
    fn archive_module_result(
        &self,
        key: &str,
        ttl_secs: u64,
        entities: &[Entity],
        truncation: Option<&str>,
    ) -> Result<()> {
        self.inner()
            .archive_module_result(key, ttl_secs, entities, truncation)
    }
    fn lookup_module_result_fresh(
        &self,
        key: &str,
    ) -> Result<Option<crate::core::port::CachedModuleResult>> {
        self.inner().lookup_module_result_fresh(key)
    }
    fn record_pathway_template(&self, template: &str) -> Result<()> {
        self.inner().record_pathway_template(template)
    }
    fn pathway_template_count(&self, template: &str) -> Result<u32> {
        if self.refuse_template_counts {
            return Err(injected(REFUSED_TEMPLATE_COUNT));
        }
        self.inner().pathway_template_count(template)
    }
    fn insert_stealer_rows_batch(
        &self,
        scan_id: &str,
        rows: &[crate::core::stealer_row::StealerRow],
    ) -> Result<usize> {
        self.inner().insert_stealer_rows_batch(scan_id, rows)
    }
    fn stealer_rows_for_scan(
        &self,
        scan_id: &str,
    ) -> Result<Vec<crate::core::stealer_row::StealerRow>> {
        self.inner().stealer_rows_for_scan(scan_id)
    }
    fn insert_rf_sightings_batch(
        &self,
        scan_id: &str,
        rows: &[crate::core::rf::RfSighting],
    ) -> Result<usize> {
        self.inner().insert_rf_sightings_batch(scan_id, rows)
    }
    fn rf_latest_scan_id(&self) -> Result<Option<String>> {
        self.inner().rf_latest_scan_id()
    }
    fn rf_summary(&self, scan_id: &str) -> Result<crate::core::rf::RfSummary> {
        self.inner().rf_summary(scan_id)
    }
    fn rf_devices_for_scan(&self, scan_id: &str) -> Result<Vec<crate::core::rf::RfDeviceRow>> {
        self.inner().rf_devices_for_scan(scan_id)
    }
    fn rf_trackable_devices(&self, scan_id: &str) -> Result<Vec<crate::core::rf::RfDeviceRow>> {
        self.inner().rf_trackable_devices(scan_id)
    }
    fn rf_sightings_for_device(
        &self,
        scan_id: &str,
        network_id: &str,
    ) -> Result<Vec<crate::core::rf::RfSighting>> {
        self.inner().rf_sightings_for_device(scan_id, network_id)
    }
    fn rf_device_track(
        &self,
        network_id: &str,
        limit: usize,
    ) -> Result<Vec<crate::core::rf::RfTrackPoint>> {
        self.inner().rf_device_track(network_id, limit)
    }
    fn insert_wifi_link(&self, scan_id: &str, link: &crate::core::link::LinkState) -> Result<()> {
        self.inner().insert_wifi_link(scan_id, link)
    }
    fn wifi_link_for_scan(&self, scan_id: &str) -> Result<Option<crate::core::link::LinkState>> {
        self.inner().wifi_link_for_scan(scan_id)
    }
    fn checkpoint_truncate(&self) -> Result<()> {
        self.inner().checkpoint_truncate()
    }
    fn integrity_check(&self) -> Result<Vec<String>> {
        self.inner().integrity_check()
    }
    fn prune_events(&self, max_age_secs: u64, max_rows: usize) -> Result<usize> {
        self.inner().prune_events(max_age_secs, max_rows)
    }
    fn prune_module_result_cache(&self, max_rows: usize) -> Result<usize> {
        self.inner().prune_module_result_cache(max_rows)
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

/// Assert that `echo` — a point-lookup module's re-emission of the
/// `Coordinates` it was queried on — is an ANNOTATION of that point
/// (REQ-GEO-008): it carries the confidence floor, every record is
/// non-corroborating, and merged onto a search-engine centroid of the same
/// value it neither raises the centroid's confidence nor adds a corroborating
/// source. The one statement of that contract for `au_geo`, `overpass`,
/// `qld_cadastre`, `sunrise_sunset` and `wigle`.
pub fn assert_point_annotation(echo: &Entity) {
    use crate::core::confidence;
    use crate::core::entity::{EntityKind, Evidence};
    assert_eq!(echo.kind, EntityKind::Coordinates);
    assert!(
        echo.confidence <= confidence::DERIVED_FLOOR + 1e-9,
        "{}: an annotation carries the floor, got {}",
        echo.value,
        echo.confidence
    );
    assert!(
        !echo.evidence.is_empty() && echo.evidence.iter().all(Evidence::is_non_corroborating),
        "{}: every record is an annotation",
        echo.value
    );
    let base = confidence::HIGH_PLUS;
    let mut centroid = Entity::new(EntityKind::Coordinates, &echo.value, base, "s");
    centroid.add_evidence(Evidence::new("search_engines", "known-city centroid"));
    centroid.merge(echo.clone());
    assert!(
        (centroid.confidence - base).abs() < 1e-9,
        "{}: the annotation raised the point to {}",
        echo.value,
        centroid.confidence
    );
    assert_eq!(centroid.source_count(), 1, "{}", echo.value);
    assert_eq!(
        centroid.corroborating_sources(),
        std::collections::HashSet::from(["search_engines"])
    );
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
