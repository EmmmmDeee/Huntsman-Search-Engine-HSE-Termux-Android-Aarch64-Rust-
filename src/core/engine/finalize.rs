//! Finalise-scan pipeline steps.
//!
//! `ScanEngine::finalise_scan` runs the post-ingestion pipeline inside one
//! `spawn_blocking` closure (persist off the async reactor). That closure was a
//! ~430-line god function fusing ~9 unrelated responsibilities; each is now a
//! named, single-responsibility free function here, so the closure reads as the
//! ordered pipeline it is and each step is independently unit-testable.
//!
//! These are FREE functions (not `ScanEngine` methods) because the closure moves
//! its captures across the blocking-thread boundary and cannot borrow `&self`.
//! Each takes exactly the state it needs — the `StoragePort`, the working entity
//! set, the scan id, and (where it emits) the `EventEmitter` + the live-dedup
//! `emitted_corr` set — and every store interaction stays best-effort exactly as
//! it was inline: a persistence hiccup is logged, never fatal to a finished scan.

use super::*;

/// Fold every FOREIGN API key harvested from this scan's endpoint responses into
/// `entity_map` by UID (GREATEST-merge), so a key a specialised module already
/// emitted with richer tags/evidence is never duplicated or blindly overwritten,
/// and a leaked third-party key lands in the graph + dossier no matter which
/// module surfaced it. Our own auth keys were already excluded at the sink.
pub(super) fn merge_found_keys(scan_id: &str, entity_map: &mut HashMap<String, Entity>) {
    for e in crate::core::hooks::drain_found_keys(scan_id) {
        match entity_map.get_mut(&e.uid) {
            Some(existing) => existing.merge(e),
            None => {
                entity_map.insert(e.uid.clone(), e);
            }
        }
    }
}

/// The finalise-time offline enrichment / promotion pipeline, applied ONCE after
/// every module (APIs included) and every expansion round has contributed —
/// free, offline, and deterministic, so an imported dossier finalises identically
/// to a live scan:
///   * consolidate address-locality variants ("X, NSW" vs "X, NSW 2582") into the
///     most-specific one, the engine backstop to per-module dedup;
///   * promote a geo-corroborated family candidate (shared surname + postcode in
///     the subject's confirmed area) and a same-name breach candidate in the
///     subject's metro out of namesake quarantine;
///   * tag `geo-discordant` a same-surname candidate a region away (demote, never
///     inflate);
///   * cross-scan recall (history/co-occurrence/relation) — provenance-only tags
///     for identifiers seen in earlier scans, run before persist so a hit is
///     genuinely prior;
///   * canonicalise each entity's evidence/tag ordering so concurrent dispatch's
///     completion-order merging can't leak into the stored/exported result.
pub(super) fn apply_finalise_enrichment_passes(
    store: &dyn StoragePort,
    entities: &mut Vec<Entity>,
    scan_id: &str,
) {
    consolidate_address_localities(entities);
    promote_geo_corroborated_family(entities);
    promote_breach_candidate_geo_corroborated(entities);
    flag_geo_discordant_namesakes(entities);
    history::link_cross_scan_history(store, entities, scan_id);
    history::link_cross_scan_cooccurrence(store, entities, scan_id);
    history::link_cross_scan_relations(store, entities, scan_id);
    for e in entities.iter_mut() {
        e.canonicalize_order();
    }
}

/// Persist the scan's entities in a single transaction, falling back to
/// per-entity upserts if the batch rolls back. Returns `(persisted, first_err)`.
///
/// The batch collapses N commits into one WAL fsync — the dominant cost on
/// low-power aarch64 — but is all-or-nothing, so on any error we salvage whatever
/// is individually persistable and recover the granular `first_err`, preserving
/// the continue-on-error resilience the caller's status logic depends on
/// (partial persist → Complete-with-error; nothing persisted → Failed).
pub(super) fn persist_entities_with_fallback(
    store: &dyn StoragePort,
    entities: &[Entity],
    scan_id: &str,
) -> (usize, Option<String>) {
    match store.upsert_entities_batch(entities) {
        Ok(n) => (n, None),
        Err(batch_err) => {
            warn!(scan_id = %scan_id, error = %batch_err, "batch entity persist rolled back; falling back to per-entity upserts");
            let mut persisted = 0usize;
            let mut first_err: Option<String> = None;
            for entity in entities {
                match store.upsert_entity(entity) {
                    Ok(()) => persisted += 1,
                    Err(e) => {
                        warn!(scan_id = %scan_id, entity_uid = %entity.uid, error = %e, "entity persist failed");
                        if first_err.is_none() {
                            first_err = Some(e.to_string());
                        }
                    }
                }
            }
            (persisted, first_err)
        }
    }
}

/// Derive the typed entity-relation edges (attribution graph) and persist them
/// alongside the lineage edges captured during expansion. The structural set is
/// derived identically here and on the import paths via `derive_all_within`, so a
/// live scan and an imported dossier can't drift on which edges a finished scan
/// carries. Bounded by `DERIVE_BUDGET` so a `max_entities`-filled graph can't run
/// the super-linear pass chain for minutes; partial relations still persist.
/// Best-effort: a relation that fails to persist is logged, never fatal.
pub(super) fn derive_and_persist_relations(
    store: &dyn StoragePort,
    entities: &[Entity],
    scan_id: &str,
    lineage_relations: &[Relation],
) {
    let derive_deadline = Some(Instant::now() + crate::core::relation::DERIVE_BUDGET);
    let derived = crate::core::relation::derive_all_within(entities, scan_id, derive_deadline);
    if !lineage_relations.is_empty() || !derived.is_empty() {
        let mut rel_persisted = 0usize;
        for r in lineage_relations.iter().chain(derived.iter()) {
            match store.upsert_relation(r) {
                Ok(()) => rel_persisted += 1,
                Err(e) => {
                    warn!(scan_id = %scan_id, relation = %r.id, error = %e, "relation persist failed");
                }
            }
        }
        info!(
            scan_id = %scan_id,
            lineage = lineage_relations.len(),
            derived = derived.len(),
            persisted = rel_persisted,
            "entity relations persisted"
        );
    }
}

/// Run the authoritative finalise-time correlation pass (entity + graph-aware
/// relation rules) over the persisted scan, persisting every firing and emitting
/// `CorrelationFound` only for correlations not already streamed live during
/// ingestion (deduped via `emitted_corr`). Guarded against a rule panicking on
/// adversarial persisted data: a caught panic (or returned error) degrades to
/// "no finalise correlations" — the terminal `ScanComplete` and key-pool
/// restoration still run — exactly as the live incremental pass does. The
/// `CorrelationsDone` count is the authoritative total for the scan.
pub(super) fn run_finalise_correlation(
    store: &Arc<dyn StoragePort>,
    emitter: &EventEmitter,
    scan_id: &str,
    emitted_corr: &mut HashSet<String>,
) {
    if let Some(firings) = guarded_finalise_correlation(scan_id, || {
        crate::core::correlator::Correlator::new(Arc::clone(store)).run(scan_id)
    }) {
        for c in &firings {
            if emitted_corr.insert(correlation_key(c)) {
                emitter.emit(
                    scan_id,
                    EventKind::CorrelationFound {
                        correlation: c.clone(),
                    },
                );
            }
        }
        emitter.emit(
            scan_id,
            EventKind::CorrelationsDone {
                count: firings.len(),
            },
        );
    }
}

/// Cross-scan pathway-template learning (C1 universal linking): generalise this
/// scan's confirmed connections into direction-canonical routes, credit routes a
/// *prior* scan already proved (the engine-level AU-065 finding — storage-
/// dependent, so it can't be a pure correlator rule), then record every route
/// this scan produced so a link learned once lifts every later scan. A *fragile*
/// single-pathway link (AU-063 gap) whose route shape is proven in ≥2 prior scans
/// is the AU-066 finding: accumulated cross-scan knowledge is the orthogonal
/// pathway that fills the gap.
///
/// Returns the `xscan_boost` map (endpoint UID → reason) of AU-066 endpoints
/// queued for the conservative corroboration boost. Best-effort — a storage
/// hiccup never aborts a finalised scan (returns an empty map).
pub(super) fn learn_cross_scan_pathways(
    store: &dyn StoragePort,
    emitter: &EventEmitter,
    scan_id: &str,
    emitted_corr: &mut HashSet<String>,
) -> HashMap<String, String> {
    let mut xscan_boost: HashMap<String, String> = HashMap::new();
    if let (Ok(ents), Ok(rels)) = (
        store.entities_for_scan(scan_id),
        store.relations_for_scan(scan_id),
    ) {
        // The fragile single-route identity pairs (a<b) — exactly AU-063's notion
        // of an uncorroborated link, via the shared detector so the gap the lead
        // flags is the gap the engine fills.
        let fragile: HashSet<(String, String)> =
            crate::core::correlator::single_route_identity_links(&ents, &rels)
                .into_iter()
                .map(|l| (l.a_uid, l.b_uid))
                .collect();
        for ct in crate::core::relation::connection_templates(&ents, &rels, 4) {
            let prior = store.pathway_template_count(&ct.template).unwrap_or(0);
            if prior >= 1 {
                let mut uids: std::collections::BTreeSet<String> =
                    std::collections::BTreeSet::new();
                for (f, t) in &ct.pairs {
                    uids.insert(f.clone());
                    uids.insert(t.clone());
                }
                let c = crate::core::correlator::Correlation::new(
                    "AU-065",
                    "Cross-scan corroborated route",
                    crate::core::correlator::Severity::Medium,
                    format!(
                        "the route [{}] connecting {} identity pair(s) here was \
                         confirmed in {} prior scan(s) — a historically proven \
                         attribution pattern, not a one-off",
                        ct.template,
                        ct.pairs.len(),
                        prior,
                    ),
                    uids.into_iter().collect::<Vec<_>>(),
                    scan_id,
                    crate::core::entity::unix_now(),
                );
                if store.upsert_correlation(&c).is_ok() && emitted_corr.insert(correlation_key(&c))
                {
                    emitter.emit(scan_id, EventKind::CorrelationFound { correlation: c });
                }
            }
            // AU-066 — cross-scan route fills a single-pathway gap. A fragile link
            // whose route shape is proven in ≥2 PRIOR scans (stricter than AU-065's
            // ≥1, to keep the gap-fill conservative) is corroborated by the proven
            // attribution method itself: the accumulated cross-scan pathway is the
            // orthogonal route the AU-063 gap was missing. Its endpoints are queued
            // for the boost.
            if prior >= 2 {
                for (f, t) in &ct.pairs {
                    if !fragile.contains(&(f.clone(), t.clone())) {
                        continue; // only fragile (single-route) links are gaps to fill
                    }
                    let reason = format!(
                        "the single-pathway link's route shape [{}] was independently \
                         confirmed in {prior} prior scans — the proven attribution method \
                         is the orthogonal pathway that fills the single-route gap",
                        ct.template,
                    );
                    let c = crate::core::correlator::Correlation::new(
                        "AU-066",
                        "Cross-scan route fills single-pathway gap",
                        crate::core::correlator::Severity::Medium,
                        reason.clone(),
                        vec![f.clone(), t.clone()],
                        scan_id,
                        crate::core::entity::unix_now(),
                    );
                    if store.upsert_correlation(&c).is_ok()
                        && emitted_corr.insert(correlation_key(&c))
                    {
                        emitter.emit(scan_id, EventKind::CorrelationFound { correlation: c });
                    }
                    xscan_boost
                        .entry(f.clone())
                        .or_insert_with(|| reason.clone());
                    xscan_boost.entry(t.clone()).or_insert(reason);
                }
            }
            let _ = store.record_pathway_template(&ct.template);
        }
    }
    xscan_boost
}

/// Corroboration boosts: feed the scan's own confirmed links back into the entity
/// set so the OUTPUT reflects what its analysis established — multipath (C2, ≥2
/// edge-disjoint in-scan routes) and cross-scan (AU-066, route shape proven in ≥2
/// prior scans, via `xscan_boost`). Both tag + evidence-stamp only the identity
/// ENDPOINTS, are idempotent via their tags, and use unscored ("other") evidence
/// so they never inflate the in-scan orthogonality measure. The single re-persist
/// runs only when a boost actually fires and never aborts a finalised scan.
pub(super) fn apply_corroboration_boosts(
    store: &dyn StoragePort,
    entities: &mut [Entity],
    scan_id: &str,
    xscan_boost: &HashMap<String, String>,
) {
    let mut boosted_any = false;
    if let Ok(rels) = store.relations_for_scan(scan_id) {
        boosted_any |= promote_multipath_corroborated(entities, &rels) > 0;
    }
    boosted_any |= promote_cross_scan_corroborated(entities, xscan_boost) > 0;
    if boosted_any {
        let boosted: Vec<Entity> = entities
            .iter_mut()
            .filter(|e| e.has_tag("multipath-corroborated") || e.has_tag("cross-scan-corroborated"))
            .map(|e| {
                e.canonicalize_order();
                e.clone()
            })
            .collect();
        match store.upsert_entities_batch(&boosted) {
            Ok(n) => info!(
                scan_id = %scan_id,
                boosted = n,
                "corroboration-boosted identities re-persisted (confirmed links strengthened the scan)"
            ),
            Err(e) => warn!(
                scan_id = %scan_id,
                error = %e,
                "corroboration boost re-persist failed (non-fatal)"
            ),
        }
    }
}

/// Scan-boundary maintenance, all best-effort so a busy store just defers to the
/// next boundary: persist the harvested key pool to disk, fold + truncate the WAL
/// (bounds the on-disk/mmap footprint under a long-lived `serve`/`live` process),
/// and prune the `events` table and `raw_archive` cache to their retention caps
/// (otherwise unbounded between the startup prunes).
pub(super) fn run_scan_boundary_maintenance(store: &dyn StoragePort, scan_id: &str) {
    let pool = crate::util::key_pool::global_pool();
    if let Err(e) = crate::util::key_pool::save_pool(&pool) {
        warn!("failed to save key pool after scan: {e}");
    }
    if let Err(e) = store.checkpoint_truncate() {
        warn!(scan_id = %scan_id, error = %e, "WAL checkpoint deferred (busy)");
    }
    if let Err(e) = store.prune_events(
        crate::core::port::EVENTS_RETENTION_SECS,
        crate::core::port::EVENTS_MAX_ROWS,
    ) {
        warn!(scan_id = %scan_id, error = %e, "events prune deferred");
    }
    if let Err(e) = store.prune_raw_archive(crate::core::port::RAW_ARCHIVE_MAX_ROWS) {
        warn!(scan_id = %scan_id, error = %e, "raw_archive prune deferred");
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex as StdMutex;

    use super::*;
    use crate::core::correlator::Correlation;
    use crate::core::entity::{Entity, EntityKind};
    use crate::core::error::Error;
    use crate::core::event::Event;
    use crate::core::relation::{Relation, RelationKind, connection_templates};
    use crate::core::scan::Scan;
    use crate::core::test_support::InMemoryStore;

    /// A configurable [`StoragePort`] probe wrapping [`InMemoryStore`]. It can be
    /// told to fail the batch upsert (to drive the per-entity fallback) and to
    /// reject one specific UID on per-entity upsert (to drive PARTIAL salvage), and
    /// it tracks pathway-template counts for real — the default port double reports
    /// a flat `0`, so cross-scan crediting could never fire against it. Every other
    /// method delegates verbatim to the inner in-memory store.
    struct ProbeStore {
        inner: InMemoryStore,
        fail_batch: bool,
        poison_uid: Option<String>,
        templates: StdMutex<HashMap<String, u32>>,
    }

    impl ProbeStore {
        fn new() -> Self {
            Self {
                inner: InMemoryStore::new(),
                fail_batch: false,
                poison_uid: None,
                templates: StdMutex::new(HashMap::new()),
            }
        }

        /// A store whose batch upsert always rolls back, optionally poisoning one
        /// UID so its per-entity fallback also fails (partial-salvage scenario).
        fn failing_batch(poison_uid: Option<&str>) -> Self {
            Self {
                fail_batch: true,
                poison_uid: poison_uid.map(str::to_string),
                ..Self::new()
            }
        }
    }

    impl StoragePort for ProbeStore {
        fn upsert_scan(&self, scan: &Scan) -> Result<()> {
            self.inner.upsert_scan(scan)
        }
        fn get_scan(&self, id: &str) -> Result<Option<Scan>> {
            self.inner.get_scan(id)
        }
        fn list_scans(&self, limit: usize) -> Result<Vec<Scan>> {
            self.inner.list_scans(limit)
        }
        fn delete_scan(&self, scan_id: &str) -> Result<bool> {
            self.inner.delete_scan(scan_id)
        }
        fn upsert_entity(&self, entity: &Entity) -> Result<()> {
            if self.poison_uid.as_deref() == Some(entity.uid.as_str()) {
                return Err(Error::Other(format!("poisoned entity {}", entity.uid)));
            }
            self.inner.upsert_entity(entity)
        }
        fn upsert_entities_batch(&self, entities: &[Entity]) -> Result<usize> {
            if self.fail_batch {
                return Err(Error::Other("batch rolled back".into()));
            }
            self.inner.upsert_entities_batch(entities)
        }
        fn entities_for_scan(&self, scan_id: &str) -> Result<Vec<Entity>> {
            self.inner.entities_for_scan(scan_id)
        }
        fn entities_filtered(
            &self,
            scan_id: &str,
            kind: Option<&str>,
            min_confidence: Option<f64>,
            value_contains: Option<&str>,
        ) -> Result<Vec<Entity>> {
            self.inner
                .entities_filtered(scan_id, kind, min_confidence, value_contains)
        }
        fn entity_facets(&self, scan_id: &str) -> Result<Vec<(String, u64)>> {
            self.inner.entity_facets(scan_id)
        }
        fn get_entity(&self, uid: &str) -> Result<Option<Entity>> {
            self.inner.get_entity(uid)
        }
        fn search_entities(&self, query: &str, limit: usize) -> Result<Vec<Entity>> {
            self.inner.search_entities(query, limit)
        }
        fn scan_ids_for_entity(&self, entity_uid: &str) -> Result<Vec<String>> {
            self.inner.scan_ids_for_entity(entity_uid)
        }
        fn observation_count(&self, entity_uid: &str) -> Result<usize> {
            self.inner.observation_count(entity_uid)
        }
        fn upsert_correlation(&self, c: &Correlation) -> Result<()> {
            self.inner.upsert_correlation(c)
        }
        fn correlations_for_scan(&self, scan_id: &str) -> Result<Vec<Correlation>> {
            self.inner.correlations_for_scan(scan_id)
        }
        fn upsert_relation(&self, r: &Relation) -> Result<()> {
            self.inner.upsert_relation(r)
        }
        fn relations_for_scan(&self, scan_id: &str) -> Result<Vec<Relation>> {
            self.inner.relations_for_scan(scan_id)
        }
        fn insert_event(&self, event: &Event) -> Result<()> {
            self.inner.insert_event(event)
        }
        fn events_for_scan(&self, scan_id: &str) -> Result<Vec<Event>> {
            self.inner.events_for_scan(scan_id)
        }
        fn record_pathway_template(&self, template: &str) -> Result<()> {
            *self
                .templates
                .lock()
                .unwrap()
                .entry(template.to_string())
                .or_insert(0) += 1;
            Ok(())
        }
        fn pathway_template_count(&self, template: &str) -> Result<u32> {
            Ok(self
                .templates
                .lock()
                .unwrap()
                .get(template)
                .copied()
                .unwrap_or(0))
        }
    }

    fn mk(kind: EntityKind, value: &str, scan_id: &str) -> Entity {
        Entity::new(kind, value, 0.8, scan_id)
    }

    #[test]
    fn persist_batch_success_returns_count_and_no_error() {
        let store = InMemoryStore::new();
        let ents = vec![
            mk(EntityKind::Email, "a@x.com", "s"),
            mk(EntityKind::Person, "Alice", "s"),
        ];
        let (persisted, first_err) = persist_entities_with_fallback(&store, &ents, "s");
        assert_eq!(persisted, 2, "the batch persists every entity");
        assert!(first_err.is_none(), "a clean batch surfaces no error");
        assert_eq!(store.entity_count(), 2);
    }

    #[test]
    fn persist_batch_rollback_falls_back_and_fully_salvages() {
        // Batch rolls back but every per-entity upsert succeeds → all salvaged,
        // no error surfaced (the fallback is invisible to the caller's status).
        let store = ProbeStore::failing_batch(None);
        let ents = vec![
            mk(EntityKind::Email, "a@x.com", "s"),
            mk(EntityKind::Person, "Alice", "s"),
        ];
        let (persisted, first_err) = persist_entities_with_fallback(&store, &ents, "s");
        assert_eq!(persisted, 2, "per-entity fallback salvages every entity");
        assert!(first_err.is_none(), "no per-entity failure → no error");
        assert_eq!(
            store.inner.entity_count(),
            2,
            "the salvaged entities persist"
        );
    }

    #[test]
    fn persist_batch_rollback_partial_salvage_recovers_first_err() {
        // Batch rolls back AND one entity is individually un-persistable → the rest
        // are salvaged and the granular `first_err` is recovered. This is the exact
        // resilience contract the caller's Failed-vs-Complete status logic reads:
        // partial persist ⇒ Complete-with-error, nothing persisted ⇒ Failed.
        let poison = mk(EntityKind::Email, "poison@x.com", "s");
        let store = ProbeStore::failing_batch(Some(poison.uid.as_str()));
        let good = mk(EntityKind::Person, "Alice", "s");
        let ents = vec![good.clone(), poison.clone()];

        let (persisted, first_err) = persist_entities_with_fallback(&store, &ents, "s");

        assert_eq!(persisted, 1, "only the non-poison entity persists");
        let msg = first_err.expect("the poison failure is recovered as first_err");
        assert!(
            msg.contains(&poison.uid),
            "first_err names the failing entity: {msg}"
        );
        assert!(
            store.get_entity(&good.uid).unwrap().is_some(),
            "the good entity is salvaged"
        );
        assert!(
            store.get_entity(&poison.uid).unwrap().is_none(),
            "the poison entity is not persisted"
        );
    }

    /// A route a *strictly earlier* scan proved (`prior == 1`) fires AU-065 and is
    /// persisted, but stays below AU-066's `prior >= 2` gap-fill threshold, so no
    /// endpoint is queued for the corroboration boost. Pins the seam's crediting +
    /// dedup + boost-threshold behaviour without reaching into the connection-
    /// template / fragile-link internals the storage and smoke suites already cover.
    #[tokio::test]
    async fn learn_cross_scan_pathways_credits_a_prior_route_and_holds_the_boost_at_au065() {
        let store: Arc<dyn StoragePort> = Arc::new(ProbeStore::new());
        let sid = "s";

        // A 2-hop identity route: Email → Domain → Person, persisted to the store
        // (the helper reads its working set back from storage).
        let email = mk(EntityKind::Email, "a@x.com", sid);
        let domain = mk(EntityKind::Domain, "x.com", sid);
        let person = mk(EntityKind::Person, "Alice", sid);
        for e in [&email, &domain, &person] {
            store.upsert_entity(e).unwrap();
        }
        let rels = [
            Relation::new(
                email.uid.clone(),
                domain.uid.clone(),
                RelationKind::BelongsToDomain,
                0.8,
                sid,
            ),
            Relation::new(
                domain.uid.clone(),
                person.uid.clone(),
                RelationKind::RegisteredBy,
                0.8,
                sid,
            ),
        ];
        for r in &rels {
            store.upsert_relation(r).unwrap();
        }

        // Seed each of the route's templates once → exactly one strictly-earlier
        // scan proved it (prior == 1 when the helper consults, before it records).
        let ents = [email.clone(), domain.clone(), person.clone()];
        let templates = connection_templates(&ents, &rels, 4);
        assert!(!templates.is_empty(), "the route generalises to a template");
        for ct in &templates {
            store.record_pathway_template(&ct.template).unwrap();
        }

        let (bus, _rx) = tokio::sync::broadcast::channel(64);
        let emitter = EventEmitter::new(DbWriter::spawn(Arc::clone(&store)), bus);
        let mut emitted_corr: HashSet<String> = HashSet::new();

        let boost = learn_cross_scan_pathways(store.as_ref(), &emitter, sid, &mut emitted_corr);

        let corrs = store.correlations_for_scan(sid).unwrap();
        assert!(
            corrs.iter().any(|c| c.rule_id == "AU-065"),
            "a prior-proven route fires AU-065"
        );
        assert!(
            !corrs.iter().any(|c| c.rule_id == "AU-066"),
            "AU-066 requires >= 2 prior scans"
        );
        assert!(
            boost.is_empty(),
            "no endpoint is queued for the boost at the AU-065 threshold"
        );
        assert!(
            !emitted_corr.is_empty(),
            "the fired correlation is recorded in the live-dedup set"
        );
        // The helper also recorded this scan's own template (learning), so a future
        // scan reproducing the route would see prior >= 2.
        assert!(
            store
                .pathway_template_count(&templates[0].template)
                .unwrap()
                >= 2,
            "this scan's route is recorded for future crediting"
        );
    }
}
