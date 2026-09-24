//! Shared use case: persist an already-extracted batch of entities as a
//! completed scan.
//!
//! Two commands turn a batch of entities the operator ALREADY has — rather than
//! a live target — into a stored, correlated scan: `hse import` (breach/dossier
//! exports) and `hse ingest --auto-scan` (entities extracted from a document).
//! Both want the same finalise the live engine runs — offline geospatial
//! enrichment, deterministic relation derivation, correlation — and both must
//! open the store, which the presentation layers (`cli`/`api`) are forbidden to
//! do directly (`tests/architecture.rs`). Housing that tail here, in the
//! application layer, lets either command produce a scan indistinguishable from
//! a live one without duplicating the composition or reaching into `storage`
//! from the CLI.

use crate::core::entity::Entity;
use crate::core::error::Result;
use crate::core::scan::TargetKind;

/// A human-readable scan label: the strongest identity in `entities` — a
/// `Person`, else an `Email` — else `fallback`. Shared so every batch-persist
/// path labels its scan by the same rule and the operator sees one consistent
/// naming regardless of whether the batch arrived via `import` or `ingest`.
pub(crate) fn strongest_identity_label(entities: &[Entity], fallback: impl Into<String>) -> String {
    use crate::core::entity::EntityKind;
    entities
        .iter()
        .find(|e| e.kind == EntityKind::Person)
        .or_else(|| entities.iter().find(|e| e.kind == EntityKind::Email))
        .map_or_else(|| fallback.into(), |e| e.value.clone())
}

/// Confidence-rank `entities` in place before deriving relations — the
/// precondition `derive_all_within` → `derive_coreferences` →
/// `resolve_coreferences`'s `.take(MAX_COREF_NODES)` documents it relies on:
/// "`entities` arrives confidence-ranked, so `.take` keeps the strongest
/// identities — a deterministic prefix". Delegates to
/// [`crate::util::recon::sort_by_confidence_desc`] (Pass 26: this used to
/// carry its own byte-for-byte independent copy of that exact comparator,
/// the identical duplication `core::engine::merge_found_keys_and_flatten`'s
/// own copy — still separate — is documented as "mirroring").
///
/// [`persist_entities_as_scan`] (the shared tail of `hse import` and
/// `hse ingest --auto-scan`) used to hand entities through in raw
/// file-arrival/dedup order instead, so above the identity-entity ceiling the
/// truncation kept a DIFFERENT SUBSET on every run — re-importing the same
/// underlying data with source rows in a different order could drop a
/// different, possibly stronger, identity pair from ever being scored, not
/// merely reorder the result. Below the ceiling the ranking half was still
/// unhonoured. The web upload path (`api::scan_handlers::core`) already
/// guards this precondition with its own entity-count ceiling; this
/// CLI-facing path shares the same `derive_all_within` call but had neither
/// that ceiling nor this sort.
fn confidence_rank(entities: &mut [Entity]) {
    crate::util::recon::sort_by_confidence_desc(entities);
}

/// An import's scan row, owned from its first write to its terminal one — the
/// one lifecycle both import paths (`persist_entities_as_scan` and the web
/// upload, `api::scan_handlers::core::scan_import`) write, so they cannot
/// drift on it.
///
/// [`Self::begin`] writes the row `Running`: an import whose entities are being
/// stored HAS started, and `Running` is the state the read-time `interrupted`
/// derivation (`api::handlers::is_interrupted`, REQ-SCANSTATUS-001) watches.
/// The round-2 order (REQ-SCANSTATUS-002) wrote it `Pending` instead, which
/// that derivation deliberately ignores ("never started") — so a process
/// killed mid-import (routine on Termux) left a row reading `pending` forever,
/// counted as in progress by `/stats` and the scan list, where it had read
/// `complete` before (REQ-SCANSTATUS-005).
///
/// [`Self::finish`] writes the terminal status. Dropped WITHOUT `finish` — an
/// error returned by `?` after the first write, or a panic unwinding through
/// the import — the row is written `Failed` (best-effort, logged), so no exit
/// the process survives can leave it in progress. A kill leaves `Running`,
/// which the web process that holds the import in its in-flight registry reads
/// as interrupted once it is gone.
///
/// Every terminal write — [`Self::finish`]'s, or the `Failed` [`Drop`]
/// records — comes with the announcement a live scan ends with, in the order
/// the engine makes it (`ScanEngine::finalise_scan`'s commit step,
/// `conclude_failed`): a `scan_complete` event carrying the terminal status,
/// the stored entity count and whether the finalise fell short is recorded in
/// the scan's event log FIRST, then the row is written terminal, then the
/// event is broadcast on the bus [`Self::announce_on`] names (the web
/// upload's; the CLI import has none). A row reads `complete` or `aborted`
/// only once its `scan_complete` is in the log, so no export or event-log
/// download reads a finished import with no word of how it ended, and a
/// refused row write leaves a `running` row (then `Failed`, [`Drop`]) rather
/// than a `complete` one whose log never says so (REQ-SCANSTATUS-033). A
/// refused `scan_complete` write is a refused commit too: [`Self::finish`]
/// writes no terminal row and leaves it to [`Drop`], whose `Failed` row names
/// the refused event write (REQ-SCANSTATUS-037). That `Failed` row is
/// written even when the store refuses its own event as well — a row must
/// not read in progress forever — and its error then says the event was not
/// recorded, so the row itself tells an export what its log lacks. The row reads `running` while the import works
/// (REQ-SCANSTATUS-005), so the web scan log tails it as live — and it learns
/// that a scan ended from that event alone. With no import ever sending it,
/// the log of an import opened mid-run read `live` until the stream's idle
/// timeout and then `disconnected`, never `complete` (REQ-SCANSTATUS-031).
pub(crate) struct ImportScanRow {
    store: std::sync::Arc<dyn crate::core::StoragePort>,
    scan: crate::core::scan::Scan,
    finished: bool,
    bus: Option<crate::core::event::EventBus>,
    /// Which write of [`Self::finish`]'s commit the store refused, and why —
    /// its `scan_complete` event or its terminal row — for the `Failed` row
    /// [`Drop`] records in its place.
    refused: Option<String>,
    /// Whether that refused write was the `scan_complete` event, so the
    /// `Failed` row's error already says the log lacks one.
    completion_unlogged: bool,
}

impl ImportScanRow {
    /// Write `scan` as `Running` and take charge of its terminal status.
    ///
    /// The row claims no entities yet: nothing is stored until
    /// [`Self::store_entities`], and the count it records is what that stored
    /// (REQ-SCANSTATUS-009). It is marked an
    /// [`Import`](crate::core::scan::ScanOrigin::Import) here, the one place
    /// every import's row is written, so a shortfall on it is never told that
    /// a re-run rebuilds it (REQ-SCANSTATUS-020).
    pub(crate) fn begin(
        store: std::sync::Arc<dyn crate::core::StoragePort>,
        mut scan: crate::core::scan::Scan,
    ) -> Result<Self> {
        scan.status = crate::core::scan::ScanStatus::Running;
        scan.entity_count = 0;
        scan.origin = crate::core::scan::ScanOrigin::Import;
        store.upsert_scan(&scan)?;
        Ok(Self {
            store,
            scan,
            finished: false,
            bus: None,
            refused: None,
            completion_unlogged: false,
        })
    }

    /// Broadcast the import's `scan_complete` on `bus` too, once it is
    /// recorded — for the live subscribers of the process running it (the web
    /// scan log's stream).
    pub(crate) fn announce_on(mut self, bus: crate::core::event::EventBus) -> Self {
        self.bus = Some(bus);
        self
    }

    /// The `scan_complete` a live scan ends with, for the terminal row about
    /// to be written — its status, count and shortfall — recorded in the
    /// scan's event log BEFORE that write, as the engine's commit step
    /// records and flushes its own before the row: a row that reads
    /// `complete` or `aborted` has its `scan_complete` in the log
    /// (REQ-SCANSTATUS-033). Returns the event, for [`Self::broadcast`] once
    /// the row is written, and whether the store took it: the caller decides
    /// what a refused event write means for the row (REQ-SCANSTATUS-037).
    fn record_completion(&self) -> (crate::core::event::Event, Result<()>) {
        use crate::core::event::{Event, EventKind};
        let event = Event::new(
            self.scan.id.clone(),
            EventKind::ScanComplete {
                scan_id: self.scan.id.clone(),
                entity_count: self.scan.entity_count,
                status: self.scan.status,
                finalise_incomplete: self.scan.finalise_incomplete(),
            },
        );
        let recorded = self.store.insert_event(&event);
        if let Err(e) = &recorded {
            tracing::warn!(
                scan_id = %self.scan.id,
                error = %e,
                "import: could not record its scan_complete event"
            );
        }
        (event, recorded)
    }

    /// Broadcast a recorded `scan_complete` on the bus, after the row it
    /// describes is written — so a subscriber that re-reads the row on the
    /// event reads it terminal, as the engine orders its own.
    fn broadcast(&self, event: crate::core::event::Event) {
        if let Some(bus) = &self.bus {
            // Errors only when nobody is subscribed — the usual case.
            let _ = bus.send(event);
        }
    }

    /// Store the import's entities — one atomic batch, so it lands whole or
    /// not at all — and only then count them on the row, for the terminal
    /// write ([`Self::finish`], or the `Failed` [`Drop`] records). The count
    /// used to be set before [`Self::begin`], so a batch the store refused (a
    /// full or locked disk) left a `Failed` row claiming every entity while
    /// `entities_for_scan` returned none, and `/stats` summed them into
    /// `total_entities`. A row claims what the store holds for the scan
    /// (REQ-SCANSTATUS-009), as a live scan's `Failed` row does
    /// (`ScanEngine::conclude_failed` counts `entities_for_scan`).
    pub(crate) fn store_entities(&mut self, entities: &[Entity]) -> Result<()> {
        self.store.upsert_entities_batch(entities)?;
        self.scan.entity_count = entities.len();
        Ok(())
    }

    /// Write the terminal `status` — the import's last write — together with
    /// what the import's finalise did not complete: `tally`'s message, the one
    /// [`Scan::error`](crate::core::scan::Scan::error) authority
    /// ([`FinaliseTally`](crate::core::scan::FinaliseTally)), so the status and
    /// the error an export classifies the scan by are written in one place and
    /// once. Returns that error, for the caller's summary.
    ///
    /// The `scan_complete` is recorded before the row and broadcast after it
    /// ([`Self::record_completion`]). A refused row write leaves the row to
    /// [`Drop`], which records `Failed` and a `scan_complete {failed}` after
    /// this one — the log reads "complete" then "failed", its last word the
    /// row's, as a live scan's does when its commit is refused
    /// (REQ-SCANSTATUS-014); subscribers hear only the failure. A refused
    /// `scan_complete` write is refused the same way, before any terminal
    /// row is written: the row never reads `complete` with no `scan_complete`
    /// in its log (REQ-SCANSTATUS-037).
    pub(crate) fn finish(
        mut self,
        status: crate::core::scan::ScanStatus,
        tally: &crate::core::scan::FinaliseTally,
    ) -> Result<Option<String>> {
        self.scan.status = status;
        self.scan.finished_at = Some(crate::core::entity::unix_now());
        self.scan.error = tally.message();
        let (completion, recorded) = self.record_completion();
        if let Err(e) = recorded {
            self.refused = Some(format!("the scan_complete event write failed: {e}"));
            self.completion_unlogged = true;
            return Err(e);
        }
        let error = self.scan.error.clone();
        match self.store.upsert_scan(&self.scan) {
            Ok(()) => {
                self.finished = true;
                self.broadcast(completion);
                Ok(error)
            }
            Err(e) => {
                self.refused = Some(format!("the terminal status write failed: {e}"));
                Err(e)
            }
        }
    }
}

impl Drop for ImportScanRow {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        self.scan.status = crate::core::scan::ScanStatus::Failed;
        self.scan.finished_at = Some(crate::core::entity::unix_now());
        self.scan.error = Some(match self.refused.take() {
            // A write of `finish`'s commit was refused: say which, after the
            // shortfall it carried, as the engine's refused commit does.
            Some(refused) => match self.scan.error.take() {
                Some(shortfall) => format!("{shortfall}; {refused}"),
                None => refused,
            },
            None if std::thread::panicking() => {
                "import panicked before its terminal write".to_string()
            }
            None => "import failed before its terminal write".to_string(),
        });
        // Recorded before the row, broadcast after it, as `finish` does. The
        // row is written `Failed` even when the store refuses this event too
        // — a row must not read in progress forever — and then says its log
        // lacks the event, unless its error already does (REQ-SCANSTATUS-037).
        let (completion, recorded) = self.record_completion();
        if let (Err(e), false) = (recorded, self.completion_unlogged)
            && let Some(error) = self.scan.error.as_mut()
        {
            use std::fmt::Write as _;
            let _ = write!(error, "; the scan_complete event write failed: {e}");
        }
        if let Err(e) = self.store.upsert_scan(&self.scan) {
            tracing::warn!(
                scan_id = %self.scan.id,
                error = %e,
                "import: could not record the Failed status; the row still reads running"
            );
        }
        // Broadcast even when the row write failed, as `conclude_failed`
        // does: the event still says how the import ended.
        self.broadcast(completion);
    }
}

/// Device-safety bound shared by every import: every caller of
/// [`persist_entities_as_scan`] (`hse import`, `hse investigate --auto-scan`,
/// `hse ingest --auto-scan`) and the web upload
/// (`api::scan_handlers::core::scan_import`), each through
/// [`skip_enrichment_over_cap`].
///
/// Cross-entry enrichment (relation derivation + the correlator) is pairwise
/// WITHIN same-key buckets, so a pathological single-key batch — e.g. tens of
/// thousands of `*@one-domain.tld` rows, exactly the shape a real leaked
/// database table takes — degrades to a multi-minute O(n²) pass that would
/// lock a 2-core Termux phone. Reproduced live: a synthetic 4,000-row
/// same-domain SQL-dump import already took 36+ seconds with NO cap in place
/// (this function had none prior to this guard; the web upload handler
/// carried its own identical `IMPORT_ENRICH_MAX_ENTITIES` copy until both
/// read this one through [`skip_enrichment_over_cap`]).
///
/// The import's PRIMARY contract — persist every parsed entity — is met
/// unconditionally by [`persist_entities_as_scan`]; only this best-effort
/// enrichment is bounded, so a huge batch always COMPLETES. A realistic batch
/// (well under the cap) still gets full relations + correlations.
pub(crate) const PERSIST_ENRICH_MAX_ENTITIES: usize = 5_000;

/// Whether an import of `entity_count` entities skips its relation and
/// correlation passes for size ([`PERSIST_ENRICH_MAX_ENTITIES`]) — and, when
/// it does, the skip recorded on `tally` as a
/// [`FinalisePass::ImportEnrichment`](crate::core::scan::FinalisePass::ImportEnrichment)
/// that did not run, with a deterministic reason. The one cap check both
/// import paths make (the CLI's [`persist_batch_into`], the web upload's
/// `api::scan_handlers::core::scan_import`).
///
/// The skip used to be visible only in the caller's `enriched=false` — the
/// CLI summary line or the HTTP response. The scan was written `Complete`
/// with `error: None`, so every export of a 6,000-row breach import read
/// "complete" with CORRELATIONS (0): a correlator that never ran, read as
/// one that found nothing. Recorded here, the scan's `error` carries it and
/// every export reads it "partial, finalise-incomplete", as it does a pass
/// that failed (REQ-SCANSTATUS-010).
pub(crate) fn skip_enrichment_over_cap(
    entity_count: usize,
    tally: &mut crate::core::scan::FinaliseTally,
) -> bool {
    if entity_count <= PERSIST_ENRICH_MAX_ENTITIES {
        return false;
    }
    tally.import_enrichment_skipped(entity_count, PERSIST_ENRICH_MAX_ENTITIES);
    true
}

/// What [`persist_entities_as_scan`] stored, for the caller's summary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PersistedBatch {
    /// Entities stored — the batch AFTER [`prepare_import_batch`] appended the
    /// Coordinates it derives from addresses, so the count the enrichment cap
    /// ([`skip_enrichment_over_cap`]) and the scan row read. A caller's own
    /// pre-preparation count is not what was stored: a 4,990-row file whose
    /// addresses derived 11 fixes stored 5,001 entities and tripped the cap,
    /// while the summary said "4990 entities" (REQ-SCANSTATUS-013).
    pub entities: usize,
    /// Relations persisted.
    pub relations: usize,
    /// Correlations persisted.
    pub correlations: usize,
    /// `false` when relations/correlations were skipped for size
    /// ([`PERSIST_ENRICH_MAX_ENTITIES`]) — distinguishes that from a batch that
    /// genuinely yielded none.
    pub enriched: bool,
    /// What the scan's finalise did not complete, as recorded in its `error`
    /// field — relations or correlations the store refused, a correlation
    /// pass that failed outright, or both passes skipped for size
    /// ([`skip_enrichment_over_cap`]) — or `None` when it completed.
    /// The scan is still `Complete`; every export of it now reads partial
    /// ("finalise-incomplete"), and a caller's summary must say so too rather
    /// than report the counts as if they were the whole graph.
    pub finalise_error: Option<String>,
}

impl PersistedBatch {
    /// The summary every CLI import surface prints (`hse import`, `hse ingest
    /// --auto-scan`, `hse investigate --auto-scan`), each under its own
    /// prefix ("Stored:", "auto-scan: stored"): the scan that was stored,
    /// counted from this batch, then — when the finalise did not complete —
    /// that the scan is incomplete and why.
    ///
    /// The one statement of an enrichment-cap skip is that second line: the
    /// skip is recorded in [`Self::finalise_error`] with the count the cap
    /// read ([`skip_enrichment_over_cap`]). Each surface also printed its own
    /// "relations/correlations skipped — N entities exceeds the cap" note from
    /// its pre-preparation count, so one skip read "5001 entities exceed the
    /// cap" and "4990 entities exceeds the cap" on consecutive lines — and
    /// 4990 does not exceed 5000 (REQ-SCANSTATUS-013).
    pub(crate) fn summary_lines(&self, sid: &str) -> Vec<String> {
        let mut lines = vec![format!(
            "scan {sid} ({} entities, {} relations, {} correlations) — view with `hse list`",
            self.entities, self.relations, self.correlations
        )];
        if let Some(err) = &self.finalise_error {
            lines.push(format!(
                "the scan is stored but INCOMPLETE — {err}; its exports read partial \
                 (finalise-incomplete)"
            ));
        }
        lines
    }
}

/// Persist `entities` as a `Complete` scan `sid` (labelled `label`, target kind
/// `kind`) in the default store, then derive the deterministic entity relations
/// and run the correlator over it — exactly as a live scan's finalise does, so a
/// batch-persisted scan carries the same graph a live scan would. The scan then
/// appears in `hse list` and every view/export (entities, dossier, debug bundle,
/// GEXF) works on it, and its pivots can later seed a re-scan.
///
/// Not fatal on relations and correlations: the entities are already persisted,
/// so a hiccup storing the graph must not fail the whole operation — but it is
/// no longer silent either. Each refused write, and a correlation pass that
/// fails outright, is counted into the scan's
/// [`FinaliseTally`](crate::core::scan::FinaliseTally) and recorded on the scan
/// (see [`PersistedBatch::finalise_error`]).
pub(crate) async fn persist_entities_as_scan(
    sid: &str,
    label: String,
    kind: TargetKind,
    entities: &[Entity],
) -> Result<PersistedBatch> {
    use crate::core::StoragePort;
    use std::sync::Arc;

    // Offline geospatial enrichment, exactly as the live scan finalise does:
    // parse each Address, geohash/timezone/country-tag each Coordinates, and
    // derive Coordinates from any Address whose city resolves offline — so the
    // batch's addresses feed the geo-correlation stack (co-location, AU-014/017/
    // 032/056/057/085) instead of sitting inert. Deterministic, no network; runs
    // before relations/correlations so the derived fixes are persisted, related
    // and correlated in this same pass.
    let mut entities = entities.to_vec();
    prepare_import_batch(&mut entities, sid);

    let store: Arc<dyn StoragePort> =
        Arc::new(crate::storage::Store::open(&crate::default_db_path())?);
    persist_batch_into(&store, sid, label, kind, &entities)
}

/// What every import does to its parsed entities before storing them — the
/// CLI's (`hse import` / `ingest` / `investigate`, through
/// [`persist_entities_as_scan`]) and the web upload's
/// (`api::scan_handlers::core::scan_import`) — so the same bytes imported
/// through either surface are stored as the same scan: the offline geospatial
/// enrichment a live scan's finalise applies
/// ([`enrich_offline_geo`](crate::core::engine::enrich_offline_geo) — address
/// parsing, geohash/timezone/country tags, admission grain stamps, and
/// Coordinates derived from addresses), then the strongest-first ranking
/// relation derivation relies on ([`confidence_rank`]). The web upload used to
/// skip both, so an Address "10 Smith St, Sydney NSW 2000" became a Sydney fix
/// through `hse import` and nothing through the browser, and every relation,
/// correlation and place label downstream differed (REQ-GEOLABEL-033).
/// Derived Coordinates are appended, so a caller counts the batch after this.
pub(crate) fn prepare_import_batch(entities: &mut Vec<Entity>, sid: &str) {
    crate::core::engine::enrich_offline_geo(entities, sid);
    confidence_rank(entities);
}

/// The store-facing body of [`persist_entities_as_scan`], over an injected
/// store so a test can hand it one that refuses writes.
fn persist_batch_into(
    store: &std::sync::Arc<dyn crate::core::StoragePort>,
    sid: &str,
    label: String,
    kind: TargetKind,
    entities: &[Entity],
) -> Result<PersistedBatch> {
    use crate::core::scan::{FinaliseTally, Scan, ScanStatus, Target};

    // The scan row is written `Running` and turned `Complete` only after its
    // entities, relations and correlations are all stored. Exports classify a
    // scan by its stored status (`partial_export_reason`), so writing
    // `Complete` first let an export taken mid-import brand a half-written
    // scan whole, the same window the live engine's finalise had (see
    // `ScanEngine::finalise_scan`'s commit step). Any exit before `finish` —
    // an error below, a panic — records `Failed` (`ImportScanRow`).
    let scan = Scan::new(sid.to_string(), Target::new(kind, label));
    let mut row = ImportScanRow::begin(std::sync::Arc::clone(store), scan)?;
    row.store_entities(entities)?;
    let mut tally = FinaliseTally::default();
    let (relations, correlations, enriched) =
        enrich_persisted_batch(store, sid, entities, &mut tally);
    // The batch was imported in full, so the status is `Complete`; what the
    // finalise did not complete is recorded beside it by the row's one
    // terminal write, where every export's completeness check reads it.
    let finalise_error = row.finish(ScanStatus::Complete, &tally)?;
    Ok(PersistedBatch {
        entities: entities.len(),
        relations,
        correlations,
        enriched,
        finalise_error,
    })
}

/// The best-effort enrichment half of [`persist_entities_as_scan`]: relations
/// and correlations over the already-stored batch, bounded by
/// [`PERSIST_ENRICH_MAX_ENTITIES`], each write counted into `tally` through the
/// same persist steps the live finalise uses
/// ([`persist_relations`](crate::core::engine::persist_relations),
/// [`correlate_and_persist`](crate::core::engine::correlate_and_persist)).
/// Returns `(relations, correlations, enriched)` — the counts that persisted.
fn enrich_persisted_batch(
    store: &std::sync::Arc<dyn crate::core::StoragePort>,
    sid: &str,
    entities: &[Entity],
    tally: &mut crate::core::scan::FinaliseTally,
) -> (usize, usize, bool) {
    use crate::core::scan::FinaliseWrite;

    // Device-safety bound: skip the O(n²) enrichment on a pathologically
    // large batch (entities are already persisted above; nothing lost) — see
    // `PERSIST_ENRICH_MAX_ENTITIES`'s own doc for why and the reproduction.
    // The skip is recorded on the tally, so the scan does not read whole.
    if skip_enrichment_over_cap(entities.len(), tally) {
        return (0, 0, false);
    }

    // Bound derivation by wall-clock, identically to a live scan
    // (engine::derive_and_persist_relations): a large batch must not run the
    // super-linear derivation pass chain for minutes. Partial relations
    // persist, and a cut is recorded on the tally, so the scan does not read
    // whole (REQ-SCANSTATUS-024).
    let derived = crate::core::engine::derive_finalise_relations(entities, sid, tally);
    let relations = crate::core::engine::persist_relations(store.as_ref(), sid, &derived, tally);

    // The full correlator runs under the canonical panic guard inside
    // `correlate_and_persist` — a rule panicking on adversarial batch data (a
    // crafted imported dossier, or entities extracted from an arbitrary
    // document via `ingest --auto-scan`) degrades to "no correlations" rather
    // than unwinding the whole persist after the entities were already stored
    // and shown to the operator. The firings themselves are not needed here,
    // only how many the store kept.
    let _firings = crate::core::engine::correlate_and_persist(store, sid, tally);
    let correlations = tally.persisted(FinaliseWrite::Correlations);

    (relations, correlations, true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::entity::{Entity, EntityKind};

    /// REQ-SCANSTATUS-005: an import's row reads `Running` while it runs (the
    /// state the read-time `interrupted` derivation watches — `Pending` is
    /// "never started" to it), and any exit before its terminal write — an
    /// error, a panic — records `Failed` instead of leaving it in progress
    /// forever.
    #[test]
    fn an_import_row_never_outlives_its_import_in_progress() {
        use crate::core::StoragePort;
        use crate::core::scan::{Scan, ScanStatus, Target};
        use std::sync::Arc;
        let store: Arc<dyn StoragePort> = Arc::new(crate::core::test_support::InMemoryStore::new());
        let status = |id: &str| store.get_scan(id).unwrap().expect("row written").status;
        let scan = |id: &str| Scan::new(id.to_string(), Target::new(TargetKind::FullName, "x"));

        let row = ImportScanRow::begin(Arc::clone(&store), scan("ok")).unwrap();
        assert_eq!(
            status("ok"),
            ScanStatus::Running,
            "an import in progress has started"
        );
        let recorded = row
            .finish(
                ScanStatus::Complete,
                &crate::core::scan::FinaliseTally::default(),
            )
            .unwrap();
        assert_eq!(recorded, None, "a finalise that completed records nothing");
        assert_eq!(status("ok"), ScanStatus::Complete);

        // An error returned by `?` after the first write.
        let failing = || -> Result<()> {
            let _row = ImportScanRow::begin(Arc::clone(&store), scan("err"))?;
            Err(crate::core::error::Error::Other("disk full".into()))
        };
        assert!(failing().is_err());
        let failed = store.get_scan("err").unwrap().unwrap();
        assert_eq!(failed.status, ScanStatus::Failed);
        assert!(failed.finished_at.is_some() && failed.error.is_some());

        // A panic unwinding through the import.
        let panicking = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _row = ImportScanRow::begin(Arc::clone(&store), scan("panic")).unwrap();
            panic!("a rule panicked on adversarial data");
        }));
        assert!(panicking.is_err());
        assert_eq!(status("panic"), ScanStatus::Failed);
    }

    /// REQ-SCANSTATUS-031: every import ends with the `scan_complete` a live
    /// scan ends with — recorded in the scan's event log on each terminal
    /// write (`finish`, and the `Failed` its Drop records) and broadcast on the
    /// bus it was given, after the row is terminal.
    #[test]
    fn every_import_exit_announces_how_it_ended() {
        use crate::core::StoragePort;
        use crate::core::event::EventKind;
        use crate::core::scan::{FinaliseTally, FinaliseWrite, Scan, ScanStatus, Target};
        use std::sync::Arc;
        let store: Arc<dyn StoragePort> = Arc::new(crate::core::test_support::InMemoryStore::new());
        let scan = |id: &str| Scan::new(id.to_string(), Target::new(TargetKind::FullName, "x"));
        let announced = |id: &str| -> Vec<(ScanStatus, usize, bool)> {
            store
                .events_for_scan(id)
                .unwrap()
                .into_iter()
                .filter_map(|e| match e.kind {
                    EventKind::ScanComplete {
                        status,
                        entity_count,
                        finalise_incomplete,
                        ..
                    } => Some((status, entity_count, finalise_incomplete)),
                    _ => None,
                })
                .collect()
        };

        // A finish with a shortfall, on a bus: recorded, then broadcast
        // with the row already terminal.
        let (bus, mut rx) = tokio::sync::broadcast::channel(4);
        let mut row = ImportScanRow::begin(Arc::clone(&store), scan("short"))
            .unwrap()
            .announce_on(bus);
        row.store_entities(&[Entity::new(EntityKind::Email, "a@b.com", 0.9, "short")])
            .unwrap();
        let mut tally = FinaliseTally::default();
        tally.add(FinaliseWrite::Relations, 2, 2, Some("disk full".into()));
        row.finish(ScanStatus::Complete, &tally).unwrap();
        assert_eq!(announced("short"), vec![(ScanStatus::Complete, 1, true)]);
        let heard = rx.try_recv().expect("broadcast");
        assert_eq!(heard.scan_id, "short");
        assert!(matches!(heard.kind, EventKind::ScanComplete { .. }));

        // A CLI import (no bus) still records it.
        let row = ImportScanRow::begin(Arc::clone(&store), scan("cli")).unwrap();
        row.finish(ScanStatus::Complete, &FinaliseTally::default())
            .unwrap();
        assert_eq!(announced("cli"), vec![(ScanStatus::Complete, 0, false)]);

        // An exit before the terminal write announces `Failed`.
        drop(ImportScanRow::begin(Arc::clone(&store), scan("dropped")).unwrap());
        assert_eq!(announced("dropped"), vec![(ScanStatus::Failed, 0, false)]);
    }

    /// REQ-SCANSTATUS-033: an import records its `scan_complete` BEFORE the
    /// row reads terminal, as the engine's commit step does. It used to write
    /// the row first, so an export or event-log download between the two read
    /// a finished import with no `scan_complete`; and a refused terminal write
    /// left no `complete` in the log ahead of the `failed` its Drop records.
    #[test]
    fn an_import_row_reads_terminal_only_once_its_completion_is_logged() {
        use crate::core::StoragePort;
        use crate::core::event::EventKind;
        use crate::core::scan::{FinaliseTally, FinaliseWrite, Scan, ScanStatus, Target};
        use crate::core::test_support::{InMemoryStore, REFUSED_SCAN, RefusingStore};
        use std::sync::Arc;
        let scan = |id: &str| Scan::new(id.to_string(), Target::new(TargetKind::FullName, "x"));
        let logged = |store: &dyn StoragePort, id: &str| -> Vec<ScanStatus> {
            store
                .events_for_scan(id)
                .unwrap()
                .into_iter()
                .filter_map(|e| match e.kind {
                    EventKind::ScanComplete { status, .. } => Some(status),
                    _ => None,
                })
                .collect()
        };

        // Every terminal row write — `finish`'s and the `Failed` of Drop —
        // finds its `scan_complete` already in the log.
        let inner = Arc::new(InMemoryStore::new());
        let store: Arc<dyn StoragePort> = inner.clone();
        ImportScanRow::begin(Arc::clone(&store), scan("done"))
            .unwrap()
            .finish(ScanStatus::Complete, &FinaliseTally::default())
            .unwrap();
        drop(ImportScanRow::begin(Arc::clone(&store), scan("dropped")).unwrap());
        let witnesses = inner.terminal_witnesses();
        assert_eq!(witnesses.len(), 2, "{witnesses:?}");
        for w in &witnesses {
            assert!(w.completion_event, "{w:?}");
        }

        // A terminal write the store refuses: the log keeps the `complete`
        // it recorded first, then the `failed` of the row that replaced it —
        // its last word the row's — and the row says why.
        let inner = Arc::new(InMemoryStore::new());
        let store: Arc<dyn StoragePort> = Arc::new(
            RefusingStore::new(inner.clone()).refusing_scan_writes_in(ScanStatus::Complete),
        );
        let (bus, mut rx) = tokio::sync::broadcast::channel(4);
        let row = ImportScanRow::begin(Arc::clone(&store), scan("refused"))
            .unwrap()
            .announce_on(bus);
        let mut tally = FinaliseTally::default();
        tally.add(FinaliseWrite::Relations, 2, 2, Some("disk full".into()));
        assert!(row.finish(ScanStatus::Complete, &tally).is_err());
        assert_eq!(
            logged(inner.as_ref(), "refused"),
            vec![ScanStatus::Complete, ScanStatus::Failed]
        );
        let stored = inner.get_scan("refused").unwrap().expect("row written");
        assert_eq!(stored.status, ScanStatus::Failed);
        assert_eq!(
            stored.error.as_deref(),
            Some(
                format!(
                    "2/2 relations failed to persist: disk full; \
                     the terminal status write failed: {REFUSED_SCAN}"
                )
                .as_str()
            )
        );
        // Subscribers hear only how it ended: the failure.
        let heard = rx.try_recv().expect("broadcast");
        assert!(
            matches!(
                heard.kind,
                EventKind::ScanComplete {
                    status: ScanStatus::Failed,
                    ..
                }
            ),
            "{heard:?}"
        );
        assert!(rx.try_recv().is_err(), "one broadcast");
    }

    /// REQ-SCANSTATUS-037: a refused `scan_complete` write is a refused
    /// commit. `record_completion` only logged it, and `finish` wrote the row
    /// `complete` anyway, so a store that refused the new event row (a nearly
    /// full disk, `SQLITE_BUSY` behind a live scan's writer) but took the
    /// `UPDATE` left a finished import whose log never says how it ended —
    /// what REQ-SCANSTATUS-033 said could no longer happen.
    #[test]
    fn an_import_whose_completion_event_is_refused_never_reads_complete() {
        use crate::core::StoragePort;
        use crate::core::event::EventKind;
        use crate::core::scan::{FinaliseTally, FinaliseWrite, Scan, ScanStatus, Target};
        use crate::core::test_support::{InMemoryStore, REFUSED_EVENT, RefusingStore};
        use std::sync::Arc;
        let scan = |id: &str| Scan::new(id.to_string(), Target::new(TargetKind::FullName, "x"));
        let inner = Arc::new(InMemoryStore::new());
        let store: Arc<dyn StoragePort> =
            Arc::new(RefusingStore::new(inner.clone()).refusing_event_writes());

        let (bus, mut rx) = tokio::sync::broadcast::channel(4);
        let row = ImportScanRow::begin(Arc::clone(&store), scan("unlogged"))
            .unwrap()
            .announce_on(bus);
        let mut tally = FinaliseTally::default();
        tally.add(FinaliseWrite::Relations, 2, 2, Some("disk full".into()));
        assert!(row.finish(ScanStatus::Complete, &tally).is_err());
        // The row never read `complete`: its one terminal write is `Failed`.
        let statuses: Vec<ScanStatus> = inner
            .terminal_witnesses()
            .iter()
            .map(|w| w.status)
            .collect();
        assert_eq!(statuses, vec![ScanStatus::Failed]);
        let stored = inner.get_scan("unlogged").unwrap().expect("row written");
        assert_eq!(stored.status, ScanStatus::Failed);
        // It says which write was refused, after the shortfall it carried —
        // so the row itself tells a reader its log has no `scan_complete`.
        assert_eq!(
            stored.error.as_deref(),
            Some(
                format!(
                    "2/2 relations failed to persist: disk full; \
                     the scan_complete event write failed: {REFUSED_EVENT}"
                )
                .as_str()
            )
        );
        assert!(
            inner.events_for_scan("unlogged").unwrap().is_empty(),
            "the store took no event"
        );
        // Live subscribers still hear how it ended.
        let heard = rx.try_recv().expect("broadcast");
        assert!(
            matches!(
                heard.kind,
                EventKind::ScanComplete {
                    status: ScanStatus::Failed,
                    ..
                }
            ),
            "{heard:?}"
        );
        assert!(rx.try_recv().is_err(), "one broadcast");

        // An import that exits before `finish` is still written `Failed` —
        // never left in progress — and its row says its log lacks the event.
        drop(ImportScanRow::begin(Arc::clone(&store), scan("dropped")).unwrap());
        let stored = inner.get_scan("dropped").unwrap().expect("row written");
        assert_eq!(stored.status, ScanStatus::Failed);
        assert_eq!(
            stored.error.as_deref(),
            Some(
                format!(
                    "import failed before its terminal write; \
                     the scan_complete event write failed: {REFUSED_EVENT}"
                )
                .as_str()
            )
        );
    }

    /// REQ-SCANSTATUS-009: an import row claims only the entities it stored.
    /// The count was set before [`ImportScanRow::begin`], so the `Running` row
    /// claimed every parsed entity before any was stored, and a batch the
    /// store refused left a `Failed` row claiming them all while
    /// `entities_for_scan` returned none — `/stats` summed them into
    /// `total_entities`.
    #[test]
    fn an_import_row_claims_only_the_entities_it_stored() {
        use crate::core::StoragePort as _;
        use crate::core::scan::ScanStatus;
        use crate::core::test_support::{InMemoryStore, RefusingStore};
        use std::sync::Arc;

        let sid = "persist-refused-entities";
        let inner = Arc::new(InMemoryStore::new());
        let store: Arc<dyn crate::core::StoragePort> =
            Arc::new(RefusingStore::new(inner.clone()).refusing_entity_writes());
        let refused = persist_batch_into(
            &store,
            sid,
            "jsmith".into(),
            TargetKind::FullName,
            &enrichable_batch(sid),
        );
        assert!(refused.is_err(), "{refused:?}");
        let row = inner.get_scan(sid).unwrap().expect("row written");
        assert_eq!(row.status, ScanStatus::Failed);
        assert_eq!(row.entity_count, 0, "{row:?}");
        assert!(inner.entities_for_scan(sid).unwrap().is_empty());

        // While it runs, before its batch is stored, the row claims none.
        let mut claimed = crate::core::scan::Scan::new(
            "persist-running".to_string(),
            crate::core::scan::Target::new(TargetKind::FullName, "x"),
        );
        claimed.entity_count = 7;
        let running = ImportScanRow::begin(Arc::clone(&store), claimed).unwrap();
        assert_eq!(
            inner
                .get_scan("persist-running")
                .unwrap()
                .unwrap()
                .entity_count,
            0
        );
        drop(running);

        // Control: a stored batch is counted on the terminal row.
        let whole_store: Arc<dyn crate::core::StoragePort> = Arc::new(InMemoryStore::new());
        let entities = enrichable_batch(sid);
        persist_batch_into(
            &whole_store,
            sid,
            "jsmith".into(),
            TargetKind::FullName,
            &entities,
        )
        .expect("persist succeeds");
        let row = whole_store.get_scan(sid).unwrap().expect("row written");
        assert_eq!(row.status, ScanStatus::Complete);
        assert_eq!(row.entity_count, entities.len());
    }

    /// The merge of REQ-SCANSTATUS-005's lifecycle with REQ-SCANSTATUS-003's
    /// tally: the row's ONE terminal write carries both the status and what the
    /// finalise did not complete, so no second write can race or contradict
    /// it — and a shortfall never turns a finished import `Failed`.
    #[test]
    fn an_import_rows_terminal_write_carries_the_finalise_record() {
        use crate::core::StoragePort;
        use crate::core::scan::{FinaliseTally, FinaliseWrite, Scan, ScanStatus, Target};
        use std::sync::Arc;
        let store: Arc<dyn StoragePort> = Arc::new(crate::core::test_support::InMemoryStore::new());
        let scan = Scan::new("short".to_string(), Target::new(TargetKind::FullName, "x"));
        let row = ImportScanRow::begin(Arc::clone(&store), scan).unwrap();
        let mut tally = FinaliseTally::default();
        tally.add(FinaliseWrite::Relations, 4, 4, Some("disk full".into()));
        let recorded = row.finish(ScanStatus::Complete, &tally).unwrap();
        assert_eq!(recorded, tally.message());
        let stored = store.get_scan("short").unwrap().expect("row written");
        assert_eq!(stored.status, ScanStatus::Complete, "the import did finish");
        assert_eq!(
            stored.error.as_deref(),
            Some("4/4 relations failed to persist: disk full")
        );
        // REQ-SCANSTATUS-020: the row is an import's, so its shortfall is not
        // sent to a re-run — a live scan of the label that rebuilds nothing.
        assert_eq!(stored.origin, crate::core::scan::ScanOrigin::Import);
        let caveat = stored.completeness_caveat("the import").expect("caveated");
        assert!(!caveat.contains("re-run the scan"), "{caveat}");
        assert!(
            caveat.ends_with("re-import the data to rebuild it"),
            "{caveat}"
        );
    }

    #[test]
    fn strongest_identity_prefers_person_then_email_then_fallback() {
        let email = Entity::new(EntityKind::Email, "a@b.com", 0.9, "s");
        let person = Entity::new(EntityKind::Person, "Jane Doe", 0.9, "s");

        // Person wins over a present email.
        assert_eq!(
            strongest_identity_label(&[email.clone(), person.clone()], "fallback"),
            "Jane Doe"
        );
        // Email wins when there is no person.
        assert_eq!(
            strongest_identity_label(std::slice::from_ref(&email), "fallback"),
            "a@b.com"
        );
        // Fallback only when neither is present.
        let ip = Entity::new(EntityKind::IpAddress, "1.1.1.1", 0.9, "s");
        assert_eq!(strongest_identity_label(&[ip], "fallback"), "fallback");
    }

    #[test]
    fn confidence_rank_delegates_to_the_shared_comparator() {
        // Regression: `persist_entities_as_scan` used to hand entities to
        // `derive_all_within` in raw arrival order, so `resolve_coreferences`'s
        // `.take(MAX_COREF_NODES)` truncation (above the 5,000 identity-entity
        // ceiling) kept an arbitrary subset rather than the strongest one.
        // `confidence_rank` must sort strongest-first. The full tie-break
        // algorithm (uid order, not arrival order, on an exact confidence tie)
        // is `util::recon::sort_by_confidence_desc`'s own contract, pinned by
        // that function's tests — this just confirms the wrapper here still
        // forwards to it rather than drifting back into its own copy.
        let weak = Entity::new(EntityKind::Email, "weak@example.com", 0.3, "s");
        let strong = Entity::new(EntityKind::Email, "strong@example.com", 0.9, "s");
        let mid = Entity::new(EntityKind::Email, "mid@example.com", 0.6, "s");
        let mut entities = vec![weak.clone(), strong.clone(), mid.clone()];
        confidence_rank(&mut entities);
        assert_eq!(
            entities.iter().map(|e| e.value.clone()).collect::<Vec<_>>(),
            vec!["strong@example.com", "mid@example.com", "weak@example.com"],
            "must be strongest-first regardless of arrival order"
        );
    }

    #[tokio::test]
    async fn persist_entities_as_scan_makes_a_readable_complete_scan() {
        // The core contract every batch-persist path relies on: after this call
        // the store holds a Complete scan whose entities read back — so `hse
        // list`, views and exports all work. Under cfg(test) the store is rooted
        // in a temp dir (util::paths::huntsman_dir), so this touches no real
        // ~/.huntsman. That store is SHARED and persists across runs, so the sid
        // must be unique per run — otherwise a prior run's rows would mask a
        // regression (a broken persist would still "read back" stale data).
        use crate::core::scan::ScanStatus;

        let sid = format!(
            "test-persist-readable-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos())
        );
        let sid = sid.as_str();
        let entities = vec![
            Entity::new(EntityKind::Email, "subject@example.com", 0.9, sid),
            Entity::new(EntityKind::Person, "Test Subject", 0.9, sid),
        ];
        let label = strongest_identity_label(&entities, "batch");
        assert_eq!(label, "Test Subject", "label should be the person");

        let batch = persist_entities_as_scan(sid, label, TargetKind::FullName, &entities)
            .await
            .expect("persist should succeed against the temp store");
        assert!(batch.enriched, "a small batch must not be size-capped");
        assert_eq!(
            batch.finalise_error, None,
            "a store that keeps every write leaves no shortfall"
        );

        let store =
            crate::storage::Store::open(&crate::default_db_path()).expect("reopen the temp store");
        let scan = store
            .get_scan(sid)
            .expect("query the scan")
            .expect("the scan must have been persisted");
        assert_eq!(scan.status, ScanStatus::Complete);
        assert!(
            scan.finished_at.is_some(),
            "a Complete scan has a finish time"
        );
        assert_eq!(scan.error, None, "a whole import records no error");

        let stored = store.entities_for_scan(sid).expect("read entities back");
        assert!(
            stored.iter().any(|e| e.value == "subject@example.com"),
            "the persisted entities must read back from the store"
        );
        assert!(
            stored.iter().any(|e| e.value == "Test Subject"),
            "every entity in the batch must be persisted, not just the label"
        );
    }

    #[tokio::test]
    async fn persist_entities_as_scan_caps_enrichment_above_the_threshold() {
        // Regression: `persist_entities_as_scan` used to carry NO entity-count
        // cap on its O(n^2)-pairwise-within-same-key-bucket enrichment pass
        // (relation derivation + correlator), unlike the web upload handler's
        // pre-existing cap — a same-domain batch
        // above the cap hung for 60+ real seconds (see
        // `PERSIST_ENRICH_MAX_ENTITIES`'s own doc for the live reproduction).
        // The primary contract — every entity persisted — must hold regardless;
        // only the best-effort enrichment may be skipped. Same-domain values
        // mirror the exact adversarial shape (all rows sharing one email-domain
        // key bucket) that produced the original hang, so this test would time
        // out rather than merely fail if the cap regressed.
        let sid = format!(
            "test-persist-cap-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos())
        );
        let sid = sid.as_str();

        let count = PERSIST_ENRICH_MAX_ENTITIES + 1;
        let entities: Vec<Entity> = (0..count)
            .map(|i| {
                Entity::new(
                    EntityKind::Email,
                    format!("user{i}@one-domain.tld"),
                    0.9,
                    sid,
                )
            })
            .collect();

        let batch =
            persist_entities_as_scan(sid, "batch".to_string(), TargetKind::FullName, &entities)
                .await
                .expect("persist should succeed even when enrichment is capped");
        assert!(
            !batch.enriched,
            "a batch above PERSIST_ENRICH_MAX_ENTITIES must skip enrichment"
        );
        assert_eq!(
            batch.relations, 0,
            "capped enrichment reports zero relations"
        );
        assert_eq!(
            batch.correlations, 0,
            "capped enrichment reports zero correlations"
        );

        let store =
            crate::storage::Store::open(&crate::default_db_path()).expect("reopen the temp store");
        let stored = store.entities_for_scan(sid).expect("read entities back");
        assert_eq!(
            stored.len(),
            count,
            "every entity must still be persisted even when enrichment is skipped"
        );
    }

    /// REQ-SCANSTATUS-010: an import over the enrichment cap never runs its
    /// relation and correlation passes, and was written `Complete` with
    /// `error: None` — so every export read it whole, its CORRELATIONS (0) a
    /// correlator that found nothing rather than one that never ran. The skip
    /// is recorded on the scan, which then exports as partial.
    #[test]
    fn a_batch_over_the_enrichment_cap_is_stored_partial() {
        use crate::core::StoragePort as _;
        use crate::core::test_support::InMemoryStore;
        use std::sync::Arc;

        let sid = "persist-over-cap";
        let inner = Arc::new(InMemoryStore::new());
        let store: Arc<dyn crate::core::StoragePort> = inner.clone();
        let entities: Vec<Entity> = (0..=PERSIST_ENRICH_MAX_ENTITIES)
            .map(|i| {
                Entity::new(
                    EntityKind::Email,
                    format!("user{i}@one-domain.tld"),
                    0.9,
                    sid,
                )
            })
            .collect();
        let batch =
            persist_batch_into(&store, sid, "batch".into(), TargetKind::FullName, &entities)
                .expect("the import itself succeeds");
        assert!(!batch.enriched);
        let want = format!(
            "relation and correlation pass failed: skipped — {} entities exceed the \
             {PERSIST_ENRICH_MAX_ENTITIES}-entity import enrichment cap",
            PERSIST_ENRICH_MAX_ENTITIES + 1
        );
        assert_eq!(batch.finalise_error.as_deref(), Some(want.as_str()));
        let scan = inner
            .get_scan(sid)
            .expect("query the scan")
            .expect("the scan row exists");
        assert_eq!(scan.status, crate::core::scan::ScanStatus::Complete);
        assert_eq!(scan.error.as_deref(), Some(want.as_str()));
        assert!(
            scan.completeness_caveat("the import").is_some(),
            "a scan whose correlator never ran is not a complete answer"
        );
        // Control: at the cap the passes run and nothing is recorded.
        let mut tally = crate::core::scan::FinaliseTally::default();
        assert!(!skip_enrichment_over_cap(
            PERSIST_ENRICH_MAX_ENTITIES,
            &mut tally
        ));
        assert_eq!(tally.message(), None);
    }

    /// REQ-SCANSTATUS-013: an import's summary counts the batch it stored —
    /// after [`prepare_import_batch`] appended the Coordinates its addresses
    /// derive — and states an enrichment-cap skip once. Each CLI surface
    /// printed "Stored: … (N entities …)" and a "skipped — N entities exceeds
    /// the cap" note from its own pre-preparation count, beside the recorded
    /// skip that counts the prepared batch: a 5,000-row file whose address
    /// derived a fix stored 5,001 entities and read "5000 entities exceeds
    /// the 5000-entity cap" under "5001 entities exceed" — two counts for one
    /// skip, one of them false.
    #[test]
    fn an_import_summary_counts_the_batch_it_stored_and_states_a_skip_once() {
        use crate::core::entity::Evidence;
        use crate::core::test_support::InMemoryStore;
        use std::sync::Arc;

        let sid = "persist-summary";
        let mut entities: Vec<Entity> = (0..PERSIST_ENRICH_MAX_ENTITIES - 1)
            .map(|i| {
                Entity::new(
                    EntityKind::Email,
                    format!("user{i}@one-domain.tld"),
                    0.9,
                    sid,
                )
            })
            .collect();
        let mut addr = Entity::new(
            EntityKind::Address,
            "10 Smith St, Sydney NSW 2000",
            0.7,
            sid,
        );
        addr.add_evidence(Evidence::new("import:dossier", "breach record"));
        entities.push(addr);
        let parsed = entities.len();
        assert_eq!(parsed, PERSIST_ENRICH_MAX_ENTITIES, "fixture: at the cap");
        prepare_import_batch(&mut entities, sid);
        assert_eq!(entities.len(), parsed + 1, "fixture: one derived fix");

        let store: Arc<dyn crate::core::StoragePort> = Arc::new(InMemoryStore::new());
        let batch =
            persist_batch_into(&store, sid, "batch".into(), TargetKind::FullName, &entities)
                .expect("the import itself succeeds");
        assert_eq!(batch.entities, parsed + 1);
        assert!(!batch.enriched);

        let lines = batch.summary_lines(sid);
        assert_eq!(lines.len(), 2, "{lines:#?}");
        assert!(
            lines[0].contains(&format!("({} entities,", parsed + 1)),
            "{lines:#?}"
        );
        let cap_mentions = lines.iter().filter(|l| l.contains("cap")).count();
        assert_eq!(cap_mentions, 1, "the skip is stated once: {lines:#?}");
        assert!(
            lines
                .iter()
                .all(|l| !l.contains(&format!("{parsed} entities"))),
            "no line counts the batch before preparation: {lines:#?}"
        );

        // Control: a whole batch prints the stored line alone.
        let whole = PersistedBatch {
            entities: 2,
            relations: 1,
            correlations: 0,
            enriched: true,
            finalise_error: None,
        };
        assert_eq!(
            whole.summary_lines("s"),
            vec![
                "scan s (2 entities, 1 relations, 0 correlations) — view with `hse list`"
                    .to_string()
            ]
        );
    }

    /// A batch whose relations and correlations both derive — a username and
    /// the mailbox sharing its handle (`AliasOf`), the mailbox seen by three
    /// independent sources (AU-003).
    fn enrichable_batch(sid: &str) -> Vec<Entity> {
        use crate::core::entity::Evidence;
        let mut email = Entity::new(EntityKind::Email, "jsmith@gmail.com", 0.95, sid);
        for src in ["hibp", "dehashed", "search_engines"] {
            email.add_evidence(Evidence::new(src, "seen"));
        }
        let mut user = Entity::new(EntityKind::Username, "jsmith", 0.9, sid);
        user.add_evidence(Evidence::new("github_user", "profile"));
        vec![email, user]
    }

    /// Review of #649, second round: a correlator pass that failed outright on
    /// the import path (here, a refused read of the graph it evaluates) left
    /// the scan `Complete` with no error and no correlations. The failure is
    /// recorded on the scan and returned to the caller's summary.
    #[test]
    fn a_batch_whose_correlation_pass_fails_records_it() {
        use crate::core::StoragePort as _;
        use crate::core::test_support::{InMemoryStore, REFUSED_RELATION_READ, RefusingStore};
        use std::sync::Arc;

        let sid = "persist-pass-failed";
        let inner = Arc::new(InMemoryStore::new());
        let store: Arc<dyn crate::core::StoragePort> =
            Arc::new(RefusingStore::new(inner.clone()).refusing_relation_reads());
        let batch = persist_batch_into(
            &store,
            sid,
            "jsmith".into(),
            TargetKind::FullName,
            &enrichable_batch(sid),
        )
        .expect("the import itself still succeeds");
        assert_eq!(
            batch.finalise_error.as_deref(),
            Some(format!("correlation pass failed: {REFUSED_RELATION_READ}").as_str())
        );
        assert_eq!(batch.correlations, 0);
        let scan = inner
            .get_scan(sid)
            .expect("query the scan")
            .expect("the scan row exists");
        assert_eq!(scan.status, crate::core::scan::ScanStatus::Complete);
        assert_eq!(scan.error, batch.finalise_error);
    }

    /// Copilot review of #649: `hse import` / `hse ingest --auto-scan` counted
    /// relation and correlation writes with `.is_ok()` and dropped the error,
    /// then wrote the scan `Complete` with `error: None` — so a batch whose
    /// graph the store refused exported as a whole scan. The scan must stay
    /// `Complete` (the batch was imported in full) with the shortfall recorded
    /// on it and returned to the caller's summary.
    #[test]
    fn a_batch_whose_store_refuses_its_graph_records_the_shortfall() {
        use crate::core::StoragePort as _;
        use crate::core::scan::ScanStatus;
        use crate::core::test_support::{InMemoryStore, REFUSED_RELATION, RefusingStore};
        use std::sync::Arc;

        let sid = "persist-refused-graph";
        let entities = enrichable_batch(sid);

        // Control: a store that keeps every write — a whole scan.
        let whole_store: Arc<dyn crate::core::StoragePort> = Arc::new(InMemoryStore::new());
        let whole = persist_batch_into(
            &whole_store,
            sid,
            "jsmith".into(),
            TargetKind::FullName,
            &entities,
        )
        .expect("persist succeeds");
        assert_eq!(whole.finalise_error, None);
        assert!(whole.relations > 0 && whole.correlations > 0, "{whole:?}");

        let inner = Arc::new(InMemoryStore::new());
        let store: Arc<dyn crate::core::StoragePort> = Arc::new(
            RefusingStore::new(inner.clone())
                .refusing_relations()
                .refusing_correlations(),
        );
        let batch = persist_batch_into(
            &store,
            sid,
            "jsmith".into(),
            TargetKind::FullName,
            &entities,
        )
        .expect("the import itself still succeeds — every entity is stored");
        assert_eq!((batch.relations, batch.correlations), (0, 0));
        let err = batch
            .finalise_error
            .clone()
            .expect("the refused graph must be reported, not dropped");
        // Every derived edge counted; every firing counted (how many fire can
        // differ from the control, since the graph rules read the relations
        // this store refused — so only its shape is pinned); the first
        // refusal's error, which in finalise order is a relation's.
        let (rels, rest) = err
            .split_once(" relations, ")
            .expect("relations listed first");
        assert_eq!(rels, format!("{r}/{r}", r = whole.relations), "{err}");
        let (corr, tail) = rest
            .split_once(" correlations")
            .expect("correlations listed");
        let (failed, attempted) = corr.split_once('/').expect("n/m");
        assert!(failed == attempted && failed != "0", "{err}");
        assert_eq!(tail, format!(" failed to persist: {REFUSED_RELATION}"));

        let scan = inner
            .get_scan(sid)
            .expect("query the scan")
            .expect("the scan row exists");
        assert_eq!(scan.status, ScanStatus::Complete);
        assert_eq!(scan.error.as_deref(), Some(err.as_str()));
        assert_eq!(
            inner.entities_for_scan(sid).expect("read back").len(),
            entities.len(),
            "every entity is still stored"
        );
    }
}
