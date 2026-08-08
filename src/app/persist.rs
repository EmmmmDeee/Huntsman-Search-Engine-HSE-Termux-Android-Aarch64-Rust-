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

/// Persist `entities` as a `Complete` scan `sid` (labelled `label`, target kind
/// `kind`) in the default store, then derive the deterministic entity relations
/// and run the correlator over it — exactly as a live scan's finalise does, so a
/// batch-persisted scan carries the same graph a live scan would. The scan then
/// appears in `hse list` and every view/export (entities, dossier, debug bundle,
/// GEXF) works on it, and its pivots can later seed a re-scan.
///
/// Best-effort on relations and correlations: the entities are already
/// persisted, so a hiccup deriving the graph must not fail the whole operation.
/// Returns `(relations, correlations)` persisted, for the caller's summary.
pub(crate) async fn persist_entities_as_scan(
    sid: &str,
    label: String,
    kind: TargetKind,
    entities: &[Entity],
) -> Result<(usize, usize)> {
    use crate::core::StoragePort;
    use crate::core::entity::unix_now;
    use crate::core::scan::{Scan, ScanStatus, Target};
    use std::sync::Arc;

    // Offline geospatial enrichment, exactly as the live scan finalise does:
    // parse each Address, geohash/timezone/country-tag each Coordinates, and
    // derive Coordinates from any Address whose city resolves offline — so the
    // batch's addresses feed the geo-correlation stack (co-location, AU-014/017/
    // 032/056/057/085) instead of sitting inert. Deterministic, no network; runs
    // before relations/correlations so the derived fixes are persisted, related
    // and correlated in this same pass.
    let mut entities = entities.to_vec();
    crate::core::engine::enrich_offline_geo(&mut entities, sid);
    let entities = &entities[..];

    let store: Arc<dyn StoragePort> =
        Arc::new(crate::storage::Store::open(&crate::default_db_path())?);

    let mut scan = Scan::new(sid.to_string(), Target::new(kind, label));
    scan.status = ScanStatus::Complete;
    scan.finished_at = Some(unix_now());
    scan.entity_count = entities.len();
    store.upsert_scan(&scan)?;
    store.upsert_entities_batch(entities)?;

    let mut relations = 0usize;
    // Bound derivation by wall-clock, identically to a live scan
    // (engine::derive_and_persist_relations): a large batch must not run the
    // super-linear derivation pass chain for minutes. Partial relations persist.
    let derive_deadline = Some(std::time::Instant::now() + crate::core::relation::DERIVE_BUDGET);
    for r in &crate::core::relation::derive_all_within(entities, sid, derive_deadline) {
        if store.upsert_relation(r).is_ok() {
            relations += 1;
        }
    }

    // Run the full correlator under the canonical panic guard
    // (`guarded_correlation_pass`) — the single sanctioned way any caller invokes
    // the finalise-time rule engine. A rule panicking on adversarial batch data
    // (a crafted imported dossier, or entities extracted from an arbitrary
    // document via `ingest --auto-scan`) must degrade to "no correlations", not
    // unwind the whole persist after the entities were already stored and shown
    // to the operator.
    // `Correlator::run` persists every firing itself, so this counts them
    // rather than writing them a second time. The old loop re-upserted each
    // correlation after `run` had already stored it: on the real store that
    // second write is provably a no-op — its set-containment dedup skips a
    // member set equal to one already present — so it bought nothing and cost
    // an extra SQLite write transaction plus an extra full candidate-row scan
    // per correlation, on a flash-backed device, for a result already known.
    // The engine's finalise path never did this, so the two callers disagreed
    // about whose job persistence was; `run` owns it.
    let mut correlations = 0usize;
    let guard_store = Arc::clone(&store);
    if let Some(run) = crate::core::engine::guarded_correlation_pass(sid, move || {
        crate::core::correlator::Correlator::new(guard_store).run(sid)
    }) {
        correlations = run.firings.len();
        // A budget-truncated pass returns a strictly partial answer that is
        // shaped exactly like a complete one. The caller reports this count to
        // the operator, so it must not present a floor as a total.
        if let Some(note) = run.truncation_note() {
            eprintln!("warning: {note}");
        }
    }

    Ok((relations, correlations))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::entity::{Entity, EntityKind};

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

        let (_relations, _correlations) =
            persist_entities_as_scan(sid, label, TargetKind::FullName, &entities)
                .await
                .expect("persist should succeed against the temp store");

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
}
