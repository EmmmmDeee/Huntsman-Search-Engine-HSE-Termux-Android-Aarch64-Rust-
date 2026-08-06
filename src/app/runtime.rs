//! Shared application runtime construction.

use std::sync::Arc;

use crate::{
    core::{
        engine::ScanEngine,
        error::{Error, Result},
        event::EventBus,
        port::{EVENTS_MAX_ROWS, EVENTS_RETENTION_SECS, RAW_ARCHIVE_MAX_ROWS, StoragePort},
    },
    default_db_path,
    modules::{module_runtime, registry},
    storage::Store,
};

/// Concrete application services shared by CLI commands and the HTTP server.
///
/// The store is exposed through [`StoragePort`]; SQLite remains a composition
/// detail owned by this module.
pub struct ApplicationRuntime {
    pub store: Arc<dyn StoragePort>,
    pub bus: EventBus,
    pub engine: Arc<ScanEngine>,
}

/// Open and maintain the store, create the event bus, and construct the scan
/// engine over the complete module registry.
pub fn build_runtime(bus_capacity: usize) -> Result<ApplicationRuntime> {
    let db = Store::open(&default_db_path())?;
    let _ = db.prune_events(EVENTS_RETENTION_SECS, EVENTS_MAX_ROWS);
    let _ = db.prune_raw_archive(RAW_ARCHIVE_MAX_ROWS);
    let store: Arc<dyn StoragePort> = Arc::new(db);
    let (bus, _rx) = tokio::sync::broadcast::channel(bus_capacity);
    let engine = Arc::new(ScanEngine::with_runtime_and_host(
        registry(),
        Arc::clone(&store),
        bus.clone(),
        module_runtime(),
        // The composition root is the one layer allowed to name both sides, so
        // the real egress pool and health policy are wired in here rather than
        // reached for from inside `core`.
        Arc::new(crate::util::engine_host::UtilEngineHost),
    ));
    Ok(ApplicationRuntime { store, bus, engine })
}

/// The operator-facing caveat [`resolve_scan_id`] should print for a
/// non-`Complete` scan being read for offline analysis (`benchmark`, `export`,
/// `audit`, `gap`, `diff`) — or `None` when the scan needs no caveat at all.
///
/// Pulled out as a pure function so the one real distinction it draws —
/// `Aborted` is not like the others — is unit-testable directly, without
/// capturing `stderr`.
///
/// [`ScanStatus::Aborted`](crate::core::scan::ScanStatus::Aborted)'s own doc
/// comment establishes that "entities + correlations produced before the
/// cancel are persisted as for a `Complete` scan" — an aborted scan has no
/// writer still racing this read and no more data ever arriving; what's on
/// disk for it is exactly as final as a `Complete` scan's, just shorter
/// because the operator chose to stop it. Bucketing it with `Failed` /
/// `Pending` / `Running` under one "may be incomplete, still recovering
/// partial/checkpointed data" message was wrong for that one case: those
/// three genuinely can still change (a crash-recovered partial write, a scan
/// that hasn't started, one actively being written to), but a completed
/// abort cannot.
#[must_use]
fn scan_incompleteness_warning(status: crate::core::scan::ScanStatus, raw: &str) -> Option<String> {
    use crate::core::scan::ScanStatus;
    match status {
        ScanStatus::Complete => None,
        ScanStatus::Aborted => Some(format!(
            "⚠ scan {raw} was stopped early by the operator (aborted) — entities from \
             modules that completed before the stop are final; no further data will \
             arrive for this scan"
        )),
        other => Some(format!(
            "⚠ scan {raw} is {status}, not complete — recovering its checkpointed \
             (partial) entities; results may be incomplete",
            status = other.as_str()
        )),
    }
}

/// Resolve `latest` or validate an explicit scan id for read-oriented use cases.
pub fn resolve_scan_id(store: &Store, raw: &str) -> Result<String> {
    if raw == "latest" {
        let scan = store
            .latest_finished_scan()?
            .ok_or_else(|| Error::Other("no finished scans in store".into()))?;
        // `latest` can now resolve to an aborted scan (its data is final —
        // see `latest_finished_scan`). Surface the same "stopped early, entities
        // are final" caveat the explicit-id path below prints, so resolving
        // `latest` never silently hands back partial-looking data without the
        // note. `Complete` yields no warning.
        if let Some(warning) = scan_incompleteness_warning(scan.status, "latest") {
            eprintln!("{warning}");
        }
        return Ok(scan.id);
    }

    match store.get_scan(raw)? {
        None => Err(Error::Other(format!("scan {raw} not found"))),
        Some(scan) => {
            if let Some(warning) = scan_incompleteness_warning(scan.status, raw) {
                eprintln!("{warning}");
            }
            Ok(raw.to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{ApplicationRuntime, scan_incompleteness_warning};
    use crate::core::scan::ScanStatus;

    #[test]
    fn application_runtime_is_publicly_nameable() {
        fn accepts_runtime(_: Option<ApplicationRuntime>) {}
        accepts_runtime(None);
    }

    #[test]
    fn scan_incompleteness_warning_is_silent_for_a_complete_scan() {
        assert_eq!(
            scan_incompleteness_warning(ScanStatus::Complete, "s1"),
            None
        );
    }

    #[test]
    fn scan_incompleteness_warning_tells_an_aborted_scan_its_data_is_final() {
        // The regression this pins: an aborted scan is NOT "may be
        // incomplete, still recovering partial data" — ScanStatus::Aborted's
        // own doc guarantees its persisted entities are as final as a
        // Complete scan's. The message must say so, and must NOT reuse the
        // generic "recovering checkpointed (partial) entities" framing that
        // fits Failed/Pending/Running but actively misleads for Aborted.
        let msg = scan_incompleteness_warning(ScanStatus::Aborted, "s1")
            .expect("an aborted scan still gets a caveat — it stopped early");
        assert!(
            msg.contains("stopped early") && msg.contains("final"),
            "aborted message must say the data is final, not partial: {msg}"
        );
        assert!(
            !msg.contains("may be incomplete") && !msg.contains("checkpointed"),
            "aborted message must not reuse the partial-recovery framing: {msg}"
        );
    }

    #[test]
    fn scan_incompleteness_warning_still_flags_genuinely_incomplete_states() {
        // Failed, Pending and Running are the states that genuinely may
        // still change (a crash-recovered partial write, a scan that hasn't
        // started, one actively being written to) — the pre-existing
        // "may be incomplete" framing is correct for exactly these three,
        // and must survive unchanged.
        for status in [ScanStatus::Failed, ScanStatus::Pending, ScanStatus::Running] {
            let msg = scan_incompleteness_warning(status, "s1")
                .unwrap_or_else(|| panic!("{status:?} must still produce a caveat"));
            assert!(
                msg.contains("may be incomplete") && msg.contains("checkpointed"),
                "{status:?} must keep the partial-recovery framing: {msg}"
            );
            assert!(
                msg.contains(status.as_str()),
                "{status:?} message must name the actual status: {msg}"
            );
        }
    }
}
