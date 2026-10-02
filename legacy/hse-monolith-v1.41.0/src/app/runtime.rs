//! Shared application runtime construction.

use std::sync::Arc;

use crate::{
    core::{
        engine::ScanEngine,
        error::{Error, Result},
        event::EventBus,
        port::{EVENTS_MAX_ROWS, EVENTS_RETENTION_SECS, MODULE_RESULT_CACHE_MAX_ROWS, StoragePort},
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
    let _ = db.prune_module_result_cache(MODULE_RESULT_CACHE_MAX_ROWS);
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

/// The operator-facing caveat [`resolve_scan_id`] should print for a scan
/// being read for offline analysis (`benchmark`, `export`, `audit`, `gap`,
/// `diff`) — or `None` when the scan needs no caveat at all.
///
/// A thin adapter over [`Scan::completeness_caveat`](crate::core::scan::Scan::completeness_caveat),
/// which is the single source for this wording across every read path. It used
/// to key off [`ScanStatus`](crate::core::scan::ScanStatus) alone, which meant
/// it could not see the one case a status cannot express: a scan that reached
/// `Complete` with its expansion cut short by a budget. Taking the whole `Scan`
/// lets that case be disclosed too — see
/// [`StopReason`](crate::core::scan::StopReason).
#[must_use]
fn scan_incompleteness_warning(scan: &crate::core::scan::Scan, raw: &str) -> Option<String> {
    scan.completeness_caveat(&format!("scan {raw}"))
        .map(|c| format!("⚠ {c}"))
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
        if let Some(warning) = scan_incompleteness_warning(&scan, "latest") {
            eprintln!("{warning}");
        }
        return Ok(scan.id);
    }

    match store.get_scan(raw)? {
        None => Err(Error::Other(format!("scan {raw} not found"))),
        Some(scan) => {
            if let Some(warning) = scan_incompleteness_warning(&scan, raw) {
                eprintln!("{warning}");
            }
            Ok(raw.to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{ApplicationRuntime, scan_incompleteness_warning};
    use crate::core::scan::{Scan, ScanStatus, StopReason, Target, TargetKind};

    /// A terminal scan in `status`, with no expansion-stop reason recorded —
    /// i.e. exactly what every scan row written before `stop_reason` existed
    /// deserialises to.
    fn scan_with(status: ScanStatus) -> Scan {
        let mut s = Scan::new(
            "s1",
            Target {
                kind: TargetKind::Email,
                value: "a@b.test".into(),
            },
        );
        s.status = status;
        s
    }

    #[test]
    fn application_runtime_is_publicly_nameable() {
        fn accepts_runtime(_: Option<ApplicationRuntime>) {}
        accepts_runtime(None);
    }

    #[test]
    fn scan_incompleteness_warning_is_silent_for_a_complete_scan() {
        assert_eq!(
            scan_incompleteness_warning(&scan_with(ScanStatus::Complete), "s1"),
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
        let msg = scan_incompleteness_warning(&scan_with(ScanStatus::Aborted), "s1")
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
            let msg = scan_incompleteness_warning(&scan_with(status), "s1")
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

    #[test]
    fn a_budget_truncated_complete_scan_is_disclosed_not_reported_as_whole() {
        // The defect this pins: a scan cut off by `max_entities` /
        // `max_wall_time_secs` reaches ScanStatus::Complete like any other, so
        // keying the caveat off status alone reported it as a complete answer.
        // An analyst reading "complete" concludes the absent result does not
        // exist; the truth is only that the search stopped.
        for reason in [StopReason::MaxEntities(500), StopReason::MaxWallTime(60)] {
            let mut scan = scan_with(ScanStatus::Complete);
            scan.stop_reason = Some(reason);
            let msg = scan_incompleteness_warning(&scan, "s1")
                .unwrap_or_else(|| panic!("{reason:?} must be disclosed, not silent"));
            assert!(
                msg.contains("TRUNCATED"),
                "{reason:?} must be named as a truncation: {msg}"
            );
            assert!(
                msg.contains("not evidence"),
                "{reason:?} must warn that absence here is not evidence of absence: {msg}"
            );
            assert!(
                msg.contains(&reason.label()),
                "{reason:?} must name the budget that cut it short: {msg}"
            );
        }
    }

    #[test]
    fn a_benignly_stopped_complete_scan_stays_silent() {
        // The other half of the guarantee: exhausting the candidate frontier or
        // running every requested depth round is a COMPLETE answer, and must
        // not acquire a scary caveat. `None` (an old row, or a depth-0 scan
        // that ran no expansion) must stay silent too — never invent a warning
        // on no evidence.
        for reason in [
            None,
            Some(StopReason::NoMoreCandidates),
            Some(StopReason::DepthExhausted),
        ] {
            let mut scan = scan_with(ScanStatus::Complete);
            scan.stop_reason = reason;
            assert_eq!(
                scan_incompleteness_warning(&scan, "s1"),
                None,
                "{reason:?} is a complete answer and must not be caveated"
            );
        }
    }
}
