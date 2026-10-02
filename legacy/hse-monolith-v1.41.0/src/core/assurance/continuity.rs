//! BSI 200-4 business continuity — per-capability recovery objectives, and the
//! state each one has actually EARNED from recovery-test evidence.
//!
//! The control-level view (`HSE-200-4-BCM` in the control catalogue) says whether
//! recovery is tested at all. This concept is finer: it names every capability
//! whose loss matters, the faults in scope for it (the failure classification),
//! its objectives (MTPD, RTO, RPO), how it degrades, what the fallback is, how
//! it is recovered, and which executable tests prove that — so an untested
//! capability is a named, visible gap rather than something a green control
//! hides.
//!
//! Honesty rules, enforced in code:
//! - [`ContinuityState`] is derived: `Observed` needs a recorded runtime
//!   recovery, `Tested` needs at least one named recovery test, else
//!   `Untested`. Nothing here can be set green.
//! - Every named recovery test must exist as a real `fn` in the test sources —
//!   a unit test walks `src/` and `tests/` and fails when a name has rotted, so
//!   the catalogue can never cite a test that no longer runs.
//! - Objectives quote only bounds a test asserts (the store's `rto_secs` is the
//!   crash test's own `< 10 s`); an unasserted bound is `None`, never a guess.
//! - Untested capabilities sort first and are listed by name in the summary.

use serde::Serialize;

use super::Criticality;

/// The recovery point a capability guarantees after its in-scope faults.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RecoveryPoint {
    /// Everything committed before the fault survives; only the in-flight
    /// transaction is lost.
    LastCommit,
    /// Everything checkpointed before the fault survives (per event / entity).
    LastCheckpoint,
    /// The previously installed binary keeps running.
    PreviousBinary,
    /// Nothing to recover — a stateless dependency.
    NotApplicable,
}

impl RecoveryPoint {
    /// A short label for tables.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::LastCommit => "last commit",
            Self::LastCheckpoint => "last checkpoint",
            Self::PreviousBinary => "previous binary",
            Self::NotApplicable => "n/a",
        }
    }
}

/// How far a capability's recovery has been proven. Ordered worst-first so
/// gaps sort to the top of every view.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ContinuityState {
    /// Recovery is implemented or documented, but no test proves it.
    Untested,
    /// At least one executable recovery test proves it (A4-equivalent).
    Tested,
    /// A real runtime recovery has been recorded (A5-equivalent).
    Observed,
}

impl ContinuityState {
    /// The screaming-snake identifier (matches the serde output).
    #[must_use]
    pub fn id(self) -> &'static str {
        match self {
            Self::Untested => "UNTESTED",
            Self::Tested => "TESTED",
            Self::Observed => "OBSERVED",
        }
    }
}

/// A recorded runtime recovery — never synthesised from tests.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ObservedRecovery {
    /// Wall-clock seconds from fault to restored service.
    pub recovery_secs: u64,
    /// What was lost, in the operator's words (`none`, `last 3 s of events`).
    pub data_loss: String,
    /// Provenance: the runtime event or incident record that captured it.
    pub source: String,
    /// Unix seconds when it was recorded.
    pub recorded_at: u64,
}

/// One capability's continuity objective and the evidence behind it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ContinuityObjective {
    /// Stable capability id, e.g. `persistence`.
    pub capability: &'static str,
    /// Human-readable name.
    pub name: &'static str,
    /// The assurance control this objective belongs to.
    pub control_id: &'static str,
    /// Operational criticality of the capability.
    pub criticality: Criticality,
    /// The fault modes in scope — the failure classification.
    pub faults: &'static [&'static str],
    /// Maximum tolerable period of disruption, in seconds (`None` = not objectified).
    pub mtpd_secs: Option<u64>,
    /// Recovery time objective, in seconds — quoted only when a test asserts it.
    pub rto_secs: Option<u64>,
    /// Recovery point objective.
    pub rpo: RecoveryPoint,
    /// How the capability behaves while degraded.
    pub degraded_mode: &'static str,
    /// The fallback path while degraded.
    pub fallback: &'static str,
    /// The recovery procedure (automatic or operator-driven).
    pub recovery_procedure: &'static str,
    /// Names of the executable tests that prove recovery — each must exist.
    pub recovery_tests: &'static [&'static str],
    /// A recorded runtime recovery, when one exists.
    pub observed: Option<ObservedRecovery>,
}

impl ContinuityObjective {
    /// The state this objective has earned from its evidence.
    #[must_use]
    pub fn state(&self) -> ContinuityState {
        if self.observed.is_some() {
            ContinuityState::Observed
        } else if self.recovery_tests.is_empty() {
            ContinuityState::Untested
        } else {
            ContinuityState::Tested
        }
    }
}

/// An objective together with its derived state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ContinuityAssessment {
    /// The objective.
    pub objective: ContinuityObjective,
    /// Its derived state.
    pub state: ContinuityState,
}

/// Raw counts over an assessment, plus the untested capabilities by name so a
/// gap is never just a number.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ContinuitySummary {
    /// Capabilities assessed.
    pub total: usize,
    /// Capabilities with no recovery test.
    pub untested: usize,
    /// Capabilities proven by at least one test.
    pub tested: usize,
    /// Capabilities with a recorded runtime recovery.
    pub observed: usize,
    /// The untested capabilities' ids, worst-first.
    pub untested_capabilities: Vec<&'static str>,
}

/// The control every continuity objective belongs to.
const CONTROL: &str = "HSE-200-4-BCM";

/// The continuity objectives HSE declares — one per capability whose loss
/// matters. Recovery tests named here are real test functions; a unit test
/// proves each one still exists.
#[must_use]
pub fn objectives() -> Vec<ContinuityObjective> {
    vec![
        ContinuityObjective {
            capability: "persistence",
            name: "SQLite WAL store (scans, entities, correlations, events)",
            control_id: CONTROL,
            criticality: Criticality::Critical,
            faults: &[
                "process death mid-write",
                "disk full (SQLITE_FULL)",
                "database corruption",
                "WAL checkpoint blocked by a reader",
                "scan not finalised (partial persistence)",
            ],
            mtpd_secs: Some(3600),
            // The crash test asserts reopen-with-recovery completes in < 10 s.
            rto_secs: Some(10),
            rpo: RecoveryPoint::LastCommit,
            degraded_mode: "Reads continue; a write that hits the growth cap or a \
                            corrupt page returns an explicit error, never a silent \
                            partial row.",
            fallback: "Free space or raise HSE_SQLITE_MAX_PAGES; a blocked \
                       checkpoint is reported, not claimed.",
            recovery_procedure: "Restart the process — WAL recovery replays to the \
                                 last commit automatically; run `hse doctor` for \
                                 the integrity check.",
            recovery_tests: &[
                "a_crash_mid_write_recovers_to_the_last_commit_on_reopen",
                "writes_fail_loudly_at_the_page_cap_keep_committed_data_and_recover_when_raised",
                "integrity_check_reports_problems_on_a_corrupted_db",
                "entities_for_scan_recovers_from_event_log_when_not_finalised",
                "checkpoint_truncate_reports_a_blocked_checkpoint_instead_of_claiming_success",
            ],
            observed: None,
        },
        ContinuityObjective {
            capability: "scan_engine",
            name: "Scan engine (module isolation, checkpointing)",
            control_id: CONTROL,
            criticality: Criticality::Critical,
            faults: &[
                "module panic",
                "process death mid-scan",
                "task leak when an owner unwinds",
            ],
            mtpd_secs: None,
            rto_secs: None,
            rpo: RecoveryPoint::LastCheckpoint,
            degraded_mode: "A panicking module is contained as that module's error; \
                            the scan continues on every other module.",
            fallback: "Re-run the scan; partial results stay readable, marked \
                       not-finalised rather than presented as complete.",
            recovery_procedure: "`scan_rerun` (API) or re-issue the scan; \
                                 checkpointed entities are recovered from the event log.",
            recovery_tests: &[
                "module_panic_is_contained_as_error_not_process_abort",
                "a_watchdog_guard_aborts_its_task_when_its_owner_unwinds",
                "entities_for_scan_recovers_from_event_log_when_not_finalised",
            ],
            observed: None,
        },
        ContinuityObjective {
            capability: "server",
            name: "HTTP server + Web UI (`hse serve`)",
            control_id: CONTROL,
            criticality: Criticality::Important,
            faults: &["process restart", "update requested while restarting"],
            mtpd_secs: None,
            rto_secs: None,
            rpo: RecoveryPoint::LastCommit,
            degraded_mode: "While an update restart is in flight, further update \
                            requests are rejected instead of racing it.",
            fallback: "Restart `hse serve`; every setting, scan and upload lives in \
                       the store, so nothing is held only in process memory.",
            recovery_procedure: "Restart the process (the installer's wrapper does \
                                 this after an update).",
            recovery_tests: &[
                "try_start_update_rejects_while_restarting",
                "settings_toggles_put_succeeds_and_persists_the_flip",
            ],
            observed: None,
        },
        ContinuityObjective {
            capability: "self_update",
            name: "Self-update (install.sh with restore-previous)",
            control_id: CONTROL,
            criticality: Criticality::Important,
            faults: &[
                "installed binary fails verification",
                "download interrupted",
                "wrong commit served for the requested version",
            ],
            mtpd_secs: None,
            rto_secs: None,
            rpo: RecoveryPoint::PreviousBinary,
            degraded_mode: "The previously installed binary keeps serving.",
            fallback: "install.sh restores the previous binary when the newly \
                       installed one fails verification; HSE_REQUIRE_SHA pins the \
                       exact commit so a stale prebuilt is refused.",
            recovery_procedure: "Re-run `hse update`; pin with HSE_REQUIRE_SHA.",
            // Proven by the install.sh rollback tests (tests/install_invariants.rs):
            // a failed post-install verification restores the previous binary,
            // and a verified install is NOT spuriously rolled back.
            recovery_tests: &[
                "rollback_restores_the_previous_binary_when_verification_fails",
                "a_verified_install_keeps_the_new_binary_and_drops_the_rollback_copy",
            ],
            observed: None,
        },
        ContinuityObjective {
            capability: "providers",
            name: "External providers (network, HTTP 403/429/5xx, timeouts, drift)",
            control_id: CONTROL,
            criticality: Criticality::Important,
            faults: &[
                "network loss",
                "provider HTTP 403/429/5xx",
                "provider timeout",
                "wire-format drift",
            ],
            mtpd_secs: None,
            rto_secs: None,
            rpo: RecoveryPoint::NotApplicable,
            degraded_mode: "A failing provider is an explicit module error — never a \
                            false clean — and the scan continues on the others.",
            fallback: "Substitute providers per capability (several keyless \
                       alternatives beside each keyed one); the curl transport as \
                       a second path.",
            recovery_procedure: "Next scan; `hse doctor --live` / the live drift \
                                 sweep classifies alive / empty / unreachable / drifted.",
            recovery_tests: &[
                "module_panic_is_contained_as_error_not_process_abort",
                "fleet_capability_drift",
            ],
            observed: None,
        },
        ContinuityObjective {
            capability: "ble_radar",
            name: "BLE radar (scan interruption, partial observations)",
            control_id: CONTROL,
            criticality: Criticality::Routine,
            faults: &[
                "scan interrupted mid-sweep",
                "partial observation persistence",
                "sensor tool unavailable",
            ],
            mtpd_secs: None,
            rto_secs: None,
            // A sweep is persisted as one transaction, so an interrupted sweep
            // recovers to the last COMMITTED sweep: everything committed before
            // the fault survives; only the in-flight sweep is lost, and lost
            // whole.
            rpo: RecoveryPoint::LastCommit,
            degraded_mode: "A missing or broken sensor tool is reported as such, not \
                            as an empty sky.",
            fallback: "A sweep is atomic: an interrupted one is discarded whole and \
                       every committed sweep survives, so re-running it cannot \
                       double-count or corrupt the sighting history.",
            recovery_procedure: "Re-run `hse radar`; committed sightings persist \
                                 across restart.",
            recovery_tests: &[
                "an_interrupted_radar_sweep_is_atomic_and_earlier_sweeps_survive",
                "committed_sightings_survive_a_store_restart",
            ],
            observed: None,
        },
    ]
}

/// Assess every objective: its derived state, ordered worst-first — `Untested`
/// before `Tested` before `Observed`, and within a state the most critical
/// capability first, then by id for a stable order.
#[must_use]
pub fn assess() -> Vec<ContinuityAssessment> {
    let mut out: Vec<ContinuityAssessment> = objectives()
        .into_iter()
        .map(|objective| ContinuityAssessment {
            state: objective.state(),
            objective,
        })
        .collect();
    out.sort_by(|a, b| {
        a.state
            .cmp(&b.state)
            .then_with(|| b.objective.criticality.cmp(&a.objective.criticality))
            .then_with(|| a.objective.capability.cmp(b.objective.capability))
    });
    out
}

/// Summarise an assessment into raw counts and the named untested gaps.
#[must_use]
pub fn summarise(assessed: &[ContinuityAssessment]) -> ContinuitySummary {
    let mut s = ContinuitySummary {
        total: assessed.len(),
        ..ContinuitySummary::default()
    };
    for a in assessed {
        match a.state {
            ContinuityState::Untested => {
                s.untested += 1;
                s.untested_capabilities.push(a.objective.capability);
            }
            ContinuityState::Tested => s.tested += 1,
            ContinuityState::Observed => s.observed += 1,
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tested_objective() -> ContinuityObjective {
        objectives()
            .into_iter()
            .find(|o| !o.recovery_tests.is_empty())
            .expect("a tested objective exists")
    }

    #[test]
    fn state_is_derived_from_evidence_never_asserted() {
        let tested = tested_objective();
        assert_eq!(tested.state(), ContinuityState::Tested);

        let mut untested = tested.clone();
        untested.recovery_tests = &[];
        assert_eq!(untested.state(), ContinuityState::Untested);

        let mut observed = tested.clone();
        observed.observed = Some(ObservedRecovery {
            recovery_secs: 4,
            data_loss: "none".into(),
            source: "incident-42".into(),
            recorded_at: 1,
        });
        assert_eq!(observed.state(), ContinuityState::Observed);
    }

    #[test]
    fn observed_requires_a_runtime_record_not_tests() {
        // Tests alone can never earn OBSERVED — TEST PASS != RUNTIME PROOF.
        let t = tested_objective();
        assert!(t.observed.is_none());
        assert!(t.state() < ContinuityState::Observed);
    }

    #[test]
    fn no_objective_claims_an_observed_recovery_yet() {
        // Honest baseline: no production runtime recovery has been recorded.
        assert!(objectives().iter().all(|o| o.observed.is_none()));
        assert_eq!(summarise(&assess()).observed, 0);
    }

    #[test]
    fn untested_capabilities_sort_first_and_are_named_in_the_summary() {
        let assessed = assess();
        let s = summarise(&assessed);
        assert_eq!(s.total, objectives().len());
        assert_eq!(s.untested + s.tested + s.observed, s.total);
        // Worst-first ordering: every Untested precedes every Tested.
        let first_tested = assessed
            .iter()
            .position(|a| a.state == ContinuityState::Tested)
            .unwrap_or(assessed.len());
        assert!(
            assessed[..first_tested]
                .iter()
                .all(|a| a.state == ContinuityState::Untested)
        );
        // The gaps are named, not just counted.
        assert_eq!(s.untested_capabilities.len(), s.untested);
        for cap in &s.untested_capabilities {
            assert!(assessed.iter().any(|a| a.objective.capability == *cap));
        }
    }

    #[test]
    fn catalogue_is_well_formed_and_quotes_no_unasserted_bound() {
        let objs = objectives();
        let mut ids: Vec<&str> = objs.iter().map(|o| o.capability).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), objs.len(), "capability ids must be unique");
        for o in &objs {
            assert_eq!(o.control_id, CONTROL);
            assert!(
                !o.faults.is_empty(),
                "{}: faults classify the scope",
                o.capability
            );
            assert!(!o.degraded_mode.trim().is_empty(), "{}", o.capability);
            assert!(!o.fallback.trim().is_empty(), "{}", o.capability);
            assert!(!o.recovery_procedure.trim().is_empty(), "{}", o.capability);
            // An RTO is a bound a test asserts; an untested capability cannot
            // honestly quote one.
            if o.recovery_tests.is_empty() {
                assert!(o.rto_secs.is_none(), "{}: unasserted RTO", o.capability);
            }
        }
    }

    /// Walk `dir` collecting every `.rs` source into `out`.
    fn read_rs_sources(dir: &std::path::Path, out: &mut String) {
        let Ok(rd) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in rd.flatten() {
            let p = entry.path();
            if p.is_dir() {
                read_rs_sources(&p, out);
            } else if p.extension().is_some_and(|x| x == "rs")
                && let Ok(s) = std::fs::read_to_string(&p)
            {
                out.push_str(&s);
                out.push('\n');
            }
        }
    }

    #[test]
    fn every_referenced_recovery_test_exists_in_the_sources() {
        // The evidence link is enforced: a renamed or deleted recovery test
        // fails here, so the catalogue can never cite a test that no longer runs.
        let mut corpus = String::new();
        read_rs_sources(std::path::Path::new("src"), &mut corpus);
        read_rs_sources(std::path::Path::new("tests"), &mut corpus);
        assert!(
            !corpus.is_empty(),
            "test sources must be readable from the crate root"
        );
        for o in objectives() {
            for name in o.recovery_tests {
                assert!(
                    corpus.contains(&format!("fn {name}(")),
                    "{}: recovery test `{name}` does not exist in src/ or tests/",
                    o.capability
                );
            }
        }
    }
}
