//! Provider coverage: what each provider actually did on a scan, derived from
//! the engine's own dispatch events — the bridge from what the engine DID to
//! what may be concluded from its silence. PROVIDER FAILURE ≠ ZERO EVIDENCE.
//!
//! This is the one part of the intelligence contracts the product exercises on
//! every scan. Live consumers: the CLI dossier appendix, `hse report
//! --benchmark`, the `/api/v1/scans/{id}/coverage` handler and `report.json`.
//! The staged claim ledger in [`crate::core::intelligence`] records these
//! outcomes per claim and is the only other reader.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// What a provider actually did about one claim.
///
/// PROVIDER FAILURE ≠ ZERO EVIDENCE. A claim with no supporting evidence looks
/// identical whether the provider was never asked, broke mid-query, or answered
/// cleanly that it holds nothing — and only the last of those is a negative.
/// Collapsing the three is the commonest way a system invents a confident clean
/// answer about a hard target: every source that would have spoken was silent
/// for a reason that had nothing to do with the subject.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ProviderOutcome {
    /// Queried successfully and produced evidence, inserted separately.
    Observed,
    /// Queried successfully; the provider holds nothing on this subject. The
    /// only outcome that is a real negative.
    CleanNegative,
    /// Never queried — budget, a missing credential, out of scope, or a
    /// circuit already open. Says nothing about the subject.
    NotAttempted {
        /// Why it was never queried, for the operator to act on.
        reason: String,
    },
    /// Queried, and the query failed — transport, quota, auth, schema drift.
    /// Says nothing about the subject either.
    Failed {
        /// Why the query failed, for the operator to act on.
        reason: String,
    },
}

impl ProviderOutcome {
    /// Whether this outcome settles what the provider had to say. Only a
    /// successful query does; an outage and an unasked question do not.
    #[must_use]
    pub fn is_resolved(&self) -> bool {
        matches!(self, Self::Observed | Self::CleanNegative)
    }

    /// Canonical wire spelling.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Observed => "observed",
            Self::CleanNegative => "clean_negative",
            Self::NotAttempted { .. } => "not_attempted",
            Self::Failed { .. } => "failed",
        }
    }

    /// The operator-facing reason an unresolved outcome carries.
    #[must_use]
    pub fn reason(&self) -> Option<&str> {
        match self {
            Self::NotAttempted { reason } | Self::Failed { reason } => Some(reason.as_str()),
            Self::Observed | Self::CleanNegative => None,
        }
    }
}

/// One provider's coverage of one scan, aggregated from the engine's own
/// dispatch events.
///
/// The counts are kept alongside the verdict because they are not recoverable
/// from it: a provider that answered on four targets and broke on a fifth has
/// the same [`ProviderOutcome`] as one that broke on its only attempt, and an
/// operator deciding whether to re-run needs to tell those apart.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderCoverage {
    /// The module this row is about.
    pub provider_id: String,
    /// The aggregate verdict — see [`provider_coverage_from_events`] for how
    /// several dispatches collapse into one.
    pub outcome: ProviderOutcome,
    /// Dispatches that completed, failed, or were skipped.
    pub dispatches: u32,
    /// Entities produced across all of them.
    pub findings: u32,
    /// Dispatches that failed.
    pub failures: u32,
    /// Dispatches that were never made.
    pub skips: u32,
    /// For an unresolved row, whether the provider was OUT OF SCOPE for this
    /// scan or genuinely UNAVAILABLE — see [`crate::core::event::SkipClass`].
    /// `None` on a resolved
    /// row, and on one whose only gaps came from events recorded before the
    /// class existed (treated as unavailable in the counts, since unknown is
    /// not harmless).
    pub skip_class: Option<crate::core::event::SkipClass>,
}

/// Aggregate a scan's provider coverage from its event log.
///
/// This is the bridge from what the engine DID to what may be concluded from
/// its silence. Each module's dispatches collapse to one verdict,
/// **failure-dominant**: any failed dispatch makes the row `Failed`, then any
/// skipped one makes it `NotAttempted`, and only a module whose every dispatch
/// completed can be `Observed` (it produced something) or `CleanNegative` (it
/// did not). A module that found five entities on one target and broke on
/// another is reported as failed, because the question this answers is not
/// "did it find anything" — the findings are in the report either way — but
/// "is this module's silence about the rest of the target set trustworthy".
/// It is not.
///
/// Rows are sorted by provider id, so the derivation is deterministic and safe
/// to embed in a byte-reproducible export.
#[must_use]
pub fn provider_coverage_from_events(
    events: &[crate::core::event::Event],
) -> Vec<ProviderCoverage> {
    use crate::core::event::EventKind;

    struct Tally {
        dispatches: u32,
        findings: u32,
        failures: u32,
        skips: u32,
        first_error: Option<String>,
        first_skip: Option<String>,
        /// True once any gap-bearing skip was NOT merely the operator's own
        /// narrowing — an unusable provider, or an event too old to say.
        unavailable: bool,
    }

    let mut tallies: BTreeMap<&str, Tally> = BTreeMap::new();
    for event in events {
        let (EventKind::ModuleDone { module, .. }
        | EventKind::ModuleError { module, .. }
        | EventKind::ModuleSkipped { module, .. }) = &event.kind
        else {
            continue;
        };
        // A skip is only a coverage gap when the provider still owes an answer.
        // A module the engine deduped because it already ran on this target, or
        // one that could never have spoken about a private IP, is not an outage
        // — counting either as unresolved reports a gap that never existed and
        // would mark almost every real scan incomplete. An event persisted
        // before the class was recorded is treated as a gap, because unknown is
        // not harmless.
        if let EventKind::ModuleSkipped { class, .. } = &event.kind
            && class.is_some_and(|c| !c.is_coverage_gap())
        {
            continue;
        }
        let module = module.as_str();
        let tally = tallies.entry(module).or_insert(Tally {
            dispatches: 0,
            findings: 0,
            failures: 0,
            skips: 0,
            first_error: None,
            first_skip: None,
            unavailable: false,
        });
        tally.dispatches = tally.dispatches.saturating_add(1);
        match &event.kind {
            EventKind::ModuleDone { found, .. } => {
                tally.findings = tally
                    .findings
                    .saturating_add(u32::try_from(*found).unwrap_or(u32::MAX));
            }
            EventKind::ModuleError { error, .. } => {
                tally.failures = tally.failures.saturating_add(1);
                if tally.first_error.is_none() {
                    tally.first_error = Some(error.clone());
                }
            }
            EventKind::ModuleSkipped { reason, class, .. } => {
                tally.skips = tally.skips.saturating_add(1);
                // An unclassified skip counts as unavailable: an old event
                // cannot vouch for itself, and under-reporting an unusable
                // provider is the failure that matters.
                tally.unavailable |= class != &Some(crate::core::event::SkipClass::Scoped);
                if tally.first_skip.is_none() {
                    tally.first_skip = Some(reason.clone());
                }
            }
            _ => unreachable!("filtered above"),
        }
    }

    tallies
        .into_iter()
        .map(|(provider_id, tally)| {
            // A reason is always present for the branch that reads it, but an
            // event carrying an empty string must not produce an outcome that
            // `record_provider` would then reject as unreasoned.
            let outcome = if tally.failures > 0 {
                ProviderOutcome::Failed {
                    reason: non_empty(tally.first_error, "module reported an error"),
                }
            } else if tally.skips > 0 {
                ProviderOutcome::NotAttempted {
                    reason: non_empty(tally.first_skip, "module was not dispatched"),
                }
            } else if tally.findings > 0 {
                ProviderOutcome::Observed
            } else {
                ProviderOutcome::CleanNegative
            };
            let skip_class = if outcome.is_resolved() {
                None
            } else if tally.failures > 0 || tally.unavailable {
                Some(crate::core::event::SkipClass::Unavailable)
            } else {
                Some(crate::core::event::SkipClass::Scoped)
            };
            ProviderCoverage {
                provider_id: provider_id.to_string(),
                outcome,
                dispatches: tally.dispatches,
                findings: tally.findings,
                failures: tally.failures,
                skips: tally.skips,
                skip_class,
            }
        })
        .collect()
}

/// Substitute `fallback` for a missing or blank reason.
fn non_empty(value: Option<String>, fallback: &str) -> String {
    value
        .filter(|text| !text.trim().is_empty())
        .unwrap_or_else(|| fallback.to_string())
}

/// How a scan's coverage broke down: what could not be used, and what the
/// operator's own scan options put out of reach.
///
/// The two must not be summed into one "incomplete" number. On a real scan the
/// operator narrows the sweep as a matter of course — an allowlist, a category
/// focus, `--free-only` — so dozens of providers are legitimately out of scope
/// every time. A single count mixing those with the three that actually broke
/// reads as alarming on every scan and is therefore read on none, burying the
/// failures it exists to surface.
///
/// Both axes still bear on what may be concluded: silence from an out-of-scope
/// provider is no more informative than silence from a broken one. Only the
/// ACTION differs — widen the scan, versus fix a credential or wait out a
/// quota — which is exactly why they are reported apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoverageVerdict {
    /// Providers with a coverage row.
    pub provider_count: usize,
    /// Providers that could not be used: a missing credential, an open circuit,
    /// a spent quota or cost budget, a capability quarantine, or an outright
    /// failure. The actionable gaps.
    pub unavailable_count: usize,
    /// Providers the scan's own options or the engine's budget policy put out
    /// of reach. Not a fault; still not a negative.
    pub out_of_scope_count: usize,
}

impl CoverageVerdict {
    /// Whether every provider that COULD have been used answered.
    ///
    /// True with a non-zero [`Self::out_of_scope_count`] means nothing broke —
    /// the sweep was simply narrower than the whole registry.
    #[must_use]
    pub fn all_available_providers_answered(self) -> bool {
        self.unavailable_count == 0
    }

    /// Whether every provider answered, with nothing out of scope and nothing
    /// unusable. Only here is a thin result unambiguously a real negative.
    #[must_use]
    pub fn is_exhaustive(self) -> bool {
        self.unavailable_count == 0 && self.out_of_scope_count == 0
    }
}

/// Split `rows` into the two coverage axes — see [`CoverageVerdict`].
#[must_use]
pub fn coverage_verdict(rows: &[ProviderCoverage]) -> CoverageVerdict {
    let mut verdict = CoverageVerdict {
        provider_count: rows.len(),
        unavailable_count: 0,
        out_of_scope_count: 0,
    };
    for row in rows {
        match row.skip_class {
            Some(crate::core::event::SkipClass::Scoped) => verdict.out_of_scope_count += 1,
            Some(_) => verdict.unavailable_count += 1,
            None => {}
        }
    }
    verdict
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::test_support::module_event;

    #[test]
    fn a_broken_provider_never_reads_as_a_clean_negative_in_coverage() {
        use crate::core::event::EventKind;
        let events = vec![
            module_event(EventKind::ModuleDone {
                module: "quiet".to_string(),
                found: 0,
            }),
            module_event(EventKind::ModuleError {
                module: "broken".to_string(),
                error: "upstream 502".to_string(),
            }),
            module_event(EventKind::ModuleSkipped {
                module: "unasked".to_string(),
                reason: "no credential configured".to_string(),
                class: Some(crate::core::event::SkipClass::Unavailable),
            }),
            module_event(EventKind::ModuleSkipped {
                module: "narrowed".to_string(),
                reason: "requires key/payment".to_string(),
                class: Some(crate::core::event::SkipClass::Scoped),
            }),
            module_event(EventKind::ModuleDone {
                module: "productive".to_string(),
                found: 3,
            }),
            // Not a dispatch outcome: it must not create a coverage row.
            module_event(EventKind::ExpansionStop {
                reason: "budget".to_string(),
            }),
        ];
        let rows = provider_coverage_from_events(&events);
        assert_eq!(
            rows.iter()
                .map(|row| row.provider_id.as_str())
                .collect::<Vec<_>>(),
            ["broken", "narrowed", "productive", "quiet", "unasked"],
            "rows are sorted by provider id, so the derivation is deterministic"
        );
        assert_eq!(
            rows[0].outcome,
            ProviderOutcome::Failed {
                reason: "upstream 502".to_string()
            }
        );
        assert_eq!(
            rows[1].outcome,
            ProviderOutcome::NotAttempted {
                reason: "requires key/payment".to_string()
            }
        );
        assert_eq!(rows[2].outcome, ProviderOutcome::Observed);
        assert_eq!(
            rows[3].outcome,
            ProviderOutcome::CleanNegative,
            "a module that completed and found nothing IS a real negative"
        );
        assert_eq!(
            rows[4].outcome,
            ProviderOutcome::NotAttempted {
                reason: "no credential configured".to_string()
            }
        );
        let verdict = coverage_verdict(&rows);
        assert!(
            !verdict.is_exhaustive(),
            "three providers never answered, so the scan's silence is not evidence of absence"
        );
        assert_eq!(verdict.provider_count, 5);
        assert_eq!(
            verdict.unavailable_count, 2,
            "`broken` failed and `unasked` has no credential — both are unusable, and a \
             missing credential is emphatically not the operator choosing to narrow the sweep"
        );
        assert_eq!(
            verdict.out_of_scope_count, 1,
            "only `narrowed` was ruled out by the scan's own options"
        );
        assert!(
            !verdict.all_available_providers_answered(),
            "a failed provider means something broke"
        );
        assert!(
            coverage_verdict(&rows[2..4]).is_exhaustive(),
            "the two providers that answered are, between them, an exhaustive sweep"
        );
    }

    #[test]
    fn a_dedup_or_inapplicable_skip_is_not_a_coverage_gap() {
        use crate::core::event::{EventKind, SkipClass};
        // The engine emits ModuleSkipped for four different situations, and only
        // two of them mean a provider still owes an answer. A module deduped
        // because it already ran on this target HAS answered; one that could
        // never have spoken about a private IP was never owed anything.
        // Counting either as unresolved reports an outage that never happened
        // and marks almost every real scan incomplete.
        let events = vec![
            module_event(EventKind::ModuleDone {
                module: "registry".to_string(),
                found: 2,
            }),
            module_event(EventKind::ModuleSkipped {
                module: "registry".to_string(),
                reason: "already dispatched for this target".to_string(),
                class: Some(SkipClass::AlreadyCovered),
            }),
            module_event(EventKind::ModuleSkipped {
                module: "shodan".to_string(),
                reason: "private/reserved IP — external API would reject".to_string(),
                class: Some(SkipClass::NotApplicable),
            }),
        ];
        let rows = provider_coverage_from_events(&events);
        assert_eq!(
            rows.len(),
            1,
            "an inapplicable provider earns no coverage row at all: {rows:?}"
        );
        assert_eq!(rows[0].provider_id, "registry");
        assert_eq!(
            rows[0].outcome,
            ProviderOutcome::Observed,
            "a provider that answered and was then deduped is not an outage"
        );
        assert_eq!(rows[0].skips, 0);
        assert!(coverage_verdict(&rows).is_exhaustive());
    }

    #[test]
    fn a_narrowed_sweep_is_reported_apart_from_a_broken_one() {
        use crate::core::event::{EventKind, SkipClass};
        // Every real scan narrows the sweep — an allowlist, a category focus,
        // --free-only — so dozens of providers are legitimately out of scope
        // each time. Summing those with the ones that actually broke gives an
        // alarming number on every scan, which is how a warning stops being
        // read and the three real failures get buried under forty ordinary
        // exclusions.
        let mut events = vec![module_event(EventKind::ModuleError {
            module: "broken".to_string(),
            error: "upstream 502".to_string(),
        })];
        for n in 0..40 {
            events.push(module_event(EventKind::ModuleSkipped {
                module: format!("scoped_{n:02}"),
                reason: "requires key/payment".to_string(),
                class: Some(SkipClass::Scoped),
            }));
        }
        for n in 0..2 {
            events.push(module_event(EventKind::ModuleSkipped {
                module: format!("unusable_{n}"),
                reason: "circuit-open".to_string(),
                class: Some(SkipClass::Unavailable),
            }));
        }
        let rows = provider_coverage_from_events(&events);
        let verdict = coverage_verdict(&rows);
        assert_eq!(verdict.provider_count, 43);
        assert_eq!(
            verdict.unavailable_count, 3,
            "one failure plus two unusable providers — what the operator can act on"
        );
        assert_eq!(
            verdict.out_of_scope_count, 40,
            "the operator's own narrowing, counted apart"
        );
        assert!(!verdict.all_available_providers_answered());
        assert!(!verdict.is_exhaustive());

        // Drop the three that broke and the sweep is merely narrow, not
        // degraded — and that distinction is the whole point.
        let narrowed: Vec<ProviderCoverage> = rows
            .into_iter()
            .filter(|row| row.skip_class != Some(SkipClass::Unavailable))
            .collect();
        let verdict = coverage_verdict(&narrowed);
        assert!(
            verdict.all_available_providers_answered(),
            "nothing broke, so nothing needs acting on"
        );
        assert!(
            !verdict.is_exhaustive(),
            "but silence from an out-of-scope provider is still not a negative"
        );
    }

    #[test]
    fn an_unclassified_skip_is_treated_as_a_gap() {
        use crate::core::event::{EventKind, SkipClass};
        // An event persisted before the class was recorded says nothing about
        // which kind of skip it was. Unknown is not harmless: assuming the
        // benign case would silently manufacture a clean sweep out of an old
        // event log.
        let unclassified =
            provider_coverage_from_events(&[module_event(EventKind::ModuleSkipped {
                module: "legacy".to_string(),
                reason: "no key".to_string(),
                class: None,
            })]);
        assert_eq!(unclassified.len(), 1);
        assert!(!unclassified[0].outcome.is_resolved());
        let verdict = coverage_verdict(&unclassified);
        assert_eq!(
            verdict.unavailable_count, 1,
            "an unclassified gap counts as unusable, not as the operator's own narrowing"
        );
        assert!(!verdict.all_available_providers_answered());

        // Both gap classes still report as gaps, with their reasons intact.
        for class in [SkipClass::Scoped, SkipClass::Unavailable] {
            assert!(class.is_coverage_gap(), "{class:?}");
            let rows = provider_coverage_from_events(&[module_event(EventKind::ModuleSkipped {
                module: "p".to_string(),
                reason: "because".to_string(),
                class: Some(class),
            })]);
            assert_eq!(
                rows[0].outcome,
                ProviderOutcome::NotAttempted {
                    reason: "because".to_string()
                },
                "{class:?}"
            );
        }
        for class in [SkipClass::NotApplicable, SkipClass::AlreadyCovered] {
            assert!(!class.is_coverage_gap(), "{class:?}");
        }
    }

    #[test]
    fn a_partial_outage_dominates_the_findings_it_sits_beside() {
        use crate::core::event::EventKind;
        let events = vec![
            module_event(EventKind::ModuleDone {
                module: "registry".to_string(),
                found: 5,
            }),
            module_event(EventKind::ModuleError {
                module: "registry".to_string(),
                error: "connection reset".to_string(),
            }),
            module_event(EventKind::ModuleSkipped {
                module: "registry".to_string(),
                reason: "quota spent".to_string(),
                class: Some(crate::core::event::SkipClass::Unavailable),
            }),
        ];
        let rows = provider_coverage_from_events(&events);
        assert_eq!(rows.len(), 1);
        assert_eq!(
            rows[0].outcome,
            ProviderOutcome::Failed {
                reason: "connection reset".to_string()
            },
            "finding something on one target says nothing about the targets it broke on"
        );
        assert_eq!(rows[0].dispatches, 3);
        assert_eq!(rows[0].findings, 5);
        assert_eq!(rows[0].failures, 1);
        assert_eq!(rows[0].skips, 1);
    }
}
