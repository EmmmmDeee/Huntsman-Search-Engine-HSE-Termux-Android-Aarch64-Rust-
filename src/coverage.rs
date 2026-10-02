use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SkipClass {
    Scoped,
    Unavailable,
    NotApplicable,
    AlreadyCovered,
}

impl SkipClass {
    #[must_use]
    pub const fn is_coverage_gap(self) -> bool {
        matches!(self, Self::Scoped | Self::Unavailable)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Event {
    pub scan_id: String,
    pub ts: u64,
    pub kind: EventKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EventKind {
    ModuleDone {
        module: String,
        found: usize,
    },
    ModuleError {
        module: String,
        error: String,
    },
    ModuleSkipped {
        module: String,
        reason: String,
        class: Option<SkipClass>,
    },
    ExpansionStop {
        reason: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ProviderOutcome {
    Observed,
    CleanNegative,
    NotAttempted { reason: String },
    Failed { reason: String },
}

impl ProviderOutcome {
    #[must_use]
    pub fn is_resolved(&self) -> bool {
        matches!(self, Self::Observed | Self::CleanNegative)
    }

    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Observed => "observed",
            Self::CleanNegative => "clean_negative",
            Self::NotAttempted { .. } => "not_attempted",
            Self::Failed { .. } => "failed",
        }
    }

    #[must_use]
    pub fn reason(&self) -> Option<&str> {
        match self {
            Self::Observed | Self::CleanNegative => None,
            Self::NotAttempted { reason } | Self::Failed { reason } => Some(reason.as_str()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderCoverage {
    pub provider_id: String,
    pub outcome: ProviderOutcome,
    pub dispatches: u32,
    pub findings: u32,
    pub failures: u32,
    pub skips: u32,
    pub skip_class: Option<SkipClass>,
}

fn non_empty(value: Option<String>, fallback: &str) -> String {
    value
        .filter(|text| !text.trim().is_empty())
        .unwrap_or_else(|| fallback.to_owned())
}

#[must_use]
pub fn provider_coverage_from_events(events: &[Event]) -> Vec<ProviderCoverage> {
    struct Tally {
        dispatches: u32,
        findings: u32,
        failures: u32,
        skips: u32,
        first_error: Option<String>,
        first_skip: Option<String>,
        unavailable: bool,
    }

    let mut tallies: BTreeMap<&str, Tally> = BTreeMap::new();
    for event in events {
        let module = match &event.kind {
            EventKind::ModuleDone { module, .. }
            | EventKind::ModuleError { module, .. }
            | EventKind::ModuleSkipped { module, .. } => module.as_str(),
            EventKind::ExpansionStop { .. } => continue,
        };
        if let EventKind::ModuleSkipped {
            class: Some(class), ..
        } = &event.kind
        {
            if !class.is_coverage_gap() {
                continue;
            }
        }
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
                tally.unavailable |= *class != Some(SkipClass::Scoped);
                if tally.first_skip.is_none() {
                    tally.first_skip = Some(reason.clone());
                }
            }
            EventKind::ExpansionStop { .. } => {}
        }
    }

    tallies
        .into_iter()
        .map(|(provider_id, tally)| {
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
                Some(SkipClass::Unavailable)
            } else {
                Some(SkipClass::Scoped)
            };
            ProviderCoverage {
                provider_id: provider_id.to_owned(),
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoverageVerdict {
    pub provider_count: usize,
    pub unavailable_count: usize,
    pub out_of_scope_count: usize,
}

impl CoverageVerdict {
    #[must_use]
    pub const fn all_available_providers_answered(self) -> bool {
        self.unavailable_count == 0
    }

    #[must_use]
    pub const fn is_exhaustive(self) -> bool {
        self.unavailable_count == 0 && self.out_of_scope_count == 0
    }
}

#[must_use]
pub fn coverage_verdict(rows: &[ProviderCoverage]) -> CoverageVerdict {
    let mut verdict = CoverageVerdict {
        provider_count: rows.len(),
        unavailable_count: 0,
        out_of_scope_count: 0,
    };
    for row in rows {
        match row.skip_class {
            Some(SkipClass::Scoped) => verdict.out_of_scope_count += 1,
            Some(_) => verdict.unavailable_count += 1,
            None => {}
        }
    }
    verdict
}

#[cfg(test)]
mod tests {
    use super::*;

    fn module_event(kind: EventKind) -> Event {
        Event {
            scan_id: "scan".to_string(),
            ts: 0,
            kind,
        }
    }

    #[test]
    fn broken_and_scoped_providers_do_not_read_as_clean_negatives() {
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
                class: Some(SkipClass::Unavailable),
            }),
            module_event(EventKind::ModuleSkipped {
                module: "narrowed".to_string(),
                reason: "requires key/payment".to_string(),
                class: Some(SkipClass::Scoped),
            }),
            module_event(EventKind::ModuleDone {
                module: "productive".to_string(),
                found: 3,
            }),
            module_event(EventKind::ExpansionStop {
                reason: "budget".to_string(),
            }),
        ];
        let rows = provider_coverage_from_events(&events);
        assert_eq!(
            rows.iter()
                .map(|row| row.provider_id.as_str())
                .collect::<Vec<_>>(),
            ["broken", "narrowed", "productive", "quiet", "unasked"]
        );
        assert_eq!(
            rows[0].outcome,
            ProviderOutcome::Failed {
                reason: "upstream 502".to_string()
            }
        );
        assert_eq!(rows[2].outcome, ProviderOutcome::Observed);
        assert_eq!(rows[3].outcome, ProviderOutcome::CleanNegative);
        let verdict = coverage_verdict(&rows);
        assert_eq!(verdict.provider_count, 5);
        assert_eq!(verdict.unavailable_count, 2);
        assert_eq!(verdict.out_of_scope_count, 1);
        assert!(!verdict.all_available_providers_answered());
        assert!(!verdict.is_exhaustive());
    }

    #[test]
    fn dedup_and_not_applicable_skips_do_not_create_rows() {
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
                reason: "private/reserved ip".to_string(),
                class: Some(SkipClass::NotApplicable),
            }),
        ];
        let rows = provider_coverage_from_events(&events);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].provider_id, "registry");
        assert_eq!(rows[0].outcome, ProviderOutcome::Observed);
        assert_eq!(rows[0].skips, 0);
        assert!(coverage_verdict(&rows).is_exhaustive());
    }

    #[test]
    fn unclassified_skip_fails_closed() {
        let rows = provider_coverage_from_events(&[module_event(EventKind::ModuleSkipped {
            module: "legacy".to_string(),
            reason: "no key".to_string(),
            class: None,
        })]);
        assert_eq!(rows.len(), 1);
        assert!(!rows[0].outcome.is_resolved());
        let verdict = coverage_verdict(&rows);
        assert_eq!(verdict.unavailable_count, 1);
        assert!(!verdict.all_available_providers_answered());
    }

    #[test]
    fn partial_outage_dominates_successes_beside_it() {
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
                class: Some(SkipClass::Unavailable),
            }),
        ];
        let rows = provider_coverage_from_events(&events);
        assert_eq!(rows.len(), 1);
        assert_eq!(
            rows[0].outcome,
            ProviderOutcome::Failed {
                reason: "connection reset".to_string()
            }
        );
        assert_eq!(rows[0].dispatches, 3);
        assert_eq!(rows[0].findings, 5);
        assert_eq!(rows[0].failures, 1);
        assert_eq!(rows[0].skips, 1);
    }
}
