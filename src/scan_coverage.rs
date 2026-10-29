//! Read-only accounting of the six concrete people-lookup legs.
//!
//! Catalogue coverage is not global discovery completeness or proof of target absence.
//! Selection is reconstructed with the same module and use-case rules as scan execution.
//! No requests are sent and no saved scan data is changed.

use serde::Serialize;

use crate::module;
use crate::scan_store::{ScanRecord, ScanResults, ScanStatus};
use crate::source_outcome::SourceOutcomeKind;

/// Concrete provider executions that a people lookup can record, and the module
/// selection that gates each one, in execution order. ASIC people uses one parent
/// selector for three legs; `wikidata` runs beside the registers as a candidate lead.
const PEOPLE_LEGS: [(&str, &str); 6] = [
    ("asic_persons.banned", crate::asic_persons::SRC),
    ("asic_persons.advisers", crate::asic_persons::SRC),
    ("asic_persons.credit", crate::asic_persons::SRC),
    (crate::asic_director::SRC, crate::asic_director::SRC),
    (crate::wikidata::SOURCE, crate::wikidata::SOURCE),
    (
        crate::seeknow_collector::COLLECTOR_ID,
        crate::seeknow_collector::COLLECTOR_ID,
    ),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PeopleSourceStatus {
    Accepted,
    NotConfigured,
    Unresolved,
    NotObserved,
}

/// One *selected* concrete people source. An absent row is not a negative.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PeopleSourceRow {
    pub module: &'static str,
    pub status: PeopleSourceStatus,
    pub recorded_executions: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PeopleSourceCoverage {
    pub scope: &'static str,
    pub catalogued_sources: usize,
    pub selected_sources: usize,
    pub accepted_sources: usize,
    pub not_configured_sources: usize,
    pub unresolved_sources: usize,
    pub not_observed_sources: usize,
    pub excluded_sources: Vec<&'static str>,
    pub sources: Vec<PeopleSourceRow>,
    pub complete_within_catalogue: bool,
    pub discovery_completeness: &'static str,
}

/// Classify only known people sources; other scan kinds require their own concrete
/// leg-to-selector mappings before catalogue coverage can be asserted.
///
/// Returns `None` if this is not a people scan or the saved selection cannot be
/// reconstructed. That fails closed instead of fabricating an execution plan.
#[must_use]
pub fn derive(record: &ScanRecord, results: Option<&ScanResults>) -> Option<PeopleSourceCoverage> {
    if record.kind != "people" {
        return None;
    }
    let named = module::selection(&record.options.modules).ok()?;
    let usecase = if record.options.usecase.trim().is_empty() {
        "all"
    } else {
        record.options.usecase.as_str()
    };
    let selection = module::use_case_selection(usecase, &named);

    let mut sources = Vec::new();
    let mut excluded_sources = Vec::new();
    let mut accepted_sources = 0;
    let mut not_configured_sources = 0;
    let mut unresolved_sources = 0;
    let mut not_observed_sources = 0;
    for (leg, selector) in PEOPLE_LEGS {
        if !selection.runs(selector) {
            excluded_sources.push(leg);
            continue;
        }
        let matches: Vec<_> = results
            .into_iter()
            .flat_map(|saved| saved.outcomes.iter())
            .filter(|outcome| outcome.module == leg)
            .collect();
        // Multiple observations of the same leg can be about different pivots.
        // One accepted response must never suppress an unresolved execution.
        let status = if matches.is_empty() {
            PeopleSourceStatus::NotObserved
        } else if matches.iter().all(|outcome| outcome.kind.is_accepted()) {
            PeopleSourceStatus::Accepted
        } else if matches
            .iter()
            .all(|outcome| outcome.kind == SourceOutcomeKind::NotConfigured)
        {
            PeopleSourceStatus::NotConfigured
        } else {
            PeopleSourceStatus::Unresolved
        };
        match status {
            PeopleSourceStatus::Accepted => accepted_sources += 1,
            PeopleSourceStatus::NotConfigured => not_configured_sources += 1,
            PeopleSourceStatus::Unresolved => unresolved_sources += 1,
            PeopleSourceStatus::NotObserved => not_observed_sources += 1,
        }
        sources.push(PeopleSourceRow {
            module: leg,
            status,
            recorded_executions: matches.len(),
        });
    }

    let selected_sources = sources.len();
    Some(PeopleSourceCoverage {
        scope: "people_lookup_catalogue",
        catalogued_sources: PEOPLE_LEGS.len(),
        selected_sources,
        accepted_sources,
        not_configured_sources,
        unresolved_sources,
        not_observed_sources,
        excluded_sources,
        complete_within_catalogue: record.status == ScanStatus::Finished
            && results.is_some()
            && selected_sources > 0
            && accepted_sources == selected_sources,
        discovery_completeness: "unverified",
        sources,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan_store::{FORMAT_VERSION, RiskCounts, ScanOptions, ScanResults};
    use crate::source_outcome::SourceExecutionOutcome;
    use crate::termination::TerminationReason;

    fn record() -> ScanRecord {
        ScanRecord {
            format_version: FORMAT_VERSION,
            id: "0123456789abcdef".into(),
            name: "person".into(),
            target: "ada lovelace".into(),
            target_type: "HUMAN_NAME".into(),
            kind: "people".into(),
            options: ScanOptions {
                usecase: "all".into(),
                ..ScanOptions::default()
            },
            status: ScanStatus::Finished,
            created: 0,
            started: None,
            ended: None,
            elements: 1,
            unique: 1,
            correlations: RiskCounts::default(),
            errors: 0,
            modules_run: Vec::new(),
            owner: None,
            owner_started: None,
        }
    }

    fn results(outcomes: Vec<SourceExecutionOutcome>) -> ScanResults {
        ScanResults {
            format_version: FORMAT_VERSION,
            scan_id: "0123456789abcdef".into(),
            text: String::new(),
            entities: Vec::new(),
            outcomes,
            elements: Vec::new(),
            correlations: Vec::new(),
            lineage: Vec::new(),
            termination: Some(TerminationReason::FixedPoint),
        }
    }

    #[test]
    fn exported_six_leg_scan_has_partial_catalogue_coverage_even_at_fixed_point() {
        let observations = results(vec![
            SourceExecutionOutcome::valid_zero("asic_persons.banned", 1),
            SourceExecutionOutcome::valid_zero("asic_persons.advisers", 1),
            SourceExecutionOutcome::valid_zero("asic_persons.credit", 1),
            SourceExecutionOutcome::valid_zero("asic_director", 1),
            SourceExecutionOutcome::valid_zero("wikidata", 1),
            SourceExecutionOutcome::not_configured("seeknow", 1),
        ]);
        let coverage = derive(&record(), Some(&observations)).unwrap();
        assert_eq!(coverage.catalogued_sources, 6);
        assert_eq!(coverage.selected_sources, 6);
        assert_eq!(coverage.accepted_sources, 5);
        assert_eq!(coverage.not_configured_sources, 1);
        assert_eq!(coverage.not_observed_sources, 0);
        assert!(!coverage.complete_within_catalogue);
        assert_eq!(coverage.discovery_completeness, "unverified");
    }

    #[test]
    fn an_unrecorded_selected_leg_is_not_a_valid_zero() {
        let observations = results(vec![SourceExecutionOutcome::valid_zero("asic_director", 1)]);
        let coverage = derive(&record(), Some(&observations)).unwrap();
        assert_eq!(coverage.accepted_sources, 1);
        assert_eq!(coverage.not_observed_sources, 5);
        assert!(!coverage.complete_within_catalogue);
        assert_eq!(coverage.sources[0].status, PeopleSourceStatus::NotObserved);
    }

    #[test]
    fn module_selection_excludes_asic_children_when_the_parent_is_not_chosen() {
        let mut chosen = record();
        chosen.options.modules = vec!["asic_director".into()];
        let observations = results(vec![SourceExecutionOutcome::valid_zero("asic_director", 1)]);
        let coverage = derive(&chosen, Some(&observations)).unwrap();
        assert_eq!(coverage.selected_sources, 1);
        assert_eq!(coverage.accepted_sources, 1);
        assert_eq!(coverage.excluded_sources.len(), 5);
        assert!(coverage.complete_within_catalogue);
        assert_eq!(coverage.discovery_completeness, "unverified");
    }

    #[test]
    fn unresolved_retry_is_not_masked_by_an_accepted_response() {
        let observations = results(vec![
            SourceExecutionOutcome::valid_zero("asic_director", 1),
            SourceExecutionOutcome::inconclusive("asic_director", 2, "contract drift"),
        ]);
        let mut selected = record();
        selected.options.modules = vec!["asic_director".into()];
        let coverage = derive(&selected, Some(&observations)).unwrap();
        assert_eq!(coverage.unresolved_sources, 1);
        assert_eq!(coverage.sources[0].recorded_executions, 2);
        assert!(!coverage.complete_within_catalogue);
    }

    #[test]
    fn unfinished_or_missing_results_never_establish_catalogue_completion() {
        let observations = results(vec![SourceExecutionOutcome::valid_zero("asic_director", 1)]);
        let mut selected = record();
        selected.options.modules = vec!["asic_director".into()];
        selected.status = ScanStatus::Running;
        assert!(
            !derive(&selected, Some(&observations))
                .unwrap()
                .complete_within_catalogue
        );
        selected.status = ScanStatus::Finished;
        assert!(!derive(&selected, None).unwrap().complete_within_catalogue);
        selected.kind = "domain".into();
        assert!(derive(&selected, Some(&observations)).is_none());
        selected.kind = "people".into();
        selected.options.modules = vec!["unknown source".into()];
        assert!(derive(&selected, Some(&observations)).is_none());
    }
}
