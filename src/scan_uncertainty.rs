//! A derived, read-only register of observable scan uncertainties.
//!
//! No extra requests, persistent fields, estimated confidence, or invented absence claims.
//! Group repeated source failures by module/outcome, preserve observation counts and time
//! ranges, then list incomplete execution conditions separately from universal scope limits.

use std::collections::BTreeMap;

use serde::Serialize;

use crate::scan_store::{ScanRecord, ScanResults, ScanStatus};
use crate::source_outcome::{SourceExecutionOutcome, SourceOutcomeKind};
use crate::termination::TerminationReason;

/// Each item is a question or limitation, not a finding about the scan target.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UncertaintyItem {
    pub id: String,
    /// 1 is most urgent; priorities express remediation order, not confidence.
    pub priority: u8,
    pub category: &'static str,
    pub module: Option<String>,
    pub outcome: Option<SourceOutcomeKind>,
    pub observations: usize,
    pub first_observed_unix: Option<u64>,
    pub last_observed_unix: Option<u64>,
    pub evidence_path: &'static str,
    pub uncertainty: &'static str,
    pub next_action: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UncertaintyRegister {
    /// Source invocations recorded in the saved scan; not the theoretical source universe.
    pub recorded_executions: usize,
    pub unresolved_executions: usize,
    pub distinct_provider_issues: usize,
    /// Whether the output can demonstrate exhaustive discovery: it never can.
    pub discovery_completeness: &'static str,
    pub items: Vec<UncertaintyItem>,
}

fn provider_issue(
    kind: SourceOutcomeKind,
) -> Option<(u8, &'static str, &'static str, &'static str)> {
    use SourceOutcomeKind as K;
    let item = match kind {
        K::Success | K::ValidZero => return None,
        K::NotConfigured => (
            2,
            "credential_gap",
            "The source was skipped because no required credential was configured.",
            "Configure an operator-owned credential, then rerun this source.",
        ),
        K::AuthRequired => (
            2,
            "authentication_required",
            "The provider required authentication; a confirmed negative was not observed.",
            "Check the provider authentication requirements before retrying.",
        ),
        K::AuthRejected | K::EntitlementDenied => (
            2,
            "provider_access",
            "The provider did not grant usable access to the requested data.",
            "Verify the account entitlement and credential with the provider.",
        ),
        K::QuotaExhausted => (
            2,
            "provider_quota",
            "The provider quota prevented a conclusive response.",
            "Confirm available quota and retry only within an approved budget.",
        ),
        K::RateLimited => (
            2,
            "provider_rate_limit",
            "A rate limit prevented a conclusive response.",
            "Respect the provider retry interval before repeating the request.",
        ),
        K::BotWaf => (
            2,
            "provider_challenge",
            "A challenge page prevented a usable provider response.",
            "Inspect the official access method; do not treat a challenge as zero hits.",
        ),
        K::DnsFailure | K::ConnectFailure | K::TlsFailure | K::TtfbTimeout | K::BodyTimeout => (
            2,
            "transport_failure",
            "A transport failure left provider coverage unresolved.",
            "Verify connectivity and retry with bounded timeouts.",
        ),
        K::RefusedBeforeSending => (
            2,
            "refused_before_sending",
            "Huntsman's egress policy or request guard refused the request before it was sent; \
             the source was not asked.",
            "Check DNS filtering, a captive portal or proxy, or the credential's origin binding, \
             then rerun this source.",
        ),
        K::Upstream4xx | K::Upstream5xx => (
            2,
            "upstream_failure",
            "The upstream response was not verified as a confirmed negative.",
            "Check the response contract and provider availability before retrying.",
        ),
        K::RedirectChanged
        | K::ProtocolDrift
        | K::InteractionDrift
        | K::SchemaDrift
        | K::ParserDrift
        | K::SemanticDrift => (
            1,
            "provider_contract",
            "The provider contract or parsing interpretation may have changed.",
            "Revalidate the provider schema and add a reproducing parser test.",
        ),
        K::ZeroYieldAnomaly | K::Inconclusive => (
            1,
            "inconclusive_result",
            "The observation did not establish either a finding or a confirmed negative.",
            "Inspect the saved outcome and corroborate through another source.",
        ),
        K::ConfirmedDead => (
            1,
            "provider_unavailable",
            "The source is classified unavailable; this does not establish target absence.",
            "Check an independently maintained replacement or repair the source.",
        ),
    };
    Some(item)
}

fn general(
    id: &str,
    priority: u8,
    category: &'static str,
    evidence_path: &'static str,
    uncertainty: &'static str,
    next_action: &'static str,
) -> UncertaintyItem {
    UncertaintyItem {
        id: id.to_owned(),
        priority,
        category,
        module: None,
        outcome: None,
        observations: 0,
        first_observed_unix: None,
        last_observed_unix: None,
        evidence_path,
        uncertainty,
        next_action,
    }
}

fn termination_issue(reason: TerminationReason) -> Option<(&'static str, &'static str)> {
    use TerminationReason as T;
    match reason {
        T::FixedPoint => None,
        T::MaxDepth => Some((
            "The configured recursion depth stopped further expansion.",
            "Increase depth within the budget and compare the subsequent scan.",
        )),
        T::TimeLimit | T::RequestBudget | T::ProviderBudget | T::ResourceLimit => Some((
            "An execution limit stopped the scan with a potentially incomplete frontier.",
            "Inspect which limit stopped progress; rerun only with feasible bounds.",
        )),
        T::MarginalGainLimit => Some((
            "The marginal-gain threshold stopped expansion before exhaustive discovery.",
            "Review the gain threshold and unresolved candidate pivots.",
        )),
        T::Cancelled | T::FatalError => Some((
            "The scan stopped without establishing a complete run.",
            "Inspect the scan log and resume or rerun when the blocker is resolved.",
        )),
    }
}

fn grouped_provider_issues(outcomes: &[SourceExecutionOutcome]) -> (usize, Vec<UncertaintyItem>) {
    let mut unresolved_executions = 0;
    let mut groups: BTreeMap<(String, String), UncertaintyItem> = BTreeMap::new();
    for outcome in outcomes {
        let Some((priority, category, uncertainty, next_action)) = provider_issue(outcome.kind)
        else {
            continue;
        };
        unresolved_executions += 1;
        // The debug label is internal to the grouping key; the serialized outcome
        // retains the stable snake_case name supplied by SourceOutcomeKind.
        let key = (outcome.module.clone(), format!("{:?}", outcome.kind));
        let item = groups.entry(key).or_insert_with(|| UncertaintyItem {
            id: format!("provider:{}:{:?}", outcome.module, outcome.kind),
            priority,
            category,
            module: Some(outcome.module.clone()),
            outcome: Some(outcome.kind),
            observations: 0,
            first_observed_unix: None,
            last_observed_unix: None,
            evidence_path: "results.json#outcomes",
            uncertainty,
            next_action,
        });
        item.observations += 1;
        let time = outcome.observed_at_unix;
        item.first_observed_unix = Some(
            item.first_observed_unix
                .map_or(time, |prior| prior.min(time)),
        );
        item.last_observed_unix = Some(
            item.last_observed_unix
                .map_or(time, |prior| prior.max(time)),
        );
    }
    (unresolved_executions, groups.into_values().collect())
}

/// Derive the register solely from saved scan evidence. Never infer an unrecorded
/// source failure, an unobserved target, or an identity from the absence of findings.
#[must_use]
pub fn derive(record: &ScanRecord, results: Option<&ScanResults>) -> UncertaintyRegister {
    let mut items = Vec::new();
    let mut recorded_executions = 0;
    let mut unresolved_executions = 0;
    let mut distinct_provider_issues = 0;

    if record.status.is_active() {
        items.push(general(
            "scan:in_progress",
            2,
            "execution_state",
            "scan.json#status",
            "The scan is active and its recorded findings may still change.",
            "Wait for the recorded terminal state before treating the scan as completed.",
        ));
    } else if record.status != ScanStatus::Finished {
        items.push(general(
            "scan:incomplete",
            1,
            "execution_state",
            "scan.json#status",
            "The scan did not finish successfully; its collected evidence may be partial.",
            "Inspect the saved log and termination reason before a bounded rerun.",
        ));
    }

    if let Some(saved) = results {
        recorded_executions = saved.outcomes.len();
        let (unresolved_count, grouped) = grouped_provider_issues(&saved.outcomes);
        unresolved_executions = unresolved_count;
        distinct_provider_issues = grouped.len();
        items.extend(grouped);
        if saved.outcomes.is_empty() {
            items.push(general(
                "sources:no_recorded_executions",
                1,
                "missing_observations",
                "results.json#outcomes",
                "No provider executions are recorded. Source coverage is unknown, not zero.",
                "Inspect module selection, lookup status and scan logs.",
            ));
        }
        if let Some(reason) = saved.termination {
            if let Some((uncertainty, action)) = termination_issue(reason) {
                items.push(general(
                    &format!("scan:termination:{}", reason.as_str()),
                    2,
                    "frontier_limit",
                    "results.json#termination",
                    uncertainty,
                    action,
                ));
            }
        }
    } else {
        items.push(general(
            "scan:results_unavailable",
            1,
            "missing_observations",
            "results.json",
            "Saved results are unavailable; no conclusion about provider coverage follows.",
            "Check scan state and storage errors before drawing conclusions.",
        ));
    }

    items.push(general(
        "scope:exhaustiveness_unverified",
        3,
        "scope_limit",
        "scan.json#options",
        "Recorded sources do not establish exhaustive public-data coverage, source independence, or target absence.",
        "Identify excluded source families, corroborate material claims, and document acquisition limits.",
    ));
    items.sort_by(|left, right| {
        left.priority
            .cmp(&right.priority)
            .then_with(|| left.category.cmp(right.category))
            .then_with(|| left.id.cmp(&right.id))
    });
    UncertaintyRegister {
        recorded_executions,
        unresolved_executions,
        distinct_provider_issues,
        discovery_completeness: "unverified",
        items,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan_store::{FORMAT_VERSION, RiskCounts, ScanOptions, ScanStatus};
    use crate::source_outcome::SourceExecutionOutcome;

    fn record(status: ScanStatus) -> ScanRecord {
        ScanRecord {
            format_version: FORMAT_VERSION,
            id: "0123456789abcdef".into(),
            name: "example".into(),
            target: "example.com".into(),
            target_type: "INTERNET_NAME".into(),
            kind: "domain".into(),
            options: ScanOptions::default(),
            status,
            created: 0,
            started: None,
            ended: None,
            elements: 0,
            unique: 0,
            correlations: RiskCounts::default(),
            errors: 0,
            modules_run: Vec::new(),
            owner: None,
            owner_started: None,
        }
    }

    fn saved(outcomes: Vec<SourceExecutionOutcome>) -> ScanResults {
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
    fn groups_repeated_failures_without_erasing_observation_times_or_confirmed_zero() {
        let mut results = saved(vec![
            SourceExecutionOutcome::failed(
                "provider_a",
                11,
                SourceOutcomeKind::NotConfigured,
                None,
                "no key",
            ),
            SourceExecutionOutcome::failed(
                "provider_a",
                15,
                SourceOutcomeKind::NotConfigured,
                None,
                "still no key",
            ),
            SourceExecutionOutcome::valid_zero("provider_b", 12),
            SourceExecutionOutcome::success("provider_c", 14, 2),
            SourceExecutionOutcome::inconclusive("provider_d", 19, "unverified parse"),
        ]);
        let register = derive(&record(ScanStatus::Finished), Some(&results));
        assert_eq!(register.recorded_executions, 5);
        assert_eq!(register.unresolved_executions, 3);
        assert_eq!(register.distinct_provider_issues, 2);
        let first = register
            .items
            .iter()
            .find(|i| i.module.as_deref() == Some("provider_a"))
            .unwrap();
        assert_eq!(
            (
                first.observations,
                first.first_observed_unix,
                first.last_observed_unix
            ),
            (2, Some(11), Some(15))
        );
        assert!(
            register
                .items
                .iter()
                .all(|i| i.module.as_deref() != Some("provider_b"))
        );
        assert!(
            register
                .items
                .iter()
                .any(|i| i.id == "scope:exhaustiveness_unverified")
        );
        results.termination = Some(TerminationReason::RequestBudget);
        let bounded = derive(&record(ScanStatus::Finished), Some(&results));
        assert!(
            bounded
                .items
                .iter()
                .any(|i| i.id == "scan:termination:request_budget")
        );
    }

    #[test]
    fn a_refused_row_is_its_own_issue_and_not_a_transport_failure() {
        let results = saved(vec![
            SourceExecutionOutcome::refused_before_sending(
                "rdap",
                11,
                "network: egress-policy: destination (0.0.0.0) is not publicly routable",
            ),
            SourceExecutionOutcome::failed(
                "ripestat",
                12,
                SourceOutcomeKind::ConnectFailure,
                None,
                "no route",
            ),
        ]);
        let register = derive(&record(ScanStatus::Finished), Some(&results));
        assert_eq!(register.unresolved_executions, 2);
        let refused = register
            .items
            .iter()
            .find(|i| i.module.as_deref() == Some("rdap"))
            .expect("the refused row is an issue");
        assert_eq!(refused.category, "refused_before_sending");
        assert_eq!(
            refused.outcome,
            Some(SourceOutcomeKind::RefusedBeforeSending)
        );
        assert_eq!(refused.priority, 2);
        assert!(refused.uncertainty.ends_with("the source was not asked."));
        let silent = register
            .items
            .iter()
            .find(|i| i.module.as_deref() == Some("ripestat"))
            .expect("the transport failure is an issue");
        assert_eq!(silent.category, "transport_failure");
    }

    #[test]
    fn missing_results_and_active_scans_never_masquerade_as_negative_evidence() {
        let empty = derive(&record(ScanStatus::Running), None);
        assert_eq!(empty.recorded_executions, 0);
        assert_eq!(empty.discovery_completeness, "unverified");
        assert!(empty.items.iter().any(|i| i.id == "scan:in_progress"));
        assert!(
            empty
                .items
                .iter()
                .any(|i| i.id == "scan:results_unavailable")
        );
        let no_outcomes = derive(&record(ScanStatus::Finished), Some(&saved(Vec::new())));
        assert!(
            no_outcomes
                .items
                .iter()
                .any(|i| i.id == "sources:no_recorded_executions")
        );
        assert!(
            !no_outcomes
                .items
                .iter()
                .any(|i| i.id == "scan:results_unavailable")
        );
    }
}
