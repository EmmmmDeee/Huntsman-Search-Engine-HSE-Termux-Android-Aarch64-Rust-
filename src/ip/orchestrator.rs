//! Bounded, deterministic orchestration for IP-investigation providers.
//!
//! This layer schedules work. Providers continue to own request construction and
//! parsing, the guarded fetch boundary owns network execution, and claim aggregation
//! owns evidentiary truth. Ranking may change execution order but never claim state.

use std::cmp::Ordering;
use std::collections::BTreeSet;

use crate::evidence_ancestry::canonical_family;
use crate::http::Transport;
use crate::module::HistoricalDepthClass;

use super::claims::{apply_observations, independent_support_count};
use super::{
    IpActionRecord, IpCapability, IpClaimKind, IpClaimState, IpInvestigation, IpObservationKind,
    IpProvider, IpProviderAction, IpTarget, execute_provider_action,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpMode {
    Base,
    Deep,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpBudget {
    pub max_calls: u32,
    pub max_actions: u32,
    pub max_depth: u32,
}

impl Default for IpBudget {
    fn default() -> Self {
        Self {
            max_calls: 16,
            max_actions: 32,
            max_depth: 4,
        }
    }
}

struct PendingAction<'a> {
    provider: &'a dyn IpProvider,
    action: IpProviderAction,
    reliability: f64,
    historical_depth: u8,
    optionality: f64,
    request_cost: f64,
    root: String,
    depth: u32,
}

/// Execute one bounded IP investigation over an injected transport and provider set.
#[must_use]
pub fn run_investigation<T: Transport + ?Sized>(
    transport: &T,
    target: IpTarget,
    providers: &[&dyn IpProvider],
    mode: IpMode,
    budget: IpBudget,
    now_unix: u64,
) -> IpInvestigation {
    let mut investigation = IpInvestigation::new(target);
    if !investigation.target.is_public() {
        investigation.termination_reason = Some("non_public_target".into());
        return investigation;
    }

    let mut pending = plan_actions(&investigation, providers, mode);

    loop {
        let admissible = pending
            .iter()
            .enumerate()
            .filter(|(_, action)| action_has_positive_value(action, &investigation, mode))
            .map(|(index, _)| index)
            .collect::<Vec<_>>();

        if admissible.is_empty() {
            investigation.termination_reason = Some(
                match mode {
                    IpMode::Base => "base_complete",
                    IpMode::Deep => "fixed_point",
                }
                .into(),
            );
            break;
        }

        if investigation.budget_used.actions >= budget.max_actions {
            investigation.termination_reason = Some("action_budget".into());
            break;
        }
        if investigation.budget_used.calls >= budget.max_calls {
            investigation.termination_reason = Some("request_budget".into());
            break;
        }

        let within_depth = admissible
            .into_iter()
            .filter(|index| pending[*index].depth <= budget.max_depth)
            .collect::<Vec<_>>();
        if within_depth.is_empty() {
            investigation.termination_reason = Some("max_depth".into());
            break;
        }

        let next = select_next(&pending, &within_depth, &investigation);
        let work = pending.remove(next);
        investigation.actions_considered.push(IpActionRecord {
            provider_id: work.provider.id().into(),
            action_id: work.action.action_id.clone(),
            reason: action_reason(work.action.capability, &investigation),
            executed: true,
        });
        investigation.budget_used.actions += 1;
        investigation.budget_used.calls += 1;
        investigation.budget_used.max_depth_reached =
            investigation.budget_used.max_depth_reached.max(work.depth);

        let result = execute_provider_action(
            transport,
            work.provider,
            &work.action,
            now_unix.saturating_add(u64::from(investigation.budget_used.calls - 1)),
        );
        investigation.observations.extend(result.observations);
        investigation.failures.extend(result.failures);
        apply_observations(&mut investigation);
    }

    investigation
}

fn plan_actions<'a>(
    investigation: &IpInvestigation,
    providers: &[&'a dyn IpProvider],
    mode: IpMode,
) -> Vec<PendingAction<'a>> {
    let mut pending = Vec::new();
    for provider in providers {
        let descriptor = provider.descriptor();
        for action in provider.plan(&investigation.target) {
            if mode == IpMode::Base && !is_base_capability(action.capability) {
                continue;
            }
            let root = canonical_family(&action.lineage_family);
            if root.is_empty() {
                continue;
            }
            pending.push(PendingAction {
                provider: *provider,
                depth: capability_depth(action.capability),
                historical_depth: historical_depth_rank(
                    action.capability,
                    descriptor.historical_depth_class,
                ),
                action,
                reliability: sanitized_prior(descriptor.reliability_prior),
                optionality: sanitized_prior(descriptor.optionality_prior),
                request_cost: sanitized_cost(descriptor.cost_per_request),
                root,
            });
        }
    }

    pending.sort_by(|left, right| static_quality_cmp(right, left));
    let mut seen_roots = BTreeSet::new();
    pending.retain(|action| seen_roots.insert((action.root.clone(), action.action.capability)));
    pending
}

fn select_next(
    pending: &[PendingAction<'_>],
    admissible: &[usize],
    investigation: &IpInvestigation,
) -> usize {
    admissible
        .iter()
        .copied()
        .max_by(|left, right| dynamic_cmp(&pending[*left], &pending[*right], investigation))
        .unwrap_or(0)
}

fn dynamic_cmp(
    left: &PendingAction<'_>,
    right: &PendingAction<'_>,
    investigation: &IpInvestigation,
) -> Ordering {
    priority_class(left.action.capability, investigation)
        .cmp(&priority_class(right.action.capability, investigation))
        .then_with(|| static_quality_cmp(left, right))
}

fn static_quality_cmp(left: &PendingAction<'_>, right: &PendingAction<'_>) -> Ordering {
    left.reliability
        .total_cmp(&right.reliability)
        .then_with(|| left.historical_depth.cmp(&right.historical_depth))
        .then_with(|| left.optionality.total_cmp(&right.optionality))
        .then_with(|| right.request_cost.total_cmp(&left.request_cost))
        .then_with(|| right.provider.id().cmp(left.provider.id()))
        .then_with(|| right.action.action_id.cmp(&left.action.action_id))
}

fn action_has_positive_value(
    action: &PendingAction<'_>,
    investigation: &IpInvestigation,
    mode: IpMode,
) -> bool {
    if !evidence_unlocks(action.action.capability, investigation) {
        return false;
    }

    let kind = claim_kind(action.action.capability);
    let support_count = independent_support_count(investigation, kind);
    if mode == IpMode::Base {
        return support_count == 0;
    }

    let contradicted = investigation
        .claims
        .iter()
        .find(|claim| claim.kind == kind)
        .is_some_and(|claim| claim.state == IpClaimState::Contradicted);
    support_count < desired_independent_supports(action.action.capability, contradicted)
}

fn evidence_unlocks(capability: IpCapability, investigation: &IpInvestigation) -> bool {
    match capability {
        IpCapability::HistoricalDns | IpCapability::Certificate => investigation
            .observations
            .iter()
            .any(|observation| observation.kind == IpObservationKind::ReverseDns),
        _ => true,
    }
}

fn priority_class(capability: IpCapability, investigation: &IpInvestigation) -> u8 {
    let unresolved = claim_needs_resolution(claim_kind(capability), investigation);
    match (is_base_capability(capability), unresolved) {
        (true, true) => 3,
        (false, true) => 2,
        (true, false) => 1,
        (false, false) => 0,
    }
}

fn claim_needs_resolution(kind: IpClaimKind, investigation: &IpInvestigation) -> bool {
    !investigation
        .claims
        .iter()
        .any(|claim| claim.kind == kind && claim.state == IpClaimState::Supported)
}

const fn desired_independent_supports(capability: IpCapability, contradicted: bool) -> usize {
    if contradicted {
        return 3;
    }
    match capability {
        IpCapability::ReverseDns | IpCapability::Service => 1,
        IpCapability::Geolocation => 3,
        _ => 2,
    }
}

fn action_reason(capability: IpCapability, investigation: &IpInvestigation) -> String {
    if claim_needs_resolution(claim_kind(capability), investigation) {
        "resolve_missing_or_conflicted_claim".into()
    } else {
        "corroborate_existing_claim".into()
    }
}

const fn claim_kind(capability: IpCapability) -> IpClaimKind {
    match capability {
        IpCapability::Allocation => IpClaimKind::Allocation,
        IpCapability::Routing => IpClaimKind::Routing,
        IpCapability::ReverseDns => IpClaimKind::ReverseDns,
        IpCapability::HistoricalDns => IpClaimKind::HistoricalDns,
        IpCapability::Certificate => IpClaimKind::Certificate,
        IpCapability::Service => IpClaimKind::Service,
        IpCapability::Reputation => IpClaimKind::Reputation,
        IpCapability::Anonymization => IpClaimKind::Anonymization,
        IpCapability::Geolocation => IpClaimKind::Geolocation,
        IpCapability::InfrastructureClass => IpClaimKind::InfrastructureClass,
    }
}

const fn is_base_capability(capability: IpCapability) -> bool {
    matches!(
        capability,
        IpCapability::Allocation | IpCapability::Routing | IpCapability::ReverseDns
    )
}

const fn capability_depth(capability: IpCapability) -> u32 {
    match capability {
        IpCapability::HistoricalDns | IpCapability::Certificate => 1,
        _ => 0,
    }
}

const fn historical_depth_rank(capability: IpCapability, depth: HistoricalDepthClass) -> u8 {
    if !matches!(capability, IpCapability::HistoricalDns) {
        return 0;
    }
    match depth {
        HistoricalDepthClass::Live => 0,
        HistoricalDepthClass::RollingWindow => 1,
        HistoricalDepthClass::DeepArchive => 2,
    }
}

fn sanitized_prior(prior: f64) -> f64 {
    if prior.is_finite() {
        prior.clamp(0.0, 1.0)
    } else {
        0.0
    }
}

fn sanitized_cost(cost: Option<f64>) -> f64 {
    match cost {
        Some(value) if value.is_finite() && value >= 0.0 => value,
        _ => f64::INFINITY,
    }
}
