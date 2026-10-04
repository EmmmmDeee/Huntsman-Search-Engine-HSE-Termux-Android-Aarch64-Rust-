//! Bounded, deterministic orchestration for IP-investigation providers.
//!
//! This layer schedules work. Providers continue to own request construction and
//! parsing, the guarded fetch boundary owns network execution, and claim aggregation
//! owns evidentiary truth. Ranking may change execution order but never claim state.

use std::collections::BTreeSet;

use crate::evidence_ancestry::canonical_family;
use crate::http::Transport;

use super::claims::apply_observations;
use super::{
    IpActionRecord, IpCapability, IpClaimKind, IpClaimState, IpInvestigation, IpProvider,
    IpProviderAction, IpTarget, execute_provider_action,
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
    let mut pending = Vec::new();
    let mut seen_work = BTreeSet::new();

    for provider in providers {
        let descriptor = provider.descriptor();
        let reliability = sanitized_prior(descriptor.reliability_prior);
        for action in provider.plan(&investigation.target) {
            if mode == IpMode::Base && !is_base_capability(action.capability) {
                investigation.actions_considered.push(IpActionRecord {
                    provider_id: provider.id().into(),
                    action_id: action.action_id,
                    reason: "outside_base_frontier".into(),
                    executed: false,
                });
                continue;
            }

            let work_key = work_key(&action);
            if !seen_work.insert(work_key) {
                investigation.actions_considered.push(IpActionRecord {
                    provider_id: provider.id().into(),
                    action_id: action.action_id,
                    reason: "duplicate_upstream_target".into(),
                    executed: false,
                });
                continue;
            }

            pending.push(PendingAction {
                provider: *provider,
                depth: initial_depth(action.capability),
                action,
                reliability,
            });
        }
    }

    while !pending.is_empty() {
        if investigation.budget_used.actions >= budget.max_actions {
            investigation.termination_reason = Some("action_budget".into());
            break;
        }
        if investigation.budget_used.calls >= budget.max_calls {
            investigation.termination_reason = Some("request_budget".into());
            break;
        }

        let next = select_next(&pending, &investigation);
        if pending[next].depth > budget.max_depth {
            investigation.actions_considered.push(IpActionRecord {
                provider_id: pending[next].provider.id().into(),
                action_id: pending[next].action.action_id.clone(),
                reason: "max_depth".into(),
                executed: false,
            });
            investigation.termination_reason = Some("max_depth".into());
            break;
        }

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

    if investigation.termination_reason.is_none() {
        investigation.termination_reason = Some(
            match mode {
                IpMode::Base => "base_complete",
                IpMode::Deep => "fixed_point",
            }
            .into(),
        );
    }

    investigation
}

fn select_next(pending: &[PendingAction<'_>], investigation: &IpInvestigation) -> usize {
    pending
        .iter()
        .enumerate()
        .max_by(|(_, left), (_, right)| {
            let left_unresolved = !capability_resolved(left.action.capability, investigation);
            let right_unresolved = !capability_resolved(right.action.capability, investigation);
            right
                .depth
                .cmp(&left.depth)
                .then_with(|| left_unresolved.cmp(&right_unresolved))
                .then_with(|| left.reliability.total_cmp(&right.reliability))
                .then_with(|| right.provider.id().cmp(left.provider.id()))
                .then_with(|| right.action.action_id.cmp(&left.action.action_id))
        })
        .map_or(0, |(index, _)| index)
}

fn action_reason(capability: IpCapability, investigation: &IpInvestigation) -> String {
    if capability_resolved(capability, investigation) {
        "corroborate_existing_claim".into()
    } else {
        "resolve_missing_claim".into()
    }
}

fn capability_resolved(capability: IpCapability, investigation: &IpInvestigation) -> bool {
    let kind = claim_kind(capability);
    investigation
        .claims
        .iter()
        .any(|claim| claim.kind == kind && claim.state == IpClaimState::Supported)
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

const fn initial_depth(capability: IpCapability) -> u32 {
    if is_base_capability(capability) { 0 } else { 1 }
}

fn work_key(action: &IpProviderAction) -> String {
    let lineage = canonical_family(&action.lineage_family);
    format!("{lineage}|{:?}|{}", action.capability, action.request.url)
}

fn sanitized_prior(prior: f64) -> f64 {
    if prior.is_finite() {
        prior.clamp(0.0, 1.0)
    } else {
        0.0
    }
}
