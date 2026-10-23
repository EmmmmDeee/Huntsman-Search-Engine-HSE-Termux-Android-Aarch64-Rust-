//! Deterministic, bounded dispatch planning across module metadata and discovery routes.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use crate::attack;
use crate::classifier;
use crate::dependency::{Module, ModuleGraph, Target, TargetKind};
use crate::module::{
    ModuleSpec, ProviderDescriptor, derive_default_provider_descriptor,
    unknown_cost_paid_provider_blocked,
};
use crate::pipeline::{NormalizedSeed, PipelineLimits};
use crate::roi::{
    DispatchUtility, DispatchUtilityInputs, compute_dispatch_utility, is_geoint_bearing,
};
use crate::source_registry;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct DispatchKey {
    pub provider_id: String,
    pub kind: TargetKind,
    pub value: String,
}

impl DispatchKey {
    #[must_use]
    pub fn new(provider_id: impl Into<String>, kind: TargetKind, value: impl Into<String>) -> Self {
        Self {
            provider_id: provider_id.into(),
            kind,
            value: value.into(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DispatchExclusion {
    Unsupported,
    Duplicate,
    CredentialUnavailable,
    Budget,
    QuotaExhausted,
    UnknownPaidCost,
    ResourceLimit,
}

#[derive(Debug, Clone, PartialEq)]
pub enum DispatchAction {
    Module {
        module_index: usize,
    },
    Route {
        source_id: &'static str,
        url: String,
    },
    ServiceProbe {
        service: &'static str,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub struct PlannedDispatch {
    pub target: Target,
    pub action: DispatchAction,
    pub utility: Option<DispatchUtility>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExcludedDispatch {
    pub target: Target,
    pub provider_id: String,
    pub reason: DispatchExclusion,
}

#[derive(Debug, Clone, PartialEq)]
pub struct DispatchPlan {
    pub selected: Vec<PlannedDispatch>,
    pub excluded: Vec<ExcludedDispatch>,
    pub truncated: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PlannerPolicy {
    pub budget_usd: Option<f64>,
    pub allow_unknown_paid_cost: bool,
    pub convex_budget: bool,
    pub configured_providers: BTreeSet<String>,
    pub quota_remaining: BTreeMap<String, bool>,
    pub prior_dispatches: BTreeSet<DispatchKey>,
}

impl Default for PlannerPolicy {
    fn default() -> Self {
        Self {
            budget_usd: None,
            allow_unknown_paid_cost: false,
            convex_budget: true,
            configured_providers: BTreeSet::new(),
            quota_remaining: BTreeMap::new(),
            prior_dispatches: BTreeSet::new(),
        }
    }
}

struct ModuleSpecAdapter<'a> {
    module: &'a dyn Module,
}

impl ModuleSpec for ModuleSpecAdapter<'_> {
    fn name(&self) -> &'static str {
        self.module.name()
    }

    fn priority(&self) -> u8 {
        self.module.priority()
    }

    fn cost(&self) -> crate::dependency::ModuleCost {
        self.module.cost()
    }

    fn passive(&self) -> bool {
        self.module.is_passive()
    }

    fn category(&self) -> crate::dependency::ModuleCategory {
        self.module.category()
    }

    fn consumes(&self) -> Vec<&'static str> {
        self.module
            .consumes()
            .into_iter()
            .map(TargetKind::canonical_str)
            .collect()
    }

    fn produces(&self) -> Vec<&'static str> {
        self.module
            .produces()
            .into_iter()
            .map(|kind| kind.as_str())
            .collect()
    }
}

fn descriptor(module: &dyn Module) -> ProviderDescriptor {
    derive_default_provider_descriptor(&ModuleSpecAdapter { module })
}

fn exceeds_budget(budget_usd: Option<f64>, cost_per_request: Option<f64>) -> bool {
    match (budget_usd, cost_per_request) {
        (Some(budget), Some(cost)) => cost > budget,
        _ => false,
    }
}

fn module_exclusion(
    module: &dyn Module,
    kind: TargetKind,
    value: &str,
    policy: &PlannerPolicy,
) -> Option<DispatchExclusion> {
    let provider_id = module.name();
    let key = DispatchKey::new(provider_id, kind, value);
    if policy.prior_dispatches.contains(&key) {
        return Some(DispatchExclusion::Duplicate);
    }
    if policy.quota_remaining.get(provider_id) == Some(&false) {
        return Some(DispatchExclusion::QuotaExhausted);
    }
    let provider = descriptor(module);
    if provider.requires_key && !policy.configured_providers.contains(provider_id) {
        return Some(DispatchExclusion::CredentialUnavailable);
    }
    if unknown_cost_paid_provider_blocked(
        &provider,
        policy.budget_usd,
        policy.allow_unknown_paid_cost,
    ) {
        return Some(DispatchExclusion::UnknownPaidCost);
    }
    exceeds_budget(policy.budget_usd, provider.cost_per_request)
        .then_some(DispatchExclusion::Budget)
}

fn planned_module(
    module: &dyn Module,
    module_index: usize,
    seed: &NormalizedSeed,
    target: &Target,
    policy: &PlannerPolicy,
) -> PlannedDispatch {
    let provider_id = module.name();
    let provider = descriptor(module);
    let classified = classifier::classify(&seed.value);
    let utility = compute_dispatch_utility(&DispatchUtilityInputs {
        source_count: 0,
        entity_confidence: Some(classified.confidence),
        optionality_prior: provider.optionality_prior,
        novelty_prior: provider.uniqueness_prior,
        reliability_prior: provider.reliability_prior,
        cost_per_request_usd: provider.cost_per_request,
        quota_remaining: policy.quota_remaining.get(provider_id).copied(),
        configured_timeout_ms: u64::try_from(crate::http::DEFAULT_TIMEOUT.as_millis())
            .unwrap_or(u64::MAX),
        already_dispatched_this_module_target: false,
        geoint_bearing: is_geoint_bearing(&module.produces(), module.category()),
    });
    PlannedDispatch {
        target: target.clone(),
        action: DispatchAction::Module { module_index },
        utility: Some(utility),
    }
}

fn action_id(action: &DispatchAction, modules: &[Arc<dyn Module>]) -> String {
    match action {
        DispatchAction::Module { module_index } => modules.get(*module_index).map_or_else(
            || format!("module:{module_index}"),
            |module| module.name().to_string(),
        ),
        DispatchAction::Route { source_id, url } => format!("route:{source_id}:{url}"),
        DispatchAction::ServiceProbe { service } => format!("probe:{service}"),
    }
}

/// Scored dispatches first, highest utility first, then by action id. The ids are passed in,
/// formatted once per dispatch: formatting them in here cost two allocations per comparison.
fn utility_cmp(
    (left_id, left): &(String, PlannedDispatch),
    (right_id, right): &(String, PlannedDispatch),
) -> Ordering {
    match (&left.utility, &right.utility) {
        (Some(left_utility), Some(right_utility)) => right_utility
            .final_utility
            .total_cmp(&left_utility.final_utility)
            .then_with(|| left_id.cmp(right_id)),
        (Some(_), None) => Ordering::Less,
        (None, Some(_)) => Ordering::Greater,
        (None, None) => left_id.cmp(right_id),
    }
}

/// ATT&CK Reconnaissance technique opportunities that this candidate's provider class can
/// contribute to. These are possible acquisition methods, never claims of observed evidence.
fn reconnaissance_opportunities(
    dispatch: &PlannedDispatch,
    modules: &[Arc<dyn Module>],
) -> Vec<&'static str> {
    let DispatchAction::Module { module_index } = &dispatch.action else {
        return Vec::new();
    };
    let Some(module) = modules.get(*module_index) else {
        return Vec::new();
    };
    attack::techniques_for_category(module.category())
        .iter()
        .copied()
        .filter(|id| {
            attack::technique(id)
                .is_some_and(|technique| technique.tactics.contains(&"reconnaissance"))
        })
        .collect()
}

/// Preserve the existing ROI ordering exactly across different utility values. Inside a
/// genuine utility tie, greedily prefer providers that add ATT&CK Reconnaissance opportunities
/// not already selected for the same target. This changes which executable modules survive a
/// tight dispatch cap; no additional network requests or new target identifiers are generated.
/// Unmapped modules remain eligible and retain the existing stable name tie-break.
fn diversify_equal_utility(
    candidates: Vec<(String, PlannedDispatch)>,
    modules: &[Arc<dyn Module>],
) -> Vec<(String, PlannedDispatch)> {
    let mut ordered = Vec::with_capacity(candidates.len());
    let mut seen = BTreeSet::<(TargetKind, String, &'static str)>::new();
    let mut remaining = candidates.into_iter().peekable();
    while let Some(first) = remaining.next() {
        let score = first
            .1
            .utility
            .as_ref()
            .map(|utility| utility.final_utility);
        let mut group = vec![first];
        while remaining
            .peek()
            .is_some_and(|(_, item)| item.utility.as_ref().map(|u| u.final_utility) == score)
        {
            if let Some(next) = remaining.next() {
                group.push(next);
            }
        }
        let mut group = group
            .into_iter()
            .map(|(name, item)| {
                let opportunities = reconnaissance_opportunities(&item, modules);
                (name, item, opportunities)
            })
            .collect::<Vec<_>>();
        // One bounded sort, then a single pass: even 256 seeds multiplied by many
        // modules must not turn ATT&CK diversification into quadratic phone work.
        group.sort_by(|a, b| b.2.len().cmp(&a.2.len()).then_with(|| a.0.cmp(&b.0)));
        let mut deferred = Vec::new();
        for (name, item, opportunities) in group {
            let adds_technique = opportunities.iter().any(|&technique| {
                !seen.contains(&(item.target.kind, item.target.value.clone(), technique))
            });
            if adds_technique {
                for technique in opportunities {
                    seen.insert((item.target.kind, item.target.value.clone(), technique));
                }
                ordered.push((name, item));
            } else {
                deferred.push((name, item));
            }
        }
        // Retain tied sources with overlapping or absent mappings, even when a
        // constrained admission budget later excludes them.
        ordered.extend(deferred);
    }
    ordered
}

#[must_use]
pub fn build_dispatch_plan(
    modules: &[Arc<dyn Module>],
    seeds: &[NormalizedSeed],
    limits: &PipelineLimits,
    policy: &PlannerPolicy,
) -> DispatchPlan {
    let graph = ModuleGraph::build(modules);
    let mut selected = Vec::new();
    let mut excluded = Vec::new();

    for seed in seeds {
        let Some(kind) = TargetKind::from_entity_kind(&seed.kind) else {
            continue;
        };
        let target = Target::new(kind, seed.value.clone());
        for &module_index in graph.dispatch_order_for(kind, policy.convex_budget) {
            let Some(module) = modules.get(module_index) else {
                continue;
            };
            if let Some(reason) = module_exclusion(module.as_ref(), kind, &seed.value, policy) {
                excluded.push(ExcludedDispatch {
                    target: target.clone(),
                    provider_id: module.name().to_string(),
                    reason,
                });
            } else {
                selected.push(planned_module(
                    module.as_ref(),
                    module_index,
                    seed,
                    &target,
                    policy,
                ));
            }
        }
        // A handle is routed as the operator wrote it, each spelling of it; its canonical
        // value drops the separators that tell `octo-cat` from `octocat`.
        let route_values: Vec<&str> = if kind == TargetKind::Username {
            std::iter::once(seed.raw.as_str())
                .chain(seed.other_spellings.iter().map(String::as_str))
                .collect()
        } else {
            vec![seed.value.as_str()]
        };
        for route_value in route_values {
            for route in source_registry::routes_for(&seed.kind, route_value) {
                selected.push(PlannedDispatch {
                    target: target.clone(),
                    action: DispatchAction::Route {
                        source_id: route.source_id,
                        url: route.url,
                    },
                    utility: None,
                });
            }
        }
    }

    let mut keyed = selected
        .into_iter()
        .map(|item| (action_id(&item.action, modules), item))
        .collect::<Vec<_>>();
    keyed.sort_by(utility_cmp);
    // ATT&CK affects actual module admission under max_dispatches, not only report labels.
    // Never trade a higher-valued action for a lower-valued one.
    let keyed = diversify_equal_utility(keyed, modules);
    let mut selected = keyed.into_iter().map(|(_, item)| item).collect::<Vec<_>>();
    excluded.sort_by(|left, right| {
        left.provider_id
            .cmp(&right.provider_id)
            .then_with(|| left.target.kind.cmp(&right.target.kind))
            .then_with(|| left.target.value.cmp(&right.target.value))
    });

    let truncated = selected.len() > limits.max_dispatches;
    if truncated {
        for item in selected.drain(limits.max_dispatches..) {
            excluded.push(ExcludedDispatch {
                provider_id: action_id(&item.action, modules),
                target: item.target,
                reason: DispatchExclusion::ResourceLimit,
            });
        }
    }

    DispatchPlan {
        selected,
        excluded,
        truncated,
    }
}
