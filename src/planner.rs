//! Deterministic, bounded dispatch planning across module metadata and discovery routes.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

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
use crate::service_defs;
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
    pub rationale: Vec<String>,
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

fn utility_cmp(
    left: &PlannedDispatch,
    right: &PlannedDispatch,
    modules: &[Arc<dyn Module>],
) -> Ordering {
    match (&left.utility, &right.utility) {
        (Some(left_utility), Some(right_utility)) => right_utility
            .final_utility
            .total_cmp(&left_utility.final_utility)
            .then_with(|| action_id(&left.action, modules).cmp(&action_id(&right.action, modules))),
        (Some(_), None) => Ordering::Less,
        (None, Some(_)) => Ordering::Greater,
        (None, None) => action_id(&left.action, modules).cmp(&action_id(&right.action, modules)),
    }
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
        let module_indices = graph.dispatch_order_for(kind, policy.convex_budget);
        for &module_index in module_indices {
            let Some(module) = modules.get(module_index) else {
                continue;
            };
            let provider_id = module.name();
            let key = DispatchKey::new(provider_id, kind, &seed.value);
            let exclude = if policy.prior_dispatches.contains(&key) {
                Some(DispatchExclusion::Duplicate)
            } else if policy.quota_remaining.get(provider_id) == Some(&false) {
                Some(DispatchExclusion::QuotaExhausted)
            } else {
                let provider = descriptor(module.as_ref());
                if provider.requires_key && !policy.configured_providers.contains(provider_id) {
                    Some(DispatchExclusion::CredentialUnavailable)
                } else if unknown_cost_paid_provider_blocked(
                    &provider,
                    policy.budget_usd,
                    policy.allow_unknown_paid_cost,
                ) {
                    Some(DispatchExclusion::UnknownPaidCost)
                } else if let (Some(budget), Some(cost)) =
                    (policy.budget_usd, provider.cost_per_request)
                    && cost > budget
                {
                    Some(DispatchExclusion::Budget)
                } else {
                    None
                }
            };
            if let Some(reason) = exclude {
                excluded.push(ExcludedDispatch {
                    target: target.clone(),
                    provider_id: provider_id.to_string(),
                    reason,
                });
                continue;
            }

            let provider = descriptor(module.as_ref());
            let classified = classifier::classify(&seed.value);
            let quota = policy.quota_remaining.get(provider_id).copied();
            let utility = compute_dispatch_utility(&DispatchUtilityInputs {
                source_count: 0,
                entity_confidence: Some(classified.confidence),
                optionality_prior: provider.optionality_prior,
                novelty_prior: provider.uniqueness_prior,
                reliability_prior: provider.reliability_prior,
                cost_per_request_usd: provider.cost_per_request,
                quota_remaining: quota,
                configured_timeout_ms: u64::try_from(crate::http::DEFAULT_TIMEOUT.as_millis())
                    .unwrap_or(u64::MAX),
                already_dispatched_this_module_target: false,
                geoint_bearing: is_geoint_bearing(&module.produces(), module.category()),
            });
            let mut rationale = utility.explanation.clone();
            if service_defs::find_service(provider_id).is_some() {
                rationale.push("provider has keyed service definition".to_string());
            }
            selected.push(PlannedDispatch {
                target: target.clone(),
                action: DispatchAction::Module { module_index },
                utility: Some(utility),
                rationale,
            });
        }

        for route in source_registry::routes_for(&seed.kind, &seed.value) {
            selected.push(PlannedDispatch {
                target: target.clone(),
                action: DispatchAction::Route {
                    source_id: route.source_id,
                    url: route.url,
                },
                utility: None,
                rationale: vec!["discovery lead only; generated route is not evidence".to_string()],
            });
        }
    }

    selected.sort_by(|left, right| utility_cmp(left, right, modules));
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
