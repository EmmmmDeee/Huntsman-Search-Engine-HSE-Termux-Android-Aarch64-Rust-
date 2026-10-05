use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use huntsman_recon::dependency::{Module, ModuleCategory, ModuleCost, Target, TargetKind};
use huntsman_recon::entity::EntityKind;
use huntsman_recon::pipeline::{NormalizedSeed, PipelineLimits};
use huntsman_recon::planner::{
    DispatchAction, DispatchExclusion, DispatchKey, PlannerPolicy, build_dispatch_plan,
};

struct FreeDomain;
impl Module for FreeDomain {
    fn name(&self) -> &'static str { "free_domain" }
    fn priority(&self) -> u8 { 80 }
    fn category(&self) -> ModuleCategory { ModuleCategory::Search }
    fn accepts(&self, target: &Target) -> bool { target.kind == TargetKind::Domain }
    fn produces(&self) -> Vec<EntityKind> { vec![EntityKind::Email] }
}

struct IntelxLike;
impl Module for IntelxLike {
    fn name(&self) -> &'static str { "intelx" }
    fn cost(&self) -> ModuleCost { ModuleCost::Paid }
    fn category(&self) -> ModuleCategory { ModuleCategory::Breach }
    fn accepts(&self, target: &Target) -> bool { target.kind == TargetKind::Domain }
    fn produces(&self) -> Vec<EntityKind> { vec![EntityKind::Email] }
}

fn seed() -> NormalizedSeed {
    NormalizedSeed {
        raw: "Example.COM".to_string(),
        kind: EntityKind::Domain,
        value: "example.com".to_string(),
    }
}

fn modules() -> Vec<Arc<dyn Module>> {
    vec![Arc::new(FreeDomain), Arc::new(IntelxLike)]
}

#[test]
fn planner_uses_dependency_graph_and_roi_ordering() {
    let plan = build_dispatch_plan(&modules(), &[seed()], &PipelineLimits::default(), &PlannerPolicy::default());
    assert!(matches!(plan.selected[0].action, DispatchAction::Module { module_index: 0 }));
    assert!(plan.selected.iter().any(|item| matches!(item.action, DispatchAction::Route { .. })));
}

#[test]
fn planner_excludes_duplicate_module_target_pair() {
    let mut policy = PlannerPolicy::default();
    policy.prior_dispatches.insert(DispatchKey::new("free_domain", TargetKind::Domain, "example.com"));
    let plan = build_dispatch_plan(&modules(), &[seed()], &PipelineLimits::default(), &policy);
    assert!(plan.excluded.iter().any(|item| item.provider_id == "free_domain" && item.reason == DispatchExclusion::Duplicate));
}

#[test]
fn planner_blocks_exhausted_quota() {
    let mut policy = PlannerPolicy::default();
    policy.quota_remaining.insert("free_domain".to_string(), false);
    let plan = build_dispatch_plan(&modules(), &[seed()], &PipelineLimits::default(), &policy);
    assert!(plan.excluded.iter().any(|item| item.provider_id == "free_domain" && item.reason == DispatchExclusion::QuotaExhausted));
}

#[test]
fn planner_blocks_unknown_paid_cost_under_budget() {
    let mut policy = PlannerPolicy {
        budget_usd: Some(10.0),
        configured_providers: BTreeSet::from(["intelx".to_string()]),
        ..PlannerPolicy::default()
    };
    policy.quota_remaining = BTreeMap::from([("intelx".to_string(), true)]);
    let plan = build_dispatch_plan(&modules(), &[seed()], &PipelineLimits::default(), &policy);
    assert!(plan.excluded.iter().any(|item| item.provider_id == "intelx" && item.reason == DispatchExclusion::UnknownPaidCost));
}

#[test]
fn lead_routes_are_planned_as_leads_not_evidence() {
    let plan = build_dispatch_plan(&[], &[seed()], &PipelineLimits::default(), &PlannerPolicy::default());
    assert!(plan.selected.iter().all(|item| matches!(item.action, DispatchAction::Route { .. })));
    assert!(plan.selected.iter().any(|item| matches!(&item.action, DispatchAction::Route { source_id, .. } if *source_id == "wayback")));
}

#[test]
fn planner_output_is_stable_across_repeated_runs() {
    let policy = PlannerPolicy::default();
    let left = build_dispatch_plan(&modules(), &[seed()], &PipelineLimits::default(), &policy);
    let right = build_dispatch_plan(&modules(), &[seed()], &PipelineLimits::default(), &policy);
    assert_eq!(left, right);
}
