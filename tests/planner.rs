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
    fn name(&self) -> &'static str {
        "free_domain"
    }
    fn priority(&self) -> u8 {
        80
    }
    fn category(&self) -> ModuleCategory {
        ModuleCategory::Search
    }
    fn accepts(&self, target: &Target) -> bool {
        target.kind == TargetKind::Domain
    }
    fn produces(&self) -> Vec<EntityKind> {
        vec![EntityKind::Email]
    }
}

struct IntelxLike;
impl Module for IntelxLike {
    fn name(&self) -> &'static str {
        "intelx"
    }
    fn cost(&self) -> ModuleCost {
        ModuleCost::Paid
    }
    fn category(&self) -> ModuleCategory {
        ModuleCategory::Breach
    }
    fn accepts(&self, target: &Target) -> bool {
        target.kind == TargetKind::Domain
    }
    fn produces(&self) -> Vec<EntityKind> {
        vec![EntityKind::Email]
    }
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
    let plan = build_dispatch_plan(
        &modules(),
        &[seed()],
        &PipelineLimits::default(),
        &PlannerPolicy::default(),
    );
    assert!(matches!(
        plan.selected[0].action,
        DispatchAction::Module { module_index: 0 }
    ));
    assert!(
        plan.selected
            .iter()
            .any(|item| matches!(item.action, DispatchAction::Route { .. }))
    );
}

#[test]
fn planner_excludes_duplicate_module_target_pair() {
    let mut policy = PlannerPolicy::default();
    policy.prior_dispatches.insert(DispatchKey::new(
        "free_domain",
        TargetKind::Domain,
        "example.com",
    ));
    let plan = build_dispatch_plan(&modules(), &[seed()], &PipelineLimits::default(), &policy);
    assert!(plan.excluded.iter().any(
        |item| item.provider_id == "free_domain" && item.reason == DispatchExclusion::Duplicate
    ));
}

#[test]
fn planner_blocks_exhausted_quota() {
    let mut policy = PlannerPolicy::default();
    policy
        .quota_remaining
        .insert("free_domain".to_string(), false);
    let plan = build_dispatch_plan(&modules(), &[seed()], &PipelineLimits::default(), &policy);
    assert!(
        plan.excluded
            .iter()
            .any(|item| item.provider_id == "free_domain"
                && item.reason == DispatchExclusion::QuotaExhausted)
    );
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
    assert!(
        plan.excluded.iter().any(|item| item.provider_id == "intelx"
            && item.reason == DispatchExclusion::UnknownPaidCost)
    );
}

#[test]
fn lead_routes_are_planned_as_leads_not_evidence() {
    let plan = build_dispatch_plan(
        &[],
        &[seed()],
        &PipelineLimits::default(),
        &PlannerPolicy::default(),
    );
    assert!(
        plan.selected
            .iter()
            .all(|item| matches!(item.action, DispatchAction::Route { .. }))
    );
    assert!(plan.selected.iter().any(|item| matches!(&item.action, DispatchAction::Route { source_id, .. } if *source_id == "wayback")));
}

/// The seed's canonical value drops separators, and `octocat` is another account, so a handle's
/// routes are built from the handle as written.
#[test]
fn username_routes_keep_the_handle_as_written() {
    let handle = NormalizedSeed {
        raw: "@octo-cat".to_string(),
        kind: EntityKind::Username,
        value: "octocat".to_string(),
    };
    let plan = build_dispatch_plan(
        &[],
        &[handle],
        &PipelineLimits::default(),
        &PlannerPolicy::default(),
    );
    let urls = plan
        .selected
        .iter()
        .filter_map(|item| match &item.action {
            DispatchAction::Route { url, .. } => Some(url.as_str()),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert!(
        urls.contains(&"https://github.com/search?q=octo-cat&type=users"),
        "{urls:?}"
    );
    assert!(
        urls.contains(&"https://www.google.com/search?q=%22octo-cat%22"),
        "{urls:?}"
    );
    assert!(urls.iter().all(|url| !url.contains("octocat")), "{urls:?}");
}

#[test]
fn planner_output_is_stable_across_repeated_runs() {
    let policy = PlannerPolicy::default();
    let left = build_dispatch_plan(&modules(), &[seed()], &PipelineLimits::default(), &policy);
    let right = build_dispatch_plan(&modules(), &[seed()], &PipelineLimits::default(), &policy);
    assert_eq!(left, right);
}

struct AlternateSearch;
impl Module for AlternateSearch {
    fn name(&self) -> &'static str {
        "a_search"
    }
    fn category(&self) -> ModuleCategory {
        ModuleCategory::Search
    }
    fn accepts(&self, target: &Target) -> bool {
        target.kind == TargetKind::Domain
    }
    fn produces(&self) -> Vec<EntityKind> {
        vec![EntityKind::Email]
    }
}

struct PassiveDns;
impl Module for PassiveDns {
    fn name(&self) -> &'static str {
        "z_dns"
    }
    fn category(&self) -> ModuleCategory {
        ModuleCategory::DnsRecon
    }
    fn accepts(&self, target: &Target) -> bool {
        target.kind == TargetKind::Domain
    }
    fn produces(&self) -> Vec<EntityKind> {
        vec![EntityKind::Email]
    }
}

#[test]
fn attack_reconnaissance_diversity_changes_real_admission_only_with_equal_roi() {
    // Both free modules have the same cost, output kind, reliability and utility.
    // The alphabetically earlier search used to win the tie. Bounded dispatch now
    // chooses the DNS source with distinct reconnaissance opportunities instead.
    let modules: Vec<Arc<dyn Module>> = vec![Arc::new(AlternateSearch), Arc::new(PassiveDns)];
    let limits = PipelineLimits {
        max_dispatches: 1,
        ..PipelineLimits::default()
    };
    let plan = build_dispatch_plan(&modules, &[seed()], &limits, &PlannerPolicy::default());
    assert_eq!(plan.selected.len(), 1);
    assert!(matches!(
        plan.selected[0].action,
        DispatchAction::Module { module_index: 1 }
    ));
    assert!(plan.excluded.iter().any(|item| {
        item.provider_id == "a_search" && item.reason == DispatchExclusion::ResourceLimit
    }));
}

#[test]
fn attack_reconnaissance_selection_still_obeys_credential_quota_and_prior_dispatch_gates() {
    let modules: Vec<Arc<dyn Module>> = vec![Arc::new(AlternateSearch), Arc::new(PassiveDns)];
    let limits = PipelineLimits {
        max_dispatches: 1,
        ..PipelineLimits::default()
    };
    let mut policy = PlannerPolicy::default();
    policy.quota_remaining.insert("z_dns".to_owned(), false);
    let plan = build_dispatch_plan(&modules, &[seed()], &limits, &policy);
    assert!(matches!(
        plan.selected[0].action,
        DispatchAction::Module { module_index: 0 }
    ));
    assert!(plan.excluded.iter().any(|item| {
        item.provider_id == "z_dns" && item.reason == DispatchExclusion::QuotaExhausted
    }));
    policy.quota_remaining.remove("z_dns");
    policy
        .prior_dispatches
        .insert(DispatchKey::new("z_dns", TargetKind::Domain, "example.com"));
    let plan = build_dispatch_plan(&modules, &[seed()], &limits, &policy);
    assert!(matches!(
        plan.selected[0].action,
        DispatchAction::Module { module_index: 0 }
    ));
    assert!(plan.excluded.iter().any(|item| {
        item.provider_id == "z_dns" && item.reason == DispatchExclusion::Duplicate
    }));
}
