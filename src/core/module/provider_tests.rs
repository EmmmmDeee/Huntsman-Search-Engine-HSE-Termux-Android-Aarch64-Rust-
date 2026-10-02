use super::*;
use crate::core::module::{ModuleContext, ModuleResult};
use crate::core::scan::Target;

/// A minimal local stub — deliberately NOT `crate::modules::registry()`.
/// `src/core/` must stay module-agnostic (`core_does_not_import_modules`,
/// `tests/architecture.rs`); the registry-wide completeness/consistency
/// checks that need the real 188-module registry live in
/// `tests/architecture_parts/architecture_part7.rs` instead, where that
/// import is allowed.
struct StubModule;

#[async_trait::async_trait]
impl Module for StubModule {
    fn name(&self) -> &'static str {
        "stub_provider_probe"
    }
    fn priority(&self) -> u8 {
        50
    }
    fn accepts(&self, _: &Target) -> bool {
        true
    }
    async fn process(
        &self,
        _: &Target,
        _: &ModuleContext,
    ) -> crate::core::error::Result<ModuleResult> {
        Ok(ModuleResult::new())
    }
}

fn sample_module() -> std::sync::Arc<dyn Module> {
    // Only `derive_default_provider_descriptor`'s own field-override
    // behaviour is under test below, not any particular real provider's
    // identity — a local stub keeps this file free of `crate::modules`.
    std::sync::Arc::new(StubModule)
}

// ── env_cost_per_request ─────────────────────────────────────────────────

#[test]
fn env_cost_per_request_is_none_when_unset() {
    // A provider id essentially guaranteed unset in any test environment.
    assert_eq!(env_cost_per_request("no_such_provider_xyz123"), None);
}

#[test]
fn parse_cost_per_request_accepts_only_finite_nonnegative_numbers() {
    assert_eq!(parse_cost_per_request("0.0025"), Some(0.0025_f64));
    assert_eq!(parse_cost_per_request("  1.5  "), Some(1.5_f64));
    assert_eq!(parse_cost_per_request("0"), Some(0.0_f64));
    assert_eq!(
        parse_cost_per_request("-1.0"),
        None,
        "a negative configured cost must be rejected, not silently accepted"
    );
    assert_eq!(parse_cost_per_request("not-a-number"), None);
    assert_eq!(parse_cost_per_request("NaN"), None);
    assert_eq!(parse_cost_per_request("inf"), None);
    assert_eq!(parse_cost_per_request(""), None);
}

// ── unknown_cost_paid_provider_blocked — pure truth table ───────────────────

fn descriptor_with(access_class: AccessClass, cost_model: CostModel) -> ProviderDescriptor {
    let mut d = derive_default(&*sample_module());
    d.access_class = access_class;
    d.cost_model = cost_model;
    d
}

#[test]
fn unknown_cost_gate_only_blocks_paid_or_enterprise_unknown_cost_under_a_budget() {
    let paid_unknown = descriptor_with(AccessClass::Paid, CostModel::Unknown);
    let enterprise_unknown = descriptor_with(AccessClass::Enterprise, CostModel::Unknown);
    let paid_estimated = descriptor_with(AccessClass::Paid, CostModel::Estimated);
    let keyless_free = descriptor_with(AccessClass::Keyless, CostModel::Free);

    // No budget at all -> never blocked, regardless of everything else.
    assert!(!unknown_cost_paid_provider_blocked(
        &paid_unknown,
        None,
        false
    ));

    // Budget active, paid + unknown cost, no opt-in -> blocked.
    assert!(unknown_cost_paid_provider_blocked(
        &paid_unknown,
        Some(10.0),
        false
    ));
    assert!(unknown_cost_paid_provider_blocked(
        &enterprise_unknown,
        Some(10.0),
        false
    ));

    // Budget active, paid + unknown cost, WITH explicit opt-in -> not blocked.
    assert!(!unknown_cost_paid_provider_blocked(
        &paid_unknown,
        Some(10.0),
        true
    ));

    // Budget active, but the cost model isn't Unknown -> never blocked (a
    // known/estimated cost is exactly what the budget mechanism needs to
    // actually enforce a real cap on — that's future work, not this gate's
    // job, which is only to stop an UNKNOWN cost from silently running).
    assert!(!unknown_cost_paid_provider_blocked(
        &paid_estimated,
        Some(10.0),
        false
    ));

    // Budget active, but access_class isn't Paid/Enterprise -> never blocked.
    assert!(!unknown_cost_paid_provider_blocked(
        &keyless_free,
        Some(10.0),
        false
    ));
}
