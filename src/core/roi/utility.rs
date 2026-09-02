//! Canonical dispatch-utility evaluation — the fourth ROI lever.
//!
//! Extends the three existing pure levers (saturation-pruning, top-K/knee
//! cutoff, adaptive-depth termination — see the module doc comment one level
//! up) with a single, explainable, per-(module, target) utility score that
//! folds in novelty, source independence, pivot optionality, source
//! reliability, expected information gain, monetary cost, quota cost,
//! latency, failure probability, and duplication probability.
//!
//! **Additive, not multiplicative.** Every factor enters `final_utility` as
//! a bounded `+`/`-` term against a running sum. A missing/unknown input
//! resolves to a documented neutral default — never a silent `0.0` benefit
//! or `1.0` penalty — so one uncertain factor can move the score by at most
//! its own term's weight. This is the opposite of a `weight *= reliability`
//! formulation, where an unknown `reliability` coerced to `0.0` would zero
//! out every other signal; [`compute_dispatch_utility`] cannot do that by
//! construction (see `missing_factors_never_collapse_dominant_term`).
//!
//! **Eligibility gates run first, always.** [`quota_exhausted_blocked`] is a
//! hard pre-ranking gate (mirroring
//! [`crate::core::module::unknown_cost_paid_provider_blocked`]), wired into
//! `crate::core::engine::dispatch::module_skip_reason`. A candidate that
//! fails any eligibility gate — allowlist/exclude, circuit-open, disabled,
//! `free_only`, unknown-cost budget, quota-exhausted, quarantine, and so on
//! — never reaches [`compute_dispatch_utility`] at all. One consequence
//! worth stating explicitly: because the circuit breaker
//! (`crate::core::engine::circuit::is_open`) is *already* one of those hard
//! gates, any candidate that DOES reach this scorer is, by construction,
//! circuit-closed right now — so `reliability` below is driven purely by
//! [`crate::core::module::ProviderDescriptor::reliability_prior`] (the
//! cold-start prior), not a redundant live circuit check.
//!
//! Pure function of [`DispatchUtilityInputs`]; no I/O, matching this
//! module's existing "all pure functions over scalars" contract. The
//! *caller* (`crate::core::engine::dispatch`) is responsible for resolving
//! those inputs from real engine/provider state before calling in.

/// Canonical evaluation result for one (module, candidate-target) dispatch
/// decision. Every `f64` field is `[0, 1]`-normalised where the underlying
/// signal naturally lives there; `Option<f64>` fields mean the underlying
/// signal can be genuinely unknown (never coerced to a fake zero). The whole
/// thing carries its own human-readable derivation via `explanation`.
#[derive(Debug, Clone, PartialEq)]
pub struct DispatchUtility {
    /// Expected new-information value of dispatching this candidate, in
    /// `[0, 1]` — derived from how little is already confirmed about the
    /// target entity (see formula below). The single largest additive term.
    pub expected_information_value: f64,
    /// How novel this module's likely output is relative to what a scan
    /// typically already knows, in `[0, 1]` — currently the same
    /// `module_cascade`-derived signal as `expected_optionality` (see that
    /// field's doc); a redundancy-aware novelty check (weighted against
    /// entity kinds *this specific scan* has already produced) is a
    /// documented future extension, not built here.
    pub expected_novelty: f64,
    /// How independent this candidate is from sources already corroborating
    /// the target entity — `[0, 1]`, derived from `source_count` via the
    /// same diminishing-returns shape `is_saturated`'s own signal uses.
    pub expected_independence: f64,
    /// Heavy-tailed "keeps future pivots open" value of this module's
    /// declared outputs — `[0, 1]`, read directly from
    /// [`crate::core::module::ProviderDescriptor::optionality_prior`].
    pub expected_optionality: f64,
    /// Provider reliability — `[0, 1]`, 1.0 = maximally reliable. Cold-start
    /// only (see module doc: the live circuit-breaker signal is already an
    /// eligibility gate upstream of this scorer).
    pub reliability: f64,
    /// Estimated monetary cost of this dispatch in USD, when knowable.
    /// `None` when the provider's cost model is
    /// [`crate::core::module::CostModel::Unknown`] — distinct from
    /// `Some(0.0)`, which means a *confirmed* free dispatch.
    pub estimated_cost: Option<f64>,
    /// Whether this dispatch would spend from an exhausted-adjacent local
    /// quota — `None` when the provider tracks no local quota, or its
    /// remaining state isn't currently resolvable (see
    /// [`crate::core::module::Module::quota_remaining`]).
    pub quota_cost: Option<f64>,
    /// Normalised latency penalty in `[0, 1]` (0 = a tight configured
    /// timeout budget, 1 = at/over the longest reasonable budget). A
    /// **budget-based proxy**, not an observed measurement — no
    /// `Instant::elapsed()` capture exists around module dispatch today
    /// (see module doc); flagged as a scoped-out future extension.
    pub latency_penalty: f64,
    /// Estimated probability this dispatch fails outright, in `[0, 1]` —
    /// the deterministic complement of `reliability` (`1.0 - reliability`),
    /// kept as its own field so the explanation shows both independently.
    pub failure_penalty: f64,
    /// `1.0` if this exact (module, target) pair has already been
    /// dispatched this scan, else `0.0` — read from
    /// `crate::core::engine::DispatchLog`, the same dedup ledger
    /// `dispatch_key` already enforces.
    pub duplicate_penalty: f64,
    /// The final additive utility score. **Not** bounded to `[0, 1]` — it is
    /// a ranking score, comparable only against other
    /// `DispatchUtility::final_utility` values computed this same round.
    /// Higher is better.
    pub final_utility: f64,
    /// Human-readable "factor: contribution" breakdown, one line per term
    /// plus a final line restating `final_utility` — see
    /// `explanation_is_never_empty_and_always_restates_final_utility`.
    /// Always non-empty.
    pub explanation: Vec<String>,
}

/// Raw inputs to [`compute_dispatch_utility`], assembled by the caller
/// (`crate::core::engine::dispatch`) from real engine/provider state. Every
/// `Option` means "genuinely unknown, use the documented neutral default" —
/// never pre-collapse an unknown to `0.0`/`false` before calling this
/// function, or the missing-value robustness guarantee is defeated before
/// the formula ever runs.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct DispatchUtilityInputs {
    /// `entity.source_count()` for the entity this candidate target was
    /// derived from — `0` for a target with no matching entity yet.
    pub source_count: u32,
    /// `entity.c_effective()` for that same entity — `None` when there is
    /// no entity yet (a wholly new candidate), which is itself a strong
    /// "nothing confirmed yet" signal, not an unknown to default away.
    pub entity_confidence: Option<f64>,
    /// `ProviderDescriptor::optionality_prior` for the module that would be
    /// dispatched. Always defined (the descriptor guarantees `[0,1]`).
    pub optionality_prior: f64,
    /// `crate::core::convex::module_cascade(module.produces(),
    /// module.category())`, resolved by the caller — see
    /// [`DispatchUtility::expected_novelty`]'s doc for why this currently
    /// equals `optionality_prior` in practice.
    pub novelty_prior: f64,
    /// `ProviderDescriptor::reliability_prior` for the module. Always
    /// defined (the descriptor guarantees `[0,1]`, neutral `0.5` default).
    pub reliability_prior: f64,
    /// `ProviderDescriptor::cost_model` + `cost_per_request`, pre-resolved
    /// by the caller into a single optional USD figure: `Free` → `Some(0.0)`,
    /// `Exact`/`Estimated` with a configured price → `Some(price)`,
    /// `Unknown` (or `Free` with no configured price, which cannot happen
    /// per `derive_default`) → `None`.
    pub cost_per_request_usd: Option<f64>,
    /// `Module::quota_remaining()` for the module — `Some(true)` = has
    /// budget, `Some(false)` = exhausted, `None` = untracked/unresolvable.
    pub quota_remaining: Option<bool>,
    /// `module.constrained_timeout_ms()` — the configured per-dispatch
    /// budget, ms. Always known (every module has a default).
    pub configured_timeout_ms: u64,
    /// Whether this exact (module, target) pair has already been dispatched
    /// this scan (a read of `DispatchLog`, not a mutation).
    pub already_dispatched_this_module_target: bool,
}

// ── Tunable weights — additive, never multiplied against `final_utility` ───

/// Dominant benefit term, mirroring the base expansion weight's role in the
/// existing (unmodified) ranking pipeline this design deliberately does not
/// replace.
pub const W_INFO: f64 = 3.0;
/// Weight on `expected_novelty`.
pub const W_NOV: f64 = 1.0;
/// Weight on `expected_independence`.
pub const W_INDEP: f64 = 1.0;
/// Weight on `expected_optionality`.
pub const W_OPT: f64 = 1.0;
/// Weight on `reliability`.
pub const W_REL: f64 = 1.0;
/// Weight on the cost penalty.
pub const W_COST: f64 = 1.0;
/// Weight on the quota-cost penalty.
pub const W_QUOTA: f64 = 0.5;
/// Weight on `latency_penalty`.
pub const W_LAT: f64 = 0.5;
/// Weight on `failure_penalty`.
pub const W_FAIL: f64 = 1.0;
/// Near-veto weight — still additive/subtractive, never multiplicative, so
/// even a duplicate dispatch of an otherwise maximally-valuable candidate
/// degrades rather than annihilates its score.
pub const W_DUP: f64 = 2.0;

/// Fixed penalty applied when a paid provider's per-request cost is
/// genuinely unknown — deliberately non-zero (an unknown price is not a
/// free one) and deliberately less than the maximum penalty (this is a soft
/// ranking nudge; the actual **hard** stop for an unknown-cost paid
/// provider under a finite budget is
/// [`crate::core::module::unknown_cost_paid_provider_blocked`], an
/// eligibility gate, not this formula).
pub const UNKNOWN_COST_PENALTY: f64 = 0.3;
/// Cost softness — a per-request cost of roughly this many dollars maps to
/// a ~0.5 normalised penalty; the mapping saturates smoothly toward 1.0 for
/// larger costs and never blows up.
const COST_SOFTNESS: f64 = 5.0;
/// Default quota-cost contribution when a module tracks no local quota (the
/// common case) — small and non-punitive, matching "nothing to spend down".
pub const QUOTA_COST_NEUTRAL: f64 = 0.2;
/// The longest configured per-dispatch timeout this formula treats as
/// "maximally slow" — matches `CONSTRAINED_MODULE_TIMEOUT_CAP_MS`.
const MAX_REASONABLE_TIMEOUT_MS: f64 = 45_000.0;

fn normalised_cost_penalty(cost: Option<f64>) -> (f64, String) {
    match cost {
        Some(c) if c <= 0.0 => (0.0, format!("CostModel confirmed free -> Some({c:.4})")),
        Some(c) => {
            let p = (c / (c + COST_SOFTNESS)).clamp(0.0, 1.0);
            (p, format!("cost_per_request=${c:.4} -> normalised {p:.3}"))
        }
        None => (
            UNKNOWN_COST_PENALTY,
            format!("cost unknown -> fixed penalty {UNKNOWN_COST_PENALTY:.3}"),
        ),
    }
}

fn quota_penalty(remaining: Option<bool>) -> (f64, String) {
    match remaining {
        // Eligibility already blocks a genuinely exhausted quota before this
        // scorer ever runs; `Some(false)` reaching here would mean a caller
        // bypassed that gate, so it is scored maximally costly rather than
        // trusted.
        Some(false) => (1.0, "quota reported exhausted".to_string()),
        Some(true) => (0.0, "quota has budget remaining -> 0.0".to_string()),
        None => (
            QUOTA_COST_NEUTRAL,
            format!("no local quota tracked -> neutral default {QUOTA_COST_NEUTRAL:.3}"),
        ),
    }
}

/// Pure evaluation: maps [`DispatchUtilityInputs`] to a [`DispatchUtility`].
/// See the module doc for the additive/log-space rationale and the crate's
/// design notes (`docs/REQUIREMENTS_LEDGER.md`, Section 12) for the exact
/// per-factor source mapping this implements.
#[must_use]
pub fn compute_dispatch_utility(inputs: &DispatchUtilityInputs) -> DispatchUtility {
    let expected_information_value = 1.0 - inputs.entity_confidence.unwrap_or(0.0);
    let expected_novelty = inputs.novelty_prior.clamp(0.0, 1.0);
    let expected_independence = 1.0 - 1.0 / (1.0 + f64::from(inputs.source_count));
    let expected_optionality = inputs.optionality_prior.clamp(0.0, 1.0);
    let reliability = inputs.reliability_prior.clamp(0.0, 1.0);
    let failure_penalty = 1.0 - reliability;
    let (cost_penalty, cost_note) = normalised_cost_penalty(inputs.cost_per_request_usd);
    let (quota_penalty_v, quota_note) = quota_penalty(inputs.quota_remaining);
    let latency_penalty =
        (inputs.configured_timeout_ms as f64 / MAX_REASONABLE_TIMEOUT_MS).clamp(0.0, 1.0);
    let duplicate_penalty = f64::from(u8::from(inputs.already_dispatched_this_module_target));

    let final_utility = W_INFO.mul_add(
        expected_information_value,
        W_NOV.mul_add(
            expected_novelty,
            W_INDEP.mul_add(
                expected_independence,
                W_OPT.mul_add(expected_optionality, W_REL * reliability),
            ),
        ),
    ) - W_COST.mul_add(
        cost_penalty,
        W_QUOTA.mul_add(
            quota_penalty_v,
            W_LAT.mul_add(
                latency_penalty,
                W_FAIL.mul_add(failure_penalty, W_DUP * duplicate_penalty),
            ),
        ),
    );

    let explanation = vec![
        format!(
            "expected_information_value: +{:.3} (entity_confidence={:.3} -> {:.3}, x W_INFO={W_INFO})",
            W_INFO * expected_information_value,
            inputs.entity_confidence.unwrap_or(0.0),
            expected_information_value
        ),
        format!(
            "expected_novelty: +{:.3} (module_cascade -> {expected_novelty:.3}, x W_NOV={W_NOV})",
            W_NOV * expected_novelty
        ),
        format!(
            "expected_independence: +{:.3} (source_count={} -> {expected_independence:.3}, x W_INDEP={W_INDEP})",
            W_INDEP * expected_independence,
            inputs.source_count
        ),
        format!(
            "expected_optionality: +{:.3} (ProviderDescriptor.optionality_prior={:.3}, x W_OPT={W_OPT})",
            W_OPT * expected_optionality,
            inputs.optionality_prior
        ),
        format!(
            "reliability: +{:.3} (cold-start prior={reliability:.3} — circuit-open already gated upstream, x W_REL={W_REL})",
            W_REL * reliability
        ),
        format!(
            "estimated_cost: -{:.3} ({cost_note}, x W_COST={W_COST})",
            W_COST * cost_penalty
        ),
        format!(
            "quota_cost: -{:.3} ({quota_note}, x W_QUOTA={W_QUOTA})",
            W_QUOTA * quota_penalty_v
        ),
        format!(
            "latency_penalty: -{:.3} (configured_timeout_ms={} / {MAX_REASONABLE_TIMEOUT_MS}, x W_LAT={W_LAT})",
            W_LAT * latency_penalty,
            inputs.configured_timeout_ms
        ),
        format!(
            "failure_penalty: -{:.3} (1 - reliability={reliability:.3}, x W_FAIL={W_FAIL})",
            W_FAIL * failure_penalty
        ),
        format!(
            "duplicate_penalty: -{:.3} (already_dispatched={}, x W_DUP={W_DUP})",
            W_DUP * duplicate_penalty,
            inputs.already_dispatched_this_module_target
        ),
        format!("final_utility: {final_utility:.3}"),
    ];

    DispatchUtility {
        expected_information_value,
        expected_novelty,
        expected_independence,
        expected_optionality,
        reliability,
        estimated_cost: inputs.cost_per_request_usd,
        // `None` only when the provider tracks no local quota at all — a
        // known `Some(true|false)` remaining state always yields a scored
        // `Some(quota_penalty_v)`, even though the *penalty magnitude* is
        // the same neutral default the `None` case would use internally
        // (see `quota_penalty`'s `Some(true)` arm) for a module confirmed to
        // have full remaining budget.
        quota_cost: inputs.quota_remaining.map(|_| quota_penalty_v),
        latency_penalty,
        failure_penalty,
        duplicate_penalty,
        final_utility,
        explanation,
    }
}

/// Hard eligibility gate: true iff the module tracks a local quota
/// (`quota_unit.is_some()`) and its current remaining-budget state is
/// known to be exhausted (`remaining == Some(false)`). Checked BEFORE
/// ranking, exactly like
/// [`crate::core::module::unknown_cost_paid_provider_blocked`], which this
/// mirrors. A module with no local quota tracking (`quota_unit.is_none()`)
/// never blocks — there's nothing to be exhausted. An *unknown* remaining
/// state (`remaining == None`) never blocks either — unknown is not
/// exhausted, the same "don't coerce uncertainty to the worst case" rule
/// this whole module follows.
#[must_use]
pub fn quota_exhausted_blocked(quota_unit: Option<&'static str>, remaining: Option<bool>) -> bool {
    quota_unit.is_some() && remaining == Some(false)
}

#[cfg(test)]
mod tests {
    include!("utility_tests.rs");
}
