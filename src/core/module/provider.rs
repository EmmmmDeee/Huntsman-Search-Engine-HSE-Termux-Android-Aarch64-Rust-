//! Provider capability + economics descriptor.
//!
//! The single canonical answer to "what kind of thing does this module talk
//! to, and what does using it cost" — extending the `Module` trait's existing
//! metadata (`cost()`, `category()`, `is_high_value_only()`,
//! `requires_geo_corroboration()`, `cache_ttl_secs()`, `consumes()`) rather
//! than duplicating it in a second, disconnected registry.
//! [`Module::provider_descriptor`] derives every field from those existing
//! methods by default, so all 188 registered modules get a descriptor "for
//! free" the same way `consumes()` gets correct behaviour for free from
//! `accepts()`. A handful of modules whose real economics differ from the
//! mechanical derivation (`oathnet_pro`, `wigle`, `see_know`, `osintcat` —
//! the four genuinely paid/quota-tracked providers, per a directed audit of
//! `src/util/{oathnet,see_know,wigle}` and `src/modules/osintcat`) override
//! it explicitly.
//!
//! `Module::info()` embeds this descriptor, so every consumer that already
//! reads `ModuleInfo` (CLI `hse modules --json`, `GET /api/v1/modules`) gets
//! it automatically — see the `provider_capability_metadata_matches_between_cli_and_api`
//! architecture test for the single-source-of-truth guarantee.
//!
//! Vendor prices are never compiled in here as literals: [`cost_per_request`]
//! is always `None` unless the operator configures it via
//! `HSE_PROVIDER_COST_<PROVIDER_ID>` (see [`env_cost_per_request`]) — an
//! **unknown** cost is a distinct, more conservative state than a **free**
//! one (see [`CostModel`] and [`unknown_cost_paid_provider_blocked`]).
//!
//! [`cost_per_request`]: ProviderDescriptor::cost_per_request

use super::{Module, ModuleCategory, ModuleCost};
use crate::core::scan::TargetKind;
use serde::Serialize;

/// How a provider is accessed. Orthogonal to [`ModuleCost`] (which only
/// distinguishes free/key-gated/paid for the `--free-only` filter): this adds
/// the finer split a real economics/eligibility model needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessClass {
    /// No credential of any kind — a public, unauthenticated endpoint.
    Keyless,
    /// Requires a free-to-register key/account, with no HSE-enforced quota
    /// tracking (the common case for the majority of key-gated modules).
    FreeAccount,
    /// Requires a free key AND HSE locally tracks/enforces a quota budget
    /// for it (reserved — no current module needs this; every locally
    /// quota-tracked provider today is `Paid`).
    FreeQuota,
    /// Requires a paid subscription or pay-per-use billing.
    Paid,
    /// Requires a negotiated enterprise contract, not a self-serve paid plan
    /// (see_know's own `enterprise_config` module — `src/util/see_know/`).
    Enterprise,
}

/// How aggressively a provider should be escalated to. Six bands, cold to
/// hot: local-only, then increasingly costly/specialised remote sources.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EscalationBand {
    /// Local device sensor, no network call at all (`Module::is_passive()`).
    L0Local,
    /// Free, keyless public endpoint.
    L1FreePublic,
    /// Free but key-gated (a free account/quota is required).
    L2FreeQuota,
    /// Paid, but low/uncoordinated per-call cost — an ordinary metered API.
    L3Microcost,
    /// A specialist provider the engine deliberately defers: gated behind
    /// cross-correlation (`Module::is_high_value_only`) or geo-corroboration
    /// (`Module::requires_geo_corroboration`) before it's allowed to fire on
    /// a discovered (non-seed) target.
    L4Specialist,
    /// Enterprise-contract access (see [`AccessClass::Enterprise`]).
    L5Enterprise,
}

/// Whether — and how confidently — a per-request monetary cost is known for
/// a provider. **`Unknown` is not `Free`**: a paid provider whose per-request
/// price isn't locally known must never be treated as costless.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CostModel {
    /// Genuinely free — no monetary cost exists to know.
    Free,
    /// A precise cost is known (typically supplied live by the provider
    /// itself, e.g. osintcat's `price_per_search` preflight field), even
    /// though this static descriptor doesn't carry the live number.
    Exact,
    /// A rough cost can be estimated (e.g. from a provider's own
    /// credit-cost table) but isn't a precise dollar figure.
    Estimated,
    /// Paid, but no cost estimate is available at all — the conservative
    /// default for every paid/enterprise provider until an operator
    /// configures [`ProviderDescriptor::cost_per_request`].
    Unknown,
}

/// Whether a module may be re-dispatched against the same target within one
/// scan. Describes the existing `DispatchLog` dedup ledger's behaviour
/// (`src/core/engine/ledger/mod.rs`) — it does not itself enforce anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecursiveUsePolicy {
    /// May be re-dispatched against the same (module, target) pair within
    /// one scan — `DispatchLog`'s existing exemption for free modules
    /// (`ledger/mod.rs`: "Free modules are explicitly exempt... since
    /// re-running a zero-cost module can corroborate with fresh evidence").
    Unrestricted,
    /// Dispatched at most once per (module, target) pair per scan —
    /// `DispatchLog`'s default for keyed/paid modules.
    OncePerTargetPerScan,
}

/// Whether the inter-scan entity cache is active for this module. Describes
/// `Module::cache_ttl_secs()`, not a separate mechanism.
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CachePolicy {
    /// `cache_ttl_secs() == 0` — every dispatch re-queries the provider.
    Disabled,
    /// Results are served from the inter-scan cache for this many seconds
    /// (`Module::cache_ttl_secs()`) before re-querying.
    TtlSeconds(u64),
}

/// How a module's outbound requests are rate-limited. Describes the existing
/// shared, per-host circuit breaker (`crate::util::circuit_breaker`), not a
/// separate per-module limiter — there isn't one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RateLimitPolicy {
    /// No network calls, so no rate limiting applies.
    None,
    /// Bound by the shared per-host circuit breaker: a 429 or 5 consecutive
    /// failures opens the breaker for this module's host, shared with every
    /// other module hitting the same host.
    SharedHostCircuitBreaker,
}

/// Any documented licensing/ToS constraint on using this provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LicensingPolicy {
    /// No documented constraint beyond the provider's own API terms — the
    /// default for almost every module today.
    Unspecified,
    /// Actively fetches and respects the target's `robots.txt` before
    /// crawling (currently only `web_crawler`).
    RespectsRobotsTxt,
}

/// How far back in time a provider's data typically reaches. A coarse,
/// categorical prior — not calibrated per-module beyond the `Breach`
/// category default (breach/stealer corpora are inherently archival; every
/// other category defaults to live/current data).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoricalDepthClass {
    /// Current/real-time data only.
    Live,
    /// Recent history within a bounded rolling window.
    RollingWindow,
    /// Long historical range (breach corpora, archived records).
    DeepArchive,
}

/// The canonical per-provider capability + economics descriptor. See the
/// module doc comment for how it's derived and why every field exists.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ProviderDescriptor {
    /// Stable provider identifier. Equal to `module_id` today (one module =
    /// one provider); kept distinct in case a future provider ever backs
    /// more than one module.
    pub provider_id: &'static str,
    /// `Module::name()`.
    pub module_id: &'static str,
    /// `Module::category()`, under this descriptor's naming.
    pub source_class: ModuleCategory,
    /// `Module::consumes()` — the `TargetKind`s this provider dispatches on.
    pub supported_seed_types: Vec<TargetKind>,
    /// How this provider is accessed — see [`AccessClass`].
    pub access_class: AccessClass,
    /// Which dispatch tier this provider escalates into — see
    /// [`EscalationBand`].
    pub escalation_band: EscalationBand,
    /// `Module::cost() != ModuleCost::Free`.
    pub requires_key: bool,
    /// Whether this provider may be re-queried for the same target within a
    /// scan — see [`RecursiveUsePolicy`].
    pub recursive_use_policy: RecursiveUsePolicy,
    /// How long a response from this provider is cached — see
    /// [`CachePolicy`].
    pub cache_policy: CachePolicy,
    /// How this provider's request rate is throttled — see
    /// [`RateLimitPolicy`].
    pub rate_limit_policy: RateLimitPolicy,
    /// Any licensing/usage constraint this provider's data carries — see
    /// [`LicensingPolicy`].
    pub licensing_policy: LicensingPolicy,
    /// Whether — and how precisely — this provider's per-request cost is
    /// known. See [`CostModel`]; note `Unknown` is never treated as `Free`.
    pub cost_model: CostModel,
    /// Operator-configured USD cost per request, via
    /// `HSE_PROVIDER_COST_<PROVIDER_ID>`. Always `None` unless explicitly
    /// configured — never a compiled-in vendor price.
    pub cost_per_request: Option<f64>,
    /// The unit a provider's locally-tracked quota is denominated in (e.g.
    /// `"lookup"` for oathnet, `"credit"` for see_know), or `None` when
    /// nothing local is tracked.
    pub quota_unit: Option<&'static str>,
    /// How far back in time this provider's data reaches — see
    /// [`HistoricalDepthClass`].
    pub historical_depth_class: HistoricalDepthClass,
    /// `[0, 1]`. Neutral (`0.5`) by default — no existing signal to derive
    /// this from; a handful of modules whose doc comments make an explicit
    /// fidelity claim override it (see `provider_overrides_tests`).
    pub provenance_quality_prior: f64,
    /// `[0, 1]`. Neutral (`0.5`) by default, same rationale.
    pub uniqueness_prior: f64,
    /// `[0, 1]`. Neutral (`0.5`) by default, same rationale.
    pub reliability_prior: f64,
    /// `[0, 1]`. Derived from the existing, real
    /// [`crate::core::convex::module_cascade`] signal (`produces()` +
    /// `category()`) rather than a fresh neutral default — this is the one
    /// prior with a genuine pre-existing analogue (see the module doc
    /// comment and `docs/REQUIREMENTS_LEDGER.md`'s provider-capability
    /// section for the full rationale).
    pub optionality_prior: f64,
}

/// Neutral prior used for the three quality dimensions with no existing
/// signal to derive from (see the struct field docs).
const NEUTRAL_PRIOR: f64 = 0.5;

/// Build the mechanically-derived default descriptor for `module` from its
/// existing trait methods. This is what [`Module::provider_descriptor`]'s
/// default body calls; kept as a free function so the handful of overriding
/// modules can call it too and only patch the fields that genuinely differ
/// (see e.g. `oathnet_pro`'s `impl Module`), rather than re-listing every
/// field from scratch.
pub fn derive_default<M: Module + ?Sized>(module: &M) -> ProviderDescriptor {
    let cost = module.cost();
    let is_passive = module.is_passive();
    let escalates = module.is_high_value_only() || module.requires_geo_corroboration();

    let access_class = match cost {
        ModuleCost::Free => AccessClass::Keyless,
        ModuleCost::KeyGated => AccessClass::FreeAccount,
        ModuleCost::Paid => AccessClass::Paid,
    };
    let escalation_band = if is_passive {
        EscalationBand::L0Local
    } else if escalates {
        EscalationBand::L4Specialist
    } else {
        match cost {
            ModuleCost::Free => EscalationBand::L1FreePublic,
            ModuleCost::KeyGated => EscalationBand::L2FreeQuota,
            ModuleCost::Paid => EscalationBand::L3Microcost,
        }
    };
    let cost_model = match cost {
        ModuleCost::Free => CostModel::Free,
        // UNKNOWN != FREE: a key-gated or paid module's true cost is
        // unknown until an operator configures it, never assumed free.
        ModuleCost::KeyGated | ModuleCost::Paid => CostModel::Unknown,
    };
    let category = module.category();

    ProviderDescriptor {
        provider_id: module.name(),
        module_id: module.name(),
        source_class: category,
        supported_seed_types: module.consumes(),
        access_class,
        escalation_band,
        requires_key: cost != ModuleCost::Free,
        recursive_use_policy: if cost == ModuleCost::Free {
            RecursiveUsePolicy::Unrestricted
        } else {
            RecursiveUsePolicy::OncePerTargetPerScan
        },
        cache_policy: match module.cache_ttl_secs() {
            0 => CachePolicy::Disabled,
            secs => CachePolicy::TtlSeconds(secs),
        },
        rate_limit_policy: if is_passive {
            RateLimitPolicy::None
        } else {
            RateLimitPolicy::SharedHostCircuitBreaker
        },
        licensing_policy: LicensingPolicy::Unspecified,
        cost_model,
        cost_per_request: env_cost_per_request(module.name()),
        quota_unit: None,
        historical_depth_class: if category == ModuleCategory::Breach {
            HistoricalDepthClass::DeepArchive
        } else {
            HistoricalDepthClass::Live
        },
        provenance_quality_prior: NEUTRAL_PRIOR,
        uniqueness_prior: NEUTRAL_PRIOR,
        reliability_prior: NEUTRAL_PRIOR,
        optionality_prior: crate::core::convex::module_cascade(module.produces(), category),
    }
}

/// Operator-configured USD cost per request for `provider_id`, read from
/// `HSE_PROVIDER_COST_<PROVIDER_ID_UPPERCASED>` (e.g. `HSE_PROVIDER_COST_SEE_KNOW`
/// for `see_know`). `None` when unset or [`parse_cost_per_request`] rejects
/// the value — this is the ONLY place a provider's monetary cost may enter
/// the codebase, deliberately never a compiled-in literal, since vendor
/// prices change (see the module doc comment).
pub fn env_cost_per_request(provider_id: &str) -> Option<f64> {
    let var = format!("HSE_PROVIDER_COST_{}", provider_id.to_ascii_uppercase());
    std::env::var(var)
        .ok()
        .and_then(|v| parse_cost_per_request(&v))
}

/// The parsing/validation half of [`env_cost_per_request`], split out so it's
/// unit-testable without mutating process environment (this crate forbids
/// `unsafe_code`, which `std::env::set_var` requires). `None` for anything
/// non-numeric, non-finite, or negative — a malformed or nonsensical
/// operator-supplied value must fall back to "not configured", not panic or
/// silently clamp to zero.
fn parse_cost_per_request(raw: &str) -> Option<f64> {
    raw.trim()
        .parse::<f64>()
        .ok()
        .filter(|v| v.is_finite() && *v >= 0.0)
}

/// The eligibility gate: true iff a finite monetary budget is active
/// (`max_cost_usd.is_some()`), the provider is paid/enterprise access with
/// an unknown cost, and the operator has not explicitly opted into
/// unknown-cost dispatch. This is a hard gate checked BEFORE ranking, not a
/// ranking penalty — see `crate::core::engine::dispatch::module_skip_reason`,
/// which calls this directly.
#[must_use]
pub fn unknown_cost_paid_provider_blocked(
    descriptor: &ProviderDescriptor,
    max_cost_usd: Option<f64>,
    allow_unknown_cost_dispatch: bool,
) -> bool {
    if allow_unknown_cost_dispatch || max_cost_usd.is_none() {
        return false;
    }
    matches!(
        descriptor.access_class,
        AccessClass::Paid | AccessClass::Enterprise
    ) && descriptor.cost_model == CostModel::Unknown
}

#[cfg(test)]
mod tests {
    include!("provider_tests.rs");
}
