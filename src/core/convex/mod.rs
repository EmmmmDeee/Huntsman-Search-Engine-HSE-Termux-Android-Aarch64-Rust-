//! Convex (optionality / barbell) budget allocation for expansion.
//!
//! The engine's base weight ranks an expansion candidate by its **expected**
//! value (confidence × richness × corroboration). That is the right ranking when
//! every probe costs the same and payoffs are symmetric. Under a bounded budget
//! on a low-power Termux device, neither holds:
//!
//!   * **Cost is uneven.** Dispatching an identity lead (an Email, a Username)
//!     fires a handful of cheap keyless lookups; dispatching a Domain or an ASN
//!     fans out into dozens of infrastructure modules that mostly yield more
//!     infrastructure — the very over-indexing a real scan exhibits (thousands
//!     of CDN domains, one person).
//!   * **Payoffs are heavy-tailed.** Most OSINT probes return little; a few
//!     crack the case open. Under a convex payoff `f`, Jensen's inequality gives
//!     `E[f(X)] ≥ f(E[X])` — an *uncertain, high-ceiling* lead is worth more than
//!     a *certain, low* one of the same mean.
//!
//! This module re-weights candidates the way a convex **barbell** strategy does:
//! divide value by **cost** and multiply by a **convexity premium** for upside
//! dispersion. The effect is to spend the scarce budget on many cheap,
//! high-optionality identity probes while starving expensive, already-saturated
//! infrastructure — without touching the base weight when the option is off.
//!
//! Everything here is a pure, deterministic function of scalars; no I/O, no
//! engine state. Opt-in via [`crate::core::scan::ScanOptions::convex_budget`].

use crate::core::scan::TargetKind;

/// Strength of the convexity premium. A maximally heavy-tailed lead (`tail = 1`)
/// has its weight doubled before the cost divide; a fully-explored lead
/// (`tail = 0`) gets no premium. Chosen at 1.0 so the premium is meaningful but
/// never dominates the base expected-value signal (it can at most double it).
const CONVEXITY_LAMBDA: f64 = 1.0;

/// Coefficient on the log-dampening of upside by exploration. Each additional
/// independent source that has already confirmed a lead shrinks its remaining
/// optionality (there is less left to discover). Matches the gentle,
/// diminishing shape the rest of the scoring uses for corroboration.
const TAIL_EXPLORATION_COEFF: f64 = 0.5;

/// Relative **dispatch cost** of expanding a target of this kind — how much of
/// the bounded budget its dispatch is expected to consume. Identity and terminal
/// geo kinds are cheap (a few keyless lookups); infrastructure kinds are dear
/// because they fan out into large module sets that predominantly surface *more
/// infrastructure*. Always ≥ 1.0: a probe never costs less than "free".
///
/// This is the lever that makes a convex scan resist infrastructure skew — an
/// ASN or a mega-domain must clear a higher optionality bar than an Email to win
/// the same slice of budget.
fn dispatch_cost(kind: TargetKind) -> f64 {
    match kind {
        // Cheap, identity-bearing, high-yield-per-dispatch, plus the terminal
        // geo / registry leads (bounded, a hop or two from done).
        TargetKind::Email
        | TargetKind::Username
        | TargetKind::Phone
        | TargetKind::FullName
        | TargetKind::Coordinates
        | TargetKind::Address
        | TargetKind::MacAddress
        | TargetKind::AbnAcn
        | TargetKind::CryptoAddress
        | TargetKind::ApiKey
        | TargetKind::DeviceId => 1.0,
        TargetKind::Organisation => 1.3,
        TargetKind::Url => 1.5,
        // Infrastructure: each dispatch fans into a large, mostly self-referential
        // module set. Priced up so the convex allocator only spends budget here
        // when the option value genuinely warrants it.
        TargetKind::IpAddress => 1.8,
        TargetKind::Cidr => 2.0,
        TargetKind::Domain => 2.2,
        TargetKind::Asn => 2.5,
        // Tracking IDs fan out to co-owned domains — bounded, terminal pivot.
        TargetKind::TrackingId => 1.0,
    }
}

/// The **upside tail** of a candidate in `[0, 1]`: how heavy-tailed its remaining
/// payoff is. High when a lead is information-*rich* (many entity kinds it could
/// still unlock) yet *uncertain* and lightly explored — the leads where a probe
/// might crack something open. It decays toward 0 as confidence rises and as
/// independent sources accumulate (a confirmed, saturated lead has little left
/// to give).
///
/// `tail = richness · (1 − c_eff) / (1 + β·ln(source_count))`, clamped to `[0,1]`.
fn upside_tail(source_count: u32, c_eff: f64, richness: f64) -> f64 {
    let r = richness.clamp(0.0, 1.0);
    let uncertainty = (1.0 - c_eff.clamp(0.0, 1.0)).max(0.0);
    let explored = TAIL_EXPLORATION_COEFF.mul_add(f64::from(source_count.max(1)).ln(), 1.0);
    (r * uncertainty / explored).clamp(0.0, 1.0)
}

/// The convex re-weighting multiplier applied to a candidate's base expansion
/// weight under [`crate::core::scan::ScanOptions::convex_budget`]:
///
/// `(1 + λ·tail) / cost(kind)`
///
/// The numerator is the convexity premium (optionality reward); the denominator
/// is the dispatch cost. A cheap, rich, unconfirmed identity lead is lifted
/// (premium ≈ 2, cost = 1 → ×2); a confirmed mega-domain is damped (premium ≈ 1,
/// cost = 2.2 → ×0.45). A cheap, fully-explored lead lands near ×1, so the
/// confident identity core keeps its order — the premium only re-sorts the
/// uncertain tail and the expensive infrastructure.
pub fn optionality_multiplier(
    kind: TargetKind,
    source_count: u32,
    c_eff: f64,
    richness: f64,
) -> f64 {
    let premium = CONVEXITY_LAMBDA.mul_add(upside_tail(source_count, c_eff, richness), 1.0);
    premium / dispatch_cost(kind)
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
