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

use crate::core::entity::EntityKind;
use crate::core::module::{ModuleCategory, ModuleCost};
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
        | TargetKind::DeviceId
        | TargetKind::Ssid => 1.0,
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

// ─────────────────────────────────────────────────────────────────────────────
// Query-level convexity: which *queries* (module dispatches) to fire, and in
// what order, for a given target.
//
// `optionality_multiplier` above ranks which discovered *targets* to pivot on.
// The complementary lever is which of a target's accepting modules to dispatch
// FIRST — because a module dispatch **is** a query (a bounded set of outbound
// HTTP requests that spends the scarce Termux budget: wall-time, battery, and —
// for paid providers — real API quota). Under any truncation of the dispatch
// sequence (`max_entities`, `max_wall_time_secs`, an operator cancel, a dying
// battery) only a *prefix* of that sequence runs, so the ORDER of the queries
// decides the return per unit of budget.
//
// The same barbell shape applies: reward a query's heavy-tailed **optionality**
// (does firing it unlock NEW options — fresh identities, credentials, keys that
// cascade into more cheap high-upside queries?) and divide by its **cost** (a
// keyless local read is ~free; a paid provider burns quota). The left end of
// the barbell — cheap, keyless, identity-/key-unlocking modules — fires first;
// the right end — expensive, terminal, one-and-done providers — fires last. So
// a scan cut short by the phone's budget has already spent it on the queries
// that compound. This is a pure, deterministic function of module metadata, so
// the ordering is precomputed once (see [`crate::core::dependency::ModuleGraph`])
// and is byte-identical run to run.
// ─────────────────────────────────────────────────────────────────────────────

/// Relative **dispatch cost** of firing one module — how much of the bounded
/// budget one query of it consumes. A passive/local-sensor module makes no
/// network call at all (a device read: GPS, ARP, interface list), so it is the
/// cheapest query there is; a keyless HTTP module is the "free" unit; a key-gated
/// provider costs more (a registered credential, still a bounded resource); a
/// paid provider is dearest because each query burns metered quota that refills
/// slowly. Always ≥ the passive floor: a query never costs less than a local read.
fn module_dispatch_cost(cost: ModuleCost, is_passive: bool) -> f64 {
    if is_passive {
        // No network, no quota — only battery. The barbell's far-left anchor.
        return 0.8;
    }
    match cost {
        ModuleCost::Free => 1.0,
        ModuleCost::KeyGated => 1.5,
        ModuleCost::Paid => 2.5,
    }
}

/// Optionality of **producing** an entity of this kind: how heavy-tailed the new
/// query surface it opens is. Identity and credential kinds are the barbell's
/// high-upside end — an email, a username, or a person fans out into many cheap
/// downstream identity lookups, and a discovered key/credential is a literal
/// query *multiplier* (it unlocks a whole authenticated provider, i.e. more
/// queries, mirroring [`crate::util::key_roi::KeyRoi::Multiplier`]). Terminal
/// GEOINT and scoring kinds (a coordinate, an abuse score) resolve and stop, so
/// they carry little optionality. In `[0, 1]`.
fn entity_cascade(kind: &EntityKind) -> f64 {
    match kind {
        // Richest identity fan-out — the seed kinds a whole scan is built to chase.
        EntityKind::Person | EntityKind::Email | EntityKind::Username => 1.0,
        // A credential/key unlocks an authenticated provider → MORE queries. The
        // highest-ROI thing a query can surface (KeyRoi::Multiplier).
        EntityKind::ApiKey | EntityKind::Credential | EntityKind::Password => 1.0,
        // Identity-adjacent, moderate fan-out.
        EntityKind::Phone => 0.75,
        EntityKind::Domain => 0.70,
        EntityKind::Organisation | EntityKind::AbnAcn => 0.60,
        // Crawlable — may still surface identities/keys, but noisier.
        EntityKind::Url => 0.45,
        // Fans out, but predominantly into more (saturating) infrastructure.
        EntityKind::IpAddress | EntityKind::Asn | EntityKind::Cidr => 0.40,
        // Single-hop-to-geo / co-ownership pivots — bounded, near-terminal.
        EntityKind::MacAddress | EntityKind::DeviceId | EntityKind::Ssid => 0.30,
        EntityKind::TrackingId | EntityKind::CryptoAddress => 0.30,
        // Terminal GEOINT — the pipeline's convergence point, no new query surface.
        EntityKind::Address | EntityKind::Coordinates => 0.20,
        // Undeclared/other → conservative.
        EntityKind::Other(_) => 0.20,
    }
}

/// Optionality implied by a module's functional **category** — the always-present
/// fallback signal for a module that has not declared its `produces()` outputs
/// (the trait default is empty). The category already encodes what class of
/// collection the module performs, which is a faithful proxy for whether its
/// output cascades: breach/people/social/email collection surfaces identities and
/// credentials (high optionality); geo/threat collection is terminal scoring
/// (low). In `[0, 1]`.
fn category_cascade(category: ModuleCategory) -> f64 {
    match category {
        // Breach corpora / stealer logs → credentials + emails + usernames: the
        // richest cascade surface a free query has (feeds key_harvest → more keys).
        ModuleCategory::Breach => 0.95,
        // People enrichment (proxycurl/epieos/keybase) → emails/usernames/persons.
        ModuleCategory::People => 0.90,
        // Username-search across platforms → new personas and handles.
        ModuleCategory::Social => 0.80,
        // Email parse/verify → usernames, domains, provider pivots.
        ModuleCategory::Email => 0.75,
        // SERP scraping surfaces everything — URLs, emails, domains, docs.
        ModuleCategory::Search => 0.70,
        // Company registry → officers (people) and registered domains.
        ModuleCategory::Corporate => 0.60,
        // DNS/cert/subdomain → domains and occasional identity leakage.
        ModuleCategory::DnsRecon => 0.45,
        // Site/app crawl → can surface keys/identities amid a lot of noise.
        ModuleCategory::Web => 0.45,
        // Carrier/area-code metadata → moderate, region-bound.
        ModuleCategory::Phone => 0.45,
        // IP/ASN/BGP → mostly more (saturating) infrastructure.
        ModuleCategory::Infrastructure => 0.40,
        // Local device sensors — terminal reads, but zero-cost (priced in cost).
        ModuleCategory::Sensor => 0.25,
        // Abuse/malware/C2 scoring → terminal verdicts.
        ModuleCategory::Threat => 0.25,
        // Geocode/BSSID/address → terminal coordinates.
        ModuleCategory::Geo => 0.20,
        // Uncategorised → neutral.
        ModuleCategory::Other => 0.40,
    }
}

/// A module's overall **cascade optionality** in `[0, 1]`: the heavy-tailed upside
/// of firing one query of it. Takes the MAX of its declared-output optionality
/// ([`entity_cascade`] over each kind it `produces()`) and its category proxy
/// ([`category_cascade`]) — the *max*, because optionality is heavy-tailed: a
/// module that can surface even one identity/key is worth the premium regardless
/// of what else it emits, and the category floor keeps the estimate faithful for
/// the many modules that have not yet declared their outputs.
pub fn module_cascade(produces: &[EntityKind], category: ModuleCategory) -> f64 {
    let from_outputs = produces.iter().map(entity_cascade).fold(0.0_f64, f64::max);
    from_outputs.max(category_cascade(category)).clamp(0.0, 1.0)
}

/// The convex **query value** of dispatching one module — its optionality premium
/// over its dispatch cost:
///
/// `(1 + λ·cascade) / cost(module)`
///
/// Higher = fire earlier under a bounded budget. A cheap, keyless,
/// identity-/key-unlocking module (cascade ≈ 1, cost = 1 → ×2) leads; a terminal
/// paid provider (cascade ≈ 0.2, cost = 2.5 → ×0.48) trails. Purely a function of
/// static module metadata (cost, passivity, produced kinds, category), so the
/// resulting dispatch order is deterministic and can be precomputed once at engine
/// construction — it never touches per-scan state, and never changes *which*
/// modules run, only the order in which the budget reaches them.
pub fn query_value(cost: ModuleCost, is_passive: bool, cascade: f64) -> f64 {
    let premium = CONVEXITY_LAMBDA.mul_add(cascade.clamp(0.0, 1.0), 1.0);
    premium / module_dispatch_cost(cost, is_passive)
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
