//! Expansion economics: the geometric yield model that drives adaptive depth,
//! per-kind expansion weighting, and corroboration priors. Pure functions over
//! `TargetKind` / confidence — no scan state — split out of `scan` so the data
//! types and the scoring model read separately. Re-exported from the parent so
//! external paths (`crate::core::scan::expansion_weight`, …) are unchanged.

use super::{
    ExpansionStrategy, MARGINAL_YIELD_FLOOR, MAX_DEPTH, TargetKind, domain_expansion_factor,
};

/// Expected marginal yield of the **first** expansion round (round 1) for a
/// seed of `kind` at the given API tier — `m₁` in the geometric yield model
/// `m(d) = m₁ · q^(d−1)` used by [`optimal_depth`]. Units: new graph-advancing
/// entities per dispatched pivot.
///
/// Anchored to the two live Termux scans in the validation transcript:
///   * a `FullName` seed surfaced 446 seed-round entities (oathnet 374,
///     name_intel 51, social_probe 3, qld 18) → a dense round-1 pivot pool;
///   * a `Username` seed surfaced 91 (username_search 65, social_probe 19,
///     oathnet 6, variants 1) → a sparser pool.
///
/// The ordering `FullName (2.9) > Username (2.4)` reproduces that 446 ≫ 91 gap.
/// Unobserved kinds are placed by their expandable-pivot fan-out: identity
/// seeds richest; terminal geo/registry seeds (Coordinates, AbnAcn, ApiKey)
/// sit near the 1.0 "one weak pivot" floor. Paid keys raise the ceiling
/// because OathNet/IntelX re-queries on round-1 discoveries keep the frontier
/// novel for an extra round instead of re-confirming.
pub(super) fn seed_marginal_yield(kind: TargetKind, has_paid_keys: bool) -> f64 {
    let (paid, free) = match kind {
        // Identity seeds — richest expandable fan-out (emails → usernames →
        // domains → socials), and the only kinds the paid tier can keep novel
        // for a third round.
        TargetKind::Email => (3.2, 2.0),
        TargetKind::FullName => (2.9, 1.9),
        TargetKind::Username => (2.4, 1.6),
        TargetKind::Domain => (2.2, 1.7),
        // High-value geo pivots — one or two reliable hops to coordinates.
        TargetKind::Address => (1.9, 1.5),
        TargetKind::IpAddress | TargetKind::Cidr => (1.6, 1.25),
        TargetKind::MacAddress => (1.4, 1.4),
        // Mid fan-out — a handful of corroborating leads per round.
        TargetKind::Phone => (1.6, 1.15),
        TargetKind::Asn => (1.6, 1.2),
        TargetKind::Organisation => (1.6, 1.2),
        TargetKind::Url => (1.55, 1.2),
        // Terminal / registry seeds — resolve and stop.
        TargetKind::AbnAcn => (1.3, 1.1),
        TargetKind::Coordinates => (1.2, 1.2),
        TargetKind::ApiKey => (1.1, 1.0),
        // A wallet address enriches to on-chain activity then stops — terminal,
        // a single reliable hop with no identity fan-out.
        TargetKind::CryptoAddress => (1.1, 1.05),
        // A cell tower ID resolves to a coordinate via OpenCelliD — terminal,
        // single-hop: tower → location.
        TargetKind::DeviceId => (1.2, 1.2),
    };
    if has_paid_keys { paid } else { free }
}

/// Per-round retention `q ∈ (0,1)` — the fraction of a round's marginal yield
/// carried into the next round before re-confirmation and frontier drift erode
/// it. Identity seeds retain most (each round still surfaces independent new
/// pivots); geo/terminal seeds collapse fast once the coordinate/address is
/// resolved. Combined with [`seed_marginal_yield`] this fixes the shape of the
/// decay curve [`optimal_depth`] integrates.
fn round_retention(kind: TargetKind) -> f64 {
    match kind {
        TargetKind::Email | TargetKind::FullName | TargetKind::Username | TargetKind::Domain => {
            0.60
        }
        TargetKind::Address | TargetKind::MacAddress => 0.55,
        TargetKind::IpAddress | TargetKind::Cidr | TargetKind::Asn | TargetKind::Organisation => {
            0.52
        }
        TargetKind::Phone | TargetKind::Url => 0.50,
        TargetKind::AbnAcn => 0.45,
        TargetKind::Coordinates
        | TargetKind::ApiKey
        | TargetKind::CryptoAddress
        | TargetKind::DeviceId => 0.40,
    }
}

/// Predicted marginal yield of expansion `round` (1-indexed) for a seed of
/// `kind` — the geometric decay `m(round) = m₁ · q^(round−1)`. Exposed so the
/// depth choice in [`optimal_depth`] and its statistical invariants are
/// machine-checkable (see tests), and so callers can reason about the curve.
#[must_use]
pub fn predicted_marginal_yield(kind: TargetKind, has_paid_keys: bool, round: u32) -> f64 {
    let m1 = seed_marginal_yield(kind, has_paid_keys);
    let q = round_retention(kind);
    m1 * q.powi(i32::try_from(round.saturating_sub(1)).unwrap_or(0))
}

/// Confidence floor for `--auto` expansion, scaled with the scheduled depth.
/// Deeper auto-scans raise the bar — each extra round compounds false-positive
/// risk through `c_eff`, so a higher floor keeps expected precision roughly
/// constant across rounds; the paid tier starts marginally lower because its
/// leads arrive better-corroborated. Clamped to a sane `[0.40, 0.55]` band.
pub(super) fn auto_min_expand_confidence(depth: u32, has_paid_keys: bool) -> f64 {
    let base = if has_paid_keys { 0.42 } else { 0.46 };
    (base + 0.03 * f64::from(depth.saturating_sub(1))).clamp(0.40, 0.55)
}

/// Statistically-grounded expansion depth for a seed and API tier, via a
/// geometric **yield-curve** model rather than hand-tuned per-kind constants.
///
/// The previous constants (4–5 per kind) were silently flattened by the
/// [`MAX_DEPTH`] = 3 clamp — every kind resolved to depth 3 — so depth carried
/// no signal. This model instead schedules the *largest round whose predicted
/// marginal yield still clears [`MARGINAL_YIELD_FLOOR`]*:
///
/// ```text
///   m(d) = m₁ · q^(d−1)                          (geometric decay of new/dispatch)
///   D*   = max{ d ∈ 1..=MAX_DEPTH : m(d) ≥ floor }    (≥ 1 — one round is cheap)
/// ```
///
/// where `m₁` = [`seed_marginal_yield`] (anchored to the live transcript:
/// FullName 446 vs Username 91 seed entities) and `q` = [`round_retention`].
/// This is the same `dE/dDispatch → 0` cutoff the engine enforces at runtime
/// via [`crate::core::roi::should_terminate_adaptive`]; computing it ahead of
/// time lets `--auto` stop one round *before* paying for a round the curve
/// already predicts is re-confirmation. Net effect: rich identity seeds earn
/// the full depth-3 budget with paid keys and depth 2 keyless, while terminal
/// seeds (Coordinates/AbnAcn/ApiKey) correctly resolve at depth 1 — the
/// differentiation the old constants intended but the clamp erased.
///
/// Returns `(depth, min_expand_confidence)`.
pub fn optimal_depth(kind: TargetKind, has_paid_keys: bool) -> (u32, f64) {
    // Walk the curve outward and keep the last round that clears the floor.
    // Floor at 1: a single expansion round is cheap and almost always pays,
    // and the runtime adaptive guard cuts it short anyway if it doesn't.
    let mut depth: u32 = 1;
    for round in 1..=MAX_DEPTH {
        // `- f64::EPSILON` admits a round whose predicted yield sits exactly on
        // the floor (e.g. Url paid R2) rather than letting FP error drop it.
        if predicted_marginal_yield(kind, has_paid_keys, round)
            >= MARGINAL_YIELD_FLOOR - f64::EPSILON
        {
            depth = round;
        } else {
            break;
        }
    }
    (depth, auto_min_expand_confidence(depth, has_paid_keys))
}

/// Geo-specific NPV: expected Coordinates + Address entity yield.
///
/// v2.0 recalibration for 79-module pipeline. New geo paths:
///   Email: +email_header_geo, +email_locale, +seon, +epieos, +contact_enrich
///   Phone: +phone_area_geo, +phone_carrier_geo
///   Username: +social_location (GitHub/Reddit profile location extraction)
///   Domain: +geo_domain_classifier (ccTLD/service → country)
///   Organisation: +cloud_storage exposure scanning → domain → geo
///   Address: +geocode/photon bidirectional, +overpass infrastructure
///   IP: +abuseipdb country_code, +bgpview ASN→prefix→geo
pub fn geo_npv(kind: TargetKind, has_paid_keys: bool) -> f64 {
    match kind {
        TargetKind::Email => {
            if has_paid_keys {
                68.0
            } else {
                22.5
            }
        }
        TargetKind::FullName => {
            if has_paid_keys {
                58.0
            } else {
                28.0
            }
        }
        TargetKind::Domain => 32.0,
        TargetKind::IpAddress | TargetKind::Cidr => 18.5,
        TargetKind::Username => 20.0,
        TargetKind::Phone => {
            if has_paid_keys {
                16.0
            } else {
                9.5
            }
        }
        TargetKind::Address => 24.0,
        TargetKind::MacAddress => 14.0,
        TargetKind::Asn => 10.5,
        TargetKind::Url => 12.0,
        TargetKind::Organisation => 11.0,
        TargetKind::Coordinates => 8.5,
        TargetKind::AbnAcn => 7.0,
        TargetKind::ApiKey => 3.8,
        // A wallet address carries no geolocation signal of its own.
        TargetKind::CryptoAddress => 2.0,
        // A cell tower ID resolves directly to a coordinate — single-hop, terminal.
        TargetKind::DeviceId => 8.5,
    }
}

/// Composite expansion weight: `geo_npv × c_eff × domain_factor × geo_proximity`.
///
/// - `c_eff` rewards entities confirmed by multiple sources
/// - `domain_factor` dampens known-generic mega-domains (0.15x)
/// - `geo_proximity` boosts entities one hop from Coordinates/Address
///   (IpAddress 1.8x, MacAddress 2.0x, Address 2.2x, Phone 1.5x)
///   so the pipeline converges on geolocation as fast as possible
pub fn expansion_weight(kind: TargetKind, c_eff: f64, value: &str, has_paid_keys: bool) -> f64 {
    let base = geo_npv(kind, has_paid_keys);
    let dampener = if kind == TargetKind::Domain {
        domain_expansion_factor(value)
    } else {
        1.0
    };
    let geo_boost = geo_proximity_boost(kind);
    base * c_eff * dampener * geo_boost
}

/// Strategy-aware expansion weight.
///
/// Each variant of [`ExpansionStrategy`] computes a different primary
/// score so the engine can sort the round's candidate queue with a
/// single comparison. `richness ∈ [0.0, 1.0]` is the normalised
/// module-count yield from [`crate::core::dependency::ModuleGraph`].
///
/// The legacy `expansion_weight()` corresponds exactly to
/// `GeoConverge` with `richness = 1.0`, so callers that haven't
/// migrated still get the established production behaviour.
pub fn expansion_weight_for_strategy(
    strategy: ExpansionStrategy,
    kind: TargetKind,
    c_eff: f64,
    value: &str,
    has_paid_keys: bool,
    richness: f64,
) -> f64 {
    let r = richness.clamp(0.0, 1.0);
    match strategy {
        ExpansionStrategy::GeoConverge => {
            // Established weight, plus a gentle (0.5–1.0) richness lift
            // so two candidates with identical geo weight tie-break on
            // module yield. Reaches 1.0 at the most-served kind.
            expansion_weight(kind, c_eff, value, has_paid_keys) * (0.5 + 0.5 * r)
        }
        ExpansionStrategy::BreadthFirst => {
            // Confidence × richness only. No geo bias, no domain
            // dampener — every confident lead competes flat.
            c_eff * (0.25 + 0.75 * r)
        }
        ExpansionStrategy::DepthFirst => {
            // c_eff dominates; richness used only as a tiebreaker.
            // Multiplying by 1.0 + 0.01·r keeps the order strictly by
            // c_eff for distinct values but breaks ties deterministic-
            // ally toward richer kinds.
            c_eff * (1.0 + 0.01 * r)
        }
        ExpansionStrategy::RichestFirst => {
            // Richness dominates. Confidence is the secondary key —
            // we still gate by `min_expand_confidence` upstream, so
            // letting it act here only as a tiebreaker is safe.
            r * (0.5 + 0.5 * c_eff)
        }
    }
}

/// Multiplicative boost for entity types that are one hop from producing
/// Coordinates or Address entities. Ensures the expansion pipeline
/// prioritises geo-convergent paths over non-geo paths at every round.
fn geo_proximity_boost(kind: TargetKind) -> f64 {
    match kind {
        // Coordinates ARE the terminal node — promote them above Address
        // so geo-rich entities resolve first when both appear in the
        // expansion queue. Was 1.6 (below Address 2.2); now 2.5.
        TargetKind::Coordinates => 2.5,
        // Address with a string value → geocode/photon → Coordinates.
        // Single hop, high reliability.
        TargetKind::Address => 2.2,
        // MAC → wigle/mylnikov → Coordinates. Single hop.
        TargetKind::MacAddress => 2.0,
        // IP → ip_geo/ipinfo → Coordinates. Single hop, highly reliable.
        TargetKind::IpAddress => 1.8,
        // CIDR → enumerated host IPs → ip_geo → Coordinates. Two hops — one
        // further than a bare IP, but firmly geo-convergent: a discovered block
        // resolves to its hosts' locations. Without an explicit arm a Cidr fell
        // through to the non-geo 1.0 default, ranking it BELOW the ASN (1.2)
        // that produced it even though it is one hop CLOSER to coordinates — an
        // inverted ordering. Placed alongside the other two-hop kinds (Phone),
        // restoring ASN(1.2) < Cidr(1.5) < IP(1.8). Consistent with geo_npv /
        // seed_marginal_yield, which already group IpAddress | Cidr as geo-rich.
        TargetKind::Cidr => 1.5,
        // Phone → phone_area_geo/phone_carrier_geo → Country/State. Two hops.
        TargetKind::Phone => 1.5,
        // Organisation → opencorporates → registered address → Coords. Two hops.
        TargetKind::Organisation => 1.3,
        // ASN → bgpview → prefixes → IPs → Coords. Three hops, but each
        // ASN often resolves to a fixed datacenter location.
        TargetKind::Asn => 1.2,
        // DeviceId → OpenCelliD cell/get → Coordinates. Single hop, like IP→geo.
        TargetKind::DeviceId => 1.8,
        _ => 1.0,
    }
}

/// Coefficient on the corroboration prior. Larger than `c_eff`'s 0.15 because
/// ranking can be more assertive than a calibrated confidence — but small
/// enough that corroboration only *refines order within* a geo-proximity tier,
/// never overrides geo-convergence (an 8-source far entity scores ×1.52, still
/// under a 1-source IP's ×1.8 geo boost).
const CORROBORATION_PRIOR_COEFF: f64 = 0.25;

/// Non-saturating ranking multiplier rewarding independent cross-correlation.
///
/// `c_effective()` already folds corroboration in via `1 + 0.15·ln(sources)`,
/// but it is **clamped to 1.0** — so for confident pivots the corroboration
/// signal is erased: a c_eff=1.0 entity confirmed by six independent sources
/// ranks identically to a single-source one. Expansion ranking is exactly
/// where that signal matters most (a cross-corroborated lead is far likelier
/// to be genuine, so its dispatch is likelier to yield real children), so we
/// re-introduce it here as an *uncapped* factor on the expansion weight.
///
/// `1 + β·ln(source_count)` with `source_count ≥ 1`: a single source gives
/// `ln(1)=0 → 1.0` (neutral — no penalty vs today's behaviour), and each
/// additional independent source adds sharply diminishing weight. Uses the
/// distinct-source count (the honest cross-correlation measure), never the
/// inflatable `corroboration` magnitude.
#[must_use]
pub fn corroboration_prior(source_count: u32) -> f64 {
    let sources = f64::from(source_count.max(1));
    CORROBORATION_PRIOR_COEFF.mul_add(sources.ln(), 1.0)
}
