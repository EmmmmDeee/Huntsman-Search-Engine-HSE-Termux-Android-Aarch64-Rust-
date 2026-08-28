//! Standard confidence values for entity emission across all modules.
//! Using consistent confidence levels ensures comparability across diverse
//! extraction sources and allows tuning signal strength globally.
//!
//! # Reading the ladder
//!
//! Constants are declared in **ascending numeric order**, and that order is
//! the authority — the `_PLUS` / `_HIGH` name suffixes are *not* a reliable
//! ranking. Two pairs in particular do not rank the way their names suggest:
//!
//! - [`MEDIUM_HIGH`] (0.55) sits *below* [`MEDIUM_PLUS`] (0.60).
//! - [`VERY_HIGH`] (0.75) sits *below* [`HIGH_PLUSPLUS`] (0.80) and
//!   [`HIGH_PLUSPLUS_PLUS`] (0.85).
//!
//! These values are load-bearing: ~800 call sites across the crate already
//! encode them, and every persisted entity score derives from them, so the
//! numbers are deliberately left as-is. Pick a constant by the **number you
//! want**, confirmed against this list, never by which name sounds stronger.
//! `ladder_is_ascending` below pins the order so it cannot silently drift.

/// No signal — for entity validation gates only, never emitted.
pub const ZERO: f64 = 0.00;

/// Very low confidence — stray signal or weak contextual match.
pub const VERY_LOW: f64 = 0.25;

/// Speculative — geo-inferred from email headers, crowd-triangulated, or
/// otherwise derived from an indirect signal with no confirming source.
pub const SPECULATIVE: f64 = 0.30;

/// Tentative — code-search or loose enrichment result; plausible but not
/// structurally confirmed by the emitting source.
pub const TENTATIVE: f64 = 0.35;

/// Low confidence — minimal context or distant source.
pub const LOW: f64 = 0.40;

/// Low-medium confidence — some context, moderate source reliability.
pub const LOW_MEDIUM: f64 = 0.45;

/// Medium confidence — reasonable context or solid source.
pub const MEDIUM: f64 = 0.50;

/// Medium-light — secondary API source; above [`MEDIUM`] but not yet
/// independently corroborated.
pub const MEDIUM_LIGHT: f64 = 0.52;

/// Medium-high confidence — good context and source.
///
/// Note: ranks *below* [`MEDIUM_PLUS`] despite the name.
pub const MEDIUM_HIGH: f64 = 0.55;

/// Medium-solid — org names and URLs from third-party databases; credible
/// single-source data without independent verification.
pub const MEDIUM_SOLID: f64 = 0.58;

/// Medium confidence + — solid context, slightly elevated reliability.
///
/// Note: ranks *above* [`MEDIUM_HIGH`] despite the name.
pub const MEDIUM_PLUS: f64 = 0.60;

/// Notable — reliable single-source entity; structurally present in the
/// source data and well-formed, but not yet cross-validated.
pub const NOTABLE: f64 = 0.62;

/// High confidence — strong context or reliable source.
pub const HIGH: f64 = 0.65;

/// High confidence + — between [`HIGH`] and [`VERY_HIGH`], elevated agreement.
pub const HIGH_PLUS: f64 = 0.70;

/// Attributed — attributed to a reliable authoritative source and
/// structurally verified, but not yet independently cross-validated across
/// a second source.
pub const ATTRIBUTED: f64 = 0.72;

/// Very high confidence — multi-source agreement or very strong context.
///
/// Note: ranks *below* both [`HIGH_PLUSPLUS`] and [`HIGH_PLUSPLUS_PLUS`]
/// despite the name.
pub const VERY_HIGH: f64 = 0.75;

/// Strong corroborated confidence — above the multi-source floor, below
/// authoritative corroboration. Secondary-pivot default for reliable-source
/// discoveries that are not yet independently cross-validated.
pub const STRONG: f64 = 0.78;

/// High confidence ++ — strong corroboration; exceeds [`VERY_HIGH`].
pub const HIGH_PLUSPLUS: f64 = 0.80;

/// Corroborated — independently confirmed by a second source above the
/// [`HIGH_PLUSPLUS`] floor; exceeds strong corroboration but stops short
/// of near-authoritative.
pub const CORROBORATED: f64 = 0.82;

/// High confidence +++ — near-expert level, nearly authoritative.
pub const HIGH_PLUSPLUS_PLUS: f64 = 0.85;

/// Expert confidence — subject-supplied data or authoritative source.
pub const EXPERT: f64 = 0.88;

/// Very high confidence + — exceeds multi-source threshold.
pub const VERY_HIGH_PLUS: f64 = 0.90;

/// Authoritative — primary target record from an authoritative source
/// (e.g. government registry, official directory); highest confidence
/// short of a direct identity assertion.
pub const AUTHORITATIVE: f64 = 0.92;

/// Very high confidence ++ — near-certain agreement across sources.
pub const VERY_HIGH_PLUSPLUS: f64 = 0.95;

/// Certainty — direct identity match or canonical source.
pub const CERTAIN: f64 = 0.99;

/// The step a finding loses when it is *derived* from another finding rather
/// than observed directly — a coordinate inferred from an address, an org
/// re-stated from a registry record. One rung, not a guess: the derived thing is
/// only ever as good as its parent, and strictly weaker.
pub const DERIVATION_STEP: f64 = 0.10;

/// The floor a derived value may not fall below.
///
/// [`ZERO`] is documented "never emitted" — it exists for validation gates — so a
/// chain of derivations must not walk a finding down to it. Set at the value the
/// registry modules already floored at by hand (`abn_lookup`, `opencorporates`,
/// `gleif_lei`), so those sites keep their exact behaviour.
pub const DERIVED_FLOOR: f64 = 0.10;

/// Confidence for a finding derived from `parent`: one [`DERIVATION_STEP`] down,
/// never below [`DERIVED_FLOOR`].
///
/// # Why this is a function and not eleven copies
///
/// Eleven production sites hand-rolled `parent - 0.10`. Four of them
/// (`abn_lookup::parse`, `opencorporates`, `gleif_lei::{transform,family}`)
/// floored the result at `0.10`; the other seven did not — so a parent below
/// `0.10` produced a finding at [`ZERO`], the one value the ladder documents as
/// never emitted. Half the codebase guarded that and half did not, which is
/// exactly the drift a single owner prevents.
///
/// Callers that need a *different* step keep their own arithmetic on purpose:
/// `phone_geo` uses 0.08, and `steam_profile` uses a graded family from 0.05 to
/// 0.33 with its own per-kind floors. Those differences are deliberate, so
/// folding them in here would erase information rather than share it.
///
/// ```
/// use huntsman_search_engine::core::confidence::{self, derived_from};
///
/// // One rung down from a strong parent.
/// assert!((derived_from(confidence::HIGH_PLUSPLUS) - 0.70).abs() < 1e-9);
/// // Never below the floor, however weak the parent.
/// assert_eq!(derived_from(0.05), confidence::DERIVED_FLOOR);
/// assert_eq!(derived_from(confidence::ZERO), confidence::DERIVED_FLOOR);
/// // Never produces the "never emitted" ZERO.
/// assert!(derived_from(confidence::VERY_LOW) > confidence::ZERO);
/// ```
#[must_use]
pub fn derived_from(parent: f64) -> f64 {
    (parent - DERIVATION_STEP).max(DERIVED_FLOOR)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The ladder in declaration order, paired with its name for a legible
    /// failure message.
    const LADDER: &[(&str, f64)] = &[
        ("ZERO", ZERO),
        ("VERY_LOW", VERY_LOW),
        ("SPECULATIVE", SPECULATIVE),
        ("TENTATIVE", TENTATIVE),
        ("LOW", LOW),
        ("LOW_MEDIUM", LOW_MEDIUM),
        ("MEDIUM", MEDIUM),
        ("MEDIUM_LIGHT", MEDIUM_LIGHT),
        ("MEDIUM_HIGH", MEDIUM_HIGH),
        ("MEDIUM_SOLID", MEDIUM_SOLID),
        ("MEDIUM_PLUS", MEDIUM_PLUS),
        ("NOTABLE", NOTABLE),
        ("HIGH", HIGH),
        ("HIGH_PLUS", HIGH_PLUS),
        ("ATTRIBUTED", ATTRIBUTED),
        ("VERY_HIGH", VERY_HIGH),
        ("STRONG", STRONG),
        ("HIGH_PLUSPLUS", HIGH_PLUSPLUS),
        ("CORROBORATED", CORROBORATED),
        ("HIGH_PLUSPLUS_PLUS", HIGH_PLUSPLUS_PLUS),
        ("EXPERT", EXPERT),
        ("VERY_HIGH_PLUS", VERY_HIGH_PLUS),
        ("AUTHORITATIVE", AUTHORITATIVE),
        ("VERY_HIGH_PLUSPLUS", VERY_HIGH_PLUSPLUS),
        ("CERTAIN", CERTAIN),
    ];

    /// Declaration order must equal numeric order. This is the guard that makes
    /// the module docs trustworthy: a reader ranks constants by where they
    /// appear, so a value edit that breaks that correspondence must fail here
    /// rather than silently mislead every future call site.
    #[test]
    fn ladder_is_ascending() {
        for w in LADDER.windows(2) {
            let (lo_name, lo) = w[0];
            let (hi_name, hi) = w[1];
            assert!(
                lo < hi,
                "confidence ladder out of order: {lo_name} ({lo}) must be < {hi_name} ({hi}) \
                 — declaration order is the documented ranking, so either move the constant \
                 or correct its value"
            );
        }
    }

    /// Every level must be a usable probability. `CERTAIN` is deliberately
    /// below 1.0 so no finding is ever emitted as absolute certainty.
    #[test]
    fn ladder_stays_in_unit_range() {
        for &(name, v) in LADDER {
            assert!((0.0..1.0).contains(&v), "{name} ({v}) outside [0.0, 1.0)");
        }
    }

    /// Look a level up by name, which also asserts it is listed in `LADDER`.
    /// Going through the slice keeps the comparisons below runtime values
    /// rather than compile-time constants — the point is to pin the
    /// relationship the module docs describe, not to fold it away.
    fn value_of(name: &str) -> f64 {
        LADDER
            .iter()
            .find(|(n, _)| *n == name)
            .unwrap_or_else(|| panic!("{name} is missing from LADDER"))
            .1
    }

    /// A derived finding is strictly weaker than its parent — the whole claim
    /// the step encodes. Asserted across the real ladder rather than a couple of
    /// hand-picked numbers.
    ///
    /// The qualifier is load-bearing: this holds for every parent **at or above
    /// [`DERIVED_FLOOR`]**. Below the floor the clamp necessarily raises the
    /// result *above* the parent, which is asserted explicitly below rather than
    /// left as an unstated edge. [`ZERO`] is the only ladder rung in that
    /// region, and it is documented as never emitted, so no real parent reaches
    /// it — but the arithmetic says what it says, and a reader deserves to see
    /// that written down.
    #[test]
    fn derivation_is_weaker_than_its_parent_at_or_above_the_floor() {
        for &(name, parent) in LADDER {
            let derived = derived_from(parent);
            if parent < DERIVED_FLOOR {
                assert!(
                    derived > parent,
                    "below the floor, {name} = {parent} must be clamped UP to \
                     {DERIVED_FLOOR}; got {derived}"
                );
                continue;
            }
            assert!(
                derived <= parent,
                "derived_from({name} = {parent}) = {derived} is stronger than its parent"
            );
            if parent > DERIVED_FLOOR + DERIVATION_STEP {
                assert!(
                    derived < parent,
                    "derived_from({name} = {parent}) = {derived} did not step down"
                );
            }
        }
    }

    /// **The behaviour this refactor changed.** Seven of the eleven sites that
    /// hand-rolled the step wrote a bare `parent - 0.10` with no floor, so a
    /// parent at or below `0.10` produced a finding at [`ZERO`] — the one rung
    /// the module docs promise is "never emitted". The other four floored it.
    ///
    /// Written against the *naive* arithmetic those seven used, so it fails if
    /// the floor is ever removed: `VERY_LOW - 0.10 - 0.10` is exactly `0.05`
    /// naively, and a second step from there is negative.
    #[test]
    fn derivation_never_reaches_the_never_emitted_zero() {
        for &(name, parent) in LADDER {
            assert!(
                derived_from(parent) > ZERO,
                "derived_from({name} = {parent}) emitted ZERO, which the ladder \
                 documents as never emitted"
            );
        }

        // A parent already at or under the floor cannot be walked below it.
        assert_eq!(derived_from(ZERO), DERIVED_FLOOR);
        assert_eq!(derived_from(DERIVED_FLOOR), DERIVED_FLOOR);

        // The floor is what keeps every result off ZERO. Pinned once, here, so
        // the loop below can check the floor alone: `next >= DERIVED_FLOOR`
        // then implies `next > ZERO` rather than restating it. Both operands
        // are constants, so this holds at compile time — if the floor is ever
        // lowered onto ZERO, the crate stops building rather than this test
        // failing later.
        const {
            assert!(
                DERIVED_FLOOR > ZERO,
                "DERIVED_FLOOR must sit above ZERO, or nothing stops a derived \
                 finding landing on the never-emitted rung"
            );
        }

        // Chained derivation converges to the floor and stays there; the naive
        // form would have gone negative by the third step.
        let mut c = VERY_LOW;
        for step in 0..10 {
            let next = derived_from(c);
            assert!(
                next >= DERIVED_FLOOR,
                "chained derivation fell to {next} at step {step}"
            );
            c = next;
        }
        assert_eq!(
            c, DERIVED_FLOOR,
            "chained derivation did not settle on the floor"
        );
    }

    /// The four sites that already floored by hand (`abn_lookup::parse`,
    /// `opencorporates`, `gleif_lei::{transform,family}`) must keep their exact
    /// prior behaviour — the refactor is only supposed to change the *unfloored*
    /// sites. This pins that the shared step is byte-identical to what they wrote.
    #[test]
    fn shared_step_matches_the_hand_rolled_floored_form() {
        for &(name, parent) in LADDER {
            let hand_rolled = (parent - 0.10_f64).max(0.10);
            assert!(
                (derived_from(parent) - hand_rolled).abs() < 1e-12,
                "derived_from({name} = {parent}) = {} diverges from the registry \
                 modules' prior `(x - 0.10).max(0.10)` = {hand_rolled}",
                derived_from(parent)
            );
        }
    }

    /// The two documented name/value inversions are real and intentional.
    /// If a future change makes the names honest, this test fails and the
    /// module docs (which warn about exactly these two) must be updated with it.
    #[test]
    fn documented_name_inversions_still_hold() {
        assert!(
            value_of("MEDIUM_HIGH") < value_of("MEDIUM_PLUS"),
            "MEDIUM_HIGH/MEDIUM_PLUS inversion documented in the module header no longer holds"
        );
        assert!(
            value_of("VERY_HIGH") < value_of("HIGH_PLUSPLUS")
                && value_of("VERY_HIGH") < value_of("HIGH_PLUSPLUS_PLUS"),
            "VERY_HIGH/HIGH_PLUSPLUS inversion documented in the module header no longer holds"
        );
    }
}
