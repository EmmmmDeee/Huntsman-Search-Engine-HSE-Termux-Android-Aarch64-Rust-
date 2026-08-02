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
