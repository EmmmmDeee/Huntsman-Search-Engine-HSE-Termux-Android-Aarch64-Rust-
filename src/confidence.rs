//! Effective confidence from corroboration. Rebuilt from the monolith's `hse-core`
//! `Entity::c_effective`, `Classification`, and depth decay. Pure, no I/O.
//!
//! `C_eff = clamp(max(C * (1 + 0.15 ln n), 1 - (1 - C) * 0.65^(n - 1)), 0, 1)`
//! where `n` is the number of independent sources.
//!
//! What changed from the monolith: the doubt kept per extra source was a fixed 0.65,
//! so five independent sources of confidence 0.05 each reached 0.83 (Verified) and
//! even a zero-confidence claim reached it. Doubt now shrinks no faster than the
//! source's own doubt, `max(0.65, 1 - C)`, which is the noisy-OR bound for weak
//! sources and is identical to the monolith for `C >= 0.35`. Also, `n` was a count of distinct source labels, so
//! two mirrors of one dump counted twice. [`effective_from_ancestry`] counts
//! independent root families from the evidence graph instead. Non-finite or
//! out-of-range confidence is clamped to [0, 1] (NaN is 0), so a bad input can
//! never raise a tier. Depth decay refuses a base above 1, which would have
//! amplified confidence.

use crate::evidence_ancestry::{AncestryError, EvidenceAncestryGraph, EvidenceNodeId};

/// Boost per `ln n` in the multiplicative term.
pub const CORROBORATION_COEFF: f64 = 0.15;
/// Residual doubt kept per additional independent source.
pub const CORROBORATION_DOUBT_DECAY: f64 = 0.65;
/// Lower bound of the Verified tier.
pub const VERIFIED_MIN: f64 = 0.75;
/// Lower bound of the Probable tier.
pub const PROBABLE_MIN: f64 = 0.40;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Classification {
    Candidate,
    Probable,
    Verified,
}

impl Classification {
    /// A non-finite value is `Candidate`, the conservative tier.
    #[must_use]
    pub fn from_effective(c_eff: f64) -> Self {
        if c_eff >= VERIFIED_MIN {
            Self::Verified
        } else if c_eff >= PROBABLE_MIN {
            Self::Probable
        } else {
            Self::Candidate
        }
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Candidate => "CANDIDATE",
            Self::Probable => "PROBABLE",
            Self::Verified => "VERIFIED",
        }
    }
}

fn unit(x: f64) -> f64 {
    if x.is_nan() { 0.0 } else { x.clamp(0.0, 1.0) }
}

/// Effective confidence for `confidence` backed by `sources` independent sources.
/// Zero sources is floored to one: a lone observation is one source. The result is
/// in [`confidence`, 1], never below the input, and non-decreasing in `sources`.
#[must_use]
pub fn effective(confidence: f64, sources: u32) -> f64 {
    let c = unit(confidence);
    let n = f64::from(sources.max(1));
    let multiplicative = c * CORROBORATION_COEFF.mul_add(n.ln(), 1.0);
    let decay = CORROBORATION_DOUBT_DECAY.max(1.0 - c);
    let agreement = 1.0 - (1.0 - c) * decay.powf(n - 1.0);
    multiplicative.max(agreement).clamp(c, 1.0)
}

/// [`effective`] with `n` taken as independent root families behind `support`.
/// Two mirrors of one dump are one source. Fails closed on unknown ancestry.
///
/// # Errors
/// A missing node or a cycle in the ancestry of any support node.
pub fn effective_from_ancestry(
    confidence: f64,
    graph: &EvidenceAncestryGraph,
    support: &[EvidenceNodeId],
) -> Result<f64, AncestryError> {
    let n = graph.independent_support_count(support)?;
    Ok(effective(confidence, u32::try_from(n).unwrap_or(u32::MAX)))
}

/// Discount for distance from the seed: `c_eff * base^generation`, in [0, 1].
/// `base` must be in (0, 1]; anything else is `None`, because a base above 1 would
/// turn a discount into a boost.
#[must_use]
pub fn depth_decayed(c_eff: f64, base: f64, generation: u32) -> Option<f64> {
    if !(base > 0.0 && base <= 1.0) {
        return None;
    }
    let exp = i32::try_from(generation).unwrap_or(i32::MAX);
    Some((unit(c_eff) * base.powi(exp)).clamp(0.0, 1.0))
}

#[cfg(test)]
#[allow(clippy::float_cmp)] // exact 0.0/1.0 sentinels are the contract under test
mod tests {
    use super::*;
    use crate::evidence_ancestry::EvidenceAncestryNode;

    #[test]
    fn documented_values() {
        assert!((effective(0.6, 1) - 0.6).abs() < 1e-12);
        assert!(
            (effective(0.6, 2) - 0.74).abs() < 0.005,
            "{}",
            effective(0.6, 2)
        );
        assert!(
            (effective(0.6, 3) - 0.831).abs() < 0.001,
            "{}",
            effective(0.6, 3)
        );
        assert_eq!(
            Classification::from_effective(effective(0.6, 3)),
            Classification::Verified
        );
        assert_eq!(
            Classification::from_effective(0.9),
            Classification::Verified
        );
        assert_eq!(
            Classification::from_effective(0.5),
            Classification::Probable
        );
        assert_eq!(
            Classification::from_effective(0.2),
            Classification::Candidate
        );
    }

    #[test]
    fn bounded_never_below_input_and_monotone_over_a_grid() {
        for ci in 0..=100 {
            let c = f64::from(ci) / 100.0;
            let mut prev = c;
            for n in 0..=60u32 {
                let e = effective(c, n);
                assert!((c..=1.0).contains(&e), "c={c} n={n} e={e}");
                assert!(e >= prev - 1e-12, "not monotone in n: c={c} n={n}");
                prev = e;
            }
        }
        for n in 1..=20u32 {
            let mut prev = 0.0;
            for ci in 0..=100 {
                let e = effective(f64::from(ci) / 100.0, n);
                assert!(e >= prev - 1e-12, "not monotone in c at n={n}");
                prev = e;
            }
        }
    }

    /// The monolith's formula, kept as a differential oracle.
    fn legacy(c: f64, n: u32) -> f64 {
        let n = f64::from(n.max(1));
        let m = c * CORROBORATION_COEFF.mul_add(n.ln(), 1.0);
        let a = 1.0 - (1.0 - c) * CORROBORATION_DOUBT_DECAY.powf(n - 1.0);
        m.max(a).clamp(0.0, 1.0)
    }

    #[test]
    fn identical_to_the_monolith_from_035_and_never_more_generous() {
        for ci in 0..=1000 {
            let c = f64::from(ci) / 1000.0;
            for n in 1..=40u32 {
                let (new, old) = (effective(c, n), legacy(c, n));
                assert!(new <= old + 1e-12, "c={c} n={n}: {new} > {old}");
                if c >= 0.35 {
                    assert!((new - old).abs() < 1e-12, "c={c} n={n}: {new} != {old}");
                }
            }
        }
    }

    #[test]
    fn weak_sources_cannot_compound_into_verified() {
        assert!(
            legacy(0.05, 5) > VERIFIED_MIN,
            "the monolith defect this fixes"
        );
        for n in 1..=200u32 {
            let e = effective(0.05, n);
            let noisy_or = 1.0 - 0.95_f64.powi(i32::try_from(n).unwrap());
            assert!(
                e <= noisy_or.max(0.05 * (1.0 + 0.15 * f64::from(n).ln())) + 1e-12,
                "n={n} {e}"
            );
        }
        assert!(effective(0.05, 5) < PROBABLE_MIN);
        assert_eq!(effective(0.0, 1000), 0.0);
    }

    #[test]
    fn hostile_inputs_cannot_raise_a_tier() {
        assert_eq!(effective(f64::NAN, 5), 0.0);
        assert_eq!(effective(-3.0, 5), 0.0);
        assert_eq!(effective(7.0, 1), 1.0);
        assert_eq!(effective(f64::INFINITY, 1), 1.0);
        assert_eq!(effective(f64::NEG_INFINITY, 9), 0.0);
        assert_eq!(effective(0.0, 0), 0.0, "zero confidence stays zero");
        assert_eq!(
            effective(0.0, u32::MAX),
            0.0,
            "corroboration cannot create belief"
        );
        assert!(effective(0.5, u32::MAX).is_finite());
        assert_eq!(
            Classification::from_effective(f64::NAN),
            Classification::Candidate
        );
    }

    #[test]
    fn mirrors_of_one_dump_are_one_source() {
        let mut g = EvidenceAncestryGraph::default();
        let mut add = |id: &str, family: &str, parents: &[&str]| {
            g.insert(EvidenceAncestryNode {
                id: id.into(),
                source_family: family.into(),
                parents: parents.iter().copied().map(EvidenceNodeId::from).collect(),
                derived: !parents.is_empty(),
            })
            .unwrap();
        };
        add("dump", "adobe 2013", &[]);
        add("mirror-a", "provider-a", &["dump"]);
        add("mirror-b", "provider-b", &["dump"]);
        add("registry", "company registry", &[]);
        let ids = |v: &[&str]| {
            v.iter()
                .copied()
                .map(EvidenceNodeId::from)
                .collect::<Vec<_>>()
        };
        let mirrors = effective_from_ancestry(0.6, &g, &ids(&["mirror-a", "mirror-b"])).unwrap();
        let independent =
            effective_from_ancestry(0.6, &g, &ids(&["mirror-a", "registry"])).unwrap();
        assert!((mirrors - 0.6).abs() < 1e-12, "{mirrors}");
        assert!(independent > 0.7, "{independent}");
        assert!(
            effective_from_ancestry(0.6, &g, &ids(&["ghost"])).is_err(),
            "unknown ancestry fails closed"
        );
    }

    #[test]
    fn depth_decay_discounts_and_refuses_amplification() {
        assert_eq!(depth_decayed(0.8, 0.9, 0), Some(0.8));
        assert!((depth_decayed(0.8, 0.5, 2).unwrap() - 0.2).abs() < 1e-12);
        assert_eq!(depth_decayed(0.8, 1.0, 50), Some(0.8));
        for base in [0.0, -0.1, 1.0001, 2.0, f64::NAN, f64::INFINITY] {
            assert_eq!(depth_decayed(0.5, base, 2), None, "{base}");
        }
        assert_eq!(depth_decayed(f64::NAN, 0.9, 1), Some(0.0));
        assert_eq!(depth_decayed(0.9, 0.5, u32::MAX), Some(0.0));
    }
}
