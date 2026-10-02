//! Deterministic benchmark harness for automatic identity-resolution decisions.
//!
//! The benchmark does not estimate identity probability. It evaluates the policy's
//! binary automatic-merge decision against synthetic or curated expected outcomes.

use crate::evidence_ancestry::EvidenceAncestryGraph;
use crate::identity_resolution::{AutoMergePolicy, IdentityResolutionDecision};

#[derive(Debug, Clone)]
pub struct BenchmarkCase {
    pub name: String,
    pub decision: IdentityResolutionDecision,
    pub expected_auto_merge: bool,
}

impl BenchmarkCase {
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        decision: IdentityResolutionDecision,
        expected_auto_merge: bool,
    ) -> Self {
        Self {
            name: name.into(),
            decision,
            expected_auto_merge,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct IdentityBenchmarkSummary {
    pub cases: usize,
    pub true_positive: usize,
    pub true_negative: usize,
    pub false_positive: usize,
    pub false_negative: usize,
    pub precision: f64,
    pub recall: f64,
}

/// Evaluate automatic-merge behavior against explicit expected outcomes.
#[must_use]
pub fn evaluate(
    cases: &[BenchmarkCase],
    graph: &EvidenceAncestryGraph,
    policy: AutoMergePolicy,
) -> IdentityBenchmarkSummary {
    let mut true_positive = 0usize;
    let mut true_negative = 0usize;
    let mut false_positive = 0usize;
    let mut false_negative = 0usize;

    for case in cases {
        let actual = case.decision.allows_automatic_merge(graph, policy);
        match (actual, case.expected_auto_merge) {
            (true, true) => true_positive += 1,
            (false, false) => true_negative += 1,
            (true, false) => false_positive += 1,
            (false, true) => false_negative += 1,
        }
    }

    let precision = ratio(true_positive, true_positive + false_positive);
    let recall = ratio(true_positive, true_positive + false_negative);

    IdentityBenchmarkSummary {
        cases: cases.len(),
        true_positive,
        true_negative,
        false_positive,
        false_negative,
        precision,
        recall,
    }
}

fn ratio(numerator: usize, denominator: usize) -> f64 {
    if denominator == 0 {
        1.0
    } else {
        numerator as f64 / denominator as f64
    }
}
