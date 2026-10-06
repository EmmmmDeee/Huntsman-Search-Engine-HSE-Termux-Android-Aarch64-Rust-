//! Differential test against the legacy `hse` oracle (7dca720) breach-consensus rule.
//!
//! `tests/fixtures/legacy_7dca720_breach_consensus.json` holds the fixture identities
//! and the outcomes the legacy code produced on them (captured by running the oracle;
//! see the file's `oracle.capture`). Recon preserves the useful legacy grouping signal,
//! except listed intentional grouping differences, but does not inherit the oracle's
//! assumption that two differently named corpora are automatically independent proof.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use huntsman_recon::entity::{Evidence, EvidenceProvenance};
use huntsman_recon::evidence_ancestry::EvidenceNodeId;
use huntsman_recon::identity_resolution::{
    AutoMergePolicy, HoldReason, IdentityResolutionDecision, ResolutionState,
};
use huntsman_recon::lineage::{MergeOutcome, Observation, Resolution, resolve_with_lineage};
use serde_json::Value;

fn oracle() -> Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/legacy_7dca720_breach_consensus.json");
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn observations(fixture: &Value) -> Vec<Observation> {
    let name = fixture["name"].as_str().unwrap();
    fixture["observations"]
        .as_array()
        .unwrap()
        .iter()
        .enumerate()
        .map(|(i, o)| Observation {
            id: EvidenceNodeId(format!("{name}-{i}")),
            evidence: o["attributes"].as_object().unwrap().iter().fold(
                Evidence::new(
                    EvidenceProvenance::new(o["collector"].as_str().unwrap()),
                    "breach record",
                ),
                |e, (k, v)| e.with_attr(k.as_str(), v.as_str().unwrap()),
            ),
        })
        .collect()
}

fn run(fixture: &Value, probability: Option<f64>) -> Resolution {
    let obs = observations(fixture);
    let decision = IdentityResolutionDecision {
        left_entity_uid: "email:jane@example.com".into(),
        right_entity_uid: "username:janecitizen".into(),
        state: ResolutionState::Match,
        probability,
        supporting: obs.iter().map(|o| o.id.clone()).collect(),
        contradicting: vec![],
        temporal_conflict: false,
        geographic_conflict: false,
        decided_at_unix: 1,
    };
    resolve_with_lineage(obs, vec![decision], AutoMergePolicy::default()).unwrap()
}

fn count(v: &Value) -> usize {
    usize::try_from(v.as_u64().unwrap()).unwrap()
}

/// Observation indices grouped by key, as a set of groups (labels erased).
fn partition<'a>(keys: impl Iterator<Item = &'a str>) -> BTreeSet<BTreeSet<usize>> {
    let mut groups: BTreeMap<&str, BTreeSet<usize>> = BTreeMap::new();
    for (i, k) in keys.enumerate() {
        groups.entry(k).or_default().insert(i);
    }
    groups.into_values().collect()
}

#[test]
fn recon_reproduces_legacy_grouping_but_not_unproven_corroboration() {
    let doc = oracle();
    let fixtures = doc["fixtures"].as_array().unwrap();
    assert_eq!(fixtures.len(), 9);
    let mut differences = Vec::new();
    for fixture in fixtures {
        let name = fixture["name"].as_str().unwrap();
        let legacy = &fixture["legacy"];
        let legacy_count = count(&legacy["source_count"]);
        let r = run(fixture, Some(0.99));
        let c = &r.candidates[0];
        let families = c.independent_families.len();

        // The lineage-only API has no artifact-backed independence evidence, so
        // family-label multiplicity can never authorize a two-route auto-merge.
        assert_ne!(c.outcome, MergeOutcome::AutoMerge, "{name}: unproven merge");
        if legacy["is_corroborated"].as_bool().unwrap() {
            let MergeOutcome::Held { reasons } = &c.outcome else {
                unreachable!()
            };
            assert!(
                reasons.iter().any(|reason| matches!(
                    reason,
                    HoldReason::InsufficientIndependentFamilies {
                        found: 1,
                        required: 2
                    }
                )),
                "{name}: legacy corroboration was not explicitly demoted"
            );
        }

        if let Some(diff) = fixture.get("intentional_difference") {
            let want = count(&diff["recon_families"]);
            assert_eq!(families, want, "{name}: pinned recon value moved");
            assert!(diff["reason"].as_str().is_some_and(|r| r.len() > 20));
            differences.push(name);
            continue;
        }
        assert_eq!(families, legacy_count, "{name}: family count");
        let legacy_keys = legacy["breach_corpus_key"].as_array().unwrap();
        let ours: Vec<&str> = r
            .observations
            .iter()
            .map(|o| o.lineage.family().unwrap())
            .collect();
        assert_eq!(
            partition(ours.into_iter()),
            partition(legacy_keys.iter().map(|k| k.as_str().unwrap())),
            "{name}: grouping"
        );
    }
    assert_eq!(
        differences,
        [
            "unattributed_collectors",
            "case_and_whitespace_variant",
            "dump_plus_registry"
        ]
    );
}

/// The default policy keeps legacy's two-source numeric threshold for compatibility,
/// but satisfying that count is no longer sufficient without proven independence.
#[test]
fn default_policy_preserves_legacy_numeric_thresholds_without_inheriting_its_proof_rule() {
    let doc = oracle();
    let ceiling: Vec<f64> = doc["oracle"]["supported_ceiling_0_to_3"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_f64().unwrap())
        .collect();
    let policy = AutoMergePolicy::default();
    let first_corroborated = doc["fixtures"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| f["legacy"]["is_corroborated"].as_bool().unwrap())
        .map(|f| count(&f["legacy"]["source_count"]))
        .min()
        .unwrap();
    assert_eq!(policy.min_independent_support_families, first_corroborated);
    assert_eq!(policy.min_independent_support_families, 2);
    assert!((ceiling[2] - policy.min_match_probability).abs() < f64::EPSILON);
    assert!(ceiling[1] < policy.min_match_probability);
}

/// Legacy grades corroboration with no match probability. Recon additionally refuses
/// to auto-merge without one, independently of the proven-independence requirement.
#[test]
fn legacy_corroborated_fixtures_are_held_without_a_probability() {
    for fixture in oracle()["fixtures"].as_array().unwrap() {
        let c = &run(fixture, None).candidates[0];
        let MergeOutcome::Held { reasons } = &c.outcome else {
            panic!("{} merged without a probability", fixture["name"]);
        };
        assert!(reasons.contains(&HoldReason::ProbabilityMissing));
    }
}
