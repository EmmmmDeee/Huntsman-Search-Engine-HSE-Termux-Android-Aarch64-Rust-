use std::collections::BTreeSet;

use super::model::{FinalizedConditionResult, IdentityCluster, SealedTruth};

#[derive(Debug, Clone, PartialEq)]
pub struct CaseScore {
    pub entity_precision: f64,
    pub entity_recall: f64,
    pub relation_precision: f64,
    pub relation_recall: f64,
    pub claim_precision: f64,
    pub claim_recall: f64,
    pub identity_pair_precision: f64,
    pub identity_pair_recall: f64,
    pub false_merge_pairs: usize,
    pub false_split_pairs: usize,
    pub max_false_merge_cascade: usize,
    pub evidence_completeness: f64,
    pub completed: bool,
    pub comparable: bool,
}

fn precision_recall<T: Ord>(
    observed: &BTreeSet<T>,
    truth: &BTreeSet<T>,
) -> (f64, f64, usize, usize) {
    let true_positive = observed.intersection(truth).count();
    let false_positive = observed.difference(truth).count();
    let false_negative = truth.difference(observed).count();

    let precision = if observed.is_empty() {
        if truth.is_empty() { 1.0 } else { 0.0 }
    } else {
        true_positive as f64 / observed.len() as f64
    };
    let recall = if truth.is_empty() {
        1.0
    } else {
        true_positive as f64 / truth.len() as f64
    };
    (precision, recall, false_positive, false_negative)
}

fn cluster_pairs(clusters: &[IdentityCluster]) -> BTreeSet<(String, String)> {
    let mut pairs = BTreeSet::new();
    for cluster in clusters {
        let members: Vec<&String> = cluster.members.iter().collect();
        for (index, left) in members.iter().enumerate() {
            for right in members.iter().skip(index + 1) {
                pairs.insert(((*left).clone(), (*right).clone()));
            }
        }
    }
    pairs
}

fn false_merge_cascade(
    observed: &[IdentityCluster],
    truth: &[IdentityCluster],
) -> usize {
    let truth_by_member: std::collections::BTreeMap<&str, &str> = truth
        .iter()
        .flat_map(|cluster| {
            cluster
                .members
                .iter()
                .map(move |member| (member.as_str(), cluster.cluster_id.as_str()))
        })
        .collect();

    observed
        .iter()
        .map(|cluster| {
            let true_clusters = cluster
                .members
                .iter()
                .filter_map(|member| truth_by_member.get(member.as_str()).copied())
                .collect::<BTreeSet<_>>();
            if true_clusters.len() > 1 {
                cluster.members.len()
            } else {
                0
            }
        })
        .max()
        .unwrap_or(0)
}

#[must_use]
pub fn score_case(truth: &SealedTruth, result: &FinalizedConditionResult) -> CaseScore {
    let (entity_precision, entity_recall, _, _) =
        precision_recall(&result.entity_ids, &truth.entity_ids);
    let (relation_precision, relation_recall, _, _) =
        precision_recall(&result.relations, &truth.relations);
    let (claim_precision, claim_recall, _, _) =
        precision_recall(&result.claims, &truth.claims);

    let observed_pairs = cluster_pairs(&result.identity_clusters);
    let truth_pairs = cluster_pairs(&truth.identity_clusters);
    let (
        identity_pair_precision,
        identity_pair_recall,
        false_merge_pairs,
        false_split_pairs,
    ) = precision_recall(&observed_pairs, &truth_pairs);

    CaseScore {
        entity_precision,
        entity_recall,
        relation_precision,
        relation_recall,
        claim_precision,
        claim_recall,
        identity_pair_precision,
        identity_pair_recall,
        false_merge_pairs,
        false_split_pairs,
        max_false_merge_cascade: false_merge_cascade(
            &result.identity_clusters,
            &truth.identity_clusters,
        ),
        evidence_completeness: result.evidence_completeness.clamp(0.0, 1.0),
        completed: result.completed,
        comparable: result.comparable,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;
    use crate::eval::{
        ClaimTruth, EvalCondition, IdentityCluster, RelationTruth,
    };

    fn set(values: &[&str]) -> BTreeSet<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    #[test]
    fn false_identity_bridge_is_counted_separately_from_yield() {
        let truth = SealedTruth {
            entity_ids: set(&["a", "b", "c"]),
            identity_clusters: vec![
                IdentityCluster {
                    cluster_id: "p1".into(),
                    members: set(&["a", "b"]),
                },
                IdentityCluster {
                    cluster_id: "p2".into(),
                    members: set(&["c"]),
                },
            ],
            relations: BTreeSet::<RelationTruth>::new(),
            claims: BTreeSet::<ClaimTruth>::new(),
        };
        let result = FinalizedConditionResult {
            case_id: "fixture".into(),
            condition: EvalCondition::Full,
            entity_ids: set(&["a", "b", "c"]),
            identity_clusters: vec![IdentityCluster {
                cluster_id: "wrong".into(),
                members: set(&["a", "b", "c"]),
            }],
            relations: BTreeSet::new(),
            claims: BTreeSet::new(),
            evidence_completeness: 1.0,
            request_count: 1,
            wall_time_ms: 1,
            provider_cost_usd: 0.0,
            completed: true,
            comparable: true,
        };

        let score = score_case(&truth, &result);
        assert_eq!(score.entity_recall, 1.0);
        assert!(score.false_merge_pairs > 0);
        assert_eq!(score.max_false_merge_cascade, 3);
    }
}
