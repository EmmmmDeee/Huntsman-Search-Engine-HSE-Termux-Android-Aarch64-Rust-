//! Bounded, conservative counting of mutually proven-independent evidence routes.
//!
//! The search returns a proven lower bound. Exhausting the configured search budget
//! can only weaken the result (`incomplete = true`); it can never manufacture support.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::evidence_ancestry::{
    AncestryError, EvidenceAncestryGraph, EvidenceNodeId, IndependenceState,
};

/// Conservative result of bounded independent-route search.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndependenceRouteCount {
    /// Number of mutually independent routes actually proven by the completed search.
    pub proven: usize,
    /// True when the search budget ended before the next route cardinality was decided.
    pub incomplete: bool,
}

fn resolved_roots(
    graph: &EvidenceAncestryGraph,
    id: &EvidenceNodeId,
) -> Result<BTreeSet<EvidenceNodeId>, AncestryError> {
    let mut roots = BTreeSet::new();
    let mut done = BTreeSet::new();
    let mut on_path = BTreeSet::new();
    let mut stack = vec![(id.clone(), false)];

    while let Some((current, expanded)) = stack.pop() {
        if expanded {
            on_path.remove(&current);
            done.insert(current);
            continue;
        }
        if done.contains(&current) {
            continue;
        }
        if !on_path.insert(current.clone()) {
            return Err(AncestryError::Cycle(current));
        }

        let node = graph
            .get(&current)
            .ok_or_else(|| AncestryError::MissingNode(current.clone()))?;
        stack.push((current.clone(), true));
        if node.parents.is_empty() {
            roots.insert(current);
            continue;
        }

        for parent in node.parents.iter().rev() {
            if on_path.contains(parent) {
                return Err(AncestryError::Cycle(parent.clone()));
            }
            if !done.contains(parent) {
                stack.push((parent.clone(), false));
            }
        }
    }

    Ok(roots)
}

fn advance_combination(indices: &mut [usize], universe_len: usize) -> bool {
    let width = indices.len();
    for position in (0..width).rev() {
        let maximum = universe_len - width + position;
        if indices[position] < maximum {
            indices[position] += 1;
            for next in position + 1..width {
                indices[next] = indices[next - 1] + 1;
            }
            return true;
        }
    }
    false
}

impl EvidenceAncestryGraph {
    /// Count only routes whose pairwise independence has been explicitly proven.
    ///
    /// The algorithm resolves and deduplicates canonical provenance roots, then tests
    /// combinations in deterministic lexicographic order from cardinality two upward.
    /// A single resolved root is intrinsically one route; additional routes count only
    /// when every pair in the candidate subset is `ProvenIndependent`.
    ///
    /// `max_search_states` bounds combination evaluations. If the budget ends while an
    /// undecided cardinality still has candidates, the function returns the strongest
    /// already-proven lower bound with `incomplete = true`. `Unknown` never counts.
    ///
    /// # Errors
    /// Missing or cyclic ancestry fails closed with the existing ancestry errors.
    pub fn proven_independent_route_count<'a>(
        &self,
        ids: impl IntoIterator<Item = &'a EvidenceNodeId>,
        required: usize,
        max_search_states: usize,
    ) -> Result<IndependenceRouteCount, AncestryError> {
        let mut root_set = BTreeSet::new();
        for id in ids {
            root_set.extend(resolved_roots(self, id)?);
        }

        if required == 0 {
            return Ok(IndependenceRouteCount {
                proven: 0,
                incomplete: false,
            });
        }
        if root_set.is_empty() {
            return Ok(IndependenceRouteCount {
                proven: 0,
                incomplete: false,
            });
        }

        let roots: Vec<_> = root_set.into_iter().collect();
        let mut proven = 1;
        if required == 1 || roots.len() == 1 {
            return Ok(IndependenceRouteCount {
                proven,
                incomplete: false,
            });
        }

        let target = required.min(roots.len());
        let mut searched_states = 0usize;

        for width in 2..=target {
            let mut combination: Vec<usize> = (0..width).collect();
            loop {
                if searched_states >= max_search_states {
                    return Ok(IndependenceRouteCount {
                        proven,
                        incomplete: true,
                    });
                }
                searched_states += 1;

                let mut all_proven = true;
                'pairs: for left in 0..width {
                    for right in left + 1..width {
                        if self.independence_state(
                            &roots[combination[left]],
                            &roots[combination[right]],
                        )? != IndependenceState::ProvenIndependent
                        {
                            all_proven = false;
                            break 'pairs;
                        }
                    }
                }

                if all_proven {
                    proven = width;
                    break;
                }
                if !advance_combination(&mut combination, roots.len()) {
                    return Ok(IndependenceRouteCount {
                        proven,
                        incomplete: false,
                    });
                }
            }

            if proven >= required {
                return Ok(IndependenceRouteCount {
                    proven,
                    incomplete: false,
                });
            }
        }

        Ok(IndependenceRouteCount {
            proven,
            incomplete: false,
        })
    }
}
