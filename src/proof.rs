//! Bounded minimal proof environments for auditable claim justification.
//!
//! Environments retain the evidence, roots, dependencies, derivations, and
//! assumptions required by one sufficient justification. Minimalisation keeps
//! only an antichain of non-redundant environments. Resource bounds fail
//! conservatively: discarded or truncated environments set `incomplete=true`.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::intelligence::EvidenceId;

macro_rules! string_id {
    ($name:ident) => {
        #[derive(
            Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
        )]
        #[serde(transparent)]
        pub struct $name(pub String);

        impl From<&str> for $name {
            fn from(value: &str) -> Self {
                Self(value.to_owned())
            }
        }
    };
}

string_id!(AssumptionId);
string_id!(DerivationId);
string_id!(DependencyDomainId);

#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct MinimalProofEnvironment {
    pub assertions: BTreeSet<EvidenceId>,
    pub roots: BTreeSet<String>,
    pub dependencies: BTreeSet<DependencyDomainId>,
    pub derivations: BTreeSet<DerivationId>,
    pub assumptions: BTreeSet<AssumptionId>,
}

impl MinimalProofEnvironment {
    #[must_use]
    pub fn cardinality(&self) -> usize {
        self.assertions.len()
            + self.roots.len()
            + self.dependencies.len()
            + self.derivations.len()
            + self.assumptions.len()
    }

    #[must_use]
    pub fn subsumes(&self, other: &Self) -> bool {
        self.assertions.is_subset(&other.assertions)
            && self.roots.is_subset(&other.roots)
            && self.dependencies.is_subset(&other.dependencies)
            && self.derivations.is_subset(&other.derivations)
            && self.assumptions.is_subset(&other.assumptions)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofEnvironmentSet {
    pub environments: Vec<MinimalProofEnvironment>,
    pub incomplete: bool,
}

/// Combines premise environments for one derivation.
///
/// The output inherits every root, dependency, assumption, prior derivation,
/// and assertion from its premises. The derivation id is added, but no new root
/// can be supplied by this operation.
#[must_use]
pub fn derive_environment(
    inputs: &[MinimalProofEnvironment],
    derivation: DerivationId,
) -> MinimalProofEnvironment {
    let mut output = MinimalProofEnvironment::default();
    for input in inputs {
        output.assertions.extend(input.assertions.iter().cloned());
        output.roots.extend(input.roots.iter().cloned());
        output
            .dependencies
            .extend(input.dependencies.iter().cloned());
        output.derivations.extend(input.derivations.iter().cloned());
        output.assumptions.extend(input.assumptions.iter().cloned());
    }
    output.derivations.insert(derivation);
    output
}

/// Reduces candidate proof environments to a deterministic minimal antichain.
///
/// Environments whose total cardinality exceeds `max_cardinality` are omitted
/// and mark the result incomplete. After subsumption, at most
/// `max_environments` environments are retained. Any such truncation also marks
/// the result incomplete, allowing claim assessment to fail closed.
#[must_use]
pub fn minimalize_environments(
    mut environments: Vec<MinimalProofEnvironment>,
    max_environments: usize,
    max_cardinality: usize,
) -> ProofEnvironmentSet {
    environments.sort();
    environments.dedup();

    let mut incomplete = false;
    let mut minimal: Vec<MinimalProofEnvironment> = Vec::new();

    for environment in environments {
        if environment.cardinality() > max_cardinality {
            incomplete = true;
            continue;
        }
        if minimal
            .iter()
            .any(|existing| existing.subsumes(&environment))
        {
            continue;
        }
        minimal.retain(|existing| !environment.subsumes(existing));
        minimal.push(environment);
        minimal.sort();
    }

    if minimal.len() > max_environments {
        minimal.truncate(max_environments);
        incomplete = true;
    }

    ProofEnvironmentSet {
        environments: minimal,
        incomplete,
    }
}
