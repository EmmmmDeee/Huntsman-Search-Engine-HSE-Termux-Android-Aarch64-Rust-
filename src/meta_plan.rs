//! Fail-closed dispatch plan.
//!
//! A plan is admissible only when every material field was supplied for this
//! round. Static registries, fixed utility weights, and a missing model are not
//! fallbacks. This module does not fetch, does not hash evidence, and does not
//! mint `ClaimState::Verified`.

use serde::{Deserialize, Serialize};

use crate::canonical::{canonicalise_selector, canonicalise_token, canonical_whitespace};

/// Why a plan is refused. Refusal is the success path when inheritance is attempted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlanReject {
    EmptySeed,
    MissingField(&'static str),
    InheritedFallback,
    VerificationClaim,
    EmptyDispatch,
    NoReversalObservation,
}

/// One ordered action. A route stays a lead until a body is admitted elsewhere.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanAction {
    pub source_id: String,
    pub query: String,
    pub why: String,
    pub reversal_observation: String,
    pub requires_key: bool,
    pub lead_only: bool,
}

/// The whole round. Absence of any field is rejection, not a default.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetaPlan {
    pub seed: String,
    pub hypotheses: Vec<String>,
    pub determination_method: String,
    pub method_reversal: String,
    pub actions: Vec<PlanAction>,
    pub stop_rule: String,
    pub next_pivot: String,
}

impl MetaPlan {
    /// Accept the plan or refuse it.
    ///
    /// # Errors
    /// Returns the first hard refusal. Do not repair the plan here.
    pub fn admit(mut self) -> Result<Self, PlanReject> {
        let Some(seed) = canonicalise_selector(&self.seed) else {
            return Err(PlanReject::EmptySeed);
        };
        self.seed = seed;
        require(&self.determination_method, "determination_method")?;
        require(&self.method_reversal, "method_reversal")?;
        require(&self.stop_rule, "stop_rule")?;
        require(&self.next_pivot, "next_pivot")?;
        self.determination_method = canonical_whitespace(&self.determination_method);
        self.method_reversal = canonical_whitespace(&self.method_reversal);
        self.stop_rule = canonical_whitespace(&self.stop_rule);
        self.next_pivot = canonical_whitespace(&self.next_pivot);
        if self.hypotheses.is_empty() {
            return Err(PlanReject::MissingField("hypotheses"));
        }
        for hypothesis in &mut self.hypotheses {
            let Some(value) = canonicalise_selector(hypothesis) else {
                return Err(PlanReject::MissingField("hypotheses"));
            };
            *hypothesis = value;
        }
        if self.actions.is_empty() {
            return Err(PlanReject::EmptyDispatch);
        }
        if mentions_inheritance(&self.determination_method) {
            return Err(PlanReject::InheritedFallback);
        }
        for action in &mut self.actions {
            let Some(source_id) = canonicalise_token(&action.source_id) else {
                return Err(PlanReject::MissingField("source_id"));
            };
            let Some(query) = canonicalise_selector(&action.query) else {
                return Err(PlanReject::MissingField("query"));
            };
            action.source_id = source_id;
            action.query = query;
            require(&action.why, "why")?;
            require(&action.reversal_observation, "reversal_observation")?;
            action.why = canonical_whitespace(&action.why);
            action.reversal_observation = canonical_whitespace(&action.reversal_observation);
            if action.why.to_ascii_lowercase().contains("verified") {
                return Err(PlanReject::VerificationClaim);
            }
        }
        Ok(self)
    }
}

fn require(value: &str, field: &'static str) -> Result<(), PlanReject> {
    if value.trim().is_empty() {
        Err(PlanReject::MissingField(field))
    } else {
        Ok(())
    }
}

fn mentions_inheritance(method: &str) -> bool {
    let method = method.to_ascii_lowercase();
    method.contains("static source")
        || method.contains("utility weight")
        || method.contains("infer_kind")
        || method.contains("fallback")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn action() -> PlanAction {
        PlanAction {
            source_id: "crtsh".into(),
            query: "example.com".into(),
            why: "structured names before html".into(),
            reversal_observation: "quarantine or valid zero".into(),
            requires_key: false,
            lead_only: true,
        }
    }

    fn plan() -> MetaPlan {
        MetaPlan {
            seed: "example.com".into(),
            hypotheses: vec!["domain".into()],
            determination_method: "reversal-tested case construction".into(),
            method_reversal: "a fetched body that contradicts the source physics".into(),
            actions: vec![action()],
            stop_rule: "two independent admitted origins, or structured tier adds none".into(),
            next_pivot: "none until a body is admitted".into(),
        }
    }

    #[test]
    fn complete_plan_is_admitted() {
        assert!(plan().admit().is_ok());
    }

    #[test]
    fn missing_field_is_refused() {
        let mut raw = plan();
        raw.stop_rule.clear();
        assert_eq!(raw.admit(), Err(PlanReject::MissingField("stop_rule")));
    }

    #[test]
    fn inherited_method_is_refused() {
        let mut raw = plan();
        raw.determination_method = "fallback to static source table".into();
        assert_eq!(raw.admit(), Err(PlanReject::InheritedFallback));
    }

    #[test]
    fn verified_claim_is_refused() {
        let mut raw = plan();
        raw.actions[0].why = "this source is verified".into();
        assert_eq!(raw.admit(), Err(PlanReject::VerificationClaim));
    }
    #[test]
    fn admit_canonicalises_seed_query_and_source() {
        let mut raw = plan();
        raw.seed = "  Example.COM ".into();
        raw.actions[0].source_id = " CrtSh ".into();
        raw.actions[0].query = "  Example.COM ".into();
        let admitted = raw.admit().expect("canonical plan");
        assert_eq!(admitted.seed, "example.com");
        assert_eq!(admitted.actions[0].source_id, "crtsh");
        assert_eq!(admitted.actions[0].query, "example.com");
    }
}
