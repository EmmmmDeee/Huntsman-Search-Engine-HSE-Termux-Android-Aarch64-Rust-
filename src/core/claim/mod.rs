//! `core::claim` — the assertion layer: ENTITY ≠ CLAIM ≠ EVIDENCE ≠ INFERENCE.
//!
//! # Why this module exists
//!
//! Before this module the engine had two of the four things it reasons about.
//! [`Entity`](crate::core::entity::Entity) is a *thing* (an email, a person, a
//! coordinate) and [`Evidence`](crate::core::entity::Evidence) is an
//! *observation* a module made. What was missing is the layer in between and
//! the layer above:
//!
//! * a **CLAIM** — an assertion *about* entities ("this phone belongs to that
//!   person", "this company was controlled by that director in 2019") which can
//!   be supported, contradicted, contested or refuted, and which has a
//!   **lifecycle** independent of any single observation; and
//! * an **INFERENCE** — a conclusion *derived from* claims rather than observed,
//!   which must never be laundered back into the record as though a source had
//!   reported it.
//!
//! Collapsing these is the failure this module exists to prevent. When an
//! observation is stored directly as a conclusion, three things become
//! impossible: you cannot hold two conflicting values at once (the second
//! overwrites the first), you cannot say *why* a conclusion is believed
//! (evidence and inference are indistinguishable), and you cannot withdraw a
//! conclusion when its source is retracted (nothing records which conclusions
//! rested on it). [`Claim`] is the record that makes all three possible.
//!
//! # The invariants this module enforces in types
//!
//! Each is stated in the operational contract and made machine-checkable here,
//! with the test that pins it named alongside:
//!
//! | Invariant | Enforced by |
//! |---|---|
//! | ENTITY ≠ CLAIM ≠ EVIDENCE ≠ INFERENCE | [`Support::provenance`] — an inference can never be its own support |
//! | SOURCE COUNT ≠ SOURCE INDEPENDENCE | [`Claim::independent_lineages`] counts *lineages*, not records |
//! | IDENTIFIER MATCH ≠ ENTITY IDENTITY | [`ClaimKind::IdentityLink`] is a claim, never an entity merge |
//! | EXPLORE AGGRESSIVELY → PROMOTE CONSERVATIVELY | [`Claim::may_expand`] vs [`Claim::recompute_state`] |
//! | EVERY NODE IS ELIGIBLE FOR EXPANSION ≠ EVERY NODE MUST BE EXPANDED | [`Claim::may_expand`] returns eligibility, never a schedule |
//! | HARD TARGET ≠ LOWER STANDARD | [`PromotionThresholds::for_difficulty`] is constant in difficulty |
//! | ABSENCE OF EASY EVIDENCE ≠ ABSENCE OF A NEXUS | [`Support::Unattempted`]/[`Support::Failed`] never reduce a claim's state |
//! | EXPAND BROADLY ≠ CONCLUDE BROADLY | expansion reads [`Claim::may_expand`]; conclusions read [`ClaimState::is_actionable`] |
//!
//! # What this module is not
//!
//! It is pure: no I/O, no clock, no network, no storage. Every function is a
//! total function of its inputs so the whole lifecycle is unit-testable without
//! a scan, and so a claim's state is reproducible from its record alone rather
//! than from the order events happened to arrive in.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

#[cfg(test)]
mod tests;

/// How strongly the engine may act on a claim. The lifecycle is deliberately
/// NOT a confidence number: a scalar cannot express "two sources agree but a
/// third contradicts them", which is exactly the state a hard target produces
/// most often.
///
/// Transitions are computed, never assigned: [`Claim::recompute_state`] derives
/// the state from the claim's own support and contradiction records, so the
/// same record always yields the same state regardless of arrival order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimState {
    /// Proposed but not yet supported by any observation. The state a claim
    /// starts in, and the state it STAYS in when a lookup was never attempted
    /// or failed — absence of easy evidence is not evidence of absence.
    Hypothesised,
    /// At least one supporting observation, but not from independent lineages.
    /// A single source — or several that trace to one upstream corpus — can
    /// support a claim; it cannot corroborate it.
    Supported,
    /// Supported by at least [`PromotionThresholds::independent_lineages`]
    /// genuinely independent lineages, with no unresolved contradiction.
    Corroborated,
    /// Corroborated AND carrying evidence that discriminates it from its
    /// competing hypotheses. The only state that survives an adversarial read,
    /// and the highest a claim can reach.
    Established,
    /// Carries at least one unresolved [`Contradiction`]. Contested is NOT
    /// "weak": a contested claim may have overwhelming support on both sides.
    /// It is the honest state for conflicting evidence, and it is preserved
    /// rather than collapsed until discriminating evidence resolves it.
    Contested,
    /// Discriminating evidence AGAINST the claim was observed. Distinct from
    /// `Hypothesised` (nothing found) — this is a positive finding of falsity.
    Refuted,
    /// A source this claim rested on was retracted or its lineage invalidated.
    /// Terminal: re-establishing requires new support, not re-scoring.
    Withdrawn,
}

impl ClaimState {
    /// Whether a conclusion, export, or operator-facing finding may assert this
    /// claim as fact. EXPAND BROADLY ≠ CONCLUDE BROADLY: expansion consults
    /// [`Claim::may_expand`], which admits far more than this does.
    ///
    /// `Contested` is deliberately excluded. A contested claim is reportable —
    /// the operator must see the conflict — but it is not assertable as fact,
    /// which is what this gate governs.
    #[must_use]
    pub fn is_actionable(self) -> bool {
        matches!(self, Self::Corroborated | Self::Established)
    }

    /// Whether the claim is still open to new evidence. Only the two terminal
    /// states are closed; everything else — including `Established` — remains
    /// open, because an established claim can still be contradicted later.
    #[must_use]
    pub fn is_open(self) -> bool {
        !matches!(self, Self::Refuted | Self::Withdrawn)
    }

    /// The canonical wire/CLI spelling, stable across releases.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Hypothesised => "hypothesised",
            Self::Supported => "supported",
            Self::Corroborated => "corroborated",
            Self::Established => "established",
            Self::Contested => "contested",
            Self::Refuted => "refuted",
            Self::Withdrawn => "withdrawn",
        }
    }
}

/// Where a piece of support came from, and — critically — whether it is an
/// OBSERVATION or an INFERENCE.
///
/// This enum is the type-level form of ENTITY ≠ CLAIM ≠ EVIDENCE ≠ INFERENCE.
/// An inference may support a claim, but [`Claim::independent_lineages`] never
/// counts one toward corroboration: a conclusion derived from the graph is not
/// a second witness to it, and letting it count is how one source becomes
/// "three independent sources" after two derivation hops.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Provenance {
    /// A module observed this directly from a source. Carries the lineage key
    /// (see [`SourceLineage`]) so resold copies of one corpus collapse.
    Observed(SourceLineage),
    /// Derived from other claims by a rule. Never corroborating: it adds
    /// reasoning, not an independent witness. Names the rule so the derivation
    /// can be re-checked or withdrawn wholesale if the rule proves unsound.
    Inferred { rule_id: String },
}

/// The upstream ORIGIN of an observation, which is not the same thing as the
/// module that fetched it.
///
/// SOURCE COUNT ≠ SOURCE INDEPENDENCE, made concrete: a breach corpus resold by
/// three aggregators is one witness, not three. Counting provider names would
/// call it three. `corpus` is what actually separates witnesses — when a module
/// can name the underlying dataset (a breach dump, a registry extract, a
/// filing), that name is the identity; only when it genuinely cannot does the
/// provider itself stand as the lineage.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SourceLineage {
    /// The module/provider that fetched it (`see_know`, `asic_director`).
    pub provider: String,
    /// The upstream dataset, when the provider names one (`linkedin-2021`,
    /// `ASIC-companies-2024Q1`). `None` means the provider is the origin as far
    /// as this observation can establish — a first-party API answering about
    /// its own records.
    pub corpus: Option<String>,
    /// Jurisdiction the record was filed/held under, where meaningful. Two
    /// registries in different jurisdictions reporting the same fact ARE
    /// independent; the same filing mirrored twice is not.
    pub jurisdiction: Option<String>,
}

impl SourceLineage {
    /// A lineage identified only by its provider — the honest default when the
    /// upstream corpus is unknown.
    #[must_use]
    pub fn provider(provider: impl Into<String>) -> Self {
        Self {
            provider: provider.into(),
            corpus: None,
            jurisdiction: None,
        }
    }

    /// A lineage that names its upstream dataset, so resold copies collapse to
    /// one witness regardless of which provider served them.
    #[must_use]
    pub fn corpus(provider: impl Into<String>, corpus: impl Into<String>) -> Self {
        Self {
            provider: provider.into(),
            corpus: Some(corpus.into()),
            jurisdiction: None,
        }
    }

    /// Set the filing jurisdiction (builder).
    #[must_use]
    pub fn in_jurisdiction(mut self, jurisdiction: impl Into<String>) -> Self {
        self.jurisdiction = Some(jurisdiction.into());
        self
    }

    /// The key two observations must SHARE to be the same witness.
    ///
    /// When the corpus is known it alone is the identity — that is the whole
    /// point: `see_know` and `dehashed` both serving `linkedin-2021` are one
    /// witness. A jurisdiction qualifies a corpus (the same register filed in
    /// two jurisdictions is two filings) but never splits one: appending it
    /// when it is absent on one copy would wrongly re-separate them.
    #[must_use]
    pub fn witness_key(&self) -> String {
        match (&self.corpus, &self.jurisdiction) {
            (Some(c), Some(j)) => format!("corpus:{j}/{c}"),
            (Some(c), None) => format!("corpus:{c}"),
            (None, _) => format!("provider:{}", self.provider),
        }
    }
}

/// One unit of support for or against a claim — including the two outcomes that
/// are NOT evidence and must never be scored as such.
///
/// ABSENCE OF EASY EVIDENCE ≠ ABSENCE OF A NEXUS lives here. `Unattempted` and
/// `Failed` are recorded because they are operationally vital (they tell the
/// operator the search was incomplete, and they tell the scheduler where to
/// spend next) but they carry no evidentiary weight in either direction. This
/// is the type-level fix for the whole class of provider bugs where a failed
/// lookup returned an empty result and read as a clean negative.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Support {
    /// An observation or inference supporting the claim.
    For(Provenance),
    /// An observation or inference opposing the claim. Opposing evidence is
    /// first-class: the engine actively seeks it, and it is never discarded to
    /// keep a conclusion tidy.
    Against(Provenance),
    /// A source that WOULD bear on this claim was never queried (budget,
    /// missing credential, out of scope). Not a negative.
    Unattempted { provider: String, reason: String },
    /// A source was queried and the query FAILED (transport, quota, auth,
    /// schema drift). Emphatically not a negative: the commonest way a system
    /// invents a false clean answer about a hard target.
    Failed { provider: String, reason: String },
}

impl Support {
    /// The provenance backing this support, if it is evidentiary at all.
    #[must_use]
    pub fn provenance(&self) -> Option<&Provenance> {
        match self {
            Self::For(p) | Self::Against(p) => Some(p),
            Self::Unattempted { .. } | Self::Failed { .. } => None,
        }
    }

    /// Whether this support carries evidentiary weight. False for both
    /// non-outcomes, which is what keeps a failed lookup from reading as a
    /// finding of absence.
    #[must_use]
    pub fn is_evidentiary(&self) -> bool {
        self.provenance().is_some()
    }
}

/// Two observations that cannot both be true, preserved together.
///
/// The engine does not resolve a contradiction by picking a winner, and it does
/// not resolve one by averaging. It holds both values, marks the claim
/// [`ClaimState::Contested`], and records what evidence WOULD discriminate —
/// so the scheduler can go and look for exactly that.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Contradiction {
    /// The field or aspect the two observations disagree about (`dob`,
    /// `registered_address`, `controlling_shareholder`).
    pub aspect: String,
    /// The competing values, each with the lineage that asserted it. A
    /// `BTreeMap` keyed by value so the record is order-independent and two
    /// engines observing the same conflict serialise it identically.
    pub values: BTreeMap<String, Vec<SourceLineage>>,
    /// What observation would settle it. Empty means the engine has not yet
    /// identified a discriminator — itself a useful signal, not a failure.
    pub discriminators: Vec<String>,
    /// Set once discriminating evidence has actually resolved the conflict. The
    /// contradiction is RETAINED after resolution (the historical disagreement
    /// is part of the provenance) but stops contesting the claim.
    pub resolved_to: Option<String>,
}

impl Contradiction {
    /// A new, unresolved contradiction between two asserted values.
    #[must_use]
    pub fn new(
        aspect: impl Into<String>,
        left: (impl Into<String>, SourceLineage),
        right: (impl Into<String>, SourceLineage),
    ) -> Self {
        let mut values: BTreeMap<String, Vec<SourceLineage>> = BTreeMap::new();
        values.entry(left.0.into()).or_default().push(left.1);
        values.entry(right.0.into()).or_default().push(right.1);
        Self {
            aspect: aspect.into(),
            values,
            discriminators: Vec::new(),
            resolved_to: None,
        }
    }

    /// Record another lineage asserting one of the competing values (or a third
    /// value). Weight of numbers does NOT resolve a contradiction — this only
    /// enriches the record.
    pub fn add_assertion(&mut self, value: impl Into<String>, lineage: SourceLineage) {
        self.values.entry(value.into()).or_default().push(lineage);
    }

    /// Name an observation that would settle this conflict, for the scheduler
    /// to pursue.
    pub fn add_discriminator(&mut self, what: impl Into<String>) {
        let what = what.into();
        if !self.discriminators.contains(&what) {
            self.discriminators.push(what);
        }
    }

    /// Whether this still contests the claim.
    #[must_use]
    pub fn is_unresolved(&self) -> bool {
        self.resolved_to.is_none()
    }

    /// Resolve to one of the competing values. Refuses a value nobody asserted,
    /// so a resolution cannot invent an answer that no source ever gave.
    ///
    /// # Errors
    /// Returns the offending value when it is not among [`Self::values`].
    pub fn resolve_to(&mut self, value: impl Into<String>) -> Result<(), String> {
        let value = value.into();
        if !self.values.contains_key(&value) {
            return Err(value);
        }
        self.resolved_to = Some(value);
        Ok(())
    }
}

/// What a claim asserts. The variants exist so that rules can reason about
/// claim TYPE without string-matching a description.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimKind {
    /// Two identifiers name the same real-world entity.
    ///
    /// IDENTIFIER MATCH ≠ ENTITY IDENTITY: a matching handle, name, or hash
    /// produces THIS — a claim to be corroborated — and never an entity merge.
    /// The merge is a consequence of the claim reaching an actionable state,
    /// not a consequence of the match.
    IdentityLink { left_uid: String, right_uid: String },
    /// An entity has an attribute value (`dob`, `nationality`, `address`).
    Attribute { entity_uid: String, aspect: String },
    /// A relationship holds between two entities, optionally only during a
    /// bounded period — the shape a historical directorship or ownership takes.
    Relationship {
        from_uid: String,
        to_uid: String,
        nature: String,
    },
    /// An entity was at a place. Carries no coordinates itself: the geometry
    /// and its uncertainty live in [`crate::core::geo_confidence`].
    Presence { entity_uid: String, place: String },
    /// Control or beneficial ownership, possibly concealed through
    /// intermediaries — the structure hard targets are built from.
    Control {
        controller_uid: String,
        controlled_uid: String,
        mechanism: String,
    },
}

/// Temporal validity of a claim. A hard target's records are historical: a
/// directorship that ended in 2016 is not false, it is bounded, and treating
/// bounded facts as current (or as refuted) is a recurring source of wrong
/// conclusions.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Validity {
    /// Unix seconds the claim became true, if known.
    pub from: Option<u64>,
    /// Unix seconds it ceased to be true, if known. `None` with a known `from`
    /// means "still true as far as the evidence shows", NOT "true forever".
    pub until: Option<u64>,
}

impl Validity {
    /// Whether the claim holds at `at` (unix seconds). An unbounded end is open,
    /// and a wholly unknown period is treated as holding — the evidence simply
    /// does not bound it, and inventing a bound would be a fabricated finding.
    #[must_use]
    pub fn holds_at(&self, at: u64) -> bool {
        self.from.is_none_or(|f| at >= f) && self.until.is_none_or(|u| at < u)
    }

    /// Whether this period overlaps another — the test behind "were they
    /// directors of the same company AT THE SAME TIME", which is a materially
    /// different claim from "both were directors at some point".
    #[must_use]
    pub fn overlaps(&self, other: &Self) -> bool {
        let start = self.from.max(other.from);
        let end = match (self.until, other.until) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (Some(a), None) => Some(a),
            (None, Some(b)) => Some(b),
            (None, None) => None,
        };
        match (start, end) {
            (Some(s), Some(e)) => s < e,
            _ => true,
        }
    }
}

/// The bar a claim must clear to be promoted. Held as a value (not constants)
/// so a test can prove the bar does not move.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PromotionThresholds {
    /// Independent lineages required for [`ClaimState::Corroborated`].
    pub independent_lineages: usize,
    /// Whether [`ClaimState::Established`] additionally requires evidence that
    /// discriminates the claim from its competing hypotheses.
    pub established_requires_discriminator: bool,
}

impl Default for PromotionThresholds {
    fn default() -> Self {
        Self {
            independent_lineages: 2,
            established_requires_discriminator: true,
        }
    }
}

impl PromotionThresholds {
    /// The promotion bar for a target of the given difficulty.
    ///
    /// HARD TARGET ≠ LOWER STANDARD: this **ignores** `difficulty` and returns
    /// the same thresholds for every value. The parameter is present precisely
    /// so the invariant is visible at every call site and so
    /// `promotion_bar_is_identical_at_every_difficulty` can pin it — a future
    /// change that relaxes the bar for sparse targets has to delete a test that
    /// says, in words, why it must not.
    ///
    /// Difficulty legitimately changes how much the engine SPENDS
    /// ([`crate::core::claim::ExpansionBudget`]) — never what it BELIEVES.
    #[must_use]
    pub fn for_difficulty(_difficulty: TargetDifficulty) -> Self {
        Self::default()
    }
}

/// How hard a target is to research. Drives effort, never standards.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetDifficulty {
    /// Well-indexed, unambiguous, current.
    Routine,
    /// Sparse or fragmented traces; some ambiguity.
    Sparse,
    /// Obscured, multilingual, historical, cross-jurisdictional, or actively
    /// compartmentalised. Warrants the most effort and the same standards.
    Adversarial,
}

impl TargetDifficulty {
    /// Multiplier on the expansion budget. Explicitly super-linear for
    /// `Adversarial`: a hard target is where recursion must go DEEPER, since the
    /// nexus is real but its traces are dispersed across more hops.
    #[must_use]
    pub fn budget_multiplier(self) -> f64 {
        match self {
            Self::Routine => 1.0,
            Self::Sparse => 2.0,
            Self::Adversarial => 4.0,
        }
    }
}

/// An assertion about entities, with its full evidentiary record.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Claim {
    /// Stable identity of the claim itself.
    pub id: String,
    /// What is asserted.
    pub kind: ClaimKind,
    /// Every unit of support, including non-outcomes.
    pub support: Vec<Support>,
    /// Conflicts touching this claim, preserved whether resolved or not.
    pub contradictions: Vec<Contradiction>,
    /// Observations that discriminate this claim from its rivals. Distinct from
    /// mere support: a discriminator is evidence that the alternatives predict
    /// differently, which is the only kind that can close a hypothesis set.
    pub discriminating_evidence: Vec<Provenance>,
    /// When the claim holds.
    pub validity: Validity,
    /// Computed lifecycle state. Never set directly by callers — see
    /// [`Self::recompute_state`].
    pub state: ClaimState,
}

impl Claim {
    /// A new, unsupported claim. It starts — correctly — as
    /// [`ClaimState::Hypothesised`]: proposing a claim is not evidence for it.
    #[must_use]
    pub fn new(id: impl Into<String>, kind: ClaimKind) -> Self {
        Self {
            id: id.into(),
            kind,
            support: Vec::new(),
            contradictions: Vec::new(),
            discriminating_evidence: Vec::new(),
            validity: Validity::default(),
            state: ClaimState::Hypothesised,
        }
    }

    /// Add support and recompute the state.
    pub fn add_support(&mut self, support: Support, thresholds: PromotionThresholds) {
        self.support.push(support);
        self.recompute_state(thresholds);
    }

    /// Record a contradiction and recompute the state.
    pub fn add_contradiction(
        &mut self,
        contradiction: Contradiction,
        thresholds: PromotionThresholds,
    ) {
        self.contradictions.push(contradiction);
        self.recompute_state(thresholds);
    }

    /// Record evidence that discriminates this claim from its alternatives.
    pub fn add_discriminator(&mut self, p: Provenance, thresholds: PromotionThresholds) {
        self.discriminating_evidence.push(p);
        self.recompute_state(thresholds);
    }

    /// The number of genuinely INDEPENDENT witnesses supporting this claim.
    ///
    /// Three rules, each of which one-source-looks-like-three depends on:
    /// 1. only `Support::For` counts (a non-outcome is not a witness);
    /// 2. only [`Provenance::Observed`] counts (an inference is not a witness);
    /// 3. lineages are deduplicated by [`SourceLineage::witness_key`], so one
    ///    corpus resold by several providers counts once.
    #[must_use]
    pub fn independent_lineages(&self) -> usize {
        self.support
            .iter()
            .filter_map(|s| match s {
                Support::For(Provenance::Observed(l)) => Some(l.witness_key()),
                _ => None,
            })
            .collect::<BTreeSet<_>>()
            .len()
    }

    /// Lineages observed AGAINST the claim, deduplicated the same way.
    #[must_use]
    pub fn opposing_lineages(&self) -> usize {
        self.support
            .iter()
            .filter_map(|s| match s {
                Support::Against(Provenance::Observed(l)) => Some(l.witness_key()),
                _ => None,
            })
            .collect::<BTreeSet<_>>()
            .len()
    }

    /// Providers whose lookup was never made or failed — the engine's own map of
    /// what it does NOT know. Surfaced to the operator so an incomplete search is
    /// never mistaken for an exhaustive one.
    #[must_use]
    pub fn unresolved_gaps(&self) -> Vec<&str> {
        self.support
            .iter()
            .filter_map(|s| match s {
                Support::Unattempted { provider, .. } | Support::Failed { provider, .. } => {
                    Some(provider.as_str())
                }
                _ => None,
            })
            .collect()
    }

    /// Whether any contradiction is still open.
    #[must_use]
    pub fn is_contested(&self) -> bool {
        self.contradictions.iter().any(Contradiction::is_unresolved)
    }

    /// Derive the lifecycle state from the record.
    ///
    /// EXPLORE AGGRESSIVELY → PROMOTE CONSERVATIVELY: every branch here reduces
    /// or holds; none reaches for the benefit of the doubt. Order matters and is
    /// deliberate — `Withdrawn` and `Refuted` are terminal, contest beats
    /// corroboration (a conflict is not outvoted by weight of numbers), and a
    /// claim with only non-outcomes falls back to `Hypothesised` rather than
    /// anything that reads as a negative finding.
    pub fn recompute_state(&mut self, thresholds: PromotionThresholds) {
        if self.state == ClaimState::Withdrawn {
            return; // terminal: only new support via a fresh claim can revisit it
        }

        // Discriminating evidence AGAINST is the one thing that refutes. Weight
        // of ordinary opposing evidence does not: it contests.
        let refuted = self
            .support
            .iter()
            .any(|s| matches!(s, Support::Against(Provenance::Observed(_))))
            && self.independent_lineages() == 0;
        if refuted {
            self.state = ClaimState::Refuted;
            return;
        }

        if self.is_contested() || self.opposing_lineages() > 0 {
            self.state = ClaimState::Contested;
            return;
        }

        let lineages = self.independent_lineages();
        self.state = if lineages == 0 {
            // Includes the case where every support is Unattempted/Failed:
            // absence of easy evidence is not absence of a nexus.
            ClaimState::Hypothesised
        } else if lineages < thresholds.independent_lineages {
            ClaimState::Supported
        } else if thresholds.established_requires_discriminator
            && self.discriminating_evidence.is_empty()
        {
            ClaimState::Corroborated
        } else {
            ClaimState::Established
        };
    }

    /// Withdraw the claim because a source it rested on was retracted.
    pub fn withdraw(&mut self) {
        self.state = ClaimState::Withdrawn;
    }

    /// Whether the entities in this claim remain ELIGIBLE for expansion.
    ///
    /// EVERY NODE IS ELIGIBLE FOR EXPANSION ≠ EVERY NODE MUST BE EXPANDED: this
    /// answers only the first half. It is deliberately permissive — a
    /// hypothesised claim with zero support is eligible, because that is exactly
    /// the claim whose expansion might find the missing nexus, and a contested
    /// one is eligible because expansion is how contradictions get resolved.
    /// Only the terminal states are closed. What actually runs is decided by the
    /// scheduler's ranking under a budget, never by this predicate.
    #[must_use]
    pub fn may_expand(&self) -> bool {
        self.state.is_open()
    }
}

/// A set of mutually exclusive explanations for the same observations.
///
/// Hard targets almost never yield one explanation; they yield several, and the
/// failure mode is picking the most available one early. This type keeps the
/// alternatives alive and names what would separate them, so the scheduler can
/// spend its budget on the observation that actually decides rather than on more
/// of the evidence that does not.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CompetingHypotheses {
    /// What is being explained.
    pub question: String,
    /// The rival claims, by id.
    pub alternatives: Vec<String>,
    /// Observations that would raise one alternative and lower the others.
    pub discriminators: Vec<String>,
}

impl CompetingHypotheses {
    /// A new hypothesis set. Fewer than two alternatives is not a hypothesis
    /// set — it is a foregone conclusion — so callers should include the null
    /// or "someone else entirely" alternative explicitly.
    #[must_use]
    pub fn new(question: impl Into<String>, alternatives: Vec<String>) -> Self {
        Self {
            question: question.into(),
            alternatives,
            discriminators: Vec::new(),
        }
    }

    /// Whether the set is still genuinely open, i.e. more than one alternative
    /// remains unrefuted. `claims` supplies the current state of each id.
    #[must_use]
    pub fn is_open(&self, claims: &BTreeMap<String, ClaimState>) -> bool {
        self.alternatives
            .iter()
            .filter(|id| {
                claims
                    .get(*id)
                    .is_none_or(|s| !matches!(s, ClaimState::Refuted | ClaimState::Withdrawn))
            })
            .count()
            > 1
    }

    /// Whether a single alternative may be concluded: exactly one survives AND
    /// it carries discriminating evidence. Premature closure — one survivor
    /// merely because the others were never investigated — is refused here.
    #[must_use]
    pub fn concluded<'a>(&'a self, claims: &BTreeMap<String, Claim>) -> Option<&'a str> {
        let mut survivors = self.alternatives.iter().filter(|id| {
            claims
                .get(*id)
                .is_none_or(|c| !matches!(c.state, ClaimState::Refuted | ClaimState::Withdrawn))
        });
        let only = survivors.next()?;
        if survivors.next().is_some() {
            return None;
        }
        let survivor = claims.get(only)?;
        (!survivor.discriminating_evidence.is_empty() && survivor.state.is_actionable())
            .then_some(only.as_str())
    }
}

/// The recursion allowance for one expansion, scaled by difficulty.
///
/// Adaptive rather than fixed: a hard target gets MORE budget, not a lower bar.
/// The budget bounds work; it never bounds belief.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExpansionBudget {
    /// Remaining dispatches this expansion may spend.
    pub remaining: u32,
    /// Hard ceiling on hops from the seed, independent of `remaining`, so a
    /// cheap-but-deep chain still terminates.
    pub max_depth: u8,
}

impl ExpansionBudget {
    /// Budget for `difficulty`, from a base allowance.
    #[must_use]
    pub fn for_difficulty(base: u32, max_depth: u8, difficulty: TargetDifficulty) -> Self {
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let remaining = (f64::from(base) * difficulty.budget_multiplier()).round() as u32;
        Self {
            remaining,
            max_depth,
        }
    }

    /// Spend one dispatch. Returns false when exhausted, which the scheduler
    /// treats as "stop expanding" — never as "the claim is settled".
    pub fn spend(&mut self) -> bool {
        if self.remaining == 0 {
            return false;
        }
        self.remaining -= 1;
        true
    }
}
