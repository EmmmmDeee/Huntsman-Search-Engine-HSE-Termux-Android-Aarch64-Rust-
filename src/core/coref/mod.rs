//! `core::coref` — cross-identifier **co-reference scoring** (people-centric
//! identity resolution).
//!
//! Three existing layers resolve identity in HSE, each from a different angle:
//!
//! * [`crate::core::resolve::suggest_merges`] collapses two spellings of the
//!   *same identifier* (Gmail dot-blindness, phone notation, name token order)
//!   into one entity — record-level **de-duplication** of one kind.
//! * The exact-UID correlator fuses values that normalise identically.
//! * [`crate::core::relation::graph::resolve_identity_clusters`] groups
//!   identities that are already joined by **relation edges** (union-find over
//!   the relation graph).
//!
//! None of them answers the people-centric question an investigator actually
//! asks of a pile of raw selectors: *do this **email** and this **username**, or
//! this **phone** and this **person**, belong to the **same individual**?* —
//! when no relation edge exists yet and the two are different kinds, so neither
//! dedup nor the exact matcher can see it. This module fills that gap with a
//! graded, multi-signal **record-linkage** score over every pair of
//! identity-bearing entities.
//!
//! # The score — independent signals fused by noisy-OR
//! Each pair accrues evidence from orthogonal signals, combined as
//! `1 − ∏(1 − wᵢ)` so independent corroboration *compounds* (two weak signals
//! beat either alone) without ever exceeding 1.0:
//!
//! * **handle-equivalence** (`0.80`) — the two canonical handles
//!   ([`crate::core::scan::identity_norm`]) are *equal* (`jsmith` ↔
//!   `jsmith@gmail.com`): the strongest single cross-kind tie.
//! * **name-token-match** (`0.62`) — one side is a `Person` whose every name
//!   token (≥2 chars) appears in the other's canonical handle (`John Smith` ↔
//!   `johnsmith_au`), with ≥2 tokens so a bare shared first name can't fire it.
//! * **substring-overlap** (`0.45`) — the handles share a ≥4-char run
//!   ([`crate::core::scan::identity_overlaps`]) without being equal.
//! * **shared-source** (`1 − 0.7ᵏ`, k = shared corroborating sources) —
//!   the pair co-occurs in `k` independent corroborating sources. Deliberately
//!   sub-threshold for a single shared source (k=1 → 0.30): one common crawl
//!   source is weak co-occurrence, but several compound into a real tie, and it
//!   lifts any string signal it accompanies.
//!
//! The three string signals are mutually exclusive (only the strongest tier
//! fires); **shared-source** is orthogonal and stacks on top.
//!
//! # Read-only, pure, deterministic
//! [`resolve_coreferences`] borrows the entity slice immutably, allocates its
//! own state, performs no I/O, and mutates nothing — every hypothesis is a
//! suggestion the caller may ignore. Output is a pure function of the input
//! multiset: candidates are sorted by score (then UID pair), so shuffling the
//! input yields identical output. Conservative by design — a pair below
//! `min_score` is simply absent, so a namesake with no shared source and a
//! different handle never appears.

use crate::core::entity::{Entity, EntityKind};
use crate::core::relation::graph::is_identity_kind;
use crate::core::scan::{identity_norm, identity_overlaps};

/// Weight of an exact canonical-handle match — the strongest cross-kind tie.
const W_HANDLE_EQUIV: f64 = 0.80;
/// Weight of a `Person`'s name tokens all appearing in the other's handle.
const W_NAME_TOKEN: f64 = 0.62;
/// Weight of a ≥4-char shared substring that is not a full handle match.
const W_SUBSTRING: f64 = 0.45;
/// Per-shared-source decay base: the shared-source signal is `1 − BASE^k`.
const SHARED_SOURCE_BASE: f64 = 0.7;
/// Default emission threshold — a pair must reach this fused score to surface.
pub const DEFAULT_MIN_SCORE: f64 = 0.55;

/// A scored hypothesis that two **distinct** identity entities refer to the same
/// individual — the output of [`resolve_coreferences`]. Carries enough to render
/// the link and explain *why* it was proposed, without re-deriving the score.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct CoReference {
    /// UID of the lexicographically-smaller endpoint (stable orientation).
    pub uid_a: String,
    /// UID of the larger endpoint.
    pub uid_b: String,
    /// Value of `uid_a`'s entity (for display).
    pub value_a: String,
    /// Value of `uid_b`'s entity (for display).
    pub value_b: String,
    /// Kind of `uid_a`'s entity.
    pub kind_a: EntityKind,
    /// Kind of `uid_b`'s entity.
    pub kind_b: EntityKind,
    /// Fused noisy-OR co-reference score in `0.0..=1.0`; higher = more likely the
    /// same individual.
    pub score: f64,
    /// The signals that fired, strongest-first — the human-readable basis.
    pub signals: Vec<&'static str>,
}

/// The strongest string-similarity signal between two canonical handles, as
/// `(weight, label)`, or `None` when the handles are unrelated. Tiers are
/// mutually exclusive: an exact match never also counts as an overlap.
///
/// `a_is_person` / `b_is_person` enable the name-token tier, which only applies
/// when one side is a `Person` (a multi-token legal name embedded in the other's
/// handle). `norm_a` / `norm_b` are the pre-computed [`identity_norm`] forms.
fn string_signal(
    raw_a: &str,
    raw_b: &str,
    norm_a: &str,
    norm_b: &str,
    a_is_person: bool,
    b_is_person: bool,
) -> Option<(f64, &'static str)> {
    if norm_a.is_empty() || norm_b.is_empty() {
        return None;
    }
    if norm_a == norm_b {
        return Some((W_HANDLE_EQUIV, "handle-equivalence"));
    }
    // Name-token match: a Person's every token (≥2 chars), of which there are ≥2,
    // is a substring of the OTHER side's canonical handle.
    let name_token = |person: &str, handle_norm: &str| -> bool {
        let tokens: Vec<String> = person
            .split_whitespace()
            .map(identity_norm)
            .filter(|t| t.len() >= 2)
            .collect();
        tokens.len() >= 2 && tokens.iter().all(|t| handle_norm.contains(t.as_str()))
    };
    if (a_is_person && name_token(raw_a, norm_b)) || (b_is_person && name_token(raw_b, norm_a)) {
        return Some((W_NAME_TOKEN, "name-token-match"));
    }
    if identity_overlaps(raw_a, raw_b) {
        return Some((W_SUBSTRING, "substring-overlap"));
    }
    None
}

/// Combine independent signal weights by noisy-OR: `1 − ∏(1 − wᵢ)`. Independent
/// corroboration compounds (two 0.5 signals → 0.75) and the result never exceeds
/// 1.0. Order-independent. An empty iterator yields `0.0`.
fn noisy_or(weights: impl IntoIterator<Item = f64>) -> f64 {
    1.0 - weights
        .into_iter()
        .fold(1.0, |acc, w| acc * (1.0 - w.clamp(0.0, 1.0)))
}

/// Resolve graded **co-reference** hypotheses over the identity-bearing entities
/// in `entities`: every pair of distinct [`is_identity_kind`] entities whose
/// fused multi-signal score reaches `min_score`, strongest-first.
///
/// This is the people-centric record-linkage layer described in the module docs
/// — it links *different* selectors (an email and a username, a phone and a
/// person) that belong to one individual, complementing (never replacing) the
/// same-identifier dedup of [`crate::core::resolve::suggest_merges`] and the
/// relation-graph clustering of
/// [`crate::core::relation::graph::resolve_identity_clusters`]. Pure, read-only
/// and deterministic; truncated to `limit`. Pass `min_score = 0.0` to surface
/// every co-occurring pair, or [`DEFAULT_MIN_SCORE`] for the conservative default.
///
/// O(N²) over the identity entities (the same order as the subject-network
/// synthesis), each pair scored in near-constant time.
#[must_use]
pub fn resolve_coreferences(entities: &[Entity], min_score: f64, limit: usize) -> Vec<CoReference> {
    // Project to the identity entities once, pre-computing the per-entity fields
    // every pair re-reads: canonical handle, person flag, corroborating sources.
    struct Node<'a> {
        e: &'a Entity,
        norm: String,
        is_person: bool,
        sources: std::collections::HashSet<&'a str>,
    }
    let nodes: Vec<Node> = entities
        .iter()
        .filter(|e| is_identity_kind(&e.kind))
        .map(|e| Node {
            e,
            norm: identity_norm(&e.value),
            is_person: e.kind == EntityKind::Person,
            sources: e.corroborating_sources(),
        })
        .collect();

    let mut out: Vec<CoReference> = Vec::new();
    for (i, a) in nodes.iter().enumerate() {
        for b in &nodes[i + 1..] {
            // Stable orientation: smaller UID is endpoint A.
            let (lo, hi) = if a.e.uid <= b.e.uid { (a, b) } else { (b, a) };

            let mut signals: Vec<&'static str> = Vec::new();
            let mut weights: Vec<f64> = Vec::new();

            if let Some((w, label)) = string_signal(
                &lo.e.value,
                &hi.e.value,
                &lo.norm,
                &hi.norm,
                lo.is_person,
                hi.is_person,
            ) {
                signals.push(label);
                weights.push(w);
            }

            let shared = lo.sources.intersection(&hi.sources).count();
            if shared > 0 {
                weights.push(1.0 - SHARED_SOURCE_BASE.powi(shared as i32));
                signals.push("shared-source");
            }

            if signals.is_empty() {
                continue;
            }
            let score = noisy_or(weights.iter().copied());
            if score + f64::EPSILON < min_score {
                continue;
            }
            out.push(CoReference {
                uid_a: lo.e.uid.clone(),
                uid_b: hi.e.uid.clone(),
                value_a: lo.e.value.clone(),
                value_b: hi.e.value.clone(),
                kind_a: lo.e.kind.clone(),
                kind_b: hi.e.kind.clone(),
                score,
                signals,
            });
        }
    }

    // Strongest-first; deterministic UID-pair tie-break.
    out.sort_by(|x, y| {
        y.score
            .partial_cmp(&x.score)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| x.uid_a.cmp(&y.uid_a))
            .then_with(|| x.uid_b.cmp(&y.uid_b))
    });
    out.truncate(limit);
    out
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
