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
//!   `jsmith@gmail.com`): the strongest single cross-kind tie. **Not applied
//!   between two mailboxes at different domains** — see "Different mailboxes"
//!   below.
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
//! # Different mailboxes are different accounts
//!
//! No string signal fires between two email addresses at different domains.
//! [`identity_norm`] keeps only the local part, so every `jstewart@*` in a scan
//! normalises to `jstewart` and compares equal to every other — and a real
//! report showed the result: ~200 pairs asserting that one named individual held
//! mailboxes at an aerospace firm, a national navy, a university and dozens of
//! unrelated employers, each at `0.86` (handle-equivalence `0.80` fused with a
//! single shared source `0.30`), on a page that simultaneously reported 0%
//! corroboration.
//!
//! Two mailboxes at different domains are by construction different accounts.
//! They may still belong to one person, but a shared local part is not the
//! evidence that shows it — for a common name it is barely evidence at all. Such
//! a pair can still surface here, since **shared-source** alone reaches `0.657`
//! at three independent sources; it must simply be earned by corroboration
//! rather than granted by a coincidence of spelling.
//!
//! The suppression covers the whole string ladder rather than just the top tier,
//! because two identical handles also satisfy `substring-overlap` — demoting
//! instead of suppressing would still clear [`DEFAULT_MIN_SCORE`] once fused
//! with one shared source, and would have changed nothing.
//!
//! A known adjacent weakness, stated because it is not addressed here: a common
//! handle weakens *cross-kind* matches by the same logic (`jstewart` the
//! username against `jstewart@navy.mil`), but cross-kind linking is what
//! handle-equivalence exists for, and the evidence in hand covers the
//! email↔email case only. Narrowing further would need a frequency signal —
//! how many distinct domains carry a handle within the scan — not a wider ban.
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
use crate::core::resolve::canonical_email;
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

/// One side of a co-reference comparison — the canonical inputs
/// [`string_signal`] reads for a single entity. `is_person` enables the name-token
/// tier; `is_email` gates the domain-aware handle-equivalence tightening; `norm`
/// is the pre-computed [`identity_norm`] form of `raw`.
struct HandleSide<'a> {
    raw: &'a str,
    norm: &'a str,
    is_person: bool,
    is_email: bool,
}

/// The lower-cased domain of `value` if it is shaped like an email address.
///
/// Deliberately strict: exactly one `@`, with a non-empty local part and a
/// domain containing a dot. A username that merely contains `@`, or a bare
/// handle, yields `None` and is left to the ordinary string ladder — the
/// cross-domain suppression must only fire when both sides really are mailboxes,
/// because suppressing a genuine cross-kind match would lose real links.
fn email_domain(value: &str) -> Option<&str> {
    let (local, domain) = value.trim().split_once('@')?;
    if local.is_empty() || domain.contains('@') || !domain.contains('.') {
        return None;
    }
    Some(domain)
}

/// The strongest string-similarity signal between two canonical handles, as
/// `(weight, label)`, or `None` when the handles are unrelated. Tiers are
/// mutually exclusive: an exact match never also counts as an overlap.
fn string_signal(a: HandleSide<'_>, b: HandleSide<'_>) -> Option<(f64, &'static str)> {
    if a.norm.is_empty() || b.norm.is_empty() {
        return None;
    }
    // Two mailboxes at DIFFERENT domains are, by construction, different
    // accounts. A shared local part between them is not evidence of one person;
    // for a common name it is barely evidence of anything.
    //
    // [`identity_norm`] keeps only the local part, so every `jstewart@*` in a
    // scan normalises to `jstewart` and compares equal. A real report showed
    // what that costs: ~200 pairs asserting one named individual held mailboxes
    // at an aerospace firm, a national navy, a university and dozens of
    // unrelated employers, each scored 0.86 — `W_HANDLE_EQUIV` (0.80) fused with
    // a single shared source (0.30) — on a page simultaneously reporting 0%
    // corroboration. Those are defamatory-grade claims about a real person, and
    // they drown the genuine links in the dossier.
    //
    // The suppression covers the whole string ladder, not just the top tier:
    // `jstewart` and `jstewart` also satisfy [`identity_overlaps`], so demoting
    // to `W_SUBSTRING` (0.45) would still clear `DEFAULT_MIN_SCORE` once fused
    // with one shared source (0.615) and change nothing. Such a pair can still
    // surface — `shared-source` alone reaches 0.657 at three independent
    // sources — but it must now be earned by corroboration rather than granted
    // by a coincidence of spelling.
    //
    // Deliberately narrow: this is the email↔email case the evidence covers.
    // Cross-KIND matches (`jsmith` ↔ `jsmith@gmail.com`) are what
    // `W_HANDLE_EQUIV` was designed for and are left alone, though a common
    // handle weakens those too — see the module docs.
    if let (Some(dom_a), Some(dom_b)) = (email_domain(a.raw), email_domain(b.raw))
        && !dom_a.eq_ignore_ascii_case(dom_b)
    {
        return None;
    }
    if a.norm == b.norm {
        // Same domain (or not both emails) confirmed above. For an Email×Email
        // pair, still require the FULL canonical mailbox to match — not just the
        // shared local part — so `canonical_email`'s gmail dot/`+tag`/googlemail
        // folding is what decides genuine same-mailbox spellings, rather than a
        // bare local-part collision alone. Cross-kind ties (email local ↔
        // username / person) keep the local-part bridge — that is the intended
        // alias signal, not a domain-scoped identifier.
        let handle_equiv = if a.is_email && b.is_email {
            matches!(
                (canonical_email(a.raw), canonical_email(b.raw)),
                (Some(ca), Some(cb)) if ca == cb
            )
        } else {
            true
        };
        if handle_equiv {
            return Some((W_HANDLE_EQUIV, "handle-equivalence"));
        }
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
    if (a.is_person && name_token(a.raw, b.norm)) || (b.is_person && name_token(b.raw, a.norm)) {
        return Some((W_NAME_TOKEN, "name-token-match"));
    }
    if identity_overlaps(a.raw, b.raw) {
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
        is_email: bool,
        sources: std::collections::HashSet<&'a str>,
    }
    // Bound the O(N²) sweep. An imported breach/stealer dossier can seat 10^5+
    // identity entities; scoring every pair of those would pin a blocking-pool
    // thread for minutes. `entities` arrives confidence-ranked, so `.take` keeps
    // the strongest identities — a deterministic prefix (mirrors the
    // import-enrichment entity ceiling of 5_000).
    const MAX_COREF_NODES: usize = 5_000;
    let nodes: Vec<Node> = entities
        .iter()
        .filter(|e| is_identity_kind(&e.kind))
        .map(|e| Node {
            e,
            norm: identity_norm(&e.value),
            is_person: e.kind == EntityKind::Person,
            is_email: e.kind == EntityKind::Email,
            sources: e.corroborating_sources(),
        })
        .take(MAX_COREF_NODES)
        .collect();

    // Bound peak memory to ~`limit`, not O(N²): in a single-source dump every
    // pair shares that source (a >0 score), so an all-pairs `out` would allocate
    // billions of CoReferences before the final truncate → OOM. Trim down to the
    // top `limit` whenever the buffer fills; the survivors are exactly what the
    // final sort would keep, so the result is unchanged.
    let trim_at = limit.saturating_mul(4).max(4096);
    let mut out: Vec<CoReference> = Vec::new();
    for (i, a) in nodes.iter().enumerate() {
        for b in &nodes[i + 1..] {
            // Stable orientation: smaller UID is endpoint A.
            let (lo, hi) = if a.e.uid <= b.e.uid { (a, b) } else { (b, a) };

            let mut signals: Vec<&'static str> = Vec::new();
            let mut weights: Vec<f64> = Vec::new();

            if let Some((w, label)) = string_signal(
                HandleSide {
                    raw: &lo.e.value,
                    norm: &lo.norm,
                    is_person: lo.is_person,
                    is_email: lo.is_email,
                },
                HandleSide {
                    raw: &hi.e.value,
                    norm: &hi.norm,
                    is_person: hi.is_person,
                    is_email: hi.is_email,
                },
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
            if out.len() >= trim_at {
                out.sort_by(coref_order);
                out.truncate(limit);
            }
        }
    }

    // Strongest-first; deterministic UID-pair tie-break.
    out.sort_by(coref_order);
    out.truncate(limit);
    out
}

/// Ordering for [`resolve_coreferences`] results: strongest score first, then a
/// deterministic UID-pair tie-break. Shared by the in-loop trim and the final
/// sort so the bounded buffer keeps exactly the pairs the final sort would.
fn coref_order(x: &CoReference, y: &CoReference) -> std::cmp::Ordering {
    y.score
        .partial_cmp(&x.score)
        .unwrap_or(std::cmp::Ordering::Equal)
        .then_with(|| x.uid_a.cmp(&y.uid_a))
        .then_with(|| x.uid_b.cmp(&y.uid_b))
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
