//! Target-identity matching for breach / stealer records.
//!
//! A broad provider search — above all a `full_name` — returns rows for many
//! different people. [`TargetMatch`] decides whether a given record actually
//! identifies the scan target, so every breach/stealer parser can quarantine
//! strangers (via `Entity::demote_to_candidate`) instead of minting them at full
//! confidence. Shared by `oathnet_pro` and `see_know` so the "is this row the
//! subject?" decision is defined in exactly one place rather than drifting
//! between the two pools. This module is purely the *matcher* — the demotion it
//! feeds is an orthogonal entity-tier capability that lives on `Entity` itself.

use serde_json::Value;

use crate::util::json::val_str;

/// Record fields, in priority order, whose value can identify the target. The
/// UNION of the spellings the providers use for the same identifier (`phone`
/// vs `phone_number`, `name` vs `full_name`), so a record is recognised as the
/// subject whichever key the upstream chose — matching on more fields only ever
/// *confirms* a genuine row, never invents a match (the value must still equal
/// or contain the target's terms).
const MATCH_FIELDS: &[&str] = &[
    "email",
    "username",
    "phone_number",
    "phone",
    "full_name",
    "name",
    "ip_address",
    "ip",
    "last_ip",
];

/// Shortest alphanumeric run a LONE target token may be and still license
/// substring matching. A one-token target is a handle (`alikareem`), where the
/// record often carries a suffixed variant (`alikareem2024`), so substring is
/// the right predicate — but only once the token is long enough to be
/// self-identifying. Below this a bare `"jo"` would hit inside every `"John"`.
const MIN_SIGNIFICANT_TERM: usize = 3;

/// How a target's own shape decides the strictness of its record matching.
///
/// Chosen once in [`TargetMatch::new`] from the target's UNFILTERED token count,
/// which is the fix for the defect this enum replaces: strictness used to be
/// derived from the *significance-filtered* term list, so a two-word name with a
/// short part (`"Sarah Ng"`, `"Ali Ng"`, `"Li Wu"` — short surnames are ordinary,
/// and the bug therefore fell hardest on non-Anglo names) kept only one term and
/// silently downgraded to permissive substring matching. That accepted any
/// stranger sharing the given name, and worse, a short term matches INSIDE an
/// unrelated word — `"ali"` hits in `"Natalie"` — minting an unrelated person's
/// PII onto the subject at full confidence.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Mode {
    /// Target has 2+ tokens: EVERY token must appear as a whole word in one
    /// field. Whole-word (not substring) is what stops the short-token-inside-a
    /// -longer-word false positive; a genuinely matching row still lands,
    /// because a row that IS the subject carries the name in its own name/email
    /// field where each token stands as a word.
    AllTokensWholeWord,
    /// Target is a single token of at least [`MIN_SIGNIFICANT_TERM`]: substring
    /// against the BARE token, not the raw target value — a leading `@` or other
    /// punctuation on a handle must not have to reappear in the record field.
    SingleTermSubstring(String),
    /// Nothing self-identifying to match on (a lone `"jo"`, or an empty value):
    /// exact equality only, never a partial hit. Deliberately conservative — a
    /// missed row is quarantined as a `candidate` and stays recoverable, whereas
    /// a false hit attributes a stranger's PII to the subject.
    ExactOnly,
}

/// Pre-computed, row-independent matching context for a single scan target.
///
/// Built once per scan (not per record) so the `to_lowercase()` allocation and
/// the mode decision happen exactly once rather than once per item on large
/// pages.
pub struct TargetMatch {
    /// Lowercased target value — the exact-equality short-circuit, and the
    /// needle handed to [`whole_word_token_match`](crate::util::str_util::whole_word_token_match)
    /// in multi-token mode.
    lower: String,
    /// Matching strictness, decided from the target's own shape.
    mode: Mode,
}

impl TargetMatch {
    pub fn new(target_value: &str) -> Self {
        let lower = target_value.to_lowercase();
        // Count the target's OWN tokens with no significance filter: the token
        // count answers "how many parts must corroborate?", which is a different
        // question from "is this part long enough to match loosely?". Deriving
        // both from one filtered list is precisely what let a short surname
        // collapse a two-part name into permissive single-term matching.
        let mut tokens = lower
            .split(|c: char| !c.is_alphanumeric())
            .filter(|w| !w.is_empty());
        let first = tokens.next();
        let mode = match (first, tokens.next()) {
            (Some(_), Some(_)) => Mode::AllTokensWholeWord,
            (Some(t), None) if t.len() >= MIN_SIGNIFICANT_TERM => {
                Mode::SingleTermSubstring(t.to_string())
            }
            _ => Mode::ExactOnly,
        };
        Self { lower, mode }
    }

    /// The pre-computed lowercased target value. Lets callers reuse the single
    /// `to_lowercase()` allocation already held here (e.g. for an exact-equality
    /// comparison against a record field) instead of re-lowercasing the target
    /// once per record on a hot per-row loop.
    #[inline]
    pub fn lower(&self) -> &str {
        &self.lower
    }

    /// True if any matchable field of `item` identifies the target.
    pub fn matches(&self, item: &Value) -> bool {
        for field in MATCH_FIELDS {
            if let Some(v) = val_str(item, field) {
                let vl = v.to_lowercase();
                if vl == self.lower {
                    return true;
                }
                let hit = match &self.mode {
                    // Delegated to the canonical whole-word predicate rather
                    // than re-implemented, so this matcher can never drift from
                    // the definition `au_unclaimed` / `wikidata` / the register
                    // matchers already share.
                    Mode::AllTokensWholeWord => {
                        crate::util::str_util::whole_word_token_match(&vl, &self.lower)
                    }
                    Mode::SingleTermSubstring(term) => vl.contains(term.as_str()),
                    Mode::ExactOnly => false,
                };
                if hit {
                    return true;
                }
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
