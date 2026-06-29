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
];

/// Pre-computed, row-independent matching context for a single scan target.
///
/// Built once per scan (not per record) and reused across every row, so the
/// `to_lowercase()` allocation and the significant-term split happen exactly
/// once instead of once per item on large pages.
pub struct TargetMatch {
    /// Lowercased target value, used both for the exact-equality short-circuit
    /// and as the backing store the borrowed `terms` slice into.
    lower: String,
    /// Significant (`len >= 3`) alphanumeric terms of `lower`.
    terms: Vec<(usize, usize)>,
    /// Multi-term targets must match EVERY term within a single field.
    require_all_terms: bool,
}

impl TargetMatch {
    pub fn new(target_value: &str) -> Self {
        let lower = target_value.to_lowercase();
        // Store term spans (byte ranges) rather than `&str` to sidestep the
        // self-referential borrow of `lower`; resolved on demand in `matches`.
        let terms: Vec<(usize, usize)> = lower
            .split(|c: char| !c.is_alphanumeric())
            .filter(|w| w.len() >= 3)
            .map(|w| {
                let start = w.as_ptr() as usize - lower.as_ptr() as usize;
                (start, start + w.len())
            })
            .collect();
        let require_all_terms = terms.len() >= 2;
        Self {
            lower,
            terms,
            require_all_terms,
        }
    }

    /// True if any matchable field of `item` identifies the target.
    pub fn matches(&self, item: &Value) -> bool {
        for field in MATCH_FIELDS {
            if let Some(v) = val_str(item, field) {
                let vl = v.to_lowercase();
                if vl == self.lower {
                    return true;
                }
                if self.terms.is_empty() {
                    continue;
                }
                let mut terms = self.terms.iter().map(|&(s, e)| &self.lower[s..e]);
                // Multi-term targets (a full name like "Jordan Avery", or an
                // email) must match EVERY significant term within a single
                // field — not just one — so a row for "Jordan Parker" no longer
                // counts as the target on the shared first name (the dominant
                // junk source on name scans). Single-term targets keep
                // substring-contains matching.
                let hit = if self.require_all_terms {
                    terms.all(|t| vl.contains(t))
                } else {
                    terms.any(|t| vl.contains(t))
                };
                if hit {
                    return true;
                }
            }
        }
        false
    }
}

/// Whole-word, all-token, order-independent, case-insensitive name match: every
/// token of `query` must appear as a whole word in `candidate`.
///
/// The single shared definition of the conservative name-field comparison the
/// data.gov.au register modules (`agor`, the `asic_*` family) use to decide an
/// *exact* name hit before promoting a row to full confidence — previously
/// copied verbatim into ten module `entity.rs` files. Tokenisation splits on any
/// non-alphanumeric run, so it is agnostic to the register's name shape: a
/// register's `"SURNAME, FIRSTNAME"` and a seed's `"First Surname"` both reduce
/// to the same token set and match regardless of order, while the whole-word
/// requirement blocks a substring false-positive (`"Acme"` does not match
/// `"ACMEX"`, `"Ben"` does not match `"Benjamin"`). An empty `query` never
/// matches — a blank seed must not promote every row.
#[must_use]
pub fn name_all_tokens_match(candidate: &str, query: &str) -> bool {
    fn tokens(s: &str) -> Vec<&str> {
        s.split(|c: char| !c.is_alphanumeric())
            .filter(|t| !t.is_empty())
            .collect()
    }
    let words = tokens(candidate);
    let seed = tokens(query);
    !seed.is_empty()
        && seed
            .iter()
            .all(|tok| words.iter().any(|w| w.eq_ignore_ascii_case(tok)))
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
