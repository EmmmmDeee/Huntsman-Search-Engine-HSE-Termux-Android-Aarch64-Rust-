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
                if self.terms.is_empty() {
                    continue;
                }
                let mut terms = self.terms.iter().map(|&(s, e)| &self.lower[s..e]);
                // Multi-term targets (a full name like "Jordan Avery", or an
                // email) must match EVERY significant term within a single field,
                // AT A TOKEN BOUNDARY — each term must be a WHOLE alphanumeric token
                // of the field value, not merely a substring buried inside a longer
                // token. Requiring all terms already stopped a shared FIRST name
                // ("Jordan Parker") from matching; the token-boundary check
                // additionally stops a look-alike whose every term is a PREFIX of an
                // unrelated token ("Jordanna Averyl" — jordan ⊂ jordanna, avery ⊂
                // averyl), the residual namesake leak on name scans. A genuine row
                // ("JORDAN MICHAEL AVERY") still matches — its tokens include the
                // exact terms. Single-term targets (a handle) keep substring
                // matching, so a concatenated variant ("alikareem2024") still counts.
                let hit = if self.require_all_terms {
                    let field_tokens: std::collections::HashSet<&str> = vl
                        .split(|c: char| !c.is_alphanumeric())
                        .filter(|w| !w.is_empty())
                        .collect();
                    terms.all(|t| field_tokens.contains(t))
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

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
