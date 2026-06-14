//! Built-in OathNet **batch query generator**.
//!
//! Expands a single seed (email / username / name / phone / IP / domain) into
//! a large, de-duplicated array of distinct OathNet queries by crossing three
//! axes:
//!
//!   1. **Surface** — the breach corpus, plus (for login-indexable selectors)
//!      the stealer corpus.
//!   2. **Selector field** — `email` / `username` / `phone` / `domain` / `ip`
//!      / `q`, derived from the seed *and* from sub-parts of it (an email's
//!      local part becomes a `username` search, its domain a `domain` search).
//!   3. **Value permutation** — names and email local parts fan out into the
//!      handle shapes real accounts use (`first.last`, `flast`, `firstl`, …);
//!      phone numbers fan out into the digit/E.164 formats breach dumps store
//!      them in.
//!
//! The surface↔path and target-kind↔selector-field vocabulary is shared with
//! the `oathnet_pro` scan module via [`crate::util::oathnet`] (single source of
//! truth) rather than re-encoded here.
//!
//! The generator is **pure** (no IO, no quota) so the full plan can be previewed
//! for free and is exhaustively unit-testable; the CLI layer is what actually
//! dispatches it (and is what spends OathNet credits).
//!
//! # Guarantees
//!
//! [`generate`] returns a `Vec<BatchQuery>` that is:
//!
//! * **deterministic** — the same input always yields the same vec, in the same
//!   order (no `HashMap` iteration order leaks in);
//! * **seed-first** — the seed's own queries precede every derived query;
//! * **de-duplicated** — no two queries share a `(surface, field, value)` triple
//!   when compared case-insensitively on the value;
//! * **well-formed** — every query's `value` is trimmed and non-empty and its
//!   `field` is one of OathNet's selector fields; and
//! * **bounded** — at most `opts.max_queries` queries when that cap is non-zero.
//!
//! These are enforced by the test suite, not merely intended.
//!
//! # Limitations
//!
//! Handle permutation is **ASCII-only**: [`crate::util::oathnet_batch::helpers::name_tokens`]
//! treats any non-ASCII character as a separator, so an accented name
//! (`"Renée"`) loses the accented run rather than being transliterated. This is
//! deliberate — account handles are overwhelmingly ASCII and a fold table would
//! add a dependency for little real-world recall — but it means non-Latin seeds
//! fall back to the free-text `q` search only.

mod helpers;
mod query_gen;
mod types;

pub use query_gen::generate;
pub use types::{BatchOptions, BatchQuery, Origin, Surface};

#[cfg(test)]
mod tests;
