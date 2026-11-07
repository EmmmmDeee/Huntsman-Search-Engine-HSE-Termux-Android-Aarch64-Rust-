//! Opt-in `DeHashed` search client.
//!
//! A search is one exact-match identifier, one declared [`Purpose`], and one
//! bounded page. Wildcards, regex, lists and bulk input are refused before any
//! request is built ([`query`]). The key is sent only to the fixed API origin
//! ([`client`]). Two paths reach this module: the explicit `dehashed` command
//! ([`cli`]), and the `exposure` leg ([`exposure`]), which reuses the same
//! client to add `DeHashed` to the keyed breach legs of `exposure ADDR`.
//!
//! The response schema in [`types`] follows `DeHashed`'s published v2
//! documentation and live unauthenticated probes; that file's header says which
//! fields are first-party and which are reported by others. On 2026-11-07 it was
//! verified against the live API with a real key (`tests/dehashed_live.rs`, run
//! with `--ignored`): every record of a page decoded, every non-credential value
//! kept verbatim, no credential value retained, and an email search exact.

pub mod cli;
pub mod client;
pub mod collector;
pub mod exposure;
pub mod query;
pub mod types;

pub use client::{DehashedClient, DehashedError, SearchOutcome, SearchRequest};
pub use collector::{COLLECTOR_ID, collect};
pub use query::{Field, Purpose, QueryError, Selector};

#[cfg(test)]
mod tests;
