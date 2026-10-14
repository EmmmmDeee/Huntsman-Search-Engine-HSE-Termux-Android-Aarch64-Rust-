//! Opt-in `DeHashed` search client.
//!
//! A search is one exact-match identifier, one declared [`Purpose`], and one
//! bounded page. Wildcards, regex, lists and bulk input are refused before any
//! request is built ([`query`]). The key is sent only to the fixed API origin
//! ([`client`]). Two paths reach this module: the explicit `dehashed` command
//! ([`cli`]), and the `exposure` leg ([`exposure`]), which reuses the same
//! client to add `DeHashed` to the keyed breach legs of `exposure ADDR`.
//!
//! The response schema in [`types`] is not verified against a live key. Read
//! that file's header before relying on field names.

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
