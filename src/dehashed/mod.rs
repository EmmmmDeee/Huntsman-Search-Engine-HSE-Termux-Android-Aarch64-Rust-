//! Opt-in `DeHashed` search client.
//!
//! A search is one exact-match identifier, one declared [`Purpose`], and one
//! bounded page. Wildcards, regex, lists and bulk input are refused before any
//! request is built ([`query`]). The key is sent only to the fixed API origin
//! ([`client`]). Nothing in the scan pipeline calls this module: it is reached
//! only through the explicit `dehashed` command ([`cli`]).
//!
//! The response schema in [`types`] is not verified against a live key. Read
//! that file's header before relying on field names.

pub mod cli;
pub mod client;
pub mod query;
pub mod types;

pub use client::{DehashedClient, DehashedError, SearchOutcome, SearchRequest};
pub use query::{Field, Purpose, QueryError, Selector};

#[cfg(test)]
mod tests;
