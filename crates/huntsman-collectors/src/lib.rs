//! Huntsman Collectors: OSINT collectors over the async `Transport`, feeding the typed DAG.
//!
//! The first collector covers matrix domain 1 (Domain & DNS Topology): an unprivileged
//! RFC 1035 resolver over UDP/53 with a zero-copy, bounded response parser. All network I/O
//! routes through the injectable transport, so every collector tests fully offline.
//!
//! Lint levels live in `Cargo.toml` `[lints]`, per workspace policy.

pub mod dns;
mod dns_collector;

pub use dns_collector::DnsResolveCollector;
