//! Stable identifier helpers — a thin façade re-exporting the canonical UID
//! derivations from [`crate::core::entity`].
//!
//! The CLI surface (`cli::scan`, `cli::radar`, `cli::provision`) reaches for scan
//! identifiers through `util::uid` so the command layer depends on one foldable
//! utility path rather than wiring directly into `core::entity`'s internals. The
//! single source of the derivation still lives in [`crate::core::entity::scan_id`];
//! this only forwards to it, so the two can never drift.

/// Derive the deterministic scan identifier for a `(kind, value)` target.
///
/// Forwards verbatim to [`crate::core::entity::scan_id`] — see there for the hash
/// construction and the timestamp/counter mix that makes each invocation unique.
#[must_use]
pub fn scan_id(kind: &str, value: &str) -> String {
    crate::core::entity::scan_id(kind, value)
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
