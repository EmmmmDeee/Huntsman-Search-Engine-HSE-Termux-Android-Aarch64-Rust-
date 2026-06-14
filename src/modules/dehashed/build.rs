//! Pure helpers for DeHashed entity construction.

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    scan::TargetKind,
    tags,
};

use super::types::Entry;

pub(super) const SRC: &str = "dehashed";

/// Top breach databases to surface by frequency.
pub(super) const MAX_DATABASES: usize = 5;

/// The DeHashed query selector for a target kind, or `None` for a kind this
/// module does not search. **Pure** — kept in lockstep with [`super::DeHashed`]'s
/// `accepts` implementation.
/// The v2 selector syntax is unchanged from v1 (`email:`, `username:`, …).
pub(super) fn selector_for(kind: TargetKind) -> Option<&'static str> {
    Some(match kind {
        TargetKind::Email => "email",
        TargetKind::Username => "username",
        TargetKind::Phone => "phone",
        TargetKind::FullName => "name",
        TargetKind::IpAddress => "ip_address",
        TargetKind::Domain => "domain",
        _ => return None,
    })
}

/// Flatten a v2 `database_name` value (`string | [string] | null`) into the
/// source-database names it carries. Non-string array members are skipped.
pub(super) fn db_names(v: &serde_json::Value) -> Vec<&str> {
    match v {
        serde_json::Value::String(s) => vec![s.as_str()],
        serde_json::Value::Array(a) => a.iter().filter_map(serde_json::Value::as_str).collect(),
        _ => Vec::new(),
    }
}

/// Render the v2 `balance` value for display, accepting either a JSON number
/// or string and rejecting anything else (or a blank string) as absent.
pub(super) fn balance_str(v: &Option<serde_json::Value>) -> Option<String> {
    match v {
        Some(serde_json::Value::Number(n)) => Some(n.to_string()),
        Some(serde_json::Value::String(s)) if !s.trim().is_empty() => Some(s.trim().to_string()),
        _ => None,
    }
}

/// Build the breach entity from a v2 response. **Pure** (no network/IO): folds
/// the returned `entries` into aggregate-only evidence — total hit count, rows
/// returned, the top source databases by frequency, and the remaining credit
/// balance — and raises the breach tags. Per the no-credentials-in-evidence
/// invariant, `Entry` binds no password/hash fields, so none can leak here.
/// `total` is the server's full count (which can exceed the truncated
/// `entries.len()`).
pub(super) fn build_breach_entity(
    kind: EntityKind,
    value: &str,
    selector: &str,
    entries: &[Entry],
    total: u64,
    balance: Option<&str>,
    scan_id: &str,
) -> Entity {
    let mut entity = Entity::new(kind, value, 0.88, scan_id);
    entity.tag(tags::BREACH);
    entity.tag("dehashed");

    // Top databases by frequency. v2 lists a record's source(s) in
    // `database_name` (an array), so flatten across all entries.
    let top = crate::util::freq::top_n(
        entries.iter().flat_map(|e| db_names(&e.database_name)),
        MAX_DATABASES,
    );

    let mut ev = Evidence::new(
        SRC,
        format!("DeHashed: {total} breach record(s) for {selector}={value}"),
    )
    .with_attr("hits", total.to_string())
    .with_attr("returned", entries.len().to_string())
    .with_attr("selector", selector);
    if !top.is_empty() {
        ev = ev.with_attr("top_databases", top);
    }
    if let Some(b) = balance {
        ev = ev.with_attr("credit_balance", b);
    }
    entity.add_evidence(ev);
    entity
}
