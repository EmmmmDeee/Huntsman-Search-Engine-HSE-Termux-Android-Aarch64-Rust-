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

/// Per-field cap on breach-linked pivot identifiers — a heavily-breached subject
/// can co-occur with hundreds of stale aliases; a sample is enough to pivot on
/// without flooding expansion or the credit-bounded page.
pub(super) const MAX_PIVOTS_PER_FIELD: usize = 25;

/// Validity gate for a candidate pivot of `kind`. **Pure.** Keeps obvious junk
/// (a bare IP masquerading as a domain, a 1-char "name", a non-numeric phone)
/// out of the graph so a breach-linked pivot is always a usable identifier.
fn valid_pivot(kind: &EntityKind, v: &str) -> bool {
    match kind {
        EntityKind::Email => v.contains('@') && v.contains('.'),
        EntityKind::IpAddress => v.parse::<std::net::IpAddr>().is_ok(),
        EntityKind::Domain => v.contains('.') && v.parse::<std::net::IpAddr>().is_err(),
        EntityKind::Phone => v.chars().filter(char::is_ascii_digit).count() >= 7,
        EntityKind::Person => v.len() >= 2,
        // Username (and any other kind): any non-blank token.
        _ => !v.is_empty(),
    }
}

/// Build the full entity set for a DeHashed v2 response: the aggregate breach
/// entity ([`build_breach_entity`]) **plus** the non-credential identifiers the
/// returned records tie to the subject — the subject's *other* emails,
/// usernames, real name, phone, IPs and domains seen in the same leaks, emitted
/// as deduplicated `breach-linked` pivots. **Pure** (no network/IO). The queried
/// value is never echoed back, each field is capped at [`MAX_PIVOTS_PER_FIELD`],
/// and — per the no-credentials invariant — only the non-secret fields `Entry`
/// binds can appear here (passwords/hashes are unbound upstream).
pub(super) fn build_entities(
    kind: EntityKind,
    value: &str,
    selector: &str,
    entries: &[Entry],
    total: u64,
    balance: Option<&str>,
    scan_id: &str,
) -> Vec<Entity> {
    let mut out = vec![build_breach_entity(
        kind, value, selector, entries, total, balance, scan_id,
    )];

    let seed = value.trim().to_ascii_lowercase();
    let mut seen: std::collections::HashSet<(EntityKind, String)> = std::collections::HashSet::new();

    // (kind, the per-entry field carrying that identifier). One pass per field
    // keeps the cap per-field rather than global, so a noisy `username` list
    // can't starve the rarer `name`/`phone` pivots.
    // (identifier kind, the per-entry field that carries it).
    type FieldAccessor = fn(&Entry) -> &serde_json::Value;
    let fields: [(EntityKind, FieldAccessor); 6] = [
        (EntityKind::Email, |e| &e.email),
        (EntityKind::Username, |e| &e.username),
        (EntityKind::Person, |e| &e.name),
        (EntityKind::Phone, |e| &e.phone),
        (EntityKind::IpAddress, |e| &e.ip_address),
        (EntityKind::Domain, |e| &e.domain),
    ];

    for (ekind, accessor) in fields {
        let mut emitted = 0usize;
        for raw in entries.iter().flat_map(|e| db_names(accessor(e))) {
            if emitted >= MAX_PIVOTS_PER_FIELD {
                break;
            }
            let v = raw.trim();
            let lc = v.to_ascii_lowercase();
            if v.is_empty() || lc == seed || !valid_pivot(&ekind, v) {
                continue;
            }
            if !seen.insert((ekind.clone(), lc)) {
                continue;
            }
            let mut e = Entity::new(ekind.clone(), v, 0.55, scan_id);
            e.tag(tags::BREACH);
            e.tag("dehashed");
            e.tag("breach-linked");
            e.add_evidence(
                Evidence::new(
                    SRC,
                    format!("Identifier co-occurring with {selector}={value} in DeHashed leak(s)"),
                )
                .with_attr("linked_to", value)
                .with_attr("linked_via", selector),
            );
            out.push(e);
            emitted += 1;
        }
    }

    out
}
