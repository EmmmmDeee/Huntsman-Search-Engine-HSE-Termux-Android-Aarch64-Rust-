//! `core::leads` — proactive next-best-action recommendations.
//!
//! Discovery → connection ([`crate::core::relation`]) → synthesis
//! ([`crate::core::network`]) → **action**. This closes the loop: it ranks the
//! identities a scan surfaced but did NOT pivot on — most importantly the
//! family/associate connections the engine deliberately keeps below the
//! expansion floor (so a scan doesn't auto-fan-out across a whole family tree) —
//! and turns each into a one-click "scan this next" lead for the analyst.
//!
//! It builds directly on the network synthesis (no second graph traversal):
//! every lead is one of the subject's connections, re-scored for *pivot value*
//! (how much a fresh scan of it would yield) and annotated with *why* it matters
//! and whether it is still untapped. Pure over `(entities, relations, floor)`, so
//! it is deterministic and unit-testable; `GET /api/v1/scans/{id}/leads` and the
//! web UI's Leads tab render it directly. Bounded for a low-RAM Termux device.

use serde::Serialize;

use crate::core::entity::Entity;
use crate::core::network::{self, ConnectionGroup};
use crate::core::relation::Relation;

/// Maximum leads returned — a focused, actionable shortlist, not a second entity
/// dump. Ranked, so the cap keeps the highest-value pivots.
const LEAD_CAP: usize = 25;

/// A recommended next investigation step: an entity worth pivoting on, why, and
/// the scan that would pursue it.
#[derive(Debug, Clone, Serialize)]
pub struct Lead {
    pub uid: String,
    pub value: String,
    /// The entity kind (display form).
    pub kind: String,
    /// The `TargetKind` to seed a follow-up scan with (the web UI POSTs this).
    pub target_kind: &'static str,
    /// The recommended action — currently always a fresh focused scan.
    pub action: &'static str,
    /// A short, grounded justification ("A relative of the subject · not yet
    /// investigated").
    pub reason: String,
    /// Pivot-value score (higher = investigate sooner). Opaque ranking number.
    pub score: f64,
    /// Far-end entity tier (`VERIFIED` / `PROBABLE` / `CANDIDATE`).
    pub classification: String,
    /// The network group this lead came from (`people` / `identifiers` / …).
    pub group: &'static str,
}

/// Base pivot value by entity kind — how widely a fresh scan of it tends to fan
/// out (mirrors the engine's seed-yield ordering: identities richest, infra
/// thinner). `None` ⇒ not independently pivotable, so never a lead.
fn pivot(kind: &str) -> Option<(&'static str, f64)> {
    match kind {
        "person" => Some(("full_name", 1.0)),
        "email" => Some(("email", 0.9)),
        "username" => Some(("username", 0.7)),
        "phone" => Some(("phone", 0.55)),
        "domain" => Some(("domain", 0.5)),
        "ip_address" => Some(("ip_address", 0.35)),
        _ => None,
    }
}

/// Per-group lead weight: a *new* person or persona is fresh territory to map,
/// while an identifier the subject already owns is confirmation more than
/// expansion — so people/aliases lead, owned identifiers and infra trail.
fn group_weight(group: &str) -> f64 {
    match group {
        "people" => 1.0,
        "aliases" => 0.85,
        "identifiers" => 0.6,
        "locations" => 0.4,
        _ => 0.5,
    }
}

/// Composite pivot score: kind value × group weight × node trust × link strength,
/// boosted when the entity is still untapped (below the expansion floor, so the
/// engine did not pivot it — exactly the lead a human should pick up). The trust
/// term floors at 0.4 so a low-confidence-but-novel relative still ranks, not
/// zero.
fn score(
    kind_value: f64,
    group_weight: f64,
    entity_conf: f64,
    edge_conf: f64,
    untapped: bool,
) -> f64 {
    let base = kind_value * group_weight * (0.4 + 0.6 * entity_conf) * (0.5 + 0.5 * edge_conf);
    if untapped { base * 1.6 } else { base }
}

/// A grounded, human reason for the lead, from its group, label, exposure tags
/// and untapped status.
fn reason(group: &str, label: &str, tags: &[String], untapped: bool) -> String {
    let head = match group {
        "people" if label == "relative" => "A relative of the subject",
        "people" => "An associate of the subject",
        "identifiers" => "An identifier the subject owns",
        "aliases" => "An alias of the subject's persona",
        "locations" => "A place tied to the subject",
        _ => "Connected to the subject's network",
    };
    let mut r = head.to_string();
    if tags
        .iter()
        .any(|t| t == "breach" || t == "stealer-log" || t == "breach-derived")
    {
        r.push_str(" · exposed in a breach");
    }
    if untapped {
        r.push_str(" · not yet investigated");
    }
    r
}

/// Rank the scan's untapped pivots into a focused, actionable shortlist.
///
/// `expansion_floor` is the scan's `min_expand_confidence`; a connection below it
/// was not auto-pivoted by the engine, so it earns the untapped boost. Pure and
/// deterministic: leads are ranked by score, ties broken by value, capped at
/// [`LEAD_CAP`].
#[must_use]
pub fn recommend(entities: &[Entity], relations: &[Relation], expansion_floor: f64) -> Vec<Lead> {
    let net = network::synthesize(entities, relations);
    let mut leads: Vec<Lead> = net
        .groups
        .iter()
        .flat_map(|group: &ConnectionGroup| {
            group.items.iter().filter_map(move |conn| {
                let (target_kind, kind_value) = pivot(&conn.kind)?;
                let untapped = conn.entity_confidence < expansion_floor;
                Some(Lead {
                    uid: conn.uid.clone(),
                    value: conn.value.clone(),
                    kind: conn.kind.clone(),
                    target_kind,
                    action: "scan",
                    reason: reason(group.key, &conn.label, &conn.tags, untapped),
                    score: score(
                        kind_value,
                        group_weight(group.key),
                        conn.entity_confidence,
                        conn.edge_confidence,
                        untapped,
                    ),
                    classification: conn.classification.clone(),
                    group: group.key,
                })
            })
        })
        .collect();

    leads.sort_by(|a, b| {
        b.score
            .total_cmp(&a.score)
            .then_with(|| a.value.cmp(&b.value))
    });
    leads.truncate(LEAD_CAP);
    leads
}

#[cfg(test)]
mod tests;
