//! `core::network` — subject-centric relationship synthesis.
//!
//! The relation layer ([`crate::core::relation`]) produces typed edges; this turns
//! them into the analyst-facing picture a person scan is *for*: who the subject
//! is, and — grouped by *how* — everyone and everything they connect to, ranked
//! by the strength of the link. It is pure synthesis over a persisted
//! `(entities, relations)` snapshot (no store / engine access), so it is
//! deterministic and unit-testable, and both the web UI's Network view and
//! `GET /api/v1/scans/{id}/network` render it directly. Output is bounded per
//! group so the payload and the DOM stay small on a low-RAM Termux device.

use std::collections::{HashMap, HashSet};

use serde::Serialize;

use crate::core::entity::Entity;
use crate::core::relation::{Relation, RelationKind, reachable_count, undirected_adjacency};

/// Maximum connections returned per group; the remainder are summarised by
/// [`ConnectionGroup::total`]. A phone screen can't usefully scroll thousands of
/// edges, and the JSON stays small on a metered mobile link.
const GROUP_CAP: usize = 100;

/// One connection from the subject's point of view: the entity on the far end of
/// an incident edge, plus how it connects and how strongly.
#[derive(Debug, Clone, Serialize)]
pub struct Connection {
    pub uid: String,
    pub value: String,
    /// Far-end entity kind (display form, e.g. `email`, `person`).
    pub kind: String,
    /// The relation kind's wire string (e.g. `associated_with`).
    pub relation: String,
    /// A short human label for the edge (`relative`, `alias`, `email`, …).
    pub label: String,
    /// The edge's own confidence (how trusted the *link* is).
    pub edge_confidence: f64,
    /// The far-end entity's effective confidence (how trusted the *node* is).
    pub entity_confidence: f64,
    /// Far-end entity tier (`VERIFIED` / `PROBABLE` / `CANDIDATE`).
    pub classification: String,
    pub tags: Vec<String>,
}

/// A named, analyst-meaningful bucket of connections (people, identifiers, …).
#[derive(Debug, Clone, Serialize)]
pub struct ConnectionGroup {
    pub key: &'static str,
    pub label: &'static str,
    /// Connections, ranked strongest-first, capped at [`GROUP_CAP`].
    pub items: Vec<Connection>,
    /// Distinct connections in this group *before* the cap.
    pub total: usize,
}

/// The scanned subject — the seed-anchored hub every connection hangs off.
#[derive(Debug, Clone, Serialize)]
pub struct SubjectCard {
    pub uid: String,
    pub value: String,
    pub kind: String,
    pub confidence: f64,
    pub classification: String,
}

/// The synthesised subject network: the hub, its connections grouped by kind,
/// and reach statistics. `subject` is `None` only for an empty entity set.
#[derive(Debug, Clone, Default, Serialize)]
pub struct SubjectNetwork {
    pub subject: Option<SubjectCard>,
    pub groups: Vec<ConnectionGroup>,
    /// Distinct entities directly connected to the subject.
    pub direct_count: usize,
    /// Distinct entities in the subject's connected component (its whole reach,
    /// via any number of hops), excluding the subject itself.
    pub reachable_count: usize,
    /// Total relation edges in the scan.
    pub edge_count: usize,
}

/// Analyst-priority group order — people first (the point of a person scan),
/// infrastructure last (the haystack).
const GROUP_ORDER: &[&str] = &[
    "people",
    "identifiers",
    "aliases",
    "locations",
    "infrastructure",
];

/// Map a relation kind to its `(group key, group label)`. Exhaustive, so a new
/// `RelationKind` must be triaged here rather than silently vanishing from the
/// synthesis.
fn group_for(kind: RelationKind) -> (&'static str, &'static str) {
    match kind {
        RelationKind::AssociatedWith => ("people", "People — family & associates"),
        RelationKind::IdentifiedBy => ("identifiers", "Identifiers — accounts & contacts"),
        RelationKind::AliasOf | RelationKind::SameAs => ("aliases", "Aliases — the same persona"),
        RelationKind::LocatedAt | RelationKind::CoLocatedWith => ("locations", "Locations"),
        RelationKind::SubdomainOf
        | RelationKind::BelongsToDomain
        | RelationKind::HostedOn
        | RelationKind::ResolvesTo
        | RelationKind::RegisteredBy
        | RelationKind::DerivedFrom => ("infrastructure", "Infrastructure & lineage"),
    }
}

/// A short, human edge label, refined by the far-end entity where the relation
/// kind alone is ambiguous (an `AssociatedWith` to a `family-candidate` is a
/// "relative"; an `IdentifiedBy` is labelled by the identifier's kind).
fn label_for(kind: RelationKind, other: &Entity) -> String {
    match kind {
        RelationKind::AssociatedWith => {
            if other.has_tag("family-candidate") {
                "relative".to_string()
            } else {
                "associate".to_string()
            }
        }
        RelationKind::IdentifiedBy => other.kind.to_string(),
        RelationKind::AliasOf => "alias".to_string(),
        RelationKind::SameAs => "same as".to_string(),
        RelationKind::LocatedAt => "located at".to_string(),
        RelationKind::CoLocatedWith => "co-located".to_string(),
        RelationKind::SubdomainOf => "subdomain of".to_string(),
        RelationKind::BelongsToDomain => "mail domain".to_string(),
        RelationKind::HostedOn => "hosted on".to_string(),
        RelationKind::ResolvesTo => "resolves to".to_string(),
        RelationKind::RegisteredBy => "registered by".to_string(),
        RelationKind::DerivedFrom => "derived from".to_string(),
    }
}

/// Pick the subject hub: the seed-anchored entity (tagged `subject`, else `seed`)
/// — there is normally exactly one — falling back to the single
/// highest-effective-confidence entity so even an import with no anchor still
/// centres on its strongest node. Ties break on the smaller UID for determinism.
fn pick_subject(entities: &[Entity]) -> Option<&Entity> {
    let by_tag = |tag: &str| -> Option<&Entity> {
        entities.iter().filter(|e| e.has_tag(tag)).max_by(|a, b| {
            a.c_effective()
                .total_cmp(&b.c_effective())
                .then_with(|| b.uid.cmp(&a.uid))
        })
    };
    by_tag("subject").or_else(|| by_tag("seed")).or_else(|| {
        entities.iter().max_by(|a, b| {
            a.c_effective()
                .total_cmp(&b.c_effective())
                .then_with(|| b.uid.cmp(&a.uid))
        })
    })
}

/// Synthesise the subject network from a scan's persisted entities and relations.
///
/// Pure and deterministic: the same snapshot always yields the same network
/// (groups in [`GROUP_ORDER`], items ranked by edge then node confidence then
/// value, capped at [`GROUP_CAP`]). Robust to dangling edges (an endpoint UID not
/// present in `entities` is skipped, never panics).
#[must_use]
pub fn synthesize(entities: &[Entity], relations: &[Relation]) -> SubjectNetwork {
    let by_uid: HashMap<&str, &Entity> = entities.iter().map(|e| (e.uid.as_str(), e)).collect();

    let Some(subject) = pick_subject(entities) else {
        return SubjectNetwork {
            edge_count: relations.len(),
            ..Default::default()
        };
    };

    // Undirected adjacency: for the subject's view a link counts whichever way the
    // edge points. Shared with the path finder / AU-060 via the one canonical
    // builder (`None` = keep dangling endpoints; they're pruned at lookup below).
    let adj = undirected_adjacency(relations, None);

    // ── Direct connections, deduplicated per (group, neighbour) keeping the
    // strongest edge (a pair linked by two kinds shows once, under its primary
    // relation, at its best confidence). ──
    let mut best: HashMap<(&'static str, &str), Connection> = HashMap::new();
    let mut direct: HashSet<&str> = HashSet::new();
    if let Some(neighbours) = adj.get(subject.uid.as_str()) {
        for &(other_uid, kind, edge_conf) in neighbours {
            if other_uid == subject.uid {
                continue; // a self-loop is never a connection
            }
            let Some(other) = by_uid.get(other_uid).copied() else {
                continue; // dangling endpoint — skip, don't panic
            };
            direct.insert(other_uid);
            let (key, _) = group_for(kind);
            let slot = best.entry((key, other_uid)).or_insert_with(|| Connection {
                uid: other.uid.clone(),
                value: other.value.clone(),
                kind: other.kind.to_string(),
                relation: kind.as_str().to_string(),
                label: label_for(kind, other),
                edge_confidence: edge_conf,
                entity_confidence: other.c_effective(),
                classification: other.classify().as_str().to_string(),
                tags: other.tags.clone(),
            });
            if edge_conf > slot.edge_confidence {
                slot.edge_confidence = edge_conf;
                slot.relation = kind.as_str().to_string();
                slot.label = label_for(kind, other);
            }
        }
    }

    // Bucket the deduped connections into their groups.
    let mut buckets: HashMap<&'static str, Vec<Connection>> = HashMap::new();
    for ((key, _), conn) in best {
        buckets.entry(key).or_default().push(conn);
    }

    // Emit groups in analyst order; rank + cap each.
    let mut groups = Vec::new();
    for &key in GROUP_ORDER {
        let Some(mut items) = buckets.remove(key) else {
            continue;
        };
        items.sort_by(|a, b| {
            b.edge_confidence
                .total_cmp(&a.edge_confidence)
                .then_with(|| b.entity_confidence.total_cmp(&a.entity_confidence))
                .then_with(|| a.value.cmp(&b.value))
        });
        let total = items.len();
        items.truncate(GROUP_CAP);
        let label = group_for_key(key);
        groups.push(ConnectionGroup {
            key,
            label,
            items,
            total,
        });
    }

    SubjectNetwork {
        subject: Some(SubjectCard {
            uid: subject.uid.clone(),
            value: subject.value.clone(),
            kind: subject.kind.to_string(),
            confidence: subject.c_effective(),
            classification: subject.classify().as_str().to_string(),
        }),
        direct_count: direct.len(),
        reachable_count: reachable_count(subject.uid.as_str(), &adj),
        edge_count: relations.len(),
        groups,
    }
}

/// The group label for a key (the one place [`GROUP_ORDER`] keys are turned back
/// into labels, so the two can't drift).
fn group_for_key(key: &str) -> &'static str {
    match key {
        "people" => "People — family & associates",
        "identifiers" => "Identifiers — accounts & contacts",
        "aliases" => "Aliases — the same persona",
        "locations" => "Locations",
        _ => "Infrastructure & lineage",
    }
}

#[cfg(test)]
mod tests;
