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

/// `(key, label)` for every group the synthesis can produce, in analyst-priority
/// emission order — people first (the point of a person scan), infrastructure
/// last (the haystack).
///
/// ONE table, so a group's display name cannot drift from the key
/// [`group_for`] assigns it. (It previously could: `group_for` returned a label
/// its only caller discarded, and a separate key→label function with a catch-all
/// arm produced the one that shipped. A group added to the first and missed by
/// the second silently rendered under "Infrastructure & lineage".)
const GROUPS: &[(&str, &str)] = &[
    ("people", "People — family & associates"),
    ("identifiers", "Identifiers — accounts & contacts"),
    ("aliases", "Aliases — the same persona"),
    (
        "affiliations",
        "Affiliations — organisations, offices & control",
    ),
    ("locations", "Locations"),
    ("infrastructure", "Infrastructure & lineage"),
];

/// Map a relation kind to its group key (labelled by [`GROUPS`]). Exhaustive, so
/// a new `RelationKind` must be triaged here rather than silently vanishing from
/// the synthesis.
fn group_for(kind: RelationKind) -> &'static str {
    match kind {
        RelationKind::AssociatedWith => "people",
        RelationKind::IdentifiedBy | RelationKind::SharesSecretWith => "identifiers",
        RelationKind::AliasOf | RelationKind::SameAs | RelationKind::SameIdentity => "aliases",
        RelationKind::LocatedAt | RelationKind::CoLocatedWith => "locations",
        RelationKind::SubdomainOf
        | RelationKind::BelongsToDomain
        | RelationKind::HostedOn
        | RelationKind::ResolvesTo
        | RelationKind::RegisteredBy
        | RelationKind::DerivedFrom
        | RelationKind::SameOperator => "infrastructure",
        RelationKind::OfficerOf
        | RelationKind::EmployedBy
        | RelationKind::MemberOf
        | RelationKind::ControlledBy
        | RelationKind::OperatedBy => "affiliations",
    }
}

/// Evidence attribute keys carrying the ROLE an affiliation edge represents,
/// most-specific first — a registry's officer position, a profile's job title, a
/// listed degree. Read off the ORGANISATION at the far end of the edge, which is
/// where the grounding modules attach them (`opencorporates`' `officer_position`,
/// `proxycurl`'s `title` and `degree`).
const AFFILIATION_ROLE_ATTRS: &[&str] = &["officer_position", "title", "degree"];

/// The first [`AFFILIATION_ROLE_ATTRS`] value on `org`, lowercased and trimmed —
/// the concrete role behind an affiliation edge, so the operator reads
/// "secretary" or "chief financial officer" rather than the generic edge name.
/// `None` when the source recorded no role, leaving the caller its generic label.
fn affiliation_role(org: &Entity) -> Option<String> {
    AFFILIATION_ROLE_ATTRS.iter().find_map(|key| {
        org.evidence
            .iter()
            .flat_map(|ev| &ev.attributes)
            .find(|(k, v)| k.eq_ignore_ascii_case(key) && !v.trim().is_empty())
            .map(|(_, v)| v.trim().to_lowercase())
    })
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
        RelationKind::SameOperator => "same operator".to_string(),
        RelationKind::SameIdentity => "profile".to_string(),
        RelationKind::SharesSecretWith => "shared secret".to_string(),
        // The affiliation edges name the concrete role where the source recorded
        // one — "director" beats "officer of", and it is the difference an
        // analyst is actually reading the group for.
        RelationKind::OfficerOf => affiliation_role(other).unwrap_or_else(|| "officer".to_string()),
        RelationKind::EmployedBy => {
            affiliation_role(other).unwrap_or_else(|| "employer".to_string())
        }
        RelationKind::MemberOf => {
            affiliation_role(other).unwrap_or_else(|| "member of".to_string())
        }
        RelationKind::ControlledBy => "controlled by".to_string(),
        RelationKind::OperatedBy => "operated by".to_string(),
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
/// (groups in [`GROUPS`] order, items ranked by edge then node confidence then
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

    // Undirected adjacency CONFINED to present entities: for the subject's view a
    // link counts whichever way the edge points, but only between entities that
    // actually exist in this scan. Confining (vs the old `None`, which kept dangling
    // endpoints) keeps `reachable_count` — a plain component walk over `adj` — honest
    // to its "distinct ENTITIES reachable" contract and consistent with
    // `direct_count`, which already skips endpoints absent from `by_uid`. Without it
    // `reachable_count` inflated the total by counting dangling UIDs that have no
    // entity, disagreeing with `direct_count` on the very same graph.
    let present: HashSet<&str> = by_uid.keys().copied().collect();
    let adj = undirected_adjacency(relations, Some(&present));

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
            let key = group_for(kind);
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
    for &(key, label) in GROUPS {
        let Some(mut items) = buckets.remove(key) else {
            continue;
        };
        items.sort_by(|a, b| {
            b.edge_confidence
                .total_cmp(&a.edge_confidence)
                .then_with(|| b.entity_confidence.total_cmp(&a.entity_confidence))
                .then_with(|| a.value.cmp(&b.value))
                // `value` alone is NOT a total key: a bucket holds distinct-uid
                // connections and two of different kinds can share a stored value,
                // tying on all three keys above. `uid` (unique) makes the order —
                // and so which survive the `truncate(GROUP_CAP)` cut below —
                // deterministic instead of leaking `best`'s HashMap order.
                .then_with(|| a.uid.cmp(&b.uid))
        });
        let total = items.len();
        items.truncate(GROUP_CAP);
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

#[cfg(test)]
mod tests;
