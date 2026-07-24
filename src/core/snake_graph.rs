//! Snake entity graph: a simplified concentric-ring view of an entity graph.
//!
//! The full relation graph is a hairball. This projection picks one entity as
//! the centre and lays the rest out in rings by hop distance, keeping only
//! edges between adjacent rings so the result reads as a set of nested circles
//! rather than a mesh.

use crate::core::entity::{Entity, EntityKind};
use crate::core::relation::{Relation, RelationKind};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, VecDeque};

/// Minimum relation strength retained in the projection.
const MIN_EDGE_STRENGTH: f64 = 0.3;

/// The entity to centre a projection on when the caller names none.
///
/// The scan subject (or seed) if there is one — the operator already reads that
/// entity as the origin, so centring anywhere else would misrepresent the graph.
/// Failing that, the most-connected entity, since a projection anchored on a leaf
/// pushes the bulk of the graph past the horizon. Ties break on uid so the choice
/// is deterministic. `None` only when there are no entities at all.
#[must_use]
pub fn default_center(entities: &[Entity], relations: &[Relation]) -> Option<String> {
    if let Some(uid) = crate::core::metrics::subject_uid(entities) {
        return Some(uid.to_string());
    }
    let mut degree: BTreeMap<&str, usize> = entities.iter().map(|e| (e.uid.as_str(), 0)).collect();
    for r in relations {
        for uid in [r.from_uid.as_str(), r.to_uid.as_str()] {
            if let Some(d) = degree.get_mut(uid) {
                *d += 1;
            }
        }
    }
    degree
        .into_iter()
        .max_by(|(a_uid, a_deg), (b_uid, b_deg)| a_deg.cmp(b_deg).then_with(|| b_uid.cmp(a_uid)))
        .map(|(uid, _)| uid.to_string())
}

/// A node placed on one of the concentric rings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnakeNode {
    pub uid: String,
    pub value: String,
    pub kind: String,
    pub confidence: f64,
    /// Hop distance from the centre; 0 is the centre itself.
    pub ring: usize,
    /// Unit-circle coordinates, centre at the origin.
    pub x: f64,
    pub y: f64,
    pub color: String,
    pub radius: f64,
}

/// An edge retained in the projection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnakeEdge {
    pub from_uid: String,
    pub to_uid: String,
    pub relation_kind: String,
    pub confidence: f64,
    pub strength: f64,
}

/// A concentric-ring projection of an entity graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnakeGraph {
    pub center_uid: String,
    pub nodes: Vec<SnakeNode>,
    pub edges: Vec<SnakeEdge>,
    pub max_ring: usize,
    /// Entities reachable from the centre but beyond `max_distance`.
    pub nodes_beyond_horizon: usize,
}

impl SnakeGraph {
    /// Project `entities`/`relations` into rings around `center_uid`.
    ///
    /// Entities further than `max_distance` hops are counted in
    /// `nodes_beyond_horizon` rather than silently dropped.
    pub fn build(
        center_uid: &str,
        entities: &[Entity],
        relations: &[Relation],
        max_distance: usize,
    ) -> Self {
        let entity_map: HashMap<&str, &Entity> =
            entities.iter().map(|e| (e.uid.as_str(), e)).collect();

        let mut adj: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
        for rel in relations {
            if relation_strength(rel.kind) < MIN_EDGE_STRENGTH {
                continue;
            }
            adj.entry(rel.from_uid.as_str())
                .or_default()
                .push(rel.to_uid.as_str());
            adj.entry(rel.to_uid.as_str())
                .or_default()
                .push(rel.from_uid.as_str());
        }

        // BFS out from the centre, recording hop distance.
        let mut distance: BTreeMap<&str, usize> = BTreeMap::new();
        // A set, not a counter: the same out-of-range node is reachable from every
        // frontier node adjacent to it, and it is one entity however many times the
        // sweep bumps into it.
        let mut beyond: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
        let mut queue = VecDeque::new();
        distance.insert(center_uid, 0);
        queue.push_back(center_uid);

        while let Some(uid) = queue.pop_front() {
            let d = distance[uid];
            let Some(neighbours) = adj.get(uid) else {
                continue;
            };
            for neighbour in neighbours {
                if distance.contains_key(neighbour) {
                    continue;
                }
                if d + 1 > max_distance {
                    beyond.insert(neighbour);
                    continue;
                }
                distance.insert(neighbour, d + 1);
                queue.push_back(neighbour);
            }
        }
        let beyond_horizon = beyond.len();

        // Group by ring so each ring's nodes can be spread evenly around it.
        let mut rings: BTreeMap<usize, Vec<&str>> = BTreeMap::new();
        for (uid, d) in &distance {
            if entity_map.contains_key(uid) {
                rings.entry(*d).or_default().push(uid);
            }
        }

        let mut nodes = Vec::new();
        let mut max_ring = 0;
        for (ring, uids) in &rings {
            let ring_size = uids.len();
            for (index, uid) in uids.iter().enumerate() {
                let entity = entity_map[uid];
                let (x, y) = ring_position(*ring, index, ring_size);
                nodes.push(SnakeNode {
                    uid: (*uid).to_string(),
                    value: entity.value.clone(),
                    kind: entity.kind.to_string(),
                    confidence: entity.confidence,
                    ring: *ring,
                    x,
                    y,
                    color: color_for_kind(&entity.kind).to_string(),
                    radius: 4.0 + entity.confidence * 8.0,
                });
            }
            max_ring = max_ring.max(*ring);
        }

        // Keep only edges spanning at most one ring — the rest is what makes
        // the raw graph unreadable.
        let mut edges = Vec::new();
        for rel in relations {
            let strength = relation_strength(rel.kind);
            if strength < MIN_EDGE_STRENGTH {
                continue;
            }
            let (Some(from_d), Some(to_d)) = (
                distance.get(rel.from_uid.as_str()),
                distance.get(rel.to_uid.as_str()),
            ) else {
                continue;
            };
            if from_d.abs_diff(*to_d) > 1 {
                continue;
            }
            edges.push(SnakeEdge {
                from_uid: rel.from_uid.clone(),
                to_uid: rel.to_uid.clone(),
                relation_kind: rel.kind.as_str().to_string(),
                confidence: rel.confidence,
                strength,
            });
        }

        Self {
            center_uid: center_uid.to_string(),
            nodes,
            edges,
            max_ring,
            nodes_beyond_horizon: beyond_horizon,
        }
    }

    /// Render as a standalone SVG, `size` pixels square.
    ///
    /// The 18% margin left by `0.82` is what holds a node's own radius and the
    /// label printed under it inside the frame; the outermost ring guide is
    /// placed exactly on that boundary.
    pub fn to_svg(&self, size: f64) -> String {
        let centre = size / 2.0;
        // `ring_radius` passes 1.0 at ring 6, and the API admits a depth of 8 —
        // so a deep graph drawn at a fixed scale puts its outer rings, and every
        // node and label on them, outside the viewBox, where they are silently
        // clipped. Normalising by the outermost radius makes the outer ring fit
        // by construction, at any depth.
        //
        // The `max(1.0)` keeps graphs of depth <= 6 rendering exactly as before,
        // which is deliberate: a ring then means the same absolute distance in
        // every such SVG, so an operator flipping between two scans is comparing
        // like with like. Only a graph that would otherwise overflow is shrunk.
        let scale = centre * 0.82 / ring_radius(self.max_ring).max(1.0);
        let position: HashMap<&str, (f64, f64)> = self
            .nodes
            .iter()
            .map(|n| (n.uid.as_str(), (centre + n.x * scale, centre + n.y * scale)))
            .collect();

        let mut svg = format!(
            "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"{size}\" height=\"{size}\" \
             viewBox=\"0 0 {size} {size}\">\n\
             <rect width=\"{size}\" height=\"{size}\" fill=\"#0f1115\"/>\n"
        );

        // Ring guides, faintest first.
        for ring in 1..=self.max_ring {
            let r = ring_radius(ring) * scale;
            svg.push_str(&format!(
                "<circle cx=\"{centre}\" cy=\"{centre}\" r=\"{r:.1}\" fill=\"none\" \
                 stroke=\"#242a33\" stroke-width=\"1\"/>\n"
            ));
        }

        for edge in &self.edges {
            let (Some(&(x1, y1)), Some(&(x2, y2))) = (
                position.get(edge.from_uid.as_str()),
                position.get(edge.to_uid.as_str()),
            ) else {
                continue;
            };
            svg.push_str(&format!(
                "<line x1=\"{x1:.1}\" y1=\"{y1:.1}\" x2=\"{x2:.1}\" y2=\"{y2:.1}\" \
                 stroke=\"#4a5568\" stroke-width=\"{:.2}\" stroke-opacity=\"{:.2}\"/>\n",
                0.5 + edge.strength * 2.0,
                0.25 + edge.strength * 0.5
            ));
        }

        for node in &self.nodes {
            let Some(&(x, y)) = position.get(node.uid.as_str()) else {
                continue;
            };
            svg.push_str(&format!(
                "<circle cx=\"{x:.1}\" cy=\"{y:.1}\" r=\"{:.1}\" fill=\"{}\" \
                 stroke=\"#0f1115\" stroke-width=\"1.5\"/>\n",
                node.radius, node.color
            ));
            svg.push_str(&format!(
                "<text x=\"{x:.1}\" y=\"{:.1}\" fill=\"#c8cdd4\" font-family=\"sans-serif\" \
                 font-size=\"10\" text-anchor=\"middle\">{}</text>\n",
                y + node.radius + 11.0,
                escape_xml(&truncate(&node.value, 22))
            ));
        }

        svg.push_str("</svg>\n");
        svg
    }
}

/// Radius of a ring in unit-circle space.
fn ring_radius(ring: usize) -> f64 {
    ring as f64 / 6.0
}

/// Even angular placement of `index` among `ring_size` nodes on `ring`.
fn ring_position(ring: usize, index: usize, ring_size: usize) -> (f64, f64) {
    if ring == 0 {
        return (0.0, 0.0);
    }
    let radius = ring_radius(ring);
    let angle = std::f64::consts::TAU * index as f64 / ring_size.max(1) as f64;
    (radius * angle.cos(), radius * angle.sin())
}

fn color_for_kind(kind: &EntityKind) -> &'static str {
    match kind {
        EntityKind::Person => "#2ecc71",
        EntityKind::Email => "#3498db",
        EntityKind::Username => "#e74c3c",
        EntityKind::Phone => "#9b59b6",
        EntityKind::Password | EntityKind::Credential | EntityKind::ApiKey => "#95a5a6",
        EntityKind::IpAddress | EntityKind::Cidr | EntityKind::Asn => "#1abc9c",
        EntityKind::Domain | EntityKind::Url => "#5dade2",
        EntityKind::Address | EntityKind::Coordinates => "#e67e22",
        EntityKind::Organisation | EntityKind::AbnAcn => "#f1c40f",
        _ => "#7f8c8d",
    }
}

/// Visual weight of an edge kind — also the retention gate.
fn relation_strength(kind: RelationKind) -> f64 {
    match kind {
        RelationKind::SameAs | RelationKind::SameIdentity => 1.0,
        RelationKind::IdentifiedBy | RelationKind::AliasOf => 0.95,
        RelationKind::SharesSecretWith => 0.85,
        RelationKind::SameOperator => 0.8,
        RelationKind::SubdomainOf | RelationKind::BelongsToDomain => 0.8,
        RelationKind::ResolvesTo | RelationKind::RegisteredBy => 0.75,
        RelationKind::CoLocatedWith | RelationKind::LocatedAt => 0.7,
        RelationKind::AssociatedWith => 0.6,
        RelationKind::DerivedFrom | RelationKind::HostedOn => 0.5,
    }
}

fn truncate(s: &str, max_chars: usize) -> String {
    if s.chars().count() <= max_chars {
        return s.to_string();
    }
    let kept: String = s.chars().take(max_chars.saturating_sub(1)).collect();
    format!("{kept}…")
}

fn escape_xml(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::confidence;

    fn entity(kind: EntityKind, value: &str) -> Entity {
        Entity::new(kind, value, confidence::HIGH, "scan-1")
    }

    fn relation(from: &Entity, to: &Entity, kind: RelationKind) -> Relation {
        Relation::new(from.uid.clone(), to.uid.clone(), kind, 0.9, "scan-1")
    }

    #[test]
    fn centre_sits_at_the_origin() {
        assert_eq!(ring_position(0, 0, 1), (0.0, 0.0));
    }

    #[test]
    fn ring_nodes_share_a_radius() {
        let (x1, y1) = ring_position(1, 0, 4);
        let (x2, y2) = ring_position(1, 2, 4);
        let r1 = x1.hypot(y1);
        let r2 = x2.hypot(y2);
        assert!((r1 - r2).abs() < 1e-9);
        assert!(r1 > 0.0);
    }

    #[test]
    fn outer_rings_sit_further_out() {
        assert!(ring_radius(3) > ring_radius(1));
    }

    #[test]
    fn strong_relations_outrank_weak_ones() {
        assert!(
            relation_strength(RelationKind::SameAs) > relation_strength(RelationKind::DerivedFrom)
        );
        assert!(relation_strength(RelationKind::DerivedFrom) >= MIN_EDGE_STRENGTH);
    }

    #[test]
    fn kinds_get_distinct_colors() {
        assert_ne!(
            color_for_kind(&EntityKind::Email),
            color_for_kind(&EntityKind::Username)
        );
    }

    #[test]
    fn lone_entity_forms_a_single_centre() {
        let centre = entity(EntityKind::Email, "test@example.com");
        let graph = SnakeGraph::build(&centre.uid, std::slice::from_ref(&centre), &[], 3);

        assert_eq!(graph.nodes.len(), 1);
        assert_eq!(graph.nodes[0].ring, 0);
        assert!(graph.edges.is_empty());
        assert_eq!(graph.max_ring, 0);
    }

    #[test]
    fn neighbours_land_on_ring_one() {
        let centre = entity(EntityKind::Person, "Subject");
        let neighbour = entity(EntityKind::Email, "subject@example.com");
        let rels = vec![relation(&centre, &neighbour, RelationKind::IdentifiedBy)];
        let entities = vec![centre.clone(), neighbour.clone()];

        let graph = SnakeGraph::build(&centre.uid, &entities, &rels, 3);

        assert_eq!(graph.nodes.len(), 2);
        assert_eq!(graph.max_ring, 1);
        let n = graph.nodes.iter().find(|n| n.uid == neighbour.uid).unwrap();
        assert_eq!(n.ring, 1);
        assert_eq!(graph.edges.len(), 1);
    }

    #[test]
    fn entities_past_the_horizon_are_counted_not_dropped() {
        let a = entity(EntityKind::Person, "A");
        let b = entity(EntityKind::Email, "b@example.com");
        let c = entity(EntityKind::Username, "c");
        let rels = vec![
            relation(&a, &b, RelationKind::IdentifiedBy),
            relation(&b, &c, RelationKind::AliasOf),
        ];
        let entities = vec![a.clone(), b.clone(), c.clone()];

        let graph = SnakeGraph::build(&a.uid, &entities, &rels, 1);

        assert_eq!(graph.nodes.len(), 2);
        assert_eq!(graph.nodes_beyond_horizon, 1);
    }

    #[test]
    fn svg_renders_every_node() {
        let centre = entity(EntityKind::Person, "Subject");
        let neighbour = entity(EntityKind::Email, "subject@example.com");
        let rels = vec![relation(&centre, &neighbour, RelationKind::IdentifiedBy)];
        let entities = vec![centre.clone(), neighbour.clone()];

        let svg = SnakeGraph::build(&centre.uid, &entities, &rels, 3).to_svg(600.0);

        assert!(svg.starts_with("<svg"));
        assert!(svg.ends_with("</svg>\n"));
        assert_eq!(svg.matches("<circle").count(), 1 + 2); // one ring guide + two nodes
        assert!(svg.contains("Subject"));
    }

    /// `ring_radius` passes 1.0 at ring 6 and the API admits depth 8, so a deep
    /// graph drawn at a fixed scale would place its outer ring outside the
    /// viewBox — clipping the nodes and labels that live there without any
    /// indication they were ever drawn.
    #[test]
    fn the_outer_ring_stays_inside_the_frame_at_every_admitted_depth() {
        let size = 600.0;
        let centre = size / 2.0;
        for max_ring in 0..=8_usize {
            let graph = SnakeGraph {
                center_uid: "c".into(),
                nodes: Vec::new(),
                edges: Vec::new(),
                max_ring,
                nodes_beyond_horizon: 0,
            };
            let scale = centre * 0.82 / ring_radius(graph.max_ring).max(1.0);
            let outer = ring_radius(max_ring) * scale;
            assert!(
                outer <= centre,
                "depth {max_ring}: outer ring at {outer} escapes the {centre}px half-frame"
            );
        }
    }

    /// Deliberate: a ring must mean the same absolute distance in every SVG a
    /// shallow scan produces, so an operator flipping between two of them is
    /// comparing like with like. Only a graph that would overflow is shrunk.
    #[test]
    fn shallow_graphs_are_not_rescaled() {
        for max_ring in 0..=6_usize {
            assert!(
                (ring_radius(max_ring).max(1.0) - 1.0).abs() < f64::EPSILON,
                "depth {max_ring} must render at the unnormalised scale"
            );
        }
        assert!(ring_radius(7).max(1.0) > 1.0, "depth 7 must be normalised");
    }

    #[test]
    fn xml_special_characters_are_escaped() {
        let centre = entity(EntityKind::Other("note".into()), "a<b&c");
        let svg =
            SnakeGraph::build(&centre.uid, std::slice::from_ref(&centre), &[], 2).to_svg(400.0);

        assert!(svg.contains("a&lt;b&amp;c"));
        assert!(!svg.contains("a<b&c"));
    }
}
