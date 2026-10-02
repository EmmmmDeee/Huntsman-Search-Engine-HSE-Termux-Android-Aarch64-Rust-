//! GEXF export for the entity graph.

use std::fmt::Write;

use crate::entity::Entity;
use crate::graph::{EntityRelation, Graph};

fn escape_xml(raw: &str) -> String {
    raw.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

#[must_use]
pub fn to_gexf(entities: &[Entity], relations: &[EntityRelation]) -> String {
    let graph = Graph::build(entities, relations);
    let entity_by_uid = entities
        .iter()
        .map(|entity| (entity.uid.as_str(), entity))
        .collect::<std::collections::HashMap<_, _>>();
    let mut out = String::from(
        r#"<?xml version="1.0" encoding="UTF-8"?><gexf version="1.3"><graph defaultedgetype="undirected"><nodes>"#,
    );
    for index in 0..graph.node_count() {
        let uid = graph.uid(index);
        let entity = entity_by_uid[uid];
        let _ = write!(
            out,
            r#"<node id="{uid}" label="{}"><attvalues><attvalue for="kind" value="{}"/><attvalue for="confidence" value="{:.3}"/></attvalues></node>"#,
            escape_xml(&entity.raw_value),
            entity.kind,
            entity.confidence
        );
    }
    out.push_str("</nodes><edges>");
    for (id, (left, right)) in graph.edge_pairs().into_iter().enumerate() {
        let Some(edge) = graph.edge(left, right) else {
            continue;
        };
        let labels = edge
            .relation_kinds
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(",");
        let _ = write!(
            out,
            r#"<edge id="{id}" source="{}" target="{}" label="{}" weight="{:.3}"/>"#,
            graph.uid(left),
            graph.uid(right),
            escape_xml(&labels),
            edge.max_confidence
        );
    }
    out.push_str("</edges></graph></gexf>");
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entity::{Entity, EntityKind};
    use crate::graph::RelationKind;

    #[test]
    fn exports_xml_safe_gexf() {
        let left = Entity::new(EntityKind::Organisation, "A&B <Org>", 0.6, "scan");
        let right = Entity::new(EntityKind::Domain, "example.com", 0.6, "scan");
        let xml = to_gexf(
            &[left.clone(), right.clone()],
            &[EntityRelation::new(
                left.uid.clone(),
                right.uid.clone(),
                RelationKind::Owns,
                0.8,
            )],
        );
        assert!(xml.contains("&amp;"));
        assert!(xml.contains("edge"));
    }
}
