//! GEXF export for the entity graph, with canonical escaping and bounded output.
//!
//! The bounded writer counts the exact UTF-8 bytes even after output is over budget.
//! Oversized export never allocates the full XML document.

use std::fmt::{self, Write};

use crate::entity::Entity;
use crate::graph::{EntityRelation, Graph};

#[derive(Debug)]
struct BoundedXml {
    text: String,
    limit: usize,
    required_bytes: usize,
}

impl BoundedXml {
    fn new(limit: usize) -> Self {
        Self {
            text: String::new(),
            limit,
            required_bytes: 0,
        }
    }

    fn finish(self) -> Result<String, usize> {
        if self.required_bytes > self.limit {
            Err(self.required_bytes)
        } else {
            Ok(self.text)
        }
    }
}

impl Write for BoundedXml {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        self.required_bytes = self.required_bytes.saturating_add(value.len());
        if self.required_bytes <= self.limit {
            self.text.push_str(value);
        }
        Ok(())
    }
}

/// Escape content and attributes using one implementation. XML 1.0 cannot carry
/// most C0 controls even as entities; those become U+FFFD.
fn write_escaped(out: &mut impl Write, raw: &str) -> fmt::Result {
    for character in raw.chars() {
        match character {
            '&' => out.write_str("&amp;")?,
            '<' => out.write_str("&lt;")?,
            '>' => out.write_str("&gt;")?,
            '"' => out.write_str("&quot;")?,
            '\'' => out.write_str("&apos;")?,
            c if (c as u32) < 0x20 && !matches!(c, '\t' | '\n' | '\r') => {
                out.write_char('\u{fffd}')?;
            }
            c => out.write_char(c)?,
        }
    }
    Ok(())
}

/// Text as XML character data or an attribute value.
#[must_use]
pub fn escape_xml(raw: &str) -> String {
    let mut text = String::with_capacity(raw.len());
    let _ = write_escaped(&mut text, raw);
    text
}

/// Original unrestricted interface, retained for external callers.
#[must_use]
pub fn to_gexf(entities: &[Entity], relations: &[EntityRelation]) -> String {
    to_gexf_bounded(entities, relations, usize::MAX)
        .expect("GEXF content must fit in addressable memory")
}

/// Serialize the whole graph without retaining XML beyond the supplied limit.
/// Oversize output reports the complete, byte-exact size; never partial XML.
pub fn to_gexf_bounded(
    entities: &[Entity],
    relations: &[EntityRelation],
    max_bytes: usize,
) -> Result<String, usize> {
    let graph = Graph::build(entities, relations);
    let entity_by_uid = entities
        .iter()
        .map(|entity| (entity.uid.as_str(), entity))
        .collect::<std::collections::HashMap<_, _>>();
    let mut out = BoundedXml::new(max_bytes);
    let _ = out.write_str(
        r#"<?xml version="1.0" encoding="UTF-8"?><gexf version="1.3"><graph defaultedgetype="undirected"><nodes>"#,
    );
    for index in 0..graph.node_count() {
        let uid = graph.uid(index);
        let entity = entity_by_uid[uid];
        let _ = out.write_str(r#"<node id=""#);
        let _ = write_escaped(&mut out, uid);
        let _ = out.write_str(r#"" label=""#);
        let _ = write_escaped(&mut out, &entity.raw_value);
        let _ = write!(
            out,
            r#""><attvalues><attvalue for="kind" value="{}"/><attvalue for="confidence" value="{:.3}"/></attvalues></node>"#,
            entity.kind, entity.confidence
        );
    }
    let _ = out.write_str("</nodes><edges>");
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
        let _ = write!(out, r#"<edge id="{id}" source=""#);
        let _ = write_escaped(&mut out, graph.uid(left));
        let _ = out.write_str(r#"" target=""#);
        let _ = write_escaped(&mut out, graph.uid(right));
        let _ = out.write_str(r#"" label=""#);
        let _ = write_escaped(&mut out, &labels);
        let _ = write!(out, r#"" weight="{:.3}"/>"#, edge.max_confidence);
    }
    let _ = out.write_str("</edges></graph></gexf>");
    out.finish()
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

    #[test]
    fn controls_that_xml_cannot_carry_become_replacement_characters() {
        assert_eq!(escape_xml("a\u{1}b\tc'"), "a\u{fffd}b\tc&apos;");
    }

    #[test]
    fn imported_entity_ids_are_escaped_as_xml_attributes() {
        let mut left = Entity::new(EntityKind::Email, "left@example.com", 0.6, "scan");
        let mut right = Entity::new(EntityKind::Email, "right@example.com", 0.6, "scan");
        left.uid = String::from("a\"&<'");
        right.uid = String::from("b>&\"");
        let xml = to_gexf(
            &[left.clone(), right.clone()],
            &[EntityRelation::new(
                left.uid.clone(),
                right.uid.clone(),
                RelationKind::Uses,
                0.6,
            )],
        );
        assert!(xml.contains(r#"id="a&quot;&amp;&lt;&apos;""#));
        assert!(xml.contains(r#"id="b&gt;&amp;&quot;""#));
        assert!(xml.contains(r#"source="a&quot;&amp;&lt;&apos;""#));
        assert!(xml.contains(r#"target="b&gt;&amp;&quot;""#));
    }

    #[test]
    fn bounded_gexf_has_the_same_bytes_and_never_truncates_xml() {
        let left = Entity::new(EntityKind::Email, "left@example.com", 0.6, "scan");
        let right = Entity::new(EntityKind::Domain, "example.com", 0.6, "scan");
        let relations = vec![EntityRelation::new(
            left.uid.clone(),
            right.uid.clone(),
            RelationKind::Uses,
            0.7,
        )];
        let entities = vec![left, right];
        let full = to_gexf(&entities, &relations);
        assert_eq!(
            to_gexf_bounded(&entities, &relations, full.len()),
            Ok(full.clone())
        );
        assert_eq!(
            to_gexf_bounded(&entities, &relations, full.len() - 1),
            Err(full.len())
        );
        assert_eq!(to_gexf_bounded(&entities, &relations, 0), Err(full.len()));
    }
}
