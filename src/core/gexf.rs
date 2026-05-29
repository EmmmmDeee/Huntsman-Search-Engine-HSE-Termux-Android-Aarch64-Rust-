//! GEXF graph export — entities and their relationships as XML for Gephi.
//!
//! GEXF (Graph Exchange XML Format) is the standard import format for Gephi,
//! the most widely-used open-source network analysis tool. This module
//! serializes scan entities as nodes and evidence-based relationships as
//! edges, enabling visual link analysis.

use std::fmt::Write;

use crate::core::entity::Entity;
use crate::core::relation::Relation;

/// Truncated node id — must match the form used when emitting `<node>`
/// elements so relation edges reference existing nodes.
fn short_uid(uid: &str) -> &str {
    &uid[..uid.len().min(12)]
}

/// Serialize a scan's entities (nodes) and edges (typed `Relation` edges +
/// shared-evidence co-occurrence edges) as GEXF for Gephi / Cytoscape.
pub fn entities_to_gexf(entities: &[Entity], relations: &[Relation], scan_id: &str) -> String {
    let mut xml = String::with_capacity(entities.len() * 256);

    let _ = writeln!(xml, r#"<?xml version="1.0" encoding="UTF-8"?>"#);
    let _ = writeln!(xml, r#"<gexf xmlns="http://gexf.net/1.3" version="1.3">"#);
    let _ = writeln!(xml, r#"  <meta>"#);
    let _ = writeln!(xml, r#"    <creator>Huntsman Search Engine</creator>"#);
    let _ = writeln!(xml, r#"    <description>Scan {scan_id}</description>"#);
    let _ = writeln!(xml, r#"  </meta>"#);
    let _ = writeln!(xml, r#"  <graph defaultedgetype="directed" mode="static">"#);

    // Node attributes
    let _ = writeln!(xml, r#"    <attributes class="node" mode="static">"#);
    let _ = writeln!(
        xml,
        r#"      <attribute id="0" title="kind" type="string"/>"#
    );
    let _ = writeln!(
        xml,
        r#"      <attribute id="1" title="confidence" type="float"/>"#
    );
    let _ = writeln!(
        xml,
        r#"      <attribute id="2" title="c_effective" type="float"/>"#
    );
    let _ = writeln!(
        xml,
        r#"      <attribute id="3" title="classification" type="string"/>"#
    );
    let _ = writeln!(
        xml,
        r#"      <attribute id="4" title="corroboration" type="integer"/>"#
    );
    let _ = writeln!(xml, r#"    </attributes>"#);

    // Nodes
    let _ = writeln!(xml, r#"    <nodes>"#);
    for e in entities {
        let label = xml_escape(&e.value);
        let short_uid = &e.uid[..e.uid.len().min(12)];
        let _ = writeln!(xml, r#"      <node id="{}" label="{label}">"#, short_uid);
        let _ = writeln!(xml, r#"        <attvalues>"#);
        let _ = writeln!(xml, r#"          <attvalue for="0" value="{}"/>"#, e.kind);
        let _ = writeln!(
            xml,
            r#"          <attvalue for="1" value="{:.3}"/>"#,
            e.confidence
        );
        let _ = writeln!(
            xml,
            r#"          <attvalue for="2" value="{:.3}"/>"#,
            e.c_effective()
        );
        let _ = writeln!(
            xml,
            r#"          <attvalue for="3" value="{}"/>"#,
            e.classify()
        );
        let _ = writeln!(
            xml,
            r#"          <attvalue for="4" value="{}"/>"#,
            e.corroboration
        );
        let _ = writeln!(xml, r#"        </attvalues>"#);
        let _ = writeln!(xml, r#"      </node>"#);
    }
    let _ = writeln!(xml, r#"    </nodes>"#);

    // Edges. Two kinds:
    //   1. Typed Relation edges (the explicit attribution graph), labelled by
    //      relation kind (subdomain_of / belongs_to_domain / hosted_on /
    //      derived_from), weighted by edge confidence.
    //   2. Shared-evidence co-occurrence edges, labelled by the shared sources.
    let _ = writeln!(xml, r#"    <edges>"#);
    let mut edge_id = 0u64;
    for r in relations {
        let src = short_uid(&r.from_uid);
        let tgt = short_uid(&r.to_uid);
        let _ = writeln!(
            xml,
            r#"      <edge id="{edge_id}" source="{src}" target="{tgt}" weight="{:.3}" label="{}"/>"#,
            r.confidence,
            xml_escape(r.kind.as_str())
        );
        edge_id += 1;
    }
    for (i, src) in entities.iter().enumerate() {
        let src_sources = src.evidence_sources();
        for tgt in entities.iter().skip(i + 1) {
            let tgt_sources = tgt.evidence_sources();
            let shared: Vec<&str> = src_sources.intersection(&tgt_sources).copied().collect();
            if !shared.is_empty() {
                let src_uid = &src.uid[..src.uid.len().min(12)];
                let tgt_uid = &tgt.uid[..tgt.uid.len().min(12)];
                let _ = writeln!(
                    xml,
                    r#"      <edge id="{edge_id}" source="{src_uid}" target="{tgt_uid}" weight="{}.0" label="{}"/>"#,
                    shared.len(),
                    xml_escape(&shared.join(", "))
                );
                edge_id += 1;
            }
        }
    }
    let _ = writeln!(xml, r#"    </edges>"#);
    let _ = writeln!(xml, r#"  </graph>"#);
    let _ = writeln!(xml, r#"</gexf>"#);

    xml
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::entity::{Entity, EntityKind, Evidence};

    #[test]
    fn gexf_has_xml_header() {
        let xml = entities_to_gexf(&[], &[], "test-scan");
        assert!(xml.starts_with("<?xml"));
        assert!(xml.contains("<gexf"));
        assert!(xml.contains("</gexf>"));
    }

    #[test]
    fn gexf_contains_nodes_for_entities() {
        let e = Entity::new(EntityKind::Email, "alice@example.com", 0.9, "s");
        let xml = entities_to_gexf(&[e], &[], "test-scan");
        assert!(xml.contains("alice@example.com"));
        assert!(xml.contains("<node"));
    }

    #[test]
    fn gexf_creates_edges_for_shared_sources() {
        let mut a = Entity::new(EntityKind::Email, "a@x.com", 0.8, "s");
        a.add_evidence(Evidence::new("hibp", "breach"));
        let mut b = Entity::new(EntityKind::Domain, "x.com", 0.7, "s");
        b.add_evidence(Evidence::new("hibp", "domain breach"));
        let xml = entities_to_gexf(&[a, b], &[], "test-scan");
        assert!(xml.contains("<edge"), "shared source should create edge");
        assert!(xml.contains("hibp"));
    }

    #[test]
    fn gexf_no_edges_for_unrelated_entities() {
        let mut a = Entity::new(EntityKind::Email, "a@x.com", 0.8, "s");
        a.add_evidence(Evidence::new("hibp", "breach"));
        let mut b = Entity::new(EntityKind::Domain, "y.com", 0.7, "s");
        b.add_evidence(Evidence::new("dns_intel", "resolved"));
        let xml = entities_to_gexf(&[a, b], &[], "test-scan");
        assert!(!xml.contains(r#"<edge "#));
    }

    #[test]
    fn gexf_emits_typed_relation_edges() {
        use crate::core::relation::{Relation, RelationKind};
        let parent = Entity::new(EntityKind::Domain, "example.com", 0.9, "s");
        let child = Entity::new(EntityKind::Domain, "blog.example.com", 0.8, "s");
        let rel = Relation::new(
            child.uid.clone(),
            parent.uid.clone(),
            RelationKind::SubdomainOf,
            0.8,
            "s",
        );
        let xml = entities_to_gexf(&[parent.clone(), child.clone()], &[rel], "test-scan");
        // Typed edge labelled by kind…
        assert!(
            xml.contains(r#"label="subdomain_of""#),
            "expected a kind-labelled edge, got:\n{xml}"
        );
        // …referencing the same truncated node ids the <node> elements use.
        let src = &child.uid[..12];
        let tgt = &parent.uid[..12];
        assert!(
            xml.contains(&format!(r#"source="{src}" target="{tgt}""#)),
            "relation edge must reference existing (truncated) node ids"
        );
    }

    #[test]
    fn xml_escape_special_chars() {
        assert_eq!(
            xml_escape("a<b>c&d\"e'f"),
            "a&lt;b&gt;c&amp;d&quot;e&apos;f"
        );
    }
}
