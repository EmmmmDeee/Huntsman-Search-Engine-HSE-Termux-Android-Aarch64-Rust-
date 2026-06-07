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

    write_preamble(&mut xml, scan_id);

    let _ = writeln!(xml, r#"    <nodes>"#);
    for e in entities {
        write_node(&mut xml, e);
    }
    let _ = writeln!(xml, r#"    </nodes>"#);

    // Edges. Two kinds:
    //   1. Typed Relation edges (the explicit attribution graph), labelled by
    //      relation kind (subdomain_of / belongs_to_domain / hosted_on /
    //      derived_from), weighted by edge confidence.
    //   2. Shared-evidence co-occurrence edges, labelled by the shared sources.
    // Edge ids are assigned sequentially: relation edges first, then the
    // co-occurrence edges continue the same counter.
    let _ = writeln!(xml, r#"    <edges>"#);
    let mut edge_id = 0u64;
    for r in relations {
        write_relation_edge(&mut xml, r, &mut edge_id);
    }
    write_shared_evidence_edges(&mut xml, entities, &mut edge_id);
    let _ = writeln!(xml, r#"    </edges>"#);

    let _ = writeln!(xml, r#"  </graph>"#);
    let _ = writeln!(xml, r#"</gexf>"#);

    xml
}

/// XML header, `<meta>`, the `<graph>` open tag, and the node attribute
/// declarations (kind / confidence / c_effective / classification /
/// corroboration). Leaves `xml` positioned to receive `<nodes>`.
fn write_preamble(xml: &mut String, scan_id: &str) {
    let _ = writeln!(xml, r#"<?xml version="1.0" encoding="UTF-8"?>"#);
    let _ = writeln!(xml, r#"<gexf xmlns="http://gexf.net/1.3" version="1.3">"#);
    let _ = writeln!(xml, r#"  <meta>"#);
    let _ = writeln!(xml, r#"    <creator>Huntsman Search Engine</creator>"#);
    let _ = writeln!(xml, r#"    <description>Scan {scan_id}</description>"#);
    let _ = writeln!(xml, r#"  </meta>"#);
    let _ = writeln!(xml, r#"  <graph defaultedgetype="directed" mode="static">"#);

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
}

/// One `<node>` element with its five `<attvalue>`s. The id is the truncated
/// uid (see [`short_uid`]) so relation/co-occurrence edges can reference it.
fn write_node(xml: &mut String, e: &Entity) {
    let label = xml_escape(&e.value);
    let _ = writeln!(
        xml,
        r#"      <node id="{}" label="{label}">"#,
        short_uid(&e.uid)
    );
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

/// One typed `Relation` edge, weighted by edge confidence and labelled by the
/// relation kind. Advances `edge_id`.
fn write_relation_edge(xml: &mut String, r: &Relation, edge_id: &mut u64) {
    let _ = writeln!(
        xml,
        r#"      <edge id="{edge_id}" source="{}" target="{}" weight="{:.3}" label="{}"/>"#,
        short_uid(&r.from_uid),
        short_uid(&r.to_uid),
        r.confidence,
        xml_escape(r.kind.as_str())
    );
    *edge_id += 1;
}

/// Shared-evidence co-occurrence edges: for every unordered entity pair that
/// shares ≥1 evidence source, an edge weighted by the shared-source count and
/// labelled by the joined source names. Advances `edge_id` per emitted edge.
fn write_shared_evidence_edges(xml: &mut String, entities: &[Entity], edge_id: &mut u64) {
    for (i, src) in entities.iter().enumerate() {
        let src_sources = src.evidence_sources();
        for tgt in entities.iter().skip(i + 1) {
            let tgt_sources = tgt.evidence_sources();
            let shared: Vec<&str> = src_sources.intersection(&tgt_sources).copied().collect();
            if !shared.is_empty() {
                let _ = writeln!(
                    xml,
                    r#"      <edge id="{edge_id}" source="{}" target="{}" weight="{}.0" label="{}"/>"#,
                    short_uid(&src.uid),
                    short_uid(&tgt.uid),
                    shared.len(),
                    xml_escape(&shared.join(", "))
                );
                *edge_id += 1;
            }
        }
    }
}

fn xml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            // XML 1.0 §2.2 forbids the C0 control chars (except tab/LF/CR) and the
            // noncharacters U+FFFE/U+FFFF — they are illegal even as numeric
            // references. An entity value carrying a stray control byte (breach
            // dumps and scraped pages do) would otherwise make the WHOLE .gexf
            // unparseable, not just that node. Drop them at the serialization
            // boundary. (C1 controls 0x80–0x9F are valid in XML 1.0 and kept.)
            '\u{FFFE}' | '\u{FFFF}' => {}
            c if (c as u32) < 0x20 && !matches!(c, '\t' | '\n' | '\r') => {}
            c => out.push(c),
        }
    }
    out
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

    #[test]
    fn xml_escape_drops_illegal_control_chars() {
        // A stray C0 control byte in an entity value must be dropped, not emitted —
        // otherwise the whole .gexf is unparseable. tab/LF/CR are legal and kept.
        assert_eq!(
            xml_escape("ab\u{0}c\u{7}d\u{1b}e"),
            "abcde",
            "NUL/BEL/ESC must be stripped"
        );
        assert_eq!(
            xml_escape("a\tb\nc\rd"),
            "a\tb\nc\rd",
            "tab/LF/CR preserved"
        );
        // C1 controls (0x80–0x9F) are valid in XML 1.0 and must be kept.
        assert_eq!(
            xml_escape("a\u{85}b"),
            "a\u{85}b",
            "C1 NEL kept (legal in XML 1.0)"
        );
        // Noncharacters are illegal and dropped.
        assert_eq!(xml_escape("a\u{FFFF}b"), "ab", "U+FFFF dropped");
    }

    /// Characterisation golden: pins the EXACT byte output for a deterministic
    /// input (entity uids are SHA-256(kind:value), so they're stable). Locks the
    /// full document — header, node attvalues, typed relation edge, and
    /// shared-evidence co-occurrence edge — so any byte-level change during a
    /// refactor is caught, not just the presence of substrings.
    #[test]
    fn gexf_golden_output_is_byte_stable() {
        use crate::core::relation::{Relation, RelationKind};
        let mut a = Entity::new(EntityKind::Domain, "example.com", 0.9, "s");
        a.add_evidence(Evidence::new("crtsh", "cert"));
        let mut b = Entity::new(EntityKind::Domain, "blog.example.com", 0.8, "s");
        b.add_evidence(Evidence::new("crtsh", "cert"));
        let rel = Relation::new(
            b.uid.clone(),
            a.uid.clone(),
            RelationKind::SubdomainOf,
            0.8,
            "s",
        );
        let xml = entities_to_gexf(&[a, b], &[rel], "scan-1");
        let expected = r#"<?xml version="1.0" encoding="UTF-8"?>
<gexf xmlns="http://gexf.net/1.3" version="1.3">
  <meta>
    <creator>Huntsman Search Engine</creator>
    <description>Scan scan-1</description>
  </meta>
  <graph defaultedgetype="directed" mode="static">
    <attributes class="node" mode="static">
      <attribute id="0" title="kind" type="string"/>
      <attribute id="1" title="confidence" type="float"/>
      <attribute id="2" title="c_effective" type="float"/>
      <attribute id="3" title="classification" type="string"/>
      <attribute id="4" title="corroboration" type="integer"/>
    </attributes>
    <nodes>
      <node id="ed152b32b035" label="example.com">
        <attvalues>
          <attvalue for="0" value="domain"/>
          <attvalue for="1" value="0.900"/>
          <attvalue for="2" value="0.900"/>
          <attvalue for="3" value="VERIFIED"/>
          <attvalue for="4" value="1"/>
        </attvalues>
      </node>
      <node id="df4bda23ac18" label="blog.example.com">
        <attvalues>
          <attvalue for="0" value="domain"/>
          <attvalue for="1" value="0.800"/>
          <attvalue for="2" value="0.800"/>
          <attvalue for="3" value="VERIFIED"/>
          <attvalue for="4" value="1"/>
        </attvalues>
      </node>
    </nodes>
    <edges>
      <edge id="0" source="df4bda23ac18" target="ed152b32b035" weight="0.800" label="subdomain_of"/>
      <edge id="1" source="ed152b32b035" target="df4bda23ac18" weight="1.0" label="crtsh"/>
    </edges>
  </graph>
</gexf>
"#;
        assert_eq!(xml, expected);
    }
}
