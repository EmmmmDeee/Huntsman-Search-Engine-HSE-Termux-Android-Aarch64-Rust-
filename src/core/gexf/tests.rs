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
    fn gexf_excludes_non_corroborating_co_occurrence() {
        // Two candidates that share ONLY `name_intel` (the seed's permutation
        // engine) must NOT draw a co-occurrence edge: that is common-derivation,
        // not a shared sighting, and would wire every name-guess into a false
        // cluster. Their lineage is carried by the typed `DerivedFrom` edges.
        let mut a = Entity::new(EntityKind::Username, "jmeyers", 0.4, "s");
        a.add_evidence(Evidence::new("name_intel", "derived"));
        let mut b = Entity::new(EntityKind::Email, "jmeyers@gmail.com", 0.4, "s");
        b.add_evidence(Evidence::new("name_intel", "derived"));
        let xml = entities_to_gexf(&[a, b], &[], "s");
        assert!(
            !xml.contains(r#"<edge "#),
            "name_intel-only derivation must not draw a co-occurrence edge"
        );

        // Once an INDEPENDENT source (hibp) names both, they genuinely co-occur —
        // and the edge is labelled by the corroborating source alone, never the
        // derivation pass.
        let mut a = Entity::new(EntityKind::Username, "jmeyers", 0.4, "s");
        a.add_evidence(Evidence::new("name_intel", "derived"));
        a.add_evidence(Evidence::new("hibp", "breach"));
        let mut b = Entity::new(EntityKind::Email, "jmeyers@gmail.com", 0.4, "s");
        b.add_evidence(Evidence::new("name_intel", "derived"));
        b.add_evidence(Evidence::new("hibp", "breach"));
        let xml = entities_to_gexf(&[a, b], &[], "s");
        assert!(
            xml.contains(r#"label="hibp""#),
            "a genuine shared source must co-occur, labelled by that source"
        );
        assert!(
            !xml.contains("name_intel"),
            "the derivation source is not a co-occurrence basis"
        );
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

    // ── short_uid ─────────────────────────────────────────────────────────────

    #[test]
    fn short_uid_truncates_to_twelve_chars() {
        // A long uid is cut to its first 12 chars (matching the node-id form).
        assert_eq!(short_uid("0123456789abcdef0000"), "0123456789ab");
        // Exactly 12 is unchanged.
        assert_eq!(short_uid("0123456789ab"), "0123456789ab");
        // Shorter than 12 passes through (the `min` guards the slice).
        assert_eq!(short_uid("abc"), "abc");
        assert_eq!(short_uid(""), "");
    }
