//! GEXF graph export — entities and their relationships as XML for Gephi.
//!
//! GEXF (Graph Exchange XML Format) is the standard import format for Gephi,
//! the most widely-used open-source network analysis tool. This module
//! serializes scan entities as nodes and evidence-based relationships as
//! edges, enabling visual link analysis.

use std::collections::HashMap;
use std::fmt::Write;

use crate::core::entity::Entity;
use crate::core::graph::Graph;
use crate::core::relation::Relation;

/// Truncated node id — must match the form used when emitting `<node>`
/// elements so relation edges reference existing nodes.
fn short_uid(uid: &str) -> &str {
    &uid[..uid.len().min(12)]
}

/// Serialize a scan's entities (nodes) and edges (typed `Relation` edges +
/// shared-evidence co-occurrence edges) as GEXF for Gephi / Cytoscape.
///
/// Each node carries a `coreness` attribute (k-core index, Batagelj–Zaversnik)
/// so Gephi can distinguish the redundantly-corroborated main core from the
/// fragile periphery — the structural complement to the `classification`
/// attribute (which captures confidence-tier) and `c_effective` (which captures
/// multi-source strength). Coreness is computed once from the same entity+relation
/// graph, adding O(V+E) time to the GEXF serialization path (export is not hot).
pub fn entities_to_gexf(entities: &[Entity], relations: &[Relation], scan_id: &str) -> String {
    let mut xml = String::with_capacity(entities.len() * 256);

    // Build the coreness map: uid → k-core index. Zero for any entity absent
    // from the graph (isolated entities with no relation edges have coreness 0
    // even if the builder would omit them — Gephi reads 0 as "periphery").
    let graph = Graph::build(entities, relations);
    let raw_coreness = graph.coreness();
    let coreness_map: HashMap<&str, usize> = (0..graph.node_count())
        .map(|i| (graph.uid(i), raw_coreness[i]))
        .collect();

    write_preamble(&mut xml, scan_id);

    let _ = writeln!(xml, r#"    <nodes>"#);
    for e in entities {
        let c = coreness_map.get(e.uid.as_str()).copied().unwrap_or(0);
        write_node(&mut xml, e, c);
    }
    let _ = writeln!(xml, r#"    </nodes>"#);

    // Edges. Two kinds:
    //   1. Typed Relation edges (the explicit attribution graph), labelled by
    //      relation kind (subdomain_of / belongs_to_domain / hosted_on /
    //      derived_from), weighted by edge confidence.
    //   2. Shared-evidence co-occurrence edges, labelled by the shared sources.
    // Edge ids are assigned sequentially: relation edges first, then the
    // co-occurrence edges continue the same counter.
    //
    // A relation edge is emitted only when BOTH its endpoints are among the nodes
    // written above. A caller that passes a filtered entity subset (e.g. the
    // exports that drop quarantined `candidate` rows) but the full relation set
    // would otherwise emit an `<edge>` referencing an undeclared node id —
    // structurally-invalid GEXF that Gephi rejects. Enforcing it here makes
    // "every edge references a declared node" an invariant of the serializer, so
    // no caller can produce a dangling edge regardless of which subset it passes.
    // (Co-occurrence edges are built only from `entities`, so they are always
    // in-set by construction.)
    let node_ids: std::collections::HashSet<&str> =
        entities.iter().map(|e| short_uid(&e.uid)).collect();
    let _ = writeln!(xml, r#"    <edges>"#);
    let mut edge_id = 0u64;
    for r in relations {
        if node_ids.contains(short_uid(&r.from_uid)) && node_ids.contains(short_uid(&r.to_uid)) {
            write_relation_edge(&mut xml, r, &mut edge_id);
        }
    }
    write_shared_evidence_edges(&mut xml, entities, &mut edge_id);
    let _ = writeln!(xml, r#"    </edges>"#);

    let _ = writeln!(xml, r#"  </graph>"#);
    let _ = writeln!(xml, r#"</gexf>"#);

    xml
}

/// XML header, `<meta>`, the `<graph>` open tag, and the node attribute
/// declarations (kind / confidence / c_effective / classification /
/// corroboration / coreness / tags / diamond_vertex / generation). Leaves `xml`
/// positioned to receive `<nodes>`.
fn write_preamble(xml: &mut String, scan_id: &str) {
    let _ = writeln!(xml, r#"<?xml version="1.0" encoding="UTF-8"?>"#);
    let _ = writeln!(xml, r#"<gexf xmlns="http://gexf.net/1.3" version="1.3">"#);
    let _ = writeln!(xml, r#"  <meta>"#);
    let _ = writeln!(xml, r#"    <creator>Huntsman Search Engine</creator>"#);
    // `scan_id` is XML *text* content here: escape it so a metachar (`<`/`&`)
    // can't break the whole document (defence-in-depth — scan ids are UUIDs today).
    let _ = writeln!(
        xml,
        r#"    <description>Scan {}</description>"#,
        xml_escape(scan_id)
    );
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
    let _ = writeln!(
        xml,
        r#"      <attribute id="5" title="coreness" type="integer"/>"#
    );
    let _ = writeln!(
        xml,
        r#"      <attribute id="6" title="tags" type="string"/>"#
    );
    // Diamond Model attribution vertex (victim / infrastructure / capability) —
    // the deterministic `core::diamond` classification, exported so a Gephi
    // analyst can partition or colour the WHOLE entity graph by attribution role
    // in one click, not just by kind. A fixed lowercase enum string, never
    // adversary (that role is relational, carried by the edges, not the node).
    let _ = writeln!(
        xml,
        r#"      <attribute id="7" title="diamond_vertex" type="string"/>"#
    );
    // `generation` — how many pivots out from the seed this node was found
    // (0 = the seed itself). Exported so a Gephi analyst can size/colour the
    // graph by expansion depth and see the pivot frontier at a glance. The
    // debug bundle and the CSV export already carry it; GEXF was the last graph
    // artifact dropping it.
    let _ = writeln!(
        xml,
        r#"      <attribute id="8" title="generation" type="integer"/>"#
    );
    let _ = writeln!(xml, r#"    </attributes>"#);
}

/// One `<node>` element with its nine `<attvalue>`s. The id is the truncated
/// uid (see [`short_uid`]) so relation/co-occurrence edges can reference it.
/// `coreness` is the k-core index (0 = isolated periphery, higher = more
/// deeply embedded in a densely-connected cluster). `tags` is `|`-joined (the
/// same convention the CSV export's `tags` column uses) so an analyst working
/// purely from the Gephi import — e.g. to filter/colour `breach`/`candidate`
/// (quarantine) nodes — isn't forced back to the CSV/JSON for data the SPA
/// already shows as pills.
fn write_node(xml: &mut String, e: &Entity, coreness: usize) {
    let label = xml_escape(&e.value);
    let _ = writeln!(
        xml,
        r#"      <node id="{}" label="{label}">"#,
        short_uid(&e.uid)
    );
    let _ = writeln!(xml, r#"        <attvalues>"#);
    // The `kind` attvalue must be escaped: `EntityKind::Other(s)` renders as
    // `other:<s>` where `s` is data-derived and can carry `<`/`&`/`"`, which
    // would otherwise break this attribute (and the whole node) in Gephi.
    let _ = writeln!(
        xml,
        r#"          <attvalue for="0" value="{}"/>"#,
        xml_escape(&e.kind.to_string())
    );
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
    let _ = writeln!(xml, r#"          <attvalue for="5" value="{coreness}"/>"#);
    let _ = writeln!(
        xml,
        r#"          <attvalue for="6" value="{}"/>"#,
        xml_escape(&e.tags.join("|"))
    );
    // Diamond attribution vertex — a fixed lowercase enum string, XML-safe by
    // construction (no escaping needed), so no scan can ever produce an
    // unclassified node in the graph view.
    let _ = writeln!(
        xml,
        r#"          <attvalue for="7" value="{}"/>"#,
        e.diamond_vertex().as_str()
    );
    // Expansion depth (hops from the seed) — integer, XML-safe by construction.
    let _ = writeln!(
        xml,
        r#"          <attvalue for="8" value="{}"/>"#,
        e.generation
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
/// shares ≥1 corroborating evidence **record**, an edge weighted by the
/// shared-record count and labelled by the joined source names. Advances
/// `edge_id` per emitted edge.
///
/// Keys on [`Entity::corroborating_records`] — the `(source, summary)` pair —
/// NOT the bare source name ([`Entity::corroborating_sources`]) and NOT
/// `evidence_sources`. Two entities genuinely co-occur only when an INDEPENDENT
/// source named them both in the SAME finding:
///
/// * The non-corroborating passes are excluded already (record inherits the
///   source filter): `name_intel` is the seed's permutation engine and
///   `recall` / `cross_scan_history` are replays of a prior observation.
/// * The record-level key additionally defeats one-to-many *fan-out
///   enumeration*. A probe like `username_search` checks a single handle across
///   dozens of platforms, emitting a distinct entity + distinct per-platform
///   summary each; those are independent existence-proofs of one selector, not a
///   joint sighting. Keyed on the source NAME they all shared `username_search`
///   and wired into a false N-clique that swamped the genuine structure in Gephi
///   (on a real username scan this was ~80% of all export edges — the exact
///   "dense web of false clusters" this edge kind is meant to avoid); keyed on
///   the record their differing summaries draw no edge.
///
/// A real joint record — both selectors in the same breach dump (identical
/// `("hibp", "Breach 'Apollo'")`) or extracted from the same crawled page — is
/// shared verbatim, so the true co-occurrence edge survives. Seed-derivation
/// lineage remains carried, correctly, by the typed `DerivedFrom` relation edges.
fn write_shared_evidence_edges(xml: &mut String, entities: &[Entity], edge_id: &mut u64) {
    for (i, src) in entities.iter().enumerate() {
        let src_records = src.corroborating_records();
        for tgt in entities.iter().skip(i + 1) {
            let tgt_records = tgt.corroborating_records();
            let shared: Vec<(&str, &str)> =
                src_records.intersection(&tgt_records).copied().collect();
            if shared.is_empty() {
                continue;
            }
            // Weight = number of shared records (strength of the joint sighting).
            // Label = the DISTINCT source names among those records, sorted for a
            // deterministic, readable Gephi label (HashSet order is not stable;
            // two entities can share several records from one source).
            let mut labels: Vec<&str> = shared.iter().map(|&(s, _)| s).collect();
            labels.sort_unstable();
            labels.dedup();
            let _ = writeln!(
                xml,
                r#"      <edge id="{edge_id}" source="{}" target="{}" weight="{}.0" label="{}"/>"#,
                short_uid(&src.uid),
                short_uid(&tgt.uid),
                shared.len(),
                xml_escape(&labels.join(", "))
            );
            *edge_id += 1;
        }
    }
}

// This module's own hardened escaper, now shared. It was correct here and wrong in
// `core::snake_graph`, which had a second copy covering only the five metacharacters — the defect
// was that there were two. Moved to `core::xml` verbatim so both serializers call one
// implementation and cannot drift again; the rationale for dropping XML-illegal characters rather
// than escaping them lives there.
use crate::core::xml::escape as xml_escape;

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
