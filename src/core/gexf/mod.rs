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

    // The nearest-place label of each coordinate, from this scan's own stored
    // records among the nodes being written (REQ-GEOLABEL-002).
    let place_ctx = crate::core::place::PlaceContext::for_scan(entities, scan_id);

    let _ = writeln!(xml, r#"    <nodes>"#);
    for e in entities {
        let c = coreness_map.get(e.uid.as_str()).copied().unwrap_or(0);
        let place = crate::core::place::describe(e, &place_ctx);
        write_node(&mut xml, e, c, place.as_ref());
    }
    let _ = writeln!(xml, r#"    </nodes>"#);

    // Edges. Two kinds, told apart by the `edge_type` edge attribute (never by
    // guessing which label strings are relation kinds and which are module
    // names), and weighted on ONE scale, [0, 1]:
    //   1. Typed Relation edges (the explicit attribution graph), labelled by
    //      relation kind (subdomain_of / belongs_to_domain / hosted_on /
    //      derived_from), weighted by edge confidence. `edge_type=relation`.
    //   2. Shared-evidence co-occurrence edges, labelled by the shared sources,
    //      weighted by `coref::shared_evidence_weight` of the shared-record
    //      count. `edge_type=co_occurrence`, count in `shared_records`.
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
        entities.iter().map(|e| e.uid.as_str()).collect();
    let _ = writeln!(xml, r#"    <edges>"#);
    let mut edge_id = 0u64;
    for r in relations {
        if node_ids.contains(r.from_uid.as_str()) && node_ids.contains(r.to_uid.as_str()) {
            write_relation_edge(&mut xml, r, &mut edge_id);
        }
    }
    write_shared_evidence_edges(&mut xml, entities, &mut edge_id);
    let _ = writeln!(xml, r#"    </edges>"#);

    let _ = writeln!(xml, r#"  </graph>"#);
    let _ = writeln!(xml, r#"</gexf>"#);

    xml
}

/// XML header, `<meta>`, the `<graph>` open tag, the node attribute
/// declarations (kind / confidence / c_effective / classification /
/// corroboration / coreness / tags / diamond_vertex / generation) and the edge
/// attribute declarations (edge_type / shared_records). Leaves `xml`
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
    // Diamond Model attribution vertex (victim / unattributed / infrastructure /
    // capability) — `core::diamond::scoped_vertex_label`, exported so a Gephi
    // analyst can partition or colour the WHOLE entity graph by attribution role
    // in one click, not just by kind. `victim` is reserved for identity nodes
    // the engine scoped to the subject; any other identity node is
    // `unattributed`, so the one-click partition never merges a namesake, a
    // relative or a stranger's handle into the subject. A fixed lowercase
    // string, never adversary (that role is relational, carried by the edges).
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
    // The nearest-place label of a coordinate (`core::place::describe`), empty
    // on every other kind. Appended as the next id so every existing attribute
    // keeps its number.
    let _ = writeln!(
        xml,
        r#"      <attribute id="9" title="place_label" type="string"/>"#
    );
    let _ = writeln!(xml, r#"    </attributes>"#);

    // Edge attributes. GEXF scopes attribute ids per class, so these ids do
    // not collide with the node attributes above. `edge_type` is what lets a
    // Gephi analyst filter or style the two edge families apart — a relation
    // (a typed structural or attribution fact) and a co-occurrence (two
    // entities named in one evidence record) are different claims, and the
    // label namespace alone (relation kinds vs module names) never said which
    // was which. `shared_records` keeps the raw count a co-occurrence weight is
    // derived from, so normalising the weight loses nothing.
    let _ = writeln!(xml, r#"    <attributes class="edge" mode="static">"#);
    let _ = writeln!(
        xml,
        r#"      <attribute id="0" title="edge_type" type="string"/>"#
    );
    let _ = writeln!(
        xml,
        r#"      <attribute id="1" title="shared_records" type="integer"/>"#
    );
    let _ = writeln!(xml, r#"    </attributes>"#);
}

/// One `<node>` element with its ten `<attvalue>`s. The id is the entity's
/// full uid (the hex SHA-256 digest — always XML-`ID`-safe, no escaping
/// needed) so relation/co-occurrence edges can reference it unambiguously.
/// A PRIOR version truncated this to 12 hex chars (48 bits): two distinct
/// entities whose full uids merely agreed on that prefix were emitted as two
/// `<node>` elements sharing one id — structurally-invalid GEXF that Gephi
/// silently resolves by keeping only one node's data, leaving every edge
/// referencing that id ambiguous as to which entity it actually connects.
/// Reachable in practice: a scan ingests attacker-controlled breach/scrape
/// text, and a 48-bit collision is findable offline well within a motivated
/// adversary's reach. The full uid eliminates the collision class rather
/// than shrinking its probability.
/// `coreness` is the k-core index (0 = isolated periphery, higher = more
/// deeply embedded in a densely-connected cluster). `tags` is `|`-joined (the
/// same convention the CSV export's `tags` column uses) so an analyst working
/// purely from the Gephi import — e.g. to filter/colour `breach`/`candidate`
/// (quarantine) nodes — isn't forced back to the CSV/JSON for data the SPA
/// already shows as pills.
///
/// A `Coordinates` node with a place label is LABELLED `{place} [{value}]`, so
/// a Gephi canvas reads "Brisbane, QLD (city centroid …) [-27.4698,153.0251]"
/// instead of a bare pair of numbers; its id stays the uid, so no edge moves.
fn write_node(
    xml: &mut String,
    e: &Entity,
    coreness: usize,
    place: Option<&crate::core::place::PlaceLabel>,
) {
    let label = match place {
        Some(p) => xml_escape(&format!("{} [{}]", p.text, e.value)),
        None => xml_escape(&e.value),
    };
    let _ = writeln!(xml, r#"      <node id="{}" label="{label}">"#, e.uid);
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
    // Diamond attribution vertex, scoped to the subject — a fixed lowercase
    // string, XML-safe by construction (no escaping needed). Per ENTITY, not
    // per kind: see `scoped_vertex_label` for why an unscoped identity node is
    // `unattributed` rather than `victim`.
    let _ = writeln!(
        xml,
        r#"          <attvalue for="7" value="{}"/>"#,
        crate::core::diamond::scoped_vertex_label(e)
    );
    // Expansion depth (hops from the seed) — integer, XML-safe by construction.
    let _ = writeln!(
        xml,
        r#"          <attvalue for="8" value="{}"/>"#,
        e.generation
    );
    let _ = writeln!(
        xml,
        r#"          <attvalue for="9" value="{}"/>"#,
        xml_escape(place.map_or("", |p| p.text.as_str()))
    );
    let _ = writeln!(xml, r#"        </attvalues>"#);
    let _ = writeln!(xml, r#"      </node>"#);
}

/// One typed `Relation` edge, weighted by edge confidence (`[0, 1]`), labelled
/// by the relation kind and typed `edge_type=relation`. Advances `edge_id`.
fn write_relation_edge(xml: &mut String, r: &Relation, edge_id: &mut u64) {
    let _ = writeln!(
        xml,
        r#"      <edge id="{edge_id}" source="{}" target="{}" weight="{:.3}" label="{}">"#,
        r.from_uid,
        r.to_uid,
        r.confidence,
        xml_escape(r.kind.as_str())
    );
    let _ = writeln!(xml, r#"        <attvalues>"#);
    let _ = writeln!(xml, r#"          <attvalue for="0" value="relation"/>"#);
    let _ = writeln!(xml, r#"        </attvalues>"#);
    let _ = writeln!(xml, r#"      </edge>"#);
    *edge_id += 1;
}

/// Shared-evidence co-occurrence edges: for every unordered entity pair that
/// shares ≥1 corroborating evidence **record**, an edge labelled by the joined
/// source names, typed `edge_type=co_occurrence`, carrying the shared-record
/// count as `shared_records`, and weighted `1 − 0.7^count`
/// (`coref::shared_evidence_weight`) — the SAME `[0, 1]` scale as a relation
/// edge's confidence. Advances `edge_id` per emitted edge.
///
/// The weight used to be the raw count (`1.0`, `2.0`, …) in the same `weight`
/// attribute as relation confidences (≤ 0.95). Gephi's weighted degree,
/// modularity and edge-weight filters read every edge's `weight` as one
/// quantity, so one shared search snippet outranked any verified typed
/// relation — in scan 7258fc07 ~276 co-occurrence edges sat at ≥ 1.0 beside
/// ~21,000 relations at ≤ 0.95.
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
///
/// The key is sound only if every emitter's summary NAMES its record: a module
/// that writes one templated summary for distinct findings ("Profile found on
/// twitter" for three different profiles) makes them look like one shared
/// record, and this function wires them into a false clique. That contract is
/// enforced at the emitters, not patched here. Attributes are deliberately NOT
/// part of the key: `Entity::absorb` merges a record's attributes across
/// observations and modules add per-entity ones, so a genuine joint record's
/// attributes legitimately differ between the entities that carry it — keying
/// on them would drop real edges (a `huggingface_user` person ↔ profile pair)
/// while keeping templated ones whose attributes happen to agree.
fn write_shared_evidence_edges(xml: &mut String, entities: &[Entity], edge_id: &mut u64) {
    // Each entity's record set is built ONCE, up front.
    //
    // `corroborating_records` is not a getter: it filters the entity's evidence
    // and collects a fresh `HashSet` on every call. The outer loop hoisted that
    // for `src`, but the inner loop called it again for every `tgt`, so each
    // entity's set was rebuilt n-1 times — n(n-1)/2 set allocations to draw the
    // edges of an n-entity graph, each one re-hashing that entity's whole
    // evidence list. `entities` here is the complete, uncapped entity list of a
    // scan (`scan_export`'s `scan.gexf` route and `app::export` both pass it
    // straight through, filtered only for CANDIDATE), so n grows with scan
    // breadth and with the size of any imported dump.
    //
    // Precomputing makes it n allocations. The pairwise comparison itself stays
    // O(n^2) — that is inherent to drawing an edge per co-occurring pair — but
    // the allocation and re-hashing cost drops from quadratic to linear.
    // `core::coref` and the `identity::account` rule already solve this exact
    // shape the same way; this was the site that had been missed.
    //
    // Output is unchanged: the pair iteration order is identical, and `shared`
    // is consumed only by `.len()` and by `labels`, which is sorted and deduped
    // before it is written.
    //
    // An ENGINE-DERIVED corroboration record (geo / multipath / cross-scan
    // agreement) is excluded from the key. It is a per-entity inference, not a
    // source naming two entities together, and its summary is a template: the
    // geo-family pass writes "Shared-surname relative ~0 km from the subject's
    // confirmed location …" onto every promoted entity at the same rounded
    // distance, so the identical text wired every one of them to every other —
    // 12,319 of a real "Ian Thorpe" export's 33,473 edges were that one false
    // clique (REQ-GEO-FAMILY-001). The typed relation edges still carry any real
    // link the pass established.
    let records: Vec<std::collections::HashSet<(&str, &str)>> = entities
        .iter()
        .map(|e| {
            let mut r = e.corroborating_records();
            r.retain(|&(source, _)| !crate::core::entity::is_engine_corroboration_source(source));
            r
        })
        .collect();
    for (i, src) in entities.iter().enumerate() {
        let src_records = &records[i];
        for (j, tgt) in entities.iter().enumerate().skip(i + 1) {
            let tgt_records = &records[j];
            let shared: Vec<(&str, &str)> =
                src_records.intersection(tgt_records).copied().collect();
            if shared.is_empty() {
                continue;
            }
            // Weight = `shared_evidence_weight(count)`: the strength of the
            // joint sighting on the relation edges' [0, 1] scale (the count
            // itself is kept as `shared_records`).
            // Label = the DISTINCT source names among those records, sorted for a
            // deterministic, readable Gephi label (HashSet order is not stable;
            // two entities can share several records from one source).
            let mut labels: Vec<&str> = shared.iter().map(|&(s, _)| s).collect();
            labels.sort_unstable();
            labels.dedup();
            let _ = writeln!(
                xml,
                r#"      <edge id="{edge_id}" source="{}" target="{}" weight="{:.3}" label="{}">"#,
                src.uid,
                tgt.uid,
                crate::core::coref::shared_evidence_weight(shared.len()),
                xml_escape(&labels.join(", "))
            );
            let _ = writeln!(xml, r#"        <attvalues>"#);
            let _ = writeln!(
                xml,
                r#"          <attvalue for="0" value="co_occurrence"/>"#
            );
            let _ = writeln!(
                xml,
                r#"          <attvalue for="1" value="{}"/>"#,
                shared.len()
            );
            let _ = writeln!(xml, r#"        </attvalues>"#);
            let _ = writeln!(xml, r#"      </edge>"#);
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
