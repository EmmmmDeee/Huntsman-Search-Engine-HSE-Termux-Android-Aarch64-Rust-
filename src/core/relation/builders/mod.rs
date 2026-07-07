//! Relation derivation: the master pass order ([`derive_all`],
//! [`derive_all_within`]) plus the small set of helpers shared across the
//! builder families below.
//!
//! Each family lives in its own satellite, split along the boundary the
//! original module already documented in its own section comments:
//!   - [`infra`] — the infrastructure graph (subdomains, hosting, DNS, WHOIS,
//!     co-ownership).
//!   - [`identity`] — the person-centric graph (handle aliases, identifier
//!     ownership, residency, kinship, co-residence, co-mention, affiliation).
//!   - [`consolidation`] — collapsing separately-extracted entities that are
//!     the same real-world identity (canonical identities, profile links,
//!     co-reference promotion).
//!
//! This hub holds only what genuinely crosses those boundaries —
//! [`persons_by_name`], [`sort_edges`], [`emit_pairwise`] — plus the pass
//! chain that ties every family together into one deterministic edge set.

mod consolidation;
mod identity;
mod infra;

use crate::core::entity::{Entity, EntityKind};
use crate::core::relation::types::{Relation, RelationKind};

pub use consolidation::{derive_canonical_identities, derive_coreferences, derive_profile_links};
pub use identity::{
    derive_co_mention, derive_co_residence, derive_declared_associations, derive_handles,
    derive_identity_ownership, derive_kinship, derive_regional_kinship, derive_residency,
    derive_reused_secret_link, derive_shared_selector,
};
pub use infra::{
    CO_LOCATION_KM, derive_co_ownership, derive_colocation, derive_name_lineage,
    derive_registration, derive_resolution, derive_structural,
};

/// Index present Person entities by their folded full name, resolving collisions
/// deterministically (higher confidence, then smaller uid) so the chosen target
/// never depends on the caller's entity order — the determinism invariant the
/// whole module holds to. Shared across families: infra's `derive_name_lineage`
/// and every identity builder that resolves an evidence-named person index into
/// this same key.
fn persons_by_name(entities: &[Entity]) -> std::collections::HashMap<String, &Entity> {
    let mut persons = std::collections::HashMap::new();
    for p in entities.iter().filter(|e| e.kind == EntityKind::Person) {
        persons
            .entry(p.value.trim().to_lowercase())
            .and_modify(|cur: &mut &Entity| {
                if p.confidence > cur.confidence
                    || (p.confidence == cur.confidence && p.uid < cur.uid)
                {
                    *cur = p;
                }
            })
            .or_insert(p);
    }
    persons
}

/// Stable output order (by endpoints) so a builder whose internal grouping uses a
/// `HashMap` still returns a deterministic `Vec` — matching the module contract.
fn sort_edges(edges: &mut [Relation]) {
    edges.sort_by(|a, b| {
        (a.from_uid.as_str(), a.to_uid.as_str()).cmp(&(b.from_uid.as_str(), b.to_uid.as_str()))
    });
}

/// Emit one canonically-directed (`smaller-uid → larger`), deduplicated `kind` edge
/// per distinct pair within each group, the confidence from `conf(from, to)`. The
/// shared "clique → symmetric pairwise edges" core every group-based builder needs
/// (co-residence, co-mention, shared-selector, canonical identities): each assembles
/// the entity groups it judges related — already filtered / capped to its own rules —
/// and this performs the pairing, canonical direction, cross-group dedup, and
/// deterministic final ordering ONCE, instead of every builder re-implementing the
/// same nested loop. Members are sorted by UID, so the edge set is independent of how
/// a caller ordered each group.
fn emit_pairwise<'a>(
    groups: impl IntoIterator<Item = Vec<&'a Entity>>,
    kind: RelationKind,
    scan_id: &str,
    conf: impl Fn(&Entity, &Entity) -> f64,
) -> Vec<Relation> {
    use std::collections::HashSet;

    let mut seen: HashSet<(String, String)> = HashSet::new();
    let mut out = Vec::new();
    for mut members in groups {
        members.sort_by(|a, b| a.uid.cmp(&b.uid));
        for i in 0..members.len() {
            for j in (i + 1)..members.len() {
                let (a, b) = (members[i], members[j]);
                let (from, to) = if a.uid <= b.uid { (a, b) } else { (b, a) };
                if from.uid != to.uid && seen.insert((from.uid.clone(), to.uid.clone())) {
                    out.push(Relation::new(
                        from.uid.as_str(),
                        to.uid.as_str(),
                        kind,
                        conf(from, to),
                        scan_id,
                    ));
                }
            }
        }
    }
    sort_edges(&mut out);
    out
}

/// Derive every deterministic, evidence-grounded relation the engine knows how
/// to reconstruct from a persisted entity set alone — the infrastructure layer
/// (structural ownership, geo co-location, DNS resolution, WHOIS registration,
/// name lineage) and the identity layer (handle aliases, identifier ownership,
/// residency, kinship, co-residence) — in a single stable order. This is the
/// lineage-free
/// counterpart to the live scan's relation pass: the import paths (CLI `hse
/// import` and the web `scan_import` upload) have no in-flight expansion edges,
/// but every edge derivable from the entities + their evidence still applies, so
/// an imported dossier gets the same graph a live scan would. One definition so
/// the live and import paths can't drift on which relations a finished scan
/// carries.
pub fn derive_all(entities: &[Entity], scan_id: &str) -> Vec<Relation> {
    derive_all_within(entities, scan_id, None)
}

/// Wall-clock budget for the finalise-time relation derivation. Most of the
/// ~16 passes pair entities, so the chain is super-linear in the entity count;
/// on a pathological graph (a `--full --expand-all-identities` scan that fills
/// `max_entities`) the unbounded chain can run for minutes, and an operator
/// timeout SIGKILL mid-derivation drops the whole dossier (observed: a
/// 2500-entity scan killed in finalise wrote zero output). 90 s is generous —
/// a normal scan's derivation completes in well under a second, so only a
/// pathological graph ever trips it.
pub const DERIVE_BUDGET: std::time::Duration = std::time::Duration::from_secs(90);

/// Same as [`derive_all`], but stops starting NEW derivation passes once
/// `deadline` is reached, returning whatever edges were built so far. The
/// passes are ordered by dependency (structural / resolution / registration
/// first, then the inference passes that consume them), so a budget cut keeps
/// the foundational attribution graph and only drops the softer inference
/// edges — the finalise then persists a partial-but-coherent relation set
/// instead of being SIGKILLed with nothing. `None` runs the full chain
/// unconditionally (the import path and every test exercise that branch).
///
/// Mirrors the correlator's finalise budget so a scan ALWAYS converges to a
/// written dossier: collection stops at the wall-time, derivation stops at this
/// deadline, and correlation has its own budget — every phase is bounded.
pub fn derive_all_within(
    entities: &[Entity],
    scan_id: &str,
    deadline: Option<std::time::Instant>,
) -> Vec<Relation> {
    // Stop the pass chain if the budget is spent; `passed` names the last pass
    // that completed so the log shows how far derivation got. `out` is threaded
    // in as an argument (not captured) so it resolves to the function-local
    // accumulator under macro hygiene rather than a fresh macro-scoped binding.
    macro_rules! budget_spent {
        ($out:expr, $passed:expr) => {
            if deadline.is_some_and(|dl| std::time::Instant::now() >= dl) {
                tracing::warn!(
                    scan_id,
                    entities = entities.len(),
                    after = $passed,
                    "relation-derivation budget exceeded — finalising with partial relations"
                );
                return $out;
            }
        };
    }

    let mut out = derive_structural(entities, scan_id);
    budget_spent!(out, "structural");
    out.extend(derive_colocation(entities, scan_id));
    budget_spent!(out, "colocation");
    out.extend(derive_resolution(entities, scan_id));
    budget_spent!(out, "resolution");
    out.extend(derive_registration(entities, scan_id));
    budget_spent!(out, "registration");
    out.extend(derive_name_lineage(entities, scan_id));
    budget_spent!(out, "name_lineage");
    // Co-ownership — needs RegisteredBy and ResolvesTo edges built above.
    let co = derive_co_ownership(entities, &out, scan_id);
    out.extend(co);
    budget_spent!(out, "co_ownership");
    // Identity-profile links — Username → social profile Url.
    out.extend(derive_profile_links(entities, scan_id));
    budget_spent!(out, "profile_links");
    out.extend(derive_handles(entities, scan_id));
    budget_spent!(out, "handles");
    // The graph-native counterpart of the AU-047/AU-048/AU-106 "controller behind
    // reused secrets" correlations — a proven shared-secret tie as a walkable edge,
    // not just a standalone finding.
    out.extend(derive_reused_secret_link(entities, scan_id));
    budget_spent!(out, "reused_secret_link");
    out.extend(derive_identity_ownership(entities, scan_id));
    budget_spent!(out, "identity_ownership");
    out.extend(derive_residency(entities, scan_id));
    budget_spent!(out, "residency");
    out.extend(derive_kinship(entities, scan_id));
    budget_spent!(out, "kinship");
    // Geo-gated kinship: recover the COMMON-surname families derive_kinship drops,
    // corroborated by a shared AU town. Disjoint from kinship (common surnames
    // only), so it only ADDS the family links the commonness discount would miss.
    out.extend(derive_regional_kinship(entities, scan_id));
    budget_spent!(out, "regional_kinship");
    // Co-residence after kinship: an evidence-grounded household edge (×0.8)
    // outranks a surname guess (×0.5) on the same pair, and links the
    // DIFFERENT-surname household members kinship can't reach.
    out.extend(derive_co_residence(entities, scan_id));
    budget_spent!(out, "co_residence");
    // Co-mention after co-residence: the document-level association analog — people a
    // single SOURCE names together (an obituary, a family notice, one result page).
    // Damped below co-residence; a same-surname co-mentioned pair keeps its stronger
    // kinship edge, so independent angles corroborate rather than double-count.
    out.extend(derive_co_mention(entities, scan_id));
    budget_spent!(out, "co_mention");
    // Shared-selector affiliation: entities sharing a DISTINCTIVE owner / infra
    // selector (registrant, TLS/SSH fingerprint, gravatar) — the universal
    // reverse-WHOIS / fingerprint pivot, domain-agnostic across every scan.
    out.extend(derive_shared_selector(entities, scan_id));
    budget_spent!(out, "shared_selector");
    // Canonical identities: collapse contextual VARIANTS of one entity (Gmail dot/+tag,
    // phone formats, name reorderings) into SameAs edges via the canonical resolver —
    // the reflexive self-pairing that makes a seed and its variants one traversable node.
    out.extend(derive_canonical_identities(entities, scan_id));
    budget_spent!(out, "canonical_identities");
    // Co-reference promotion AFTER every structural identity builder, reading the
    // edges built so far so it only ADDS the same-individual links they missed
    // (name-token / substring / multi-breach co-occurrence) and never restates one
    // they already emitted. The graph-enriching counterpart to the read-only
    // `/identities` view.
    let coref = derive_coreferences(entities, &out, scan_id);
    out.extend(coref);
    budget_spent!(out, "coreferences");
    // Declared associations LAST so a `(from, kind, to)` edge a surname guess or a
    // co-residence inference already emitted is re-emitted here at full (declared)
    // confidence.
    out.extend(derive_declared_associations(entities, scan_id));
    // Collapse duplicate edges to their MAX confidence. Several builders emit the
    // same `(from, kind, to)` pair — hence the same `Relation::id`, which EXCLUDES
    // confidence — weakest-first (surname kinship ×0.5 → co-residence ×0.8 →
    // declared full trust). Persistence upserts `ON CONFLICT(id) DO NOTHING`
    // (first-write-wins), so without this the WEAKEST edge would persist and the
    // stronger ones silently drop — the inverse of the "later, higher-trust edge
    // wins" intent the emit order assumes. That would record high-value identity
    // links at surname-guess confidence and can flip downstream confidence-floor
    // gating (resolve_identity_clusters / connection_brokers). Collapsing here makes
    // the intent hold regardless of emit order or the persistence conflict policy.
    collapse_to_max_confidence(out)
}

/// Collapse duplicate edges (same [`Relation::id`] — same `from`/`kind`/`to`/`scan`,
/// which EXCLUDES confidence) to the single edge with the greatest confidence.
/// First-occurrence order of distinct ids is preserved and an equal-confidence tie
/// keeps the earliest edge, so the result is deterministic — the `HashMap` is a
/// membership index only; output order comes from the input, not its iteration.
pub(super) fn collapse_to_max_confidence(relations: Vec<Relation>) -> Vec<Relation> {
    let mut idx: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    let mut out: Vec<Relation> = Vec::with_capacity(relations.len());
    for r in relations {
        if let Some(&i) = idx.get(&r.id) {
            if r.confidence > out[i].confidence {
                out[i] = r;
            }
        } else {
            idx.insert(r.id.clone(), out.len());
            out.push(r);
        }
    }
    out
}
