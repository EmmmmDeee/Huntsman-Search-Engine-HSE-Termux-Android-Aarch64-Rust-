//! Orchestrates the full deterministic relation-derivation chain: the
//! infrastructure-graph builders ([`super::infra_builders`]) and the
//! identity-graph builders ([`super::identity_builders`]), run in one
//! dependency-ordered pass via [`derive_all`]/[`derive_all_within`] so the
//! live scan and import paths can never derive a different edge set from the
//! same entities.

use crate::core::entity::Entity;
use crate::core::relation::social_extract::derive_profile_links;
use crate::core::relation::types::Relation;

pub use super::identity_builders::{
    derive_canonical_identities, derive_co_mention, derive_co_residence, derive_coreferences,
    derive_declared_associations, derive_handles, derive_identity_ownership, derive_kinship,
    derive_regional_kinship, derive_residency, derive_reused_secret_link, derive_shared_selector,
};
pub use super::infra_builders::{
    CO_LOCATION_KM, derive_co_ownership, derive_colocation, derive_name_lineage,
    derive_registration, derive_resolution, derive_structural,
};

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
