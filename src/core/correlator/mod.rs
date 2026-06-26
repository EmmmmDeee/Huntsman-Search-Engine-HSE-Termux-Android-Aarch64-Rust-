// Correlator — rule-based cross-correlation analysis.
//
// Two entry points share the same deterministic rule set:
//
//   * [`Correlator::run`] — the authoritative finalise-time pass. Loads the
//     scan's persisted entities *and* the typed relation edges, evaluates
//     both the entity rules and the graph-aware relation rules, and persists
//     every firing.
//   * [`correlate_entities`] — a live, in-memory pass the engine invokes
//     during ingestion (after the seed round and after each expansion round)
//     so high-confidence correlations stream out as the graph grows rather
//     than only after the scan finishes. Entity rules only — relation rules
//     need the persisted edge set, so they stay in `run`.
//
// Each firing rule produces a [`Correlation`] record persisted alongside the
// scan and emitted on the event bus. Rules are deterministic — no LLMs,
// no fuzzy matching.

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

use crate::core::entity::Entity;
use crate::core::error::Result;
use crate::core::port::StoragePort;
use crate::core::relation::Relation;

// ─── Severity ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_canonical(&self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }

    /// Ordinal weight for ranking. Higher = more severe. Used as the severity
    /// factor in a correlation's rank score (`weight × max child C_eff`).
    pub fn weight(&self) -> f64 {
        match self {
            Self::Low => 1.0,
            Self::Medium => 2.0,
            Self::High => 3.0,
            Self::Critical => 4.0,
        }
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Low => write!(f, "LOW"),
            Self::Medium => write!(f, "MEDIUM"),
            Self::High => write!(f, "HIGH"),
            Self::Critical => write!(f, "CRITICAL"),
        }
    }
}

// ─── Correlation ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Correlation {
    pub rule_id: String,
    pub rule_name: String,
    pub severity: Severity,
    pub description: String,
    pub entity_uids: Vec<String>,
    pub scan_id: String,
    pub ts: u64,
    /// Ranking score = `severity.weight() × max(C_eff)` over the child
    /// entities. Computed once in `Correlator::run` after the rules fire (the
    /// rules themselves don't have the entity C_eff map handy) and used to
    /// order the Correlations view highest-value-first. `#[serde(default)]`
    /// keeps correlation rows persisted before this field existed readable
    /// (they deserialize with rank 0.0 and simply sort last).
    #[serde(default)]
    pub rank: f64,
}

/// Compute `severity.weight() × max(C_eff)` over the child entities of each
/// correlation, write it into `rank`, and sort the slice rank-descending with
/// a stable severity/rule_id tie-break. Shared by both the finalize pass
/// (`Correlator::run`) and the live incremental pass (engine) so a correlation
/// carries the same rank whether it was streamed mid-scan or produced at the
/// end. `ceff` maps entity uid → c_effective().
pub fn rank_and_sort(corrs: &mut [Correlation], ceff: &std::collections::HashMap<String, f64>) {
    for c in corrs.iter_mut() {
        let max_child = c
            .entity_uids
            .iter()
            .filter_map(|uid| ceff.get(uid).copied())
            .fold(0.0_f64, f64::max);
        c.rank = c.severity.weight() * max_child;
    }
    corrs.sort_by(|a, b| {
        b.rank
            .partial_cmp(&a.rank)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then(b.severity.cmp(&a.severity))
            .then(a.rule_id.cmp(&b.rule_id))
            // Total tie-break so the ORDER is deterministic even when one rule
            // fires for several entity groups (same rule_id): the per-group
            // entity_uids are already individually sorted, so comparing the lists
            // gives identical inputs an identical correlation ordering rather than
            // leaving same-rule ties to non-deterministic generation order.
            .then_with(|| a.entity_uids.cmp(&b.entity_uids))
    });
}

impl Correlation {
    pub(crate) fn new(
        rule_id: &str,
        rule_name: &str,
        severity: Severity,
        description: String,
        entity_uids: Vec<String>,
        scan_id: &str,
        ts: u64,
    ) -> Self {
        Self {
            rule_id: rule_id.into(),
            rule_name: rule_name.into(),
            severity,
            description,
            entity_uids,
            scan_id: scan_id.into(),
            ts,
            rank: 0.0,
        }
    }
}

// ─── Correlator ────────────────────────────────────────────────────────────

pub struct Correlator {
    store: Arc<dyn StoragePort>,
}

impl Correlator {
    pub fn new(store: Arc<dyn StoragePort>) -> Self {
        Self { store }
    }

    pub fn run(&self, scan_id: &str) -> Result<Vec<Correlation>> {
        let entities = self.store.entities_for_scan(scan_id)?;
        if entities.is_empty() {
            return Ok(Vec::new());
        }
        // Build the quarantine-filtered confirmed view ONCE and share it across
        // both the entity-only and the graph-aware passes. Each pass otherwise
        // re-filtered + re-cloned the full entity slice (`confirmed_only`); for a
        // finalise pass that runs both, that was two full clones of the entity
        // set per scan.
        let confirmed = confirmed_only(&entities);
        let now = crate::core::entity::unix_now();
        // One shared wall-clock deadline across the entity AND relation passes, so
        // the WHOLE finalise correlator phase is bounded (a huge recalled graph
        // can't hang the scan). Never reached by a normal scan.
        let deadline = Some(std::time::Instant::now() + CORRELATOR_BUDGET);
        let mut firings = evaluate_rules_on(&confirmed, scan_id, now, deadline);

        // Graph-aware pass: rules that need the typed relation edges (the
        // attribution graph), not just the flat entity list. Relations are
        // persisted by `finalise_scan` before the correlator runs.
        let relations = self.store.relations_for_scan(scan_id)?;
        if !relations.is_empty() {
            firings.extend(evaluate_relation_rules_on(
                &confirmed, &relations, scan_id, now, deadline,
            ));
        }

        // Rank each firing by severity × highest child C_eff and sort
        // (shared with the live incremental pass so ranks are consistent).
        let ceff: std::collections::HashMap<String, f64> = entities
            .iter()
            .map(|e| (e.uid.clone(), e.c_effective()))
            .collect();
        rank_and_sort(&mut firings, &ceff);

        for c in &firings {
            self.store.upsert_correlation(c)?;
        }
        debug!(scan_id, fired = firings.len(), "correlator done");
        Ok(firings)
    }
}

// ─── Rules ─────────────────────────────────────────────────────────────────

type RuleFn = fn(&[Entity], &str, u64) -> Vec<Correlation>;

mod rules;
pub(crate) use rules::location::{au059_synergy_fix, is_anchoring_geo_source};
// The shared multi-pathway corroboration detector — the AU-062 rule and the
// engine's `promote_multipath_corroborated` pass both call this one finder, so
// the correlation and the confidence boost can never drift apart. (The
// `MultipathLink` it returns is `pub(in crate::core)`, so callers read its
// fields by inference without naming the type.)
pub(in crate::core) use rules::multipath::multipath_corroborated_links;
// The shared single-pathway (fragile-link) detector — the AU-063 gap lead and
// the engine's cross-scan gap resolution (AU-066) both call this one finder, so
// the lead that flags a gap and the logic that fills it can't drift apart.
pub(in crate::core) use rules::gap::single_route_identity_links;
// Active gap-fill: the gap endpoints + the orthogonal families missing from each,
// and the source-family classifier the engine maps those families to modules
// with — so what AU-063 names, the engine actually pursues.
pub(in crate::core) use rules::gap::gap_fill_probes;
pub(in crate::core) use rules::source_family;
use rules::*;

const RULES: &[RuleFn] = &[
    rule_au_001_multi_breach,
    rule_au_002_identity_cluster,
    rule_au_003_high_corroboration,
    rule_au_004_malicious_infrastructure,
    rule_au_005_anonymous_network,
    rule_au_006_proxy_vpn,
    rule_au_007_high_risk_reputation,
    rule_au_008_exposed_service,
    rule_au_009_stealer_log,
    rule_au_010_infra_consensus,
    rule_au_011_cross_platform_username,
    rule_au_012_identity_linked_domain,
    rule_au_013_local_network_discovery,
    rule_au_014_geo_cluster,
    rule_au_015_threat_intel_hit,
    rule_au_016_breach_ip_geo_chain,
    rule_au_017_multi_geo_convergence,
    rule_au_018_email_address_colocation,
    rule_au_019_temporal_breach_cluster,
    rule_au_020_person_entity_cluster,
    rule_au_021_api_key_exposure,
    // AU-097: subject's IP/ASN belongs to an Australian ISP (Telstra/Optus/TPG/…)
    // or AARNet — a network-layer AU residency/affiliation signal.
    rule_au_097_au_isp_network,
    // AU-095: ranked exposure-intelligence portfolio over all harvested ApiKey
    // entities (provider × criticality × detection) — a revoke-first priority
    // order, complementing AU-021's flat per-key findings. Catalogue-only.
    rule_au_095_exposed_key_portfolio,
    // AU-096: a harvested key for an OSINT provider (Shodan/Dehashed/IntelX/…)
    // identifies its holder as an OSINT practitioner — provider + tradecraft
    // categories as the pivot. Reads the osint-practitioner/osint-category tags.
    rule_au_096_osint_practitioner,
    rule_au_022_organisation_with_breach,
    rule_au_023_cross_platform_identity,
    rule_au_024_email_fraud_signal,
    rule_au_025_corporate_identity_link,
    rule_au_026_validated_address,
    rule_au_027_address_coordinates_chain,
    rule_au_028_subdomain_takeover_risk,
    rule_au_029_cloud_storage_exposure,
    rule_au_030_geo_convergence_score,
    rule_au_033_abn_organisation_link,
    rule_au_034_handle_reuse_identity,
    rule_au_035_confirmed_derived_handle,
    rule_au_036_email_alias_convergence,
    rule_au_037_credential_exposure,
    rule_au_038_verified_cross_platform_identity,
    rule_au_039_wallet_identity,
    rule_au_040_wallet_breach_exposure,
    rule_au_041_ens_identity,
    rule_au_042_pgp_email_identity,
    rule_au_043_paste_exposure,
    rule_au_044_shared_tracking_id,
    rule_au_045_multi_service_identity,
    rule_au_072_payid_payment_surface,
    rule_au_073_subject_date_of_birth,
    rule_au_074_au_government_id_exposure,
    rule_au_075_named_associate,
    // AU-090: the subject's AU state/territory mined from a breach `state` /
    // state-of-issue field — a residency/jurisdiction geo anchor (sits with the
    // AU-073/074/075 breach-field family it shares breach_pii.rs with).
    rule_au_090_au_jurisdiction,
    // AU-091: the subject's residential postcode mined from a breach `postcode`
    // field, resolved offline to its state + gazetteer coordinate — finer than
    // AU-090's state grain.
    rule_au_091_au_postcode_locality,
    // AU-092: cross-checks the breach-stated state/postcode (AU-090/091) against
    // the geolocated coordinate/address footprint — agreement corroborates
    // residency, a disjoint state flags stale data / a move / a namesake.
    rule_au_092_breach_locality_footprint_crosscheck,
    // AU-093: assembles the subject's suburb / full residential address from the
    // co-located fields of one breach record, offline-geocoded — the dwelling-
    // grade locator AU-090/091 (single-field) can't reach.
    rule_au_093_au_address_from_breach,
    // AU-098: the multi-source residency verdict — fuses coordinate + address +
    // breach-record + phone-area-code into one jurisdiction, scored by how many
    // independent signal classes agree. The gold-standard geolocation finding.
    rule_au_098_residency_consensus,
    // Free, offline identity-resolution rules — require no API keys.
    // AU-076: email local-part ↔ username canonical match (zero-API bridge).
    // AU-077: name-derived username independently confirmed on a platform.
    // AU-078: hub entity observed in 3+ distinct prior investigations.
    // AU-079: profile bio / twitter attr names another username in the graph.
    // AU-080: recurring co-occurrence pair from cross-scan history now active.
    // AU-081: two Person records from different sources share a canonical name.
    // AU-082: same API key found in 2+ independent source families (dual-pathway).
    rule_au_076_email_username_localpart_bridge,
    rule_au_077_name_derived_username_confirmed,
    rule_au_078_hub_entity,
    rule_au_079_bio_cross_mention,
    rule_au_080_recurring_cooccurrence_link,
    rule_au_081_canonical_person_name_match,
    rule_au_082_api_key_dual_pathway,
    // AU-083: ≥2 emails independently match the same locale naming pattern.
    rule_au_083_locale_multi_email_corroboration,
    rule_au_046_cross_platform_identity_resolution,
    rule_au_068_anonymous_sim,
    rule_au_047_reused_secret_identity,
    rule_au_048_shared_public_key,
    rule_au_049_shared_address_association,
    rule_au_050_shared_phone_association,
    rule_au_051_shared_surname_kin,
    rule_au_052_geographic_area_of_operation,
    rule_au_053_out_of_area_location,
    rule_au_054_data_broker_exposure,
    rule_au_055_primary_source_accounts,
    rule_au_056_jurisdiction_cross_check,
    // AU-099: reverse-geocode a coordinate fix to its nearest AU population
    // centre (offline) — a human locality label for a bare GPS/EXIF lat-long.
    rule_au_099_coordinate_reverse_geocode,
    rule_au_057_synthesised_location_fix,
    rule_au_058_professional_profile_geo,
    rule_au_059_cross_seed_geo_synergy,
    rule_au_061_family_geo_corroboration,
    // AU-084: dual-source cell tower corroboration (live sensor × crowdsourced DB).
    rule_au_084_cell_tower_dual_source,
    // AU-085: AU fixed-line area code cross-checked against address/coordinate state.
    rule_au_085_phone_region_jurisdiction,
    // AU-086: a name-derived email guess independently confirmed in real data.
    rule_au_086_name_derived_email_confirmed,
    // AU-087: ≥2 identities share a specific (non-freemail) organisational email
    // domain — an employer / university / agency affiliation surface.
    rule_au_087_shared_org_email_domain,
    // AU-088: subject confirmed by N authoritative AU public registers (AHPRA,
    // ASIC, electoral, property, AustLII, ACNC, ABR) — government-grounded ID.
    rule_au_088_authoritative_register_confirmation,
    // AU-089: ≥2 distinct registered AU companies (checksum-valid ACN/company-
    // ABN) in the graph — an officeholder/controller corporate-network footprint.
    rule_au_089_corporate_network,
    // AU-094: a non-company ABN (sole trader / trust / partnership) — the people-
    // centric complement to AU-089, tying a natural person to an operating
    // business. The majority of AU ABN holders are non-company.
    rule_au_094_sole_trader_abn,
    // AU-100: the subject's employer/affiliation from their own AU organisational
    // email domain (.com.au/.gov.au/.edu.au/…), classified by registrant type.
    rule_au_100_au_employer_affiliation,
    // AU-101: identity-resolution breadth — how many distinct identity facet
    // classes (name, email, phone, username, address, business id, DOB, gov ID)
    // are pinned to the subject. The people-centric analogue of AU-098's
    // residency consensus, measuring breadth rather than single-value depth.
    rule_au_101_identity_resolution,
];

fn evaluate_rules(entities: &[Entity], scan_id: &str) -> Vec<Correlation> {
    let now = crate::core::entity::unix_now();
    // Quarantine: speculative `candidate` entities never enter correlation.
    // These are the non-target breach-dump rows (other people returned by a
    // broad name search), unconfirmed username permutations, and search-only
    // guesses — each tagged `candidate` by its module. Excluding them here is
    // what stops a single broad search from fusing hundreds of strangers into
    // a "critical identity cluster" (AU-002) or manufacturing AU-003/AU-018
    // corroboration out of noise. The entities remain in the store and the
    // candidates view; they simply don't get to assert relationships.
    let confirmed = confirmed_only(entities);
    // The live incremental pass is per-round and small — no budget, full
    // determinism (its streaming correlations must be reproducible).
    evaluate_rules_on(&confirmed, scan_id, now, None)
}

/// Wall-clock budget for the FINALISE correlator pass (entity rules + the
/// graph-aware relation rules share it). The rule set is near-instant on a
/// normal scan, but a very large recalled entity/relation graph — a deep
/// `--expand-all-identities` sweep that pulls a big prior graph in via recall —
/// can push the graph-traversal rules (transitive closure, clustering) into
/// MINUTES. Observed at 20+ on a ~500-entity recalled set, which left scans hung
/// at finalise and (before the recovery fix) lost everything. Cap it: run as
/// many rules as fit, then finalise with the correlations computed so far — the
/// full entity set and the partial correlations still persist and the scan
/// COMPLETES instead of hanging. Only the pathological large-graph case ever
/// reaches this deadline; a normal scan finishes in well under a second, so the
/// finalise stays deterministic in every realistic case. Generous so legitimate
/// scans keep every correlation.
const CORRELATOR_BUDGET: std::time::Duration = std::time::Duration::from_secs(120);

/// Run every entity-only rule over an already quarantine-filtered, confirmed
/// entity slice. Split out from [`evaluate_rules`] so a caller that runs both
/// the entity and the relation passes (`Correlator::run`) can filter once and
/// share the confirmed view instead of cloning it per pass. `deadline` (set only
/// on the finalise pass) caps total wall-time: once reached, no further rule is
/// started and the pass returns what it has — a complete scan with partial
/// correlations beats one hung forever.
fn evaluate_rules_on(
    confirmed: &[Entity],
    scan_id: &str,
    now: u64,
    deadline: Option<std::time::Instant>,
) -> Vec<Correlation> {
    let mut out = Vec::new();
    for (i, rule) in RULES.iter().enumerate() {
        if deadline.is_some_and(|dl| std::time::Instant::now() >= dl) {
            warn!(
                scan_id,
                ran = i,
                total = RULES.len(),
                "correlator entity-rule budget exceeded — finalising with partial correlations"
            );
            break;
        }
        out.extend(rule(confirmed, scan_id, now));
    }
    out
}

/// Entities minus the `candidate`-tagged quarantine set — the view every
/// correlation rule sees. Allocates a filtered copy because the rule fns take
/// `&[Entity]`; correlation runs are infrequent and entity counts bounded, so
/// the clone is negligible.
fn confirmed_only(entities: &[Entity]) -> Vec<Entity> {
    entities
        .iter()
        .filter(|e| !e.has_tag(crate::core::tags::CANDIDATE))
        .cloned()
        .collect()
}

/// Evaluate the entity-only rules against an in-memory entity slice.
///
/// This is the live-ingestion entry point: the engine calls it against the
/// working entity map after each dispatch round so correlations stream out
/// during the scan, with no store round-trip. The graph-aware relation rules
/// are intentionally excluded here — they need the persisted edge set, which
/// only exists once [`Correlator::run`] derives it at finalise.
pub(crate) fn correlate_entities(entities: &[Entity], scan_id: &str) -> Vec<Correlation> {
    evaluate_rules(entities, scan_id)
}

// ─── Graph-aware rules ───────────────────────────────────────────────────────
// Rules that consume the typed `Relation` edge set in addition to entities.
// Kept separate from `RULES` so the 30 entity-only rules need no signature
// change.

type RelationRuleFn = fn(&[Entity], &[Relation], &str, u64) -> Vec<Correlation>;

const RELATION_RULES: &[RelationRuleFn] = &[
    rule_au_031_malicious_adjacency,
    rule_au_032_colocation_cluster,
    rule_au_060_transitive_identity_closure,
    rule_au_062_multipath_corroboration,
    rule_au_063_corroboration_gap,
    rule_au_064_generalized_pathway_template,
    rule_au_067_resolved_identity_cluster,
    rule_au_069_high_integrity_connection,
    rule_au_070_connection_broker,
    rule_au_071_robust_identity_cluster,
    rule_au_076_shared_registrant,
    rule_au_077_shared_hosting_ip,
];

/// Run every relation-aware rule over an already quarantine-filtered, confirmed
/// entity slice (see [`evaluate_rules_on`]). Lets `Correlator::run` reuse the
/// single confirmed view it already built for the entity pass.
fn evaluate_relation_rules_on(
    confirmed: &[Entity],
    relations: &[Relation],
    scan_id: &str,
    now: u64,
    deadline: Option<std::time::Instant>,
) -> Vec<Correlation> {
    let mut out = Vec::new();
    for (i, rule) in RELATION_RULES.iter().enumerate() {
        // The graph-aware rules are the costly ones on a large recalled graph, so
        // the shared finalise deadline matters most here.
        if deadline.is_some_and(|dl| std::time::Instant::now() >= dl) {
            warn!(
                scan_id,
                ran = i,
                total = RELATION_RULES.len(),
                "correlator relation-rule budget exceeded — finalising with partial correlations"
            );
            break;
        }
        out.extend(rule(confirmed, relations, scan_id, now));
    }
    out
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod perf;
