//! Pure expansion/dedup bookkeeping helpers used by the round loop: stable
//! dedup keys for correlations and visited targets, the deterministic total
//! order over expansion candidates, and the per-candidate admission-and-scoring
//! policy. No engine state — split out so the loop reads as control flow while
//! the key/ordering/gating policy lives in one place.

use std::collections::HashSet;
use std::time::{Duration, Instant};

use crate::core::entity::{Entity, normalise};
use crate::core::scan::{ScanOptions, Target, TargetKind};

use super::StopReason;

/// Stable dedup key for a correlation: rule id + its entity uids (sorted), joined
/// with control characters that can't appear in either, so two correlations are
/// "the same finding" iff they share a rule and entity set regardless of order.
pub(super) fn correlation_key(c: &crate::core::correlator::Correlation) -> String {
    let mut uids = c.entity_uids.clone();
    uids.sort();
    format!("{}\u{1f}{}", c.rule_id, uids.join("\u{1e}"))
}

/// Visit-key for the expansion visited-set. Normalises the value the same
/// way `Entity::new` does, so the seed target matches entities that point
/// back at it.
pub(super) fn visit_key(target: &Target) -> (TargetKind, String) {
    let entity_kind = target.kind.to_entity_kind();
    let normalised = normalise(&entity_kind, &target.value);
    (target.kind, normalised)
}

/// Deterministic total order for expansion candidates `(Target, weight, parent)`:
/// highest weight first, ties broken by target kind then value. A NaN weight
/// sorts last (treated as the lowest) rather than silently comparing Equal. This
/// is what makes a budgeted scan reproducible — see the call site in the
/// expansion loop for why the HashMap-iteration input order must not leak through
/// a weight tie into which candidates a `truncate(keep)` keeps.
pub(super) fn cmp_expansion_candidates(
    a: &(Target, f64, String),
    b: &(Target, f64, String),
) -> std::cmp::Ordering {
    // Descending weight: `b` vs `a`. NaN is pushed to the bottom deterministically.
    let by_weight = match (a.1.is_nan(), b.1.is_nan()) {
        (false, false) => b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal),
        (true, false) => std::cmp::Ordering::Greater, // a is NaN → a after b
        (false, true) => std::cmp::Ordering::Less,
        (true, true) => std::cmp::Ordering::Equal,
    };
    by_weight
        .then_with(|| a.0.kind.canonical_str().cmp(b.0.kind.canonical_str()))
        .then_with(|| a.0.value.cmp(&b.0.value))
}

/// ROI top-K + knee cutoff over a weight-sorted candidate round, releasing the
/// visited keys of everything it cuts.
///
/// The release is the load-bearing half: `visited` means "dispatched (or still
/// queued)", but a candidate cut here is *neither* — it was queued, then
/// dropped before any dispatch. Leaving its key in `visited` excluded the same
/// lead as `already_dispatched_this_scan` in every later round, so a lead whose
/// weight rises as corroboration accrues could never compete again — silently
/// lost for the rest of the scan. Releasing the key lets it re-enter a later
/// round's ranking on its new weight. Halting is unaffected: rounds are capped
/// by `depth`, each round dispatches at most the cutoff, and a re-queued
/// candidate either dispatches (entering `visited` for good) or is cut again.
pub(super) fn apply_roi_cutoff(
    next: &mut Vec<(Target, f64, String)>,
    visited: &mut HashSet<(TargetKind, String)>,
    max_concurrent: usize,
) {
    let weights: Vec<f64> = next.iter().map(|(_, w, _)| *w).collect();
    let keep = crate::core::roi::effective_cutoff(&weights, max_concurrent);
    if next.len() > keep {
        for (t, _, _) in &next[keep..] {
            visited.remove(&visit_key(t));
        }
        next.truncate(keep);
    }
}

/// Stop the expansion when an entity- or wall-time budget is hit. Pure over
/// `ScanOptions` + the round's start instant and current entity count.
pub(super) fn budget_check(
    opts: &ScanOptions,
    started: Instant,
    current_count: usize,
) -> Option<StopReason> {
    if let Some(max) = opts.max_entities
        && current_count >= max
    {
        return Some(StopReason::MaxEntities(max));
    }
    if let Some(max_secs) = opts.max_wall_time_secs
        && started.elapsed() >= Duration::from_secs(max_secs)
    {
        return Some(StopReason::MaxWallTime(max_secs));
    }
    None
}

/// Normalise a candidate value for the seed-identity comparison `is_incidental_infra`
/// needs: trims whitespace, drops a leading `www.`, lowercases. Shared by the
/// caller (which computes it once for the seed) and [`gate_and_score_candidate`]
/// (which computes it per candidate) so the two sides of the comparison can never
/// drift on what "the same value" means.
pub(super) fn strip_www(s: &str) -> String {
    s.trim().trim_start_matches("www.").to_ascii_lowercase()
}

/// Per-round context invariant across every candidate entity considered this
/// round — bundled so [`gate_and_score_candidate`] takes one borrow instead of
/// five always-together arguments, mirroring `dispatch::DispatchCx`.
pub(super) struct CandidateRoundCx<'a> {
    pub opts: &'a ScanOptions,
    pub seed: &'a Target,
    /// [`strip_www`] applied to `seed.value`, computed once per round (not
    /// once per candidate) by the caller.
    pub seed_stripped: &'a str,
    /// The seed value plus every `Username`/`Person`/`Email` entity confirmed
    /// at `Classification::VERIFIED_MIN` or above, as of this round's start —
    /// the wrong-identity gate's comparison set. Empty under
    /// `--expand-all-identities` (the gate is bypassed entirely in that case).
    pub subject_identities: &'a [String],
    pub has_paid: bool,
}

/// Gate-and-score a single expansion candidate entity: the pure admission
/// policy plus the dispatch-priority weight, unified because both read the
/// same `c_effective()`/`source_count()`/`TargetKind` derivation and the
/// original inline loop computed them together. Mirrors `dispatch::
/// admission_rejection`'s shape — `Err(reason)` is the exact string the caller
/// already passed to `emit_excluded`, in the exact prior gate order; `Ok`
/// carries the `(Target, weight, parent_uid)` triple the caller pushes onto
/// this round's candidate list.
///
/// `visited` IS mutated here (the "already queued/dispatched this scan" check
/// is itself a gate, and was always evaluated in this position in the
/// original chain) — every other parameter is a read-only view over round- or
/// scan-level state. `richness_for` is a closure rather than `&ModuleGraph`
/// so this module stays decoupled from `core::dependency`'s concrete type.
pub(super) fn gate_and_score_candidate(
    entity: &Entity,
    cx: &CandidateRoundCx<'_>,
    visited: &mut HashSet<(TargetKind, String)>,
    richness_for: impl Fn(TargetKind) -> f64,
) -> Result<(Target, f64, String), &'static str> {
    let c_eff = entity.c_effective();
    if c_eff < cx.opts.effective_min_expand_confidence() {
        return Err("below_min_expand_confidence");
    }
    let source_count = entity.source_count();
    // Search-snippet recycling is the lowest-reliability discovery path: a
    // value scraped from the *text* of whatever page a search engine returned
    // for a recycled query. At the relaxed deep/`--full` expansion floor these
    // clear `min_expand_confidence` on a single source, so without this gate
    // the recursion budget gets burned pivoting on strangers. Record the
    // lead, but don't pivot until a second, independent source corroborates
    // it — corroboration lifts `source_count` past 1 and the entity expands
    // normally on a later round.
    if entity.is_uncorroborated_recycled() {
        return Err("uncorroborated_recycled");
    }
    // ROI bundle: convergence-pruning. Once an entity has 2+ corroborating
    // sources at high confidence, further dispatch only re-confirms what we
    // already know. Skip it.
    if cx.opts.max_roi && crate::core::roi::is_saturated(entity) {
        return Err("roi_saturated");
    }
    // A kind with no external search target (Credential, Password, DeviceId,
    // TrackingId, Other) cannot be pivoted on.
    let Some(tk) = TargetKind::from_entity_kind(&entity.kind) else {
        return Err("non_pivotable_kind");
    };
    // Speculative name-permutation gate — OPT-IN (`--gate-speculative`), OFF
    // by default. name_intel's `firstname.lastname@provider` / handle guesses
    // are frequently the subject's REAL identifiers, so by default the scan
    // EXPANDS and validates them; only when the operator opts in does an
    // uncorroborated permutation stay a recorded-but-not-pivoted candidate
    // until a reliable source confirms it.
    if cx.opts.gate_speculative
        && !cx.opts.expand_all_identities
        && entity.is_uncorroborated_name_permutation()
    {
        return Err("uncorroborated_speculative");
    }
    // Wrong-identity gate: an uncorroborated, non-verified Username/Person
    // whose handle shares no overlap with the subject's confirmed identity is
    // a different person. Verified or multi-source identities, and anything
    // overlapping the subject, still expand.
    if !cx.opts.expand_all_identities
        && crate::core::scan::is_wrong_identity_pivot(
            &entity.kind,
            c_eff,
            source_count,
            &entity.value,
            cx.subject_identities,
        )
    {
        return Err("identity_mismatch");
    }
    // Never pivot on a non-routable / reserved / documentation IP. No
    // external OSINT source can resolve these, so expanding them only burns
    // whole rounds on guaranteed-empty lookups and pollutes the graph.
    if tk == TargetKind::IpAddress && crate::core::validation::is_non_routable_ip(&entity.value) {
        return Err("non_routable_ip");
    }
    // Don't deep-expand *incidentally-discovered* haystack infrastructure —
    // it maps a platform/CDN/provider's own estate, not the subject. Still
    // expand when the candidate IS the seed (investigating that property
    // itself).
    let candidate_is_seed = cx.seed.kind == tk && cx.seed_stripped == strip_www(&entity.value);
    let is_incidental_infra = match tk {
        TargetKind::Domain => crate::core::scan::is_noncentral_domain(&entity.value),
        TargetKind::IpAddress => crate::core::validation::is_cdn_edge_ip(&entity.value),
        _ => false,
    };
    if is_incidental_infra && !candidate_is_seed {
        return Err("incidental_infra");
    }
    let new_target = Target::new(tk, entity.value.clone());
    let key = visit_key(&new_target);
    if !visited.insert(key) {
        // This exact target was already dispatched (or queued) this scan.
        // Skipping it prevents an infinite pivot cycle.
        return Err("already_dispatched_this_scan");
    }

    let richness = richness_for(tk);
    // Strategy weight × a non-saturating corroboration prior. `c_effective()`
    // clamps at 1.0, erasing the cross-correlation signal for confident
    // pivots; re-apply it on the ranking so a lead confirmed by N independent
    // sources is dispatched ahead of an equally-confident single-source lead.
    let mut weight = crate::core::scan::expansion_weight_for_strategy(
        cx.opts.expansion_strategy,
        tk,
        c_eff,
        &entity.value,
        cx.has_paid,
        richness,
    ) * crate::core::scan::corroboration_prior(source_count);
    // Convex (optionality / barbell) budget allocation, opt-in: multiply by a
    // convexity premium for heavy-tailed upside over per-kind dispatch cost.
    if cx.opts.convex_budget {
        weight *= crate::core::convex::optionality_multiplier(tk, source_count, c_eff, richness);
    }
    // Geo-corroboration bonus: entities confirmed by anchoring geo sources
    // rank slightly ahead of equal-weight entities with no person-anchored
    // geo signal. +2% per anchoring source, capped at +10%.
    let anchoring_geo_count = entity
        .corroborating_sources()
        .into_iter()
        .filter(|s| crate::core::correlator::is_anchoring_geo_source(s))
        .count();
    if anchoring_geo_count > 0 {
        weight *= 1.0 + (anchoring_geo_count as f64 * 0.02).min(0.10);
    }
    // Social-profile URL priority boost: a confirmed social-profile URL crawl
    // can complete the tracking-ID co-ownership pivot. +15%.
    if tk == TargetKind::Url && entity.has_tag("social-profile") {
        weight *= 1.15;
    }
    Ok((new_target, weight, entity.uid.clone()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::correlator::{Correlation, Severity};

    fn corr(rule: &str, uids: &[&str]) -> Correlation {
        Correlation::new(
            rule,
            "title",
            Severity::Medium,
            "desc".to_string(),
            uids.iter().map(|s| (*s).to_string()).collect(),
            "scan",
            0,
        )
    }

    #[test]
    fn correlation_key_is_order_independent_over_uids() {
        // Same rule + same uid SET in different orders → identical key.
        let a = correlation_key(&corr("AU-001", &["u3", "u1", "u2"]));
        let b = correlation_key(&corr("AU-001", &["u1", "u2", "u3"]));
        assert_eq!(a, b);
    }

    #[test]
    fn correlation_key_differs_on_rule_or_uid_set() {
        let base = correlation_key(&corr("AU-001", &["u1", "u2"]));
        // Different rule id → different finding.
        assert_ne!(base, correlation_key(&corr("AU-002", &["u1", "u2"])));
        // Different uid set → different finding.
        assert_ne!(base, correlation_key(&corr("AU-001", &["u1", "u3"])));
    }

    // ── gate_and_score_candidate ────────────────────────────────────────────
    //
    // Direct coverage of the expansion round's per-candidate admission-and-
    // scoring policy, extracted from `ScanEngine::run_expansion` into this pure
    // function so it is testable in isolation (previously every gate was
    // exercised only end-to-end). One case per gate proves the reason string
    // and the load-bearing order, mirroring `dispatch::
    // admission_rejection_covers_every_drop_filter_and_order`.
    mod gate_and_score_candidate_tests {
        use super::*;
        use crate::core::entity::{Entity, EntityKind, Evidence};
        use crate::core::scan::ExpansionStrategy;

        fn ent(kind: EntityKind, value: &str, confidence: f64) -> Entity {
            Entity::new(kind, value, confidence, "gate-test")
        }

        fn seed_target() -> Target {
            Target::new(TargetKind::FullName, "Jordan Avery")
        }

        fn base_cx<'a>(
            opts: &'a ScanOptions,
            seed: &'a Target,
            seed_stripped: &'a str,
        ) -> CandidateRoundCx<'a> {
            CandidateRoundCx {
                opts,
                seed,
                seed_stripped,
                subject_identities: &[],
                has_paid: false,
            }
        }

        /// A neutral, always-1.0 richness closure — the round-loop wiring
        /// (`self.graph.richness_for`) is exercised by the engine's own
        /// end-to-end tests, not re-verified here.
        fn flat_richness(_: TargetKind) -> f64 {
            1.0
        }

        #[test]
        fn admits_a_clean_confident_candidate_and_scores_it() {
            let opts = ScanOptions::default();
            let seed = seed_target();
            let seed_stripped = strip_www(&seed.value);
            let cx = base_cx(&opts, &seed, &seed_stripped);
            let mut visited = HashSet::new();
            let entity = ent(EntityKind::Email, "jordan@example.org", 0.9);

            let result = gate_and_score_candidate(&entity, &cx, &mut visited, flat_richness);

            let (target, weight, parent_uid) = result.expect("a clean candidate must be admitted");
            assert_eq!(target.kind, TargetKind::Email);
            assert_eq!(target.value, "jordan@example.org");
            assert_eq!(parent_uid, entity.uid);
            assert!(
                weight > 0.0,
                "an admitted candidate must carry a positive weight"
            );
            assert!(
                visited.contains(&visit_key(&target)),
                "admission must mark the target visited"
            );
        }

        #[test]
        fn rejects_below_the_expansion_confidence_floor() {
            let opts = ScanOptions {
                min_expand_confidence: 0.8,
                ..ScanOptions::default()
            };
            let seed = seed_target();
            let seed_stripped = strip_www(&seed.value);
            let cx = base_cx(&opts, &seed, &seed_stripped);
            let mut visited = HashSet::new();
            let entity = ent(EntityKind::Email, "low@example.org", 0.2);

            assert!(matches!(
                gate_and_score_candidate(&entity, &cx, &mut visited, flat_richness),
                Err("below_min_expand_confidence")
            ));
            assert!(
                visited.is_empty(),
                "a rejected candidate must not be marked visited"
            );
        }

        #[test]
        fn rejects_an_uncorroborated_recycled_snippet() {
            let opts = ScanOptions::default();
            let seed = seed_target();
            let seed_stripped = strip_www(&seed.value);
            let cx = base_cx(&opts, &seed, &seed_stripped);
            let mut visited = HashSet::new();
            let mut entity = ent(EntityKind::Address, "Austin, Texas", 0.9);
            entity.tag("recycled");

            assert!(matches!(
                gate_and_score_candidate(&entity, &cx, &mut visited, flat_richness),
                Err("uncorroborated_recycled")
            ));
        }

        #[test]
        fn rejects_a_roi_saturated_candidate_under_max_roi() {
            let opts = ScanOptions {
                max_roi: true,
                ..ScanOptions::default()
            };
            let seed = seed_target();
            let seed_stripped = strip_www(&seed.value);
            let cx = base_cx(&opts, &seed, &seed_stripped);
            let mut visited = HashSet::new();
            // >= SATURATION_CORROBORATION (2) DISTINCT sources, >=
            // SATURATION_CONFIDENCE (0.85) confidence. `Entity::new` starts with
            // zero evidence (`source_count()` then falls back to the default
            // `corroboration = 1`), so two independent sources must be added
            // explicitly to reach source_count() == 2.
            let mut entity = ent(EntityKind::Domain, "corroborated.example", 0.95);
            entity.add_evidence(Evidence::new("shodan", "first independent source"));
            entity.add_evidence(Evidence::new("censys", "second independent source"));

            assert!(matches!(
                gate_and_score_candidate(&entity, &cx, &mut visited, flat_richness),
                Err("roi_saturated")
            ));
        }

        #[test]
        fn rejects_a_non_pivotable_kind() {
            let opts = ScanOptions::default();
            let seed = seed_target();
            let seed_stripped = strip_www(&seed.value);
            let cx = base_cx(&opts, &seed, &seed_stripped);
            let mut visited = HashSet::new();
            // `Credential` has no TargetKind mapping — can never be a scan target.
            let entity = ent(EntityKind::Credential, "s3cr3t", 0.9);

            assert!(matches!(
                gate_and_score_candidate(&entity, &cx, &mut visited, flat_richness),
                Err("non_pivotable_kind")
            ));
        }

        #[test]
        fn rejects_an_uncorroborated_speculative_permutation_when_gated() {
            let opts = ScanOptions {
                gate_speculative: true,
                ..ScanOptions::default()
            };
            let seed = seed_target();
            let seed_stripped = strip_www(&seed.value);
            let cx = base_cx(&opts, &seed, &seed_stripped);
            let mut visited = HashSet::new();
            let mut entity = ent(EntityKind::Email, "jordan.avery@guessmail.example", 0.6);
            entity.tag("name-derived");

            assert!(matches!(
                gate_and_score_candidate(&entity, &cx, &mut visited, flat_richness),
                Err("uncorroborated_speculative")
            ));

            // The identical candidate is NOT gated when --gate-speculative is off
            // (the product default): it must be admitted.
            let default_opts = ScanOptions::default();
            let cx2 = base_cx(&default_opts, &seed, &seed_stripped);
            let mut visited2 = HashSet::new();
            assert!(
                gate_and_score_candidate(&entity, &cx2, &mut visited2, flat_richness).is_ok(),
                "gate_speculative is opt-in — off by default, the permutation must expand"
            );
        }

        #[test]
        fn rejects_an_unverified_identity_with_no_subject_overlap() {
            let opts = ScanOptions::default();
            let seed = seed_target();
            let seed_stripped = strip_www(&seed.value);
            let cx = CandidateRoundCx {
                opts: &opts,
                seed: &seed,
                seed_stripped: &seed_stripped,
                // No overlap with "strangerhandle" below.
                subject_identities: &["jordanavery".to_string()],
                has_paid: false,
            };
            let mut visited = HashSet::new();
            // Single-source, below VERIFIED_MIN, Username kind.
            let entity = ent(EntityKind::Username, "strangerhandle", 0.5);

            assert!(matches!(
                gate_and_score_candidate(&entity, &cx, &mut visited, flat_richness),
                Err("identity_mismatch")
            ));
        }

        #[test]
        fn rejects_a_non_routable_ip() {
            let opts = ScanOptions::default();
            let seed = seed_target();
            let seed_stripped = strip_www(&seed.value);
            let cx = base_cx(&opts, &seed, &seed_stripped);
            let mut visited = HashSet::new();
            // TEST-NET-1 documentation range — never externally resolvable.
            let entity = ent(EntityKind::IpAddress, "192.0.2.1", 0.9);

            assert!(matches!(
                gate_and_score_candidate(&entity, &cx, &mut visited, flat_richness),
                Err("non_routable_ip")
            ));
        }

        #[test]
        fn rejects_incidental_infrastructure_unless_it_is_the_seed() {
            let opts = ScanOptions::default();
            let seed = seed_target();
            let seed_stripped = strip_www(&seed.value);
            let cx = base_cx(&opts, &seed, &seed_stripped);
            let mut visited = HashSet::new();
            // A managed-DNS provider domain — shared infrastructure, never the
            // subject's own estate.
            let entity = ent(EntityKind::Domain, "dnsmadeeasy.com", 0.9);

            assert!(matches!(
                gate_and_score_candidate(&entity, &cx, &mut visited, flat_richness),
                Err("incidental_infra")
            ));

            // The exemption: when the candidate IS the (domain) seed, it still
            // expands even though it independently matches the infra list.
            let infra_seed = Target::new(TargetKind::Domain, "dnsmadeeasy.com");
            let infra_seed_stripped = strip_www(&infra_seed.value);
            let cx2 = base_cx(&opts, &infra_seed, &infra_seed_stripped);
            let mut visited2 = HashSet::new();
            assert!(
                gate_and_score_candidate(&entity, &cx2, &mut visited2, flat_richness).is_ok(),
                "investigating the infra domain itself must not be excluded as incidental"
            );
        }

        #[test]
        fn rejects_a_target_already_visited_this_scan() {
            let opts = ScanOptions::default();
            let seed = seed_target();
            let seed_stripped = strip_www(&seed.value);
            let cx = base_cx(&opts, &seed, &seed_stripped);
            let entity = ent(EntityKind::Email, "jordan@example.org", 0.9);
            let mut visited = HashSet::new();
            visited.insert(visit_key(&Target::new(
                TargetKind::Email,
                "jordan@example.org",
            )));

            assert!(matches!(
                gate_and_score_candidate(&entity, &cx, &mut visited, flat_richness),
                Err("already_dispatched_this_scan")
            ));
        }

        #[test]
        fn gate_order_is_load_bearing_earliest_gate_wins() {
            // An entity that trips MULTIPLE gates (below the confidence floor
            // AND a non-routable IP) must report the FIRST — below_min_expand_
            // confidence, not non_routable_ip — exactly mirroring
            // `admission_rejection`'s documented ordering contract.
            let opts = ScanOptions {
                min_expand_confidence: 0.8,
                ..ScanOptions::default()
            };
            let seed = seed_target();
            let seed_stripped = strip_www(&seed.value);
            let cx = base_cx(&opts, &seed, &seed_stripped);
            let mut visited = HashSet::new();
            let entity = ent(EntityKind::IpAddress, "192.0.2.1", 0.1);

            assert!(
                matches!(
                    gate_and_score_candidate(&entity, &cx, &mut visited, flat_richness),
                    Err("below_min_expand_confidence")
                ),
                "the earliest gate in the chain wins"
            );
        }

        #[test]
        fn social_profile_url_scores_higher_than_an_otherwise_identical_url() {
            let opts = ScanOptions {
                expansion_strategy: ExpansionStrategy::BreadthFirst,
                ..ScanOptions::default()
            };
            let seed = seed_target();
            let seed_stripped = strip_www(&seed.value);
            let cx = base_cx(&opts, &seed, &seed_stripped);

            let plain = ent(EntityKind::Url, "https://example.org/a", 0.9);
            let mut visited_plain = HashSet::new();
            let (_, plain_weight, _) =
                gate_and_score_candidate(&plain, &cx, &mut visited_plain, flat_richness).unwrap();

            let mut social = ent(EntityKind::Url, "https://example.org/b", 0.9);
            social.tag("social-profile");
            let mut visited_social = HashSet::new();
            let (_, social_weight, _) =
                gate_and_score_candidate(&social, &cx, &mut visited_social, flat_richness).unwrap();

            assert!(
                social_weight > plain_weight,
                "a social-profile URL must rank above an equal-confidence plain URL: \
                 social={social_weight} plain={plain_weight}"
            );
        }
    }
}
