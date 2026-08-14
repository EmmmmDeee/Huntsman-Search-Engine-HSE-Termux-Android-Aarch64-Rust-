//! Unit tests for the entity model.
//!
//! Split out of the module file (mechanical, behaviour-preserving) so the
//! source reads as implementation; tests reach private items via `use super::*`.

use super::*;

// helpers
fn email(v: &str) -> Entity {
    Entity::new(EntityKind::Email, v, 0.6, "scan-test")
}

// ── UID determinism ──────────────────────────────────────────────────────

#[test]
fn uid_is_deterministic() {
    let a = email("Matt@Example.com");
    let b = email("matt@example.com"); // normalised → same
    assert_eq!(a.uid, b.uid);
}

#[test]
fn uid_differs_across_kinds() {
    let e = Entity::new(EntityKind::Email, "x@y.com", 0.5, "s");
    let d = Entity::new(EntityKind::Domain, "x@y.com", 0.5, "s");
    assert_ne!(e.uid, d.uid);
}

#[test]
fn demote_to_candidate_caps_confidence_tags_and_is_idempotent() {
    let mut e = Entity::new(EntityKind::Email, "stranger@example.com", 0.70, "s");
    e.demote_to_candidate();
    assert!((e.confidence - CANDIDATE_CONF).abs() < f64::EPSILON);
    assert!(e.has_tag(crate::core::tags::CANDIDATE));
    // Lands in the Candidate tier (the demotion's whole purpose).
    assert_eq!(e.classify(), Classification::Candidate);
    // Idempotent: a second call neither lowers confidence further nor
    // duplicates the tag (min + de-duped tag).
    e.demote_to_candidate();
    assert!((e.confidence - CANDIDATE_CONF).abs() < f64::EPSILON);
    assert_eq!(
        e.tags
            .iter()
            .filter(|t| *t == crate::core::tags::CANDIDATE)
            .count(),
        1
    );
    // Never RAISES an already-lower confidence.
    let mut low = Entity::new(EntityKind::Email, "x@y.com", 0.10, "s");
    low.demote_to_candidate();
    assert!((low.confidence - 0.10).abs() < f64::EPSILON);
}

// ── C_eff formula ────────────────────────────────────────────────────────

#[test]
fn c_eff_single_source() {
    // corroboration=1 → ln(1)=0 → c_eff == confidence
    let e = email("a@b.com");
    assert!((e.c_effective() - 0.6).abs() < 1e-9);
}

#[test]
fn c_eff_boost_with_corroboration() {
    let mut e = email("a@b.com");
    e.corroboration = 4;
    // No evidence attached → source_count() falls back to the field (4).
    // C_eff = max(multiplicative, independent-agreement). At n=4 the
    // agreement term dominates: 1 - 0.4·γ^3 ≈ 0.890 > 0.726 multiplicative.
    let mult = 0.6 * 0.15f64.mul_add(4f64.ln(), 1.0);
    let agreement = 1.0 - 0.4 * CORROBORATION_DOUBT_DECAY.powf(3.0);
    let expected = mult.max(agreement);
    assert!((e.c_effective() - expected).abs() < 1e-9);
    assert!(
        e.c_effective() > 0.85,
        "4 independent sources → near-Verified"
    );
}

#[test]
fn c_eff_boosts_on_distinct_sources_not_summed_corroboration() {
    // THE FIX: an entity backed by 2 DISTINCT sources but with a summed
    // corroboration of 8 (the merge() over-count bug) must boost on 2, not 8.
    let mut e = email("a@b.com");
    e.corroboration = 8; // as if hibp(5) merged with search_engines(3)
    e.add_evidence(Evidence::new("hibp", "found in 5 breaches"));
    e.add_evidence(Evidence::new("search_engines", "5 engines agree"));
    assert_eq!(e.source_count(), 2, "distinct sources, not the summed 8");
    // Boost is driven by the 2 DISTINCT sources, not the inflated count of 8.
    let mult = 0.6 * 0.15f64.mul_add(2f64.ln(), 1.0);
    let agreement = 1.0 - 0.4 * CORROBORATION_DOUBT_DECAY; // n=2 → γ^1
    let expected = mult.max(agreement);
    assert!(
        (e.c_effective() - expected).abs() < 1e-9,
        "C_eff must boost on 2 distinct sources, not the inflated corroboration=8"
    );
    // A summed-corroboration of 8 would (wrongly) push c_eff much higher.
    let if_summed = 1.0 - 0.4 * CORROBORATION_DOUBT_DECAY.powf(7.0);
    assert!(
        e.c_effective() < if_summed,
        "must not credit the inflated 8"
    );
}

#[test]
fn geo_normalize_does_not_count_as_corroboration() {
    // A coarse geo guess (one real module) that the engine's geospatial
    // enrichment pass also touched must NOT be credited as two-source
    // agreement: `geo_normalize` is deterministic self-enrichment, not an
    // independent observation. Otherwise a 0.30 candidate suburb would be
    // lifted into the Probable tier and fire the corroboration rules.
    let mut suburb = Entity::new(
        EntityKind::Address,
        "Maleny, QLD 4552, Australia",
        0.30,
        "s",
    );
    suburb.add_evidence(Evidence::new("qld_unclaimed", "locality within postcode"));
    suburb.add_evidence(Evidence::new(
        "geo_normalize",
        "Address parse + normalization",
    ));
    // Display still surfaces both sources…
    assert_eq!(suburb.evidence_sources().len(), 2);
    // …but corroboration sees only the one real intelligence source.
    assert_eq!(suburb.corroborating_sources().len(), 1);
    assert_eq!(suburb.source_count(), 1);
    // So c_eff stays at the base confidence → Candidate, not lifted to
    // Probable by a phantom second source.
    assert!((suburb.c_effective() - 0.30).abs() < 1e-9);
    assert_eq!(suburb.classify(), Classification::Candidate);

    // A second *real* source still corroborates as before.
    suburb.add_evidence(Evidence::new("geocode", "address confirmed"));
    assert_eq!(suburb.source_count(), 2);
    assert!(
        suburb.c_effective() > 0.30,
        "real second source still boosts"
    );
}

#[test]
fn name_intel_permutation_does_not_count_as_corroboration() {
    // The H3 flaw: `name_intel` permutes the seed name into speculative
    // `name × freemail` email guesses. Such a guess is a derivation of the
    // input, not an independent sighting, so it must NOT self-corroborate into
    // the cross-source rules (AU-003 fires at 2 sources). A pure permutation
    // therefore has zero corroborating sources.
    let mut email = Entity::new(EntityKind::Email, "cindy.haynes@gmail.com", 0.30, "s");
    email.add_evidence(Evidence::new(
        "name_intel",
        "Speculative email permuted from name",
    ));
    // Display surfaces the derived lead…
    assert_eq!(email.evidence_sources().len(), 1);
    // …but corroboration credits no source, so AU-003/AU-034 cannot fire on it.
    assert_eq!(email.corroborating_sources().len(), 0);

    // One genuine observation = one source (still below the 2-source bar): the
    // permutation does not contribute a phantom second source.
    email.add_evidence(Evidence::new("search_engines", "found on a public page"));
    assert_eq!(email.source_count(), 1, "only the real source counts");

    // Two genuine sources DO corroborate — the speculation never blocked that.
    email.add_evidence(Evidence::new("hibp", "appears in a breach"));
    assert_eq!(email.source_count(), 2);
}

#[test]
fn recall_does_not_count_as_corroboration() {
    // The exact fresh-vs-recalled regression: a single-source finding (here a
    // breach co-occurrence row) replayed from the local DB by the recall pass
    // must NOT gain a phantom second source and be promoted CANDIDATE → PROBABLE.
    // Recall is a second look at the SAME prior observation, not a new one.
    let mut e = Entity::new(EntityKind::Person, "Андрей Кулябин Алексеевич", 0.25, "s");
    e.add_evidence(Evidence::new("oathnet_pro", "Breach on fincup.ru"));
    e.add_evidence(Evidence::new(
        "recall",
        "Recalled from the local intelligence database",
    ));
    // Provenance keeps both, but corroboration sees only the one real source.
    assert_eq!(e.evidence_sources().len(), 2);
    assert_eq!(e.source_count(), 1, "recall is not an independent source");
    assert!(
        (e.c_effective() - 0.25).abs() < 1e-9,
        "a recalled-only entity keeps its true confidence (was inflated to 0.51)"
    );
    assert_eq!(
        e.classify(),
        Classification::Candidate,
        "stays CANDIDATE on re-scan, not falsely promoted to PROBABLE"
    );

    // A genuinely independent live module discovered alongside recall DOES boost.
    e.add_evidence(Evidence::new("hibp", "verified breach"));
    assert_eq!(
        e.source_count(),
        2,
        "a real second module still corroborates"
    );
    assert!(e.c_effective() > 0.25);
}

#[test]
fn uncorroborated_recycled_is_gated_until_a_second_source_confirms() {
    // Regression: a value scraped only from a recycled search snippet (the
    // lowest-reliability discovery path) must NOT be promoted to an expansion
    // seed on its own — otherwise the recursion budget gets spent pivoting on
    // strangers (a Subway-directory "Austin, Texas", an unrelated contact
    // email). This mirrors the real dossier entity: `search_engines` recycling
    // plus the deterministic `geo_normalize` self-enrichment, which does NOT
    // count as corroboration.
    let mut addr = Entity::new(EntityKind::Address, "Austin, Texas", 0.45, "s");
    addr.tag(crate::core::tags::SEARCH_DISCOVERED);
    addr.tag("recycled");
    addr.add_evidence(Evidence::new("search_engines", "from recycled search"));
    addr.add_evidence(Evidence::new(
        "geo_normalize",
        "Address parse + normalization",
    ));
    assert_eq!(
        addr.source_count(),
        1,
        "geo_normalize is self-enrichment, not an independent source"
    );
    assert!(
        addr.is_uncorroborated_recycled(),
        "single-source recycled extraction must be gated from expansion"
    );

    // One independent, real corroborating source lifts it past the gate, so a
    // genuine lead is never permanently lost — it expands on a later round.
    addr.add_evidence(Evidence::new("whitepages", "address confirmed"));
    assert_eq!(addr.source_count(), 2);
    assert!(
        !addr.is_uncorroborated_recycled(),
        "a corroborated recycled value expands normally"
    );

    // The gate is specific to the `recycled` tag: a normally-discovered
    // single-source entity (e.g. a breach hit) is never suppressed by it.
    let mut breach_email = email("a@b.com");
    breach_email.add_evidence(Evidence::new("hibp", "breached"));
    assert!(!breach_email.is_uncorroborated_recycled());
}

#[test]
fn uncorroborated_name_permutation_is_gated_until_a_second_source_confirms() {
    // A `firstname.lastname@provider` email guessed by name_intel from the seed
    // name (tagged `name-derived`) is a candidate, not a finding: recording it is
    // fine, but auto-pivoting on the dozens one name generates fans the scan out
    // across strangers and never converges. So a single-source permutation must
    // be gated from expansion.
    let mut guess = Entity::new(EntityKind::Email, "moale.mcknight@gmail.com", 0.30, "s");
    guess.tag("derived");
    guess.tag("name-derived");
    guess.tag("permuted");
    // name_intel is the derivation pass (non-corroborating), so the guess has
    // zero independent sources — gated.
    guess.add_evidence(Evidence::new(
        "name_intel",
        "Speculative email permuted from name",
    ));
    assert!(
        guess.is_uncorroborated_name_permutation(),
        "a name-permutation with no independent source must be gated from expansion"
    );

    // A bare search_engines snippet hit must NOT lift the gate: search is asked
    // to look up the permutation it then "confirms" (circular), and the string
    // is as likely a namesake/aggregator as the subject.
    guess.add_evidence(Evidence::new("search_engines", "appears in 1 result"));
    assert!(
        guess.is_uncorroborated_name_permutation(),
        "a search-only snippet must not lift the name-permutation gate"
    );

    // A reliable independent source (a breach hit) confirms the guess, so a
    // permutation that turns out real expands.
    guess.add_evidence(Evidence::new("hibp", "found in a breach"));
    assert!(
        !guess.is_uncorroborated_name_permutation(),
        "a permutation confirmed by a reliable source expands normally"
    );

    // The gate is specific to the `name-derived` tag: a normally-discovered
    // single-source email is never suppressed by it.
    let mut found = email("real@corp.com");
    found.add_evidence(Evidence::new("comb_search", "breach record"));
    assert!(!found.is_uncorroborated_name_permutation());
}

#[test]
fn c_eff_independent_agreement_lifts_moderate_findings() {
    // The grunt: independent corroboration of a MODERATE finding drives
    // confidence toward certainty, where the multiplicative model alone
    // would leave it merely "Probable". Monotonic non-decreasing in n.
    let mut e = email("a@b.com");
    e.confidence = 0.60;
    let mut last = e.c_effective(); // n=1 → 0.60
    assert!((last - 0.60).abs() < 1e-9, "single source unchanged");
    for n in 2..=5u32 {
        e.corroboration = n;
        let c = e.c_effective();
        assert!(
            c >= last,
            "c_eff must be monotonic non-decreasing in sources"
        );
        assert!(c <= 1.0);
        last = c;
    }
    // 3 independent sources earn Verified (≥ 0.75); 5 are near-certain.
    e.corroboration = 3;
    assert!(
        e.c_effective() >= 0.75,
        "3 independent sources → Verified tier"
    );
    e.corroboration = 5;
    assert!(
        e.c_effective() >= 0.90,
        "5 independent sources → near-certain"
    );
}

#[test]
fn source_count_collapses_same_module_duplicate_evidence() {
    // Multiple evidence rows from ONE module (e.g. oathnet_pro returning
    // many breach rows) are a single independent source.
    let mut e = email("a@b.com");
    e.corroboration = 172; // oathnet within-module row count
    for i in 0..5 {
        e.add_evidence(Evidence::new("oathnet_pro", format!("breach row {i}")));
    }
    assert_eq!(
        e.source_count(),
        1,
        "one module = one source regardless of rows"
    );
    // ln(1)=0 → no boost; a single source must not be inflated.
    assert!((e.c_effective() - 0.6).abs() < 1e-9);
}

#[test]
fn source_count_no_evidence_uses_field() {
    // Synthetic entity with no evidence honours the explicit field.
    let mut e = email("a@b.com");
    e.corroboration = 3;
    assert_eq!(e.source_count(), 3);
}

#[test]
fn source_count_ignores_stored_field_when_all_evidence_is_noncorroborating() {
    // Regression (live "Cindy Haynes" scan): a speculative name-permuted email
    // whose ONLY evidence is the non-corroborating `name_intel` permutation plus
    // a `recall` replay was lifted to VERIFIED — `source_count` fell back to the
    // stored `corroboration` field, which recall ratchets up by one on every
    // re-scan (the bundle showed C_eff 0.81 at corroboration=4). With evidence
    // present but ALL non-corroborating, the count must be 1 (the stored
    // magnitude is ignored), so the guess stays at its base confidence and the
    // fallback is reserved for genuinely evidence-less synthetic entities.
    let mut e = Entity::new(EntityKind::Email, "cindy.haynes@gmail.com", 0.30, "s");
    e.corroboration = 4; // ratcheted up across recall cycles
    e.add_evidence(Evidence::new(
        "name_intel",
        "Speculative email permuted from name",
    ));
    e.add_evidence(Evidence::new(
        "recall",
        "Recalled from the local intelligence database",
    ));
    assert_eq!(e.evidence_sources().len(), 2, "provenance keeps both");
    assert_eq!(
        e.source_count(),
        1,
        "all-non-corroborating evidence is one source; stored field ignored"
    );
    assert!(
        (e.c_effective() - 0.30).abs() < 1e-9,
        "stays at base confidence, not resurrected to VERIFIED"
    );
    assert_eq!(e.classify(), Classification::Candidate);
}

#[test]
fn promotion_source_alone_does_not_ground_entity() {
    // A multipath_corroboration evidence item with no real source underneath
    // must NOT push source_count above 1 — the grounding gate is the guard.
    let mut e = Entity::new(EntityKind::Email, "x@example.com", 0.55, "s");
    e.add_evidence(Evidence::new(
        MULTIPATH_CORROBORATION_SOURCE,
        "Seen on two graph paths",
    ));
    assert_eq!(
        e.source_count(),
        1,
        "promotion source alone: no real source → gate blocks it, falls to fallback=1"
    );
}

#[test]
fn promotion_source_amplifies_grounded_entity() {
    // One real source grounds the entity; a multipath_corroboration on top
    // must count as a second distinct source (the gate is satisfied).
    let mut e = Entity::new(EntityKind::Email, "x@example.com", 0.55, "s");
    e.add_evidence(Evidence::new("haveibeenpwned", "Found in breach dataset"));
    e.add_evidence(Evidence::new(
        MULTIPATH_CORROBORATION_SOURCE,
        "Seen on two graph paths",
    ));
    assert_eq!(
        e.source_count(),
        2,
        "real_src=1 satisfies the gate → promotion source counts"
    );
}

#[test]
fn cross_scan_corroboration_gated_same_as_multipath() {
    // CROSS_SCAN_CORROBORATION_SOURCE is the same tier as multipath — it is a
    // promotion source and must be gated identically.
    let mut solo = Entity::new(EntityKind::Email, "y@example.com", 0.55, "s");
    solo.add_evidence(Evidence::new(
        CROSS_SCAN_CORROBORATION_SOURCE,
        "Matched across scan boundary",
    ));
    assert_eq!(
        solo.source_count(),
        1,
        "no real source → gate blocks cross_scan"
    );

    let mut grounded = Entity::new(EntityKind::Email, "y@example.com", 0.55, "s");
    grounded.add_evidence(Evidence::new("snusbase", "Found in leak"));
    grounded.add_evidence(Evidence::new(
        CROSS_SCAN_CORROBORATION_SOURCE,
        "Matched across scan boundary",
    ));
    assert_eq!(
        grounded.source_count(),
        2,
        "grounded entity → cross_scan counts"
    );
}

#[test]
fn derived_entity_needs_two_real_sources_for_promotion_to_count() {
    // A `derived` entity (e.g. a name→email permutation) whose generator is a
    // non-corroborating source (here: `name_intel`) contributes real=0.
    // The derived gate requires real≥2, so promotion is blocked even when a
    // promotion pass has also fired. Two independent corroborating sources are
    // needed before promotion is allowed to amplify the count.
    let mut one_real = Entity::new(EntityKind::Email, "guess@example.com", 0.55, "s");
    one_real.tag("derived");
    one_real.add_evidence(Evidence::new("name_intel", "Permuted from name")); // non-corroborating
    one_real.add_evidence(Evidence::new(
        MULTIPATH_CORROBORATION_SOURCE,
        "Seen on two graph paths",
    ));
    // name_intel is non-corroborating, so real=0, gate(derived)=false → promotion blocked
    assert_eq!(
        one_real.source_count(),
        1,
        "derived with 1 non-corroborating source + promotion: gate still blocks"
    );

    // Now add a genuine real source — that satisfies the derived gate (real >= 2
    // counting only corroborating; name_intel is non-corroborating so a real
    // observed source is the second corroborating one).
    let mut two_real = Entity::new(EntityKind::Email, "guess@example.com", 0.55, "s");
    two_real.tag("derived");
    two_real.add_evidence(Evidence::new("name_intel", "Permuted from name")); // non-corroborating
    two_real.add_evidence(Evidence::new("haveibeenpwned", "Confirmed in breach")); // real
    two_real.add_evidence(Evidence::new("snusbase", "Confirmed in second breach")); // real
    two_real.add_evidence(Evidence::new(
        MULTIPATH_CORROBORATION_SOURCE,
        "Seen on two graph paths",
    ));
    // real=2 (hibp + snusbase), derived gate: real >= 2 → grounded → promo counts
    assert_eq!(
        two_real.source_count(),
        3,
        "derived with 2 real sources satisfies the gate → promotion also counts"
    );
}

#[test]
fn c_eff_clamped_to_one() {
    let mut e = email("a@b.com");
    e.confidence = 0.99;
    e.corroboration = 1000;
    assert!(e.c_effective() <= 1.0);
}

#[test]
fn tier_rank_is_monotonic_and_finite() {
    // Tier ladder used by the bounded best-first halting bound.
    assert!(Classification::Candidate.rank() < Classification::Probable.rank());
    assert!(Classification::Probable.rank() < Classification::Verified.rank());
    assert_eq!(Classification::COUNT, 3);
    // Highest rank must be < COUNT so it indexes a finite ladder.
    assert!(Classification::Verified.rank() < Classification::COUNT);
}

#[test]
fn tier_tracks_c_eff_bands() {
    let mut e = email("a@b.com");
    e.confidence = 0.30;
    assert_eq!(e.tier(), Classification::Candidate);
    e.confidence = 0.50;
    assert_eq!(e.tier(), Classification::Probable);
    e.confidence = 0.90;
    assert_eq!(e.tier(), Classification::Verified);
}

#[test]
fn c_eff_safe_with_zero_corroboration() {
    let mut e = email("a@b.com");
    e.corroboration = 0;
    let c = e.c_effective();
    assert!(!c.is_nan(), "c_effective must not be NaN");
    assert!((0.0..=1.0).contains(&c));
}

#[test]
fn c_effective_contract_holds_across_grid() {
    // The analytical core's documented invariants, swept rather than
    // spot-checked — classification tiers AND the recursion/expansion gate
    // (`c_effective() >= min_expand_confidence`) ride on them, so a future
    // formula tweak that broke any of these would silently corrupt findings:
    //   (1) the fused confidence stays in [0, 1],
    //   (2) corroboration never *reduces* an entity's own confidence,
    //   (3) it is non-decreasing in the corroborating-source count, and
    //   (4) a single source is the identity (c_eff == confidence).
    for ci in 0..=20 {
        let c = f64::from(ci) / 20.0; // 0.00, 0.05, … 1.00
        let mut prev = f64::NEG_INFINITY;
        for n in 1..=25u32 {
            let mut e = email("a@b.com");
            e.confidence = c;
            e.corroboration = n; // no evidence ⇒ source_count() == n
            let ce = e.c_effective();
            assert!(
                (0.0..=1.0).contains(&ce),
                "c_eff out of [0,1]: c={c} n={n} ce={ce}"
            );
            assert!(
                ce + 1e-12 >= c,
                "corroboration must never reduce confidence: c={c} n={n} ce={ce}"
            );
            assert!(
                ce + 1e-12 >= prev,
                "c_eff must be non-decreasing in n: c={c} n={n} ce={ce} prev={prev}"
            );
            if n == 1 {
                assert!(
                    (ce - c).abs() < 1e-12,
                    "a single source must be the identity: c={c} ce={ce}"
                );
            }
            prev = ce;
        }
    }
}

#[test]
fn merge_clamps_confidence() {
    let mut a = email("x@y.com");
    a.confidence = 1.5; // corrupted
    let b = email("x@y.com");
    a.merge(b);
    assert!(a.confidence <= 1.0, "merge must clamp confidence");
}

#[test]
fn merge_corroboration_never_zero() {
    let mut a = email("x@y.com");
    a.corroboration = 0;
    let mut b = email("x@y.com");
    b.corroboration = 0;
    a.merge(b);
    assert!(
        a.corroboration >= 1,
        "corroboration must be at least 1 after merge"
    );
}

// ── Classification ───────────────────────────────────────────────────────

#[test]
fn classify_candidate() {
    let mut e = email("a@b.com");
    e.confidence = 0.2;
    assert_eq!(e.classify(), Classification::Candidate);
}

#[test]
fn classify_probable() {
    let mut e = email("a@b.com");
    e.confidence = 0.55;
    assert_eq!(e.classify(), Classification::Probable);
}

#[test]
fn classify_verified() {
    let mut e = email("a@b.com");
    e.confidence = 0.9;
    assert_eq!(e.classify(), Classification::Verified);
}

// ── Merge (GREATEST-semantics) ───────────────────────────────────────────

#[test]
fn merge_confidence_never_decreases() {
    let mut a = email("x@y.com");
    a.confidence = 0.8;
    let mut b = email("x@y.com");
    b.confidence = 0.3;
    a.merge(b);
    assert!((a.confidence - 0.8).abs() < 1e-9);
}

#[test]
fn merge_corroboration_accumulates() {
    let mut a = email("x@y.com");
    let mut b = email("x@y.com");
    b.corroboration = 3;
    a.merge(b);
    assert_eq!(a.corroboration, 4); // 1 + 3
}

/// `candidate` is a confidence-TIER quarantine (see [`Entity::demote_to_candidate`]),
/// not an accumulating multi-source label like an ordinary tag — every default
/// view filters entities purely on this tag (`api::scan_export`,
/// `api::scan_handlers::analysis`). A stranger's non-matching, low-confidence
/// observation of the SAME uid (a breach row `TargetMatch` classified as a
/// non-match, tagged `candidate` by `demote_to_candidate`) must not poison an
/// otherwise-verified entity — confidence already resolves to the max of the
/// two sides, so tag status must track that: a single non-candidate
/// corroboration promotes the merged entity out of quarantine for good.
#[test]
fn merge_does_not_let_a_candidate_duplicate_poison_a_verified_entity() {
    let mut verified = email("x@y.com");
    verified.confidence = 0.9;
    verified.tag("subject");

    let mut stray_candidate = email("x@y.com");
    stray_candidate.demote_to_candidate();

    verified.merge(stray_candidate);

    assert!(
        !verified.has_tag(crate::core::tags::CANDIDATE),
        "a verified entity must not be quarantined by a merged-in candidate duplicate"
    );
    assert!((verified.confidence - 0.9).abs() < 1e-9);
    assert!(verified.has_tag("subject"));
}

/// Symmetric case: a genuinely candidate entity gets corroborated later by a
/// trusted, non-candidate observation of the same uid — it must be promoted
/// OUT of the candidate tier (not stay hidden from default views forever).
#[test]
fn merge_promotes_a_candidate_entity_once_a_verified_duplicate_lands() {
    let mut candidate = email("x@y.com");
    candidate.demote_to_candidate();
    assert!(candidate.has_tag(crate::core::tags::CANDIDATE));

    let mut verified = email("x@y.com");
    verified.confidence = 0.9;

    candidate.merge(verified);

    assert!(
        !candidate.has_tag(crate::core::tags::CANDIDATE),
        "a non-candidate corroboration must promote the entity out of quarantine"
    );
}

/// Two candidate-only observations of the same uid must remain quarantined —
/// there is no genuine corroboration to promote on.
#[test]
fn merge_keeps_two_candidate_duplicates_quarantined() {
    let mut a = email("x@y.com");
    a.demote_to_candidate();
    let mut b = email("x@y.com");
    b.demote_to_candidate();

    a.merge(b);

    assert!(a.has_tag(crate::core::tags::CANDIDATE));
}

// ── Decay ────────────────────────────────────────────────────────────────

#[test]
fn decay_immediate_is_unchanged() {
    let e = email("a@b.com");
    // observed_at == now, so elapsed ≈ 0 → GAMMA^0 = 1.0
    let d = e.decayed_confidence();
    assert!((d - e.confidence).abs() < 0.001);
}

#[test]
fn decay_one_hour_ago() {
    let mut e = email("a@b.com");
    e.confidence = 1.0;
    e.observed_at = unix_now() - 3600; // 1 hour ago
    let d = e.decayed_confidence();
    // Should be ≈ GAMMA_PER_HOUR^1 = 0.85
    assert!((d - GAMMA_PER_HOUR).abs() < 0.01);
}

// ── Normalisation ────────────────────────────────────────────────────────

#[test]
fn normalise_email_lowercases() {
    assert_eq!(
        normalise(&EntityKind::Email, " Matt@EXAMPLE.COM "),
        "matt@example.com"
    );
}

#[test]
fn normalise_email_strips_breach_escape_tail() {
    // Regression (live oathnet breach co-occurrence): a value carrying the
    // literal escape tail `\r\n` (the chars `\ r \ n`, not real whitespace) must
    // fold to the clean address so it shares one UID and never leaks malformed.
    assert_eq!(
        normalise(&EntityKind::Email, "user@gmail.com\\r\\n"),
        "user@gmail.com"
    );
    // Internal whitespace (a glued-on second field) is also cut.
    assert_eq!(
        normalise(&EntityKind::Email, "user@gmail.com extra"),
        "user@gmail.com"
    );
    // The clean and dirty forms must share a UID (the dedup point).
    assert_eq!(
        Entity::new(EntityKind::Email, "user@gmail.com\\r\\n", 0.3, "s").uid,
        Entity::new(EntityKind::Email, "user@gmail.com", 0.3, "s").uid
    );
}

#[test]
fn normalise_email_strips_invisible_and_control_noise() {
    let clean = "user@gmail.com";
    // A UTF-8 BOM an exporter prepended is NOT whitespace, so it used to survive
    // and key the same mailbox to a different UID (identity fragmentation).
    assert_eq!(
        normalise(&EntityKind::Email, "\u{feff}user@gmail.com"),
        clean
    );
    // A zero-width space embedded mid-value is removed (not cut — the address
    // before AND after it is real).
    assert_eq!(
        normalise(&EntityKind::Email, "user@gmail\u{200b}.com"),
        clean
    );
    // A NUL-separated junk suffix is cut like the escape tail.
    assert_eq!(
        normalise(&EntityKind::Email, "user@gmail.com\u{0}junk"),
        clean
    );
    // All three forms share the clean address's UID — the dedup point.
    for dirty in [
        "\u{feff}user@gmail.com",
        "user@gmail\u{200b}.com",
        "user@gmail.com\u{0}junk",
    ] {
        assert_eq!(
            Entity::new(EntityKind::Email, dirty, 0.3, "s").uid,
            Entity::new(EntityKind::Email, clean, 0.3, "s").uid,
            "{dirty:?} must fold to the clean UID"
        );
    }
    // A pristine address is untouched (no needless allocation path regression).
    assert_eq!(normalise(&EntityKind::Email, clean), clean);
}

#[test]
fn normalise_email_strips_surrounding_quotes() {
    // A seed/CSV/shell-quoted address (`"matt@x.com`, `'matt@x.com'`) must fold to
    // the clean address — a stray quote otherwise forks the UID and poisons every
    // derived entity (the real `"matthewdiegmann@gmail.com` contamination).
    let clean = "matthewdiegmann@gmail.com";
    for dirty in [
        "\"matthewdiegmann@gmail.com",
        "\"matthewdiegmann@gmail.com\"",
        "'matthewdiegmann@gmail.com'",
        "`matthewdiegmann@gmail.com`",
    ] {
        assert_eq!(
            normalise(&EntityKind::Email, dirty),
            clean,
            "{dirty:?} must fold to the clean address"
        );
        assert_eq!(
            Entity::new(EntityKind::Email, dirty, 0.9, "s").uid,
            Entity::new(EntityKind::Email, clean, 0.9, "s").uid,
            "{dirty:?} must share the clean UID"
        );
    }
    // Idempotent + no false positives on a clean address.
    assert_eq!(normalise(&EntityKind::Email, clean), clean);
}

#[test]
fn normalise_username_strips_surrounding_quotes_and_at_sigil() {
    // A quoted handle sheds the quote AND the `@` sigil, in either order, so the
    // contaminated `"matthewdiegmann` folds to the clean derived username.
    let clean = "matthewdiegmann";
    for dirty in [
        "\"matthewdiegmann",
        "\"matthewdiegmann\"",
        "'@matthewdiegmann'",
        "@matthewdiegmann",
    ] {
        assert_eq!(
            normalise(&EntityKind::Username, dirty),
            clean,
            "{dirty:?} must fold to the clean handle"
        );
    }
}

#[test]
fn normalise_phone_strips_formatting() {
    let r = normalise(&EntityKind::Phone, "+61 04 1234 5678");
    assert_eq!(r, "+61041234567 8".replace(' ', ""));
}

#[test]
fn normalise_phone_trims_before_plus_check() {
    // Leading whitespace must not eat the country-code `+`: the `+` check runs
    // on the first char, so an untrimmed " +61…" used to normalise to "61…",
    // splitting one number across two UIDs.
    assert_eq!(
        normalise(&EntityKind::Phone, "  +61 412 345 678 "),
        "+61412345678"
    );
    assert_eq!(
        normalise(&EntityKind::Phone, "  +61 412 345 678 "),
        normalise(&EntityKind::Phone, "+61412345678")
    );
}

#[test]
fn normalise_coordinates_collapses_negative_zero() {
    // -0.0000001 rounds to zero at 6 dp; it must canonicalise to "0.000000",
    // not "-0.000000" — same point, and it must be the same UID.
    assert_eq!(
        normalise(&EntityKind::Coordinates, "-0.0000001,0.0"),
        "0.000000,0.000000"
    );
    assert_eq!(
        normalise(&EntityKind::Coordinates, "-0.0,-0.0"),
        "0.000000,0.000000"
    );
    // Real negative coordinates are untouched.
    assert_eq!(
        normalise(&EntityKind::Coordinates, "-27.5,153.0"),
        "-27.500000,153.000000"
    );
}

#[test]
fn normalise_coordinates_rejects_non_finite() {
    // NaN/inf must not be formatted into a pseudo-coordinate string; the raw
    // (trimmed) value falls through so validity gates see it untouched.
    assert_eq!(normalise(&EntityKind::Coordinates, "NaN,NaN"), "NaN,NaN");
    assert_eq!(normalise(&EntityKind::Coordinates, " inf,5 "), "inf,5");
}

#[test]
fn normalise_domain_strips_trailing_dot() {
    assert_eq!(
        normalise(&EntityKind::Domain, "example.com."),
        "example.com"
    );
}

#[test]
fn normalise_url_lowercases_host_strips_fragment() {
    assert_eq!(
        normalise(&EntityKind::Url, "HTTPS://GitHub.Com/user/repo#readme"),
        "https://github.com/user/repo"
    );
    assert_eq!(
        normalise(&EntityKind::Url, "https://X.COM/Profile/"),
        "https://x.com/Profile"
    );
    assert_eq!(
        normalise(&EntityKind::Url, "http://example.com/search?q=test"),
        "http://example.com/search?q=test"
    );
}

#[test]
fn normalise_url_strips_tracking_params() {
    // A bare X/Twitter share URL with the platform's own ref tracking and one
    // appended by a SERP must reduce to the bare profile so the two engines'
    // copies corroborate instead of fragmenting.
    assert_eq!(
        normalise(
            &EntityKind::Url,
            "https://x.com/ryno23?ref_src=twsrc%5Etfw&utm_source=google"
        ),
        "https://x.com/ryno23"
    );
    // utm_* family (any suffix) + fbclid are dropped; nothing remains → no `?`.
    assert_eq!(
        normalise(
            &EntityKind::Url,
            "https://example.com/page?utm_medium=email&utm_campaign=x&fbclid=abc123"
        ),
        "https://example.com/page"
    );
    // Instagram igshid tracking stripped, leaving the bare profile.
    assert_eq!(
        normalise(
            &EntityKind::Url,
            "https://instagram.com/ryne.manka?igshid=YmMyMTA2M2Y="
        ),
        "https://instagram.com/ryne.manka"
    );
}

#[test]
fn normalise_url_preserves_meaningful_params_and_sorts() {
    // A resource-identifying param (YouTube `v`) is kept; only tracking (`si`
    // is NOT in the denylist so it stays, but utm_* goes) is removed, and the
    // survivors are order-normalised so param order can't fragment the UID.
    assert_eq!(
        normalise(
            &EntityKind::Url,
            "https://youtube.com/watch?v=AbC123&utm_source=x"
        ),
        "https://youtube.com/watch?v=AbC123"
    );
    // Same params in different order → identical UID after sorting.
    let a = normalise(&EntityKind::Url, "https://e.com/p?b=2&a=1");
    let b = normalise(&EntityKind::Url, "https://e.com/p?a=1&b=2");
    assert_eq!(a, b);
    assert_eq!(a, "https://e.com/p?a=1&b=2");
    // The value's case is preserved (only keys are matched case-insensitively).
    assert_eq!(
        normalise(&EntityKind::Url, "https://e.com/p?Token=AbC"),
        "https://e.com/p?Token=AbC"
    );
}

#[test]
fn url_tracking_variants_share_one_uid() {
    // The end-to-end invariant the change exists for: two discoveries of the
    // same profile, differently tracked, produce one UID → one corroborated
    // entity rather than two single-source ones.
    let e1 = Entity::new(
        EntityKind::Url,
        "https://x.com/ryno23?ref_src=twsrc%5Etfw",
        0.6,
        "s",
    );
    let e2 = Entity::new(
        EntityKind::Url,
        "https://x.com/ryno23?utm_source=bing&utm_medium=organic",
        0.6,
        "s",
    );
    assert_eq!(e1.uid, e2.uid, "tracked variants must share a UID");
}

// ── Tags ─────────────────────────────────────────────────────────────────

#[test]
fn tag_dedup() {
    let mut e = email("a@b.com");
    e.tag("au:breach");
    e.tag("au:breach");
    assert_eq!(e.tags.len(), 1);
}

// ── Display ──────────────────────────────────────────────────────────────

#[test]
fn display_contains_kind_and_classification() {
    let e = email("a@b.com");
    let s = e.to_string();
    assert!(s.contains("email"));
    assert!(s.contains("CANDIDATE") || s.contains("PROBABLE") || s.contains("VERIFIED"));
}

// ── apply_decay ─────────────────────────────────────────────────────────

#[test]
fn apply_decay_mutates_confidence_in_place() {
    let mut e = email("a@b.com");
    e.confidence = 1.0;
    e.observed_at = unix_now() - 7200; // 2 hours ago
    let expected = e.decayed_confidence();
    e.apply_decay();
    assert!((e.confidence - expected).abs() < 1e-9);
}

// ── add_evidence ────────────────────────────────────────────────────────

#[test]
fn add_evidence_appends_to_vec() {
    let mut e = email("a@b.com");
    assert!(e.evidence.is_empty());
    e.add_evidence(Evidence::new("mod-a", "found via breach db"));
    e.add_evidence(Evidence::new("mod-b", "confirmed via DNS"));
    assert_eq!(e.evidence.len(), 2);
    assert_eq!(e.evidence[0].source, "mod-a");
    assert_eq!(e.evidence[1].source, "mod-b");
}

// ── Evidence::new ───────────────────────────────────────────────────────

#[test]
fn evidence_new_sets_fields_and_empty_attributes() {
    let before = unix_now();
    let ev = Evidence::new("src", "summary text");
    let after = unix_now();
    assert_eq!(ev.source, "src");
    assert_eq!(ev.summary, "summary text");
    assert!(ev.attributes.is_empty());
    assert!(ev.recorded_at >= before && ev.recorded_at <= after);
}

// ── Evidence::with_attr ─────────────────────────────────────────────────

#[test]
fn evidence_with_attr_chaining() {
    let ev = Evidence::new("src", "sum")
        .with_attr("key1", "val1")
        .with_attr("key2", "val2");
    assert_eq!(ev.attributes.len(), 2);
    assert_eq!(ev.attributes.get("key1").expect("should succeed"), "val1");
    assert_eq!(ev.attributes.get("key2").expect("should succeed"), "val2");
}

#[test]
fn evidence_attributes_serialize_in_stable_sorted_order() {
    // BTreeMap → byte-identical JSON regardless of insertion order, so
    // identical findings serialise reproducibly (hashable evidence chains).
    let ev = Evidence::new("src", "sum")
        .with_attr("zulu", "1")
        .with_attr("alpha", "2")
        .with_attr("mike", "3");
    assert_eq!(
        serde_json::to_string(&ev.attributes).expect("should succeed"),
        r#"{"alpha":"2","mike":"3","zulu":"1"}"#
    );
}

// ── Entity::new confidence clamping ─────────────────────────────────────

#[test]
fn new_clamps_confidence_above_one() {
    let e = Entity::new(EntityKind::Email, "a@b.com", 1.5, "s");
    assert!((e.confidence - 1.0).abs() < 1e-9);
}

#[test]
fn new_clamps_confidence_below_zero() {
    let e = Entity::new(EntityKind::Email, "a@b.com", -0.3, "s");
    assert!((e.confidence - 0.0).abs() < 1e-9);
}

// ── Entity merge: evidence appended ─────────────────────────────────────

#[test]
fn merge_evidence_appended_from_both() {
    let mut a = email("x@y.com");
    a.add_evidence(Evidence::new("mod-a", "evidence A"));
    let mut b = email("x@y.com");
    b.add_evidence(Evidence::new("mod-b", "evidence B"));
    b.add_evidence(Evidence::new("mod-c", "evidence C"));
    a.merge(b);
    assert_eq!(a.evidence.len(), 3);
    let sources: Vec<&str> = a.evidence.iter().map(|e| e.source.as_str()).collect();
    assert!(sources.contains(&"mod-a"));
    assert!(sources.contains(&"mod-b"));
    assert!(sources.contains(&"mod-c"));
}

#[test]
fn canonicalize_order_is_merge_order_independent() {
    // DETERMINISM REQUIREMENT (evidence): an entity built by merging the same
    // module results in DIFFERENT orders (as concurrent completion-order
    // dispatch does) must finalise to identical evidence + tag ordering.
    let build = |order: &[(&str, &str)], tags: &[&str]| {
        let mut e = email("x@y.com");
        for (src, sum) in order {
            e.add_evidence(Evidence::new(*src, (*sum).to_string()));
        }
        for t in tags {
            e.tag(*t);
        }
        e.canonicalize_order();
        e
    };
    let a = build(
        &[("zmod", "z"), ("amod", "a"), ("amod", "b")],
        &["zeta", "alpha", "mid"],
    );
    let b = build(
        &[("amod", "b"), ("zmod", "z"), ("amod", "a")],
        &["mid", "zeta", "alpha"],
    );
    let ev = |e: &Entity| {
        e.evidence
            .iter()
            .map(|x| (x.source.clone(), x.summary.clone()))
            .collect::<Vec<_>>()
    };
    assert_eq!(ev(&a), ev(&b), "evidence order depends on merge order");
    assert_eq!(a.tags, b.tags, "tag order depends on merge order");
    // Deterministic canonical order: evidence by (source, summary), tags sorted.
    assert_eq!(
        ev(&a),
        vec![
            ("amod".to_string(), "a".to_string()),
            ("amod".to_string(), "b".to_string()),
            ("zmod".to_string(), "z".to_string()),
        ]
    );
    assert_eq!(a.tags, vec!["alpha", "mid", "zeta"]);
}

// ── Entity merge: tags union dedup ───────────────────────────────────────

#[test]
fn merge_tags_union_dedup() {
    let mut a = email("x@y.com");
    a.tag("shared");
    a.tag("only-a");
    let mut b = email("x@y.com");
    b.tag("shared");
    b.tag("only-b");
    a.merge(b);
    assert!(a.has_tag("shared"));
    assert!(a.has_tag("only-a"));
    assert!(a.has_tag("only-b"));
    // "shared" must not be duplicated
    assert_eq!(a.tags.iter().filter(|t| *t == "shared").count(), 1);
}

// ── Entity merge: observed_at takes max ─────────────────────────────────

#[test]
fn merge_observed_at_takes_max() {
    let mut a = email("x@y.com");
    a.observed_at = 1000;
    let mut b = email("x@y.com");
    b.observed_at = 2000;
    a.merge(b);
    assert_eq!(a.observed_at, 2000);

    // Also verify when self is already newer
    let mut c = email("x@y.com");
    c.observed_at = 5000;
    let mut d = email("x@y.com");
    d.observed_at = 3000;
    c.merge(d);
    assert_eq!(c.observed_at, 5000);
}

// ── Entity generation (expansion generation) ─────────────────────────────────

#[test]
fn expansion_timeline_counts_entities_per_generation_in_order() {
    let mut ents = vec![
        email("a@x.com"),
        email("b@x.com"),
        email("c@x.com"),
        email("d@x.com"),
    ];
    ents[0].generation = 0;
    ents[1].generation = 0;
    ents[2].generation = 2; // note: skips generation 1
    ents[3].generation = 2;
    let timeline = crate::core::entity::expansion_timeline(&ents);
    // BTreeMap keeps generations ordered; only populated generations appear.
    let pairs: Vec<(u32, usize)> = timeline.into_iter().collect();
    assert_eq!(pairs, vec![(0, 2), (2, 2)]);
}

#[test]
fn depth_decay_discounts_c_effective_by_generation() {
    let mut e = email("x@y.com");
    let base_c = e.c_effective(); // single source ⇒ c_effective == confidence

    // base^0 = 1: a seed-round (generation 0) entity is never discounted.
    e.generation = 0;
    assert!((e.c_effective_depth_decayed(0.9) - base_c).abs() < 1e-9);

    // Each generation multiplies by `base`: generation 2 ⇒ ×base².
    e.generation = 2;
    assert!((e.c_effective_depth_decayed(0.9) - base_c * 0.9 * 0.9).abs() < 1e-9);

    // base = 1.0 is a total no-op at any depth (the default-off behaviour).
    e.generation = 5;
    assert!((e.c_effective_depth_decayed(1.0) - base_c).abs() < 1e-9);

    // The result stays clamped to [0, 1].
    assert!((0.0..=1.0).contains(&e.c_effective_depth_decayed(0.5)));
}

#[test]
fn new_entity_starts_at_generation_zero() {
    // Modules never know their round, so every freshly-built entity is generation 0.
    assert_eq!(email("x@y.com").generation, 0);
}

#[test]
fn merge_preserves_the_earliest_generation() {
    // The load-bearing invariant: an entity first surfaced deep in expansion
    // (engine-stamped, here generation 3) must NOT be reset to the seed generation
    // when a later round re-emits it via a module (which always carries the
    // default generation 0). merge folds `other` INTO the pre-existing entity,
    // so `self`'s generation is kept.
    let mut deep = email("x@y.com");
    deep.generation = 3;
    let reemit = email("x@y.com"); // module default: generation 0
    deep.merge(reemit);
    assert_eq!(
        deep.generation, 3,
        "re-emission must not reset the generation"
    );
}

#[test]
fn generation_serde_round_trips_and_defaults_for_legacy_rows() {
    // New rows carry the generation through data_json.
    let mut e = email("x@y.com");
    e.generation = 2;
    let json = serde_json::to_string(&e).expect("should succeed");
    let back: Entity = serde_json::from_str(&json).expect("should succeed");
    assert_eq!(back.generation, 2);

    // A legacy row persisted before the field existed has no `generation` key;
    // #[serde(default)] must decode it to 0 (no storage migration needed).
    let legacy = serde_json::to_value(&e).expect("should succeed");
    let mut obj = legacy.as_object().expect("should succeed").clone();
    obj.remove("generation");
    let recovered: Entity =
        serde_json::from_value(serde_json::Value::Object(obj)).expect("should succeed");
    assert_eq!(
        recovered.generation, 0,
        "legacy rows default to generation 0"
    );
}

#[test]
fn merge_raw_value_is_order_independent() {
    // Same UID (case-insensitive email), differing only in display spelling.
    let upper = email("Foo@Bar.com");
    let lower = email("foo@bar.com");
    assert_eq!(upper.uid, lower.uid, "must share a UID to exercise merge");

    // Merge both directions: the stored raw_value must not depend on order.
    let mut a = upper.clone();
    a.merge(lower.clone());
    let mut b = lower.clone();
    b.merge(upper.clone());
    assert_eq!(
        a.raw_value, b.raw_value,
        "raw_value must be merge-order independent (Determinism Requirement)"
    );
    // min() semantics: "Foo@Bar.com" < "foo@bar.com" (uppercase sorts first).
    assert_eq!(a.raw_value, "Foo@Bar.com");
}

// ── Entity merge: UID mismatch is no-op (release mode) ──────────────────

#[test]
#[cfg(not(debug_assertions))]
fn merge_uid_mismatch_is_noop() {
    let mut a = email("x@y.com");
    let original_confidence = a.confidence;
    let original_corroboration = a.corroboration;
    let b = Entity::new(EntityKind::Email, "different@z.com", 0.9, "s");
    a.merge(b);
    assert!((a.confidence - original_confidence).abs() < 1e-9);
    assert_eq!(a.corroboration, original_corroboration);
}

// ── EntityKind::Other Display ───────────────────────────────────────────

#[test]
fn entity_kind_other_display() {
    let kind = EntityKind::Other("foo".to_string());
    assert_eq!(kind.to_string(), "other:foo");
}

/// `derive_uid` hashes `Display(kind) + ":" + normalised_value`, and
/// `Other(s)` displays as `"other:{s}"` — so the FULL preimage for an
/// `Other` entity is `"other:" + s + ":" + value` with no escaping between
/// the field-name segment and the value segment. Two semantically DISTINCT
/// (field_name, value) pairs — a scraped breach-JSON key/value, per
/// `modules::breach_rich`'s catch-all loop — must never collide onto the
/// same uid just because a `:` moved from one segment to the other.
#[test]
fn other_kind_uid_does_not_collide_when_the_delimiter_shifts_between_name_and_value() {
    let a = Entity::new(EntityKind::Other("a".to_string()), "b:c", 0.5, "s");
    let b = Entity::new(EntityKind::Other("a:b".to_string()), "c", 0.5, "s");
    assert_ne!(
        a.uid, b.uid,
        "Other(\"a\")+\"b:c\" and Other(\"a:b\")+\"c\" must not share a uid"
    );
}

// ── EntityRef from Entity ───────────────────────────────────────────────

#[test]
fn entity_ref_from_entity() {
    let e = email("a@b.com");
    let r = EntityRef::from(&e);
    assert_eq!(r.uid, e.uid);
    assert_eq!(r.kind, e.kind);
    assert_eq!(r.value, e.value);
}

// ── normalise: non-email kinds just trim ────────────────────────────────

#[test]
fn normalise_ip_address_trims() {
    let result = normalise(&EntityKind::IpAddress, "  192.168.1.1  ");
    assert_eq!(result, "192.168.1.1");
}

#[test]
fn normalise_other_kind_trims() {
    let result = normalise(&EntityKind::Other("custom".into()), "  some value  ");
    assert_eq!(result, "some value");
}

// ── normalise: Username ─────────────────────────────────────────────────

#[test]
fn normalise_username_lowercases_and_trims() {
    let result = normalise(&EntityKind::Username, "  MyUser  ");
    assert_eq!(result, "myuser");
}

#[test]
fn normalise_username_strips_leading_handle_sigil_for_dedup() {
    // `@jordanavery` and `jordanavery` are the same account: both must
    // normalise (and therefore derive the same UID) to the bare handle.
    assert_eq!(
        normalise(&EntityKind::Username, "@JordanAvery"),
        "jordanavery"
    );
    assert_eq!(
        normalise(&EntityKind::Username, "  @ jordanavery "),
        "jordanavery"
    );
    assert_eq!(
        derive_uid(
            &EntityKind::Username,
            &normalise(&EntityKind::Username, "@jordanavery")
        ),
        derive_uid(
            &EntityKind::Username,
            &normalise(&EntityKind::Username, "jordanavery")
        ),
        "@handle and handle must share a UID"
    );
    // Email is unaffected — a leading `@` there is a genuine fragment.
    assert_eq!(normalise(&EntityKind::Email, "Foo@Bar.com"), "foo@bar.com");
}

#[test]
fn normalise_username_is_a_fixed_point_when_whitespace_shields_a_sigil() {
    // Regression for the property test `normalise_is_idempotent`, whose minimal
    // shrink was `kind=Username, v="`\t`\0"`. A whitespace char wedged *between*
    // two strip sigils used to survive the leading-sigil pass: the first pass
    // stripped the outer backtick, then a separate `.trim()` removed the tab and
    // exposed the inner backtick at the front one normalise too late. Re-running
    // normalise then stripped that backtick too, so `` `\t`\0 `` keyed to `` `\0 ``
    // once but `` \0 `` twice — forking one account across two UIDs. Folding
    // whitespace into the same strip run as the sigils makes a single pass a
    // fixed point.
    let v = "`\t`\u{0}";
    let once = normalise(&EntityKind::Username, v);
    let twice = normalise(&EntityKind::Username, &once);
    assert_eq!(once, twice, "username normalise must be idempotent: {v:?}");
    // Both leading backticks and the interleaved tab are consumed in one pass,
    // leaving only the non-strippable NUL.
    assert_eq!(once, "\u{0}");

    // A handle reachable only by stripping *through* interior whitespace still
    // collapses to the bare account in a single pass — and shares its UID.
    assert_eq!(normalise(&EntityKind::Username, "\"\t@\t bob "), "bob");
    assert_eq!(
        derive_uid(
            &EntityKind::Username,
            &normalise(&EntityKind::Username, "  `@` bob ")
        ),
        derive_uid(
            &EntityKind::Username,
            &normalise(&EntityKind::Username, "bob")
        ),
        "a whitespace/sigil-wrapped handle must share the bare account's UID"
    );
}

#[test]
fn normalise_username_and_domain_strip_invisible_noise() {
    // Identity integrity across the identity kinds: a BOM/zero-width char must not
    // fork the UID for a username or a domain any more than for an email.
    // A BOM before the `@handle` must still be removed AND the `@` stripped.
    assert_eq!(
        normalise(&EntityKind::Username, "\u{feff}@JordanAvery"),
        "jordanavery"
    );
    assert_eq!(
        normalise(&EntityKind::Username, "jordan\u{200b}avery"),
        "jordanavery"
    );
    assert_eq!(
        normalise(&EntityKind::Domain, "\u{feff}Example.COM"),
        "example.com"
    );
    // Each noisy form shares the clean UID.
    assert_eq!(
        Entity::new(EntityKind::Username, "\u{feff}@jordanavery", 0.3, "s").uid,
        Entity::new(EntityKind::Username, "jordanavery", 0.3, "s").uid
    );
    assert_eq!(
        Entity::new(EntityKind::Domain, "\u{feff}example.com", 0.3, "s").uid,
        Entity::new(EntityKind::Domain, "example.com", 0.3, "s").uid
    );
}

#[test]
fn normalise_folds_non_ascii_uppercase_for_dedup() {
    // Regression: the old fast path returned early when a value had no ASCII
    // uppercase byte, so a value whose only capital is NON-ASCII (e.g. a
    // German/Scandinavian name, a Cyrillic/Greek handle, Turkish dotted-I)
    // was never folded — fragmenting one real identity across two UIDs while
    // its all-caps spelling folded correctly. Unicode folding must be total.
    for (mixed, lower) in [
        ("Ölaf", "ölaf"),
        ("İstanbul", "i\u{307}stanbul"), // İ folds to i + combining dot above
        ("ÉRIC", "éric"),
    ] {
        for kind in [EntityKind::Email, EntityKind::Username] {
            assert_eq!(
                normalise(&kind, mixed),
                lower,
                "{kind:?}: {mixed:?} must fold to {lower:?}"
            );
            // The mixed-case and lower-case spellings must share a UID.
            assert_eq!(
                Entity::new(kind.clone(), mixed, 0.5, "s").uid,
                Entity::new(kind.clone(), lower, 0.5, "s").uid,
                "{kind:?}: {mixed:?} and {lower:?} must dedup to one UID"
            );
        }
    }
}

/// All entity kinds, for the cross-kind normalisation invariants below.
fn all_kinds() -> Vec<EntityKind> {
    use EntityKind::*;
    let kinds = vec![
        Person,
        Email,
        Phone,
        Username,
        Credential,
        ApiKey,
        Password,
        IpAddress,
        Domain,
        Url,
        Asn,
        Cidr,
        Address,
        Coordinates,
        Organisation,
        AbnAcn,
        MacAddress,
        DeviceId,
        Ssid,
        TrackingId,
        CryptoAddress,
        Other("x".into()),
    ];
    // Exhaustiveness tripwire: this match names every `EntityKind` variant with no
    // `_` arm, so adding a new kind fails to compile *here* until it is also added
    // to the vec above. That keeps every test iterating `all_kinds()` — the
    // idempotency / dedup / case-fold property checks and the per-kind normalise
    // sweep — from silently skipping a newly-introduced kind. (Cidr/Ssid/TrackingId
    // were previously absent, leaving their normalise arms unswept.)
    for k in &kinds {
        match k {
            Person | Email | Phone | Username | Credential | ApiKey | Password | IpAddress
            | Domain | Url | Asn | Cidr | Address | Coordinates | Organisation | AbnAcn
            | MacAddress | DeviceId | Ssid | TrackingId | CryptoAddress | Other(_) => {}
        }
    }
    kinds
}

/// A corpus of awkward values spanning every normalisation arm: non-ASCII
/// capitals, `+tag` emails, repeated/leading `www.`, mixed-case URLs with
/// query+fragment, coordinates, dashed/`-0.0` numbers, MAC variants, IPv6.
const NORM_CORPUS: &[&str] = &[
    "Ölaf",
    "ölaf",
    "ÉRIC",
    "İstanbul",
    "Ηandle",
    "Jordan.Avery+tag@Gmail.COM",
    "  spaced@x.com  ",
    "WWW.Example.COM.",
    "www.WWW.com",
    "www.com",
    "www.www.google.com",
    "HTTPS://Host.COM/Path/Sub/?Q=1&b=2#frag",
    "http://A.B/",
    "1.23456789,-2.5",
    "-0.0,0.0",
    "-0.0000001,179.9999999",
    "NaN,NaN",
    "  +61 412 345 678 ",
    "AA-BB-CC-DD-EE-FF",
    "+1 (555) 234-9999",
    "::ffff:1.2.3.4",
    "2001:DB8::1",
    "AS13335",
    "MixedCaseHandle",
];

#[test]
fn normalise_is_idempotent_for_every_kind() {
    // The normalised value keys the entity UID, so re-normalising an
    // already-normalised value MUST be a no-op — otherwise a stored or
    // re-emitted value can shift UID and silently fail to dedup. (Regression:
    // the `www.` strip removed only the first label, so `www.www.foo.com`
    // normalised to `www.foo.com` which then re-normalised to `foo.com`.)
    for k in all_kinds() {
        for v in NORM_CORPUS {
            let once = normalise(&k, v);
            let twice = normalise(&k, &once);
            assert_eq!(
                once, twice,
                "normalise not idempotent for {k:?}: {v:?} → {once:?} → {twice:?}"
            );
        }
    }
}

#[test]
fn normalise_is_case_insensitive_for_folded_kinds() {
    // Email/Username/Domain dedup must be invariant under input case (full
    // Unicode), so the same identity from differently-cased sources merges.
    for k in [EntityKind::Email, EntityKind::Username, EntityKind::Domain] {
        for v in NORM_CORPUS {
            let base = normalise(&k, v);
            assert_eq!(
                base,
                normalise(&k, &v.to_uppercase()),
                "{k:?} not case-invariant (upper): {v:?}"
            );
            assert_eq!(
                base,
                normalise(&k, &v.to_lowercase()),
                "{k:?} not case-invariant (lower): {v:?}"
            );
        }
    }
}

#[test]
fn normalise_domain_collapses_repeated_www_to_a_fixed_point() {
    assert_eq!(
        normalise(&EntityKind::Domain, "www.www.google.com"),
        "google.com"
    );
    assert_eq!(normalise(&EntityKind::Domain, "WWW.Foo.COM"), "foo.com");
    // A bare `www.` is never collapsed to the empty string (its trailing dot
    // is stripped first, leaving the literal `www`, which has no `www.` prefix).
    assert_eq!(normalise(&EntityKind::Domain, "www."), "www");
    // `www.www.` → trailing dot stripped → `www.www` → strip leading labels
    // down to the last non-`www.` label, which is itself `www`.
    assert_eq!(normalise(&EntityKind::Domain, "www.www."), "www");
}

#[test]
fn normalise_domain_is_idempotent_when_a_bom_shields_a_control_byte() {
    // Regression (proptest minimal case): a leading BOM is not whitespace, so it
    // shields a following control/whitespace byte from `value.trim()`. Stripping
    // the BOM exposes that byte at the edge — it must be re-trimmed in the SAME
    // pass, or the first normalise keeps it (`\u{b}¡`) while a second strips it
    // (`¡`), forking one host into two UIDs.
    let once = normalise(&EntityKind::Domain, "\u{feff}\u{b}¡");
    let twice = normalise(&EntityKind::Domain, &once);
    assert_eq!(once, twice, "normalise must be a fixed point");
    assert_eq!(
        once, "¡",
        "the shielded control byte is trimmed in one pass"
    );
}

#[test]
fn normalise_domain_is_idempotent_when_www_label_exposes_whitespace() {
    // Regression: stripping a `www.` label that is immediately followed by
    // whitespace must re-trim the leading edge, or the whitespace survives to
    // the result but a re-normalise (no `www.` left to strip) would trim it —
    // forking one host into two UIDs.
    assert_eq!(normalise(&EntityKind::Domain, "www. foo.com"), "foo.com");
    let once = normalise(&EntityKind::Domain, "www. foo.com");
    let twice = normalise(&EntityKind::Domain, &once);
    assert_eq!(once, twice, "normalise must be a fixed point");
    assert_eq!(
        once, "foo.com",
        "whitespace exposed by www. strip is trimmed"
    );
}

#[test]
fn normalise_email_is_idempotent_when_a_bom_shields_whitespace() {
    // Regression: a leading BOM/zero-width is not whitespace, so `value.trim()`
    // stops at it and leaves whitespace behind it. Stripping the BOM exposes the
    // whitespace at the edge — it must be re-trimmed in the SAME pass, or the
    // result truncates at the space (cut finds `is_whitespace()`) and a second
    // pass trims it first. This forked one address across two UIDs and truncated
    // to empty string in the worst case.
    let once = normalise(&EntityKind::Email, "\u{feff} alice@example.com");
    let twice = normalise(&EntityKind::Email, &once);
    assert_eq!(
        once, twice,
        "normalise must be idempotent (found '{once}' then '{twice}')"
    );
    assert_eq!(
        once, "alice@example.com",
        "whitespace exposed by BOM strip is trimmed"
    );
    // Extreme case: zero-width char + space. After stripping the zero-width,
    // the re-trim removes the space, resulting in empty. This is correct —
    // space-only (or zero-width + space) is not a valid email address.
    let just_space = normalise(&EntityKind::Email, "\u{200b} ");
    assert_eq!(just_space, "", "space-only input trims to empty");
}

// ── Classification::as_str round-trips ──────────────────────────────────

#[test]
fn classification_as_str_round_trips() {
    assert_eq!(Classification::Candidate.as_str(), "CANDIDATE");
    assert_eq!(Classification::Probable.as_str(), "PROBABLE");
    assert_eq!(Classification::Verified.as_str(), "VERIFIED");

    // Also verify Display matches as_str
    assert_eq!(Classification::Candidate.to_string(), "CANDIDATE");
    assert_eq!(Classification::Probable.to_string(), "PROBABLE");
    assert_eq!(Classification::Verified.to_string(), "VERIFIED");
}

// ── EntityKind serde round-trip ─────────────────────────────────────────

#[test]
fn entity_kind_serde_round_trip() {
    let variants = vec![
        EntityKind::Person,
        EntityKind::Email,
        EntityKind::Phone,
        EntityKind::Username,
        EntityKind::Credential,
        EntityKind::Password,
        EntityKind::IpAddress,
        EntityKind::Domain,
        EntityKind::Url,
        EntityKind::Asn,
        EntityKind::Cidr,
        EntityKind::Address,
        EntityKind::Coordinates,
        EntityKind::Organisation,
        EntityKind::AbnAcn,
        EntityKind::MacAddress,
        EntityKind::DeviceId,
        EntityKind::TrackingId,
        EntityKind::CryptoAddress,
        EntityKind::Other("custom".to_string()),
    ];
    for kind in variants {
        let json = serde_json::to_string(&kind)
            .unwrap_or_else(|e| panic!("serialize {kind:?} failed: {e}"));
        let back: EntityKind = serde_json::from_str(&json)
            .unwrap_or_else(|e| panic!("deserialize {json} failed: {e}"));
        assert_eq!(kind, back, "round-trip failed for {json}");
    }
}

// ── scan_id ─────────────────────────────────────────────────────────────

#[test]
fn scan_id_is_64_hex_chars() {
    let id = scan_id("email", "x@y.com");
    assert_eq!(id.len(), 64);
    assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn scan_id_is_collision_free_for_rapid_identical_calls() {
    // Regression: two scans created within the SAME second with identical
    // (kind, value) previously hashed to the same id (only `unix_now()` at
    // 1 s resolution was mixed) and overwrote each other — a real defect for
    // rapid web imports / batch creates. No sleep: a tight burst of identical
    // calls must all be distinct.
    let ids: std::collections::HashSet<String> =
        (0..1000).map(|_| scan_id("email", "a@b.com")).collect();
    assert_eq!(
        ids.len(),
        1000,
        "scan_id must be collision-free within a second"
    );
}

#[test]
fn scan_id_different_kinds_differ() {
    let a = scan_id("email", "x");
    let b = scan_id("domain", "x");
    assert_ne!(a, b);
}

#[test]
fn classification_ladder_is_single_sourced_and_boundary_exact() {
    use Classification as C;
    // The documented tier values — a recalibration must be deliberate (update
    // this pin alongside the constants), never an accidental drift.
    assert!((C::VERIFIED_MIN - 0.75).abs() < 1e-12);
    assert!((C::PROBABLE_MIN - 0.40).abs() < 1e-12);
    // Boundary-exact: the lower bounds are inclusive.
    assert_eq!(C::from_c_eff(C::VERIFIED_MIN), C::Verified);
    assert_eq!(C::from_c_eff(C::VERIFIED_MIN - 1e-9), C::Probable);
    assert_eq!(C::from_c_eff(C::PROBABLE_MIN), C::Probable);
    assert_eq!(C::from_c_eff(C::PROBABLE_MIN - 1e-9), C::Candidate);
    // Non-finite lands in the conservative tier (c_effective clamps, so this
    // is defensive only).
    assert_eq!(C::from_c_eff(f64::NAN), C::Candidate);
    // Entity::classify is exactly from_c_eff over c_effective.
    for conf in [0.1, 0.40, 0.5, 0.74, 0.75, 0.9] {
        let e = Entity::new(EntityKind::Email, "x@example.com", conf, "s");
        assert_eq!(e.classify(), C::from_c_eff(e.c_effective()), "conf {conf}");
    }
}

#[test]
fn with_attr_accumulates_repeated_keys_additively_and_dedups() {
    // Operator full-fidelity policy: a repeated attribute key must RETAIN every
    // distinct value, not let the last write clobber the earlier ones (e.g.
    // several breach rows folded into one evidence record, each with a
    // different gender/DOB). Single-set keys are unchanged.
    let ev = Evidence::new("m", "s").with_attr("country", "AU");
    assert_eq!(ev.attributes.get("country").map(String::as_str), Some("AU"));

    // Distinct values accumulate, first-seen first; a re-asserted value is
    // idempotent (de-duplicated, no "M; F; M" bloat).
    let ev = Evidence::new("m", "s")
        .with_attr("gender", "M")
        .with_attr("gender", "F")
        .with_attr("gender", "M");
    assert_eq!(
        ev.attributes.get("gender").map(String::as_str),
        Some("M; F")
    );
}

#[test]
fn evidence_sources_dedups_sorts_and_spans_entities() {
    use super::{Entity, EntityKind, Evidence, evidence_sources};
    let mut a = Entity::new(EntityKind::Email, "a@x.com", 0.6, "t");
    a.add_evidence(Evidence::new("hibp", "s1"));
    a.add_evidence(Evidence::new("dehashed", "s2"));
    a.add_evidence(Evidence::new("hibp", "s3")); // dup source within an entity
    let mut b = Entity::new(EntityKind::Domain, "x.com", 0.6, "t");
    b.add_evidence(Evidence::new("crtsh", "s4"));
    b.add_evidence(Evidence::new("dehashed", "s5")); // dup source across entities

    let ents = [a, b];
    let got: Vec<&str> = evidence_sources(&ents).into_iter().collect();
    // Deduplicated and sorted (BTreeSet) across the whole slice.
    assert_eq!(got, vec!["crtsh", "dehashed", "hibp"]);
    let empty: &[Entity] = &[];
    assert!(evidence_sources(empty).is_empty());
}

// ── is_enrichment_source ──────────────────────────────────────────────────────

#[test]
fn is_enrichment_source_only_for_deterministic_passes() {
    assert!(is_enrichment_source("geo_normalize"));
    assert!(!is_enrichment_source("hibp"));
    assert!(!is_enrichment_source(""));
}

// ── has_evidence_from ─────────────────────────────────────────────────────────

#[test]
fn has_evidence_from_is_exact_source_match() {
    let mut e = Entity::new(EntityKind::Email, "a@b.com", 0.5, "s");
    e.add_evidence(Evidence::new("hibp", "breach"));
    assert!(e.has_evidence_from("hibp"));
    assert!(!e.has_evidence_from("dehashed"));
    // Exact, not substring.
    assert!(!e.has_evidence_from("hib"));
}

// ── absorb ────────────────────────────────────────────────────────────────────

#[test]
fn absorb_folds_signal_and_preserves_identity() {
    let mut a = Entity::new(EntityKind::Address, "X, NSW", 0.40, "s");
    a.corroboration = 2;
    a.observed_at = 100;
    a.add_evidence(Evidence::new("wigle", "geo"));
    a.tag("alpha");
    let original_uid = a.uid.clone();

    let mut b = Entity::new(EntityKind::Address, "X, NSW 2582", 0.70, "s");
    b.corroboration = 3;
    b.observed_at = 250;
    b.add_evidence(Evidence::new("exif", "geo"));
    b.add_evidence(Evidence::new("wigle", "geo")); // duplicate (source,summary) — dropped
    b.tag("beta");

    a.absorb(b);

    // Confidence = max, corroboration = saturating sum, recency = max.
    assert!((a.confidence - 0.70).abs() < 1e-9);
    assert_eq!(a.corroboration, 5);
    assert_eq!(a.observed_at, 250);
    // Evidence deduped by (source, summary): wigle/exif only, no duplicate wigle.
    assert_eq!(a.evidence.len(), 2);
    assert!(a.has_evidence_from("exif"));
    // Tags unioned; identity (uid + value) untouched.
    assert!(a.has_tag("alpha") && a.has_tag("beta"));
    assert_eq!(a.uid, original_uid);
    assert_eq!(a.value, "X, NSW");
}

#[test]
fn absorb_merges_new_attributes_on_same_source_summary() {
    // Regression (breach-PII proof): re-observing an entity from the SAME source
    // with the SAME summary but NEW attributes (an updated breach dump) must NOT
    // drop them — they merge into the one deduped record. Previously the whole
    // record was discarded, so a re-import that gained a date_of_birth/tfn lost
    // it and the AU-073/074 rules never fired.
    let mut a = Entity::new(EntityKind::Email, "x@contoso.com", 0.6, "s");
    a.add_evidence(
        Evidence::new("import:dossier", "Breach entry").with_attr("email", "x@contoso.com"),
    );
    let mut b = Entity::new(EntityKind::Email, "x@contoso.com", 0.6, "s");
    b.add_evidence(
        Evidence::new("import:dossier", "Breach entry")
            .with_attr("email", "x@contoso.com")
            .with_attr("date_of_birth", "1980-11-08")
            .with_attr("tfn", "123456782"),
    );
    a.merge(b);

    assert_eq!(
        a.evidence.len(),
        1,
        "still one record (deduped by source+summary)"
    );
    let attrs = &a.evidence[0].attributes;
    assert_eq!(
        attrs.get("date_of_birth").map(String::as_str),
        Some("1980-11-08")
    );
    assert_eq!(attrs.get("tfn").map(String::as_str), Some("123456782"));
}

#[test]
fn absorb_attribute_merge_is_order_independent() {
    // A key both records set with DIFFERING values accumulates BOTH distinct
    // observations (the conflict is evidence — e.g. a namesake's other DOB),
    // sorted so the result is identical regardless of merge order (the Determinism
    // Requirement). Matches `with_attr`'s in-record accumulation.
    let mk = |v: &str| {
        let mut e = Entity::new(EntityKind::Email, "x@contoso.com", 0.6, "s");
        e.add_evidence(Evidence::new("src", "sum").with_attr("k", v));
        e
    };
    let mut ab = mk("alpha");
    ab.merge(mk("beta"));
    let mut ba = mk("beta");
    ba.merge(mk("alpha"));
    assert_eq!(
        ab.evidence[0].attributes.get("k"),
        ba.evidence[0].attributes.get("k"),
        "merge order must not change the accumulated value"
    );
    assert_eq!(
        ab.evidence[0].attributes.get("k").map(String::as_str),
        Some("alpha; beta"),
        "both distinct observations are kept (sorted), not one dropped"
    );
}

#[test]
fn absorb_dedups_identically_on_both_branches() {
    // The evidence dedup has two implementations chosen by `len*len <= 256`.
    // Build entities large enough to cross into the HashSet branch (17×17 = 289)
    // and assert the result matches the small-input linear-branch fold of the same
    // logical data: each side contributes its own unique rows, the one shared row
    // (`shared`/`s`) is folded once.
    let build = |n: usize, src: &str| {
        let mut e = Entity::new(EntityKind::Email, "a@b.com", 0.5, "x");
        e.add_evidence(Evidence::new("shared", "s"));
        for i in 0..n {
            e.add_evidence(Evidence::new(src, format!("row{i}")));
        }
        e
    };
    // Small inputs → linear branch (1+2)*(1+2) = 9 ≤ 256.
    let mut small_a = build(2, "a");
    small_a.absorb(build(2, "b"));
    // 1 shared + 2 a-rows + 2 b-rows = 5.
    assert_eq!(small_a.evidence.len(), 5);

    // Large inputs → fingerprint-index branch (1+16)*(1+16) = 289 > 256.
    let mut big_a = build(16, "a");
    let mut big_b = build(16, "b");
    big_b.add_evidence(Evidence::new("shared", "s").with_attr("new", "value"));
    big_a.absorb(big_b);
    // 1 shared + 16 a-rows + 16 b-rows = 33; the shared row folded once.
    assert_eq!(big_a.evidence.len(), 33);
    assert_eq!(
        big_a
            .evidence
            .iter()
            .filter(|e| e.source == "shared")
            .count(),
        1,
        "the shared (source,summary) row must be folded to one on the indexed branch"
    );
    let shared = big_a
        .evidence
        .iter()
        .find(|e| e.source == "shared" && e.summary == "s")
        .expect("shared evidence must remain present");
    assert_eq!(
        shared.attributes.get("new").map(String::as_str),
        Some("value"),
        "duplicates within the incoming batch must merge their attributes"
    );
}

#[test]
fn derived_entity_promotion_source_is_not_an_independent_source() {
    // A `derived` entity whose only real source is its own generator
    // (`email_parse`) must NOT be lifted to two-source agreement by a promotion
    // pass. `source_count` already gated this; `corroborating_sources` did not,
    // so ~20 correlator gates counted it as two independent sources.
    let mut e = Entity::new(EntityKind::Username, "example-user", 0.55, "s");
    e.tag("derived");
    e.add_evidence(Evidence::new(
        "email_parse",
        "Derived from example-user@protonmail.com",
    ));
    e.add_evidence(Evidence::new(
        "multipath_corroboration",
        "Linked across 3 independent pathways",
    ));
    assert_eq!(e.corroborating_sources().len(), 1);
    assert!(e.corroborating_sources().contains("email_parse"));
    assert!(
        !e.corroborating_sources()
            .contains("multipath_corroboration")
    );
    // The SET and the COUNT must agree.
    assert_eq!(e.corroborating_sources().len() as u32, e.source_count());
}

#[test]
fn grounded_entity_still_counts_its_promotion_source() {
    // A non-derived entity with one real source IS grounded, so a promotion
    // pass legitimately adds breadth: two distinct corroborating sources.
    let mut e = Entity::new(EntityKind::Email, "a@b.com", 0.5, "s");
    e.add_evidence(Evidence::new("hibp", "breach"));
    e.add_evidence(Evidence::new("multipath_corroboration", "linked"));
    assert_eq!(e.corroborating_sources().len(), 2);
    assert_eq!(e.corroborating_sources().len() as u32, e.source_count());
}

#[test]
fn corroborating_sources_len_equals_source_count_across_shapes() {
    // The SET and the grounded COUNT agree for every combination of derived-ness
    // and source mix — the invariant that keeps the confidence model and the
    // rule gates from disagreeing.
    let sources = [
        "email_parse",
        "hibp",
        "crtsh",
        "geo_normalize",
        "recall",
        "multipath_corroboration",
        "cross_scan_corroboration",
    ];
    for mask in 0u32..(1 << sources.len()) {
        for derived in [false, true] {
            let mut e = Entity::new(EntityKind::Username, "x", 0.4, "s");
            if derived {
                e.tag("derived");
            }
            for (i, s) in sources.iter().enumerate() {
                if mask & (1 << i) != 0 {
                    e.add_evidence(Evidence::new(*s, "ev"));
                }
            }
            let set = e.corroborating_sources();
            if !set.is_empty() {
                assert_eq!(
                    set.len() as u32,
                    e.source_count(),
                    "mask={mask} derived={derived}"
                );
            }
            assert!(set.is_subset(&e.evidence_sources()));
        }
    }
}

// ── Property tests (proptest) ──────────────────────────────────────────────
mod prop {
    use proptest::prelude::*;

    use super::super::{Entity, EntityKind, derive_uid, normalise};

    /// Build a Username entity with a chosen raw spelling, confidence, and
    /// corroboration. Username normalises to lowercase, so case variants share a
    /// UID — the setup for the merge-determinism laws.
    fn mk(raw: &str, conf: f64, corr: u32) -> Entity {
        let mut e = Entity::new(EntityKind::Username, raw, conf, "scan");
        e.corroboration = corr;
        e
    }

    /// Every `EntityKind` — drawn from the exhaustive, tripwire-guarded
    /// [`super::all_kinds`] so the property checks (idempotency, UID determinism,
    /// merge laws) fuzz arbitrary values against *every* `normalise` arm, not a
    /// hand-picked subset. A new kind is swept automatically once it is added to
    /// `all_kinds()` (which a compile-time match forces). This is what surfaces a
    /// shielding non-idempotency the moment a new arm introduces one.
    fn any_kind() -> impl Strategy<Value = EntityKind> {
        prop::sample::select(super::all_kinds())
    }

    proptest! {
        /// `normalise` is **idempotent** for every kind — the UID-stability
        /// invariant. Re-normalising an already-normalised value must be a fixed
        /// point; otherwise the same real-world entity could key to two different
        /// UIDs across scans (the `www.www.` fixed-point bug class), silently
        /// fragmenting one identity into two and breaking cross-scan dedup.
        #[test]
        fn normalise_is_idempotent(kind in any_kind(), v in ".{0,48}") {
            let once = normalise(&kind, &v);
            let twice = normalise(&kind, &once);
            prop_assert_eq!(&once, &twice, "kind={:?} value={:?}", kind, v);
        }

        /// `derive_uid` is a pure, total function of `(kind, normalised value)`:
        /// equal inputs yield the equal UID, and it never panics on arbitrary
        /// (possibly multibyte/control-char) normalised text.
        #[test]
        fn derive_uid_is_deterministic(kind in any_kind(), v in ".{0,48}") {
            let n = normalise(&kind, &v);
            prop_assert_eq!(derive_uid(&kind, &n), derive_uid(&kind, &n));
        }

        /// `merge`'s GREATEST-semantics on the corroborating signal (PROBLEM_TREE
        /// determinism invariant): confidence folds to the **clamped max** (never
        /// decreases, stays in [0,1]); corroboration folds to the **saturating
        /// sum floored at 1** (never decreases). A regression that let a merge
        /// *lower* confidence or drop corroboration would silently erode a
        /// cross-correlated finding.
        #[test]
        fn merge_signal_is_greatest_semantics(
            v in "[a-z]{1,12}",
            ca in 0.0f64..=1.0, cb in 0.0f64..=1.0,
            cra in 1u32..100_000, crb in 1u32..100_000,
        ) {
            let a = mk(&v, ca, cra);
            let b = mk(&v, cb, crb);
            prop_assert_eq!(&a.uid, &b.uid); // same normalised value ⇒ same UID
            let mut merged = a.clone();
            merged.merge(b);
            prop_assert!((0.0..=1.0).contains(&merged.confidence));
            prop_assert!((merged.confidence - ca.max(cb)).abs() < 1e-12);
            prop_assert!(merged.confidence >= a.confidence);
            prop_assert_eq!(merged.corroboration, cra.saturating_add(crb).max(1));
            prop_assert!(merged.corroboration >= a.corroboration);
        }

        /// `merge` is **order-independent** on the persisted signal — the property
        /// that makes concurrent dispatch deterministic. Two raw spellings that
        /// share a UID (case variants), merged in either order, yield the same
        /// canonical `raw_value` (lexicographic min), `value`, confidence, and
        /// corroboration, so the dossier never leaks task-completion order.
        ///
        /// Runs over `Person` as well as `Username`, and generates whitespace-run
        /// variants: `Username` normalises to lowercase, so its same-UID entities
        /// always share one `value` and the `value` limb of this property is
        /// vacuous for it. `Person` is case- and whitespace-FOLDED at UID
        /// derivation only, so it is the kind that can actually break the law —
        /// while this property covered `Username` alone it was structurally blind
        /// to the one case that failed.
        #[test]
        fn merge_is_order_independent(
            v in "[a-z]{1,8}", upper in any::<bool>(),
            person in any::<bool>(), double_space in any::<bool>(),
            ca in 0.0f64..=1.0, cb in 0.0f64..=1.0,
            cra in 1u32..100_000, crb in 1u32..100_000,
        ) {
            let kind = if person { EntityKind::Person } else { EntityKind::Username };
            let mk2 = |raw: &str, conf: f64, corr: u32| {
                let mut e = Entity::new(kind.clone(), raw, conf, "scan");
                e.corroboration = corr;
                e
            };
            // For Person, a spacing variant still folds to one UID — the exact
            // shape ("Jeremy  Stewart" vs "Jeremy Stewart") that used to persist
            // whichever spelling merged first.
            let raw_a = if person && double_space { format!("{v}  {v}") } else { v.clone() };
            let base_b = if person && double_space { format!("{v} {v}") } else { v.clone() };
            let raw_b = if upper { base_b.to_uppercase() } else { base_b };

            let mut ab = mk2(&raw_a, ca, cra);
            ab.merge(mk2(&raw_b, cb, crb));
            ab.canonicalize_order();
            let mut ba = mk2(&raw_b, cb, crb);
            ba.merge(mk2(&raw_a, ca, cra));
            ba.canonicalize_order();

            prop_assert_eq!(&ab.uid, &ba.uid);
            prop_assert_eq!(&ab.raw_value, &ba.raw_value);
            prop_assert_eq!(&ab.value, &ba.value);
            prop_assert!((ab.confidence - ba.confidence).abs() < 1e-12);
            prop_assert_eq!(ab.corroboration, ba.corroboration);
        }

        /// `c_effective` is a well-behaved confidence model for EVERY source count:
        /// it stays in `[0, 1]` and finite, is never below the base `confidence`
        /// (corroboration only ever ADDS confidence — the `max(mult, agreement)`
        /// design), is monotonic non-decreasing in the number of sources, and is
        /// TOTAL — `n = 0` is floored to `1`, so no `ln(0)` / `γ^(-1)` NaN or
        /// sub-base value can escape the public `c_effective_with_source_count`.
        #[test]
        fn c_effective_is_bounded_monotonic_and_at_least_confidence(
            v in "[a-z]{1,12}", conf in 0.0f64..=1.0, n in 0u32..64,
        ) {
            let e = mk(&v, conf, 1);
            let c_n = e.c_effective_with_source_count(n);
            let c_n1 = e.c_effective_with_source_count(n + 1);
            // Bounded and finite.
            prop_assert!((0.0..=1.0).contains(&c_n), "c_eff out of range: {}", c_n);
            prop_assert!(c_n.is_finite());
            // Never below the base confidence (n floored at 1 ⇒ C_eff ≥ confidence).
            prop_assert!(c_n + 1e-12 >= e.confidence, "c_eff {} < conf {}", c_n, e.confidence);
            // n = 0 is the totality guard: identical to n = 1, never a NaN/sub-base.
            prop_assert!(
                (e.c_effective_with_source_count(0) - e.c_effective_with_source_count(1)).abs()
                    < 1e-12
            );
            // Monotonic non-decreasing in the source count.
            prop_assert!(c_n1 + 1e-12 >= c_n, "c_eff not monotonic: {} -> {}", c_n, c_n1);
        }
    }
}

// ── Identity vs display: one person, one node ───────────────────────────────

/// The observed fragmentation, pinned. One person spelled three ways by three
/// sources produced three UIDs — and therefore three graph nodes, each holding
/// only its own source's evidence.
#[test]
fn person_case_and_spacing_variants_resolve_to_one_identity() {
    let variants = [
        "Jeremy Stewart",
        "jeremy stewart",
        "JEREMY STEWART",
        "Jeremy  Stewart",
        "  Jeremy Stewart  ",
    ];
    let uids: std::collections::BTreeSet<String> = variants
        .iter()
        .map(|v| Entity::new(EntityKind::Person, *v, 0.7, "s").uid)
        .collect();
    assert_eq!(
        uids.len(),
        1,
        "one person must be one node; got {} distinct UIDs from {variants:?}",
        uids.len()
    );
}

/// Identity folding must not cost display quality: the dossier still shows the
/// name as the source spelled it. This is the reason the fold lives in
/// `derive_uid` rather than in `normalise`, whose output IS the display value.
#[test]
fn folding_identity_does_not_downcase_the_displayed_name() {
    let e = Entity::new(EntityKind::Person, "Jeremy Stewart", 0.7, "s");
    assert_eq!(e.value, "Jeremy Stewart", "display value is preserved");
    assert_eq!(e.raw_value, "Jeremy Stewart");
}

/// The symptom this actually cures. The engine derives the SEED's UID from the
/// operator's target string via `derive_uid`, while modules derive theirs from
/// whatever spelling they emit. When those disagree the seed is an isolated node
/// and every derived edge attaches to a twin it cannot reach — "the subject has
/// no derived connections yet", on a graph holding thousands of edges.
#[test]
fn a_seed_and_the_entity_its_modules_emit_are_the_same_node() {
    // Exactly what `core::engine` does for the seed.
    let typed = "Jeremy Stewart";
    let seed_uid = derive_uid(&EntityKind::Person, &normalise(&EntityKind::Person, typed));
    // What a module emits after a breach source lower-cased it.
    let emitted = Entity::new(EntityKind::Person, "jeremy stewart", 0.7, "s");
    assert_eq!(
        seed_uid, emitted.uid,
        "the seed must BE the node its own modules populate"
    );
}

/// Organisations carry the same free-text spelling variance as people.
#[test]
fn organisation_case_variants_resolve_to_one_identity() {
    let a = Entity::new(EntityKind::Organisation, "Acme Corp", 0.7, "s");
    let b = Entity::new(EntityKind::Organisation, "ACME  CORP", 0.7, "s");
    assert_eq!(a.uid, b.uid);
    assert_eq!(
        a.value, "Acme Corp",
        "display is still the original spelling"
    );
}

/// `merge` must canonicalise the DISPLAY value, not just `raw_value`.
///
/// `identity_fold` deliberately makes `uid` insensitive to case and whitespace
/// runs for `Person`/`Organisation` while `normalise` leaves `value` untouched —
/// so these are the only two kinds where same-UID entities can hold *different*
/// `value` strings. `merge` canonicalised `raw_value` (citing the Determinism
/// Requirement) but never `value`, so the surviving display spelling was decided
/// by module completion order: two runs of one scan produced diffing dossiers.
///
/// The pre-existing `merge_is_order_independent` property could not catch this —
/// its `mk` helper builds a `Username`, whose `normalise` lowercases, so its
/// same-UID entities always share one `value`. The property was structurally
/// blind to the only kinds that can fail it.
#[test]
fn merge_canonicalises_the_display_value_not_just_raw_value() {
    // Two real sources: a registry that shouts, and a scraper that title-cases.
    let a = Entity::new(EntityKind::Person, "JEREMY STEWART", 0.6, "scan");
    let b = Entity::new(EntityKind::Person, "Jeremy Stewart", 0.6, "scan");
    assert_eq!(a.uid, b.uid, "precondition: one person, one node");

    let mut ab = a.clone();
    ab.merge(b.clone());
    ab.canonicalize_order();
    let mut ba = b.clone();
    ba.merge(a.clone());
    ba.canonicalize_order();

    assert_eq!(
        ab.raw_value, ba.raw_value,
        "raw_value was already canonical"
    );
    assert_eq!(
        ab.value, ba.value,
        "display value must not depend on merge order"
    );

    // Organisation folds identically, and adds the whitespace-run case: the
    // surviving spelling must not be the double-spaced one.
    let x = Entity::new(EntityKind::Organisation, "ACME  CORP", 0.6, "scan");
    let y = Entity::new(EntityKind::Organisation, "Acme Corp", 0.6, "scan");
    assert_eq!(x.uid, y.uid);
    let mut xy = x.clone();
    xy.merge(y.clone());
    let mut yx = y.clone();
    yx.merge(x.clone());
    assert_eq!(xy.value, yx.value, "org display value must be order-free");
}

/// SSIDs are case-SENSITIVE by IEEE 802.11 — folding them would merge two
/// genuinely different networks, which for a geolocation tool is a false
/// identity claim about a physical place.
#[test]
fn ssids_are_never_folded_because_case_is_significant() {
    let a = Entity::new(EntityKind::Ssid, "HomeNet", 0.7, "s");
    let b = Entity::new(EntityKind::Ssid, "homenet", 0.7, "s");
    assert_ne!(a.uid, b.uid, "two distinct networks must stay distinct");
}

/// Every kind that already canonicalises in `normalise` must hash exactly as it
/// did before the fold existed — the change is scoped to free-text name kinds,
/// and a silent UID shift elsewhere would strand persisted entities.
#[test]
fn identifier_kinds_keep_their_pre_existing_uids() {
    for (kind, value) in [
        (EntityKind::Email, "Alice@Example.COM"),
        (EntityKind::Username, "@Alice"),
        (EntityKind::Domain, "Example.com."),
        (EntityKind::IpAddress, "1.1.1.1"),
        (EntityKind::Url, "https://example.com/a"),
    ] {
        let normalised = normalise(&kind, value);
        // The fold must be a no-op for these: UID == hash of the normalised
        // value with no further transformation.
        assert_eq!(
            Entity::new(kind.clone(), value, 0.7, "s").uid,
            derive_uid(&kind, &normalised),
            "{kind} UID must be unchanged by identity folding"
        );
    }
}
