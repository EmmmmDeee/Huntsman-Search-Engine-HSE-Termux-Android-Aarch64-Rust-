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
fn uncorroborated_recycled_is_gated_until_a_second_source_confirms() {
    // Regression: a value scraped only from a recycled search snippet (the
    // lowest-reliability discovery path) must NOT be promoted to an expansion
    // seed on its own — otherwise the recursion budget gets spent pivoting on
    // strangers (a Subway-directory "Austin, Texas", an unrelated contact
    // email). This mirrors the real dossier entity: `search_engines` recycling
    // plus the deterministic `geo_normalize` self-enrichment, which does NOT
    // count as corroboration.
    let mut addr = Entity::new(EntityKind::Address, "Austin, Texas", 0.45, "s");
    addr.tag("search-discovered");
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
    assert_eq!(ev.attributes.get("key1").unwrap(), "val1");
    assert_eq!(ev.attributes.get("key2").unwrap(), "val2");
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
        serde_json::to_string(&ev.attributes).unwrap(),
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
    vec![
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
        Address,
        Coordinates,
        Organisation,
        AbnAcn,
        MacAddress,
        DeviceId,
        CryptoAddress,
        Other("x".into()),
    ]
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
