#[test]
fn au080_recurring_cooccurrence_link_fires_on_tagged_pair() {
    use super::rules::rule_au_080_recurring_cooccurrence_link;
    let mut a = Entity::new(EntityKind::Email, "alice@example.com", 0.9, "s");
    // The co-occurrence summary format exactly matches COOCCURRENCE_MARKER prefix.
    a.add_evidence(Evidence::new(
        "cross_scan_history",
        "Co-occurred with `bob@example.com` across 2 earlier scan(s) in the local \
         intelligence database — a recurring association that bridges investigations"
            .to_string(),
    ));
    a.tag("cross-scan-cooccurrence");
    let mut b = Entity::new(EntityKind::Email, "bob@example.com", 0.9, "s");
    b.add_evidence(Evidence::new("breach", "Breach record".to_string()));
    let r = rule_au_080_recurring_cooccurrence_link(&RuleContext::new(&[a, b]), "s", 0);
    assert!(
        !r.is_empty(),
        "AU-080 must fire when a co-occurrence partner is present"
    );
    assert_eq!(r[0].rule_id, "AU-080");
    assert_eq!(r[0].severity, super::Severity::Medium);
    // Hub-level (≥3 scans) escalates to High
    let mut a2 = Entity::new(EntityKind::Email, "alice2@example.com", 0.9, "s");
    a2.add_evidence(Evidence::new(
        "cross_scan_history",
        "Co-occurred with `bob2@example.com` across 3 earlier scan(s) in the local \
         intelligence database — a recurring association that bridges investigations"
            .to_string(),
    ));
    a2.tag("cross-scan-cooccurrence");
    a2.tag("hub-cooccurrence");
    let b2 = Entity::new(EntityKind::Email, "bob2@example.com", 0.9, "s");
    let r2 = rule_au_080_recurring_cooccurrence_link(&RuleContext::new(&[a2, b2]), "s", 0);
    assert!(
        !r2.is_empty(),
        "AU-080 must fire for hub-level co-occurrence"
    );
    assert_eq!(
        r2[0].severity,
        super::Severity::High,
        "hub-level must be High severity"
    );
}

#[test]
fn au080_gates_sub_floor_endpoints_and_bounds_the_tail() {
    use super::rules::rule_au_080_recurring_cooccurrence_link;

    // A corroborated hub that co-occurred with many partners across prior scans.
    let mut hub = Entity::new(EntityKind::Email, "hub@example.com", 0.9, "s");
    const N: usize = 15; // > MAX_PAIRS (12), so the tail must be rolled up
    let mut all: Vec<Entity> = Vec::new();
    for i in 0..N {
        let val = format!("partner{i}@example.com");
        hub.add_evidence(Evidence::new(
            "cross_scan_history",
            format!(
                "Co-occurred with `{val}` across 2 earlier scan(s) in the local \
                 intelligence database — a recurring association that bridges investigations"
            ),
        ));
        all.push(Entity::new(EntityKind::Email, val, 0.9, "s"));
    }
    // One partner is a bare generated candidate below the confidence floor: the
    // recurring pairing with it is noise (regenerated identically every scan) and
    // must be gated out, never counted toward the cap or the rollup.
    hub.add_evidence(Evidence::new(
        "cross_scan_history",
        "Co-occurred with `weakcandidate@example.com` across 2 earlier scan(s) in the local \
         intelligence database — a recurring association that bridges investigations"
            .to_string(),
    ));
    all.push(Entity::new(
        EntityKind::Email,
        "weakcandidate@example.com",
        0.30,
        "s",
    ));
    hub.tag("cross-scan-cooccurrence");
    all.insert(0, hub);

    let r = rule_au_080_recurring_cooccurrence_link(&RuleContext::new(&all), "s", 0);

    // 15 above-floor pairs → 12 ranked + 1 rollup = 13; the 0.30 candidate is
    // gated out and never becomes a pair.
    assert_eq!(
        r.len(),
        13,
        "12 strongest pairs kept + 1 honest rollup summary"
    );
    let rollup = r.last().expect("should succeed");
    assert_eq!(
        rollup.severity,
        super::Severity::Low,
        "the rolled-up tail is a low-severity summary"
    );
    assert!(
        rollup
            .description
            .contains("3 further recurring co-occurrence"),
        "rollup must state the 3 suppressed pairs, not drop them silently — got: {}",
        rollup.description
    );
    assert!(
        r.iter().all(|c| !c.description.contains("weakcandidate")),
        "a sub-floor generated candidate must be gated out of AU-080 entirely"
    );
}

#[test]
fn au081_canonical_person_name_match_fires_on_cross_source_same_name() {
    use super::rules::rule_au_081_canonical_person_name_match;
    // Two Person entities: one from a breach (family "breach"), one from a social
    // profile (family "social"). Same canonical name, different source families.
    let mut breach_p = Entity::new(EntityKind::Person, "Haigen Bamford", 0.8, "s");
    breach_p.add_evidence(Evidence::new("oathnet_pro", "Breach record".to_string()));
    let mut social_p = Entity::new(EntityKind::Person, "HAIGEN BAMFORD", 0.75, "s");
    social_p.add_evidence(Evidence::new("social_probe", "Social profile".to_string()));
    let r =
        rule_au_081_canonical_person_name_match(&RuleContext::new(&[breach_p, social_p]), "s", 0);
    assert!(
        !r.is_empty(),
        "AU-081 must fire for same-name persons from different source families"
    );
    assert_eq!(r[0].rule_id, "AU-081");
    assert_eq!(r[0].severity, super::Severity::High);
    // "Last, First" vs "First Last" must also match
    let mut breach2 = Entity::new(EntityKind::Person, "Bamford, Haigen", 0.8, "s");
    breach2.add_evidence(Evidence::new("dehashed", "Breach record".to_string()));
    let mut social2 = Entity::new(EntityKind::Person, "Haigen Bamford", 0.75, "s");
    social2.add_evidence(Evidence::new("github_user", "GitHub profile".to_string()));
    let r2 =
        rule_au_081_canonical_person_name_match(&RuleContext::new(&[breach2, social2]), "s", 0);
    assert!(
        !r2.is_empty(),
        "AU-081 must match 'Last, First' vs 'First Last' format"
    );
    // Same source must NOT fire
    let mut dup1 = Entity::new(EntityKind::Person, "Haigen Bamford", 0.8, "s");
    dup1.add_evidence(Evidence::new("name_intel", "Derived".to_string()));
    let mut dup2 = Entity::new(EntityKind::Person, "Haigen Bamford", 0.8, "s");
    dup2.add_evidence(Evidence::new("name_intel", "Derived".to_string()));
    let r3 = rule_au_081_canonical_person_name_match(&RuleContext::new(&[dup1, dup2]), "s", 0);
    assert!(
        r3.is_empty(),
        "AU-081 must not fire for identical source sets"
    );
}

#[test]
fn au081_same_family_different_databases_is_not_independent() {
    use super::rules::rule_au_081_canonical_person_name_match;
    // Two Person records with the SAME canonical name, from two DIFFERENT breach
    // databases (`dehashed` and `leakcheck`). Their source strings differ, but
    // `source_family` maps both to "breach" — so they are co-derived, not
    // independent, and the family gate must suppress the match. (Guards the
    // independence contract: distinct database names alone are not independence.)
    let mut dehashed_p = Entity::new(EntityKind::Person, "Haigen Bamford", 0.8, "s");
    dehashed_p.add_evidence(Evidence::new("dehashed", "Breach record".to_string()));
    let mut leakcheck_p = Entity::new(EntityKind::Person, "Haigen Bamford", 0.8, "s");
    leakcheck_p.add_evidence(Evidence::new("leakcheck", "Breach record".to_string()));
    let r = rule_au_081_canonical_person_name_match(
        &RuleContext::new(&[dehashed_p, leakcheck_p]),
        "s",
        0,
    );
    assert!(
        r.is_empty(),
        "two databases of the same source family are not independent — must not fire"
    );
}

#[test]
fn au081_common_name_is_a_medium_lead_not_a_high_assert() {
    use super::rules::rule_au_081_canonical_person_name_match;
    // Two independently-sourced "John Smith" records — a breach dump and a
    // proxycurl profile. The rule cannot tell whether these are one person or
    // two unrelated strangers who happen to share the single most common
    // full-name shape in the anglophone world. Asserting High "same
    // individual" there is a confident false merge; it must be a Medium lead
    // to VERIFY instead. ("smith" is in COMMON_SURNAMES.)
    let mut breach_p = Entity::new(EntityKind::Person, "John Smith", 0.8, "s");
    breach_p.add_evidence(Evidence::new("oathnet_pro", "Breach record".to_string()));
    let mut social_p = Entity::new(EntityKind::Person, "Smith John", 0.75, "s");
    social_p.add_evidence(Evidence::new("proxycurl", "LinkedIn profile".to_string()));
    let r =
        rule_au_081_canonical_person_name_match(&RuleContext::new(&[breach_p, social_p]), "s", 0);
    assert!(
        !r.is_empty(),
        "AU-081 must still fire on a shared canonical name — the discount \
         changes severity, not whether the lead surfaces"
    );
    assert_eq!(
        r[0].severity,
        super::Severity::Medium,
        "a common full name is a high-volume coincidence — must be a Medium \
         lead, not a High identity assertion"
    );
    assert!(
        r[0].description.contains("VERIFY"),
        "a common-name match must be phrased as a lead to verify, not a merge: {}",
        r[0].description
    );

    // Control: a DISTINCTIVE full name (no common token) whose two records agree on
    // order — here via an explicit "Last, First" comma — stays a High identity
    // bridge; the common-surname discount must not blunt genuine matches.
    let mut breach_d = Entity::new(EntityKind::Person, "Haigen Bamford", 0.8, "s");
    breach_d.add_evidence(Evidence::new("oathnet_pro", "Breach record".to_string()));
    let mut social_d = Entity::new(EntityKind::Person, "Bamford, Haigen", 0.75, "s");
    social_d.add_evidence(Evidence::new("proxycurl", "LinkedIn profile".to_string()));
    let rd =
        rule_au_081_canonical_person_name_match(&RuleContext::new(&[breach_d, social_d]), "s", 0);
    assert!(!rd.is_empty(), "AU-081 must fire on the distinctive name");
    assert_eq!(
        rd[0].severity,
        super::Severity::High,
        "a distinctive full name must remain a High identity bridge"
    );
    assert!(
        rd[0].description.contains("same individual"),
        "a distinctive-name match keeps the confident 'same individual' wording: {}",
        rd[0].description
    );
}

#[test]
fn au081_bare_transposition_is_a_medium_lead_not_a_high_merge() {
    use super::rules::rule_au_081_canonical_person_name_match;
    // "Haigen Bamford" and "Bamford Haigen" (distinctive tokens, neither a common
    // surname) are two plausibly-DIFFERENT people. Matched only by reordering, with
    // no "Last, First" comma to confirm which token is the surname, this is a Medium
    // lead — NOT the High identity merge the sorted-canonical grouping alone asserts.
    let mut breach = Entity::new(EntityKind::Person, "Haigen Bamford", 0.8, "s");
    breach.add_evidence(Evidence::new("oathnet_pro", "Breach record".to_string()));
    let mut social = Entity::new(EntityKind::Person, "Bamford Haigen", 0.75, "s");
    social.add_evidence(Evidence::new("proxycurl", "LinkedIn profile".to_string()));
    let r = rule_au_081_canonical_person_name_match(&RuleContext::new(&[breach, social]), "s", 0);
    assert!(
        !r.is_empty(),
        "AU-081 still surfaces the transposition as a lead"
    );
    assert_eq!(
        r[0].severity,
        super::Severity::Medium,
        "a bare (comma-less) transposition of a distinctive name is a Medium lead"
    );
    assert!(
        r[0].description.contains("VERIFY"),
        "a transposition match must be phrased as a lead to verify: {}",
        r[0].description
    );

    // Control: the same two tokens, but one record declares surname-first with a
    // comma — the order is confirmed, so the distinctive-name match is High.
    let mut breach_c = Entity::new(EntityKind::Person, "Haigen Bamford", 0.8, "s");
    breach_c.add_evidence(Evidence::new("oathnet_pro", "Breach record".to_string()));
    let mut social_c = Entity::new(EntityKind::Person, "Bamford, Haigen", 0.75, "s");
    social_c.add_evidence(Evidence::new("proxycurl", "LinkedIn profile".to_string()));
    let rc =
        rule_au_081_canonical_person_name_match(&RuleContext::new(&[breach_c, social_c]), "s", 0);
    assert_eq!(rc.len(), 1);
    assert_eq!(
        rc[0].severity,
        super::Severity::High,
        "a comma-confirmed 'Last, First' order makes the distinctive-name match High"
    );
}

#[test]
fn au081_hyphenated_surname_does_not_collide_with_unrelated_three_token_name() {
    use super::rules::rule_au_081_canonical_person_name_match;
    // Regression: the rule used to tokenise on '-' and '.' as if they were word
    // separators, so a hyphenated compound surname ("Smith-Jones") reduced to
    // the SAME sorted token set as an unrelated space-separated name
    // ("Smith Jones") — and unlike a bare reordering, `is_bare_transposition`
    // did not catch this: the tokens' ORIGINAL order was identical too (the
    // hyphen split lined up with the space split), so it fired as a full,
    // undamped match. The shared `name_word_tokens` tokeniser preserves the
    // hyphen inside its token, so the two names no longer share a canonical
    // form at all — same defect class, same fix, as
    // `core::resolve::canonical_name`'s identical regression test.
    let mut breach = Entity::new(EntityKind::Person, "Anna Smith-Jones", 0.8, "s");
    breach.add_evidence(Evidence::new("oathnet_pro", "Breach record".to_string()));
    let mut social = Entity::new(EntityKind::Person, "Anna Smith Jones", 0.75, "s");
    social.add_evidence(Evidence::new("proxycurl", "LinkedIn profile".to_string()));
    let r = rule_au_081_canonical_person_name_match(&RuleContext::new(&[breach, social]), "s", 0);
    assert!(
        r.is_empty(),
        "a hyphenated compound surname must not collide with an unrelated \
         space-separated name: {r:?}"
    );
}

#[test]
fn au081_tool_derived_name_is_not_independent_corroboration() {
    use super::rules::rule_au_081_canonical_person_name_match;
    // The manufactured-corroboration hole: one Person is a REAL record from a
    // code-hosting profile (`github_user` → family "code"); the other carries the
    // SAME canonical name but its ONLY evidence is `name_intel` — the tool's own
    // firstname/lastname permutation of the seed (a non-corroborating enrichment
    // pass that maps to the real "identity_registry" family). Their source
    // strings differ AND their families differ, so the old raw-`evidence` gates
    // both passed and AU-081 fired a High "independently-sourced records for the
    // same individual". But `name_intel` did not independently OBSERVE anyone — it
    // derived the name from the seed — so this is the tool corroborating itself.
    // The finding must NOT fire.
    let mut real = Entity::new(EntityKind::Person, "Haigen Bamford", 0.8, "s");
    real.add_evidence(Evidence::new("github_user", "GitHub profile".to_string()));
    let mut derived = Entity::new(EntityKind::Person, "Bamford, Haigen", 0.7, "s");
    derived.add_evidence(Evidence::new("name_intel", "Derived from name".to_string()));
    let r = rule_au_081_canonical_person_name_match(&RuleContext::new(&[real, derived]), "s", 0);
    assert!(
        r.is_empty(),
        "a name known only from the tool's own derivation (name_intel) is not an \
         independent record — AU-081 must not manufacture corroboration from it"
    );
}

#[test]
fn au081_still_fires_when_a_genuine_second_source_is_also_name_enriched() {
    use super::rules::rule_au_081_canonical_person_name_match;
    // Control for the fix: a legitimate cross-source match must survive even when
    // `name_intel` ALSO enriched one side. `e1` carries a REAL code-hosting source
    // (`github_user` → "code") PLUS the tool's `name_intel` derivation; `e2` is a
    // REAL breach record (`oathnet_pro` → "breach"). After filtering the
    // non-corroborating `name_intel`, both sides still hold a genuine, distinct
    // source family (code vs breach), so the match is real and must fire — the fix
    // refuses `name_intel` as the SOLE independence, it does not blunt a real one.
    let mut e1 = Entity::new(EntityKind::Person, "Haigen Bamford", 0.8, "s");
    e1.add_evidence(Evidence::new("github_user", "GitHub profile".to_string()));
    e1.add_evidence(Evidence::new("name_intel", "Derived from name".to_string()));
    // "Last, First" comma form so the match is order-confirmed (High), isolating
    // this test to the independence gate rather than the transposition discount.
    let mut e2 = Entity::new(EntityKind::Person, "Bamford, Haigen", 0.75, "s");
    e2.add_evidence(Evidence::new("oathnet_pro", "Breach record".to_string()));
    let r = rule_au_081_canonical_person_name_match(&RuleContext::new(&[e1, e2]), "s", 0);
    assert!(
        !r.is_empty(),
        "a genuine code+breach cross-source match must still fire even when \
         name_intel also enriched one side"
    );
    assert_eq!(r[0].severity, super::Severity::High);
    // The human-readable label must name the genuine source, never `name_intel`.
    assert!(
        r[0].description.contains("github_user") && !r[0].description.contains("name_intel"),
        "the match must be labelled by its genuine source, not the enrichment pass: {}",
        r[0].description
    );
}

#[test]
fn au082_api_key_dual_pathway_fires_on_code_plus_breach() {
    use super::rules::rule_au_082_api_key_dual_pathway;
    use crate::core::entity::{Entity, EntityKind, Evidence};
    // Same API key found in a code repo (github_code_search → code family)
    // and in a breach pool (oathnet_pro → breach family).
    let mut e = Entity::new(EntityKind::ApiKey, "sk-realkey-abc123xyz", 0.85, "s");
    e.add_evidence(Evidence::new(
        "github_code_search",
        "Found in public repository".to_string(),
    ));
    e.add_evidence(Evidence::new(
        "oathnet_pro",
        "Found in stealer log".to_string(),
    ));
    let r = rule_au_082_api_key_dual_pathway(&RuleContext::new(&[e]), "s", 0);
    assert!(
        !r.is_empty(),
        "AU-082 must fire when same API key appears in code+breach families"
    );
    assert_eq!(r[0].rule_id, "AU-082");
    assert_eq!(r[0].severity, super::Severity::Critical);
    // Single-family key must NOT fire AU-082 (AU-021 handles that).
    let mut single = Entity::new(EntityKind::ApiKey, "sk-only-breach", 0.85, "s");
    single.add_evidence(Evidence::new("oathnet_pro", "Stealer".to_string()));
    let r2 = rule_au_082_api_key_dual_pathway(&RuleContext::new(&[single]), "s", 0);
    assert!(
        r2.is_empty(),
        "AU-082 must not fire for a single-family API key"
    );
}

#[test]
fn au082_does_not_fire_on_a_recall_replay_of_the_same_sighting() {
    // Regression: a single genuine sighting (github_code_search → "code") plus
    // the SAME observation re-attached by the `recall` replay pass (a prior
    // scan's evidence re-injected, not a new independent sighting) must NOT
    // read as a second "source family". Before the fix, `recall` fell through
    // to the unclassified "other" bucket, so `{code, other}.len() >= 2`
    // trivially fired a false Critical "dual-pathway... key was already
    // circulating outside the original leak" alert from one real sighting.
    use super::rules::rule_au_082_api_key_dual_pathway;
    use crate::core::entity::{Entity, EntityKind, Evidence};
    let mut e = Entity::new(EntityKind::ApiKey, "sk-realkey-abc123xyz", 0.85, "s");
    e.add_evidence(Evidence::new(
        "github_code_search",
        "Found in public repository".to_string(),
    ));
    e.add_evidence(Evidence::new(
        crate::core::entity::RECALL_SOURCE,
        "Recalled from a prior scan".to_string(),
    ));
    let r = rule_au_082_api_key_dual_pathway(&RuleContext::new(&[e]), "s", 0);
    assert!(
        r.is_empty(),
        "a recall replay of the same sighting must not manufacture a second \
         source family: {r:?}"
    );

    // A deterministic enrichment pass riding along (geo_normalize/name_intel/
    // payid) must be excluded too — it's a derivation of the input, not an
    // independent observation.
    let mut e2 = Entity::new(EntityKind::ApiKey, "sk-anotherkey-def456", 0.85, "s");
    e2.add_evidence(Evidence::new(
        "github_code_search",
        "Found in public repository".to_string(),
    ));
    e2.add_evidence(Evidence::new("payid", "Derived enrichment".to_string()));
    let r2 = rule_au_082_api_key_dual_pathway(&RuleContext::new(&[e2]), "s", 0);
    assert!(
        r2.is_empty(),
        "an enrichment-pass evidence entry must not manufacture a second \
         source family: {r2:?}"
    );
}

#[test]
fn correlator_budget_stops_starting_new_rules_past_the_deadline() {
    use super::{evaluate_relation_rules_on, evaluate_rules_on};
    // A confirmed entity that WOULD produce correlations under several rules.
    let mut e = Entity::new(EntityKind::Email, "moale.mcknight@gmail.com", 0.72, "s");
    e.tag("name-derived");
    e.add_evidence(Evidence::new("name_intel", "permuted"));
    e.add_evidence(Evidence::new("hibp", "breached"));
    let ents = vec![e];

    // No deadline → rules run normally (AU-086 fires for this predict+confirm email).
    let full = evaluate_rules_on(&RuleContext::new(&ents), "s", 0, None);
    assert!(
        full.iter().any(|c| c.rule_id == "AU-086"),
        "without a budget the confirmed name-derived email must fire AU-086"
    );

    // A deadline already in the past → no rule is started, empty result, no hang.
    let past = Some(std::time::Instant::now() - std::time::Duration::from_secs(1));
    assert!(
        evaluate_rules_on(&RuleContext::new(&ents), "s", 0, past).is_empty(),
        "an elapsed budget must stop the entity-rule pass immediately"
    );
    assert!(
        evaluate_relation_rules_on(&RuleContext::new(&ents), &[], "s", 0, past).is_empty(),
        "an elapsed budget must stop the relation-rule pass immediately"
    );
}

#[test]
fn readme_correlator_rule_count_matches_the_registry() {
    // The README's headline "N correlator rules" is hand-maintained and had
    // drifted badly (it read 74 / "AU-001 through AU-086" against a real total of
    // 110 / AU-112). Pin it to the live dispatch tables — `RULES` (entity rules)
    // plus `RELATION_RULES` (graph-aware rules) — so adding a rule without
    // updating the README fails CI, the same guard the module count already has.
    // Lives here (a `core::correlator` unit test) because both tables are private
    // to this module; the integration `tests/architecture.rs` can't see them.
    let readme = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/README.md"))
        .expect("README.md must exist at the crate root");
    let n = RULES.len() + RELATION_RULES.len();
    let idx = readme
        .find("correlator rules")
        .expect("README must state the correlator rule count as 'N correlator rules'");
    // The integer immediately preceding "correlator rules" (commas stripped).
    let stated: usize = readme[..idx]
        .trim_end()
        .rsplit(|c: char| !c.is_ascii_digit() && c != ',')
        .next()
        .unwrap_or_default()
        .replace(',', "")
        .parse()
        .expect("a numeric rule count must immediately precede 'correlator rules' in README");
    assert_eq!(
        stated,
        n,
        "README says {stated} correlator rules but the registry dispatches {n} \
         (RULES {} + RELATION_RULES {}); update the count in README.md",
        RULES.len(),
        RELATION_RULES.len()
    );
}

// ─── Bench-only entry points (F.3 / SOL-F3) ────────────────────────────────
//
// `bench_synthetic_entities`/`bench_correlate_entities` are wholly new `pub`
// surface added solely so `benches/correlation_pass.rs` (a separate
// compilation unit that only sees this crate's public API) can reach the
// `pub(crate)` correlation pass. Git-stash-provable: the pre-fix tree has
// neither function, so these tests fail to compile against it — the
// strongest possible regression signal for wholly new code, the same
// precedent the 2026-07-14 cargo-fuzz cycle established for
// `fuzz_entry_parse_der`.

/// Canonical JSON encoding of an entity set for equality comparison, with
/// every live-clock field zeroed first: each `Entity::observed_at` and every
/// `Evidence::recorded_at` in its evidence chain.
///
/// Both are stamped from the real wall clock (`unix_now()`, inside
/// `Entity::new`/`Evidence::new`) — `bench_synthetic_entities` calls both for
/// every entity it builds, so despite its own doc comment's "pure and
/// deterministic (no RNG)" claim, two calls a moment apart legitimately
/// produce different `observed_at`/`recorded_at` whenever they straddle a
/// real second boundary. This is the identical bug class
/// [`ts_blind_json`] fixes for `Correlation` just below (see its doc
/// comment for the live-reproduced CI failure this whole family of fixes
/// responds to) — found by checking this file's OTHER full-JSON-equality
/// determinism test for the same latent flakiness rather than assuming it
/// was fine, and confirmed real the same way: forcing a real 1.1s sleep
/// between two calls reliably fails the raw (pre-fix) comparison here too.
fn ts_blind_entities_json(ents: &[Entity]) -> String {
    let blinded: Vec<Entity> = ents
        .iter()
        .cloned()
        .map(|mut e| {
            e.observed_at = 0;
            for ev in &mut e.evidence {
                ev.recorded_at = 0;
            }
            e
        })
        .collect();
    serde_json::to_string(&blinded).expect("should succeed")
}

#[test]
fn bench_synthetic_entities_yields_exactly_n_deterministic_entities() {
    for &n in &[0usize, 1, 4, 37, 200] {
        let a = bench_synthetic_entities(n);
        let b = bench_synthetic_entities(n);
        assert_eq!(
            a.len(),
            n,
            "bench_synthetic_entities({n}) must yield exactly n entities"
        );
        // Neither `Entity` nor `Correlation` derive `PartialEq` (large,
        // evolving structs — see e.g. line ~366's precedent), so compare via
        // their canonical JSON encoding, same as this file already does
        // elsewhere for structural equality — `ts`-blind, see
        // `ts_blind_entities_json`'s own doc comment for why.
        assert_eq!(
            ts_blind_entities_json(&a),
            ts_blind_entities_json(&b),
            "bench_synthetic_entities is documented pure/deterministic (no RNG) — \
             two calls at the same n must produce identical entities (bar the real \
             wall-clock observed_at/recorded_at stamps), or bench-to-bench \
             comparisons and the perf-guard ratio assertion it also feeds \
             (core::correlator::perf) would be meaningless"
        );
    }
}

#[test]
fn bench_synthetic_entities_is_ts_blind_deterministic_across_a_real_second_boundary() {
    // Same forced-race technique as `bench_correlate_entities_is_ts_blind_
    // deterministic_across_a_real_second_boundary` just below — see its doc
    // comment for why a real sleep past a real clock boundary, not a
    // mocked/injected clock.
    let a = bench_synthetic_entities(200);
    std::thread::sleep(std::time::Duration::from_millis(1_100));
    let b = bench_synthetic_entities(200);

    assert_ne!(
        a.first().map(|e| e.observed_at),
        b.first().map(|e| e.observed_at),
        "this test's whole point is to force a real second-boundary crossing \
         between the two calls — if observed_at didn't move, the sleep isn't \
         doing its job and this test isn't actually proving anything"
    );
    assert_eq!(
        ts_blind_entities_json(&a),
        ts_blind_entities_json(&b),
        "entity content must stay identical even when the two calls land in \
         different wall-clock seconds"
    );
}

/// Canonical JSON encoding of a correlation set for equality comparison,
/// with every `ts` zeroed first.
///
/// `ts` is stamped from the real wall clock (`unix_now()`, called fresh
/// inside `evaluate_rules` on every invocation) — it legitimately differs
/// between two calls made a moment apart, whenever they happen to straddle
/// a real second boundary. That's correct behaviour for a field that
/// records *when* a correlation fired, not a determinism defect in the
/// rules themselves. Live-reproduced on 2026-07-15: a real GitHub Actions
/// run failed `bench_correlate_entities_matches_the_internal_pass_and_is_
/// deterministic` with `left`/`right` differing in exactly one respect —
/// every one of 106 findings carried `ts=1784092984` on one side and
/// `ts=1784092985` on the other (rule firings, descriptions, entity_uids,
/// ranks, and ordering were all byte-identical) — because the runner was
/// briefly slow enough for two back-to-back calls to cross a real second.
/// The property this file actually needs to guarantee — that the RULES'
/// decisions (which fire, on which entities, in which order, ranked how)
/// are a pure function of the input — holds regardless; comparing through
/// this `ts`-blind view is what actually tests that, without also
/// asserting something about the OS clock that was never the point.
/// Neither `Correlation` nor `Entity` derive `PartialEq` (see this file's
/// header comment), so equality is still via canonical JSON, same
/// precedent as every other struct-equality check here — just of a
/// `ts`-blind clone rather than the raw value.
fn ts_blind_json(corrs: &[Correlation]) -> String {
    let blinded: Vec<Correlation> = corrs
        .iter()
        .cloned()
        .map(|mut c| {
            c.ts = 0;
            c
        })
        .collect();
    serde_json::to_string(&blinded).expect("should succeed")
}

#[test]
fn bench_correlate_entities_matches_the_internal_pass_and_is_deterministic() {
    let ents = bench_synthetic_entities(200);
    // Delegates straight to `correlate_entities` — must produce byte-identical
    // output (bar the real wall-clock `ts`, see `ts_blind_json`) to calling
    // the internal pass directly, not a divergent copy.
    let via_bench = bench_correlate_entities(&ents, "scan");
    let via_internal = correlate_entities(&ents, "scan");
    assert_eq!(
        ts_blind_json(&via_bench),
        ts_blind_json(&via_internal),
        "bench_correlate_entities must be a pure delegation to correlate_entities, \
         not an independently-drifting copy"
    );
    // Determinism-by-construction: running the pass
    // twice over the same input must yield identical rule decisions — the
    // property the criterion bench and the perf module's
    // `pass_is_subquadratic` guard both implicitly rely on when comparing
    // timings/ratios across runs.
    let again = bench_correlate_entities(&ents, "scan");
    assert_eq!(
        ts_blind_json(&via_bench),
        ts_blind_json(&again),
        "the correlation pass must be deterministic across repeated calls on \
         identical input"
    );
    assert!(
        !bench_correlate_entities(&ents, "scan").is_empty(),
        "the representative synthetic set (shared handles, breach/stealer tags) \
         must exercise at least one firing rule, or the bench would be timing an \
         early-exit no-op rather than real correlation work"
    );
}

#[test]
fn bench_correlate_entities_is_ts_blind_deterministic_across_a_real_second_boundary() {
    // Directly, reliably reproduces the 2026-07-15 live CI failure above
    // instead of relying on the two calls happening to straddle a wall-clock
    // second by luck: sleeps a real 1.1s (guaranteeing `unix_now()`, which
    // truncates to whole seconds, advances by at least one full second
    // between the calls) and confirms `ts` DOES genuinely differ — proving
    // this test is actually exercising the race, not accidentally passing —
    // while the `ts`-blind view stays equal. A real sleep past a real clock
    // boundary, not a mocked/injected clock: the same "exercise real
    // behaviour, don't fake it" discipline this file uses for its other
    // timing-sensitive coverage.
    let ents = bench_synthetic_entities(200);
    let first = correlate_entities(&ents, "scan");
    std::thread::sleep(std::time::Duration::from_millis(1_100));
    let second = correlate_entities(&ents, "scan");

    assert_ne!(
        first.first().map(|c| c.ts),
        second.first().map(|c| c.ts),
        "this test's whole point is to force a real second-boundary crossing \
         between the two calls — if ts didn't move, the sleep isn't doing its \
         job and this test isn't actually proving anything"
    );
    assert_eq!(
        ts_blind_json(&first),
        ts_blind_json(&second),
        "rule firings/attribution/ranking must stay identical even when the \
         two calls land in different wall-clock seconds"
    );
}

/// The condition that voids the whole correlation phase without anyone noticing.
///
/// `confirmed_only` strips `candidate`-quarantined entities, and the rules only
/// ever see what survives. In a real 1081-entity dossier the subject never
/// gained a confirmed location, so `promote_breach_candidate_geo_corroborated`
/// promoted nothing and effectively every breach record stayed quarantined —
/// leaving a handful of entities for the rules. The scan reported 0
/// correlations, which reads as "nothing correlated" when the truth was
/// "almost nothing was examined". Those demand opposite operator responses.
///
/// This pins the shape so the alarm threshold stays meaningful: a scan can be
/// overwhelmingly quarantined, and the examined set is what the correlation
/// count is really a statement about.
#[test]
fn a_mostly_quarantined_scan_leaves_the_rules_almost_nothing_to_examine() {
    let mut ents = vec![ent(
        EntityKind::Email,
        "subject@example.com",
        0.8,
        "s",
        false,
    )];
    for i in 0..99 {
        ents.push(ent(
            EntityKind::Email,
            &format!("breach{i}@example.com"),
            0.25,
            "s",
            true, // candidate-quarantined
        ));
    }

    let examined = confirmed_only(&ents).len();
    let quarantined = ents.len() - examined;
    assert_eq!(examined, 1, "only the confirmed entity reaches the rules");
    assert_eq!(quarantined, 99);

    // The alarm condition the correlator now reports on: under 1/N examined.
    assert!(
        examined * QUARANTINE_ALARM_RATIO < ents.len(),
        "this shape must trip the quarantine alarm"
    );
}

/// The alarm must NOT fire for a healthy scan that merely carries some
/// candidates — quarantining a minority is the system working as intended, and
/// an alarm that cries wolf on normal scans is worse than none.
#[test]
fn a_normally_quarantined_scan_does_not_trip_the_alarm() {
    let mut ents = Vec::new();
    for i in 0..90 {
        ents.push(ent(
            EntityKind::Email,
            &format!("ok{i}@example.com"),
            0.8,
            "s",
            false,
        ));
    }
    for i in 0..10 {
        ents.push(ent(
            EntityKind::Email,
            &format!("cand{i}@example.com"),
            0.25,
            "s",
            true,
        ));
    }
    let examined = confirmed_only(&ents).len();
    assert_eq!(examined, 90);
    assert!(
        examined * QUARANTINE_ALARM_RATIO >= ents.len(),
        "90% examined must not raise an alarm"
    );
}
