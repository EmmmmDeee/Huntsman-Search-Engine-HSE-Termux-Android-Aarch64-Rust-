use super::analysis::{audit, is_fragment};
use super::types::{AuditEntity, AuditReport, GeoSummary, LogSignals, Severity};

fn ent(kind: &str, value: &str, c: f64, corr: u32, tags: &[&str]) -> AuditEntity {
    AuditEntity {
        kind: kind.into(),
        value: value.into(),
        c_effective: c,
        corroboration: corr,
        sources: vec!["test".into()],
        tags: tags.iter().map(|s| (*s).to_string()).collect(),
    }
}

#[test]
fn quarantined_breach_co_occurrence_is_excluded_from_the_grade() {
    use crate::core::tags;
    // The breach modules deliberately quarantine records that don't match the
    // subject (tag `candidate`). They're already excluded from the scan view,
    // export, and correlator, so the audit must agree: a thorough breach search
    // that quarantined dozens of strangers must NOT be graded as "noise" for raw
    // material it correctly set aside. One real subject finding + three strangers:
    let entities = vec![
        ent("person", "Subject Name", 0.90, 3, &[]),
        ent(
            "person",
            "Stranger One",
            0.30,
            1,
            &[tags::BREACH, tags::CANDIDATE],
        ),
        ent(
            "email",
            "x@dump.example",
            0.30,
            1,
            &[tags::BREACH, tags::CANDIDATE],
        ),
        ent(
            "person",
            "Stranger Three",
            0.30,
            1,
            &[tags::BREACH, tags::CANDIDATE],
        ),
    ];
    let r = audit(&entities, LogSignals::default());
    assert_eq!(r.entity_total, 1, "only the actionable entity is graded");
    assert_eq!(r.tiers, (1, 0, 0), "1 verified, zero candidate noise");
    assert_eq!(
        r.quarantined, 3,
        "the strangers are reported separately, not as noise"
    );
    assert!(
        r.noise_ratio < 1e-9,
        "the operator's actionable view is clean → 0% noise"
    );
}

#[test]
fn empty_scan_is_flagged_not_scored_as_clean() {
    // A 0-entity scan must NOT score a misleading 100/100 "well-sourced": it
    // is flagged with an `empty-result` finding and drops out of the A band.
    let r = audit(&[], LogSignals::default());
    let f = r
        .findings
        .iter()
        .find(|f| f.category == "empty-result")
        .expect("empty scan must surface an empty-result finding");
    assert_eq!(f.severity, Severity::High);
    assert!(
        r.score < 90,
        "an empty scan must not grade as A, got {}",
        r.score
    );
    // A non-empty scan must NOT get the empty-result finding.
    let nonempty = audit(
        &[ent("email", "a@b.com", 1.0, 2, &[])],
        LogSignals::default(),
    );
    assert!(
        !nonempty
            .findings
            .iter()
            .any(|f| f.category == "empty-result")
    );
}

#[test]
fn clean_individualised_scan_scores_high() {
    let ents = vec![
        ent("email", "jordanavery@gmail.com", 1.0, 4, &[]),
        ent("username", "jordanavery", 1.0, 3, &[]),
        ent("person", "Jordan Avery", 0.8, 2, &[]),
        ent("address", "Ellington, Connecticut", 0.7, 2, &[]),
        ent("url", "https://gravatar.com/jordanavery", 0.6, 1, &[]),
    ];
    let r = audit(&ents, LogSignals::default());
    assert!(
        r.score >= 90,
        "clean scan should score high, got {}",
        r.score
    );
    assert!(
        !r.findings
            .iter()
            .any(|f| f.category == "infrastructure-pollution"),
        "no infra in a clean scan"
    );
}

#[test]
fn infrastructure_pollution_is_flagged_critical() {
    // The exact failure from the real screenshots.
    let ents = vec![
        ent(
            "ip_address",
            "172.66.147.185",
            1.0,
            258,
            &["cloudflare", "hosting"],
        ),
        ent("ip_address", "104.20.37.187", 1.0, 268, &["cloudflare"]),
        ent("email", "dns@cloudflare.com", 1.0, 2, &[]),
        ent("email", "abuse@cloudflare.com", 1.0, 1, &[]),
        ent("domain", "cloudflare.com", 1.0, 5, &[]),
    ];
    let r = audit(&ents, LogSignals::default());
    let f = r
        .findings
        .iter()
        .find(|f| f.category == "infrastructure-pollution")
        .expect("must flag infra pollution");
    assert_eq!(f.severity, Severity::Critical);
    assert!(
        r.score < 80,
        "infra pollution must hurt the score, got {}",
        r.score
    );
}

#[test]
fn fragment_values_are_detected() {
    assert!(is_fragment("email", "@gmail"));
    assert!(is_fragment("email", "matthew@"));
    assert!(is_fragment("email", "a@b")); // no dot in domain
    assert!(is_fragment("url", "example.com/path")); // no scheme
    assert!(is_fragment("domain", "ab")); // too short / no dot
    assert!(!is_fragment("email", "real.person@onet.eu"));
    assert!(!is_fragment("url", "https://x.com/u"));
    assert!(!is_fragment("domain", "example.com"));

    let ents = vec![ent("email", "@gmail", 0.5, 1, &[])];
    let r = audit(&ents, LogSignals::default());
    assert!(r.findings.iter().any(|f| f.category == "fragment-values"));
}

#[test]
fn log_parser_defect_is_surfaced() {
    let mut log = LogSignals::default();
    log.engine_parser_defects.push("brave".into());
    log.lines_parsed = 100;
    let r = audit(&[], log);
    assert!(
        r.findings
            .iter()
            .any(|f| f.category == "engine-parser-defect" && f.severity == Severity::High)
    );
}

#[test]
fn heavy_identity_gating_surfaces_recall_risk() {
    // Few entities kept, many username/person pivots suppressed → the
    // wrong-identity gate dominated the result. That is a recall blind spot
    // and must be surfaced (MEDIUM) with the --expand-all-identities tip.
    let ents = vec![ent("email", "x@y.com", 1.0, 2, &[])];
    let mut log = LogSignals::default();
    log.excluded_reasons.insert("identity_mismatch".into(), 12);
    let r = audit(&ents, log);
    let f = r
        .findings
        .iter()
        .find(|f| f.category == "recursion-recall")
        .expect("recall finding");
    assert_eq!(f.severity, Severity::Medium);
    assert!(f.recommendation.contains("--expand-all-identities"));
}

#[test]
fn non_recall_exclusions_are_info_only() {
    // Dedup / terminal-kind exclusions are expected; they must appear as
    // INFO context (zero score penalty), never as a recall finding.
    let ents = vec![ent("email", "x@y.com", 1.0, 2, &[])];
    let mut log = LogSignals::default();
    log.excluded_reasons
        .insert("already_dispatched_this_scan".into(), 40);
    log.excluded_reasons.insert("non_pivotable_kind".into(), 5);
    let r = audit(&ents, log);
    let f = r
        .findings
        .iter()
        .find(|f| f.category == "expansion-ledger")
        .expect("ledger finding");
    assert_eq!(f.severity, Severity::Info);
    assert!(!r.findings.iter().any(|f| f.category == "recursion-recall"));
}

#[test]
fn missed_pii_when_email_but_no_person() {
    let ents = vec![ent("email", "x@y.com", 1.0, 2, &[])];
    let r = audit(&ents, LogSignals::default());
    assert!(r.findings.iter().any(|f| f.category == "missed-pii"));
}

#[test]
fn to_json_is_stable_and_complete() {
    let ents = vec![ent("email", "dns@cloudflare.com", 1.0, 1, &[])];
    let j = audit(&ents, LogSignals::default()).to_json();
    assert!(j["score"].as_u64().is_some());
    assert!(
        j["grade"]
            .as_str()
            .unwrap()
            .starts_with(|c: char| c.is_ascii_uppercase())
    );
    assert!(
        j["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| { f["category"] == "role-mailbox-as-pii" })
    );
    assert!(j["source_health"]["engines_down"].is_array());
}

#[test]
fn grade_bands_are_monotonic() {
    let mk = |score: u32| AuditReport {
        entity_total: 0,
        by_kind: vec![],
        tiers: (0, 0, 0),
        noise_ratio: 0.0,
        quarantined: 0,
        findings: vec![],
        score,
        log: LogSignals::default(),
        geo: GeoSummary::default(),
    };
    assert!(mk(95).grade().starts_with("A"));
    assert!(mk(80).grade().starts_with("B"));
    assert!(mk(50).grade().starts_with("D"));
    assert!(mk(10).grade().starts_with("F"));
}

#[test]
fn geo_divergence_flags_an_outlier_against_consensus() {
    // Three nearby fixes (a real metro) + one ~3800 km outlier (a datacenter
    // or mis-geocode). The outlier must be flagged, consensus recognised.
    let ents = vec![
        ent("coordinates", "35.4137,-114.1762", 0.6, 1, &[]), // Bullhead City, AZ
        ent("coordinates", "35.4200,-114.1800", 0.6, 1, &[]),
        ent("coordinates", "35.4000,-114.2000", 0.6, 1, &[]),
        ent("coordinates", "45.5019,-73.5674", 0.4, 1, &[]), // Montreal — outlier
    ];
    let r = audit(&ents, LogSignals::default());
    let f = r
        .findings
        .iter()
        .find(|f| f.category == "geo-divergence")
        .expect("must flag geo divergence");
    assert_eq!(f.severity, Severity::Medium, "consensus exists → medium");
    assert!(r.geo.has_consensus);
    assert_eq!(r.geo.outliers, 1);
    assert!(r.geo.max_spread_km > 1000.0);
    assert!(f.examples.iter().any(|e| e.contains("45.5019")));
}

#[test]
fn geo_consensus_produces_no_finding() {
    let ents = vec![
        ent("coordinates", "35.4137,-114.1762", 0.6, 1, &[]),
        ent("coordinates", "35.4200,-114.1800", 0.6, 2, &[]),
    ];
    let r = audit(&ents, LogSignals::default());
    assert!(!r.findings.iter().any(|f| f.category == "geo-divergence"));
    assert_eq!(r.geo.coord_count, 2);
    assert!(r.geo.max_spread_km < 50.0);
}

/// Regression: `hse radar` / `POST /api/v1/radar` seeds every sweep with a
/// sentinel coordinate (0,0 — "null island") purely so the local-sensor
/// modules, which gate on target KIND and ignore the value, dispatch. Before
/// this fix, `geo_consistency` treated that sentinel as a real competing
/// location claim, so a real GPS/Wi-Fi fix anywhere on Earth (thousands of km
/// from 0,0) triggered a spurious geo-divergence finding on EVERY single
/// radar sweep — dinging the self-audit score for a fixed artifact of how the
/// sweep is seeded, not a genuine source disagreement. This exact shape
/// (one real fix + the `seed`-tagged sentinel) is reproduced from a live
/// scan's debug bundle (scan cdaf0195…), which showed `0.000000,0.000000
/// [seed] — 15802 km from consensus` as a [MEDIUM] finding despite there
/// being only ONE genuine coordinate source.
#[test]
fn radar_sentinel_seed_does_not_trigger_geo_divergence() {
    let ents = vec![
        ent(
            "coordinates",
            "0.000000,0.000000",
            0.9,
            50,
            &["seed", "subject"],
        ),
        ent("coordinates", "-27.587302,152.926999", 0.9, 2, &[]),
        ent("coordinates", "-27.587396,152.926844", 0.9, 2, &[]),
    ];
    let r = audit(&ents, LogSignals::default());
    assert!(
        !r.findings.iter().any(|f| f.category == "geo-divergence"),
        "the radar sentinel must never be compared against real fixes as a \
         location claim: findings = {:?}",
        r.findings
    );
    // The sentinel is excluded entirely — only the 2 real fixes count.
    assert_eq!(r.geo.coord_count, 2);
    assert!(
        r.geo.max_spread_km < 1.0,
        "the 2 real fixes are metres apart"
    );

    // The raw sentinel form (pre-normalisation, "0,0") must be excluded too —
    // `is_radar_sentinel` recognises both the raw and normalised spellings.
    let ents_raw = vec![
        ent("coordinates", "0,0", 0.9, 50, &["seed", "subject"]),
        ent("coordinates", "-27.587302,152.926999", 0.9, 2, &[]),
    ];
    let r_raw = audit(&ents_raw, LogSignals::default());
    assert_eq!(
        r_raw.geo.coord_count, 1,
        "the raw-form sentinel is excluded too"
    );

    // A GENUINE (0,0)-seeded scan is not the radar's use case, but a real
    // subject coordinate anywhere else must still be cross-validated normally
    // — this guard is scoped to the exact sentinel spellings, not "any
    // near-origin value" or "any seed-tagged coordinate".
    let ents_real_seed = vec![
        ent(
            "coordinates",
            "35.4137,-114.1762",
            0.9,
            5,
            &["seed", "subject"],
        ),
        ent("coordinates", "45.5019,-73.5674", 0.4, 1, &[]), // genuine outlier
    ];
    let r_real = audit(&ents_real_seed, LogSignals::default());
    assert!(
        r_real
            .findings
            .iter()
            .any(|f| f.category == "geo-divergence"),
        "a genuine seed coordinate must still be cross-validated against \
         other fixes — only the exact radar sentinel is exempt"
    );
}

#[test]
fn noise_ratio_and_tiers_are_computed() {
    let ents = vec![
        ent("username", "real", 1.0, 2, &[]),
        ent("username", "junk1", 0.3, 1, &[]),
        ent("username", "junk2", 0.3, 1, &[]),
    ];
    let r = audit(&ents, LogSignals::default());
    assert_eq!(r.tiers, (1, 0, 2));
    assert!((r.noise_ratio - 2.0 / 3.0).abs() < 1e-9);
}
