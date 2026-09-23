use super::analysis::{audit, is_fragment};
use super::types::{AuditEntity, AuditReport, GeoSummary, LogSignals, Severity};

fn ent(kind: &str, value: &str, c: f64, corr: u32, tags: &[&str]) -> AuditEntity {
    AuditEntity {
        kind: kind.into(),
        value: value.into(),
        c_effective: c,
        corroboration: corr,
        sources: vec!["test".into()],
        corroborating_sources: None,
        tags: tags.iter().map(|s| (*s).to_string()).collect(),
    }
}

/// A coordinate fix from a person-anchoring source (`geocode`): the only kind
/// the geo-consensus check admits (REQ-AUDIT-GEO-001). [`ent`]'s placeholder
/// `"test"` source anchors nothing, so a coordinate built with it is excluded.
fn fix(value: &str, c: f64, corr: u32, tags: &[&str]) -> AuditEntity {
    AuditEntity {
        sources: vec!["geocode".into()],
        ..ent("coordinates", value, c, corr, tags)
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
    // Every one of these five actionable entities is provider infrastructure,
    // and every one is high-confidence (c_effective 1.0), so the candidate tier
    // is empty. The headline noise figure must NOT read 0% while this very
    // report raises a Critical infrastructure-pollution finding about the same
    // rows — that self-contradiction told operators a pure-CDN scan was clean.
    assert!(
        (r.noise_ratio - 1.0).abs() < 1e-9,
        "all five actionable entities are provider infrastructure, so noise must be 100%, got {}",
        r.noise_ratio
    );
}

#[test]
fn infrastructure_noise_does_not_double_count_low_confidence_candidates() {
    // A LOW-confidence infrastructure entity is already inside the candidate
    // tier. Counting it again as infrastructure noise would make one entity
    // contribute two units and could drive the ratio past 1.0.
    let ents = vec![
        ent("ip_address", "172.66.147.185", 0.30, 1, &["cloudflare"]),
        ent("person", "Subject Name", 0.90, 3, &[]),
    ];
    let r = audit(&ents, LogSignals::default());
    assert!(
        (r.noise_ratio - 0.5).abs() < 1e-9,
        "the low-confidence infrastructure entity is one noisy entity, not candidate + infra twice: {}",
        r.noise_ratio
    );
}

#[test]
fn ns_mx_soa_tagged_domains_are_not_infrastructure_pollution() {
    // A domain a DNS-recon module already labelled ns/mx/soa/nameserver is a
    // correctly-attributed record of the subject's OWN zone — not a
    // provider's estate silently entering the graph. Flagging it as
    // "pollution" told the operator to suppress their own scan's DNS recon.
    let ents = vec![
        ent("email", "jordanavery@gmail.com", 1.0, 4, &[]),
        ent("username", "jordanavery", 1.0, 3, &[]),
        ent("domain", "ns7-66.akam.net", 0.9, 1, &["dns", "ns"]),
        ent("domain", "aspmx.l.google.com", 0.95, 1, &["dns", "mx"]),
        ent(
            "domain",
            "ns1.example.com",
            0.9,
            1,
            &["dns", "soa", "nameserver"],
        ),
    ];
    let r = audit(&ents, LogSignals::default());
    assert!(
        !r.findings
            .iter()
            .any(|f| f.category == "infrastructure-pollution"),
        "ns/mx/soa-tagged domains must not be counted as infrastructure pollution"
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
    let mut log = LogSignals::default();
    log.module_timeouts.insert("slow_mod".into(), 3);
    let j = audit(&ents, log).to_json();
    assert!(j["score"].as_u64().is_some());
    assert!(
        j["grade"]
            .as_str()
            .expect("should succeed")
            .starts_with(|c: char| c.is_ascii_uppercase())
    );
    assert!(
        j["findings"]
            .as_array()
            .expect("should succeed")
            .iter()
            .any(|f| { f["category"] == "role-mailbox-as-pii" })
    );
    assert!(j["source_health"]["engines_down"].is_array());
    // The per-module timeout tally is surfaced beside its sibling module_errors,
    // not silently dropped — it is the constrained-Termux signal an operator
    // reads from `hse audit --json` and the web audit endpoint alike.
    assert_eq!(j["source_health"]["module_timeouts"]["slow_mod"], 3);
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
        fix("35.4137,-114.1762", 0.6, 1, &[]), // Bullhead City, AZ
        fix("35.4200,-114.1800", 0.6, 1, &[]),
        fix("35.4000,-114.2000", 0.6, 1, &[]),
        fix("45.5019,-73.5674", 0.4, 1, &[]), // Montreal — outlier
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
        fix("35.4137,-114.1762", 0.6, 1, &[]),
        fix("35.4200,-114.1800", 0.6, 2, &[]),
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
        fix("0.000000,0.000000", 0.9, 50, &["seed", "subject"]),
        fix("-27.587302,152.926999", 0.9, 2, &[]),
        fix("-27.587396,152.926844", 0.9, 2, &[]),
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
        fix("0,0", 0.9, 50, &["seed", "subject"]),
        fix("-27.587302,152.926999", 0.9, 2, &[]),
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
        fix("35.4137,-114.1762", 0.9, 5, &["seed", "subject"]),
        fix("45.5019,-73.5674", 0.4, 1, &[]), // genuine outlier
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

#[test]
fn weak_corroboration_counts_distinct_sources_not_observation_magnitude() {
    // Regression (live andersonbushikai.com scan, debug bundle 6b2d34664852…):
    // the audit reported "76% of entities have a single source" when 14 of the
    // 17 entities carried source_count=1 — 82%. It filtered on `corroboration`,
    // the summed per-module observation MAGNITUDE, rather than the count of
    // distinct sources. `Entity::source_count`'s own doc warns about exactly
    // this: summed within-module counts "are NOT a count of independent
    // sources", and using them "over-credited single-source findings".
    //
    // The bundle's shape: `mail.andersonbushikai.com` had one source
    // (`dns_intel`) but corroboration=2 — two records from the SAME module — so
    // it was scored as corroborated and the single-source share was understated.
    let mut entities: Vec<AuditEntity> = Vec::new();
    for i in 0..13 {
        let mut e = ent("domain", &format!("single{i}.example.com"), 0.8, 1, &[]);
        e.sources = vec!["dns_intel".into()];
        entities.push(e);
    }
    // One source, but two same-module records — the entity the old check missed.
    let mut magnitude_only = ent("domain", "mail.example.com", 0.8, 2, &[]);
    magnitude_only.sources = vec!["dns_intel".into()];
    entities.push(magnitude_only);
    // Genuinely corroborated: three distinct sources.
    for i in 0..3 {
        let mut e = ent("domain", &format!("multi{i}.example.com"), 0.9, 3, &[]);
        e.sources = vec!["dns_intel".into(), "doh_resolver".into(), "crtsh".into()];
        entities.push(e);
    }
    assert_eq!(entities.len(), 17);

    let r = audit(&entities, LogSignals::default());
    let f = r
        .findings
        .iter()
        .find(|f| f.category == "weak-corroboration")
        .expect("14 of 17 single-source must raise the finding");
    assert!(
        f.message.starts_with("82%"),
        "must report the distinct-source share (14/17 = 82%), got {:?}",
        f.message
    );
}

#[test]
fn weak_corroboration_ignores_non_corroborating_sources() {
    // A `seed` or `url_extract` record is the operator's own input restated, not
    // an independent sighting, so an entity backed only by one real lookup plus
    // one of those is still single-source for this finding — the same rule
    // `Entity::source_count` applies.
    let mut entities: Vec<AuditEntity> = Vec::new();
    for i in 0..14 {
        let mut e = ent("domain", &format!("d{i}.example.com"), 0.8, 1, &[]);
        e.sources = vec!["dns_intel".into(), "seed".into(), "url_extract".into()];
        entities.push(e);
    }
    for i in 0..3 {
        let mut e = ent("domain", &format!("m{i}.example.com"), 0.9, 2, &[]);
        e.sources = vec!["dns_intel".into(), "doh_resolver".into()];
        entities.push(e);
    }
    let r = audit(&entities, LogSignals::default());
    let f = r
        .findings
        .iter()
        .find(|f| f.category == "weak-corroboration")
        .expect("seed/url_extract must not mask single-source dominance");
    assert!(f.message.starts_with("82%"), "got {:?}", f.message);
}

#[test]
fn weak_corroboration_reads_the_per_record_verdict_of_a_stored_entity() {
    // REQ-GEO-008 / REQ-CORE-017: an annotation of the value (a point lookup)
    // and a name-only register match do not corroborate, so a stored entity
    // backed by one real source plus those is single-source here exactly as
    // `Entity::source_count` says — its source NAMES alone would read as three.
    use crate::core::entity::{Entity, EntityKind, Evidence, VerificationMethod};
    let mut entities: Vec<AuditEntity> = Vec::new();
    for i in 0..14 {
        let mut e = Entity::new(
            EntityKind::Coordinates,
            format!("-33.86{i},151.2"),
            0.72,
            "s",
        );
        e.add_evidence(Evidence::new("search_engines", "centroid"));
        e.add_evidence(Evidence::new("au_geo", "ASGS").as_annotation());
        e.add_evidence(
            Evidence::new("qld_unclaimed", "row").with_verification(VerificationMethod::Unverified),
        );
        let a = AuditEntity::from_entity(&e);
        assert_eq!(a.sources.len(), 3);
        assert_eq!(a.corroborating_source_count(), 1);
        entities.push(a);
    }
    for i in 0..3 {
        let mut e = ent("domain", &format!("m{i}.example.com"), 0.9, 2, &[]);
        e.sources = vec!["dns_intel".into(), "doh_resolver".into()];
        entities.push(e);
    }
    let r = audit(&entities, LogSignals::default());
    let f = r
        .findings
        .iter()
        .find(|f| f.category == "weak-corroboration")
        .expect("annotations and name-only matches must not mask single-source dominance");
    assert!(f.message.starts_with("82%"), "got {:?}", f.message);
}

/// REQ-AUDIT-GEO-001: the self-audit's geo consensus admits only fixes that
/// could locate the subject — the correlator's person-anchor gate. Scan
/// 7258fc07's consensus was a cloud of Overpass substations and Wikipedia
/// nearby-place POIs around one search-snippet city centroid, and the
/// subject's real Brisbane/Perth fixes were reported as its outliers.
#[test]
fn self_audit_geo_consensus_ignores_nearby_poi_and_infrastructure() {
    fn geo(v: &str, srcs: &[&str], tags: &[&str]) -> AuditEntity {
        AuditEntity {
            kind: "coordinates".into(),
            value: v.into(),
            c_effective: 0.6,
            corroboration: 1,
            sources: srcs.iter().map(|s| (*s).to_string()).collect(),
            corroborating_sources: None,
            tags: tags.iter().map(|s| (*s).to_string()).collect(),
        }
    }
    let mut ents = vec![
        geo(
            "-27.469800,153.025100",
            &["geo_normalize", "search_engines", "recall"],
            &["search-geocoded"],
        ),
        geo("-31.950500,115.860500", &["geo_normalize", "geocode"], &[]),
    ];
    // Eight Overpass infrastructure nodes around the Sydney pivot.
    for (i, v) in [
        "-33.865500,151.213000",
        "-33.866100,151.211200",
        "-33.867000,151.210400",
        "-33.868200,151.209900",
        "-33.869400,151.208800",
        "-33.870600,151.208100",
        "-33.871900,151.209500",
        "-33.873100,151.209000",
    ]
    .iter()
    .enumerate()
    {
        let tag = if i % 2 == 0 {
            "infra:substation"
        } else {
            "infra:surveillance"
        };
        ents.push(geo(v, &["geo_normalize", "overpass", "recall"], &[tag]));
    }
    // Ten Wikipedia / Wikidata nearby-place POIs around the same pivot.
    for i in 0..10 {
        let v = format!("-33.86{:02}00,151.20{:02}00", 50 + i, 80 + i);
        let srcs: &[&str] = if i % 2 == 0 {
            &["geo_normalize", "wiki_geosearch", "recall"]
        } else {
            &["wikidata"]
        };
        ents.push(geo(&v, srcs, &["nearby-place", "wikipedia"]));
    }

    let r = audit(&ents, LogSignals::default());
    assert_eq!(r.geo.coord_count, 2, "only the person-anchored fixes vote");
    assert_eq!(
        r.geo.source_count, 2,
        "search_engines + geocode; passes and POI sources are not corroboration"
    );
    assert!(
        !r.geo.has_consensus,
        "two cities ~3,600 km apart agree on nothing"
    );
    let f = r
        .findings
        .iter()
        .find(|f| f.category == "geo-divergence")
        .expect("Brisbane and Perth genuinely disagree");
    assert_eq!(f.severity, Severity::High);
    assert!(
        !f.examples
            .iter()
            .any(|e| e.contains("-33.86") || e.contains("-33.87")),
        "no POI is an outlier or the consensus: {:?}",
        f.examples
    );

    // Control: a geocoder's Sydney fix IS person-anchored and is admitted —
    // the gate is the anchor allowlist, not a Sydney-specific drop.
    ents.push(geo(
        "-33.869844,151.208285",
        &["geo_normalize", "geocode", "photon"],
        &[],
    ));
    let r = audit(&ents, LogSignals::default());
    assert_eq!(r.geo.coord_count, 3);
}

/// An outlier example names the sources that VOTED for the point — the
/// corroborating set the person-anchor gate admitted it on — not every module
/// that touched the value. `geo_consistency` gated on
/// `corroborating_source_names()` but stored `e.sources`, so the example
/// printed the annotator (`geo_normalize`) and the recall pass as if they
/// disagreed about the subject's location (Copilot review of #649).
#[test]
fn geo_outlier_example_names_only_its_corroborating_sources() {
    let geo = |v: &str, srcs: &[&str], corroborating: Option<&[&str]>| AuditEntity {
        kind: "coordinates".into(),
        value: v.into(),
        c_effective: 0.6,
        corroboration: 1,
        sources: srcs.iter().map(|s| (*s).to_string()).collect(),
        corroborating_sources: corroborating.map(|c| c.iter().map(|s| (*s).to_string()).collect()),
        tags: Vec::new(),
    };
    let consensus = [
        geo("35.4137,-114.1762", &["geocode"], None),
        geo("35.4200,-114.1800", &["geocode"], None),
        geo("35.4000,-114.2000", &["geocode"], None),
    ];
    let outlier_example = |outlier: AuditEntity| -> String {
        let mut ents = consensus.to_vec();
        ents.push(outlier);
        let r = audit(&ents, LogSignals::default());
        let f = r
            .findings
            .iter()
            .find(|f| f.category == "geo-divergence")
            .expect("the Montreal fix is an outlier");
        f.examples
            .iter()
            .find(|e| e.contains("45.5019"))
            .expect("the outlier is named")
            .clone()
    };

    // A CSV-shaped entity (no per-record verdict): the annotator and the pass
    // are dropped by the source-level rule; the voters print sorted.
    let ex = outlier_example(geo(
        "45.5019,-73.5674",
        &["recall", "photon", "geo_normalize", "geocode"],
        None,
    ));
    assert!(ex.contains("[geocode,photon]"), "{ex}");
    assert!(
        !ex.contains("geo_normalize") && !ex.contains("recall"),
        "an annotator or pass never voted: {ex}"
    );

    // A stored entity carries its own per-record verdict: a source whose only
    // record here is an annotation is excluded even though its name alone
    // would pass.
    let ex = outlier_example(geo(
        "45.5019,-73.5674",
        &["geocode", "photon", "geo_normalize"],
        Some(&["geocode"]),
    ));
    assert!(ex.contains("[geocode]"), "{ex}");
    assert!(!ex.contains("photon"), "{ex}");
}
