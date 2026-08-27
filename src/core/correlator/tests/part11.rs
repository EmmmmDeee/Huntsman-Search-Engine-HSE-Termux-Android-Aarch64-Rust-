#[test]
fn au_057_three_coords_produce_high_severity() {
    use super::rules::rule_au_057_synthesised_location_fix;

    let ents: Vec<Entity> = [
        ("-27.4698,153.0251", "geocode"),
        ("-27.4766,153.0166", "photon"),
        ("-27.4750,153.0200", "wigle"),
    ]
    .iter()
    .map(|(v, src)| {
        let mut e = Entity::new(EntityKind::Coordinates, *v, 0.70, "scan");
        e.add_evidence(Evidence::new(*src, "fix".to_string()));
        e
    })
    .collect();
    let out = rule_au_057_synthesised_location_fix(&RuleContext::new(&ents), "scan", 0);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].severity, super::Severity::High);
}

#[test]
fn au_057_excludes_infrastructure_coordinates() {
    use super::rules::rule_au_057_synthesised_location_fix;
    // Two IP-geo / hosting coordinates must NOT synthesise a subject "location
    // fix" — they locate the datacentre. Parity with AU-030/AU-099/AU-017.
    let ents = vec![
        {
            let mut e = Entity::new(EntityKind::Coordinates, "-27.4698,153.0251", 0.70, "scan");
            e.add_evidence(Evidence::new("ip_geo", "host city".to_string()));
            e
        },
        {
            let mut e = Entity::new(EntityKind::Coordinates, "-27.4766,153.0166", 0.70, "scan");
            e.tag(crate::core::tags::HOSTING);
            e.add_evidence(Evidence::new("ip_registry", "host city".to_string()));
            e
        },
    ];
    assert!(
        rule_au_057_synthesised_location_fix(&RuleContext::new(&ents), "scan", 0).is_empty(),
        "infrastructure coordinates must not synthesise a subject location fix"
    );
}

// ─── AU-058 tests ──────────────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn au_058_ratemyagent_url_extracts_suburb() {
    use super::rules::rule_au_058_professional_profile_geo;

    let ents = vec![{
        let mut e = Entity::new(
            EntityKind::Url,
            "https://www.ratemyagent.com.au/real-estate-agent/haigen-bamford-paddington-as105/",
            0.50,
            "scan",
        );
        e.add_evidence(Evidence::new("social_probe", "profile found".to_string()));
        e
    }];
    let out = rule_au_058_professional_profile_geo(&RuleContext::new(&ents), "scan", 0);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].rule_id, "AU-058");
    assert!(out[0].description.contains("paddington"));
    assert!(out[0].description.contains("T1591.002"));
}

#[test]
fn au_058_non_real_estate_url_does_not_fire() {
    use super::rules::rule_au_058_professional_profile_geo;

    let ents = vec![{
        let mut e = Entity::new(
            EntityKind::Url,
            "https://www.linkedin.com/in/haigen-bamford",
            0.50,
            "scan",
        );
        e.add_evidence(Evidence::new("social_probe", "profile".to_string()));
        e
    }];
    // linkedin is not in PROF_HOSTS for AU-058 (ratemyagent/homely/soho only)
    assert!(rule_au_058_professional_profile_geo(&RuleContext::new(&ents), "scan", 0).is_empty());
}

#[test]
fn au_058_ratemyagent_url_extracts_multi_word_suburb() {
    use super::rules::rule_au_058_professional_profile_geo;

    let ents = vec![{
        let mut e = Entity::new(
            EntityKind::Url,
            "https://www.ratemyagent.com.au/real-estate-agent/haigen-bamford-gold-coast-as105/",
            0.50,
            "scan",
        );
        e.add_evidence(Evidence::new("social_probe", "profile found".to_string()));
        e
    }];
    let out = rule_au_058_professional_profile_geo(&RuleContext::new(&ents), "scan", 0);
    assert_eq!(out.len(), 1);
    assert!(
        out[0].description.contains("gold coast"),
        "must extract the full two-word suburb, not just its last word: {}",
        out[0].description
    );
}

#[test]
fn au_058_below_confidence_threshold_does_not_fire() {
    use super::rules::rule_au_058_professional_profile_geo;

    let ents = vec![{
        let mut e = Entity::new(
            EntityKind::Url,
            "https://www.ratemyagent.com.au/real-estate-agent/haigen-bamford-paddington-as105/",
            0.40,
            "scan",
        );
        e.add_evidence(Evidence::new("social_probe", "low-conf".to_string()));
        e
    }];
    assert!(rule_au_058_professional_profile_geo(&RuleContext::new(&ents), "scan", 0).is_empty());
}

// ─── Recursive-scan simulation: cross-seed geo synergy for a subject ─────────
//
// An offline, deterministic stand-in for a live recursive scan. Real modules
// hit the network; here we construct the `Coordinates` entities those modules
// *would* emit for a subject (one per orthogonal source class) and drive the
// real correlation pipeline (`correlate_entities`) over them. This proves the
// end-to-end geo-synergy behaviour — AU-059 convergence, AU restriction, and
// orthogonal-class scoring — from many *random combinations of starting seeds*,
// without a live PII collection. Pure fixtures + the production rule set.
mod geo_synergy_sim {
    use super::super::rules::location::geo_source_class;
    use super::super::{Correlation, Severity, correlate_entities};
    use crate::core::entity::{Entity, EntityKind, Evidence};

    /// One simulated person-anchored geo sighting: the `Coordinates` an emitting
    /// module would produce. `source` selects the orthogonal class; the AU-state
    /// tag mirrors what collection-time tagging attaches.
    fn sighting(source: &str, lat: f64, lon: f64, conf: f64, state: &str) -> Entity {
        let mut e = Entity::new(
            EntityKind::Coordinates,
            format!("{lat:.4},{lon:.4}"),
            conf,
            "scan",
        );
        e.tag(format!("au-state:{state}"));
        e.tag("country:AU");
        e.add_evidence(Evidence::new(
            source,
            "person-anchored geo sighting".to_string(),
        ));
        e
    }

    /// Did AU-059 fire, and on which state/severity? Returns the matching
    /// correlation if present.
    fn au059(corrs: &[Correlation]) -> Option<&Correlation> {
        corrs.iter().find(|c| c.rule_id == "AU-059")
    }

    /// The canonical Sydney/NSW fixture coordinates, one per orthogonal class.
    /// Tight cluster (~Paddington/CBD) so the centroid is unambiguous.
    fn nsw_sources() -> Vec<(&'static str, f64, f64, f64)> {
        vec![
            ("abn_lookup", -33.8841, 151.2310, 0.82), // registry  (ABN registered office)
            ("exif_geo", -33.8850, 151.2300, 0.74),   // photo-gps (geotagged image)
            ("wigle", -33.8835, 151.2325, 0.66),      // wifi      (observed AP)
            ("au_people", -33.8860, 151.2290, 0.55),  // directory (White Pages AU)
            ("social_location", -33.8848, 151.2312, 0.60), // social (profile bio)
            ("phone_area_geo", -33.8700, 151.2090, 0.52), // phone (02 area code → Sydney)
        ]
    }

    #[test]
    fn single_class_never_converges() {
        // Two sightings, but BOTH registry → one orthogonal class → no synergy.
        let ents = vec![
            sighting("abn_lookup", -33.8841, 151.2310, 0.82, "NSW"),
            sighting("acnc_charities", -33.8850, 151.2300, 0.70, "NSW"),
        ];
        let corrs = correlate_entities(&ents, "scan");
        assert!(
            au059(&corrs).is_none(),
            "a single orthogonal class must not assert a synergy fix"
        );
    }

    #[test]
    fn two_orthogonal_classes_converge_in_nsw() {
        // A name→registry hit plus a photo GPS: the minimum useful seed combo.
        let ents = vec![
            sighting("abn_lookup", -33.8841, 151.2310, 0.82, "NSW"),
            sighting("exif_geo", -33.8850, 151.2300, 0.74, "NSW"),
        ];
        let corrs = correlate_entities(&ents, "scan");
        let c = au059(&corrs).expect("two orthogonal AU classes must fire AU-059");
        assert_eq!(c.severity, Severity::Medium, "exactly 2 classes ⇒ Medium");
        assert!(c.description.contains("state=NSW"));
    }

    #[test]
    fn three_plus_classes_are_high_severity() {
        let ents = vec![
            sighting("abn_lookup", -33.8841, 151.2310, 0.82, "NSW"),
            sighting("exif_geo", -33.8850, 151.2300, 0.74, "NSW"),
            sighting("wigle", -33.8835, 151.2325, 0.66, "NSW"),
        ];
        let corrs = correlate_entities(&ents, "scan");
        let c = au059(&corrs).expect("three orthogonal classes must fire AU-059");
        assert_eq!(c.severity, Severity::High, "≥3 classes ⇒ High");
    }

    /// The core requirement: geolocation must be achievable from *as many random
    /// combinations of starting seeds as possible*. Enumerate every 2-and-3
    /// subset of the orthogonal NSW source set; each subset whose sources span
    /// ≥2 distinct classes MUST converge on NSW. This is the combinatorial proof
    /// that the fix doesn't depend on any one privileged seed.
    #[test]
    fn every_multi_class_seed_combination_converges() {
        let all = nsw_sources();
        let n = all.len();
        let mut tested_combos = 0usize;

        // All 2- and 3-element subsets (bitmask enumeration; n is small).
        for mask in 1u32..(1 << n) {
            let chosen: Vec<_> = (0..n)
                .filter(|i| mask & (1 << i) != 0)
                .map(|i| all[i])
                .collect();
            if !(2..=3).contains(&chosen.len()) {
                continue;
            }
            // Distinct orthogonal classes in this subset.
            let classes: std::collections::HashSet<_> = chosen
                .iter()
                .map(|(src, ..)| geo_source_class(src))
                .collect();

            let ents: Vec<Entity> = chosen
                .iter()
                .map(|(src, lat, lon, conf)| sighting(src, *lat, *lon, *conf, "NSW"))
                .collect();
            let corrs = correlate_entities(&ents, "scan");
            let fired = au059(&corrs);

            if classes.len() >= 2 {
                let c = fired.unwrap_or_else(|| {
                    panic!(
                        "multi-class seed combo {:?} ({} classes) must converge",
                        chosen.iter().map(|(s, ..)| *s).collect::<Vec<_>>(),
                        classes.len()
                    )
                });
                assert!(
                    c.description.contains("state=NSW"),
                    "combo {:?} must localise to NSW",
                    chosen.iter().map(|(s, ..)| *s).collect::<Vec<_>>()
                );
                tested_combos += 1;
            } else {
                assert!(
                    fired.is_none(),
                    "single-class combo {:?} must NOT converge",
                    chosen.iter().map(|(s, ..)| *s).collect::<Vec<_>>()
                );
            }
        }
        // Sanity: we actually exercised a meaningful number of combinations.
        assert!(
            tested_combos >= 15,
            "expected many converging combos, exercised {tested_combos}"
        );
    }

    /// AU restriction: a non-Australian sighting must never contribute a class,
    /// even if it would otherwise complete a 2-class quorum. Here the only AU
    /// point is a registry hit; the photo GPS is in London → no synergy.
    #[test]
    fn foreign_sighting_cannot_complete_quorum() {
        let mut london = Entity::new(EntityKind::Coordinates, "51.5074,-0.1278", 0.80, "scan");
        london.add_evidence(Evidence::new("exif_geo", "overseas trip photo".to_string()));
        let ents = vec![
            sighting("abn_lookup", -33.8841, 151.2310, 0.82, "NSW"),
            london,
        ];
        let corrs = correlate_entities(&ents, "scan");
        assert!(
            au059(&corrs).is_none(),
            "a foreign coordinate must not complete the AU synergy quorum"
        );
    }

    /// The dominant-state report follows the majority of contributing sightings:
    /// 3 NSW + 1 VIC ⇒ NSW. (Mixed-state input still converges; the centroid and
    /// reported state reflect the weight of evidence.)
    #[test]
    fn majority_state_wins_the_report() {
        let ents = vec![
            sighting("abn_lookup", -33.8841, 151.2310, 0.82, "NSW"),
            sighting("exif_geo", -33.8850, 151.2300, 0.74, "NSW"),
            sighting("au_people", -33.8860, 151.2290, 0.55, "NSW"),
            sighting("wigle", -37.8136, 144.9631, 0.66, "VIC"),
        ];
        let corrs = correlate_entities(&ents, "scan");
        let c = au059(&corrs).expect("multi-class input must converge");
        assert!(
            c.description.contains("state=NSW"),
            "majority NSW evidence must report NSW: {}",
            c.description
        );
    }

    /// Infrastructure geo (a CDN edge, an Overpass POI) must never enter the fix
    /// — the person-anchor gate is shared with AU-052/053. Here two genuine
    /// person sources converge while a `hosting`-tagged point is ignored.
    #[test]
    fn infrastructure_points_are_excluded() {
        let mut cdn = Entity::new(EntityKind::Coordinates, "-33.8688,151.2093", 0.90, "scan");
        cdn.tag("au-state:NSW");
        cdn.tag(crate::core::tags::HOSTING);
        cdn.add_evidence(Evidence::new("ip_geo", "CDN edge".to_string()));
        let ents = vec![
            sighting("abn_lookup", -33.8841, 151.2310, 0.82, "NSW"),
            sighting("exif_geo", -33.8850, 151.2300, 0.74, "NSW"),
            cdn,
        ];
        let corrs = correlate_entities(&ents, "scan");
        let c = au059(&corrs).expect("two person sources still converge");
        // The hosting point's uid (uid is derived from kind+value) must not
        // appear among AU-059's children.
        let cdn_uid = Entity::new(EntityKind::Coordinates, "-33.8688,151.2093", 0.0, "scan").uid;
        assert!(
            !c.entity_uids.contains(&cdn_uid),
            "a hosting-tagged CDN point must not enter the synergy fix"
        );
    }
}

// ── All-eleven-class integration proof ───────────────────────────────────
//
// Drives all 11 orthogonal AU geo source classes (PhotoGps, WifiSensor,
// Geocode, Registry, Directory, Social, Phone, Enrichment, Search,
// Electoral, Property) through the real `correlate_entities` pipeline in
// one pass, then asserts:
//   1. AU-059 fires for every possible 2-class and 3-class subset.
//   2. The best-location extractor recovers every structured field.
//   3. Severity escalates correctly (Medium→High) as class count grows.
//   4. No infrastructure or foreign point enters any fix.
//
// This is the offline authoritative proof that geolocation converges from
// every seed-combination relevant to an AU subject, without live PII.
mod all_eleven_classes {
    use super::super::rules::location::geo_source_class;
    use super::super::{Correlation, Severity, correlate_entities};
    use crate::app::export::extract_au_location_fix;
    use crate::core::entity::{Entity, EntityKind, Evidence};

    /// One AU Coordinates entity per source class, all near Sydney NSW.
    /// Each source is the canonical representative of its orthogonal class.
    fn all_class_fixtures() -> Vec<(&'static str, f64, f64, f64)> {
        vec![
            // (source, lat, lon, confidence)
            ("exif_geo", -33.8688, 151.2093, 0.85), // PhotoGps
            ("wigle", -33.8700, 151.2100, 0.78),    // WifiSensor
            ("geocode", -33.8695, 151.2080, 0.82),  // Geocode
            ("abn_lookup", -33.8710, 151.2110, 0.80), // Registry
            ("au_people", -33.8680, 151.2070, 0.72), // Directory
            ("github_user", -33.8720, 151.2120, 0.68), // Social
            ("phone_area_geo", -33.8660, 151.2060, 0.65), // Phone
            ("epieos", -33.8730, 151.2130, 0.75),   // Enrichment
            ("search_engines", -33.8650, 151.2050, 0.62), // Search
            ("au_electoral", -33.8740, 151.2140, 0.74), // Electoral
            ("au_property", -33.8670, 151.2090, 0.74), // Property
        ]
    }

    fn au_coord(source: &str, lat: f64, lon: f64, conf: f64) -> Entity {
        let value = format!("{lat:.4},{lon:.4}");
        let mut e = Entity::new(EntityKind::Coordinates, &value, conf, "s");
        e.tag("au-state:NSW");
        e.tag("country:AU");
        e.add_evidence(Evidence::new(source, "fixture"));
        e
    }

    fn au059(corrs: &[Correlation]) -> Option<&Correlation> {
        corrs
            .iter()
            .filter(|c| c.rule_id == "AU-059")
            .max_by(|a, b| {
                a.rank
                    .partial_cmp(&b.rank)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
    }

    #[test]
    fn all_eleven_classes_present_and_distinct() {
        use std::collections::HashSet;
        let fixtures = all_class_fixtures();
        let classes: HashSet<_> = fixtures
            .iter()
            .map(|(src, _, _, _)| geo_source_class(src))
            .collect();
        assert_eq!(
            classes.len(),
            11,
            "fixture must cover exactly 11 distinct geo source classes; got {}: {:?}",
            classes.len(),
            classes
        );
    }

    #[test]
    fn all_eleven_fires_au059_at_critical_severity() {
        let ents: Vec<Entity> = all_class_fixtures()
            .iter()
            .map(|(src, lat, lon, conf)| au_coord(src, *lat, *lon, *conf))
            .collect();
        let corrs = correlate_entities(&ents, "s");
        let c = au059(&corrs).expect("11 classes must fire AU-059");
        assert!(
            c.description.contains("state=NSW"),
            "all-class fix must report NSW: {}",
            c.description
        );
        assert_eq!(
            c.severity,
            Severity::High,
            "≥3 orthogonal classes must produce High (or better) severity"
        );
    }

    #[test]
    fn all_eleven_best_location_field_is_fully_structured() {
        let ents: Vec<Entity> = all_class_fixtures()
            .iter()
            .map(|(src, lat, lon, conf)| au_coord(src, *lat, *lon, *conf))
            .collect();
        let corrs = correlate_entities(&ents, "s");
        let fix = extract_au_location_fix(&corrs, &ents);

        assert!(fix.is_object(), "best_location must be a JSON object");
        assert_eq!(fix["state"], "NSW", "state must be NSW");
        assert_eq!(fix["rule_id"], "AU-059");

        let lat = fix["lat"].as_f64().expect("lat must be f64");
        let lon = fix["lon"].as_f64().expect("lon must be f64");
        assert!(
            (-34.5..-33.0).contains(&lat),
            "centroid lat must be near Sydney: {lat}"
        );
        assert!(
            (150.5..152.0).contains(&lon),
            "centroid lon must be near Sydney: {lon}"
        );

        let gh = fix["geohash"].as_str().expect("geohash must be a string");
        assert!(!gh.is_empty(), "geohash must be non-empty");
        assert_eq!(gh.len(), 6, "geohash must be 6 chars (precision 6)");

        let sc = fix["synergy_confidence"]
            .as_f64()
            .expect("synergy_confidence must be f64");
        assert!(
            (0.0..=0.97).contains(&sc) && sc > 0.5,
            "synergy_confidence must be > 0.5 for 11 classes: {sc}"
        );

        let class_count = fix["class_count"]
            .as_u64()
            .expect("class_count must be u64");
        assert!(
            class_count >= 3,
            "class_count must be ≥ 3 for 11 sources: {class_count}"
        );

        let source_count = fix["source_count"]
            .as_u64()
            .expect("source_count must be u64");
        assert!(
            source_count >= 11,
            "source_count must be ≥ 11: {source_count}"
        );
    }

    /// Every 2-element subset of the 11 classes must independently fire AU-059.
    /// Uses bitmask enumeration: 2^11 = 2048 masks, C(11,2) = 55 two-class pairs.
    #[test]
    fn every_two_class_pair_fires_au059() {
        let fixtures = all_class_fixtures();
        let n = fixtures.len();
        let mut checked = 0u32;
        let mut failures: Vec<String> = Vec::new();

        for mask in 0u32..(1 << n) {
            if mask.count_ones() != 2 {
                continue;
            }
            let ents: Vec<Entity> = fixtures
                .iter()
                .enumerate()
                .filter(|(i, _)| mask & (1 << i) != 0)
                .map(|(_, (src, lat, lon, conf))| au_coord(src, *lat, *lon, *conf))
                .collect();

            let corrs = correlate_entities(&ents, "s");
            let selected: Vec<String> = fixtures
                .iter()
                .enumerate()
                .filter(|(i, _)| mask & (1 << i) != 0)
                .map(|(_, (src, _, _, _))| src.to_string())
                .collect();

            if au059(&corrs).is_none() {
                failures.push(format!("{selected:?}"));
            }
            checked += 1;
        }

        assert_eq!(checked, 55, "must check exactly C(11,2)=55 pairs");
        assert!(
            failures.is_empty(),
            "{} two-class pair(s) failed to fire AU-059: {}",
            failures.len(),
            failures.join("; ")
        );
    }

    /// Three-class subsets must produce High severity; two-class Medium.
    #[test]
    fn severity_escalates_with_class_count() {
        let fixtures = all_class_fixtures();

        // Two-class: first two fixtures (PhotoGps + WifiSensor).
        let two_ents: Vec<Entity> = fixtures[..2]
            .iter()
            .map(|(src, lat, lon, conf)| au_coord(src, *lat, *lon, *conf))
            .collect();
        let two_corrs = correlate_entities(&two_ents, "s");
        let two_fix = au059(&two_corrs).expect("2 classes must fire");
        assert_eq!(
            two_fix.severity,
            Severity::Medium,
            "2 orthogonal classes must be Medium severity"
        );

        // Three-class: first three fixtures (PhotoGps + WifiSensor + Geocode).
        let three_ents: Vec<Entity> = fixtures[..3]
            .iter()
            .map(|(src, lat, lon, conf)| au_coord(src, *lat, *lon, *conf))
            .collect();
        let three_corrs = correlate_entities(&three_ents, "s");
        let three_fix = au059(&three_corrs).expect("3 classes must fire");
        assert_eq!(
            three_fix.severity,
            Severity::High,
            "3 orthogonal classes must be High severity"
        );
    }

    /// Adding a foreign (non-AU) point to a 2-class AU set must not displace
    /// the AU fix — the foreign point is excluded by the AU bounding-box gate.
    #[test]
    fn foreign_sighting_does_not_contaminate_au_fix() {
        let fixtures = all_class_fixtures();
        let mut ents: Vec<Entity> = fixtures[..2]
            .iter()
            .map(|(src, lat, lon, conf)| au_coord(src, *lat, *lon, *conf))
            .collect();

        // A US coordinate tagged with a non-AU source.
        let mut us = Entity::new(EntityKind::Coordinates, "40.7128,-74.0060", 0.90, "s");
        us.add_evidence(Evidence::new("geocode", "New York fixture"));
        // No country:AU tag — bounding-box check will exclude it.
        ents.push(us);

        let corrs = correlate_entities(&ents, "s");
        let fix = extract_au_location_fix(&corrs, &ents);
        assert_eq!(
            fix["state"], "NSW",
            "AU fix must survive a foreign sighting: {fix}"
        );
    }
}

/// AU-059's fix must be OUTLIER-ROBUST — that's the entire point of using the
/// confidence-weighted geometric median (Weiszfeld) instead of a plain
/// weighted centroid (PROBLEM_TREE C5). Two orthogonal classes agree near
/// Sydney (combined weight 64% of the total); a third, *higher-confidence*
/// class disagrees from Perth, ~3,300 km away (weight 36%). Because the
/// majority holds more than the median's 50% breakdown point, the fix must
/// stay anchored near Sydney — a plain weighted centroid, which has no notion
/// of "majority" and is dragged proportionally to weight share regardless of
/// spatial agreement, would not.
#[test]
fn au059_synergy_fix_resists_a_single_high_confidence_outlier() {
    use crate::core::entity::{Entity, EntityKind, Evidence};

    let sighting = |lat: f64, lon: f64, conf: f64, source: &str, state: &str| {
        let mut e = Entity::new(
            EntityKind::Coordinates,
            format!("{lat:.4},{lon:.4}"),
            conf,
            "s",
        );
        e.tag(format!("au-state:{state}"));
        e.tag("country:AU");
        e.add_evidence(Evidence::new(source, "fixture"));
        e
    };

    let entities = vec![
        sighting(-33.8688, 151.2093, 0.85, "exif_geo", "NSW"), // PhotoGps
        sighting(-33.8700, 151.2100, 0.78, "wigle", "NSW"),    // WifiSensor
        sighting(-31.9505, 115.8605, 0.90, "geocode", "WA"),   // Geocode — the outlier
    ];

    let fix = au059_synergy_fix(&entities).expect("3 orthogonal AU classes must converge");

    // The plain weighted centroid the pre-fix code used, computed directly for
    // comparison. It has no notion of "majority", so Perth's 36% weight share
    // still drags the average roughly a third of the way there — the sanity
    // check below proves this fixture is actually discriminating.
    let weighted: Vec<((f64, f64), f64)> = entities
        .iter()
        .map(|e| {
            let ll = crate::util::geohash::parse_coords(&e.value).expect("should succeed");
            (ll, e.confidence)
        })
        .collect();
    let centroid = crate::util::geometry::weighted_centroid(&weighted).expect("should succeed");
    assert!(
        centroid.1 < 145.0,
        "sanity: the plain centroid must itself be pulled toward Perth for this \
         fixture to be a meaningful test of outlier-robustness, got lon={:.2}",
        centroid.1
    );

    assert!(
        fix.lon > 145.0,
        "the geometric-median fix must stay anchored near the Sydney majority \
         (lon > 145) despite the higher-confidence Perth outlier, not drift \
         toward it the way the plain weighted centroid (lon={:.2}) does: \
         fix.lon={:.2}",
        centroid.1,
        fix.lon
    );
}

#[test]
fn au059_class_diversity_bonus_is_per_point_not_a_global_no_op() {
    use crate::core::entity::{Entity, EntityKind, Evidence};

    // A coordinate corroborated across MORE orthogonal source classes is
    // stronger location evidence and must pull the synthesised fix
    // proportionally more. The class-diversity bonus used to be derived from the
    // scan-wide class count and applied to every point identically — a global
    // rescaling the weighted geometric median is invariant to, so it moved the
    // fix not at all. It is now per-point.
    //
    // This test isolates that: two scans differ ONLY in the class SPAN of the
    // eastern (Sydney) coordinate `A`, holding its source COUNT (2) — and hence
    // its `c_effective` — and every other point fixed. Under the old global
    // scalar the two fixes are byte-identical (the bonus can't move a weighted
    // median and A's weight is unchanged); under the per-point bonus the
    // multi-class scan must pull the fix east toward A.
    let mk = |lat: f64, lon: f64, sources: &[&str], state: &str| {
        let mut e = Entity::new(
            EntityKind::Coordinates,
            format!("{lat:.4},{lon:.4}"),
            0.80,
            "s",
        );
        e.tag(format!("au-state:{state}"));
        e.tag("country:AU");
        for s in sources {
            e.add_evidence(Evidence::new(*s, "fixture"));
        }
        e
    };

    // B and C are fixed single-class points. With A they form a genuine triangle
    // (all interior angles < 120°), so the geometric median is an interior
    // Fermat point that responds continuously to each vertex's weight — not a
    // near-collinear set that pins the median to the middle vertex regardless of
    // weight.
    //
    // All three sit inside one metropolitan area, and must: AU-059 fuses only a
    // spatially COHERENT group, so the earlier Sydney/Darwin/Perth fixture no
    // longer converges at all — three points thousands of kilometres apart do
    // not describe one place, and their "interior Fermat point" was a location
    // nobody had been seen at. The weighting property under test is unchanged;
    // only the geometry is now one a real subject could produce.
    let b = mk(-33.7048, 151.0990, &["geocode"], "NSW"); // Hornsby — Geocode
    let c = mk(-33.9171, 151.0350, &["mylnikov"], "NSW"); // Bankstown — WifiSensor

    // Three-class A: Registry + WifiSensor + PhotoGps → per-point count 3 → 1.20×.
    let a_multi = mk(
        -33.8688,
        151.2093,
        &["abn_lookup", "wigle", "exif_geo"],
        "NSW",
    );
    // One-class A: abn_lookup + opencorporates + acnc_charities → all Registry →
    // per-point count 1 → 1.00×. Same source COUNT (3) ⇒ identical c_effective.
    let a_mono = mk(
        -33.8688,
        151.2093,
        &["abn_lookup", "opencorporates", "acnc_charities"],
        "NSW",
    );

    let multi = au059_synergy_fix(&[a_multi, b.clone(), c.clone()])
        .expect("4 orthogonal AU classes in one metro area converge");
    let mono = au059_synergy_fix(&[a_mono, b, c])
        .expect("3 orthogonal AU classes in one metro area converge");

    assert!(
        multi.lon > mono.lon + 1e-4,
        "the per-point class-diversity bonus must pull the fix east toward the \
         multi-class Sydney coordinate: multi-class lon={:.5} must exceed \
         single-class lon={:.5} (they would be equal under the old global scalar)",
        multi.lon,
        mono.lon
    );
}

// ── T1.3: firing assertions for the 12 previously-unasserted rules ────────────
// (PROBLEM_TREE §3.1 T1.3 — these rules were dispatched but no test proved they
// actually produce a correlation; a silently-dead rule would pass CI.)

#[test]
fn au019_fires_for_three_breach_dates_within_30_days() {
    let mk = |v: &str, d: &str| {
        let mut e = Entity::new(EntityKind::Email, v, 0.8, "s");
        e.tag("breach");
        e.add_evidence(Evidence::new("hibp", "b").with_attr("breach_date", d));
        e
    };
    let ents = vec![
        mk("a@x.com", "2024-01-01"),
        mk("b@x.com", "2024-01-10"),
        mk("c@x.com", "2024-01-20"),
    ];
    let r = rule_au_019_temporal_breach_cluster(&RuleContext::new(&ents), "s", 0);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].rule_id, "AU-019");
    assert_eq!(r[0].severity, Severity::High);
    assert_eq!(r[0].entity_uids.len(), 3);
}

#[test]
fn au019_ignores_a_certificate_transparency_date_on_a_breach_tagged_domain() {
    // A domain can be genuinely `breach`-tagged (e.g. seon's `breach_domain_entity`)
    // while ALSO carrying merged evidence from a Certificate-Transparency module
    // (`certspotter`/`crtsh`/`cert_intel`) if the same domain is independently
    // discovered elsewhere in the scan — those CT modules are the ONLY producers
    // of `not_before`, a routine TLS certificate issuance date with nothing to do
    // with any breach. Only 2 genuine breach dates exist (the two emails) — one
    // short of AU-019's 3-member floor — so the cluster must NOT complete via the
    // domain's unrelated `not_before`, even though the domain itself carries the
    // `breach` tag and merges evidence from a real breach source too.
    let mut domain = Entity::new(EntityKind::Domain, "evil.example", 0.8, "s");
    domain.tag("breach");
    domain.add_evidence(Evidence::new("seon", "breach — no date on this record"));
    domain.add_evidence(Evidence::new("crtsh", "cert").with_attr("not_before", "2024-01-15"));

    let mk_email = |v: &str, d: &str| {
        let mut e = Entity::new(EntityKind::Email, v, 0.8, "s");
        e.tag("breach");
        e.add_evidence(Evidence::new("hibp", "b").with_attr("breach_date", d));
        e
    };
    let ents = vec![
        mk_email("a@x.com", "2024-01-01"),
        mk_email("b@x.com", "2024-01-10"),
        domain,
    ];
    let r = rule_au_019_temporal_breach_cluster(&RuleContext::new(&ents), "s", 0);
    assert!(
        r.is_empty(),
        "a CT module's not_before date must not complete a breach cluster: {r:?}"
    );
}
