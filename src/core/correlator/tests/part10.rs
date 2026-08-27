#[test]
fn au052_excludes_overpass_poi_cluster_live_toronto_case() {
    // Regression from a real scan: ~20 Overpass POIs (surveillance cameras, cell
    // towers) cluster tightly around one IP-geolocated point. They are map
    // features, not sightings — an exclude-list missed `overpass` and would have
    // built a tight downtown footprint with a geometric median on a traffic
    // camera. The positive person-anchor allowlist drops them all.
    let mut ents: Vec<Entity> = (0..20)
        .map(|i| {
            let lat = 43.650 + (i as f64) * 0.0003;
            overpass_poi(&format!("{lat:.4},-79.3830"), "infra:surveillance")
        })
        .collect();
    // Plus the central IP-geo point (hosting) — also excluded.
    ents.push(hosting_coord("43.6532,-79.3832", "ip_geo"));
    assert!(
        super::rules::rule_au_052_geographic_area_of_operation(&RuleContext::new(&ents), "s", 0)
            .is_empty(),
        "Overpass POIs must not form a person's footprint"
    );
    assert!(
        super::rules::rule_au_053_out_of_area_location(&RuleContext::new(&ents), "s", 0).is_empty(),
        "Overpass POIs must not establish an area for the anomaly rule either"
    );
}

#[test]
fn au052_tight_multisource_footprint_is_a_high_location_fix() {
    // Three person-anchored sightings around one suburb (photo EXIF, Wi-Fi,
    // geocoded address) → a tight, High-severity fix with a centroid.
    let ents = vec![
        coord_from("-33.8700,151.2100", "geocode"),
        coord_from("-33.8720,151.2150", "exif_geo"),
        coord_from("-33.8680,151.2080", "wigle"),
    ];
    let hits =
        super::rules::rule_au_052_geographic_area_of_operation(&RuleContext::new(&ents), "s", 0);
    assert_eq!(hits.len(), 1, "three multi-source coords bound an area");
    assert_eq!(hits[0].rule_id, "AU-052");
    assert_eq!(hits[0].severity, super::Severity::High);
    assert!(hits[0].description.contains("centroid"));
    assert!(hits[0].description.contains("tight"));
    // The headline fix is the outlier-robust geometric median; the Chebyshev
    // centre is retained as the bounding circle with its uncertainty radius.
    assert!(hits[0].description.contains("geometric median"));
    assert!(hits[0].description.contains("Chebyshev centre"));
    assert!(hits[0].description.contains("±"));
}

#[test]
fn au052_requires_three_points_and_two_sources() {
    // Two points: no area.
    let two = vec![
        coord_from("-33.8700,151.2100", "geocode"),
        coord_from("-33.8720,151.2150", "exif_geo"),
    ];
    assert!(
        super::rules::rule_au_052_geographic_area_of_operation(&RuleContext::new(&two), "s", 0)
            .is_empty()
    );

    // Three points but all from ONE source (a single device's track) → not
    // multi-source convergence, must not assert a footprint.
    let one_source = vec![
        coord_from("-33.8700,151.2100", "exif_geo"),
        coord_from("-33.8720,151.2150", "exif_geo"),
        coord_from("-33.8680,151.2080", "exif_geo"),
    ];
    assert!(
        super::rules::rule_au_052_geographic_area_of_operation(
            &RuleContext::new(&one_source),
            "s",
            0
        )
        .is_empty()
    );
}

#[test]
fn au052_dispersed_footprint_is_medium_travel_pattern() {
    // Person-anchored sightings hundreds of km apart → a dispersed,
    // Medium-severity travel footprint (not a single-residence fix).
    let ents = vec![
        coord_from("-33.8700,151.2100", "geocode"),  // Sydney
        coord_from("-37.8100,144.9600", "exif_geo"), // Melbourne
        coord_from("-27.4700,153.0200", "wigle"),    // Brisbane
    ];
    let hits =
        super::rules::rule_au_052_geographic_area_of_operation(&RuleContext::new(&ents), "s", 0);
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].severity, super::Severity::Medium);
    assert!(hits[0].description.contains("dispersed"));
}

#[test]
fn au052_excludes_infrastructure_geo_live_peekyou_case() {
    // Regression from a real peekyou.com-pivoted scan: every coordinate
    // geolocated the target's web HOST, not the target. A Cloudflare edge
    // (hosting-tagged) plus two IP/WHOIS-only datacenter coords must NOT form a
    // person's footprint — otherwise the hull spans four continents of CDN.
    let ents = vec![
        hosting_coord("43.6532,-79.3832", "ip_geo"), // Toronto CF edge (hosting)
        coord_from("37.7621,-122.3971", "ipinfo"),   // SF — IP-geo only
        coord_from("36.0345,-89.3856", "ip_whois_geo"), // Tennessee — WHOIS-geo only
    ];
    assert!(
        super::rules::rule_au_052_geographic_area_of_operation(&RuleContext::new(&ents), "s", 0)
            .is_empty(),
        "infrastructure coordinates must not form a person's area of operation"
    );

    // But a real person-anchored coordinate mixed in is kept: if the same scan
    // ALSO held three EXIF/Wi-Fi/geocode sightings in one suburb, those — and
    // only those — would fix the location.
    let mixed = vec![
        hosting_coord("43.6532,-79.3832", "ip_geo"),
        coord_from("-33.8700,151.2100", "exif_geo"),
        coord_from("-33.8720,151.2150", "wigle"),
        coord_from("-33.8680,151.2080", "geocode"),
    ];
    let hits =
        super::rules::rule_au_052_geographic_area_of_operation(&RuleContext::new(&mixed), "s", 0);
    assert_eq!(hits.len(), 1, "the three real sightings fix the location");
    assert!(hits[0].description.contains("tight"));
}

// ─── Geo out-of-area anomaly (AU-053) ────────────────────────────────────────────

#[test]
fn au053_flags_a_sighting_outside_the_established_area() {
    // Three tight Sydney sightings (the established area) + one Perth sighting
    // ~3300 km away. AU-053 flags Perth as out-of-area; the Sydney points, being
    // the dominant cluster, are never themselves flagged.
    let ents = vec![
        coord_from("-33.8700,151.2100", "geocode"),
        coord_from("-33.8720,151.2150", "exif_geo"),
        coord_from("-33.8680,151.2080", "wigle"),
        coord_from("-31.9520,115.8570", "exif_geo"), // Perth
    ];
    let hits = super::rules::rule_au_053_out_of_area_location(&RuleContext::new(&ents), "s", 0);
    assert_eq!(hits.len(), 1, "the Perth sighting is out of area");
    assert_eq!(hits[0].rule_id, "AU-053");
    assert_eq!(hits[0].severity, super::Severity::Medium);
    assert!(hits[0].description.contains("outside"));
}

#[test]
fn au053_does_not_fire_on_a_single_coherent_area() {
    // Four tight sightings in one suburb — no outlier, no anomaly.
    let ents = vec![
        coord_from("-33.8700,151.2100", "geocode"),
        coord_from("-33.8720,151.2150", "exif_geo"),
        coord_from("-33.8680,151.2080", "wigle"),
        coord_from("-33.8710,151.2120", "geocode"),
    ];
    assert!(
        super::rules::rule_au_053_out_of_area_location(&RuleContext::new(&ents), "s", 0).is_empty()
    );
}

#[test]
fn au053_ignores_infrastructure_and_needs_an_established_area() {
    // The live peekyou.com case: infra coords are excluded, leaving too few
    // person-anchored points to form an established area → no anomaly fires.
    let ents = vec![
        hosting_coord("43.6532,-79.3832", "ip_geo"),
        coord_from("37.7621,-122.3971", "ipinfo"),
        coord_from("36.0345,-89.3856", "ip_whois_geo"),
        coord_from("-33.8700,151.2100", "exif_geo"), // one real point
    ];
    assert!(
        super::rules::rule_au_053_out_of_area_location(&RuleContext::new(&ents), "s", 0).is_empty()
    );
}

#[test]
fn severity_as_canonical_matches_serde() {
    // CONVENTIONS.md §3 pin. as_canonical feeds the persisted
    // `correlations.severity` column AND the SQL `ORDER BY CASE` in
    // `correlations_for_scan` hard-codes these exact strings in this exact ORDER,
    // so a drift between as_canonical, the serde wire form, and the weight/Ord
    // ranking would silently desync the stored value from the query that ranks it
    // (and the in-memory `rank_and_sort` from the persisted order).
    //
    // `EVERY` is walked by an arm-less `match` (no `_`): adding a Severity variant
    // fails to compile until it is listed — the compile-forced guard a hardcoded
    // array lacks. (RelationKind::SharesSecretWith silently slipped exactly this
    // way, staying unpinned until the array-based test was made exhaustive.)
    const EVERY: &[Severity] = &[
        Severity::Low,
        Severity::Medium,
        Severity::High,
        Severity::Critical,
    ];
    for &sev in EVERY {
        match sev {
            Severity::Low | Severity::Medium | Severity::High | Severity::Critical => {}
        }
        let json = serde_json::to_string(&sev).expect("should succeed");
        assert_eq!(
            json.trim_matches('"'),
            sev.as_canonical(),
            "as_canonical vs serde: {sev:?}"
        );
        // Display is the deliberately UPPERCASE human form — never the wire form.
        assert_eq!(
            sev.to_string(),
            sev.as_canonical().to_uppercase(),
            "Display vs as_canonical: {sev:?}"
        );
        // The persisted string must deserialise back to the same variant.
        let back: Severity = serde_json::from_str(&json).expect("should succeed");
        assert_eq!(back, sev, "serde round-trip: {sev:?}");
    }

    // The three ranking representations must encode ONE order: declaration order
    // (EVERY) == weight() ascending == Ord ascending. `rank_and_sort` ranks by
    // `weight()` and tie-breaks by the derived `Ord`, and the SQL `ORDER BY CASE`
    // mirrors it — so a variant whose weight or Ord disagreed with its position
    // would make the persisted and in-memory rankings diverge. Pin strict
    // monotonic agreement across every consecutive pair.
    for pair in EVERY.windows(2) {
        assert!(
            pair[0].weight() < pair[1].weight(),
            "weight order must match declaration: {:?} !< {:?}",
            pair[0],
            pair[1]
        );
        assert!(
            pair[0] < pair[1],
            "Ord must match declaration: {:?} !< {:?}",
            pair[0],
            pair[1]
        );
    }
}

#[test]
fn au_056_corroborates_when_coord_and_address_agree_on_state() {
    use super::rules::rule_au_056_jurisdiction_cross_check;

    // A Brisbane coordinate (tagged au-state:QLD by the geo builders) and a QLD
    // address independently name the same state → High corroboration.
    let ents = vec![
        mk_tagged(
            EntityKind::Coordinates,
            "-27.4766,153.0166",
            "geocode",
            &["geoint", "au-relevant", "au-state:QLD"],
        ),
        mk_tagged(
            EntityKind::Address,
            "12 Mary Street, Brisbane City QLD 4000",
            "see_know",
            &[],
        ),
    ];
    let out = rule_au_056_jurisdiction_cross_check(&RuleContext::new(&ents), "scan", 0);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].rule_id, "AU-056");
    assert_eq!(out[0].severity, super::Severity::High);
    assert!(out[0].description.contains("QLD"));
    assert!(out[0].description.contains("corroborated"));
    assert_eq!(out[0].entity_uids.len(), 2);
}

#[test]
fn au_056_derives_coord_state_from_latlong_without_a_tag() {
    use super::rules::rule_au_056_jurisdiction_cross_check;

    // Regression from a live scan: a Brisbane coordinate person-anchored via a
    // search-engine snippet carries NO au-state tag, yet the rule must still
    // derive QLD from the lat/long and corroborate the QLD address. `search_engines`
    // is an anchoring geo source, so the coordinate is a real subject fix (not
    // infrastructure geo excluded by `coord_state`).
    let ents = vec![
        mk_tagged(
            EntityKind::Coordinates,
            "-27.4698,153.0251",
            "search_engines",
            &["geoint"], // deliberately no au-state: tag
        ),
        mk_tagged(EntityKind::Address, "Brisbane, QLD", "search_engines", &[]),
    ];
    let out = rule_au_056_jurisdiction_cross_check(&RuleContext::new(&ents), "scan", 0);
    assert_eq!(out.len(), 1, "cross-check must fire on a tag-less AU coord");
    assert_eq!(out[0].rule_id, "AU-056");
    assert!(out[0].description.contains("QLD"));
    assert!(out[0].rule_name.contains("corroborated"));
}

#[test]
fn au_056_flags_conflict_when_states_disagree() {
    use super::rules::rule_au_056_jurisdiction_cross_check;

    // Coordinate says QLD, the address says VIC → disjoint → Medium conflict.
    let ents = vec![
        mk_tagged(
            EntityKind::Coordinates,
            "-27.4766,153.0166",
            "geocode",
            &["geoint", "au-state:QLD"],
        ),
        mk_tagged(
            EntityKind::Address,
            "5 Collins Street, Melbourne VIC 3000",
            "see_know",
            &[],
        ),
    ];
    let out = rule_au_056_jurisdiction_cross_check(&RuleContext::new(&ents), "scan", 0);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].severity, super::Severity::Medium);
    assert!(out[0].rule_name.contains("conflict") || out[0].description.contains("travel"));
    assert!(out[0].description.contains("QLD") && out[0].description.contains("VIC"));
}

#[test]
fn au_056_agreement_stays_medium_and_lists_the_split_side() {
    use super::rules::rule_au_056_jurisdiction_cross_check;

    // Two coordinate fixes — one QLD, one NSW — but the address is QLD only. The
    // classes AGREE on QLD (a shared state ⇒ corroboration), yet the coordinate
    // side is internally split, so severity drops from High to Medium and the
    // description enumerates each side. This exercises the split-agreement branch
    // (the only path that emits the "(coordinates: …; addresses: …)" enumeration).
    let ents = vec![
        mk_tagged(
            EntityKind::Coordinates,
            "-27.4766,153.0166",
            "geocode",
            &["geoint", "au-state:QLD"],
        ),
        mk_tagged(
            EntityKind::Coordinates,
            "-33.8688,151.2093",
            "geocode",
            &["geoint", "au-state:NSW"],
        ),
        mk_tagged(
            EntityKind::Address,
            "12 Mary Street, Brisbane City QLD 4000",
            "see_know",
            &[],
        ),
    ];
    let out = rule_au_056_jurisdiction_cross_check(&RuleContext::new(&ents), "scan", 0);
    assert_eq!(out.len(), 1);
    assert_eq!(
        out[0].severity,
        super::Severity::Medium,
        "a split on one side downgrades corroboration to Medium"
    );
    assert!(out[0].rule_name.contains("corroborated"));
    // BTreeSet ordering makes the enumeration deterministic and slash-joined.
    assert!(
        out[0]
            .description
            .contains("(coordinates: NSW/QLD; addresses: QLD)"),
        "split side is enumerated: {}",
        out[0].description
    );
}

#[test]
fn au_056_silent_without_both_signal_classes() {
    use super::rules::rule_au_056_jurisdiction_cross_check;

    // Only a coordinate (no address) → nothing to cross-check.
    let coord_only = vec![mk_tagged(
        EntityKind::Coordinates,
        "-27.4766,153.0166",
        "geocode",
        &["au-state:QLD"],
    )];
    assert!(
        rule_au_056_jurisdiction_cross_check(&RuleContext::new(&coord_only), "scan", 0).is_empty()
    );

    // Only an address → likewise nothing.
    let addr_only = vec![mk_tagged(
        EntityKind::Address,
        "12 Mary Street, Brisbane City QLD 4000",
        "see_know",
        &[],
    )];
    assert!(
        rule_au_056_jurisdiction_cross_check(&RuleContext::new(&addr_only), "scan", 0).is_empty()
    );
}

// ─── AU-085 tests (phone-region jurisdiction cross-check) ───────────────────────────

#[test]
fn au_085_corroborates_when_phone_region_matches_address_state() {
    use super::rules::rule_au_085_phone_region_jurisdiction;

    // A NSW landline (02 → Central East: NSW/ACT) and a NSW address agree.
    let ents = vec![
        mk_tagged(EntityKind::Phone, "+61 2 9876 5432", "phone_au", &[]),
        mk_tagged(
            EntityKind::Address,
            "12 Smith Street, Sydney NSW 2000",
            "see_know",
            &[],
        ),
    ];
    let out = rule_au_085_phone_region_jurisdiction(&RuleContext::new(&ents), "scan", 0);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].rule_id, "AU-085");
    assert!(out[0].rule_name.contains("corroborates"));
    assert!(out[0].description.contains("NSW"));
    assert_eq!(out[0].entity_uids.len(), 2);
}

#[test]
fn au_056_infrastructure_address_does_not_vote_jurisdiction() {
    use super::rules::rule_au_056_jurisdiction_cross_check;
    // A hosting datacentre address is the HOST's location, not the subject's.
    // Paired with the subject's real QLD coordinate, the pre-fix rule read the
    // datacentre "Sydney NSW" as an address-state and fired a false NSW-vs-QLD
    // "jurisdiction conflict". The address side must exclude infrastructure geo
    // exactly as the coordinate side (`coord_state`) already does.
    let ents = vec![
        mk_tagged(
            EntityKind::Coordinates,
            "-27.4766,153.0166",
            "geocode",
            &["geoint", "au-state:QLD"],
        ),
        mk_tagged(
            EntityKind::Address,
            "Sydney NSW, AU",
            "urlscan",
            &[crate::core::tags::HOSTING],
        ),
    ];
    assert!(
        rule_au_056_jurisdiction_cross_check(&RuleContext::new(&ents), "scan", 0).is_empty(),
        "a hosting datacentre address must not vote the subject's jurisdiction"
    );
}

#[test]
fn au_085_infrastructure_address_does_not_corroborate_phone_region() {
    use super::rules::rule_au_085_phone_region_jurisdiction;
    // The AU-056 fix applies identically here: a WHOIS-registrant / hosting
    // datacentre address must not corroborate the subject's phone region. A NSW
    // landline + a registrant "Sydney NSW" address previously manufactured an NSW
    // agreement from pure infrastructure geo.
    let ents = vec![
        mk_tagged(EntityKind::Phone, "+61 2 9876 5432", "phone_au", &[]),
        mk_tagged(
            EntityKind::Address,
            "Sydney NSW, AU",
            "whois",
            &[crate::core::tags::REGISTRANT],
        ),
    ];
    assert!(
        rule_au_085_phone_region_jurisdiction(&RuleContext::new(&ents), "scan", 0).is_empty(),
        "a registrant datacentre address must not corroborate the phone region"
    );
}

#[test]
fn au_085_corroborates_against_a_tagless_coordinate_state() {
    use super::rules::rule_au_085_phone_region_jurisdiction;

    // A QLD landline (07) and a Brisbane coordinate with NO au-state tag — the
    // state is still derived from the lat/long, so the cross-check fires.
    // `search_engines` is an anchoring geo source, so the coordinate is a real
    // subject fix (not infrastructure geo excluded by `coord_state`).
    let ents = vec![
        mk_tagged(EntityKind::Phone, "(07) 3000 1234", "import", &[]),
        mk_tagged(
            EntityKind::Coordinates,
            "-27.4698,153.0251",
            "search_engines",
            &["geoint"],
        ),
    ];
    let out = rule_au_085_phone_region_jurisdiction(&RuleContext::new(&ents), "scan", 0);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].rule_id, "AU-085");
    assert!(out[0].description.contains("QLD"));
}

#[test]
fn au_085_flags_conflict_when_region_disagrees_with_address() {
    use super::rules::rule_au_085_phone_region_jurisdiction;

    // A VIC/TAS landline (03 → South East) but the only known address is in WA
    // (Central & West) → disjoint → a conflict worth surfacing.
    let ents = vec![
        mk_tagged(EntityKind::Phone, "+61 3 9876 5432", "phone_au", &[]),
        mk_tagged(
            EntityKind::Address,
            "5 Hay Street, Perth WA 6000",
            "see_know",
            &[],
        ),
    ];
    let out = rule_au_085_phone_region_jurisdiction(&RuleContext::new(&ents), "scan", 0);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].rule_id, "AU-085");
    assert!(out[0].rule_name.contains("conflicts"));
    assert!(out[0].description.contains("WA"));
}

#[test]
fn au_085_silent_for_mobile_or_missing_class() {
    use super::rules::rule_au_085_phone_region_jurisdiction;

    // A mobile has no geographic region — even with an address, nothing fires.
    let mobile = vec![
        mk_tagged(EntityKind::Phone, "+61 412 345 678", "phone_au", &[]),
        mk_tagged(
            EntityKind::Address,
            "12 Smith Street, Sydney NSW 2000",
            "x",
            &[],
        ),
    ];
    assert!(
        rule_au_085_phone_region_jurisdiction(&RuleContext::new(&mobile), "scan", 0).is_empty()
    );

    // A geographic landline but no address/coordinate → nothing to cross-check.
    let phone_only = vec![mk_tagged(
        EntityKind::Phone,
        "+61 2 9876 5432",
        "phone_au",
        &[],
    )];
    assert!(
        rule_au_085_phone_region_jurisdiction(&RuleContext::new(&phone_only), "scan", 0).is_empty()
    );
}

// ─── AU-102 tests (phone line-type profile) ────────────────────────────────────

#[test]
fn au_102_profiles_premises_mobile_and_business_lines() {
    use super::rules::rule_au_102_phone_line_type_profile;

    // A QLD landline (premises), a personal mobile, and a 1300 business line.
    let ents = vec![
        mk_tagged(EntityKind::Phone, "(07) 3000 1234", "phone_au", &[]),
        mk_tagged(EntityKind::Phone, "+61 412 345 678", "phone_au", &[]),
        mk_tagged(EntityKind::Phone, "1300 975 707", "import", &[]),
    ];
    let out = rule_au_102_phone_line_type_profile(&RuleContext::new(&ents), "scan", 0);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].rule_id, "AU-102");
    assert_eq!(out[0].severity, super::Severity::Medium);
    assert!(out[0].description.contains("geographic fixed line"));
    assert!(out[0].description.contains("North East")); // 07 → QLD region
    assert!(out[0].description.contains("personal mobile"));
    assert!(out[0].description.contains("business/service line"));
    assert_eq!(out[0].entity_uids.len(), 3);
}

#[test]
fn au_102_two_mobiles_only_is_low_and_fires() {
    use super::rules::rule_au_102_phone_line_type_profile;

    // Two distinct personal mobiles — no premises/business line → Low, but the
    // multiple-handset signal is worth surfacing.
    let ents = vec![
        mk_tagged(EntityKind::Phone, "+61 412 345 678", "phone_au", &[]),
        mk_tagged(EntityKind::Phone, "0413 222 333", "phone_au", &[]),
    ];
    let out = rule_au_102_phone_line_type_profile(&RuleContext::new(&ents), "scan", 0);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].severity, super::Severity::Low);
    assert!(out[0].description.contains("2 personal mobiles"));
    assert!(out[0].description.contains("multiple personal mobiles"));
}

#[test]
fn au_102_silent_for_a_single_lone_mobile() {
    use super::rules::rule_au_102_phone_line_type_profile;

    // One mobile alone is left to the bare Phone entity — no finding.
    let ents = vec![mk_tagged(
        EntityKind::Phone,
        "+61 412 345 678",
        "phone_au",
        &[],
    )];
    assert!(rule_au_102_phone_line_type_profile(&RuleContext::new(&ents), "scan", 0).is_empty());
}

#[test]
fn au_102_dedups_the_same_number_across_formats() {
    use super::rules::rule_au_102_phone_line_type_profile;

    // The same QLD landline in two formats normalises to one E.164 value → it is
    // counted once, so the profile reads "1 geographic fixed line".
    let ents = vec![
        mk_tagged(EntityKind::Phone, "(07) 3000 1234", "phone_au", &[]),
        mk_tagged(EntityKind::Phone, "0730001234", "import", &[]),
    ];
    let out = rule_au_102_phone_line_type_profile(&RuleContext::new(&ents), "scan", 0);
    assert_eq!(out.len(), 1);
    assert!(out[0].description.contains("1 geographic fixed line"));
    assert!(!out[0].description.contains("2 geographic"));
}

// ─── AU-103 tests (autonomous device self-location) ───────────────────────────────────────────

#[test]
fn au_103_gps_fix_with_corroboration_is_high_self_location() {
    use super::rules::rule_au_103_device_self_location;

    // A Brisbane GPS fix (device-sensor) + Wi-Fi APs + a serving AU cell.
    let mut fix = mk_tagged(
        EntityKind::Coordinates,
        "-27.4705,153.0260",
        "signal_radar",
        &["device-sensor", "provider:gps", "accuracy:8m", "geoint"],
    );
    fix.confidence = 0.90;
    let wifi1 = mk_tagged(
        EntityKind::MacAddress,
        "AA:BB:CC:DD:EE:01",
        "signal_radar",
        &[crate::core::tags::WIFI_AP],
    );
    let wifi2 = mk_tagged(
        EntityKind::MacAddress,
        "AA:BB:CC:DD:EE:02",
        "signal_radar",
        &[crate::core::tags::WIFI_AP],
    );
    let cell = mk_tagged(
        EntityKind::DeviceId,
        "505-1-100-200",
        "signal_radar",
        &[crate::core::tags::CELL_TOWER],
    );
    let out =
        rule_au_103_device_self_location(&RuleContext::new(&[fix, wifi1, wifi2, cell]), "scan", 0);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].rule_id, "AU-103");
    assert_eq!(out[0].severity, super::Severity::High);
    assert!(out[0].description.contains("near Brisbane"));
    assert!(out[0].description.contains("GPS fix"));
    assert!(out[0].description.contains("±8 m"));
    assert!(out[0].description.contains("2 Wi-Fi APs"));
    assert!(out[0].description.contains("no seed input"));
    assert_eq!(out[0].entity_uids.len(), 4);
}

#[test]
fn au_103_network_fix_only_is_medium() {
    use super::rules::rule_au_103_device_self_location;

    // A network-grade fix (no provider:gps tag) → Medium.
    let mut fix = mk_tagged(
        EntityKind::Coordinates,
        "-31.9523,115.8613",
        "device_sensors",
        &["device-sensor", "provider:network", "accuracy:450m"],
    );
    fix.confidence = 0.60;
    let out = rule_au_103_device_self_location(&RuleContext::new(&[fix]), "scan", 0);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].severity, super::Severity::Medium);
    assert!(out[0].description.contains("network fix"));
    assert!(out[0].description.contains("Perth"));
}

#[test]
fn au_103_presence_only_without_a_fix_is_low() {
    use super::rules::rule_au_103_device_self_location;

    // No coordinate fix, but Wi-Fi + cell + Bluetooth establish presence → Low.
    let wifi = mk_tagged(
        EntityKind::MacAddress,
        "AA:BB:CC:DD:EE:01",
        "signal_radar",
        &[crate::core::tags::WIFI_AP],
    );
    let cell = mk_tagged(
        EntityKind::DeviceId,
        "505-2-1-2",
        "signal_radar",
        &[crate::core::tags::CELL_TOWER],
    );
    let bt = mk_tagged(
        EntityKind::MacAddress,
        "11:22:33:44:55:66",
        "signal_radar",
        &["bluetooth"],
    );
    let out = rule_au_103_device_self_location(&RuleContext::new(&[wifi, cell, bt]), "scan", 0);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].severity, super::Severity::Low);
    assert!(out[0].description.contains("no precise fix"));
    assert!(out[0].description.contains("1 Wi-Fi AP"));
    assert!(out[0].description.contains("1 Bluetooth device"));
}

#[test]
fn au_103_flags_foreign_cell_under_an_au_fix() {
    use super::rules::rule_au_103_device_self_location;

    // An AU GPS fix served by a non-AU cell (MCC 310, USA) → roaming/SIM note.
    let mut fix = mk_tagged(
        EntityKind::Coordinates,
        "-27.4705,153.0260",
        "signal_radar",
        &["device-sensor", "provider:gps", "accuracy:10m"],
    );
    fix.confidence = 0.90;
    let cell = mk_tagged(
        EntityKind::DeviceId,
        "310-260-1-2",
        "signal_radar",
        &[crate::core::tags::CELL_TOWER],
    );
    let out = rule_au_103_device_self_location(&RuleContext::new(&[fix, cell]), "scan", 0);
    assert_eq!(out.len(), 1);
    assert!(out[0].description.contains("MCC 310 is non-Australian"));
}

#[test]
fn au_103_silent_with_no_device_signals() {
    use super::rules::rule_au_103_device_self_location;

    // A remote subject's coordinate (NOT device-sensor tagged) must not fire — the
    // rule concerns only the operator's own device.
    let subject = mk_tagged(
        EntityKind::Coordinates,
        "-33.8688,151.2093",
        "see_know",
        &[],
    );
    assert!(rule_au_103_device_self_location(&RuleContext::new(&[subject]), "scan", 0).is_empty());
    assert!(rule_au_103_device_self_location(&RuleContext::new(&[]), "scan", 0).is_empty());
}

// ─── AU-057 tests ───────────────────────────────────────────────────────────────────

#[test]
fn au_057_two_brisbane_coords_produce_synthesised_fix() {
    use super::rules::rule_au_057_synthesised_location_fix;

    // Two Brisbane coordinates both at confidence 0.70, both person-anchoring
    // sources → AU-057 fires with a synthesised point between them; severity is
    // Medium (2 inputs).
    let ents = vec![
        {
            let mut e = Entity::new(EntityKind::Coordinates, "-27.4698,153.0251", 0.70, "scan");
            e.add_evidence(Evidence::new("geocode", "Brisbane CBD fix".to_string()));
            e
        },
        {
            let mut e = Entity::new(EntityKind::Coordinates, "-27.4766,153.0166", 0.70, "scan");
            e.add_evidence(Evidence::new("wigle", "Brisbane suburb fix".to_string()));
            e
        },
    ];
    let out = rule_au_057_synthesised_location_fix(&RuleContext::new(&ents), "scan", 0);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].rule_id, "AU-057");
    assert_eq!(out[0].severity, super::Severity::Medium);
    assert!(out[0].description.contains("2 confirmed"));
    assert!(out[0].entity_uids.len() == 2);
    // The synthesised median is named via the offline reverse geocoder.
    assert!(
        out[0]
            .description
            .contains("primary location near Brisbane, QLD"),
        "synthesised fix is reverse-geocoded: {}",
        out[0].description
    );
}

#[test]
fn au_057_single_coord_does_not_fire() {
    use super::rules::rule_au_057_synthesised_location_fix;

    let ents = vec![{
        let mut e = Entity::new(EntityKind::Coordinates, "-27.4698,153.0251", 0.70, "scan");
        e.add_evidence(Evidence::new("geocode", "single fix".to_string()));
        e
    }];
    assert!(rule_au_057_synthesised_location_fix(&RuleContext::new(&ents), "scan", 0).is_empty());
}

#[test]
fn au_057_low_confidence_coords_do_not_fire() {
    use super::rules::rule_au_057_synthesised_location_fix;

    // Both coords are below the 0.60 threshold → rule is silent.
    let ents = vec![
        {
            let mut e = Entity::new(EntityKind::Coordinates, "-27.4698,153.0251", 0.55, "scan");
            e.add_evidence(Evidence::new("geocode", "Brisbane CBD fix".to_string()));
            e
        },
        {
            let mut e = Entity::new(EntityKind::Coordinates, "-27.4766,153.0166", 0.55, "scan");
            e.add_evidence(Evidence::new("photon", "Brisbane suburb fix".to_string()));
            e
        },
    ];
    assert!(rule_au_057_synthesised_location_fix(&RuleContext::new(&ents), "scan", 0).is_empty());
}
