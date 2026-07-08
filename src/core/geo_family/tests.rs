use super::*;
use crate::core::entity::Evidence;

fn fam(value: &str, postcode: Option<&str>) -> Entity {
    let mut e = Entity::new(EntityKind::Person, value, 0.32, "s");
    e.tag("family-candidate");
    if let Some(pc) = postcode {
        e.add_evidence(Evidence::new("qld_unclaimed", "owner").with_attr("postcode", pc));
    }
    e
}

#[test]
fn au_postcode_reads_value_token_then_evidence() {
    // From the value ("QLD 4518, Australia").
    let addr = {
        let mut e = Entity::new(EntityKind::Address, "QLD 4518, Australia", 0.3, "s");
        e.tag("family-candidate");
        e
    };
    assert_eq!(au_postcode(&addr).as_deref(), Some("4518"));
    // From a `postcode` evidence attribute on an owner Person.
    assert_eq!(
        au_postcode(&fam("Stephen Moreau", Some("4169"))).as_deref(),
        Some("4169")
    );
    // None when there's no AU postcode anywhere.
    assert!(au_postcode(&fam("Stephen Moreau", None)).is_none());
    // A 4-digit token out of the AU range is rejected.
    let bad = Entity::new(EntityKind::Address, "Apt 9999 Nowhere", 0.3, "s");
    assert!(au_postcode(&bad).is_none());
}

#[test]
fn au_postcode_ignores_a_leading_us_street_number() {
    // Real captured US breach addresses (Huntsman scan 90b936dc…). The leading
    // 4-digit STREET NUMBER must not be read as an AU postcode — the real ZIP is a
    // 5-digit value that trails, so only it is a candidate and it is rejected for
    // length. Without this the Missouri street number "1019" resolved as an AU
    // postcode and dragged the foreign record into the subject's geo footprint.
    let us = Entity::new(
        EntityKind::Address,
        "1019 Winston Dr, Jefferson City, MO, 65101",
        0.25,
        "s",
    );
    assert!(au_postcode(&us).is_none());
    let us2 = Entity::new(
        EntityKind::Address,
        "5528 North 73rd Avenue, Glendale, AZ, 85303",
        0.25,
        "s",
    );
    assert!(au_postcode(&us2).is_none());
    // A genuine AU value still resolves from its trailing postcode.
    let au = Entity::new(
        EntityKind::Address,
        "12 Smith St, Beerwah QLD 4519",
        0.25,
        "s",
    );
    assert_eq!(au_postcode(&au).as_deref(), Some("4519"));
}

#[test]
fn au_postcode_ignores_value_digits_of_non_address_kinds() {
    // Regression: a stray 4-digit run in an Email / Username / Url / Person VALUE
    // must NOT be read as an AU postcode — previously it geolocated the entity to a
    // confident FALSE location. Only an Address carries a postcode in its value.
    for kind in [
        EntityKind::Email,
        EntityKind::Username,
        EntityKind::Url,
        EntityKind::Person,
    ] {
        let e = Entity::new(kind.clone(), "handle2000", 0.5, "s");
        assert!(
            au_postcode(&e).is_none(),
            "{kind:?} value digits must not be read as a postcode"
        );
    }
    // A STRUCTURED postcode evidence attribute still resolves for any kind.
    let mut u = Entity::new(EntityKind::Username, "someone", 0.5, "s");
    u.add_evidence(Evidence::new("src", "sum").with_attr("postcode", "4000"));
    assert_eq!(au_postcode(&u).as_deref(), Some("4000"));
}

#[test]
fn corroboration_needs_a_confirmed_subject_fix_and_proximity() {
    // Subject's confirmed on-device GPS near Woodford, QLD; a coarse 0.4 guess
    // must NOT anchor (only a genuine device/person-anchored fix does).
    let mut gps = Entity::new(EntityKind::Coordinates, "-26.815,152.814", 0.9, "s");
    gps.tag("geoint");
    gps.tag("device-sensor");
    let weak = Entity::new(EntityKind::Coordinates, "-20.0,145.0", 0.4, "s");

    let subject = subject_locations(&[gps.clone(), weak.clone()]);
    assert_eq!(
        subject.len(),
        1,
        "only the confirmed fix anchors the subject"
    );

    // Near (Beerwah 45xx / Brisbane 41xx) is corroborated; far (Cairns 48xx) not.
    let near_addr = {
        let mut e = Entity::new(EntityKind::Address, "QLD 4518, Australia", 0.3, "s");
        e.tag("family-candidate");
        e
    };
    let near_person = fam("Stephen Moreau", Some("4169"));
    let far = {
        let mut e = Entity::new(EntityKind::Address, "QLD 4870, Australia", 0.3, "s");
        e.tag("family-candidate");
        e
    };
    assert!(is_geo_corroborated_family(&near_addr, &subject));
    assert!(is_geo_corroborated_family(&near_person, &subject));
    assert!(!is_geo_corroborated_family(&far, &subject), "Cairns is far");

    // A non-family-candidate near the subject is not corroborated as family
    // (no `family-candidate` tag → the surname angle never applied).
    let other = Entity::new(EntityKind::Address, "QLD 4518, Australia", 0.3, "s");
    assert!(!is_geo_corroborated_family(&other, &subject));

    // No confirmed subject fix → nothing corroborates.
    assert!(!is_geo_corroborated_family(&near_addr, &[]));
}

#[test]
fn a_coarse_ip_derived_fix_never_anchors_the_subject_even_at_high_confidence() {
    // `ip_geo`'s own "fixed connection" city-level guess reaches EXACTLY
    // SUBJECT_FIX_MIN (0.60, see `ip_geo::mod::geo_conf`'s `else` branch) —
    // confidence alone must not be enough to anchor, since a free IP-geo API
    // routinely misses residential geolocation by tens of km even for "fixed"
    // connections (the module's own doc comment). Un-tagged, un-sourced this
    // would have anchored under the old confidence-only gate.
    let mut ip_fix = Entity::new(EntityKind::Coordinates, "-26.815,152.814", 0.60, "s");
    ip_fix.tag("geoint");
    ip_fix.add_evidence(Evidence::new("ip_geo", "fixed-connection geolocation"));
    assert!(
        subject_locations(&[ip_fix.clone()]).is_empty(),
        "a bare IP-geo lookup must not anchor the subject even at SUBJECT_FIX_MIN confidence"
    );

    // The same coordinate, this time genuinely person-anchored (a geocoded home
    // address), DOES anchor at the identical confidence and value.
    let mut geocoded = Entity::new(EntityKind::Coordinates, "-26.815,152.814", 0.60, "s");
    geocoded.tag("geoint");
    geocoded.add_evidence(Evidence::new("geocode", "forward geocode"));
    assert_eq!(
        subject_locations(&[geocoded]).len(),
        1,
        "a genuine person-anchoring source at the same confidence still anchors"
    );

    // And a device-sensor fix anchors even BELOW SUBJECT_FIX_MIN — on-device
    // telemetry is trusted regardless of its own accuracy-derived confidence.
    let mut weak_gps = Entity::new(EntityKind::Coordinates, "-26.815,152.814", 0.30, "s");
    weak_gps.tag("geoint");
    weak_gps.tag("device-sensor");
    assert_eq!(
        subject_locations(&[weak_gps]).len(),
        1,
        "a low-accuracy on-device fix still anchors — it is first-party telemetry, not third-party inference"
    );
}

#[test]
fn discordant_namesake_is_the_far_complement_of_corroboration() {
    // Subject's confirmed on-device GPS near Woodford, QLD (Brisbane catchment).
    let mut gps = Entity::new(EntityKind::Coordinates, "-26.815,152.814", 0.9, "s");
    gps.tag("geoint");
    gps.tag("device-sensor");
    let subject = subject_locations(&[gps]);

    // A same-surname candidate in Perth, WA (~3600 km) — shares the name, but a
    // whole continent away: flagged as a likely namesake.
    let perth = {
        let mut e = Entity::new(EntityKind::Address, "WA 6000, Australia", 0.32, "s");
        e.tag("family-candidate");
        e
    };
    assert!(is_geo_discordant_namesake(&perth, &subject));
    assert!(!is_geo_corroborated_family(&perth, &subject));

    // The bands don't overlap: an in-area relative (Beerwah 4519) is corroborated
    // and NEVER discordant — the near band and the far band are disjoint.
    let near = {
        let mut e = Entity::new(EntityKind::Address, "QLD 4519, Australia", 0.32, "s");
        e.tag("family-candidate");
        e
    };
    assert!(is_geo_corroborated_family(&near, &subject));
    assert!(!is_geo_discordant_namesake(&near, &subject));

    // A non-family-candidate is never flagged (the surname angle never applied).
    let other = Entity::new(EntityKind::Address, "WA 6000, Australia", 0.32, "s");
    assert!(!is_geo_discordant_namesake(&other, &subject));
    // No confirmed subject fix → nothing is judged discordant.
    assert!(!is_geo_discordant_namesake(&perth, &[]));

    // The namesake decision composes geometry with surname distinctiveness: a far
    // bearer is a namesake only when the shared surname is COMMON. A distinctive
    // surname (the rare-surname subject's interstate kin) is never mislabelled.
    assert!(
        is_namesake(&perth, &subject, true),
        "far + common = namesake"
    );
    assert!(
        !is_namesake(&perth, &subject, false),
        "far + distinctive surname = distant kin, not a namesake"
    );
    assert!(
        !is_namesake(&near, &subject, true),
        "a near relative is never a namesake, common surname or not"
    );
}

#[test]
fn subject_anchors_on_own_address_when_no_gps() {
    // The common scan: no GPS, but the subject's own suburb is known from a
    // register hit whose owner name exactly matched them (`exact-name-match`).
    let mut own = Entity::new(EntityKind::Address, "QLD 4519, Australia", 0.38, "s");
    own.tag("exact-name-match"); // the subject's own residence (Beerwah)
    // A coarse postcode-centroid coordinate (below the GPS gate) must NOT anchor…
    let weak = Entity::new(EntityKind::Coordinates, "-26.85,152.96", 0.30, "s");
    // …and a relative's own address never anchors (family-candidate, not the subject).
    let kin_addr = {
        let mut e = Entity::new(EntityKind::Address, "QLD 4518, Australia", 0.32, "s");
        e.tag("family-candidate");
        e
    };

    let fixes = subject_fixes(&[own.clone(), weak, kin_addr.clone()]);
    assert_eq!(fixes.len(), 1, "only the subject's own address anchors");
    assert_eq!(fixes[0].uid, own.uid);

    // With that address anchor alone, the geo angle still works: a nearby kin is
    // corroborated and a far namesake flagged — no GPS required.
    let subject = subject_locations(&[own]);
    assert!(is_geo_corroborated_family(&kin_addr, &subject));
    let perth = {
        let mut e = Entity::new(EntityKind::Person, "Curt Moreau", 0.32, "s");
        e.tag("family-candidate");
        e.add_evidence(Evidence::new("qld_unclaimed", "owner").with_attr("postcode", "6000"));
        e
    };
    assert!(is_geo_discordant_namesake(&perth, &subject));
}
