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
fn corroboration_needs_a_confirmed_subject_fix_and_proximity() {
    // Subject's confirmed GPS near Woodford, QLD; a coarse 0.4 guess must NOT
    // anchor (only ≥0.60 confirmed fixes do).
    let mut gps = Entity::new(EntityKind::Coordinates, "-26.815,152.814", 0.9, "s");
    gps.tag("geoint");
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
fn discordant_namesake_is_the_far_complement_of_corroboration() {
    // Subject's confirmed GPS near Woodford, QLD (Brisbane catchment).
    let mut gps = Entity::new(EntityKind::Coordinates, "-26.815,152.814", 0.9, "s");
    gps.tag("geoint");
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
