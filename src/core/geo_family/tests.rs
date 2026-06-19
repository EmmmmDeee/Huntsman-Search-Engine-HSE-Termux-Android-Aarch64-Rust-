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
fn family_postcode_reads_value_token_then_evidence() {
    // From the value ("QLD 4518, Australia").
    let addr = {
        let mut e = Entity::new(EntityKind::Address, "QLD 4518, Australia", 0.3, "s");
        e.tag("family-candidate");
        e
    };
    assert_eq!(family_postcode(&addr).as_deref(), Some("4518"));
    // From a `postcode` evidence attribute on an owner Person.
    assert_eq!(
        family_postcode(&fam("Stephen Moreau", Some("4169"))).as_deref(),
        Some("4169")
    );
    // None when there's no AU postcode anywhere.
    assert!(family_postcode(&fam("Stephen Moreau", None)).is_none());
    // A 4-digit token out of the AU range is rejected.
    let bad = Entity::new(EntityKind::Address, "Apt 9999 Nowhere", 0.3, "s");
    assert!(family_postcode(&bad).is_none());
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
