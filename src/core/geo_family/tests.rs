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
    // Subject's confirmed GPS near Woodford, QLD; a coarse 0.4 guess must NOT
    // anchor (only ≥0.60 confirmed fixes do).
    let mut gps = Entity::new(EntityKind::Coordinates, "-26.815,152.814", 0.9, "s");
    gps.tag("geoint");
    // Anchoring source (handset GNSS) — a real person fix, not infrastructure geo.
    gps.add_evidence(Evidence::new("signal_radar", "gps"));
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
fn radar_sentinel_never_anchors_a_subject_fix() {
    // `hse radar` seeds every sweep with a sentinel Coordinates entity (0,0) at
    // confidence 0.90 with `seed`/`subject` tags — high enough to clear
    // SUBJECT_FIX_MIN on its own. Without the sentinel guard it would anchor
    // every family-candidate proximity check on null island; a Cairns namesake
    // ~9600 km from (0,0) would then wrongly read as "far from the subject" for
    // the right reason but the wrong location, and a coincidental near-(0,0)
    // resolution (there is none in AU postcodes, but the anchor itself is
    // simply wrong) would corroborate nobody real.
    let mut sentinel = Entity::new(
        EntityKind::Coordinates,
        crate::core::scan::RADAR_SENTINEL_COORD_RAW,
        0.90,
        "s",
    );
    sentinel.tag("seed");
    sentinel.tag("subject");
    let mut real_gps = Entity::new(EntityKind::Coordinates, "-26.815,152.814", 0.9, "s");
    real_gps.tag("geoint");
    real_gps.add_evidence(Evidence::new("signal_radar", "gps"));

    let fixes = subject_fixes(&[sentinel.clone(), real_gps.clone()]);
    assert_eq!(
        fixes.len(),
        1,
        "the sentinel must not become a second confirmed subject fix"
    );
    assert_eq!(fixes[0].uid, real_gps.uid);

    // Sentinel-only (a MAC-radar sweep with no other geo source) must anchor
    // nothing at all, not fall back to null island.
    assert!(subject_fixes(&[sentinel]).is_empty());
}

#[test]
fn discordant_namesake_is_the_far_complement_of_corroboration() {
    // Subject's confirmed GPS near Woodford, QLD (Brisbane catchment).
    let mut gps = Entity::new(EntityKind::Coordinates, "-26.815,152.814", 0.9, "s");
    gps.tag("geoint");
    // Anchoring source (handset GNSS) — a real person fix, not infrastructure geo.
    gps.add_evidence(Evidence::new("signal_radar", "gps"));
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
fn subject_fix_excludes_infrastructure_coordinates() {
    // A datacentre/hosting coordinate can clear SUBJECT_FIX_MIN yet is NOT the
    // subject's location: anchoring on it would widen the "confirmed area" to the
    // host's metro, so a same-surname candidate near the DATACENTRE reads as kin.
    // A HOSTING-tagged coord and a bare coord (no anchoring source) must both be
    // excluded from subject_fixes; a person-anchored coord is included (control).
    let mut hosting = Entity::new(EntityKind::Coordinates, "-27.4698,153.0251", 0.9, "s");
    hosting.tag(crate::core::tags::HOSTING);
    hosting.add_evidence(Evidence::new("ip_geo", "geolocated"));
    assert!(
        subject_fixes(&[hosting]).is_empty(),
        "a hosting coordinate must not anchor the subject"
    );

    let mut bare = Entity::new(EntityKind::Coordinates, "-27.4698,153.0251", 0.9, "s");
    bare.add_evidence(Evidence::new("ip_geo", "geolocated"));
    assert!(
        subject_fixes(&[bare]).is_empty(),
        "a bare IP-geo coordinate (no anchoring source) must not anchor the subject"
    );

    // Control: the same point, person-anchored (device GPS), IS a subject fix.
    let mut anchored = Entity::new(EntityKind::Coordinates, "-27.4698,153.0251", 0.9, "s");
    anchored.add_evidence(Evidence::new("signal_radar", "gps"));
    assert_eq!(
        subject_fixes(&[anchored]).len(),
        1,
        "a person-anchored coordinate still anchors the subject"
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

#[test]
fn real_scan_us_breach_address_reproduction() {
    // Direct reproduction of a real "Riley Morley" scan's debug bundle: a US
    // oathnet_pro breach-candidate Address entity
    // "1218 E Grumling Rd., Hodges, Sc, 29653" (South Carolina, evidence
    // `postal_code=29653`, `addr_postal=29653`) was tagged `geo_corroboration`
    // "~0 km from the subject's confirmed location" against an Australian
    // subject anchor (QLD 4124). Check what `au_postcode`/`distance_to_subject`
    // actually return for this entity shape, so a genuine defect is root-caused
    // against real data rather than assumed.
    let mut us_breach = Entity::new(
        EntityKind::Address,
        "1218 E Grumling Rd., Hodges, Sc, 29653",
        0.32,
        "s",
    );
    us_breach.tag("breach");
    us_breach.tag("oathnet-pro");
    us_breach.tag(crate::core::tags::CANDIDATE);
    us_breach.add_evidence(
        Evidence::new("oathnet_pro", "Breach on ebay.com")
            .with_attr("city", "Hodges")
            .with_attr("country", "US")
            .with_attr("postal_code", "29653")
            .with_attr("state", "Sc"),
    );
    us_breach.add_evidence(
        Evidence::new("geo_normalize", "Address parse + normalization")
            .with_attr("addr_city", "Hodges")
            .with_attr("addr_postal", "29653")
            .with_attr("addr_street", "1218 E Grumling Rd."),
    );

    // The value's own trailing digit run ("29653") is 5 digits — rejected.
    // Neither evidence record uses the literal key "postcode" (they use
    // `postal_code` / `addr_postal`), so no AU postcode should resolve here.
    assert!(
        au_postcode(&us_breach).is_none(),
        "a 5-digit US ZIP under postal_code/addr_postal keys must never resolve as an AU postcode"
    );

    let subject = subject_locations(&[{
        let mut anchor = Entity::new(EntityKind::Address, "QLD 4124, Australia", 0.38, "s");
        anchor.tag("exact-name-match");
        anchor
    }]);
    assert!(!subject.is_empty(), "the QLD anchor itself must resolve");
    assert_eq!(
        distance_to_subject(&us_breach, &subject),
        None,
        "a US breach address with no resolvable AU postcode must not report ANY distance \
         to the subject — it must never be corroborated as '~0 km' away"
    );
}

#[test]
fn person_grain_postcode_refuses_an_ip_geolocation() {
    // Exactly what `ipquery` builds: a CITY-grain Address composed from the IP's
    // city/state/country, carrying `geo_ev()` — which folds the IP block's `zip`
    // in as `postcode` alongside the `ip` it came from
    // (`modules/ipquery/mod.rs:267,292`). `ip2location` and `ip_geo` do the same.
    let ip_geo = {
        let mut e = Entity::new(
            EntityKind::Address,
            "Sydney, New South Wales, Australia",
            0.58,
            "s",
        );
        e.tag("ipquery");
        e.add_evidence(
            Evidence::new("ipquery", "Geolocation for 1.2.3.4")
                .with_attr("ip", "1.2.3.4")
                .with_attr("postcode", "2000"),
        );
        e
    };
    // `au_postcode` still reports it — the raw accessor is unchanged, and other
    // callers may legitimately want the IP's postcode.
    assert_eq!(au_postcode(&ip_geo).as_deref(), Some("2000"));
    // The person-grain accessor refuses it. This is what keeps a geolocation
    // database's guess for an IP BLOCK out of the headline residence rung, where
    // it was reported as an 8 km "postcode / suburb grain" fix at full
    // confidence — walking around the login-IP rung's deliberate ≤ 0.50 cap.
    assert!(
        au_postcode_person_grain(&ip_geo).is_none(),
        "an IP geolocation must not supply a suburb-grain postcode"
    );
}

#[test]
fn person_grain_postcode_keeps_a_real_postal_record() {
    // A breach/register postcode on a NON-family-candidate entity carries no
    // `ip` attribute and no `family-candidate` tag, so it is untouched — the
    // legitimate rung-3/4 input must still work.
    let mut owner = Entity::new(EntityKind::Person, "Stephen Moreau", 0.32, "s");
    owner.add_evidence(Evidence::new("qld_unclaimed", "owner").with_attr("postcode", "4169"));
    assert_eq!(au_postcode_person_grain(&owner).as_deref(), Some("4169"));
    // An Address naming its postcode in the VALUE, with no evidence at all.
    let addr = Entity::new(EntityKind::Address, "QLD 4518, Australia", 0.3, "s");
    assert_eq!(au_postcode_person_grain(&addr).as_deref(), Some("4518"));
}

#[test]
fn person_grain_postcode_refuses_a_family_candidate() {
    // `fam()` mints exactly the real au_unclaimed shape: a non-exact co-owner
    // Person at confidence 0.32, tagged `family-candidate`, carrying a
    // structured `postcode` attribute (qld_helpers.rs:373-414). `au_postcode`
    // still reports it (the raw accessor is unchanged and `distance_to_subject`
    // legitimately needs it to measure a relative's distance FROM the subject).
    let relative = fam("Stephen Moreau", Some("4169"));
    assert_eq!(au_postcode(&relative).as_deref(), Some("4169"));
    // The person-grain accessor refuses it: `subject_fixes` already refuses this
    // same source for the SUBJECT's own anchor ("a family-candidate's own
    // address never anchors... so there is no circularity") — this closes the
    // same gap for `au_postcode_person_grain`'s two callers
    // (`best_au_location_estimate`'s postcode rung and
    // `au_location_corroboration`), which do not go through `subject_fixes`.
    // Without this, a scan with no exact-name-matched subject address could
    // report a RELATIVE's suburb as the subject's own headline residence.
    assert!(
        au_postcode_person_grain(&relative).is_none(),
        "a family-candidate's postcode must not supply the subject's own location"
    );
}

#[test]
fn person_grain_postcode_survives_a_mixed_provenance_entity() {
    // An entity corroborated by BOTH an IP geolocation and a real postal record
    // keeps the postal one: only the IP-derived evidence records are skipped,
    // not the whole entity.
    let mut mixed = Entity::new(EntityKind::Person, "Stephen Moreau", 0.5, "s");
    mixed.add_evidence(
        Evidence::new("ipquery", "Geolocation for 1.2.3.4")
            .with_attr("ip", "1.2.3.4")
            .with_attr("postcode", "2000"),
    );
    mixed.add_evidence(Evidence::new("qld_unclaimed", "owner").with_attr("postcode", "4169"));
    assert_eq!(
        au_postcode_person_grain(&mixed).as_deref(),
        Some("4169"),
        "the real postal record must survive alongside an IP geolocation"
    );
}
