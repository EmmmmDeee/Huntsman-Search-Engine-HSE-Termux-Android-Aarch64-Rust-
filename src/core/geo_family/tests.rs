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

/// An entity may carry several records that each name a postcode — one QLD
/// unclaimed-money owner record per register row (review of #649). Taking the
/// first valid one let evidence ORDER choose the owner's town; records that
/// disagree give no single town, so none anchors, in either order. Records
/// that agree still anchor, and a pooled attribute is judged the same way.
#[test]
fn au_postcode_anchors_only_on_a_single_distinct_postcode() {
    let owner = |pcs: &[&str]| {
        let mut e = Entity::new(EntityKind::Person, "Curt Avery", 0.32, "s");
        for (i, pc) in pcs.iter().enumerate() {
            e.add_evidence(
                Evidence::new("au_unclaimed", format!("owner row {i}")).with_attr("postcode", *pc),
            );
        }
        e
    };
    assert_eq!(au_postcode(&owner(&["4555", "4557"])), None);
    assert_eq!(
        au_postcode(&owner(&["4557", "4555"])),
        None,
        "order-independent"
    );
    assert_eq!(
        au_postcode(&owner(&["4555", "4555"])).as_deref(),
        Some("4555"),
        "rows that agree anchor"
    );
    // An invalid value beside a valid one is not a second town.
    assert_eq!(
        au_postcode(&owner(&["65101", "4555"])).as_deref(),
        Some("4555")
    );
    let mut pooled = Entity::new(EntityKind::Person, "Curt Avery", 0.32, "s");
    pooled.add_evidence(Evidence::new("au_unclaimed", "owner").with_attr("postcode", "4555; 4557"));
    assert_eq!(
        au_postcode(&pooled),
        None,
        "a pooled attribute, judged alike"
    );
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
    assert!(is_geo_corroborated_family(&near_addr, &subject, None));
    assert!(is_geo_corroborated_family(&near_person, &subject, None));
    assert!(
        !is_geo_corroborated_family(&far, &subject, None),
        "Cairns is far"
    );

    // A non-family-candidate near the subject is not corroborated as family
    // (no `family-candidate` tag → the surname angle never applied).
    let other = Entity::new(EntityKind::Address, "QLD 4518, Australia", 0.3, "s");
    assert!(!is_geo_corroborated_family(&other, &subject, None));

    // No confirmed subject fix → nothing corroborates.
    assert!(!is_geo_corroborated_family(&near_addr, &[], None));
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
    assert!(is_geo_discordant_namesake(&perth, &subject, None));
    assert!(!is_geo_corroborated_family(&perth, &subject, None));

    // The bands don't overlap: an in-area relative (Beerwah 4519) is corroborated
    // and NEVER discordant — the near band and the far band are disjoint.
    let near = {
        let mut e = Entity::new(EntityKind::Address, "QLD 4519, Australia", 0.32, "s");
        e.tag("family-candidate");
        e
    };
    assert!(is_geo_corroborated_family(&near, &subject, None));
    assert!(!is_geo_discordant_namesake(&near, &subject, None));

    // A non-family-candidate is never flagged (the surname angle never applied).
    let other = Entity::new(EntityKind::Address, "WA 6000, Australia", 0.32, "s");
    assert!(!is_geo_discordant_namesake(&other, &subject, None));
    // No confirmed subject fix → nothing is judged discordant.
    assert!(!is_geo_discordant_namesake(&perth, &[], None));

    // The namesake decision composes geometry with surname distinctiveness: a far
    // bearer is a namesake only when the shared surname is COMMON. A distinctive
    // surname (the rare-surname subject's interstate kin) is never mislabelled.
    assert!(
        is_namesake(&perth, &subject, None, true),
        "far + common = namesake"
    );
    assert!(
        !is_namesake(&perth, &subject, None, false),
        "far + distinctive surname = distant kin, not a namesake"
    );
    assert!(
        !is_namesake(&near, &subject, None, true),
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
    assert!(is_geo_corroborated_family(&kin_addr, &subject, None));
    let perth = {
        let mut e = Entity::new(EntityKind::Person, "Curt Moreau", 0.32, "s");
        e.tag("family-candidate");
        e.add_evidence(Evidence::new("qld_unclaimed", "owner").with_attr("postcode", "6000"));
        e
    };
    assert!(is_geo_discordant_namesake(&perth, &subject, None));
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
    // A breach/register postcode carries no `ip` attribute, so it is untouched —
    // the legitimate rung-3/4 input must still work.
    assert_eq!(
        au_postcode_person_grain(&fam("Stephen Moreau", Some("4169"))).as_deref(),
        Some("4169")
    );
    // An Address naming its postcode in the VALUE, with no evidence at all.
    let addr = Entity::new(EntityKind::Address, "QLD 4518, Australia", 0.3, "s");
    assert_eq!(au_postcode_person_grain(&addr).as_deref(), Some("4518"));
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

/// REQ-GEO-FAMILY-001. A real "Ian Thorpe" scan promoted every Thorley that a
/// pivot's register search returned to a "shared-surname relative" of the
/// subject, and stamped the seed Person itself as its own relative: the engine's
/// promotion pass read `family-candidate` (set relative to whichever name the
/// module ran on) as "the subject's family" with no surname check, while AU-061
/// applied one inline. One membership test now decides for both.
#[test]
fn only_the_subjects_surname_kin_and_never_the_subject_are_family() {
    let mut own = Entity::new(EntityKind::Address, "QLD 4519, Australia", 0.38, "s");
    own.tag("exact-name-match");
    let subject = subject_locations(&[own]);
    let kin = |name: &str| {
        let mut e = Entity::new(EntityKind::Person, name, 0.35, "s");
        e.tag("family-candidate");
        e.add_evidence(Evidence::new("qld_unclaimed", "owner").with_attr("postcode", "4518"));
        e
    };

    let relative = kin("Carol Thorpe");
    let near_surname = kin("Anna Thorley");
    assert!(is_geo_corroborated_family(
        &relative,
        &subject,
        Some("thorpe")
    ));
    assert!(
        !is_geo_corroborated_family(&near_surname, &subject, Some("thorpe")),
        "a Thorley is not a Thorpe's shared-surname relative"
    );
    // Without a known subject surname the old behaviour holds (nothing to check).
    assert!(is_geo_corroborated_family(&near_surname, &subject, None));

    // The subject is never its own relative, however the tag reached it.
    for role in ["seed", "subject", "exact-name-match"] {
        let mut me = kin("Ian Thorpe");
        me.tag(role);
        assert!(
            !is_geo_corroborated_family(&me, &subject, Some("thorpe")),
            "a `{role}` entity must not be promoted as the subject's relative"
        );
        assert!(!is_subject_family_candidate(&me, Some("thorpe")));
    }

    // The far half shares the membership test.
    let mut far = kin("Anna Thorley");
    far.evidence.clear();
    far.add_evidence(Evidence::new("qld_unclaimed", "owner").with_attr("postcode", "6000"));
    assert!(!is_geo_discordant_namesake(&far, &subject, Some("thorpe")));
    assert!(!is_namesake(&far, &subject, Some("thorpe"), true));
}

#[test]
fn subject_surname_prefers_the_seed_over_a_register_name_match() {
    // A register row exact-matched to some name, listed ahead of the seed anchor:
    // the seed still decides "whose surname".
    let mut row = Entity::new(EntityKind::Person, "Ian Thorley", 0.6, "s");
    row.tag("exact-name-match");
    let mut seed = Entity::new(EntityKind::Person, "Ian Thorpe", 0.6, "s");
    seed.tag("seed");
    seed.tag("subject");
    assert_eq!(
        subject_surname(&[row.clone(), seed]).as_deref(),
        Some("thorpe")
    );
    // With no seed anchor the register match is still used.
    assert_eq!(subject_surname(&[row]).as_deref(), Some("thorley"));
}

/// REQ-GEO-FAMILY-002: a city named in a search result, a centroid derived from
/// an Address, and a forward geocode of a venue named after the subject all
/// clear the confidence floor and the correlator's anchoring allowlist, yet
/// none of them observed the subject. Scan 7258fc07 anchored "the subject's
/// confirmed location" on exactly these three and promoted ~235 register rows
/// within 150 km of them to corroborated relatives.
#[test]
fn a_search_snippet_city_or_forward_geocode_is_not_a_subject_fix() {
    let mut city = Entity::new(EntityKind::Coordinates, "-33.8688,151.2093", 0.72, "s");
    city.tag("geoint");
    city.tag(crate::core::tags::SEARCH_GEOCODED);
    city.add_evidence(
        Evidence::new(
            "search_engines",
            "Geocoded from search address: Sydney, New South Wales",
        )
        .with_attr("method", "known-city-lookup")
        .with_attr("source_address", "Sydney, New South Wales"),
    );

    let mut derived = Entity::new(EntityKind::Coordinates, "-27.4698,153.0251", 0.65, "s");
    derived.tag(crate::core::tags::ADDR_DERIVED);
    derived.add_evidence(
        Evidence::new(
            "search_engines",
            "Inline geocode of address 'Brisbane, QLD'",
        )
        .with_attr(crate::core::engine::ADDR_ENTITY_UID_ATTR, "x")
        .with_attr("addr_value", "Brisbane, QLD"),
    );

    let mut poi = Entity::new(EntityKind::Coordinates, "-33.877410,151.198900", 0.60, "s");
    poi.tag("photon");
    poi.add_evidence(
        Evidence::new(
            "photon",
            "Photon geocoded \"Ian Thorpe Aquatic Centre in Ultimo, New South Wales\"",
        )
        .with_attr(
            "input_address",
            "Ian Thorpe Aquatic Centre in Ultimo, New South Wales",
        ),
    );

    // A device-class source copied from an Address onto a centroid is still the
    // Address's source, not a sighting of the subject.
    let mut copied = Entity::new(EntityKind::Coordinates, "-31.9505,115.8605", 0.70, "s");
    copied.add_evidence(
        Evidence::new("exif_geo", "Inline geocode of address 'Perth, WA'")
            .with_attr(crate::core::engine::ADDR_ENTITY_UID_ATTR, "y"),
    );

    assert!(
        subject_fixes(&[city.clone(), derived, poi, copied]).is_empty(),
        "no snippet city, derived centroid or forward geocode anchors the subject"
    );

    // Control: a handset GNSS fix on the very same point does.
    let mut gps = Entity::new(EntityKind::Coordinates, "-33.8688,151.2093", 0.9, "s");
    gps.add_evidence(Evidence::new("signal_radar", "gps"));
    assert_eq!(subject_fixes(&[city, gps]).len(), 1);
}
