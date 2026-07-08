//! AU correlation rules — geo family. See `super` (rules/mod.rs) for the
//! shared helpers; every rule reaches them through `use super::*`.

use super::*;

mod chain;
mod cluster;
mod jurisdiction;
mod profile;

pub(in crate::core::correlator) use chain::*;
pub(in crate::core::correlator) use cluster::*;
pub(in crate::core::correlator) use jurisdiction::*;
pub(in crate::core::correlator) use profile::*;

/// The AU state/territory a confirmed `Coordinates` entity asserts. Prefers the
/// `au-state:XX` tag the geo builders attach, but falls back to deriving the
/// state straight from the lat/long via [`crate::util::geo::au_state_for_coords`]
/// when the tag is absent — a coordinate enters the graph from many modules
/// (`geo_normalize`, `search_engines`, `exif_geo`, …), only three of which tag
/// it, so a tag-only read silently dropped most real fixes (seen on a live
/// scan: a Brisbane coordinate from `geo_normalize` carried no tag and the
/// jurisdiction cross-check never fired). Only confirmed fixes (≥0.50) count, so
/// an off-region candidate can't assert a jurisdiction.
///
/// Infrastructure coordinates are excluded ([`is_infrastructure_geo`]): a bare
/// IP-geo/hosting/registrant fix locates the datacentre or domain owner, not the
/// subject, so it must not vote the subject's jurisdiction — the same guard every
/// sibling location rule applies (AU-018/026/030, AU-052/053/059). Without it a
/// Sydney-datacentre server IP behind the subject's domain would assert `NSW` and
/// manufacture a false AU-056 "jurisdiction conflict" against a real QLD address.
pub(super) fn coord_state(e: &Entity) -> Option<&'static str> {
    if e.kind != EntityKind::Coordinates || e.confidence < 0.50 || is_infrastructure_geo(e) {
        return None;
    }
    const AU_STATES: [&str; 8] = ["ACT", "NSW", "NT", "QLD", "SA", "TAS", "VIC", "WA"];
    if let Some(state) = e
        .tags
        .iter()
        .find_map(|t| t.strip_prefix("au-state:"))
        .and_then(|code| AU_STATES.into_iter().find(|s| *s == code))
    {
        return Some(state);
    }
    crate::util::geohash::parse_coords(&e.value)
        .and_then(|(lat, lon)| crate::util::geo::au_state_for_coords(lat, lon))
}

/// AU-099 — reverse-geocode the subject's coordinate fix to a human AU locality.
///
/// `coord_state` (and AU-056/098) resolve a coordinate to its *state*; a bare
/// `(-26.73, 152.76)` is still opaque to read. This labels each confirmed
/// `Coordinates` fix with the **nearest Australian population centre** — offline,
/// via [`crate::util::geo::nearest_au_locality`] — so an EXIF/GPS/geocoded fix
/// reads as "Maleny, QLD (~2 km)" instead of a lat/long. The distance is shown so
/// the precision is honest: a metro fix lands on its suburb/city, a remote one on
/// its nearest regional centre. Deduplicated per locality; Medium (a derived,
/// human-readable label on a coordinate the graph already holds). Offline, pure.
pub(in crate::core::correlator) fn rule_au_099_coordinate_reverse_geocode(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    use std::collections::{BTreeMap, BTreeSet};

    // locality -> (state, nearest km seen, contributing coordinate uids).
    // Infrastructure coordinates are excluded ([`is_infrastructure_geo`]): a bare
    // IP-geo/hosting fix is the datacentre's position, not the subject's, so it must
    // not be announced as "the subject's coordinate fix" — the same guard the
    // location-voting rules (AU-052/053/059, coord_state) already apply.
    let mut by_loc: BTreeMap<&'static str, (&'static str, f64, BTreeSet<String>)> = BTreeMap::new();
    for e in entities.iter().filter(|e| {
        e.kind == EntityKind::Coordinates && e.confidence >= 0.50 && !is_infrastructure_geo(e)
    }) {
        if let Some((lat, lon)) = crate::util::geohash::parse_coords(&e.value)
            && let Some((name, state, km)) = crate::util::geo::nearest_au_locality(lat, lon)
        {
            let entry = by_loc.entry(name).or_insert((state, km, BTreeSet::new()));
            if km < entry.1 {
                entry.1 = km;
            }
            entry.2.insert(e.uid.clone());
        }
    }

    by_loc
        .into_iter()
        .map(|(name, (state, km, uids))| {
            Correlation::new(
                "AU-099",
                "Coordinate reverse-geocoded to AU locality",
                Severity::Medium,
                format!(
                    "Subject's coordinate fix resolves to {name}, {state} (≈{km:.0} km, offline \
                     reverse geocode) — a human-readable locality for a bare GPS/EXIF fix"
                ),
                uids.into_iter().collect(),
                scan_id,
                ts,
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── AU-061 family geo-corroboration ───────────────────────────────────────

    #[test]
    fn au_061_corroborates_only_family_in_the_subjects_area() {
        use crate::core::entity::Evidence;
        // Subject's confirmed on-device GPS fix near Woodford, QLD.
        let mut gps = Entity::new(EntityKind::Coordinates, "-26.815,152.814", 0.9, "s");
        gps.tag("geoint");
        gps.tag("device-sensor");
        // Same-surname family, all `family-candidate`, postcode in value or evidence.
        let mut near_addr = Entity::new(EntityKind::Address, "QLD 4518, Australia", 0.32, "s");
        near_addr.tag("family-candidate"); // Beerwah (45xx) — ~40 km
        let mut near_person = Entity::new(EntityKind::Person, "Stephen Moreau", 0.35, "s");
        near_person.tag("family-candidate");
        near_person
            .add_evidence(Evidence::new("qld_unclaimed", "owner").with_attr("postcode", "4169"));
        let mut far = Entity::new(EntityKind::Address, "QLD 4870, Australia", 0.32, "s");
        far.tag("family-candidate"); // Cairns (48xx) — ~1000 km, must be excluded
        // Not family-candidate → ignored even though it's in the area.
        let other = Entity::new(EntityKind::Address, "QLD 4000, Australia", 0.5, "s");

        let ents = vec![
            gps.clone(),
            near_addr.clone(),
            near_person.clone(),
            far.clone(),
            other,
        ];
        let out = rule_au_061_family_geo_corroboration(&ents, "s", 0);
        assert_eq!(out.len(), 1, "one geo-corroboration correlation");
        let c = &out[0];
        assert_eq!(c.rule_id, "AU-061");
        assert!(matches!(c.severity, Severity::High), "2 in-area → High");
        assert!(c.description.contains("Stephen Moreau") && c.description.contains("4518"));
        assert!(!c.description.contains("4870"), "Cairns is excluded as far");
        // Links the subject coordinate + the two in-area relatives, not the far one.
        assert!(c.entity_uids.contains(&gps.uid));
        assert!(c.entity_uids.contains(&near_addr.uid) && c.entity_uids.contains(&near_person.uid));
        assert!(!c.entity_uids.contains(&far.uid));

        // No confirmed subject coordinate → nothing fires (no anchor to compare to).
        let no_gps = vec![near_addr];
        assert!(rule_au_061_family_geo_corroboration(&no_gps, "s", 0).is_empty());
    }

    // Build a GPS fix + a named subject + 3 same-surname family-candidates all in
    // the Brisbane catchment (≤150 km), to exercise the 3-candidate escalation.
    fn three_same_surname_in_area(subject_full_name: &str, surname: &str) -> Vec<Entity> {
        use crate::core::entity::Evidence;
        let mut gps = Entity::new(EntityKind::Coordinates, "-27.47,153.02", 0.9, "s"); // Brisbane
        gps.tag("geoint");
        gps.tag("device-sensor");
        let mut subject = Entity::new(EntityKind::Person, subject_full_name, 0.8, "s");
        subject.tag("subject");
        let cand = |given: &str, pc: &str| {
            let mut p = Entity::new(EntityKind::Person, format!("{given} {surname}"), 0.35, "s");
            p.tag("family-candidate");
            p.add_evidence(Evidence::new("qld_unclaimed", "owner").with_attr("postcode", pc));
            p
        };
        vec![
            gps,
            subject,
            cand("Erik", "4000"),
            cand("Jane", "4169"),
            cand("Paul", "4101"),
        ]
    }

    #[test]
    fn au_061_common_surname_caps_at_high_not_critical() {
        // Three "Smith"s in one metro catchment is coincidence, not a 3-relative
        // household — a COMMON subject surname must not reach Critical.
        let out = rule_au_061_family_geo_corroboration(
            &three_same_surname_in_area("Dana Smith", "Smith"),
            "s",
            0,
        );
        assert_eq!(out.len(), 1);
        assert!(
            matches!(out[0].severity, Severity::High),
            "common surname must cap at High, got {:?}",
            out[0].severity
        );
        assert!(out[0].description.to_lowercase().contains("common surname"));
    }

    #[test]
    fn au_061_distinctive_surname_reaches_critical_at_three() {
        // A distinctive surname keeps the strong 3-relative Critical signal.
        let out = rule_au_061_family_geo_corroboration(
            &three_same_surname_in_area("Dana Bamford", "Bamford"),
            "s",
            0,
        );
        assert_eq!(out.len(), 1);
        assert!(
            matches!(out[0].severity, Severity::Critical),
            "distinctive surname → Critical at 3, got {:?}",
            out[0].severity
        );
        assert!(out[0].description.contains("independently corroborate"));
    }

    #[test]
    fn au_061_excludes_different_surname_household_candidates() {
        use crate::core::entity::Evidence;
        // A see_know-style household member with a DIFFERENT surname is tagged
        // `family-candidate` but is NOT a shared-surname relative — it must not be
        // counted toward AU-061's "shared surname" claim (a false evidentiary basis).
        let mut gps = Entity::new(EntityKind::Coordinates, "-27.47,153.02", 0.9, "s");
        gps.tag("geoint");
        gps.tag("device-sensor");
        let mut subject = Entity::new(EntityKind::Person, "Dana Bamford", 0.8, "s");
        subject.tag("subject");
        let cand = |name: &str, pc: &str| {
            let mut p = Entity::new(EntityKind::Person, name, 0.35, "s");
            p.tag("family-candidate");
            p.add_evidence(Evidence::new("see_know", "household").with_attr("postcode", pc));
            p
        };
        let ents = vec![
            gps,
            subject,
            cand("Erik Bamford", "4000"),
            cand("Jane Bamford", "4169"),
            cand("Bob Jones", "4101"), // co-resident, DIFFERENT surname → excluded
        ];
        let out = rule_au_061_family_geo_corroboration(&ents, "s", 0);
        assert_eq!(out.len(), 1);
        assert!(out[0].description.contains("Bamford"));
        assert!(
            !out[0].description.contains("Jones"),
            "different-surname household member must be excluded from the shared-surname finding"
        );
        // Two shared-surname relatives remain → High (not Critical).
        assert!(matches!(out[0].severity, Severity::High));
    }

    // ── coord_state ───────────────────────────────────────────────────────────

    #[test]
    fn coord_state_prefers_the_au_state_tag() {
        use crate::core::entity::Evidence;
        // A real person-anchored fix (carries an anchoring geo source), so it is
        // not excluded as infrastructure geo.
        let mut e = Entity::new(EntityKind::Coordinates, "-27.47,153.02", 0.6, "s");
        e.tag("au-state:QLD");
        e.add_evidence(Evidence::new("exif_geo", "photo GPS"));
        assert_eq!(coord_state(&e), Some("QLD"));
    }

    #[test]
    fn coord_state_falls_back_to_lat_lon_when_untagged() {
        use crate::core::entity::Evidence;
        // Brisbane, no tag → derived from the coordinate. A real person-anchored
        // fix (anchoring source present), so not excluded as infrastructure geo.
        let mut e = Entity::new(EntityKind::Coordinates, "-27.4705,153.0260", 0.6, "s");
        e.add_evidence(Evidence::new("exif_geo", "photo GPS"));
        assert_eq!(coord_state(&e), Some("QLD"));
    }

    #[test]
    fn coord_state_none_below_threshold_or_wrong_kind() {
        let weak = Entity::new(EntityKind::Coordinates, "-27.47,153.02", 0.49, "s");
        assert_eq!(coord_state(&weak), None);
        let email = Entity::new(EntityKind::Email, "a@b.com", 0.9, "s");
        assert_eq!(coord_state(&email), None);
    }

    // ── H5: infrastructure geo must not vote the subject's location ────────────

    #[test]
    fn infrastructure_geo_excluded_from_address_rollup_rules() {
        use crate::core::entity::Evidence;
        let email = {
            let mut e = Entity::new(EntityKind::Email, "subject@example.com", 0.8, "s");
            e.add_evidence(Evidence::new("hibp", "breach"));
            e
        };
        // A WHOIS registrant filing address and a hosting-country address — both
        // infrastructure geo, not the subject's home.
        let registrant = {
            let mut a = Entity::new(EntityKind::Address, "California, US", 0.50, "s");
            a.tag(crate::core::tags::REGISTRANT);
            a.add_evidence(Evidence::new("whois", "Registrant location"));
            a
        };
        let hosting = {
            let mut a = Entity::new(EntityKind::Address, "Sydney NSW, AU", 0.50, "s");
            a.tag(crate::core::tags::HOSTING);
            a.add_evidence(Evidence::new("urlscan", "Hosting country"));
            a
        };
        let infra = vec![email.clone(), registrant, hosting];

        // AU-018: no genuine subject address → no identity↔location linkage.
        assert!(
            rule_au_018_email_address_colocation(&infra, "s", 0).is_empty(),
            "infra geo must not forge an email↔location linkage"
        );
        // AU-030: two infra-geo addresses are not multi-source convergence.
        assert!(
            rule_au_030_geo_convergence_score(&infra, "s", 0).is_empty(),
            "infra geo must not manufacture geo convergence"
        );

        // AU-026: an address "validated" only by two IP-geo lookups is the host's
        // location, not a street address — IP-geo is no longer an allowed source.
        let ip_only = {
            let mut a = Entity::new(EntityKind::Address, "Ashburn, Virginia, US", 0.6, "s");
            a.add_evidence(Evidence::new("ip_geo", "IP city"));
            a.add_evidence(Evidence::new("ipinfo", "IP city"));
            a
        };
        assert!(
            rule_au_026_validated_address(&[ip_only], "s", 0).is_empty(),
            "two IP-geo lookups are not street-address validation"
        );

        // Control: a genuine geocoded home address STILL co-locates with the
        // email — the fix targets infrastructure geo, not real fixes.
        let home = {
            let mut a = Entity::new(
                EntityKind::Address,
                "12 Smith St, Brisbane QLD 4000",
                0.7,
                "s",
            );
            a.add_evidence(Evidence::new("geocode", "geocoded"));
            a
        };
        assert!(
            !rule_au_018_email_address_colocation(&[email, home], "s", 0).is_empty(),
            "a real geocoded address still co-locates with the email"
        );
    }

    #[test]
    fn coord_state_excludes_bare_ip_geo_infrastructure_coordinate() {
        use crate::core::entity::Evidence;
        // A datacentre server IP behind the subject's domain, geolocated to Sydney
        // by ip_geo (a non-anchoring source) and tagged au-state:NSW. It locates
        // the host, not the subject, so it must NOT assert a jurisdiction — else it
        // manufactures a false AU-056 "coordinate vs address" conflict against a
        // real interstate home address.
        let mut infra = Entity::new(EntityKind::Coordinates, "-33.8688,151.2093", 0.60, "s");
        infra.tag("au-state:NSW");
        infra.add_evidence(Evidence::new(
            "ip_geo",
            "IP geolocation for the domain's host",
        ));
        assert_eq!(
            coord_state(&infra),
            None,
            "a bare IP-geo (infrastructure) coordinate must not vote a state"
        );

        // Control: a person-anchored EXIF/GPS fix at the same point STILL asserts
        // NSW — the guard targets infrastructure geo, not real subject fixes.
        let mut anchored = Entity::new(EntityKind::Coordinates, "-33.8688,151.2093", 0.60, "s");
        anchored.tag("au-state:NSW");
        anchored.add_evidence(Evidence::new("exif_geo", "photo GPS"));
        assert_eq!(coord_state(&anchored), Some("NSW"));
    }

    #[test]
    fn au099_reverse_geocode_excludes_infrastructure_coordinates() {
        use crate::core::entity::Evidence;
        // A bare IP-geo datacentre coordinate must not be announced as "the
        // subject's coordinate fix" resolving to an AU locality.
        let mut infra = Entity::new(EntityKind::Coordinates, "-27.4698,153.0251", 0.60, "s");
        infra.add_evidence(Evidence::new("ip_geo", "IP city"));
        assert!(
            rule_au_099_coordinate_reverse_geocode(&[infra], "s", 0).is_empty(),
            "AU-099 must not reverse-geocode an infrastructure coordinate as the subject's fix"
        );

        // Control: a genuine EXIF fix at the same point IS reverse-geocoded.
        let mut anchored = Entity::new(EntityKind::Coordinates, "-27.4698,153.0251", 0.60, "s");
        anchored.add_evidence(Evidence::new("exif_geo", "photo GPS"));
        assert!(
            !rule_au_099_coordinate_reverse_geocode(&[anchored], "s", 0).is_empty(),
            "AU-099 must still reverse-geocode a real person-anchored coordinate fix"
        );
    }

    // ── extract_ratemyagent_suburb ────────────────────────────────────────────

    #[test]
    fn extract_ratemyagent_suburb_reads_slug_and_strips_query() {
        assert_eq!(
            extract_ratemyagent_suburb(
                "https://www.ratemyagent.com.au/real-estate-agent/john-smith-brisbane-abc12/"
            ),
            Some("brisbane".to_string())
        );
        // A trailing query string is stripped before parsing.
        assert_eq!(
            extract_ratemyagent_suburb(
                "https://www.ratemyagent.com.au/real-estate-agent/jane-doe-geelong-x9z?ref=1"
            ),
            Some("geelong".to_string())
        );
    }

    #[test]
    fn extract_ratemyagent_suburb_rejects_malformed_slugs() {
        // No agent path at all.
        assert_eq!(
            extract_ratemyagent_suburb("https://example.com/agent/x"),
            None
        );
        // Fewer than 4 hyphen parts.
        assert_eq!(
            extract_ratemyagent_suburb("https://x/real-estate-agent/a-b-c/"),
            None
        );
        // Suburb token carries a digit → rejected.
        assert_eq!(
            extract_ratemyagent_suburb("https://x/real-estate-agent/john-smith-bris2-abc12/"),
            None
        );
    }
}
