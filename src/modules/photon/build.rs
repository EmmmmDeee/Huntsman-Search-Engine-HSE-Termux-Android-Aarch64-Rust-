//! Pure entity-building helpers for Photon geocoder results.

use crate::core::{
    confidence,
    entity::{Entity, EntityKind, Evidence},
};
use crate::util::str_util::nonempty;

use super::types::{Feature, Props};

pub(super) const SRC: &str = "photon";

/// Join the present address parts in order, dropping case-insensitive duplicates
/// (the place `name` is often also the `city`, e.g. "Sydney").
pub(super) fn join_unique(parts: &[Option<&str>]) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    parts
        .iter()
        .filter_map(|o| *o)
        .filter(|s| seen.insert(s.to_lowercase()))
        .map(String::from)
        .collect()
}

/// Add the OSM feature classification (`key`/`value`) to a geocode result, both
/// as evidence attributes and an `osm:<value>` tag that conveys precision/nature.
pub(super) fn osm_attrs(ev: Evidence, entity: &mut Entity, props: &Props) -> Evidence {
    let mut ev = ev;
    if let Some(v) = nonempty(&props.osm_value) {
        ev = ev.with_attr("osm_value", v);
        entity.tag(format!("osm:{v}"));
    }
    if let Some(k) = nonempty(&props.osm_key) {
        ev = ev.with_attr("osm_key", k);
    }
    ev
}

/// Forward geocode (`Address` → `Coordinates`). Returns `None` when the feature
/// has no usable geometry.
///
/// Confidence and off-region gating follow Photon's own `countrycode` when
/// present, falling back to the offline bounding box only when it's absent —
/// same country-code-first, box-as-fallback order `geocode::au_relevance`
/// uses. Regression: this used to (a) call `tag_au_state` unconditionally,
/// so a genuinely foreign hit that happened to fall in the box's known
/// false-positive band (e.g. Rote Island/West Timor, Indonesia) got a
/// self-contradicting `country:ID` + `country:AU` + `au-state:WA` on the
/// same entity, and (b) sit at a flat confidence regardless of region, so an
/// unrelated foreign address could anchor an AU-focused scan as if
/// corroborated. When multiple candidates exist (ambiguity detected), the
/// unambiguous confidence is downgraded: an AU-relevant fix drops from
/// MEDIUM_PLUS to MEDIUM_HIGH, and off-region stays at LOW.
pub(super) fn build_forward(
    addr: &str,
    feature: &Feature,
    is_ambiguous: bool,
    scan_id: &str,
) -> Option<Entity> {
    let geom = feature.geometry.as_ref()?;
    if geom.coordinates.len() < 2 {
        return None;
    }
    let (lon, lat) = (geom.coordinates[0], geom.coordinates[1]);
    if !crate::util::geo::is_valid_coords(lat, lon) {
        return None;
    }
    let coords = format!("{lat:.6},{lon:.6}");

    let country_code = feature
        .properties
        .as_ref()
        .and_then(|p| nonempty(&p.countrycode));
    let in_au = match country_code {
        Some(cc) => cc.eq_ignore_ascii_case("au"),
        None => crate::util::geo::is_in_australia(lat, lon),
    };
    let confidence = match (in_au, is_ambiguous) {
        (true, true) => confidence::MEDIUM_HIGH,
        (true, false) => confidence::MEDIUM_PLUS,
        (false, _) => confidence::LOW,
    };

    let mut e = Entity::new(EntityKind::Coordinates, &coords, confidence, scan_id);
    e.tag("photon");
    e.tag("geocoded");
    let mut ev = Evidence::new(SRC, format!("Photon geocoded \"{addr}\" -> {coords}"))
        .with_attr("input_address", addr)
        .with_attr("latitude", format!("{lat:.6}"))
        .with_attr("longitude", format!("{lon:.6}"));
    if is_ambiguous {
        ev = ev.with_attr("ambiguity_detected", "true");
    }
    if let Some(props) = &feature.properties {
        if let Some(name) = nonempty(&props.name) {
            ev = ev.with_attr("place_name", name);
        }
        if let Some(cc) = country_code {
            ev = ev.with_attr("country_code", cc);
            e.tag(format!("country:{}", cc.to_uppercase()));
        }
        if let Some(pt) = nonempty(&props.place_type) {
            ev = ev.with_attr("place_type", pt);
        }
        ev = osm_attrs(ev, &mut e, props);
    }
    if in_au {
        crate::util::geo::tag_au_state(&mut e, lat, lon);
        if is_ambiguous {
            e.tag("ambiguous");
        }
    } else {
        e.tag("off-region");
        e.tag("candidate");
    }
    e.add_evidence(ev);
    Some(e)
}

/// Reverse geocode (`Coordinates` → `Address`): the NEAREST ADDRESS to the
/// point, built from the feature's address components — `"{housenumber}
/// {street}"` (or the street alone), city, state, postcode, country, deduped
/// case-insensitively. Returns `None` when fewer than two components resolve.
///
/// The feature's `name` is part of the value only when the feature IS an
/// address component: a road (`osm_key = highway`, as the street when Photon
/// gave none) or a place (`osm_key = place`, as the locality ahead of the
/// city). Any other name is the business or landmark occupying the point —
/// "Nina Armando" (a clothes shop), "Sydney Opera House" — and it used to lead
/// the value, so `util::geohash::parse_address` (which reads a leading part
/// without a digit as the city) recorded `addr_city = "Nina Armando"`
/// (REQ-GEO-010). It goes to evidence as `place_name` / `nearest_feature`.
///
/// Confidence and off-region gating follow the same country-code-first,
/// box-as-fallback order as [`build_forward`] — see its doc comment.
pub(super) fn build_reverse(lat: f64, lon: f64, props: &Props, scan_id: &str) -> Option<Entity> {
    let name = nonempty(&props.name);
    let osm_key = nonempty(&props.osm_key);
    let street_name = nonempty(&props.street).or(name.filter(|_| osm_key == Some("highway")));
    let street = street_name.map(|st| match nonempty(&props.housenumber) {
        Some(n) => format!("{n} {st}"),
        None => st.to_string(),
    });
    let locality = name.filter(|_| osm_key == Some("place"));
    let parts = join_unique(&[
        street.as_deref(),
        locality,
        nonempty(&props.city),
        nonempty(&props.state),
        nonempty(&props.postcode),
        nonempty(&props.country),
    ]);
    if parts.len() < 2 {
        return None;
    }
    let display = parts.join(", ");

    let country_code = nonempty(&props.countrycode);
    let in_au = match country_code {
        Some(cc) => cc.eq_ignore_ascii_case("au"),
        None => crate::util::geo::is_in_australia(lat, lon),
    };
    let confidence = if in_au {
        confidence::HIGH_PLUS
    } else {
        confidence::LOW
    };

    let mut ae = Entity::new(EntityKind::Address, &display, confidence, scan_id);
    ae.tag("photon");
    ae.tag("reverse-geocoded");
    ae.tag("nearest-address");
    ae.tag("geoint");
    // Inferred, not observed — the nearest address to a point, exactly as
    // `geocode`'s reverse leg marks its record (REQ-GEOLABEL-006).
    let mut ev = Evidence::new(SRC, format!("Photon reverse geocode for {lat:.6},{lon:.6}"))
        .with_attr("latitude", format!("{lat:.6}"))
        .with_attr("longitude", format!("{lon:.6}"))
        .with_inferred(true);
    if let Some(name) = name {
        ev = ev.with_attr("place_name", name);
        if !matches!(osm_key, Some("highway" | "place")) {
            ev = ev.with_attr("nearest_feature", name);
        }
    }
    if let Some(st) = &street {
        ev = ev.with_attr("street", st);
    }
    if let Some(c) = nonempty(&props.city) {
        ev = ev.with_attr("city", c);
    }
    if let Some(s) = nonempty(&props.state) {
        ev = ev.with_attr("state", s);
    }
    if let Some(c) = nonempty(&props.country) {
        ev = ev.with_attr("country", c);
    }
    if let Some(cc) = country_code {
        ev = ev.with_attr("country_code", cc);
        ae.tag(format!("country:{}", cc.to_uppercase()));
    }
    if let Some(p) = nonempty(&props.postcode) {
        ev = ev.with_attr("postcode", p);
    }
    ev = osm_attrs(ev, &mut ae, props);
    if in_au {
        crate::util::geo::tag_au_state(&mut ae, lat, lon);
    } else {
        ae.tag("off-region");
        ae.tag("candidate");
    }
    ae.add_evidence(ev);
    Some(ae)
}
