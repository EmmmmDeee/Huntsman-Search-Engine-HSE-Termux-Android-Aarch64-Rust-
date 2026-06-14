//! Pure entity-building helpers for Photon geocoder results.

use crate::core::entity::{Entity, EntityKind, Evidence};
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
pub(super) fn build_forward(addr: &str, feature: &Feature, scan_id: &str) -> Option<Entity> {
    let geom = feature.geometry.as_ref()?;
    if geom.coordinates.len() < 2 {
        return None;
    }
    let (lon, lat) = (geom.coordinates[0], geom.coordinates[1]);
    if !crate::util::geo::is_valid_coords(lat, lon) {
        return None;
    }
    let coords = format!("{lat:.6},{lon:.6}");

    let mut e = Entity::new(EntityKind::Coordinates, &coords, 0.60, scan_id);
    e.tag("photon");
    e.tag("geocoded");
    let mut ev = Evidence::new(SRC, format!("Photon geocoded \"{addr}\" -> {coords}"))
        .with_attr("input_address", addr)
        .with_attr("latitude", format!("{lat:.6}"))
        .with_attr("longitude", format!("{lon:.6}"));
    if let Some(props) = &feature.properties {
        if let Some(name) = nonempty(&props.name) {
            ev = ev.with_attr("place_name", name);
        }
        if let Some(cc) = nonempty(&props.countrycode) {
            ev = ev.with_attr("country_code", cc);
            e.tag(format!("country:{}", cc.to_uppercase()));
        }
        if let Some(pt) = nonempty(&props.place_type) {
            ev = ev.with_attr("place_type", pt);
        }
        ev = osm_attrs(ev, &mut e, props);
    }
    if let Some(state) = crate::util::geo::au_state_for_coords(lat, lon) {
        e.tag(format!("au-state:{state}"));
        e.tag("country:AU");
    }
    e.add_evidence(ev);
    Some(e)
}

/// Reverse geocode (`Coordinates` → `Address`). The resolved place **name** is
/// the most-specific component of the display (deduped against city). Returns
/// `None` when fewer than two address components resolve.
pub(super) fn build_reverse(lat: f64, lon: f64, props: &Props, scan_id: &str) -> Option<Entity> {
    let parts = join_unique(&[
        nonempty(&props.name),
        nonempty(&props.housenumber),
        nonempty(&props.street),
        nonempty(&props.city),
        nonempty(&props.state),
        nonempty(&props.country),
    ]);
    if parts.len() < 2 {
        return None;
    }
    let display = parts.join(", ");

    let mut ae = Entity::new(EntityKind::Address, &display, 0.70, scan_id);
    ae.tag("photon");
    ae.tag("reverse-geocoded");
    ae.tag("geoint");
    let mut ev = Evidence::new(SRC, format!("Photon reverse geocode for {lat:.6},{lon:.6}"))
        .with_attr("latitude", format!("{lat:.6}"))
        .with_attr("longitude", format!("{lon:.6}"));
    if let Some(name) = nonempty(&props.name) {
        ev = ev.with_attr("place_name", name);
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
    if let Some(cc) = nonempty(&props.countrycode) {
        ev = ev.with_attr("country_code", cc);
        ae.tag(format!("country:{}", cc.to_uppercase()));
    }
    if let Some(p) = nonempty(&props.postcode) {
        ev = ev.with_attr("postcode", p);
    }
    ev = osm_attrs(ev, &mut ae, props);
    if let Some(state) = crate::util::geo::au_state_for_coords(lat, lon) {
        ae.tag(format!("au-state:{state}"));
        ae.tag("country:AU");
    }
    ae.add_evidence(ev);
    Some(ae)
}
