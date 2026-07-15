//! Entity builders for electoral division findings.

use crate::core::entity::{Entity, EntityKind, Evidence};

use super::{
    SRC,
    division_map::{division_centroid, infer_state_from_division},
};

/// Confidence for the Address when a suburb was actually resolved — either the
/// caller's own `suburb_hint` or the offline centroid table's suburb. Per the
/// module doc's confidence model: electoral roll enrolment is compulsory and
/// address-verified, so a suburb-level match is the high-confidence tier.
const ADDRESS_WITH_SUBURB_CONF: f64 = 0.72;
/// Confidence for the Address when only the division name is known — no
/// suburb from a hint or a centroid lookup. A bare division can span many
/// suburbs, so this is a materially weaker locate than the suburb-level tier.
const ADDRESS_DIVISION_ONLY_CONF: f64 = 0.58;

/// Build entity set from a confirmed electoral division match. Pure.
/// Returns Address + Coordinates (when division centroid is known) tagged
/// with au-state and country:AU, all attributed to the electoral source.
pub(crate) fn build_electoral_entities(
    division: &str,
    suburb_hint: Option<&str>,
    full_name: &str,
    scan_id: &str,
) -> Vec<Entity> {
    let mut out = Vec::new();
    let evid = Evidence::new(SRC, format!("Electoral division: {division}"));

    let (state, suburb, lat, lon, coord_conf) = if let Some(info) = division_centroid(division) {
        (
            info.state,
            suburb_hint.unwrap_or(info.suburb).to_string(),
            Some(info.lat),
            Some(info.lon),
            0.65_f64,
        )
    } else {
        // Division not in offline table — emit address-only, no coords.
        let state = infer_state_from_division(division).unwrap_or("AU");
        (
            state,
            suburb_hint.unwrap_or("").to_string(),
            None,
            None,
            0.0,
        )
    };

    // Address entity: "Suburb, STATE" (suburb-level match) or "Division
    // (STATE)" when no suburb was resolved — a materially weaker locate, so it
    // gets the lower confidence tier rather than the flat suburb-level score.
    let (addr_value, addr_conf) = if !suburb.is_empty() {
        (format!("{suburb}, {state}"), ADDRESS_WITH_SUBURB_CONF)
    } else {
        (
            format!("{division} (electoral division), {state}"),
            ADDRESS_DIVISION_ONLY_CONF,
        )
    };
    let mut addr = Entity::new(EntityKind::Address, &addr_value, addr_conf, scan_id);
    addr.add_evidence(
        evid.clone()
            .with_attr("division", division)
            .with_attr("source_name", full_name),
    );
    addr.tag(format!("au-state:{state}"));
    addr.tag("country:AU");
    addr.tag("source:electoral");
    out.push(addr);

    // Coordinates entity when we have an offline centroid.
    if let (Some(lat), Some(lon)) = (lat, lon) {
        let coord_value = format!("{lat:.4},{lon:.4}");
        let mut coord = Entity::new(EntityKind::Coordinates, &coord_value, coord_conf, scan_id);
        coord.add_evidence(
            evid.with_attr("division", division)
                .with_attr("suburb", &suburb)
                .with_attr("source_name", full_name),
        );
        coord.tag(format!("au-state:{state}"));
        coord.tag("country:AU");
        out.push(coord);
    }

    out
}
