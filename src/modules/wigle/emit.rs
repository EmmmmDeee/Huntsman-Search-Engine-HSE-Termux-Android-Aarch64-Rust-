//! Entity emission helpers for WiGLE observations.

use super::*;
use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    module::ModuleResult,
};

/// Extract Organisation entities (mobile carriers) from a cell-tower
/// observation response. Each Network record's SSID-like field holds
/// the operator/carrier name when WiGLE has it; we mode-rank to find
/// the dominant carrier in the bbox.
pub(super) fn extract_cell_intel(
    resp: &Resp,
    target_value: &str,
    scan_id: &str,
    result: &mut ModuleResult,
) {
    if resp.success != Some(true) || resp.results.is_empty() {
        return;
    }
    let carriers: Vec<&str> = resp
        .results
        .iter()
        .filter_map(|n| n.ssid.as_deref())
        .filter(|s| !s.is_empty() && !is_generic_ssid(s))
        .collect();
    if carriers.is_empty() {
        return;
    }
    let top = mode(&carriers);
    if top.is_empty() {
        return;
    }
    let total = resp.results.len();
    let mut org = Entity::new(EntityKind::Organisation, top, 0.55, scan_id);
    org.tag("wigle");
    org.tag("cell-carrier");
    org.add_evidence(
        Evidence::new(
            SRC,
            format!("Cell carrier presence inferred from WiGLE near {target_value}"),
        )
        .with_attr("cell_observations", total.to_string())
        .with_attr("dominant_carrier", top)
        .with_attr("source", "wigle_cell"),
    );
    result.push(org);
}

/// Extract Bluetooth beacon MAC addresses near the target. Limited
/// to the 3 most consistently-observed beacons so we don't flood
/// downstream pivots with hardware that's only been seen once.
pub(super) fn extract_bluetooth_intel(
    resp: &Resp,
    target_value: &str,
    scan_id: &str,
    result: &mut ModuleResult,
) {
    if resp.success != Some(true) || resp.results.is_empty() {
        return;
    }
    result.extend(resp.results.iter().take(3).filter_map(|net| {
        let mac = net.netid.as_deref()?;
        if mac.len() < 12 {
            return None;
        }
        let mut e = Entity::new(EntityKind::MacAddress, mac, 0.55, scan_id);
        e.tag("wigle");
        e.tag("bluetooth-beacon");
        let mut ev = Evidence::new(
            SRC,
            format!("Bluetooth beacon observed near {target_value}"),
        )
        .with_attr("source", "wigle_bluetooth")
        .with_attr("coordinates", target_value);
        if let Some(oui) = crate::util::oui::classify_mac(mac) {
            e.tag(format!("vendor:{}", oui.vendor));
            e.tag(format!("device:{}", oui.class.as_str()));
            ev = ev
                .with_attr("vendor", oui.vendor)
                .with_attr("device_class", oui.class.as_str());
        }
        e.add_evidence(ev);
        if let Some(ref ssid) = net.ssid {
            e.tag(format!("name:{}", ssid.trim()));
        }
        Some(e)
    }));
}

/// Emit Address + Coordinates entities for a successful BSSID
/// detail lookup. Tags include the observation type so downstream
/// correlators can distinguish a WiFi-located MAC from a
/// cell-tower-located one.
pub(super) fn emit_bssid_entities(
    bssid: &str,
    kind: NetworkKind,
    results: &[Network],
    scan_id: &str,
) -> ModuleResult {
    let mut result = ModuleResult::new();
    let Some(net) = results.first() else {
        return result;
    };
    let Some(lat) = net.trilat else {
        return result;
    };
    let lon = net.trilong.unwrap_or(0.0);
    let observation_tag = match kind {
        NetworkKind::Wifi => "bssid-located",
        NetworkKind::Cell => "cell-located",
        NetworkKind::Bluetooth => "bluetooth-located",
    };
    let kind_label = kind.as_str();

    let parts: Vec<&str> = [
        net.city.as_deref(),
        net.region.as_deref(),
        net.country.as_deref(),
    ]
    .iter()
    .filter_map(|p| *p)
    .filter(|p| !p.is_empty())
    .collect();
    if parts.len() >= 2 {
        let addr_str = parts.join(", ");
        let mut addr = Entity::new(EntityKind::Address, &addr_str, 0.70, scan_id);
        addr.tag("wigle");
        addr.tag(observation_tag);
        addr.add_evidence(
            Evidence::new(SRC, format!("WiGLE {kind_label} BSSID lookup for {bssid}"))
                .with_attr("bssid", bssid)
                .with_attr("observation_type", kind_label),
        );
        result.push(addr);
    }
    if crate::util::geo::is_plausible_provider_coord(lat, lon) {
        let mut e = Entity::new(
            EntityKind::Coordinates,
            format!("{lat:.6},{lon:.6}"),
            0.75,
            scan_id,
        );
        e.tag("geoint");
        e.tag("wigle");
        e.tag(observation_tag);
        if let Some(state) = crate::util::geo::au_state_for_coords(lat, lon) {
            e.tag(format!("au-state:{state}"));
            e.tag("country:AU");
        }
        e.add_evidence(
            Evidence::new(
                SRC,
                format!("WiGLE {kind_label} BSSID {bssid} → coordinates"),
            )
            .with_attr("bssid", bssid)
            .with_attr("latitude", lat.to_string())
            .with_attr("longitude", lon.to_string())
            .with_attr("observation_type", kind_label),
        );
        result.push(e);
    }
    result
}
