//! Entity emission helpers for WiGLE observations.

use super::*;
use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    module::ModuleResult,
};

/// Extract Organisation + Coordinates entities from a WiGLE cell-tower
/// observation response.
///
/// **Organisation** — mode-ranked carrier name from the SSID-like field.
///
/// **Coordinates** — each tower record that carries a `trilat`/`trilong`
/// position is emitted as a `Coordinates` entity (capped at 3, sorted by
/// proximity to the scan target).  These feed the OpenCelliD `getInArea`
/// path automatically via the engine's entity→target routing, closing the
/// WiGLE→cell-position→OpenCelliD corroboration loop without any manual
/// pivot.  The cap prevents quota exhaustion when WiGLE returns a dense
/// urban grid.
pub(super) fn extract_cell_intel(
    resp: &Resp,
    target_value: &str,
    scan_id: &str,
    result: &mut ModuleResult,
) {
    if resp.success != Some(true) || resp.results.is_empty() {
        return;
    }

    // ── Organisation: dominant carrier ──────────────────────────────────────
    let carriers: Vec<&str> = resp
        .results
        .iter()
        .filter_map(|n| n.ssid.as_deref())
        .filter(|s| !s.is_empty() && !is_generic_ssid(s))
        .collect();
    if !carriers.is_empty() {
        let top = mode(&carriers);
        if !top.is_empty() {
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
    }

    // ── Coordinates: top-3 tower positions (closest to target) ──────────────
    // Parse the target coords for proximity ranking; skip if unparseable.
    let target_coords = crate::util::geo::parse_coords(target_value).ok();
    let mut towers: Vec<(f64, f64, f64)> = resp
        .results
        .iter()
        .filter_map(|n| {
            let lat = n.trilat?;
            let lon = n.trilong?;
            if !crate::util::geo::is_valid_coords(lat, lon) {
                return None;
            }
            let dist = target_coords.map_or(0.0, |(t_lat, t_lon)| {
                let dlat = lat - t_lat;
                let dlon = lon - t_lon;
                dlat * dlat + dlon * dlon
            });
            Some((lat, lon, dist))
        })
        .collect();
    towers.sort_by(|a, b| a.2.partial_cmp(&b.2).unwrap_or(std::cmp::Ordering::Equal));
    towers.dedup_by(|a, b| (a.0 - b.0).abs() < 1e-5 && (a.1 - b.1).abs() < 1e-5);

    for (lat, lon, _) in towers.into_iter().take(3) {
        let coords = format!("{lat:.6},{lon:.6}");
        let mut geo = Entity::new(EntityKind::Coordinates, &coords, 0.65, scan_id);
        geo.tag("wigle");
        geo.tag("cell-tower");
        geo.tag("cell-observed");
        crate::util::geo::tag_au_state(&mut geo, lat, lon);
        geo.add_evidence(
            Evidence::new(
                SRC,
                format!("WiGLE cell tower position near {target_value}"),
            )
            .with_attr("source", "wigle_cell")
            .with_attr("latitude", lat.to_string())
            .with_attr("longitude", lon.to_string()),
        );
        result.push(geo);
    }
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
        crate::util::geo::tag_au_state(&mut e, lat, lon);
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

/// Max matched networks surfaced for an SSID search — a unique SSID resolves to
/// a handful of points (the victim's location(s)); more means it isn't unique.
const SSID_RESULT_CAP: usize = 10;

/// Emit geolocation entities for a unique SSID's matched networks: each
/// network's coordinates (where WiGLE observed it) and its BSSID (tying the SSID
/// to a concrete access point), so a personalised network name from a stealer
/// log places its owner.
pub(super) fn emit_ssid_entities(ssid: &str, results: &[Network], scan_id: &str) -> ModuleResult {
    let mut result = ModuleResult::new();
    for net in results.iter().take(SSID_RESULT_CAP) {
        let (Some(lat), Some(lon)) = (net.trilat, net.trilong) else {
            continue;
        };
        if !crate::util::geo::is_plausible_provider_coord(lat, lon) {
            continue;
        }
        let mut e = Entity::new(
            EntityKind::Coordinates,
            format!("{lat:.6},{lon:.6}"),
            0.72,
            scan_id,
        );
        e.tag("geoint");
        e.tag("wigle");
        e.tag("ssid-located");
        crate::util::geo::tag_au_state(&mut e, lat, lon);
        let mut ev = Evidence::new(SRC, format!("WiGLE SSID `{ssid}` observed → coordinates"))
            .with_attr("ssid", ssid)
            .with_attr("latitude", lat.to_string())
            .with_attr("longitude", lon.to_string());
        if let Some(bssid) = net.netid.as_deref().filter(|b| !b.is_empty()) {
            ev = ev.with_attr("bssid", bssid);
        }
        e.add_evidence(ev);
        result.push(e);

        // The matched access point's BSSID — ties the SSID to a concrete AP.
        if let Some(bssid) = net.netid.as_deref().filter(|b| !b.is_empty()) {
            let mut m = Entity::new(EntityKind::MacAddress, bssid, 0.70, scan_id);
            m.tag("wigle");
            m.tag("ssid-match");
            m.add_evidence(
                Evidence::new(SRC, format!("BSSID broadcasting SSID `{ssid}`"))
                    .with_attr("ssid", ssid)
                    .with_attr("bssid", bssid),
            );
            result.push(m);
        }
    }
    result
}
