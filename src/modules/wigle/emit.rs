//! Entity emission helpers for WiGLE observations.

use super::*;
use crate::core::{
    confidence,
    entity::{Entity, EntityKind, Evidence},
    module::ModuleResult,
};

/// The output of [`consensus_address`]: the built Address entity plus the
/// three mode-consensus place values that fed it, so the caller can still
/// attach them as evidence attrs on its own, message-specific `Evidence`.
pub(super) struct ConsensusAddress<'a> {
    pub(super) entity: Entity,
    pub(super) top_city: &'a str,
    pub(super) top_region: &'a str,
    pub(super) top_country: &'a str,
}

/// Mode-consensus city/region/country/postcode across a set of WiGLE network
/// records, built into an Address entity when at least two of the three
/// place components resolve (a postcode alone, or a single bare component,
/// is too thin to anchor a place). Shared by the WiFi AP (`mod.rs::process`),
/// cell-tower ([`extract_cell_intel`]), and SSID ([`emit_ssid_entities`])
/// observation paths, which previously each re-implemented this identically.
/// The only things they differ on — confidence, tags beyond the shared
/// `"wigle"` + `postcode:<code>`, and the evidence message/count attribute —
/// are left to the caller, mirroring `profile_kit`'s "un-tagged entity, caller
/// decorates" toolkit shape. Returns `None` when fewer than two place
/// components resolve.
pub(super) fn consensus_address<'a>(
    networks: &'a [Network],
    confidence: f64,
    scan_id: &str,
) -> Option<ConsensusAddress<'a>> {
    let cities: Vec<&str> = networks
        .iter()
        .filter_map(|n| n.city.as_deref())
        .filter(|c| !c.is_empty())
        .collect();
    let regions: Vec<&str> = networks
        .iter()
        .filter_map(|n| n.region.as_deref())
        .filter(|r| !r.is_empty())
        .collect();
    let countries: Vec<&str> = networks
        .iter()
        .filter_map(|n| n.country.as_deref())
        .filter(|c| !c.is_empty())
        .collect();
    let postcodes: Vec<&str> = networks
        .iter()
        .filter_map(|n| n.postalcode.as_deref())
        .filter(|p| !p.is_empty())
        .collect();

    let top_city = mode(&cities);
    let top_region = mode(&regions);
    let top_country = mode_or(&countries, || {
        networks
            .iter()
            .find_map(|n| n.country.as_deref())
            .unwrap_or("")
    });
    let top_postcode = mode(&postcodes);

    let addr_parts: Vec<&str> = [top_city, top_region, top_country]
        .iter()
        .copied()
        .filter(|s| !s.is_empty())
        .collect();
    if addr_parts.len() < 2 {
        return None;
    }

    let mut addr_str = addr_parts.join(", ");
    if !top_postcode.is_empty() {
        addr_str = format!("{addr_str} {top_postcode}");
    }
    let mut entity = Entity::new(EntityKind::Address, &addr_str, confidence, scan_id);
    entity.tag("wigle");
    if !top_postcode.is_empty() {
        entity.tag(format!("postcode:{top_postcode}"));
    }
    Some(ConsensusAddress {
        entity,
        top_city,
        top_region,
        top_country,
    })
}

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
            let mut org = Entity::new(
                EntityKind::Organisation,
                top,
                confidence::MEDIUM_HIGH,
                scan_id,
            );
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

    // ── Address: city/region/country/postalcode consensus ───────────────────
    // Mirrors the WiFi-geo bbox Address block in mod.rs::process(), but over
    // cell-tower observations — coarser geolocation than WiFi AP-level, so
    // confidence stays modest.
    if let Some(ca) = consensus_address(&resp.results, confidence::MEDIUM_HIGH, scan_id) {
        let mut addr = ca.entity;
        addr.tag("cell-derived");
        addr.add_evidence(
            Evidence::new(
                SRC,
                format!("Address from WiGLE cell tower observation consensus near {target_value}"),
            )
            .with_attr("cell_observations", resp.results.len().to_string())
            .with_attr("city", ca.top_city)
            .with_attr("region", ca.top_region)
            .with_attr("country", ca.top_country),
        );
        result.push(addr);
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
    // Total distinct tower positions, surfaced on every emitted Coordinates below
    // (independent of the carrier Organisation entity, which is suppressed for
    // generic AU carriers) so the top-3-nearest bound is never a silent drop.
    let tower_positions = towers.len();

    for (lat, lon, _) in towers.into_iter().take(3) {
        let coords = format!("{lat:.6},{lon:.6}");
        let mut geo = Entity::new(EntityKind::Coordinates, &coords, confidence::HIGH, scan_id);
        geo.tag("wigle");
        geo.tag(crate::core::tags::CELL_TOWER);
        geo.tag("cell-observed");
        crate::util::geo::tag_au_state(&mut geo, lat, lon);
        geo.add_evidence(
            Evidence::new(
                SRC,
                format!("WiGLE cell tower position near {target_value}"),
            )
            .with_attr("source", "wigle_cell")
            .with_attr("latitude", lat.to_string())
            .with_attr("longitude", lon.to_string())
            .with_attr("tower_positions_observed", tower_positions.to_string()),
        );
        result.push(geo);
    }
}

/// Extract Bluetooth beacon MAC addresses observed near the target. Bounded to a
/// few beacons — Bluetooth is transient (a passing device leaves a one-off
/// beacon), so flooding downstream pivots with it is noise — in the order WiGLE
/// returns them (the API exposes no per-beacon observation count to rank by). The
/// total number observed is surfaced on each emitted entity's `beacons_observed`
/// evidence so the bound is visible, never a silent drop.
pub(super) fn extract_bluetooth_intel(
    resp: &Resp,
    target_value: &str,
    scan_id: &str,
    result: &mut ModuleResult,
) {
    if resp.success != Some(true) || resp.results.is_empty() {
        return;
    }
    let beacons_observed = resp.results.len();
    result.extend(resp.results.iter().take(3).filter_map(|net| {
        let mac = net.netid.as_deref()?;
        if mac.len() < 12 {
            return None;
        }
        let mut e = Entity::new(
            EntityKind::MacAddress,
            mac,
            confidence::MEDIUM_HIGH,
            scan_id,
        );
        e.tag("wigle");
        e.tag("bluetooth-beacon");
        let ev = Evidence::new(
            SRC,
            format!("Bluetooth beacon observed near {target_value}"),
        )
        .with_attr("source", "wigle_bluetooth")
        .with_attr("coordinates", target_value)
        .with_attr("beacons_observed", beacons_observed.to_string());
        // Shared OUI-classification primitive (parity with the signal_radar
        // Bluetooth/Wi-Fi paths): also carries the trackable/randomized
        // distinction AU-122 needs, which this call site previously lacked.
        let ev = crate::util::oui::tag_oui_classification(&mut e, ev, mac);
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
        let mut addr = Entity::new(
            EntityKind::Address,
            &addr_str,
            confidence::HIGH_PLUS,
            scan_id,
        );
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
            confidence::VERY_HIGH,
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

/// Max matched networks surfaced for an SSID search. Aligned to the admission
/// gate [`super::SSID_UNIQUE_MAX`]: an SSID is only searched when it has at most
/// that many global observations (more ⇒ not a unique/personal network), so
/// emission must surface ALL of an admitted SSID's location fixes. A smaller cap
/// here silently dropped up to half the subject-location points of a network the
/// module had already judged unique — the very fixes that "place its owner".
const SSID_RESULT_CAP: usize = super::SSID_UNIQUE_MAX as usize;

/// Emit geolocation entities for a unique SSID's matched networks: each
/// network's coordinates (where WiGLE observed it) and its BSSID (tying the SSID
/// to a concrete access point), so a personalised network name from a stealer
/// log places its owner.
pub(super) fn emit_ssid_entities(ssid: &str, results: &[Network], scan_id: &str) -> ModuleResult {
    let mut result = ModuleResult::new();

    // ── Address from SSID observation consensus (free geo!) ─────────────────
    // Mirrors the WiFi-geo bbox Address block in mod.rs::process(): mode()
    // across ALL matched networks (not per-record), so a single network
    // observed at many points doesn't mint near-duplicate Address entities.
    if let Some(ca) = consensus_address(results, confidence::HIGH, scan_id) {
        let mut addr = ca.entity;
        addr.tag("ssid-located");
        addr.add_evidence(
            Evidence::new(
                SRC,
                format!("Address from SSID `{ssid}` observation consensus"),
            )
            .with_attr("ssid", ssid)
            .with_attr("networks_sampled", results.len().to_string())
            .with_attr("city", ca.top_city)
            .with_attr("region", ca.top_region)
            .with_attr("country", ca.top_country),
        );
        result.push(addr);
    }

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
            confidence::ATTRIBUTED,
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
            let mut m = Entity::new(
                EntityKind::MacAddress,
                bssid,
                confidence::HIGH_PLUS,
                scan_id,
            );
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
