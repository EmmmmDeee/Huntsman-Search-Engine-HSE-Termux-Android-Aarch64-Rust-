//! Pure helper functions: entity building, OpenCelliD query, confidence
//! mapping, MCC table, and JSON normalisation.

use crate::core::{
    confidence,
    entity::{Entity, EntityKind, Evidence},
    error::Result,
};
use crate::util::geo::is_valid_coords;
use crate::util::http::urlencode;

use super::SRC;
use super::types::{Cell, OpenCellidResp, TowerKey};

/// Build the `DeviceId` entity for one cell tower. Single source of truth for
/// the tower-survey entity shape, shared by the live `process()` path and the
/// `parse_cells_survey` test helper so the two can never drift in their tags or
/// evidence-attribute set (they were previously byte-identical copies).
pub(super) fn build_tower_device(cell: &Cell, key: &TowerKey, scan_id: &str) -> Entity {
    let mut e = Entity::new(
        EntityKind::DeviceId,
        &key.tower_id,
        confidence::HIGH_PLUSPLUS,
        scan_id,
    );
    e.tag(crate::core::tags::CELL_TOWER);
    e.tag(format!("radio:{}", key.ctype));
    e.add_evidence(
        Evidence::new(SRC, format!("Cell tower {} {}", key.ctype, key.tower_id))
            .with_attr("type", key.ctype)
            .with_attr("mcc", key.mcc.as_ref())
            .with_attr("mnc", key.mnc.as_ref())
            .with_attr("lac_tac", key.lac.to_string())
            .with_attr("cid", key.cid.to_string())
            .with_attr("pci", cell.pci.unwrap_or(0).to_string())
            .with_attr("dbm", cell.dbm.unwrap_or(0).to_string())
            .with_attr("asu", cell.asu.unwrap_or(0).to_string())
            .with_attr("level", cell.level.unwrap_or(0).to_string())
            .with_attr("registered", cell.registered.unwrap_or(false).to_string()),
    );
    e
}

pub(super) async fn query_opencellid(
    ctx: &crate::core::module::ModuleContext,
    api_key: &str,
    tower: &TowerKey<'_>,
    radio: &str,
) -> Option<(f64, f64, u64)> {
    // URL-encode every interpolated value (consistent with censys). mcc/mnc
    // come from json_to_str of arbitrary cellinfo JSON; a malformed value with
    // a `&`/space would otherwise corrupt the query string. Numeric codes
    // (the normal case) pass through unchanged.
    let url = format!(
        "https://opencellid.org/cell/get?key={}&mcc={}&mnc={}&lac={}&cellid={}&radio={}&format=json",
        urlencode(api_key),
        urlencode(&tower.mcc),
        urlencode(&tower.mnc),
        tower.lac,
        tower.cid,
        urlencode(radio),
    );

    let resp = ctx
        .http
        .get(&url)
        .header("Accept", "application/json")
        .send()
        .await
        .ok()?;

    let status = resp.status();
    if !status.is_success() {
        // Reported against the registered "opencellid" SERVICE, not this
        // module's own `SRC` ("cell_intel") — `HUNTSMAN_OPENCELLID_KEY` is
        // the same key the standalone `opencellid` module uses and reports
        // against; reporting under "cell_intel" would silently no-op (no
        // such service registered) and the pool would never learn the real
        // "opencellid" key was rejected/throttled, exactly the T2.153 class
        // of bug this fixes.
        crate::util::http::note_keyed_error(status.as_u16(), "opencellid", api_key, ctx);
        return None;
    }

    let data: OpenCellidResp = crate::util::http::json_scanned(resp, SRC).await.ok()?;

    if data.error.is_some() {
        // See `OpenCellidResp::error`'s doc comment — a body-level key
        // failure OpenCelliD signals as a plain 200, so this can't be
        // caught by the status check above. Distinct from the `status:
        // "error"` case just below (a genuine "couldn't geolocate this
        // tower" negative with a real key — not a key problem).
        crate::util::http::note_keyed_error(401, "opencellid", api_key, ctx);
        return None;
    }
    if data.status.as_deref() == Some("error") {
        return None;
    }

    let lat = data.lat?;
    let lon = data.lon?;
    // Shared validator: rejects Null Island AND out-of-range / non-finite
    // values a malformed OpenCelliD payload could carry (see util::geo).
    if !is_valid_coords(lat, lon) {
        return None;
    }

    Some((lat, lon, data.range.unwrap_or(5000)))
}

/// Map a cell fix's accuracy radius (metres) to a coordinate confidence.
/// Delegates to the single authoritative implementation in `cell_db`.
pub(super) use crate::util::cell_db::accuracy_to_confidence;

/// The `Coordinates` `cell_intel` mints for a tower OpenCelliD could not
/// locate: the centroid of the country its Mobile Country Code names
/// ([`mcc_to_centroid`]), or `None` for an unrecognised MCC.
///
/// A COUNTRY signal, not a measurement. The MCC says only which country's
/// network the tower belongs to, and the point is a stand-in for that whole
/// country — MCC 530's is Wellington's row, MCC 505's the continent's centre.
/// So the record names itself one (`source=`
/// [`MCC_CENTROID_METHOD`](crate::core::place::grain::MCC_CENTROID_METHOD),
/// and the [`MCC_INFERRED_TAG`](crate::core::place::grain::MCC_INFERRED_TAG)
/// that survives a CSV round trip), which the precision authority reads as a
/// country signal: labelled the country, no radius, never a best-location
/// anchor. It carries the country in words (`country`, what the label names)
/// and its ISO code (`country_code`), and no `au-state:` tag — the MCC names
/// no state, and the NT tag the continent's centre used to earn was the
/// stand-in's, not the tower's.
pub(crate) fn mcc_centroid_point(mcc: &str, tower_id: &str, scan_id: &str) -> Option<Entity> {
    let (lat, lon, country) = mcc_to_centroid(mcc)?;
    let coords = format!("{lat:.4},{lon:.4}");
    let mut e = Entity::new(
        EntityKind::Coordinates,
        &coords,
        confidence::VERY_LOW,
        scan_id,
    );
    e.tag("geoint");
    e.tag(crate::core::tags::CELL_TOWER);
    e.tag(crate::core::tags::COARSE);
    e.tag(crate::core::place::grain::MCC_INFERRED_TAG);
    e.tag(format!("country:{country}"));
    e.add_evidence(
        Evidence::new(
            SRC,
            format!("Cell tower MCC {mcc} -> {country} (country centroid)"),
        )
        .with_attr("tower_id", tower_id)
        .with_attr("mcc", mcc)
        .with_attr(
            "country",
            crate::util::geohash::country_name_for_iso(country).unwrap_or(country),
        )
        .with_attr("country_code", country)
        .with_attr("source", crate::core::place::grain::MCC_CENTROID_METHOD)
        .with_attr("accuracy", "country-level"),
    );
    Some(e)
}

/// The Mobile Country Code table [`mcc_to_centroid`] reads, as `(MCCs, lat,
/// lon, ISO)`: each point is a stand-in inside the named country — its
/// centroid, or (NZ) its capital. Australia (`505`) leads, consistent with the
/// platform's AU focus; global MCCs follow so a roaming/non-AU device still
/// resolves. A table, not a `match`, so a test can check EVERY row lies in its
/// own country: MCC 216 (Hungary) once carried Istanbul's coordinates and 219
/// (Croatia) central Serbia's, so a device camped on a Hungarian network was
/// labelled "Hungary" with its pin, geohash and timezone in Turkey
/// (REQ-GEOLABEL-032).
pub(super) const MCC_CENTROIDS: &[(&[&str], f64, f64, &str)] = &[
    // Oceania / Australia
    (&["505"], -25.2744, 133.7751, "AU"),
    (&["530"], -41.2865, 174.7762, "NZ"),
    // North America
    (
        &["310", "311", "312", "313", "314", "315", "316"],
        39.8283,
        -98.5795,
        "US",
    ),
    (&["302"], 56.1304, -106.3468, "CA"),
    (&["334"], 23.6345, -102.5528, "MX"),
    // Europe
    (&["234", "235"], 55.3781, -3.4360, "GB"),
    (&["262"], 51.1657, 10.4515, "DE"),
    (&["208"], 46.6034, 1.8883, "FR"),
    (&["222"], 41.8719, 12.5674, "IT"),
    (&["214"], 40.4637, -3.7492, "ES"),
    (&["204"], 52.1326, 5.2913, "NL"),
    (&["206"], 50.5039, 4.4699, "BE"),
    (&["228"], 46.8182, 8.2275, "CH"),
    (&["232"], 47.5162, 14.5501, "AT"),
    (&["240"], 60.1282, 18.6435, "SE"),
    (&["242"], 60.4720, 8.4689, "NO"),
    (&["244"], 61.9241, 25.7482, "FI"),
    (&["238"], 56.2639, 9.5018, "DK"),
    (&["260"], 51.9194, 19.1451, "PL"),
    (&["226"], 45.9432, 24.9668, "RO"),
    (&["230"], 49.8175, 15.4730, "CZ"),
    (&["216"], 47.1625, 19.5033, "HU"),
    (&["219"], 45.1000, 15.2000, "HR"),
    (&["202"], 39.0742, 21.8243, "GR"),
    (&["268"], 39.3999, -8.2245, "PT"),
    (&["272"], 53.4129, -8.2439, "IE"),
    (&["255"], 48.3794, 31.1656, "UA"),
    // Asia
    (&["440", "441"], 36.2048, 138.2529, "JP"),
    (&["450"], 35.9078, 127.7669, "KR"),
    (&["460", "461"], 35.8617, 104.1954, "CN"),
    (&["404", "405"], 20.5937, 78.9629, "IN"),
    (&["510"], -0.7893, 113.9213, "ID"),
    (&["502"], 4.2105, 101.9758, "MY"),
    (&["520"], 15.8700, 100.9925, "TH"),
    (&["515"], 12.8797, 121.7740, "PH"),
    (&["452"], 14.0583, 108.2772, "VN"),
    (&["525"], 1.3521, 103.8198, "SG"),
    // Middle East
    (&["420"], 23.8859, 45.0792, "SA"),
    (&["424"], 23.4241, 53.8478, "AE"),
    (&["425"], 31.0461, 34.8516, "IL"),
    (&["432"], 32.4279, 53.6880, "IR"),
    // South America
    (&["724"], -14.2350, -51.9253, "BR"),
    (&["722"], -38.4161, -63.6167, "AR"),
    (&["730"], -35.6751, -71.5430, "CL"),
    (&["716"], -9.1900, -75.0152, "PE"),
    (&["732"], 4.5709, -74.2973, "CO"),
    // Africa
    (&["655"], -30.5595, 22.9375, "ZA"),
    (&["621"], 9.0820, 8.6753, "NG"),
    (&["620"], -6.3690, 34.8888, "TZ"),
    (&["639"], -0.0236, 37.9062, "KE"),
    (&["602"], 26.8206, 30.8025, "EG"),
    (&["604"], 31.7917, -7.0926, "MA"),
    // Russia
    (&["250"], 61.5240, 105.3188, "RU"),
];

/// Coarse country fix from a cell's **Mobile Country Code**: `(lat, lon, ISO)` at
/// the country's stand-in point ([`MCC_CENTROIDS`]), or `None` for an
/// unrecognised MCC. The fallback when no precise tower location is available —
/// at least the device's *country* is known from the network it's camped on.
pub(super) fn mcc_to_centroid(mcc: &str) -> Option<(f64, f64, &'static str)> {
    MCC_CENTROIDS
        .iter()
        .find(|(mccs, ..)| mccs.contains(&mcc))
        .map(|&(_, lat, lon, iso)| (lat, lon, iso))
}

// ---------------------------------------------------------------------------
// Standalone parse helper (used in tests to exercise survey logic without
// needing a ModuleContext / async runtime).
// ---------------------------------------------------------------------------

#[cfg(test)]
pub(super) fn parse_cells_survey(
    stdout: &[u8],
    scan_id: &str,
) -> crate::core::module::ModuleResult {
    let cells: Vec<Cell> = match serde_json::from_slice(stdout) {
        Ok(v) => v,
        Err(_) => return crate::core::module::ModuleResult::new(),
    };

    let mut result = crate::core::module::ModuleResult {
        entities: Vec::with_capacity(cells.len()),
        truncation: None,
        sightings: Vec::new(),
        link: None,
    };
    for cell in &cells {
        // Same parse/skip + builder the live process() path uses, so these
        // tests pin the real entity shape rather than a parallel copy.
        let Some(key) = TowerKey::from_cell(cell) else {
            continue;
        };
        result.push(build_tower_device(cell, &key, scan_id));
    }
    result
}

// Suppress unused-import warning: Result is needed by query_opencellid's
// return type inference via json_scanned, but the compiler may not see it.
const _: fn() -> Result<()> = || Ok(());
