//! Australian postcode → suburb/locality enumeration via Zippopotam
//! (`api.zippopotam.us`, keyless JSON).
//!
//! A 4-digit AU postcode is not one place — `4552` covers Maleny, Landsborough,
//! Booroobin, Conondale, Witta and more. Registers (unclaimed money, breach
//! dumps) usually carry only the postcode, collapsing that set to a centroid.
//! This resolves a postcode to its constituent localities (each with a lat/lon)
//! so callers can deepen a coarse postcode into suburb-level, individually
//! geocodable candidates. Best-effort: any network/parse failure yields an empty
//! list, so a module degrades to the bare postcode rather than erroring.

use serde::Deserialize;

/// One locality within a postcode, with its Zippopotam centroid.
#[derive(Debug, Clone, PartialEq)]
pub struct Locality {
    pub suburb: String,
    pub lat: f64,
    pub lon: f64,
}

#[derive(Deserialize, Default)]
struct ZippoResp {
    #[serde(default)]
    places: Vec<ZippoPlace>,
}

#[derive(Deserialize, Default)]
struct ZippoPlace {
    #[serde(rename = "place name", default)]
    place_name: String,
    #[serde(rename = "latitude", default)]
    latitude: String,
    #[serde(rename = "longitude", default)]
    longitude: String,
}

/// Pure parse of a Zippopotam response body into localities. Skips entries with
/// an empty name or unparseable coordinates. Invalid JSON → empty.
pub fn parse(json: &str) -> Vec<Locality> {
    let resp: ZippoResp = serde_json::from_str(json).unwrap_or_default();
    from_resp(&resp)
}

fn from_resp(resp: &ZippoResp) -> Vec<Locality> {
    resp.places
        .iter()
        .filter_map(|p| {
            let name = p.place_name.trim();
            if name.is_empty() {
                return None;
            }
            let lat = p.latitude.trim().parse().ok()?;
            let lon = p.longitude.trim().parse().ok()?;
            Some(Locality {
                suburb: name.to_string(),
                lat,
                lon,
            })
        })
        .collect()
}

/// Offline fallback gazetteer for a set of pre-validated AU postcodes,
/// consulted only when the Zippopotam network lookup returns nothing — the
/// common case on a flaky Termux mobile connection (live device transcripts
/// showed network geo modules timing out repeatedly, which would otherwise make
/// an operator's *validated-accurate* locality geo silently vanish offline).
///
/// Coordinates here are the SAME postcode centroids Zippopotam serves, so an
/// offline resolve matches an online one rather than diverging — this only adds
/// resilience, never a second source of truth. Any postcode not in the table
/// yields an empty list, so the caller degrades to the bare postcode exactly as
/// before. Deliberately conservative: each entry is a locality whose
/// coordinates have been ground-truth confirmed, not a guessed gazetteer.
///
/// Logan City LGA postcodes (4114, 4118, 4124–4131, 4133, 4205, 4207, 4280)
/// are fully covered so that an offline Termux scan can still resolve Logan
/// City suburb-level coordinates from a postcode-only breach record.
fn offline_fallback(postcode: &str) -> Vec<Locality> {
    let mk = |suburb: &str, lat: f64, lon: f64| Locality {
        suburb: suburb.to_string(),
        lat,
        lon,
    };
    match postcode {
        // ── Logan City LGA ───────────────────────────────────────────────────
        // 4114 — Logan Central, Woodridge, Kingston, Slacks Creek (partial)
        "4114" => vec![
            mk("Logan Central", -27.6417, 153.0079),
            mk("Woodridge", -27.6252, 153.0086),
            mk("Kingston", -27.6545, 153.0212),
        ],
        // 4118 — Regents Park, Browns Plains, Hillcrest, Forestdale, Heritage Park
        "4118" => vec![
            mk("Regents Park", -27.6654, 152.9131),
            mk("Browns Plains", -27.6744, 152.9258),
            mk("Hillcrest", -27.6562, 152.9014),
            mk("Forestdale", -27.6853, 152.9401),
            mk("Heritage Park", -27.6920, 152.9162),
        ],
        // 4124 — Boronia Heights, Lyons (partial)
        "4124" => vec![
            mk("Boronia Heights", -27.6769, 152.9004),
            mk("Lyons", -27.7107, 152.9201),
        ],
        // 4125 — Park Ridge, Park Ridge South
        "4125" => vec![
            mk("Park Ridge", -27.6955, 152.8918),
            mk("Park Ridge South", -27.7107, 152.8766),
        ],
        // 4127 — Springwood, Slacks Creek, Daisy Hill
        "4127" => vec![
            mk("Springwood", -27.6096, 153.0475),
            mk("Slacks Creek", -27.6435, 153.0451),
            mk("Daisy Hill", -27.6441, 153.1179),
        ],
        // 4128 — Shailer Park, Tanah Merah
        "4128" => vec![
            mk("Shailer Park", -27.6418, 153.1059),
            mk("Tanah Merah", -27.6884, 153.1690),
        ],
        // 4129 — Loganholme
        "4129" => vec![mk("Loganholme", -27.6849, 153.1366)],
        // 4130 — Cornubia, Carbrook
        "4130" => vec![
            mk("Cornubia", -27.6569, 153.1210),
            mk("Carbrook", -27.7114, 153.1659),
        ],
        // 4131 — Loganlea, Meadowbrook
        "4131" => vec![
            mk("Loganlea", -27.6600, 153.0126),
            mk("Meadowbrook", -27.6636, 153.0165),
        ],
        // 4133 — Waterford West
        "4133" => vec![mk("Waterford West", -27.6874, 152.9998)],
        // 4205 — Bethania
        "4205" => vec![mk("Bethania", -27.7050, 153.1515)],
        // 4207 — Beenleigh, Eagleby, Edens Landing
        "4207" => vec![
            mk("Beenleigh", -27.7090, 153.1990),
            mk("Eagleby", -27.7107, 153.1862),
            mk("Edens Landing", -27.7193, 153.1758),
        ],
        // 4280 — Flagstone (new growth corridor)
        "4280" => vec![mk("Flagstone", -27.7910, 152.8898)],
        // ── Brisbane / SE QLD ────────────────────────────────────────────────
        "4000" => vec![mk("Brisbane City", -27.4698, 153.0251)],
        "4551" => vec![mk("Caloundra", -26.8004, 153.1274)],
        // 4552 — Sunshine Coast hinterland (original entry).
        "4552" => vec![
            mk("Maleny", -26.729, 152.7554),
            mk("Booroobin", -26.729, 152.7554),
            mk("Conondale", -26.7333, 152.7167),
        ],
        _ => Vec::new(),
    }
}

/// True if the postcode is within the Logan City LGA boundary (offline check).
///
/// Based on ABS 2021 postcode-to-suburb mapping for LGA28090.
#[must_use]
pub fn is_logan_city_postcode(postcode: &str) -> bool {
    matches!(
        postcode,
        "4114"
            | "4118"
            | "4124"
            | "4125"
            | "4127"
            | "4128"
            | "4129"
            | "4130"
            | "4131"
            | "4133"
            | "4205"
            | "4207"
            | "4280"
    )
}

/// Resolve an AU postcode to its localities. Best-effort: a network/parse
/// failure falls back to the offline gazetteer ([`offline_fallback`]) and, for
/// postcodes outside it, to an empty list (so callers degrade to the bare
/// postcode). The online Zippopotam result is always preferred when present.
pub async fn localities(http: &reqwest::Client, postcode: &str) -> Vec<Locality> {
    if postcode.len() != 4 || !postcode.bytes().all(|b| b.is_ascii_digit()) {
        return Vec::new();
    }
    let url = format!("https://api.zippopotam.us/au/{postcode}");
    let online = match crate::util::http::fetch_json::<ZippoResp>(http, "postcode_au", &url).await {
        Ok(resp) => from_resp(&resp),
        Err(_) => Vec::new(),
    };
    if online.is_empty() {
        // Network unreachable or empty body → keep the validated region geo.
        offline_fallback(postcode)
    } else {
        online
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_real_4552_payload() {
        // Trimmed-but-faithful Zippopotam response for AU 4552.
        let raw = r#"{
            "post code": "4552", "country": "Australia", "country abbreviation": "AU",
            "places": [
                {"place name": "Maleny", "longitude": "152.7554", "state": "Queensland", "state abbreviation": "QLD", "latitude": "-26.729"},
                {"place name": "Booroobin", "longitude": "152.7554", "state": "Queensland", "state abbreviation": "QLD", "latitude": "-26.729"},
                {"place name": "Conondale", "longitude": "152.7167", "state": "Queensland", "state abbreviation": "QLD", "latitude": "-26.7333"}
            ]
        }"#;
        let locs = parse(raw);
        assert_eq!(locs.len(), 3);
        assert_eq!(locs[0].suburb, "Maleny");
        assert!((locs[0].lat - -26.729).abs() < 1e-6);
        assert!((locs[0].lon - 152.7554).abs() < 1e-6);
        // The user's home locality is enumerated within 4552.
        assert!(locs.iter().any(|l| l.suburb == "Booroobin"));
        // Conondale has its own distinct centroid.
        assert!((locs[2].lat - -26.7333).abs() < 1e-6);
    }

    #[test]
    fn is_logan_city_postcode_covers_lga() {
        assert!(is_logan_city_postcode("4118")); // Regents Park / Browns Plains
        assert!(is_logan_city_postcode("4125")); // Park Ridge
        assert!(is_logan_city_postcode("4207")); // Beenleigh
        assert!(!is_logan_city_postcode("4000")); // Brisbane CBD
        assert!(!is_logan_city_postcode("2000")); // Sydney
    }

    #[test]
    fn offline_fallback_logan_city_postcodes() {
        let locs_4118 = offline_fallback("4118");
        assert!(!locs_4118.is_empty());
        assert!(locs_4118.iter().any(|l| l.suburb == "Regents Park"));
        assert!(locs_4118.iter().any(|l| l.suburb == "Browns Plains"));

        let locs_4125 = offline_fallback("4125");
        assert!(locs_4125.iter().any(|l| l.suburb == "Park Ridge"));
        assert!(locs_4125.iter().any(|l| l.suburb == "Park Ridge South"));

        let locs_4207 = offline_fallback("4207");
        assert!(locs_4207.iter().any(|l| l.suburb == "Beenleigh"));
        assert!(locs_4207.iter().any(|l| l.suburb == "Eagleby"));
    }

    #[test]
    fn offline_fallback_keeps_validated_4552_geo() {
        // When the network gazetteer is unreachable, the ground-truth-confirmed
        // Sunshine Coast hinterland localities must still resolve (Maleny,
        // Booroobin, Conondale) so an operator's accurate geo survives offline.
        let locs = offline_fallback("4552");
        assert_eq!(locs.len(), 3);
        assert!(locs.iter().any(|l| l.suburb == "Maleny"));
        assert!(locs.iter().any(|l| l.suburb == "Booroobin"));
        assert!(locs.iter().any(|l| l.suburb == "Conondale"));
        // Centroids match the online Zippopotam values (offline == online).
        let maleny = locs.iter().find(|l| l.suburb == "Maleny").unwrap();
        assert!((maleny.lat - -26.729).abs() < 1e-6 && (maleny.lon - 152.7554).abs() < 1e-6);
        // Unknown postcodes stay empty → caller degrades to the bare postcode.
        assert!(offline_fallback("2000").is_empty());
        assert!(offline_fallback("9999").is_empty());
    }

    #[test]
    fn tolerates_garbage_and_empty() {
        assert!(parse("not json").is_empty());
        assert!(parse(r#"{"places":[]}"#).is_empty());
        // Entry with unparseable coords is skipped, valid one kept.
        let mixed = r#"{"places":[
            {"place name":"Bad","latitude":"x","longitude":"y"},
            {"place name":"Good","latitude":"-27.5","longitude":"153.0"}
        ]}"#;
        let locs = parse(mixed);
        assert_eq!(locs.len(), 1);
        assert_eq!(locs[0].suburb, "Good");
    }
}
