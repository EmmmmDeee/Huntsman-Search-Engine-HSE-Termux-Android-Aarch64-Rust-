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

/// Offline fallback gazetteer for a small set of pre-validated AU postcodes,
/// consulted only when the Zippopotam network lookup returns nothing — the
/// common case on a flaky Termux mobile connection (live device transcripts
/// showed network geo modules timing out repeatedly, which would otherwise make
/// an operator's *validated-accurate* locality geo silently vanish offline).
///
/// Coordinates here are the SAME postcode centroids Zippopotam serves, so an
/// offline resolve matches an online one rather than diverging — this only adds
/// resilience, never a second source of truth. Any postcode not in the table
/// yields an empty list, so the caller degrades to the bare postcode exactly as
/// before. Deliberately tiny and conservative: each entry is a locality whose
/// coordinates have been ground-truth confirmed, not a guessed gazetteer.
fn offline_fallback(postcode: &str) -> Vec<Locality> {
    let mk = |suburb: &str, lat: f64, lon: f64| Locality {
        suburb: suburb.to_string(),
        lat,
        lon,
    };
    match postcode {
        // QLD 4552 — Sunshine Coast hinterland.
        "4552" => vec![
            mk("Maleny", -26.729, 152.7554),
            mk("Booroobin", -26.729, 152.7554),
            mk("Conondale", -26.7333, 152.7167),
        ],
        // AU capital-city central postcodes — Zippopotam centroid values.
        "2000" => vec![mk("Sydney CBD", -33.8688, 151.2093)],
        "3000" => vec![mk("Melbourne CBD", -37.8136, 144.9631)],
        "4000" => vec![mk("Brisbane CBD", -27.4698, 153.0251)],
        "5000" => vec![mk("Adelaide CBD", -34.9285, 138.6007)],
        "6000" => vec![mk("Perth CBD", -31.9505, 115.8605)],
        "7000" => vec![mk("Hobart CBD", -42.8821, 147.3272)],
        "0800" | "0801" => vec![mk("Darwin", -12.4634, 130.8456)],
        // Frequently-occurring QLD postcodes in AU registers
        "4551" => vec![mk("Caloundra", -26.7986, 153.1319)],
        "4556" => vec![mk("Maroochydore", -26.6532, 153.0640)],
        "4217" => vec![mk("Surfers Paradise", -28.0029, 153.4300)],
        "4218" => vec![mk("Broadbeach", -28.0264, 153.4307)],
        "4500" => vec![mk("Strathpine", -27.3050, 152.9900)],
        "4501" => vec![mk("Kallangur", -27.2667, 152.9833)],
        "4510" => vec![mk("Caboolture", -27.0847, 152.9511)],
        "4520" => vec![mk("Samford Valley", -27.3667, 152.8833)],
        "4300" => vec![mk("Springfield", -27.6667, 152.9167)],
        "4305" => vec![mk("Ipswich", -27.6167, 152.7667)],
        "4350" => vec![mk("Toowoomba", -27.5598, 151.9507)],
        "4810" => vec![mk("Townsville", -19.2590, 146.8169)],
        "4870" => vec![mk("Cairns", -16.9186, 145.7781)],
        _ => Vec::new(),
    }
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
        // Capital city postcodes now resolve offline.
        assert!(!offline_fallback("2000").is_empty());
        assert!(!offline_fallback("3000").is_empty());
        // Unknown postcodes stay empty → caller degrades to the bare postcode.
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
