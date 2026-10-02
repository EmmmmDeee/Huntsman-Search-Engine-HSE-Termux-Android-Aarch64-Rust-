//! AU postcode lookup rebuilt from the monolith's `util::postcode_au`.
//! Network I/O is injected through the shared HTTP transport; tests use fakes.

use serde::Deserialize;

use crate::http::{Request, Response, Transport};

#[derive(Debug, Clone, PartialEq)]
pub struct Locality {
    pub suburb: String,
    pub lat: f64,
    pub lon: f64,
}

#[derive(Debug, Deserialize, Default)]
struct ZippoResp {
    #[serde(default)]
    places: Vec<ZippoPlace>,
}

#[derive(Debug, Deserialize, Default)]
struct ZippoPlace {
    #[serde(rename = "place name", default)]
    place_name: String,
    #[serde(rename = "latitude", default)]
    latitude: String,
    #[serde(rename = "longitude", default)]
    longitude: String,
}

#[must_use]
pub fn is_shaped(value: &str) -> bool {
    value.len() == 4 && value.bytes().all(|byte| byte.is_ascii_digit())
}

#[must_use]
pub fn is_in_au_range(value: &str) -> bool {
    is_shaped(value)
        && value
            .parse::<u32>()
            .is_ok_and(|number| (800..=9999).contains(&number))
}

#[must_use]
pub fn parse(json: &str) -> Vec<Locality> {
    let response: ZippoResp = serde_json::from_str(json).unwrap_or_default();
    from_resp(&response)
}

#[must_use]
pub fn offline_centroid(postcode: &str) -> Option<(f64, f64)> {
    offline_fallback(postcode)
        .first()
        .map(|locality| (locality.lat, locality.lon))
}

/// Resolve an AU postcode to localities. The caller supplies the shared transport.
/// Any transport/status/parse miss falls back to the validated offline gazetteer.
pub fn localities_with<T: Transport>(postcode: &str, transport: &T) -> Vec<Locality> {
    if !is_shaped(postcode) {
        return Vec::new();
    }
    let request = Request::get(format!("https://api.zippopotam.us/au/{postcode}"))
        .header("accept", "application/json");
    let online = match transport.send(&request) {
        Ok(response) if response.status == 200 && !response.truncated => parse_response(&response),
        _ => Vec::new(),
    };
    if online.is_empty() {
        offline_fallback(postcode)
    } else {
        online
    }
}

fn parse_response(response: &Response) -> Vec<Locality> {
    crate::http::parse_json_body::<ZippoResp>(response)
        .ok()
        .map_or_else(Vec::new, |parsed| from_resp(&parsed))
}

fn from_resp(response: &ZippoResp) -> Vec<Locality> {
    response
        .places
        .iter()
        .filter_map(|place| {
            let suburb = place.place_name.trim();
            if suburb.is_empty() {
                return None;
            }
            let lat = place.latitude.trim().parse::<f64>().ok()?;
            let lon = place.longitude.trim().parse::<f64>().ok()?;
            if !(lat.is_finite()
                && lon.is_finite()
                && (-44.0..=-10.0).contains(&lat)
                && (112.0..=154.0).contains(&lon))
            {
                return None;
            }
            Some(Locality {
                suburb: suburb.to_string(),
                lat,
                lon,
            })
        })
        .collect()
}

fn offline_fallback(postcode: &str) -> Vec<Locality> {
    let locality = |suburb: &str, lat: f64, lon: f64| Locality {
        suburb: suburb.to_string(),
        lat,
        lon,
    };
    match postcode {
        "0800" | "0801" => vec![locality("Darwin", -12.4634, 130.8456)],
        "0870" => vec![locality("Alice Springs", -23.6980, 133.8807)],
        "2000" => vec![locality("Sydney CBD", -33.8688, 151.2093)],
        "2170" => vec![locality("Liverpool", -33.9200, 150.9228)],
        "2300" => vec![locality("Newcastle", -32.9283, 151.7817)],
        "2500" => vec![locality("Wollongong", -34.4278, 150.8931)],
        "2600" | "2601" => vec![locality("Canberra City", -35.2809, 149.1300)],
        "3000" => vec![locality("Melbourne CBD", -37.8136, 144.9631)],
        "3220" => vec![locality("Geelong", -38.1499, 144.3617)],
        "4000" => vec![locality("Brisbane CBD", -27.4698, 153.0251)],
        "4217" => vec![locality("Surfers Paradise", -28.0029, 153.4300)],
        "4552" => vec![
            locality("Maleny", -26.7290, 152.7554),
            locality("Booroobin", -26.7290, 152.7554),
            locality("Conondale", -26.7333, 152.7167),
        ],
        "4700" => vec![locality("Rockhampton", -23.3791, 150.5100)],
        "5290" => vec![locality("Mount Gambier", -37.8307, 140.7828)],
        "6000" => vec![locality("Perth CBD", -31.9505, 115.8605)],
        "6210" => vec![locality("Mandurah", -32.5264, 115.7239)],
        "7000" => vec![locality("Hobart CBD", -42.8821, 147.3272)],
        "7250" => vec![locality("Launceston", -41.4388, 147.1347)],
        "7310" => vec![locality("Devonport", -41.1769, 146.3506)],
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use std::{cell::RefCell, collections::VecDeque};

    use crate::{
        http::{Method, Request, Response, Transport, TransportFailure},
        source_outcome::SourceOutcomeKind,
    };

    use super::*;

    struct FakeTransport {
        script: RefCell<VecDeque<Result<Response, TransportFailure>>>,
        seen: RefCell<Vec<Request>>,
    }

    impl FakeTransport {
        fn new(script: Vec<Result<Response, TransportFailure>>) -> Self {
            Self {
                script: RefCell::new(script.into()),
                seen: RefCell::new(Vec::new()),
            }
        }
    }

    impl Transport for FakeTransport {
        fn send(&self, request: &Request) -> Result<Response, TransportFailure> {
            self.seen.borrow_mut().push(request.clone());
            self.script.borrow_mut().pop_front().unwrap_or_else(|| {
                Err(TransportFailure {
                    kind: SourceOutcomeKind::ConnectFailure,
                    detail: "unexpected request".into(),
                    blocked: false,
                })
            })
        }
    }

    #[test]
    fn parses_real_4552_payload() {
        let raw = r#"{
            "post code": "4552", "country": "Australia", "country abbreviation": "AU",
            "places": [
                {"place name": "Maleny", "longitude": "152.7554", "state": "Queensland", "state abbreviation": "QLD", "latitude": "-26.729"},
                {"place name": "Booroobin", "longitude": "152.7554", "state": "Queensland", "state abbreviation": "QLD", "latitude": "-26.729"},
                {"place name": "Conondale", "longitude": "152.7167", "state": "Queensland", "state abbreviation": "QLD", "latitude": "-26.7333"}
            ]
        }"#;
        let localities = parse(raw);
        assert_eq!(localities.len(), 3);
        assert_eq!(localities[0].suburb, "Maleny");
        assert!((localities[0].lat + 26.729).abs() < 1e-6);
        assert!((localities[0].lon - 152.7554).abs() < 1e-6);
        assert!(localities.iter().any(|row| row.suburb == "Booroobin"));
    }

    #[test]
    fn parse_skips_blank_or_nonsensical_coords() {
        let mixed = r#"{"places":[
            {"place name":"","latitude":"-27.5","longitude":"153.0"},
            {"place name":"NullIsland","latitude":"0","longitude":"0"},
            {"place name":"OutOfRange","latitude":"200","longitude":"-999"},
            {"place name":"Good","latitude":"-27.5","longitude":"153.0"}
        ]}"#;
        let localities = parse(mixed);
        assert_eq!(localities.len(), 1);
        assert_eq!(localities[0].suburb, "Good");
        let parsed = parse("not json");
        assert!(parsed.is_empty(), "{parsed:?}");
    }

    #[test]
    fn shape_and_centroid_helpers_work() {
        assert!(is_shaped("4552"));
        assert!(is_shaped("0800"));
        assert!(is_in_au_range("4552"));
        assert!(!is_shaped("455"));
        assert!(!is_shaped("45a2"));
        assert!(!is_in_au_range("0100"));
        assert_eq!(offline_centroid("7250"), Some((-41.4388, 147.1347)));
    }

    #[test]
    fn online_lookup_uses_shared_transport_and_falls_back_cleanly() {
        let transport = FakeTransport::new(vec![Ok(Response {
            status: 200,
            headers: Vec::new(),
            body: br#"{"places":[{"place name":"Maleny","latitude":"-26.729","longitude":"152.7554"}]}"#.to_vec(),
            truncated: false,
        })]);
        let localities = localities_with("4552", &transport);
        assert_eq!(localities.len(), 1);
        let seen = transport.seen.borrow();
        let request = seen.first().expect("request recorded");
        assert_eq!(request.method, Method::Get);
        assert_eq!(request.url, "https://api.zippopotam.us/au/4552");
        assert_eq!(request.header_value("accept"), Some("application/json"));
        assert!(request.body.is_empty(), "{:?}", request.body);

        let fallback = localities_with(
            "4552",
            &FakeTransport::new(vec![Err(TransportFailure {
                kind: SourceOutcomeKind::ConnectFailure,
                detail: "boom".into(),
                blocked: false,
            })]),
        );
        assert_eq!(fallback.len(), 3);
        let empty = localities_with(
            "4552",
            &FakeTransport::new(vec![Ok(Response {
                status: 404,
                headers: Vec::new(),
                body: Vec::new(),
                truncated: false,
            })]),
        );
        assert_eq!(empty.len(), 3);
        let unshaped = localities_with(
            "bad",
            &FakeTransport::new(vec![Ok(Response {
                status: 200,
                headers: Vec::new(),
                body: Vec::new(),
                truncated: false,
            })]),
        );
        assert!(unshaped.is_empty(), "{unshaped:?}");
    }
}
