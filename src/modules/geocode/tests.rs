use super::*;
use crate::util::geo::parse_coords;

// -- forward_fetch failure contract (T2.131) -------------------------

/// One-shot local HTTP server answering with `status` + `body`. Mirrors the
/// chain_intel / sanctions_ofac test pattern.
async fn serve_once(status: u16, body: &'static str) -> std::net::SocketAddr {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let Ok((mut sock, _)) = listener.accept().await else {
            return;
        };
        let mut buf = vec![0u8; 2048];
        let _ = sock.read(&mut buf).await;
        let reason = if status == 200 { "OK" } else { "Error" };
        let head = format!(
            "HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\n\r\n",
            body.len()
        );
        let _ = sock.write_all(head.as_bytes()).await;
        let _ = sock.write_all(body.as_bytes()).await;
        let _ = sock.flush().await;
    });
    addr
}

#[tokio::test]
async fn forward_fetch_surfaces_total_failure_when_transport_and_curl_both_fail() {
    // T2.131 regression: forward() previously returned Ok(empty) when the reqwest
    // call AND the curl fallback both failed — indistinguishable from "address
    // not resolvable", silently dropping the coordinate anchor downstream geo
    // enrichers depend on. Port 1 has nothing listening: reqwest is refused, and
    // curl against the same host is refused too, so the lookup cannot execute and
    // must now surface as an Err (mirrors reverse()).
    let client = reqwest::Client::new();
    let out = forward_fetch(&client, "http://127.0.0.1:1/").await;
    assert!(
        out.is_err(),
        "a total transport+curl failure must surface as Err, not a swallowed empty result"
    );
}

#[tokio::test]
async fn forward_fetch_keeps_an_empty_array_as_a_clean_no_match() {
    // The legitimate negative MUST be preserved: a 200 with an empty JSON array
    // is Nominatim's honest "no match", an empty Vec (Ok), NOT an error — so the
    // fix surfaces outages without turning "address not resolvable" into noise.
    let addr = serve_once(200, "[]").await;
    let client = reqwest::Client::new();
    let out = forward_fetch(&client, &format!("http://{addr}/")).await;
    assert!(
        matches!(out, Ok(ref v) if v.is_empty()),
        "a 200 empty array must stay a clean no-match (Ok, empty), got {:?}",
        out.is_ok()
    );
}

#[tokio::test]
async fn forward_fetch_surfaces_parse_failure_on_a_200_garbage_body() {
    // A 200 whose body is not the expected JSON (truncation / contract change) is
    // a real anomaly, not "no match" — previously swallowed via unwrap_or_default.
    let addr = serve_once(200, "definitely not json <<<>>>").await;
    let client = reqwest::Client::new();
    let out = forward_fetch(&client, &format!("http://{addr}/")).await;
    assert!(
        out.is_err(),
        "a 200 with an unparseable body must surface as Err, not a swallowed empty result"
    );
}

// -- acceptance tests (from forward_geocode) -------------------------

#[test]
fn accepts_address() {
    let m = Geocode;
    assert!(m.accepts(&Target::new(TargetKind::Address, "Brisbane")));
}

#[test]
fn rejects_domain_and_email() {
    let m = Geocode;
    assert!(!m.accepts(&Target::new(TargetKind::Domain, "example.com")));
    assert!(!m.accepts(&Target::new(TargetKind::Email, "a@b.com")));
}

// -- acceptance tests (from reverse_geocode) --------------------------

#[test]
fn accepts_coordinates() {
    let m = Geocode;
    assert!(m.accepts(&Target::new(TargetKind::Coordinates, "0,0")));
}

#[test]
fn rejects_ip_address() {
    let m = Geocode;
    assert!(!m.accepts(&Target::new(TargetKind::IpAddress, "1.1.1.1")));
}

// -- parse_coords tests (from reverse_geocode) ------------------------

#[test]
fn parse_coords_valid() {
    let (lat, lon) = parse_coords("-33.8688,151.2093").unwrap();
    assert!((lat - (-33.8688)).abs() < 1e-4);
    assert!((lon - 151.2093).abs() < 1e-4);
}

#[test]
fn parse_coords_with_spaces() {
    let (lat, lon) = parse_coords(" 40.7128 , -74.0060 ").unwrap();
    assert!((lat - 40.7128).abs() < 1e-4);
    assert!((lon - (-74.0060)).abs() < 1e-4);
}

#[test]
fn parse_coords_invalid() {
    assert!(parse_coords("not-coords").is_err());
    assert!(parse_coords("").is_err());
}

// -- module metadata --------------------------------------------------

#[test]
fn module_metadata() {
    let m = Geocode;
    assert_eq!(m.name(), "geocode");
    assert_eq!(m.priority(), 21);
    assert_eq!(m.max_timeout_ms(), 8_000);
}

// -- AU-relevance shaping of reverse geocode --------------------------

fn resp(json: serde_json::Value) -> NominatimResp {
    serde_json::from_value(json).unwrap()
}

#[test]
fn forward_geocode_shapes_confidence_by_au_relevance() {
    // An AU result is a strong on-region anchor; a foreign one is a demoted
    // candidate that won't be expanded or counted as confirmed.
    let au = build_forward_entity(-27.4766, 153.0166, "-27.476600,153.016600", "scan");
    assert!((au.confidence - 0.70).abs() < 1e-9);
    assert!(au.has_tag("au-relevant"));
    assert!(au.has_tag("au-state:QLD")); // Brisbane
    assert!(au.has_tag("geocoded"));
    assert!(!au.has_tag("candidate"));

    let foreign = build_forward_entity(51.5074, -0.1278, "51.507400,-0.127800", "scan");
    assert!((foreign.confidence - 0.40).abs() < 1e-9);
    assert!(foreign.has_tag("off-region"));
    assert!(foreign.has_tag("candidate"));
    assert!(!foreign.has_tag("au-relevant"));
}

#[test]
fn reverse_in_australia_by_country_code_is_a_strong_anchor() {
    let data = resp(serde_json::json!({
        "display_name": "Brisbane City, QLD, Australia",
        "address": { "city": "Brisbane", "state": "Queensland", "country_code": "au" }
    }));
    let e = build_reverse_entity(-27.4766, 153.0166, &data, "scan");
    assert!((e.confidence - 0.78).abs() < 1e-9);
    assert!(e.has_tag("au-relevant"));
    assert!(e.has_tag("country:AU"));
    assert!(e.has_tag("au-state:QLD"));
    assert!(!e.has_tag("candidate"));
}

#[test]
fn reverse_off_region_by_country_code_is_a_candidate() {
    let data = resp(serde_json::json!({
        "display_name": "Manhattan, New York, USA",
        "address": { "city": "New York", "country_code": "us" }
    }));
    let e = build_reverse_entity(40.7128, -74.0060, &data, "scan");
    assert!((e.confidence - 0.40).abs() < 1e-9);
    assert!(e.has_tag("candidate"));
    assert!(e.has_tag("country:US"));
    assert!(!e.has_tag("au-relevant"));
}

#[test]
fn reverse_without_country_code_falls_back_to_the_bounding_box() {
    // No country code: an AU coordinate is still recognised on-region via
    // the offline bounding box, while a foreign one stays Unknown (neutral).
    let bare = resp(serde_json::json!({ "display_name": "somewhere" }));
    let au = build_reverse_entity(-33.8688, 151.2093, &bare, "scan");
    assert!((au.confidence - 0.78).abs() < 1e-9);
    assert!(au.has_tag("au-relevant"));

    let foreign = build_reverse_entity(48.8566, 2.3522, &bare, "scan");
    assert!((foreign.confidence - 0.55).abs() < 1e-9);
    assert!(!foreign.has_tag("au-relevant"));
    assert!(!foreign.has_tag("candidate"));
}

fn addr(json: serde_json::Value) -> NominatimAddr {
    serde_json::from_value(json).unwrap()
}

#[test]
fn au_relevance_country_code_au_is_in_australia_regardless_of_coords() {
    let a = addr(serde_json::json!({ "country_code": "AU" }));
    assert_eq!(au_relevance(0.0, 0.0, Some(&a)), AuRelevance::InAustralia);
}

#[test]
fn au_relevance_other_country_code_is_off_region() {
    let a = addr(serde_json::json!({ "country_code": "us" }));
    assert_eq!(
        au_relevance(-27.47, 153.02, Some(&a)),
        AuRelevance::OffRegion
    );
}

#[test]
fn au_relevance_no_country_code_falls_back_to_bounding_box() {
    assert_eq!(
        au_relevance(-27.4766, 153.0166, None),
        AuRelevance::InAustralia
    );
    let a = addr(serde_json::json!({ "city": "Nowhere" }));
    assert_eq!(
        au_relevance(-27.4766, 153.0166, Some(&a)),
        AuRelevance::InAustralia
    );
}

#[test]
fn au_relevance_no_country_code_outside_box_is_unknown() {
    assert_eq!(au_relevance(48.8566, 2.3522, None), AuRelevance::Unknown);
}

// -- T2.104: forward `/search?addressdetails=1` must parse the `address`
// breakdown it requests, not silently discard it -----------------------

#[test]
fn nominatim_result_deserializes_the_requested_address_breakdown() {
    // The forward request URL hardcodes `addressdetails=1`, so a real
    // Nominatim `/search` response always carries this shape. Regression
    // for T2.104: pre-fix, `NominatimResult` had no `address` field at all,
    // so this line would fail to *compile*, not just assert wrong.
    let json = serde_json::json!({
        "lat": "-27.4766",
        "lon": "153.0166",
        "display_name": "Brisbane City, QLD, Australia",
        "type": "city",
        "address": {
            "road": "George Street",
            "house_number": "1",
            "suburb": "Brisbane City",
            "city": "Brisbane",
            "state": "Queensland",
            "postcode": "4000",
            "country": "Australia",
            "country_code": "au"
        }
    });
    let r: NominatimResult = serde_json::from_value(json).unwrap();
    let a = r.address.expect("address must deserialize, not be dropped");
    assert_eq!(a.city.as_deref(), Some("Brisbane"));
    assert_eq!(a.state.as_deref(), Some("Queensland"));
    assert_eq!(a.postcode.as_deref(), Some("4000"));
    assert_eq!(a.country_code.as_deref(), Some("au"));
}

#[test]
fn nominatim_result_without_address_still_parses() {
    // Some Nominatim deployments/results omit the block entirely (e.g. a
    // coarse country-level hit) — must stay optional, never required.
    let json = serde_json::json!({
        "lat": "-27.4766",
        "lon": "153.0166",
        "display_name": "Australia",
        "type": "country"
    });
    let r: NominatimResult = serde_json::from_value(json).unwrap();
    assert!(r.address.is_none());
}

#[test]
fn fold_address_attrs_surfaces_the_full_breakdown() {
    let a = addr(serde_json::json!({
        "road": "George Street",
        "house_number": "1",
        "suburb": "Brisbane City",
        "city": "Brisbane",
        "county": "Greater Brisbane",
        "state": "Queensland",
        "postcode": "4000",
        "country": "Australia",
        "country_code": "au"
    }));
    let ev = fold_address_attrs(Evidence::new(SRC, "test"), &a);
    assert_eq!(
        ev.attributes.get("city").map(String::as_str),
        Some("Brisbane")
    );
    assert_eq!(
        ev.attributes.get("state").map(String::as_str),
        Some("Queensland")
    );
    assert_eq!(
        ev.attributes.get("country").map(String::as_str),
        Some("Australia")
    );
    assert_eq!(
        ev.attributes.get("country_code").map(String::as_str),
        Some("AU")
    );
    assert_eq!(
        ev.attributes.get("postcode").map(String::as_str),
        Some("4000")
    );
    assert_eq!(
        ev.attributes.get("street").map(String::as_str),
        Some("1 George Street")
    );
    assert_eq!(
        ev.attributes.get("suburb").map(String::as_str),
        Some("Brisbane City")
    );
    assert_eq!(
        ev.attributes.get("county").map(String::as_str),
        Some("Greater Brisbane")
    );
}

#[test]
fn fold_address_attrs_falls_back_through_city_town_village_municipality() {
    let a = addr(serde_json::json!({ "village": "Nowhereville" }));
    let ev = fold_address_attrs(Evidence::new(SRC, "test"), &a);
    assert_eq!(
        ev.attributes.get("city").map(String::as_str),
        Some("Nowhereville")
    );
}

#[test]
fn fold_address_attrs_road_without_house_number_omits_the_number() {
    let a = addr(serde_json::json!({ "road": "George Street" }));
    let ev = fold_address_attrs(Evidence::new(SRC, "test"), &a);
    assert_eq!(
        ev.attributes.get("street").map(String::as_str),
        Some("George Street")
    );
}

#[test]
fn fold_address_attrs_empty_address_adds_no_attrs() {
    let a = addr(serde_json::json!({}));
    let ev = fold_address_attrs(Evidence::new(SRC, "test"), &a);
    assert!(ev.attributes.is_empty());
}
