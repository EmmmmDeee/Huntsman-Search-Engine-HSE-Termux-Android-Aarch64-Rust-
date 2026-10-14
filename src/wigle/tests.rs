use std::sync::Mutex;

use super::*;
use crate::http::{Method, TransportFailure};

const USER: &str = "AIDtest0123456789abcdef";
const TOKEN: &str = "wigle-test-token-0123456789abcdef";

fn keys() -> Keys {
    match Keys::parse(&format!("{USER_SLOT}={USER}\n{TOKEN_SLOT}={TOKEN}\n")) {
        Ok(keys) => keys,
        Err(error) => panic!("fixture keys parse: {error}"),
    }
}

fn bssid() -> NetworkSelector {
    NetworkSelector::Bssid("3c:5a:b4:01:02:03".into())
}

/// A `NetSearchResponse` as the Swagger schema shapes it: two networks, a repeat of the first,
/// a row whose `netid` is not a BSSID, and `WiGLE`'s literal "null" strings.
fn sample() -> Value {
    serde_json::json!({
        "success": true,
        "totalResults": 4,
        "first": 1,
        "last": 4,
        "resultCount": 4,
        "searchAfter": "1234",
        "search_after": 1234,
        "results": [
            {"trilat": -27.469_812, "trilong": 153.025_123, "ssid": "Cafe Guest", "qos": 2,
             "transid": "20240101-00000", "firsttime": "2021-03-04T05:06:07.000Z",
             "lasttime": "2026-09-01T10:00:00.000Z", "lastupdt": "2026-09-02T00:00:00.000Z",
             "netid": "3C:5A:B4:01:02:03", "name": null, "type": "infra", "comment": null,
             "wep": "2", "bcninterval": 0, "freenet": "?", "dhcp": "?", "paynet": "?",
             "userfound": false, "channel": 6, "frequency": 2437, "encryption": "wpa2",
             "country": "AU", "region": "QLD", "road": "Queen Street", "city": "Brisbane",
             "housenumber": "100", "postalcode": "4000"},
            {"trilat": 0.0, "trilong": 0.0, "ssid": "", "netid": "02:11:22:33:44:55",
             "channel": 0, "encryption": "unknown", "city": "null"},
            {"trilat": -27.0, "trilong": 153.0, "ssid": "Cafe Guest", "netid": "3c:5a:b4:01:02:03"},
            {"trilat": -27.0, "trilong": 153.0, "ssid": "Cell", "netid": "50501_28693_147572482"}
        ]
    })
}

fn decoded(body: &Value) -> Search {
    match decode(Database::Wifi, body.to_string().as_bytes(), &[TOKEN]) {
        Ok(search) => search,
        Err(error) => panic!("decode failed: {error}"),
    }
}

#[test]
fn results_become_wigle_sightings_with_their_recorded_context() {
    let search = decoded(&sample());
    assert_eq!(search.results, 4);
    assert_eq!(search.unusable, 1, "a cell id is not a BSSID");
    assert_eq!(search.total, Some(4));
    assert_eq!(search.truncation(), None);
    let ids: Vec<&str> = search.networks.iter().map(Network::bssid).collect();
    assert_eq!(
        ids,
        ["3c:5a:b4:01:02:03", "02:11:22:33:44:55"],
        "a repeat is kept once"
    );

    let cafe = &search.networks[0];
    assert_eq!(cafe.sighting.source, RfSource::WigleApi);
    assert_eq!(cafe.sighting.radio, RadioKind::Wifi);
    assert_eq!(cafe.ssid(), Some("Cafe Guest"));
    assert_eq!(cafe.sighting.encryption.as_deref(), Some("wpa2"));
    assert_eq!(cafe.sighting.raw_type.as_deref(), Some("infra"));
    assert_eq!(cafe.position(), Some((-27.469_812, 153.025_123)));
    assert_eq!(cafe.channel, Some(6));
    assert_eq!(cafe.frequency_mhz, Some(2437));
    assert_eq!(cafe.first_seen.as_deref(), Some("2021-03-04T05:06:07.000Z"));
    assert_eq!(
        cafe.sighting.observed_at.as_deref(),
        Some("2026-09-01T10:00:00.000Z")
    );
    assert!(cafe.sighting.observed_epoch.is_some());
    assert_eq!(
        cafe.address().as_deref(),
        Some("100 Queen Street, Brisbane, QLD, 4000, AU")
    );

    let hidden = &search.networks[1];
    assert_eq!(hidden.ssid(), None, "a blank SSID is no SSID");
    assert_eq!(hidden.position(), None, "0,0 is not a position");
    assert_eq!(hidden.channel, None);
    assert_eq!(hidden.city, None, "WiGLE's literal null is no value");
    assert_eq!(hidden.address(), None);
}

#[test]
fn more_networks_than_read_is_partial() {
    let mut body = sample();
    body["totalResults"] = serde_json::json!(250);
    let note = decoded(&body).truncation().unwrap_or_default();
    assert!(note.contains("first 4 of 250"), "{note}");
}

#[test]
fn an_empty_success_is_a_zero_and_a_failure_envelope_is_not() {
    let empty = decoded(&serde_json::json!({"success": true, "totalResults": 0, "results": []}));
    assert!(empty.networks.is_empty());
    assert_eq!(empty.truncation(), None);

    let refused = decode(
        Database::Wifi,
        format!(r#"{{"success": false, "message": "too many queries today {TOKEN}\u0007"}}"#)
            .as_bytes(),
        &[TOKEN],
    );
    let Err(WigleError::Provider(words)) = refused else {
        panic!("expected a provider failure, got {refused:?}");
    };
    assert!(!words.contains(TOKEN), "{words}");
    assert!(!words.contains('\u{7}'), "{words}");
}

#[test]
fn a_body_that_is_not_the_envelope_is_schema_drift_and_quotes_nothing() {
    for body in [
        r#"{"success": true}"#,
        r#"{"success": true, "results": "Cafe Guest"}"#,
        "<html>Cafe Guest</html>",
    ] {
        let error = match decode(Database::Wifi, body.as_bytes(), &[TOKEN]) {
            Err(error) => error,
            Ok(search) => panic!("{body:?} decoded as {search:?}"),
        };
        assert_eq!(
            error.outcome_kind(),
            SourceOutcomeKind::SchemaDrift,
            "{body}"
        );
        assert!(!error.to_string().contains("Cafe"), "{error}");
    }
}

#[test]
fn provider_text_is_bounded_and_control_free() {
    let body = serde_json::json!({"success": true, "results": [
        {"netid": "3c:5a:b4:01:02:03", "ssid": "a\u{1b}[2J\nforged", "road": "r".repeat(500)}
    ]});
    let net = &decoded(&body).networks[0];
    let ssid = net.ssid().unwrap_or_default();
    assert!(!ssid.chars().any(char::is_control), "{ssid:?}");
    assert_eq!(net.road.as_deref().map(|r| r.chars().count()), Some(120));
}

#[test]
fn each_selector_is_one_query_on_the_search_endpoint() {
    assert_eq!(
        search_url(Database::Wifi, &bssid()),
        "https://api.wigle.net/api/v2/network/search?netid=3C%3A5A%3AB4%3A01%3A02%3A03&resultsPerPage=100"
    );
    assert_eq!(
        search_url(
            Database::Wifi,
            &NetworkSelector::Ssid("Cafe Guest&x=1".into())
        ),
        "https://api.wigle.net/api/v2/network/search?ssid=Cafe+Guest%26x%3D1&resultsPerPage=100"
    );
    assert_eq!(
        search_url(
            Database::Wifi,
            &NetworkSelector::Area {
                lat: -27.4698,
                lon: 153.0251
            }
        ),
        "https://api.wigle.net/api/v2/network/search?latrange1=-27.471800&latrange2=-27.467800\
         &longrange1=153.023100&longrange2=153.027100&closestLat=-27.469800&closestLong=153.025100\
         &resultsPerPage=100"
    );
    // The box is clamped to the globe.
    let edge = search_url(
        Database::Wifi,
        &NetworkSelector::Area {
            lat: 89.9995,
            lon: -179.9995,
        },
    );
    assert!(edge.contains("latrange2=90.000000"), "{edge}");
    assert!(edge.contains("longrange1=-180.000000"), "{edge}");
}

/// Answers each request with the next canned response and records what was sent.
struct Recorder {
    responses: Mutex<Vec<Response>>,
    sent: Mutex<Vec<Request>>,
}

impl Recorder {
    fn new(responses: Vec<Response>) -> Self {
        Self {
            responses: Mutex::new(responses),
            sent: Mutex::default(),
        }
    }

    fn sent(&self) -> Vec<Request> {
        self.sent
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}

impl Transport for Recorder {
    fn send(&self, request: &Request) -> Result<Response, TransportFailure> {
        self.sent
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(request.clone());
        let mut responses = self
            .responses
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if responses.is_empty() {
            return Ok(status(500, ""));
        }
        Ok(responses.remove(0))
    }
}

fn status(code: u16, body: &str) -> Response {
    Response {
        status: code,
        headers: vec![("content-type".into(), "application/json".into())],
        body: body.as_bytes().to_vec(),
        truncated: false,
    }
}

#[test]
fn the_search_sends_one_get_with_basic_credentials_to_the_fixed_origin() {
    let transport = Recorder::new(vec![crate::test_support::json_ok(&sample().to_string())]);
    let search = match search(&transport, &keys(), Database::Wifi, &bssid(), 7) {
        Ok(search) => search,
        Err(error) => panic!("search failed: {error}"),
    };
    assert_eq!(search.networks.len(), 2);
    let sent = transport.sent();
    assert_eq!(sent.len(), 1);
    let request = &sent[0];
    assert_eq!(request.method, Method::Get);
    assert_eq!(request.url, search_url(Database::Wifi, &bssid()));
    let expected = format!(
        "Basic {}",
        crate::base64::standard(format!("{USER}:{TOKEN}").as_bytes())
    );
    assert_eq!(
        request.header_value("authorization"),
        Some(expected.as_str())
    );
}

#[test]
fn credentials_need_both_slots_and_send_nothing_without_them() {
    for text in [
        String::new(),
        format!("{USER_SLOT}={USER}\n"),
        format!("{TOKEN_SLOT}={TOKEN}\n"),
    ] {
        let keys = match Keys::parse(&text) {
            Ok(keys) => keys,
            Err(error) => panic!("keys parse: {error}"),
        };
        assert!(!configured(&keys));
        let transport = Recorder::new(Vec::new());
        assert_eq!(
            search(&transport, &keys, Database::Wifi, &bssid(), 7),
            Err(WigleError::MissingKey)
        );
        assert!(transport.sent().is_empty());
    }
    assert!(configured(&keys()));
}

#[test]
fn a_user_with_a_colon_is_refused_before_sending() {
    let keys = match Keys::parse(&format!("{USER_SLOT}=AIDx:y\n{TOKEN_SLOT}={TOKEN}\n")) {
        Ok(keys) => keys,
        Err(error) => panic!("keys parse: {error}"),
    };
    let transport = Recorder::new(Vec::new());
    let result = search(&transport, &keys, Database::Wifi, &bssid(), 7);
    assert!(matches!(result, Err(WigleError::Refused(_))), "{result:?}");
    assert!(transport.sent().is_empty());
}

#[test]
fn statuses_map_to_outcomes_and_never_quote_the_body_or_credentials() {
    let mut limited = status(
        429,
        r#"{"success": false, "message": "too many queries today."}"#,
    );
    limited.headers.push(("retry-after".into(), "3600".into()));
    let cases = [
        (status(400, "{}"), SourceOutcomeKind::Upstream4xx, Some(400)),
        (
            // WiGLE answers a bad credential with plain text, not JSON.
            status(401, "Not Authorized (WiGLE.net)"),
            SourceOutcomeKind::AuthRejected,
            Some(401),
        ),
        (
            status(402, "{}"),
            SourceOutcomeKind::EntitlementDenied,
            Some(402),
        ),
        (
            status(403, "{}"),
            SourceOutcomeKind::EntitlementDenied,
            Some(403),
        ),
        (status(410, "{}"), SourceOutcomeKind::Upstream4xx, Some(410)),
        (limited, SourceOutcomeKind::RateLimited, Some(429)),
        (
            status(503, "Cafe Guest"),
            SourceOutcomeKind::Upstream5xx,
            Some(503),
        ),
        (status(404, "{}"), SourceOutcomeKind::Upstream4xx, Some(404)),
    ];
    for (response, kind, http) in cases {
        let code = response.status;
        let transport = Recorder::new(vec![response]);
        let error = match search(&transport, &keys(), Database::Wifi, &bssid(), 7) {
            Err(error) => error,
            Ok(search) => panic!("HTTP {code} gave {search:?}"),
        };
        assert_eq!(error.outcome_kind(), kind, "HTTP {code}");
        assert_eq!(error.http_status(), http, "HTTP {code}");
        let text = error.to_string();
        for leak in ["Cafe", USER, TOKEN] {
            assert!(!text.contains(leak), "{leak} in {text}");
        }
        if code == 429 {
            assert_eq!(
                error,
                WigleError::RateLimited {
                    retry_after: Some(3600)
                }
            );
        }
    }
}

#[test]
fn a_redirect_is_not_followed_so_the_credentials_go_nowhere_else() {
    let mut moved = status(302, "");
    moved
        .headers
        .push(("location".into(), "https://elsewhere.example/steal".into()));
    let transport = Recorder::new(vec![moved]);
    let result = search(&transport, &keys(), Database::Wifi, &bssid(), 7);
    assert_eq!(result, Err(WigleError::Unexpected(302)));
    let sent = transport.sent();
    assert_eq!(sent.len(), 1, "only the first request is sent");
    assert!(sent[0].url.starts_with(API_URL));
}

#[test]
fn a_mac_or_a_place_is_searched_in_both_databases_and_an_ssid_only_in_wifi() {
    assert_eq!(
        Database::for_selector(&bssid()),
        [Database::Wifi, Database::Bluetooth]
    );
    let area = NetworkSelector::Area {
        lat: -27.4698,
        lon: 153.0251,
    };
    assert_eq!(
        Database::for_selector(&area),
        [Database::Wifi, Database::Bluetooth]
    );
    assert_eq!(
        Database::for_selector(&NetworkSelector::Ssid("Cafe".into())),
        [Database::Wifi]
    );
    assert_eq!(
        search_url(Database::Bluetooth, &bssid()),
        "https://api.wigle.net/api/v2/bluetooth/search?netid=3C%3A5A%3AB4%3A01%3A02%3A03&resultsPerPage=100"
    );
    assert!(
        search_url(Database::Bluetooth, &area).starts_with(&format!("{BLUETOOTH_URL}?latrange1="))
    );
    assert!(
        search_url(
            Database::Bluetooth,
            &NetworkSelector::Ssid("Ada Buds".into())
        )
        .contains("?name=Ada+Buds&")
    );
}

#[test]
fn bluetooth_rows_keep_their_radio_class_and_device_name() {
    let body = serde_json::json!({"success": true, "totalResults": 3, "results": [
        {"netid": "F4:5C:89:AA:BB:CC", "name": "Ada Buds", "type": "BLE",
         "trilat": -27.47, "trilong": 153.02, "lasttime": "2026-09-01T10:00:00.000Z"},
        {"netid": "00:1a:7d:da:71:13", "name": "Car Kit", "type": "BTAttributes: Car Audio;10"},
        {"netid": "00:1a:7d:da:71:14", "ssid": "Legacy", "type": "?"}
    ]});
    let search = match decode(Database::Bluetooth, body.to_string().as_bytes(), &[TOKEN]) {
        Ok(search) => search,
        Err(error) => panic!("decode failed: {error}"),
    };
    let buds = &search.networks[0];
    assert_eq!(buds.sighting.radio, RadioKind::Ble);
    assert_eq!(buds.ssid(), Some("Ada Buds"));
    assert_eq!(buds.sighting.source, RfSource::WigleApi);
    assert_eq!(buds.position(), Some((-27.47, 153.02)));
    let car = &search.networks[1];
    assert_eq!(car.sighting.radio, RadioKind::BtClassic);
    assert_eq!(car.sighting.device_class.as_deref(), Some("Car Audio"));
    let legacy = &search.networks[2];
    assert_eq!(
        legacy.sighting.radio,
        RadioKind::Ble,
        "an unknown type is BLE"
    );
    assert_eq!(legacy.ssid(), Some("Legacy"), "name falls back to ssid");
}

#[test]
fn a_bluetooth_search_uses_the_same_pinned_credentials() {
    let transport = Recorder::new(vec![crate::test_support::json_ok(
        r#"{"success":true,"totalResults":0,"results":[]}"#,
    )]);
    let found = search(&transport, &keys(), Database::Bluetooth, &bssid(), 7);
    assert!(
        matches!(&found, Ok(s) if s.networks.is_empty()),
        "{found:?}"
    );
    let sent = transport.sent();
    assert_eq!(sent.len(), 1);
    assert!(sent[0].url.starts_with(BLUETOOTH_URL), "{}", sent[0].url);
    assert!(
        sent[0]
            .header_value("authorization")
            .is_some_and(|v| v.starts_with("Basic "))
    );
}
