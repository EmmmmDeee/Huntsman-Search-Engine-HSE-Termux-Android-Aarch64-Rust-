use std::sync::Mutex;

use super::*;
use crate::http::{Request, Response, TransportFailure};

const USER: &str = "AIDtest0123456789abcdef";
const TOKEN: &str = "wigle-test-token-0123456789abcdef";

fn keys() -> Keys {
    match Keys::parse(&format!(
        "{}={USER}\n{}={TOKEN}\n",
        wigle::USER_SLOT,
        wigle::TOKEN_SLOT
    )) {
        Ok(keys) => keys,
        Err(error) => panic!("fixture keys parse: {error}"),
    }
}

/// Answers every request with one canned answer and records each requested URL.
struct Canned {
    answer: Result<Response, TransportFailure>,
    urls: Mutex<Vec<String>>,
}

impl Canned {
    fn json(body: &serde_json::Value) -> Self {
        Self {
            answer: Ok(crate::test_support::json_ok(&body.to_string())),
            urls: Mutex::default(),
        }
    }

    fn urls(&self) -> Vec<String> {
        self.urls
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}

impl Transport for Canned {
    fn send(&self, request: &Request) -> Result<Response, TransportFailure> {
        self.urls
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(request.url.clone());
        self.answer.clone()
    }
}

fn cafe() -> serde_json::Value {
    serde_json::json!({"success": true, "totalResults": 1, "results": [
        {"trilat": -27.469_812, "trilong": 153.025_123, "ssid": "Cafe Guest",
         "netid": "3C:5A:B4:01:02:03", "channel": 6, "encryption": "wpa2",
         "firsttime": "2021-03-04T05:06:07.000Z", "lasttime": "2026-09-01T10:00:00.000Z",
         "road": "Queen Street", "city": "Brisbane", "country": "AU"}
    ]})
}

fn printed(run_result: NetworkRun) -> (String, Report) {
    match run_result {
        NetworkRun::Printed { text, report } => (text, report),
        other => panic!("expected a printed report, got {other:?}"),
    }
}

#[test]
fn selectors_parse_and_their_canonical_form_reads_back() {
    let cases = [
        (
            "00-1A-2B-3C-4D-5E",
            NetworkSelector::Bssid("00:1a:2b:3c:4d:5e".into()),
        ),
        (" Cafe Guest ", NetworkSelector::Ssid("Cafe Guest".into())),
        (
            "ssid:00:1a:2b:3c:4d:5e",
            NetworkSelector::Ssid("00:1a:2b:3c:4d:5e".into()),
        ),
        (
            "ssid:-27.4,153.0",
            NetworkSelector::Ssid("-27.4,153.0".into()),
        ),
        ("ssid:ssid:x", NetworkSelector::Ssid("ssid:x".into())),
        (
            "-27.4698, 153.0251",
            NetworkSelector::Area {
                lat: -27.4698,
                lon: 153.0251,
            },
        ),
    ];
    for (raw, expected) in cases {
        let parsed = NetworkSelector::parse(raw);
        assert_eq!(parsed.as_ref(), Some(&expected), "{raw}");
        let canonical = expected.canonical();
        assert_eq!(
            NetworkSelector::parse(&canonical),
            Some(expected),
            "{canonical}"
        );
    }
    assert_eq!(
        NetworkSelector::Ssid("00:1a:2b:3c:4d:5e".into()).canonical(),
        "ssid:00:1a:2b:3c:4d:5e"
    );
    for bad in ["", "   ", "ssid:", "a\u{7}b", &"x".repeat(33), "0,0"] {
        let parsed = NetworkSelector::parse_identifier(bad);
        assert_eq!(parsed, None, "{bad:?} is not an identifier");
    }
    for bad in ["", "   ", "ssid:", "a\u{7}b", &"x".repeat(33)] {
        assert_eq!(NetworkSelector::parse(bad), None, "{bad:?}");
    }
    // An SSID is never an identifier, so scan cannot infer one.
    assert_eq!(NetworkSelector::parse_identifier("Cafe Guest"), None);
}

#[test]
fn without_credentials_a_bssid_is_still_classified_and_wigle_reports_not_configured() {
    let (text, report) = printed(run(
        &crate::test_support::Refusing,
        &Keys::default(),
        "3C:5A:B4:01:02:03",
        7,
    ));
    let legs: Vec<_> = report
        .outcomes
        .iter()
        .map(|o| (o.module.as_str(), o.kind))
        .collect();
    assert_eq!(
        legs,
        [
            (OUI_SOURCE, SourceOutcomeKind::Success),
            (wigle::SOURCE, SourceOutcomeKind::NotConfigured),
            (wigle::BLUETOOTH_SOURCE, SourceOutcomeKind::NotConfigured)
        ]
    );
    assert_eq!(report.wigle, None, "no answer is not a zero");
    assert_eq!(report.entities.len(), 1, "seed and OUI evidence merge");
    // The registry is read for the address's own prefix: nothing has observed the address.
    assert!(
        report.entities[0].corroborating_sources().is_empty(),
        "{:?}",
        report.entities[0]
    );
    let vendor = report.entities[0]
        .evidence
        .iter()
        .find_map(|e| e.attributes.get("vendor"))
        .cloned();
    assert_eq!(
        vendor.as_deref(),
        Some("Google, Inc."),
        "the IEEE assignee: {text}"
    );
    assert!(
        text.ends_with("wigle_networks=none\nwigle_bluetooth_devices=none\n"),
        "{text}"
    );
    assert!(text.contains(wigle::USER_SLOT), "{text}");
}

/// A BSSID `WiGLE` recorded is observed by `WiGLE` alone: the OUI registry's reading of its prefix is
/// no second source of it.
#[test]
fn a_bssids_manufacturer_is_no_source_of_it() {
    let wifi = cafe().to_string();
    let transport = crate::test_support::RoutedTransport::new(&[
        (wigle::API_URL, 200, wifi.leak()),
        (
            wigle::BLUETOOTH_URL,
            200,
            r#"{"success": true, "totalResults": 0, "results": []}"#,
        ),
    ]);
    let keys = keys();
    let (text, report) = printed(run(&transport, &keys, "3C:5A:B4:01:02:03", 7));
    let bssid = report
        .entities
        .iter()
        .find(|e| e.kind == EntityKind::MacAddress && e.value == "3c:5a:b4:01:02:03")
        .unwrap_or_else(|| panic!("no BSSID entity: {text}"));
    let sources = bssid.evidence_sources();
    assert!(
        sources.contains(OUI_SOURCE) && sources.contains(wigle::SOURCE),
        "{sources:?}"
    );
    let corroborating = bssid.corroborating_sources();
    assert!(!corroborating.contains(OUI_SOURCE), "{corroborating:?}");
    assert!(corroborating.contains(wigle::SOURCE), "{corroborating:?}");
    assert_eq!(
        bssid.source_count(),
        u32::try_from(corroborating.len()).unwrap(),
        "{bssid:?}"
    );
    // So no correlation holds it as corroborated by independent sources.
    let correlations = crate::correlator::evaluate_rules(&report.entities, &[], "scan");
    assert!(
        correlations
            .iter()
            .all(|correlation| !(correlation.rule_id == "AU-003"
                && correlation.entity_uids.contains(&bssid.uid))),
        "{correlations:#?}"
    );
}

#[test]
fn a_prefix_no_manufacturer_is_registered_for_reports_none() {
    // 10:10:10 has no IEEE MA-L assignment: the registry names no manufacturer, so the OUI row
    // is a validated zero and no "Unknown" manufacturer is recorded as found.
    let (text, report) = printed(run(
        &crate::test_support::Refusing,
        &Keys::default(),
        "10:10:10:01:02:03",
        7,
    ));
    assert_eq!(report.outcomes[0].module, OUI_SOURCE);
    assert_eq!(
        report.outcomes[0].kind,
        SourceOutcomeKind::ValidZero,
        "{text}"
    );
    assert!(
        report
            .entities
            .iter()
            .flat_map(|entity| &entity.evidence)
            .all(|evidence| !evidence.attributes.contains_key("vendor")),
        "{text}"
    );
}

#[test]
fn a_half_configured_account_makes_no_request() {
    let transport = Canned::json(&cafe());
    let only_user = match Keys::parse(&format!("{}={USER}\n", wigle::USER_SLOT)) {
        Ok(keys) => keys,
        Err(error) => panic!("keys parse: {error}"),
    };
    let (_, report) = printed(run(&transport, &only_user, "Cafe Guest", 7));
    assert!(transport.urls().is_empty());
    assert_eq!(
        report.outcomes.last().map(|o| o.kind),
        Some(SourceOutcomeKind::NotConfigured)
    );
}

#[test]
fn wigle_networks_become_bssid_entities_with_ssid_and_position_pivots() {
    let transport = Canned::json(&cafe());
    let keys = keys();
    let (text, report) = printed(run(&transport, &keys, "ssid:Cafe Guest", 7));
    let urls = transport.urls();
    assert_eq!(urls.len(), 1, "{urls:?}");
    assert!(urls[0].contains("ssid=Cafe+Guest"), "{urls:?}");

    let outcome = report
        .outcomes
        .iter()
        .find(|o| o.module == wigle::SOURCE)
        .unwrap_or_else(|| panic!("no wigle outcome: {text}"));
    assert_eq!(outcome.kind, SourceOutcomeKind::Success);
    assert_eq!(outcome.found, Some(1));

    let bssid = report
        .entities
        .iter()
        .find(|e| e.kind == EntityKind::MacAddress)
        .unwrap_or_else(|| panic!("no BSSID entity: {text}"));
    assert_eq!(bssid.value, "3c:5a:b4:01:02:03");
    assert!(bssid.tags.iter().any(|t| t == tags::GEOINT));
    let evidence = bssid
        .evidence
        .iter()
        .find(|e| e.provenance.source == wigle::SOURCE)
        .unwrap_or_else(|| panic!("no wigle evidence: {text}"));
    for (key, value) in [
        ("ssid", "Cafe Guest"),
        ("encryption", "wpa2"),
        ("channel", "6"),
        ("position", "-27.469812,153.025123"),
        ("first_seen", "2021-03-04T05:06:07.000Z"),
        ("last_seen", "2026-09-01T10:00:00.000Z"),
        ("address", "Queen Street, Brisbane, AU"),
    ] {
        assert_eq!(
            evidence.attributes.get(key).map(String::as_str),
            Some(value),
            "{key}"
        );
    }
    // The SSID seed and the SSID WiGLE records are one entity.
    let ssids: Vec<_> = report
        .entities
        .iter()
        .filter(|e| e.kind == EntityKind::Ssid)
        .collect();
    assert_eq!(ssids.len(), 1, "{ssids:?}");
    assert!(
        report
            .entities
            .iter()
            .any(|e| e.kind == EntityKind::Coordinates && e.value == "-27.469812,153.025123"),
        "{text}"
    );
    assert!(text.contains("\nwigle_networks=1\n"), "{text}");
    assert!(
        text.contains(
            "wigle_network\t3c:5a:b4:01:02:03\tssid=Cafe Guest\tencryption=wpa2\tchannel=6\t\
             position=-27.469812,153.025123\tfirst_seen=2021-03-04T05:06:07.000Z\t\
             last_seen=2026-09-01T10:00:00.000Z\taddress=Queen Street, Brisbane, AU\n"
        ),
        "{text}"
    );
    for leak in [USER, TOKEN] {
        assert!(!text.contains(leak), "{leak} in {text}");
    }
}

#[test]
fn a_coordinate_selector_searches_the_box_around_it() {
    let transport =
        Canned::json(&serde_json::json!({"success": true, "totalResults": 0, "results": []}));
    let keys = keys();
    let (text, report) = printed(run(&transport, &keys, "-27.4698,153.0251", 7));
    let urls = transport.urls();
    assert!(urls[0].contains("latrange1=-27.471800"), "{urls:?}");
    let row = |source: &str| {
        report
            .outcomes
            .iter()
            .find(|o| o.module == source)
            .map(|o| o.kind)
    };
    assert_eq!(
        row(wigle::BLUETOOTH_SOURCE),
        Some(SourceOutcomeKind::ValidZero)
    );
    // Without its key OpenCelliD's area search makes no request and says so.
    assert_eq!(
        row(opencellid::SOURCE),
        Some(SourceOutcomeKind::NotConfigured)
    );
    assert_eq!(urls.len(), 2, "WiFi then Bluetooth: {urls:?}");
    assert!(urls[1].starts_with(wigle::BLUETOOTH_URL), "{urls:?}");
    assert!(
        text.ends_with("wigle_networks=0\nwigle_bluetooth_devices=0\n"),
        "{text}"
    );
}

#[test]
fn a_request_wigle_answered_with_an_error_is_a_row_of_the_report() {
    let limited = Canned {
        answer: Ok(Response {
            status: 429,
            headers: Vec::new(),
            body: br#"{"success":false,"message":"too many queries today."}"#.to_vec(),
            truncated: false,
        }),
        urls: Mutex::default(),
    };
    let keys = keys();
    let (text, report) = printed(run(&limited, &keys, "Cafe Guest", 7));
    assert_eq!(
        report.outcomes.last().map(|o| o.kind),
        Some(SourceOutcomeKind::RateLimited)
    );
    assert!(text.ends_with("wigle_networks=none\n"), "{text}");
}

/// A transport whose every request fails the same way.
fn failing(blocked: bool) -> Canned {
    Canned {
        answer: Err(TransportFailure {
            kind: SourceOutcomeKind::TtfbTimeout,
            detail: "timed out".into(),
            blocked,
        }),
        urls: Mutex::default(),
    }
}

/// The CLI's exit codes: no usable response is 69 (`Failed`), a refusal by the egress policy 77
/// (`Network`). A timeout is not a refusal.
#[test]
fn with_nothing_answered_no_response_is_unavailable_and_a_refusal_is_refused() {
    let keys = keys();
    match run(&failing(false), &keys, "Cafe Guest", 7) {
        NetworkRun::Failed(why) => assert!(
            why.starts_with("no source answered the network lookup: wigle: no response"),
            "{why}"
        ),
        other => panic!("a search that got no response is unavailable, got {other:?}"),
    }
    match run(&failing(true), &keys, "Cafe Guest", 7) {
        NetworkRun::Network(why) => assert!(why.starts_with("wigle: request refused"), "{why}"),
        other => panic!("a search the egress policy refused is a refusal, got {other:?}"),
    }
    // A BSSID still has its offline classification, so it prints either way.
    for blocked in [false, true] {
        assert!(matches!(
            run(&failing(blocked), &keys, "3c:5a:b4:01:02:03", 7),
            NetworkRun::Printed { .. }
        ));
    }
}

#[test]
fn a_mac_found_as_a_bluetooth_device_is_reported_with_its_class() {
    let body = serde_json::json!({"success": true, "totalResults": 1, "results": [
        {"netid": "00:1A:7D:DA:71:13", "name": "Car Kit", "type": "BTAttributes: Car Audio;10",
         "trilat": -27.47, "trilong": 153.02, "lasttime": "2026-09-01T10:00:00.000Z"}
    ]});
    let transport = Canned::json(&body);
    let keys = keys();
    let (text, report) = printed(run(&transport, &keys, "00:1a:7d:da:71:13", 7));
    assert_eq!(transport.urls().len(), 2, "WiFi then Bluetooth");
    let bluetooth = report
        .outcomes
        .iter()
        .find(|o| o.module == wigle::BLUETOOTH_SOURCE)
        .unwrap_or_else(|| panic!("no bluetooth outcome: {text}"));
    assert_eq!(bluetooth.found, Some(1));
    let mac = report
        .entities
        .iter()
        .find(|e| e.kind == EntityKind::MacAddress)
        .unwrap_or_else(|| panic!("no MAC entity: {text}"));
    let evidence = mac
        .evidence
        .iter()
        .find(|e| e.provenance.source == wigle::BLUETOOTH_SOURCE)
        .unwrap_or_else(|| panic!("no bluetooth evidence: {text}"));
    assert_eq!(
        evidence.attributes.get("radio").map(String::as_str),
        Some("bt")
    );
    assert_eq!(
        evidence.attributes.get("device_name").map(String::as_str),
        Some("Car Kit")
    );
    assert!(
        !report.entities.iter().any(|e| e.kind == EntityKind::Ssid),
        "a device name is not an SSID"
    );
    assert!(
        text.contains(
            "wigle_bluetooth\t00:1a:7d:da:71:13\tname=Car Kit\tradio=bt\tclass=Car Audio\t\
             position=-27.470000,153.020000\tfirst_seen=unknown\t\
             last_seen=2026-09-01T10:00:00.000Z\taddress=unknown\n"
        ),
        "{text}"
    );
}

/// A cell site, as `radar cells` reports one, is a network selector of its own: written
/// `cell:MCC:MNC:AREA:CELL`, inferred by `scan`, and never taken for an SSID unless written as one.
#[test]
fn a_cell_site_selector_parses_canonically_and_is_inferred() {
    for (raw, canonical) in [
        ("cell:505:01:17:91", "cell:505:01:17:91"),
        (" CELL:505:010:17:91 ", "cell:505:010:17:91"),
        (
            "cell:310:410:65535:68719476735",
            "cell:310:410:65535:68719476735",
        ),
    ] {
        let selector = NetworkSelector::parse(raw).expect(raw);
        assert!(matches!(selector, NetworkSelector::Cell { .. }), "{raw}");
        assert_eq!(selector.canonical(), canonical);
        assert_eq!(NetworkSelector::parse(canonical), Some(selector));
        assert_eq!(
            crate::scan_route::infer_kind(raw),
            crate::scan_route::ScanKind::Network
        );
    }
    for bad in [
        "cell:000:01:17:91",
        "cell:505:1:17:91",
        "cell:505:01:17",
        "cell:505:01:17:91:2",
        "cell:505:01:+17:91",
        "cell:505:01:17:68719476736",
        "cell:5050:01:17:91",
    ] {
        assert_eq!(NetworkSelector::parse_identifier(bad), None, "{bad}");
        // A mistyped cell site is refused, not searched for as a network named after it.
        assert_eq!(NetworkSelector::parse(bad), None, "{bad}");
    }
    // An SSID that reads as a cell site is written with its prefix, and reads back as an SSID.
    let ssid = NetworkSelector::parse("ssid:cell:505:01:17:91").expect("an SSID");
    assert_eq!(ssid, NetworkSelector::Ssid("cell:505:01:17:91".into()));
    assert_eq!(ssid.canonical(), "ssid:cell:505:01:17:91");
}

/// Without the `OpenCelliD` key a cell lookup makes no request and says so; it does not print
/// `WiGLE` rows, since `WiGLE` is not searched for a cell.
#[test]
fn without_its_key_a_cell_lookup_reports_opencellid_not_configured() {
    let transport = Canned::json(&serde_json::json!({}));
    for keys in [Keys::default(), keys()] {
        let (text, report) = printed(run(&transport, &keys, "cell:505:01:17:91", 7));
        let legs: Vec<_> = report
            .outcomes
            .iter()
            .map(|o| (o.module.as_str(), o.kind))
            .collect();
        assert_eq!(
            legs,
            [(opencellid::SOURCE, SourceOutcomeKind::NotConfigured)]
        );
        assert!(text.contains(opencellid::KEY_SLOT), "{text}");
        assert!(!text.contains("wigle_"), "{text}");
    }
    assert!(transport.urls().is_empty(), "no request was made");
}

/// With the key, `OpenCelliD` is asked for the cell, a 5G cell's 36-bit identity whole, and the
/// position it gives is evidence on the lookup.
#[test]
fn a_cell_site_is_looked_up_in_opencellid() {
    let keys = Keys::parse(&format!(
        "{}=ocid-test-key-0123456789\n",
        opencellid::KEY_SLOT
    ))
    .expect("fixture keys");
    let transport = Canned::json(&serde_json::json!({
        "lat": -27.4698, "lon": 153.0251, "range": 1200, "samples": 40
    }));
    let (text, report) = printed(run(&transport, &keys, "cell:505:01:20:68719476735", 7));
    let urls = transport.urls();
    assert_eq!(urls.len(), 1, "{urls:?}");
    assert!(
        urls[0].starts_with(
            "https://opencellid.org/cell/get?mcc=505&mnc=1&lac=20&cellid=68719476735&format=json"
        ),
        "{}",
        urls[0]
    );
    assert_eq!(report.outcomes.len(), 1, "{:?}", report.outcomes);
    assert_eq!(report.outcomes[0].module, opencellid::SOURCE);
    assert!(
        report.outcomes[0].kind.is_accepted(),
        "{:?}",
        report.outcomes
    );
    assert!(text.contains("-27.4698"), "{text}");
    assert!(!text.contains("wigle_"), "{text}");
}

/// With the `OpenCelliD` key a point is searched for the cell sites listed in the square around
/// it: one bounded `getInArea` request, each site a `cell:` entity the lookup can take back
/// whole (a 36-bit NR identity included), and a note when the area holds more than are listed.
#[test]
fn a_point_lists_the_cell_sites_opencellid_places_around_it() {
    let keys = Keys::parse(&format!(
        "{}=ocid-test-key-0123456789\n",
        opencellid::KEY_SLOT
    ))
    .expect("fixture keys");
    let transport = Canned::json(&serde_json::json!({"count": 120, "cells": [
        {"lat": -27.4701, "lon": 153.0249, "mcc": 505, "mnc": 1, "lac": 20,
         "cellid": 68_719_476_735_u64, "radio": "NR", "range": 900, "samples": 12},
        {"lat": -27.4690, "lon": 153.0260, "mcc": 505, "mnc": 2, "lac": 7, "cellid": 17811,
         "radio": "LTE"}
    ]}));
    let (_, report) = printed(run(&transport, &keys, "-27.4698,153.0251", 7));
    let urls = transport.urls();
    assert_eq!(urls.len(), 1, "only OpenCelliD has a key: {urls:?}");
    assert!(
        urls[0].starts_with(
            "https://opencellid.org/cell/getInArea?BBOX=-27.477885,153.015988,-27.461715,153.034212&limit=50&format=json"
        ),
        "{}",
        urls[0]
    );
    assert!(urls[0].contains("&limit=50&format=json"), "{}", urls[0]);
    let row = report
        .outcomes
        .iter()
        .find(|o| o.module == opencellid::SOURCE)
        .expect("an OpenCelliD row");
    assert_eq!(row.kind, SourceOutcomeKind::Success);
    assert_eq!(row.found, Some(2));

    let nr = report
        .entities
        .iter()
        .find(|e| e.value == "cell:505:01:20:68719476735")
        .expect("the NR site");
    assert!(nr.has_tag(tags::GEOINT));
    assert!(
        nr.evidence[0]
            .attr_values("position")
            .eq(["-27.470100,153.024900"])
    );
    assert!(nr.evidence[0].attr_values("radio").eq(["NR"]));
    assert!(matches!(
        NetworkSelector::parse(&nr.value),
        Some(NetworkSelector::Cell {
            cell: 68_719_476_735,
            ..
        })
    ));
    let point = report
        .entities
        .iter()
        .find(|e| e.kind == EntityKind::Coordinates)
        .expect("the point");
    assert!(
        point
            .evidence
            .iter()
            .any(|ev| ev.attr_values("cells_in_area").eq(["120"])),
        "{:#?}",
        point.evidence
    );
}
