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
fn without_credentials_a_bssid_is_still_classified_and_wigle_reports_auth_required() {
    let (text, report) = printed(run(None, "3C:5A:B4:01:02:03", 7));
    let legs: Vec<_> = report
        .outcomes
        .iter()
        .map(|o| (o.module.as_str(), o.kind))
        .collect();
    assert_eq!(
        legs,
        [
            (OUI_SOURCE, SourceOutcomeKind::Success),
            (wigle::SOURCE, SourceOutcomeKind::AuthRequired)
        ]
    );
    assert_eq!(report.wigle, None, "no answer is not a zero");
    assert_eq!(report.entities.len(), 1, "seed and OUI evidence merge");
    let vendor = report.entities[0]
        .evidence
        .iter()
        .find_map(|e| e.attributes.get("vendor"))
        .cloned();
    assert!(vendor.is_some_and(|v| !v.is_empty()), "{text}");
    assert!(text.ends_with("wigle_networks=none\n"), "{text}");
    assert!(text.contains(wigle::USER_SLOT), "{text}");
}

#[test]
fn a_half_configured_account_makes_no_request() {
    let transport = Canned::json(&cafe());
    let only_user = match Keys::parse(&format!("{}={USER}\n", wigle::USER_SLOT)) {
        Ok(keys) => keys,
        Err(error) => panic!("keys parse: {error}"),
    };
    let (_, report) = printed(run(Some((&transport, &only_user)), "Cafe Guest", 7));
    assert!(transport.urls().is_empty());
    assert_eq!(
        report.outcomes.last().map(|o| o.kind),
        Some(SourceOutcomeKind::AuthRequired)
    );
}

#[test]
fn wigle_networks_become_bssid_entities_with_ssid_and_position_pivots() {
    let transport = Canned::json(&cafe());
    let keys = keys();
    let (text, report) = printed(run(Some((&transport, &keys)), "ssid:Cafe Guest", 7));
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
    let (text, report) = printed(run(Some((&transport, &keys)), "-27.4698,153.0251", 7));
    let urls = transport.urls();
    assert!(urls[0].contains("latrange1=-27.471800"), "{urls:?}");
    assert_eq!(
        report.outcomes.last().map(|o| o.kind),
        Some(SourceOutcomeKind::ValidZero)
    );
    assert!(text.ends_with("wigle_networks=0\n"), "{text}");
}

#[test]
fn a_failed_request_is_reported_and_a_network_failure_with_nothing_else_is_refused() {
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
    let (text, report) = printed(run(Some((&limited, &keys)), "Cafe Guest", 7));
    assert_eq!(
        report.outcomes.last().map(|o| o.kind),
        Some(SourceOutcomeKind::RateLimited)
    );
    assert!(text.ends_with("wigle_networks=none\n"), "{text}");

    let offline = Canned {
        answer: Err(TransportFailure {
            kind: SourceOutcomeKind::TtfbTimeout,
            detail: "timed out".into(),
            blocked: false,
        }),
        urls: Mutex::default(),
    };
    assert!(matches!(
        run(Some((&offline, &keys)), "Cafe Guest", 7),
        NetworkRun::Network(_)
    ));
    // A BSSID still has its offline classification, so it prints.
    assert!(matches!(
        run(Some((&offline, &keys)), "3c:5a:b4:01:02:03", 7),
        NetworkRun::Printed { .. }
    ));
}
