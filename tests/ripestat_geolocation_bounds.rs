//! Geolocation numbers are observations, not merely JSON floats. Invalid places must not
//! become positive evidence through either real front end; valid places retain their order.

use huntsman_recon::api_leg::LegError;
use huntsman_recon::http::{Request, Response, Transport, TransportFailure};
use huntsman_recon::keys::Keys;
use huntsman_recon::lookup_report::LookupReport;
use huntsman_recon::ripestat::decode_geolocation;
use huntsman_recon::source_outcome::SourceOutcomeKind;
use huntsman_recon::threat_feeds::Feeds;
use huntsman_recon::{ip_cli, netblock_cli};
use serde_json::{Value, json};

fn body(locations: &Value) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "status": "ok",
        "data": {"located_resources": [{"locations": locations}]}
    }))
    .expect("fixture is JSON")
}

#[test]
fn geolocation_out_of_range_coordinates_are_decode_failures() {
    for [latitude, longitude] in [
        [91.0, 0.0],
        [-91.0, 0.0],
        [0.0, 181.0],
        [0.0, -181.0],
        [1e300, 0.0],
        [0.0, -1e300],
    ] {
        let bytes = body(&json!([{
            "country": "AU", "latitude": latitude, "longitude": longitude
        }]));
        assert!(
            matches!(decode_geolocation(&bytes), Err(LegError::Decode(_))),
            "out-of-range coordinates were accepted"
        );
    }
}

#[test]
fn geolocation_out_of_range_coverage_is_not_place_evidence() {
    for share in [-1.0, 101.0, -1e300, 1e300] {
        let bytes = body(&json!([{"country": "AU", "covered_percentage": share}]));
        assert!(
            matches!(decode_geolocation(&bytes), Err(LegError::Decode(_))),
            "out-of-range percentage was accepted"
        );
    }
}

#[test]
fn valid_geolocation_boundaries_names_and_order_are_preserved() {
    let bytes = body(&json!([
        {"latitude": 90.0, "longitude": 180.0, "covered_percentage": 100.0},
        {"latitude": -90.0, "longitude": -180.0, "covered_percentage": 0.0},
        {"latitude": 0.0, "longitude": 0.0, "covered_percentage": 100.0},
        {"country": "AU"}
    ]));
    let geo = decode_geolocation(&bytes).expect("valid boundary places are kept");
    assert_eq!(geo.locations.len(), 4);
    assert_eq!(
        geo.summary(),
        "at 90,180 covering 100%; at -90,-180 covering 0%; at 0,0 covering 100%; AU"
    );
    // Coverage is checked per reported place, never normalised across places.
    assert_eq!(geo.locations[2].covered_percentage, Some(100.0));
    assert_eq!(geo.locations[3].covered_percentage, None);
}

struct GeolocationReply(Vec<u8>);

impl Transport for GeolocationReply {
    fn runs_module(&self, module: &str) -> bool {
        module == "ripestat"
    }

    fn send(&self, request: &Request) -> Result<Response, TransportFailure> {
        let bytes = if request
            .url
            .starts_with("https://stat.ripe.net/data/geoloc/data.json?")
        {
            self.0.clone()
        } else if request
            .url
            .starts_with("https://stat.ripe.net/data/prefix-overview/data.json?")
        {
            br#"{"status":"ok","data":{"announced":false,"asns":[],"resource":"1.1.1.0/24"}}"#
                .to_vec()
        } else {
            return Err(TransportFailure {
                kind: SourceOutcomeKind::ConnectFailure,
                detail: "offline fixture has no other route".into(),
                blocked: false,
            });
        };
        Ok(Response {
            status: 200,
            headers: Vec::new(),
            body: bytes,
            truncated: false,
        })
    }
}

fn reports(transport: &GeolocationReply) -> [LookupReport; 2] {
    let ip_cli::IpRun::Printed { report: ip, .. } = ip_cli::run(
        transport,
        &Keys::default(),
        &Feeds::none(),
        "1.1.1.1",
        1_760_000_000,
    ) else {
        panic!("the valid routing leg must still print the IP report");
    };
    let netblock_cli::NetblockRun::Printed { report: block, .. } =
        netblock_cli::run(transport, &Feeds::none(), "1.1.1.0/24", 1_760_000_000)
    else {
        panic!("the valid routing leg must still print the block report");
    };
    [ip, block]
}

#[test]
fn invalid_geolocation_cannot_reach_ip_or_netblock_evidence() {
    for place in [
        json!({"country": "AU", "latitude": 91.0, "longitude": 151.0}),
        json!({"country": "AU", "covered_percentage": 101.0}),
    ] {
        for report in reports(&GeolocationReply(body(&json!([place])))) {
            assert!(
                report
                    .entities
                    .iter()
                    .flat_map(|entity| &entity.evidence)
                    .all(|evidence| { !evidence.attributes.contains_key("locations") }),
                "invalid geolocation became positive evidence"
            );
            assert!(
                report.outcomes.iter().any(|outcome| {
                    outcome.module == "ripestat" && outcome.kind == SourceOutcomeKind::SchemaDrift
                }),
                "invalid geolocation was not an explicit failed leg"
            );
        }
    }
}

#[test]
fn valid_geolocation_still_reaches_both_front_ends_unchanged() {
    let bytes = body(&json!([{
        "country": "AU", "city": "Sydney", "latitude": -33.5,
        "longitude": 151.0, "covered_percentage": 90.0
    }]));
    for report in reports(&GeolocationReply(bytes)) {
        let places: Vec<_> = report
            .entities
            .iter()
            .flat_map(|entity| &entity.evidence)
            .filter_map(|evidence| evidence.attributes.get("locations").map(String::as_str))
            .collect();
        assert_eq!(places, ["AU Sydney at -33.5,151 covering 90%"]);
        assert!(!report.outcomes.iter().any(|outcome| {
            outcome.module == "ripestat" && outcome.kind == SourceOutcomeKind::SchemaDrift
        }));
    }
}
