//! An `ip` lookup with an `IPQualityScore` key keeps everything IPQS says about where the address
//! is: the position as a coordinates entity, and the region, postcode and time zone on the
//! address's own evidence. These run `ip_cli::run`, the function the `ip` command, `scan` and the
//! web UI call, through a transport that answers as IPQS documents and refuses every other host.

use huntsman_recon::entity::{Entity, EntityKind};
use huntsman_recon::http::{Request, Response, Transport, TransportFailure};
use huntsman_recon::ip_cli::{IpRun, run};
use huntsman_recon::keys::Keys;
use huntsman_recon::ledger;
use huntsman_recon::lookup_save::{self, IP_POLICY};
use huntsman_recon::sf_elements::{self, Target};
use huntsman_recon::source_outcome::SourceOutcomeKind;
use huntsman_recon::tags;
use huntsman_recon::threat_feeds::Feeds;

/// The documented IP reputation response fields, filled for a Dutch address.
const IPQS: &str = r#"{"success":true,"message":"Success","fraud_score":12,"country_code":"NL","region":"North Holland","city":"Amsterdam","ISP":"Example Hosting","ASN":64500,"organization":"Example Hosting B.V.","is_crawler":false,"timezone":"Europe/Amsterdam","mobile":false,"host":"exit-12.example.net","proxy":false,"vpn":false,"tor":false,"active_vpn":false,"active_tor":false,"recent_abuse":false,"bot_status":false,"connection_type":"Data Center","abuse_velocity":"none","zip_code":"1012","latitude":52.37,"longitude":4.89,"request_id":"r0"}"#;

struct OnlyIpqs(&'static str);

impl Transport for OnlyIpqs {
    fn send(&self, request: &Request) -> Result<Response, TransportFailure> {
        if request
            .url
            .starts_with("https://www.ipqualityscore.com/api/json/ip?ip=1.2.3.4")
        {
            return Ok(Response {
                status: 200,
                headers: Vec::new(),
                body: self.0.as_bytes().to_vec(),
                truncated: false,
            });
        }
        Err(TransportFailure {
            kind: SourceOutcomeKind::ConnectFailure,
            detail: "no route".into(),
            blocked: false,
        })
    }
}

fn ipqs_lookup(body: &'static str) -> huntsman_recon::ip_cli::Report {
    let keys =
        Keys::parse("HUNTSMAN_IPQS_KEY=ipqs-test-key-0815").unwrap_or_else(|e| panic!("{e}"));
    match run(
        &OnlyIpqs(body),
        &keys,
        &Feeds::none(),
        "1.2.3.4",
        1_760_000_000,
    ) {
        IpRun::Printed { text, report } => {
            assert!(text.contains("IPQualityScore IP:"));
            report
        }
        IpRun::Network(why) | IpRun::Failed(why) => panic!("ip 1.2.3.4 did not print: {why}"),
    }
}

fn entities() -> Vec<Entity> {
    ipqs_lookup(IPQS).entities
}

fn address(report: &huntsman_recon::ip_cli::Report) -> &Entity {
    report
        .entities
        .iter()
        .find(|entity| entity.kind == EntityKind::IpAddress && entity.value == "1.2.3.4")
        .expect("IPQS address evidence")
}

#[test]
fn suspected_tor_and_a_proxy_score_cannot_invent_an_active_exit_or_malicious_ip() {
    let report = ipqs_lookup(
        r#"{"success":true,"fraud_score":85,"proxy":true,"vpn":true,"tor":true,"active_tor":false,"recent_abuse":false}"#,
    );
    let ip = address(&report);
    assert!(ip.has_tag("proxy"));
    assert!(ip.has_tag("tor-suspected"));
    assert!(!ip.has_tag(tags::TOR_EXIT));
    assert!(!ip.has_tag(tags::MALICIOUS));
    let evidence = ip
        .evidence
        .iter()
        .find(|row| row.provenance.source == "ipqs")
        .unwrap();
    assert_eq!(evidence.attributes["fraud_score"], "85");
    assert_eq!(evidence.attributes["active_tor"], "false");
    let elements = sf_elements::elements(
        Target {
            value: "1.2.3.4",
            kind: "IP_ADDRESS",
        },
        &report.entities,
        1_760_000_000,
    );
    assert!(
        elements
            .iter()
            .all(|row| !matches!(row.kind.as_str(), "TOR_EXIT_NODE" | "MALICIOUS_IPADDR"))
    );
}

#[test]
fn an_explicit_active_tor_exit_and_reported_abuse_reach_the_scan_view() {
    let report = ipqs_lookup(
        r#"{"success":true,"fraud_score":92,"tor":true,"active_tor":true,"recent_abuse":true}"#,
    );
    let ip = address(&report);
    assert!(ip.has_tag(tags::TOR_EXIT));
    assert!(ip.has_tag("ipqs-high-risk"));
    assert!(ip.has_tag(tags::MALICIOUS));
    let elements = sf_elements::elements(
        Target {
            value: "1.2.3.4",
            kind: "IP_ADDRESS",
        },
        &report.entities,
        1_760_000_000,
    );
    assert!(
        elements
            .iter()
            .any(|row| row.kind == "TOR_EXIT_NODE" && row.module == "ipqs")
    );
    assert!(
        elements
            .iter()
            .any(|row| row.kind == "MALICIOUS_IPADDR" && row.module == "ipqs")
    );
}

#[test]
fn enterprise_booleans_keep_false_and_absent_distinct_in_the_saved_ledger() {
    let report = ipqs_lookup(
        r#"{"success":true,"fraud_score":12,"frequent_abuser":false,"high_risk_attacks":true,"shared_connection":true,"dynamic_connection":false,"security_scanner":true,"trusted_network":false}"#,
    );
    let dir = std::env::temp_dir().join(format!("hse-ipqs-evidence-{}", std::process::id()));
    std::fs::create_dir(&dir).unwrap();
    let path = dir.join("ip.json");
    lookup_save::save(&path, &report.entities, &report.outcomes, IP_POLICY).unwrap();
    let saved = ledger::load_chain(&path).unwrap();
    std::fs::remove_dir_all(dir).unwrap();
    assert!(ledger::chain_intact(&saved));
    let expected = [
        ("frequent_abuser", "false"),
        ("high_risk_attacks", "true"),
        ("shared_connection", "true"),
        ("dynamic_connection", "false"),
        ("security_scanner", "true"),
        ("trusted_network", "false"),
    ];
    let evidence = saved
        .iter()
        .filter(|row| row.claim.source == "ipqs")
        .filter_map(|row| serde_json::from_str::<serde_json::Value>(&row.claim.claim).ok())
        .find(|row| row["evidence"]["provenance"]["source"] == "ipqs")
        .unwrap();
    let absent = ipqs_lookup(r#"{"success":true,"fraud_score":12}"#);
    let absence = address(&absent)
        .evidence
        .iter()
        .find(|row| row.provenance.source == "ipqs")
        .unwrap();
    for (key, value) in expected {
        assert_eq!(evidence["evidence"]["attributes"][key], value);
        assert!(!absence.attributes.contains_key(key));
    }
    assert!(!address(&report).has_tag(tags::MALICIOUS));
    assert!(address(&report).has_tag("ipqs-abuse-reported"));
}

#[test]
fn a_high_score_without_an_abuse_report_remains_a_risk_signal() {
    let report = ipqs_lookup(r#"{"success":true,"fraud_score":95,"proxy":true}"#);
    let ip = address(&report);
    assert!(ip.has_tag("ipqs-high-risk"));
    assert!(!ip.has_tag("ipqs-abuse-reported"));
    assert!(!ip.has_tag(tags::MALICIOUS));
    let evidence = ip
        .evidence
        .iter()
        .find(|row| row.provenance.source == "ipqs")
        .unwrap();
    assert!(!evidence.attributes.contains_key("active_tor"));
}

#[test]
fn ip_fraud_scores_keep_fractional_precision_and_the_documented_boundary() {
    use huntsman_recon::{indicator_sources::Indicator, ipqs};

    let ip = Indicator::Ip("1.2.3.4");
    let low = ipqs::decode(
        br#"{"success":true,"fraud_score":89.9,"recent_abuse":true}"#,
        ip,
    )
    .unwrap();
    assert!(low.attrs.contains(&("fraud_score", "89.9".into())));
    assert!(!low.tags.contains(&tags::MALICIOUS));
    let threshold = ipqs::decode(
        br#"{"success":true,"fraud_score":90.0,"recent_abuse":true}"#,
        ip,
    )
    .unwrap();
    assert!(threshold.tags.contains(&tags::MALICIOUS));
    for invalid in [r#""92.5""#, "-0.1", "100.1"] {
        let body = format!(r#"{{"success":true,"fraud_score":{invalid}}}"#);
        assert!(ipqs::decode(body.as_bytes(), ip).is_err());
    }
}

#[test]
fn the_position_ipqs_gives_is_a_coordinates_entity_of_the_lookup() {
    let entities = entities();
    let place = entities
        .iter()
        .find(|e| e.kind == EntityKind::Coordinates)
        .unwrap_or_else(|| panic!("no coordinates entity: {entities:#?}"));
    assert_eq!(place.value, "52.370000,4.890000");
    assert!(place.has_tag("geoint"), "{:?}", place.tags);
    assert!(
        place
            .evidence
            .iter()
            .any(|e| e.provenance.source == "ipqs"
                && e.attr_values("ip").any(|ip| ip == "1.2.3.4")),
        "{:?}",
        place.evidence
    );
}

#[test]
fn the_region_postcode_and_time_zone_stay_on_the_address() {
    let entities = entities();
    let address = entities
        .iter()
        .find(|e| e.kind == EntityKind::IpAddress && e.value == "1.2.3.4")
        .unwrap_or_else(|| panic!("no address entity: {entities:#?}"));
    let ipqs = address
        .evidence
        .iter()
        .find(|e| e.provenance.source == "ipqs")
        .unwrap_or_else(|| panic!("no IPQS evidence: {:?}", address.evidence));
    let attr = |key: &str| ipqs.attr_values(key).collect::<Vec<_>>();
    assert_eq!(attr("region"), ["North Holland"]);
    assert_eq!(attr("postal_code"), ["1012"]);
    assert_eq!(attr("timezone"), ["Europe/Amsterdam"]);
    assert_eq!(attr("coordinates"), ["52.370000,4.890000"]);
}
