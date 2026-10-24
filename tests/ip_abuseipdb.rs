//! An `ip` lookup with an `AbuseIPDB` key asks for every report (`verbose`) and keeps each one,
//! the abuse categories they give, the address's registry facts and the whole answer. These run
//! `ip_cli::run`, the function the `ip` command, `scan` and the web UI call, through a transport
//! that answers `AbuseIPDB`'s documented `check` shape (with the report list only when `verbose`
//! asks for it, as the API does) and refuses every other host. When the report list is past the
//! body limit, the lookup asks again without it, keeps the score and says the reports were unread.
//! An address the check marks a Tor exit carries the one Tor-exit tag every source gives.

use huntsman_recon::entity::{EntityKind, Evidence};
use huntsman_recon::http::{Request, Response, Transport, TransportFailure};
use huntsman_recon::ip_cli::{IpRun, run};
use huntsman_recon::keys::Keys;
use huntsman_recon::source_outcome::SourceOutcomeKind;
use huntsman_recon::tags;
use huntsman_recon::threat_feeds::Feeds;

/// The documented `check` answer for the address, without the report list.
const CHECK: &str = r#"{"data":{"ipAddress":"118.25.6.39","isPublic":true,"ipVersion":4,"isWhitelisted":false,"abuseConfidenceScore":100,"countryCode":"CN","countryName":"China","usageType":"Data Center/Web Hosting/Transit","isp":"Tencent Cloud Computing (Beijing) Co. Ltd","domain":"tencent.com","hostnames":[],"isTor":false,"totalReports":3,"numDistinctUsers":2,"lastReportedAt":"2026-10-14T20:55:14+00:00"}}"#;

/// The report list `verbose` adds.
const REPORTS: &str = r#","reports":[{"reportedAt":"2026-10-14T20:55:14+00:00","comment":"SSH login attempts\non port 22","categories":[18,22],"reporterId":1,"reporterCountryCode":"US","reporterCountryName":"United States"},{"reportedAt":"2026-10-13T08:00:00+00:00","comment":"Port scan","categories":[14],"reporterId":2,"reporterCountryCode":"DE","reporterCountryName":"Germany"},{"reportedAt":"2026-10-12T08:00:00+00:00","comment":"","categories":[18,99],"reporterId":2,"reporterCountryCode":"DE","reporterCountryName":"Germany"}]"#;

struct OnlyAbuseIpdb;

impl Transport for OnlyAbuseIpdb {
    fn send(&self, request: &Request) -> Result<Response, TransportFailure> {
        if request
            .url
            .starts_with("https://api.abuseipdb.com/api/v2/check?ipAddress=118.25.6.39&")
        {
            let body = if request.url.contains("&verbose") {
                CHECK.replacen(
                    r#""lastReportedAt":"2026-10-14T20:55:14+00:00""#,
                    &format!(r#""lastReportedAt":"2026-10-14T20:55:14+00:00"{REPORTS}"#),
                    1,
                )
            } else {
                CHECK.to_owned()
            };
            return Ok(Response {
                status: 200,
                headers: Vec::new(),
                body: body.into_bytes(),
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

fn abuseipdb() -> Evidence {
    let keys = Keys::parse("HUNTSMAN_ABUSEIPDB_KEY=abuseipdb-test-key-0815")
        .unwrap_or_else(|e| panic!("{e}"));
    let entities = match run(
        &OnlyAbuseIpdb,
        &keys,
        &Feeds::none(),
        "118.25.6.39",
        1_760_000_000,
    ) {
        IpRun::Printed { report, .. } => report.entities,
        IpRun::Network(why) | IpRun::Failed(why) => {
            panic!("ip 118.25.6.39 did not print: {why}")
        }
    };
    let address = entities
        .iter()
        .find(|e| e.kind == EntityKind::IpAddress && e.value == "118.25.6.39")
        .unwrap_or_else(|| panic!("no address entity: {entities:#?}"));
    address
        .evidence
        .iter()
        .find(|e| e.provenance.source == "abuseipdb")
        .cloned()
        .unwrap_or_else(|| panic!("no AbuseIPDB evidence: {:?}", address.evidence))
}

#[test]
fn every_report_abuseipdb_holds_reaches_the_address() {
    let abuseipdb = abuseipdb();
    assert_eq!(
        abuseipdb.attr_values("reports").collect::<Vec<_>>(),
        [
            "2026-10-14T20:55:14+00:00 | Brute-Force, SSH | reporter 1 (United States) | SSH login attempts on port 22",
            "2026-10-13T08:00:00+00:00 | Port Scan | reporter 2 (Germany) | Port scan",
            "2026-10-12T08:00:00+00:00 | Brute-Force, category 99 | reporter 2 (Germany)"
        ],
        "{:?}",
        abuseipdb.attributes
    );
    assert_eq!(
        abuseipdb
            .attr_values("report_categories")
            .collect::<Vec<_>>(),
        [
            "Brute-Force (2)",
            "Port Scan (1)",
            "SSH (1)",
            "category 99 (1)"
        ]
    );
    assert_eq!(
        abuseipdb.attributes.get("country_name").map(String::as_str),
        Some("China")
    );
    assert_eq!(
        abuseipdb.attributes.get("public").map(String::as_str),
        Some("true")
    );
    assert!(
        abuseipdb
            .attributes
            .get("raw_answer")
            .is_some_and(|raw| raw.contains(r#""reporterId":2"#)),
        "{:?}",
        abuseipdb.attributes
    );
}

/// Answers the summary, and an answer cut at the body limit when every report is asked for.
struct ReportsPastTheLimit;

impl Transport for ReportsPastTheLimit {
    fn send(&self, request: &Request) -> Result<Response, TransportFailure> {
        if request
            .url
            .starts_with("https://api.abuseipdb.com/api/v2/check?ipAddress=118.25.6.39&")
        {
            let verbose = request.url.contains("&verbose");
            return Ok(Response {
                status: 200,
                headers: Vec::new(),
                body: if verbose {
                    br#"{"data":{"ipAddress":"118.25.6.39","reports":[{"#.to_vec()
                } else {
                    CHECK.as_bytes().to_vec()
                },
                truncated: verbose,
            });
        }
        Err(TransportFailure {
            kind: SourceOutcomeKind::ConnectFailure,
            detail: "no route".into(),
            blocked: false,
        })
    }
}

#[test]
fn a_report_list_past_the_body_limit_still_keeps_the_score() {
    let keys = Keys::parse("HUNTSMAN_ABUSEIPDB_KEY=abuseipdb-test-key-0815")
        .unwrap_or_else(|e| panic!("{e}"));
    let report = match run(
        &ReportsPastTheLimit,
        &keys,
        &Feeds::none(),
        "118.25.6.39",
        1_760_000_000,
    ) {
        IpRun::Printed { report, .. } => report,
        IpRun::Network(why) | IpRun::Failed(why) => panic!("ip did not print: {why}"),
    };
    let abuseipdb = report
        .entities
        .iter()
        .filter(|e| e.kind == EntityKind::IpAddress && e.value == "118.25.6.39")
        .flat_map(|e| &e.evidence)
        .find(|e| e.provenance.source == "abuseipdb")
        .unwrap_or_else(|| panic!("no AbuseIPDB evidence: {:#?}", report.entities));
    assert_eq!(
        abuseipdb
            .attributes
            .get("abuse_confidence")
            .map(String::as_str),
        Some("100")
    );
    assert!(
        abuseipdb.attributes.contains_key("reports_unread"),
        "{:?}",
        abuseipdb.attributes
    );
    let kinds: Vec<SourceOutcomeKind> = report
        .outcomes
        .iter()
        .filter(|o| o.module == "abuseipdb")
        .map(|o| o.kind)
        .collect();
    assert_eq!(kinds, [SourceOutcomeKind::Success], "{:?}", report.outcomes);
}

/// Answers the documented `check` with `isTor` set, as `AbuseIPDB` marks a Tor exit relay.
struct TorExit;

impl Transport for TorExit {
    fn send(&self, request: &Request) -> Result<Response, TransportFailure> {
        if request
            .url
            .starts_with("https://api.abuseipdb.com/api/v2/check?ipAddress=118.25.6.39&")
        {
            return Ok(Response {
                status: 200,
                headers: Vec::new(),
                body: CHECK
                    .replacen(r#""isTor":false"#, r#""isTor":true"#, 1)
                    .into_bytes(),
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

#[test]
fn a_tor_exit_carries_the_tag_every_tor_source_gives() {
    let keys = Keys::parse("HUNTSMAN_ABUSEIPDB_KEY=abuseipdb-test-key-0815")
        .unwrap_or_else(|e| panic!("{e}"));
    let report = match run(
        &TorExit,
        &keys,
        &Feeds::none(),
        "118.25.6.39",
        1_760_000_000,
    ) {
        IpRun::Printed { report, .. } => report,
        IpRun::Network(why) | IpRun::Failed(why) => panic!("ip did not print: {why}"),
    };
    let address = report
        .entities
        .iter()
        .find(|e| e.kind == EntityKind::IpAddress && e.value == "118.25.6.39")
        .unwrap_or_else(|| panic!("no address entity: {:#?}", report.entities));
    assert!(address.has_tag(tags::TOR_EXIT), "{:?}", address.tags);
}
