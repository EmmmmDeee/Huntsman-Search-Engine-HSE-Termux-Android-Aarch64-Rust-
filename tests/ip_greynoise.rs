//! A GreyNoise Community lookup must only be sent for routable IPv4, never IPv6.
use std::sync::Mutex;

use huntsman_recon::greynoise;
use huntsman_recon::http::{Request, Response, Transport, TransportFailure};
use huntsman_recon::ip_cli::{IpRun, Report, run};
use huntsman_recon::keys::Keys;
use huntsman_recon::source_outcome::SourceOutcomeKind;
use huntsman_recon::threat_feeds::Feeds;

const GREYNOISE: &str = "https://api.greynoise.io/v3/community/";
const RIPESTAT_UNANNOUNCED: &str = r#"{"status":"ok","data":{"announced":false,"asns":[]}}"#;

#[derive(Default)]
struct Upstreams {
    urls: Mutex<Vec<String>>,
}

impl Upstreams {
    fn asked_greynoise(&self) -> bool {
        self.urls
            .lock()
            .unwrap()
            .iter()
            .any(|url| url.starts_with(GREYNOISE))
    }
}

impl Transport for Upstreams {
    fn runs_module(&self, module: &str) -> bool {
        matches!(module, "greynoise" | "ripestat")
    }

    fn send(&self, request: &Request) -> Result<Response, TransportFailure> {
        self.urls.lock().unwrap().push(request.url.clone());
        let reply = |status: u16, body: String| Response {
            status,
            headers: Vec::new(),
            body: body.into_bytes(),
            truncated: false,
        };
        if let Some(ip) = request.url.strip_prefix(GREYNOISE) {
            return Ok(if ip.parse::<std::net::Ipv4Addr>().is_ok() {
                reply(
                    404,
                    format!(
                        r#"{{"ip":"{ip}","noise":false,"riot":false,"message":"IP not observed scanning the internet."}}"#
                    ),
                )
            } else {
                reply(
                    400,
                    r#"{"message":"Request is not a valid routable IPv4 address"}"#.into(),
                )
            });
        }
        if request.url.starts_with("https://stat.ripe.net/") {
            return Ok(reply(200, RIPESTAT_UNANNOUNCED.to_owned()));
        }
        Err(TransportFailure {
            kind: SourceOutcomeKind::ConnectFailure,
            detail: "no fixture response".into(),
            blocked: false,
        })
    }
}

fn printed(ip: &str) -> (Report, Upstreams) {
    let upstreams = Upstreams::default();
    let answer = run(
        &upstreams,
        &Keys::default(),
        &Feeds::none(),
        ip,
        1_760_000_000,
    );
    let report = match answer {
        IpRun::Printed { report, .. } => report,
        IpRun::Network(why) | IpRun::Failed(why) => panic!("ip {ip} did not print: {why}"),
    };
    (report, upstreams)
}

#[test]
fn accepts_ipv4_but_not_ipv6_or_malformed_targets() {
    assert!(greynoise::answers_for("8.8.8.8"));
    assert!(!greynoise::answers_for("2606:4700:4700::1111"));
    assert!(!greynoise::answers_for("garbage"));
}

#[test]
fn ipv6_lookup_skips_greynoise_without_inventing_a_failure() {
    let (report, upstreams) = printed("2606:4700:4700::1111");
    assert!(!upstreams.asked_greynoise());
    assert!(report.outcomes.iter().all(|row| row.module != "greynoise"));
}

#[test]
fn ipv4_lookup_still_reports_greynoise_valid_zero() {
    let (report, upstreams) = printed("8.8.8.8");
    assert!(upstreams.asked_greynoise());
    let rows: Vec<_> = report
        .outcomes
        .iter()
        .filter(|row| row.module == "greynoise")
        .map(|row| row.kind)
        .collect();
    assert_eq!(rows, vec![SourceOutcomeKind::ValidZero]);
}
