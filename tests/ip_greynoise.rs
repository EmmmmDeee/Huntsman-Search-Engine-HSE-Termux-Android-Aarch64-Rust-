//! `ip` asks `GreyNoise` only about an address its Community API answers for. The API answers an
//! IPv6 address with `400` "Request is not a valid routable IPv4 address" (checked 2026-10-15), so
//! asking for one would add a failed row to every IPv6 lookup. These run `ip_cli::run`, the
//! function the `ip` command, `scan` and the web UI call, through a transport that answers as
//! `GreyNoise` and `RIPEstat` do and refuses every other host.

use std::sync::Mutex;

use huntsman_recon::http::{Request, Response, Transport, TransportFailure};
use huntsman_recon::ip_cli::{IpRun, Report, run};
use huntsman_recon::keys::Keys;
use huntsman_recon::source_outcome::SourceOutcomeKind;

const GREYNOISE: &str = "https://api.greynoise.io/v3/community/";
/// Recorded without a key for `2606:4700:4700::1111` on 2026-10-15 (HTTP 400).
const GREYNOISE_NOT_IPV4: &str =
    "{\n    \"error\": \"Request is not a valid routable IPv4 address\"\n}";
/// The `RIPEstat` answer for an address no route covers: a valid zero, so the lookup prints.
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
    fn send(&self, request: &Request) -> Result<Response, TransportFailure> {
        self.urls.lock().unwrap().push(request.url.clone());
        let answer = |status: u16, body: String| Response {
            status,
            headers: Vec::new(),
            body: body.into_bytes(),
            truncated: false,
        };
        if let Some(ip) = request.url.strip_prefix(GREYNOISE) {
            return Ok(if ip.parse::<std::net::Ipv4Addr>().is_ok() {
                answer(
                    404,
                    format!(
                        r#"{{"ip":"{ip}","noise":false,"riot":false,"message":"IP not observed scanning the internet."}}"#
                    ),
                )
            } else {
                answer(400, GREYNOISE_NOT_IPV4.to_owned())
            });
        }
        if request.url.starts_with("https://stat.ripe.net/") {
            return Ok(answer(200, RIPESTAT_UNANNOUNCED.to_owned()));
        }
        Err(TransportFailure {
            kind: SourceOutcomeKind::ConnectFailure,
            detail: "no route".into(),
            blocked: false,
        })
    }
}

fn printed(ip: &str) -> (Report, Upstreams) {
    let upstreams = Upstreams::default();
    match run(&upstreams, &Keys::default(), ip, 1_760_000_000) {
        IpRun::Printed { report, .. } => (report, upstreams),
        IpRun::Network(why) | IpRun::Failed(why) => panic!("ip {ip} did not print: {why}"),
    }
}

fn greynoise_rows(report: &Report) -> Vec<SourceOutcomeKind> {
    report
        .outcomes
        .iter()
        .filter(|o| o.module == "greynoise")
        .map(|o| o.kind)
        .collect()
}

#[test]
fn an_ipv6_lookup_does_not_ask_greynoise() {
    let (report, upstreams) = printed("2606:4700:4700::1111");
    assert!(
        !upstreams.asked_greynoise(),
        "GreyNoise was asked about an IPv6 address"
    );
    assert_eq!(greynoise_rows(&report), Vec::new());
}

#[test]
fn an_ipv4_lookup_still_asks_greynoise() {
    let (report, upstreams) = printed("8.8.8.8");
    assert!(upstreams.asked_greynoise());
    assert_eq!(greynoise_rows(&report), vec![SourceOutcomeKind::ValidZero]);
}
