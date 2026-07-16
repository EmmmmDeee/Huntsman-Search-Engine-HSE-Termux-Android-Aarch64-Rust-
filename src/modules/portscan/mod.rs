//! Active TCP-connect port scan.
//!
//! For an `IpAddress` target, attempts a bounded, polite TCP connect to a curated
//! list of common service ports and reports which are open — the missing active
//! counterpart to the passive infrastructure intel (Shodan/Censys). It pairs with
//! `netblock`: a CIDR seed expands to host IPs, each of which this module sweeps.
//!
//! On an open web port it emits a `Url` entity (`http(s)://ip:port`) so
//! `web_crawler` / `webserver_banner` enrich the live service automatically; the
//! IP itself is re-emitted carrying an `open_ports` evidence attribute.
//!
//! **Non-passive** (it touches the target) — skipped under `--passive-only`.
//! Pure tokio, no API, no native deps, no root (a TCP *connect* scan needs no raw
//! sockets). Bounded by a short per-port timeout × capped concurrency, and it
//! refuses non-routable / reserved IPs so it can't be turned on internal space.

use std::io::ErrorKind;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tokio::net::TcpStream;
use tokio::sync::Semaphore;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::{Error, Result},
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};

const SRC: &str = "portscan";

/// Per-port connect budget. Short — a closed/filtered port should fail fast on a
/// mobile link rather than hold the scan; an open port answers in well under this.
const CONNECT_TIMEOUT: Duration = Duration::from_millis(1500);

/// Concurrent connects (matches the DNS-brute budget — polite on a phone link).
const MAX_CONCURRENT: usize = 16;

/// Curated common service ports with a human label. Kept deliberately small
/// (~tcp top-services) so a sweep is quick and unobtrusive, not a full 65k scan.
const PORTS: &[(u16, &str)] = &[
    (21, "ftp"),
    (22, "ssh"),
    (23, "telnet"),
    (25, "smtp"),
    (53, "dns"),
    (80, "http"),
    (110, "pop3"),
    (143, "imap"),
    (443, "https"),
    (445, "smb"),
    (587, "smtp-submission"),
    (993, "imaps"),
    (995, "pop3s"),
    (1433, "mssql"),
    (3306, "mysql"),
    (3389, "rdp"),
    (5432, "postgres"),
    (6379, "redis"),
    (8000, "http-alt"),
    (8080, "http-proxy"),
    (8443, "https-alt"),
    (9200, "elasticsearch"),
    (27017, "mongodb"),
];

pub struct PortScan;

#[async_trait]
impl Module for PortScan {
    fn name(&self) -> &'static str {
        SRC
    }

    fn description(&self) -> &'static str {
        "Active TCP-connect scan of common service ports on an IP (open ports + web URLs)"
    }

    fn priority(&self) -> u8 {
        // Below passive IP intel; it's an active probe run after the cheap
        // lookups have classified the address.
        22
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Infrastructure
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        // Active, target-touching scanning — ATT&CK T1595 Active Scanning, NOT
        // the passive "search open technical databases" the Infrastructure
        // category defaults to. This is the case the per-module override exists
        // for: the functional category is too coarse for the actual technique.
        &["T1595", "T1595.001"]
    }

    fn is_passive(&self) -> bool {
        // Touches the target — excluded from `--passive-only` scans.
        false
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::IpAddress)
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[EntityKind::IpAddress, EntityKind::Url];
        KINDS
    }

    fn max_timeout_ms(&self) -> u64 {
        // ceil(PORTS/concurrency) × CONNECT_TIMEOUT, plus headroom.
        12_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let mut result = ModuleResult::new();
        let host = target.value.trim();

        // Only scan a genuine, globally-routable IP literal. Refuse reserved /
        // private / documentation space so the module can't be pointed at
        // internal infrastructure, and skip hostnames (this consumes IpAddress).
        let Ok(ip) = host.parse::<IpAddr>() else {
            return Ok(result);
        };
        if crate::core::validation::is_non_routable_ip(host) {
            return Ok(result);
        }

        let (open, transport_failures) = scan_ports(ip, PORTS, MAX_CONCURRENT).await;
        if all_ports_failed_transport(transport_failures, PORTS.len(), open.len()) {
            return Err(Error::module(
                SRC,
                "every port connect attempt failed at the transport level (no route to target?) — cannot determine whether the target has open ports",
            ));
        }
        if open.is_empty() {
            return Ok(result);
        }

        // Re-emit the IP enriched with the open-port summary.
        let summary = open
            .iter()
            .map(|(p, svc)| format!("{p}/{svc}"))
            .collect::<Vec<_>>()
            .join(", ");
        let mut ipe = Entity::new(EntityKind::IpAddress, host, 0.75, &ctx.scan_id);
        ipe.tag("portscan");
        ipe.tag("active-probe");
        ipe.add_evidence(
            Evidence::new(SRC, format!("{} open TCP port(s): {summary}", open.len()))
                .with_attr("open_ports", &summary),
        );
        result.push(ipe);

        // Web ports → Url entities so the crawler / banner modules enrich them.
        result.extend(open.iter().filter_map(|(port, svc)| {
            let scheme = match *port {
                443 | 8443 => "https",
                80 | 8000 | 8080 => "http",
                _ => return None,
            };
            let url = format!("{scheme}://{}:{port}/", bracketed(ip));
            let mut e = Entity::new(EntityKind::Url, &url, 0.65, &ctx.scan_id);
            e.tag("portscan");
            e.tag("live-service");
            e.add_evidence(
                Evidence::new(SRC, format!("Open {svc} service on {host}:{port}"))
                    .with_attr("ip", host)
                    .with_attr("port", port.to_string()),
            );
            Some(e)
        }));
        Ok(result)
    }
}

/// Bracket an IPv6 literal for use in a URL authority (`[::1]`); pass IPv4 through.
fn bracketed(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => format!("[{v6}]"),
    }
}

/// The classified outcome of one port's connect attempt.
enum PortOutcome {
    Open(u16, &'static str),
    /// A genuine target-side negative: refused (RST) or silently dropped
    /// within [`CONNECT_TIMEOUT`] — the scan reached the target.
    Closed,
    /// The connect never reached the network at all — no route to the
    /// destination's address family (`NetworkUnreachable`/`HostUnreachable`),
    /// plausible on this project's mobile/Termux deployment target. This is
    /// categorically different from a target-side refusal or timeout.
    TransportFailure,
}

/// Concurrently TCP-connect to each `(port, service)` and return the open
/// ones (sorted by port, deterministic) alongside a count of connects that
/// failed at the transport level rather than receiving a genuine
/// closed/filtered response from the target.
async fn scan_ports(
    ip: IpAddr,
    ports: &[(u16, &'static str)],
    concurrency: usize,
) -> (Vec<(u16, &'static str)>, usize) {
    let sem = Arc::new(Semaphore::new(concurrency.max(1)));
    let mut set = tokio::task::JoinSet::new();
    for &(port, svc) in ports {
        let sem = Arc::clone(&sem);
        set.spawn(async move {
            let Ok(_permit) = sem.acquire_owned().await else {
                return PortOutcome::Closed;
            };
            let addr = SocketAddr::new(ip, port);
            match tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(addr)).await {
                Ok(Ok(_stream)) => PortOutcome::Open(port, svc),
                Ok(Err(e))
                    if matches!(
                        e.kind(),
                        ErrorKind::NetworkUnreachable | ErrorKind::HostUnreachable
                    ) =>
                {
                    PortOutcome::TransportFailure
                }
                _ => PortOutcome::Closed,
            }
        });
    }
    let mut open: Vec<(u16, &'static str)> = Vec::new();
    let mut transport_failures = 0usize;
    while let Some(joined) = set.join_next().await {
        match joined {
            Ok(PortOutcome::Open(port, svc)) => open.push((port, svc)),
            // A JoinError (task panic/cancel) means the outcome is unknown,
            // not a genuine closed/filtered response — count it the same as
            // a transport failure rather than silently treating it as clean.
            Ok(PortOutcome::TransportFailure) | Err(_) => transport_failures += 1,
            Ok(PortOutcome::Closed) => {}
        }
    }
    open.sort_by_key(|(p, _)| *p);
    (open, transport_failures)
}

/// True only when every port connect attempt failed at the transport level
/// (never reached the target) and nothing was found — a genuine total
/// outage, distinguished from ports that were merely closed/filtered.
fn all_ports_failed_transport(transport_failures: usize, total_ports: usize, found: usize) -> bool {
    found == 0 && total_ports > 0 && transport_failures == total_ports
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
