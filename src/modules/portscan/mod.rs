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

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tokio::net::TcpStream;
use tokio::sync::Semaphore;

use crate::core::{confidence, 
    entity::{Entity, EntityKind, Evidence},
    error::Result,
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
        "Active TCP-connect sweep — probes common service ports on an IP to surface open ports and live web URLs"
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

        let open = scan_ports(ip, PORTS, MAX_CONCURRENT).await;
        if open.is_empty() {
            return Ok(result);
        }

        // Re-emit the IP enriched with the open-port summary.
        let summary = open
            .iter()
            .map(|(p, svc)| format!("{p}/{svc}"))
            .collect::<Vec<_>>()
            .join(", ");
        let mut ipe = Entity::new(EntityKind::IpAddress, host, confidence::VERY_HIGH, &ctx.scan_id);
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
            let mut e = Entity::new(EntityKind::Url, &url, confidence::HIGH, &ctx.scan_id);
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

/// Concurrently TCP-connect to each `(port, service)` and return the open ones,
/// sorted by port (deterministic). A connect that succeeds within
/// [`CONNECT_TIMEOUT`] = open; timeout / refused / error = not reported.
async fn scan_ports(
    ip: IpAddr,
    ports: &[(u16, &'static str)],
    concurrency: usize,
) -> Vec<(u16, &'static str)> {
    let sem = Arc::new(Semaphore::new(concurrency.max(1)));
    let mut set = tokio::task::JoinSet::new();
    for &(port, svc) in ports {
        let sem = Arc::clone(&sem);
        set.spawn(async move {
            let _permit = sem.acquire_owned().await.ok()?;
            let addr = SocketAddr::new(ip, port);
            match tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(addr)).await {
                Ok(Ok(_stream)) => Some((port, svc)),
                _ => None,
            }
        });
    }
    let mut open: Vec<(u16, &'static str)> = Vec::new();
    while let Some(joined) = set.join_next().await {
        if let Ok(Some(hit)) = joined {
            open.push(hit);
        }
    }
    open.sort_by_key(|(p, _)| *p);
    open
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
