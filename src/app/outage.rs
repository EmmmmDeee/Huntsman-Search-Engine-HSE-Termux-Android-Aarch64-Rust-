//! I/O collector for `core::outage` (T6 cycle 3, REQ-RESILIENCE-003): the
//! DNS/HTTP/TLS probes whose results `core::outage::classify` turns into a
//! judgement about what kind of trouble stands between the device and the
//! internet.
//!
//! Same split as [`crate::app::signal`] over [`crate::core::link`]: probing
//! is I/O and lives here; judging is pure and lives in `core::`. Every leg
//! is bounded — a wedged or dead path degrades this collector, never
//! freezes the caller, matching the "a slow or dead service degrades the
//! scan, never freezes it" requirement every other network-bound leg of HSE
//! already honours (`util::dns::shared_resolver`'s own 2s/1-attempt bound,
//! `util::curl::fetch_with_status`'s fixed 4s `--max-time`).
//!
//! Deliberately NOT wired into the radar's existing auto-refreshing
//! disruption poll (`refreshDisruptions()` on every sweep/stream/poll tick):
//! these are live network probes, not a database read, and issuing five of
//! them (two DNS lookups, a raw TCP connect, an HTTP fetch, a TLS handshake)
//! on every poll tick would add real latency and outbound traffic to a
//! network HSE may already be struggling on — exactly backwards for a
//! resilience feature. [`collect`] is opt-in everywhere it is exposed (`hse
//! doctor --live`, `hse signal --disruptions --live`, `GET
//! /api/v1/radar/disruptions?live=1`), mirroring the existing `doctor(live:
//! bool)` gate that already exists for this same "extra live network probing
//! beyond the fast/local checks" purpose.

use crate::core::outage::OutagePath;
use crate::util::x509_field::{OID_O, extract_field_from_der};
use serde::Deserialize;
use std::net::IpAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// The single stable domain probed for the system/independent-DNS comparison
/// and the TLS-issuer leg — deliberately the SAME host [`collect`]'s
/// connectivity leg already targets (by way of
/// [`crate::util::egress::PROBE_URL`]), so this collector adds no new
/// outbound footprint beyond what the egress pool already establishes as
/// safe and neutral to reach from every network.
const PROBE_DOMAIN: &str = "www.gstatic.com";

/// A well-known public DNS resolver's own IP literal. Connecting to it
/// requires no DNS lookup at all, so success here means the network has SOME
/// route out, regardless of whether DNS itself works.
const IP_LITERAL_ANCHOR: &str = "1.1.1.1:443";

/// Cloudflare's DNS-over-HTTPS JSON API. Queried directly over HTTPS+JSON —
/// no new dependency, the shared reqwest client already speaks both — as an
/// independent second DNS path to compare the system resolver's answer
/// against.
///
/// Deliberately NOT `util::curl_client`'s existing `doh_fallback_url`: that
/// mechanism only ever activates once the system resolver has already
/// FAILED to resolve (a retry-on-failure fallback for one paid-API request).
/// A DNS hijack is exactly the case where the system resolver SUCCEEDS with
/// a *wrong* answer — a fallback gated on failure would never run and could
/// never catch it. This probe runs unconditionally, every time, specifically
/// to compare two independent answers for the same lookup.
const DOH_JSON_URL: &str = "https://cloudflare-dns.com/dns-query";

/// Per-leg probe bound. Every leg that can itself hang without one (a
/// non-IP-literal DNS lookup, a raw TCP connect) is wrapped in
/// `tokio::time::timeout` at this bound; the HTTP-based legs carry their own
/// client-level or curl-level timeout instead (see each helper).
const PROBE_TIMEOUT: Duration = Duration::from_secs(3);

/// DNS record type A (RFC 1035 §3.2.2) — the only record type
/// [`doh_dns_lookup`] asks the DoH JSON endpoint for, and the only
/// `Answer[].type` its parse keeps.
const DNS_RTYPE_A: u16 = 1;

/// Collect a live [`OutagePath`] snapshot using the real, pinned probe
/// targets — the one entry point `hse doctor --live`, `hse signal
/// --disruptions --live`, and `GET /api/v1/radar/disruptions?live=1` all
/// share. See [`collect_against`] for the injectable core the tests use to
/// point this at loopback stubs instead of the live internet.
pub async fn collect() -> OutagePath {
    collect_against(
        PROBE_DOMAIN,
        IP_LITERAL_ANCHOR,
        crate::util::egress::PROBE_URL,
        DOH_JSON_URL,
    )
    .await
}

/// Same as [`collect`], but every probe target is injectable — matching this
/// codebase's established testable-collector pattern (e.g.
/// `TileSource::from_env`'s own upstream override for REQ-RADAR-003), so
/// tests can point every leg at a loopback stub rather than the live
/// internet.
///
/// `pub(crate)`, not `pub`: `ip_literal_anchor` reaches a raw
/// `TcpStream::connect` and `connectivity_url` reaches
/// `util::curl::fetch_with_status`, and neither carries the SSRF-safe
/// host-checking this crate's shared reqwest client enforces — the exact
/// gap the whole SSRF-hardening wave (REQ-SSRF-001/002) closed everywhere
/// else a caller-supplied target reaches the network. Safe only because
/// every real caller is [`collect`], which pins the four targets itself;
/// widening this to `pub` would hand an external caller a bare
/// loopback/metadata probing primitive.
///
/// All five legs run concurrently (`tokio::join!`): the wall-clock cost of
/// [`collect_against`] is the slowest single leg, not their sum.
pub(crate) async fn collect_against(
    domain: &str,
    ip_literal_anchor: &str,
    connectivity_url: &str,
    doh_json_url: &str,
) -> OutagePath {
    let at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());

    let (
        system_dns,
        doh_dns,
        ip_literal_reachable,
        connectivity_status,
        (tls_cert_captured, tls_issuer_org),
    ) = tokio::join!(
        system_dns_lookup(domain),
        doh_dns_lookup(domain, doh_json_url),
        ip_literal_reachable(ip_literal_anchor),
        connectivity_check(connectivity_url),
        tls_issuer_probe(domain),
    );

    OutagePath {
        at,
        system_dns,
        doh_dns,
        ip_literal_reachable,
        connectivity_status,
        tls_cert_captured,
        tls_issuer_org,
    }
}

/// The system/OS resolver's own answer (`getaddrinfo` under `tokio::net`,
/// which respects Android's Private DNS override and whatever the network's
/// DHCP handed out) — deliberately a DIFFERENT resolution path from
/// [`doh_dns_lookup`]'s fixed HTTPS endpoint, so the two legs can actually
/// disagree when something on the local network is rewriting plain DNS
/// answers. Bounded by [`PROBE_TIMEOUT`] since `lookup_host` carries no
/// timeout of its own; a wedge here degrades to an empty (honest
/// "unavailable") answer rather than hanging the caller.
async fn system_dns_lookup(domain: &str) -> Vec<IpAddr> {
    let host = format!("{domain}:443");
    match tokio::time::timeout(PROBE_TIMEOUT, tokio::net::lookup_host(host)).await {
        Ok(Ok(addrs)) => addrs.map(|a| a.ip()).collect(),
        _ => Vec::new(),
    }
}

/// One DoH-JSON answer record (the common `{"type": <u16>, "data": <string>}`
/// shape Cloudflare's and Google's DoH JSON APIs both answer with).
#[derive(Debug, Deserialize)]
struct DohAnswer {
    /// The DNS record type ([`DNS_RTYPE_A`] is the only one this module reads).
    #[serde(rename = "type")]
    rtype: u16,
    /// The record's value — for an A record, a dotted-quad IPv4 address.
    data: String,
}

/// The DoH JSON endpoint's response shape, trimmed to the one field this
/// module reads. A response with no `Answer` array at all (NXDOMAIN,
/// SERVFAIL) deserialises to an empty `Vec` via `#[serde(default)]`, not an
/// error.
#[derive(Debug, Deserialize)]
struct DohResponse {
    /// The records the resolver returned, if any.
    #[serde(rename = "Answer", default)]
    answer: Vec<DohAnswer>,
}

/// An independent DNS path for the same `domain` [`system_dns_lookup`] asked
/// about, over HTTPS+JSON to a fixed public DoH resolver rather than
/// whatever resolver the local network assigned. Always returns `Some` from
/// this live collector (it always attempts the query); a connection
/// failure, a non-JSON response, or an empty answer set are all folded into
/// `Some(vec![])` — "ran, found nothing usable" — which
/// [`crate::core::outage::classify`]'s `disjoint` check already treats as no
/// signal, never as a false hijack.
async fn doh_dns_lookup(domain: &str, doh_json_url: &str) -> Option<Vec<IpAddr>> {
    let client = crate::util::http::build_client_with_timeout(PROBE_TIMEOUT);
    let ips = match client
        .get(doh_json_url)
        .query(&[("name", domain), ("type", "A")])
        .header("accept", "application/dns-json")
        .send()
        .await
    {
        Ok(resp) => match resp.text().await {
            Ok(body) => parse_doh_a_records(&body),
            Err(_) => Vec::new(),
        },
        Err(_) => Vec::new(),
    };
    Some(ips)
}

/// Turn a DoH JSON response body into the A-record addresses it carries.
/// Pure — no I/O — so the parsing logic is unit-tested directly against a
/// literal response body, the same one [`doh_dns_lookup`] delegates to
/// rather than duplicating: one authority for the parse, exercised by both
/// the live path and the tests. Unparseable JSON, a missing `Answer` array,
/// and a non-A record all read as "no address from this record", never a
/// panic or a fabricated address.
fn parse_doh_a_records(body: &str) -> Vec<IpAddr> {
    serde_json::from_str::<DohResponse>(body)
        .map(|parsed| {
            parsed
                .answer
                .into_iter()
                .filter(|a| a.rtype == DNS_RTYPE_A)
                .filter_map(|a| a.data.parse::<IpAddr>().ok())
                .collect()
        })
        .unwrap_or_default()
}

/// A raw TCP connect to a fixed IP-literal anchor — no DNS lookup involved by
/// construction, so success here means the network has SOME route out
/// regardless of whether DNS works at all.
async fn ip_literal_reachable(anchor: &str) -> bool {
    matches!(
        tokio::time::timeout(PROBE_TIMEOUT, tokio::net::TcpStream::connect(anchor)).await,
        Ok(Ok(_))
    )
}

/// The neutral `generate_204`-shaped connectivity check — the same probe
/// shape Android's and Chrome's own captive-portal detectors issue. `None`
/// means the request never completed at all (curl's own status-0 "no
/// definitive answer"); a captive portal answers with something other than
/// an empty 204, never with silence, so a `None` here is inconclusive, not
/// portal evidence — [`crate::core::outage::classify`] already treats it
/// that way.
async fn connectivity_check(url: &str) -> Option<u16> {
    let probe = crate::util::curl::fetch_with_status(url, 4_000, false).await;
    (probe.status != 0).then_some(probe.status)
}

/// A TLS handshake to `domain`, reusing `modules::cert_intel`'s own capture
/// pattern (`.tls_info(true)` is enabled crate-wide by the shared client
/// builder) rather than a second TLS-parsing path. Returns `(cert_captured,
/// issuer_org)`; a handshake that never completes, or completes with no peer
/// certificate exposed, is `(false, None)` — never evidence of interception
/// by itself, only that this leg did not run far enough to see a
/// certificate at all.
async fn tls_issuer_probe(domain: &str) -> (bool, Option<String>) {
    let client = crate::util::http::build_client_with_timeout(PROBE_TIMEOUT);
    let url = format!("https://{domain}/");
    let Ok(resp) = client.head(&url).send().await else {
        return (false, None);
    };
    let Some(der) = resp
        .extensions()
        .get::<reqwest::tls::TlsInfo>()
        .and_then(|info| info.peer_certificate())
    else {
        return (false, None);
    };
    (true, extract_field_from_der(der, OID_O, true))
}

/// The classification as JSON, `advice` carried beside it — the same
/// discipline as `app::signal::disruption_report_json`, so the shell and the
/// page cannot drift.
#[must_use]
pub fn outage_report_json(report: &crate::core::outage::OutageReport) -> serde_json::Value {
    let mut v = serde_json::to_value(report).unwrap_or(serde_json::Value::Null);
    if let serde_json::Value::Object(m) = &mut v {
        m.insert(
            "advice".to_string(),
            serde_json::Value::String(report.advice().to_string()),
        );
    }
    v
}

#[cfg(test)]
mod tests {
    include!("outage_tests.rs");
}
