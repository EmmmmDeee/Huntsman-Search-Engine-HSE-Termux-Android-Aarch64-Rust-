// Tests for `app::outage`. Plain `//`: `include!`d into `mod tests`.

use super::*;
use crate::core::outage::{OutageKind, OutageReport};
use crate::util::http::test_server::{Canned, serve};
use std::time::Instant;

/// Bind a loopback listener and immediately drop it, returning an address
/// nothing is listening on — connecting to it fails fast (ECONNREFUSED)
/// rather than hanging, unlike an unroutable address that would eat a whole
/// timeout. The reliable way to get "definitely refused" without depending
/// on any specific port being free in the test sandbox.
async fn refused_addr() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind loopback");
    let addr = listener.local_addr().expect("local addr").to_string();
    drop(listener);
    addr
}

#[tokio::test]
async fn ip_literal_reachable_is_true_against_a_real_listener() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind loopback");
    let addr = listener.local_addr().expect("local addr").to_string();
    // Accept and immediately drop each connection — only the TCP handshake
    // is under test, nothing is read or written.
    tokio::spawn(async move {
        loop {
            let Ok((sock, _)) = listener.accept().await else {
                return;
            };
            drop(sock);
        }
    });
    assert!(ip_literal_reachable(&addr).await);
}

#[tokio::test]
async fn ip_literal_reachable_is_false_against_a_refused_port() {
    let addr = refused_addr().await;
    assert!(!ip_literal_reachable(&addr).await);
}

#[tokio::test]
async fn system_dns_lookup_resolves_an_ip_literal_with_no_real_dns_needed() {
    // "127.0.0.1" needs no resolver at all — `lookup_host` recognises an
    // IP-literal host directly, so this is fully hermetic.
    let ips = system_dns_lookup("127.0.0.1").await;
    assert_eq!(ips, vec!["127.0.0.1".parse::<IpAddr>().unwrap()]);
}

#[tokio::test]
async fn connectivity_check_reports_a_204_as_some_204() {
    let base = serve(vec![Canned::text(204, "")]).await;
    let status = connectivity_check(&format!("{base}/generate_204")).await;
    assert_eq!(status, Some(204));
}

#[tokio::test]
async fn connectivity_check_reports_a_200_body_as_some_200_the_captive_portal_shape() {
    let base = serve(vec![Canned::html(200, "<html>Sign in to Wi-Fi</html>")]).await;
    let status = connectivity_check(&format!("{base}/generate_204")).await;
    assert_eq!(status, Some(200));
}

#[tokio::test]
async fn connectivity_check_reports_a_refused_port_as_none_not_a_fabricated_status() {
    let addr = refused_addr().await;
    let status = connectivity_check(&format!("http://{addr}/generate_204")).await;
    assert_eq!(status, None);
}

#[test]
fn parse_doh_a_records_reads_the_answer_array() {
    let body = r#"{"Status":0,"Answer":[{"name":"example.com.","type":1,"TTL":300,"data":"93.184.216.34"}]}"#;
    let ips = parse_doh_a_records(body);
    assert_eq!(ips, vec!["93.184.216.34".parse::<IpAddr>().unwrap()]);
}

#[test]
fn parse_doh_a_records_ignores_non_a_records() {
    // type 28 is AAAA, type 5 is CNAME — neither is what DNS_RTYPE_A asked
    // for; only the A record should survive the filter.
    let body = r#"{"Answer":[
        {"name":"example.com.","type":5,"data":"cname.example.com."},
        {"name":"example.com.","type":28,"data":"::1"},
        {"name":"example.com.","type":1,"data":"93.184.216.34"}
    ]}"#;
    let ips = parse_doh_a_records(body);
    assert_eq!(ips, vec!["93.184.216.34".parse::<IpAddr>().unwrap()]);
}

#[test]
fn parse_doh_a_records_on_a_missing_answer_array_is_empty_not_an_error() {
    // NXDOMAIN/SERVFAIL shape: a real Status field, no Answer key at all.
    assert!(parse_doh_a_records(r#"{"Status":3}"#).is_empty());
}

#[test]
fn parse_doh_a_records_on_garbage_json_is_empty_never_a_panic() {
    assert!(parse_doh_a_records("not json at all").is_empty());
    assert!(parse_doh_a_records("").is_empty());
}

#[tokio::test]
async fn doh_dns_lookup_against_a_refused_endpoint_is_some_empty_not_none() {
    // Whether refused by a closed loopback port or by the shared client's own
    // private-IP guard, the observable contract is identical: the collector
    // attempted the query, so this is "ran, found nothing" (`Some(vec![])`),
    // never "the check did not run" (`None`) and never a hang.
    let addr = refused_addr().await;
    let result = doh_dns_lookup("example.invalid", &format!("http://{addr}/dns-query")).await;
    assert_eq!(result, Some(Vec::new()));
}

#[tokio::test]
async fn tls_issuer_probe_against_an_unreachable_target_is_false_none() {
    let addr = refused_addr().await;
    let (captured, issuer) = tls_issuer_probe(&addr).await;
    assert!(!captured);
    assert_eq!(issuer, None);
}

#[tokio::test]
async fn tls_issuer_probe_against_a_plain_http_responder_is_false_none() {
    // An HTTPS handshake against a server that only speaks plain HTTP fails
    // at the TLS layer — no certificate is ever exposed to capture.
    let base = serve(vec![Canned::text(200, "ok")]).await;
    let host_port = base.trim_start_matches("http://");
    let (captured, issuer) = tls_issuer_probe(host_port).await;
    assert!(!captured);
    assert_eq!(issuer, None);
}

#[tokio::test]
async fn collect_against_stays_bounded_and_reads_offline_when_every_leg_is_unreachable() {
    let addr = refused_addr().await;
    let unreachable = format!("http://{addr}");
    let started = Instant::now();
    let path = collect_against(&addr, &addr, &unreachable, &unreachable).await;
    // Five legs run concurrently (`tokio::join!`); the wall-clock cost is the
    // slowest single leg (curl's fixed 4s `--max-time`), not their sum —
    // proving "every iteration bounded" end to end, not just leg by leg.
    assert!(
        started.elapsed().as_secs() < 8,
        "collect_against took {:?}; legs must run concurrently and stay bounded",
        started.elapsed()
    );
    assert!(path.system_dns.is_empty());
    assert!(!path.ip_literal_reachable);
    assert_eq!(path.connectivity_status, None);
    assert!(!path.tls_cert_captured);
    let report = crate::core::outage::classify(&path);
    assert_eq!(report.kind, OutageKind::Offline, "{report:?}");
}

#[tokio::test]
async fn collect_against_composes_cleanly_when_only_the_direct_path_answers() {
    // system_dns empty (a refused endpoint has nothing to resolve to; here we
    // force it via a host with no A record reachable) but the IP-literal
    // anchor is a real listener: DnsUnavailable, not Offline.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind loopback");
    let anchor = listener.local_addr().expect("local addr").to_string();
    tokio::spawn(async move {
        loop {
            let Ok((sock, _)) = listener.accept().await else {
                return;
            };
            drop(sock);
        }
    });
    let refused = refused_addr().await;
    let unreachable = format!("http://{refused}");
    // A domain `lookup_host` cannot resolve without a real (and in this
    // sandbox, likely absent) resolver — using the RFC 2606-reserved TLD
    // keeps this from depending on live network reachability either way,
    // since an empty result is exactly what this test wants from that leg.
    let path = collect_against(
        "outage-test.invalid",
        &anchor,
        &unreachable,
        &unreachable,
    )
    .await;
    assert!(path.ip_literal_reachable);
    // `system_dns_lookup` calls the OS resolver directly (there is no inject
    // point for it, unlike the HTTP-based legs above) — a sandbox whose
    // network is locked down enough to make a RFC 2606-reserved TLD reliably
    // NXDOMAIN is the common case, but not a guarantee: a resolver that
    // sinkholes every unknown name would silently skip the assertion this
    // test exists to make. Fail loudly instead of skipping quietly, so a
    // sandbox where this domain unexpectedly resolves is a visible test
    // failure to fix, not a permanently untested composition.
    assert!(
        path.system_dns.is_empty(),
        "outage-test.invalid resolved to {:?} in this sandbox — the \
         DnsUnavailable composition below was not exercised; this reserved \
         TLD is expected to be NXDOMAIN everywhere this suite runs",
        path.system_dns
    );
    let report = crate::core::outage::classify(&path);
    assert_eq!(report.kind, OutageKind::DnsUnavailable, "{report:?}");
}

#[test]
fn outage_report_json_embeds_the_advice_beside_the_report() {
    let report = OutageReport {
        kind: OutageKind::CaptivePortal,
        at: 1_700_000_000,
        evidence: "a 200 where 204 was expected".to_string(),
    };
    let v = outage_report_json(&report);
    assert_eq!(v["kind"], serde_json::json!("captive_portal"));
    assert_eq!(v["at"], serde_json::json!(1_700_000_000));
    assert_eq!(v["advice"], serde_json::json!(report.advice()));
}
