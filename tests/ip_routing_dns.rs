use std::net::IpAddr;

use huntsman_recon::http::Response;
use huntsman_recon::ip::providers::doh_ptr::{CloudflarePtrProvider, reverse_dns_name};
use huntsman_recon::ip::providers::ripestat::RipeStatNetworkInfoProvider;
use huntsman_recon::ip::{IpObservationKind, IpProvider, IpProviderParseError, IpTarget};

fn response(body: &str) -> Response {
    Response {
        status: 200,
        headers: Vec::new(),
        body: body.as_bytes().to_vec(),
        truncated: false,
    }
}

#[test]
fn ripestat_plans_canonical_network_info_lookup() {
    let provider = RipeStatNetworkInfoProvider;
    let target = IpTarget::parse("1.1.1.1").expect("target");
    let action = provider.plan(&target).pop().expect("action");
    assert_eq!(
        action.request.url,
        "https://stat.ripe.net/data/network-info/data.json?resource=1.1.1.1"
    );
    assert_eq!(action.lineage_family, "ripe-stat-network-info");
}

#[test]
fn ripestat_routed_ipv4_yields_prefix_and_every_announcing_asn() {
    let provider = RipeStatNetworkInfoProvider;
    let target = IpTarget::parse("1.1.1.1").expect("target");
    let action = provider.plan(&target).pop().expect("action");
    let observations = provider
        .parse(
            &action,
            &response(r#"{"status":"ok","data":{"asns":[13335,20940],"prefix":"1.1.1.0/24"}}"#),
            123,
        )
        .expect("RIPEstat response");
    assert_eq!(observations.len(), 1);
    let observation = &observations[0];
    assert_eq!(observation.kind, IpObservationKind::Routing);
    assert_eq!(
        observation.attributes.get("prefix").map(String::as_str),
        Some("1.1.1.0/24")
    );
    assert_eq!(
        observation.attributes.get("asns").map(String::as_str),
        Some("13335; 20940")
    );
    assert_eq!(observation.observed_at_unix, None);
    assert_eq!(observation.retrieved_at_unix, 123);
}

#[test]
fn ripestat_routed_ipv6_is_preserved() {
    let provider = RipeStatNetworkInfoProvider;
    let target = IpTarget::parse("2606:4700:4700::1111").expect("target");
    let action = provider.plan(&target).pop().expect("action");
    let observations = provider
        .parse(
            &action,
            &response(r#"{"status":"ok","data":{"asns":[13335],"prefix":"2606:4700:4700::/48"}}"#),
            456,
        )
        .expect("RIPEstat response");
    assert_eq!(
        observations[0].attributes.get("prefix").map(String::as_str),
        Some("2606:4700:4700::/48")
    );
}

#[test]
fn ripestat_empty_asns_do_not_become_negative_attribution() {
    let provider = RipeStatNetworkInfoProvider;
    let target = IpTarget::parse("1.1.1.1").expect("target");
    let action = provider.plan(&target).pop().expect("action");
    let observations = provider
        .parse(
            &action,
            &response(r#"{"status":"ok","data":{"asns":[],"prefix":"1.1.1.0/24"}}"#),
            123,
        )
        .expect("RIPEstat response");
    assert_eq!(observations.len(), 1);
    assert_eq!(
        observations[0].attributes.get("prefix").map(String::as_str),
        Some("1.1.1.0/24")
    );
    assert!(!observations[0].attributes.contains_key("asns"));
    assert!(
        !observations[0]
            .summary
            .to_ascii_lowercase()
            .contains("no asn")
    );
}

#[test]
fn ripestat_malformed_or_schema_drifted_response_fails_closed() {
    let provider = RipeStatNetworkInfoProvider;
    let target = IpTarget::parse("1.1.1.1").expect("target");
    let action = provider.plan(&target).pop().expect("action");
    assert!(matches!(
        provider.parse(&action, &response("{broken"), 123),
        Err(IpProviderParseError::Parse(_))
    ));
    assert!(matches!(
        provider.parse(
            &action,
            &response(r#"{"status":"ok","data":{"asns":[13335]}}"#),
            123
        ),
        Err(IpProviderParseError::Schema(_))
    ));
}

#[test]
fn ipv4_reverse_dns_name_is_correct() {
    let address: IpAddr = "1.2.3.4".parse().expect("IPv4");
    assert_eq!(reverse_dns_name(address), "4.3.2.1.in-addr.arpa");
}

#[test]
fn ipv6_reverse_dns_name_is_nibble_reversed() {
    let address: IpAddr = "2001:db8::1".parse().expect("IPv6");
    assert_eq!(
        reverse_dns_name(address),
        "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa"
    );
}

#[test]
fn cloudflare_ptr_plans_json_doh_request() {
    let provider = CloudflarePtrProvider;
    let target = IpTarget::parse("1.1.1.1").expect("target");
    let action = provider.plan(&target).pop().expect("action");
    assert_eq!(
        action.request.url,
        "https://cloudflare-dns.com/dns-query?name=1.1.1.1.in-addr.arpa&type=PTR"
    );
    assert_eq!(
        action.request.header_value("Accept"),
        Some("application/dns-json")
    );
    assert_eq!(action.lineage_family, "cloudflare-dns");
}

#[test]
fn cloudflare_ptr_answers_become_reverse_dns_observations() {
    let provider = CloudflarePtrProvider;
    let target = IpTarget::parse("1.1.1.1").expect("target");
    let action = provider.plan(&target).pop().expect("action");
    let observations = provider
        .parse(
            &action,
            &response(
                r#"{"Status":0,"Answer":[{"name":"1.1.1.1.in-addr.arpa.","type":12,"TTL":300,"data":"one.one.one.one."}]}"#,
            ),
            789,
        )
        .expect("DoH response");
    assert_eq!(observations.len(), 1);
    assert_eq!(observations[0].kind, IpObservationKind::ReverseDns);
    assert_eq!(observations[0].summary, "one.one.one.one");
    assert_eq!(
        observations[0].attributes.get("ttl").map(String::as_str),
        Some("300")
    );
    assert_eq!(observations[0].observed_at_unix, None);
}

#[test]
fn cloudflare_nxdomain_or_empty_answer_is_empty_not_absence_proof() {
    let provider = CloudflarePtrProvider;
    let target = IpTarget::parse("1.1.1.1").expect("target");
    let action = provider.plan(&target).pop().expect("action");
    for body in [r#"{"Status":3}"#, r#"{"Status":0,"Answer":[]}"#] {
        let observations = provider
            .parse(&action, &response(body), 123)
            .expect("valid DNS empty response");
        assert!(observations.is_empty(), "{body}");
    }
}

#[test]
fn cloudflare_ptr_malformed_or_wrong_answer_shape_fails_closed() {
    let provider = CloudflarePtrProvider;
    let target = IpTarget::parse("1.1.1.1").expect("target");
    let action = provider.plan(&target).pop().expect("action");
    assert!(matches!(
        provider.parse(&action, &response("{broken"), 123),
        Err(IpProviderParseError::Parse(_))
    ));
    assert!(matches!(
        provider.parse(
            &action,
            &response(r#"{"Status":0,"Answer":"not-an-array"}"#),
            123
        ),
        Err(IpProviderParseError::Schema(_))
    ));
}
