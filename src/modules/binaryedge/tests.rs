use super::types::{IpResp, SubdomainResp};
use super::{BinaryEdge, build_ip_entities, build_subdomain_entities};
use crate::core::entity::{Entity, EntityKind};
use crate::core::module::{Module, ModuleCost};
use crate::core::scan::{Target, TargetKind};

#[test]
fn accepts_ip_and_domain_only() {
    let m = BinaryEdge;
    assert!(m.accepts(&Target::new(TargetKind::IpAddress, "1.1.1.1")));
    assert!(m.accepts(&Target::new(TargetKind::Domain, "example.com")));
    assert!(!m.accepts(&Target::new(TargetKind::Email, "a@b.com")));
    assert!(!m.accepts(&Target::new(TargetKind::Username, "user")));
}

#[test]
fn cost_is_paid() {
    assert!(matches!(BinaryEdge.cost(), ModuleCost::Paid));
}

#[test]
fn module_metadata() {
    let m = BinaryEdge;
    assert_eq!(m.name(), "binaryedge");
    assert_eq!(m.priority(), 78);
    assert_eq!(m.max_timeout_ms(), 10_000);
    assert_eq!(m.cache_ttl_secs(), 86_400);
    let desc = m.description();
    assert!(desc.contains("BinaryEdge"));
    assert!(desc.contains("port"));
}

fn attr<'a>(e: &'a Entity, k: &str) -> Option<&'a str> {
    e.evidence[0].attributes.get(k).map(String::as_str)
}

// ── IpResp deserialisation ──────────────────────────────────────────

#[test]
fn deserialise_full_ip_response() {
    // The exact shape confirmed against BinaryEdge's own documented example
    // (see mod.rs's header) — origin/target/result.data.{state,service}
    // nested under events[].results[], grouped by events[].port. `origin`,
    // `state`, `banner`, and `method` are present in the fixture (as the
    // real API returns them) but intentionally unmodelled — proving extra
    // upstream fields never break decoding.
    let json = r#"{
        "total": 2,
        "query": "203.0.113.10",
        "events": [
            {
                "port": 443,
                "results": [
                    {
                        "origin": {
                            "module": "grabber",
                            "port": 41574,
                            "ip": "203.0.113.10",
                            "type": "service-simple",
                            "ts": 1537060019061,
                            "country": "us"
                        },
                        "result": {
                            "data": {
                                "state": { "state": "open" },
                                "service": {
                                    "banner": "HTTP/1.1 400 Bad Request...",
                                    "method": "probe_matching",
                                    "cpe": ["cpe:/a:igor_sysoev:nginx"],
                                    "name": "ssl/http",
                                    "product": "nginx",
                                    "version": "1.18.0"
                                }
                            }
                        },
                        "target": { "protocol": "tcp", "port": 443, "ip": "203.0.113.10" }
                    }
                ]
            }
        ]
    }"#;
    let resp: IpResp = serde_json::from_str(json).expect("fixture is valid IpResp JSON");
    assert_eq!(resp.total, Some(2));
    assert_eq!(resp.events.len(), 1);
    let event = &resp.events[0];
    assert_eq!(event.port, Some(443));
    assert_eq!(event.results.len(), 1);
    let target = event.results[0].target.as_ref().expect("target present");
    assert_eq!(target.port, Some(443));
    assert_eq!(target.protocol.as_deref(), Some("tcp"));
    let service = event.results[0]
        .result
        .as_ref()
        .and_then(|r| r.data.as_ref())
        .and_then(|d| d.service.as_ref())
        .expect("service present");
    assert_eq!(service.name.as_deref(), Some("ssl/http"));
    assert_eq!(service.product.as_deref(), Some("nginx"));
    assert_eq!(service.version.as_deref(), Some("1.18.0"));
    assert_eq!(service.cpe, vec!["cpe:/a:igor_sysoev:nginx".to_string()]);
}

#[test]
fn deserialise_empty_ip_response() {
    let resp: IpResp = serde_json::from_str(r#"{"events":[]}"#).expect("should succeed");
    assert!(resp.events.is_empty());
    assert!(resp.total.is_none());
}

#[test]
fn deserialise_bare_port_with_no_results() {
    let resp: IpResp =
        serde_json::from_str(r#"{"events":[{"port":22,"results":[]}]}"#).expect("should succeed");
    assert_eq!(resp.events.len(), 1);
    assert_eq!(resp.events[0].port, Some(22));
    assert!(resp.events[0].results.is_empty());
}

// ── build_ip_entities (pure extraction) ─────────────────────────────

fn ip_body(json: &str) -> IpResp {
    serde_json::from_str(json).expect("fixture is valid IpResp JSON")
}

#[test]
fn full_ip_response_yields_ports_services_and_cpes() {
    let body = ip_body(
        r#"{
            "total": 3,
            "events": [
                {
                    "port": 22,
                    "results": [{
                        "target": { "protocol": "tcp", "port": 22 },
                        "result": { "data": { "service": { "name": "ssh", "product": "OpenSSH" } } }
                    }]
                },
                {
                    "port": 443,
                    "results": [{
                        "target": { "protocol": "tcp", "port": 443 },
                        "result": { "data": { "service": {
                            "name": "ssl/http", "product": "nginx", "version": "1.18.0",
                            "cpe": ["cpe:/a:igor_sysoev:nginx"]
                        } } }
                    }]
                }
            ]
        }"#,
    );
    let ents = build_ip_entities(&body, "203.0.113.10", "s");
    assert_eq!(ents.len(), 1);
    let ip = &ents[0];
    assert_eq!(ip.kind, EntityKind::IpAddress);
    assert!(ip.has_tag("binaryedge"));
    assert_eq!(attr(ip, "port_count"), Some("2"));
    assert_eq!(attr(ip, "ports"), Some("22,443"), "sorted + deduped");
    assert_eq!(
        attr(ip, "total_events"),
        Some("3"),
        "uses reported total, not events.len()"
    );
    assert_eq!(
        attr(ip, "services"),
        Some("22/tcp ssh OpenSSH; 443/tcp ssl/http nginx 1.18.0")
    );
    assert_eq!(attr(ip, "cpes"), Some("cpe:/a:igor_sysoev:nginx"));
}

#[test]
fn bare_port_with_no_service_still_counts_the_port() {
    let body = ip_body(r#"{"events":[{"port":8080,"results":[]}]}"#);
    let ents = build_ip_entities(&body, "203.0.113.10", "s");
    assert_eq!(ents.len(), 1);
    let ip = &ents[0];
    assert_eq!(attr(ip, "ports"), Some("8080"));
    // No service metadata at all → no `services` or `cpes` attribute emitted.
    assert!(!ip.evidence[0].attributes.contains_key("services"));
    assert!(!ip.evidence[0].attributes.contains_key("cpes"));
    // total_events falls back to events.len() when `total` is absent.
    assert_eq!(attr(ip, "total_events"), Some("1"));
}

#[test]
fn service_with_no_name_falls_back_to_unknown() {
    let body = ip_body(
        r#"{"events":[{"port":9200,"results":[{
            "target": { "protocol": "tcp" },
            "result": { "data": { "service": { "product": "Elasticsearch" } } }
        }]}]}"#,
    );
    let ents = build_ip_entities(&body, "203.0.113.10", "s");
    assert_eq!(
        attr(&ents[0], "services"),
        Some("9200/tcp unknown Elasticsearch")
    );
}

#[test]
fn empty_events_yield_nothing() {
    let body = ip_body(r#"{"events":[]}"#);
    assert!(build_ip_entities(&body, "203.0.113.10", "s").is_empty());
}

#[test]
fn port_and_cpe_lists_are_capped() {
    let events: String = (0..40)
        .map(|i| {
            let port = 10000 + i;
            format!(
                r#"{{"port":{port},"results":[{{"target":{{"protocol":"tcp"}},
                   "result":{{"data":{{"service":{{"name":"svc{port}","cpe":["cpe:/a:vendor:app{port}"]}}}}}}}}]}}"#
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    let body = ip_body(&format!(r#"{{"events":[{events}]}}"#));
    let ents = build_ip_entities(&body, "203.0.113.10", "s");
    let ip = &ents[0];
    assert_eq!(
        attr(ip, "ports")
            .expect("should succeed")
            .split(',')
            .count(),
        super::MAX_LIST
    );
    assert_eq!(
        attr(ip, "cpes").expect("should succeed").split(',').count(),
        super::MAX_LIST
    );
}

// ── build_subdomain_entities (pure extraction) ──────────────────────

fn sub_body(json: &str) -> SubdomainResp {
    serde_json::from_str(json).expect("fixture is valid SubdomainResp JSON")
}

#[test]
fn deserialise_subdomain_response() {
    // Confirmed shape: `events` is a flat array of full hostnames (not bare
    // labels), plus `total`/`page`/`pagesize` (only `total` is modelled).
    let json = r#"{
        "query": "root:example.com",
        "page": 1,
        "pagesize": 100,
        "total": 6308,
        "events": ["m.example.com", "startup.example.com"]
    }"#;
    let resp: SubdomainResp = serde_json::from_str(json).expect("should succeed");
    assert_eq!(resp.total, Some(6308));
    let events: Vec<&str> = resp.events.iter().map(String::as_str).collect();
    assert_eq!(events, vec!["m.example.com", "startup.example.com"]);
}

#[test]
fn subdomains_are_emitted_and_filtered() {
    let body = sub_body(
        r#"{
            "total": 5,
            "events": [
                "m.example.com",
                "EXAMPLE.COM",
                "startup.example.com.",
                "203.0.113.10",
                "  ",
                "has space.example.com"
            ]
        }"#,
    );
    let ents = build_subdomain_entities("example.com", &body, "s");
    let values: Vec<&str> = ents.iter().map(|e| e.value.as_str()).collect();
    assert_eq!(
        values,
        vec!["m.example.com", "startup.example.com"],
        "self-echo, IP literal, blank, and whitespace-bearing entries dropped; \
         trailing dot trimmed; case-insensitive self-match"
    );
    for e in &ents {
        assert_eq!(e.kind, EntityKind::Domain);
        assert!(e.has_tag("binaryedge") && e.has_tag("subdomain"));
        assert_eq!(attr(e, "parent_domain"), Some("example.com"));
        // The reported total, not events.len().
        assert_eq!(attr(e, "total_subdomains"), Some("5"));
    }
}

#[test]
fn a_host_not_actually_under_the_queried_domain_gets_lower_confidence_and_no_subdomain_tag() {
    // Regression: BinaryEdge's subdomain-enumeration endpoint can echo back a
    // host that passes the blank/self-echo/dotless/IP-literal filters yet
    // isn't actually a subdomain of the queried domain (a CNAME target, an
    // unrelated host). Mirrors c99's `non_subdomain_entry_gets_lower_
    // confidence_and_no_subdomain_tag` for the identical endpoint shape.
    use crate::core::confidence;
    let body = sub_body(
        r#"{
            "total": 2,
            "events": ["m.example.com", "cdn.fastly.net"]
        }"#,
    );
    let ents = build_subdomain_entities("example.com", &body, "s");
    assert_eq!(ents.len(), 2, "both hosts still reported: {ents:?}");

    let real_sub = ents
        .iter()
        .find(|e| e.value == "m.example.com")
        .expect("genuine subdomain present");
    assert!(real_sub.has_tag("subdomain"));
    assert!((real_sub.confidence - confidence::EXPERT).abs() < 1e-9);

    let unverified = ents
        .iter()
        .find(|e| e.value == "cdn.fastly.net")
        .expect("unrelated host still reported, just not as a verified subdomain");
    assert!(
        !unverified.has_tag("subdomain"),
        "a host not under the queried domain must not carry the subdomain tag"
    );
    assert!(
        (unverified.confidence - confidence::MEDIUM_PLUS).abs() < 1e-9,
        "an unverified host must not outrank a verified one: {}",
        unverified.confidence
    );
}

#[test]
fn subdomain_total_falls_back_to_events_len_when_absent() {
    let body = sub_body(r#"{"events":["a.example.com","b.example.com"]}"#);
    let ents = build_subdomain_entities("example.com", &body, "s");
    assert_eq!(ents.len(), 2);
    assert_eq!(attr(&ents[0], "total_subdomains"), Some("2"));
}

#[test]
fn empty_subdomain_list_yields_nothing() {
    let body = sub_body(r#"{"events":[]}"#);
    assert!(build_subdomain_entities("example.com", &body, "s").is_empty());
}
