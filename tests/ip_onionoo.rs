use huntsman_recon::http::Response;
use huntsman_recon::ip::providers::onionoo::TorOnionooProvider;
use huntsman_recon::ip::{IpObservationKind, IpProvider, IpProviderParseError, IpTarget};
use huntsman_recon::timefmt::parse_timestamp;

fn response(body: &str) -> Response {
    Response {
        status: 200,
        headers: Vec::new(),
        body: body.as_bytes().to_vec(),
        truncated: false,
    }
}

#[test]
fn onionoo_plans_bounded_exact_ip_candidate_search() {
    let provider = TorOnionooProvider;
    let target = IpTarget::parse("204.8.96.141").expect("target");
    let action = provider.plan(&target).pop().expect("action");
    assert_eq!(
        action.request.url,
        "https://onionoo.torproject.org/details?search=204.8.96.141&type=relay&limit=20&fields=nickname%2Cfingerprint%2Cor_addresses%2Cexit_addresses%2Clast_seen%2Crunning%2Cflags"
    );
    assert_eq!(action.lineage_family, "tor-network-status");
}

#[test]
fn onionoo_running_exit_relay_becomes_temporally_explicit_anonymization_observation() {
    let provider = TorOnionooProvider;
    let target = IpTarget::parse("204.8.96.141").expect("target");
    let action = provider.plan(&target).pop().expect("action");
    let observations = provider
        .parse(
            &action,
            &response(
                r#"{"version":"8.0","relays_published":"2026-10-04 04:00:00","relays":[{"nickname":"Quintex152","fingerprint":"0008D9640FE4947F73E355F67E20C2D290BBC72C","or_addresses":["204.8.96.141:444","[2620:7:6003::141]:81"],"exit_addresses":["204.8.96.141"],"last_seen":"2026-10-04 04:00:00","running":true,"flags":["Exit","Fast","Running","Valid"]}],"bridges":[]}"#,
            ),
            1_759_550_500,
        )
        .expect("Onionoo response");
    assert_eq!(observations.len(), 1);
    let observation = &observations[0];
    assert_eq!(observation.kind, IpObservationKind::Anonymization);
    assert_eq!(
        observation.attributes.get("classification").map(String::as_str),
        Some("tor_exit")
    );
    assert_eq!(
        observation.attributes.get("fingerprint").map(String::as_str),
        Some("0008D9640FE4947F73E355F67E20C2D290BBC72C")
    );
    assert_eq!(
        observation.attributes.get("running").map(String::as_str),
        Some("true")
    );
    assert_eq!(
        observation.observed_at_unix,
        parse_timestamp("2026-10-04 04:00:00").and_then(|value| u64::try_from(value).ok())
    );
}

#[test]
fn onionoo_prefix_search_collision_is_not_a_positive_match() {
    let provider = TorOnionooProvider;
    let target = IpTarget::parse("204.8.96.14").expect("target");
    let action = provider.plan(&target).pop().expect("action");
    let observations = provider
        .parse(
            &action,
            &response(
                r#"{"version":"8.0","relays":[{"nickname":"DifferentAddress","fingerprint":"0008D9640FE4947F73E355F67E20C2D290BBC72C","or_addresses":["204.8.96.141:444"],"exit_addresses":["204.8.96.141"],"last_seen":"2026-10-04 04:00:00","running":true,"flags":["Exit","Running"]}]}"#,
            ),
            1_759_550_500,
        )
        .expect("valid but non-matching Onionoo response");
    assert!(observations.is_empty());
}

#[test]
fn onionoo_ipv6_socket_address_is_matched_exactly() {
    let provider = TorOnionooProvider;
    let target = IpTarget::parse("2620:7:6003::141").expect("target");
    let action = provider.plan(&target).pop().expect("action");
    let observations = provider
        .parse(
            &action,
            &response(
                r#"{"version":"8.0","relays":[{"nickname":"Quintex152","fingerprint":"0008D9640FE4947F73E355F67E20C2D290BBC72C","or_addresses":["204.8.96.141:444","[2620:7:6003::141]:81"],"exit_addresses":["204.8.96.141"],"last_seen":"2026-10-04 04:00:00","running":true,"flags":["Exit","Running"]}]}"#,
            ),
            1_759_550_500,
        )
        .expect("Onionoo IPv6 response");
    assert_eq!(observations.len(), 1);
}

#[test]
fn onionoo_empty_relays_remain_empty_not_global_absence_proof() {
    let provider = TorOnionooProvider;
    let target = IpTarget::parse("1.1.1.1").expect("target");
    let action = provider.plan(&target).pop().expect("action");
    let observations = provider
        .parse(&action, &response(r#"{"version":"8.0","relays":[]}"#), 123)
        .expect("valid Onionoo empty response");
    assert!(observations.is_empty());
}

#[test]
fn onionoo_malformed_or_schema_drifted_response_fails_closed() {
    let provider = TorOnionooProvider;
    let target = IpTarget::parse("204.8.96.141").expect("target");
    let action = provider.plan(&target).pop().expect("action");
    assert!(matches!(
        provider.parse(&action, &response("{broken"), 123),
        Err(IpProviderParseError::Parse(_))
    ));
    assert!(matches!(
        provider.parse(
            &action,
            &response(r#"{"version":"8.0","relays":"not-an-array"}"#),
            123
        ),
        Err(IpProviderParseError::Schema(_))
    ));
    assert!(matches!(
        provider.parse(
            &action,
            &response(r#"{"version":"8.0","relays":[{"fingerprint":"bad","or_addresses":"not-an-array","last_seen":"2026-10-04 04:00:00","running":true}]}"#),
            123
        ),
        Err(IpProviderParseError::Schema(_))
    ));
}
