use super::types::{CensysResp, HostResult};
use super::{Censys, build_entities};
use crate::core::entity::{Entity, EntityKind};
use crate::core::module::{Module, ModuleCost};
use crate::core::scan::{Target, TargetKind};
use crate::util::geo::is_valid_coords;

#[test]
fn accepts_ip_only() {
    let m = Censys;
    assert!(m.accepts(&Target::new(TargetKind::IpAddress, "1.1.1.1")));
    assert!(!m.accepts(&Target::new(TargetKind::Domain, "example.com")));
    assert!(!m.accepts(&Target::new(TargetKind::Email, "a@b.com")));
    assert!(!m.accepts(&Target::new(TargetKind::Username, "user")));
}

#[test]
fn cost_is_key_gated() {
    assert!(matches!(Censys.cost(), ModuleCost::KeyGated));
}

#[test]
fn module_metadata() {
    let m = Censys;
    assert_eq!(m.name(), "censys");
    assert_eq!(m.priority(), 78);
    assert_eq!(m.max_timeout_ms(), 10_000);
    // Host-scan data is stable within a day — one of C9's own named
    // motivating examples for the inter-scan cache.
    assert_eq!(m.cache_ttl_secs(), 86_400);
    let desc = m.description();
    assert!(desc.contains("Censys"));
    assert!(desc.contains("port"));
}

#[test]
fn deserialise_full_response() {
    let json = r#"{
        "result": {
            "services": [
                {
                    "port": 80,
                    "service_name": "HTTP",
                    "transport_protocol": "TCP"
                },
                {
                    "port": 443,
                    "service_name": "HTTPS",
                    "transport_protocol": "TCP"
                },
                {
                    "port": 22,
                    "service_name": "SSH",
                    "transport_protocol": "TCP"
                }
            ],
            "location": {
                "coordinates": {
                    "latitude": -33.8688,
                    "longitude": 151.2093
                },
                "country": "Australia",
                "country_code": "AU",
                "city": "Sydney",
                "province": "New South Wales"
            }
        }
    }"#;

    let resp: CensysResp = serde_json::from_str(json).expect("should succeed");
    let host = resp.result.expect("should succeed");
    assert_eq!(host.services.len(), 3);
    assert_eq!(host.services[0].port, Some(80));
    assert_eq!(host.services[0].service_name.as_deref(), Some("HTTP"));
    assert_eq!(host.services[0].transport_protocol.as_deref(), Some("TCP"));

    let loc = host.location.expect("should succeed");
    assert_eq!(loc.country.as_deref(), Some("Australia"));
    assert_eq!(loc.country_code.as_deref(), Some("AU"));
    assert_eq!(loc.city.as_deref(), Some("Sydney"));
    let coords = loc.coordinates.expect("should succeed");
    assert!((coords.latitude.expect("should succeed") - (-33.8688)).abs() < 1e-4);
    assert!((coords.longitude.expect("should succeed") - 151.2093).abs() < 1e-4);
}

#[test]
fn deserialise_empty_result() {
    let json = r#"{ "result": { "services": [], "location": null } }"#;
    let resp: CensysResp = serde_json::from_str(json).expect("should succeed");
    let host = resp.result.expect("should succeed");
    assert!(host.services.is_empty());
    assert!(host.location.is_none());
}

#[test]
fn deserialise_missing_fields() {
    let json = r#"{ "result": { "services": [{ "port": 53 }] } }"#;
    let resp: CensysResp = serde_json::from_str(json).expect("should succeed");
    let host = resp.result.expect("should succeed");
    assert_eq!(host.services.len(), 1);
    assert_eq!(host.services[0].port, Some(53));
    assert!(host.services[0].service_name.is_none());
    assert!(host.services[0].transport_protocol.is_none());
}

#[test]
fn deserialise_no_result() {
    let json = r"{}";
    let resp: CensysResp = serde_json::from_str(json).expect("should succeed");
    assert!(resp.result.is_none());
}

#[test]
fn coordinate_gate_rejects_null_island() {
    // Censys uses the shared validator for its coordinates gate: a 0,0
    // "unknown location" placeholder must NOT become a Coordinates entity,
    // while an in-range data-centre coord passes. (Validates the policy the
    // process() if-let chain depends on.)
    assert!(!is_valid_coords(0.0, 0.0));
    assert!(!is_valid_coords(91.0, 10.0));
    assert!(is_valid_coords(-33.8688, 151.2093));
}

// ── build_entities (pure extraction) ───────────────────────────────

fn host(json: &str) -> HostResult {
    let resp: CensysResp = serde_json::from_str(json).expect("fixture is valid CensysResp JSON");
    resp.result.expect("fixture carries a result")
}
fn of_kind(ents: &[Entity], kind: EntityKind) -> Option<&Entity> {
    ents.iter().find(|e| e.kind == kind)
}

#[test]
fn full_host_yields_ip_coords_and_address() {
    let ents = build_entities(
        &host(
            r#"{ "result": {
                "services": [
                    { "port": 443, "service_name": "HTTPS", "transport_protocol": "TCP" },
                    { "port": 80,  "service_name": "HTTP",  "transport_protocol": "TCP" },
                    { "port": 53,  "service_name": "DNS",   "transport_protocol": "UDP" }
                ],
                "location": {
                    "coordinates": { "latitude": -33.8688, "longitude": 151.2093 },
                    "country": "Australia", "country_code": "au",
                    "city": "Sydney", "province": "New South Wales"
                }
            } }"#,
        ),
        "8.8.8.8",
        "s",
    );
    assert_eq!(ents.len(), 3);

    let ip = of_kind(&ents, EntityKind::IpAddress).expect("subject IP");
    assert!(ip.has_tag("censys"));
    let attr = |k: &str| ip.evidence[0].attributes.get(k).map(String::as_str);
    assert_eq!(attr("port_count"), Some("3"));
    // Ports are sorted + deduped.
    assert_eq!(attr("ports"), Some("53,80,443"));
    assert_eq!(
        attr("services"),
        Some("443/TCP HTTPS; 80/TCP HTTP; 53/UDP DNS")
    );
    // Protocols are a sorted, deduplicated set.
    assert_eq!(attr("protocols"), Some("TCP,UDP"));

    let geo = of_kind(&ents, EntityKind::Coordinates).expect("coords");
    assert!(geo.has_tag("geoint") && geo.has_tag("censys"));
    assert!(geo.has_tag("country:AU"), "country code is uppercased");
    assert_eq!(geo.value, "-33.868800,151.209300");
    let gattr = |k: &str| geo.evidence[0].attributes.get(k).map(String::as_str);
    assert_eq!(gattr("city"), Some("Sydney"));
    assert_eq!(gattr("province"), Some("New South Wales"));
    assert_eq!(gattr("source"), Some("censys"));

    let addr = of_kind(&ents, EntityKind::Address).expect("address");
    assert_eq!(addr.value, "Sydney, New South Wales, Australia");
    assert!(addr.has_tag("censys") && addr.has_tag("geoint"));
}

#[test]
fn coordinates_carry_the_originating_ip_for_login_ip_recognition() {
    // Pass 31: the correlator's shared `person_login_ip_coords` (used by
    // `best_au_location_estimate` and `au_location_corroboration`) only
    // recognises a Coordinates fix as tied to a subject's breach/stealer
    // login IP when its evidence carries an `ip` attribute equal to that
    // IP — the same property `ipinfo`/`ip_whois_geo`/`ipquery`/`ip_geo`
    // already pin.
    let ents = build_entities(
        &host(
            r#"{ "result": {
                "location": {
                    "coordinates": { "latitude": -33.8688, "longitude": 151.2093 },
                    "country": "Australia", "country_code": "au"
                }
            } }"#,
        ),
        "8.8.8.8",
        "s",
    );
    let geo = of_kind(&ents, EntityKind::Coordinates).expect("coords");
    assert_eq!(
        geo.evidence[0].attributes.get("ip").map(String::as_str),
        Some("8.8.8.8"),
        "Coordinates evidence must carry the originating IP so \
         person_login_ip_coords can recognise this as a login-IP fix"
    );
}

#[test]
fn autonomous_system_yields_asn_org_and_reverse_dns_domains() {
    let ents = build_entities(
        &host(
            r#"{ "result": {
                "services": [{ "port": 443 }],
                "autonomous_system": {
                    "asn": 15169, "name": "GOOGLE",
                    "description": "Google LLC", "country_code": "US"
                },
                "dns": { "reverse_dns": { "names": [
                    "dns.google", "dns.google", "8.8.8.8", "no-dot", "dns.google."
                ] } }
            } }"#,
        ),
        "8.8.8.8",
        "s",
    );

    let asn = of_kind(&ents, EntityKind::Asn).expect("AS<n> Asn entity");
    assert_eq!(asn.value, "AS15169");
    assert!(asn.has_tag("censys"));
    assert_eq!(
        asn.evidence[0]
            .attributes
            .get("country")
            .map(String::as_str),
        Some("US")
    );

    let org = of_kind(&ents, EntityKind::Organisation).expect("operator Organisation");
    // Prefers `name` over `description`.
    assert_eq!(org.value, "GOOGLE");

    // Reverse-DNS names → one deduped Domain (IP-shaped + dotless + dup dropped).
    let domains: Vec<&str> = ents
        .iter()
        .filter(|e| e.kind == EntityKind::Domain)
        .map(|e| e.value.as_str())
        .collect();
    assert_eq!(domains, ["dns.google"], "deduped, IP/dotless dropped");
    assert!(
        ents.iter()
            .find(|e| e.kind == EntityKind::Domain)
            .expect("should succeed")
            .has_tag("ptr")
    );
}

#[test]
fn zero_or_absent_asn_is_skipped_but_operator_org_survives() {
    let ents = build_entities(
        &host(
            r#"{ "result": { "services": [],
                "autonomous_system": { "asn": 0, "description": "Some Net" } } }"#,
        ),
        "1.2.3.4",
        "s",
    );
    assert!(
        of_kind(&ents, EntityKind::Asn).is_none(),
        "a 0 ASN is skipped, never emitted as AS0"
    );
    // Falls back to `description` when `name` is absent.
    assert_eq!(
        of_kind(&ents, EntityKind::Organisation)
            .expect("should succeed")
            .value,
        "Some Net"
    );
}

#[test]
fn empty_host_yields_nothing() {
    // Neither services nor location → the builder short-circuits.
    let ents = build_entities(
        &host(r#"{ "result": { "services": [], "location": null } }"#),
        "1.2.3.4",
        "s",
    );
    assert!(ents.is_empty());
}

#[test]
fn services_only_yields_just_the_ip() {
    let ents = build_entities(
        &host(r#"{ "result": { "services": [{ "port": 22 }] } }"#),
        "1.2.3.4",
        "s",
    );
    assert_eq!(ents.len(), 1);
    let ip = &ents[0];
    assert_eq!(ip.kind, EntityKind::IpAddress);
    let attr = |k: &str| ip.evidence[0].attributes.get(k).map(String::as_str);
    assert_eq!(attr("ports"), Some("22"));
    // Missing service_name/transport default to unknown/tcp in the service list.
    assert_eq!(attr("services"), Some("22/tcp unknown"));
    // No transport_protocol on any service → no `protocols` attribute.
    assert!(!ip.evidence[0].attributes.contains_key("protocols"));
}

#[test]
fn null_island_coordinates_yield_no_coords_entity() {
    // A 0,0 placeholder location with no services: the location is present
    // (so the builder does not short-circuit) but the invalid coords are
    // dropped, leaving no entities at all.
    let ents = build_entities(
        &host(
            r#"{ "result": { "services": [],
                "location": { "coordinates": { "latitude": 0.0, "longitude": 0.0 },
                              "country": "Nowhere", "city": "Null", "country_code": "ZZ" } } }"#,
        ),
        "1.2.3.4",
        "s",
    );
    assert!(of_kind(&ents, EntityKind::Coordinates).is_none());
    assert!(
        ents.is_empty(),
        "no services and an invalid coord → nothing"
    );
}

#[test]
fn coords_without_city_or_country_yield_no_address() {
    // Valid coordinates but the city/country needed for an Address are absent.
    let ents = build_entities(
        &host(
            r#"{ "result": { "services": [],
                "location": { "coordinates": { "latitude": -33.87, "longitude": 151.2 },
                              "country_code": "AU" } } }"#,
        ),
        "1.2.3.4",
        "s",
    );
    assert!(of_kind(&ents, EntityKind::Coordinates).is_some());
    assert!(
        of_kind(&ents, EntityKind::Address).is_none(),
        "no city/country → no Address pivot"
    );
}

#[test]
fn address_omits_province_when_absent() {
    let ents = build_entities(
        &host(
            r#"{ "result": { "services": [],
                "location": { "coordinates": { "latitude": -33.87, "longitude": 151.2 },
                              "country": "Australia", "city": "Sydney" } } }"#,
        ),
        "1.2.3.4",
        "s",
    );
    assert_eq!(
        of_kind(&ents, EntityKind::Address)
            .expect("should succeed")
            .value,
        "Sydney, Australia"
    );
}

#[test]
fn blank_country_code_adds_no_tag_but_keeps_other_geo_attrs() {
    let ents = build_entities(
        &host(
            r#"{ "result": { "services": [],
                "location": { "coordinates": { "latitude": -33.87, "longitude": 151.2 },
                              "country_code": "", "city": "Sydney", "country": "Australia" } } }"#,
        ),
        "1.2.3.4",
        "s",
    );
    let geo = of_kind(&ents, EntityKind::Coordinates).expect("coords");
    assert!(
        !geo.tags.iter().any(|t| t.starts_with("country:")),
        "a blank country code adds no country tag"
    );
    // The blank country_code is skipped as an attribute, but city/country remain.
    assert!(!geo.evidence[0].attributes.contains_key("country_code"));
    assert_eq!(
        geo.evidence[0].attributes.get("city").map(String::as_str),
        Some("Sydney")
    );
}

#[test]
fn near_null_island_jitter_coordinates_yield_no_coords_entity() {
    // REQ-CENSYS-001: Censys is a coarse IP-geo provider and must reject the
    // near-null-island jitter band (0.001 to 0.01) those APIs emit as an
    // "unknown" placeholder. The stricter is_plausible_provider_coord gate is
    // required, not the weaker is_valid_coords. A (0.005, 0.005) jitter
    // coordinate must not become a Coordinates entity, and Address is gated on it.
    let ents = build_entities(
        &host(
            r#"{ "result": { "services": [],
                "location": { "coordinates": { "latitude": 0.005, "longitude": 0.005 },
                              "country": "Unknown", "city": "Null" } } }"#,
        ),
        "1.2.3.4",
        "s",
    );
    assert!(
        of_kind(&ents, EntityKind::Coordinates).is_none(),
        "near-null-island jitter coordinates (0.005, 0.005) must be rejected"
    );
    assert!(
        of_kind(&ents, EntityKind::Address).is_none(),
        "no Address when coordinates are rejected"
    );
}

// ── REQ-KEYSKIP-002: a missing SECRET is a skip, not a clean negative ───────

fn ctx_with(keys: &[(&str, &str)]) -> crate::core::module::ModuleContext {
    let (bus, _rx) = tokio::sync::broadcast::channel(1);
    crate::core::module::ModuleContext {
        scan_id: "scan".into(),
        bus,
        http: reqwest::Client::new(),
        keys: keys
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect(),
        cancel: crate::core::cancel::CancelHandle::new(),
    }
}

/// LOCK. Censys authenticates with HTTP Basic `api_id:api_secret` — its own
/// header says both are required, and `process` sends them together. With the
/// ID present and the SECRET missing, the module cannot make a request at all,
/// so the provider is never contacted.
///
/// It used to return `Ok(ModuleResult::new())` for that. Dispatch records an
/// empty result as `ModuleDone { found: 0 }`, which coverage aggregates to
/// `ProviderOutcome::CleanNegative` — documented as "the only outcome that is a
/// real negative", and the one `settles_absence` trusts. So a half-configured
/// censys asserted that censys holds nothing on the subject.
///
/// REQ-KEYSKIP-001 established `Error::MissingKey` as the contract for exactly
/// this and converted ~8 modules, including the `api_id` arm **two lines above
/// this one**. The secret arm was left behind. A sweep of every credential
/// lookup in `src/modules` with a quiet-empty miss arm found this as the only
/// survivor tree-wide.
#[tokio::test]
async fn a_missing_secret_is_a_typed_skip_not_a_clean_negative() {
    let ctx = ctx_with(&[(super::ID_ENV, "an-api-id")]);
    let err = Censys
        .process(&Target::new(TargetKind::IpAddress, "1.1.1.1"), &ctx)
        .await
        .expect_err("half-configured censys was never asked, so this is a skip");
    assert!(
        matches!(err, crate::core::error::Error::MissingKey(ref k) if k == super::SECRET_ENV),
        "expected MissingKey({}), got {err:?}",
        super::SECRET_ENV
    );
}

/// CONTROL. The fix must name the credential that is actually missing, not
/// error on anything incomplete: with NEITHER key set, the ID is still the one
/// reported, because it is checked first. A repair that returned
/// `MissingKey(SECRET_ENV)` here — or that erred unconditionally — would fail
/// this while passing the lock above.
#[tokio::test]
async fn with_neither_credential_the_id_is_still_the_one_reported() {
    let ctx = ctx_with(&[]);
    let err = Censys
        .process(&Target::new(TargetKind::IpAddress, "1.1.1.1"), &ctx)
        .await
        .expect_err("no credentials at all is still a skip");
    assert!(
        matches!(err, crate::core::error::Error::MissingKey(ref k) if k == super::ID_ENV),
        "expected MissingKey({}), got {err:?}",
        super::ID_ENV
    );
}
