use super::*;
use super::extract::{extract_entities, extract_geo_entities};
use super::helpers::{resolve_identity_pivots, should_skip_seed};
use crate::core::entity::Entity;
use std::collections::HashSet;

#[test]
fn module_timeout_exceeds_seeknow_curl_outer_budget() {
    assert!(
        SeekNow.max_timeout_ms() >= 78_000,
        "see_know max_timeout_ms {} must be >= 78_000 (curl-client outer timeout)",
        SeekNow.max_timeout_ms()
    );
}

#[test]
fn should_skip_seed_matches_preflight_policy() {
    assert!(should_skip_seed(TargetKind::Email, "x@localhost"));
    assert!(should_skip_seed(TargetKind::Username, "abc"));
    assert!(should_skip_seed(TargetKind::Username, "12345"));
    assert!(should_skip_seed(TargetKind::Phone, "12345"));
    assert!(should_skip_seed(TargetKind::FullName, "Jordan"));
    assert!(should_skip_seed(TargetKind::IpAddress, "192.168.1.1"));
    assert!(should_skip_seed(TargetKind::Coordinates, "0,0"));
    assert!(!should_skip_seed(TargetKind::Email, "jordan.meyer@wartburg.edu"));
    assert!(!should_skip_seed(TargetKind::Username, "jmeyer82291"));
    assert!(!should_skip_seed(TargetKind::Phone, "+15551234567"));
    assert!(!should_skip_seed(TargetKind::FullName, "Jordan Meyer"));
    assert!(!should_skip_seed(TargetKind::IpAddress, "8.8.8.8"));
    assert!(!should_skip_seed(TargetKind::Domain, "example.com"));
}

#[test]
fn extract_entities_characterization() {
    use serde_json::json;
    let item = json!({
        "dbname": "TestBreach",
        "email": "Jordan.Meyer@Example.com",
        "username": "jmeyer",
        "phone": "15551234567",
        "full_name": "Jordan Meyer",
        "ip": "8.8.8.8",
        "country": "US",
        "discord_id": "123456789012345678",
        "steam_id": "76561198000000000",
        "domain": "example.com"
    });
    let mut seen = HashSet::new();
    let mut result = ModuleResult::new();
    extract_entities(
        &item,
        "15551234567",
        "scan",
        "search",
        "see-know.eu:test",
        &mut seen,
        &mut result,
    );

    assert_eq!(
        result.entities.len(),
        9,
        "kinds: {:?}",
        result.entities.iter().map(|e| (e.kind.to_string(), e.value.clone())).collect::<Vec<_>>()
    );
    for e in &result.entities {
        assert!(e.has_tag("see-know"), "{} missing see-know", e.value);
        assert_eq!(
            e.has_tag("breach"),
            e.kind != EntityKind::Domain,
            "breach tag policy wrong for {} ({})",
            e.value,
            e.kind
        );
    }
    let has = |k: EntityKind, v: &str| result.entities.iter().any(|e| e.kind == k && e.value == v);
    assert!(has(EntityKind::Email, "jordan.meyer@example.com"));
    assert!(has(EntityKind::Username, "jmeyer"));
    assert!(has(EntityKind::Phone, "15551234567"));
    assert!(has(EntityKind::Person, "Jordan Meyer"));
    assert!(has(EntityKind::Address, "US"));
    assert!(has(EntityKind::Domain, "example.com"));
    assert!(result.entities.iter().any(|e| e.kind == EntityKind::IpAddress && e.has_tag("geolocation-lead")));
    assert!(result.entities.iter().any(|e| e.value == "discord:123456789012345678" && e.has_tag("discord")));
    assert!(result.entities.iter().any(|e| e.value == "steam:76561198000000000" && e.has_tag("steam")));
}

#[test]
fn extract_entities_spiders_stealer_url_into_pivots() {
    use serde_json::json;
    let item = json!({
        "dbname": "RedlineStealer",
        "username": "victim_login",
        "password": "hunter2",
        "url": "https://accounts.example.com/login?ref=1",
    });
    let mut seen = HashSet::new();
    let mut result = ModuleResult::new();
    extract_entities(&item, "victim_login", "scan", "stealer", "see-know.eu:test", &mut seen, &mut result);

    let find = |k: EntityKind, pred: &dyn Fn(&Entity) -> bool| {
        result.entities.iter().find(|e| e.kind == k && pred(e))
    };
    let url = find(EntityKind::Url, &|e| e.value.contains("accounts.example.com"))
        .expect("stealer URL must surface as a Url entity");
    assert!(url.has_tag("stealer") && url.has_tag("see-know"));
    assert!(!url.has_tag("breach"), "stealer URL must NOT be tagged breach");
    let dom = find(EntityKind::Domain, &|e| e.value == "accounts.example.com")
        .expect("stealer URL host must surface as a Domain pivot");
    assert!(dom.has_tag("stealer") && !dom.has_tag("breach"));
    assert!(
        find(EntityKind::Credential, &|e| {
            e.value == "victim_login@https://accounts.example.com/login?ref=1"
        })
        .is_some(),
        "login↔surface must surface as a Credential entity"
    );
}

#[test]
fn extract_rich_detail_surfaces_the_whole_record() {
    use serde_json::json;
    let item = json!({
        "first_name": "Jordan",
        "last_name": "Avery",
        "company": "Acme Pty Ltd",
        "mac_address": "DC:44:27:AA:BB:CC",
        "hwid": "WIN-ABC123XYZ",
        "telegram": "javery",
        "city": "Brisbane",
        "state": "QLD",
        "postal": "4000",
        "country": "AU",
        "gender": "M",
        "ip_country_code": "AU"
    });
    let mut seen = HashSet::new();
    let mut result = ModuleResult::new();
    extract_entities(&item, "x", "scan", "search", "see-know.eu:test", &mut seen, &mut result);

    let has = |k: EntityKind, pred: &dyn Fn(&Entity) -> bool| {
        result.entities.iter().any(|e| e.kind == k && pred(e))
    };
    assert!(has(EntityKind::Person, &|e| e.value == "Jordan Avery"));
    assert!(has(EntityKind::Organisation, &|e| e.value == "Acme Pty Ltd"));
    assert!(has(EntityKind::MacAddress, &|e| e.value.to_lowercase().contains("dc:44:27")));
    assert!(has(EntityKind::DeviceId, &|e| e.value == "WIN-ABC123XYZ" && e.has_tag("stealer")));
    assert!(has(EntityKind::Username, &|e| e.value == "telegram:javery"));
    assert!(has(EntityKind::Address, &|e| e.value.contains("Brisbane") && e.value.contains("AU") && e.has_tag("composed-address")));
    assert!(has(EntityKind::Other("gender".into()), &|e| e.value == "M" && e.has_tag("raw-field")));
    assert!(has(EntityKind::Other("ip_country_code".into()), &|e| e.value == "AU"));
    assert!(!result.entities.iter().any(|e| matches!(&e.kind, EntityKind::Other(k) if k == "first_name")));
}

#[test]
fn extract_geo_entities_characterization() {
    use serde_json::json;

    {
        let (mut seen, mut r) = (HashSet::new(), ModuleResult::new());
        extract_geo_entities(&json!({"lat": 40.7128, "lon": -74.0060}), "ip_info", "s", &mut seen, &mut r);
        assert!(r.entities.iter().any(|e| e.kind == EntityKind::Coordinates && e.has_tag("via:ip_info")), "f64 coords");
    }
    {
        let (mut seen, mut r) = (HashSet::new(), ModuleResult::new());
        extract_geo_entities(&json!({"latitude": "51.5", "longitude": "-0.12"}), "phone_info", "s", &mut seen, &mut r);
        assert!(r.entities.iter().any(|e| e.kind == EntityKind::Coordinates), "string coords");
    }
    {
        let (mut seen, mut r) = (HashSet::new(), ModuleResult::new());
        extract_geo_entities(&json!({"lat": 999.0, "lon": 0.0}), "ip_info", "s", &mut seen, &mut r);
        assert!(!r.entities.iter().any(|e| e.kind == EntityKind::Coordinates), "out-of-range rejected");
    }
    {
        let (mut seen, mut r) = (HashSet::new(), ModuleResult::new());
        extract_geo_entities(&json!({"lat": 0.0, "lon": 0.0}), "ip_info", "s", &mut seen, &mut r);
        assert!(!r.entities.iter().any(|e| e.kind == EntityKind::Coordinates), "Null Island rejected");
    }
    {
        let (mut seen, mut r) = (HashSet::new(), ModuleResult::new());
        extract_geo_entities(
            &json!({"location": "Sydney, NSW", "timezone": "Australia/Sydney", "asn": "AS15169", "org": "Google"}),
            "ip_info", "s", &mut seen, &mut r,
        );
        assert!(r.entities.iter().any(|e| e.value == "Sydney, NSW" && e.has_tag("geo-hint")));
        assert!(r.entities.iter().any(|e| e.value == "tz:Australia/Sydney" && e.has_tag("timezone")));
        assert!(r.entities.iter().any(|e| e.kind == EntityKind::Asn && e.value == "AS15169"));
        assert!(r.entities.iter().any(|e| e.kind == EntityKind::Organisation));
    }
    {
        let (mut seen, mut r) = (HashSet::new(), ModuleResult::new());
        extract_geo_entities(&json!({"asn": "AS1"}), "phone_info", "s", &mut seen, &mut r);
        assert!(!r.entities.iter().any(|e| e.kind == EntityKind::Asn));
    }
    {
        let (mut seen, mut r) = (HashSet::new(), ModuleResult::new());
        extract_geo_entities(
            &json!({"registrant_city": "Reno", "registrant_state": "NV", "registrant_country": "US"}),
            "whois", "s", &mut seen, &mut r,
        );
        assert!(r.entities.iter().any(|e| e.value == "Reno, NV, US" && e.has_tag("whois-registrant")));
    }
}

#[test]
fn accepts_six_target_kinds() {
    let m = SeekNow;
    for k in [
        TargetKind::Email, TargetKind::Username, TargetKind::Phone,
        TargetKind::IpAddress, TargetKind::Domain, TargetKind::FullName,
    ] {
        assert!(m.accepts(&Target::new(k, "x")));
    }
}

#[test]
fn cost_is_paid() {
    assert!(matches!(SeekNow.cost(), ModuleCost::Paid));
}

#[test]
fn priority_above_oathnet_pro() {
    assert!(
        SeekNow.priority() > 127,
        "SeekNow priority {} must exceed oathnet_pro's 127 so it runs first",
        SeekNow.priority()
    );
}

#[test]
fn category_is_breach() {
    assert_eq!(SeekNow.category(), ModuleCategory::Breach);
}

#[test]
fn attack_techniques_credit_the_full_recon_surface() {
    use crate::core::attack;
    let t = SeekNow.attack_techniques();
    for default in attack::techniques_for_category(ModuleCategory::Breach) {
        assert!(t.contains(default), "see_know mapping must keep the Breach default {default}, got {t:?}");
    }
    for id in ["T1589.003", "T1590.005", "T1591.001", "T1591.002", "T1592", "T1593.001"] {
        assert!(t.contains(&id), "see_know must claim {id}");
        assert!(attack::technique(id).is_some(), "{id} must be catalogued");
    }
}

#[test]
fn produces_includes_geo_and_identity_kinds() {
    let kinds = SeekNow.produces();
    assert!(kinds.contains(&EntityKind::Coordinates));
    assert!(kinds.contains(&EntityKind::Address));
    assert!(kinds.contains(&EntityKind::Email));
    assert!(kinds.contains(&EntityKind::Username));
    assert!(kinds.contains(&EntityKind::Phone));
    assert!(kinds.contains(&EntityKind::ApiKey));
}

#[tokio::test]
async fn resolve_identity_pivots_is_noop_and_terminates_without_ids() {
    crate::util::see_know::reset_budget();
    let mut seen = HashSet::new();
    let mut result = ModuleResult::new();
    result.push(Entity::new(EntityKind::Email, "a@b.com", 0.8, "t"));
    let before = result.entities.len();
    resolve_identity_pivots("key", "see-know.eu:test", "seed", "t", &mut seen, &mut result).await;
    assert_eq!(result.entities.len(), before, "no pivot IDs ⇒ no dispatch, no growth, clean halt");
}
