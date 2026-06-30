// Included into `breach_rich.rs` via `include!`, so `super::*` is in scope.
use super::*;
use serde_json::json;

fn run(item: &Value, source: &str) -> ModuleResult {
    let ev = Evidence::new("test", "rec".to_string());
    let mut seen = HashSet::new();
    let mut result = ModuleResult::new();
    extract_rich_detail(item, "scan", source, &ev, &mut seen, &mut result);
    result
}

fn has(result: &ModuleResult, kind: EntityKind, value: &str) -> bool {
    result
        .entities
        .iter()
        .any(|e| e.kind == kind && e.value == value)
}

#[test]
fn surfaces_device_fingerprints_as_context_not_breach() {
    let item = json!({
        "hwid": "ABCDEF0123456789",
        "mac_address": "AA:BB:CC:DD:EE:FF",
        "hostname": "DESKTOP-VICTIM",
    });
    let r = run(&item, "oathnet-pro");
    let dev = r
        .entities
        .iter()
        .find(|e| e.kind == EntityKind::DeviceId && e.value == "ABCDEF0123456789")
        .expect("hwid → DeviceId");
    // Context, not leaked PII: the provider tag is present, `breach` is not.
    assert!(dev.tags.iter().any(|t| t == "oathnet-pro"));
    assert!(dev.tags.iter().any(|t| t == "device"));
    assert!(!dev.tags.iter().any(|t| t == "breach"));
    // MacAddress normalises to lowercase colon-separated form.
    assert!(has(&r, EntityKind::MacAddress, "aa:bb:cc:dd:ee:ff"));
    assert!(has(&r, EntityKind::DeviceId, "DESKTOP-VICTIM"));
}

#[test]
fn composes_person_and_org_and_social_handles() {
    let item = json!({
        "first_name": "Jordan",
        "last_name": "Meyer",
        "employer": "Acme Pty Ltd",
        "telegram": "jmeyer",
    });
    let r = run(&item, "see-know");
    assert!(has(&r, EntityKind::Person, "Jordan Meyer"));
    assert!(has(&r, EntityKind::Organisation, "Acme Pty Ltd"));
    // Platform-prefixed Username pivot.
    assert!(has(&r, EntityKind::Username, "telegram:jmeyer"));
    // The composed Person carries the provider source tag.
    let p = r
        .entities
        .iter()
        .find(|e| e.kind == EntityKind::Person)
        .unwrap();
    assert!(p.tags.iter().any(|t| t == "see-know"));
}

#[test]
fn catch_all_surfaces_long_tail_scalars_but_skips_noise() {
    let item = json!({
        "gender": "M",
        "date_birth": "1990-04-02",
        "followers": 1234,
        // Skip-listed structural/metadata noise must NOT become nodes.
        "uid": "internal-row-key",
        "dbname": "SomeBreach",
        "status": "active",
        // Nested objects/arrays are never stringified into a node.
        "dns": {"a": "1.2.3.4"},
    });
    let r = run(&item, "oathnet-pro");
    assert!(has(&r, EntityKind::Other("gender".into()), "M"));
    assert!(has(&r, EntityKind::Other("date_birth".into()), "1990-04-02"));
    assert!(has(&r, EntityKind::Other("followers".into()), "1234"));
    // Raw-field nodes are tagged for filtering.
    assert!(
        r.entities
            .iter()
            .filter(|e| matches!(&e.kind, EntityKind::Other(_)))
            .all(|e| e.tags.iter().any(|t| t == "raw-field"))
    );
    // Noise/plumbing fields are suppressed.
    assert!(!has(&r, EntityKind::Other("uid".into()), "internal-row-key"));
    assert!(!has(&r, EntityKind::Other("dbname".into()), "SomeBreach"));
    assert!(!has(&r, EntityKind::Other("status".into()), "active"));
    assert!(!r.entities.iter().any(|e| matches!(&e.kind, EntityKind::Other(k) if k == "dns")));
}

#[test]
fn sql_null_sentinel_names_are_not_composed_into_a_person() {
    // Real breach/stealer dumps write the SQL NULL `\N` for an absent column —
    // 303 such name fields in one real SeekNow export. It must never compose a
    // "\N \N" (nor a half-real "\N Smith") Person.
    let both_null = run(&json!({"first_name": "\\N", "last_name": "\\N"}), "see-know");
    assert!(!both_null.entities.iter().any(|e| e.kind == EntityKind::Person));
    let half_null = run(&json!({"first_name": "\\N", "last_name": "Smith"}), "see-know");
    assert!(!half_null.entities.iter().any(|e| e.kind == EntityKind::Person));
    // A `\N` in a long-tail scalar field is also dropped, not surfaced as a node.
    let field_null = run(&json!({"city_1": "\\N"}), "see-know");
    assert!(!field_null.entities.iter().any(|e| matches!(&e.kind, EntityKind::Other(_))));
    // Positive control: a genuine name (incl. the real surname "Null") still composes.
    assert!(has(
        &run(&json!({"first_name": "Anna", "last_name": "Null"}), "see-know"),
        EntityKind::Person,
        "Anna Null"
    ));
}

#[test]
fn source_tag_is_parameterised() {
    let item = json!({ "gender": "F" });
    let see = run(&item, "see-know");
    let oath = run(&item, "oathnet-pro");
    assert!(
        see.entities
            .iter()
            .any(|e| e.tags.iter().any(|t| t == "see-know"))
    );
    assert!(
        oath.entities
            .iter()
            .any(|e| e.tags.iter().any(|t| t == "oathnet-pro"))
    );
    // The same field set is surfaced regardless of provider.
    assert_eq!(see.entities.len(), oath.entities.len());
}
