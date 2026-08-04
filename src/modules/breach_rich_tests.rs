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
        .expect("should succeed");
    assert!(p.tags.iter().any(|t| t == "see-know"));
}

#[test]
fn mines_github_tiktok_reddit_handles_as_username_pivots() {
    let item = json!({
        "github": "octocat",
        "tiktok": "charlidamelio",
        "reddit": "spez",
    });
    let r = run(&item, "see-know");
    // First-class platform-prefixed Username pivots (resolvable by the
    // github_user/reddit_user/… modules), not opaque catch-all nodes.
    assert!(has(&r, EntityKind::Username, "github:octocat"));
    assert!(has(&r, EntityKind::Username, "tiktok:charlidamelio"));
    assert!(has(&r, EntityKind::Username, "reddit:spez"));
    // And NOT duplicated as an unclassified Other("github") junk node.
    assert!(
        !r.entities
            .iter()
            .any(|e| matches!(&e.kind, EntityKind::Other(k) if k == "github")),
        "github must be a Username pivot, not a catch-all Other node"
    );
}

#[test]
fn mines_bio_for_alternate_contacts() {
    let item = json!({
        "username": "u",
        "bio": "book me at alt.contact@example.com or call +1 415 555 0132",
    });
    let r = run(&item, "see-know");
    let email = r
        .entities
        .iter()
        .find(|e| e.kind == EntityKind::Email && e.value == "alt.contact@example.com")
        .expect("an email embedded in the bio must be mined as an Email lead");
    assert!(email.tags.iter().any(|t| t == "bio-mined"));
    assert!(
        r.entities.iter().any(|e| e.kind == EntityKind::Phone),
        "a phone embedded in the bio must be mined as a Phone lead"
    );
    // The raw bio must NOT also appear as an unclassified Other("bio") node.
    assert!(
        !r.entities
            .iter()
            .any(|e| matches!(&e.kind, EntityKind::Other(k) if k == "bio")),
        "bio is mined, not emitted verbatim as a catch-all node"
    );
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
fn username_derived_names_are_not_composed_into_a_person() {
    // Breach dumps store `full_name = "{username} {username}"` when only a handle
    // is known; the shared first+last composer must not mint a Person from a
    // doubled username or a hyphen+digit slug (observed live: a
    // Person("rhino-ryno23 rhino-ryno23") expanded into a large child scan).
    let doubled = run(
        &json!({"first_name": "rhino-ryno23", "last_name": "rhino-ryno23"}),
        "see-know",
    );
    assert!(!doubled.entities.iter().any(|e| e.kind == EntityKind::Person));
    let half_slug = run(
        &json!({"first_name": "rhino-ryno23", "last_name": "Smith"}),
        "see-know",
    );
    assert!(!half_slug.entities.iter().any(|e| e.kind == EntityKind::Person));
    // Positive control: a genuine hyphenated surname (no digit) still composes.
    assert!(has(
        &run(&json!({"first_name": "Mary", "last_name": "Smith-Jones"}), "see-know"),
        EntityKind::Person,
        "Mary Smith-Jones"
    ));
}

#[test]
fn hardware_serials_become_deviceid_without_duplicate_other_nodes() {
    // A globally-unique IMEI / hardware serial is a strong single-device anchor;
    // it must be typed as DeviceId (so AU-106 can link on it), and — because it
    // is also skip-listed — must NOT additionally leak a duplicate `Other` node
    // from the catch-all's distinct dedup namespace.
    let item = json!({
        "imei": "359881234567890",
        "serial": "C02ABCXYZ123",
        "serial_number": "SN-998877",
        "email": "a@x.com",
    });
    let r = run(&item, "oathnet-pro");
    for v in ["359881234567890", "C02ABCXYZ123", "SN-998877"] {
        assert!(has(&r, EntityKind::DeviceId, v), "{v} → DeviceId");
    }
    assert!(
        !r.entities
            .iter()
            .any(|e| matches!(&e.kind, EntityKind::Other(k) if k == "imei" || k == "serial" || k == "serial_number")),
        "a serial typed as DeviceId must not also emit a duplicate Other node"
    );
    // DeviceId carries the device/stealer tags AU-106's siblings expect.
    let dev = r
        .entities
        .iter()
        .find(|e| e.kind == EntityKind::DeviceId && e.value == "359881234567890")
        .expect("should succeed");
    assert!(dev.tags.iter().any(|t| t == "device"));
}

#[test]
fn bios_placeholder_serials_and_trivial_macs_are_not_typed_as_devices() {
    // Stealer logs capture SMBIOS/dmidecode placeholders verbatim from boards
    // whose OEM never set a real serial — the SAME string recurs across thousands
    // of UNRELATED machines, so it must never become a DeviceId (which AU-106
    // would then use to falsely link two strangers as one machine). Likewise a
    // trivial all-zero / broadcast MAC is not a real device anchor.
    for placeholder in [
        "To Be Filled By O.E.M.",
        "System Serial Number",
        "Default string",
        "Not Specified",
        "0000000000",
        "Default",
    ] {
        let r = run(&json!({ "serial": placeholder }), "oathnet-pro");
        assert!(
            !r.entities.iter().any(|e| e.kind == EntityKind::DeviceId),
            "placeholder serial {placeholder:?} must not become a DeviceId"
        );
    }
    // Trivial MACs.
    for mac in ["00:00:00:00:00:00", "FF:FF:FF:FF:FF:FF"] {
        let r = run(&json!({ "bssid": mac }), "oathnet-pro");
        assert!(
            !r.entities.iter().any(|e| e.kind == EntityKind::MacAddress),
            "trivial MAC {mac:?} must not become a device MacAddress"
        );
    }
    // Positive control: a real serial / MAC still types as a device.
    let real = run(
        &json!({ "serial": "C02ABCXYZ123", "bssid": "AA:BB:CC:11:22:33" }),
        "oathnet-pro",
    );
    assert!(has(&real, EntityKind::DeviceId, "C02ABCXYZ123"));
    assert!(
        real.entities
            .iter()
            .any(|e| e.kind == EntityKind::MacAddress)
    );
}

#[test]
fn absence_and_redaction_markers_never_mint_typed_nodes() {
    // A record where every value-bearing field is an absence marker: the SQL
    // NULL `\N` (303 such fields in one real export) or a provider redaction
    // placeholder. NONE of these is data — they must mint zero graph nodes, or
    // two records each carrying `\N`/`REDACTED` in `company`/`city` would yield
    // identical `Organisation("\N")`/`Address("\N")` nodes and falsely co-occur.
    let item = json!({
        "company": "\\N",
        "employer": "REDACTED",
        "organization": "UPGRADE_TO_SEE_FULL",
        "telegram": "\\N",
        "skype": "UPGRADE_TO_SEE",
        "city": "\\N",
        "state": "REDACTED",
        "street": "UPGRADE_TO_SEE_FULL",
        "gender": "REDACTED",
        "hwid": "REDACTED",
    });
    let r = run(&item, "see-know");
    let by_kind = |k: &dyn Fn(&EntityKind) -> bool| r.entities.iter().filter(|e| k(&e.kind)).count();
    assert_eq!(
        by_kind(&|k| matches!(k, EntityKind::Organisation)),
        0,
        "redaction/NULL markers must not become Organisation nodes"
    );
    assert_eq!(
        by_kind(&|k| matches!(k, EntityKind::Address)),
        0,
        "redaction/NULL markers must not become Address nodes"
    );
    assert_eq!(
        by_kind(&|k| matches!(k, EntityKind::Username)),
        0,
        "redaction/NULL markers must not become Username nodes"
    );
    assert_eq!(
        by_kind(&|k| matches!(k, EntityKind::DeviceId)),
        0,
        "a REDACTED hwid must not become a DeviceId node"
    );
    assert_eq!(
        by_kind(&|k| matches!(k, EntityKind::Other(_))),
        0,
        "a REDACTED long-tail field must not become an Other node"
    );
    // Positive control: real values in the same fields DO surface.
    let real = run(
        &json!({"company": "Acme Pty Ltd", "city": "Brisbane", "telegram": "alice"}),
        "see-know",
    );
    assert!(has(&real, EntityKind::Organisation, "Acme Pty Ltd"));
    assert!(has(&real, EntityKind::Username, "telegram:alice"));
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

#[test]
fn saved_wifi_names_type_as_ssid_so_the_geo_pivot_can_run() {
    // A stealer log's saved network name is a locatable identifier: `wigle`
    // accepts `TargetKind::Ssid` and resolves a unique name to GPS points. Left
    // as an `Other("ssid")` node it is a dead end, because only a typed kind
    // maps to a `TargetKind`.
    for key in ["ssid", "wifi_ssid", "wifi_name", "network_name"] {
        let r = run(&json!({ key: "Stewart-Family-5G" }), "oathnet-pro");
        assert!(
            has(&r, EntityKind::Ssid, "Stewart-Family-5G"),
            "{key} must type as Ssid so the WiGLE pivot can dispatch"
        );
        // Infrastructure/context, not leaked PII — same class as the BSSID it
        // pairs with, so `breach` must NOT be applied.
        let e = r
            .entities
            .iter()
            .find(|e| e.kind == EntityKind::Ssid)
            .expect("ssid entity");
        assert!(e.tags.iter().any(|t| t == "wifi-network"), "{key}");
        assert!(e.tags.iter().any(|t| t == "oathnet-pro"), "{key}");
        assert!(!e.tags.iter().any(|t| t == "breach"), "{key}");
        // Typed, so the catch-all must not ALSO mint a duplicate raw-field node.
        assert!(
            !r.entities
                .iter()
                .any(|e| matches!(&e.kind, EntityKind::Other(k) if k == key)),
            "{key} must not be duplicated as an Other() node"
        );
    }
}

#[test]
fn ssid_case_is_preserved_because_802_11_names_are_case_sensitive() {
    // Two networks differing only in case are genuinely different networks, so
    // the dedup key must not fold case (`core::entity` excludes `Ssid` from
    // identity folding for the same reason).
    let r = run(&json!({ "ssid": "HomeNet", "wifi_ssid": "homenet" }), "see-know");
    assert!(has(&r, EntityKind::Ssid, "HomeNet"));
    assert!(has(&r, EntityKind::Ssid, "homenet"));
}

#[test]
fn over_length_and_absent_ssid_values_are_never_silently_dropped() {
    // Longer than the 802.11 32-octet limit: not an SSID, so it must not be
    // typed as one — but it is real recorded data, so it must still surface.
    let long = "X".repeat(64);
    let r = run(&json!({ "ssid": long.clone() }), "oathnet-pro");
    assert!(
        !r.entities.iter().any(|e| e.kind == EntityKind::Ssid),
        "an over-length value must not be typed as an SSID"
    );
    assert!(
        r.entities
            .iter()
            .any(|e| matches!(&e.kind, EntityKind::Other(k) if k == "ssid") && e.value == long),
        "an over-length value must still be surfaced, never dropped"
    );
    // Exactly at the limit is a legal SSID.
    let at_limit = "Y".repeat(MAX_SSID_OCTETS);
    let r = run(&json!({ "ssid": at_limit.clone() }), "oathnet-pro");
    assert!(has(&r, EntityKind::Ssid, &at_limit));
    // An absence/redaction marker must never mint a node of either kind.
    let r = run(&json!({ "ssid": "\\N", "wifi_name": "REDACTED" }), "see-know");
    assert!(
        !r.entities
            .iter()
            .any(|e| e.kind == EntityKind::Ssid
                || matches!(&e.kind, EntityKind::Other(k) if k == "ssid" || k == "wifi_name")),
        "absence markers must not mint Ssid or Other nodes"
    );
}
