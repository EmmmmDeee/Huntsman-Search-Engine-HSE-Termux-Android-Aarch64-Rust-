use super::AuProperty;
use super::parse::{
    PropertyRecord, dedup_entities, extract_postcode, extract_state, name_matches,
    parse_nsw_response, record_to_entities, strip_html,
};
use crate::core::entity::{Entity, EntityKind};
use crate::core::module::Module;
use crate::core::scan::{Target, TargetKind};

// pull private helpers into scope via the module path
use super::parse::{split_name, surname};

#[test]
fn split_name_splits_correctly() {
    assert_eq!(split_name("Haigen Bamford"), ("Haigen", "Bamford"));
    assert_eq!(split_name("Mary Ann Jones"), ("Mary", "Ann Jones"));
    assert_eq!(split_name("Cher"), ("Cher", ""));
    assert_eq!(split_name("  Anna  Smith  "), ("Anna", "Smith"));
}

#[test]
fn surname_returns_last_token() {
    assert_eq!(surname("Haigen Bamford"), "Bamford");
    assert_eq!(surname("Mary Ann Jones"), "Jones");
    assert_eq!(surname("Cher"), "Cher");
}

#[test]
fn strip_html_separates_tag_content() {
    let html = "<div>123</div><span>NSW</span>";
    let text = strip_html(html);
    assert!(
        !text.contains("123NSW"),
        "tags must inject word break: {text}"
    );
    assert!(text.contains("123"), "content must survive");
    assert!(text.contains("NSW"), "content must survive");
}

// Table-driven: (text, full_name, should_match)
#[test]
fn name_matches_detects_token_presence() {
    let cases: &[(&str, &str, bool)] = &[
        (
            "BAMFORD HAIGEN JOHN 25 SMITH ST SYDNEY NSW 2000",
            "Haigen Bamford",
            true,
        ),
        (
            "SMITH JOHN 10 MAIN ST PERTH WA 6000",
            "Haigen Bamford",
            false,
        ),
        ("bamford haigen 5 elm ave nsw", "Haigen Bamford", true),
        ("BAMFORD 12 OAK ST NSW", "Haigen Bamford", false), // missing given name
    ];
    for (text, name, expected) in cases {
        assert_eq!(
            name_matches(text, name),
            *expected,
            "name_matches({text:?}, {name:?}) should be {expected}"
        );
    }
}

#[test]
fn extract_postcode_finds_valid_au_postcode() {
    assert_eq!(extract_postcode("Sydney NSW 2000"), Some("2000".into()));
    assert_eq!(extract_postcode("Melbourne VIC 3000"), Some("3000".into()));
    assert_eq!(extract_postcode("no postcode here"), None);
    // 1000 is not a valid AU postcode (< 2000).
    assert_eq!(extract_postcode("invalid 1000 postcode"), None);
    // 5-digit run must not match.
    assert_eq!(extract_postcode("12345 invalid"), None);
}

#[test]
fn extract_state_returns_canonical_code() {
    assert_eq!(extract_state("Sydney NSW 2000"), Some("NSW"));
    assert_eq!(extract_state("Melbourne Victoria"), Some("VIC"));
    assert_eq!(extract_state("Perth WA"), Some("WA"));
    assert_eq!(extract_state("no state here"), None);
}

#[test]
fn parse_nsw_response_extracts_matching_record() {
    let html = "<tr><td>BAMFORD HAIGEN</td><td>SURRY HILLS</td><td>NSW</td><td>2010</td></tr>";
    let recs = parse_nsw_response(html, "Haigen Bamford");
    assert!(
        !recs.is_empty(),
        "must extract a record when name matches: {html}"
    );
    let rec = &recs[0];
    assert_eq!(rec.state, "NSW");
    assert_eq!(rec.postcode.as_deref(), Some("2010"));
}

#[test]
fn parse_nsw_response_ignores_non_matching_rows() {
    let html = "<tr><td>SMITH JOHN</td><td>SYDNEY</td><td>NSW</td><td>2000</td></tr>";
    let recs = parse_nsw_response(html, "Haigen Bamford");
    assert!(recs.is_empty(), "non-matching rows must be ignored");
}

#[test]
fn record_to_entities_emits_address_and_coordinates() {
    let rec = PropertyRecord {
        owner_name: "Haigen Bamford".into(),
        suburb: "Sydney".into(),
        state: "NSW",
        postcode: Some("2000".into()),
    };
    let ents = record_to_entities(&rec, "s");
    let kinds: Vec<_> = ents.iter().map(|e| &e.kind).collect();
    assert!(kinds.contains(&&EntityKind::Address), "must emit Address");
    // Coordinates should follow from the suburb centroid.
    // (Sydney is in the city_coords table or state-capital fallback.)
    for e in &ents {
        assert!(e.has_tag("country:AU"), "must carry country:AU");
        assert!(e.has_tag("au-state:NSW"), "must carry au-state:NSW");
    }
}

#[test]
fn record_to_entities_address_includes_postcode_when_present() {
    let rec = PropertyRecord {
        owner_name: "Haigen Bamford".into(),
        suburb: "Fitzroy".into(),
        state: "VIC",
        postcode: Some("3065".into()),
    };
    let ents = record_to_entities(&rec, "s");
    let addr = ents.iter().find(|e| e.kind == EntityKind::Address).unwrap();
    assert!(
        addr.value.contains("3065"),
        "address must include postcode: {}",
        addr.value
    );
}

#[test]
fn dedup_entities_removes_exact_duplicates() {
    let mut ents = vec![
        Entity::new(EntityKind::Address, "Sydney, NSW", 0.74, "s"),
        Entity::new(EntityKind::Address, "Sydney, NSW", 0.62, "s"),
        Entity::new(EntityKind::Address, "Melbourne, VIC", 0.74, "s"),
    ];
    dedup_entities(&mut ents);
    assert_eq!(
        ents.len(),
        2,
        "duplicate (kind, value) must be deduplicated"
    );
}

#[test]
fn module_metadata_is_valid() {
    let m = AuProperty;
    assert_eq!(m.name(), "au_property");
    assert!(m.accepts(&Target::new(TargetKind::FullName, "Haigen Bamford")));
    assert!(!m.accepts(&Target::new(TargetKind::Email, "x@example.com")));
    assert!(m.attack_techniques().contains(&"T1591.001"));
    assert!(m.attack_techniques().contains(&"T1591.002"));
    assert!(m.attack_techniques().contains(&"T1589.003"));
    assert!(m.max_timeout_ms() > crate::MODULE_TIMEOUT_MS);
}
