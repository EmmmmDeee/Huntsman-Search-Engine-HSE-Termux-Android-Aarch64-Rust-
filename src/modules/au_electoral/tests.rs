use crate::core::entity::EntityKind;
use crate::core::scan::{Target, TargetKind};

use super::{
    AuElectoral,
    division_map::division_centroid,
    entity::build_electoral_entities,
    parse::{extract_division, strip_electoral_html},
};

use crate::core::module::Module;

#[test]
fn division_centroid_returns_sydney_for_sydney() {
    let info = division_centroid("Sydney").unwrap();
    assert_eq!(info.state, "NSW");
    assert!((info.lat - -33.8688).abs() < 0.01);
    assert!((info.lon - 151.2093).abs() < 0.01);
}

#[test]
fn division_centroid_is_case_insensitive() {
    assert!(division_centroid("MELBOURNE").is_some());
    assert!(division_centroid("brisbane").is_some());
    assert!(division_centroid("Perth").is_some());
}

#[test]
fn division_centroid_returns_none_for_unknown() {
    assert!(division_centroid("Xyzzy").is_none());
    assert!(division_centroid("").is_none());
}

// Table-driven: (html_snippet, expected_division, expected_suburb_contains)
#[test]
fn extract_division_parses_aec_pattern() {
    let cases: &[(&str, &str, Option<&str>)] = &[
        (
            "<p>You are enrolled for the Division of Sydney, NSW.</p>",
            "Sydney",
            None,
        ),
        (
            "<div>enrolled for Melbourne (VIC) 3000 Southbank</div>",
            "Melbourne",
            None,
        ),
        (
            "<span>You are enrolled in the Division of Brisbane</span>",
            "Brisbane",
            None,
        ),
        (
            "Division of North Sydney – electorate details",
            "North Sydney",
            None,
        ),
    ];
    for (html, expected_div, _suburb) in cases {
        let result = extract_division(html);
        assert!(result.is_some(), "expected a division from: {html}");
        let (div, _) = result.unwrap();
        assert!(
            div.to_lowercase().contains(&expected_div.to_lowercase()),
            "expected '{expected_div}' in div '{div}'"
        );
    }
}

#[test]
fn extract_division_returns_none_for_not_enrolled() {
    let cases = &[
        "We could not find an enrolment for this name.",
        "No results found.",
        "<p>Your name was not found on the electoral roll.</p>",
    ];
    for html in cases {
        assert!(
            extract_division(html).is_none(),
            "should not extract from: {html}"
        );
    }
}

#[test]
fn build_electoral_entities_emits_address_and_coords() {
    let ents = build_electoral_entities("Sydney", None, "Haigen Bamford", "s");
    assert!(!ents.is_empty(), "Sydney division must produce entities");
    let kinds: Vec<_> = ents.iter().map(|e| &e.kind).collect();
    assert!(kinds.contains(&&EntityKind::Address), "must emit Address");
    assert!(
        kinds.contains(&&EntityKind::Coordinates),
        "must emit Coordinates"
    );
    // All entities must be AU-tagged.
    for e in &ents {
        assert!(e.has_tag("country:AU"), "entity must carry country:AU");
        assert!(e.has_tag("au-state:NSW"), "Sydney division must be NSW");
    }
}

#[test]
fn build_electoral_entities_unknown_division_emits_address_only() {
    let ents = build_electoral_entities("Xyzzy", None, "Test", "s");
    assert!(
        ents.iter().any(|e| e.kind == EntityKind::Address),
        "must still emit Address for unknown division"
    );
    assert!(
        !ents.iter().any(|e| e.kind == EntityKind::Coordinates),
        "no Coordinates for unknown division (no centroid)"
    );
}

#[test]
fn build_electoral_entities_suburb_hint_overrides_centroid_suburb() {
    let ents = build_electoral_entities("Sydney", Some("Newtown"), "Test", "s");
    let addr = ents.iter().find(|e| e.kind == EntityKind::Address).unwrap();
    assert!(
        addr.value.contains("Newtown"),
        "suburb hint should override centroid suburb: {}",
        addr.value
    );
}

#[test]
fn strip_electoral_html_separates_adjacent_tags() {
    let html = "<div>Division</div><span>of</span><p>Sydney</p>";
    let text = strip_electoral_html(html);
    // Tags must be replaced by spaces so "DivisionofSydney" doesn't occur.
    assert!(
        !text.contains("Divisionof"),
        "tags must inject word breaks: {text}"
    );
    assert!(text.contains("Division"), "content must survive: {text}");
    assert!(text.contains("Sydney"), "content must survive: {text}");
}

#[test]
fn split_name_handles_edge_cases() {
    assert_eq!(super::split_name("Haigen Bamford"), ("Haigen", "Bamford"));
    assert_eq!(super::split_name("Mary Ann Jones"), ("Mary", "Ann Jones"));
    assert_eq!(super::split_name("Cher"), ("Cher", ""));
    assert_eq!(super::split_name("  Anna  Smith  "), ("Anna", "Smith"));
}

#[test]
fn infer_state_from_division_maps_name_fragments() {
    use super::division_map::infer_state_from_division;
    assert_eq!(infer_state_from_division("North Sydney"), Some("NSW"));
    assert_eq!(infer_state_from_division("parramatta"), Some("NSW"));
    assert_eq!(infer_state_from_division("Hunter"), Some("NSW"));
    assert_eq!(infer_state_from_division("Newcastle"), Some("NSW"));
    assert_eq!(infer_state_from_division("MELBOURNE"), Some("VIC"));
    assert_eq!(infer_state_from_division("Geelong"), Some("VIC"));
    assert_eq!(infer_state_from_division("Ballarat"), Some("VIC"));
    assert_eq!(infer_state_from_division("Brisbane"), Some("QLD"));
    assert_eq!(infer_state_from_division("Gold Coast"), Some("QLD"));
    assert_eq!(infer_state_from_division("Perth"), Some("WA"));
    assert_eq!(infer_state_from_division("Fremantle"), Some("WA"));
    assert_eq!(infer_state_from_division("Adelaide"), Some("SA"));
    assert_eq!(infer_state_from_division("Hobart"), Some("TAS"));
    assert_eq!(infer_state_from_division("Launceston"), Some("TAS"));
    assert_eq!(infer_state_from_division("Canberra"), Some("ACT"));
    assert_eq!(infer_state_from_division("Darwin"), Some("NT"));
    assert_eq!(infer_state_from_division("Wentworth"), None);
}

#[test]
fn module_metadata_is_valid() {
    let m = AuElectoral;
    assert_eq!(m.name(), "au_electoral");
    assert!(m.accepts(&Target::new(TargetKind::FullName, "Haigen Bamford")));
    assert!(!m.accepts(&Target::new(TargetKind::Email, "x@example.com")));
    assert!(m.attack_techniques().contains(&"T1591.001"));
    assert!(m.attack_techniques().contains(&"T1589.003"));
}

#[test]
fn extract_division_no_panic_on_multibyte_before_marker() {
    // Regression (PROBLEM_TREE T0.1): a multibyte uppercase char before the
    // marker shifted a `to_lowercase()`-derived offset onto a non-char-boundary
    // in the original text → `str` slice panic. `find_ascii_ci` is boundary-safe.
    let html = "<p>İstanbul — Division of Sydney.</p>";
    let (div, _) = extract_division(html).expect("division parses without panic");
    assert!(div.starts_with("Sydney"), "got {div:?}");
}

/// Adversarial-input coverage (PROBLEM_TREE T2.7): `au_electoral` was one of
/// the two modules (alongside `au_property`) still missing the never-panics
/// proptest already applied to `au_people`'s HTML parsers. `html` is the
/// untrusted, scraped AEC/state-EC response; a plain proptest string covers
/// it directly since `extract_division` takes no seed name.
mod prop {
    use proptest::prelude::*;

    use super::extract_division;

    proptest! {
        #[test]
        fn extract_division_never_panics(s in ".{0,256}") {
            let _ = extract_division(&s);
        }
    }
}
