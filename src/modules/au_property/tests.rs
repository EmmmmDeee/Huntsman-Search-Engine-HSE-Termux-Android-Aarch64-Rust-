use super::parse::{
    PropertyRecord, dedup_entities, extract_postcode, extract_state, name_matches,
    parse_nsw_response, parse_qld_response, parse_vic_response, record_to_entities,
    state_capital_coords, strip_html,
};
use super::{AuProperty, all_legs_unreachable};
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
fn name_matches_requires_whole_word_not_substring() {
    // "le" is a SUBSTRING of "alexander" but not a whole word. The old substring
    // gate returned true here, which — now that a match stamps `owner` +
    // `exact-name-match` — would fabricate a subject↔property link for an
    // AU-common short surname. Whole-word matching must reject it.
    assert!(
        !name_matches("Alexander Smith 5 Oak St NSW 2000", "Le Smith"),
        "a short surname appearing only as a substring must NOT match"
    );
    assert!(name_matches("Le Smith 5 Oak St NSW 2000", "Le Smith"));
}

#[test]
fn record_to_entities_stamps_owner_and_exact_name_match() {
    // The name-matched owner must be stamped as an `owner` attr and both entities
    // tagged `exact-name-match`, so the relation layer links the subject Person
    // to their registered property instead of leaving it a graph orphan.
    let rec = PropertyRecord {
        owner_name: "Jordan Avery".into(),
        suburb: "Sydney".into(),
        state: "NSW",
        postcode: Some("2000".into()),
    };
    let ents = record_to_entities(&rec, "s");
    let addr = ents
        .iter()
        .find(|e| e.kind == EntityKind::Address)
        .expect("must emit Address");
    assert_eq!(
        addr.evidence[0].attributes.get("owner").map(String::as_str),
        Some("Jordan Avery"),
        "owner attr must carry the matched name so derive_residency can bind it"
    );
    assert!(
        ents.iter().all(|e| e.has_tag("exact-name-match")),
        "both the Address and Coordinates must be tagged exact-name-match"
    );
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
fn parse_vic_response_extracts_vic_record() {
    // Mirror of the NSW test: a VIC line yields a VIC-stated record.
    let html = "<tr><td>BAMFORD HAIGEN</td><td>FITZROY</td><td>VIC</td><td>3065</td></tr>";
    let recs = parse_vic_response(html, "Haigen Bamford");
    assert!(!recs.is_empty(), "must extract a record when name matches");
    assert_eq!(recs[0].state, "VIC");
    assert_eq!(recs[0].postcode.as_deref(), Some("3065"));
}

#[test]
fn parse_vic_response_default_state_needs_no_state_token_yields_nothing() {
    // The VIC default only labels the record's state; the suburb extractor still
    // requires the state token in the line, so a token-less line is dropped.
    let html = "<tr><td>BAMFORD HAIGEN</td><td>FITZROY</td><td>3065</td></tr>";
    assert!(parse_vic_response(html, "Haigen Bamford").is_empty());
}

#[test]
fn parse_vic_response_ignores_non_matching_rows() {
    let html = "<tr><td>SMITH JOHN</td><td>FITZROY</td><td>VIC</td><td>3065</td></tr>";
    let recs = parse_vic_response(html, "Haigen Bamford");
    assert!(recs.is_empty(), "non-matching rows must be ignored");
}

#[test]
fn parse_qld_response_extracts_qld_record() {
    let html = "<tr><td>BAMFORD HAIGEN</td><td>TOOWONG</td><td>QLD</td><td>4066</td></tr>";
    let recs = parse_qld_response(html, "Haigen Bamford");
    assert!(!recs.is_empty(), "must extract a record when name matches");
    assert_eq!(recs[0].state, "QLD");
    assert_eq!(recs[0].postcode.as_deref(), Some("4066"));
}

#[test]
fn parse_qld_response_explicit_state_overrides_default() {
    // An explicit NSW token in a QLD-portal line wins over the QLD default.
    let html = "<tr><td>BAMFORD HAIGEN</td><td>SURRY HILLS</td><td>NSW</td><td>2010</td></tr>";
    let recs = parse_qld_response(html, "Haigen Bamford");
    assert!(!recs.is_empty());
    assert_eq!(recs[0].state, "NSW");
}

#[test]
fn state_capital_coords_covers_eight_states_and_rejects_others() {
    for (code, lat, lon) in [
        ("NSW", -33.8688, 151.2093),
        ("VIC", -37.8136, 144.9631),
        ("QLD", -27.4698, 153.0251),
        ("SA", -34.9285, 138.6007),
        ("WA", -31.9505, 115.8605),
        ("TAS", -42.8821, 147.3272),
        ("ACT", -35.2809, 149.1300),
        ("NT", -12.4634, 130.8456),
    ] {
        let (got_lat, got_lon) = state_capital_coords(code).expect("should succeed");
        assert!((got_lat - lat).abs() < 1e-9, "{code} lat");
        assert!((got_lon - lon).abs() < 1e-9, "{code} lon");
    }
    assert!(state_capital_coords("XYZ").is_none());
    assert!(state_capital_coords("").is_none());
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
    let addr = ents.iter().find(|e| e.kind == EntityKind::Address).expect("should succeed");
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

/// Adversarial-input coverage (PROBLEM_TREE T2.7): `au_property` was one of
/// the two modules (alongside `au_electoral`) still missing the never-panics
/// proptest already applied to `au_people`'s HTML parsers. `text` is the
/// untrusted, scraped portal response; `full_name` is held to the project's
/// synthetic placeholder since it originates from the operator's own typed
/// scan target, not third-party bytes.
mod prop {
    use proptest::prelude::*;

    use super::{parse_nsw_response, parse_qld_response, parse_vic_response};

    proptest! {
        #[test]
        fn parse_nsw_response_never_panics(s in ".{0,256}") {
            let _ = parse_nsw_response(&s, "Jordan Avery");
        }

        #[test]
        fn parse_vic_response_never_panics(s in ".{0,256}") {
            let _ = parse_vic_response(&s, "Jordan Avery");
        }

        #[test]
        fn parse_qld_response_never_panics(s in ".{0,256}") {
            let _ = parse_qld_response(&s, "Jordan Avery");
        }
    }
}

// ── `all_legs_unreachable` — the "every portal is down" vs "genuinely no
// records" distinction (2026-07-14 live finding: NSW/VIC/QLD all now 404). ──

#[test]
fn all_legs_unreachable_true_when_every_leg_failed_and_nothing_found() {
    // Regression: this is the REAL state confirmed live for NSW ELVIS, VIC
    // MapShare WFS, and QLD titles search on 2026-07-14 — all three return
    // 404 from live, reachable government servers. Before this fix,
    // `process()` swallowed this into a silent `Ok(empty)`, indistinguishable
    // from "this person genuinely has no property record."
    assert!(all_legs_unreachable(false, false));
}

#[test]
fn all_legs_unreachable_false_when_a_leg_responded_even_with_no_match() {
    // A portal answered (any_leg_http_ok) but this particular name had no
    // record there — a genuinely empty, honest result, not a failure.
    assert!(!all_legs_unreachable(true, false));
}

#[test]
fn all_legs_unreachable_false_when_entities_were_found() {
    // Found something, regardless of the HTTP-status bookkeeping — never
    // report a hard failure over a real result.
    assert!(!all_legs_unreachable(false, true));
    assert!(!all_legs_unreachable(true, true));
}
