use super::*;

const SCAN: &str = "scan-auspost";

fn locality(loc: Option<&str>, state: Option<&str>, postcode: Option<&str>) -> AusPostAddress {
    AusPostAddress {
        location: loc.map(str::to_string),
        state: state.map(str::to_string),
        postcode: postcode.map(str::to_string),
    }
}

fn resp(localities: Vec<AusPostAddress>) -> AusPostResponse {
    AusPostResponse { localities }
}

#[test]
fn a_full_locality_is_combined_into_one_address_entity() {
    let out = build_entities(
        &resp(vec![locality(Some("Melbourne"), Some("VIC"), Some("3000"))]),
        SCAN,
    );
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].kind, EntityKind::Address);
    assert_eq!(out[0].value, "Melbourne VIC 3000");
}

#[test]
fn confidence_matches_the_source_calibration() {
    // The source module's ADDRESS_CONFIDENCE = 0.85 — an authoritative
    // government postal registry — carried over unchanged.
    let out = build_entities(
        &resp(vec![locality(Some("Sydney"), Some("NSW"), Some("2000"))]),
        SCAN,
    );
    assert!((out[0].confidence - confidence::HIGH_PLUSPLUS_PLUS).abs() < 1e-9);
    assert!((out[0].confidence - 0.85).abs() < 1e-9);
}

#[test]
fn no_coordinates_entity_is_ever_produced() {
    // Regression pinned from the source module's own test: AusPost's
    // postcode-search endpoint carries no lat/lon field, so this module must
    // never synthesise one — matching the source's assertion that a
    // Geolocation entity is never emitted, translated to this crate's kinds.
    let out = build_entities(
        &resp(vec![locality(Some("Melbourne"), Some("VIC"), Some("3000"))]),
        SCAN,
    );
    assert!(
        !out.iter().any(|e| e.kind == EntityKind::Coordinates),
        "AusPost has no coordinate data to report"
    );
    assert!(out.iter().all(|e| e.kind == EntityKind::Address));
}

#[test]
fn a_locality_with_no_components_is_skipped() {
    let out = build_entities(&resp(vec![locality(None, None, None)]), SCAN);
    assert!(out.is_empty());
}

#[test]
fn empty_localities_list_yields_nothing() {
    let out = build_entities(&resp(vec![]), SCAN);
    assert!(out.is_empty());
}

#[test]
fn a_partial_locality_still_emits_whatever_components_are_present() {
    // Only a postcode, no locality/state text — still a real, reportable
    // marker, not discarded for being incomplete.
    let out = build_entities(&resp(vec![locality(None, None, Some("3000"))]), SCAN);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].value, "3000");
}

#[test]
fn blank_components_are_treated_as_absent() {
    // A component present but whitespace-only must not contribute a stray
    // space to the combined marker or count as "has content".
    let out = build_entities(
        &resp(vec![locality(Some("  "), Some("VIC"), Some(""))]),
        SCAN,
    );
    assert_eq!(out.len(), 1);
    assert_eq!(
        out[0].value, "VIC",
        "blank components excluded from the join"
    );
}

#[test]
fn dedup_across_localities_is_case_insensitive() {
    // Mirrors the source module's `push_deduped`, whose dedup key is
    // `value.to_lowercase()`: two localities that read the same modulo case
    // describe the SAME place and must collapse to one entity — the
    // opposite judgement from `bitcoin`'s case-sensitive base58 dedup, where
    // case is data.
    let out = build_entities(
        &resp(vec![
            locality(Some("Melbourne"), Some("VIC"), Some("3000")),
            locality(Some("melbourne"), Some("vic"), Some("3000")),
        ]),
        SCAN,
    );
    assert_eq!(
        out.len(),
        1,
        "case-differing duplicates must collapse to one entity: {:?}",
        out.iter().map(|e| &e.value).collect::<Vec<_>>()
    );
}

#[test]
fn distinct_localities_are_not_deduplicated() {
    let out = build_entities(
        &resp(vec![
            locality(Some("Melbourne"), Some("VIC"), Some("3000")),
            locality(Some("Melbourne"), Some("VIC"), Some("3004")),
        ]),
        SCAN,
    );
    assert_eq!(out.len(), 2);
}

#[test]
fn every_locality_carries_evidence_attributes_for_the_components_present() {
    let out = build_entities(
        &resp(vec![locality(Some("Perth"), Some("WA"), Some("6000"))]),
        SCAN,
    );
    let ev = out[0].evidence.first().expect("evidence attached");
    assert_eq!(ev.source, "auspost");
    assert_eq!(
        ev.attributes.get("locality").map(String::as_str),
        Some("Perth")
    );
    assert_eq!(ev.attributes.get("state").map(String::as_str), Some("WA"));
    assert_eq!(
        ev.attributes.get("postcode").map(String::as_str),
        Some("6000")
    );
}

#[test]
fn projection_is_deterministic() {
    let r = resp(vec![
        locality(Some("Hobart"), Some("TAS"), Some("7000")),
        locality(Some("Launceston"), Some("TAS"), Some("7250")),
    ]);
    let a = build_entities(&r, SCAN);
    let b = build_entities(&r, SCAN);
    let va: Vec<_> = a.iter().map(|e| &e.value).collect();
    let vb: Vec<_> = b.iter().map(|e| &e.value).collect();
    assert_eq!(va, vb, "identical input must yield an identical projection");
}

#[test]
fn deserializes_a_flat_multi_locality_response() {
    // `AusPostResponse`/`AusPostAddress` are ported verbatim from the source
    // module's own struct shape — a flat `{"localities":[{...}, ...]}` array
    // of `{locality, state, postcode}` objects. This pins that shape against
    // drift; it is NOT independently verified against the live AusPost API
    // from this port (see the port's `self_check_notes`).
    let flat = r#"{"localities":[
        {"locality":"MELBOURNE","state":"VIC","postcode":"3000"},
        {"locality":"MELBOURNE","state":"VIC","postcode":"3004"}
    ]}"#;
    let parsed: AusPostResponse = serde_json::from_str(flat).expect("flat shape parses");
    assert_eq!(parsed.localities.len(), 2);
    let out = build_entities(&parsed, SCAN);
    assert_eq!(out.len(), 2);
}

#[test]
fn missing_localities_key_defaults_to_empty() {
    let parsed: AusPostResponse = serde_json::from_str("{}").expect("missing key defaults");
    assert!(parsed.localities.is_empty());
    assert!(build_entities(&parsed, SCAN).is_empty());
}

#[test]
fn module_metadata_is_coherent() {
    let m = AusPost;
    assert_eq!(m.name(), "auspost");
    assert_eq!(m.priority(), 48);
    assert_eq!(m.cost(), ModuleCost::KeyGated);
    assert!(!m.description().is_empty());
    assert!(
        m.produces().contains(&EntityKind::Address),
        "produces() must declare what build_entities actually emits"
    );
}

#[test]
fn accepts_coordinates_targets_only() {
    // The source module gates on `EntityType::Geolocation`, which the source
    // repository's own model confirms is a coordinate-pair type (verified
    // against `ipinfo`/`wigle`, which populate it with literal "lat,lon"
    // strings) — this crate's exact analogue is `TargetKind::Coordinates`,
    // not `Address`. See the module doc comment for the full trail.
    let m = AusPost;
    assert!(m.accepts(&Target::new(TargetKind::Coordinates, "-37.8,144.9")));
    assert!(!m.accepts(&Target::new(TargetKind::Address, "3000")));
    assert!(!m.accepts(&Target::new(TargetKind::Domain, "example.com")));
}

#[test]
fn empty_value_is_declined() {
    assert!(!AusPost::handles_value(""));
    assert!(!AusPost::handles_value("   "));
    assert!(AusPost::handles_value("3000"));
}

// ── Backlog #5: the wire shape is the PAC envelope, not a bare list ──────────

/// The shape Australia Post documents for `postcode/search.json` (multiple
/// matches): the `localities.locality` array, `location` for the name, a
/// numeric postcode. Before this fix the struct wanted a top-level array with a
/// `locality` string field and a string postcode — so this, the ordinary
/// answer, failed to decode and the module never produced anything.
#[test]
fn the_documented_multi_match_envelope_decodes() {
    let raw = r#"{"localities":{"locality":[
        {"category":"Delivery Area","id":8367,"latitude":-33.86,"location":"SYDNEY","longitude":151.2,"postcode":2000,"state":"NSW"},
        {"category":"Post Office Boxes","id":8368,"latitude":-33.86,"location":"SYDNEY SOUTH","longitude":151.2,"postcode":1235,"state":"NSW"}
    ]}}"#;
    let resp: AusPostResponse = serde_json::from_str(raw).expect("the documented envelope decodes");
    assert_eq!(resp.localities.len(), 2);
    assert_eq!(resp.localities[0].location.as_deref(), Some("SYDNEY"));
    assert_eq!(
        resp.localities[0].postcode.as_deref(),
        Some("2000"),
        "a numeric postcode reads as text"
    );
    let out = build_entities(&resp, SCAN);
    assert_eq!(out.len(), 2);
    assert_eq!(out[0].value, "SYDNEY NSW 2000");
}

/// XML-derived quirk: exactly one match arrives as an object, not a
/// one-element array.
#[test]
fn a_single_match_arrives_as_an_object_and_decodes() {
    let raw = r#"{"localities":{"locality":{"category":"Delivery Area","id":8367,"latitude":-33.86,"location":"SYDNEY","longitude":151.2,"postcode":2000,"state":"NSW"}}}"#;
    let resp: AusPostResponse = serde_json::from_str(raw).expect("a lone locality object decodes");
    assert_eq!(resp.localities.len(), 1);
    assert_eq!(build_entities(&resp, SCAN)[0].value, "SYDNEY NSW 2000");
}

/// No match at all is `"localities": ""` — a string, which must read as an
/// empty list (the clean negative), not as a decode failure.
#[test]
fn no_match_is_an_empty_string_and_reads_as_empty() {
    let resp: AusPostResponse =
        serde_json::from_str(r#"{"localities":""}"#).expect("the empty-string no-match decodes");
    assert!(resp.localities.is_empty());
    assert!(build_entities(&resp, SCAN).is_empty());
}

/// A wrapper that is an object but not the PAC shape is a decode failure — a
/// shape drift must surface, not read as "no localities".
#[test]
fn an_unrecognised_wrapper_is_a_decode_failure_not_an_empty_answer() {
    assert!(serde_json::from_str::<AusPostResponse>(r#"{"localities":{"results":[]}}"#).is_err());
    assert!(serde_json::from_str::<AusPostResponse>(r#"{"localities":42}"#).is_err());
}

/// The pre-fix spelling (a bare list with `locality` / string postcode) still
/// decodes, so any captured fixture in that form keeps reading.
#[test]
fn the_pre_fix_bare_list_spelling_still_decodes() {
    let resp: AusPostResponse = serde_json::from_str(
        r#"{"localities":[{"locality":"Melbourne","state":"VIC","postcode":"3000"}]}"#,
    )
    .expect("bare list decodes");
    assert_eq!(build_entities(&resp, SCAN)[0].value, "Melbourne VIC 3000");
}
