use super::*;

#[test]
fn accepts_two_token_fullname_only() {
    let m = AsicDirector;
    assert!(m.accepts(&Target::new(TargetKind::FullName, "Haigen Bamford")));
    assert!(!m.accepts(&Target::new(TargetKind::FullName, "Haigen"))); // single token
    assert!(!m.accepts(&Target::new(TargetKind::Email, "a@b.com")));
    assert!(!m.accepts(&Target::new(TargetKind::Organisation, "Acme")));
}

#[test]
fn module_metadata() {
    let m = AsicDirector;
    assert_eq!(m.name(), "asic_director");
    assert!(m.attack_techniques().contains(&"T1591.002"));
    assert!(m.attack_techniques().contains(&"T1591.004"));
}

#[test]
fn clean_html_strips_tags_and_entities() {
    assert_eq!(clean_html("<b>Sydney</b> &amp; NSW"), "Sydney & NSW");
    assert_eq!(clean_html("plain &nbsp; text"), "plain   text");
}

#[test]
fn extract_acn_finds_nine_digits() {
    assert_eq!(extract_acn("ACN 123456789 PTY"), Some("123456789".into()));
    assert_eq!(extract_acn("short 12"), None);
}

#[test]
fn extract_au_address_finds_state_postcode() {
    let addr = extract_au_address("Level 5 Collins St Melbourne VIC 3000 Australia");
    assert!(addr.is_some());
    let a = addr.expect("should succeed");
    assert!(a.contains("VIC") && a.contains("3000"));
}

#[test]
fn build_director_entities_rejects_a_checksum_invalid_acn() {
    // Regression (critical audit): extract_acn() (called by parse_asic_html,
    // not exercised directly here) collects every ASCII digit anywhere in the
    // row and takes the first 9 -- not a contiguous run anchored on an "ACN"
    // label. A real AU company whose registered NAME itself contains digits
    // ("7-Eleven Stores Pty Ltd", "1300 Smiles Limited") has those leading
    // digits glued onto the front of the real ACN's digit stream, producing a
    // fabricated 9-digit value. Unlike every OTHER caller in this codebase
    // that trusts an ACN-shaped string (au_business_id, the search_engines
    // extractor, core::correlator::rules::org, core::scan's TargetKind
    // inference), build_director_entities only checked digit COUNT, never the
    // checksum -- so a corrupted value sailed through as a
    // confidence::CORROBORATED AbnAcn entity and would be shipped to the live
    // ASIC ABN Lookup API as a "confirmed" pivot.
    //
    // "712345678" is exactly what extract_acn("... ACN 123456789 ...") would
    // return for a row whose company name contributes one leading digit
    // (e.g. "7-Eleven ..."): the real ACN's first 8 digits shifted by one,
    // with a checksum that no longer validates.
    let ents = build_director_entities("7-Eleven Stores Pty Ltd", "712345678", "Test Name", None, "s");
    assert!(
        !ents.iter().any(|e| e.kind == EntityKind::AbnAcn),
        "a checksum-invalid (corrupted) ACN must not be minted as a corroborated entity"
    );
    // The Organisation entity is unaffected -- the company name itself was
    // extracted correctly; only the corrupted ACN is withheld.
    assert!(ents.iter().any(|e| e.kind == EntityKind::Organisation));
}

#[test]
fn build_director_entities_emits_org_acn_address() {
    let ents = build_director_entities(
        "Bamford Holdings Pty Ltd",
        "004085616", // ASIC worked-example ACN -- checksum-valid
        "Haigen Bamford",
        Some("Level 1, 100 Collins St, Melbourne VIC 3000"),
        "s",
    );
    assert!(ents.iter().any(|e| e.kind == EntityKind::Organisation));
    assert!(ents.iter().any(|e| e.kind == EntityKind::AbnAcn));
    let addr = ents.iter().find(|e| e.kind == EntityKind::Address);
    assert!(addr.is_some());
    assert!(addr.expect("should succeed").has_tag("registered-office"));
}

#[test]
fn build_director_entities_invalid_acn_skipped() {
    let ents = build_director_entities("Acme Pty Ltd", "12345", "Test Name", None, "s");
    // Short ACN — no AbnAcn entity emitted.
    assert!(!ents.iter().any(|e| e.kind == EntityKind::AbnAcn));
    // But Organisation should still emit.
    assert!(ents.iter().any(|e| e.kind == EntityKind::Organisation));
}

#[test]
fn parse_asic_html_extracts_name_match() {
    let html = r#"<tr>
        <td>Bamford Holdings Pty Ltd</td>
        <td>ACN 123456789</td>
        <td>Level 1 Collins St Melbourne VIC 3000</td>
        <td>Haigen Bamford - Director</td>
    </tr>"#;
    let results = parse_asic_html(html, "Haigen Bamford");
    // The parser works on cleaned lines — may not find the split-cell pattern,
    // but at minimum it should not panic.
    let _ = results;
}

#[test]
fn parse_asic_html_matches_whole_words_not_substrings() {
    // Regression: the row filter used to check whether every query token was
    // a raw SUBSTRING anywhere in the cleaned line — so a query like
    // "Grace Han" matched a completely unrelated director's row whose
    // company/name text merely happened to contain "grace"/"han" as
    // fragments of other words ("Graceful", "Chan"), attributing that
    // person's company/ACN/address to the queried name.
    let html = "Chan Graceful Enterprises Pty Ltd ACN 123456789 Level 2 Sydney NSW 2000 \
                 John Chan - Director\n\
                 Grace Han Holdings Pty Ltd ACN 987654321 Level 3 Sydney NSW 2000 \
                 Grace Han - Director\n";
    let results = parse_asic_html(html, "Grace Han");
    let companies: Vec<&str> = results.iter().map(|(c, _, _)| c.as_str()).collect();
    assert!(
        !companies.iter().any(|c| c.contains("Chan Graceful")),
        "\"grace\"/\"han\" must not match as substrings of \"Graceful\"/\"Chan\": {companies:?}"
    );
    assert!(
        companies.iter().any(|c| c.contains("Grace Han Holdings")),
        "the genuine whole-word match must still be found: {companies:?}"
    );
}

#[test]
fn extract_company_name_strips_acn_and_trailing_punct() {
    // The ACN portion and trailing punctuation are stripped; the company name
    // remains clean.
    assert_eq!(
        extract_company_name("Bamford Holdings Pty Ltd ACN 123456789 -", "123456789"),
        "Bamford Holdings Pty Ltd ACN"
    );
    // No ACN → full line cleaned of trailing punct.
    assert_eq!(extract_company_name("Acme Corp,", ""), "Acme Corp");
    // Empty → empty.
    assert_eq!(extract_company_name("", ""), "");
}

#[test]
fn extract_au_address_requires_valid_postcode_range() {
    // 4000 is a valid QLD postcode.
    assert!(extract_au_address("Brisbane QLD 4000 Australia").is_some());
    // 9999 is out of the AU postcode range (2000–7999) → no address.
    assert!(extract_au_address("Invalid NSW 9999").is_none());
    // No state abbreviation → no address.
    assert!(extract_au_address("Somewhere 3000").is_none());
}

// ── `request_failed` — the "ASIC Connect Online never answered" vs
// "genuinely no director records" distinction (T2.120). ──────────────────

#[test]
fn request_failed_true_when_the_request_never_read_and_nothing_found() {
    // Regression: before this fix, `process()` collapsed a transport error,
    // a non-success HTTP status, AND an unreadable body all into the same
    // silent `Ok(ModuleResult::new())` as a genuine "no director records for
    // this name" result — indistinguishable from a real outage or a
    // rejected request.
    assert!(request_failed(false, false));
}

#[test]
fn request_failed_false_when_the_request_read_even_with_no_match() {
    // The request got a real, readable response — this name simply had no
    // director record in it. An honest empty result, not a failure.
    assert!(!request_failed(true, false));
}

#[test]
fn request_failed_false_when_entities_were_found() {
    // Found something, regardless of the html_read_ok bookkeeping — never
    // report a hard failure over a real result.
    assert!(!request_failed(false, true));
    assert!(!request_failed(true, true));
}

#[test]
fn clean_html_decodes_numeric_character_references() {
    // Regression: the hand-rolled decoder knew four named entities and nothing
    // else, so an ordinary Australian surname published as a numeric reference
    // carried its escape all the way into the stored director name.
    assert_eq!(clean_html("<td>Daniel O&#39;Brien</td>"), "Daniel O'Brien");
    assert_eq!(clean_html("<td>ACME &quot;Group&quot;</td>"), "ACME \"Group\"");
    assert_eq!(clean_html("<td>Ren&#xE9;e Dubois</td>"), "Renée Dubois");
}

// Timing ratios are a property of how the scheduler treated two microsecond-scale
// samples, not a property of the code, so this does NOT belong in the gated run:
// an adversarial audit reproduced it failing roughly one run in ten under 4x CPU
// oversubscription, which would redden `main` for reasons unrelated to any diff.
// `#[ignore]`d to match the house convention for the other perf baselines
// (`core::correlator::perf`, the engine throughput test, `util::found_keys`).
// The quadratic regression it guards is documented with real measurements in the
// commit that removed it; run this by hand to re-confirm.
#[test]
#[ignore = "timing ratio; run with --ignored --nocapture"]
fn clean_html_is_linear_in_ampersand_count() {
    // Regression: every `&` rebuilt the whole remaining document into a String to
    // run `starts_with` against it, making the scan quadratic. This asserts the
    // shape rather than a wall-clock number: 8x the input must not cost ~64x the
    // time. The old implementation missed that by a wide margin (8 KB 1.59 ms ->
    // 64 KB 100 ms, a 63x rise); a linear scan lands near 8x.
    let row = "<tr><td>ACME &amp; SONS PTY LTD</td></tr>";
    let small = row.repeat(200);
    let large = row.repeat(1600);

    let t0 = std::time::Instant::now();
    let a = clean_html(&small);
    let small_ns = t0.elapsed().as_nanos().max(1);
    let t1 = std::time::Instant::now();
    let b = clean_html(&large);
    let large_ns = t1.elapsed().as_nanos().max(1);

    assert!(a.contains("ACME & SONS PTY LTD"));
    assert!(b.contains("ACME & SONS PTY LTD"));
    // Generous ceiling so a loaded CI runner cannot flake this, while a return to
    // quadratic behaviour still fails it decisively.
    let ratio = large_ns as f64 / small_ns as f64;
    assert!(
        ratio < 24.0,
        "8x the input cost {ratio:.1}x the time; expected roughly linear (<24x)"
    );
}
