use super::*;

#[test]
fn accepts_two_token_fullname_only() {
    let m = AuPeople;
    assert!(m.accepts(&Target::new(TargetKind::FullName, "Haigen Bamford")));
    assert!(!m.accepts(&Target::new(TargetKind::FullName, "Haigen"))); // single token
    assert!(!m.accepts(&Target::new(TargetKind::Email, "a@b.com")));
    assert!(!m.accepts(&Target::new(TargetKind::Username, "haigen")));
}

#[test]
fn module_metadata() {
    let m = AuPeople;
    assert_eq!(m.name(), "au_people");
    assert!(m.attack_techniques().contains(&"T1591.001"));
    assert!(m.attack_techniques().contains(&"T1589.003"));
}

#[test]
fn parse_relatives_extracts_same_surname_family_and_binds_to_subject() {
    // A True-People-Search-AU-style relatives section (Title- and UPPER-case,
    // middle initials, page chrome interleaved). Only same-surname family is
    // kept, each bound to the subject via `related_to`.
    let html = r#"
      <h2>Possible Relatives</h2>
      <ul>
        <li><a href="/x">Stephen R Moreau</a> — View Profile</li>
        <li><a href="/y">HELENE MOREAU</a> Background Check</li>
        <li>Marianne Moreau, Sunshine Coast QLD</li>
        <li>Fletcher Moreau (this person)</li>
      </ul>
      <h2>Possible Associates</h2>
      <p>Jane Smith and Bob Jones also appear.</p>
    "#;
    let rel = parse_relatives(html, "Fletcher Moreau", "s");
    let names: std::collections::BTreeSet<&str> = rel.iter().map(|e| e.value.as_str()).collect();

    assert!(
        names.contains("Stephen R Moreau"),
        "title-case + middle initial"
    );
    assert!(names.contains("Helene Moreau"), "UPPER-case normalised");
    assert!(names.contains("Marianne Moreau"));
    assert!(
        !names.contains("Fletcher Moreau"),
        "the subject is never their own relative"
    );
    // Different-surname associates are NOT emitted here (precision over recall —
    // those come from the breach/people-search APIs, not the surname filter).
    assert!(
        !names
            .iter()
            .any(|n| n.contains("Smith") || n.contains("Jones"))
    );

    for e in &rel {
        assert_eq!(e.kind, EntityKind::Person);
        assert!(e.has_tag("family-candidate") && e.has_tag("relatives"));
        assert!(
            e.confidence < 0.50,
            "below the expansion floor (recorded, not auto-pivoted)"
        );
        let related = e
            .evidence
            .iter()
            .find_map(|ev| ev.attributes.get("related_to"))
            .map(String::as_str);
        assert_eq!(related, Some("Fletcher Moreau"), "bound to the subject");
    }

    // No relationship section → nothing (no false positives from a plain page).
    assert!(
        parse_relatives(
            "<p>No results found for that name.</p>",
            "Fletcher Moreau",
            "s"
        )
        .is_empty()
    );
}

#[test]
fn split_name_standard() {
    assert_eq!(split_name("Haigen Bamford"), ("Haigen", "Bamford"));
    assert_eq!(split_name("Mary Jane Watson"), ("Mary", "Jane Watson"));
    assert_eq!(split_name("Solo"), ("Solo", ""));
}

#[test]
fn parse_tps_html_extracts_au_address() {
    let html = "<div>Results for Test Person</div><p>Bondi Beach, NSW 2026</p><p>Other line</p>";
    let ents = parse_tps_html(html, "Test Person", "s");
    assert!(
        ents.iter().any(|e| e.kind == EntityKind::Address
            && e.value.contains("NSW")
            && e.has_tag("au-state:NSW")),
        "should extract NSW address"
    );
}

#[test]
fn parse_tps_html_skips_non_au_lines() {
    // No AU state abbreviation or postcode → nothing emitted.
    let html = "<p>London, UK</p><p>New York, NY 10001</p>";
    let ents = parse_tps_html(html, "Test Person", "s");
    assert!(
        ents.iter().all(|e| e.kind != EntityKind::Address),
        "non-AU addresses should not be emitted"
    );
}

#[test]
fn dedup_removes_same_kind_value() {
    let mut ents = vec![
        Entity::new(EntityKind::Address, "Sydney NSW 2000", 0.5, "s"),
        Entity::new(EntityKind::Address, "Sydney NSW 2000", 0.6, "s"),
        Entity::new(EntityKind::Email, "a@b.com", 0.5, "s"),
    ];
    dedup_by_kind_value(&mut ents);
    assert_eq!(ents.len(), 2);
}

#[test]
fn state_tag_from_text_recognises_au_states() {
    assert_eq!(
        state_tag_from_text("Bondi Beach NSW 2026"),
        Some("au-state:NSW".into())
    );
    assert_eq!(
        state_tag_from_text("Melbourne VIC 3000"),
        Some("au-state:VIC".into())
    );
    assert!(state_tag_from_text("London UK").is_none());
}

#[test]
fn whitepages_phone_converts_local_mobile_to_e164() {
    // A local AU mobile 04XX XXX XXX → E.164 +61 with the leading 0 dropped.
    let html = "<div>Contact: 0412 345 678</div>";
    let ents = parse_whitepages_html(html, "Haigen Bamford", "s");
    let phone = ents
        .iter()
        .find(|e| e.kind == EntityKind::Phone)
        .expect("a mobile number should be parsed");
    assert_eq!(phone.value, "+61412345678");
    assert!(phone.has_tag("whitepages"));
    assert!(phone.has_tag("country:AU"));
    assert_eq!(
        phone.evidence[0].attributes.get("raw").map(String::as_str),
        Some("0412345678")
    );
}

#[test]
fn whitepages_dedups_repeated_phone() {
    let html = "<p>0412 345 678</p><p>0412 345 678</p>";
    let ents = parse_whitepages_html(html, "Haigen Bamford", "s");
    assert_eq!(
        ents.iter().filter(|e| e.kind == EntityKind::Phone).count(),
        1,
        "the same number must be emitted once"
    );
}

#[test]
fn whitepages_address_confidence_boosted_when_name_present() {
    // The seed name appears in the window around the postcode → 0.55, else 0.42.
    let html = "<p>Haigen Bamford lives at Bondi Beach NSW 2026</p>";
    let ents = parse_whitepages_html(html, "Haigen Bamford", "s");
    let addr = ents
        .iter()
        .find(|e| e.kind == EntityKind::Address)
        .expect("an address should be built around the postcode");
    assert!((addr.confidence - 0.55).abs() < 1e-9, "name-matched → 0.55");
    assert!(addr.has_tag("whitepages"));
    assert!(addr.has_tag("au-state:NSW"));

    // A page that does not name the subject near the postcode → demoted 0.42.
    let other = "<p>Someone Else at Bondi Beach NSW 2026</p>";
    let ents2 = parse_whitepages_html(other, "Haigen Bamford", "s");
    let addr2 = ents2
        .iter()
        .find(|e| e.kind == EntityKind::Address)
        .expect("address still built without the name");
    assert!((addr2.confidence - 0.42).abs() < 1e-9, "name absent → 0.42");
}

#[test]
fn whitepages_ignores_out_of_range_postcode() {
    // 1234 < 2000 and 8500 > 7999 are out of the accepted AU range.
    let html = "<p>Nowhere Town XX 1234</p><p>Elsewhere YY 8500</p>";
    let ents = parse_whitepages_html(html, "Haigen Bamford", "s");
    assert!(
        ents.iter().all(|e| e.kind != EntityKind::Address),
        "out-of-range postcodes build no address"
    );
}

#[test]
fn clean_au_locality_strips_directory_chrome() {
    // Live-scan artifact: a breadcrumb heading bled into the suburb because the
    // raw ±60-char window was emitted verbatim. The cleaner must keep only the
    // real `Suburb, STATE POSTCODE` tail.
    assert_eq!(
        clean_au_locality("Australian Suburbs Woronora, NSW 2232"),
        Some("Woronora, NSW 2232".to_string())
    );
    // Genuine multi-word suburbs survive (no chrome word to strip).
    assert_eq!(
        clean_au_locality("results Gold Coast QLD 4217 profile"),
        Some("Gold Coast, QLD 4217".to_string())
    );
    // A window that is only chrome around the postcode yields nothing.
    assert_eq!(clean_au_locality("Search Results Profile NSW 2000"), None);
    // No recognisable locality shape → None.
    assert_eq!(clean_au_locality("just some text 99"), None);
}

#[test]
fn whitepages_address_value_excludes_chrome_prefix() {
    // End-to-end: the malformed "Australian SuburbsWoronora" must never reach
    // the Address value. White Pages renders the breadcrumb + result together.
    let html = "<nav>Australian Suburbs</nav><div>Woronora, NSW 2232</div>";
    let ents = parse_whitepages_html(html, "Onur Ada", "s");
    let addr = ents
        .iter()
        .find(|e| e.kind == EntityKind::Address)
        .expect("a clean address should be built");
    assert_eq!(addr.value, "Woronora, NSW 2232");
    assert!(!addr.value.contains("Suburbs"), "chrome must be stripped");
}

#[test]
fn whitepages_mines_contact_emails() {
    let html = "<p>Email: haigen@example.com.au for enquiries</p>";
    let ents = parse_whitepages_html(html, "Haigen Bamford", "s");
    let email = ents
        .iter()
        .find(|e| e.kind == EntityKind::Email)
        .expect("a visible email should be mined");
    assert_eq!(email.value, "haigen@example.com.au");
    assert!(email.has_tag("whitepages"));
}

/// Adversarial-input coverage (PROBLEM_TREE T2.7-adjacent): none of this
/// module's three HTML parsers previously had a property test proving they
/// never panic on arbitrary bytes, unlike the shared primitives they
/// delegate to (`util::html::strip_html`, `util::str_util::find_ascii_ci`),
/// which already carry this exact `mod prop` pattern. `html` is the
/// untrusted, scraped input; `full_name`/`scan_id` are held to the
/// project's synthetic placeholder (see CLAUDE.md) since they originate
/// from the operator's own typed scan target, not third-party bytes.
mod prop {
    use proptest::prelude::*;

    use super::{parse_relatives, parse_tps_html, parse_whitepages_html};

    proptest! {
        #[test]
        fn parse_whitepages_html_never_panics(s in ".{0,256}") {
            let _ = parse_whitepages_html(&s, "Jordan Avery", "s");
        }

        #[test]
        fn parse_tps_html_never_panics(s in ".{0,256}") {
            let _ = parse_tps_html(&s, "Jordan Avery", "s");
        }

        #[test]
        fn parse_relatives_never_panics(s in ".{0,256}") {
            let _ = parse_relatives(&s, "Jordan Avery", "s");
        }
    }
}
