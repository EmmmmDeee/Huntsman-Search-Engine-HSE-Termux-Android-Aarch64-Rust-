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
fn module_no_longer_dispatches_the_retired_whitepages_leg() {
    // Regression for the White Pages AU leg removal: one remaining lookup
    // (TPS AU), not two.
    let m = AuPeople;
    assert_eq!(m.max_timeout_ms(), 6_000);
}
