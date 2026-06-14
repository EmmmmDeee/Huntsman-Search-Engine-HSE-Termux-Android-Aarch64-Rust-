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
fn split_name_standard() {
    assert_eq!(split_name("Haigen Bamford"), ("Haigen", "Bamford"));
    assert_eq!(split_name("Mary Jane Watson"), ("Mary", "Jane Watson"));
    assert_eq!(split_name("Solo"), ("Solo", ""));
}

#[test]
fn strip_html_tags_removes_markup() {
    // Tags are replaced by spaces; adjacent content stays separated.
    let r = strip_html_tags("<b>Sydney</b>, <span>NSW</span> 2000");
    assert!(r.contains("Sydney") && r.contains("NSW") && r.contains("2000"));
    assert_eq!(strip_html_tags("plain text"), "plain text");
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
