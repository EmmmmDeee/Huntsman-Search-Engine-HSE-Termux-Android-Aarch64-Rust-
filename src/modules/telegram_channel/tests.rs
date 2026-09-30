use super::*;

/// A minimal but structurally real `/s/{handle}` preview page — the same
/// element shapes observed live on `t.me/s/durov` 2026-09-30 (attribute
/// order, the `tgme_channel_info` wrapper class, the counter div).
fn preview_html(title: &str, description: &str, counter: &str) -> String {
    format!(
        r#"<!doctype html><html><head>
<meta property="og:title" content="{title}">
<meta property="og:description" content="{description}">
<meta property="og:image" content="https://cdn4.telesco.pe/file/example.jpg">
</head><body>
<div class="tgme_page_context tgme_channel_info">
<div class="tgme_header_counter">{counter}</div>
</div>
</body></html>"#
    )
}

#[test]
fn builds_username_and_url_from_a_confirmed_channel() {
    let html = preview_html("Pavel Durov", "Founder of Telegram.", "10.6M subscribers");
    let ents = build_entities("durov", &html, "scan-tg-001");
    let u = ents
        .iter()
        .find(|e| e.kind == EntityKind::Username && e.value == "durov");
    assert!(u.is_some(), "must emit a confirmed Username entity");
    assert!(u.expect("checked").has_tag("telegram"));
    let url = ents
        .iter()
        .find(|e| e.kind == EntityKind::Url && e.value == "https://t.me/durov");
    assert!(url.is_some(), "must emit the canonical channel URL");
}

#[test]
fn emits_person_from_a_multi_word_channel_title() {
    let html = preview_html("Pavel Durov", "Founder of Telegram.", "10.6M subscribers");
    let ents = build_entities("durov", &html, "scan-tg-002");
    let p = ents.iter().find(|e| e.kind == EntityKind::Person);
    assert!(p.is_some(), "a real-name-shaped title must become a Person");
    assert_eq!(p.expect("checked").value, "Pavel Durov");
}

#[test]
fn a_single_word_brand_title_does_not_become_a_person() {
    let html = preview_html(
        "TechCrunch",
        "Startup and technology news.",
        "1.2M subscribers",
    );
    let ents = build_entities("techcrunch", &html, "scan-tg-003");
    assert!(
        !ents.iter().any(|e| e.kind == EntityKind::Person),
        "a single-token brand name must not be promoted to a Person"
    );
}

#[test]
fn extracts_email_from_channel_description() {
    let html = preview_html(
        "Example Channel",
        "Contact us at press@example.com for enquiries.",
        "500 subscribers",
    );
    let ents = build_entities("examplechan", &html, "scan-tg-004");
    assert!(
        ents.iter()
            .any(|e| e.kind == EntityKind::Email && e.value == "press@example.com"),
        "must extract an email mentioned in the channel description"
    );
}

#[test]
fn extracts_external_link_from_description_but_excludes_self_link() {
    let html = preview_html(
        "Example Channel",
        "Visit https://example.org/about or find us at https://t.me/examplechan too.",
        "500 subscribers",
    );
    let ents = build_entities("examplechan", &html, "scan-tg-005");
    assert!(
        ents.iter()
            .any(|e| e.kind == EntityKind::Url && e.value == "https://example.org/about"),
        "must extract a genuine external link from the description"
    );
    // The module always emits exactly one canonical `Url` entity for the
    // channel's own address; the description also mentions that same t.me
    // link, so the self-link exclusion must stop the bio scan from minting a
    // SECOND, redundant one.
    let self_link_count = ents
        .iter()
        .filter(|e| e.kind == EntityKind::Url && e.value.contains("t.me/examplechan"))
        .count();
    assert_eq!(
        self_link_count, 1,
        "the channel's own t.me link must appear exactly once (the canonical Url entity), \
         not duplicated by the bio-link scan"
    );
}

#[test]
fn html_entities_in_the_title_are_decoded() {
    let html = preview_html(
        "Tom &amp; Jerry Fan Club",
        "Cartoons &amp; nostalgia.",
        "42 subscribers",
    );
    let ents = build_entities("tomjerry", &html, "scan-tg-006");
    let u = ents
        .iter()
        .find(|e| e.kind == EntityKind::Username)
        .expect("checked");
    let ev = &u.evidence.first().expect("checked");
    assert_eq!(
        ev.attributes.get("title").map(String::as_str),
        Some("Tom & Jerry Fan Club"),
        "an HTML entity in the title must be decoded exactly once"
    );
}

#[test]
fn extract_og_reads_content_before_or_after_property() {
    let after = r#"<meta property="og:title" content="After">"#;
    let before = r#"<meta content="Before" property="og:title">"#;
    assert_eq!(extract_og(after, "og:title"), Some("After".to_string()));
    assert_eq!(extract_og(before, "og:title"), Some("Before".to_string()));
    assert_eq!(
        extract_og("<meta property=\"og:other\" content=\"x\">", "og:title"),
        None
    );
}

#[test]
fn extract_subscriber_count_reads_the_counter_div() {
    let html = r#"<div class="tgme_header_counter">10.6M subscribers</div>"#;
    assert_eq!(
        extract_subscriber_count(html),
        Some("10.6M subscribers".to_string())
    );
    assert_eq!(extract_subscriber_count("<div>no counter here</div>"), None);
}

#[test]
fn the_username_entity_carries_the_subscriber_count_as_evidence() {
    let html = preview_html("Some Channel", "A description.", "3.4K subscribers");
    let ents = build_entities("somechan", &html, "scan-tg-007");
    let u = ents
        .iter()
        .find(|e| e.kind == EntityKind::Username)
        .expect("checked");
    assert_eq!(
        u.evidence
            .first()
            .expect("checked")
            .attributes
            .get("subscribers")
            .map(String::as_str),
        Some("3.4K subscribers")
    );
}
