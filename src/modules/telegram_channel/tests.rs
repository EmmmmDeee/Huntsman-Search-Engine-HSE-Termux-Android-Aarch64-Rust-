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

/// A channel title is never promoted to a `Person`, even a real-name-shaped
/// one like Pavel Durov's own channel: unlike a profile module's
/// self-reported real-name field, a channel title is set by whoever
/// administers it and is routinely an organisation ("BBC News", "Example
/// Channel" — the latter literally this test file's own brand fixture), so
/// nothing on this page distinguishes an individual's channel from one. The
/// title still reaches the confirmed Username's own evidence.
#[test]
fn does_not_promote_the_channel_title_to_a_person() {
    let html = preview_html("Pavel Durov", "Founder of Telegram.", "10.6M subscribers");
    let ents = build_entities("durov", &html, "scan-tg-002");
    assert!(
        !ents.iter().any(|e| e.kind == EntityKind::Person),
        "a channel title, however real-name-shaped, must never become a Person"
    );
    let u = ents
        .iter()
        .find(|e| e.kind == EntityKind::Username)
        .expect("checked");
    assert_eq!(
        u.evidence
            .first()
            .expect("checked")
            .attributes
            .get("title")
            .map(String::as_str),
        Some("Pavel Durov"),
        "the title stays visible as evidence, just not as an inferred identity"
    );
}

#[test]
fn a_brand_title_does_not_become_a_person() {
    let html = preview_html(
        "TechCrunch",
        "Startup and technology news.",
        "1.2M subscribers",
    );
    let ents = build_entities("techcrunch", &html, "scan-tg-003");
    assert!(
        !ents.iter().any(|e| e.kind == EntityKind::Person),
        "a brand name must not be promoted to a Person"
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

/// Only the channel's *own* `t.me` link is suppressed; a link to a different
/// Telegram channel or group mentioned in the bio is a discovery pivot and
/// must be kept, tagged distinctly. Regression for the review finding on the
/// pre-fix code, which filtered out every `t.me` link by host alone.
#[test]
fn preserves_links_to_other_telegram_channels_as_pivots() {
    let html = preview_html(
        "Example Channel",
        "Our partner channel is https://t.me/partnerchannel, and our own link is \
         https://t.me/examplechan.",
        "500 subscribers",
    );
    let ents = build_entities("examplechan", &html, "scan-tg-005b");
    let pivot = ents
        .iter()
        .find(|e| e.kind == EntityKind::Url && e.value == "https://t.me/partnerchannel")
        .expect("a link to a different Telegram channel must be kept as a pivot");
    assert!(pivot.has_tag("telegram-pivot"));
    // The channel's own link, in whatever form the description mentions it,
    // still must not be duplicated.
    let self_link_count = ents
        .iter()
        .filter(|e| e.kind == EntityKind::Url && e.value.contains("t.me/examplechan"))
        .count();
    assert_eq!(
        self_link_count, 1,
        "the channel's own link appears exactly once"
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
fn redirects_to_telegram_org_matches_only_that_documented_destination() {
    assert!(redirects_to_telegram_org(Some("https://telegram.org/")));
    assert!(redirects_to_telegram_org(Some(
        "https://telegram.org/about"
    )));
    assert!(redirects_to_telegram_org(Some("https://TELEGRAM.ORG/")));
    assert!(!redirects_to_telegram_org(Some("https://t.me/somehandle")));
    assert!(!redirects_to_telegram_org(Some(
        "https://evil-telegram.org/"
    )));
    assert!(!redirects_to_telegram_org(Some("not a url")));
    assert!(!redirects_to_telegram_org(None));
}

#[test]
fn is_own_channel_link_matches_the_handle_in_either_url_form() {
    assert!(is_own_channel_link("https://t.me/durov", "durov"));
    assert!(is_own_channel_link("https://t.me/DUROV", "durov"));
    assert!(is_own_channel_link("https://t.me/s/durov", "durov"));
    // A link to one specific post within the own channel is still the own
    // channel, not an external pivot.
    assert!(is_own_channel_link("https://t.me/durov/12345", "durov"));
    assert!(!is_own_channel_link("https://t.me/partnerchannel", "durov"));
    assert!(!is_own_channel_link("https://example.org/durov", "durov"));
    assert!(!is_own_channel_link("not a url", "durov"));
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
