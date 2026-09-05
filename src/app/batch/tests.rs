use super::sites::{self, LineSyntax, SITES, Site};
use super::*;
use crate::core::confidence;
use crate::core::entity::{Entity, EntityKind};

#[test]
fn a_seed_fans_out_once_per_selector_not_once_per_surface() {
    // The shared generator emits the same value for the breach AND stealer
    // surfaces; a paste list wants each query once.
    let sels = selectors_from_seed(
        TargetKind::Email,
        "jane.doe@example.com",
        &BatchOptions::default(),
    );
    let emails: Vec<&Selector> = sels
        .iter()
        .filter(|s| s.kind == SelectorKind::Email)
        .collect();
    assert_eq!(
        emails
            .iter()
            .filter(|s| s.value == "jane.doe@example.com")
            .count(),
        1,
        "the seed appears exactly once: {sels:?}"
    );
    assert!(
        sels.iter()
            .any(|s| s.kind == SelectorKind::Domain && s.value == "example.com"),
        "the email's domain is derived: {sels:?}"
    );
    assert!(
        sels.iter().any(|s| s.kind == SelectorKind::Username),
        "the local part fans out into usernames: {sels:?}"
    );
    let mut keys: Vec<(SelectorKind, String)> = sels
        .iter()
        .map(|s| (s.kind, s.value.to_ascii_lowercase()))
        .collect();
    let before = keys.len();
    keys.sort();
    keys.dedup();
    assert_eq!(keys.len(), before, "no duplicate (kind, value) pairs");
}

#[test]
fn scan_entities_become_selectors_in_confidence_order_and_unindexed_kinds_are_dropped() {
    let mk = |kind: EntityKind, v: &str, c: f64| Entity::new(kind, v, c, "s");
    let entities = vec![
        mk(EntityKind::Url, "https://example.com/", confidence::HIGH),
        mk(EntityKind::Email, "low@example.com", confidence::LOW),
        mk(EntityKind::Email, "high@example.com", confidence::VERY_HIGH),
        mk(EntityKind::Email, "HIGH@example.com", confidence::HIGH), // same value, other case
        mk(EntityKind::Domain, "example.com", confidence::MEDIUM),
        mk(EntityKind::Coordinates, "-33.8,151.2", confidence::HIGH),
    ];
    let sels = selectors_from_entities(&entities);
    let values: Vec<&str> = sels.iter().map(|s| s.value.as_str()).collect();
    assert_eq!(
        values,
        vec!["high@example.com", "example.com", "low@example.com"]
    );
}

#[test]
fn a_provider_only_gets_the_kinds_it_indexes_and_spells_lines_its_way() {
    let bare = Site {
        id: "t",
        name: "T",
        url: "https://t.example/",
        how: "paste",
        accepts: &[SelectorKind::Email],
        syntax: LineSyntax::Bare,
        evidence: "https://t.example/docs",
    };
    let prefixed = Site {
        syntax: LineSyntax::Prefixed(&[
            (SelectorKind::Email, "email"),
            (SelectorKind::Domain, "domain"),
        ]),
        accepts: &[SelectorKind::Email, SelectorKind::Domain],
        ..bare
    };
    let sels = vec![
        Selector {
            kind: SelectorKind::Email,
            value: "a@b.c".into(),
        },
        Selector {
            kind: SelectorKind::Domain,
            value: "b.c".into(),
        },
        Selector {
            kind: SelectorKind::Phone,
            value: "+61400000000".into(),
        },
    ];
    let leaked: &'static Site = Box::leak(Box::new(bare));
    let r = render(leaked, &sels);
    assert_eq!(r.lines, vec!["a@b.c"]);
    assert_eq!(r.skipped, 2);
    let leaked: &'static Site = Box::leak(Box::new(prefixed));
    let r = render(leaked, &sels);
    assert_eq!(r.lines, vec!["email:a@b.c", "domain:b.c"]);
    assert_eq!(r.skipped, 1);
}

#[test]
fn a_prefixed_provider_quotes_a_field_value_that_has_whitespace() {
    // DeHashed documents `name:"John Smith"` — a multi-word value must be
    // quoted so the field syntax parses; a single token stays bare.
    let site = Site {
        id: "t",
        name: "T",
        url: "https://t.example/",
        how: "paste",
        accepts: &[SelectorKind::Name],
        syntax: LineSyntax::Prefixed(&[(SelectorKind::Name, "name")]),
        evidence: "https://t.example/docs",
    };
    let leaked: &'static Site = Box::leak(Box::new(site));
    let spaced = Selector {
        kind: SelectorKind::Name,
        value: "John Smith".into(),
    };
    let single = Selector {
        kind: SelectorKind::Name,
        value: "jsmith".into(),
    };
    // An embedded quote is escaped so the `field:"…"` term never closes early.
    let quoted = Selector {
        kind: SelectorKind::Name,
        value: "Ab \"Ace\" Cee".into(),
    };
    assert_eq!(line_for(leaked, &spaced).unwrap(), "name:\"John Smith\"");
    assert_eq!(line_for(leaked, &single).unwrap(), "name:jsmith");
    assert_eq!(
        line_for(leaked, &quoted).unwrap(),
        "name:\"Ab \\\"Ace\\\" Cee\""
    );
}

#[test]
fn text_output_is_one_query_per_line_with_comment_headers_unless_bare() {
    let sels = vec![Selector {
        kind: SelectorKind::Email,
        value: "a@b.c".into(),
    }];
    let rendered: Vec<Rendered> = SITES.iter().take(2).map(|s| render(s, &sels)).collect();
    let text = to_text(&rendered, false);
    assert!(text.starts_with("# "), "headers are comment lines: {text}");
    assert_eq!(text.lines().filter(|l| *l == "a@b.c").count(), 2);
    let bare = to_text(&rendered, true);
    assert!(
        !bare.contains('#'),
        "bare output carries only queries: {bare}"
    );
    assert_eq!(bare.trim().lines().filter(|l| !l.is_empty()).count(), 2);
}

#[test]
fn every_registered_provider_is_grounded_and_uniquely_named() {
    let mut ids: Vec<&str> = SITES.iter().map(|s| s.id).collect();
    ids.sort();
    ids.dedup();
    assert_eq!(ids.len(), SITES.len(), "site ids must be unique");
    for s in SITES {
        assert!(
            s.evidence.starts_with("https://"),
            "{}: evidence must be a URL",
            s.id
        );
        assert!(s.url.starts_with("https://"), "{}: url must be a URL", s.id);
        assert!(
            !s.accepts.is_empty(),
            "{}: must accept at least one selector kind",
            s.id
        );
        assert!(
            s.id.chars().all(|c| c.is_ascii_lowercase() || c == '-'),
            "{}: id is kebab-case",
            s.id
        );
        if let LineSyntax::Prefixed(fields) = s.syntax {
            for k in s.accepts {
                assert!(
                    fields.iter().any(|(fk, _)| fk == k),
                    "{}: no field name for {k:?}",
                    s.id
                );
            }
        }
        assert!(sites::find(s.id).is_some());
        assert!(
            sites::find(&s.id.to_ascii_uppercase()).is_some(),
            "lookup is case-insensitive"
        );
    }
    assert!(sites::find("no-such-site").is_none());
}
