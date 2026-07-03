use super::*;

#[test]
fn accepts_identifier_kinds_with_real_search_value() {
    let m = TorSearchPivot;
    for k in [
        TargetKind::Email,
        TargetKind::Username,
        TargetKind::FullName,
        TargetKind::Domain,
        TargetKind::CryptoAddress,
    ] {
        assert!(m.accepts(&Target::new(k, "x")), "should accept {k:?}");
    }
}

#[test]
fn rejects_kinds_with_no_meaningful_search_term() {
    let m = TorSearchPivot;
    for k in [
        TargetKind::Coordinates,
        TargetKind::Asn,
        TargetKind::Cidr,
        TargetKind::IpAddress,
        TargetKind::ApiKey,
    ] {
        assert!(!m.accepts(&Target::new(k, "x")), "should reject {k:?}");
    }
}

#[test]
fn is_passive_and_free() {
    let m = TorSearchPivot;
    assert!(m.is_passive());
    assert!(matches!(m.cost(), crate::core::module::ModuleCost::Free));
}

#[test]
fn build_pivots_returns_two_entities_clearnet_and_onion() {
    let target = Target::new(TargetKind::Username, "alice123");
    let result = build_pivots(&target, "scan");
    assert_eq!(result.entities.len(), 2);
    // Entity::new's Url normaliser strips the trailing '/' before a query
    // string (harmless here: Django's APPEND_SLASH redirects `/search?q=`
    // to `/search/?q=` transparently for a human clicking the link), so
    // assert on host+path rather than the raw pre-normalisation constant.
    let urls: Vec<&str> = result.entities.iter().map(|e| e.value.as_str()).collect();
    assert!(
        urls.iter()
            .any(|u| u.starts_with("https://ahmia.fi/search?q="))
    );
    assert!(urls.iter().any(|u| u.contains(".onion/search?q=")));
}

#[test]
fn build_pivots_url_encodes_the_query() {
    let target = Target::new(TargetKind::FullName, "Jane Doe");
    let result = build_pivots(&target, "scan");
    for e in &result.entities {
        assert!(
            e.value.contains("Jane+Doe") || e.value.contains("Jane%20Doe"),
            "expected an encoded space in {}",
            e.value
        );
        assert!(
            !e.value.contains(' '),
            "raw space leaked into URL: {}",
            e.value
        );
    }
}

#[test]
fn build_pivots_tags_every_entity_as_a_candidate_pivot() {
    let target = Target::new(TargetKind::Email, "alice@example.com");
    let result = build_pivots(&target, "scan");
    for e in &result.entities {
        assert!(
            e.has_tag(tags::CANDIDATE),
            "pivot suggestions must be quarantined from the correlator/exposure/footprint"
        );
        assert!(e.has_tag("tor-search-pivot"));
        assert_eq!(e.kind, EntityKind::Url);
    }
}

#[test]
fn build_pivots_returns_nothing_for_a_blank_value() {
    let target = Target::new(TargetKind::Username, "   ");
    let result = build_pivots(&target, "scan");
    assert!(result.entities.is_empty());
}

#[test]
fn produces_covers_the_emitted_kind() {
    assert_eq!(TorSearchPivot.produces(), &[EntityKind::Url]);
}
