use super::{Ahmia, MAX_HITS, build_entities};
use crate::core::entity::EntityKind;
use crate::core::module::{Module, ModuleCost};
use crate::core::scan::{Target, TargetKind};
use crate::util::ahmia::AhmiaResult;

fn hit(onion: &str, title: &str, snippet: &str) -> AhmiaResult {
    AhmiaResult {
        onion_url: onion.to_string(),
        title: title.to_string(),
        snippet: snippet.to_string(),
    }
}

#[test]
fn each_onion_mention_becomes_a_flagged_exposure_url() {
    let hits = vec![hit(
        "http://exampleleakindexabcdefghij234567.onion/dump",
        "Combolist dump mentioning acme.example",
        "acme.example credentials found in the 2019 collection",
    )];
    let res = build_entities(&hits, "scan");
    let e = res
        .entities
        .iter()
        .find(|e| e.kind == EntityKind::Url)
        .expect("an onion mention must emit a Url exposure finding");
    assert_eq!(
        e.value,
        "http://exampleleakindexabcdefghij234567.onion/dump"
    );
    // A full-text onion mention is unverified identity: conservative confidence,
    // flagged, and held out of the confirmed view until corroborated.
    assert!((e.confidence - crate::core::confidence::LOW_MEDIUM).abs() < 1e-9);
    assert!(e.has_tag("dark-web"));
    assert!(e.has_tag("exposure"));
    assert!(e.has_tag("needs-identity-verification"));
    assert!(
        e.evidence[0].attributes.contains_key("caution"),
        "every onion exposure hit must carry the identity/verify caution"
    );
    assert_eq!(
        e.evidence[0]
            .attributes
            .get("onion_url")
            .map(String::as_str),
        Some("http://exampleleakindexabcdefghij234567.onion/dump")
    );
    // The engine's non-fetch gate must recognise exactly what this module emits,
    // so a dark-web finding can never be pivoted into (fetched).
    assert!(
        crate::core::validation::is_onion_url(&e.value),
        "every onion Url this module emits must be gated by is_onion_url"
    );
}

#[test]
fn duplicate_onion_pages_collapse_to_one_finding() {
    let hits = vec![
        hit("http://dupabcdefghij234567.onion/a", "Page", "one"),
        hit("http://dupabcdefghij234567.onion/a", "Page again", "two"),
    ];
    let res = build_entities(&hits, "scan");
    assert_eq!(
        res.entities
            .iter()
            .filter(|e| e.kind == EntityKind::Url)
            .count(),
        1,
        "the same onion URL listed twice must yield one exposure finding"
    );
}

#[test]
fn empty_onion_url_is_skipped() {
    let hits = vec![hit("", "no url", "body")];
    let res = build_entities(&hits, "scan");
    assert!(
        res.entities.is_empty(),
        "a hit with no onion URL is not an exposure finding"
    );
}

#[test]
fn hits_are_capped_at_max() {
    let hits: Vec<AhmiaResult> = (0..MAX_HITS + 25)
        .map(|i| {
            hit(
                &format!("http://cap{i:04}abcdefghij234567.onion/"),
                "t",
                "s",
            )
        })
        .collect();
    let res = build_entities(&hits, "scan");
    assert_eq!(
        res.entities
            .iter()
            .filter(|e| e.kind == EntityKind::Url)
            .count(),
        MAX_HITS,
        "no more than MAX_HITS onion findings may be emitted for one target"
    );
}

#[test]
fn accepts_only_asset_exposure_kinds() {
    let m = Ahmia;
    for k in [
        TargetKind::Email,
        TargetKind::Username,
        TargetKind::FullName,
        TargetKind::Domain,
        TargetKind::Organisation,
    ] {
        assert!(
            m.accepts(&Target::new(k, "acme")),
            "must accept the asset-exposure kind {k:?}"
        );
    }
    for k in [
        TargetKind::IpAddress,
        TargetKind::Coordinates,
        TargetKind::Phone,
        TargetKind::MacAddress,
    ] {
        assert!(
            !m.accepts(&Target::new(k, "x")),
            "must not run dark-web full-text search for the noisy kind {k:?}"
        );
    }
}

#[test]
fn module_metadata_is_a_free_passive_breach_sensor() {
    let m = Ahmia;
    assert_eq!(m.name(), "ahmia");
    assert!(matches!(m.cost(), ModuleCost::Free));
    assert!(m.is_passive());
    assert!(matches!(
        m.category(),
        crate::core::module::ModuleCategory::Breach
    ));
    assert!(m.produces().contains(&EntityKind::Url));
}
