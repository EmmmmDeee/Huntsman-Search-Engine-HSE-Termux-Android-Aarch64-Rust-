use super::{WikiTree, WtEnvelope, WtMatch, build_entities, trim_wikitree_date};
use crate::core::{
    entity::EntityKind,
    module::{Module, ModuleCost},
    scan::{Target, TargetKind},
};

/// Live response captured 2026-09-06 for `searchPerson&FirstName=John&LastName=Smith&BirthDate=1880&limit=3&appId=…`
/// — including the private-profile stub the API returns as the third match.
const LIVE: &str = r#"[{"status":0,"matches":[{"Id":6819925,"Name":"Smith-54274","FirstName":"John","LastNameAtBirth":"Smith","BirthDate":"1880-11-24","DeathDate":"1951-08-19","BirthLocation":"Woodville, New Zealand","DeathLocation":"Palmerston North, New Zealand","Father":6953891,"Mother":20479519,"index":0},{"Id":35574650,"Name":"Smith-283065","FirstName":"John","LastNameAtBirth":"Smith","BirthDate":"1880-02-00","DeathDate":"1940-00-00","BirthLocation":"De Soto Parish, Louisiana, United States of America","DeathLocation":"Texas, United States of America","Father":35574104,"Mother":35574620,"index":1},{"Id":6611905,"Name":"Smith-52589","index":2}],"total":602,"start":0,"limit":3}]"#;

/// The keyless-without-appId refusal, as served (HTTP 429).
const RATE_LIMITED: &str = r#"[{ "status": "Limit exceeded." }]"#;

#[test]
fn metadata() {
    let m = WikiTree;
    assert_eq!(m.name(), "wikitree");
    assert_eq!(m.priority(), 43);
    assert!(!m.description().is_empty());
    assert_eq!(m.cost(), ModuleCost::Free);
    assert!(m.accepts(&Target::new(TargetKind::FullName, "John Smith")));
    assert!(!m.accepts(&Target::new(TargetKind::Username, "jsmith")));
    assert!(m.max_timeout_ms() > 3000);
    assert!(!m.attack_techniques().is_empty());
    assert!(m.produces().contains(&EntityKind::Person));
    assert!(m.produces().contains(&EntityKind::Url));
    assert_eq!(m.cache_ttl_secs(), 86_400);
}

#[test]
fn live_shape_yields_a_person_and_a_source_per_detailed_profile_and_counts_stubs() {
    let envelopes: Vec<WtEnvelope> = serde_json::from_str(LIVE).expect("live shape parses");
    let env = envelopes.into_iter().next().expect("one envelope");
    assert_eq!(env.status.as_u64(), Some(0));
    assert_eq!(env.total, Some(602));
    assert_eq!(env.matches.len(), 3);

    let res = build_entities("John Smith", 602, &env.matches, "scan");
    let persons: Vec<_> = res
        .entities
        .iter()
        .filter(|e| e.kind == EntityKind::Person)
        .collect();
    let urls: Vec<_> = res
        .entities
        .iter()
        .filter(|e| e.kind == EntityKind::Url)
        .collect();
    // Two detailed profiles; the stub (Id + Name only) is counted, not emitted.
    assert_eq!(persons.len(), 2);
    assert_eq!(urls.len(), 2);
    assert!(persons.iter().all(|p| p.value == "John Smith"));
    assert!(
        persons
            .iter()
            .all(|p| p.has_tag("wikitree") && p.has_tag("needs-identity-verification"))
    );

    let nz = persons
        .iter()
        .find(|p| {
            p.evidence[0]
                .attributes
                .get("profile_id")
                .map(String::as_str)
                == Some("Smith-54274")
        })
        .expect("the NZ profile");
    let a = &nz.evidence[0].attributes;
    assert_eq!(a.get("born").map(String::as_str), Some("1880-11-24"));
    assert_eq!(a.get("died").map(String::as_str), Some("1951-08-19"));
    assert_eq!(
        a.get("birth_place").map(String::as_str),
        Some("Woodville, New Zealand")
    );
    assert_eq!(a.get("father_user_id").map(String::as_str), Some("6953891"));
    assert_eq!(
        a.get("private_profiles_matching").map(String::as_str),
        Some("1")
    );
    assert_eq!(a.get("matches_total").map(String::as_str), Some("602"));
    assert_eq!(
        a.get("url").map(String::as_str),
        Some("https://www.wikitree.com/wiki/Smith-54274")
    );
    assert!(!a.contains_key("caution"));

    // Partial dates keep only the known parts.
    let la = persons
        .iter()
        .find(|p| {
            p.evidence[0]
                .attributes
                .get("profile_id")
                .map(String::as_str)
                == Some("Smith-283065")
        })
        .expect("the Louisiana profile");
    assert_eq!(
        la.evidence[0].attributes.get("born").map(String::as_str),
        Some("1880-02")
    );
    assert_eq!(
        la.evidence[0].attributes.get("died").map(String::as_str),
        Some("1940")
    );

    assert!(
        urls.iter()
            .any(|u| u.value == "https://www.wikitree.com/wiki/Smith-283065")
    );
    assert!(urls.iter().all(|u| u.has_tag("source-document")));
}

#[test]
fn a_rate_limit_envelope_is_not_a_success_status() {
    let envelopes: Vec<WtEnvelope> = serde_json::from_str(RATE_LIMITED).unwrap();
    assert_ne!(envelopes[0].status.as_u64(), Some(0));
    assert!(
        build_entities("John Smith", 0, &[], "scan")
            .entities
            .is_empty()
    );
}

#[test]
fn dates_trim_their_unknown_parts() {
    assert_eq!(
        trim_wikitree_date("1880-11-24").as_deref(),
        Some("1880-11-24")
    );
    assert_eq!(trim_wikitree_date("1880-02-00").as_deref(), Some("1880-02"));
    assert_eq!(trim_wikitree_date("1940-00-00").as_deref(), Some("1940"));
    assert_eq!(trim_wikitree_date("0000-00-00"), None);
    assert_eq!(trim_wikitree_date(""), None);
    assert_eq!(trim_wikitree_date("abcd-01-01"), None);
}

#[test]
fn a_name_only_profile_is_demoted_and_flagged_and_a_married_name_is_kept() {
    let m = WtMatch {
        id: Some(1),
        name: Some("Doe-1".into()),
        first_name: Some("Jane".into()),
        last_name_at_birth: Some("Doe".into()),
        last_name_current: Some("Smith".into()),
        ..WtMatch::default()
    };
    let res = build_entities("Jane Doe", 1, &[m], "scan");
    let p = res
        .entities
        .iter()
        .find(|e| e.kind == EntityKind::Person)
        .expect("person");
    assert_eq!(p.value, "Jane Doe");
    assert!(p.confidence < crate::core::confidence::LOW_MEDIUM);
    let a = &p.evidence[0].attributes;
    assert!(a.contains_key("caution"));
    assert_eq!(a.get("current_surname").map(String::as_str), Some("Smith"));
    assert!(!a.contains_key("private_profiles_matching"));
}

#[test]
fn a_missing_total_still_yields_the_returned_matches() {
    // `total` is optional; if the API omits it the returned matches must not be
    // dropped. matches_total falls back to matches.len().
    let m = WtMatch {
        id: Some(1),
        name: Some("Smith-1".into()),
        first_name: Some("John".into()),
        last_name_at_birth: Some("Smith".into()),
        birth_date: Some("1880-01-01".into()),
        ..WtMatch::default()
    };
    let res = build_entities("John Smith", 0, &[m], "scan");
    let p = res
        .entities
        .iter()
        .find(|e| e.kind == EntityKind::Person)
        .expect("a missing total must not suppress the returned matches");
    assert_eq!(
        p.evidence[0]
            .attributes
            .get("matches_total")
            .map(String::as_str),
        Some("1")
    );
}
