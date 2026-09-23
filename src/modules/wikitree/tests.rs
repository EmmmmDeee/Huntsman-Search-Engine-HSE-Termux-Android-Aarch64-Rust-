use super::{WikiTree, WtEnvelope, WtMatch, build_entities, search_names, trim_wikitree_date};
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

    let res = build_entities("John Smith", Some(602), &env.matches, "scan");
    let persons: Vec<_> = res
        .entities
        .iter()
        .filter(|e| e.kind == EntityKind::Person)
        .collect();
    let urls: Vec<_> = res
        .entities
        .iter()
        .filter(|e| e.kind == EntityKind::Url && !e.has_tag("private-profile"))
        .collect();
    // Two detailed profiles; the stub (Id + Name only) is never a Person — it
    // is a private-profile source Url.
    assert_eq!(persons.len(), 2);
    assert_eq!(urls.len(), 2);
    let private: Vec<_> = res
        .entities
        .iter()
        .filter(|e| e.has_tag("private-profile"))
        .map(|e| e.value.as_str())
        .collect();
    assert_eq!(private, ["https://www.wikitree.com/wiki/Smith-52589"]);
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
        build_entities("John Smith", None, &[], "scan")
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
    let res = build_entities("Jane Doe", Some(1), &[m], "scan");
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
    let res = build_entities("John Smith", None, &[m], "scan");
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

fn live_matches() -> Vec<WtMatch> {
    let envelopes: Vec<WtEnvelope> = serde_json::from_str(LIVE).expect("live shape parses");
    envelopes.into_iter().next().expect("one envelope").matches
}

#[test]
fn a_namesakes_birth_date_on_the_subject_anchor_is_not_the_subjects_disclosure() {
    // REQ-WIKITREE-001: FAILS without the ownership mark. The seed Person and
    // every WikiTree "John Smith" share one uid, so the engine merges the
    // namesakes' vitals onto the subject's anchor — and the exposure index
    // scored a man born 1880 in New Zealand as the subject's disclosed DOB.
    use crate::core::entity::Entity;
    let dob_counted = |anchor: &Entity| {
        crate::core::exposure::assess(std::slice::from_ref(anchor), &[])
            .components
            .iter()
            .any(|c| c.detail.contains("date of birth"))
    };
    let mut anchor = Entity::new(EntityKind::Person, "John Smith", 0.60, "scan");
    anchor.tag("seed");
    for e in build_entities("John Smith", Some(602), &live_matches(), "scan").entities {
        if e.uid == anchor.uid {
            anchor.merge(e);
        }
    }
    assert!(
        anchor
            .evidence
            .iter()
            .any(|ev| ev.attributes.contains_key("born")),
        "merged, as the engine does"
    );
    assert!(
        !dob_counted(&anchor),
        "a namesake's birth date is not the subject's"
    );

    // Control: the subject's own DOB on the same anchor still counts, so the
    // assertion above is not vacuous.
    anchor.add_evidence(
        crate::core::entity::Evidence::new("oathnet_pro", "breach row")
            .with_attr("dob", "1990-01-01"),
    );
    assert!(dob_counted(&anchor));
}

#[test]
fn a_seed_that_does_not_split_is_a_typed_skip_not_an_empty_answer() {
    // REQ-WIKITREE-002: FAILS on Ok(empty), which coverage reads as "WikiTree
    // holds no profile" for a tree that was never asked.
    let err = search_names("Madonna").expect_err("a mononym is not queried");
    assert!(
        matches!(
            err,
            crate::core::error::Error::Skipped {
                class: crate::core::event::SkipClass::Scoped,
                ..
            }
        ),
        "{err:?}"
    );
    assert_eq!(
        search_names("John Smith").expect("splits"),
        ("John".to_string(), "Smith".to_string())
    );
}

#[test]
fn a_page_short_of_wikitrees_total_is_declared_truncated() {
    // REQ-WIKITREE-002: FAILS when `total` stays a private attribute. 3 of 602
    // "John Smith" profiles came back as a complete answer.
    let res = build_entities("John Smith", Some(602), &live_matches(), "scan");
    let cut = res.truncation.as_deref().expect("declared");
    assert!(cut.contains("3 of 602"), "{cut}");
}

#[test]
fn a_page_holding_the_whole_total_is_complete() {
    let m = live_matches();
    assert!(
        build_entities("John Smith", Some(3), &m, "scan")
            .truncation
            .is_none()
    );
    // No total and a short page: bounded by the data, not the cap.
    assert!(
        build_entities("John Smith", None, &m, "scan")
            .truncation
            .is_none()
    );
    // No total and a full page: bounded by the cap.
    let full: Vec<WtMatch> = (0..10)
        .map(|i| WtMatch {
            name: Some(format!("Smith-{i}")),
            ..WtMatch::default()
        })
        .collect();
    assert!(
        build_entities("John Smith", None, &full, "scan")
            .truncation
            .is_some()
    );
}

#[test]
fn an_answer_of_only_private_profiles_is_not_a_clean_negative() {
    // REQ-WIKITREE-002: FAILS when stubs are only counted. Two private profiles
    // under the exact name emitted nothing, and coverage read "WikiTree holds
    // nothing on this subject".
    let stubs: Vec<WtEnvelope> = serde_json::from_str(
        r#"[{"status":0,"matches":[{"Id":1,"Name":"Nguyen-1","index":0},{"Id":2,"Name":"Nguyen-2","index":1}],"total":2}]"#,
    )
    .expect("parses");
    let m = &stubs[0].matches;
    let res = build_entities("An Nguyen", Some(2), m, "scan");
    assert!(
        !res.entities.iter().any(|e| e.kind == EntityKind::Person),
        "no Person from a stub"
    );
    let urls: Vec<&str> = res
        .entities
        .iter()
        .filter(|e| e.kind == EntityKind::Url && e.has_tag("private-profile"))
        .map(|e| e.value.as_str())
        .collect();
    assert_eq!(
        urls,
        [
            "https://www.wikitree.com/wiki/Nguyen-1",
            "https://www.wikitree.com/wiki/Nguyen-2"
        ]
    );
    assert!(
        res.entities
            .iter()
            .all(|e| e.confidence < crate::core::confidence::MEDIUM)
    );
}
