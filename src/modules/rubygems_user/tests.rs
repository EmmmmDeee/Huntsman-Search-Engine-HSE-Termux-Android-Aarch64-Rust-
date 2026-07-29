use super::*;

fn gem(
    name: &str,
    authors: Option<&str>,
    homepage_uri: Option<&str>,
    source_code_uri: Option<&str>,
) -> RgGem {
    RgGem {
        name: Some(name.to_string()),
        authors: authors.map(str::to_string),
        homepage_uri: homepage_uri.map(str::to_string),
        source_code_uri: source_code_uri.map(str::to_string),
    }
}

#[test]
fn emits_username_and_profile_url() {
    let ents = build_entities(vec![gem("mygem", None, None, None)], "alice", "scan-rg-001");
    assert!(
        ents.iter()
            .any(|e| e.kind == EntityKind::Username && e.value == "alice"),
        "must emit Username entity"
    );
    let u = ents
        .iter()
        .find(|e| e.kind == EntityKind::Username && e.value == "alice")
        .expect("should succeed");
    assert!(u.has_tag("rubygems") && u.has_tag("public-profile"));
    assert!(
        ents.iter()
            .any(|e| e.kind == EntityKind::Url && e.value.contains("rubygems.org/profiles/alice")),
        "must emit profile URL"
    );
}

#[test]
fn emits_person_from_multi_word_author() {
    let ents = build_entities(
        vec![gem("mygem", Some("Alice Smith"), None, None)],
        "alice",
        "scan-rg-002",
    );
    let p = ents.iter().find(|e| e.kind == EntityKind::Person);
    assert!(p.is_some(), "must emit Person from multi-word author");
    assert_eq!(p.expect("should succeed").value, "Alice Smith");
}

#[test]
fn no_person_for_single_word_author() {
    let ents = build_entities(
        vec![gem("mygem", Some("alice"), None, None)],
        "alice",
        "scan-rg-003",
    );
    assert!(
        ents.iter().all(|e| e.kind != EntityKind::Person),
        "single-token author must not produce a Person entity"
    );
}

#[test]
fn deduplicates_authors_across_gems() {
    let ents = build_entities(
        vec![
            gem("gem1", Some("Alice Smith"), None, None),
            gem("gem2", Some("Alice Smith"), None, None),
        ],
        "alice",
        "scan-rg-004",
    );
    let persons: Vec<_> = ents
        .iter()
        .filter(|e| e.kind == EntityKind::Person)
        .collect();
    assert_eq!(
        persons.len(),
        1,
        "duplicate author names must not produce duplicate Person entities"
    );
}

#[test]
fn emits_homepage_url_and_domain() {
    let ents = build_entities(
        vec![gem("mygem", None, Some("https://alice.dev"), None)],
        "alice",
        "scan-rg-005",
    );
    assert!(
        ents.iter()
            .any(|e| e.kind == EntityKind::Url && e.value == "https://alice.dev"),
        "must emit homepage URL"
    );
    assert!(
        ents.iter()
            .any(|e| e.kind == EntityKind::Domain && e.value == "alice.dev"),
        "must emit domain from homepage"
    );
}

#[test]
fn extracts_github_username_from_source_code_uri() {
    let ents = build_entities(
        vec![gem(
            "mygem",
            None,
            None,
            Some("https://github.com/alicedev/mygem"),
        )],
        "alice",
        "scan-rg-006",
    );
    let gh = ents
        .iter()
        .find(|e| e.kind == EntityKind::Username && e.value == "alicedev");
    assert!(
        gh.is_some(),
        "must emit GitHub username from source_code_uri"
    );
    assert!(
        gh.expect("should succeed").has_tag("github")
            && gh.expect("should succeed").has_tag("rubygems-pivot")
    );
}

#[test]
fn deduplicates_github_pivots_across_gems() {
    let ents = build_entities(
        vec![
            gem("gem1", None, None, Some("https://github.com/alicedev/gem1")),
            gem("gem2", None, None, Some("https://github.com/alicedev/gem2")),
        ],
        "alice",
        "scan-rg-007",
    );
    let gh_count = ents
        .iter()
        .filter(|e| e.kind == EntityKind::Username && e.value == "alicedev")
        .count();
    assert_eq!(
        gh_count, 1,
        "same GitHub user from multiple gems must be emitted once"
    );
}

#[test]
fn scans_every_gem_not_capped() {
    // 35 owned gems, each with a DISTINCT github source_code_uri → 35 distinct
    // GitHub-pivot Usernames. A prior take(30) silently dropped the last five
    // gems' pivots; every gem must now be scanned.
    let gems: Vec<RgGem> = (0..35)
        .map(|i| {
            gem(
                &format!("gem{i:02}"),
                None,
                None,
                Some(&format!("https://github.com/ghuser{i:02}/gem{i:02}")),
            )
        })
        .collect();
    let ents = build_entities(gems, "prolific", "scan-rg-cap");

    let gh_pivots = ents
        .iter()
        .filter(|e| e.kind == EntityKind::Username && e.has_tag("rubygems-pivot"))
        .count();
    assert_eq!(
        gh_pivots, 35,
        "every gem's distinct GitHub pivot is emitted, not capped at 30"
    );
    // The coverage summary reports the TRUE owned-gem total, not the capped count.
    let u = ents
        .iter()
        .find(|e| e.kind == EntityKind::Username && e.value == "prolific")
        .expect("should succeed");
    assert!(
        u.evidence.iter().any(|ev| ev
            .attributes
            .get("gems")
            .is_some_and(|g| g.contains("(35 gems)"))),
        "coverage summary reports the true total of 35 gems"
    );
}

#[test]
fn empty_gem_list_produces_only_header_entities() {
    // build_entities always emits the Username + profile URL; the process()
    // function guards against empty gem lists before calling build_entities, so
    // this path is unreachable in practice but the helper itself is correct.
    let ents = build_entities(vec![], "ghost", "scan-rg-008");
    assert!(
        ents.iter()
            .any(|e| e.kind == EntityKind::Username && e.value == "ghost"),
        "must emit Username even with no gems"
    );
    assert!(
        !ents.iter().any(|e| e.kind == EntityKind::Person),
        "no Person entities when gems is empty"
    );
}

#[test]
fn gem_coverage_reports_the_true_total_not_the_max_gems_cap() {
    // A prolific owner with more gems than MAX_GEMS (30) must have their real
    // total reported in the `gems` evidence attribute, not the capped sample's
    // own length — the old code used `gem_names.len()` (post-cap) for both the
    // threshold check and the count, silently understating a 35-gem owner as
    // "(30 gems)".
    let gems: Vec<RgGem> = (0..35)
        .map(|i| gem(&format!("gem{i}"), None, None, None))
        .collect();
    let ents = build_entities(gems, "prolific", "scan-rg-010");
    let u = ents
        .iter()
        .find(|e| e.kind == EntityKind::Username && e.value == "prolific")
        .expect("username entity");
    let summary = u
        .evidence
        .iter()
        .find_map(|e| e.attributes.get("gems"))
        .expect("gem coverage evidence attribute");
    assert!(
        summary.ends_with("(35 gems)"),
        "must report the true total (35), not the MAX_GEMS-capped sample length (30): {summary}"
    );
}

#[test]
fn skips_platform_host_in_homepage() {
    let ents = build_entities(
        vec![gem(
            "mygem",
            None,
            Some("https://github.com/alice/mygem"),
            None,
        )],
        "alice",
        "scan-rg-009",
    );
    // github.com is in PLATFORM_HOSTS — should not emit a Domain entity for it.
    assert!(
        ents.iter()
            .all(|e| e.kind != EntityKind::Domain || e.value != "github.com"),
        "platform host must not produce a Domain entity"
    );
}
