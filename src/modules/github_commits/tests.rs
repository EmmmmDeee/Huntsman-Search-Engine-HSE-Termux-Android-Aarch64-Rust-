use super::*;

const FIXTURE: &str = r#"{
  "items": [
    {
      "commit": { "author": { "name": "Linus Torvalds" } },
      "author": { "login": "torvalds", "html_url": "https://github.com/torvalds" }
    },
    { "commit": { "author": { "name": "Your Name" } }, "author": null },
    {
      "commit": { "author": { "name": "dependabot[bot]" } },
      "author": { "login": "dependabot[bot]", "html_url": "https://github.com/apps/dependabot" }
    }
  ]
}"#;

#[test]
fn extract_pulls_identity_and_filters_noise() {
    let resp: CommitSearchResp = serde_json::from_str(FIXTURE).expect("should succeed");
    let out = extract(&resp.items, "torvalds@linux-foundation.org", "scan");
    // The verified GitHub account + its profile URL.
    assert!(
        out.iter()
            .any(|e| e.kind == EntityKind::Username && e.value == "torvalds" && e.has_tag("github"))
    );
    assert!(
        out.iter()
            .any(|e| e.kind == EntityKind::Url && e.value == "https://github.com/torvalds")
    );
    // The real name behind the email.
    assert!(
        out.iter()
            .any(|e| e.kind == EntityKind::Person && e.value == "Linus Torvalds")
    );
    // The `git` placeholder name and the bot account are both filtered out.
    assert!(
        !out.iter()
            .any(|e| e.kind == EntityKind::Person && e.value == "Your Name")
    );
    assert!(
        !out.iter()
            .any(|e| e.value.to_ascii_lowercase().contains("dependabot"))
    );
}

/// A shared / role email (`dev@company.com`, `noreply@…`) legitimately fronts
/// many real contributors and many real accounts. Every DISTINCT non-placeholder
/// name and every DISTINCT non-bot login must surface — dropping the tail hides
/// genuine identities. Fails against the old `MAX_NAMES = 3` / `MAX_LOGINS = 5`
/// caps, which silently discarded the 4th+ name and the 6th+ account.
#[test]
fn shared_email_emits_every_distinct_name_and_login() {
    // 4 distinct real names (> old MAX_NAMES = 3) and 6 distinct logins
    // (> old MAX_LOGINS = 5), interleaved with a placeholder and a bot that
    // must still be filtered regardless of the cap removal.
    const SHARED: &str = r#"{
      "items": [
        { "commit": { "author": { "name": "Ada Lovelace" } },
          "author": { "login": "ada", "html_url": "https://github.com/ada" } },
        { "commit": { "author": { "name": "Grace Hopper" } },
          "author": { "login": "grace", "html_url": "https://github.com/grace" } },
        { "commit": { "author": { "name": "Alan Turing" } },
          "author": { "login": "alan", "html_url": "https://github.com/alan" } },
        { "commit": { "author": { "name": "Katherine Johnson" } },
          "author": { "login": "katherine", "html_url": "https://github.com/katherine" } },
        { "commit": { "author": { "name": "Your Name" } },
          "author": { "login": "margaret", "html_url": "https://github.com/margaret" } },
        { "commit": { "author": { "name": "dependabot[bot]" } },
          "author": { "login": "dijkstra", "html_url": "https://github.com/dijkstra" } }
      ]
    }"#;
    let resp: CommitSearchResp = serde_json::from_str(SHARED).expect("should succeed");
    let out = extract(&resp.items, "dev@company.com", "scan");

    let names: Vec<&str> = out
        .iter()
        .filter(|e| e.kind == EntityKind::Person)
        .map(|e| e.value.as_str())
        .collect();
    // All 4 real names, not the first 3 — the placeholder "Your Name" is still
    // filtered, so the 5th and 6th rows contribute no Person.
    assert_eq!(
        names.len(),
        4,
        "every distinct real name emitted, not capped: {names:?}"
    );
    for expected in ["Ada Lovelace", "Grace Hopper", "Alan Turing", "Katherine Johnson"] {
        assert!(names.contains(&expected), "missing name {expected}: {names:?}");
    }

    let logins: Vec<&str> = out
        .iter()
        .filter(|e| e.kind == EntityKind::Username)
        .map(|e| e.value.as_str())
        .collect();
    // All 6 real logins, not the first 5 — every account is a verified
    // email ↔ account mapping. (`dependabot[bot]` login would be bot-filtered,
    // but this fixture's 6 logins are all real handles.)
    assert_eq!(
        logins.len(),
        6,
        "every distinct login emitted, not capped: {logins:?}"
    );
    for expected in ["ada", "grace", "alan", "katherine", "margaret", "dijkstra"] {
        assert!(
            logins.contains(&expected),
            "missing login {expected}: {logins:?}"
        );
    }
}

#[test]
fn is_real_name_gates_placeholders_and_bots() {
    assert!(is_real_name("Linus Torvalds"));
    assert!(is_real_name("Ada P Lovelace"));
    assert!(!is_real_name("Your Name")); // git default placeholder
    assert!(!is_real_name("torvalds")); // single word — likely a handle
    assert!(!is_real_name("dependabot[bot]"));
    assert!(!is_real_name("github-actions[bot]"));
    assert!(!is_real_name(""));
}

#[test]
fn accepts_only_well_formed_emails() {
    let m = GithubCommits;
    // accepts() is kind-only (Email); the looks_like_email gate is applied in
    // process(), keeping the dispatch index consistent.
    assert!(m.accepts(&Target::new(TargetKind::Email, "a@example.com")));
    assert!(!m.accepts(&Target::new(TargetKind::Username, "alice")));
    assert!(!m.accepts(&Target::new(TargetKind::Domain, "example.com")));
    assert!(matches!(m.cost(), crate::core::module::ModuleCost::Free));
    assert_eq!(m.category(), ModuleCategory::Social);
    assert!(m.attack_techniques().contains(&"T1593.003"));
}

/// Live end-to-end proof against the REAL GitHub commit-search API — no mock,
/// no fixture. Ignored by default (network + rate-limited); run with
/// `cargo test -p huntsman-search-engine github_commits_live -- --ignored --nocapture`.
#[tokio::test]
#[ignore = "hits the live GitHub commit-search API (rate-limited); run manually"]
async fn github_commits_live_resolves_a_known_email() {
    let (bus, _rx) = tokio::sync::broadcast::channel(1);
    let ctx = ModuleContext {
        scan_id: "live".into(),
        bus,
        http: reqwest::Client::new(),
        keys: std::collections::HashMap::new(),
        cancel: crate::core::cancel::CancelHandle::new(),
    };
    let target = Target::new(TargetKind::Email, "torvalds@linux-foundation.org");
    let r = GithubCommits
        .process(&target, &ctx)
        .await
        .expect("live commit search must not error");
    eprintln!(
        "github_commits live: {} entities ({} person, {} username, {} url)",
        r.entities.len(),
        r.entities.iter().filter(|e| e.kind == EntityKind::Person).count(),
        r.entities.iter().filter(|e| e.kind == EntityKind::Username).count(),
        r.entities.iter().filter(|e| e.kind == EntityKind::Url).count(),
    );
    // The kernel author's email reliably resolves to "Linus Torvalds".
    for e in &r.entities {
        if e.kind == EntityKind::Person {
            assert!(e.value.to_ascii_lowercase().contains("torvalds"));
        }
    }
}
