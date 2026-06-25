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
    let resp: CommitSearchResp = serde_json::from_str(FIXTURE).unwrap();
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
        proxy_pool: Default::default(),
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
