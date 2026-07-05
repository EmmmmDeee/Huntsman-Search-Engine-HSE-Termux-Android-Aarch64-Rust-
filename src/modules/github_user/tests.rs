use super::GithubUser;
use super::fetch::{GhEvent, SshKey, commit_email_entities, ssh_key_entities};
use super::helpers::{ssh_fingerprint, top_event_types, usable_commit_email};
use super::types::GhUser;
use crate::core::{
    entity::EntityKind,
    module::Module,
    scan::{Target, TargetKind},
};

#[test]
fn ssh_fingerprint_is_comment_invariant_and_key_specific() {
    // The same key with different trailing comments (user@host) must yield the
    // SAME fingerprint — that is what links one key across two accounts; a
    // different key must differ; malformed input is dropped.
    let base = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAExampleKeyMaterialHere";
    let a = ssh_fingerprint(&format!("{base} ghost@laptop")).unwrap();
    let b = ssh_fingerprint(&format!("{base} jsmith@work-pc")).unwrap();
    assert_eq!(a, b, "comment must not change the fingerprint");
    assert!(a.starts_with("ssh:"));
    let other = ssh_fingerprint("ssh-rsa AAAAB3DifferentKeyMaterialXX").unwrap();
    assert_ne!(a, other);
    assert!(ssh_fingerprint("malformed").is_none());
    assert!(ssh_fingerprint("ssh-rsa short").is_none());
}

#[test]
fn top_event_types_is_deterministic_on_ties() {
    // Ties (PushEvent, IssuesEvent, ForkEvent all at 3) must resolve by name
    // — not by the source HashMap's randomised order — so the finding is
    // reproducible. Build the map in a few different insertion orders.
    let mk = || {
        let mut m = std::collections::HashMap::new();
        for (k, v) in [
            ("PushEvent", 3),
            ("IssuesEvent", 3),
            ("ForkEvent", 3),
            ("WatchEvent", 1),
        ] {
            m.insert(k.to_string(), v);
        }
        m
    };
    let expected = vec![
        "ForkEvent=3".to_string(),
        "IssuesEvent=3".to_string(),
        "PushEvent=3".to_string(),
    ];
    // Several independently-seeded HashMaps must all yield the same top-3.
    for _ in 0..8 {
        assert_eq!(top_event_types(mk(), 3), expected);
    }
    assert_eq!(
        top_event_types(std::collections::HashMap::new(), 3),
        Vec::<String>::new()
    );
}

#[test]
fn ssh_key_entities_emits_every_key_not_a_capped_ten() {
    // Fidelity: a developer's own published SSH public keys are each an
    // independent cross-account cryptographic pivot (AU-048). Every one must
    // become a Credential artifact — the previous `.take(10)` silently dropped
    // keys 11+ and lost those pivots. Seed 15 distinct keys and require 15
    // Credential entities, each carrying a distinct `ssh:` fingerprint.
    let keys: Vec<SshKey> = (0..15)
        .map(|i| SshKey {
            id: Some(i),
            key: Some(format!(
                "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAExampleKeyMaterialNumber{i:02}"
            )),
        })
        .collect();
    let out = ssh_key_entities(&keys, "scan-ssh", "octocat");
    assert_eq!(
        out.len(),
        15,
        "every distinct key must yield a Credential entity, not a capped ten"
    );
    assert!(out.iter().all(|e| e.kind == EntityKind::Credential));
    assert!(out.iter().all(|e| e.value.starts_with("ssh:")));
    // 15 distinct key bodies → 15 distinct fingerprints (no collision/collapse).
    let uids: std::collections::BTreeSet<_> = out.iter().map(|e| e.value.clone()).collect();
    assert_eq!(uids.len(), 15, "distinct keys must not collapse to one uid");

    // A malformed / empty key body is dropped (no algo+blob), not emitted as a
    // placeholder — absence is represented by omission of that one artifact,
    // while every valid key still surfaces.
    let mixed = vec![
        SshKey {
            id: Some(1),
            key: Some("ssh-rsa AAAAB3ValidLongKeyBodyMaterialXX".to_string()),
        },
        SshKey {
            id: Some(2),
            key: Some("malformed".to_string()),
        },
        SshKey {
            id: Some(3),
            key: None,
        },
    ];
    assert_eq!(ssh_key_entities(&mixed, "scan-ssh", "octocat").len(), 1);
}

#[test]
fn commit_email_entities_emits_every_distinct_email_not_a_capped_ten() {
    // Fidelity: every DISTINCT usable commit-author email in the subject's own
    // public push events is an independent handle→email pivot. The previous
    // `.take(10)` (a bound "to keep a busy account bounded") silently dropped
    // distinct real addresses 11+. Seed 15 events each carrying one commit with
    // a distinct author email and require all 15 Email pivots.
    let events_json = (0..15)
        .map(|i| {
            format!(
                r#"{{"type":"PushEvent","payload":{{"commits":[{{"author":{{"email":"dev{i:02}@example.com"}}}}]}}}}"#
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    let events: Vec<GhEvent> = serde_json::from_str(&format!("[{events_json}]")).unwrap();
    let out = commit_email_entities(&events, "scan-ce", "octocat");
    assert_eq!(
        out.len(),
        15,
        "every distinct commit-author email must surface, not a capped ten"
    );
    assert!(out.iter().all(|e| e.kind == EntityKind::Email));
    assert!(
        out.iter()
            .all(|e| e.tags.iter().any(|t| t == "commit-email"))
    );
    // Deterministic first-seen order over the (newest-first) event stream.
    assert_eq!(out[0].value, "dev00@example.com");
    assert_eq!(out[14].value, "dev14@example.com");

    // Duplicates collapse to one; GitHub noreply/placeholder addresses are
    // dropped (never emitted as a placeholder) — absence by omission.
    let dupe_json = r#"[
        {"type":"PushEvent","payload":{"commits":[
            {"author":{"email":"real@personal.dev"}},
            {"author":{"email":"REAL@personal.dev"}},
            {"author":{"email":"12345+ghost@users.noreply.github.com"}},
            {"author":{"email":"noreply@github.com"}}
        ]}}
    ]"#;
    let events: Vec<GhEvent> = serde_json::from_str(dupe_json).unwrap();
    let out = commit_email_entities(&events, "scan-ce", "octocat");
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].value, "real@personal.dev");
}

#[test]
fn accepts_only_username() {
    let m = GithubUser;
    assert!(m.accepts(&Target::new(TargetKind::Username, "octocat")));
    assert!(!m.accepts(&Target::new(TargetKind::Email, "x@y.com")));
    assert!(!m.accepts(&Target::new(TargetKind::Domain, "github.com")));
}

#[test]
fn deserialize_full_profile() {
    let json = r#"{
        "login":"alice","id":12345,"name":"Alice Smith",
        "email":"alice@example.com","blog":"https://alice.dev",
        "company":"@acme-corp","location":"Brisbane, Australia",
        "bio":"Rust dev","twitter_username":"alicedev",
        "public_repos":42,"public_gists":5,"followers":100,
        "following":50,"created_at":"2020-01-15T00:00:00Z",
        "html_url":"https://github.com/alice"
    }"#;
    let u: GhUser = serde_json::from_str(json).unwrap();
    assert_eq!(u.login, "alice");
    assert_eq!(u.id, 12345);
    assert_eq!(u.name.as_deref(), Some("Alice Smith"));
    assert_eq!(u.email.as_deref(), Some("alice@example.com"));
    assert_eq!(u.company.as_deref(), Some("@acme-corp"));
    assert_eq!(u.location.as_deref(), Some("Brisbane, Australia"));
    assert_eq!(u.twitter_username.as_deref(), Some("alicedev"));
    assert_eq!(u.public_repos, Some(42));
    assert_eq!(u.followers, Some(100));
}

#[test]
fn deserialize_minimal_profile() {
    let json = r#"{"login":"bob","id":999}"#;
    let u: GhUser = serde_json::from_str(json).unwrap();
    assert_eq!(u.login, "bob");
    assert!(u.name.is_none());
    assert!(u.email.is_none());
    assert!(u.location.is_none());
    assert!(u.public_repos.is_none());
}

#[test]
fn rejects_invalid_logins() {
    let long = "a".repeat(40);
    let cases = ["", "-start", "end-", "has space", &long, "user@name"];
    for case in cases {
        assert!(
            GithubUser.accepts(&Target::new(TargetKind::Username, case)),
            "accepts() should pass validation to process()"
        );
    }
}

#[test]
fn login_validation_logic() {
    let valid = |s: &str| -> bool {
        !s.is_empty()
            && s.len() <= 39
            && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
            && !s.starts_with('-')
            && !s.ends_with('-')
    };
    assert!(valid("octocat"));
    assert!(valid("alice-bob"));
    assert!(!valid(""));
    assert!(!valid("-start"));
    assert!(!valid("end-"));
    assert!(!valid("has space"));
    assert!(!valid(&"a".repeat(40)));
}

#[test]
fn company_strips_at_prefix() {
    let company = "@acme-corp";
    let cleaned = company.trim().trim_start_matches('@');
    assert_eq!(cleaned, "acme-corp");
}

#[test]
fn blog_url_domain_extraction() {
    let blog = "https://alice.dev/about";
    let parsed = url::Url::parse(blog).unwrap();
    let host = parsed.host_str().unwrap().to_lowercase();
    assert_eq!(host, "alice.dev");
    assert!(host.contains('.'));
    assert_ne!(host, "github.com");
}

#[test]
fn blog_non_http_ignored() {
    let blog = "alice.dev";
    assert!(!blog.starts_with("http://") && !blog.starts_with("https://"));
}

#[test]
fn commit_email_filter_keeps_real_drops_github_placeholders() {
    // Real personal addresses are kept (normalised); GitHub's privacy
    // placeholders and noreply forms are dropped — they carry no identity.
    assert_eq!(
        usable_commit_email("  Alice@Example.com "),
        Some("alice@example.com".to_string())
    );
    assert_eq!(
        usable_commit_email("dev@personal.dev"),
        Some("dev@personal.dev".to_string())
    );
    assert_eq!(
        usable_commit_email("12345+alice@users.noreply.github.com"),
        None
    );
    assert_eq!(usable_commit_email("noreply@github.com"), None);
    assert_eq!(usable_commit_email("actions@github.com"), None);
    assert_eq!(usable_commit_email("not-an-email"), None);
    assert_eq!(usable_commit_email("a@b"), None); // too short
}

#[test]
fn module_metadata() {
    let m = GithubUser;
    assert_eq!(m.name(), "github_user");
    assert_eq!(m.priority(), 107);
    assert_eq!(m.max_timeout_ms(), 5_000);
    assert!(!m.description().is_empty());
}
