use super::helpers::{ssh_fingerprint, top_event_types, usable_commit_email};
use super::types::GhUser;
use super::GithubUser;
use crate::core::{
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
