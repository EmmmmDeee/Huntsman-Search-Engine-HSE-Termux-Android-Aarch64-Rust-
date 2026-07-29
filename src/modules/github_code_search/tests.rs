use super::build::{build_commit_emails, build_repo_entities};
use super::types::{CodeItem, CommitAuthor, CommitDetail, CommitItem, CommitsResp};
use super::{GithubCodeSearch, ModuleCost};
use crate::core::{
    confidence,
    entity::EntityKind,
    module::Module,
    scan::{Target, TargetKind},
};

fn item_from_json(json: &str) -> CodeItem {
    serde_json::from_str(json).expect("should succeed")
}

#[test]
fn accepts_email_and_username_only() {
    let m = GithubCodeSearch;
    assert!(m.accepts(&Target::new(TargetKind::Email, "a@b.com")));
    assert!(m.accepts(&Target::new(TargetKind::Username, "haigen")));
    assert!(!m.accepts(&Target::new(TargetKind::FullName, "Haigen Bamford")));
    assert!(!m.accepts(&Target::new(TargetKind::Domain, "example.com")));
}

#[test]
fn module_metadata() {
    let m = GithubCodeSearch;
    assert_eq!(m.name(), "github_code_search");
    assert_eq!(m.cost(), ModuleCost::Free);
    assert!(m.attack_techniques().contains(&"T1593.003"));
    assert!(m.attack_techniques().contains(&"T1589.002"));
}

#[test]
fn build_repo_entities_exact_owner_match() {
    let item = item_from_json(
        r#"{"repository":{"full_name":"haigen/dotfiles","html_url":"https://github.com/haigen/dotfiles",
            "description":"my configs","owner":{"login":"haigen","html_url":"https://github.com/haigen"}}}"#,
    );
    let ents = build_repo_entities(&item, "haigen", TargetKind::Username, "s");
    let url_e = ents
        .iter()
        .find(|e| e.kind == EntityKind::Url)
        .expect("should succeed");
    assert!(url_e.confidence >= 0.58);
    assert!(url_e.has_tag("code-repo") && url_e.has_tag("github"));

    let user_e = ents
        .iter()
        .find(|e| e.kind == EntityKind::Username)
        .expect("should succeed");
    assert_eq!(user_e.value, "haigen");
    assert!(user_e.confidence >= confidence::HIGH);
    assert!(user_e.has_tag("repo-owner"));
}

#[test]
fn build_repo_entities_low_conf_unrelated() {
    // A repo that doesn't mention the seed at all → low-confidence candidate.
    let item = item_from_json(
        r#"{"repository":{"full_name":"other/project","html_url":"https://github.com/other/project",
            "description":"unrelated","owner":{"login":"other","html_url":"https://github.com/other"}}}"#,
    );
    let ents = build_repo_entities(&item, "haigen@example.com", TargetKind::Email, "s");
    let url_e = ents
        .iter()
        .find(|e| e.kind == EntityKind::Url)
        .expect("should succeed");
    assert!(
        url_e.confidence < confidence::MEDIUM,
        "unrelated repo should be sub-floor"
    );
}

#[test]
fn build_commit_emails_filters_noreply() {
    let commits = CommitsResp {
        commits: vec![
            CommitItem {
                commit: Some(CommitDetail {
                    author: Some(CommitAuthor {
                        name: Some("Alice".into()),
                        email: Some("alice@example.com".into()),
                    }),
                }),
            },
            CommitItem {
                commit: Some(CommitDetail {
                    author: Some(CommitAuthor {
                        name: Some("Bot".into()),
                        email: Some("123+bot@users.noreply.github.com".into()),
                    }),
                }),
            },
        ],
    };
    let ents = build_commit_emails(&commits, "test/repo", "s");
    assert_eq!(ents.len(), 1);
    assert_eq!(ents[0].value, "alice@example.com");
    assert!(ents[0].has_tag("commit-author"));
}

#[test]
fn build_commit_emails_deduplicates() {
    let commits = CommitsResp {
        commits: vec![
            CommitItem {
                commit: Some(CommitDetail {
                    author: Some(CommitAuthor {
                        name: Some("Alice".into()),
                        email: Some("Alice@Example.COM".into()),
                    }),
                }),
            },
            CommitItem {
                commit: Some(CommitDetail {
                    author: Some(CommitAuthor {
                        name: Some("Alice again".into()),
                        email: Some("alice@example.com".into()),
                    }),
                }),
            },
        ],
    };
    let ents = build_commit_emails(&commits, "test/repo", "s");
    let email_ents: Vec<_> = ents
        .iter()
        .filter(|e| e.kind == crate::core::entity::EntityKind::Email)
        .collect();
    assert_eq!(
        email_ents.len(),
        1,
        "duplicate lowercased email should be deduped to one Email entity"
    );
}
