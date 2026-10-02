//! Serde types for the GitHub Code Search API responses.

use serde::Deserialize;

#[derive(Deserialize)]
pub(super) struct SearchResp {
    #[serde(default)]
    pub(super) items: Vec<CodeItem>,
}

#[derive(Deserialize)]
pub(super) struct CodeItem {
    #[serde(default)]
    pub(super) repository: Option<Repo>,
}

#[derive(Deserialize)]
pub(super) struct Repo {
    #[serde(default)]
    pub(super) full_name: Option<String>,
    #[serde(default)]
    pub(super) html_url: Option<String>,
    #[serde(default)]
    pub(super) description: Option<String>,
    #[serde(default)]
    pub(super) owner: Option<Owner>,
}

#[derive(Deserialize)]
pub(super) struct Owner {
    #[serde(default)]
    pub(super) login: Option<String>,
    #[serde(default)]
    pub(super) html_url: Option<String>,
}

#[derive(Deserialize)]
pub(super) struct CommitsResp {
    #[serde(default)]
    pub(super) commits: Vec<CommitItem>,
}

#[derive(Deserialize)]
pub(super) struct CommitItem {
    #[serde(default)]
    pub(super) commit: Option<CommitDetail>,
}

#[derive(Deserialize)]
pub(super) struct CommitDetail {
    #[serde(default)]
    pub(super) author: Option<CommitAuthor>,
}

#[derive(Deserialize)]
pub(super) struct CommitAuthor {
    #[serde(default)]
    pub(super) name: Option<String>,
    #[serde(default)]
    pub(super) email: Option<String>,
}
