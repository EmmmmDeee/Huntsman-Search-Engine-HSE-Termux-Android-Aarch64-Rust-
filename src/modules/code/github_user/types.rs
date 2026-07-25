use serde::Deserialize;

#[derive(Deserialize)]
pub(super) struct GhUser {
    pub(super) login: String,
    pub(super) id: u64,
    pub(super) name: Option<String>,
    pub(super) email: Option<String>,
    pub(super) blog: Option<String>,
    pub(super) company: Option<String>,
    pub(super) location: Option<String>,
    pub(super) bio: Option<String>,
    pub(super) twitter_username: Option<String>,
    pub(super) public_repos: Option<u64>,
    pub(super) public_gists: Option<u64>,
    pub(super) followers: Option<u64>,
    pub(super) following: Option<u64>,
    pub(super) created_at: Option<String>,
    pub(super) html_url: Option<String>,
}
