//! crates.io user lookup. Free, no key — the official public registry API.
//!
//! Endpoint: `GET https://crates.io/api/v1/users/{login}`
//! (documented at <https://crates.io/data-access>; a descriptive User-Agent is
//! required by their crawler policy, which the shared client supplies). Returns
//! the registry account:
//!
//! ```json
//! {"user":{"id":1,"login":"alice","name":"Alice Smith",
//!          "avatar":"https://avatars.githubusercontent.com/u/1",
//!          "url":"https://github.com/alice"}}
//! ```
//!
//! Why it earns a place in the keyless-API set: it confirms the handle on a
//! code-registry platform (the `code` family), exposes the maintainer's REAL
//! NAME (a handle→identity link feeding AU-046), and — because crates.io
//! authenticates via GitHub — its `url` field ties the handle to the owner's
//! GitHub profile, a cross-platform confirmation. Official, keyless, exact-match.

use async_trait::async_trait;
use serde::Deserialize;

use super::profile_kit;
use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::fetch_json_or_404;

const SRC: &str = "crates_io";

pub struct CratesIo;

#[derive(Deserialize)]
struct UserResp {
    #[serde(default)]
    user: Option<CrateUser>,
}

#[derive(Deserialize)]
struct CrateUser {
    login: String,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    url: Option<String>,
}

/// Map a decoded crates.io user record to its entities. **Pure** (no network),
/// so the account→identity→linked-profile mapping is unit-testable off JSON.
///
/// | source                              | output                                 |
/// |-------------------------------------|----------------------------------------|
/// | `user.login`                        | `Username` (+ `crates-io`/`code` tags) |
/// | `user.name` (non-blank, ≥ 2 words)  | `Person` pivot + `name` attr           |
/// | `user.url` (`http(s)://…`)          | `Url` linked-profile pivot             |
///
/// Empty when the response carries no `user` (the caller maps a 404 to the same
/// no-user shape). A blank `name` adds neither the evidence attr nor the Person
/// pivot; a placeholder name (per [`crate::core::validation::is_placeholder_entity`])
/// is likewise not promoted.
fn build_entities(body: &UserResp, scan_id: &str) -> Vec<Entity> {
    let Some(user) = body.user.as_ref() else {
        return Vec::new();
    };

    let mut result = Vec::new();

    // The confirmed-on-crates.io username.
    let mut u = Entity::new(EntityKind::Username, &user.login, 0.88, scan_id);
    u.tag("crates-io");
    u.tag("code");
    let mut ev = Evidence::new(SRC, format!("crates.io registry account '{}'", user.login))
        .with_attr(
            "profile_url",
            format!("https://crates.io/users/{}", user.login),
        );
    if let Some(n) = user.name.as_deref().filter(|n| !n.is_empty()) {
        ev = ev.with_attr("name", n);
    }
    u.add_evidence(ev);
    result.push(u);

    // Real name → Person (handle→identity).
    if let Some(name) = user.name.as_deref()
        && let Some(mut p) = profile_kit::person_from_name(name, 0.70, scan_id)
    {
        p.tag("crates-io");
        p.tag("derived");
        p.add_evidence(
            Evidence::new(
                SRC,
                format!("Real name from crates.io account '{}'", user.login),
            )
            .with_attr("crates_login", &user.login),
        );
        result.push(p);
    }

    // The linked profile URL (crates.io auths via GitHub, so this is usually
    // the owner's GitHub profile — a cross-platform confirmation).
    if let Some(link) = user.url.as_deref()
        && (link.starts_with("http://") || link.starts_with("https://"))
    {
        let mut url_e = Entity::new(EntityKind::Url, link, 0.74, scan_id);
        url_e.tag("crates-io");
        url_e.tag("linked-profile");
        url_e.add_evidence(
            Evidence::new(
                SRC,
                format!("Linked profile of crates.io user '{}'", user.login),
            )
            .with_attr("source", "crates_io_profile"),
        );
        result.push(url_e);

        // Direct GitHub username extraction — crates.io authenticates via GitHub
        // so the url field is nearly always `https://github.com/{handle}`.
        // Emitting the Username directly saves one expansion round-trip.
        if let Some(gh_user) = github_username_from_url(link) {
            let mut g = Entity::new(EntityKind::Username, gh_user, 0.80, scan_id);
            g.tag("github");
            g.tag("crates-io-pivot");
            g.add_evidence(
                Evidence::new(
                    SRC,
                    format!("GitHub username from crates.io profile of '{}'", user.login),
                )
                .with_attr("source_url", link)
                .with_attr("crates_login", &user.login),
            );
            result.push(g);
        }
    }

    result
}

/// Extract the GitHub username from a URL of the form
/// `https://github.com/{username}` (path depth exactly 1, no trailing slash).
/// Returns `None` for any other URL shape.
fn github_username_from_url(url: &str) -> Option<&str> {
    let path = url
        .strip_prefix("https://github.com/")
        .or_else(|| url.strip_prefix("http://github.com/"))?;
    // Must be a bare username — no slashes (would be a repo/path), no query.
    if path.is_empty() || path.contains('/') || path.contains('?') || path.contains('#') {
        return None;
    }
    Some(path)
}

#[async_trait]
impl Module for CratesIo {
    fn name(&self) -> &'static str {
        "crates_io"
    }

    fn description(&self) -> &'static str {
        "crates.io registry user lookup (real name + linked GitHub) via the official API"
    }

    fn priority(&self) -> u8 {
        103
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Username)
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Social
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        // crates.io author packages — ATT&CK Code Repositories (T1593.003).
        &["T1593.003"]
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[EntityKind::Username, EntityKind::Person, EntityKind::Url];
        KINDS
    }

    fn max_timeout_ms(&self) -> u64 {
        6_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let handle = target.value.trim();
        // crates.io logins mirror GitHub logins: alphanumeric + hyphen, ≤39 chars.
        if handle.is_empty()
            || handle.len() > 39
            || !handle
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-')
        {
            return Ok(ModuleResult::new());
        }

        let url = format!("https://crates.io/api/v1/users/{handle}");
        let Some(body): Option<UserResp> = fetch_json_or_404(&ctx.http, SRC, &url).await? else {
            return Ok(ModuleResult::new());
        };

        let mut result = ModuleResult::new();
        result.entities = build_entities(&body, &ctx.scan_id);
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
