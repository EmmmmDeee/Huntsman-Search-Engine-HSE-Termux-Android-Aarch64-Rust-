//! Reddit user lookup. Free, no key — the official public `about.json` endpoint.
//!
//! Endpoint: `GET https://www.reddit.com/user/{name}/about.json`
//! (Reddit's documented public JSON; a descriptive `User-Agent` is required or
//! the endpoint 429s). Returns the public account under `data`:
//!
//! ```json
//! {"data":{"name":"spez","created_utc":1118030400,"link_karma":1,
//!          "comment_karma":1,"verified":true,"is_gold":false,
//!          "subreddit":{"public_description":"…bio…","title":"…"}}}
//! ```
//!
//! Why it earns a place in the keyless-API set: Reddit is one of the largest
//! username-keyed platforms, and `about.json` resolves a handle to a confirmed
//! account with rich metadata — karma, creation date, verified flag, and a
//! free-text profile bio that often links to the subject's other identifiers.
//! It is an INDEPENDENT provider in the **social** family, so a handle confirmed
//! here adds genuine cross-service agreement to the correlator's AU-045
//! multi-service identity confirmation. Anonymous calls are rate-limited; the
//! engine's circuit breaker trips on the 429 so a busy run stops re-hitting it.

use std::sync::OnceLock;

use async_trait::async_trait;
use regex::Regex;
use serde::Deserialize;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::fetch_json_or_404;

const SRC: &str = "reddit_user";

pub struct RedditUser;

#[derive(Deserialize)]
pub(super) struct AboutResp {
    #[serde(default)]
    pub(super) data: Option<AboutData>,
}

#[derive(Deserialize)]
pub(super) struct AboutData {
    pub(super) name: String,
    #[serde(default)]
    pub(super) created_utc: Option<f64>,
    #[serde(default)]
    pub(super) link_karma: Option<i64>,
    #[serde(default)]
    pub(super) comment_karma: Option<i64>,
    #[serde(default)]
    pub(super) verified: Option<bool>,
    #[serde(default)]
    pub(super) is_gold: Option<bool>,
    #[serde(default)]
    pub(super) subreddit: Option<Subreddit>,
}

#[derive(Deserialize)]
pub(super) struct Subreddit {
    #[serde(default)]
    pub(super) public_description: Option<String>,
    #[serde(default)]
    pub(super) title: Option<String>,
}

/// Email + http(s) URL extractors for the free-text profile bio. Compiled once.
fn bio_patterns() -> &'static (Regex, Regex) {
    static RES: OnceLock<(Regex, Regex)> = OnceLock::new();
    RES.get_or_init(|| {
        (
            Regex::new(r"[\w.+-]+@[\w-]+\.[\w.-]+").expect("constant bio email regex"),
            Regex::new(r#"https?://[^\s"'<>)]+"#).expect("constant bio url regex"),
        )
    })
}

#[async_trait]
impl Module for RedditUser {
    fn name(&self) -> &'static str {
        "reddit_user"
    }

    fn description(&self) -> &'static str {
        "Reddit account lookup (karma, created, verified, bio) via the official public API"
    }

    fn priority(&self) -> u8 {
        105
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Username)
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Social
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        // Social default (T1593.001 Social Media + T1589.003 Employee Names).
        // Reddit profiles carry no real-name Person entity — only a username and
        // optionally an email/URL from the profile. T1589.003 is over-claimed;
        // T1589.002 (Email Addresses) is the correct addition for profile emails.
        &["T1589.002", "T1593.001"]
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[
            EntityKind::Username,
            EntityKind::Email,
            EntityKind::Url,
            EntityKind::Organisation,
        ];
        KINDS
    }

    fn max_timeout_ms(&self) -> u64 {
        6_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let handle = target.value.trim();
        // Reddit usernames are 3–20 chars of [A-Za-z0-9_-]. Reject anything else
        // before the round-trip.
        if handle.len() < 3
            || handle.len() > 20
            || !handle
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return Ok(ModuleResult::new());
        }

        let url = format!("https://www.reddit.com/user/{handle}/about.json");
        // 404 → unknown handle → clean empty. A descriptive UA is required or
        // Reddit returns 429 (which trips the circuit breaker, as intended).
        let resp: Option<AboutResp> = fetch_json_or_404(&ctx.http, SRC, &url).await?;
        let Some(data) = resp.and_then(|r| r.data) else {
            return Ok(ModuleResult::new());
        };

        let mut result = ModuleResult::new();
        result.entities = build_entities(data, &ctx.scan_id);

        let submitted = fetch_submitted(&ctx.http, handle, &ctx.scan_id).await;
        result.extend(submitted);

        Ok(result)
    }
}

/// Pure account→entity mapping. Separated from `process()` so every branch is
/// unit-testable without I/O. Emits the confirmed Username with account metadata,
/// the `verified` tag when set, and an Email and/or Url mined from the profile bio.
pub(super) fn build_entities(data: AboutData, scan_id: &str) -> Vec<Entity> {
    let mut result = ModuleResult::new();

    let mut u = Entity::new(EntityKind::Username, &data.name, 0.90, scan_id);
    u.tag("reddit");
    if data.verified == Some(true) {
        u.tag("verified");
    }
    let ev = [
        ("link_karma", data.link_karma.map(|k| k.to_string())),
        ("comment_karma", data.comment_karma.map(|k| k.to_string())),
        (
            "created_unix",
            // Display-only epoch from untrusted JSON: clamp negative/NaN to 0
            // (an `f64 as u64` already saturates, but be explicit) before cast.
            data.created_utc.map(|c| (c.max(0.0) as u64).to_string()),
        ),
        ("is_gold", data.is_gold.map(|g| g.to_string())),
        ("verified", data.verified.map(|v| v.to_string())),
    ]
    .into_iter()
    .filter_map(|(key, value)| value.map(|v| (key, v)))
    .fold(
        Evidence::new(SRC, format!("Reddit account u/{}", data.name)).with_attr(
            "profile_url",
            format!("https://www.reddit.com/user/{}", data.name),
        ),
        |ev, (key, v)| ev.with_attr(key, v),
    );
    u.add_evidence(ev);
    result.push(u);

    if let Some(sr) = data.subreddit.as_ref() {
        let bio = format!(
            "{} {}",
            sr.public_description.as_deref().unwrap_or(""),
            sr.title.as_deref().unwrap_or("")
        );
        let (email_re, url_re) = bio_patterns();
        if let Some(m) = email_re.find(&bio) {
            let email = m.as_str().to_lowercase();
            let mut e = Entity::new(EntityKind::Email, &email, 0.76, scan_id);
            e.tag("reddit");
            e.tag("public-profile");
            e.add_evidence(
                Evidence::new(SRC, format!("Email in Reddit bio of u/{}", data.name))
                    .with_attr("source", "reddit_bio"),
            );
            result.push(e);
        }
        if let Some(m) = url_re.find(&bio) {
            let link = m.as_str().trim_end_matches(['.', ',', ')']);
            let mut url_e = Entity::new(EntityKind::Url, link, 0.70, scan_id);
            url_e.tag("reddit");
            url_e.tag("personal-site");
            url_e.add_evidence(
                Evidence::new(SRC, format!("Link in Reddit bio of u/{}", data.name))
                    .with_attr("source", "reddit_bio"),
            );
            result.push(url_e);
        }
    }

    result.entities
}

async fn fetch_submitted(http: &reqwest::Client, username: &str, scan_id: &str) -> Vec<Entity> {
    let url = format!(
        "https://www.reddit.com/user/{}/submitted.json?limit=25",
        crate::util::http::urlencode(username)
    );
    let Ok(resp) = http
        .get(&url)
        .header("User-Agent", "HSE/1.0 OSINT research tool")
        .send()
        .await
    else {
        return Vec::new();
    };
    if !resp.status().is_success() {
        return Vec::new();
    }
    let Ok(body) = resp.text().await else {
        return Vec::new();
    };

    let mut subreddits: std::collections::HashSet<String> = std::collections::HashSet::new();
    // Parse subreddit names from JSON without a full Deserialize struct
    let mut remaining = body.as_str();
    while let Some(pos) = remaining.find("\"subreddit\":\"") {
        remaining = &remaining[pos + 13..];
        let Some(end) = remaining.find('"') else {
            break;
        };
        let sub = &remaining[..end];
        if !sub.is_empty() && sub.len() <= 50 {
            subreddits.insert(sub.to_string());
        }
        remaining = &remaining[end..];
    }

    subreddits
        .into_iter()
        .take(10)
        .map(|sub| {
            let mut org = Entity::new(EntityKind::Organisation, &sub, 0.40, scan_id);
            org.tag("subreddit");
            org.add_evidence(
                Evidence::new("reddit_user", format!("u/{username} posts in r/{sub}"))
                    .with_attr("subreddit", &sub),
            );
            org
        })
        .collect()
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
