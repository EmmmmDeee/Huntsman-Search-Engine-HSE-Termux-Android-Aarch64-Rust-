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
//!
//! Both the bio and the user's `submitted.json` listing (post titles/self-text
//! — real, unmoderated free text) are also run through the universal
//! `found_keys`/`key_harvest` classifier: redditors occasionally paste a code
//! snippet containing a live key/token in a self-text post. No extra fetch —
//! both bodies are already in memory for the entity extraction above.

use async_trait::async_trait;
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
            EntityKind::Domain,
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
        if !crate::util::str_util::is_handle(handle, 3, 20) {
            return Ok(ModuleResult::new());
        }

        let url = format!("https://www.reddit.com/user/{handle}/about.json");
        // 404 → unknown handle → clean empty. A descriptive UA is required or
        // Reddit returns 429 (which trips the circuit breaker, as intended).
        let resp: Option<AboutResp> = fetch_json_or_404(&ctx.http, SRC, &url).await?;
        let Some(data) = resp.and_then(|r| r.data) else {
            return Ok(ModuleResult::new());
        };

        let pool = crate::util::key_pool::global_pool();
        let mut result = ModuleResult::new();
        result.entities = build_entities(data, &ctx.scan_id, &pool);

        let submitted = fetch_submitted(&ctx.http, handle, &ctx.scan_id, &pool).await;
        result.extend(submitted);

        Ok(result)
    }
}

/// Pure account→entity mapping. Separated from `process()` so every branch is
/// unit-testable without I/O. Emits the confirmed Username with account metadata,
/// the `verified` tag when set, and an Email and/or Url mined from the profile bio.
pub(super) fn build_entities(
    data: AboutData,
    scan_id: &str,
    pool: &crate::util::key_pool::KeyPool,
) -> Vec<Entity> {
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

        // Also scan the bio for a leaked API key/credential via the universal
        // `found_keys`/`key_harvest` classifier — the same one `web_crawler`/
        // `username_search`/`wayback`/`hacker_news` run over their own
        // fetched text. No extra fetch — `bio` is already in memory.
        mine_keys_from_text(pool, &bio, &data.name, "bio");

        // Extract ALL emails from the bio (not just the first).
        for email in crate::util::extract::emails(&bio) {
            let mut e = Entity::new(EntityKind::Email, &email, 0.76, scan_id);
            e.tag("reddit");
            e.tag("public-profile");
            e.add_evidence(
                Evidence::new(SRC, format!("Email in Reddit bio of u/{}", data.name))
                    .with_attr("source", "reddit_bio"),
            );
            result.push(e);
        }
        // Extract ALL URLs from the bio; also emit the host as a Domain entity.
        for link in crate::util::extract::urls(&bio) {
            let link = link.as_str();
            let mut url_e = Entity::new(EntityKind::Url, link, 0.70, scan_id);
            url_e.tag("reddit");
            url_e.tag("personal-site");
            url_e.add_evidence(
                Evidence::new(SRC, format!("Link in Reddit bio of u/{}", data.name))
                    .with_attr("source", "reddit_bio"),
            );
            result.push(url_e);
            // Also emit the host domain as a pivot.
            if let Some(host) = crate::util::url_util::host_from_url(link)
                && host.contains('.')
                && host != "reddit.com"
            {
                let mut d = Entity::new(EntityKind::Domain, &host, 0.65, scan_id);
                d.tag("reddit");
                d.tag("derived");
                d.tag("personal-site");
                d.add_evidence(
                    Evidence::new(SRC, format!("Domain from Reddit bio of u/{}", data.name))
                        .with_attr("source_url", link)
                        .with_attr("reddit_handle", &data.name),
                );
                result.push(d);
            }
        }
    }

    result.entities
}

async fn fetch_submitted(
    http: &reqwest::Client,
    username: &str,
    scan_id: &str,
    pool: &crate::util::key_pool::KeyPool,
) -> Vec<Entity> {
    let url = format!(
        "https://www.reddit.com/user/{}/submitted.json?limit=25",
        crate::util::http::urlencode(username)
    );
    let Ok(resp) = http
        .get(&url)
        .header("User-Agent", crate::util::http::UA_OSINT)
        .send()
        .await
    else {
        return Vec::new();
    };
    if !resp.status().is_success() {
        return Vec::new();
    }
    // Capped read (32 MiB) for the needle scan below — an uncapped `text()`
    // would buffer an unbounded body on the low-RAM Termux target.
    let Some(body) =
        crate::util::http::read_body_capped(resp, crate::util::http::JSON_BODY_CAP).await
    else {
        return Vec::new();
    };

    // A user's post titles/self-text are real, unmoderated free text —
    // redditors routinely paste code snippets in text posts, occasionally
    // with a live key. Already-fetched bytes, no extra network cost.
    mine_keys_from_text(pool, &body, username, "submitted");

    submitted_entities(&body, username, scan_id)
}

/// Scan Reddit text (a bio or a `submitted.json` body) for a leaked API key
/// via the universal `found_keys`/`key_harvest` classifier — the same one
/// `web_crawler`/`username_search`/`wayback`/`hacker_news` run over their own
/// fetched bodies — and pool any poolable hit. No network I/O of its own, so
/// it's exercised directly by tests without mocking HTTP.
fn mine_keys_from_text(
    pool: &crate::util::key_pool::KeyPool,
    text: &str,
    username: &str,
    source_label: &str,
) {
    use crate::util::found_keys::{MAX_TOKEN, key_tokens};
    use crate::util::key_harvest::identify_api_key;

    for token in key_tokens(text, MAX_TOKEN) {
        if let Some((service, key_val)) = identify_api_key(token) {
            let mut entry = crate::util::key_pool::KeyEntry::new(key_val);
            entry.notes = Some(format!("Reddit {source_label} — user {username}"));
            entry.status = crate::util::key_pool::KeyStatus::Untested;
            entry.discovered_at = Some(crate::core::entity::unix_now());
            entry.discovered_by = Some(format!("reddit_user:{username}"));
            if pool.add(service, entry) {
                tracing::info!(
                    service,
                    username,
                    source_label,
                    "API key discovered in Reddit content"
                );
            }
        }
    }
}

/// Emit one `Organisation` entity per distinct subreddit a user posts in, parsed
/// from a `submitted.json` body. Pure and deterministic: the raw scan dedups
/// through a `HashSet` (randomised iteration order), so the distinct set is
/// sorted before emission — identical input always yields the identical entity
/// set in the identical order. EVERY distinct subreddit is emitted: the caller's
/// `limit=25` listing already bounds the set, so there is no flood to cap and a
/// prior `.take(10)` was silently dropping (and non-deterministically selecting)
/// real communities the handle participates in.
fn submitted_entities(body: &str, username: &str, scan_id: &str) -> Vec<Entity> {
    // Parse subreddit names from JSON without a full Deserialize struct; cap the
    // length to skip pathological values, and dedup across the listing.
    let mut subreddits: Vec<String> = crate::util::json::scan_string_field(body, "subreddit")
        .into_iter()
        .filter(|sub| sub.len() <= 50)
        .collect::<std::collections::HashSet<String>>()
        .into_iter()
        .collect();
    subreddits.sort_unstable();

    subreddits
        .into_iter()
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
