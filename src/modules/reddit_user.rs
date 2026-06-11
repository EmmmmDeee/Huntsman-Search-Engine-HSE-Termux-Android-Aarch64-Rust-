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

/// Caps on identifiers mined from one free-text bio — bounds entity fan-out on a
/// low-memory device while covering a profile that lists several links.
const MAX_BIO_EMAILS: usize = 3;
const MAX_BIO_URLS: usize = 5;

pub struct RedditUser;

#[derive(Deserialize)]
struct AboutResp {
    #[serde(default)]
    data: Option<AboutData>,
}

#[derive(Deserialize)]
struct AboutData {
    name: String,
    #[serde(default)]
    created_utc: Option<f64>,
    #[serde(default)]
    link_karma: Option<i64>,
    #[serde(default)]
    comment_karma: Option<i64>,
    #[serde(default)]
    verified: Option<bool>,
    #[serde(default)]
    is_gold: Option<bool>,
    #[serde(default)]
    subreddit: Option<Subreddit>,
}

#[derive(Deserialize)]
struct Subreddit {
    #[serde(default)]
    public_description: Option<String>,
    #[serde(default)]
    title: Option<String>,
}

/// Email + http(s) URL extractors for the free-text profile bio. Compiled once.
fn bio_patterns() -> &'static (Regex, Regex) {
    static RES: OnceLock<(Regex, Regex)> = OnceLock::new();
    RES.get_or_init(|| {
        (
            Regex::new(r"[\w.+-]+@[\w-]+\.[\w.-]+").unwrap(),
            Regex::new(r#"https?://[^\s"'<>)]+"#).unwrap(),
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

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[EntityKind::Username, EntityKind::Email, EntityKind::Url];
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

        let mut u = Entity::new(EntityKind::Username, &data.name, 0.90, &ctx.scan_id);
        u.tag("reddit");
        if data.verified == Some(true) {
            u.tag("verified");
        }
        let mut ev = Evidence::new(SRC, format!("Reddit account u/{}", data.name)).with_attr(
            "profile_url",
            format!("https://www.reddit.com/user/{}", data.name),
        );
        if let Some(k) = data.link_karma {
            ev = ev.with_attr("link_karma", k.to_string());
        }
        if let Some(k) = data.comment_karma {
            ev = ev.with_attr("comment_karma", k.to_string());
        }
        if let Some(c) = data.created_utc {
            ev = ev.with_attr("created_unix", (c as u64).to_string());
        }
        if let Some(g) = data.is_gold {
            ev = ev.with_attr("is_gold", g.to_string());
        }
        if let Some(v) = data.verified {
            ev = ev.with_attr("verified", v.to_string());
        }
        u.add_evidence(ev);
        result.push(u);

        // Mine the profile bio (public_description + title) for identity links.
        if let Some(sr) = data.subreddit.as_ref() {
            let bio = format!(
                "{} {}",
                sr.public_description.as_deref().unwrap_or(""),
                sr.title.as_deref().unwrap_or("")
            );
            // Capture every distinct identifier the bio publishes (deduped,
            // capped to bound fan-out on a phone), not just the first — a
            // profile commonly lists several links.
            let (email_re, url_re) = bio_patterns();
            let mut seen_emails: std::collections::HashSet<String> =
                std::collections::HashSet::new();
            for m in email_re.find_iter(&bio).take(MAX_BIO_EMAILS) {
                let email = m.as_str().to_lowercase();
                if !seen_emails.insert(email.clone()) {
                    continue;
                }
                let mut e = Entity::new(EntityKind::Email, &email, 0.76, &ctx.scan_id);
                e.tag("reddit");
                e.tag("public-profile");
                e.add_evidence(
                    Evidence::new(SRC, format!("Email in Reddit bio of u/{}", data.name))
                        .with_attr("source", "reddit_bio"),
                );
                result.push(e);
            }
            let mut seen_urls: std::collections::HashSet<&str> = std::collections::HashSet::new();
            for m in url_re.find_iter(&bio).take(MAX_BIO_URLS) {
                let link = m.as_str().trim_end_matches(['.', ',', ')']);
                if link.is_empty() || !seen_urls.insert(link) {
                    continue;
                }
                let mut url_e = Entity::new(EntityKind::Url, link, 0.70, &ctx.scan_id);
                url_e.tag("reddit");
                url_e.tag("personal-site");
                url_e.add_evidence(
                    Evidence::new(SRC, format!("Link in Reddit bio of u/{}", data.name))
                        .with_attr("source", "reddit_bio"),
                );
                result.push(url_e);
            }
        }

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_only_username() {
        let m = RedditUser;
        assert!(m.accepts(&Target::new(TargetKind::Username, "spez")));
        assert!(!m.accepts(&Target::new(TargetKind::Email, "x@y.com")));
    }

    #[test]
    fn metadata() {
        let m = RedditUser;
        assert_eq!(m.name(), "reddit_user");
        assert!(!m.description().is_empty());
        assert!(m.produces().contains(&EntityKind::Username));
    }

    #[test]
    fn deserializes_about_and_missing() {
        let json = r#"{"data":{"name":"spez","created_utc":1118030400.0,
            "link_karma":12,"comment_karma":34,"verified":true,"is_gold":false,
            "subreddit":{"public_description":"contact me@example.com https://example.com/me","title":"hi"}}}"#;
        let r: AboutResp = serde_json::from_str(json).unwrap();
        let d = r.data.unwrap();
        assert_eq!(d.name, "spez");
        assert_eq!(d.link_karma, Some(12));
        assert_eq!(d.verified, Some(true));
        // An empty/suspended response (no data) is a clean None.
        let empty: AboutResp = serde_json::from_str(r#"{"data":null}"#).unwrap();
        assert!(empty.data.is_none());
    }

    #[test]
    fn bio_extracts_email_and_url() {
        let (email_re, url_re) = bio_patterns();
        let bio = "Reach Me@Example.com — https://example.com/profile.";
        assert_eq!(
            email_re.find(bio).unwrap().as_str().to_lowercase(),
            "me@example.com"
        );
        let link = url_re
            .find(bio)
            .unwrap()
            .as_str()
            .trim_end_matches(['.', ',', ')']);
        assert_eq!(link, "https://example.com/profile");
    }

    #[test]
    fn handle_validation() {
        let valid = |s: &str| -> bool {
            s.len() >= 3
                && s.len() <= 20
                && s.chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        };
        assert!(valid("spez"));
        assert!(valid("kylo4kylo"));
        assert!(!valid("ab")); // too short
        assert!(!valid("this_handle_is_way_too_long"));
        assert!(!valid("has space"));
    }
}
