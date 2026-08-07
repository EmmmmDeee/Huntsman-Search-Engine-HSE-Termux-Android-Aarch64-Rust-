//! Hacker News user lookup. Free, no key — the official public Firebase API.
//!
//! Endpoint: `GET https://hacker-news.firebaseio.com/v0/user/{id}.json`
//! (documented at <https://github.com/HackerNews/API>). Returns the public
//! account JSON, or the literal `null` for an unknown handle:
//!
//! ```json
//! {"id":"pg","created":1160418092,"karma":157222,"about":"…html…","submitted":[…]}
//! ```
//!
//! Why it earns its place in the keyless-API set: it resolves a *username* to a
//! confirmed real account with rich, structured metadata — creation date, karma,
//! and a free-text `about` bio that frequently carries the subject's email or
//! personal site. That makes HN an independent provider in the **social/dev**
//! family, so a handle confirmed here adds genuine cross-service agreement to the
//! correlator's AU-045 "multi-service identity confirmation" (rather than echoing
//! a single source). Official, stable, and rate-limit-free.

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
use crate::util::http::fetch_json;

const SRC: &str = "hacker_news";

pub struct HackerNews;

#[derive(Deserialize)]
struct HnUser {
    id: String,
    #[serde(default)]
    created: Option<u64>,
    #[serde(default)]
    karma: Option<i64>,
    #[serde(default)]
    about: Option<String>,
    #[serde(default)]
    submitted: Option<Vec<i64>>,
}

/// Email extractor for the free-text `about` bio. Compiled once (codebase
/// convention). This bio matcher intentionally keeps its looser `\w`-based
/// grammar; URL extraction uses the canonical `util::extract::URL_RE`.
fn bio_email_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"[\w.+-]+@[\w-]+\.[\w.-]+").expect("constant bio email regex"))
}

#[async_trait]
impl Module for HackerNews {
    fn name(&self) -> &'static str {
        "hacker_news"
    }

    fn description(&self) -> &'static str {
        "Hacker News account lookup (karma, created, bio) via the official public API"
    }

    fn priority(&self) -> u8 {
        106
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Username)
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Social
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        // Social default (T1593.001 Social Media + T1589.003 Employee Names).
        // HN profiles carry no real-name Person entity — only a Username and
        // optionally an email/URL from the bio. T1589.003 is over-claimed;
        // T1589.002 (Email Addresses) is the correct addition for bio emails.
        &["T1589.002", "T1593.001"]
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
        // HN handles are 2–15 chars of [A-Za-z0-9_-]. Reject anything else
        // before spending an HTTP round-trip.
        if handle.len() < 2
            || handle.len() > 15
            || !handle
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return Ok(ModuleResult::new());
        }

        let url = format!("https://hacker-news.firebaseio.com/v0/user/{handle}.json");
        // The API returns JSON `null` for an unknown user → deserialize as Option
        // so "not found" is a clean empty result, not an error.
        let user: Option<HnUser> = fetch_json(&ctx.http, SRC, &url).await?;
        let Some(user) = user else {
            return Ok(ModuleResult::new());
        };

        let mut result = ModuleResult::new();

        // The confirmed-on-HN username, carrying account metadata as evidence.
        let mut u = Entity::new(EntityKind::Username, &user.id, 0.90, &ctx.scan_id);
        u.tag("hacker-news");
        let submissions = user.submitted.as_ref().map_or(0, Vec::len);
        let ev = [
            ("karma", user.karma.map(|k| k.to_string())),
            ("created_unix", user.created.map(|c| c.to_string())),
        ]
        .into_iter()
        .filter_map(|(key, value)| value.map(|v| (key, v)))
        .fold(
            Evidence::new(SRC, format!("Hacker News account '{}'", user.id))
                .with_attr(
                    "profile_url",
                    format!("https://news.ycombinator.com/user?id={}", user.id),
                )
                .with_attr("submissions", submissions.to_string()),
            |ev, (key, v)| ev.with_attr(key, v),
        );
        u.add_evidence(ev);
        result.push(u);

        // Mine the free-text bio for identity: an email or personal site here is
        // a high-value, operator-published link from the handle to a real
        // identifier — exactly the cross-reference the correlator wants.
        if let Some(about) = user.about.as_deref() {
            if let Some(m) = bio_email_re().find(about) {
                let email = m.as_str().to_lowercase();
                let mut e = Entity::new(EntityKind::Email, &email, 0.78, &ctx.scan_id);
                e.tag("hacker-news");
                e.tag("public-profile");
                e.add_evidence(
                    Evidence::new(SRC, format!("Email in HN bio of '{}'", user.id))
                        .with_attr("source", "hn_bio"),
                );
                result.push(e);
            }
            if let Some(m) = crate::util::extract::URL_RE.find(about) {
                let link = m.as_str().trim_end_matches(['.', ',', ')']);
                let mut url_e = Entity::new(EntityKind::Url, link, 0.72, &ctx.scan_id);
                url_e.tag("hacker-news");
                url_e.tag("personal-site");
                url_e.add_evidence(
                    Evidence::new(SRC, format!("Link in HN bio of '{}'", user.id))
                        .with_attr("source", "hn_bio"),
                );
                result.push(url_e);
            }
        }

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
