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

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::extract::URL_RE;
use crate::util::http::fetch_json;

const SRC: &str = "hacker_news";

pub struct HackerNews;

#[derive(Deserialize)]
pub(super) struct HnUser {
    pub(super) id: String,
    #[serde(default)]
    pub(super) created: Option<u64>,
    #[serde(default)]
    pub(super) karma: Option<i64>,
    #[serde(default)]
    pub(super) about: Option<String>,
    #[serde(default)]
    pub(super) submitted: Option<Vec<i64>>,
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
        const KINDS: &[EntityKind] = &[
            EntityKind::Username,
            EntityKind::Email,
            EntityKind::Url,
            EntityKind::Domain,
        ];
        KINDS
    }

    fn max_timeout_ms(&self) -> u64 {
        6_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let handle = target.value.trim();
        // HN handles are 2–15 chars of [A-Za-z0-9_-]. Reject anything else
        // before spending an HTTP round-trip.
        if !crate::util::str_util::is_handle(handle, 2, 15) {
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
        result.entities = build_entities(user, &ctx.scan_id);

        let algolia_entities = fetch_algolia_submissions(&ctx.http, handle, &ctx.scan_id).await;
        result.extend(algolia_entities);

        Ok(result)
    }
}

/// Pure account→entity mapping. Separated from `process()` so every branch is
/// unit-testable without I/O. Emits the confirmed Username with account metadata,
/// plus an Email and/or Url when found in the free-text `about` bio.
pub(super) fn build_entities(user: HnUser, scan_id: &str) -> Vec<Entity> {
    let mut result = ModuleResult::new();

    let mut u = Entity::new(EntityKind::Username, &user.id, 0.90, scan_id);
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

    if let Some(about) = user.about.as_deref() {
        // Extract ALL emails and URLs from the bio (HN bios are HTML-escaped
        // free text; both often appear multiple times in developer profiles).
        for email in crate::util::extract::emails(about) {
            let mut e = Entity::new(EntityKind::Email, &email, 0.78, scan_id);
            e.tag("hacker-news");
            e.tag("public-profile");
            e.add_evidence(
                Evidence::new(SRC, format!("Email in HN bio of '{}'", user.id))
                    .with_attr("source", "hn_bio"),
            );
            result.push(e);
        }
        let mut seen_urls: std::collections::HashSet<String> = std::collections::HashSet::new();
        for m in URL_RE.find_iter(about) {
            let link = m.as_str().trim_end_matches(['.', ',', ')']);
            if !seen_urls.insert(link.to_string()) {
                continue;
            }
            let mut url_e = Entity::new(EntityKind::Url, link, 0.72, scan_id);
            url_e.tag("hacker-news");
            url_e.tag("personal-site");
            url_e.add_evidence(
                Evidence::new(SRC, format!("Link in HN bio of '{}'", user.id))
                    .with_attr("source", "hn_bio"),
            );
            result.push(url_e);
            if let Some(host) = crate::util::url_util::host_from_url(link)
                && host.contains('.')
                && host != "ycombinator.com"
                && host != "news.ycombinator.com"
            {
                let mut d = Entity::new(EntityKind::Domain, &host, 0.65, scan_id);
                d.tag("hacker-news");
                d.tag("derived");
                d.add_evidence(
                    Evidence::new(SRC, format!("Domain from HN bio of '{}'", user.id))
                        .with_attr("source_url", link)
                        .with_attr("hn_username", &user.id),
                );
                result.push(d);
            }
        }
    }

    result.entities
}

async fn fetch_algolia_submissions(
    http: &reqwest::Client,
    username: &str,
    scan_id: &str,
) -> Vec<Entity> {
    let url = format!(
        "https://hn.algolia.com/api/v1/search?tags=author_{}&hitsPerPage=50",
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

    algolia_domain_entities(&body, username, scan_id)
}

/// Emit one `Domain` entity per distinct domain linked from a user's HN
/// submissions, parsed from an Algolia `search` response body. Pure and
/// deterministic: the raw scan dedups through a `HashSet` (randomised
/// iteration order), so the distinct set is sorted before emission —
/// identical input always yields the identical entity set in the identical
/// order (a `HashSet` walked straight into `ModuleResult.entities`
/// previously let the same submissions produce differently-ordered `Domain`
/// entities — and a differently-ordered live `EntityFound` event stream —
/// across runs, the same determinism-leak class already fixed for
/// `reddit_user::submitted_entities`).
fn algolia_domain_entities(body: &str, username: &str, scan_id: &str) -> Vec<Entity> {
    // Extract URLs from "url":"..." fields, then reduce to deduped domains.
    let mut domains: Vec<String> = crate::util::json::scan_string_field(body, "url")
        .iter()
        .filter_map(|url_str| extract_domain_from_url(url_str))
        .collect::<std::collections::HashSet<String>>()
        .into_iter()
        .collect();
    domains.sort_unstable();

    domains
        .into_iter()
        .map(|dom| {
            let mut d = Entity::new(EntityKind::Domain, &dom, 0.50, scan_id);
            d.tag("hn-submission");
            d.add_evidence(
                Evidence::new(
                    "hacker_news",
                    format!("HN submissions by {username} link to {dom}"),
                )
                .with_attr("domain", &dom),
            );
            d
        })
        .collect()
}

fn extract_domain_from_url(url: &str) -> Option<String> {
    let without_scheme = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))?;
    let domain = without_scheme.split('/').next()?;
    let domain = domain.split('?').next()?;
    let domain = domain.split('#').next()?;
    // Remove port
    let domain = domain.split(':').next()?;
    if domain.contains('.') && domain.len() >= 4 {
        Some(domain.to_string())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
