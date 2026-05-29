//! Hacker News — username activity pivot via the Algolia HN Search API.
//!
//! Endpoint: `GET https://hn.algolia.com/api/v1/search?tags=author_{user}`
//! Auth: None — fully public, no key, generous unauthenticated quota.
//!
//! Given a username, this confirms a Hacker News account and harvests the
//! account's public footprint: submission/comment timestamps, the URLs the
//! user has shared, and the domains behind them. Two OSINT payoffs:
//!
//!  1. **Behavioural timeline.** Every hit carries an ISO-8601 `created_at`.
//!     Those land on the entities under the `created_at` / `first_seen` /
//!     `last_seen` attribute keys the `core::temporal` engine already mines —
//!     so a prolific account feeds the AU-033 diurnal timezone inference for
//!     free, with no extra wiring.
//!  2. **Interest graph.** Submitted URLs and their registrable hosts become
//!     `Url` / `Domain` entities — the sites a subject reads and shares, a
//!     durable interest/affiliation signal and an infrastructure pivot.
//!
//! HN's population skews developer / security-researcher, which dovetails
//! with the platform's analytical corpus (Schneier et al.).

use std::collections::HashSet;

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::{Error, Result},
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
    tags,
};
use crate::util::http::urlencode;
use crate::util::url_util::host_from_url;

const SRC: &str = "hackernews";

/// Hits requested per query. The Algolia free tier caps `hitsPerPage` at
/// 1000; 50 is plenty to characterise activity and timezone without
/// hammering the endpoint on a mobile link.
const HITS_PER_PAGE: u32 = 50;

/// Hard cap on URL/domain entities emitted, independent of hit count.
const MAX_LINK_ENTITIES: usize = 40;

// ─── Wire types ──────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct SearchResp {
    #[serde(default)]
    hits: Vec<Hit>,
    #[serde(rename = "nbHits", default)]
    nb_hits: u64,
}

#[derive(Deserialize, Default)]
struct Hit {
    #[serde(rename = "objectID", default)]
    object_id: Option<String>,
    #[serde(default)]
    title: Option<String>,
    #[serde(default)]
    url: Option<String>,
    #[serde(rename = "story_url", default)]
    story_url: Option<String>,
    #[serde(rename = "created_at", default)]
    created_at: Option<String>,
    #[serde(default)]
    points: Option<i64>,
}

impl Hit {
    /// The submitted link for this hit, if any (stories carry `url`,
    /// comments may carry the parent `story_url`).
    fn link(&self) -> Option<&str> {
        self.url
            .as_deref()
            .or(self.story_url.as_deref())
            .map(str::trim)
            .filter(|s| s.starts_with("http"))
    }
}

// ─── Module ──────────────────────────────────────────────────────────────────

pub struct HackerNews;

#[async_trait]
impl Module for HackerNews {
    fn name(&self) -> &'static str {
        "hackernews"
    }

    fn description(&self) -> &'static str {
        "Hacker News account footprint via the Algolia HN Search API (free, no key)"
    }

    fn priority(&self) -> u8 {
        28
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Username) && is_plausible_handle(&t.value)
    }

    /// `accepts()` gates on value *shape* (`is_plausible_handle`), so the
    /// probe-based default `consumes()` would mis-derive the input set
    /// depending on the probe value. Declare it explicitly — the dispatch
    /// index in `core::dependency` is built from this.
    fn consumes(&self) -> Vec<TargetKind> {
        vec![TargetKind::Username]
    }

    fn cost(&self) -> crate::core::module::ModuleCost {
        crate::core::module::ModuleCost::Free
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Social
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[EntityKind::Username, EntityKind::Url, EntityKind::Domain];
        KINDS
    }

    fn max_timeout_ms(&self) -> u64 {
        8_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let user = target.value.trim();
        if !is_plausible_handle(user) {
            return Ok(ModuleResult::new());
        }

        let url = format!(
            "https://hn.algolia.com/api/v1/search?tags=author_{}&hitsPerPage={HITS_PER_PAGE}",
            urlencode(user)
        );

        let resp = ctx
            .http
            .get(&url)
            .header("Accept", "application/json")
            .timeout(std::time::Duration::from_millis(self.max_timeout_ms()))
            .send()
            .await
            .map_err(|e| Error::module(SRC, e.to_string()))?;

        let status = resp.status();
        if !status.is_success() {
            return Err(Error::module(SRC, format!("HTTP {status}")));
        }

        let data: SearchResp = resp
            .json()
            .await
            .map_err(|e| Error::module(SRC, format!("JSON: {e}")))?;

        // Unknown authors return 200 with an empty hit list — not a finding.
        if data.hits.is_empty() {
            return Ok(ModuleResult::new());
        }

        Ok(ModuleResult {
            entities: entities_from_hits(user, &data.hits, data.nb_hits, &ctx.scan_id),
        })
    }
}

// ─── Pure core (network-free, unit-tested) ───────────────────────────────────

/// HN handles are 2–15 chars: ASCII letters, digits, `_` and `-`. Gate on
/// this so the dispatch index never sends an email-shaped or path-shaped
/// value to the author search.
fn is_plausible_handle(s: &str) -> bool {
    let s = s.trim();
    (2..=15).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// Transform a hit set into entities. Pure and deterministic so the mapping
/// logic is testable without a live endpoint.
///
/// Emits exactly one `Username` entity (the confirmed account, carrying the
/// activity span as behavioural timestamps), plus de-duplicated `Url` and
/// `Domain` entities for the links the account has shared.
fn entities_from_hits(user: &str, hits: &[Hit], nb_hits: u64, scan_id: &str) -> Vec<Entity> {
    // No public activity ⇒ no confirmed account ⇒ no finding.
    if hits.is_empty() {
        return Vec::new();
    }
    let mut out: Vec<Entity> = Vec::new();

    // Confirmed-account confidence rises with observed activity volume and
    // saturates: a single hit is suggestive, twenty is conclusive.
    let observed = hits.len().max(1);
    let volume = (observed as f64 / 20.0).clamp(0.0, 1.0);
    let confidence = 0.15f64.mul_add(volume, 0.62).clamp(0.0, 0.85);

    let total_points: i64 = hits.iter().filter_map(|h| h.points).sum();
    let timestamps: Vec<&str> = hits
        .iter()
        .filter_map(|h| h.created_at.as_deref())
        .collect();
    let earliest = timestamps.iter().min().copied();
    let latest = timestamps.iter().max().copied();

    let mut acct = Entity::new(EntityKind::Username, user, confidence, scan_id);
    acct.tag(tags::SOCIAL_PROFILE);
    acct.tag("hackernews");
    let mut ev = Evidence::new(SRC, format!("Hacker News account '{user}'"))
        .with_attr(
            "profile_url",
            format!("https://news.ycombinator.com/user?id={user}"),
        )
        .with_attr("items_observed", observed.to_string())
        .with_attr("total_items", nb_hits.to_string())
        .with_attr("total_points", total_points.to_string());
    // Behavioural timestamps — keys recognised by `core::temporal`.
    if let Some(first) = earliest {
        ev = ev.with_attr("first_seen", first);
    }
    if let Some(last) = latest {
        ev = ev.with_attr("last_seen", last);
    }
    acct.add_evidence(ev);
    out.push(acct);

    // Submitted links → Url + Domain entities, de-duplicated, capped.
    let mut seen_urls: HashSet<String> = HashSet::new();
    let mut seen_domains: HashSet<String> = HashSet::new();
    let mut link_count = 0usize;

    for hit in hits {
        if link_count >= MAX_LINK_ENTITIES {
            break;
        }
        let Some(link) = hit.link() else { continue };
        let link = link.to_string();
        if !seen_urls.insert(link.clone()) {
            continue;
        }
        link_count += 1;

        let mut u = Entity::new(EntityKind::Url, &link, 0.50, scan_id);
        u.tag(tags::WEB);
        u.tag(tags::SEARCH_DISCOVERED);
        u.tag("hackernews");
        let mut uev = Evidence::new(SRC, format!("Shared on Hacker News by '{user}'"));
        if let Some(t) = hit.title.as_deref().filter(|s| !s.is_empty()) {
            uev = uev.with_attr("title", t);
        }
        if let Some(ts) = hit.created_at.as_deref() {
            uev = uev.with_attr("created_at", ts); // behavioural timestamp
        }
        if let Some(p) = hit.points {
            uev = uev.with_attr("points", p.to_string());
        }
        if let Some(id) = hit.object_id.as_deref() {
            uev = uev.with_attr(
                "hn_item",
                format!("https://news.ycombinator.com/item?id={id}"),
            );
        }
        u.add_evidence(uev);
        out.push(u);

        if let Some(host) = host_from_url(&link)
            && seen_domains.insert(host.clone())
        {
            let mut d = Entity::new(EntityKind::Domain, &host, 0.40, scan_id);
            d.tag(tags::WEB);
            d.tag("hackernews");
            let mut dev = Evidence::new(SRC, format!("Domain shared on Hacker News by '{user}'"));
            if let Some(ts) = hit.created_at.as_deref() {
                dev = dev.with_attr("created_at", ts);
            }
            d.add_evidence(dev);
            out.push(d);
        }
    }

    out
}

// ─── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn hit(url: Option<&str>, created: &str, points: i64, id: &str) -> Hit {
        Hit {
            object_id: Some(id.to_string()),
            title: Some("A Title".into()),
            url: url.map(str::to_string),
            story_url: None,
            created_at: Some(created.to_string()),
            points: Some(points),
        }
    }

    #[test]
    fn accepts_only_plausible_usernames() {
        let m = HackerNews;
        assert!(m.accepts(&Target::new(TargetKind::Username, "patio11")));
        assert!(!m.accepts(&Target::new(TargetKind::Email, "a@b.com")));
        // Too long / contains an illegal char.
        assert!(!m.accepts(&Target::new(
            TargetKind::Username,
            "this_handle_is_way_too_long"
        )));
    }

    #[test]
    fn cost_is_free_and_described() {
        assert!(matches!(
            HackerNews.cost(),
            crate::core::module::ModuleCost::Free
        ));
        assert!(!HackerNews.description().is_empty());
    }

    #[test]
    fn plausible_handle_bounds() {
        assert!(is_plausible_handle("ab"));
        assert!(is_plausible_handle("a_b-1"));
        assert!(!is_plausible_handle("a")); // too short
        assert!(!is_plausible_handle("has space"));
        assert!(!is_plausible_handle("emoji😀"));
    }

    #[test]
    fn empty_hits_yield_no_account() {
        assert!(entities_from_hits("ghost", &[], 0, "s").is_empty());
    }

    #[test]
    fn builds_account_with_activity_span() {
        let hits = vec![
            hit(None, "2021-01-01T08:00:00Z", 10, "1"),
            hit(None, "2023-06-15T20:30:00Z", 50, "2"),
        ];
        let ents = entities_from_hits("pg", &hits, 2, "s");
        assert_eq!(ents.len(), 1); // username only, no links
        let acct = &ents[0];
        assert_eq!(acct.kind, EntityKind::Username);
        assert!(acct.has_tag("hackernews"));
        assert!(acct.has_tag(tags::SOCIAL_PROFILE));
        let ev = &acct.evidence[0];
        assert_eq!(
            ev.attributes.get("first_seen").map(String::as_str),
            Some("2021-01-01T08:00:00Z")
        );
        assert_eq!(
            ev.attributes.get("last_seen").map(String::as_str),
            Some("2023-06-15T20:30:00Z")
        );
        assert_eq!(
            ev.attributes.get("total_points").map(String::as_str),
            Some("60")
        );
    }

    #[test]
    fn extracts_url_and_domain_with_timestamp() {
        let hits = vec![hit(
            Some("https://example.com/post?x=1"),
            "2022-03-03T12:00:00Z",
            7,
            "42",
        )];
        let ents = entities_from_hits("alice", &hits, 1, "s");
        // username + url + domain
        assert_eq!(ents.len(), 3);
        let url = ents.iter().find(|e| e.kind == EntityKind::Url).unwrap();
        assert_eq!(url.value, "https://example.com/post?x=1");
        assert_eq!(
            url.evidence[0]
                .attributes
                .get("created_at")
                .map(String::as_str),
            Some("2022-03-03T12:00:00Z")
        );
        let dom = ents.iter().find(|e| e.kind == EntityKind::Domain).unwrap();
        assert_eq!(dom.value, "example.com");
        assert!(dom.has_tag("hackernews"));
    }

    #[test]
    fn deduplicates_repeated_links() {
        let hits = vec![
            hit(
                Some("https://example.com/a"),
                "2022-01-01T00:00:00Z",
                1,
                "1",
            ),
            hit(
                Some("https://example.com/a"),
                "2022-01-02T00:00:00Z",
                2,
                "2",
            ),
            hit(
                Some("https://example.com/b"),
                "2022-01-03T00:00:00Z",
                3,
                "3",
            ),
        ];
        let ents = entities_from_hits("bob", &hits, 3, "s");
        let urls = ents.iter().filter(|e| e.kind == EntityKind::Url).count();
        let doms = ents.iter().filter(|e| e.kind == EntityKind::Domain).count();
        assert_eq!(urls, 2); // /a deduped
        assert_eq!(doms, 1); // single host
    }

    #[test]
    fn confidence_scales_with_volume() {
        let one = entities_from_hits("u", &[hit(None, "2022-01-01T00:00:00Z", 0, "1")], 1, "s");
        let many: Vec<Hit> = (0..30)
            .map(|i| hit(None, "2022-01-01T00:00:00Z", 0, &i.to_string()))
            .collect();
        let lots = entities_from_hits("u", &many, 30, "s");
        assert!(lots[0].confidence > one[0].confidence);
        assert!(lots[0].confidence <= 0.85);
    }

    #[test]
    fn search_resp_deserialises() {
        let json = r#"{
            "hits":[{"objectID":"123","author":"pg","title":"T","url":"https://x.com/y","created_at":"2021-01-01T00:00:00Z","points":42}],
            "nbHits": 1
        }"#;
        let r: SearchResp = serde_json::from_str(json).unwrap();
        assert_eq!(r.nb_hits, 1);
        assert_eq!(r.hits.len(), 1);
        assert_eq!(r.hits[0].link(), Some("https://x.com/y"));
    }

    #[test]
    fn link_ignores_non_http_values() {
        let h = Hit {
            url: Some("ftp://nope".into()),
            ..Default::default()
        };
        assert_eq!(h.link(), None);
    }
}
