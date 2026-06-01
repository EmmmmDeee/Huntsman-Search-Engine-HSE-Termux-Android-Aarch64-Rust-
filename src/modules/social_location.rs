//! Social profile location extraction — parse self-reported location
//! fields from confirmed social profile URLs.
//!
//! When username_search or social_probe confirms a profile URL exists,
//! this module fetches the page and extracts the location field from
//! GitHub, Reddit, and other platforms that expose it in HTML meta tags
//! or JSON API endpoints.
//!
//! Priority 15 — runs after username_search (priority 18) has produced
//! Url entities for confirmed profiles.

use async_trait::async_trait;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::{Error, Result},
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};

const SRC: &str = "social_location";

pub struct SocialLocation;

#[async_trait]
impl Module for SocialLocation {
    fn name(&self) -> &'static str {
        SRC
    }
    fn description(&self) -> &'static str {
        "Extract self-reported location from social profile pages (GitHub, etc.)"
    }
    fn priority(&self) -> u8 {
        15
    }
    fn max_timeout_ms(&self) -> u64 {
        8_000
    }
    fn accepts(&self, t: &Target) -> bool {
        if t.kind != TargetKind::Url {
            return false;
        }
        let lower = t.value.to_lowercase();
        SUPPORTED_HOSTS.iter().any(|h| lower.contains(h))
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Geo
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[EntityKind::Address];
        KINDS
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let mut result = ModuleResult::new();
        let url = target.value.trim();

        let body = ctx
            .http
            .get(url)
            .send()
            .await
            .map_err(|e| Error::module(SRC, e.to_string()))?
            .text()
            .await
            .map_err(|e| Error::module(SRC, e.to_string()))?;

        let host = crate::util::url_util::host_from_url(url).unwrap_or_default();

        let location = if host.contains("github.com") {
            extract_github_location(&body)
        } else {
            extract_meta_location(&body)
        };

        if let Some(loc) = location {
            let trimmed = loc.trim();
            if !trimmed.is_empty() && trimmed.len() <= 200 {
                let mut e = Entity::new(EntityKind::Address, trimmed, 0.45, &ctx.scan_id);
                e.tag("geoint");
                e.tag("self-reported");
                e.tag("social-profile");
                e.add_evidence(
                    Evidence::new(SRC, format!("Self-reported location on {host}: {trimmed}"))
                        .with_attr("url", url)
                        .with_attr("platform", &host),
                );
                result.push(e);
            }
        }

        Ok(result)
    }
}

const SUPPORTED_HOSTS: &[&str] = &["github.com", "reddit.com"];

/// `&html[start..]` capped to ~`max_bytes`, with the END clamped DOWN to a UTF-8
/// char boundary. The body is an external HTTP response, so a fixed `start +
/// max_bytes` slice would panic ("byte index N is not a char boundary") whenever
/// a multi-byte char straddles the cut — and profile locations are full of them
/// ("São Paulo", "München", "東京"). `start` is always a `find()` index here, so
/// already a boundary.
fn bounded_window(html: &str, start: usize, max_bytes: usize) -> &str {
    let mut end = html.len().min(start + max_bytes);
    while end > start && !html.is_char_boundary(end) {
        end -= 1;
    }
    &html[start..end]
}

fn extract_github_location(html: &str) -> Option<String> {
    let marker = "p-label";
    let pos = html.find(marker)?;
    let after = bounded_window(html, pos, 300);
    let start = after.find('>')? + 1;
    let end = after[start..].find('<')? + start;
    let text = &after[start..end];
    let decoded = text
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&#39;", "'")
        .replace("&quot;", "\"");
    let trimmed = decoded.trim().to_string();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    }
}

fn extract_meta_location(html: &str) -> Option<String> {
    // Look for <meta name="geo.placename" content="...">
    // or <meta property="og:locality" content="...">
    for tag in [
        "geo.placename",
        "og:locality",
        "og:region",
        "og:country-name",
    ] {
        let pattern = "content=\"";
        let attr = format!("\"{tag}\"");
        if let Some(tag_pos) = html.find(&attr) {
            let search_area = bounded_window(html, tag_pos, 300);
            if let Some(content_pos) = search_area.find(pattern) {
                let start = content_pos + pattern.len();
                let end = search_area[start..].find('"').unwrap_or(0) + start;
                if end > start {
                    let val = &search_area[start..end];
                    if !val.is_empty() {
                        return Some(val.to_string());
                    }
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_window_never_splits_a_utf8_char() {
        // 'é' (2 bytes) straddles byte 300 → `&s[..300]` would panic. The window
        // must clamp the end down to a char boundary and never panic.
        let s = format!("{}é{}", "x".repeat(299), "y".repeat(50));
        let w = bounded_window(&s, 0, 300);
        assert!(
            s.is_char_boundary(w.len()),
            "window end must be a char boundary"
        );
        assert!(w.len() <= 300);
        // The real extractors must not panic on such an external body either.
        let html = format!("<span class=\"p-label\">{}München</span>", "x".repeat(290));
        let _ = extract_github_location(&html);
        let meta = format!("\"og:locality\"{}content=\"São Paulo\"", "x".repeat(290));
        let _ = extract_meta_location(&meta);
    }

    #[test]
    fn extract_github_location_from_html() {
        let html = r#"<li itemprop="homeLocation"><svg></svg><span class="p-label">Brisbane, Australia</span></li>"#;
        let loc = extract_github_location(html).unwrap();
        assert_eq!(loc, "Brisbane, Australia");
    }

    #[test]
    fn extract_github_location_missing() {
        assert!(extract_github_location("<html><body>no location</body></html>").is_none());
    }

    #[test]
    fn extract_meta_geo_placename() {
        let html = r#"<meta name="geo.placename" content="Sydney, NSW">"#;
        let loc = extract_meta_location(html).unwrap();
        assert_eq!(loc, "Sydney, NSW");
    }

    #[test]
    fn extract_meta_missing() {
        assert!(extract_meta_location("<html></html>").is_none());
    }

    #[tokio::test]
    async fn module_accepts_github_urls_only() {
        let m = SocialLocation;
        assert!(m.accepts(&Target::new(TargetKind::Url, "https://github.com/alice")));
        assert!(!m.accepts(&Target::new(TargetKind::Url, "https://example.com")));
        assert!(!m.accepts(&Target::new(TargetKind::Domain, "github.com")));
    }
}
