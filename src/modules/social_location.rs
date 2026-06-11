//! Social profile location extraction — parse self-reported location
//! fields from confirmed social profile URLs.
//!
//! When username_search or social_probe confirms a profile URL exists,
//! this module fetches the page and extracts the location field from
//! supported platforms. Coverage:
//!
//!  - **GitHub** — `p-label` span in the user profile sidebar.
//!  - **Reddit** — `og:locality` / `geo.placename` meta tags.
//!  - **LinkedIn** — `og:locality` + `og:region` meta tags.
//!  - **Seek.com.au** — JSON-LD Person schema or meta location.
//!  - **Homely.com.au** — agent profile suburb/state extraction.
//!  - **RateMyAgent** — agent card suburb/region.
//!  - **WhitePages AU** — person listing suburb/state.
//!  - **Facebook** — `og:locality` / `og:region` meta tags.
//!
//! Emits an `Address` entity tagged `self-reported`, `social-profile`,
//! and, where the location resolves to an AU state or LGA, the
//! appropriate `au-state:*` / `au-lga:*` / `au-se-qld` tags so the
//! GEOINT correlator can ingest them without a network geocode.
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
        "Extract self-reported location from social and professional profile pages"
    }

    fn priority(&self) -> u8 {
        15
    }

    fn max_timeout_ms(&self) -> u64 {
        10_000
    }

    fn is_passive(&self) -> bool {
        false
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
            .timeout(std::time::Duration::from_millis(8_000))
            .send()
            .await
            .map_err(|e| Error::module(SRC, e.to_string()))?
            .text()
            .await
            .map_err(|e| Error::module(SRC, e.to_string()))?;

        let host = crate::util::url_util::host_from_url(url).unwrap_or_default();

        let location = if host.contains("github.com") {
            extract_github_location(&body)
        } else if host.contains("seek.com.au") {
            extract_seek_location(&body)
        } else if host.contains("homely.com.au") {
            extract_homely_location(&body)
        } else if host.contains("ratemyagent.com.au") {
            extract_ratemyagent_location(&body)
        } else if host.contains("whitepages.com.au") {
            extract_whitepages_au_location(&body)
        } else {
            // Generic: LinkedIn, Reddit, Facebook, etc.
            extract_meta_location(&body)
        };

        if let Some(loc) = location {
            let trimmed = loc.trim();
            if !trimmed.is_empty() && trimmed.len() <= 200 {
                let confidence = platform_confidence(&host);
                let mut e = Entity::new(EntityKind::Address, trimmed, confidence, &ctx.scan_id);
                e.tag(crate::core::tags::GEOINT);
                e.tag("self-reported");
                e.tag("social-profile");
                for tag in au_location_tags(trimmed) {
                    e.tag(tag);
                }
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

const SUPPORTED_HOSTS: &[&str] = &[
    "github.com",
    "reddit.com",
    "linkedin.com",
    "seek.com.au",
    "homely.com.au",
    "ratemyagent.com.au",
    "whitepages.com.au",
    "yellowpages.com.au",
    "facebook.com",
    "twitter.com",
    "x.com",
];

/// Confidence by platform: structured data sources rate higher than
/// meta-tag scrapes.
fn platform_confidence(host: &str) -> f64 {
    if host.contains("linkedin.com") {
        0.55
    } else if host.contains("seek.com.au") {
        0.52
    } else if host.contains("whitepages.com.au") || host.contains("ratemyagent.com.au") {
        0.50
    } else if host.contains("github.com") {
        0.48
    } else {
        0.42
    }
}

/// Derive AU-specific tags from a free-text location string. Applied to every
/// entity this module emits so the GEOINT correlator receives `au-state:QLD`,
/// `au-lga:logan-city`, or `au-se-qld` without a geocode round-trip.
fn au_location_tags(loc: &str) -> Vec<&'static str> {
    let lower = loc.to_lowercase();
    let mut tags: Vec<&'static str> = Vec::new();

    // AU relevance gate — must contain a clear AU signal.
    let is_au = lower.contains("australia")
        || lower.contains("qld")
        || lower.contains("queensland")
        || lower.contains("nsw")
        || lower.contains("vic")
        || lower.contains("western australia")
        || lower.contains("south australia")
        || lower.contains("tasmania")
        || lower.contains("northern territory")
        || lower.ends_with(", au");
    if !is_au {
        return tags;
    }
    tags.push(crate::core::tags::AU_RELEVANT);

    // State attribution.
    if lower.contains("qld") || lower.contains("queensland") {
        tags.push(crate::core::tags::AU_STATE_QLD);
    } else if lower.contains("nsw") || lower.contains("new south wales") {
        tags.push(crate::core::tags::AU_STATE_NSW);
    } else if lower.contains(" vic") || lower.contains("victoria") {
        tags.push(crate::core::tags::AU_STATE_VIC);
    } else if lower.contains("western australia") || lower.contains(" wa,") {
        tags.push(crate::core::tags::AU_STATE_WA);
    } else if lower.contains("south australia") || lower.contains(" sa,") {
        tags.push(crate::core::tags::AU_STATE_SA);
    } else if lower.contains("tasmania") || lower.contains(" tas") {
        tags.push(crate::core::tags::AU_STATE_TAS);
    }

    // SE QLD signal: known SE QLD cities mentioned.
    let se_qld_cities = [
        "brisbane",
        "logan",
        "gold coast",
        "sunshine coast",
        "ipswich",
        "redland",
        "moreton bay",
        "toowoomba",
    ];
    if se_qld_cities.iter().any(|c| lower.contains(c)) {
        tags.push(crate::core::tags::AU_SE_QLD);
    }

    // Logan City LGA: Division 7 suburbs + Logan itself.
    let logan_suburbs = crate::util::geo::logan_div7_suburbs();
    let is_logan = lower.contains("logan")
        || logan_suburbs
            .iter()
            .any(|(s, _, _, _)| lower.contains(&s.to_lowercase()));
    if is_logan {
        tags.push(crate::core::tags::AU_LGA_LOGAN_CITY);
    }

    tags
}

fn extract_github_location(html: &str) -> Option<String> {
    let marker = "p-label";
    let pos = html.find(marker)?;
    let after = &html[pos..html.len().min(pos + 300)];
    let start = after.find('>')? + 1;
    let end = after[start..].find('<')? + start;
    let text = &after[start..end];
    let decoded = html_decode(text);
    let trimmed = decoded.trim().to_string();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    }
}

/// Seek.com.au profile/résumé — try JSON-LD Person schema first,
/// then fall back to meta tag.
fn extract_seek_location(html: &str) -> Option<String> {
    // JSON-LD: "addressLocality" or "addressRegion" inside Person schema.
    if let Some(pos) = html.find("\"addressLocality\"") {
        let snippet = &html[pos..html.len().min(pos + 120)];
        if let Some(val) = extract_json_string_value(snippet) {
            return Some(val);
        }
    }
    if let Some(pos) = html.find("\"addressRegion\"") {
        let snippet = &html[pos..html.len().min(pos + 120)];
        if let Some(val) = extract_json_string_value(snippet) {
            return Some(val);
        }
    }
    // Fallback: seek uses data-automation attributes for location.
    let marker = "data-automation=\"CandidateLocation\"";
    if let Some(pos) = html.find(marker) {
        let after = &html[pos..html.len().min(pos + 400)];
        if let Some(start) = after.find('>') {
            let rest = &after[start + 1..];
            if let Some(end) = rest.find('<') {
                let val = rest[..end].trim().to_string();
                if !val.is_empty() {
                    return Some(val);
                }
            }
        }
    }
    extract_meta_location(html)
}

/// Homely.com.au agent/listing profile — suburb + state typically in the
/// agent card heading.
fn extract_homely_location(html: &str) -> Option<String> {
    // Homely uses og:locality + og:region or a suburb span.
    if let Some(val) = extract_meta_property(html, "og:locality") {
        let region = extract_meta_property(html, "og:region").unwrap_or_default();
        return if region.is_empty() {
            Some(val)
        } else {
            Some(format!("{val}, {region}"))
        };
    }
    // "AgentLocation" data-attr or JSON-LD.
    if let Some(pos) = html.find("\"addressLocality\"") {
        let snippet = &html[pos..html.len().min(pos + 120)];
        if let Some(val) = extract_json_string_value(snippet) {
            return Some(val);
        }
    }
    extract_meta_location(html)
}

/// RateMyAgent — suburb + state in the agent card title or og tags.
fn extract_ratemyagent_location(html: &str) -> Option<String> {
    // RateMyAgent exposes suburb in og:description or og:title.
    if let Some(val) = extract_meta_property(html, "og:locality") {
        return Some(val);
    }
    // Title pattern: "Agent Name — Suburb, STATE | RateMyAgent".
    if let Some(pos) = html.find("<title>") {
        let after = &html[pos..html.len().min(pos + 200)];
        if let Some(end) = after.find("</title>") {
            let title = &after[7..end]; // strip "<title>"
            // Extract "Suburb, STATE" segment before " | ".
            if let (Some(pipe), Some(dash)) = (
                title.rfind(" | "),
                title
                    .rfind(" | ")
                    .and_then(|p| title[..p].rfind(" \u{2014} ")),
            ) {
                let sep_len = " \u{2014} ".len();
                let suburb_state = title[dash + sep_len..pipe].trim().to_string();
                if !suburb_state.is_empty() {
                    return Some(suburb_state);
                }
            }
        }
    }
    extract_meta_location(html)
}

/// WhitePages AU person listing — suburb + state from the heading.
fn extract_whitepages_au_location(html: &str) -> Option<String> {
    // og:description often contains "lives in Suburb, STATE".
    if let Some(pos) = html.find("lives in ") {
        let after = &html[pos + 9..html.len().min(pos + 60)];
        let end = after
            .find('<')
            .or_else(|| after.find('"'))
            .unwrap_or(after.len());
        let val = after[..end].trim().to_string();
        if !val.is_empty() {
            return Some(val);
        }
    }
    // Fallback to og tags.
    extract_meta_location(html)
}

fn extract_meta_location(html: &str) -> Option<String> {
    for tag in [
        "geo.placename",
        "og:locality",
        "og:region",
        "og:country-name",
    ] {
        if let Some(val) = extract_meta_name(html, tag)
            .or_else(|| extract_meta_property(html, tag))
            .filter(|v| !v.is_empty())
        {
            return Some(val);
        }
    }
    None
}

fn extract_meta_name(html: &str, name: &str) -> Option<String> {
    extract_meta_attr(html, &format!("name=\"{name}\""))
}

fn extract_meta_property(html: &str, property: &str) -> Option<String> {
    extract_meta_attr(html, &format!("property=\"{property}\""))
}

fn extract_meta_attr(html: &str, attr: &str) -> Option<String> {
    let pos = html.find(attr)?;
    let search_area = &html[pos..html.len().min(pos + 300)];
    let content_key = "content=\"";
    let content_pos = search_area.find(content_key)?;
    let start = content_pos + content_key.len();
    let end = search_area[start..].find('"').unwrap_or(0) + start;
    if end > start {
        let val = html_decode(&search_area[start..end]);
        let trimmed = val.trim().to_string();
        if !trimmed.is_empty() {
            return Some(trimmed);
        }
    }
    None
}

/// Pull the string value after `"key": "..."` in a JSON snippet (one line, no nesting).
fn extract_json_string_value(snippet: &str) -> Option<String> {
    let colon = snippet.find(':')?;
    let rest = snippet[colon + 1..].trim_start();
    if !rest.starts_with('"') {
        return None;
    }
    let inner = &rest[1..];
    let end = inner.find('"')?;
    let val = inner[..end].trim().to_string();
    if val.is_empty() { None } else { Some(val) }
}

fn html_decode(s: &str) -> String {
    s.replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&#39;", "'")
        .replace("&quot;", "\"")
        .replace("&#x27;", "'")
        .replace("&#x2F;", "/")
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn extract_meta_og_locality() {
        let html = r#"<meta property="og:locality" content="Logan City">"#;
        let loc = extract_meta_location(html).unwrap();
        assert_eq!(loc, "Logan City");
    }

    #[test]
    fn extract_meta_missing() {
        assert!(extract_meta_location("<html></html>").is_none());
    }

    #[test]
    fn extract_seek_json_ld_location() {
        let html = r#"{"@type":"Person","name":"Test","addressLocality":"Regents Park","addressRegion":"QLD"}"#;
        let loc = extract_seek_location(html).unwrap();
        assert_eq!(loc, "Regents Park");
    }

    #[test]
    fn extract_seek_candidate_location_attr() {
        let html = r#"<span data-automation="CandidateLocation">Park Ridge QLD 4125</span>"#;
        let loc = extract_seek_location(html).unwrap();
        assert_eq!(loc, "Park Ridge QLD 4125");
    }

    #[test]
    fn extract_whitepages_lives_in() {
        let html = r#"<p>John lives in Boronia Heights, QLD</p>"#;
        let loc = extract_whitepages_au_location(html).unwrap();
        assert_eq!(loc, "Boronia Heights, QLD");
    }

    #[test]
    fn au_location_tags_brisbane_qld() {
        let tags = au_location_tags("Brisbane, QLD");
        assert!(tags.contains(&"au-relevant"));
        assert!(tags.contains(&"au-state:QLD"));
        assert!(tags.contains(&"au-se-qld"));
    }

    #[test]
    fn au_location_tags_park_ridge() {
        let tags = au_location_tags("Park Ridge, QLD 4125");
        assert!(tags.contains(&"au-relevant"));
        assert!(tags.contains(&"au-state:QLD"));
        assert!(tags.contains(&"au-lga:logan-city"));
    }

    #[test]
    fn au_location_tags_foreign_returns_empty() {
        let tags = au_location_tags("London, UK");
        assert!(tags.is_empty());
    }

    #[test]
    fn extract_ratemyagent_title_suburb() {
        let html = r#"<title>Jane Smith — Browns Plains, QLD | RateMyAgent</title>"#;
        let loc = extract_ratemyagent_location(html).unwrap();
        assert_eq!(loc, "Browns Plains, QLD");
    }

    #[tokio::test]
    async fn module_accepts_supported_hosts() {
        let m = SocialLocation;
        assert!(m.accepts(&Target::new(TargetKind::Url, "https://github.com/alice")));
        assert!(m.accepts(&Target::new(
            TargetKind::Url,
            "https://www.seek.com.au/profile/test"
        )));
        assert!(m.accepts(&Target::new(
            TargetKind::Url,
            "https://homely.com.au/agent/test"
        )));
        assert!(m.accepts(&Target::new(
            TargetKind::Url,
            "https://ratemyagent.com.au/test"
        )));
        assert!(!m.accepts(&Target::new(TargetKind::Url, "https://example.com")));
        assert!(!m.accepts(&Target::new(TargetKind::Domain, "github.com")));
    }

    #[test]
    fn json_value_extract() {
        let s = r#""addressLocality": "Park Ridge""#;
        assert_eq!(extract_json_string_value(s), Some("Park Ridge".to_string()));
    }
}
