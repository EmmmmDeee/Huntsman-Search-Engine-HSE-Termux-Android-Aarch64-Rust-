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
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::RequestBuilderExt;

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

    fn attack_techniques(&self) -> &'static [&'static str] {
        // T1591.001 — Determine Physical Locations (primary geo signal)
        // T1591.002 — Business Relationships (professional/workplace location from agent portals)
        &["T1591.001", "T1591.002"]
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let mut result = ModuleResult::new();
        let url = target.value.trim();

        let resp = ctx.http.get(url).send_tagged(SRC).await?;
        let body = crate::util::http::read_text(SRC, resp).await?;

        let host = crate::util::url_util::host_from_url(url).unwrap_or_default();
        let is_professional = is_professional_host(&host);

        let location = if host.contains("github.com") {
            extract_github_location(&body)
        } else {
            extract_meta_location(&body)
        };

        if let Some(loc) = location {
            let trimmed = loc.trim();
            if !trimmed.is_empty() && trimmed.len() <= 200 {
                // Professional portals carry verified workplace addresses.
                // Self-reported bio fields are raised to 0.52 (above the 0.50
                // expansion floor) so they feed the geo-correlation chain
                // (AU-052/AU-053) after the address→coordinates enrichment pass.
                // Professional portals are set to 0.55 — the same tier as a
                // search-discovered postcode-qualified address.
                let conf = if is_professional { 0.55 } else { 0.52 };
                let mut e = Entity::new(EntityKind::Address, trimmed, conf, &ctx.scan_id);
                e.tag("geoint");
                if is_professional {
                    e.tag("professional-address");
                    e.tag("attack:T1591.002");
                } else {
                    e.tag("self-reported");
                }
                e.tag("social-profile");
                if let Some(sc) = crate::util::address_au::state_code(trimmed) {
                    e.tag(format!("au-state:{sc}"));
                    e.tag("country:AU");
                }
                e.add_evidence(
                    Evidence::new(
                        SRC,
                        format!(
                            "{} location on {host}: {trimmed}",
                            if is_professional {
                                "Professional"
                            } else {
                                "Self-reported"
                            }
                        ),
                    )
                    .with_attr("url", url)
                    .with_attr("platform", &host),
                );
                result.push(e);
            }
        }

        Ok(result)
    }
}

/// True when the host is an AU real estate / professional-profile portal whose
/// location data reflects a workplace address rather than a personal bio field.
fn is_professional_host(host: &str) -> bool {
    const PROFESSIONAL: &[&str] = &[
        "ratemyagent.com.au",
        "homely.com.au",
        "soho.com.au",
        "realestate.com.au",
        "domain.com.au",
        "linkedin.com",
    ];
    PROFESSIONAL.iter().any(|h| host.contains(h))
}

/// Hosts where a self-reported or professional location can be extracted.
///
/// The AU real estate portals (ratemyagent, homely, soho, realestate, domain)
/// carry suburb-level *professional* addresses for agent profiles — a workplace
/// location signal mapping to MITRE T1591.002 (Business Relationships).
const SUPPORTED_HOSTS: &[&str] = &[
    "github.com",
    "reddit.com",
    "linkedin.com",
    "ratemyagent.com.au",
    "homely.com.au",
    "soho.com.au",
    "realestate.com.au",
    "domain.com.au",
];

fn extract_github_location(html: &str) -> Option<String> {
    let marker = "p-label";
    let pos = html.find(marker)?;
    // `pos + 300` is an arbitrary byte offset into untrusted HTML; clamp to a
    // char boundary so a multibyte character at the window edge can't panic.
    let after = crate::util::str_util::char_window(html, pos, pos + 300);
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
    // Try each location <meta> name/property in turn and return the first whose
    // `content="…"` attribute parses to a non-empty value. The content attribute
    // is read from the whole enclosing <meta …> element, so it is found whether
    // it precedes or follows the name/property — real pages use both orderings.
    [
        "geo.placename",
        "og:locality",
        "og:region",
        "og:country-name",
    ]
    .into_iter()
    .find_map(|tag| {
        let attr = format!("\"{tag}\"");
        let tag_pos = html.find(&attr)?;
        // Bound the single element: back to its opening `<`, forward to its
        // closing `>` (capped). Both delimiters are ASCII and `char_window`
        // clamps the forward cap to a char boundary, so slicing untrusted HTML
        // here can never split a multibyte character.
        let lo = html[..tag_pos].rfind('<').map_or(tag_pos, |p| p);
        let windowed = crate::util::str_util::char_window(html, lo, tag_pos + 300);
        let element = windowed.split('>').next().unwrap_or(windowed);

        let pattern = "content=\"";
        let start = element.find(pattern)? + pattern.len();
        // The closing quote is required: an unterminated `content="…` has no
        // value to extract, so skip to the next candidate tag rather than
        // coercing a missing match into a zero-length window.
        let rel_end = element[start..].find('"')?;
        let val = element[start..start + rel_end].trim();
        (!val.is_empty()).then(|| val.to_string())
    })
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
