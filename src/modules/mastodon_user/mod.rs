//! Mastodon / Fediverse user lookup. Free, no key — the Mastodon v1 REST API
//! is fully public for read-only queries on public profiles.
//!
//! Endpoint: `GET https://{instance}/api/v1/accounts/lookup?acct={username}`
//!
//! Mastodon is a federated network; there is no single registry. This module
//! probes the most-populated public instances in priority order, using the
//! first successful exact-match hit. The instance list is intentionally short
//! to bound latency — we probe sequentially and stop on the first hit, so
//! the per-module wall-clock cost is one round-trip in the common case.
//!
//! Instance priority: mastodon.social (largest), infosec.exchange (security
//! community), fosstodon.org (FOSS/tech), hachyderm.io (tech/devops),
//! mastodon.online, sigmoid.social (AI/ML), mas.to (general), tech.lgbt
//! (inclusive tech), aus.social (Oceania), mathstodon.xyz (academic).
//!
//! The profile response surfaces `display_name`, `note` (HTML bio),
//! `url` (canonical profile URL), and `fields` (custom key-value pairs the
//! user populates — often website, pronouns, or contact links). These fields
//! are the primary extraction targets.
//!
//! ATT&CK mapping: T1593.001 Search Open Websites/Domains (social platform
//! reconnaissance); T1589.002 when the bio contains an email address.

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

const SRC: &str = "mastodon_user";

/// Instances probed in priority order. Stopping at the first hit keeps latency
/// low; lower-priority instances only run when all higher ones miss.
const INSTANCES: &[&str] = &[
    "mastodon.social",
    "infosec.exchange",
    "fosstodon.org",
    "hachyderm.io",
    "mastodon.online",
    "sigmoid.social",
    "mas.to",
    "tech.lgbt",
    "aus.social",
    "mathstodon.xyz",
];

pub struct MastodonUser;

#[derive(Deserialize)]
pub(super) struct MastodonAccount {
    pub(super) username: String,
    #[serde(rename = "display_name", default)]
    pub(super) display_name: Option<String>,
    /// HTML bio.
    #[serde(default)]
    pub(super) note: Option<String>,
    /// Canonical profile URL, e.g. `https://mastodon.social/@alice`.
    #[serde(default)]
    pub(super) url: Option<String>,
    /// User-defined key-value fields (website, location, etc.).
    #[serde(default)]
    pub(super) fields: Vec<MastodonField>,
    #[serde(default)]
    pub(super) created_at: Option<String>,
}

#[derive(Deserialize)]
pub(super) struct MastodonField {
    pub(super) name: String,
    /// HTML value — strip tags before use.
    pub(super) value: String,
    /// RFC3339 if field was verified by the server (e.g. a domain with a rel-me link).
    #[serde(default)]
    pub(super) verified_at: Option<String>,
}

#[async_trait]
impl Module for MastodonUser {
    fn name(&self) -> &'static str {
        "mastodon_user"
    }

    fn description(&self) -> &'static str {
        "Mastodon / Fediverse account lookup across top instances via public v1 API"
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
        &["T1589.002", "T1593.001"]
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[
            EntityKind::Username,
            EntityKind::Person,
            EntityKind::Email,
            EntityKind::Url,
            EntityKind::Domain,
            EntityKind::Address,
        ];
        KINDS
    }

    fn max_timeout_ms(&self) -> u64 {
        // Budget for sequential probing; most hits occur on the first instance.
        12_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let handle = target.value.trim();
        if !crate::util::str_util::is_handle(handle, 1, 100) {
            return Ok(ModuleResult::new());
        }

        let encoded = crate::util::http::urlencode(handle);
        for instance in INSTANCES {
            if ctx.cancel.is_cancelled() {
                break;
            }
            let url = format!("https://{instance}/api/v1/accounts/lookup?acct={encoded}");
            let acct: Option<MastodonAccount> = match fetch_json_or_404(&ctx.http, SRC, &url).await
            {
                Ok(v) => v,
                Err(_) => continue,
            };
            if let Some(acct) = acct {
                // Confirm exact-match (API may return a prefix match on some servers).
                if !acct.username.eq_ignore_ascii_case(handle) {
                    continue;
                }
                let mut r = ModuleResult::new();
                r.entities = build_entities(acct, instance, &ctx.scan_id);
                return Ok(r);
            }
        }
        Ok(ModuleResult::new())
    }
}

/// Pure account→entity mapping. `instance` is the Mastodon server that
/// confirmed the account.
pub(super) fn build_entities(acct: MastodonAccount, instance: &str, scan_id: &str) -> Vec<Entity> {
    let mut result = ModuleResult::new();

    let profile_url = acct.url.as_deref().unwrap_or_default().to_string();

    let mut ev = Evidence::new(
        SRC,
        format!("Mastodon account '@{}@{}'", acct.username, instance),
    )
    .with_attr("instance", instance)
    .with_attr("acct", format!("@{}@{}", acct.username, instance));
    if let Some(ref ts) = acct.created_at {
        ev = ev.with_attr("created_at", ts);
    }
    if !profile_url.is_empty() {
        ev = ev.with_attr("profile_url", &profile_url);
    }

    // Confirmed-on-Mastodon username.
    let mut u = Entity::new(EntityKind::Username, &acct.username, 0.85, scan_id);
    u.tag("mastodon");
    u.tag("fediverse");
    u.add_evidence(ev.clone());
    result.push(u);

    // Profile URL.
    if !profile_url.is_empty() && profile_url.starts_with("http") {
        let mut url_e = Entity::new(EntityKind::Url, &profile_url, 0.78, scan_id);
        url_e.tag("mastodon");
        url_e.add_evidence(Evidence::new(
            SRC,
            format!("Mastodon profile URL for '@{}@{}'", acct.username, instance),
        ));
        result.push(url_e);
    }

    // Real name → Person (≥2 tokens, non-placeholder).
    if let Some(ref name) = acct.display_name
        && let Some(mut p) = profile_kit::person_from_name(name, 0.60, scan_id)
    {
        p.tag("mastodon");
        p.tag("derived");
        p.add_evidence(
            Evidence::new(
                SRC,
                format!(
                    "Display name from Mastodon account '@{}@{}'",
                    acct.username, instance
                ),
            )
            .with_attr("instance", instance),
        );
        result.push(p);
    }

    // Bio (HTML) — strip tags, then extract emails and URLs.
    if let Some(ref note_html) = acct.note {
        let note_text = crate::util::html::strip_html(note_html);
        for email in crate::util::extract::emails(&note_text).into_iter().take(5) {
            let mut e = Entity::new(EntityKind::Email, &email, 0.68, scan_id);
            e.tag("mastodon");
            e.tag("public-profile");
            e.add_evidence(
                Evidence::new(
                    SRC,
                    format!("Email in Mastodon bio of '@{}@{}'", acct.username, instance),
                )
                .with_attr("source", "mastodon_bio"),
            );
            result.push(e);
        }
        let mut seen_urls: std::collections::HashSet<String> = std::collections::HashSet::new();
        for m in crate::util::extract::URL_RE.find_iter(&note_text).take(5) {
            let link = m.as_str().trim_end_matches(['.', ',', ')']);
            if !seen_urls.insert(link.to_string()) {
                continue;
            }
            if link.contains(instance) {
                continue;
            }
            let mut url_e = Entity::new(EntityKind::Url, link, 0.58, scan_id);
            url_e.tag("mastodon");
            url_e.add_evidence(
                Evidence::new(
                    SRC,
                    format!("Link in Mastodon bio of '@{}@{}'", acct.username, instance),
                )
                .with_attr("source", "mastodon_bio"),
            );
            result.push(url_e);

            emit_domain_from_url(link, instance, &acct.username, scan_id, &mut result, &ev);
        }
    }

    // Profile fields — the user-defined custom fields are the most reliable
    // structured source of external links. Verified fields get a confidence
    // boost: Mastodon verifies a field by checking for a `rel="me"` link
    // pointing back at the user's profile, which is a genuine ownership proof.
    for field in &acct.fields {
        let verified = field.verified_at.is_some();
        // Field value may be plain text or HTML with an <a href="...">.
        let plain = crate::util::html::strip_html(&field.value);
        let conf_url = if verified { 0.82 } else { 0.65 };
        let conf_domain = if verified { 0.80 } else { 0.58 };

        // Extract href from the raw HTML value for the URL entity.
        let href = extract_href(&field.value);
        let url_candidate = href.as_deref().unwrap_or(plain.trim());

        if url_candidate.starts_with("http://") || url_candidate.starts_with("https://") {
            if url_candidate.contains(instance) {
                // Skip self-links to the mastodon instance.
            } else {
                let mut url_e = Entity::new(EntityKind::Url, url_candidate, conf_url, scan_id);
                url_e.tag("mastodon");
                url_e.tag("profile-field");
                if verified {
                    url_e.tag("rel-me-verified");
                }
                let mut field_ev = ev
                    .clone()
                    .with_attr("field_name", &field.name)
                    .with_attr("verified", if verified { "true" } else { "false" });
                if let Some(ref ts) = field.verified_at {
                    field_ev = field_ev.with_attr("verified_at", ts);
                }
                url_e.add_evidence(field_ev.clone());
                result.push(url_e);

                if let Some(host) = crate::util::url_util::host_from_url(url_candidate)
                    && host.contains('.')
                    && !is_common_platform(&host)
                {
                    let mut d = Entity::new(EntityKind::Domain, &host, conf_domain, scan_id);
                    d.tag("mastodon");
                    d.tag("profile-field");
                    if verified {
                        d.tag("rel-me-verified");
                    }
                    d.add_evidence(field_ev);
                    result.push(d);
                }
            }
        } else if looks_like_location_field(&field.name) && !plain.trim().is_empty() {
            // Location fields → Address.
            let loc = plain.trim();
            if loc.len() <= 100 {
                let mut a = Entity::new(EntityKind::Address, loc, 0.38, scan_id);
                a.tag("mastodon");
                a.tag("self-asserted");
                a.tag("geo-hint");
                a.add_evidence(
                    ev.clone()
                        .with_attr("source_field", &field.name)
                        .with_attr("instance", instance),
                );
                result.push(a);
            }
        }
    }

    result.entities
}

/// Extract the first `href="..."` value from a snippet of HTML.
fn extract_href(html: &str) -> Option<String> {
    let lower = html.to_ascii_lowercase();
    let start = lower.find("href=\"")? + "href=\"".len();
    let end = html[start..].find('"')? + start;
    let href = html[start..end].trim().to_string();
    if href.is_empty() { None } else { Some(href) }
}

/// True when a field name indicates a geographic location.
fn looks_like_location_field(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    n.contains("location")
        || n.contains("loc")
        || n.contains("city")
        || n.contains("country")
        || n == "based in"
        || n == "where"
}

/// Suppresses Domain entities for high-volume social/platform hosts that
/// add noise rather than signal.
fn is_common_platform(host: &str) -> bool {
    matches!(
        host,
        "mastodon.social"
            | "twitter.com"
            | "x.com"
            | "github.com"
            | "instagram.com"
            | "linkedin.com"
            | "youtube.com"
            | "facebook.com"
            | "tiktok.com"
            | "bsky.app"
            | "bsky.social"
    )
}

/// Emit a Domain entity derived from a URL found in the bio, excluding the
/// instance's own domain and common platforms.
fn emit_domain_from_url(
    url: &str,
    instance: &str,
    username: &str,
    scan_id: &str,
    result: &mut ModuleResult,
    ev: &Evidence,
) {
    let Some(host) = crate::util::url_util::host_from_url(url) else {
        return;
    };
    if !host.contains('.') || host == instance || is_common_platform(&host) {
        return;
    }
    let mut d = Entity::new(EntityKind::Domain, &host, 0.52, scan_id);
    d.tag("mastodon");
    d.tag("derived");
    d.add_evidence(
        ev.clone()
            .with_attr("source_url", url)
            .with_attr("mastodon_user", username),
    );
    result.push(d);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_acct(
        username: &str,
        display_name: Option<&str>,
        note: Option<&str>,
        url: Option<&str>,
        fields: Vec<(&str, &str, bool)>,
    ) -> MastodonAccount {
        MastodonAccount {
            username: username.to_string(),
            display_name: display_name.map(str::to_string),
            note: note.map(str::to_string),
            url: url.map(str::to_string),
            fields: fields
                .into_iter()
                .map(|(name, value, verified)| MastodonField {
                    name: name.to_string(),
                    value: value.to_string(),
                    verified_at: if verified {
                        Some("2024-01-01T00:00:00Z".to_string())
                    } else {
                        None
                    },
                })
                .collect(),
            created_at: Some("2022-11-01T00:00:00Z".to_string()),
        }
    }

    #[test]
    fn builds_username_entity_confirmed_on_mastodon() {
        let acct = make_acct("alice", None, None, None, vec![]);
        let ents = build_entities(acct, "mastodon.social", "scan-mst-001");
        let u = ents
            .iter()
            .find(|e| e.kind == EntityKind::Username && e.value == "alice");
        assert!(u.is_some(), "must emit Username entity");
        assert!((u.unwrap().confidence - 0.85).abs() < 0.01);
        assert!(u.unwrap().has_tag("mastodon") && u.unwrap().has_tag("fediverse"));
    }

    #[test]
    fn emits_person_from_multi_word_display_name() {
        let acct = make_acct("alice", Some("Alice Hacker"), None, None, vec![]);
        let ents = build_entities(acct, "mastodon.social", "scan-mst-002");
        let p = ents.iter().find(|e| e.kind == EntityKind::Person);
        assert!(p.is_some(), "must emit Person from multi-word display name");
        assert_eq!(p.unwrap().value, "Alice Hacker");
    }

    #[test]
    fn emits_email_from_bio() {
        let acct = make_acct(
            "alice",
            None,
            Some("<p>Contact: <a href=\"mailto:alice@example.com\">alice@example.com</a></p>"),
            None,
            vec![],
        );
        let ents = build_entities(acct, "mastodon.social", "scan-mst-003");
        assert!(
            ents.iter()
                .any(|e| e.kind == EntityKind::Email && e.value == "alice@example.com"),
            "must extract email from HTML bio"
        );
    }

    #[test]
    fn emits_verified_url_and_domain_from_field() {
        let acct = make_acct(
            "alice",
            None,
            None,
            None,
            vec![(
                "Website",
                "<a href=\"https://alice.dev\" rel=\"me\">alice.dev</a>",
                true,
            )],
        );
        let ents = build_entities(acct, "mastodon.social", "scan-mst-004");
        let url_e = ents
            .iter()
            .find(|e| e.kind == EntityKind::Url && e.value.contains("alice.dev"));
        assert!(url_e.is_some(), "must emit URL from verified field");
        assert!(url_e.unwrap().has_tag("rel-me-verified"));
        assert!(url_e.unwrap().confidence >= 0.80);
        let dom = ents
            .iter()
            .find(|e| e.kind == EntityKind::Domain && e.value == "alice.dev");
        assert!(dom.is_some(), "must emit Domain from verified field");
        assert!(dom.unwrap().has_tag("rel-me-verified"));
    }

    #[test]
    fn emits_address_from_location_field() {
        let acct = make_acct(
            "alice",
            None,
            None,
            None,
            vec![("Location", "Berlin, Germany", false)],
        );
        let ents = build_entities(acct, "mastodon.social", "scan-mst-005");
        let a = ents.iter().find(|e| e.kind == EntityKind::Address);
        assert!(a.is_some(), "must emit Address from location field");
        assert_eq!(a.unwrap().value, "Berlin, Germany");
    }

    #[test]
    fn unverified_field_gets_lower_confidence() {
        let acct = make_acct(
            "alice",
            None,
            None,
            None,
            vec![("Blog", "https://alice.dev", false)],
        );
        let ents = build_entities(acct, "mastodon.social", "scan-mst-006");
        let url_e = ents
            .iter()
            .find(|e| e.kind == EntityKind::Url && e.value.contains("alice.dev"));
        assert!(url_e.is_some());
        assert!(
            url_e.unwrap().confidence < 0.75,
            "unverified field URL should be below 0.75"
        );
        assert!(!url_e.unwrap().has_tag("rel-me-verified"));
    }

    #[test]
    fn extract_href_works() {
        assert_eq!(
            extract_href("<a href=\"https://alice.dev\" rel=\"me\">alice.dev</a>"),
            Some("https://alice.dev".to_string())
        );
        assert_eq!(extract_href("plain text"), None);
    }
}
