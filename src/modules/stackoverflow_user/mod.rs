//! Stack Overflow / Stack Exchange user lookup. Free, no key required for
//! read-only endpoints — the official public API v2.3.
//!
//! Endpoint: `GET https://api.stackexchange.com/2.3/users?inname={username}&site=stackoverflow&filter=!9Z(-x.hbL`
//!
//! The `inname` filter returns users whose display name *contains* the query.
//! We pick the first exact-match (case-insensitive) on `display_name`. A 404
//! or empty `items` array is a clean miss. The API is throttled at ~300
//! anonymous req/day per IP, so the module exits immediately on a miss rather
//! than retrying.
//!
//! Why it earns a place in the keyless set: Stack Overflow is one of the
//! largest developer Q&A platforms — tens of millions of accounts. The profile
//! exposes `display_name`, `location`, `website_url`, and `link` (the profile
//! URL). As an independent `forum`-family source it contributes a distinct
//! corroboration pathway for AU-045 multi-service identity confirmation.

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

const SRC: &str = "stackoverflow_user";

/// Build the Stack Exchange `users?inname=` search URL for `handle`.
///
/// No custom `filter` is sent: the previously hard-coded `filter=!9Z(-x.hbL` is
/// now rejected by the API with HTTP 400 `"Invalid filter specified"`, which live
/// end-to-end testing (a real username seed) caught — it had silently broken
/// EVERY Stack Overflow lookup. The API's default filter already returns every
/// field this module reads (`display_name`, `location`, `website_url`, `link`,
/// `reputation`, `creation_date`), verified live, so omitting the parameter is
/// both correct and drift-proof (a custom encoded filter can be invalidated by an
/// API revision; the default cannot). Usernames may contain spaces, so the query
/// is URL-encoded.
fn users_by_name_url(handle: &str) -> String {
    // `pagesize=100` (the anonymous maximum) instead of the API's default 30: the
    // exact-name match we want can sit past position 30 for a common display name,
    // so the wider page raises match recall at no extra request cost (one search
    // either way). Live-verified the parameter is accepted.
    format!(
        "https://api.stackexchange.com/2.3/users?inname={}&site=stackoverflow&pagesize=100",
        crate::util::http::urlencode(handle)
    )
}

/// The network-wide "associated accounts" endpoint for a Stack Exchange
/// `account_id`: the SAME person's presence across EVERY Stack Exchange site
/// (Server Fault, Super User, the topical SEs, …) — a strong cross-platform
/// footprint + interest signal. **Pure.**
fn associated_url(account_id: i64) -> String {
    format!("https://api.stackexchange.com/2.3/users/{account_id}/associated?pagesize=100")
}

pub struct StackoverflowUser;

#[derive(Deserialize)]
pub(super) struct SoResp {
    #[serde(default)]
    pub(super) items: Vec<SoUser>,
}

#[derive(Deserialize)]
pub(super) struct SoUser {
    pub(super) display_name: String,
    #[serde(default)]
    pub(super) location: Option<String>,
    #[serde(default)]
    pub(super) website_url: Option<String>,
    /// Canonical profile URL, e.g. `https://stackoverflow.com/users/12345/alice`.
    #[serde(default)]
    pub(super) link: Option<String>,
    #[serde(default)]
    pub(super) reputation: Option<i64>,
    /// Unix epoch (UTC) the account was created — surfaced as `account_created`,
    /// an account-age temporal signal (older accounts corroborate identity and
    /// anchor breach/activity timelines).
    #[serde(default)]
    pub(super) creation_date: Option<i64>,
    /// Network-wide Stack Exchange account id — stable across every SE site and
    /// the key to the `associated` cross-site footprint lookup.
    #[serde(default)]
    pub(super) account_id: Option<i64>,
}

#[derive(Deserialize)]
pub(super) struct SoAssociatedResp {
    #[serde(default)]
    pub(super) items: Vec<SoAssociated>,
}

/// One site in a user's Stack Exchange network footprint.
#[derive(Deserialize)]
pub(super) struct SoAssociated {
    #[serde(default)]
    pub(super) site_name: Option<String>,
    #[serde(default)]
    pub(super) site_url: Option<String>,
    #[serde(default)]
    pub(super) user_id: Option<i64>,
    #[serde(default)]
    pub(super) reputation: Option<i64>,
}

#[async_trait]
impl Module for StackoverflowUser {
    fn name(&self) -> &'static str {
        "stackoverflow_user"
    }

    fn description(&self) -> &'static str {
        "Stack Overflow account recon — resolves display name, location, and website via public API"
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
        // Developer forum — T1593.001 Search Open Websites/Domains.
        // May also surface location information — T1591.001.
        &["T1591.001", "T1593.001"]
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[
            EntityKind::Username,
            EntityKind::Person,
            EntityKind::Url,
            EntityKind::Domain,
            EntityKind::Address,
            EntityKind::Coordinates,
        ];
        KINDS
    }

    fn max_timeout_ms(&self) -> u64 {
        8_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let handle = target.value.trim();
        if handle.is_empty() || handle.len() > 100 {
            return Ok(ModuleResult::new());
        }

        let url = users_by_name_url(handle);
        let resp: Option<SoResp> = fetch_json_or_404(&ctx.http, SRC, &url).await?;
        let items = match resp {
            Some(r) => r.items,
            None => return Ok(ModuleResult::new()),
        };

        // Pick the first element whose display_name exactly matches (case-insensitive).
        let user = match items
            .into_iter()
            .find(|u| u.display_name.eq_ignore_ascii_case(handle))
        {
            Some(u) => u,
            None => return Ok(ModuleResult::new()),
        };

        // Cross-Stack-Exchange footprint: a second, best-effort call to the
        // `associated` endpoint (keyed on the network account_id). A failure —
        // the anonymous ~300/day rate wall's 429, a transport error — is
        // swallowed, since the SO profile above stands on its own.
        let associated: Vec<SoAssociated> = match user.account_id {
            Some(aid) => {
                match fetch_json_or_404::<SoAssociatedResp>(&ctx.http, SRC, &associated_url(aid))
                    .await
                {
                    Ok(Some(r)) => r.items,
                    _ => Vec::new(),
                }
            }
            None => Vec::new(),
        };

        let mut result = ModuleResult::new();
        result.entities = build_entities(user, &associated, &ctx.scan_id);
        Ok(result)
    }
}

/// Pure account→entity mapping. `associated` is the (possibly empty) network
/// footprint from the `associated` endpoint.
pub(super) fn build_entities(
    user: SoUser,
    associated: &[SoAssociated],
    scan_id: &str,
) -> Vec<Entity> {
    let mut result = ModuleResult::new();

    // Confirmed-on-StackOverflow username.
    let mut u = Entity::new(EntityKind::Username, &user.display_name, 0.82, scan_id);
    u.tag("stackoverflow");
    u.tag("forum");
    let mut ev = Evidence::new(
        SRC,
        format!("Stack Overflow account '{}'", user.display_name),
    );
    if let Some(ref link) = user.link {
        ev = ev.with_attr("profile_url", link);
    }
    if let Some(rep) = user.reputation {
        ev = ev.with_attr("reputation", rep.to_string());
    }
    if let Some(created) = user.creation_date.and_then(crate::util::timefmt::ymd_utc) {
        ev = ev.with_attr("account_created", created);
    }
    // Network-wide account id — a stable identifier across every SE site.
    if let Some(aid) = user.account_id {
        ev = ev.with_attr("account_id", aid.to_string());
    }
    // Summarise the cross-network footprint on the username itself (the
    // per-site profile URLs are emitted separately below).
    if !associated.is_empty() {
        let mut sites: Vec<&str> = associated
            .iter()
            .filter_map(|a| a.site_name.as_deref())
            .collect();
        sites.sort_unstable();
        sites.dedup();
        ev = ev
            .with_attr("stackexchange_sites", sites.len().to_string())
            .with_attr("stackexchange_network", sites.join(", "));
    }
    u.add_evidence(ev);
    result.push(u);

    // Cross-Stack-Exchange footprint → one Url per site the SAME account is
    // active on (Server Fault, Super User, topical SEs). The primary
    // stackoverflow.com profile is already emitted via `link`, so it is skipped
    // here. Capped, and only real profiles (a resolvable `site_url` + `user_id`).
    const MAX_ASSOCIATED: usize = 15;
    let mut assoc_sorted: Vec<&SoAssociated> = associated.iter().collect();
    // Most-active (highest reputation) sites first, so the cap keeps the signal.
    assoc_sorted.sort_by_key(|a| std::cmp::Reverse(a.reputation.unwrap_or(0)));
    for a in assoc_sorted.into_iter().take(MAX_ASSOCIATED) {
        let (Some(site_url), Some(uid)) = (
            a.site_url
                .as_deref()
                .map(str::trim)
                .filter(|s| s.starts_with("http")),
            a.user_id,
        ) else {
            continue;
        };
        // Skip the primary Stack Overflow profile (already surfaced via `link`).
        if site_url.contains("stackoverflow.com") {
            continue;
        }
        let profile = format!("{}/users/{uid}", site_url.trim_end_matches('/'));
        let mut e = Entity::new(EntityKind::Url, &profile, 0.72, scan_id);
        e.tag("stackexchange");
        e.tag("cross-platform");
        let mut pev = Evidence::new(
            SRC,
            format!(
                "Same Stack Exchange account '{}' active on {}",
                user.display_name,
                a.site_name.as_deref().unwrap_or("another SE site")
            ),
        )
        .with_attr("so_username", &user.display_name);
        if let Some(sn) = a.site_name.as_deref() {
            pev = pev.with_attr("site_name", sn);
        }
        if let Some(rep) = a.reputation {
            pev = pev.with_attr("reputation", rep.to_string());
        }
        e.add_evidence(pev);
        result.push(e);
    }

    // Display name → Person when it looks like a real name (≥2 words).
    if let Some(mut p) = profile_kit::person_from_name(&user.display_name, 0.55, scan_id) {
        p.tag("stackoverflow");
        p.tag("derived");
        p.add_evidence(
            Evidence::new(
                SRC,
                format!(
                    "Real name from Stack Overflow account '{}'",
                    user.display_name
                ),
            )
            .with_attr("so_username", &user.display_name),
        );
        result.push(p);
    }

    // Profile URL.
    if let Some(ref link) = user.link
        && link.starts_with("http")
    {
        let mut url_e = Entity::new(EntityKind::Url, link, 0.75, scan_id);
        url_e.tag("stackoverflow");
        url_e.add_evidence(Evidence::new(
            SRC,
            format!("Stack Overflow profile URL for '{}'", user.display_name),
        ));
        result.push(url_e);
    }

    // Personal website URL + Domain.
    if let Some(ref site) = user.website_url {
        for mut e in profile_kit::website_url_and_domain(site, 0.70, 0.62, scan_id) {
            e.tag("stackoverflow");
            match e.kind {
                EntityKind::Domain => {
                    e.tag("derived");
                    e.add_evidence(
                        Evidence::new(
                            SRC,
                            format!(
                                "Domain from Stack Overflow profile of '{}'",
                                user.display_name
                            ),
                        )
                        .with_attr("source_url", site.as_str())
                        .with_attr("so_username", &user.display_name),
                    );
                }
                _ => {
                    e.tag("personal-site");
                    e.add_evidence(
                        Evidence::new(
                            SRC,
                            format!(
                                "Personal site from Stack Overflow profile of '{}'",
                                user.display_name
                            ),
                        )
                        .with_attr("source_field", "website_url"),
                    );
                }
            }
            result.push(e);
        }
    }

    // Location → coarse Address.
    if let Some(ref loc) = user.location
        && let Some(mut a) = profile_kit::location_address(loc, 0.38, scan_id)
    {
        a.tag("stackoverflow");
        a.tag("self-asserted");
        a.tag("geo-hint");
        a.add_evidence(
            Evidence::new(
                SRC,
                format!(
                    "Self-reported location from Stack Overflow profile of '{}'",
                    user.display_name
                ),
            )
            .with_attr("source_field", "location")
            .with_attr("so_username", &user.display_name),
        );
        result.push(a);
        if let Some(mut c) = profile_kit::location_coordinates(loc, 0.28, scan_id) {
            c.tag("stackoverflow");
            c.add_evidence(
                Evidence::new(
                    SRC,
                    format!(
                        "Geocode of self-reported location for '{}'",
                        user.display_name
                    ),
                )
                .with_attr("source_field", "location"),
            );
            result.push(c);
        }
    }

    result.entities
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn users_url_omits_the_invalid_custom_filter() {
        // Regression for the API drift live testing caught: the old hard-coded
        // `filter=!9Z(-x.hbL` now 400s ("Invalid filter specified"), breaking every
        // lookup. The default filter returns all needed fields, so no filter is sent.
        let url = users_by_name_url("jon skeet");
        assert!(
            !url.contains("filter="),
            "no custom filter — the default returns every field we read: {url}"
        );
        // Spaces are form-encoded (`+`); the point is the query is present + escaped.
        assert!(
            url.contains("inname=jon+skeet") && url.contains("site=stackoverflow"),
            "url: {url}"
        );
    }

    fn make_user(
        display_name: &str,
        location: Option<&str>,
        website_url: Option<&str>,
        link: Option<&str>,
        reputation: Option<i64>,
    ) -> SoUser {
        SoUser {
            display_name: display_name.to_string(),
            location: location.map(str::to_string),
            website_url: website_url.map(str::to_string),
            link: link.map(str::to_string),
            reputation,
            creation_date: Some(1_546_300_800), // 2019-01-01T00:00:00Z
            account_id: None,
        }
    }

    fn assoc(site_name: &str, site_url: &str, user_id: i64, reputation: i64) -> SoAssociated {
        SoAssociated {
            site_name: Some(site_name.to_string()),
            site_url: Some(site_url.to_string()),
            user_id: Some(user_id),
            reputation: Some(reputation),
        }
    }

    #[test]
    fn builds_username_entity_confirmed_on_so() {
        let user = make_user("alice", None, None, None, Some(1234));
        let ents = build_entities(user, &[], "scan-so-001");
        let u = ents
            .iter()
            .find(|e| e.kind == EntityKind::Username && e.value == "alice");
        assert!(u.is_some(), "must emit Username entity");
        assert!((u.unwrap().confidence - 0.82).abs() < 0.01);
        assert!(u.unwrap().has_tag("stackoverflow") && u.unwrap().has_tag("forum"));
    }

    #[test]
    fn username_evidence_surfaces_account_creation_date() {
        // creation_date was deserialized but dropped; it must now appear as the
        // `account_created` evidence attr (UTC date) — an account-age signal.
        let user = make_user("alice", None, None, None, Some(1234));
        let ents = build_entities(user, &[], "scan-so-created");
        let u = ents
            .iter()
            .find(|e| e.kind == EntityKind::Username && e.value == "alice")
            .expect("Username entity");
        assert_eq!(
            u.evidence[0]
                .attributes
                .get("account_created")
                .map(String::as_str),
            Some("2019-01-01"),
            "the deserialized creation_date must surface as a UTC date"
        );
    }

    #[test]
    fn emits_person_from_multi_word_display_name() {
        let user = make_user("Alice Developer", None, None, None, None);
        let ents = build_entities(user, &[], "scan-so-002");
        let p = ents.iter().find(|e| e.kind == EntityKind::Person);
        assert!(p.is_some(), "must emit Person from multi-word display name");
        assert_eq!(p.unwrap().value, "Alice Developer");
    }

    #[test]
    fn no_person_for_single_word_name() {
        let user = make_user("alice", None, None, None, None);
        let ents = build_entities(user, &[], "scan-so-003");
        assert!(
            ents.iter().all(|e| e.kind != EntityKind::Person),
            "single-token display name must not produce a Person entity"
        );
    }

    #[test]
    fn emits_website_url_and_domain() {
        let user = make_user(
            "alice",
            None,
            Some("https://alice.dev"),
            Some("https://stackoverflow.com/users/1/alice"),
            None,
        );
        let ents = build_entities(user, &[], "scan-so-004");
        assert!(
            ents.iter()
                .any(|e| e.kind == EntityKind::Url && e.value == "https://alice.dev"),
            "must emit website URL"
        );
        assert!(
            ents.iter()
                .any(|e| e.kind == EntityKind::Domain && e.value == "alice.dev"),
            "must emit domain from website"
        );
    }

    #[test]
    fn emits_address_from_location() {
        let user = make_user("alice", Some("Berlin, DE"), None, None, None);
        let ents = build_entities(user, &[], "scan-so-005");
        let a = ents.iter().find(|e| e.kind == EntityKind::Address);
        assert!(a.is_some(), "must emit Address from location");
        assert_eq!(a.unwrap().value, "Berlin, DE");
        assert!(a.unwrap().has_tag("self-asserted"));
    }

    #[test]
    fn no_entities_for_absent_optional_fields() {
        let user = make_user("quietuser", None, None, None, None);
        let ents = build_entities(user, &[], "scan-so-006");
        assert_eq!(ents.len(), 1, "only Username when no optional fields");
        assert_eq!(ents[0].kind, EntityKind::Username);
    }

    #[test]
    fn associated_url_targets_the_network_account() {
        assert_eq!(
            associated_url(11683),
            "https://api.stackexchange.com/2.3/users/11683/associated?pagesize=100"
        );
    }

    #[test]
    fn search_url_requests_the_max_page_size() {
        assert!(users_by_name_url("alice").contains("pagesize=100"));
    }

    #[test]
    fn account_id_and_network_footprint_surface() {
        // Verbatim shape of the live `associated` response (Jon Skeet, account 11683):
        // the same account across Server Fault / Super User / Meta, each with a
        // per-site user_id → a resolvable profile URL. The primary stackoverflow.com
        // profile is skipped (already emitted via `link`).
        let mut user = make_user(
            "Jon Skeet",
            None,
            None,
            Some("https://stackoverflow.com/users/22656/jon-skeet"),
            Some(1_528_530),
        );
        user.account_id = Some(11683);
        let assoc = vec![
            assoc(
                "Stack Overflow",
                "https://stackoverflow.com",
                22656,
                1_528_530,
            ),
            assoc("Server Fault", "https://serverfault.com", 173, 5117),
            assoc("Super User", "https://superuser.com", 410, 5144),
        ];
        let ents = build_entities(user, &assoc, "scan-so-assoc");

        // account_id + network summary land on the username entity.
        let u = ents
            .iter()
            .find(|e| e.kind == EntityKind::Username)
            .unwrap();
        assert_eq!(
            u.evidence[0]
                .attributes
                .get("account_id")
                .map(String::as_str),
            Some("11683")
        );
        assert_eq!(
            u.evidence[0]
                .attributes
                .get("stackexchange_sites")
                .map(String::as_str),
            Some("3")
        );

        // Per-site profile URLs for the OTHER sites, tagged cross-platform;
        // the stackoverflow.com one is NOT re-emitted here.
        let assoc_urls: Vec<&str> = ents
            .iter()
            .filter(|e| e.kind == EntityKind::Url && e.has_tag("stackexchange"))
            .map(|e| e.value.as_str())
            .collect();
        assert!(assoc_urls.contains(&"https://serverfault.com/users/173"));
        assert!(assoc_urls.contains(&"https://superuser.com/users/410"));
        assert!(
            !assoc_urls.iter().any(|u| u.contains("stackoverflow.com")),
            "primary SO profile must not be duplicated as an associated URL"
        );
        assert!(
            ents.iter()
                .filter(|e| e.has_tag("stackexchange"))
                .all(|e| e.has_tag("cross-platform"))
        );
    }
}
