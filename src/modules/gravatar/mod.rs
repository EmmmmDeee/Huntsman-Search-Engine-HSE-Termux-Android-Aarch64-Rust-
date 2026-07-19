//! Gravatar profile enrichment — free, no-credential email → public profile.
//!
//! Endpoint: `https://gravatar.com/<md5(lowercased-trimmed-email)>.json`. The
//! profile is owner-controlled and public; a missing one is a clean `404`. No
//! API key, no rate-limit billing — a textbook free OSINT source (the classic
//! SpiderFoot `sfp_gravatar`).
//!
//! Synergy: an `Email` seed (or any email discovered mid-scan) now yields the
//! owner's self-asserted identity graph — real name, preferred username, linked
//! social accounts, personal URLs, and location — each emitted as a first-class
//! entity that feeds the rest of the pipeline (`name_intel`, `username_search`,
//! `social_probe`, the geocoders, `web_crawler`). Because the data is published
//! by the email owner, the linkage confidence is high.
//!
//! Termux: a single small JSON GET; `termux_timeout_ms` inherits the scaled
//! default from `max_timeout_ms` so a slow mobile network still completes.

use async_trait::async_trait;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
// The Gravatar request-hash + response schema are the shared Gravatar API
// contract, single-sourced in `util::gravatar` (T2.124) — imported here under
// this module's established local names so its body and tests are unchanged.
use crate::util::gravatar::{Entry, Profile as GravatarResp, hash as gravatar_hash};
use crate::util::http::fetch_json_or_404;

const SRC: &str = "gravatar";

pub struct Gravatar;

#[async_trait]
impl Module for Gravatar {
    fn name(&self) -> &'static str {
        "gravatar"
    }

    fn description(&self) -> &'static str {
        "Gravatar public profile enrichment (email → name, accounts, URLs, location)"
    }

    fn priority(&self) -> u8 {
        // Enrichment tier: runs after the breach/identity pools so a discovered
        // email is enriched, but it produces no paid-quota pressure.
        90
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Email)
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::People
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        // People default (T1589.003 Employee Names + T1591.004 Identify Roles) but
        // Gravatar surfaces no role information — only Person, Username, URL, and a
        // profile location Address (T1591.001 Determine Physical Locations). Drop
        // the over-claimed T1591.004 and add the correct T1591.001.
        &["T1591.001", "T1589.003"]
    }

    fn max_timeout_ms(&self) -> u64 {
        // One small JSON GET, but mobile networks are slow; budget well above
        // the 3s default so a single slow response isn't a spurious timeout.
        10_000
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[
            EntityKind::Person,
            EntityKind::Username,
            EntityKind::Url,
            EntityKind::Address,
            EntityKind::Coordinates,
        ];
        KINDS
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let email = target.value.trim();
        if !email.contains('@') {
            return Ok(ModuleResult::new());
        }
        let hash = gravatar_hash(email);
        let url = format!("https://gravatar.com/{hash}.json");

        let fetched = fetch_json_or_404(&ctx.http, SRC, &url).await;
        resolve_profile(fetched, &hash, &ctx.scan_id)
    }
}

/// Turn the profile fetch's raw outcome into `process()`'s return value.
///
/// `Ok(None)` is Gravatar's own live "no such profile" signal — a genuine
/// HTTP 404 (reconfirmed live 2026-07-15 against a random unregistered
/// email; `fetch_json_or_404` maps a 404 straight to `None` before any body
/// is even read) — and stays the ordinary, honest empty success. Every
/// `Err` (a non-2xx status such as 429/5xx, or a transport failure even the
/// curl fallback could not rescue) is a genuine operational failure, not a
/// clean miss, and must propagate — surfacing as a real `ModuleError` event
/// and feeding the T2.7 health-signal streak — instead of silently
/// masquerading as "this email has no Gravatar profile" (T2.112: the
/// previous `Ok(None) | Err(_) => return Ok(result)` collapsed both into the
/// same empty result, making a real outage indistinguishable from a clean
/// negative). Pure (no I/O), so it is unit-testable without a live server,
/// unlike `process()` itself, whose URL is hardcoded to gravatar.com.
fn resolve_profile(
    fetched: Result<Option<GravatarResp>>,
    hash: &str,
    scan_id: &str,
) -> Result<ModuleResult> {
    let mut result = ModuleResult::new();
    let Some(entry) = fetched?.and_then(|r| r.entry.into_iter().next()) else {
        return Ok(result);
    };
    extract_entry(&entry, hash, scan_id, &mut result);
    Ok(result)
}

/// Turn a Gravatar profile entry into entities. Pure of I/O so it is unit-tested
/// against a fixture; the network shell in `process` stays a thin adapter.
fn extract_entry(entry: &Entry, hash: &str, scan_id: &str, result: &mut ModuleResult) {
    // Evidence shared by every derived entity: the profile's provenance.
    let ev = [
        ("profile_url", entry.profile_url.as_deref()),
        ("display_name", entry.display_name.as_deref()),
        ("about_me", entry.about_me.as_deref()),
    ]
    .into_iter()
    .filter_map(|(key, value)| value.map(|v| (key, v)))
    .fold(
        Evidence::new(SRC, "Gravatar public profile").with_attr("gravatar_hash", hash),
        |ev, (key, v)| ev.with_attr(key, v),
    );

    let push =
        |result: &mut ModuleResult, kind: EntityKind, value: &str, conf: f64, tags: &[&str]| {
            let mut e = Entity::new(kind, value, conf, scan_id);
            e.tag(SRC);
            tags.iter().for_each(|t| e.tag(*t));
            e.add_evidence(ev.clone());
            result.push(e);
        };

    // Real name — prefer the formatted name, else compose given + family, else
    // the display name when it looks like a multi-word person name.
    let name = entry
        .name
        .as_ref()
        .and_then(|n| {
            n.formatted.clone().or_else(|| {
                match (n.given_name.as_deref(), n.family_name.as_deref()) {
                    (Some(g), Some(f)) => Some(format!("{g} {f}")),
                    _ => None,
                }
            })
        })
        .or_else(|| {
            entry
                .display_name
                .clone()
                .filter(|d| d.trim().contains(' '))
        });
    if let Some(name) = name.map(|n| n.trim().to_string()).filter(|n| n.len() >= 3) {
        push(result, EntityKind::Person, &name, 0.70, &[]);
    }

    // Preferred username — a strong pivot into the free username stack.
    if let Some(u) = entry
        .preferred_username
        .as_deref()
        .map(str::trim)
        .filter(|u| u.len() >= 2)
    {
        push(result, EntityKind::Username, u, 0.65, &[]);
    }

    // Location — geo-hint the geocoders can resolve.
    if let Some(loc) = entry
        .current_location
        .as_deref()
        .map(str::trim)
        .filter(|l| l.len() >= 2)
    {
        push(result, EntityKind::Address, loc, 0.60, &["geo-hint"]);
        if let Some((lat, lon)) = crate::util::city_coords::city_coords(loc) {
            let coord_val = format!("{lat:.4},{lon:.4}");
            push(
                result,
                EntityKind::Coordinates,
                &coord_val,
                0.50,
                &["addr-derived", "geoint"],
            );
        }
    }

    // Profile + avatar URLs.
    [entry.profile_url.as_deref(), entry.thumbnail_url.as_deref()]
        .into_iter()
        .flatten()
        .map(str::trim)
        .filter(|u| u.starts_with("http"))
        .for_each(|u| push(result, EntityKind::Url, u, 0.60, &[]));

    // Personal URLs the owner listed — each carries the owner's self-asserted
    // link label (`title`, e.g. "Blog"/"Portfolio") as `link_title` evidence,
    // which was deserialized into `UrlEntry.title` but previously dropped.
    for u in &entry.urls {
        if let Some(val) = u
            .value
            .as_deref()
            .map(str::trim)
            .filter(|v| v.starts_with("http"))
        {
            let mut e = Entity::new(EntityKind::Url, val, 0.60, scan_id);
            e.tag(SRC);
            let mut prov = ev.clone();
            if let Some(t) = u.title.as_deref().map(str::trim).filter(|t| !t.is_empty()) {
                prov = prov.with_attr("link_title", t);
            }
            e.add_evidence(prov);
            result.push(e);
        }
    }

    // Linked social accounts — each becomes a bare Username pivot (tagged with
    // the platform name) so it deduplicates correctly with usernames discovered
    // by platform-native modules (devto, gitlab_user, github_user, etc.).
    // The account URL is emitted separately as a Url entity.
    for acct in &entry.accounts {
        let platform = acct
            .shortname
            .as_deref()
            .or(acct.domain.as_deref())
            .unwrap_or("account")
            .trim();
        let verified = acct.verified == Some(true);
        let mut tags: Vec<&str> = vec![platform, "gravatar-pivot"];
        if verified {
            tags.push("verified");
        }
        if let Some(uname) = acct
            .username
            .as_deref()
            .map(str::trim)
            .filter(|u| !u.is_empty())
        {
            let conf = if verified { 0.65 } else { 0.55 };
            let mut e = Entity::new(EntityKind::Username, uname, conf, scan_id);
            e.tag(SRC);
            tags.iter().for_each(|t| e.tag(*t));
            e.add_evidence(
                ev.clone()
                    .with_attr("platform", platform)
                    .with_attr("platform_handle", format!("{platform}:{uname}")),
            );
            result.push(e);
        }
        if let Some(u) = acct
            .url
            .as_deref()
            .map(str::trim)
            .filter(|u| u.starts_with("http"))
        {
            push(result, EntityKind::Url, u, 0.55, &tags);
        }
    }
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
