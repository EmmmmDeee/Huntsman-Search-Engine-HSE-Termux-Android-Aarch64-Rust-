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
use md5::{Digest, Md5};
use serde::Deserialize;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::fetch_json_or_404;

const SRC: &str = "gravatar";

pub struct Gravatar;

/// Top-level Gravatar profile response: `{ "entry": [ { … } ] }`.
#[derive(Deserialize, Default)]
#[serde(default)]
struct GravatarResp {
    entry: Vec<Entry>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Entry {
    hash: Option<String>,
    #[serde(rename = "profileUrl")]
    profile_url: Option<String>,
    #[serde(rename = "preferredUsername")]
    preferred_username: Option<String>,
    #[serde(rename = "thumbnailUrl")]
    thumbnail_url: Option<String>,
    #[serde(rename = "displayName")]
    display_name: Option<String>,
    name: Option<Name>,
    #[serde(rename = "aboutMe")]
    about_me: Option<String>,
    #[serde(rename = "currentLocation")]
    current_location: Option<String>,
    #[serde(default)]
    accounts: Vec<Account>,
    #[serde(default)]
    urls: Vec<UrlEntry>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Name {
    formatted: Option<String>,
    #[serde(rename = "givenName")]
    given_name: Option<String>,
    #[serde(rename = "familyName")]
    family_name: Option<String>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Account {
    /// Stable platform slug, e.g. `twitter`, `github`.
    shortname: Option<String>,
    domain: Option<String>,
    username: Option<String>,
    url: Option<String>,
    /// Gravatar serialises this as the string `"true"`/`"false"`.
    verified: Option<String>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct UrlEntry {
    value: Option<String>,
    title: Option<String>,
}

/// The Gravatar profile-request hash: MD5 of the email lowercased and trimmed
/// (the documented Gravatar identifier). Pure, so it is unit-testable.
fn gravatar_hash(email: &str) -> String {
    let normalised = email.trim().to_ascii_lowercase();
    let digest = Md5::digest(normalised.as_bytes());
    hex::encode(digest)
}

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
        ];
        KINDS
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let mut result = ModuleResult::new();
        let email = target.value.trim();
        if !email.contains('@') {
            return Ok(result);
        }
        let hash = gravatar_hash(email);
        let url = format!("https://gravatar.com/{hash}.json");

        // "No public profile" reaches us several ways: a 404, or a 200 whose
        // body is the literal `"User not found"` (the shape Gravatar returns on
        // the curl fallback) or otherwise isn't a `GravatarResp`. None of these
        // is an operational error — they all mean the email has no Gravatar, a
        // clean miss. Only an unparseable body was previously propagated via `?`
        // as a spurious module error; fold it into the empty-result path.
        let resp: GravatarResp = match fetch_json_or_404(&ctx.http, SRC, &url).await {
            Ok(Some(r)) => r,
            Ok(None) | Err(_) => return Ok(result),
        };
        let Some(entry) = resp.entry.into_iter().next() else {
            return Ok(result);
        };

        extract_entry(&entry, &hash, &ctx.scan_id, &mut result);
        Ok(result)
    }
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
    }

    // Profile + avatar URLs, and any personal URLs the owner listed.
    [entry.profile_url.as_deref(), entry.thumbnail_url.as_deref()]
        .into_iter()
        .flatten()
        .chain(entry.urls.iter().filter_map(|u| u.value.as_deref()))
        .map(str::trim)
        .filter(|u| u.starts_with("http"))
        .for_each(|u| push(result, EntityKind::Url, u, 0.60, &[]));

    // Linked social accounts — each becomes a platform-prefixed Username pivot
    // (mirrors the see_know/breach convention) plus its account URL.
    for acct in &entry.accounts {
        let platform = acct
            .shortname
            .as_deref()
            .or(acct.domain.as_deref())
            .unwrap_or("account")
            .trim();
        let verified = acct.verified.as_deref() == Some("true");
        let mut tags: Vec<&str> = vec![platform];
        if verified {
            tags.push("verified");
        }
        if let Some(uname) = acct
            .username
            .as_deref()
            .map(str::trim)
            .filter(|u| !u.is_empty())
        {
            push(
                result,
                EntityKind::Username,
                &format!("{platform}:{uname}"),
                if verified { 0.65 } else { 0.55 },
                &tags,
            );
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
