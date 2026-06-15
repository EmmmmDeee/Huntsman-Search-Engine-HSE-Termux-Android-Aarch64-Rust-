//! Keyless email-to-identity resolution — zero API key required.
//!
//! Replicates the entity taxonomy of the key-gated [`super::epieos`] module
//! through three fully public, unauthenticated backends:
//!
//! | Backend | What it yields |
//! |---------|----------------|
//! | **Gravatar** | display name, real name, bio, current location, linked social accounts, personal URLs |
//! | **Skype search** | Skype handle, display name, city/country |
//! | **GitHub commit search** | GitHub username from public commits authored with this email |
//!
//! All three calls run concurrently; results are merged before the module
//! returns. Any backend that errors or returns nothing is silently skipped —
//! the caller sees a degraded (not failed) result.
//!
//! Confidence mirrors the key-gated module: a Gravatar-confirmed name gets
//! 0.75, Skype 0.70, GitHub username 0.72.

#[cfg(test)]
mod tests;

use std::collections::HashSet;

use async_trait::async_trait;
use serde::Deserialize;
use tokio::join;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::str_util::{nonempty, truncate_safe};

pub(super) const SRC: &str = "epieos_free";
const BIO_CAP: usize = 200;

// ── MD5 (RFC 1321) — no external crate, no unsafe ────────────────────────────

/// Compute the lowercase hex MD5 of an email for Gravatar lookups.
fn gravatar_hash(email: &str) -> String {
    use std::fmt::Write;
    let input = email.trim().to_lowercase();
    let digest = md5_bytes(input.as_bytes());
    let mut out = String::with_capacity(32);
    for b in digest {
        write!(out, "{b:02x}").ok();
    }
    out
}

fn md5_bytes(input: &[u8]) -> [u8; 16] {
    const S: [u32; 64] = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
        5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
        4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
        6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
    ];
    const K: [u32; 64] = [
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a,
        0xa8304613, 0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
        0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340,
        0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
        0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8,
        0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
        0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa,
        0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
        0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92,
        0xffeff47d, 0x85845dd1, 0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
        0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
    ];

    let bit_len = (input.len() as u64).wrapping_mul(8);
    let mut msg: Vec<u8> = input.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_le_bytes());

    let (mut a0, mut b0, mut c0, mut d0): (u32, u32, u32, u32) =
        (0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476);

    for chunk in msg.chunks(64) {
        let mut m = [0u32; 16];
        for (i, w) in m.iter_mut().enumerate() {
            let j = i * 4;
            *w = u32::from_le_bytes([chunk[j], chunk[j + 1], chunk[j + 2], chunk[j + 3]]);
        }
        let (mut a, mut b, mut c, mut d) = (a0, b0, c0, d0);
        for i in 0u32..64 {
            let (f, g) = match i {
                0..=15  => ((b & c) | (!b & d), i),
                16..=31 => ((d & b) | (!d & c), (5 * i + 1) % 16),
                32..=47 => (b ^ c ^ d,           (3 * i + 5) % 16),
                _       => (c ^ (b | !d),         (7 * i) % 16),
            };
            let temp = d;
            d = c;
            c = b;
            b = b.wrapping_add(
                a.wrapping_add(f)
                    .wrapping_add(K[i as usize])
                    .wrapping_add(m[g as usize])
                    .rotate_left(S[i as usize]),
            );
            a = temp;
        }
        a0 = a0.wrapping_add(a);
        b0 = b0.wrapping_add(b);
        c0 = c0.wrapping_add(c);
        d0 = d0.wrapping_add(d);
    }

    let mut out = [0u8; 16];
    out[0..4].copy_from_slice(&a0.to_le_bytes());
    out[4..8].copy_from_slice(&b0.to_le_bytes());
    out[8..12].copy_from_slice(&c0.to_le_bytes());
    out[12..16].copy_from_slice(&d0.to_le_bytes());
    out
}

// ── Gravatar types ────────────────────────────────────────────────────────────

#[derive(Deserialize, Default)]
pub(super) struct GravatarProfile {
    #[serde(default)]
    pub(super) entry: Vec<GravatarEntry>,
}

#[derive(Deserialize)]
pub(super) struct GravatarEntry {
    #[serde(rename = "displayName", default)]
    pub(super) display_name: Option<String>,
    #[serde(default)]
    pub(super) name: Option<GravatarName>,
    #[serde(rename = "aboutMe", default)]
    pub(super) about_me: Option<String>,
    #[serde(rename = "currentLocation", default)]
    pub(super) current_location: Option<String>,
    #[serde(rename = "thumbnailUrl", default)]
    pub(super) thumbnail_url: Option<String>,
    #[serde(rename = "profileUrl", default)]
    pub(super) profile_url: Option<String>,
    #[serde(rename = "preferredUsername", default)]
    pub(super) preferred_username: Option<String>,
    #[serde(default)]
    pub(super) urls: Vec<GravatarUrl>,
    #[serde(default)]
    pub(super) accounts: Vec<GravatarAccount>,
}

#[derive(Deserialize)]
pub(super) struct GravatarName {
    #[serde(default)]
    pub(super) formatted: Option<String>,
}

#[derive(Deserialize)]
pub(super) struct GravatarUrl {
    #[serde(default)]
    pub(super) value: Option<String>,
    #[serde(default)]
    pub(super) title: Option<String>,
}

#[derive(Deserialize)]
pub(super) struct GravatarAccount {
    #[serde(default)]
    pub(super) domain: Option<String>,
    #[serde(default)]
    pub(super) username: Option<String>,
    #[serde(rename = "name", default)]
    pub(super) display: Option<String>,
    #[serde(default)]
    pub(super) url: Option<String>,
}

// ── Skype search types ────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub(super) struct SkypeResult {
    #[serde(rename = "SkypeId", default)]
    pub(super) skype_id: Option<String>,
    #[serde(rename = "Name", default)]
    pub(super) name: Option<String>,
    #[serde(rename = "City", default)]
    pub(super) city: Option<String>,
    #[serde(rename = "Country", default)]
    pub(super) country: Option<String>,
    #[serde(rename = "IsBot", default)]
    pub(super) is_bot: bool,
}

// ── GitHub commit search types ────────────────────────────────────────────────

#[derive(Deserialize, Default)]
pub(super) struct GhCommitSearch {
    #[serde(default)]
    pub(super) items: Vec<GhCommit>,
}

#[derive(Deserialize)]
pub(super) struct GhCommit {
    #[serde(default)]
    pub(super) author: Option<GhCommitUser>,
}

#[derive(Deserialize)]
pub(super) struct GhCommitUser {
    #[serde(default)]
    pub(super) login: Option<String>,
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// `true` when `s` is plausibly a real person name: multi-word and ≥3 chars.
pub(super) fn is_person_name(s: &str) -> bool {
    let s = s.trim();
    s.chars().count() >= 3 && s.contains(' ')
}

fn unique_logins(search: GhCommitSearch) -> Vec<String> {
    let mut seen = HashSet::new();
    search
        .items
        .into_iter()
        .filter_map(|c| c.author?.login)
        .filter(|l| seen.insert(l.clone()))
        .collect()
}

// ── Entity builder (pure — unit-testable without network I/O) ─────────────────

pub(super) fn build_entities(
    target: &Target,
    gravatar: &GravatarProfile,
    skype: &[SkypeResult],
    gh_logins: &[String],
    scan_id: &str,
) -> Vec<Entity> {
    let email = target.value.trim();
    let mut out: Vec<Entity> = Vec::new();
    let mut seen_names: HashSet<String> = HashSet::new();

    // ── Anchor email entity ──────────────────────────────────────────────
    let mut anchor = target.to_entity(0.85, scan_id);
    anchor.tag("epieos_free");

    if let Some(entry) = gravatar.entry.first() {
        anchor.tag("gravatar");
        let mut ev = Evidence::new(SRC, format!("Gravatar profile for {email}"));
        if let Some(dn) = nonempty(&entry.display_name) {
            ev = ev.with_attr("gravatar_display_name", dn);
        }
        if let Some(n) = entry.name.as_ref().and_then(|n| nonempty(&n.formatted)) {
            ev = ev.with_attr("gravatar_name", n);
        }
        if let Some(bio) = nonempty(&entry.about_me) {
            ev = ev.with_attr("bio", truncate_safe(bio, BIO_CAP));
        }
        if let Some(loc) = nonempty(&entry.current_location) {
            ev = ev.with_attr("location", loc);
        }
        if let Some(pic) = nonempty(&entry.thumbnail_url) {
            ev = ev.with_attr("profile_picture", pic);
        }
        if let Some(url) = nonempty(&entry.profile_url) {
            ev = ev.with_attr("profile_url", url);
        }
        if !entry.accounts.is_empty() {
            anchor.tag("has-linked-accounts");
            let domains: Vec<&str> = entry
                .accounts
                .iter()
                .filter_map(|a| nonempty(&a.domain))
                .collect();
            if !domains.is_empty() {
                ev = ev.with_attr("linked_platforms", domains.join(", "));
            }
        }
        anchor.add_evidence(ev);
    }
    if !skype.is_empty() {
        anchor.tag("skype");
    }
    if !gh_logins.is_empty() {
        anchor.tag("github");
    }
    out.push(anchor);

    // ── Gravatar: Person + Username + Address + linked accounts + URLs ────
    if let Some(entry) = gravatar.entry.first() {
        // Person: prefer formatted name, fall back to display name.
        let name_candidates = [
            entry.name.as_ref().and_then(|n| nonempty(&n.formatted)),
            nonempty(&entry.display_name),
        ];
        for candidate in name_candidates.into_iter().flatten() {
            if is_person_name(candidate) && seen_names.insert(candidate.to_lowercase()) {
                let mut pe = Entity::new(EntityKind::Person, candidate, 0.75, scan_id);
                pe.tag("epieos_free");
                pe.tag("gravatar");
                pe.add_evidence(Evidence::new(SRC, format!("Gravatar name for {email}")));
                out.push(pe);
                break;
            }
        }

        // Username: preferred username handle (no space → it's a handle).
        if let Some(uname) = nonempty(&entry.preferred_username)
            .filter(|u| u.chars().count() >= 3 && !u.contains(' '))
        {
            let mut ue = Entity::new(EntityKind::Username, uname, 0.65, scan_id);
            ue.tag("epieos_free");
            ue.tag("gravatar");
            ue.add_evidence(Evidence::new(
                SRC,
                format!("Gravatar username for {email}"),
            ));
            out.push(ue);
        }

        // Location → Address.
        if let Some(loc) =
            nonempty(&entry.current_location).filter(|l| l.chars().count() >= 3)
        {
            let mut ae = Entity::new(EntityKind::Address, loc, 0.55, scan_id);
            ae.tag("epieos_free");
            ae.tag("gravatar");
            ae.tag("geoint");
            if let Some(sc) = crate::util::address_au::state_code(loc) {
                ae.tag(format!("au-state:{sc}"));
                ae.tag("country:AU");
            }
            ae.add_evidence(Evidence::new(
                SRC,
                format!("Gravatar location for {email}"),
            ));
            out.push(ae);
        }

        // Linked social accounts → Username entities.
        for acct in &entry.accounts {
            let Some(domain) = nonempty(&acct.domain) else {
                continue;
            };
            let Some(uname) = nonempty(&acct.username) else {
                continue;
            };
            if uname.chars().count() < 2 {
                continue;
            }
            let platform_tag = format!(
                "platform:{}",
                domain.trim_end_matches(".com")
            );
            let mut ue = Entity::new(EntityKind::Username, uname, 0.68, scan_id);
            ue.tag("epieos_free");
            ue.tag("gravatar");
            ue.tag(&platform_tag);
            let mut ev = Evidence::new(
                SRC,
                format!("Gravatar linked account on {domain} for {email}"),
            );
            if let Some(url) = nonempty(&acct.url) {
                ev = ev.with_attr("profile_url", url);
            }
            if let Some(dn) = nonempty(&acct.display) {
                ev = ev.with_attr("display_name", dn);
            }
            ue.add_evidence(ev);
            out.push(ue);
        }

        // Personal URLs → Url entities.
        for grurl in &entry.urls {
            let Some(url) = nonempty(&grurl.value) else {
                continue;
            };
            if !url.starts_with("http") {
                continue;
            }
            let mut ue = Entity::new(EntityKind::Url, url, 0.62, scan_id);
            ue.tag("epieos_free");
            ue.tag("gravatar");
            let mut ev =
                Evidence::new(SRC, format!("Gravatar personal URL for {email}"));
            if let Some(title) = nonempty(&grurl.title) {
                ev = ev.with_attr("title", title);
            }
            ue.add_evidence(ev);
            out.push(ue);
        }
    }

    // ── Skype: Person, Username, Address ─────────────────────────────────
    for sr in skype.iter().filter(|r| !r.is_bot) {
        if let Some(name) = nonempty(&sr.name)
            && is_person_name(name)
            && seen_names.insert(name.to_lowercase())
        {
            let mut pe = Entity::new(EntityKind::Person, name, 0.70, scan_id);
            pe.tag("epieos_free");
            pe.tag("platform:skype");
            pe.add_evidence(Evidence::new(
                SRC,
                format!("Skype display name for {email}"),
            ));
            out.push(pe);
        }

        if let Some(handle) =
            nonempty(&sr.skype_id).filter(|h| h.chars().count() >= 3)
        {
            let mut ue = Entity::new(EntityKind::Username, handle, 0.70, scan_id);
            ue.tag("epieos_free");
            ue.tag("platform:skype");
            ue.add_evidence(Evidence::new(SRC, format!("Skype handle for {email}")));
            out.push(ue);
        }

        if let Some(city) =
            nonempty(&sr.city).filter(|c| c.chars().count() >= 2)
        {
            let location = match nonempty(&sr.country) {
                Some(c) => format!("{city}, {c}"),
                None => city.to_string(),
            };
            let mut ae = Entity::new(EntityKind::Address, &location, 0.50, scan_id);
            ae.tag("epieos_free");
            ae.tag("skype");
            ae.tag("geoint");
            if let Some(sc) = crate::util::address_au::state_code(&location) {
                ae.tag(format!("au-state:{sc}"));
                ae.tag("country:AU");
            }
            ae.add_evidence(Evidence::new(
                SRC,
                format!("Skype location for {email}"),
            ));
            out.push(ae);
        }
    }

    // ── GitHub: Username pivot ────────────────────────────────────────────
    for login in gh_logins.iter().take(3) {
        let mut ue = Entity::new(EntityKind::Username, login, 0.72, scan_id);
        ue.tag("epieos_free");
        ue.tag("platform:github");
        ue.add_evidence(Evidence::new(
            SRC,
            format!("GitHub commit authored with {email}"),
        ));
        out.push(ue);
    }

    out
}

// ── Live fetch helpers ────────────────────────────────────────────────────────

async fn fetch_gravatar(http: &reqwest::Client, hash: &str) -> GravatarProfile {
    let url = format!("https://www.gravatar.com/{hash}.json");
    let cache_key = format!("gravatar:{hash}");

    if let Some(cached) = crate::core::api_cache::global().get(SRC, &cache_key) {
        return serde_json::from_str(&cached.body).unwrap_or_default();
    }

    let Ok(resp) = http
        .get(&url)
        .header("User-Agent", "HSE/1.4")
        .send()
        .await
    else {
        return GravatarProfile::default();
    };

    if resp.status() == 404 {
        crate::core::api_cache::global().put(
            SRC,
            &cache_key,
            "{}",
            crate::core::api_cache::ttl_secs(SRC),
        );
        return GravatarProfile::default();
    }

    let Ok(body) = resp.text().await else {
        return GravatarProfile::default();
    };

    crate::core::api_cache::global().put(
        SRC,
        &cache_key,
        &body,
        crate::core::api_cache::ttl_secs(SRC),
    );
    serde_json::from_str(&body).unwrap_or_default()
}

async fn fetch_skype(http: &reqwest::Client, email: &str) -> Vec<SkypeResult> {
    let encoded = crate::util::http::urlencode(email);
    let url = format!(
        "https://api.skype.com/search/users/any?keyWord={encoded}&contactTypes=skype&maxResults=5"
    );
    let cache_key = format!("skype_email:{email}");

    if let Some(cached) = crate::core::api_cache::global().get(SRC, &cache_key) {
        return serde_json::from_str::<Vec<SkypeResult>>(&cached.body).unwrap_or_default();
    }

    let Ok(resp) = http
        .get(&url)
        .header("User-Agent", "HSE/1.4")
        .send()
        .await
    else {
        return Vec::new();
    };

    if !resp.status().is_success() {
        return Vec::new();
    }

    let Ok(body) = resp.text().await else {
        return Vec::new();
    };

    crate::core::api_cache::global().put(
        SRC,
        &cache_key,
        &body,
        crate::core::api_cache::ttl_secs(SRC),
    );
    serde_json::from_str::<Vec<SkypeResult>>(&body).unwrap_or_default()
}

async fn fetch_github(http: &reqwest::Client, email: &str) -> Vec<String> {
    let encoded = crate::util::http::urlencode(email);
    let url = format!(
        "https://api.github.com/search/commits?q=author-email:{encoded}&per_page=10&sort=author-date"
    );
    let cache_key = format!("github_email:{email}");

    if let Some(cached) = crate::core::api_cache::global().get(SRC, &cache_key) {
        let parsed: GhCommitSearch = serde_json::from_str(&cached.body).unwrap_or_default();
        return unique_logins(parsed);
    }

    let Ok(resp) = http
        .get(&url)
        .header("User-Agent", "HSE/1.4")
        .header("Accept", "application/vnd.github.cloak-preview")
        .send()
        .await
    else {
        return Vec::new();
    };

    if !resp.status().is_success() {
        return Vec::new();
    }

    let Ok(body) = resp.text().await else {
        return Vec::new();
    };

    crate::core::api_cache::global().put(
        SRC,
        &cache_key,
        &body,
        crate::core::api_cache::ttl_secs(SRC),
    );
    let parsed: GhCommitSearch = serde_json::from_str(&body).unwrap_or_default();
    unique_logins(parsed)
}

// ── Module ────────────────────────────────────────────────────────────────────

pub struct EpieosFree;

#[async_trait]
impl Module for EpieosFree {
    fn name(&self) -> &'static str {
        "epieos_free"
    }
    fn description(&self) -> &'static str {
        "Keyless email-to-identity: Gravatar profile, Skype search, GitHub commit pivot"
    }
    fn priority(&self) -> u8 {
        91
    }
    fn cost(&self) -> ModuleCost {
        ModuleCost::Free
    }
    fn is_passive(&self) -> bool {
        false
    }
    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Email)
    }
    fn max_timeout_ms(&self) -> u64 {
        20_000
    }
    fn category(&self) -> ModuleCategory {
        ModuleCategory::People
    }
    fn attack_techniques(&self) -> &'static [&'static str] {
        // Email enumeration (T1589.002), person name recovery (T1589.003),
        // location lead via Gravatar/Skype (T1591.001).
        &["T1589.002", "T1589.003", "T1591.001"]
    }
    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[
            EntityKind::Email,
            EntityKind::Person,
            EntityKind::Username,
            EntityKind::Address,
            EntityKind::Url,
        ];
        KINDS
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let email = target.value.trim();
        if !email.contains('@') {
            return Ok(ModuleResult::new());
        }

        let hash = gravatar_hash(email);
        let http = &ctx.http;

        let (gravatar, skype, gh_logins) = join!(
            fetch_gravatar(http, &hash),
            fetch_skype(http, email),
            fetch_github(http, email),
        );

        ctx.record_response(
            SRC,
            &format!("https://www.gravatar.com/{hash}.json"),
            &format!("gravatar:{hash}"),
            &gravatar
                .entry
                .first()
                .map(|_| "hit")
                .unwrap_or("miss")
                .to_string(),
            !gravatar.entry.is_empty(),
        );

        let mut result = ModuleResult::new();
        result.extend(build_entities(
            target,
            &gravatar,
            &skype,
            &gh_logins,
            &ctx.scan_id,
        ));
        Ok(result)
    }
}
