//! Free, keyless Steam profile resolution via the public community XML.
//!
//! `GET https://steamcommunity.com/profiles/<steamid64>?xml=1` — and the vanity
//! form `/id/<vanity>?xml=1` — return an owner-public XML profile with **no API
//! key**. This is the free emulation of SeekNow's paid `gaming/steam` endpoint,
//! completing the gaming-platform set alongside the Roblox/Minecraft
//! [`crate::modules::gaming_profile`] module.
//!
//! The high-value signal is `<realname>` — a Steam account resolving to a real
//! name — plus the profile location and the canonical SteamID64. No mock: the
//! XML is fetched live from Steam's own community service.
//!
//! Two resolution modes:
//!   * **SteamID64** (17 digits in the public `7656119…` range) → `/profiles/…`,
//!     an exact account lookup (high confidence).
//!   * **Vanity** (an explicit `steam:` handle, or a plausibly-shaped custom
//!     URL) → `/id/…`, where the handle *might* be someone else's vanity, so the
//!     derived entities are emitted at moderate confidence for the correlator to
//!     corroborate.

use async_trait::async_trait;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::{RequestBuilderExt, UA_BROWSER, read_text, urlencode};

const SRC: &str = "steam_profile";

pub struct SteamProfile;

#[async_trait]
impl Module for SteamProfile {
    fn name(&self) -> &'static str {
        "steam_profile"
    }

    fn description(&self) -> &'static str {
        "Free Steam profile lookup (SteamID64 / vanity → real name, location) via public XML"
    }

    fn priority(&self) -> u8 {
        105
    }

    fn accepts(&self, t: &Target) -> bool {
        // Kind-only so the dispatch index stays consistent with accepts(); the
        // SteamID64 / vanity shape gate is applied in process().
        matches!(t.kind, TargetKind::Username)
    }

    fn category(&self) -> ModuleCategory {
        // Gaming presence is social-media presence; the Social-category default
        // ATT&CK technique is correct, so `attack_techniques()` derives from it.
        ModuleCategory::Social
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[
            EntityKind::Person,
            EntityKind::Username,
            EntityKind::Url,
            EntityKind::Address,
            EntityKind::Coordinates,
            EntityKind::Email,
            EntityKind::Domain,
        ];
        KINDS
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        // Social default (T1593.001 Social Media + T1589.003 Employee Names)
        // is correct for the realname/persona Person entities, but this
        // module now also mines emails out of the free-text `<summary>` bio
        // (matching `reddit_user`'s identical policy), which needs the
        // explicit T1589.002 (Email Addresses) addition.
        &["T1589.002", "T1589.003", "T1593.001"]
    }

    fn max_timeout_ms(&self) -> u64 {
        8_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let mut result = ModuleResult::new();
        let Some((url, conf)) = steam_lookup_url(target.value.trim()) else {
            return Ok(result);
        };

        let resp = ctx
            .http
            .get(&url)
            .header("User-Agent", UA_BROWSER)
            .send_tagged(SRC)
            .await?;
        if !resp.status().is_success() {
            return Ok(result);
        }
        let xml = read_text(SRC, resp).await?;
        // A missing/private profile returns `<error>…could not be found</error>`
        // or carries no `<steamID64>` — a clean miss, not an error.
        if xml.contains("<error>") || !xml.contains("<steamID64>") {
            return Ok(result);
        }

        extract_profile(&xml, conf, &ctx.scan_id, &mut result);
        Ok(result)
    }
}

/// Resolve the value to a Steam XML URL and a base confidence, or `None` if it
/// isn't a Steam identity worth querying.
fn steam_lookup_url(v: &str) -> Option<(String, f64)> {
    let (val, prefixed) = match v.strip_prefix("steam:") {
        Some(rest) => (rest.trim(), true),
        None => (v, false),
    };
    // SteamID64: exactly 17 digits in the public account range (always
    // `7656119…`). This deliberately excludes Discord snowflakes (17–20 digits,
    // other prefixes) so a Discord ID never triggers a Steam lookup.
    if val.len() == 17 && val.bytes().all(|b| b.is_ascii_digit()) && val.starts_with("7656119") {
        return Some((
            format!("https://steamcommunity.com/profiles/{val}?xml=1"),
            0.85,
        ));
    }
    // Vanity: an explicit `steam:` handle (strong context) or a plausibly-shaped
    // custom URL. A bare numeric (e.g. a phone/ID) is not a vanity.
    if prefixed || is_vanity_shaped(val) {
        let conf = if prefixed { 0.70 } else { 0.60 };
        return Some((
            format!("https://steamcommunity.com/id/{}?xml=1", urlencode(val)),
            conf,
        ));
    }
    None
}

/// A plausible Steam custom-URL (vanity): 3–32 chars, ASCII alphanumeric /
/// `_` / `-`, with at least one letter (so a bare number is rejected).
fn is_vanity_shaped(v: &str) -> bool {
    let len = v.chars().count();
    (3..=32).contains(&len)
        && v.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        && v.chars().any(|c| c.is_ascii_alphabetic())
}

/// Extract entities from the Steam profile XML. Pure (no I/O) so it is unit-
/// tested against a fixture; the network shell in `process` stays a thin adapter.
fn extract_profile(xml: &str, conf: f64, scan_id: &str, result: &mut ModuleResult) {
    let Some(id64) =
        extract_tag(xml, "steamID64").filter(|s| s.bytes().all(|b| b.is_ascii_digit()))
    else {
        return;
    };

    let ev = Evidence::new(SRC, format!("Steam profile {id64}"))
        .with_attr("steam_id64", id64.as_str())
        .with_attr("source", "steamcommunity-xml");

    // Canonical profile URL.
    let profile_url = format!("https://steamcommunity.com/profiles/{id64}");
    let mut url_e = Entity::new(EntityKind::Url, &profile_url, conf, scan_id);
    url_e.tag("steam");
    url_e.tag("gaming");
    url_e.add_evidence(ev.clone());
    result.push(url_e);

    // Real name — the high-value Steam-ID → person link.
    let realname = extract_tag(xml, "realname").filter(|n| n.len() >= 3 && n.len() <= 80);
    if let Some(realname) = realname.as_deref() {
        let mut p = Entity::new(
            EntityKind::Person,
            realname,
            (conf - 0.13).max(0.45),
            scan_id,
        );
        p.tag("steam");
        p.tag("derived");
        p.add_evidence(ev.clone().with_attr("realname", realname));
        result.push(p);
    }

    // Persona name (`<steamID>`) — the account's own chosen display name,
    // distinct from both `<realname>` and the vanity `<customURL>`. A
    // multi-word persona reads as a real name, so it is promoted to Person
    // (mirroring `realname`, at a lower confidence since a self-chosen
    // persona isn't guaranteed genuine) exactly like every sibling profile
    // module's `profile_kit::person_from_name` display-name policy; a
    // single-token persona is a handle rather than a name, so it becomes a
    // Username pivot instead. Skipped when it merely duplicates a field
    // already emitted above.
    let vanity = extract_tag(xml, "customURL").filter(|u| is_vanity_shaped(u));
    if let Some(persona) =
        extract_tag(xml, "steamID").filter(|p| realname.is_none_or(|r| !r.eq_ignore_ascii_case(p)))
    {
        if let Some(mut p) = crate::modules::profile_kit::person_from_name(
            &persona,
            (conf - 0.20).max(0.40),
            scan_id,
        ) {
            p.tag("steam");
            p.tag("persona");
            p.tag("derived");
            p.add_evidence(ev.clone().with_attr("persona_name", persona.as_str()));
            result.push(p);
        } else if vanity
            .as_deref()
            .is_none_or(|v| !v.eq_ignore_ascii_case(&persona))
        {
            let mut u = Entity::new(
                EntityKind::Username,
                &persona,
                (conf - 0.05).max(0.50),
                scan_id,
            );
            u.tag("steam");
            u.tag("persona");
            u.add_evidence(ev.clone().with_attr("persona_name", persona.as_str()));
            result.push(u);
        }
    }

    // Self-reported profile location → Address (+ inline geocode).
    if let Some(loc) = extract_tag(xml, "location").filter(|l| l.len() >= 2) {
        let mut a = Entity::new(EntityKind::Address, &loc, (conf - 0.27).max(0.42), scan_id);
        a.tag("steam");
        a.tag("geoint");
        a.tag("self-reported");
        a.add_evidence(ev.clone().with_attr("location", loc.as_str()));
        result.push(a);
        if let Some((lat, lon)) = crate::util::city_coords::city_coords(&loc) {
            let coord = format!("{lat:.4},{lon:.4}");
            let mut c = Entity::new(
                EntityKind::Coordinates,
                &coord,
                (conf - 0.33).max(0.42),
                scan_id,
            );
            c.tag("steam");
            c.tag("addr-derived");
            c.tag("geoint");
            c.add_evidence(ev.clone().with_attr("location", loc.as_str()));
            result.push(c);
        }
    }

    // Vanity custom URL → a Username pivot.
    if let Some(vanity) = vanity.as_deref() {
        let mut u = Entity::new(EntityKind::Username, vanity, conf, scan_id);
        u.tag("steam");
        u.tag("steam-vanity");
        u.add_evidence(ev.clone().with_attr("custom_url", vanity));
        result.push(u);
    }

    // Free-text bio (`<summary>`) → mined emails/URLs, matching every sibling
    // Social module's bio-scanning policy (`reddit_user`, `hacker_news`, …).
    // No cap: `util::extract::emails`/`urls` already dedupe internally.
    if let Some(bio) = extract_tag(xml, "summary") {
        for email in crate::util::extract::emails(&bio) {
            let mut e = Entity::new(EntityKind::Email, &email, (conf - 0.15).max(0.45), scan_id);
            e.tag("steam");
            e.tag("public-profile");
            e.add_evidence(ev.clone().with_attr("source_field", "summary"));
            result.push(e);
        }
        for link in crate::util::extract::urls(&bio) {
            let link = link.as_str();
            let mut url_e = Entity::new(EntityKind::Url, link, (conf - 0.20).max(0.40), scan_id);
            url_e.tag("steam");
            url_e.tag("personal-site");
            url_e.add_evidence(ev.clone().with_attr("source_field", "summary"));
            result.push(url_e);
            if let Some(host) = crate::util::url_util::host_from_url(link)
                && host.contains('.')
                && host != "steamcommunity.com"
            {
                let mut d =
                    Entity::new(EntityKind::Domain, &host, (conf - 0.25).max(0.38), scan_id);
                d.tag("steam");
                d.tag("derived");
                d.tag("personal-site");
                d.add_evidence(
                    ev.clone()
                        .with_attr("source_url", link)
                        .with_attr("source_field", "summary"),
                );
                result.push(d);
            }
        }
    }
}

/// Extract the text of the first `<tag>…</tag>`, unwrapping a CDATA section and
/// decoding the few XML entities Steam emits outside CDATA. `None` if the tag is
/// absent or empty.
fn extract_tag(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = xml.find(&open)? + open.len();
    let end = xml[start..].find(&close)? + start;
    let mut inner = xml[start..end].trim();
    if let Some(s) = inner.strip_prefix("<![CDATA[") {
        inner = s.strip_suffix("]]>").unwrap_or(s).trim();
    }
    if inner.is_empty() {
        return None;
    }
    Some(
        inner
            .replace("&amp;", "&")
            .replace("&lt;", "<")
            .replace("&gt;", ">")
            .replace("&quot;", "\"")
            .replace("&#39;", "'"),
    )
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
