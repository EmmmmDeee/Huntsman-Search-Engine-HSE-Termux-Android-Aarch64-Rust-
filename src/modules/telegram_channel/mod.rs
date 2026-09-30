//! Telegram public channel lookup via the keyless web preview.
//!
//! Endpoint: `GET https://t.me/s/{handle}` — Telegram's unauthenticated,
//! server-rendered preview of a public channel's recent posts, meant for
//! browsers without the app. No key, no login, no rate-limit header exposed.
//!
//! Live-verified 2026-09-30 (the shared client follows redirects, guarded
//! against private-IP hops by `util::http::ssrf`):
//!   - a real, preview-enabled channel (`t.me/s/durov`) answers 200 on the
//!     `/s/` path itself, body containing the `tgme_channel_info` marker,
//!     `<meta property="og:title|og:description|og:image">`, and
//!     `<div class="tgme_header_counter">N subscribers</div>`;
//!   - a channel that exists but has disabled the web preview (or requires
//!     the app) 302s to `https://t.me/{handle}`, an "open in app" page with
//!     no `tgme_channel_info` marker;
//!   - a handle nobody owns 302s through to `https://telegram.org/`, the
//!     generic marketing page — also no marker.
//!
//! The last two are indistinguishable from here (Telegram does not leak
//! existence through the redirect target), so both are treated identically:
//! no entity either way. Asserting "this channel does not exist" from a
//! redirect would be a false negative for the disabled-preview case; the
//! marker is the only affirmative signal this module trusts.
//!
//! ATT&CK: T1593.001 Search Open Websites/Domains (social platform
//! reconnaissance, the same technique `mastodon_user` declares for the same
//! shape); T1589.003 when the channel title reads as a real person's name
//! (Telegram lets an individual's account behave like a broadcast channel —
//! `durov` is exactly this); T1589.002 for an email surfaced in the channel
//! description.

#[cfg(test)]
mod tests;

use async_trait::async_trait;

use super::profile_kit;
use crate::core::{
    confidence,
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::RequestBuilderExt;
use crate::util::str_util::is_handle;

const SRC: &str = "telegram_channel";
/// The marker present only on a rendered `/s/` preview — see the module docs
/// for the live-verified redirect behaviour this distinguishes from.
const PREVIEW_MARKER: &str = "tgme_channel_info";

pub struct TelegramChannel;

#[async_trait]
impl Module for TelegramChannel {
    fn name(&self) -> &'static str {
        SRC
    }

    fn description(&self) -> &'static str {
        "Telegram public channel recon — confirms a handle via the keyless web preview and reads its title, bio and subscriber count"
    }

    fn priority(&self) -> u8 {
        // Same tier as mastodon_user: a direct, single-round-trip platform
        // probe of the searched handle itself.
        102
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Username)
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Social
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        &["T1593.001", "T1589.002", "T1589.003"]
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[
            EntityKind::Username,
            EntityKind::Person,
            EntityKind::Url,
            EntityKind::Email,
        ];
        KINDS
    }

    fn max_timeout_ms(&self) -> u64 {
        8_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let handle = target.value.trim();
        // Telegram's own grammar is 5-32 chars, must start with a letter; the
        // shared charset gate (alnum/-/_) is a superset, which only costs an
        // occasional wasted round-trip on a handle Telegram would itself
        // reject, never a false negative.
        if !is_handle(handle, 5, 32) {
            return Ok(ModuleResult::new());
        }

        let url = format!("https://t.me/s/{handle}");
        let resp = ctx.http.get(&url).send_tagged(SRC).await?;
        let Some(resp) = crate::util::http::ok_or_absent(SRC, resp, &[404]).await? else {
            return Ok(ModuleResult::new());
        };
        let body = crate::util::http::read_text(SRC, resp).await?;
        if !body.contains(PREVIEW_MARKER) {
            // Absent or preview-disabled — see the module docs. Silence, not
            // a claim.
            return Ok(ModuleResult::new());
        }

        let mut r = ModuleResult::new();
        r.entities = build_entities(handle, &body, &ctx.scan_id);
        Ok(r)
    }
}

/// Pure HTML → entities. `body` is the `/s/{handle}` preview page, already
/// confirmed to carry [`PREVIEW_MARKER`].
fn build_entities(handle: &str, body: &str, scan_id: &str) -> Vec<Entity> {
    let mut result = ModuleResult::new();

    let title = extract_og(body, "og:title");
    let description = extract_og(body, "og:description");
    let subscriber_text = extract_subscriber_count(body);
    let channel_url = format!("https://t.me/{handle}");

    let mut ev = Evidence::new(SRC, format!("Telegram public channel '@{handle}'"))
        .with_attr("channel_url", &channel_url);
    if let Some(ref t) = title {
        ev = ev.with_attr("title", t);
    }
    if let Some(ref s) = subscriber_text {
        ev = ev.with_attr("subscribers", s);
    }
    if let Some(ref d) = description {
        ev = ev.with_attr("description", d);
    }

    let mut u = Entity::new(
        EntityKind::Username,
        handle,
        confidence::HIGH_PLUSPLUS_PLUS,
        scan_id,
    );
    u.tag("telegram");
    u.add_evidence(ev.clone());
    result.push(u);

    let mut url_e = Entity::new(EntityKind::Url, &channel_url, confidence::STRONG, scan_id);
    url_e.tag("telegram");
    url_e.add_evidence(Evidence::new(
        SRC,
        format!("Telegram channel URL for '@{handle}'"),
    ));
    result.push(url_e);

    if let Some(ref name) = title
        && let Some(mut p) = profile_kit::person_from_name(name, confidence::MEDIUM_PLUS, scan_id)
    {
        p.tag("telegram");
        p.tag("derived");
        p.add_evidence(
            Evidence::new(SRC, format!("Telegram channel title for '@{handle}'"))
                .with_attr("channel_url", &channel_url),
        );
        result.push(p);
    }

    if let Some(ref desc) = description {
        for mut e in profile_kit::bio_emails(desc, 0.68, scan_id) {
            e.tag("telegram");
            e.tag("public-profile");
            e.add_evidence(
                Evidence::new(
                    SRC,
                    format!("Email in Telegram channel description of '@{handle}'"),
                )
                .with_attr("channel_url", &channel_url),
            );
            result.push(e);
        }
        for link in crate::util::extract::urls(desc) {
            let link = link.as_str();
            if crate::util::url_util::host_from_url(link).as_deref() == Some("t.me") {
                continue;
            }
            let mut le = Entity::new(EntityKind::Url, link, confidence::MEDIUM_SOLID, scan_id);
            le.tag("telegram");
            le.add_evidence(
                Evidence::new(
                    SRC,
                    format!("Link in Telegram channel description of '@{handle}'"),
                )
                .with_attr("channel_url", &channel_url),
            );
            result.push(le);
        }
    }

    crate::core::entity::dedup_merge_entities(&mut result.entities);
    result.entities
}

/// The `content="…"` value of the first `<meta property="{prop}" …>` element,
/// entity-decoded. Tolerant of `content` preceding or following `property` —
/// real pages use both orderings (the same shape `social_location`'s
/// `extract_meta_location` already handles).
fn extract_og(html: &str, prop: &str) -> Option<String> {
    let needle = format!("property=\"{prop}\"");
    let tag_pos = html.find(&needle)?;
    let lo = html[..tag_pos].rfind('<').unwrap_or(tag_pos);
    let windowed = crate::util::str_util::char_window(html, lo, tag_pos + 2000);
    let element = windowed.split('>').next().unwrap_or(windowed);

    let pattern = "content=\"";
    let start = element.find(pattern)? + pattern.len();
    let rel_end = element[start..].find('"')?;
    let val = crate::util::html::decode_entities(element[start..start + rel_end].trim());
    (!val.is_empty()).then_some(val)
}

/// The text of `<div class="tgme_header_counter">…</div>` (e.g. `"10.6M
/// subscribers"`), verbatim — Telegram's own K/M-suffixed formatting is kept
/// as-is rather than parsed to a number, which would need locale rules this
/// module has no need to own.
fn extract_subscriber_count(html: &str) -> Option<String> {
    let needle = "tgme_header_counter\">";
    let start = html.find(needle)? + needle.len();
    let rest = &html[start..];
    let end = rest.find('<')?;
    let text = crate::util::html::decode_entities(rest[..end].trim());
    (!text.is_empty()).then_some(text)
}
