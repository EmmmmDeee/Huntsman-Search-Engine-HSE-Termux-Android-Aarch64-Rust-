//! Telegram public channel lookup via the keyless web preview.
//!
//! Endpoint: `GET https://t.me/s/{handle}` — Telegram's unauthenticated,
//! server-rendered preview of a public channel's recent posts, meant for
//! browsers without the app. No key, no login, no rate-limit header exposed.
//!
//! Live-verified 2026-09-30:
//!   - a real, preview-enabled channel (`t.me/s/durov`) answers 200 on the
//!     `/s/` path itself, body containing the `tgme_channel_info` marker,
//!     `<meta property="og:title|og:description|og:image">`, and
//!     `<div class="tgme_header_counter">N subscribers</div>`;
//!   - a channel that exists but has disabled the web preview (or requires
//!     the app) 302s to `https://t.me/{handle}`, a same-site "open in app"
//!     page the shared client follows (`util::http::ssrf::redirect_verdict`),
//!     with no `tgme_channel_info` marker;
//!   - a handle nobody owns 302s to `https://telegram.org/` — a *different*
//!     registrable domain, so the shared client's cross-site redirect guard
//!     stops there and hands back the 3xx itself; recognised explicitly (see
//!     `process` below) rather than reaching `ok_or_absent` as an error.
//!
//! The last two are indistinguishable from here (Telegram does not leak
//! existence through the redirect target), so both are treated identically:
//! no entity either way. Asserting "this channel does not exist" from a
//! redirect would be a false negative for the disabled-preview case; the
//! marker is the only affirmative signal this module trusts.
//!
//! The channel title is kept only as evidence on the confirmed `Username`,
//! never promoted to a standalone `Person`: unlike a developer-profile
//! module's self-reported real-name field (`profile_kit::person_from_name`'s
//! usual caller), a Telegram channel title is written by whoever administers
//! it and is routinely an organisation or brand ("BBC News", "Example
//! Channel") — no signal on this page tells such a title apart from an
//! individual's own channel (`durov` is a real example of the latter). A
//! promoted `Person` here would be a false identity pivot with nothing behind
//! it; the title stays legible in evidence without asserting it names a
//! person.
//!
//! ATT&CK: T1593.001 Search Open Websites/Domains (social platform
//! reconnaissance, the same technique `mastodon_user` declares for the same
//! shape); T1589.002 for an email surfaced in the channel description.

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
        &["T1593.001", "T1589.002"]
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[EntityKind::Username, EntityKind::Url, EntityKind::Email];
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

        // A handle nobody owns 302s to `https://telegram.org/` — a different
        // registrable domain than `t.me`, so the shared client's cross-site
        // redirect guard (`util::http::ssrf::redirect_verdict`) stops at the
        // 3xx and hands back the redirect response itself rather than
        // following it (by design: following would replay this request's
        // headers onto a site the caller never chose). Recognise exactly
        // that documented redirect as "no confirmed preview" before
        // `ok_or_absent` ever sees the status — it treats any non-2xx,
        // non-`absent` status as an error, which would otherwise turn every
        // unowned handle into a module error instead of the promised empty
        // result. Any other 3xx (an unexpected destination) stays a visible
        // error rather than being silently swallowed alongside it.
        if resp.status().is_redirection() {
            let location = resp
                .headers()
                .get(reqwest::header::LOCATION)
                .and_then(|v| v.to_str().ok());
            if redirects_to_telegram_org(location) {
                return Ok(ModuleResult::new());
            }
            return Err(crate::util::http::http_status_error(SRC, resp).await);
        }

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

    // No `Person` is minted from `title` here — see the module doc for why a
    // channel title (unlike a profile module's self-reported real name) is
    // not reliable evidence of an individual. It stays visible via the
    // `title` attribute on the Username evidence above.

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
            if is_own_channel_link(link, handle) {
                continue;
            }
            let is_telegram_pivot =
                crate::util::url_util::host_from_url(link).as_deref() == Some("t.me");
            let mut le = Entity::new(EntityKind::Url, link, confidence::MEDIUM_SOLID, scan_id);
            le.tag("telegram");
            if is_telegram_pivot {
                le.tag("telegram-pivot");
            }
            le.add_evidence(
                Evidence::new(
                    SRC,
                    if is_telegram_pivot {
                        format!(
                            "Link to another Telegram channel/group in description of '@{handle}'"
                        )
                    } else {
                        format!("Link in Telegram channel description of '@{handle}'")
                    },
                )
                .with_attr("channel_url", &channel_url),
            );
            result.push(le);
        }
    }

    crate::core::entity::dedup_merge_entities(&mut result.entities);
    result.entities
}

/// True when a redirect's `Location` header points at `https://telegram.org/`
/// (any path) — the documented destination for a handle nobody owns. `None`
/// (no header, or one that fails to parse as a URL) is never treated as a
/// match, so a malformed or absent `Location` on an otherwise-3xx response
/// still surfaces as a visible error rather than being read as "absent".
fn redirects_to_telegram_org(location: Option<&str>) -> bool {
    location
        .and_then(|l| url::Url::parse(l).ok())
        .is_some_and(|u| {
            u.host_str()
                .is_some_and(|h| h.eq_ignore_ascii_case("telegram.org"))
        })
}

/// True when `link` is this channel's own canonical `t.me/{handle}` address
/// (including its `/s/{handle}` preview form, or a link to one specific post
/// within it), the one already emitted as the canonical `Url` entity above.
///
/// Compared by host *and* first path segment, not by host alone: filtering
/// every `t.me` link out of the description (the pre-fix behaviour) also
/// discarded links to *other* Telegram channels and groups a bio mentions
/// (`t.me/partnerchannel`) — exactly the discovery pivots this scan exists to
/// surface, not noise to suppress.
fn is_own_channel_link(link: &str, handle: &str) -> bool {
    let Ok(url) = url::Url::parse(link) else {
        return false;
    };
    if !url
        .host_str()
        .is_some_and(|h| h.eq_ignore_ascii_case("t.me"))
    {
        return false;
    }
    let mut segments = url
        .path_segments()
        .into_iter()
        .flatten()
        .filter(|s| !s.is_empty());
    let first = segments.next().unwrap_or("");
    let first = if first.eq_ignore_ascii_case("s") {
        segments.next().unwrap_or("")
    } else {
        first
    };
    first.eq_ignore_ascii_case(handle)
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
