//! Libravatar avatar-presence check — free, keyless email → public avatar.
//!
//! Endpoint: `GET https://seccdn.libravatar.org/avatar/<md5>?d=404`. Libravatar
//! is the open-source, federated alternative to Gravatar. With the documented
//! `d=404` default, the central secure CDN answers `200` (the image) when the
//! address has a published avatar and `404` when it does not — a clean presence
//! signal that needs no API key.
//!
//! Hash contract: Libravatar uses the **identical** avatar identifier as
//! Gravatar — the MD5 of the trimmed, ASCII-lowercased address (a deliberate
//! Gravatar-compatibility choice). So this module reuses the single-sourced
//! [`crate::util::gravatar::hash`] rather than minting a second MD5-of-email
//! authority.
//!
//! Why it sits beside `gravatar`: it queries a **different corpus** — people who
//! publish a Libravatar (often self-hosters and privacy-conscious users who
//! avoid Gravatar) — exactly the independent-free-corpus pattern this codebase
//! already uses for `beacondb` beside `mylnikov`. A hit yields the avatar image
//! URL as a durable `Url` lead and a "this address has a public web presence"
//! corroboration.
//!
//! Scope (honest, not over-claimed): only the central federation CDN is probed.
//! A domain running its **own** federated Libravatar server (advertised via a
//! `_avatars-sec._tcp` DNS SRV record) is not resolved here, so a `404` means
//! "no avatar at the central CDN", not a proof of universal absence. The module
//! never reports absence as a finding — only a present avatar is emitted.

use async_trait::async_trait;

use crate::core::{
    confidence,
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::gravatar::hash as avatar_hash;
use crate::util::http::{RequestBuilderExt, ok_or_absent};

/// Stable evidence-source string.
pub(crate) const SRC: &str = "libravatar";

/// Central federated Libravatar CDN (HTTPS). The `<md5>` avatar path is appended.
const BASE: &str = "https://seccdn.libravatar.org/avatar/";

/// Libravatar avatar-presence module (email → public federated avatar URL,
/// keyless).
pub struct Libravatar;

#[async_trait]
impl Module for Libravatar {
    fn name(&self) -> &'static str {
        SRC
    }

    fn description(&self) -> &'static str {
        "Libravatar presence — keyless check for an email's public federated avatar (open-source Gravatar alternative)"
    }

    fn priority(&self) -> u8 {
        // Enrichment tier, beside `gravatar`: enrich a discovered email, no
        // paid-quota pressure.
        90
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Email)
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::People
    }

    fn max_timeout_ms(&self) -> u64 {
        // One small presence GET (body never read); budget above the 3s default
        // for slow mobile networks.
        10_000
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[EntityKind::Url];
        KINDS
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let email = target.value.trim();
        if !email.contains('@') {
            return Ok(ModuleResult::new());
        }
        let hash = avatar_hash(email);
        // `d=404` makes a missing avatar a clean 404 instead of the default
        // butterfly placeholder. The body is never read — presence is decided
        // by the status line alone.
        let probe = format!("{BASE}{hash}?d=404&s=80");
        let resp = ctx.http.get(&probe).send_tagged(SRC).await?;
        // 404 → no avatar (clean empty); any other non-2xx → real ModuleError.
        let Some(resp) = ok_or_absent(SRC, resp, &[404]).await? else {
            return Ok(ModuleResult::new());
        };
        // A 200 is a presence only if what came back is actually an IMAGE.
        // The status line alone cannot tell an avatar from an anti-bot
        // interstitial, a CDN error page or a consent wall — all of which are
        // served 200 with an HTML body — and this module's finding is a claim
        // about a PERSON (`public-profile`, "this address has a public web
        // presence"), so a wall minted one from nothing. (REQ-LIBRAVATAR-001;
        // same class as REQ-PROBE-004, where a Radware captcha 200 became a
        // verified social profile.)
        //
        // The check is on the CONTENT-TYPE HEADER, not the body: it costs one
        // header lookup and no read, so the module keeps the cheapness that
        // made reading the body undesirable in the first place. It is not a
        // proof the bytes decode as an image — a wall that lies about its
        // content type still passes — but it removes every honest
        // misclassification, which is what was actually happening.
        let content_type = resp
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if !is_image_content_type(content_type) {
            tracing::debug!(
                module = SRC,
                content_type,
                "200 from the avatar CDN is not an image — not a presence"
            );
            return Ok(ModuleResult::new());
        }
        Ok(build_avatar_result(&hash, &ctx.scan_id))
    }
}

/// True when a `Content-Type` header value declares an image.
///
/// Compares only the media type, discarding any parameters (`image/png;
/// charset=binary`) and matching case-insensitively, as RFC 9110 requires.
///
/// **Fails closed on an absent or unreadable header**: a real CDN image
/// response always declares its type, so a 200 that does not is not evidence
/// of an avatar. `""` (the `unwrap_or` for a missing header) therefore returns
/// false. **Pure**, so the classification is unit-tested without a live server
/// — the same discipline [`build_avatar_result`] follows.
fn is_image_content_type(value: &str) -> bool {
    value
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase()
        .starts_with("image/")
}

/// Emit the avatar `Url` for a confirmed-present Libravatar. Pure of I/O so it
/// is unit-tested without a live server; `process` stays a thin network adapter.
fn build_avatar_result(hash: &str, scan_id: &str) -> ModuleResult {
    let mut result = ModuleResult::new();
    // The stable, image-serving URL (no `d=404`, so it returns the avatar).
    let avatar_url = format!("{BASE}{hash}");
    let mut e = Entity::new(
        EntityKind::Url,
        &avatar_url,
        confidence::MEDIUM_PLUS,
        scan_id,
    );
    e.tag(SRC);
    e.tag("avatar");
    e.tag("public-profile");
    e.add_evidence(
        Evidence::new(SRC, "Libravatar federated avatar (present)").with_attr("avatar_hash", hash),
    );
    result.push(e);
    result
}

#[cfg(test)]
mod tests;
