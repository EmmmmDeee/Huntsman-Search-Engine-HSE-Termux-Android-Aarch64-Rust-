//! RansomLook.io leak-site search — free, keyless ransomware/market exposure.
//!
//! Endpoint: `GET https://www.ransomlook.io/api/search?q=<seed>` (GET only; POST
//! → 405). Response: `{groups, markets, posts:[{post_title, description,
//! group_name, discovered, link}], leaks, notes}`. The exposure signal is a
//! `posts[]` entry whose `post_title` names the seed subject, with `group_name`
//! the claiming ransomware group.
//!
//! RULE.md landmine (confirmed live 2026-09): the **documented** search param
//! `query=` is drifted/broken — it returns HTTP 400 "Query must be at least 2
//! characters" for any value. Only the **undocumented** `q=` param works
//! (`q=acme` → HTTP 200 with matching `posts[]`). This module wires `q=`,
//! justified by the observed response, and never `query=` (which would make
//! every scan look clean). Only `/api/export/<n>` needs a key; the search path
//! is keyless.
//!
//! Independent SECOND ransomware corpus beside `ransomware_live`: additive
//! because RansomLook also indexes markets/forums/notes, not only
//! double-extortion victim rows — the `beacondb`-beside-`mylnikov`,
//! `leakcheck_public`-beside-`hudsonrock` pattern. It corroborates rather than
//! opening a wholly new capability.
//!
//! Precision (RULE.md, exactly as `ransomware_live`): retain ONLY posts whose
//! `post_title` names the seed — never an incidental `description` mention — so a
//! full-text hit on unrelated victims is dropped. An empty `posts[]` is a clean
//! negative; a non-2xx/outage is a real `ModuleError`. Pure discovery: it reads
//! the public index and never fetches a leak site.

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    confidence,
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::domains::is_or_subdomain_of;
use crate::util::http::{fetch_json_or_404, urlencode};

/// Stable evidence-source string.
pub(crate) const SRC: &str = "ransomlook";

/// Base for resolving a post's relative `link` into an absolute URL lead.
const BASE: &str = "https://www.ransomlook.io";

/// RansomLook `/api/search` response — only the `posts[]` bucket answers a
/// per-seed exposure query; the other buckets are ignored.
#[derive(Deserialize, Default)]
#[serde(default)]
struct SearchResp {
    posts: Vec<Post>,
}

/// One leak-site post. Every field optional so a partial record never fails the
/// whole parse into a false miss.
#[derive(Deserialize, Default)]
#[serde(default)]
struct Post {
    post_title: Option<String>,
    group_name: Option<String>,
    discovered: Option<String>,
    /// Relative (`/leaks/…`) or absolute reference to the leak-site entry.
    link: Option<String>,
}

/// RansomLook.io keyless ransomware/market leak-site search module.
pub struct RansomLook;

#[async_trait]
impl Module for RansomLook {
    fn name(&self) -> &'static str {
        SRC
    }

    fn description(&self) -> &'static str {
        "RansomLook.io leak-site search — keyless check of whether a domain or org appears on a ransomware/market leak site"
    }

    fn priority(&self) -> u8 {
        120
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Domain | TargetKind::Organisation)
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Threat
    }

    fn max_timeout_ms(&self) -> u64 {
        12_000
    }

    fn produces(&self) -> &'static [EntityKind] {
        // RansomLook posts carry no structured domain field, so — unlike
        // `ransomware_live` — this module honestly emits only the victim
        // Organisation and the durable reference Url.
        const KINDS: &[EntityKind] = &[EntityKind::Organisation, EntityKind::Url];
        KINDS
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let keyword = target.value.trim();
        // The API rejects a <2-char query; don't spend a request on one.
        if keyword.len() < 2 {
            return Ok(ModuleResult::new());
        }
        // `q=` is the working param; `query=` is documented but drifted (400).
        let url = format!("{BASE}/api/search?q={}", urlencode(keyword));
        let Some(resp): Option<SearchResp> = fetch_json_or_404(&ctx.http, SRC, &url).await? else {
            return Ok(ModuleResult::new());
        };
        Ok(build_result(&resp, target, &ctx.scan_id))
    }
}

/// How strongly a post's `post_title` names the seed — drives retain + confidence.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Match {
    /// Title equals the org name, or contains the full seed domain — unambiguous.
    Strong,
    /// Title contains the org name / domain label as a discriminating substring.
    Partial,
}

/// Decide whether a post's `post_title` genuinely names the seed subject, and
/// how strongly — never matching on the free-text `description`.
fn classify(title: &str, needle: &str, target: &Target) -> Option<Match> {
    let title = title.trim().to_ascii_lowercase();
    if title.is_empty() {
        return None;
    }
    match target.kind {
        TargetKind::Domain => {
            // `title` is free text, so the seed must be matched on domain-LABEL
            // boundaries — a raw `contains` admits `notacme.com`, `acme.company`
            // and `acme.com.au` for seed `acme.com`. Compare each domain-shaped
            // token in the title against the seed via the single-sourced
            // `util::domains` authority (both directions, so a subdomain token
            // `sub.acme.com` matches an `acme.com` seed and vice versa) — the
            // same label-safe guard `ransomware_live` uses.
            let label = needle.split('.').next().unwrap_or("");
            let tokens = || {
                title
                    .split(|c: char| !(c.is_ascii_alphanumeric() || c == '.' || c == '-'))
                    .map(|t| t.trim_matches('.'))
                    .filter(|t| !t.is_empty())
            };
            if tokens()
                .any(|tok| is_or_subdomain_of(tok, needle) || is_or_subdomain_of(needle, tok))
            {
                return Some(Match::Strong);
            }
            // Registrable-label hit: the seed's label IS a token's own
            // registrable label (whole label before its first dot), long enough
            // to discriminate — replaces the old `title.contains(label)`, which
            // matched `notacme`/`acmeworld`.
            (label.len() >= 4 && tokens().any(|tok| tok.split('.').next().unwrap_or("") == label))
                .then_some(Match::Partial)
        }
        TargetKind::Organisation => {
            if title == needle {
                return Some(Match::Strong);
            }
            (title.contains(needle) || needle.contains(&title)).then_some(Match::Partial)
        }
        _ => None,
    }
}

/// Build entities from the matching posts. Pure of I/O so it is unit-tested
/// against fixtures; `process` stays a thin network adapter.
fn build_result(resp: &SearchResp, target: &Target, scan_id: &str) -> ModuleResult {
    let mut result = ModuleResult::new();

    // Loop-invariant: the lowercased seed needle is identical for every post, so
    // derive it once and short-circuit when it is too short to discriminate
    // (identical to the former per-post `< 3` gate).
    let needle = target.value.trim().to_ascii_lowercase();
    if needle.len() < 3 {
        return result;
    }

    for post in &resp.posts {
        let Some(title) = post
            .post_title
            .as_deref()
            .map(str::trim)
            .filter(|t| !t.is_empty())
        else {
            continue;
        };
        let Some(kind) = classify(title, &needle, target) else {
            continue;
        };
        let conf = match kind {
            Match::Strong => confidence::HIGH,
            Match::Partial => confidence::MEDIUM_HIGH,
        };

        let group = post
            .group_name
            .as_deref()
            .map(str::trim)
            .filter(|g| !g.is_empty());
        let ev = Evidence::new(SRC, "RansomLook.io leak-site index")
            .with_optional_attrs([("group", group), ("discovered", post.discovered.as_deref())]);
        let group_tag = group.map(|g| format!("group:{}", g.to_lowercase()));
        // `Option<&str>::as_slice` yields a 0-or-1-element `&[&str]` with no
        // allocation — the per-record `group:` tag (if any) as extra tags.
        let group_slice = group_tag.as_deref();
        let group_extra: &[&str] = group_slice.as_slice();

        // Victim organisation (the post title).
        let org = Entity::new(EntityKind::Organisation, title, conf, scan_id);
        result.push_with_tags(org, &ev, &[SRC, "ransomware-victim"], group_extra);

        // The leak-site reference as a durable Url lead (relative links made
        // absolute against the RansomLook base).
        if let Some(link) = post
            .link
            .as_deref()
            .map(str::trim)
            .filter(|l| !l.is_empty())
        {
            let abs = if link.starts_with("http") {
                link.to_string()
            } else if link.starts_with('/') {
                format!("{BASE}{link}")
            } else {
                format!("{BASE}/{link}")
            };
            let u = Entity::new(EntityKind::Url, &abs, confidence::HIGH_PLUS, scan_id);
            result.push_with_tags(
                u,
                &ev,
                &[SRC, "ransomware-victim", "reference"],
                group_extra,
            );
        }
    }

    result
}

#[cfg(test)]
mod tests;
