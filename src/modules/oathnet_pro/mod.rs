//! OathNet Pro — full-spectrum breach, stealer, OSINT, and intelligence API.
//!
//! Uses the shared `util::oathnet` client for API calls. This module
//! orchestrates the search→extract→enrich pipeline and produces entities.

use std::collections::HashSet;

use async_trait::async_trait;
use serde_json::Value;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
    tags,
};
use crate::util::oathnet::{self, paths, val_str, val_str_coerce, val_str_or, val_str_or_coerce};
// The target-identity matcher is shared with see_know via `util::target_match`
// (one definition for both breach pools); reached by bare name in `breach.rs`
// through its `use super::*`. The non-match demotion itself is
// `Entity::demote_to_candidate` (core) — matching stays orthogonal to tiering.
use crate::util::target_match::TargetMatch;

mod validate;
use validate::*;
mod stealer;
use stealer::*;
mod breach;
use breach::*;

/// Re-export the budget reset so `core/engine.rs` can call it without
/// importing `util::oathnet` directly (which violates the architecture rule).
pub fn reset_budget() {
    crate::util::oathnet::reset_budget();
}
use crate::util::key_harvest::{extract_api_keys_from_item, store_api_credential};

const SRC: &str = "oathnet_pro";

/// Maximum number of NON-matching (candidate) breach rows extracted into
/// entities per page. A broad search — above all a `full_name` — routinely
/// returns a whole page of strangers (the "Ali Kareem" scan got 100
/// pureincubation.com rows, none of them Ali), and each stranger row mints
/// several quarantined `candidate` entities (~5 per row), so an unbounded page
/// floods a memory-constrained device with hundreds of low-value entities.
/// Target-matching rows are always extracted in full; non-matching rows are
/// only SAMPLED up to this bound, so a genuine-but-unmatchable lead still
/// survives without the flood. Sized to keep a useful spot-check sample while
/// cutting the worst-case candidate count by ~5×.
const MAX_CANDIDATE_ROWS: usize = 20;

pub struct OathnetPro;

#[async_trait]
impl Module for OathnetPro {
    fn name(&self) -> &'static str {
        "oathnet_pro"
    }

    fn description(&self) -> &'static str {
        "Full-spectrum breach, stealer & OSINT intelligence via OathNet API"
    }

    fn priority(&self) -> u8 {
        127
    }

    fn cost(&self) -> ModuleCost {
        ModuleCost::Paid
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(
            t.kind,
            TargetKind::Email
                | TargetKind::Username
                | TargetKind::Phone
                | TargetKind::FullName
                | TargetKind::IpAddress
                | TargetKind::Domain
        )
    }

    fn max_timeout_ms(&self) -> u64 {
        30_000
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::People
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        // oathnet_pro sits in the People category for dispatch, but functionally
        // it is a breach / stealer pool: its extractors mint leaked credentials,
        // emails, employee names, network IPs, and physical addresses. The People
        // default (T1589.003 + T1591.004 "Identify Roles") both over-claims a
        // role mapping the module never performs and under-claims the
        // credential/email/IP/location collection it actually does — so declare
        // the precise set instead (mirroring au_people, which likewise drops
        // T1591.004 where no role is identified).
        &[
            "T1589.001", // Credentials — leaked passwords / hashes
            "T1589.002", // Email Addresses
            "T1589.003", // Employee Names — Person from name fields
            "T1590.005", // IP Addresses
            "T1591.001", // Determine Physical Locations — street / city / state address
        ]
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[
            EntityKind::Email,
            EntityKind::Username,
            EntityKind::Phone,
            EntityKind::Person,
            EntityKind::IpAddress,
            EntityKind::Address,
            EntityKind::Coordinates,
            EntityKind::Url,
            EntityKind::Domain,
            EntityKind::Credential,
            EntityKind::Password,
            EntityKind::Organisation,
            // Harvested from leaked records by the shared key_harvest emit path
            // (extract_api_keys_from_item) — emitted all along but undeclared.
            EntityKind::ApiKey,
            EntityKind::CryptoAddress,
        ];
        KINDS
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let key = oathnet::resolve_key(ctx.key_opt(oathnet::KEY_ENV));
        // Origin fingerprint of the exact key in use — stamped on every entity so
        // each finding declares which API key (and provider) returned it.
        let key_fp = oathnet::key_fingerprint(key);

        let mut result = ModuleResult::new();
        let mut seen: HashSet<String> = HashSet::new();
        seen.insert(target.value.to_lowercase());

        let v = target.value.trim();
        // The selector field is the single-sourced kind→field mapping shared
        // with the `oathnet_batch` generator; `None` means OathNet doesn't
        // index this kind, so there is nothing to query.
        let Some(field) = oathnet::selector_field(target.kind) else {
            return Ok(result);
        };
        // Pre-flight skips for inputs that empirically waste OathNet lookups.
        // Catching these BEFORE the cache + budget check means a junk input
        // never burns a query nor pollutes the cache.
        if should_skip_preflight(target.kind, v) {
            return Ok(result);
        }

        // Initialise a search session so breach + stealer queries on the
        // same target consume only ONE OathNet lookup instead of two.
        // Non-fatal: if init fails, queries still work at higher quota cost.
        let _ = oathnet::init_session(key, &target.value).await;

        // ── Query 1: Breach search ──────────────────────────────────────
        // Highest value endpoint: single query returns emails, usernames,
        // phones, names, IPs, addresses, passwords, geo, DOB, social
        // handles. The API charges per QUERY not per record — larger
        // page_size is free ROI, and `oathnet::search` now pages through
        // `has_more`/`next_cursor` on top of this anyway, so the actual
        // ceiling is the documented per-request maximum, not a smaller
        // hand-picked value (`docs/OATHNET_API_GUIDE.txt` §11: Breach
        // Search max 1000). The prior 100/50 split under-fetched by 10-20x
        // for a cost the API's own docs describe as free. `extract_breach_page`'s
        // existing candidate-flood cap already bounds how much of a larger
        // page becomes low-value `candidate` noise for non-matching rows,
        // so raising this doesn't reintroduce the flood problem the 50
        // value was chosen to avoid — it only means more of the real
        // result set (especially matching rows, kept in full) is seen at
        // all. Uniform across target kinds now that the ceiling is the
        // API's own documented maximum rather than a per-kind guess.
        const BREACH_PAGE_SIZE: u32 = 1000;
        let page_size: u32 = BREACH_PAGE_SIZE;
        let items = oathnet::search(key, paths::BREACH, field, &target.value, page_size).await?;
        if items.is_empty() {
            return Ok(result);
        }

        // Classify every row against the target identity ONCE. This single pass
        // drives all three downstream decisions — the honest parent dossier
        // entity, the per-row `candidate` quarantine, and the candidate-flood
        // cap — so the match is never recomputed.
        let match_ctx = TargetMatch::new(&target.value);
        let row_matches: Vec<bool> = items.iter().map(|i| match_ctx.matches(i)).collect();

        // Parent dossier entity — emitted ONLY when the subject actually appears
        // in the records. The engine pre-seeds a subject anchor, so a broad
        // `full_name` search that returns a page of strangers used to merge a
        // false 0.85 `breach` hit — plus an aggregate dump of 100 strangers'
        // names/countries — straight onto that anchor. `breach_parent_entity`
        // returns `None` on a zero-match page and aggregates the subject's
        // attributes over the MATCHING rows only.
        let matching: Vec<Value> = items
            .iter()
            .zip(row_matches.iter().copied())
            .filter(|(_, keep)| *keep)
            .map(|(i, _)| i.clone())
            .collect();
        if let Some(parent) = breach_parent_entity(target, &ctx.scan_id, &matching, items.len()) {
            result.push(parent);
        }

        // Extract every breach row into entities, applying the candidate-flood
        // cap (see `extract_breach_page`): target-matching rows are kept in full
        // while non-matching strangers are only sampled, so a broad name search
        // can't drown a memory-constrained device in low-value `candidate`
        // noise. API-key harvesting runs unconditionally for every row inside
        // the page pass.
        extract_breach_page(
            &items,
            &row_matches,
            &ctx.scan_id,
            &key_fp,
            &mut seen,
            &mut result,
        );

        // ── Query 2: Stealer search (Email/Username only) ───────────────
        // Stealer logs are indexed by login credentials (username/email +
        // password + URL). Only Email and Username targets have a direct
        // index match. Phone/FullName use free-text "q" which is noisy and
        // rarely productive. IP/Domain are already breach-only above.
        // 100 is already the documented per-request ceiling for this
        // endpoint (`docs/OATHNET_API_GUIDE.txt` §11: V2 Stealer max 100,
        // unlike Breach Search's 1000) — `oathnet::search`'s own cursor
        // pagination now carries past that ceiling if the server reports
        // more results than one page holds.
        if oathnet::stealer_indexable(field)
            && !ctx.cancel.is_cancelled()
            && let Ok(stealer_items) =
                oathnet::search(key, paths::STEALER, field, &target.value, 100).await
        {
            result.entities.reserve(stealer_items.len());
            for item in &stealer_items {
                extract_stealer_entities(item, &ctx.scan_id, &key_fp, &mut seen, &mut result);
                store_api_credential(item, SRC);
                extract_api_keys_from_item(item, &ctx.scan_id, SRC, &mut seen, &mut result);
            }
        }

        // Holehe, Discord, GHunt, IP info, Steam, Xbox, Roblox, and
        // victims endpoints are intentionally not called. Breach is the
        // highest-yield endpoint per query; stealer adds URL-specific
        // credentials for indexed targets. Platform presence (holehe's
        // output) is discovered for free by search_engines and
        // username_search. Downstream free modules (ip_geo, dns_intel,
        // geocode, etc.) handle expansion from extracted entities.

        Ok(result)
    }
}

// Pre-flight validators (`is_private_ip`, `is_placeholder_username`,
// `is_local_domain`) live in `crate::util::preflight` — both
// oathnet_pro and see_know share the policy so a target rejected
// by one provider is rejected by the other.
use crate::util::preflight::{is_local_domain, is_placeholder_username, is_private_ip};
// Rejects a breach `full_name` that is actually the username doubled or
// slugged (see `breach.rs`'s Person-creation guard) — both oathnet_pro and
// see_know extract from the same breach-schema fields, so they share this too.
use crate::core::validation::is_username_derived_name;

/// True for inputs that empirically waste an OathNet lookup for `kind` — junk
/// the breach/stealer corpora never match: test/example-TLD emails, placeholder
/// or too-short/all-digit usernames, placeholder phones, single-word names,
/// private IPs, and social-platform / local domains. **Pure** — extracted from
/// the `process` dispatcher so the per-kind gates are testable on their own and
/// kept separate from the (now single-sourced) field naming. Kinds OathNet
/// doesn't index are skipped, though `oathnet::selector_field` already filters
/// those upstream.
fn should_skip_preflight(kind: TargetKind, v: &str) -> bool {
    match kind {
        // Emails on test/example/invalid TLDs are never in real breach corpora.
        TargetKind::Email => v
            .split_once('@')
            .is_some_and(|(_, host)| is_local_domain(host)),
        // Usernames under 4 chars, all-digits, or "anonymous"-style placeholders
        // are noise — the corpora dedupe so well that hits are vanishingly rare.
        TargetKind::Username => {
            v.len() < 4 || v.chars().all(|c| c.is_ascii_digit()) || is_placeholder_username(v)
        }
        // Phone < 6 digits or all-zeros = placeholder.
        TargetKind::Phone => {
            let digits = v.chars().filter(char::is_ascii_digit).count();
            digits < 6 || v.chars().filter(char::is_ascii_digit).all(|c| c == '0')
        }
        // Single-word "names" are noise; real full-name matches have a space.
        TargetKind::FullName => !v.contains(' ') || v.len() < 5,
        TargetKind::IpAddress => is_private_ip(v),
        TargetKind::Domain => is_social_platform(v) || is_local_domain(v),
        _ => true,
    }
}

fn is_social_platform(domain: &str) -> bool {
    const PLATFORMS: &[&str] = &[
        "peekyou.com",
        "spokeo.com",
        "nuwber.com",
        "pipl.com",
        "facebook.com",
        "instagram.com",
        "twitter.com",
        "x.com",
        "linkedin.com",
        "pinterest.com",
        "tiktok.com",
        "reddit.com",
        "github.com",
        "gitlab.com",
        "bitbucket.org",
        "youtube.com",
        "twitch.tv",
        "steamcommunity.com",
        "mastodon.social",
        "bsky.app",
        "threads.net",
        "tumblr.com",
        "snapchat.com",
        "telegram.org",
        "discord.com",
        "soundcloud.com",
        "spotify.com",
        "whatsapp.com",
        "signal.org",
        "vk.com",
        "whitepages.com",
        "whitepages.com.au",
        "locatefamily.com",
        "truecaller.com",
        "cloudflare.com",
        "google.com",
        "microsoft.com",
        "amazon.com",
        "apple.com",
    ];
    let lower = domain.to_lowercase();
    PLATFORMS
        .iter()
        .any(|p| crate::util::domains::is_or_subdomain_of(&lower, p))
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
