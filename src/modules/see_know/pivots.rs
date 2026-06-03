//! Cross-platform identity-pivot primitives for the SeekNow module.
//!
//! SeekNow's unique value over the free username stack is *resolution*: given a
//! Discord snowflake or a SteamID64 surfaced in breach/profile data, it returns
//! the LINKED accounts (discord → user profile, discord → roblox, steam →
//! profile). Those links chain — a Discord ID resolves to a Roblox/Steam ID
//! which resolves further — so [`super`] drives these primitives in a bounded
//! iterative loop (`resolve_identity_pivots`) rather than a single pass.
//!
//! This module owns only the *primitives*: discovering pivot IDs already in the
//! result graph, the strict ID heuristics, and the concurrent per-ID dispatch.
//! Orchestration (the hop loop + entity extraction) lives in the parent so the
//! dependency direction stays one-way (`mod → pivots`).

use futures::future::join_all;
use serde_json::Value;

use crate::core::entity::EntityKind;
use crate::core::module::ModuleResult;
use crate::util::see_know;

/// Discord IDs (the 17–20 digit `discord:<snowflake>` strings emitted
/// by the entity extractor) pivoted through discord/user + discord/to-roblox.
pub(super) fn discover_discord_pivots(result: &ModuleResult) -> Vec<String> {
    discover_prefixed_ids(result, "discord:", looks_like_discord_id)
}

/// Steam ID64s surfaced from breach data — emitted by the entity
/// extractor as `steam:<17-digit-id>` Username entities. Pivoted
/// through gaming/steam to pull the public profile.
pub(super) fn discover_steam_pivots(result: &ModuleResult) -> Vec<String> {
    discover_prefixed_ids(result, "steam:", looks_like_steam_id)
}

/// Generalised prefix-based ID collector. Iterates extracted Username
/// entities, strips the prefix, validates the rest with `validator`,
/// and dedupes preserving first-seen order.
fn discover_prefixed_ids(
    result: &ModuleResult,
    prefix: &str,
    validator: fn(&str) -> bool,
) -> Vec<String> {
    let mut ids: Vec<String> = Vec::new();
    for e in &result.entities {
        if matches!(e.kind, EntityKind::Username)
            && let Some(rest) = e.value.strip_prefix(prefix)
            && validator(rest)
            && !ids.iter().any(|x| x == rest)
        {
            ids.push(rest.to_string());
        }
    }
    ids
}

/// Concurrent discord/user + discord/to-roblox dispatch for every
/// discovered Discord ID. Each ID consumes up to two budget slots;
/// when the budget can fit only one of the pair the `discord_user`
/// call takes priority (it's higher-yield).
///
/// User and to-roblox calls are pushed to separate per-endpoint Vecs
/// so each Vec is homogeneously typed for `join_all`; both vecs are
/// then awaited concurrently via `tokio::join!`.
pub(super) async fn dispatch_discord_pivots(
    key: &str,
    ids: Vec<String>,
) -> Vec<(&'static str, Vec<Value>)> {
    let budget = see_know::scan_budget_remaining() as usize;
    if budget == 0 || ids.is_empty() {
        return Vec::new();
    }
    let mut user_futures = Vec::new();
    let mut roblox_futures = Vec::new();
    let mut used = 0usize;
    for id in &ids {
        if used >= budget {
            break;
        }
        let id_for_user = id.clone();
        user_futures.push(async move {
            let items = see_know::discord_user(key, &id_for_user)
                .await
                .unwrap_or_default();
            ("discord_user", items)
        });
        used += 1;
        if used >= budget {
            break;
        }
        let id_for_roblox = id.clone();
        roblox_futures.push(async move {
            let items = see_know::discord_to_roblox(key, &id_for_roblox)
                .await
                .unwrap_or_default();
            ("discord_to_roblox", items)
        });
        used += 1;
    }
    let (mut user_results, roblox_results) =
        tokio::join!(join_all(user_futures), join_all(roblox_futures));
    user_results.extend(roblox_results);
    user_results
}

/// Concurrent gaming/steam dispatch for every discovered Steam ID.
/// Mirrors the discord-pivot shape so the caller can compose both.
pub(super) async fn dispatch_steam_pivots(
    key: &str,
    ids: Vec<String>,
) -> Vec<(&'static str, Vec<Value>)> {
    let budget = see_know::scan_budget_remaining() as usize;
    if budget == 0 || ids.is_empty() {
        return Vec::new();
    }
    let mut futures = Vec::new();
    for id in &ids {
        if futures.len() >= budget {
            break;
        }
        let call = {
            let id = id.clone();
            async move {
                let items = see_know::steam_profile(key, &id).await.unwrap_or_default();
                ("steam", items)
            }
        };
        futures.push(call);
    }
    join_all(futures).await
}

/// Discord snowflake heuristic — 17 to 20 decimal digits, no leading
/// zero. Strict enough to reject usernames that happen to be all
/// digits (typical 6-12 chars).
pub(super) fn looks_like_discord_id(s: &str) -> bool {
    let len = s.len();
    (17..=20).contains(&len) && s.chars().all(|c| c.is_ascii_digit()) && !s.starts_with('0')
}

/// Steam ID64 heuristic — exactly 17 decimal digits, the public
/// account universe always starts with "765611979..." (steamID64
/// base = 76561197960265728). We don't enforce that prefix here so
/// edge-case accounts still pivot, but the length + no-leading-zero
/// pair is enough to reject usernames that happen to be 16-digit
/// breach IDs.
pub(super) fn looks_like_steam_id(s: &str) -> bool {
    s.len() == 17 && s.chars().all(|c| c.is_ascii_digit()) && !s.starts_with('0')
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::entity::Entity;

    #[test]
    fn looks_like_discord_id_strict_heuristic() {
        // 17–20 digits, no leading zero.
        assert!(looks_like_discord_id("12345678901234567"));
        assert!(looks_like_discord_id("12345678901234567890"));
        // Too short, too long, leading-zero, non-digit — all reject.
        assert!(!looks_like_discord_id("1234567890123456")); // 16 digits
        assert!(!looks_like_discord_id("123456789012345678901")); // 21 digits
        assert!(!looks_like_discord_id("0123456789012345678")); // leading zero
        assert!(!looks_like_discord_id("alice1234567890"));
        assert!(!looks_like_discord_id(""));
    }

    #[test]
    fn discover_discord_pivots_extracts_unique_ids() {
        let mut r = ModuleResult::new();
        r.push(Entity::new(
            EntityKind::Username,
            "discord:359023095012345678",
            0.6,
            "test",
        ));
        // Duplicate ID — must be deduplicated.
        r.push(Entity::new(
            EntityKind::Username,
            "discord:359023095012345678",
            0.6,
            "test",
        ));
        // Non-Discord username — must be skipped.
        r.push(Entity::new(EntityKind::Username, "alice", 0.7, "test"));
        // Non-Username entity with `discord:` prefix — must be skipped.
        r.push(Entity::new(
            EntityKind::Email,
            "discord:foo@bar",
            0.5,
            "test",
        ));
        let ids = discover_discord_pivots(&r);
        assert_eq!(ids, vec!["359023095012345678".to_string()]);
    }

    #[test]
    fn looks_like_steam_id_strict_heuristic() {
        // Exactly 17 digits, no leading zero.
        assert!(looks_like_steam_id("76561198000000000"));
        assert!(looks_like_steam_id("76561198123456789"));
        // 16 / 18 digits, leading-zero, non-digit — all reject.
        assert!(!looks_like_steam_id("7656119800000000")); // 16
        assert!(!looks_like_steam_id("765611980000000000")); // 18
        assert!(!looks_like_steam_id("07561198000000000")); // leading zero
        assert!(!looks_like_steam_id("765611x8000000000"));
        assert!(!looks_like_steam_id(""));
    }

    #[test]
    fn discover_steam_pivots_extracts_unique_ids() {
        let mut r = ModuleResult::new();
        r.push(Entity::new(
            EntityKind::Username,
            "steam:76561198000000000",
            0.6,
            "test",
        ));
        r.push(Entity::new(
            EntityKind::Username,
            "steam:76561198000000000",
            0.6,
            "test",
        ));
        // Mixed-in discord entity — must be ignored by the steam
        // pivot collector.
        r.push(Entity::new(
            EntityKind::Username,
            "discord:359023095012345678",
            0.6,
            "test",
        ));
        let ids = discover_steam_pivots(&r);
        assert_eq!(ids, vec!["76561198000000000".to_string()]);
    }
}
