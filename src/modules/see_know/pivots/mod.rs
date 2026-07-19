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

/// Prefix of `ids` that fits within `budget` for the discord dispatcher — up
/// to two slots each (`discord_user` + `discord_to_roblox`; a trailing id
/// with only one slot left still gets its `discord_user` call, so it counts
/// as attempted). **Pure** so the exact truncation the dispatcher performs is
/// unit-tested without a live call — the caller's resolved-id bookkeeping
/// depends on this matching what [`dispatch_discord_pivots`] actually
/// dispatches, so it is the single source of truth both read.
pub(super) fn discord_attempt_slice(ids: &[String], budget: usize) -> &[String] {
    let mut used = 0usize;
    let mut n = 0usize;
    for _ in ids {
        if used >= budget {
            break;
        }
        n += 1;
        used += 1;
        if used >= budget {
            break;
        }
        used += 1;
    }
    &ids[..n]
}

/// Prefix of `ids` that fits within `budget` for the steam dispatcher — one
/// slot each. **Pure**, mirroring [`discord_attempt_slice`].
pub(super) fn steam_attempt_slice(ids: &[String], budget: usize) -> &[String] {
    let n = ids.len().min(budget);
    &ids[..n]
}

/// Concurrent discord/user + discord/to-roblox dispatch for every
/// discovered Discord ID. Each ID consumes up to two budget slots;
/// when the budget can fit only one of the pair the `discord_user`
/// call takes priority (it's higher-yield).
///
/// User and to-roblox calls are pushed to separate per-endpoint Vecs
/// so each Vec is homogeneously typed for `join_all`; both vecs are
/// then awaited concurrently via `tokio::join!`.
///
/// Returns the fetched items alongside exactly the ids that were actually
/// dispatched (per [`discord_attempt_slice`]) — a budget-truncated prefix of
/// `ids`, not all of `ids`. The caller must use this second list, not the
/// input `ids`, to decide which ids are "resolved": before this existed, the
/// caller marked every DISCOVERED id resolved regardless of whether the
/// budget actually allowed dispatching it, so an id past the budget cutoff
/// was silently blacklisted from every later hop despite never once being
/// queried.
pub(super) async fn dispatch_discord_pivots(
    key: &str,
    ids: Vec<String>,
) -> (Vec<(&'static str, Vec<Value>)>, Vec<String>) {
    let budget = see_know::scan_budget_remaining() as usize;
    if budget == 0 || ids.is_empty() {
        return (Vec::new(), Vec::new());
    }
    let attempted = discord_attempt_slice(&ids, budget).to_vec();
    let mut user_futures = Vec::new();
    let mut roblox_futures = Vec::new();
    let mut used = 0usize;
    for id in &attempted {
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
    (user_results, attempted)
}

/// Concurrent gaming/steam dispatch for every discovered Steam ID. Mirrors
/// the discord-pivot shape so the caller can compose both, including
/// returning the actually-attempted ids alongside the results — see
/// [`dispatch_discord_pivots`]'s doc for why the caller needs this.
pub(super) async fn dispatch_steam_pivots(
    key: &str,
    ids: Vec<String>,
) -> (Vec<(&'static str, Vec<Value>)>, Vec<String>) {
    let budget = see_know::scan_budget_remaining() as usize;
    if budget == 0 || ids.is_empty() {
        return (Vec::new(), Vec::new());
    }
    let attempted = steam_attempt_slice(&ids, budget).to_vec();
    let futures: Vec<_> = attempted
        .iter()
        .map(|id| {
            let id = id.clone();
            async move {
                let items = see_know::steam_profile(key, &id).await.unwrap_or_default();
                ("steam", items)
            }
        })
        .collect();
    (join_all(futures).await, attempted)
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
    include!("tests.rs");
}
