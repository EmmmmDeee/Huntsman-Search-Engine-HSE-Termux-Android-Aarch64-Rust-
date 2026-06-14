//! Pure-function helpers that don't fit extract.rs: seed pre-flight, message
//! mining, and the identity-pivot resolution loop.

use std::collections::HashSet;

use serde_json::Value;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    module::ModuleResult,
    scan::TargetKind,
};
use crate::util::extract::EMAIL_RE;
use crate::util::preflight::{is_local_domain, is_placeholder_username, is_private_ip};
use crate::util::see_know;
use crate::util::see_know::val_str;

use super::extract::{extract_entities, extract_geo_entities};
use super::pivots::{
    discover_discord_pivots, discover_steam_pivots, dispatch_discord_pivots, dispatch_steam_pivots,
};
use super::{MESSAGE_MENTION_RE, MAX_PIVOT_HOPS, SRC};

/// True if a seed is junk that should never reach a SeekNow HTTP call — local
/// domains, too-short / all-digit / placeholder usernames, under-length phones
/// and names, private IPs, and any unsupported target kind. Pure function of
/// `(kind, value)` so the skip policy is testable in isolation.
pub(super) fn should_skip_seed(kind: TargetKind, v: &str) -> bool {
    match kind {
        TargetKind::Email => v
            .split_once('@')
            .is_some_and(|(_, host)| is_local_domain(host)),
        TargetKind::Username => {
            v.len() < 4 || v.chars().all(|c| c.is_ascii_digit()) || is_placeholder_username(v)
        }
        TargetKind::Phone => v.chars().filter(|c| c.is_ascii_digit()).count() < 6,
        TargetKind::FullName => !v.contains(' ') || v.len() < 5,
        TargetKind::IpAddress => is_private_ip(v),
        TargetKind::Domain => is_local_domain(v),
        _ => true,
    }
}

/// Mine a `discord_messages` item's free-text `content` for embedded emails
/// and emit each as a low-confidence `Email` entity (0.30 — below pivot floor).
pub(super) fn extract_message_emails(
    item: &Value,
    scan_id: &str,
    seen: &mut HashSet<String>,
    result: &mut ModuleResult,
) {
    let Some(content) = val_str(item, "content") else {
        return;
    };
    let ev = Evidence::new(SRC, "SeekNow discord_messages content")
        .with_attr("source", "discord_messages");
    for m in EMAIL_RE.find_iter(&content) {
        let email = m.as_str().to_lowercase();
        if seen.insert(email.clone()) {
            let mut e = Entity::new(EntityKind::Email, &email, 0.30, scan_id);
            e.tag("see-know");
            e.tag("discord-message");
            e.tag("weak-lead");
            e.add_evidence(ev.clone());
            result.push(e);
        }
    }
}

/// Mine a `discord_messages` item's free-text `content` for `<@id>` / `<@!id>`
/// Discord user-mention snowflakes and emit each as a low-confidence `Username`
/// entity (`discord:<id>`, 0.30 — below pivot floor).
pub(super) fn extract_message_mentions(
    item: &Value,
    scan_id: &str,
    seen: &mut HashSet<String>,
    result: &mut ModuleResult,
) {
    let Some(content) = val_str(item, "content") else {
        return;
    };
    let ev = Evidence::new(SRC, "SeekNow discord_messages content")
        .with_attr("source", "discord_messages");
    for caps in MESSAGE_MENTION_RE.captures_iter(&content) {
        let id = &caps[1];
        if seen.insert(format!("@discord:{id}")) {
            let mut e =
                Entity::new(EntityKind::Username, format!("discord:{id}"), 0.30, scan_id);
            e.tag("see-know");
            e.tag("discord-message");
            e.tag("weak-lead");
            e.tag("mention");
            e.add_evidence(ev.clone());
            result.push(e);
        }
    }
}

/// Iteratively resolve cross-platform identity pivots — SeekNow's unique value.
///
/// Each hop scans the accumulated `result` for Discord/Steam IDs not yet
/// resolved, dispatches the unresolved ones concurrently, folds the responses
/// (entities + geo) back into the graph, and repeats. It stops when no new IDs
/// appear, a hop yields no new entities, the per-scan budget is spent, or
/// [`MAX_PIVOT_HOPS`] is reached — so it always halts.
pub(super) async fn resolve_identity_pivots(
    key: &str,
    key_fp: &str,
    seed_value: &str,
    scan_id: &str,
    seen: &mut HashSet<String>,
    result: &mut ModuleResult,
) {
    let mut resolved: HashSet<String> = HashSet::new();
    for _hop in 0..MAX_PIVOT_HOPS {
        if !see_know::budget_remaining() {
            break;
        }
        let discord: Vec<String> = discover_discord_pivots(result)
            .into_iter()
            .filter(|id| resolved.insert(format!("d:{id}")))
            .collect();
        let steam: Vec<String> = discover_steam_pivots(result)
            .into_iter()
            .filter(|id| resolved.insert(format!("s:{id}")))
            .collect();
        if discord.is_empty() && steam.is_empty() {
            break;
        }

        let mut pivot_results: Vec<(&'static str, Vec<Value>)> = Vec::new();
        if !discord.is_empty() {
            pivot_results.extend(dispatch_discord_pivots(key, discord).await);
        }
        if !steam.is_empty() && see_know::budget_remaining() {
            pivot_results.extend(dispatch_steam_pivots(key, steam).await);
        }

        let before = result.entities.len();
        for (endpoint, items) in &pivot_results {
            for item in items {
                extract_entities(item, seed_value, scan_id, endpoint, key_fp, seen, result);
                extract_geo_entities(item, endpoint, scan_id, seen, result);
                if *endpoint == "discord_messages" {
                    extract_message_emails(item, scan_id, seen, result);
                    extract_message_mentions(item, scan_id, seen, result);
                }
            }
        }
        if result.entities.len() == before {
            break;
        }
    }
}
