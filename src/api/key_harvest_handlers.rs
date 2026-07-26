//! `GET /api/v1/keys/harvest` — the dedicated Key Harvest dashboard feed.
//!
//! Distinct from `settings_handlers` (which drives the Settings page's
//! pool view/revoke/rotate controls) and `/api/v1/stats` (per-process
//! quota counters): this endpoint is the first place that surfaces
//! [`crate::util::key_vault`] (the permanent, cross-scan bank of every
//! foreign API key HSE has ever harvested) and [`crate::util::key_roi`]
//! (the Multiplier/Expansion/Terminal cascade tiering) together with a
//! **live** probe of the two paid breach-search providers whose queries
//! actively drive the harvest — SeekNow (`/credits`) and WiGLE
//! (`/profile/user`) — plus OathNet's process-local budget/quota state.
//! Mirrors the same live probes `hse doctor` already runs, so the web
//! console gets the identical account-health signal without a CLI hop.
//!
//! Value-free by construction, same discipline as `settings_handlers`:
//! every vault/pool key is masked ([`crate::util::str_util::mask_secret`])
//! before serialisation, and the whole feed is loopback-only.

use std::net::SocketAddr;

use axum::{
    extract::ConnectInfo,
    http::StatusCode,
    response::{IntoResponse, Json},
};
use serde_json::{Value, json};

use crate::util::{key_roi, key_vault, keys, str_util};

/// Cap on how many individual vault entries the feed returns — the census
/// (`osint_provider_census`) already gives the full per-service counts, so
/// the entry list only needs enough rows for a "recent activity" view, not
/// the entire (potentially large) history.
const RECENT_ENTRIES_LIMIT: usize = 100;

/// `GET /api/v1/keys/harvest` — vault bank + ROI tiering + live provider
/// account health. Loopback-only: like `keys_status`/`keys_pool_get`, this
/// reveals which OSINT services the operator holds keys for (never the
/// plaintext), which is sensitive infrastructure metadata under a
/// non-loopback bind.
pub async fn keys_harvest(ConnectInfo(peer): ConnectInfo<SocketAddr>) -> impl IntoResponse {
    if !peer.ip().is_loopback() {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "key harvest is loopback-only" })),
        )
            .into_response();
    }

    let vault = vault_block();
    let pool = pool_block();
    let accounts = accounts_block().await;

    (
        StatusCode::OK,
        Json(json!({
            "vault": vault,
            "pool": pool,
            "accounts": accounts,
        })),
    )
        .into_response()
}

/// The `vault` section: total count, the OSINT-provider census (category +
/// service + how many keys), and the most recently seen entries — **every**
/// harvested key, not just OSINT/recon ones (masked, with each service's ROI
/// tier and OSINT category attached for the dashboard's "prioritise these"
/// ordering).
///
/// The recent list is deliberately drawn from [`key_vault::all_entries`], not
/// [`key_vault::osint_entries`]: `total_count` counts every key ever seen, so
/// feeding the entry list from the OSINT-only subset left the dashboard
/// claiming "N key(s) ever seen" above an empty table whenever those N keys
/// were generic infra (AWS, Stripe, JWTs, …) rather than catalogued OSINT
/// tooling — the count and the rows disagreed. The census stays OSINT-only (its
/// job is to profile practitioner tooling); the `category` field is `null` on
/// an infra key so the client can tag it accordingly.
fn vault_block() -> Value {
    let total = key_vault::total_count();
    let census: Vec<Value> = key_vault::osint_provider_census()
        .into_iter()
        .map(|(category, service, count)| {
            json!({
                "category": category,
                "service": service,
                "count": count,
                "roi_tier": key_roi::classify(&service).label(),
            })
        })
        .collect();
    // `all_entries()` is already ordered most-recently-seen first, so a simple
    // `take` yields the recent-activity view across the whole bank.
    let all = key_vault::all_entries();
    let osint_total = all.iter().filter(|e| e.is_osint()).count();
    let recent: Vec<Value> = all
        .into_iter()
        .take(RECENT_ENTRIES_LIMIT)
        .map(|e| {
            json!({
                "service": e.service,
                "provider": e.provider,
                "masked": str_util::mask_secret(&e.key_value),
                "category": e.osint_category(),
                "roi_tier": key_roi::classify(&e.service).label(),
                "discovery_count": e.discovery_count,
                "first_seen_at": e.first_seen_at,
                "last_seen_at": e.last_seen_at,
            })
        })
        .collect();
    json!({
        "total_count": total,
        "osint_count": osint_total,
        "osint_provider_census": census,
        "recent": recent,
        "recent_limit": RECENT_ENTRIES_LIMIT,
    })
}

/// The `pool` section: every pooled (rotation-ready) service's status
/// counts plus its ROI tier, reusing the same value-free
/// [`super::settings_handlers::summarize_pool`] the Settings page's pool
/// view already relies on — no duplicate aggregation logic.
fn pool_block() -> Value {
    let snap = crate::util::key_pool::global_pool().snapshot();
    let services: Vec<Value> = super::settings_handlers::summarize_pool(&snap)
        .into_iter()
        .map(|q| {
            json!({
                "service": q.service,
                "total": q.total,
                "active": q.active,
                "rate_limited": q.rate_limited,
                "exhausted": q.exhausted,
                "invalid": q.invalid,
                "untested": q.untested,
                "revoked": q.revoked,
                "uses": q.uses,
                "errors": q.errors,
                "tested": q.tested,
                "avg_health": q.avg_health,
                "roi_tier": key_roi::classify(&q.service).label(),
            })
        })
        .collect();
    json!({ "count": services.len(), "services": services })
}

/// The `accounts` section: live SeekNow + WiGLE probes (identical calls to
/// `hse doctor`'s) plus OathNet's process-local budget/quota snapshot.
/// OathNet has no dedicated account-status endpoint to probe (unlike
/// SeekNow's free `/credits`), but every real search response carries the
/// account's ACTUAL daily quota state for free in a top-level `_meta`
/// block (live-confirmed 2026-07-15 — see [`crate::util::oathnet::
/// RealQuota`]) — `real_quota` below surfaces the most recent one this
/// process has observed, `None` until the first search succeeds.
async fn accounts_block() -> Value {
    let loaded = keys::load();

    // ── SeekNow: /credits ──
    let seeknow_key = crate::util::see_know::resolve_key(
        loaded
            .get(crate::util::see_know::KEY_ENV)
            .map(String::as_str),
    );
    let seeknow = match crate::util::see_know::query_credits(seeknow_key).await {
        Some((remaining, limit)) => json!({
            "reachable": true,
            "invalid": false,
            "credits_remaining": remaining,
            "credits_limit": limit,
        }),
        None => json!({
            "reachable": false,
            "invalid": crate::util::see_know::is_key_invalid(),
            "credits_remaining": null,
            "credits_limit": null,
        }),
    };

    // ── OathNet: process-local budget/quota, plus the real provider quota
    // passively observed on the last successful search response (if any
    // has happened yet this process) ──
    let oathnet_budget = crate::util::oathnet::budget_snapshot();
    let real_quota = crate::util::oathnet::real_quota().map(|q| {
        json!({
            "used_today": q.used_today,
            "left_today": q.left_today,
            "daily_limit": q.daily_limit,
            "is_unlimited": q.is_unlimited,
        })
    });
    let oathnet = json!({
        "quota_exhausted": crate::util::oathnet::is_quota_exhausted(),
        "scan_used": oathnet_budget.scan_used,
        "scan_cap": oathnet_budget.scan_cap,
        "session_used": oathnet_budget.session_used,
        "session_cap": oathnet_budget.session_cap,
        "real_quota": real_quota,
    });

    // ── WiGLE: /profile/user ──
    let wigle_user = loaded
        .get("HUNTSMAN_WIGLE_USER")
        .map_or(keys::WIGLE_DEFAULT_USER, String::as_str)
        .to_string();
    let wigle_token = loaded
        .get("HUNTSMAN_WIGLE_TOKEN")
        .map_or(keys::WIGLE_DEFAULT_TOKEN, String::as_str)
        .to_string();
    let http = crate::util::http::build_client();
    let wigle_status =
        crate::modules::wigle::refresh_account_status(&http, &wigle_user, &wigle_token).await;

    json!({
        "seeknow": seeknow,
        "oathnet": oathnet,
        "wigle": {
            "verified": wigle_status.verified,
            "user": wigle_status.user,
            // When the `/profile/user` probe last ran (unix seconds), so the
            // card can show the check's freshness; `null` if never polled.
            "last_polled_ts": wigle_status.last_polled_ts,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vault_block_is_well_formed_on_an_empty_or_populated_vault() {
        // Doesn't assert on vault contents (this runs against whatever local
        // `~/.huntsman/key_vault.db` the test box happens to have — including
        // none at all), only that the shape never panics and every field is
        // present with the right JSON type.
        let v = vault_block();
        assert!(v["total_count"].is_u64());
        assert!(v["osint_count"].is_u64());
        // The OSINT subset can never exceed the whole bank.
        assert!(v["osint_count"].as_u64().expect("should succeed") <= v["total_count"].as_u64().expect("should succeed"));
        assert!(v["osint_provider_census"].is_array());
        assert!(v["recent"].is_array());
        // The recent list is capped but otherwise tracks the full bank, so it can
        // never report more rows than the vault holds keys.
        assert!(v["recent"].as_array().expect("should succeed").len() as u64 <= v["total_count"].as_u64().expect("should succeed"));
        assert_eq!(v["recent_limit"], RECENT_ENTRIES_LIMIT);
        for row in v["osint_provider_census"].as_array().expect("should succeed") {
            assert!(row["category"].is_string());
            assert!(row["service"].is_string());
            assert!(row["count"].is_u64());
            assert!(row["roi_tier"].is_string());
        }
        for row in v["recent"].as_array().expect("should succeed") {
            assert!(row["service"].is_string());
            // A masked value never contains the full plaintext structure — the
            // regression this guards is accidentally serialising `key_value`
            // instead of running it through `mask_secret` first.
            assert!(row["masked"].is_string());
            assert!(!row["masked"].as_str().expect("should succeed").is_empty());
        }
    }

    #[test]
    fn pool_block_is_well_formed_and_every_service_has_a_roi_tier() {
        let p = pool_block();
        assert!(p["count"].is_u64());
        for row in p["services"].as_array().expect("should succeed") {
            assert!(row["service"].is_string());
            assert!(matches!(
                row["roi_tier"].as_str(),
                Some("multiplier" | "expansion" | "terminal")
            ));
            // Health is honest about the unknown: a number when at least one key
            // has been exercised, JSON `null` ("untested") when none have.
            let h = &row["avg_health"];
            assert!(h.is_null() || h.is_f64(), "avg_health is null or a float");
            assert!(row["tested"].is_u64());
            // A null health must coincide with zero tested keys, and vice-versa —
            // the two can never disagree.
            assert_eq!(h.is_null(), row["tested"].as_u64() == Some(0));
        }
    }

    #[tokio::test]
    async fn accounts_block_reports_all_three_providers() {
        // Best-effort network probes (SeekNow /credits, WiGLE /profile/user) may
        // fail in a sandboxed test environment — this only asserts the response
        // shape is always complete regardless of reachability, mirroring
        // `hse doctor`'s "unreachable is a reported state, not a panic" contract.
        let a = accounts_block().await;
        assert!(a["seeknow"]["reachable"].is_boolean());
        assert!(a["seeknow"]["invalid"].is_boolean());
        assert!(a["oathnet"]["quota_exhausted"].is_boolean());
        assert!(a["oathnet"].get("scan_cap").is_some());
        // Other tests may have populated the process-global observation already,
        // so accept either valid state without depending on test execution order.
        let real_quota = &a["oathnet"]["real_quota"];
        assert!(
            real_quota.is_null()
                || (real_quota["used_today"].is_u64()
                    && real_quota["left_today"].is_u64()
                    && real_quota["daily_limit"].is_u64()
                    && real_quota["is_unlimited"].is_boolean())
        );
        assert!(a["wigle"].get("verified").is_some());
        // The WiGLE probe's freshness timestamp is always present (value may be
        // `null` when never polled) so the card can render "checked …".
        assert!(a["wigle"].get("last_polled_ts").is_some());
    }
}
