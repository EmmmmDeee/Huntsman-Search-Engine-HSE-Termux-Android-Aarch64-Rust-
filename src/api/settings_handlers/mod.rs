//! HTTP handlers for keys, the key pool, and settings/toggles — the
//! configuration & secrets surface, split out of `handlers` (which keeps the
//! core read/system + SSE endpoints) the same way `scan_handlers` carries the
//! scan-data surface. Localhost-only by construction; key *values* are never
//! serialised back to the dashboard (see `summarize_pool` / `mask_secret`).

use std::collections::BTreeMap;
use std::{net::SocketAddr, sync::Arc};

use axum::{
    Json,
    extract::{ConnectInfo, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::AppState;
use super::handlers::bad_request;
use crate::secrets::keys;

/// Expose the API-key detector's prefix-match coverage. Returns the
/// full ordered table from `key_harvest::patterns` so operators can
/// see what shapes the scanner recognises — and so dashboards can
/// surface per-service coverage stats.
pub async fn keys_patterns() -> Json<Value> {
    let patterns = crate::secrets::key_harvest::pattern_catalogue();
    let by_service: std::collections::BTreeMap<&str, usize> =
        patterns
            .iter()
            .fold(std::collections::BTreeMap::new(), |mut acc, p| {
                *acc.entry(p.service).or_default() += 1;
                acc
            });
    Json(json!({
        "patterns": patterns,
        "count": patterns.len(),
        "unique_services": by_service.len(),
    }))
}

/// Per-service key-pool status summary. **Value-free by construction** — no
/// `KeyEntry.value` is ever copied here — so it is safe to surface to the
/// (localhost-only) operator dashboard.
#[derive(Debug, Default, Serialize)]
pub(crate) struct ServiceQuota {
    pub service: String,
    pub total: usize,
    pub active: usize,
    pub rate_limited: usize,
    pub exhausted: usize,
    pub invalid: usize,
    pub untested: usize,
    pub revoked: usize,
    pub uses: u64,
    pub errors: u64,
    /// Mean [`crate::secrets::key_pool::KeyEntry::health_score`] across this service's
    /// keys — the at-a-glance "how healthy is this pool" number (0.0–1.0), `0.0`
    /// for a service with no keys. The status counts above say *what* the keys
    /// are; this says how operationally healthy they are overall.
    pub avg_health: f64,
}

/// Summarise a key-pool snapshot into per-service status counts (plus the mean
/// per-key health score), dropping every key value. Does not touch the global
/// pool, so it is unit-testable; the clock is sampled once up front so every
/// score in one summary is consistent. Sorted by service.
pub(crate) fn summarize_pool(data: &crate::secrets::key_pool::PoolData) -> Vec<ServiceQuota> {
    use crate::secrets::key_pool::KeyStatus;
    let now = crate::core::entity::unix_now();
    let mut out: Vec<ServiceQuota> = data
        .services
        .iter()
        .map(|(service, entries)| {
            let mut q = ServiceQuota {
                service: service.clone(),
                total: entries.len(),
                ..Default::default()
            };
            let mut health_sum = 0.0f64;
            for e in entries {
                match e.status {
                    KeyStatus::Active => q.active += 1,
                    KeyStatus::RateLimited => q.rate_limited += 1,
                    KeyStatus::Exhausted => q.exhausted += 1,
                    KeyStatus::Invalid => q.invalid += 1,
                    KeyStatus::Untested => q.untested += 1,
                    KeyStatus::Revoked => q.revoked += 1,
                }
                q.uses += e.use_count;
                q.errors += e.error_count;
                health_sum += e.health_score(now);
            }
            // Mean over all keys; 0.0 for an empty service (avoids 0/0).
            q.avg_health = if entries.is_empty() {
                0.0
            } else {
                health_sum / entries.len() as f64
            };
            q
        })
        .collect();
    out.sort_by(|a, b| a.service.cmp(&b.service));
    out
}

/// `GET /api/v1/keys/health` — CONFIGURED keys the upstream is actively
/// rejecting, derived from what real scans observed (auth-shaped failure
/// streaks), never a synthetic probe — so it can't mis-report a working key. The
/// signal that on the CLI lives in `hse doctor`, brought to the web Settings page
/// so a Termux no-root operator sees a dead key (and exactly which env var to
/// renew) without dropping to a shell. Loopback-only and value-free, matching the
/// sibling key endpoints.
pub async fn keys_health(
    State(s): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
) -> impl IntoResponse {
    if !peer.ip().is_loopback() {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "key health is loopback-only" })),
        )
            .into_response();
    }
    // Off-reactor: the recent-outcome scan is a blocking SQLite read.
    let store = Arc::clone(&s.store);
    let events = match tokio::task::spawn_blocking(move || {
        store.recent_module_outcome_events(crate::util::scraper_health::RECENT_EVENTS_WINDOW)
    })
    .await
    {
        Ok(Ok(ev)) => ev,
        Ok(Err(e)) => return super::handlers::internal_error(&e),
        Err(e) => {
            return super::handlers::internal_error(&format!("keys-health query task failed: {e}"));
        }
    };
    let health = crate::util::scraper_health::aggregate_source_health(&events);
    let loaded = keys::load();
    // Only surface keys that are actually CONFIGURED and being rejected — the
    // actionable case. An auth failure on an unset key is expected (the module
    // skips) and already covered by the acquisition guidance.
    let rejected: Vec<Value> = crate::secrets::key_health::auth_failing_sources(&health)
        .into_iter()
        .filter(|i| i.likely_env_var.is_some_and(|e| loaded.contains_key(e)))
        .map(|i| {
            json!({
                "module": i.module,
                "env_var": i.likely_env_var,
                "consecutive_failures": i.consecutive_failures,
                "detail": i.detail,
                "hint": i.likely_env_var.and_then(keys::signup_hint),
            })
        })
        .collect();
    Json(json!({ "count": rejected.len(), "rejected": rejected })).into_response()
}

/// `GET /api/v1/keys/status` — per-service key-pool health (counts by status,
/// aggregate use/error totals, and the mean per-key health score) for the
/// operator quota view. Never exposes key values, but per-service key-pool
/// inventory is still sensitive infrastructure metadata, so — exactly like the
/// sibling `keys_pool_get` — it is **loopback-only**: under an operator-chosen
/// LAN bind a non-loopback peer gets 403 rather than a map of which services
/// hold keys and how healthy they are. Reads the process-global pool.
pub async fn keys_status(ConnectInfo(peer): ConnectInfo<SocketAddr>) -> impl IntoResponse {
    if !peer.ip().is_loopback() {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "key pool status is loopback-only" })),
        )
            .into_response();
    }
    let services = summarize_pool(&crate::secrets::key_pool::global_pool().snapshot());
    Json(json!({ "count": services.len(), "services": services })).into_response()
}

/// `GET /api/v1/settings/keys` — which key services are configured (name +
/// `set` boolean per service) plus the on-disk env file path. The same class
/// of "which services hold keys" infrastructure metadata `keys_status` /
/// `keys_pool_get` / `keys_harvest` already treat as sensitive enough to
/// gate loopback-only — this is that gate's missing sibling: the PUT on this
/// SAME route already refuses a non-loopback peer, but the GET did not.
pub async fn settings_keys_get(
    State(s): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
) -> impl IntoResponse {
    if !peer.ip().is_loopback() {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "key configuration is loopback-only" })),
        )
            .into_response();
    }
    use std::path::PathBuf;
    let path = keys::env_path();
    let loaded = keys::load_from_file_only(&PathBuf::from(&path));
    let mut all_names: std::collections::BTreeSet<String> =
        keys::KNOWN_KEYS.iter().map(|s| (*s).to_string()).collect();
    for k in loaded.keys() {
        all_names.insert(k.clone());
    }
    let entries: Vec<Value> = all_names
        .into_iter()
        .map(|name| {
            let set = loaded.contains_key(&name);
            json!({ "name": name, "set": set })
        })
        .collect();
    let count = entries.len();
    // Convex acquisition guidance: unset keys ranked highest-leverage first
    // (multiplier > expansion > terminal) with a free-signup hint each — the same
    // ranking `hse doctor` prints, surfaced to the web-UI operator so the single
    // highest-value action (register the free multiplier keys) is one tap away
    // instead of CLI-only. Sourced from the one canonical `key_roi::rank_unset_keys`.
    let acquisition: Vec<Value> = crate::secrets::key_roi::rank_unset_keys(|k| loaded.contains_key(k))
        .into_iter()
        .map(|(name, roi)| {
            json!({
                "name": name,
                "tier": roi.label(),
                "hint": keys::signup_hint(name),
            })
        })
        .collect();
    Json(json!({
        "keys": entries,
        "count": count,
        "write_enabled": s.allow_key_write,
        "env_path": path,
        "acquisition": acquisition,
    }))
    .into_response()
}

/// Body for `POST /keys/pool/add` — a new key for a poolable service, with
/// the same optional `notes`/`env` labels `hse keys add` accepts.
#[derive(Deserialize)]
pub struct KeysPoolAddRequest {
    pub service: String,
    pub key: String,
    #[serde(default)]
    pub notes: Option<String>,
    #[serde(default)]
    pub env: Option<String>,
}

/// `POST /api/v1/keys/pool/add` — add a NEW key to a service's rotation pool.
/// The web Settings page's key editor (`settings/keys` PUT) already lets an
/// operator set the PRIMARY `HUNTSMAN_*_KEY` env var for any service; this is
/// the pool's own "add" (`hse keys add`), for operators who want to add a
/// second/backup key for load-balancing across quota limits — previously the
/// only way to do this was the CLI. Gated exactly like the sibling pool
/// writes (`revoke`/`rotate`): loopback-only AND requires
/// `--allow-key-write`.
pub async fn keys_pool_add(
    State(s): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Json(req): Json<KeysPoolAddRequest>,
) -> impl IntoResponse {
    if !s.allow_key_write {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({
                "error": "key writes disabled; restart with `hse serve --allow-key-write`"
            })),
        )
            .into_response();
    }
    if !peer.ip().is_loopback() {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "key writes are loopback-only" })),
        )
            .into_response();
    }
    let service = req.service.trim();
    let key = req.key.trim();
    if service.is_empty() || key.is_empty() {
        return bad_request("service and key are required");
    }
    if !crate::secrets::service_defs::is_poolable_service(service) {
        let names: Vec<&str> = crate::secrets::key_pool::service_defs()
            .iter()
            .map(|d| d.name)
            .collect();
        return bad_request(format!(
            "'{service}' is not a poolable service — poolable services: {}",
            names.join(", ")
        ));
    }
    let pool = crate::secrets::key_pool::global_pool();
    let mut entry = crate::secrets::key_pool::KeyEntry::new(key);
    entry.notes = req.notes.clone();
    entry.environment = req.env.clone();
    if pool.add(service, entry) {
        crate::secrets::key_pool::save_pool_best_effort(&pool);
        tracing::info!(service, "key pool: added via web");
        (
            StatusCode::OK,
            Json(json!({ "status": "added", "service": service, "count": pool.service_count(service) })),
        )
            .into_response()
    } else {
        (
            StatusCode::OK,
            Json(json!({ "status": "duplicate", "service": service })),
        )
            .into_response()
    }
}

/// Body for `POST /keys/pool/revoke` — identify a pooled key by its non-secret
/// short id (never the plaintext).
#[derive(Deserialize)]
pub struct KeysPoolRevokeRequest {
    pub service: String,
    pub id: String,
}

/// Body for `POST /keys/pool/rotate` — the old key by non-secret id, plus the
/// new plaintext value to install (sent over the same loopback channel as
/// `settings/keys` PUT).
#[derive(Deserialize)]
pub struct KeysPoolRotateRequest {
    pub service: String,
    pub id: String,
    pub new: String,
}

#[derive(Deserialize)]
pub struct KeysPutRequest {
    #[serde(default)]
    pub updates: BTreeMap<String, String>,
    #[serde(default)]
    pub deletes: Vec<String>,
}

pub async fn settings_keys_put(
    State(s): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Json(req): Json<KeysPutRequest>,
) -> impl IntoResponse {
    if !s.allow_key_write {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({
                "error": "key writes disabled; restart with `hse serve --allow-key-write`"
            })),
        )
            .into_response();
    }
    if !peer.ip().is_loopback() {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "key writes are loopback-only" })),
        )
            .into_response();
    }
    if req.updates.is_empty() && req.deletes.is_empty() {
        return bad_request("no updates or deletes");
    }
    match keys::write_keys(&req.updates, &req.deletes) {
        Ok(()) => {
            tracing::info!(
                updates = req.updates.len(),
                deletes = req.deletes.len(),
                "settings/keys written"
            );
            (
                StatusCode::OK,
                Json(json!({
                    "status": "ok",
                    "updated": req.updates.len(),
                    "deleted": req.deletes.len(),
                })),
            )
                .into_response()
        }
        Err(e) => bad_request(e.to_string()),
    }
}

/// `GET /api/v1/keys/pool` — the key POOL contents for the web Settings page:
/// every pooled key MASKED, with its non-secret `id` (for revocation), service,
/// environment, status, tier and use count. Loopback-only — it reveals which
/// services/environments you hold keys for (not the plaintext). The plaintext is
/// never serialised; an operator who wants the raw values uses `hse keys export`
/// on the device shell.
pub async fn keys_pool_get(ConnectInfo(peer): ConnectInfo<SocketAddr>) -> impl IntoResponse {
    if !peer.ip().is_loopback() {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "key pool is loopback-only" })),
        )
            .into_response();
    }
    let snap = crate::secrets::key_pool::global_pool().snapshot();
    let mut services: Vec<Value> = snap
        .services
        .iter()
        .map(|(service, entries)| {
            let keys: Vec<Value> = entries
                .iter()
                .map(|e| {
                    json!({
                        "id": crate::secrets::key_pool::key_id(&e.value),
                        "masked": crate::util::str_util::mask_secret(&e.value),
                        "status": e.status.as_str(),
                        "environment": e.environment(),
                        "tier": e.tier.as_str(),
                        "use_count": e.use_count,
                    })
                })
                .collect();
            json!({ "service": service, "keys": keys })
        })
        .collect();
    services.sort_by(|a, b| a["service"].as_str().cmp(&b["service"].as_str()));
    (StatusCode::OK, Json(json!({ "services": services }))).into_response()
}

/// `POST /api/v1/keys/pool/revoke` — revoke a pooled key by its non-secret `id`
/// (from `keys_pool_get`). A write, so it's gated exactly like `settings/keys`:
/// loopback-only AND requires the operator to have started with
/// `--allow-key-write`. The key is retained for audit, never used again.
pub async fn keys_pool_revoke(
    State(s): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Json(req): Json<KeysPoolRevokeRequest>,
) -> impl IntoResponse {
    if !s.allow_key_write {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({
                "error": "key writes disabled; restart with `hse serve --allow-key-write`"
            })),
        )
            .into_response();
    }
    if !peer.ip().is_loopback() {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "key writes are loopback-only" })),
        )
            .into_response();
    }
    if req.service.trim().is_empty() || req.id.trim().is_empty() {
        return bad_request("service and id are required");
    }
    let pool = crate::secrets::key_pool::global_pool();
    if pool.revoke_by_id(&req.service, &req.id) {
        crate::secrets::key_pool::save_pool_best_effort(&pool);
        tracing::info!(service = %req.service, id = %req.id, "key pool: revoked via web");
        (
            StatusCode::OK,
            Json(json!({ "status": "revoked", "service": req.service })),
        )
            .into_response()
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "no key with that id in that service" })),
        )
            .into_response()
    }
}

/// `POST /api/v1/keys/pool/rotate` — rotate a pooled key (identified by its
/// non-secret `id`) to a new value: the old key is revoked (kept for audit) and
/// the new one added in the same environment. A write, gated exactly like
/// `settings/keys` (loopback + `--allow-key-write`). The new value is sent in the
/// body — the same loopback channel `settings/keys` PUT already uses for new keys.
pub async fn keys_pool_rotate(
    State(s): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Json(req): Json<KeysPoolRotateRequest>,
) -> impl IntoResponse {
    if !s.allow_key_write {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({
                "error": "key writes disabled; restart with `hse serve --allow-key-write`"
            })),
        )
            .into_response();
    }
    if !peer.ip().is_loopback() {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "key writes are loopback-only" })),
        )
            .into_response();
    }
    if req.service.trim().is_empty() || req.id.trim().is_empty() || req.new.trim().is_empty() {
        return bad_request("service, id and new value are required");
    }
    let pool = crate::secrets::key_pool::global_pool();
    if pool.rotate_by_id(&req.service, &req.id, req.new.trim()) {
        crate::secrets::key_pool::save_pool_best_effort(&pool);
        tracing::info!(service = %req.service, id = %req.id, "key pool: rotated via web");
        (
            StatusCode::OK,
            Json(json!({ "status": "rotated", "service": req.service })),
        )
            .into_response()
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "no key with that id in that service" })),
        )
            .into_response()
    }
}

/// `GET /api/v1/settings/toggles` — the full capability-toggle catalogue
/// (universal toggleability): every search engine and every registered module
/// with its current on/off state, grouped for the web Settings panel. Stored
/// overrides live in `~/.huntsman/settings.json`; an unset key reports its
/// in-code default (on), so a brand-new capability appears enabled.
pub async fn settings_toggles_get(State(s): State<Arc<AppState>>) -> Json<Value> {
    let engines: Vec<Value> = crate::modules::search_engines::engine_toggles()
        .into_iter()
        .map(|(key, enabled)| {
            let name = key.strip_prefix("engine.").unwrap_or(&key).to_string();
            json!({ "key": key, "name": name, "enabled": enabled })
        })
        .collect();
    // Modules sorted by name for a stable, browsable grid (registry order is by
    // priority, which is the wrong axis for a settings list).
    let mut mods: Vec<(&'static str, bool)> = s
        .engine
        .modules()
        .iter()
        .map(|m| {
            let name = m.name();
            (
                name,
                crate::util::settings::get_bool(&format!("module.{name}"), true),
            )
        })
        .collect();
    mods.sort_by_key(|(name, _)| *name);
    let modules: Vec<Value> = mods
        .into_iter()
        .map(|(name, enabled)| {
            json!({ "key": format!("module.{name}"), "name": name, "enabled": enabled })
        })
        .collect();
    // Feature toggles: capability switches that aren't a single engine/module
    // (e.g. `feature.regional`). Sourced from the one registry in `util::settings`.
    let features: Vec<Value> = crate::util::settings::feature_toggles()
        .into_iter()
        .map(|(key, enabled)| {
            let name = key.strip_prefix("feature.").unwrap_or(&key).to_string();
            json!({ "key": key, "name": name, "enabled": enabled })
        })
        .collect();
    let count = engines.len() + modules.len() + features.len();
    Json(json!({
        "groups": [
            { "group": "features", "label": "Features", "toggles": features },
            { "group": "engines", "label": "Search engines", "toggles": engines },
            { "group": "modules", "label": "Modules", "toggles": modules },
        ],
        "count": count,
    }))
}

#[derive(Deserialize)]
pub struct TogglePutRequest {
    pub key: String,
    pub enabled: bool,
}

/// `PUT /api/v1/settings/toggles` — flip one capability toggle and persist it.
/// Loopback-only (the dashboard is a local operator tool) and bounded to known
/// engine/module keys so a typo can't persist junk. No secret is involved, so —
/// unlike key writes — this does NOT require `--allow-key-write`.
pub async fn settings_toggles_put(
    State(s): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Json(req): Json<TogglePutRequest>,
) -> impl IntoResponse {
    if !peer.ip().is_loopback() {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "toggle writes are loopback-only" })),
        )
            .into_response();
    }
    if !toggle_key_is_known(&s, &req.key) {
        return bad_request(format!(
            "unknown toggle key '{}' (expected engine.<name> or module.<name>)",
            req.key
        ));
    }
    match crate::util::settings::set_bool(&req.key, req.enabled) {
        Ok(()) => {
            tracing::info!(key = %req.key, enabled = req.enabled, "settings/toggle written");
            (
                StatusCode::OK,
                Json(json!({ "status": "ok", "key": req.key, "enabled": req.enabled })),
            )
                .into_response()
        }
        Err(e) => bad_request(e.to_string()),
    }
}

/// True if `key` names a real engine (`engine.<name>`) or registered module
/// (`module.<name>`) — bounds web toggle writes to actual capabilities.
fn toggle_key_is_known(s: &AppState, key: &str) -> bool {
    if let Some(name) = key.strip_prefix("module.") {
        return s.engine.modules().iter().any(|m| m.name() == name);
    }
    if key.starts_with("engine.") {
        return crate::modules::search_engines::engine_toggles()
            .iter()
            .any(|(k, _)| k == key);
    }
    crate::util::settings::is_feature_key(key)
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
