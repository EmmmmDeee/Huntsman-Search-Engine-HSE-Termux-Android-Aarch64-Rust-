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
use crate::util::keys;

/// Expose the API-key detector's prefix-match coverage. Returns the
/// full ordered table from `key_harvest::patterns` so operators can
/// see what shapes the scanner recognises — and so dashboards can
/// surface per-service coverage stats.
pub async fn keys_patterns() -> Json<Value> {
    let patterns = crate::modules::oathnet_pro::key_harvest::pattern_catalogue();
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
    /// Mean [`crate::util::key_pool::KeyEntry::health_score`] across this service's
    /// keys — the at-a-glance "how healthy is this pool" number (0.0–1.0), `0.0`
    /// for a service with no keys. The status counts above say *what* the keys
    /// are; this says how operationally healthy they are overall.
    pub avg_health: f64,
}

/// Summarise a key-pool snapshot into per-service status counts (plus the mean
/// per-key health score), dropping every key value. Does not touch the global
/// pool, so it is unit-testable; the clock is sampled once up front so every
/// score in one summary is consistent. Sorted by service.
pub(crate) fn summarize_pool(data: &crate::util::key_pool::PoolData) -> Vec<ServiceQuota> {
    use crate::util::key_pool::KeyStatus;
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

/// `GET /api/v1/keys/status` — per-service key-pool health (counts by status,
/// aggregate use/error totals, and the mean per-key health score) for the
/// operator quota view. Never exposes key values. Reads the process-global pool.
pub async fn keys_status() -> Json<Value> {
    let services = summarize_pool(&crate::util::key_pool::global_pool().snapshot());
    Json(json!({ "count": services.len(), "services": services }))
}

pub async fn settings_keys_get(State(s): State<Arc<AppState>>) -> impl IntoResponse {
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
    Json(json!({
        "keys": entries,
        "count": count,
        "write_enabled": s.allow_key_write,
        "env_path": path,
    }))
    .into_response()
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
    let snap = crate::util::key_pool::global_pool().snapshot();
    let mut services: Vec<Value> = snap
        .services
        .iter()
        .map(|(service, entries)| {
            let keys: Vec<Value> = entries
                .iter()
                .map(|e| {
                    json!({
                        "id": crate::util::key_pool::key_id(&e.value),
                        "masked": mask_secret(&e.value),
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
    let pool = crate::util::key_pool::global_pool();
    if pool.revoke_by_id(&req.service, &req.id) {
        crate::util::key_pool::save_pool_best_effort(&pool);
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
    let pool = crate::util::key_pool::global_pool();
    if pool.rotate_by_id(&req.service, &req.id, req.new.trim()) {
        crate::util::key_pool::save_pool_best_effort(&pool);
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

/// Mask a secret to a non-reversible hint: first 4 + last 4 chars (char-safe).
fn mask_secret(value: &str) -> String {
    let chars: Vec<char> = value.chars().collect();
    // Only reveal a 4+4 head/tail hint for secrets long enough that 8 exposed
    // characters are a small fraction. Below 16, fully mask — a 9-12 char secret
    // would otherwise leak almost all of itself (e.g. 8 of 9). The hint is only
    // an operator recognition aid, never enough to reconstruct the value.
    if chars.len() < 16 {
        return "•".repeat(chars.len().max(1));
    }
    let head: String = chars.iter().take(4).collect();
    let tail: String = chars
        .iter()
        .rev()
        .take(4)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    format!("{head}…{tail}")
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
