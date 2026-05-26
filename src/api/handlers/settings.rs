//! Settings handlers: key listing and writing.

use std::{collections::BTreeMap, net::SocketAddr, sync::Arc};

use axum::{
    Json,
    extract::{ConnectInfo, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde::Deserialize;
use serde_json::{Value, json};
use tracing::info;

use crate::api::AppState;
use crate::util::keys;

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
            Json(json!({
                "error": "key writes are loopback-only"
            })),
        )
            .into_response();
    }
    if req.updates.is_empty() && req.deletes.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "no updates or deletes"})),
        )
            .into_response();
    }
    match keys::write_keys(&req.updates, &req.deletes) {
        Ok(()) => {
            info!(
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
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}
