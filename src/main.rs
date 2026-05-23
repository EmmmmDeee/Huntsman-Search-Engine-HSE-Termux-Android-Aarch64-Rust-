use std::{collections::BTreeSet, net::SocketAddr};

use axum::{
    Json, Router,
    extract::{Query, State},
    response::{Html, IntoResponse},
    routing::get,
};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::process::Command;

const REFRESH_SECONDS: u64 = 5;

#[derive(Clone)]
struct AppState {
    ip_regex: Regex,
}

#[derive(Debug, Serialize)]
struct SignalSnapshot {
    source: &'static str,
    available: bool,
    payload: Option<Value>,
    note: Option<String>,
}

#[derive(Debug, Serialize)]
struct OsintFinding {
    indicator: String,
    source: &'static str,
    detail: String,
}

#[derive(Debug, Serialize)]
struct SignalResponse {
    refresh_seconds: u64,
    live_osint_enabled: bool,
    signals: Vec<SignalSnapshot>,
    live_osint: Vec<OsintFinding>,
}

#[derive(Debug, Deserialize)]
struct SignalQuery {
    live_osint: Option<bool>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let state = AppState {
        ip_regex: Regex::new(
            r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b",
        )?,
    };

    let app = Router::new()
        .route("/", get(index))
        .route("/api/signals", get(fetch_signals))
        .with_state(state);

    let bind_addr: SocketAddr = "0.0.0.0:8080".parse()?;
    println!(
        "Huntsman Search Engine is running at http://{} (Termux/Chrome friendly)",
        bind_addr
    );
    let listener = tokio::net::TcpListener::bind(bind_addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn index() -> impl IntoResponse {
    Html(format!(
        r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Huntsman Search Engine</title>
<style>
:root {{ color-scheme: light dark; }}
body {{ font-family: system-ui, sans-serif; margin: 1rem; max-width: 900px; }}
header {{ display: flex; justify-content: space-between; align-items: center; gap: .5rem; flex-wrap: wrap; }}
.card {{ border: 1px solid #7774; border-radius: 10px; padding: .75rem; margin-top: .75rem; }}
pre {{ white-space: pre-wrap; word-break: break-word; }}
label {{ display: inline-flex; align-items: center; gap: .35rem; }}
small {{ color: #888; }}
</style>
</head>
<body>
<header>
  <h1>Huntsman Search Engine</h1>
  <button id="refresh">Refresh now</button>
</header>
<p>Optimised for Termux Android aarch64 (rootless). Open this page in Chrome and optionally enable live OSINT enrichment.</p>
<label><input type="checkbox" id="live" /> Enable live OSINT</label>
<small>Data refreshes every {refresh_seconds}s.</small>
<div class="card"><h2>Detected Mobile Signals</h2><pre id="signals">Loading...</pre></div>
<div class="card"><h2>Live OSINT Findings</h2><pre id="osint">Live OSINT disabled.</pre></div>
<script>
const signalsEl = document.getElementById('signals');
const osintEl = document.getElementById('osint');
const live = document.getElementById('live');

async function refresh() {{
  const res = await fetch(`/api/signals?live_osint=${{live.checked}}`);
  const data = await res.json();
  signalsEl.textContent = JSON.stringify(data.signals, null, 2);
  osintEl.textContent = data.live_osint_enabled
    ? JSON.stringify(data.live_osint, null, 2)
    : 'Live OSINT disabled.';
}}

live.addEventListener('change', refresh);
document.getElementById('refresh').addEventListener('click', refresh);
refresh();
setInterval(refresh, {refresh_ms});
</script>
</body>
</html>"#,
        refresh_seconds = REFRESH_SECONDS,
        refresh_ms = REFRESH_SECONDS * 1000
    ))
}

async fn fetch_signals(
    State(state): State<AppState>,
    Query(query): Query<SignalQuery>,
) -> impl IntoResponse {
    let live_osint_enabled = query.live_osint.unwrap_or(false);
    let signals = collect_signals().await;
    let live_osint = if live_osint_enabled {
        collect_live_osint(&signals, &state.ip_regex).await
    } else {
        Vec::new()
    };

    Json(SignalResponse {
        refresh_seconds: REFRESH_SECONDS,
        live_osint_enabled,
        signals,
        live_osint,
    })
}

async fn collect_signals() -> Vec<SignalSnapshot> {
    let mut signals = Vec::with_capacity(5);

    for (source, command, args) in [
        ("battery", "termux-battery-status", &[][..]),
        (
            "location",
            "termux-location",
            &["-p", "gps,network"] as &[&str],
        ),
        ("wifi_connection", "termux-wifi-connectioninfo", &[][..]),
        ("wifi_scan", "termux-wifi-scaninfo", &[][..]),
        ("telephony_device", "termux-telephony-deviceinfo", &[][..]),
    ] {
        signals.push(run_termux_json(source, command, args).await);
    }

    signals
}

async fn run_termux_json(source: &'static str, command: &str, args: &[&str]) -> SignalSnapshot {
    match Command::new(command).args(args).output().await {
        Ok(output) if output.status.success() => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            match serde_json::from_str::<Value>(&stdout) {
                Ok(payload) => SignalSnapshot {
                    source,
                    available: true,
                    payload: Some(payload),
                    note: None,
                },
                Err(_) => SignalSnapshot {
                    source,
                    available: false,
                    payload: None,
                    note: Some("Command output was not valid JSON".to_string()),
                },
            }
        }
        Ok(output) => SignalSnapshot {
            source,
            available: false,
            payload: None,
            note: Some(String::from_utf8_lossy(&output.stderr).trim().to_string()),
        },
        Err(error) => SignalSnapshot {
            source,
            available: false,
            payload: None,
            note: Some(format!("{command} unavailable: {error}")),
        },
    }
}

async fn collect_live_osint(signals: &[SignalSnapshot], ip_regex: &Regex) -> Vec<OsintFinding> {
    let mut findings = Vec::new();
    let mut indicators = BTreeSet::new();

    for signal in signals {
        if let Some(payload) = &signal.payload {
            add_indicators_from_json(payload, ip_regex, &mut indicators);
        }
    }

    if let Ok(output) = Command::new("ss").arg("-tun").output().await {
        if output.status.success() {
            for line in String::from_utf8_lossy(&output.stdout).lines() {
                if let Some(endpoint) = line.split_whitespace().nth(4)
                    && let Some(ip) = extract_ip(endpoint, ip_regex)
                {
                    indicators.insert(ip.to_string());
                }
            }
        }
    }

    findings.extend(indicators.into_iter().map(|indicator| OsintFinding {
        detail: format!("Detected from Termux/mobile runtime signal stream"),
        source: "live_osint",
        indicator,
    }));

    findings
}

fn add_indicators_from_json(value: &Value, ip_regex: &Regex, output: &mut BTreeSet<String>) {
    match value {
        Value::String(text) => {
            for matched in ip_regex.find_iter(text) {
                output.insert(matched.as_str().to_string());
            }
        }
        Value::Array(items) => {
            for item in items {
                add_indicators_from_json(item, ip_regex, output);
            }
        }
        Value::Object(map) => {
            for value in map.values() {
                add_indicators_from_json(value, ip_regex, output);
            }
        }
        _ => {}
    }
}

fn extract_ip<'a>(endpoint: &'a str, ip_regex: &Regex) -> Option<&'a str> {
    ip_regex.find(endpoint).map(|m| m.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_ip_handles_ipv4_endpoint() {
        let regex =
            Regex::new(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
                .expect("regex must compile");

        assert_eq!(extract_ip("203.0.113.5:443", &regex), Some("203.0.113.5"));
    }

    #[test]
    fn add_indicators_walks_nested_json() {
        let regex =
            Regex::new(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
                .expect("regex must compile");

        let payload = serde_json::json!({
            "network": {
                "detail": "upstream: 198.51.100.77",
                "list": ["none", "10.0.0.55"]
            }
        });

        let mut found = BTreeSet::new();
        add_indicators_from_json(&payload, &regex, &mut found);

        assert!(found.contains("198.51.100.77"));
        assert!(found.contains("10.0.0.55"));
    }
}
