//! `hse analyze` — synchronous, on-demand AI-daemon scan analysis.
//!
//! The interactive counterpart to `hse-ai-daemon` (`src/bin/hse_ai_daemon/`):
//! both call the same [`crate::ai::analysis::analyze_scan`] so they can't drift
//! on what "analyzing a scan" means. See `src/ai/mod.rs` for why this surface
//! is allowed to call a live AI/LLM at runtime at all, and the `Runtime
//! AI-independence` invariant in `src/lib.rs` for the full rationale.

use crate::ai::ollama::{DEFAULT_BASE_URL, OllamaClient};
use crate::core::error::{Error, Result};
use crate::{default_db_path, storage::Store};
use std::time::Duration;

/// Floor for `HUNTSMAN_OLLAMA_TIMEOUT_MS` — below this, a slow-but-healthy
/// local model would be indistinguishable from a hung one.
const MIN_TIMEOUT_MS: u64 = 1_000;

/// Local generation is slow relative to a network API call and varies hugely
/// by model/hardware; two minutes is a generous default an operator can
/// override per their own model/device.
const DEFAULT_TIMEOUT_MS: u64 = 120_000;

fn resolve_timeout_ms() -> u64 {
    std::env::var("HUNTSMAN_OLLAMA_TIMEOUT_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|&n| n >= MIN_TIMEOUT_MS)
        .unwrap_or(DEFAULT_TIMEOUT_MS)
}

pub async fn cmd_analyze(
    scan_id: Option<String>,
    json: bool,
    ollama_url: Option<String>,
    model: Option<String>,
) -> Result<()> {
    if !crate::util::settings::ai_daemon_enabled() {
        return Err(Error::Other(
            "AI-daemon analysis is disabled (feature.ai_daemon is off). Install and start \
             Ollama, then run `hse config feature.ai_daemon on` before using this command."
                .into(),
        ));
    }

    let store = Store::open(&default_db_path())?;
    let id = crate::app::runtime::resolve_scan_id(&store, scan_id.as_deref().unwrap_or("latest"))?;

    // `--ollama-url`/`--model` already fold in `HUNTSMAN_OLLAMA_URL`/
    // `HUNTSMAN_OLLAMA_MODEL` via clap's `env = "..."` (see `cli::command::Command::Analyze`) —
    // only the base-url default and the "no model configured" error live here.
    let base_url = ollama_url.unwrap_or_else(|| DEFAULT_BASE_URL.to_string());
    let model = model.ok_or_else(|| {
        Error::Other(
            "no Ollama model configured — pass --model or set HUNTSMAN_OLLAMA_MODEL".into(),
        )
    })?;

    let client = OllamaClient::new(base_url, model);
    client.health_check().await?;

    let timeout = Duration::from_millis(resolve_timeout_ms());
    let analysis = crate::ai::analysis::analyze_scan(&store, &client, &id, timeout).await?;

    if json {
        let out = serde_json::to_string_pretty(&analysis).map_err(|e| Error::Other(e.to_string()))?;
        println!("{out}");
    } else {
        println!("Scan {} — {}\n", analysis.scan_id, analysis.model);
        println!("{}\n", analysis.summary);
        for f in &analysis.findings {
            println!("  [{:>3}] {}", f.severity, f.description);
        }
    }
    Ok(())
}
