//! Optional, fully opt-in AI-analysis surface — the ONE place in this crate
//! allowed to call a live AI/LLM at runtime.
//!
//! This module exists as a deliberate, narrow, documented exception to the
//! `Runtime AI-independence` invariant in `src/lib.rs`, not a loophole in it:
//! it depends on `core`/`util`, never the reverse, so it cannot be reached from
//! the deterministic scan engine, module dispatch, correlator, or storage port
//! — `core_does_not_import_ai` in `tests/architecture.rs` enforces that
//! mechanically. It is reached from exactly two places, both explicit operator
//! actions: the `hse analyze` CLI subcommand (`src/app/analyze.rs`) and the
//! separate `hse-ai-daemon` binary (`src/bin/hse_ai_daemon/main.rs`) — never
//! from `hse scan`/`hse serve`/`hse live` or any code a scan itself runs.
//!
//! Both entry points gate on [`crate::util::settings::ai_daemon_enabled`]
//! (off by default) before doing anything else, and both fail closed and
//! visibly — a surfaced `Err`, never a silent no-op or a fabricated result —
//! when Ollama is absent, unreachable, or returns something unparsable.
//!
//! - [`ollama`] — a minimal HTTP client for a locally-run Ollama instance.
//!   Plain JSON over HTTP; no ML/LLM SDK crate, so
//!   `runtime_carries_no_ai_ml_inference_dependency` (`tests/architecture.rs`)
//!   never has anything to catch here in the first place.
//! - [`analysis`] — prompt construction, response parsing, and the
//!   orchestration that ties [`ollama::OllamaClient`] to
//!   [`crate::core::port::StoragePort`]. Prompt-building and response-parsing
//!   are pure functions, unit-tested without a network call — the same split
//!   this codebase's OSINT modules use between a pure `entities_from` and the
//!   I/O that feeds it.

pub mod analysis;
pub mod ollama;

use std::borrow::Cow;

/// Floor for `HUNTSMAN_OLLAMA_TIMEOUT_MS` — below this, a slow-but-healthy
/// local model would be indistinguishable from a hung one. Shared by `hse
/// analyze` and `hse-ai-daemon` so the two can't drift on what counts as a
/// sane override (they did, briefly, before this constant was hoisted here).
pub const MIN_GENERATION_TIMEOUT_MS: u64 = 1_000;

/// Local generation is slow relative to a network API call and varies hugely
/// by model/hardware; two minutes is a generous default an operator can
/// override per their own model/device.
pub const DEFAULT_GENERATION_TIMEOUT_MS: u64 = 120_000;

/// Floor for `HUNTSMAN_AI_POLL_INTERVAL_SECS` (`hse-ai-daemon` only) — below
/// this, a busy loop of mostly-empty `scans_pending_analysis` queries is not
/// meaningfully more responsive, just noisier.
pub const MIN_POLL_INTERVAL_SECS: u64 = 15;

/// Default poll interval — frequent enough that a newly-completed scan gets
/// analyzed promptly, infrequent enough not to hammer `scans_pending_analysis`
/// on an otherwise-idle install.
pub const DEFAULT_POLL_INTERVAL_SECS: u64 = 60;

/// Parse `var` as a `u64`, floored at `min`, falling back to `default` when
/// unset, unparsable, or below the floor. The one place this crate's
/// AI-daemon knobs (`HUNTSMAN_OLLAMA_TIMEOUT_MS`, `HUNTSMAN_AI_POLL_INTERVAL_SECS`)
/// get parsed, so `hse analyze` and `hse-ai-daemon` can't silently diverge on
/// the parsing/floor/default logic for a value they both read.
#[must_use]
pub fn resolve_env_u64(var: &str, min: u64, default: u64) -> u64 {
    resolve_u64(std::env::var(var).ok(), min, default)
}

/// The pure floor/default resolution behind [`resolve_env_u64`], split out so
/// it's unit-testable without mutating process-wide environment state — this
/// crate `#![forbid(unsafe_code)]` (`src/lib.rs`), and `std::env::set_var` is
/// `unsafe` as of the 2024 edition, so a test cannot exercise the floor/reject
/// path by actually setting an env var.
fn resolve_u64(raw: Option<String>, min: u64, default: u64) -> u64 {
    raw.and_then(|v| v.parse::<u64>().ok())
        .filter(|&n| n >= min)
        .unwrap_or(default)
}

/// Truncate `s` to at most `max_chars` on a `char` boundary (never a byte
/// index — this module hands arbitrary scraped/upstream UTF-8 through it),
/// appending an ellipsis when truncated. Shared by [`ollama`] (bounding an
/// error-message snippet) and [`analysis`] (bounding a per-entity prompt
/// value) so the two don't carry separate copies of the same char-counting
/// loop with two different constants.
#[must_use]
pub fn truncate_chars(s: &str, max_chars: usize) -> Cow<'_, str> {
    match s.char_indices().nth(max_chars) {
        Some((idx, _)) => Cow::Owned(format!("{}…", &s[..idx])),
        None => Cow::Borrowed(s),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_env_u64_falls_back_to_default_when_unset() {
        // A var name essentially guaranteed unset in any real environment.
        assert_eq!(
            resolve_env_u64("HUNTSMAN_AI_TEST_DOES_NOT_EXIST_XYZ", 10, 42),
            42
        );
    }

    #[test]
    fn resolve_u64_enforces_the_floor() {
        assert_eq!(
            resolve_u64(Some("1".to_string()), 10, 42),
            42,
            "a value below the floor must fall back to default"
        );
    }

    #[test]
    fn resolve_u64_accepts_a_value_at_or_above_the_floor() {
        assert_eq!(resolve_u64(Some("10".to_string()), 10, 42), 10);
        assert_eq!(resolve_u64(Some("1000".to_string()), 10, 42), 1000);
    }

    #[test]
    fn resolve_u64_falls_back_to_default_on_unparsable_input() {
        assert_eq!(resolve_u64(Some("not-a-number".to_string()), 10, 42), 42);
    }

    #[test]
    fn resolve_u64_falls_back_to_default_when_absent() {
        assert_eq!(resolve_u64(None, 10, 42), 42);
    }

    #[test]
    fn truncate_chars_is_char_boundary_safe_on_multibyte_text() {
        let s = "é".repeat(400);
        let t = truncate_chars(&s, 300);
        assert!(t.ends_with('…'));
        assert!(t.chars().count() <= 301);
    }

    #[test]
    fn truncate_chars_leaves_a_short_string_untouched() {
        assert_eq!(truncate_chars("short", 300), "short");
    }
}
