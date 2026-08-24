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
