//! Web-UI build target: Rust compiled to wasm32-unknown-unknown, replacing
//! `src/web/js/*` incrementally, view by view (simplest first — see the
//! project's own task tracker).
//!
//! Modules ported so far:
//! - [`theme`] — `src/web/js/theme.js`
//! - [`confidence`] — the `ENRICHMENT_SOURCES`/`sourceCount`/`effC`/`classify`
//!   cluster in `src/web/js/helpers.js`
//! - [`scan_info`] — `src/web/js/scan_info/*.js`, one submodule per file
//! - [`views`] — `src/web/js/views/*.js`'s pure, DOM-free rendering helpers
//!   (dash.js's module-health panel; scans.js's budget panel and scan table;
//!   diff.js's scan-comparison result rendering)
//!
//! The compiled output is checked into `pkg/` and embedded into
//! `src/api/routes/mod.rs`'s `APP_FILES` the same way every hand-written JS
//! file is — there is no `build.rs` step wiring this crate into the main
//! crate's own build. After any change here or under `hse-core/` (which this
//! crate embeds), regenerate with the ONE pipeline, then commit `pkg/`:
//! ```sh
//! scripts/wasm_ui_drift_check.sh --write
//! ```
//! Without `--write` the same script regenerates into a scratch location and
//! diffs it byte-for-byte against `pkg/` — that is what `scripts/gate.sh` and
//! CI run. The pipeline (cargo `--release --locked` for wasm32, `wasm-bindgen`
//! at the exact version pinned in `Cargo.toml`, `wasm-opt` from a pinned
//! binaryen build) lives only in that script, so the recipe cannot drift
//! from what CI verifies.
//!
//! Reproducibility is path-sensitive in two ways, both handled in the script
//! and both discovered the hard way (a CI run failing the drift check on a
//! tree with no real source change): `rustc` embeds the absolute build path
//! into panic-location strings even in `--release` (fixed with
//! `--remap-path-prefix`), and cargo's per-crate metadata hash — hence every
//! mangled symbol, hence the LTO item order — includes the absolute path of
//! `hse-core`, an out-of-workspace path dependency (fixed by building from one
//! fixed absolute path on every machine). The remap placeholders and that
//! fixed path MUST stay byte-for-byte fixed forever — changing either changes
//! every future regeneration's output.
//!
//! The `wasm-opt` feature flags are pinned to exactly what this toolchain's
//! `wasm32-unknown-unknown` output actually uses (found by starting from none
//! and adding only what `wasm-opt`'s own validator complained was missing) —
//! deliberately not `--all-features` (nor no flags/MVP-only), either of which
//! is wrong for this crate's purpose: MVP-only fails validation outright (the
//! input already uses these features), while `--all-features` risks `wasm-opt`
//! leaning on much newer features (SIMD, GC, threads, …) than this input
//! actually needs, for a measured ~120 B difference — a bad trade when the
//! entire point is a `.wasm` an older Android WebView can still load.

pub mod confidence;
pub mod entity_lookup;
pub mod html;
pub mod scan_info;
pub mod theme;
pub mod views;

use wasm_bindgen::prelude::*;

/// Converts any displayable error (chiefly a `serde_wasm_bindgen::Error` from
/// a failed JS-value deserialization) into the `JsValue` a `#[wasm_bindgen]`
/// function's `Result::Err` must carry, so it surfaces to the caller as a
/// real thrown JS error instead of a silently-swallowed one.
///
/// Constructs a real `js_sys::Error` rather than `JsValue::from_str`: every
/// JS call site that catches one of these (e.g. `scan_info/browse.js`,
/// `scan_info/audit.js`, `scan_info/communities.js`, `scan_info/leads.js`,
/// `scan_info/network.js`, `scan_info/path.js`) reads `e.message` to display
/// it, which is `undefined` on a bare thrown string — the string has no
/// `.message` property.
pub(crate) fn to_js_error(e: impl std::fmt::Display) -> JsValue {
    js_sys::Error::new(&e.to_string()).into()
}

/// Runs automatically when the browser loads this module — no explicit JS
/// call needed, unlike every other function here (which `wasm-bindgen`
/// exports for JS to call directly by name).
#[wasm_bindgen(start)]
pub fn main() {
    theme::wire_toggle_click();
}

