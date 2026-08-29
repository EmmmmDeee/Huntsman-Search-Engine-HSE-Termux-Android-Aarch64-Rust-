//! Web-UI build target: Rust compiled to wasm32-unknown-unknown, replacing
//! `src/web/js/*` incrementally, view by view (simplest first — see the
//! project's own task tracker).
//!
//! Modules ported so far:
//! - [`theme`] — `src/web/js/theme.js`
//! - [`confidence`] — the `ENRICHMENT_SOURCES`/`sourceCount`/`effC`/`classify`
//!   cluster in `src/web/js/helpers.js`
//!
//! The compiled output is checked into `pkg/` and embedded into
//! `src/api/routes/mod.rs`'s `APP_FILES` the same way every hand-written JS
//! file is — there is no `build.rs` step wiring this crate into the main
//! crate's own build. Regenerate after any change here with:
//! ```sh
//! cargo build --manifest-path wasm-ui/Cargo.toml --target wasm32-unknown-unknown --release
//! wasm-bindgen --target web --no-typescript --out-dir wasm-ui/pkg \
//!     --out-name hse_wasm_ui wasm-ui/target/wasm32-unknown-unknown/release/hse_wasm_ui.wasm
//! ```

pub mod confidence;
pub mod theme;

use wasm_bindgen::prelude::*;

/// Runs automatically when the browser loads this module — no explicit JS
/// call needed, unlike every other function here (which `wasm-bindgen`
/// exports for JS to call directly by name).
#[wasm_bindgen(start)]
pub fn main() {
    render_proof();
    theme::wire_toggle_click();
}

/// Writes a visible, checkable result into `#wasm-proof` (added only to the
/// temporary `wasm_test.html` diagnostic page, not to the real `spa.html`).
/// Exercises three things a real port will depend on: DOM access via
/// `web-sys`, calling `hse_core::unix_now()` (the function with the
/// wasm32-specific `js_sys::Date::now()` branch — proves that branch is
/// actually reachable and correct, not just present), and constructing a
/// real `hse_core::Entity` and reading its confidence-tier classification —
/// the exact capability (`Entity::c_effective`/`classify`) this whole port
/// exists to give the UI direct access to instead of a hand-mirrored JS
/// approximation.
fn render_proof() {
    let Some(window) = web_sys::window() else {
        return;
    };
    let Some(document) = window.document() else {
        return;
    };
    let Some(el) = document.get_element_by_id("wasm-proof") else {
        return;
    };

    let now = hse_core::unix_now();

    let mut e = hse_core::Entity::new(hse_core::EntityKind::Email, "proof@example.com", 0.6, "s");
    e.add_evidence(hse_core::Evidence::new(
        "second_source",
        "corroborating observation",
    ));
    let tier = e.classify();
    let c_eff = e.c_effective();

    el.set_text_content(Some(&format!(
        "hse-core reachable from wasm32: unix_now()={now}, \
         Entity::c_effective()={c_eff:.4}, classify()={tier:?}"
    )));
}
