//! Confidence-tier math — the `effC`/`classify` exports that replaced the
//! `ENRICHMENT_SOURCES`/`sourceCount`/`effC`/`classify` cluster
//! `src/web/js/helpers.js` used to hand-maintain.
//!
//! This is the concrete reason this whole port exists (see `lib.rs`'s doc
//! comment): the JS versions were a hand-maintained mirror of
//! `hse_core::Entity::source_count`/`c_effective` and `Classification`, kept
//! in sync only by a fitness test reading both sides as text
//! (`spa_enrichment_sources_matches_backend_is_non_corroborating_source` in
//! `src/api/routes/tests.rs`) — and had already drifted once (missing the
//! promotion-source grounding gate `source_count()` applies). Deserializing
//! the browser's own entity JSON straight into a real [`hse_core::Entity`]
//! and calling its real methods closes that whole drift class permanently:
//! there is no second implementation left to disagree with the first.
//!
//! Only the exports the SPA actually imports live here. `sourceCount` and
//! `isNonCorroboratingSource` were exported too until the browse renderer
//! moved into Rust ([`crate::scan_info::browse`]) and started calling
//! `hse_core` directly per row, which left them with no JS caller — an
//! unreachable export is still shipped in every on-device binary, so
//! `every_wasm_ui_export_is_imported_by_a_spa_module` (`tests/architecture`)
//! now fails on any export no SPA module imports.

use wasm_bindgen::prelude::*;

use crate::to_js_error;

/// Effective confidence for an entity — mirrors
/// [`hse_core::Entity::c_effective`] exactly, because it *is*
/// `Entity::c_effective`. `entity_js` is the entity object as the browser
/// received it from the API (the same JSON `hse_core::Entity` serializes to
/// server-side); deserialization failing indicates a real shape mismatch
/// worth surfacing as a thrown JS error, not silently guessing a value.
#[wasm_bindgen(js_name = effC)]
pub fn eff_c(entity_js: JsValue) -> Result<f64, JsValue> {
    let entity: hse_core::Entity =
        serde_wasm_bindgen::from_value(entity_js).map_err(to_js_error)?;
    Ok(entity.c_effective())
}

/// Confidence tier for an already-computed `c_eff` — mirrors
/// [`hse_core::Classification::from_c_eff`]. Takes a bare number (not an
/// entity), matching the JS original's signature: callers that already have
/// `eff_c(entity)` in hand pass it straight through without a second
/// deserialization.
#[wasm_bindgen]
pub fn classify(eff: f64) -> String {
    hse_core::Classification::from_c_eff(eff)
        .as_str()
        .to_string()
}
