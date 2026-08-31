//! Confidence-tier math — port of the `ENRICHMENT_SOURCES`/`sourceCount`/
//! `effC`/`classify` cluster in `src/web/js/helpers.js`.
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

use wasm_bindgen::prelude::*;

use crate::to_js_error;

/// Distinct corroborating sources for an entity — mirrors
/// [`hse_core::Entity::source_count`] exactly, because it *is*
/// `Entity::source_count`. `entity_js` is the entity object as the browser
/// received it from the API (the same JSON `hse_core::Entity` serializes to
/// server-side); deserialization failing indicates a real shape mismatch
/// worth surfacing as a thrown JS error, not silently guessing a value.
#[wasm_bindgen(js_name = sourceCount)]
pub fn source_count(entity_js: JsValue) -> Result<u32, JsValue> {
    let entity: hse_core::Entity =
        serde_wasm_bindgen::from_value(entity_js).map_err(to_js_error)?;
    Ok(entity.source_count())
}

/// Effective confidence for an entity — mirrors
/// [`hse_core::Entity::c_effective`] exactly, for the same reason
/// [`source_count`] does.
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

/// True if `source` must not count toward cross-source corroboration —
/// mirrors [`hse_core::is_non_corroborating_source`] exactly. This is the
/// predicate `scan_info/browse.js`'s evidence-detail rows use to mark a
/// non-corroborating source (the same "(non-corroborating: …)" annotation
/// the CLI dossier prints); the JS side used to hold its own `ENRICHMENT_SOURCES`
/// set for this before that set moved into `hse_core` under this module's
/// migration, leaving `browse.js`'s call site referencing an undefined global.
#[wasm_bindgen(js_name = isNonCorroboratingSource)]
pub fn is_non_corroborating_source(source: &str) -> bool {
    hse_core::is_non_corroborating_source(source)
}
