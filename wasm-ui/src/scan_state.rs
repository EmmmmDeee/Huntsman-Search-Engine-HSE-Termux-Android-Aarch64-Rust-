//! A scan's state as the console shows it, and the pill that draws it: one
//! rule and one piece of markup for every view that shows a scan's state.
//!
//! The API's `status` is the persisted field. A scan whose server died while
//! it ran still reads `running` there, and the API marks it with a derived
//! `interrupted: true` on every read (REQ-SCANSTATUS-001): no live process
//! holds it, and nothing will ever finish it. The console treats it as over:
//! no Stop or Abort control, no live stream, no refresh timer, no clock that
//! climbs (REQ-SCANSTATUS-002).

use serde::Deserialize;
use wasm_bindgen::prelude::*;

use crate::html::escape_html;
use crate::to_js_error;

/// A scan's display state: its `status`, except that a `running` row the API
/// marks `interrupted` is `"interrupted"`. A missing or empty status is
/// `"pending"`, the state a scan is created in.
#[must_use]
pub fn scan_state(status: Option<&str>, interrupted: bool) -> &str {
    match status {
        Some("running") if interrupted => "interrupted",
        Some(s) if !s.is_empty() => s,
        _ => "pending",
    }
}

/// Whether a scan in `state` is still in progress: something is running it,
/// or is about to. Only these get a Stop or Abort control, a live log and a
/// refresh timer. Of these, only a `running` scan's clock climbs.
#[must_use]
pub fn is_active(state: &str) -> bool {
    matches!(state, "running" | "pending")
}

/// The status pill for a display state. A state with no style of its own
/// keeps its own text in the `pending` style.
#[must_use]
pub fn status_pill(state: &str) -> String {
    let class = match state {
        "complete" => "s-complete",
        "running" => "s-running",
        "failed" => "s-failed",
        "aborted" => "s-aborted",
        "interrupted" => "s-interrupted",
        _ => "s-pending",
    };
    format!(
        "<span class=\"status-pill {class}\">{}</span>",
        escape_html(state)
    )
}

/// The two fields [`scan_state`] reads from a scan object.
#[derive(Deserialize)]
struct ScanStateFields {
    status: Option<String>,
    #[serde(default)]
    interrupted: bool,
}

/// [`scan_state`] for the JS views: `scanState(scan)`.
#[wasm_bindgen(js_name = scanState)]
pub fn scan_state_js(scan_js: JsValue) -> Result<String, JsValue> {
    let s: ScanStateFields = serde_wasm_bindgen::from_value(scan_js).map_err(to_js_error)?;
    Ok(scan_state(s.status.as_deref(), s.interrupted).to_string())
}

/// [`is_active`] of [`scan_state`] for the JS views: `scanIsActive(scan)`.
#[wasm_bindgen(js_name = scanIsActive)]
pub fn scan_is_active_js(scan_js: JsValue) -> Result<bool, JsValue> {
    let s: ScanStateFields = serde_wasm_bindgen::from_value(scan_js).map_err(to_js_error)?;
    Ok(is_active(scan_state(s.status.as_deref(), s.interrupted)))
}

/// [`status_pill`] for the JS views: `statusPillHtml(state)`. `helpers.js`'s
/// `statusPill` is this, so the markup exists once. `undefined`, `null` and
/// `""` draw as `pending`.
#[wasm_bindgen(js_name = statusPillHtml)]
#[must_use]
pub fn status_pill_html(state: Option<String>) -> String {
    status_pill(scan_state(state.as_deref(), false))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_interrupted_running_scan_is_interrupted_and_over() {
        assert_eq!(scan_state(Some("running"), true), "interrupted");
        assert!(!is_active(scan_state(Some("running"), true)));
        // The same row with a live process behind it is running.
        assert_eq!(scan_state(Some("running"), false), "running");
        assert!(is_active(scan_state(Some("running"), false)));
    }

    #[test]
    fn the_flag_only_qualifies_a_running_row() {
        // The API derives it only for `running`; a terminal row keeps its
        // own state whatever the flag says.
        for s in ["complete", "failed", "aborted", "pending"] {
            assert_eq!(scan_state(Some(s), true), s);
        }
    }

    #[test]
    fn a_missing_or_empty_status_is_pending() {
        assert_eq!(scan_state(None, false), "pending");
        assert_eq!(scan_state(Some(""), false), "pending");
        assert!(is_active("pending"));
    }

    #[test]
    fn only_running_and_pending_are_active() {
        for s in ["complete", "failed", "aborted", "interrupted", "weird"] {
            assert!(!is_active(s), "{s} must not be active");
        }
    }

    #[test]
    fn every_state_has_its_pill_and_text_is_escaped() {
        for (state, class) in [
            ("complete", "s-complete"),
            ("running", "s-running"),
            ("pending", "s-pending"),
            ("failed", "s-failed"),
            ("aborted", "s-aborted"),
            ("interrupted", "s-interrupted"),
        ] {
            assert_eq!(
                status_pill(state),
                format!("<span class=\"status-pill {class}\">{state}</span>")
            );
        }
        assert_eq!(
            status_pill("<b>"),
            "<span class=\"status-pill s-pending\">&lt;b&gt;</span>"
        );
        assert_eq!(
            status_pill_html(None),
            "<span class=\"status-pill s-pending\">pending</span>"
        );
    }
}
