//! A scan's state as the console shows it, and the pill that draws it: one
//! rule and one piece of markup for every view that shows a scan's state.
//!
//! The API's `status` is the persisted field. A scan whose server died while
//! it ran still reads `running` there, and the API marks it with a derived
//! `interrupted: true` on every read (REQ-SCANSTATUS-001): no live process
//! holds it, and nothing will ever finish it. The console treats it as over:
//! no Stop or Abort control, no live stream, no refresh timer, no clock that
//! climbs (REQ-SCANSTATUS-038).

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

/// The class and words of [`status_pill`]'s pill.
fn pill(state: &str, partial: bool) -> (&'static str, &str) {
    match state {
        "complete" if partial => ("s-partial", "partial"),
        "aborted" if partial => ("s-partial", "aborted \u{b7} partial"),
        "complete" => ("s-complete", state),
        "running" => ("s-running", state),
        "failed" => ("s-failed", state),
        "aborted" => ("s-aborted", state),
        "interrupted" => ("s-interrupted", state),
        _ => ("s-pending", state),
    }
}

/// The status pill for a display state. A state with no style of its own
/// keeps its own words in the `pending` style.
///
/// `partial` is the row's derived `finalise_incomplete` (`scan_json`, from
/// `Scan::finalise_incomplete`): a `complete` or `aborted` scan whose finalise
/// recorded a shortfall is partial, as every export of it reads it, so it
/// reads `partial` / `aborted · partial`, the words the live scan log's pill
/// uses, in a warning pill, never the green `complete` (REQ-SCANSTATUS-030).
/// Any other state ignores it.
#[must_use]
pub fn status_pill(state: &str, partial: bool) -> String {
    let (class, words) = pill(state, partial);
    format!(
        "<span class=\"status-pill {class}\">{}</span>",
        escape_html(words)
    )
}

/// The words a scan's pill shows: what the scan list's search box matches.
#[must_use]
pub fn pill_words(state: &str, partial: bool) -> &str {
    pill(state, partial).1
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

/// [`status_pill`] for the JS views: `statusPillHtml(state, partial)`.
/// `helpers.js`'s `statusPill` is this, so the markup exists once.
/// `undefined`, `null` and `""` draw as `pending`; a `partial` that is not
/// `true` is not partial.
#[wasm_bindgen(js_name = statusPillHtml)]
#[must_use]
pub fn status_pill_html(state: Option<String>, partial: Option<bool>) -> String {
    status_pill(scan_state(state.as_deref(), false), partial == Some(true))
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
                status_pill(state, false),
                format!("<span class=\"status-pill {class}\">{state}</span>")
            );
        }
        assert_eq!(
            status_pill("<b>", false),
            "<span class=\"status-pill s-pending\">&lt;b&gt;</span>"
        );
        assert_eq!(
            status_pill_html(None, None),
            "<span class=\"status-pill s-pending\">pending</span>"
        );
        assert_eq!(
            status_pill_html(Some(String::new()), None),
            "<span class=\"status-pill s-pending\">pending</span>"
        );
        assert_eq!(
            status_pill_html(Some("weird".to_string()), None),
            "<span class=\"status-pill s-pending\">weird</span>"
        );
    }

    /// REQ-SCANSTATUS-030: a scan whose finalise was cut short reads partial
    /// on every row view, as its exports and its live log pill do, never the
    /// green `complete`. Only a finished scan can be partial.
    #[test]
    fn a_scan_whose_finalise_was_cut_short_reads_partial() {
        assert_eq!(
            status_pill("complete", true),
            "<span class=\"status-pill s-partial\">partial</span>"
        );
        assert_eq!(
            status_pill("aborted", true),
            "<span class=\"status-pill s-partial\">aborted \u{b7} partial</span>"
        );
        assert_eq!(
            status_pill("aborted", false),
            "<span class=\"status-pill s-aborted\">aborted</span>"
        );
        for state in ["failed", "running", "pending", "interrupted"] {
            assert!(
                !status_pill(state, true).contains("partial"),
                "{state} cannot be partial"
            );
        }
        assert_eq!(
            status_pill_html(Some("complete".to_string()), Some(true)),
            status_pill("complete", true)
        );
        assert_eq!(pill_words("complete", true), "partial");
        assert_eq!(pill_words("interrupted", false), "interrupted");
    }
}
