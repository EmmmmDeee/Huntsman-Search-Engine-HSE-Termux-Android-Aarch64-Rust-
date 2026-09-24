//! Light/dark theme: SpiderFoot 4.0's "Dark Mode" switch.
//!
//! Light is the base look (`app.css`'s `:root` tokens), as it is in
//! SpiderFoot 4.0. `<body class="dark-theme">` is the opt-in, chosen with the
//! `#theme-toggle` checkbox in the navbar and persisted in `localStorage`
//! under SpiderFoot's own key and value: `theme` = `"dark-theme"`. Turning
//! the switch off stores `"light-theme"`. That is also the value an earlier
//! HSE console wrote for its light mode, so a choice saved by either console
//! keeps meaning what it meant.

use wasm_bindgen::JsCast;
use wasm_bindgen::prelude::*;

/// The `localStorage` value that turns dark mode on — SpiderFoot's own.
const DARK: &str = "dark-theme";
/// The value stored when the switch is turned off.
const LIGHT: &str = "light-theme";

fn window() -> web_sys::Window {
    web_sys::window().expect("no global `window` — not running in a browser")
}

fn document() -> web_sys::Document {
    window().document().expect("window has no `document`")
}

/// Whether a persisted `theme` value selects dark mode. Only SpiderFoot's
/// `"dark-theme"` does. A missing value, `"light-theme"`, or anything else is
/// the light default.
fn is_dark(stored: Option<&str>) -> bool {
    stored == Some(DARK)
}

/// Re-reads the persisted theme choice and applies it: toggles `<body
/// class="dark-theme">` and sets the `#theme-toggle` checkbox to match.
/// Called once at SPA bootstrap (by `main.js`) and again on every change of
/// the switch (see [`wire_toggle_click`]).
#[wasm_bindgen(js_name = applyTheme)]
pub fn apply_theme() {
    let stored = window()
        .local_storage()
        .ok()
        .flatten()
        .and_then(|s| s.get_item("theme").ok().flatten());
    let dark = is_dark(stored.as_deref());

    let document = document();
    if let Some(body) = document.body() {
        let classes = body.class_list();
        let _ = classes.toggle_with_force("dark-theme", dark);
        // The earlier dark-first console marked its light mode this way.
        // Nothing reads it now; clearing it keeps the two from ever co-existing.
        let _ = classes.remove_1("light-theme");
    }
    if let Some(toggle) = document.get_element_by_id("theme-toggle") {
        // The switch is an `<input type="checkbox">`; `checked` is a DOM
        // property, not an attribute, once the page has loaded.
        let _ = js_sys::Reflect::set(
            &toggle,
            &JsValue::from_str("checked"),
            &JsValue::from_bool(dark),
        );
    }
}

/// Wires the `#theme-toggle` switch: on every change, persists the new state
/// and re-applies it. Runs once, from the crate's `#[wasm_bindgen(start)]`
/// hook (see `lib.rs`).
pub fn wire_toggle_click() {
    let Some(toggle) = document().get_element_by_id("theme-toggle") else {
        return;
    };

    let handler = Closure::<dyn Fn(web_sys::Event)>::new(|event: web_sys::Event| {
        let dark = event
            .target()
            .and_then(|t| js_sys::Reflect::get(&t, &JsValue::from_str("checked")).ok())
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if let Ok(Some(storage)) = window().local_storage() {
            let _ = storage.set_item("theme", if dark { DARK } else { LIGHT });
        }
        apply_theme();
    });

    let target: &web_sys::EventTarget = toggle.unchecked_ref();
    let _ = target.add_event_listener_with_callback("change", handler.as_ref().unchecked_ref());
    // Leaks the closure deliberately: it must outlive this function (the DOM
    // holds the only reference, via the listener) and lives for the page's
    // whole lifetime — the same trade-off `wasm-bindgen`'s own docs describe
    // for a one-time, never-removed top-level listener like this one.
    handler.forget();
}

#[cfg(test)]
mod tests {
    use super::is_dark;

    #[test]
    fn only_spiderfoots_dark_value_selects_dark_mode() {
        assert!(is_dark(Some("dark-theme")));
        // Light is the default, as in SpiderFoot 4.0: nothing saved yet, the
        // switch turned off, or a value neither console writes.
        assert!(!is_dark(None));
        assert!(!is_dark(Some("light-theme")));
        assert!(!is_dark(Some("")));
        assert!(!is_dark(Some("Dark Mode")));
    }
}
