//! Light/dark theme toggle — port of `src/web/js/theme.js`.
//!
//! Behaviour is unchanged from the JS original: dark is the base look
//! (`app.css`'s `:root` tokens), `.light-theme` on `<body>` is an explicit
//! opt-out applied only when chosen, and the choice persists in
//! `localStorage` under the key `"theme"`.

use wasm_bindgen::JsCast;
use wasm_bindgen::prelude::*;

fn window() -> web_sys::Window {
    web_sys::window().expect("no global `window` — not running in a browser")
}

fn document() -> web_sys::Document {
    window().document().expect("window has no `document`")
}

/// Re-reads the persisted theme choice and applies it: toggles `<body
/// class="light-theme">` and updates `#theme-label`'s text. Called once at
/// SPA bootstrap (by `main.js`, same as the JS original) and again on every
/// toggle click (see [`wire_toggle_click`]).
#[wasm_bindgen(js_name = applyTheme)]
pub fn apply_theme() {
    let light = window()
        .local_storage()
        .ok()
        .flatten()
        .and_then(|s| s.get_item("theme").ok().flatten())
        .is_some_and(|v| v == "light-theme");

    let document = document();
    if let Some(body) = document.body() {
        let _ = body.class_list().toggle_with_force("light-theme", light);
    }
    if let Some(label) = document.get_element_by_id("theme-label") {
        label.set_text_content(Some(if light { "Dark Mode" } else { "Light Mode" }));
    }
}

/// Wires the `#theme-toggle` click handler: flips the persisted choice, then
/// re-applies it. Runs once, from the crate's `#[wasm_bindgen(start)]` hook
/// (see `lib.rs`) — the JS original registered this the same way, as a
/// top-level `DOMContentLoaded` side effect of importing `theme.js`.
pub fn wire_toggle_click() {
    let Some(toggle) = document().get_element_by_id("theme-toggle") else {
        return;
    };

    let handler = Closure::<dyn Fn(web_sys::Event)>::new(|event: web_sys::Event| {
        event.prevent_default();
        let light = document()
            .body()
            .is_some_and(|b| !b.class_list().contains("light-theme"));
        if let Ok(Some(storage)) = window().local_storage() {
            let _ = storage.set_item("theme", if light { "light-theme" } else { "dark-theme" });
        }
        apply_theme();
    });

    let target: &web_sys::EventTarget = toggle.unchecked_ref();
    let _ = target.add_event_listener_with_callback("click", handler.as_ref().unchecked_ref());
    // Leaks the closure deliberately: it must outlive this function (the DOM
    // holds the only reference, via the listener) and lives for the page's
    // whole lifetime — the same trade-off `wasm-bindgen`'s own docs describe
    // for a one-time, never-removed top-level listener like this one.
    handler.forget();
}
