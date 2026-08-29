//! HTML-escaping shared by every view port under [`crate::scan_info`] (and
//! future top-level views) — one implementation instead of each port
//! re-deriving `src/web/js/helpers.js`'s `esc()` by hand.

/// Escapes `&`, `<`, `>`, `"`, and `'` for safe interpolation into an HTML
/// string. Mirrors `helpers.js`'s `esc()` exactly (same five characters, same
/// replacements, in the same order) so a ported view's output is
/// byte-for-byte identical to what the JS it replaces produced.
pub fn escape_html(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

/// The `<span class="kind-pill k-...">...</span>` badge every view that
/// displays an entity kind uses. `kind` is already the display string (an
/// `EntityKind`'s `Display` output, e.g. `"email"`, `"other:xyz"`, or a
/// server-side field that is already flattened to the same form, e.g.
/// `crate::core::resolve::ResolutionGroup::kind`) — this function only builds
/// the markup, matching `helpers.js`'s `kindPill(kindToStr(k))` split into
/// its two halves (callers already have the string; the
/// object-or-string-shaped `kindToStr` half has no equivalent need here since
/// every Rust caller already holds a real, unambiguous kind value).
pub fn kind_pill(kind: &str) -> String {
    format!(
        "<span class=\"kind-pill k-{k}\">{k}</span>",
        k = escape_html(kind)
    )
}

/// `helpers.js`'s `NET_GROUP_ICON` map: the glyphicon for one of
/// `crate::core::network::GROUPS`'s six keys (`people`, `identifiers`,
/// `aliases`, `affiliations`, `locations`, `infrastructure`) — a closed set
/// server-side (`group_for` is an exhaustive match over `RelationKind`), but
/// `crate::core::leads::Lead::group` carries the same keys as a plain
/// `&'static str` too, so both
/// [`crate::scan_info::network`] and [`crate::scan_info::leads`] need this
/// lookup. Returns `None` for an unrecognized key rather than baking in a
/// fallback: the two JS callers each chose a different one
/// (`glyphicon-link` vs. `glyphicon-flag`), so the fallback stays the
/// caller's choice.
pub fn group_icon(key: &str) -> Option<&'static str> {
    match key {
        "people" => Some("glyphicon-user"),
        "identifiers" => Some("glyphicon-envelope"),
        "aliases" => Some("glyphicon-random"),
        "affiliations" => Some("glyphicon-briefcase"),
        "locations" => Some("glyphicon-map-marker"),
        "infrastructure" => Some("glyphicon-cloud"),
        _ => None,
    }
}

/// `helpers.js`'s `trunc()`: truncates to `n` characters (not bytes) plus an
/// ellipsis when longer, else returned as-is. Promoted from
/// [`crate::scan_info::network`]'s own copy once
/// [`crate::scan_info::browse`] needed the exact same truncation.
pub fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() > n {
        format!("{}\u{2026}", s.chars().take(n).collect::<String>())
    } else {
        s.to_string()
    }
}

/// `helpers.js`'s `extLink()`: an external `http(s)` link wrapped in
/// `<a target="_blank">`, or just the escaped (optionally truncated) text
/// for anything else (`javascript:`/`data:` stay inert). `max_text` mirrors
/// the JS original's optional second parameter: `None` renders the full
/// (escaped) url with no truncation at all, matching a caller that omits
/// the argument entirely.
pub fn ext_link(url: &str, max_text: Option<usize>) -> String {
    let text = escape_html(&max_text.map_or_else(|| url.to_string(), |n| truncate(url, n)));
    let lower = url.to_ascii_lowercase();
    if !lower.starts_with("http://") && !lower.starts_with("https://") {
        return text;
    }
    format!(
        "<a href=\"{}\" target=\"_blank\" rel=\"noopener noreferrer\">{text}</a>",
        escape_html(url)
    )
}

/// `helpers.js`'s `fmtDate()`: `ts*1000` formatted via the JS `Date` object's
/// LOCAL-timezone getters, or an em-dash for a falsy (here: zero) timestamp.
/// Uses [`js_sys::Date`] rather than reimplementing timezone logic in Rust —
/// see `wasm-ui/Cargo.toml`'s `js-sys` dependency comment. Promoted from
/// [`crate::scan_info::info`]'s own copy once [`crate::scan_info::browse`]
/// needed the exact same formatting.
pub fn fmt_date(ts: u64) -> String {
    if ts == 0 {
        return "\u{2014}".to_string();
    }
    #[allow(clippy::cast_precision_loss)]
    let millis = ts as f64 * 1000.0;
    let d = js_sys::Date::new(&wasm_bindgen::JsValue::from_f64(millis));
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        d.get_full_year(),
        d.get_month() + 1,
        d.get_date(),
        d.get_hours(),
        d.get_minutes(),
        d.get_seconds(),
    )
}

/// `helpers.js`'s `statusPill(s)`. The CSS class and the displayed text
/// default independently, exactly as the original's `m[s]||'s-pending'` /
/// `s||'pending'` do: an unrecognised non-empty status still shows its own
/// text (with the fallback class), while a missing/empty one shows the
/// literal text "pending" too. Reused as-is for `crate::views::live`'s
/// `LiveStatus` values (`"running"`/`"completed"`/`"stopped"`, a distinct
/// enum from `ScanStatus`): `"completed"` matches no arm here either, so it
/// falls to the same `s-pending` class with its own text shown — the exact
/// (mildly surprising) behaviour `helpers.js`'s original single `statusPill`
/// already gave every `live.js` call site, faithfully preserved rather than
/// "fixed" by a wider match. Promoted from [`crate::views::scans`]'s own
/// copy once [`crate::views::live`] needed the exact same mapping.
pub fn status_pill(status: Option<&str>) -> String {
    let class = match status {
        Some("complete") => "s-complete",
        Some("running") => "s-running",
        Some("failed") => "s-failed",
        Some("pending") => "s-pending",
        Some("aborted") => "s-aborted",
        _ => "s-pending",
    };
    let text = match status {
        Some(s) if !s.is_empty() => s,
        _ => "pending",
    };
    format!(
        "<span class=\"status-pill {class}\">{}</span>",
        escape_html(text)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_all_five_characters() {
        assert_eq!(
            escape_html(r#"<a href="x">'&'</a>"#),
            "&lt;a href=&quot;x&quot;&gt;&#39;&amp;&#39;&lt;/a&gt;"
        );
    }

    #[test]
    fn leaves_plain_text_untouched() {
        assert_eq!(escape_html("Elina Moreau"), "Elina Moreau");
    }

    #[test]
    fn empty_string_stays_empty() {
        assert_eq!(escape_html(""), "");
    }

    #[test]
    fn kind_pill_wraps_and_escapes() {
        assert_eq!(
            kind_pill("email"),
            "<span class=\"kind-pill k-email\">email</span>"
        );
    }

    #[test]
    fn status_pill_defaults_class_and_text_independently() {
        assert_eq!(
            status_pill(None),
            "<span class=\"status-pill s-pending\">pending</span>"
        );
        assert_eq!(
            status_pill(Some("weird")),
            "<span class=\"status-pill s-pending\">weird</span>"
        );
        assert_eq!(
            status_pill(Some("complete")),
            "<span class=\"status-pill s-complete\">complete</span>"
        );
        // LiveStatus's "completed" (not "complete") matches no arm either —
        // the exact cross-enum quirk this promotion's doc comment preserves.
        assert_eq!(
            status_pill(Some("completed")),
            "<span class=\"status-pill s-pending\">completed</span>"
        );
    }
}
