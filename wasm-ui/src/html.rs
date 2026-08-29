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
}
