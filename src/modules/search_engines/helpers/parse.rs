//! Search-engine helpers — fetch + HTML parse primitives. Self-contained:
//! depends only on `std`, so it needs nothing from the parent helper namespace.

// ─── Fetch + parse ──────────────────────────────────────────────────────────

/// Outcome of a single fetch attempt. Distinguishes "engine responded
/// but was blocked" (worth retrying with alt UA) from "engine is
/// unreachable" (retrying wastes the timeout budget).
pub(in crate::modules::search_engines) enum FetchOutcome {
    Body(String),
    Blocked,
    Unreachable,
}

/// Decode the HTML entities in SERP result markup and percent-encoded redirect
/// hrefs. Thin alias over the single shared decoder in
/// [`crate::util::html::decode_entities`] (named + numeric refs, double-decode
/// safe) so a title/snippet/URL decoded here is byte-identical to one decoded
/// anywhere else in the codebase. Kept as a `pub(super)` name so the many
/// search-engine call sites read in their own vocabulary.
#[inline]
pub(in crate::modules::search_engines) fn decode_html_entities(s: &str) -> String {
    crate::util::html::decode_entities(s)
}

/// Resolve an href into a clean URL, decoding engine-specific redirects.
pub(in crate::modules::search_engines) fn resolve_href(href: &str) -> Option<String> {
    let href = &decode_html_entities(href);

    // DuckDuckGo wraps URLs: //duckduckgo.com/l/?uddg=https%3A%2F%2Fexample.com&rut=...
    if href.contains("uddg=") {
        return extract_url_param(href, "uddg=");
    }

    // Yandex wraps URLs: //yandex.com/clck/jsredir?...&url=https%3A%2F%2Fexample.com&...
    if href.contains("yandex.com/clck") && href.contains("url=") {
        return extract_url_param(href, "url=");
    }

    // Yahoo wraps URLs: /RU=https%3a%2f%2fexample.com/RK=.../RS=...
    if href.contains("/RU=") {
        return href
            .split("/RU=")
            .nth(1)
            .and_then(|rest| rest.split("/R").next())
            .and_then(|encoded| {
                let decoded: String = url::form_urlencoded::parse(encoded.as_bytes())
                    .next()
                    .map_or_else(|| encoded.to_string(), |(k, _)| k.into_owned());
                if decoded.starts_with("http") {
                    Some(decoded)
                } else {
                    None
                }
            });
    }

    // Protocol-relative
    if href.starts_with("//") {
        return Some(format!("https:{href}"));
    }

    // Absolute HTTP(S)
    if href.starts_with("http://") || href.starts_with("https://") {
        return Some(href.to_string());
    }

    None
}

pub(in crate::modules::search_engines) fn extract_url_param(
    href: &str,
    param: &str,
) -> Option<String> {
    href.split(param)
        .nth(1)
        .and_then(|rest| rest.split('&').next())
        .map(|encoded| {
            url::form_urlencoded::parse(encoded.as_bytes())
                .next()
                .map_or_else(|| encoded.to_string(), |(k, _)| k.into_owned())
        })
}

// ─── HTML iteration ─────────────────────────────────────────────────────────

pub(in crate::modules::search_engines) struct HrefIter<'a> {
    remaining: &'a str,
}

impl<'a> HrefIter<'a> {
    pub(in crate::modules::search_engines) fn new(html: &'a str) -> Self {
        Self { remaining: html }
    }
}

impl<'a> Iterator for HrefIter<'a> {
    type Item = &'a str;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let idx = self.remaining.find("href=")?;
            self.remaining = &self.remaining[idx + 5..];

            let quote = match self.remaining.as_bytes().first()? {
                b'"' | b'\'' => self.remaining.as_bytes()[0],
                _ => continue,
            };
            self.remaining = &self.remaining[1..];
            let end = self.remaining.find(quote as char)?;
            let href = &self.remaining[..end];
            self.remaining = &self.remaining[end + 1..];

            if href.is_empty()
                || href.starts_with('#')
                || href.starts_with("javascript:")
                || href.starts_with("mailto:")
                || href.starts_with("tel:")
                || href.starts_with("data:")
            {
                continue;
            }
            return Some(href);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── resolve_href: engine-specific redirect decoding ───────────────────────

    #[test]
    fn resolve_href_decodes_duckduckgo_uddg() {
        let href = "//duckduckgo.com/l/?uddg=https%3A%2F%2Fexample.com%2Fpage&rut=abc";
        assert_eq!(
            resolve_href(href).as_deref(),
            Some("https://example.com/page")
        );
    }

    #[test]
    fn resolve_href_decodes_yandex_clck() {
        let href = "//yandex.com/clck/jsredir?from=x&url=https%3A%2F%2Fexample.com&y=1";
        assert_eq!(resolve_href(href).as_deref(), Some("https://example.com"));
    }

    #[test]
    fn resolve_href_decodes_yahoo_ru() {
        let href = "/RU=https%3a%2f%2fexample.com%2fa/RK=2/RS=signature";
        assert_eq!(resolve_href(href).as_deref(), Some("https://example.com/a"));
    }

    #[test]
    fn resolve_href_yahoo_ru_rejects_non_http_payload() {
        // A decoded payload that isn't http(s) must be dropped, not returned.
        let href = "/RU=javascript%3aalert(1)/RK=2/RS=x";
        assert_eq!(resolve_href(href), None);
    }

    #[test]
    fn resolve_href_passes_protocol_relative_and_absolute() {
        assert_eq!(
            resolve_href("//cdn.example.com/x").as_deref(),
            Some("https://cdn.example.com/x")
        );
        assert_eq!(
            resolve_href("https://example.com").as_deref(),
            Some("https://example.com")
        );
        assert_eq!(
            resolve_href("http://example.com").as_deref(),
            Some("http://example.com")
        );
    }

    #[test]
    fn resolve_href_rejects_relative_and_unknown() {
        assert_eq!(resolve_href("/search?q=x"), None);
        assert_eq!(resolve_href("relative/path"), None);
        assert_eq!(resolve_href(""), None);
    }

    #[test]
    fn resolve_href_decodes_html_entities_before_dispatch() {
        // `&amp;` in the wrapper must decode so the `uddg=`/`&` parsing still works.
        let href = "//duckduckgo.com/l/?uddg=https%3A%2F%2Fexample.com&amp;rut=abc";
        assert_eq!(resolve_href(href).as_deref(), Some("https://example.com"));
    }

    // ── extract_url_param ──────────────────────────────────────────────────────

    #[test]
    fn extract_url_param_stops_at_ampersand() {
        let href = "x?url=https%3A%2F%2Fexample.com&next=foo";
        assert_eq!(
            extract_url_param(href, "url=").as_deref(),
            Some("https://example.com")
        );
    }

    #[test]
    fn extract_url_param_missing_param_is_none() {
        assert_eq!(extract_url_param("x?other=1", "url="), None);
    }

    // ── HrefIter ───────────────────────────────────────────────────────────────

    fn hrefs(html: &str) -> Vec<&str> {
        HrefIter::new(html).collect()
    }

    #[test]
    fn href_iter_extracts_double_and_single_quoted() {
        assert_eq!(
            hrefs(r#"<a href="https://a.com">x</a><a href='https://b.com'>y</a>"#),
            ["https://a.com", "https://b.com"]
        );
    }

    #[test]
    fn href_iter_skips_non_navigational_schemes() {
        let html = r##"
            <a href="#top">a</a>
            <a href="javascript:void(0)">b</a>
            <a href="mailto:x@y.com">c</a>
            <a href="tel:+61400000000">d</a>
            <a href="data:text/plain,hi">e</a>
            <a href="">f</a>
            <a href="https://real.com">g</a>
        "##;
        assert_eq!(hrefs(html), ["https://real.com"]);
    }

    #[test]
    fn href_iter_skips_unquoted_attribute() {
        // Unquoted href value isn't extracted (SERP HTML always quotes); the
        // iterator must not panic or loop, just move past it.
        assert_eq!(
            hrefs(r#"<a href=https://unquoted.com>x</a><a href="https://ok.com">y</a>"#),
            ["https://ok.com"]
        );
    }

    #[test]
    fn href_iter_handles_multibyte_chars_in_value_without_panic() {
        // A non-ASCII path between ASCII quotes: slicing must stay on char
        // boundaries (closing quote is ASCII, so all slice points are valid).
        assert_eq!(
            hrefs(r#"<a href="https://exámple.com/café">x</a>"#),
            ["https://exámple.com/café"]
        );
    }

    #[test]
    fn href_iter_empty_and_no_href_yield_nothing() {
        assert!(hrefs("").is_empty());
        assert!(hrefs("<p>no links here</p>").is_empty());
    }

    #[test]
    fn href_iter_terminates_on_unterminated_quote() {
        // An opening quote with no close must end iteration (find returns None),
        // not spin forever.
        assert!(hrefs(r#"<a href="https://no-close.com>"#).is_empty());
    }
}
