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
