//! Minimal HTML→text helpers shared across modules.
//!
//! Not a full parser; just enough to feed plain text to regex-based
//! extractors (addresses, phones, emails, profile URLs) when the page
//! body is fetched as raw HTML.

use std::sync::OnceLock;

use memchr::memchr;
use regex::Regex;

/// Strip `<script>`/`<style>` blocks, remove remaining tags, and decode
/// the most common HTML entities. Returns plain text suitable for
/// regex extraction.
pub fn strip_html(html: &str) -> String {
    static SCRIPT: OnceLock<Regex> = OnceLock::new();
    static STYLE: OnceLock<Regex> = OnceLock::new();
    static TAG: OnceLock<Regex> = OnceLock::new();
    let script = SCRIPT.get_or_init(|| {
        Regex::new(r"(?is)<script[^>]*>.*?</script>").expect("constant script regex")
    });
    let style = STYLE
        .get_or_init(|| Regex::new(r"(?is)<style[^>]*>.*?</style>").expect("constant style regex"));
    let tag = TAG.get_or_init(|| Regex::new(r"(?s)<[^>]+>").expect("constant html-tag regex"));
    let no_script = script.replace_all(html, " ");
    let no_style = style.replace_all(&no_script, " ");
    let no_tags = tag.replace_all(&no_style, " ");
    decode_entities(&no_tags)
}

/// Strip HTML **tags only** — drop every `<…>` span and keep the text between,
/// with no entity decoding and no `<script>`/`<style>` special-casing. A single
/// left-to-right character scan (an `in_tag` toggle), so it never allocates a
/// regex and is safe on arbitrary bytes.
///
/// This is the deliberately-minimal counterpart to [`strip_html`]: use it for a
/// well-formed table cell whose text is already entity-free (the ACMA register
/// and AHPRA practitioner ArcGIS/HTML tables), where decoding entities or
/// excising script blocks would be wasted work. Reach for [`strip_html`] instead
/// on a full page body that may carry entities or embedded script/style. One
/// definition so the modules that each hand-rolled this exact `in_tag` loop stay
/// in agreement.
///
/// ```
/// use huntsman_search_engine::util::html::strip_tags_plain;
///
/// assert_eq!(strip_tags_plain("<td>Jane <b>Doe</b></td>"), "Jane Doe");
/// assert_eq!(strip_tags_plain("no tags"), "no tags");
/// ```
#[must_use]
pub fn strip_tags_plain(html: &str) -> String {
    let mut out = String::with_capacity(html.len());
    let mut in_tag = false;
    for c in html.chars() {
        match c {
            '<' => in_tag = true,
            '>' => in_tag = false,
            _ if !in_tag => out.push(c),
            _ => {}
        }
    }
    out
}

/// Split an HTML fragment into table rows of trimmed, tag-stripped `<td>` cell
/// text — one inner `Vec` per `<tr>`, in document order.
///
/// A deliberately small, dependency-free scanner (no HTML crate) for the simple
/// server-rendered result tables the AU-register scrapers consume: it walks
/// `<tr>…</tr>` spans and, within each, `<td …>…</td>` spans, running each cell
/// through [`strip_tags_plain`] and trimming. Rows are returned verbatim,
/// including short (`< N` cell) and header rows — each caller applies its own
/// column count and header-drop policy, since those differ per register. `<th>`
/// header cells are intentionally not collected, so a header row yields an empty
/// (dropped-by-the-caller) cell vector, exactly as the hand-rolled copies did.
///
/// One definition so the modules that each hand-rolled this identical `<tr>`/
/// `<td>` walk (`acma_rrl`, `ahpra`) stay in agreement.
///
/// ```
/// use huntsman_search_engine::util::html::table_rows;
///
/// let html = "<table><tr><td>Jane <b>Doe</b></td><td> 42 </td></tr></table>";
/// assert_eq!(table_rows(html), vec![vec!["Jane Doe".to_string(), "42".to_string()]]);
/// ```
#[must_use]
pub fn table_rows(html: &str) -> Vec<Vec<String>> {
    let mut rows = Vec::new();
    let mut remaining = html;
    while let Some(row_start) = remaining.find("<tr") {
        remaining = &remaining[row_start + 3..];
        let Some(row_end) = remaining.find("</tr>") else {
            break;
        };
        let row = &remaining[..row_end];
        remaining = &remaining[row_end + 5..];

        let mut cells = Vec::new();
        let mut r = row;
        while let Some(td_start) = r.find("<td") {
            r = &r[td_start..];
            let Some(td_content_start) = r.find('>') else {
                break;
            };
            r = &r[td_content_start + 1..];
            let Some(td_end) = r.find("</td>") else { break };
            let cell = &r[..td_end];
            cells.push(strip_tags_plain(cell).trim().to_string());
            r = &r[td_end + 5..];
        }
        rows.push(cells);
    }
    rows
}

/// True when `html` looks like an HTML document rather than a JSON/text payload.
///
/// Deliberately conservative — it requires an actual document opener at the very
/// start (`<!doctype …` or `<html …`), not merely an angle bracket somewhere.
/// A JSON error body that happens to quote markup in a message field must keep
/// its verbatim treatment, so "contains `<html`" would be the wrong test.
#[must_use]
pub fn looks_like_document(html: &str) -> bool {
    // `find_ascii_ci(…) == Some(0)` rather than `to_lowercase().starts_with(…)`:
    // allocation-free, and it keeps every offset in this module derived from the
    // original string (see [`title`] for why that matters).
    use crate::util::str_util::find_ascii_ci;
    let head = html.trim_start();
    find_ascii_ci(head, "<!doctype html") == Some(0) || find_ascii_ci(head, "<html") == Some(0)
}

/// The document's `<title>` text — decoded and whitespace-collapsed — or `None`
/// when there is no non-empty title.
///
/// For a CDN/WAF/origin error page the title is by far the most informative
/// line in the document: Cloudflare answers an unreachable origin with
/// `<title>example.com | 523: Origin is unreachable</title>` while the first
/// several hundred characters of the same page are doctype and IE conditional
/// comments carrying no diagnostic content at all.
#[must_use]
pub fn title(html: &str) -> Option<String> {
    // `find_ascii_ci`, NOT `to_lowercase().find(…)`: `to_lowercase` is not
    // byte-length-preserving (`İ` → `i̇`, `ẞ` → `ß`), so an offset taken from a
    // lowercased copy can land mid-codepoint when used to slice the original and
    // panic. Error bodies are fully upstream-controlled, so that input is
    // reachable by anything an upstream chooses to return. See the helper's own
    // docs — it exists for exactly this panic class.
    use crate::util::str_util::find_ascii_ci;
    let open = find_ascii_ci(html, "<title")?;
    // Skip any attributes on the tag itself.
    let after_open = open + html[open..].find('>')? + 1;
    let close = after_open + find_ascii_ci(&html[after_open..], "</title>")?;
    let text = collapse_whitespace(&decode_entities(&html[after_open..close]));
    (!text.is_empty()).then_some(text)
}

/// Collapse every run of ASCII whitespace to a single space and trim the ends.
///
/// Tag-stripped markup is mostly inter-element whitespace, so the raw output of
/// [`strip_html`] is unusable in a one-line message without this.
#[must_use]
pub fn collapse_whitespace(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Decode HTML entities in a single left-to-right pass: the named entities real
/// markup uses (`&amp; &lt; &gt; &quot; &apos; &nbsp;`, plus the common
/// typography/symbol set — see [`decode_one_entity`]) and ANY numeric character
/// reference — decimal `&#8217;` or hex `&#x2019;` (curly quotes, en/em dashes,
/// nbsp). Each `&…;` is consumed exactly once, so the escaped text `&amp;lt;`
/// round-trips to the literal `&lt;` (never double-decodes to `<`), and a
/// bare/unknown/malformed `&…;` is emitted verbatim. The single, shared decoder
/// for the whole codebase — `search_engines` delegates here so a title decoded in
/// a module matches one decoded in core/util.
pub fn decode_entities(s: &str) -> String {
    if memchr(b'&', s.as_bytes()).is_none() {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(amp) = memchr(b'&', rest.as_bytes()) {
        out.push_str(&rest[..amp]);
        let inner = &rest[amp + 1..]; // text after the '&'
        // `&` and `;` are single-byte ASCII so their byte offsets are valid char boundaries.
        if let Some(semi) = memchr(b';', inner.as_bytes())
            && semi <= 10
            && let Some(ch) = decode_one_entity(&inner[..semi])
        {
            out.push(ch);
            rest = &inner[semi + 1..];
            continue;
        }
        out.push('&');
        rest = inner;
    }
    out.push_str(rest);
    out
}

/// Decode a single entity body (text between `&` and `;`) to its character, or
/// `None` if unrecognised/malformed. Named set covers real markup — the base
/// XML five plus the "smart typography" and common-symbol entities real sites
/// use in page titles/breadcrumbs (`&rsaquo;`/`&raquo;` breadcrumb separators,
/// curly quotes, dashes, `&hellip;`, `&copy;`/`&reg;`/`&trade;`, currency
/// signs) — a real scraped title (`au.zenbu.org &rsaquo; entry &rsaquo; …`)
/// leaked the raw `&rsaquo;` into decoded output before this was added, since
/// it has no numeric fallback (real markup used the named form, not
/// `&#8250;`). Named entity names ARE case-sensitive per the HTML5 spec
/// (`&Dagger;` and `&dagger;` are different characters), matched as such here.
/// Numeric references (`#8217`, `#x2019`) are decoded generically for anything
/// not in this table.
fn decode_one_entity(body: &str) -> Option<char> {
    match body {
        "amp" => Some('&'),
        "lt" => Some('<'),
        "gt" => Some('>'),
        "quot" => Some('"'),
        "apos" => Some('\''),
        // Normalise NBSP to a regular space so decoded text stays word-splittable.
        "nbsp" => Some(' '),
        // Smart-quote / dash / ellipsis typography — pervasive in real page
        // titles and body text (news sites, blogs, breadcrumbs).
        "ldquo" => Some('\u{201C}'),  // “
        "rdquo" => Some('\u{201D}'),  // ”
        "lsquo" => Some('\u{2018}'),  // ‘
        "rsquo" => Some('\u{2019}'),  // ’
        "mdash" => Some('\u{2014}'),  // —
        "ndash" => Some('\u{2013}'),  // –
        "hellip" => Some('\u{2026}'), // …
        // Angle-quote breadcrumb separators (`Home &raquo; Products …`) and
        // guillemets — the exact gap a real scraped title hit (see doc above).
        "laquo" => Some('\u{00AB}'),  // «
        "raquo" => Some('\u{00BB}'),  // »
        "lsaquo" => Some('\u{2039}'), // ‹
        "rsaquo" => Some('\u{203A}'), // ›
        // Common symbols that turn up in titles/footers (copyright notices,
        // measurements, bullet lists).
        "copy" => Some('\u{00A9}'),   // ©
        "reg" => Some('\u{00AE}'),    // ®
        "trade" => Some('\u{2122}'),  // ™
        "deg" => Some('\u{00B0}'),    // °
        "plusmn" => Some('\u{00B1}'), // ±
        "times" => Some('\u{00D7}'),  // ×
        "divide" => Some('\u{00F7}'), // ÷
        "middot" => Some('\u{00B7}'), // ·
        "bull" => Some('\u{2022}'),   // •
        "sect" => Some('\u{00A7}'),   // §
        "para" => Some('\u{00B6}'),   // ¶
        "dagger" => Some('\u{2020}'), // †
        "Dagger" => Some('\u{2021}'), // ‡
        "euro" => Some('\u{20AC}'),   // €
        "pound" => Some('\u{00A3}'),  // £
        "cent" => Some('\u{00A2}'),   // ¢
        "yen" => Some('\u{00A5}'),    // ¥
        _ => {
            let num = body.strip_prefix('#')?;
            let cp = match num.strip_prefix(['x', 'X']) {
                Some(hex) => u32::from_str_radix(hex, 16).ok()?,
                None => num.parse::<u32>().ok()?,
            };
            char::from_u32(cp)
        }
    }
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
