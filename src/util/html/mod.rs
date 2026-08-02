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

/// Scrape an HTML `<table>`'s `<tr>`/`<td>` rows into their plain-text cells —
/// a dependency-free walk (no scraper/html5ever crate, in keeping with the
/// lean Termux build) shared by every module that hand-rolls this exact
/// pattern against a government register's search-results table (`acma_rrl`,
/// `ahpra`, …). Splits on `<tr` / `</tr>`, then within each row on `<td` /
/// `</td>`, running each cell through [`strip_tags_plain`] and trimming it.
/// Only rows with at least `min_cols` cells are kept; the caller applies its
/// own header-row / empty-field filtering and field mapping on top, since
/// those are genuinely per-source. Pure — unit-testable against a captured
/// response without a network round-trip.
#[must_use]
pub fn parse_table_rows(html: &str, min_cols: usize) -> Vec<Vec<String>> {
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

        if cells.len() >= min_cols {
            rows.push(cells);
        }
    }
    rows
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
