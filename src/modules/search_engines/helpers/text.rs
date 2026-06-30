//! Search-engine helpers — text extraction and cleaning.
//!
//! Reaches the other helper groups and shared imports through `use super::*`.

use super::*;
// Canonical char-boundary primitives live in the shared util layer so every
// module that slices scraped HTML at an arithmetic offset reaches for the same
// total helper instead of re-rolling (or partially guarding) its own.
use crate::util::str_util::{ceil_char_boundary, floor_char_boundary};

pub(in crate::modules::search_engines) fn extract_anchor_text(
    html: &str,
    href: &str,
    max_len: usize,
) -> String {
    let search_dq = format!("href=\"{href}\"");
    let search_sq = format!("href='{href}'");
    let pos = match html.find(&search_dq).or_else(|| html.find(&search_sq)) {
        Some(p) => p,
        None => return String::new(),
    };
    let after_href = &html[pos..];
    let gt = match after_href.find('>') {
        Some(g) => pos + g + 1,
        None => return String::new(),
    };
    let rest = &html[gt..];
    let end_tag = rest.find("</a>").or_else(|| rest.find("</A>"));
    let end = match end_tag {
        Some(e) => gt + e,
        None => return String::new(),
    };
    strip_tags(&html[gt..end], max_len)
}

pub(in crate::modules::search_engines) fn extract_surrounding_text(
    html: &str,
    anchor: &str,
    max_len: usize,
) -> String {
    let pos = match html.find(anchor) {
        Some(p) => p,
        None => return String::new(),
    };
    let start = floor_char_boundary(html, pos.saturating_sub(300));
    let end = ceil_char_boundary(html, (pos + anchor.len() + 300).min(html.len()));
    strip_tags(&html[start..end], max_len)
}

pub(in crate::modules::search_engines) fn extract_snippet_near(
    html: &str,
    anchor: &str,
    max_len: usize,
) -> String {
    let raw = match html.find(anchor) {
        Some(p) => p + anchor.len(),
        None => return String::new(),
    };
    let pos = ceil_char_boundary(html, raw);
    // If the anchor match lands INSIDE an open tag — a SERP href URL inside
    // `<a href="URL" …>` — the next markup char is that tag's own `>`; advance
    // past it so strip_tags doesn't begin mid-tag and dump the remaining
    // attributes (rel / target / aria-label / data-testid / class) as snippet
    // text. But when the anchor is plain text (the next markup char is `<`, a new
    // tag), the text right after it is real snippet content and must be kept.
    let rest = &html[pos..];
    let pos = match (rest.find('<'), rest.find('>')) {
        (Some(lt), Some(gt)) if gt < lt => ceil_char_boundary(html, pos + gt + 1),
        (None, Some(gt)) => ceil_char_boundary(html, pos + gt + 1),
        _ => pos,
    };
    let end = ceil_char_boundary(html, (pos + 1600).min(html.len()));
    let raw_text = strip_tags(&html[pos..end], max_len);
    clean_snippet(&raw_text)
}

pub(in crate::modules::search_engines) fn clean_snippet(s: &str) -> String {
    let mut out = s
        .replace("\\\"", "")
        .replace("\\n", " ")
        .replace("\\t", " ");
    while out.contains("  ") {
        out = out.replace("  ", " ");
    }
    // Remove Bing-style SERP ID artifacts: h="ID=SERP,1234.5"
    if let Some(start) = out.find("h=\"ID=SERP")
        && let Some(end) = out[start..].find('"').and_then(|first_q| {
            out[start + first_q + 1..]
                .find('"')
                .map(|second_q| start + first_q + 1 + second_q + 1)
        })
    {
        out = format!("{}{}", &out[..start], &out[end..]);
    }
    out.trim().to_string()
}

/// Strip HTML tags to plain text, collapsing whitespace, then decode the HTML
/// entities that survive in the text (`&amp;`, `&#39;`, `&quot;`, …). Decoding
/// happens AFTER tag removal — never before — so an encoded `&lt;`/`&gt;` in the
/// page text becomes a literal `<`/`>` in the output instead of being mistaken
/// for markup and dropped. Without this, titles/snippets reached the user as
/// raw `Smith &amp; Sons — O&#39;Brien`, which looks garbled and unverifiable.
pub(in crate::modules::search_engines) fn strip_tags(html: &str, max_len: usize) -> String {
    // Remove inline subtrees that never carry visible result text but DO contain
    // markup or raw data — an inline `<svg>` icon's `d="…"` path, `<style>`,
    // `<script>`. A stray `>` inside such a block (common in SVG path data)
    // desynchronises the tag scanner below and leaks the block's raw bytes
    // (`…5.09083Z" fill="#6573ff"`) into the title/snippet.
    let cleaned = strip_inline_blocks(html);
    let mut out = String::with_capacity(max_len);
    let mut in_tag = false;
    for c in cleaned.chars() {
        if out.len() >= max_len {
            break;
        }
        match c {
            '<' => {
                // A tag opening is a soft word boundary so adjacent elements
                // (`</h3><span>`) do not fuse into "Facebookhttps…". The same
                // `!ends_with(' ') && !is_empty()` guards used for whitespace
                // prevent a leading or doubled space.
                if !in_tag && !out.is_empty() && !out.ends_with(' ') {
                    out.push(' ');
                }
                in_tag = true;
            }
            '>' => in_tag = false,
            _ if !in_tag => {
                if c.is_whitespace() {
                    if !out.ends_with(' ') && !out.is_empty() {
                        out.push(' ');
                    }
                } else {
                    out.push(c);
                }
            }
            _ => {}
        }
    }
    decode_html_entities(out.trim())
}

/// Remove inline `<svg>` / `<style>` / `<script>` subtrees wholesale, replacing
/// each with a single space (a word boundary). Case-insensitive; an unclosed
/// block is dropped to end-of-string. These elements carry markup or raw data,
/// never the visible result text a title/snippet wants, so dropping them before
/// the tag scanner runs is both correct and what stops their stray `>`
/// characters from corrupting the output.
fn strip_inline_blocks(html: &str) -> String {
    let lower0 = html.to_ascii_lowercase();
    if !(lower0.contains("<svg") || lower0.contains("<style") || lower0.contains("<script")) {
        return html.to_string();
    }
    let mut s = html.to_string();
    for tag in ["svg", "style", "script"] {
        let open = format!("<{tag}");
        let close = format!("</{tag}>");
        loop {
            let lower = s.to_ascii_lowercase();
            let Some(start) = lower.find(&open) else {
                break;
            };
            let end = match lower[start..].find(&close) {
                Some(rel) => start + rel + close.len(),
                None => s.len(),
            };
            s.replace_range(start..end, " ");
        }
    }
    s
}

/// Extract the most relevant sentence fragment from a snippet by
/// finding the clause that overlaps most with the query terms.
pub(in crate::modules::search_engines) fn extract_key_phrase(snippet: &str, query: &str) -> String {
    if snippet.len() < 10 {
        return String::new();
    }
    let query_words: HashSet<String> = query
        .to_lowercase()
        .split(|c: char| !c.is_alphanumeric())
        .filter(|w| w.len() >= 3)
        .map(String::from)
        .collect();
    if query_words.is_empty() {
        return String::new();
    }

    let mut best = "";
    let mut best_score = 0usize;
    for clause in snippet.split(['.', '!', '?', '|']) {
        let clause = clause.trim();
        if clause.len() < 8 || clause.len() > 200 {
            continue;
        }
        let score = clause
            .to_lowercase()
            .split(|c: char| !c.is_alphanumeric())
            .filter(|w| query_words.contains(*w))
            .count();
        if score > best_score {
            best_score = score;
            best = clause;
        }
    }
    if best_score >= 1 {
        best.to_string()
    } else {
        String::new()
    }
}

/// Semantic similarity between two strings using character bigram
/// overlap (Dice coefficient). Returns 0.0–1.0.
///
/// The intersection is over **multisets**: a bigram that occurs `m` times in
/// `a` and `n` times in `b` contributes `min(m, n)` matches, not `m`. The naive
/// "is this bigram present in `b`?" count overcounts whenever a bigram repeats
/// more often in `a` than in `b` (e.g. `"aaaa"` vs `"aaa"`), which pushed the
/// score above 1.0 and falsely inflated the similarity of repetitive handles —
/// `score_username` then promoted unrelated usernames to PROBABLE on that
/// inflated score. Multiset intersection keeps the result in `[0.0, 1.0]`.
pub(in crate::modules::search_engines) fn bigram_similarity(a: &str, b: &str) -> f64 {
    fn bigrams(s: &str) -> Vec<(char, char)> {
        let chars: Vec<char> = s.to_lowercase().chars().collect();
        chars.windows(2).map(|w| (w[0], w[1])).collect()
    }
    let ba = bigrams(a);
    let bb = bigrams(b);
    if ba.is_empty() || bb.is_empty() {
        return 0.0;
    }
    // Multiset intersection: count each shared bigram by the lower of its two
    // multiplicities. Build a frequency map of `b`'s bigrams, then consume one
    // unit of credit per matching bigram in `a`.
    let mut bb_freq: std::collections::HashMap<(char, char), usize> =
        std::collections::HashMap::new();
    for bg in &bb {
        *bb_freq.entry(*bg).or_insert(0) += 1;
    }
    let mut matches = 0usize;
    for bg in &ba {
        if let Some(n) = bb_freq.get_mut(bg)
            && *n > 0
        {
            *n -= 1;
            matches += 1;
        }
    }
    (2 * matches) as f64 / (ba.len() + bb.len()) as f64
}
