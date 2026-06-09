//! Search-engine helpers — text extraction and cleaning.
//!
//! Reaches the other helper groups and shared imports through `use super::*`.

use super::*;

pub(in crate::modules::search_engines) fn floor_char_boundary(s: &str, mut i: usize) -> usize {
    if i >= s.len() {
        return s.len();
    }
    while i > 0 && !s.is_char_boundary(i) {
        i -= 1;
    }
    i
}

pub(in crate::modules::search_engines) fn ceil_char_boundary(s: &str, mut i: usize) -> usize {
    if i >= s.len() {
        return s.len();
    }
    while i < s.len() && !s.is_char_boundary(i) {
        i += 1;
    }
    i
}

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
    let mut out = String::with_capacity(max_len);
    let mut in_tag = false;
    for c in html.chars() {
        if out.len() >= max_len {
            break;
        }
        match c {
            '<' => in_tag = true,
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
    let matches = ba.iter().filter(|bg| bb.contains(bg)).count();
    (2 * matches) as f64 / (ba.len() + bb.len()) as f64
}

pub(in crate::modules::search_engines) fn is_email_local_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'.' || b == b'-' || b == b'_' || b == b'+'
}

pub(in crate::modules::search_engines) fn is_domain_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'.' || b == b'-'
}
