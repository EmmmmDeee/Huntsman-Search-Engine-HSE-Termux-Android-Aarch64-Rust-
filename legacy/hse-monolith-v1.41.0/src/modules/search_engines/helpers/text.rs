//! Search-engine helpers — text extraction and cleaning.
//!
//! Reaches the other helper groups and shared imports through `use super::*`.

use std::borrow::Cow;

use super::*;
// Canonical char-boundary primitives live in the shared util layer so every
// module that slices scraped HTML at an arithmetic offset reaches for the same
// total helper instead of re-rolling (or partially guarding) its own.
// `find_ascii_ci` is the zero-alloc, NEON-accelerated ASCII-case-insensitive
// substring scanner used to guard the inline-block strip without a lowercased copy.
use crate::util::str_util::{ceil_char_boundary, find_ascii_ci, floor_char_boundary};

pub(in crate::modules::search_engines) fn extract_anchor_text(
    html: &str,
    href: &str,
    max_len: usize,
) -> String {
    let search_dq = format!("href=\"{href}\"");
    let search_sq = format!("href='{href}'");
    // A result's own URL commonly appears in MULTIPLE `<a href="…">` occurrences
    // within the same result card — an icon-only "favicon-link" wrapper first
    // (no visible text at all), then a short site-name/display-URL anchor, then
    // the actual titled link last (a real Startpage capture,
    // `fetch/testdata/startpage_kylo4kylo.html`, has exactly this 4-deep shape
    // for every result). Stopping at the FIRST occurrence — as this function
    // used to — hits the textless icon wrapper and returns empty, forcing the
    // caller to fall back to `extract_surrounding_text`'s fixed-width window,
    // which grabs whatever visible text happens to sit nearby instead: on the
    // real capture that was either nothing (an empty title) or, for 3 of the
    // 4 results, the PRECEDING card's own "Visit in Anonymous View" proxy-link
    // label — silently corrupting the title with unrelated chrome text either
    // way. Walking every occurrence and keeping the LAST one with actual
    // visible text recovers the real title: the observed document order
    // across engines is chrome-first, full-title-last, so a later non-empty
    // occurrence is always at least as trustworthy as an earlier one, and the
    // overwhelmingly common single-occurrence case (href appears exactly
    // once) is unaffected — the loop still finds and returns that one match.
    // Two accumulators. `best` is the last-non-empty whole-anchor text (the
    // engine-agnostic fallback that already served Bing/Startpage correctly).
    // `titled` is the FIRST occurrence that is unambiguously the *title* rather
    // than the snippet/chrome — set from a title node inside the anchor (Brave)
    // or a title-class anchor tag (DDG). When present it wins, because the
    // last-non-empty heuristic backfires on two real captures:
    //   * DuckDuckGo cards emit result__a (title) / result__url / result__snippet
    //     for one href, so "last" grabbed the SNIPPET as the title.
    //   * Brave wraps the whole card header (site-name + display-URL + breadcrumb
    //     + the title node) in one anchor, so the whole-anchor strip concatenated
    //     "YouTube youtube.com › @kylo4k Kylo - YouTube" instead of "Kylo -
    //     YouTube".
    // A title-less engine leaves `titled` None and keeps the `best` fallback,
    // so nothing regresses.
    let mut best = String::new();
    let mut titled: Option<String> = None;
    let mut search_from = 0usize;
    while search_from < html.len() {
        let pos_dq = html[search_from..]
            .find(&search_dq)
            .map(|p| p + search_from);
        let pos_sq = html[search_from..]
            .find(&search_sq)
            .map(|p| p + search_from);
        let Some(pos) = (match (pos_dq, pos_sq) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (Some(a), None) | (None, Some(a)) => Some(a),
            (None, None) => None,
        }) else {
            break;
        };
        let after_href = &html[pos..];
        let Some(g) = after_href.find('>') else {
            break;
        };
        let gt = pos + g + 1;
        let rest = &html[gt..];
        let Some(e) = rest.find("</a>").or_else(|| rest.find("</A>")) else {
            break;
        };
        let end = gt + e;
        let inner = &html[gt..end];
        let text = strip_tags(inner, max_len);
        let has_text = !text.trim().is_empty();

        if titled.is_none() {
            // Brave-style: a dedicated title node inside the anchor — extract
            // ONLY it, dropping the surrounding chrome the anchor also wraps.
            if let Some(t) = title_node_text(inner, max_len) {
                titled = Some(t);
            } else if has_text {
                // DDG-style: the anchor tag itself is the title link (result__a),
                // so its whole visible text is the clean title.
                let tag_start = html[..pos].rfind('<').unwrap_or(pos);
                if is_title_anchor(&html[tag_start..gt]) {
                    titled = Some(text.clone());
                }
            }
        }
        if has_text {
            best = text;
        }
        // `gt > pos` always (`find('>')` returns `g >= 0`), so this guarantees
        // forward progress and the loop terminates.
        search_from = gt;
    }
    titled.unwrap_or(best)
}

/// The quoted value of an opening tag's `class` attribute (`class="a b c"` →
/// `a b c`), or `None`. Matches the `class=` attribute specifically so a
/// separate `title="…"` HTML attribute (Brave puts one on its title `<div>`)
/// can't be mistaken for a title *class*. Pure.
fn class_value(open_tag: &str) -> Option<&str> {
    for q in ['"', '\''] {
        let needle = format!("class={q}");
        if let Some(p) = open_tag.find(&needle) {
            let rest = &open_tag[p + needle.len()..];
            if let Some(end) = rest.find(q) {
                return Some(&rest[..end]);
            }
        }
    }
    None
}

/// True if `open_tag` (a full `<a …>` opening tag) is a search engine's title
/// *link* — its class contains `result__a` (DuckDuckGo) or `result-title`
/// (Startpage). Such an anchor's whole visible text IS the title.
fn is_title_anchor(open_tag: &str) -> bool {
    class_value(open_tag).is_some_and(|c| {
        find_ascii_ci(c, "result__a").is_some() || find_ascii_ci(c, "result-title").is_some()
    })
}

/// If `inner` (an anchor's inner HTML) contains a dedicated title node — a
/// leaf tag whose `class` contains `title` (Brave `title search-snippet-title`,
/// Startpage `wgl-title`) or a heading `<h1..h4>` — return just that node's
/// stripped text. Isolates the real title from surrounding breadcrumb/site-name
/// chrome the whole anchor may also wrap. `None` when no such node exists, so
/// the caller keeps its whole-anchor fallback. Bing is unaffected: its title
/// `<h2>` wraps the anchor (it is not *inside* the anchor), so nothing here
/// matches and the fallback still yields Bing's correct title. Pure.
fn title_node_text(inner: &str, max_len: usize) -> Option<String> {
    let mut i = 0usize;
    while let Some(rel) = inner[i..].find('<') {
        let lt = i + rel;
        let after = &inner[lt..];
        if after.starts_with("</") {
            i = lt + 2;
            continue;
        }
        let Some(gt_rel) = after.find('>') else {
            break;
        };
        let open_tag = &after[..gt_rel]; // "<div class=…" (no '>')
        let content_start = lt + gt_rel + 1;
        // Tag name: between '<' and the first whitespace / '/'.
        let name_end = open_tag[1..]
            .find(|c: char| c.is_whitespace() || c == '/')
            .map_or(open_tag.len(), |p| 1 + p);
        let name = &open_tag[1..name_end];
        let is_heading = matches!(
            name.to_ascii_lowercase().as_str(),
            "h1" | "h2" | "h3" | "h4"
        );
        let is_title_class =
            class_value(open_tag).is_some_and(|c| find_ascii_ci(c, "title").is_some());
        if is_heading || is_title_class {
            // Leaf node: text up to the next '<' (Brave/Startpage title nodes
            // are leaves). `strip_tags` also defangs any stray inline markup.
            let content = &inner[content_start..];
            let text_end = content.find('<').map_or(inner.len(), |p| content_start + p);
            let text = strip_tags(&inner[content_start..text_end], max_len);
            if !text.trim().is_empty() {
                return Some(text);
            }
        }
        i = content_start;
    }
    None
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
    let end = ceil_char_boundary(html, (pos + anchor.len() + 300).min(html.len()));
    let start = floor_char_boundary(html, pos.saturating_sub(300));
    let start = floor_char_boundary(html, skip_straddling_inline_block(html, start).min(end));
    let start = floor_char_boundary(html, skip_straddling_tag_attrs(html, start).min(end));
    strip_tags(&html[start..end], max_len)
}

/// Bounded backward lookback (bytes) when checking whether a text-extraction
/// window's start falls inside an inline `<svg>`/`<style>`/`<script>` block
/// opened earlier in the page — generous for any realistic single icon/style/
/// script block, without scanning the whole document backward.
const STRADDLE_LOOKBACK: usize = 4096;

/// If `pos` sits inside an inline `<svg>`/`<style>`/`<script>` block that opens
/// within [`STRADDLE_LOOKBACK`] bytes before `pos` and has no matching close tag
/// before `pos`, returns the byte offset just past that block's close tag (or
/// `html.len()` if it is never closed) — the safe boundary a text-extraction
/// window must start at instead. Returns `pos` unchanged when nothing straddles
/// it.
///
/// [`strip_inline_blocks`] only recognises a complete `<tag>…</tag>` pair fully
/// contained in the slice it is given. A fixed-size ±300-char window (like
/// [`extract_surrounding_text`]'s) whose start lands strictly inside such a
/// block — the block's own opening tag sits behind the window's left edge, so
/// the local scan never sees it — lets the block's raw attribute/path data
/// (`d="M20.376 0H3.624…"`, `clip-rule="evenodd"`) leak straight through
/// `strip_tags` as if it were visible text. A real Swisscows SERP capture
/// (`fetch/testdata/swisscows_kylo4kylo.html`) demonstrated exactly this: an
/// icon-only social link's title fell back to this window, which began mid-way
/// through the PRECEDING icon's `<svg><path d="…">` block, and that block's raw
/// path coordinates leaked into the extracted text as if they were a title.
///
/// Walks `[lookback, pos)` once, left to right, alternating between "outside a
/// block" (looking for the next `<svg`/`<style`/`<script`, whichever comes
/// first) and "inside a block" (looking for that specific tag's own close) —
/// a single linear pass threads correctly through any sequence of complete,
/// back-to-back blocks before `pos` (exactly what the real capture has: one
/// icon's closed `</svg>` immediately followed by the next icon's `<svg>`),
/// rather than a per-tag-type scan that could mis-pick a closed block over an
/// still-open earlier one.
fn skip_straddling_inline_block(html: &str, pos: usize) -> usize {
    let lookback = floor_char_boundary(html, pos.saturating_sub(STRADDLE_LOOKBACK));
    let mut cursor = lookback;
    loop {
        let mut next_open: Option<(usize, &'static str)> = None;
        for (open, close) in [
            ("<svg", "</svg>"),
            ("<style", "</style>"),
            ("<script", "</script>"),
        ] {
            if let Some(rel) = find_ascii_ci(&html[cursor..pos], open) {
                let abs = cursor + rel;
                if next_open.is_none_or(|(p, _)| abs < p) {
                    next_open = Some((abs, close));
                }
            }
        }
        let Some((open_pos, close_tag)) = next_open else {
            return pos; // no more open tags before `pos` — not inside a block
        };
        match find_ascii_ci(&html[open_pos..pos], close_tag) {
            Some(rel) => cursor = open_pos + rel + close_tag.len(), // closed before pos, keep scanning
            None => {
                // Unclosed before `pos` — `pos` is inside THIS block.
                return match find_ascii_ci(&html[open_pos..], close_tag) {
                    Some(rel2) => open_pos + rel2 + close_tag.len(),
                    None => html.len(),
                };
            }
        }
    }
}

/// If `pos` sits inside SOME tag's `<…>` span — the nearest `<` within
/// [`STRADDLE_LOOKBACK`] before `pos` has no real (quote-aware) `>` before
/// `pos` — returns the byte offset just past that tag's own closing `>`
/// instead. Unlike [`skip_straddling_inline_block`] (svg/style/script, whose
/// BODY must also be skipped), a void/self-closing element like `<img>` has no
/// body: skipping past its own `>` is sufficient.
///
/// A long attribute value — Brave's favicon `<img src="data:image/…;base64,
/// <hundreds of chars>" loading="lazy" onerror="…"/>` — can easily exceed the
/// ±300-char `extract_surrounding_text` window. When the window's start lands
/// mid-attribute, `strip_tags`'s `in_tag` state starts FALSE (it never saw the
/// truncated-away `<img`), so it treats the base64/attribute text as ordinary
/// visible content. A real Brave capture demonstrated exactly this: an
/// icon-only result with no title text fell back to this window, which began
/// mid-way through the PRECEDING result's favicon `<img>` tag, and its raw
/// base64 `src` leaked into the extracted text as if it were the title.
///
/// Single quote-aware forward pass from the tag's own `<`, mirroring
/// `strip_tags`'s own `in_tag`/`attr_quote` state machine so the two can never
/// disagree about where a tag really ends.
fn skip_straddling_tag_attrs(html: &str, pos: usize) -> usize {
    let lookback = floor_char_boundary(html, pos.saturating_sub(STRADDLE_LOOKBACK));
    let Some(open_rel) = html[lookback..pos].rfind('<') else {
        return pos;
    };
    let tag_start = lookback + open_rel;
    let mut attr_quote: Option<char> = None;
    let mut idx = tag_start + 1;
    for c in html[tag_start + 1..].chars() {
        match attr_quote {
            Some(q) if c == q => attr_quote = None,
            Some(_) => {}
            None if c == '"' || c == '\'' => attr_quote = Some(c),
            None if c == '>' => {
                // The tag's real close: before `pos` means it closed cleanly
                // and `pos` sits outside it; at-or-after `pos` means `pos`
                // fell inside the tag's own span — resume just past this `>`.
                return if idx < pos { pos } else { idx + c.len_utf8() };
            }
            None => {}
        }
        idx += c.len_utf8();
    }
    html.len()
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
    let out = s
        .replace("\\\"", "")
        .replace("\\n", " ")
        .replace("\\t", " ");
    // Collapse every run of ASCII spaces to one in a SINGLE pass. The former
    // `while out.contains("  ") { out = out.replace("  ", " ") }` reallocated the
    // whole string and re-scanned it on each pass — O(k·len) work and O(k)
    // throwaway allocations for a run of k spaces. This is O(len) with one
    // allocation and yields the identical fixpoint (no two adjacent spaces), and
    // like the original touches only `' '`, leaving other whitespace intact.
    let mut out = {
        let mut collapsed = String::with_capacity(out.len());
        let mut prev_space = false;
        for c in out.chars() {
            if c == ' ' {
                if !prev_space {
                    collapsed.push(' ');
                }
                prev_space = true;
            } else {
                collapsed.push(c);
                prev_space = false;
            }
        }
        collapsed
    };
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
    // Track the quote char of an attribute value while inside a tag, so a '>'
    // that appears INSIDE a quoted attribute — a JS `onerror="a=>b"`, a data URI,
    // a URL query, a `srcset` — does not prematurely close the tag and leak the
    // rest of it as visible text. This was dumping Brave's favicon `<img
    // src="…base64…" loading="lazy" onerror="…"/>` base64 `src` straight into the
    // result `page_title`. The same class of stray-'>' desync that
    // `strip_inline_blocks` already defends svg/style/script (and now comments)
    // against, handled here for every other tag.
    let mut attr_quote: Option<char> = None;
    for c in cleaned.chars() {
        if out.len() >= max_len {
            break;
        }
        if in_tag {
            match attr_quote {
                Some(q) if c == q => attr_quote = None,
                Some(_) => {}
                None => match c {
                    '"' | '\'' => attr_quote = Some(c),
                    '>' => in_tag = false,
                    _ => {}
                },
            }
            continue;
        }
        match c {
            '<' => {
                // A tag opening is a soft word boundary so adjacent elements
                // (`</h3><span>`) do not fuse into "Facebookhttps…". The same
                // `!ends_with(' ') && !is_empty()` guards used for whitespace
                // prevent a leading or doubled space.
                if !out.is_empty() && !out.ends_with(' ') {
                    out.push(' ');
                }
                in_tag = true;
            }
            // A '>' outside any tag is stray markup, never visible text — drop it
            // (the previous scanner never emitted a bare '>' either).
            '>' => {}
            _ if c.is_whitespace() => {
                if !out.ends_with(' ') && !out.is_empty() {
                    out.push(' ');
                }
            }
            _ => out.push(c),
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
fn strip_inline_blocks(html: &str) -> Cow<'_, str> {
    // Common case (no inline block): borrow the input untouched. The former guard
    // allocated a full lowercased copy of `html` solely for three `contains`
    // checks, then — on the no-block path — allocated the buffer AGAIN via
    // `to_string()`. `find_ascii_ci` is a zero-alloc, NEON substring scan and
    // `to_ascii_lowercase().contains(ascii_needle)` is exactly ASCII-CI matching,
    // so this is byte-for-byte equivalent while turning two per-call full-buffer
    // allocations into zero on the overwhelmingly common no-block path.
    if !html.contains("<!--")
        && find_ascii_ci(html, "<svg").is_none()
        && find_ascii_ci(html, "<style").is_none()
        && find_ascii_ci(html, "<script").is_none()
    {
        return Cow::Borrowed(html);
    }
    let mut s = html.to_string();

    // HTML comments first. Svelte-rendered SERPs (Brave) are dense with hydration
    // markers (`<!--[-->`, `<!--]-->`), and a comment carrying a stray '>' would
    // desync the tag scanner and leak the following markup — the same failure the
    // svg/style/script strip below prevents. Comments delimit with `<!-- … -->`
    // (not `</tag>`), so they get their own pass; an unclosed comment drops to
    // end-of-string. Literal markers (comments are not case-folded).
    if s.contains("<!--") {
        let mut ranges: Vec<(usize, usize)> = Vec::new();
        let mut from = 0;
        while let Some(rel) = s[from..].find("<!--") {
            let start = from + rel;
            let end = match s[start + 4..].find("-->") {
                Some(r) => start + 4 + r + 3,
                None => s.len(),
            };
            ranges.push((start, end));
            if end >= s.len() {
                break;
            }
            from = end;
        }
        for (start, end) in ranges.into_iter().rev() {
            s.replace_range(start..end, " ");
        }
    }

    for tag in ["svg", "style", "script"] {
        let open = format!("<{tag}");
        let close = format!("</{tag}>");
        // Lowercase ONCE per tag, not once per occurrence: collect every block's
        // byte range in a single left-to-right scan of the lowercased copy, then
        // splice them out in REVERSE so earlier offsets stay valid. The previous
        // code recomputed `s.to_ascii_lowercase()` inside the loop for EVERY match,
        // giving O(k·n) work — a crafted result body with k inline blocks could
        // burn quadratic CPU on the async reactor. This is O(n) per tag.
        let lower = s.to_ascii_lowercase();
        let mut ranges: Vec<(usize, usize)> = Vec::new();
        let mut from = 0;
        while let Some(rel) = lower[from..].find(&open) {
            let start = from + rel;
            let end = match lower[start..].find(&close) {
                Some(r) => start + r + close.len(),
                None => s.len(), // unclosed block → drop to end-of-string
            };
            ranges.push((start, end));
            if end >= s.len() {
                break;
            }
            from = end;
        }
        for (start, end) in ranges.into_iter().rev() {
            s.replace_range(start..end, " ");
        }
    }
    Cow::Owned(s)
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

/// The query-matching phrase to DISPLAY for a web result: the informative clause
/// from the `snippet` when one overlaps the query, otherwise a query-overlapping
/// fragment of the `title`. Empty when neither shares a query term — there is then
/// nothing worth quoting. Used by the `hse query` renderer to show WHY a result
/// matched, since the raw snippet is not printed on that path.
pub(in crate::modules::search_engines) fn display_key_phrase(
    title: &str,
    snippet: &str,
    query: &str,
) -> String {
    let from_snippet = extract_key_phrase(snippet, query);
    if !from_snippet.is_empty() {
        return from_snippet;
    }
    extract_key_phrase(title, query)
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
