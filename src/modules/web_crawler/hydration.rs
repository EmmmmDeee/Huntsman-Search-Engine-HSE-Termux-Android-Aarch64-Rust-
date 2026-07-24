//! Embedded SPA hydration-payload extraction — mines the server-rendered JSON
//! data that some JS frameworks embed in the HTML for client-side hydration, so
//! entities inside a JS-rendered page's data are visible WITHOUT running a
//! browser (out of reach for a no-root, single-static-binary,
//! `#![forbid(unsafe_code)]` Termux tool).
//!
//! # Scope — deliberately narrow
//! Only frameworks whose embedded payload is genuinely `serde_json`-parseable
//! are handled:
//!   - **Next.js Pages Router**: `<script id="__NEXT_DATA__" type="application/json">`.
//!     `getInlineScriptSource` escapes the payload with standard `\uXXXX` JSON
//!     escapes, so the captured text is directly valid JSON.
//!   - **Nuxt 3/4** (the current default, `renderJsonPayloads: true`):
//!     `<script type="application/json" id="__NUXT_DATA__">`, produced by
//!     `devalue`'s JSON-safe `stringify()` — also directly valid JSON (as an
//!     array in devalue's flattened wire format; the walk below treats it
//!     opaquely — it collects string leaves wherever they sit in the tree
//!     without needing to understand devalue's index-referencing scheme).
//!
//! Everything else that "looks similar" is explicitly OUT of scope because it
//! is NOT pure JSON and a JSON parser would either fail outright or silently
//! misinterpret it:
//!   - **Next.js App Router** (the default since Next 13, i.e. most current
//!     Next.js sites): no `__NEXT_DATA__` at all — data streams as
//!     `self.__next_f.push([id, "chunk"])` calls carrying React's proprietary
//!     Flight wire format, which requires a Flight decoder, not `JSON.parse`.
//!   - **Nuxt 2** (EOL): `window.__NUXT__=(function(a,b,...){...}(...))` — an
//!     IIFE call expression with unquoted keys and `new Date()`/`new Map()`
//!     literals, needing a JS evaluator.
//!   - **Remix/React Router** (Single Fetch, the unconditional default since
//!     v7): `turbo-stream`-encoded chunks — a bespoke wire format with bare
//!     `undefined`/`NaN`/`Infinity` tokens, not JSON.
//!   - **SvelteKit**: `devalue.uneval()` output — raw ECMAScript expression
//!     source (unquoted keys, literal `new Date(...)` calls), not JSON.
//!   - **Gatsby**: the real per-page payload is not present in the fetched
//!     HTML at all for the default SSG/DSG case — it requires a second,
//!     separate fetch to a companion `page-data.json` URL, which is a
//!     different capability (crawler-level follow-up fetch) than parsing one
//!     already-fetched body.
//!
//! Attempting any of the above with `serde_json::from_str` simply returns
//! `Err`, so misdetecting one of them costs nothing beyond a wasted parse
//! attempt — but they are excluded from [`HYDRATION_MARKERS`] entirely so this
//! module never even tries.

use serde_json::Value;

use crate::core::classifier::Classified;

/// Recognised hydration markers, in the order checked. Each identifies a
/// `<script type="application/json" id="...">...</script>` tag carrying
/// genuinely valid JSON (see module docs for why only these two qualify).
/// Both single- and double-quoted attribute forms are covered; matching is
/// ASCII-case-insensitive (`find_ascii_ci`) purely for tolerance — real
/// framework output is always this exact case.
const HYDRATION_MARKERS: &[&str] = &[
    "id=\"__NEXT_DATA__\"",
    "id='__NEXT_DATA__'",
    "id=\"__NUXT_DATA__\"",
    "id='__NUXT_DATA__'",
];

/// Cap on how deep the JSON tree walk recurses. `serde_json` already bounds
/// its own parse recursion (so a pathologically nested document fails to
/// parse and short-circuits at the `from_str` step before this ever runs);
/// this is a tighter, independent bound purely to cap wasted CPU/stack on a
/// still-deep-but-validly-parsed payload — defence in depth, not the primary
/// guard.
const MAX_WALK_DEPTH: usize = 64;

/// Skip JSON string leaves shorter than this. Single letters, booleans-as-text,
/// two-letter locale codes, etc. can never be a real entity and would just add
/// noise to the (already precise) locator scan in `extract`.
const MIN_LEAF_LEN: usize = 4;

/// Extract every embedded-entity candidate from a page's hydration JSON, if
/// any is present. Total: a missing marker, a truncated/malformed payload
/// (the crawler's `BODY_CAP` can slice a large blob mid-document before this
/// ever sees it), or a parse failure all yield an empty `Vec` rather than an
/// error — mirroring [`crate::core::classifier::extract`]'s own "never fails"
/// contract. Confidence on each returned [`Classified`] is exactly what
/// `classify` already assigns for its matched shape (checksum > shape >
/// residual) — deliberately NOT boosted for "came from structured JSON",
/// because this walk discards the surrounding JSON key path, so there is no
/// stronger signal available here than the shape/checksum validation
/// `classify` already performs on any candidate from any source.
pub(super) fn extract_hydration_entities(body: &str) -> Vec<Classified> {
    let Some(json_text) = locate_hydration_json(body) else {
        return Vec::new();
    };
    let Ok(value) = serde_json::from_str::<Value>(json_text) else {
        return Vec::new();
    };

    let mut leaves: Vec<&str> = Vec::new();
    collect_string_leaves(&value, 0, &mut leaves);

    let mut out = Vec::new();
    for leaf in leaves {
        out.extend(crate::core::classifier::extract(leaf));
    }
    out
}

/// How far back to look for the `<script` that must precede a hydration
/// marker. Real framework output puts `id="__NEXT_DATA__"`/`__NUXT_DATA__`
/// a few dozen bytes into its own opening tag (the longest observed real
/// attribute preamble, Nuxt's `type=... data-nuxt-data=... data-ssr=...`, is
/// well under 150 bytes) — this is a generous margin, not a tight fit.
const SCRIPT_BACKSCAN_WINDOW: usize = 512;

/// Locate the first hydration `<script type="application/json" id="...">`
/// tag's inner text, if present. Anchors on the `id="..."` marker itself
/// (attribute order differs between frameworks — Next.js emits `id` first,
/// Nuxt emits `type` first — so the marker, not a full tag prefix, is the
/// stable anchor). Before accepting it, verifies the marker is genuinely
/// inside a `<script>` opening tag — a bounded backward scan for the nearest
/// `<script` with no intervening `>` (which would mean an earlier, unrelated
/// tag already closed before the marker) — rather than assuming any bare
/// occurrence of the id literal is a real hydration script; the id strings
/// are highly specific, but this guards against a coincidental match (e.g.
/// inside an HTML comment or an unrelated attribute value). Then scans
/// FORWARD only: to the tag's own closing `>` (content start) and then to the
/// next `</script` (content end). No full HTML tokenizer is needed for this
/// narrow, well-defined shape: both frameworks' generated attribute values
/// (ids, nonces, build hashes, payload URLs) never contain a literal `>`, so
/// the first `>` after the marker is reliably the opening tag's close.
fn locate_hydration_json(body: &str) -> Option<&str> {
    let marker_pos = HYDRATION_MARKERS
        .iter()
        .filter_map(|m| crate::util::str_util::find_ascii_ci(body, m))
        .min()?;

    let window_start = crate::util::str_util::floor_char_boundary(
        body,
        marker_pos.saturating_sub(SCRIPT_BACKSCAN_WINDOW),
    );
    let window = &body[window_start..marker_pos];
    let script_open = find_last_ascii_ci(window, "<script")?;
    if window[script_open..].contains('>') {
        // Whatever opened last before the marker already closed — the
        // marker isn't inside that tag's attribute list.
        return None;
    }

    let tag_close = crate::util::str_util::find_ascii_ci(&body[marker_pos..], ">")? + marker_pos;
    let content_start = tag_close + 1;
    let content_end =
        crate::util::str_util::find_ascii_ci(&body[content_start..], "</script")? + content_start;
    let text = body.get(content_start..content_end)?.trim();
    (!text.is_empty()).then_some(text)
}

/// Rightmost ASCII-case-insensitive occurrence of `needle` in `haystack` —
/// like [`crate::util::str_util::find_ascii_ci`] but last-match instead of
/// first-match. Only ever called over the small, bounded
/// [`SCRIPT_BACKSCAN_WINDOW`] above, so a linear re-scan per match is fine.
fn find_last_ascii_ci(haystack: &str, needle: &str) -> Option<usize> {
    let mut last = None;
    let mut from = 0;
    while let Some(rel) = crate::util::str_util::find_ascii_ci(&haystack[from..], needle) {
        let pos = from + rel;
        last = Some(pos);
        from = pos + 1;
    }
    last
}

/// Recursively collect every JSON string leaf at least [`MIN_LEAF_LEN`] bytes
/// long, depth-capped at [`MAX_WALK_DEPTH`]. Numbers/bools/null are never
/// entity candidates and are skipped; object keys are not collected (only
/// values) since a hydration payload's keys are field names, not data.
fn collect_string_leaves<'a>(value: &'a Value, depth: usize, out: &mut Vec<&'a str>) {
    if depth > MAX_WALK_DEPTH {
        return;
    }
    match value {
        Value::String(s) if s.len() >= MIN_LEAF_LEN => out.push(s.as_str()),
        Value::Array(items) => {
            for item in items {
                collect_string_leaves(item, depth + 1, out);
            }
        }
        Value::Object(map) => {
            for v in map.values() {
                collect_string_leaves(v, depth + 1, out);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    include!("hydration_tests.rs");
}
