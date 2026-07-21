use serde_json::Value;

/// Filesystem-safe, human-legible slug: keep alphanumerics and a few obvious
/// separators, render `@` as the readable `_at_`, collapse everything else to
/// `_`, and cap the length so a pathological query can't blow the filename
/// limit. Empty input becomes `unknown` so a filename component is never blank.
pub(super) fn slug(s: &str, max: usize) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '.' | '-' => out.push(ch),
            '@' => out.push_str("_at_"),
            _ => out.push('_'),
        }
    }
    // Collapse runs of '_' for readability.
    while out.contains("__") {
        out = out.replace("__", "_");
    }
    // Truncate FIRST, then trim — order matters: trimming before the length cap let
    // `take(max)` slice mid-string and re-introduce a trailing '_', which then
    // merged with the `__` field separator in `build_filename` into `___`. That
    // corrupts the `split("__")` field parse in `records_filtered_dir`, shifting the
    // timestamp field and silently dropping an in-window paid response from the
    // dossier. Capping before the final trim guarantees no trailing separator
    // survives, whatever the cut point.
    let capped: String = out.chars().take(max).collect();
    let trimmed = capped.trim_matches(['_', '.', '-']);
    if trimmed.is_empty() {
        "unknown".to_string()
    } else {
        trimmed.to_string()
    }
}

/// `YYYYMMDDThhmmssZ` (UTC) for `unix_secs`. Sorts lexicographically in
/// chronological order — a directory listing is a timeline. The
/// no-date-crate civil-from-days core now lives in
/// [`crate::util::timefmt::compact_utc`] so timestamp-bearing modules render
/// dates identically; this thin alias keeps the archive's internal call sites.
pub(super) fn format_utc(unix_secs: u64) -> String {
    crate::util::timefmt::compact_utc(unix_secs)
}

/// The full, self-describing filename for one archived response.
pub(super) fn build_filename(
    provider: &str,
    endpoint: &str,
    query: &str,
    unix_secs: u64,
    seq: u64,
) -> String {
    format!(
        "{}__{}__{}__{}__{:04}.json",
        slug(provider, 24),
        slug(endpoint, 32),
        slug(query, 80),
        format_utc(unix_secs),
        seq
    )
}

/// The pretty-printed, self-describing file body: a `_meta` header naming the
/// request, plus the response under `raw` (structured when it parses, the exact
/// string otherwise). Pure (no I/O) so the shape is unit-testable.
pub(super) fn build_body(
    provider: &str,
    endpoint: &str,
    query: &str,
    unix_secs: u64,
    raw: &str,
) -> String {
    let raw_val: Value =
        serde_json::from_str(raw).unwrap_or_else(|_| Value::String(raw.to_string()));
    let doc = serde_json::json!({
        "_meta": {
            "provider": provider,
            "endpoint": endpoint,
            "query": query,
            "archived_at_utc": format_utc(unix_secs),
            "unix": unix_secs,
        },
        "raw": raw_val,
    });
    // Pretty-printed: an individual file is meant to be opened and read by a
    // human, so optimise for legibility over compactness.
    serde_json::to_string_pretty(&doc).unwrap_or_else(|_| doc.to_string())
}

#[cfg(test)]
mod format_tests {
    use super::{build_filename, slug};

    #[test]
    fn slug_never_ends_in_a_separator_even_when_truncated_mid_token() {
        // The bug: trimming before the length cap let `take(max)` slice mid-string
        // and leave a trailing '_', which merged with the '__' field delimiter into
        // '___' and corrupted the filename field split. Cap a value whose max-th
        // char lands right after a separator and assert no trailing separator.
        let s = slug("aaaaaaaa@bbbbbbbb", 9); // "aaaaaaaa_at_bbbbbbbb" capped at 9
        assert!(
            !s.ends_with('_') && !s.ends_with('.') && !s.ends_with('-'),
            "slug must not end in a separator after truncation, got {s:?}"
        );
        // A value that is all separators after the cut collapses to the sentinel.
        assert_eq!(slug("....----", 3), "unknown");
    }

    #[test]
    fn filename_fields_split_cleanly_on_the_double_underscore() {
        // End-to-end: the archive filename must split into exactly its 5 fields, so
        // the timestamp field is parseable by the pre-filter. A query that truncates
        // to a trailing separator must not shift the fields.
        let name = build_filename("prov", "endpoint", "aaaaaaaaaa@bbbbbbbbbb", 1_700_000_000, 1);
        let stem = name.strip_suffix(".json").unwrap();
        let fields: Vec<&str> = stem.split("__").collect();
        assert_eq!(fields.len(), 5, "filename must have 5 '__'-delimited fields: {name}");
        // The 4th field is the compact UTC stamp — it must start with a digit, not a
        // stray '_' bled in from a corrupted query field.
        assert!(
            fields[3].starts_with(|c: char| c.is_ascii_digit()),
            "timestamp field corrupted by a merged separator: {:?}",
            fields[3]
        );
    }
}
