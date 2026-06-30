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
    // Collapse runs of '_' for readability and trim leading/trailing separators.
    while out.contains("__") {
        out = out.replace("__", "_");
    }
    let trimmed = out.trim_matches(['_', '.', '-']).to_string();
    let trimmed = if trimmed.is_empty() {
        "unknown".to_string()
    } else {
        trimmed
    };
    trimmed.chars().take(max).collect()
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
