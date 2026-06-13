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

/// `YYYYMMDDThhmmssZ` (UTC) for `unix_secs`, computed with Hinnant's
/// civil-from-days algorithm so no date crate is needed. Sorts lexicographically
/// in chronological order — a directory listing is a timeline.
pub(super) fn format_utc(unix_secs: u64) -> String {
    let days = (unix_secs / 86_400) as i64;
    let rem = unix_secs % 86_400;
    let (hh, mi, ss) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    // civil_from_days, epoch 1970-01-01 (see Howard Hinnant, "chrono-Compatible
    // Low-Level Date Algorithms").
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let year = if m <= 2 { y + 1 } else { y };
    format!("{year:04}{m:02}{d:02}T{hh:02}{mi:02}{ss:02}Z")
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
