use serde_json::Value;

use super::format::{format_utc, slug};

/// One archived response, parsed back from disk for inclusion in a dossier.
/// `raw` is the verbatim provider body (structured JSON, or a string for a
/// non-JSON body) exactly as it was stored.
#[derive(Debug, Clone)]
pub struct ArchivedResponse {
    pub provider: String,
    pub endpoint: String,
    pub query: String,
    pub unix: u64,
    pub filename: String,
    pub raw: Value,
}

/// Env-free core for [`crate::util::raw_archive::records_in_window`] /
/// [`crate::util::raw_archive::records_for_queries`] — the window filter,
/// optional query-set filter, and parse, so all three are unit-testable against
/// a temp archive.
///
/// The archive is append-only and never evicted, so it grows without bound and
/// the auto-dossier reads it on every scan. To keep that O(matching files) and
/// not O(total archived files), each filename — which embeds the UTC timestamp
/// and the query slug (`<provider>__<endpoint>__<queryslug>__<UTC>__<seq>.json`)
/// — is pre-filtered *before* the file is opened. Only files that survive the
/// cheap filename checks are read and parsed; the exact `_meta.unix` / query
/// checks below stay as the authoritative guard.
pub(super) fn records_filtered_dir(
    dir: &std::path::Path,
    start_unix: u64,
    end_unix: u64,
    queries: Option<&std::collections::HashSet<String>>,
) -> Vec<ArchivedResponse> {
    let mut out = Vec::new();
    let Ok(rd) = std::fs::read_dir(dir) else {
        return out;
    };
    // Fixed-width UTC stamps sort lexicographically in chronological order, so a
    // string compare against the window bounds is exact. `u64::MAX` (an open
    // upper bound from a still-running scan) disables the upper filename check.
    let utc_lo = format_utc(start_unix);
    let utc_hi = (end_unix != u64::MAX).then(|| format_utc(end_unix));
    // Pre-slug the wanted queries once so the per-file check is a set lookup.
    // Lower-cased: `slug` preserves case (deliberately, for a human-readable
    // filename), but the caller's query set is already lower-cased (see
    // `cli::export::renderers`'s `scan.target.value.to_lowercase()`) while an
    // archived file's own slug keeps the ORIGINAL case it was written with
    // (`raw_archive::record`'s `query` argument is never case-folded). A
    // case-sensitive comparison between the two would silently drop every
    // file for a target with any uppercase letter (a `FullName` seed like
    // "Brett Lawnton" always has one) — exactly the class the authoritative
    // `_meta.query` check two steps below already guards against by
    // lower-casing both sides; this makes the cheap pre-filter agree with it
    // instead of rejecting the file before that check is ever reached.
    let want_slugs: Option<std::collections::HashSet<String>> =
        queries.map(|set| set.iter().map(|q| slug(q, 80).to_lowercase()).collect());

    for entry in rd.flatten() {
        let filename = entry.file_name().to_string_lossy().into_owned();
        if !filename.ends_with(".json") {
            continue;
        }
        // Cheap filename pre-filter (no I/O). Skip only when the name parses to
        // the known 5-field shape; anything else falls through to a full read so
        // a legacy/odd filename is never silently dropped.
        let parts: Vec<&str> = filename.split("__").collect();
        if parts.len() == 5 {
            let (fq_slug, futc) = (parts[2], parts[3]);
            if futc < utc_lo.as_str() {
                continue;
            }
            if let Some(hi) = &utc_hi
                && futc > hi.as_str()
            {
                continue;
            }
            if let Some(want) = &want_slugs
                && !want.contains(&fq_slug.to_lowercase())
            {
                continue;
            }
        }

        let path = entry.path();
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        let Ok(doc) = serde_json::from_str::<Value>(&text) else {
            continue;
        };
        let unix = doc
            .pointer("/_meta/unix")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        if unix < start_unix || unix > end_unix {
            continue;
        }
        let meta_str = |k: &str| {
            doc.pointer(&format!("/_meta/{k}"))
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string()
        };
        let query = meta_str("query");
        if let Some(set) = queries
            && !set.contains(&query.to_lowercase())
        {
            continue;
        }
        out.push(ArchivedResponse {
            provider: meta_str("provider"),
            endpoint: meta_str("endpoint"),
            query,
            unix,
            filename: entry.file_name().to_string_lossy().into_owned(),
            raw: doc.get("raw").cloned().unwrap_or(Value::Null),
        });
    }
    out.sort_by(|a, b| {
        a.unix
            .cmp(&b.unix)
            .then_with(|| a.filename.cmp(&b.filename))
    });
    out
}
