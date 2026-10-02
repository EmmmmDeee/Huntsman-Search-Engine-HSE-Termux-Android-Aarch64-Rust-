use super::*;

// ── canonical download helper (attachment_response / download_response) ───────

#[test]
fn download_response_sets_attachment_disposition_with_scan_scoped_filename() {
    // The scan-scoped exports (CSV / JSON / GEXF / navigator) frame the name as
    // `hse-<stem>-<short_id>.<ext>` with the scan id truncated to 12 chars.
    let resp = download_response(
        "{}".to_string(),
        "application/json; charset=utf-8",
        "abcdef0123456789deadbeef",
        "navigator",
        "json",
    );
    let cd = resp
        .headers()
        .get(axum::http::header::CONTENT_DISPOSITION)
        .and_then(|v| v.to_str().ok())
        .expect("should succeed");
    assert_eq!(cd, "attachment; filename=\"hse-navigator-abcdef012345.json\"");
    let ct = resp
        .headers()
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .expect("should succeed");
    assert_eq!(ct, "application/json; charset=utf-8");
}

#[test]
fn attachment_response_uses_the_filename_verbatim_for_system_downloads() {
    // The logs / debug-bundle path shares the SAME builder but supplies a
    // timestamped name directly (no scan id to truncate) — it must land in the
    // Content-Disposition unchanged, so the two download families can't drift.
    let resp = attachment_response(
        "log line\n".to_string(),
        "text/plain; charset=utf-8",
        "hse-debug-1700000000.log",
    );
    let cd = resp
        .headers()
        .get(axum::http::header::CONTENT_DISPOSITION)
        .and_then(|v| v.to_str().ok())
        .expect("should succeed");
    assert_eq!(cd, "attachment; filename=\"hse-debug-1700000000.log\"");
}
