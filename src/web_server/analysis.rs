//! Offline OSINT, analysis and inspection request handlers for the HTTP router.
//! Each handler answers one route and reuses the `web_server.rs` authorization, same-site and
//! bounded-body gates; behaviour is unchanged from the handlers that lived in `web_server.rs`.

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;
use std::thread;

use crate::entity::EntityKind;
use crate::image_compare;
use crate::scan_api::ScanApi;
use crate::scan_service::{INSPECT_KIND, LookupOutput, ScanService, stamp_scan_id};
use crate::source_outcome::SourceExecutionOutcome;
use crate::value_syntax::form_decode;

use super::{
    ANALYZE_STACK_BYTES, AnalyzeHandler, INSPECT_STACK_BYTES, InvestigateHandler, LookupReport,
    MAX_ANALYZE_SEEDS, MAX_FORM_BYTES, MAX_IMAGE_COMPARE_BYTES, MAX_INSPECT_BYTES,
    MAX_INSPECT_NAME_BYTES, MAX_SELECTOR_BYTES, Method, ParsedRequest, Routes, ServeConfig, Upload,
    json_error, json_ok, page_refusal,
};

/// `GET /api/analyze?seeds=…`: the offline multi-hop analysis of up to [`MAX_ANALYZE_SEEDS`]
/// seeds, one per line. It is refused cross-site like a lookup, but needs no lookup header: it
/// makes no network request and spends no key.
/// All offline analyses use the same bounded, authorized JSON POST contract.
#[derive(Clone, Copy)]
pub(super) enum OfflineOsintMode {
    Case,
    Risk,
    WorkspaceOverlaps,
}

/// Reuse Huntsman's existing authorization and same-site gates for both
/// bounded, offline JSON OSINT methods. No remote provider request is made.
pub(super) fn osint_offline_response(parsed: &ParsedRequest<'_>, mode: OfflineOsintMode) -> String {
    if parsed.method != Method::Post {
        return json_error(405, "OSINT source analysis requires POST");
    }
    if let Some(refusal) = page_refusal(parsed, "OSINT source analysis", true) {
        return refusal;
    }
    if !parsed.query.is_empty() {
        return json_error(
            400,
            "OSINT analysis accepts JSON body, not query parameters",
        );
    }
    let Some(length) = parsed.content_length else {
        return json_error(400, "OSINT analysis needs content length");
    };
    if length == 0 || length > MAX_FORM_BYTES {
        return json_error(
            413,
            "OSINT body size exceeded; use the CLI for larger datasets",
        );
    }
    let Some(body) = parsed.body else {
        return json_error(400, "OSINT analysis body missing");
    };
    if body.len() != length {
        return json_error(400, "OSINT analysis body incomplete or invalid UTF-8");
    }
    if matches!(mode, OfflineOsintMode::WorkspaceOverlaps) {
        return match crate::rhinser_workspace::Workspace::from_json(body.as_bytes())
            .and_then(|workspace| workspace.source_overlaps())
        {
            Ok(report) => serde_json::to_string(&report).map_or_else(
                |_| json_error(500, "Rhinser overlap serialization failed"),
                |json| json_ok(&json, false),
            ),
            Err(_) => json_error(400, "Rhinser workspace input invalid"),
        };
    }
    if matches!(mode, OfflineOsintMode::Risk) {
        match crate::osint_area_risk::estimate_json(body.as_bytes()) {
            Ok(report) => serde_json::to_string(&report).map_or_else(
                |_| json_error(500, "OSINT area result serialization failed"),
                |json| json_ok(&json, false),
            ),
            Err(_) => json_error(400, "OSINT area input invalid"),
        }
    } else {
        match crate::osint_casework::review_json(body.as_bytes()) {
            Ok(report) => serde_json::to_string(&report).map_or_else(
                |_| json_error(500, "OSINT case result serialization failed"),
                |json| json_ok(&json, false),
            ),
            Err(_) => json_error(400, "OSINT case input invalid"),
        }
    }
}

/// `POST /api/rhinser/native`: classify an explicit, operator-submitted capture
/// through exactly the same Rust validator as `osint native FILE`.
/// No Android sensor access, key handling, remote provider call or persistence occurs.
/// Consent and device timestamps supplied in JSON remain unauthenticated claims.
/// Restricted to loopback to avoid transferring raw APDU material to a public HTTP bind.
pub(super) fn rhinser_native_response(parsed: &ParsedRequest<'_>, config: &ServeConfig) -> String {
    if parsed.method != Method::Post {
        return json_error(405, "Rhinser native inspection requires POST");
    }
    if let Some(refusal) = page_refusal(parsed, "Rhinser native inspection", true) {
        return refusal;
    }
    if !config.bind.ip().is_loopback() {
        return json_error(403, "Rhinser native capture inspection requires loopback");
    }
    if !parsed.query.is_empty() {
        return json_error(400, "Rhinser native inspection accepts JSON body only");
    }
    let Some(length) = parsed.content_length else {
        return json_error(400, "Rhinser native inspection needs content length");
    };
    if length == 0 {
        return json_error(400, "Rhinser native inspection needs JSON body");
    }
    if length > MAX_FORM_BYTES
        || u64::try_from(length).unwrap_or(u64::MAX) > crate::rhinser_native::MAX_CAPTURE_BYTES
    {
        return json_error(
            413,
            "Rhinser native capture too large; use osint native FILE",
        );
    }
    let Some(body) = parsed.body else {
        return json_error(400, "Rhinser native capture body missing");
    };
    if body.len() != length {
        return json_error(
            400,
            "Rhinser native capture body incomplete or invalid UTF-8",
        );
    }
    match crate::rhinser_native::inspect_capture_json(body.as_bytes()) {
        Ok(report) => serde_json::to_string(&report).map_or_else(
            |_| json_error(500, "Rhinser native report serialization failed"),
            |json| json_ok(&json, false),
        ),
        Err(_) => json_error(400, "Rhinser native capture invalid or unauthorized"),
    }
}

pub(super) fn analyze_response(
    parsed: &ParsedRequest<'_>,
    analyze: Option<&AnalyzeHandler>,
) -> String {
    let Some(analyze) = analyze else {
        return json_error(404, "analysis is not enabled on this server");
    };
    if parsed.method != Method::Get {
        return json_error(405, "analysis needs GET");
    }
    if let Some(refused) = page_refusal(parsed, "analysis", false) {
        return refused;
    }
    let seeds = match parse_analyze_seeds(parsed.query) {
        Ok(seeds) => seeds,
        Err(message) => return json_error(400, &message),
    };
    let handler = Arc::clone(analyze);
    let worker = thread::Builder::new()
        .name("serve-analyze".into())
        .stack_size(ANALYZE_STACK_BYTES)
        .spawn(move || handler(&seeds));
    let outcome = match worker {
        Ok(worker) => worker.join(),
        Err(_) => return json_error(503, "could not start an analysis worker"),
    };
    match outcome {
        Ok(Ok(report)) => json_ok(&report.to_string(), false),
        Ok(Err(error)) => json_error(error.status, &error.message),
        Err(_) => json_error(500, "analysis failed unexpectedly"),
    }
}

/// `POST /api/investigate`: the actionable entities in the text sent as the body, as a report like
/// a lookup's. The text travels in the body, never the URL, which is kept in history and logs;
/// it is read whole within [`MAX_FORM_BYTES`], as a key save is, so a longer text is refused with
/// the command that reads one from a file in Termux.
pub(super) fn investigate_response(
    parsed: &ParsedRequest<'_>,
    handler: Option<&InvestigateHandler>,
) -> String {
    let Some(handler) = handler else {
        return json_error(404, "text investigation is not enabled on this server");
    };
    if parsed.method != Method::Post {
        return json_error(405, "investigation needs POST with the text as the body");
    }
    if let Some(refused) = page_refusal(parsed, "investigation", true) {
        return refused;
    }
    if !parsed.query.is_empty() {
        return json_error(
            400,
            "investigation takes no query string: send the text as the body",
        );
    }
    let length = match parsed.content_length {
        None | Some(0) => return json_error(400, "investigation needs the text as the body"),
        Some(length) if length > MAX_FORM_BYTES => {
            return json_error(
                413,
                &format!(
                    "the text is longer than {MAX_FORM_BYTES} bytes; in Termux, investigate --file FILE reads a longer one"
                ),
            );
        }
        Some(length) => length,
    };
    let Some(body) = parsed.body else {
        return json_error(400, "the request ended before its head did");
    };
    // The request was decoded lossily, so a byte that was not UTF-8 is U+FFFD by now and never
    // fewer bytes than it was: a body shorter than it announced was cut.
    if body.len() < length {
        return json_error(400, "the text ended before the length it announced");
    }
    let text = body.to_owned();
    let handler = Arc::clone(handler);
    let worker = thread::Builder::new()
        .name("serve-investigate".into())
        .stack_size(ANALYZE_STACK_BYTES)
        .spawn(move || handler(&text));
    let outcome = match worker {
        Ok(worker) => worker.join(),
        Err(_) => return json_error(503, "could not start an investigation worker"),
    };
    match outcome {
        Ok(Ok(report)) => match serde_json::to_string(&report) {
            Ok(body) => json_ok(&body, false),
            Err(_) => json_error(500, "the investigation could not be encoded"),
        },
        Ok(Err(error)) => json_error(error.status, &error.message),
        Err(_) => json_error(500, "investigation failed unexpectedly"),
    }
}

/// `POST /api/inspect?name=FILE`: the uploaded file's EXIF and embedded document metadata, as a
/// report. The body is the file's raw bytes (`fetch` with a `File` as its body), read only once
/// [`inspect_admits`] took the request; a request it did not take is answered why here.
pub(super) fn inspect_response(
    parsed: &ParsedRequest<'_>,
    upload: Option<&Upload>,
    routes: &Routes,
) -> String {
    let Some(inspect) = routes.inspect.as_ref() else {
        return json_error(404, "file inspection is not enabled on this server");
    };
    if parsed.method != Method::Post {
        return json_error(405, "inspection needs POST with the file as the body");
    }
    if let Some(refused) = page_refusal(parsed, "inspection", true) {
        return refused;
    }
    let length = match parsed.content_length {
        None | Some(0) => return json_error(400, "inspection needs the file as the body"),
        Some(length) if length > MAX_INSPECT_BYTES => {
            return json_error(413, "the file is larger than 64 MiB");
        }
        Some(length) => length,
    };
    let Some(upload) = upload else {
        // The upload gate only sees a head that ended in its blank line, so one that never did was
        // cut short. Otherwise every other check passed, and the one place was taken.
        if parsed.body.is_none() {
            return json_error(400, "the request ended before its head did");
        }
        return json_error(503, "an inspection is already running; retry shortly");
    };
    if upload.body.len() != length {
        return json_error(400, "the upload ended before the length it announced");
    }
    let label = match inspect_label(parsed.query) {
        Ok(label) => label,
        Err(message) => return json_error(400, message),
    };
    let handler = &inspect.handler;
    let body = upload.body.as_slice();
    let service = routes.scans.as_deref().map(ScanApi::service);
    let outcome = thread::scope(|scope| {
        thread::Builder::new()
            .name("serve-inspect".into())
            .stack_size(INSPECT_STACK_BYTES)
            .spawn_scoped(scope, || {
                catch_unwind(AssertUnwindSafe(|| {
                    handler(&label, body).map(|report| match service {
                        Some(service) => keep_inspection(service, &label, INSPECT_KIND, report),
                        None => report,
                    })
                }))
            })
            .map(thread::ScopedJoinHandle::join)
    });
    match outcome {
        Ok(Ok(Ok(Ok(report)))) => match serde_json::to_string(&report) {
            Ok(body) => json_ok(&body, false),
            Err(_) => json_error(500, "the inspection could not be encoded"),
        },
        Ok(Ok(Ok(Err(error)))) => json_error(error.status, &error.message),
        Ok(Ok(Err(_)) | Err(_)) => json_error(500, "inspection failed unexpectedly"),
        Err(_) => json_error(503, "could not start an inspection worker"),
    }
}

/// A browser-selected reference and candidate, both read in the existing bounded inspection slot.
/// The body begins with the reference's four-byte little-endian length, followed by both files.
pub(super) fn image_compare_response(
    parsed: &ParsedRequest<'_>,
    upload: Option<&Upload>,
    routes: &Routes,
) -> String {
    if routes.inspect.is_none() {
        return json_error(404, "image comparison is unavailable on this server");
    }
    if parsed.method != Method::Post {
        return json_error(405, "image comparison requires POST");
    }
    if let Some(refusal) = page_refusal(parsed, "inspection", true) {
        return refusal;
    }
    let Some(length) = parsed.content_length.filter(|&length| length >= 6) else {
        return json_error(400, "image comparison requires both image files");
    };
    if length > MAX_IMAGE_COMPARE_BYTES {
        return json_error(
            413,
            "image comparison accepts two files of up to 20 MiB each",
        );
    }
    let Some(upload) = upload else {
        return json_error(503, "an inspection is already running; retry shortly");
    };
    if upload.body.len() != length {
        return json_error(400, "the upload ended before the length it announced");
    }
    let (prefix, images) = upload.body.split_at(4);
    let length = u32::from_le_bytes([prefix[0], prefix[1], prefix[2], prefix[3]]) as usize;
    let maximum = image_compare::MAX_FILE_BYTES;
    if length == 0 || length >= images.len() {
        return json_error(
            400,
            "the reference image length does not identify two files",
        );
    }
    let (first, second) = images.split_at(length);
    if first.len() > maximum || second.len() > maximum {
        return json_error(413, "each image must be at most 20 MiB");
    }
    let notes = match comparison_notes(parsed.query) {
        Ok(notes) => notes,
        Err(message) => return json_error(400, message),
    };
    let service = routes.scans.as_deref().map(ScanApi::service);
    let outcome = thread::scope(|scope| {
        thread::Builder::new()
            .name("serve-image-comparison".into())
            .stack_size(INSPECT_STACK_BYTES)
            .spawn_scoped(scope, || {
                let comparison = image_compare::compare(first, second)?;
                let now = crate::clock::unix_now();
                let mut report = LookupReport {
                    route: "image_compare",
                    text: comparison.text(),
                    entities: vec![comparison.observation(
                        &notes.reference,
                        &notes.candidate,
                        notes.source_page.as_deref(),
                        notes.asset_url.as_deref(),
                        now,
                    )],
                    outcomes: vec![comparison.outcome(now)],
                    scan: None,
                    status: None,
                };
                if let Some(service) = service {
                    let label = format!("Image comparison: {}", notes.reference);
                    report = keep_inspection(service, &label, image_compare::SOURCE, report);
                }
                Ok::<_, String>(serde_json::json!({ "comparison": comparison, "report": report }))
            })
            .map(thread::ScopedJoinHandle::join)
    });
    match outcome {
        Ok(Ok(Ok(value))) => json_ok(&value.to_string(), false),
        Ok(Ok(Err(message))) => json_error(422, &message),
        Ok(Err(_)) => json_error(500, "image comparison failed unexpectedly"),
        Err(_) => json_error(503, "could not start an image comparison worker"),
    }
}

struct ComparisonNotes {
    reference: String,
    candidate: String,
    source_page: Option<String>,
    asset_url: Option<String>,
}

fn comparison_notes(raw: &str) -> Result<ComparisonNotes, &'static str> {
    let mut notes = ComparisonNotes {
        reference: "Reference image".into(),
        candidate: "Candidate image".into(),
        source_page: None,
        asset_url: None,
    };
    for field in raw.split('&').filter_map(|pair| pair.split_once('=')) {
        let value = form_decode(field.1).ok_or("comparison notes must be valid UTF-8")?;
        match field.0 {
            "reference" => notes.reference = file_label(&value),
            "candidate" => notes.candidate = file_label(&value),
            "source_page" => notes.source_page = image_compare::source_url(&value)?,
            "asset_url" => notes.asset_url = image_compare::source_url(&value)?,
            _ => return Err("unknown image comparison field"),
        }
    }
    Ok(notes)
}

/// The inspection kept as a `FINISHED` scan of the file, named in the report's `scan` and
/// `status`, with every entity stamped with that scan's id so its provenance names a scan
/// `/api/scans/ID` reads again. When the store refuses, the report is answered whole all the same,
/// with a `scans` outcome saying why it was not kept: a full store never costs the file's findings.
fn keep_inspection(
    service: &ScanService,
    label: &str,
    kind: &str,
    mut report: LookupReport,
) -> LookupReport {
    let found = LookupOutput {
        text: report.text.clone(),
        entities: report.entities.clone(),
        outcomes: report.outcomes.clone(),
    };
    match service.keep(
        label,
        crate::sf_types::base_type(&EntityKind::Document),
        kind,
        found,
    ) {
        Ok(record) => {
            stamp_scan_id(&mut report.entities, &record.id);
            report.scan = Some(record.id);
            report.status = Some(record.status.as_str());
        }
        Err(error) => report.outcomes.push(SourceExecutionOutcome::inconclusive(
            "scans",
            crate::clock::unix_now(),
            format!("not kept as a saved scan: {error}"),
        )),
    }
    report
}

/// The report label for an upload: the `name` query value, reduced to a file name (no directory),
/// with control characters dropped, within [`MAX_INSPECT_NAME_BYTES`]; `upload` when it is absent
/// or empty. Unknown keys are ignored.
pub(super) fn inspect_label(raw: &str) -> Result<String, &'static str> {
    let mut name = String::new();
    for pair in raw.split('&').filter(|pair| !pair.is_empty()) {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        if key == "name" {
            name = form_decode(value).ok_or("name is not valid percent-encoded UTF-8")?;
        }
    }
    Ok(file_label(&name))
}

fn file_label(name: &str) -> String {
    let base = name.rsplit(['/', '\\']).next().unwrap_or("");
    let mut label = String::new();
    for c in base.chars().filter(|c| !c.is_control()) {
        if label.len() + c.len_utf8() > MAX_INSPECT_NAME_BYTES {
            break;
        }
        label.push(c);
    }
    let label = label.trim();
    if label.is_empty() {
        "upload".to_owned()
    } else {
        label.to_owned()
    }
}

/// The seeds in a query's `seeds` value, one per line: each is trimmed and blank lines are
/// dropped. Unknown keys are ignored.
fn parse_analyze_seeds(raw: &str) -> Result<Vec<String>, String> {
    let mut text = String::new();
    for pair in raw.split('&').filter(|pair| !pair.is_empty()) {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        if key == "seeds" {
            text = form_decode(value)
                .ok_or_else(|| "query is not valid percent-encoded UTF-8".to_owned())?;
        }
    }
    let seeds: Vec<String> = text
        .lines()
        .map(str::trim)
        .filter(|seed| !seed.is_empty())
        .map(str::to_owned)
        .collect();
    if seeds.is_empty() {
        return Err("analysis needs seeds, one per line".to_owned());
    }
    if seeds.len() > MAX_ANALYZE_SEEDS {
        return Err(format!("analysis takes at most {MAX_ANALYZE_SEEDS} seeds"));
    }
    if seeds.iter().any(|seed| seed.len() > MAX_SELECTOR_BYTES) {
        return Err(format!("a seed is longer than {MAX_SELECTOR_BYTES} bytes"));
    }
    Ok(seeds)
}
