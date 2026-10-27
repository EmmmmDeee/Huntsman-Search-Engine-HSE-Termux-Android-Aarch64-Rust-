//! Offline OSINT, analysis and inspection request handlers for the HTTP router.
//! Each handler answers one route and reuses the `web_server.rs` authorization, same-site and
//! bounded-body gates; behaviour is unchanged from the handlers that lived in `web_server.rs`.

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;
use std::thread;

use crate::entity::EntityKind;
use crate::scan_api::ScanApi;
use crate::scan_service::{INSPECT_KIND, LookupOutput, ScanService, stamp_scan_id};
use crate::source_outcome::SourceExecutionOutcome;
use crate::value_syntax::form_decode;

use super::{
    ANALYZE_STACK_BYTES, AnalyzeHandler, INSPECT_STACK_BYTES, InvestigateHandler, LookupReport,
    MAX_ANALYZE_SEEDS, MAX_FORM_BYTES, MAX_INSPECT_BYTES, MAX_INSPECT_NAME_BYTES,
    MAX_SELECTOR_BYTES, Method, ParsedRequest, Routes, Upload, json_error, json_ok, page_refusal,
};

/// `GET /api/analyze?seeds=…`: the offline multi-hop analysis of up to [`MAX_ANALYZE_SEEDS`]
/// seeds, one per line. It is refused cross-site like a lookup, but needs no lookup header: it
/// makes no network request and spends no key.
/// Reuse Huntsman's existing authorization and same-site gates for both
/// bounded, offline JSON OSINT methods. No remote provider request is made.
pub(super) fn osint_offline_response(parsed: &ParsedRequest<'_>, risk: bool) -> String {
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
    if risk {
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
                        Some(service) => keep_inspection(service, &label, report),
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

/// The inspection kept as a `FINISHED` scan of the file, named in the report's `scan` and
/// `status`, with every entity stamped with that scan's id so its provenance names a scan
/// `/api/scans/ID` reads again. When the store refuses, the report is answered whole all the same,
/// with a `scans` outcome saying why it was not kept: a full store never costs the file's findings.
fn keep_inspection(service: &ScanService, label: &str, mut report: LookupReport) -> LookupReport {
    let found = LookupOutput {
        text: report.text.clone(),
        entities: report.entities.clone(),
        outcomes: report.outcomes.clone(),
    };
    match service.keep(
        label,
        crate::sf_types::base_type(&EntityKind::Document),
        INSPECT_KIND,
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
    let base = name.rsplit(['/', '\\']).next().unwrap_or("");
    let mut label = String::new();
    for c in base.chars().filter(|c| !c.is_control()) {
        if label.len() + c.len_utf8() > MAX_INSPECT_NAME_BYTES {
            break;
        }
        label.push(c);
    }
    let label = label.trim();
    Ok(if label.is_empty() {
        "upload".to_owned()
    } else {
        label.to_owned()
    })
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
