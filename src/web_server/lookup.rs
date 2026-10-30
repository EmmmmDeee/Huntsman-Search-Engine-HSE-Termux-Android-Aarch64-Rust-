//! Lookup, sensor and scan-listing request handlers for the HTTP router. Each handler keeps
//! the authorization, same-site, body-bound and timeout gates of `web_server.rs`; behaviour is
//! unchanged from the handlers that lived in `web_server.rs`.

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;
use std::sync::mpsc::{RecvTimeoutError, sync_channel};
use std::thread;
use std::time::Instant;

use crate::scan_api::ScanApi;
use crate::scan_route::{self, ScanKind};
use crate::scan_service::{ScanRequest, ScanService};
use crate::scan_store::{LogLevel, ScanStatus};
use crate::value_syntax::form_decode;

use super::{
    LOOKUP_STACK_BYTES, LookupQuery, LookupReport, Lookups, MAX_LOOKUPS, MAX_RADAR_REQUESTS,
    MAX_SELECTOR_BYTES, Method, ParsedRequest, RADAR_WAIT, SCANS_STACK_BYTES, Sensor, Slot,
    json_error, json_ok, page_refusal, response, response_bytes,
};

/// Read a sensor (Android's OS-cached Wi-Fi scan, or the cells it reports) or record one track
/// sweep only after an explicitly initiated, same-origin, lookup-header-bearing request of the one
/// `method` it takes. A missing sensor is an error, never a fabricated empty scan. Each worker is
/// time- and concurrency-bounded, one request to a sensor at a time.
pub(super) fn sensor_response<T: serde::Serialize + Send + 'static>(
    parsed: &ParsedRequest<'_>,
    sensor: Option<&Sensor<T>>,
    noun: &str,
    method: Method,
) -> String {
    let Some(sensor) = sensor else {
        return json_error(404, &format!("{noun} is not enabled on this server"));
    };
    if parsed.method != method {
        return json_error(405, &format!("{noun} needs {}", method.as_str()));
    }
    if let Some(refused) = page_refusal(parsed, &format!("{noun} request"), true) {
        return refused;
    }
    if !parsed.query.is_empty() {
        return json_error(400, &format!("{noun} takes no query parameters"));
    }
    if parsed.has_body {
        return json_error(400, &format!("{noun} takes no body"));
    }
    let Some(slot) = Slot::take_of(&sensor.live, MAX_RADAR_REQUESTS) else {
        return json_error(503, &format!("{noun} request already in progress"));
    };
    let handler = Arc::clone(&sensor.handler);
    let (sender, receiver) = sync_channel(1);
    let worker = thread::Builder::new()
        .name("serve-radar".into())
        .stack_size(LOOKUP_STACK_BYTES)
        .spawn(move || {
            let result = catch_unwind(AssertUnwindSafe(|| handler()));
            drop(slot);
            let _ = sender.send(result);
        });
    if worker.is_err() {
        return json_error(503, &format!("could not start a {noun} worker"));
    }
    match receiver.recv_timeout(RADAR_WAIT) {
        Ok(Ok(Ok(report))) => match serde_json::to_string(&report) {
            Ok(body) => json_ok(&body, false),
            Err(_) => json_error(500, &format!("{noun} observations could not be encoded")),
        },
        Ok(Ok(Err(error))) => json_error(error.status, &error.message),
        Ok(Err(_)) | Err(RecvTimeoutError::Disconnected) => {
            json_error(500, &format!("{noun} failed unexpectedly"))
        }
        Err(RecvTimeoutError::Timeout) => {
            json_error(504, &format!("{noun} did not answer in time"))
        }
    }
}

/// `GET /api/lookup`: one lookup, answered with its report. With saved scans on, the lookup runs
/// as a saved scan, so it is kept, listed under Scans, can be stopped there, and reads `ABORTED`
/// after a server that stopped mid-lookup starts again; the answer names it. Without them the
/// installed handler runs it and nothing is kept, as there is nowhere to keep it. Either way the
/// request waits at most [`Lookups::wait`] and then answers `504`.
pub(super) fn lookup_response(
    parsed: &ParsedRequest<'_>,
    lookups: Option<&Lookups>,
    scans: Option<&Arc<ScanApi>>,
) -> String {
    let Some(lookups) = lookups else {
        return json_error(404, "lookups are not enabled on this server");
    };
    if parsed.method != Method::Get {
        return json_error(405, "lookup needs GET");
    }
    // `none` is a typed URL or bookmark; `same-origin` is this page. Anything else came from
    // another site, which must not spend this operator's egress or keys.
    if let Some(refused) = page_refusal(parsed, "lookup", true) {
        return refused;
    }
    let query = match parse_lookup_query(parsed.query) {
        Ok(query) => query,
        Err(message) => return json_error(400, message),
    };
    let until = Instant::now() + lookups.wait;
    if let Some(scans) = scans {
        let service = Arc::clone(scans.service());
        // Reading and encoding the saved report needs more stack than a connection has.
        let worker = thread::Builder::new()
            .name("serve-lookup".into())
            .stack_size(LOOKUP_STACK_BYTES)
            .spawn(move || saved_lookup(&service, &query, until));
        return match worker.map(thread::JoinHandle::join) {
            Ok(Ok(answer)) => answer,
            Ok(Err(_)) => json_error(500, "lookup failed unexpectedly"),
            Err(_) => json_error(503, "could not start a lookup worker"),
        };
    }
    let Some(slot) = Slot::take_of(&lookups.live, MAX_LOOKUPS) else {
        return json_error(503, "lookup capacity in use; retry shortly");
    };
    let handler = Arc::clone(&lookups.handler);
    let (sender, receiver) = sync_channel(1);
    let worker = thread::Builder::new()
        .name("serve-lookup".into())
        .stack_size(LOOKUP_STACK_BYTES)
        .spawn(move || {
            let outcome = catch_unwind(AssertUnwindSafe(|| handler(&query)));
            // Free the place before answering: a client that has its answer may ask again at
            // once, and must not find its own finished lookup still counted.
            drop(slot);
            let _ = sender.send(outcome);
        });
    if worker.is_err() {
        return json_error(503, "could not start a lookup worker");
    }
    match receiver.recv_timeout(until.saturating_duration_since(Instant::now())) {
        Ok(Ok(Ok(report))) => match serde_json::to_string(&report) {
            Ok(body) => json_ok(&body, false),
            Err(_) => json_error(500, "report could not be encoded"),
        },
        Ok(Ok(Err(error))) => json_error(error.status, &error.message),
        Ok(Err(_)) | Err(RecvTimeoutError::Disconnected) => {
            json_error(500, "lookup failed unexpectedly")
        }
        Err(RecvTimeoutError::Timeout) => json_error(
            504,
            "the lookup is still running and this server keeps no saved scans, so its result \
             will not be kept; set HOME or HUNTSMAN_HOME to keep lookups as saved scans",
        ),
    }
}

/// One `/api/lookup` as a saved scan of the target: started, or joined when the same lookup is
/// already under way, then waited on until `until`. A scan that has not ended by then is answered
/// `504` and runs on; one that ended with nothing saved is answered `502` with the reason its log
/// gives. Each answer names the scan.
fn saved_lookup(service: &Arc<ScanService>, query: &LookupQuery, until: Instant) -> String {
    let request = ScanRequest {
        target: query.selector.clone(),
        kind: Some(query.kind.clone()),
        ..ScanRequest::default()
    };
    let record = match service
        .start_or_join(&request)
        .and_then(|record| service.wait(&record.id, until))
    {
        Ok(record) => record,
        Err(failure) => return json_error(failure.status(), &failure.to_string()),
    };
    let failed = |status: u16, error: String| {
        let body = serde_json::json!({ "error": error, "scan": record.id });
        response(
            status,
            "application/json; charset=utf-8",
            &format!("{body}\n"),
            false,
        )
    };
    if record.status.is_active() {
        return failed(
            504,
            format!(
                "the lookup is still running as saved scan {}; it goes on and keeps what it finds \
                 at /api/scans/{} and under Scans",
                record.id, record.id
            ),
        );
    }
    let saved = match service.store().results(&record.id) {
        Ok(saved) => saved.filter(|_| record.status != ScanStatus::ErrorFailed),
        Err(failure) => return json_error(500, &failure.to_string()),
    };
    let Some(results) = saved else {
        let log = service.store().log(&record.id).unwrap_or_default();
        let why = log
            .iter()
            .rev()
            .find(|entry| entry.level == LogLevel::Error)
            .or_else(|| log.last())
            .map_or_else(
                || "the lookup saved nothing".to_owned(),
                |entry| entry.message.clone(),
            );
        return failed(502, why);
    };
    let report = LookupReport {
        route: scan_route::parse_kind(&record.kind).map_or("scan", ScanKind::command),
        text: results.text,
        entities: results.entities,
        outcomes: results.outcomes,
        scan: Some(record.id.clone()),
        status: Some(record.status.as_str()),
    };
    match serde_json::to_string(&report) {
        Ok(body) => json_ok(&body, false),
        Err(_) => json_error(500, "report could not be encoded"),
    }
}

/// The saved scans: Spiderfoot's scan list, scan views, exports and state changes, answered by the
/// binary's [`ScanApi`]. A scan makes network requests and spends keys, and its results are the
/// operator's, so every call is guarded as a lookup is: refused cross-site or same-site, it needs
/// the lookup header (which another origin cannot send without a preflight this server never
/// approves), and on a public bind the bearer token. Parameters travel in the query string, so a
/// request that sends a body is refused rather than half read.
pub(super) fn scans_response(parsed: &ParsedRequest<'_>, scans: Option<&Arc<ScanApi>>) -> Vec<u8> {
    let Some(scans) = scans else {
        return json_error(404, "saved scans are not enabled on this server").into_bytes();
    };
    if let Some(refused) = page_refusal(parsed, "scan request", true) {
        return refused.into_bytes();
    }
    if parsed.has_body {
        return json_error(400, "send the parameters in the query string, with no body")
            .into_bytes();
    }
    // Keep the permit until the complete HTTP response is encoded, not merely until the
    // ScanApi worker finishes. A panicking worker or a failed spawn also releases it.
    let _permit = if heavy_saved_scan_response(parsed.method, parsed.path) {
        match Slot::take_of(scans.web_request_slots(), super::MAX_HEAVY_SCAN_REQUESTS) {
            Some(permit) => Some(permit),
            None => {
                return json_error(503, "saved-scan response capacity in use; retry shortly")
                    .into_bytes();
            }
        }
    } else {
        None
    };
    let head = parsed.method == Method::Head;
    let (api, method, path, query) = (
        Arc::clone(scans),
        parsed.method.as_str(),
        parsed.path.to_owned(),
        parsed.query.to_owned(),
    );
    let worker = thread::Builder::new()
        .name("serve-scans".into())
        .stack_size(SCANS_STACK_BYTES)
        .spawn(move || api.handle(method, &path, &query));
    let answer = match worker {
        Ok(worker) => worker.join(),
        Err(_) => return json_error(503, "could not start a scan API worker").into_bytes(),
    };
    match answer {
        Ok(answer) => {
            let disposition = answer.filename.as_deref().map(|name| {
                format!(
                    "Content-Disposition: attachment; filename=\"{}\"\r\n",
                    header_filename(name)
                )
            });
            response_bytes(
                answer.status,
                answer.content_type,
                &answer.body,
                head,
                disposition.as_deref().unwrap_or(""),
            )
        }
        Err(_) => json_error(500, "the scan API failed unexpectedly").into_bytes(),
    }
}

/// Only large saved-scan materialisations consume the memory-intensive worker budget. Quick
/// metadata reads and scan-control POSTs remain available even when both permits are held.
fn heavy_saved_scan_response(method: Method, path: &str) -> bool {
    if matches!(
        path,
        "/api/scans" | "/api/eventtypes" | "/api/correlationrules" | "/api/settings"
    ) {
        return false;
    }
    let Some(tail) = path.strip_prefix("/api/scans/") else {
        return true;
    };
    if let Some((id, action)) = tail.split_once('/') {
        return !(method == Method::Post
            && !id.is_empty()
            && matches!(action, "stop" | "delete" | "rerun" | "fp"));
    }
    // A two-segment GET is normally a cheap scan-status read. Reserved route names
    // are large report/search/alert operations and cannot masquerade as scan IDs.
    !(matches!(method, Method::Get | Method::Head)
        && !tail.is_empty()
        && !matches!(tail, "export" | "compare" | "alert" | "alerts" | "search"))
}

/// A file name safe inside a quoted header value: letters, digits, `.`, `-` and `_` kept, every
/// other character `_`, so a name can never end the header or start another.
pub(super) fn header_filename(name: &str) -> String {
    let safe: String = name
        .chars()
        .take(128)
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_') {
                c
            } else {
                '_'
            }
        })
        .collect();
    if safe.is_empty() {
        "export".to_owned()
    } else {
        safe
    }
}

/// `kind` (default `auto`) and `q` from a query string. Unknown keys are ignored.
fn parse_lookup_query(raw: &str) -> Result<LookupQuery, &'static str> {
    let mut kind = None;
    let mut selector = None;
    for pair in raw.split('&').filter(|pair| !pair.is_empty()) {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        let value = form_decode(value).ok_or("query is not valid percent-encoded UTF-8")?;
        match key {
            "kind" => kind = Some(value),
            "q" => selector = Some(value),
            _ => {}
        }
    }
    let selector = selector.map(|q| q.trim().to_owned()).unwrap_or_default();
    if selector.is_empty() {
        return Err("lookup needs q");
    }
    if selector.len() > MAX_SELECTOR_BYTES {
        return Err("q is too long");
    }
    let kind = kind
        .map(|k| k.trim().to_ascii_lowercase())
        .filter(|k| !k.is_empty())
        .unwrap_or_else(|| "auto".into());
    Ok(LookupQuery { kind, selector })
}
