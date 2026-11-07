//! Lookup, sensor and scan-listing request handlers for the HTTP router. Each handler keeps
//! the authorization, same-site, body-bound and timeout gates of `web_server.rs`; behaviour is
//! unchanged from the handlers that lived in `web_server.rs`.

use serde::Serialize;

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::{Arc, LazyLock};
use std::sync::atomic::AtomicUsize;
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
    MAX_SELECTOR_BYTES, Method, ParsedRequest, PeopleDiscover, RADAR_WAIT, SCANS_STACK_BYTES,
    Sensor, Slot, json_error, json_ok, page_refusal, response, response_bytes,
};

/// H1DR4 runs only on deliberate guarded requests; no credentials or
/// writable third-party API calls are ever issued.
static H1DR4_ACTIVE: LazyLock<Arc<AtomicUsize>> =
    LazyLock::new(|| Arc::new(AtomicUsize::new(0)));

fn parse_h1dr4_request(raw: &str) -> Result<(crate::h1dr4::Resource, crate::h1dr4::Bounds), &'static str> {
    let pairs = crate::value_syntax::form_pairs(raw).ok_or("invalid H1DR4 query encoding")?;
    let mut kind = String::from("search");
    let mut query = String::new();
    let mut limit = None;
    let mut pages = 1_u8;
    for (key, value) in pairs {
        match key.as_str() {
            "kind" => kind = value,
            "q" => query = value,
            "limit" => limit = Some(value.parse::<u16>().map_err(|_| "invalid H1DR4 limit")?),
            "pages" => pages = value.parse::<u8>().map_err(|_| "invalid H1DR4 pages")?,
            _ => return Err("unrecognized H1DR4 query parameter"),
        }
    }
    let (resource, max) = match kind.as_str() {
        "search" if !query.is_empty() => (crate::h1dr4::Resource::Search(query), 20),
        "case" if !query.is_empty() => (crate::h1dr4::Resource::Case(query), 200),
        "rewards" if query.is_empty() => (crate::h1dr4::Resource::OfficialRewards, 20),
        "onchain-stats" if query.is_empty() => (crate::h1dr4::Resource::OnchainStats, 1),
        _ => return Err("invalid H1DR4 mode or missing case/search query"),
    };
    let bounds = crate::h1dr4::Bounds { pages, limit: limit.unwrap_or(max) };
    bounds.checked(&resource)?;
    Ok((resource, bounds))
}

/// GET /api/h1dr4: bounded read-only public intelligence, with every original
/// upstream JSON response included. Same-origin and lookup-header requirements
/// protect users from cross-origin requests consuming network capacity.
pub(super) fn h1dr4_response(parsed: &ParsedRequest<'_>) -> String {
    if parsed.method != Method::Get {
        return json_error(405, "H1DR4 requires GET");
    }
    if let Some(refusal) = page_refusal(parsed, "H1DR4 public intelligence", true) {
        return refusal;
    }
    if parsed.has_body {
        return json_error(400, "H1DR4 takes no request body");
    }
    let (resource, bounds) = match parse_h1dr4_request(parsed.query) {
        Ok(args) => args,
        Err(reason) => return json_error(400, reason),
    };
    let Some(slot) = Slot::take_of(&H1DR4_ACTIVE, MAX_LOOKUPS) else {
        return json_error(503, "H1DR4 lookup capacity in use");
    };
    let (sender, receiver) = sync_channel(1);
    let worker = thread::Builder::new()
        .name("serve-h1dr4".into())
        .stack_size(LOOKUP_STACK_BYTES)
        .spawn(move || {
            let result = catch_unwind(AssertUnwindSafe(|| {
                let transport = crate::http::UreqTransport::new(&crate::http::TransportConfig {
                    timeout: std::time::Duration::from_secs(16),
                    max_body: 4 * 1024 * 1024,
                    ..crate::http::TransportConfig::default()
                });
                crate::h1dr4::retrieve(&transport, &resource, bounds, crate::clock::unix_now())
            }));
            drop(slot);
            let _ = sender.send(result);
        });
    if worker.is_err() {
        return json_error(503, "could not start H1DR4 worker");
    }
    match receiver.recv_timeout(super::LOOKUP_WAIT) {
        Ok(Ok(Ok(report))) => match serde_json::to_string(&report) {
            Ok(body) => json_ok(&body, false),
            Err(_) => json_error(500, "H1DR4 report could not be serialized"),
        },
        Ok(Ok(Err(_))) => json_error(502, "H1DR4 source refused or failed the request"),
        Ok(Err(_)) | Err(RecvTimeoutError::Disconnected) => {
            json_error(500, "H1DR4 lookup failed unexpectedly")
        }
        Err(RecvTimeoutError::Timeout) => {
            json_error(504, "H1DR4 lookup timed out; no report was saved")
        }
    }
}

#[cfg(test)]
mod h1dr4_endpoint_tests {
    use super::*;
    #[test]
    fn h1dr4_rejects_invalid_requests_before_network() {
        assert!(parse_h1dr4_request("kind=search&q=sample&pages=4").is_err());
        // The web parser doesn't mistake a URL-encoded separator for a route.
        // The collector additionally validates that IDs contain only safe tokens.
        assert!(parse_h1dr4_request("kind=case&q=..%2Fprivate").is_ok());
        assert!(parse_h1dr4_request("kind=rewards&q=sensitive").is_err());
        assert!(parse_h1dr4_request("kind=case&q=one&limit=201").is_err());
    }
}

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

/// One shared response contract for live and saved lookups. Deriving a lead
/// does not mutate collected entities, so the original evidence remains intact.
#[derive(Serialize)]
struct LookupWithSynergy<'a> {
    #[serde(flatten)]
    report: &'a LookupReport,
    synergy: crate::osint_synergy::SynergyReport,
}

fn serialize_lookup(report: &LookupReport) -> Result<String, serde_json::Error> {
    serde_json::to_string(&LookupWithSynergy {
        report,
        synergy: crate::osint_synergy::discover(&report.entities),
    })
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
        Ok(Ok(Ok(report))) => match serialize_lookup(&report) {
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
    match serialize_lookup(&report) {
        Ok(body) => json_ok(&body, false),
        Err(_) => json_error(500, "report could not be encoded"),
    }
}

/// Universal research selection is the same pure Rust plan as the CLI. A recognised
/// selector opens the existing scan form without spending keys. Arbitrary text is dispatched
/// to the binary's keyless adaptive web search, with the same header, origin and resource
/// protections as an ordinary lookup. Search-engine URLs are leads, not verified claims.
pub(super) fn research_response(
    parsed: &ParsedRequest<'_>,
    research: Option<&super::Research>,
) -> String {
    if parsed.method != Method::Get {
        return json_error(405, "research needs GET");
    }
    if let Some(refused) = page_refusal(parsed, "research", true) {
        return refused;
    }
    if parsed.has_body {
        return json_error(400, "research takes no request body");
    }
    let query = match parse_lookup_query(parsed.query) {
        Ok(query) => query,
        Err(message) => return json_error(400, message),
    };
    let route = match crate::research_route::plan(&query.selector) {
        Ok(route) => route,
        Err(message) => return json_error(400, message),
    };
    match route {
        crate::research_route::ResearchAction::Targeted { kind, selector } => {
            let body = serde_json::json!({
                "route": "scan",
                "kind": kind.command(),
                "selector": selector,
                "execution": "review_scan_options_before_collection",
            });
            json_ok(&body.to_string(), false)
        }
        crate::research_route::ResearchAction::AdaptiveWeb { query } => {
            let Some(research) = research else {
                return json_error(404, "adaptive research is not enabled on this server");
            };
            let Some(slot) = Slot::take_of(&research.live, MAX_LOOKUPS) else {
                return json_error(503, "research capacity in use; retry shortly");
            };
            let handler = Arc::clone(&research.handler);
            let (sender, receiver) = sync_channel(1);
            let worker = thread::Builder::new()
                .name("serve-research".into())
                .stack_size(LOOKUP_STACK_BYTES)
                .spawn(move || {
                    let outcome = catch_unwind(AssertUnwindSafe(|| handler(&query)));
                    drop(slot);
                    let _ = sender.send(outcome);
                });
            if worker.is_err() {
                return json_error(503, "could not start a research worker");
            }
            match receiver.recv_timeout(super::LOOKUP_WAIT) {
                Ok(Ok(Ok(report))) => json_ok(&report.to_string(), false),
                Ok(Ok(Err(error))) => json_error(error.status, &error.message),
                Ok(Err(_)) | Err(RecvTimeoutError::Disconnected) => {
                    json_error(500, "research failed unexpectedly")
                }
                Err(RecvTimeoutError::Timeout) => {
                    json_error(504, "research timed out; no completed report was saved")
                }
            }
        }
    }
}

/// `POST /api/people/discover`: the `people-discover` search for a JSON body
/// `{"name": …, "region": "au"|"us"}`, answered with the library's report. It never infers
/// account ownership or puts the subject in an HTTP URL. The same host, token, origin and
/// custom-header protections as a live lookup apply, and the name passes
/// `people_discovery::checked_name`, before any network work; one discovery runs at a time.
pub(super) fn people_discover_response(
    parsed: &ParsedRequest<'_>,
    discovery: Option<&PeopleDiscover>,
) -> String {
    let Some(discovery) = discovery else {
        return json_error(404, "people discovery is not enabled on this server");
    };
    if parsed.method != Method::Post {
        return json_error(405, "people discovery requires POST with a JSON body");
    }
    if let Some(refusal) = page_refusal(parsed, "people discovery", true) {
        return refusal;
    }
    if !parsed.query.is_empty() {
        return json_error(
            400,
            "people discovery parameters belong in the request body",
        );
    }
    let length = match parsed.content_length {
        Some(length @ 1..=512) => length,
        Some(0) | None => return json_error(400, "people discovery needs a JSON body"),
        _ => return json_error(413, "people discovery JSON exceeds 512 bytes"),
    };
    let Some(body) = parsed.body else {
        return json_error(400, "people discovery request body is missing");
    };
    if body.len() != length {
        return json_error(400, "people discovery request body length does not match");
    }
    let Ok(json) = serde_json::from_str::<serde_json::Value>(body) else {
        return json_error(400, "people discovery needs valid JSON");
    };
    let Some(object) = json.as_object() else {
        return json_error(400, "people discovery JSON must be an object");
    };
    if object.len() != 2 {
        return json_error(400, "people discovery accepts only name and region");
    }
    let Some(name) = object.get("name").and_then(serde_json::Value::as_str) else {
        return json_error(400, "people discovery name must be text");
    };
    let Some(region) = object
        .get("region")
        .and_then(serde_json::Value::as_str)
        .and_then(crate::people_discovery::Region::parse)
    else {
        return json_error(400, "people discovery region must be au or us");
    };
    // The library's one name contract, before a worker or the discovery slot is taken.
    let name = match crate::people_discovery::checked_name(name) {
        Ok(name) => name,
        Err(error) => return json_error(400, &error.to_string()),
    };
    // Four sequential source facets can perform twelve guarded engine calls.
    // Keep at most one such fan-out on a low-RAM Termux handset at a time.
    let Some(slot) = Slot::take_of(&discovery.live, 1) else {
        return json_error(503, "people discovery capacity in use; retry shortly");
    };
    let handler = Arc::clone(&discovery.handler);
    let (sender, receiver) = sync_channel(1);
    let worker = thread::Builder::new()
        .name("serve-people-discover".into())
        .stack_size(LOOKUP_STACK_BYTES)
        .spawn(move || {
            let result = catch_unwind(AssertUnwindSafe(|| handler(&name, region)));
            drop(slot);
            let _ = sender.send(result);
        });
    if worker.is_err() {
        return json_error(503, "could not start people discovery worker");
    }
    match receiver.recv_timeout(super::LOOKUP_WAIT) {
        Ok(Ok(Ok(report))) => json_ok(&report.to_string(), false),
        Ok(Ok(Err(error))) => json_error(error.status, &error.message),
        Ok(Err(_)) | Err(RecvTimeoutError::Disconnected) => {
            json_error(500, "people discovery failed unexpectedly")
        }
        Err(RecvTimeoutError::Timeout) => json_error(
            504,
            "people discovery timed out; no completed report was saved",
        ),
    }
}

/// Start or join a bounded, durable autonomous mission through the *existing* scan service.
/// Only exact supported identifiers can become scan seeds. General text first needs a keyless
/// discovery pass and explicit selection of a supported pivot: a search hit is not identity proof.
/// This route performs no network I/O on the connection thread, and the ordinary Scans UI owns
/// cancellation, progress, evidence, checkpoints and restart recovery.
pub(super) fn research_mission_response(
    parsed: &ParsedRequest<'_>,
    scans: Option<&Arc<ScanApi>>,
) -> String {
    if parsed.method != Method::Post {
        return json_error(405, "starting a research mission needs POST");
    }
    if let Some(refused) = page_refusal(parsed, "research mission", true) {
        return refused;
    }
    if parsed.has_body {
        return json_error(
            400,
            "send research parameters in the query string, without a body",
        );
    }
    let Some(scans) = scans else {
        return json_error(
            404,
            "saved research missions are not enabled on this server",
        );
    };
    let query = match parse_lookup_query(parsed.query) {
        Ok(query) => query,
        Err(message) => return json_error(400, message),
    };
    let (kind, selector) = match crate::research_route::plan(&query.selector) {
        Ok(crate::research_route::ResearchAction::Targeted { kind, selector }) => (kind, selector),
        Ok(crate::research_route::ResearchAction::AdaptiveWeb { .. }) => {
            return json_error(
                422,
                "an arbitrary phrase is a discovery seed, not a verified scan target; research it first and choose a supported identifier",
            );
        }
        Err(message) => return json_error(400, message),
    };
    // No new scheduler, task database or unlimited recursion. The existing worker policy caps
    // dispatch, and all intermediate evidence is checkpointed in the saved scan store.
    let request = ScanRequest {
        target: selector,
        kind: Some(kind.command().to_owned()),
        options: crate::scan_store::ScanOptions {
            usecase: "passive".to_owned(),
            depth: 1,
            ..crate::scan_store::ScanOptions::default()
        },
        ..ScanRequest::default()
    };
    let record = match scans.service().start_or_join(&request) {
        Ok(record) => record,
        Err(failure) => return json_error(failure.status(), &failure.to_string()),
    };
    let body = serde_json::json!({
        "mission_id": record.id,
        "scan": record.id,
        "status": record.status.as_str(),
        "kind": record.kind,
        "selector": record.target,
        "autonomous": true,
        "execution": "saved_scan_with_bounded_evidence_gated_recursion",
        "usecase": "passive",
        "recursion_depth": 1,
        "limitations": [
            "passive_scan_can_query_external_sources_and_configured_credentials",
            "public_observations_are_not_independent_fact_verification",
            "follow_up_scope_is_limited_by_existing_scan_recursion_policy"
        ]
    });
    response(
        202,
        "application/json; charset=utf-8",
        &format!("{body}\n"),
        false,
    )
}

/// The saved scans: Spiderfoot's scan list, scan views, exports and state changes, answered by the
/// binary's [`ScanApi`]. A scan makes network requests and spends keys, and its results are the
/// operator's, so every call is guarded as a lookup is: refused cross-site or same-site, it needs
/// the lookup header (which another origin cannot send without a preflight this server never
/// approves), and on a public bind the bearer token. New scan creation accepts bounded
/// form-encoded POST bodies to keep targets out of URLs; old query-string clients still work.
/// All other saved-scan routes continue to refuse bodies.
pub(super) fn scans_response(parsed: &ParsedRequest<'_>, scans: Option<&Arc<ScanApi>>) -> Vec<u8> {
    let Some(scans) = scans else {
        return json_error(404, "saved scans are not enabled on this server").into_bytes();
    };
    if let Some(refused) = page_refusal(parsed, "scan request", true) {
        return refused.into_bytes();
    }
    // New scans may carry private selectors in a form-encoded POST body rather than the
    // URL. This is the only scan route that accepts a body; existing query-based
    // clients remain compatible. Reject a mixed body and query instead of guessing.
    let parameters =
        if parsed.method == Method::Post && parsed.path == "/api/scans" && parsed.has_body {
            if !parsed.query.is_empty() {
                return json_error(
                    400,
                    "new scan parameters must use either body or query, not both",
                )
                .into_bytes();
            }
            let Some(length) = parsed.content_length else {
                return json_error(400, "new scan body needs a Content-Length").into_bytes();
            };
            if length == 0 || length > super::MAX_FORM_BYTES {
                return json_error(413, "new scan body exceeds the form size limit").into_bytes();
            }
            let Some(body) = parsed.body else {
                return json_error(400, "new scan body missing").into_bytes();
            };
            if body.len() != length {
                return json_error(400, "new scan body incomplete or invalid UTF-8").into_bytes();
            }
            body
        } else {
            if parsed.has_body || parsed.body.is_some_and(|body| !body.is_empty()) {
                return json_error(400, "this scan route takes no request body").into_bytes();
            }
            parsed.query
        };
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
        parameters.to_owned(),
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
/// False-positive edits are heavy: they read and rewrite the saved result and need a permit.
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
            && matches!(action, "stop" | "delete" | "rerun"));
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entity::{Entity, EntityKind, Evidence, EvidenceProvenance};

    #[test]
    fn live_lookup_json_includes_canonical_source_join_without_mutating_evidence() {
        let mut domain = Entity::new(EntityKind::Domain, "example.org", 0.8, "live-a");
        domain.add_evidence(
            Evidence::new(
                EvidenceProvenance::for_scan("dns", "live-a"),
                "DNS response",
            )
            .with_attr("ip", "192.0.2.9"),
        );
        let mut ip = Entity::new(EntityKind::IpAddress, "192.0.2.9", 0.8, "live-b");
        ip.add_evidence(Evidence::new(
            EvidenceProvenance::for_scan("rdap", "live-b"),
            "RDAP response",
        ));
        let before = vec![domain.clone(), ip.clone()];
        let report = LookupReport {
            route: "domain",
            text: String::new(),
            entities: vec![domain, ip],
            outcomes: Vec::new(),
            scan: None,
            status: None,
        };
        let encoded = serialize_lookup(&report).expect("encode lookup");
        let json: serde_json::Value = serde_json::from_str(&encoded).expect("JSON");
        assert_eq!(
            json["synergy"]["links"][0]["relation"],
            "reported_dns_address"
        );
        assert_eq!(
            json["synergy"]["links"][0]["status"],
            "separately_observed_target"
        );
        assert_eq!(json["synergy"]["links"][0]["source_scan_id"], "live-a");
        assert_eq!(json["synergy"]["links"][0]["target_scan_id"], "live-b");
        assert_eq!(report.entities, before);
        assert_eq!(json["route"], "domain");
    }

    #[test]
    fn no_source_observations_means_no_live_synergy_claim() {
        let report = LookupReport {
            route: "domain",
            text: String::new(),
            entities: vec![Entity::new(EntityKind::Domain, "example.org", 0.8, "seed")],
            outcomes: Vec::new(),
            scan: Some("seed".to_owned()),
            status: Some("FINISHED"),
        };
        let json: serde_json::Value =
            serde_json::from_str(&serialize_lookup(&report).expect("encode")).expect("JSON");
        assert_eq!(json["synergy"]["links"], serde_json::json!([]));
        assert_eq!(json["scan"], "seed");
        assert_eq!(json["status"], "FINISHED");
    }
}
