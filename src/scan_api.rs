//! Spiderfoot's web API for saved scans, as one router the embedded server delegates to.
//!
//! [`ScanApi::handle`] answers `/api/scans...`, `/api/eventtypes`, `/api/correlationrules` and
//! `/api/settings` from a
//! method, a path and a query string, and knows nothing of sockets: the server applies its own
//! guards (same-origin, the `X-Huntsman-Lookup` header, the bearer token on a public bind) and
//! writes the [`ApiResponse`]. Every answer is JSON except exports. State changes are `POST` with
//! the parameters in the query string; `GET` and `HEAD` read.
//!
//! | Spiderfoot | here |
//! | --- | --- |
//! | `scanlist` | `GET /api/scans` |
//! | `startscan` | `POST /api/scans?target=T[&name=N][&kind=K][&usecase=U][&modules=a,b][&types=A,B][&depth=D]` |
//! | `scanstatus` | `GET /api/scans/ID` |
//! | `scansummary` | `GET /api/scans/ID/summary` |
//! | (shared analysis over saved entities) | `GET /api/scans/ID/analyze` |
//! | (source-attributed entity assessment) | `GET /api/scans/ID/reality?uid=ENTITY_UID` |
//! | `scaneventresults`, `scaneventresultsunique` | `GET /api/scans/ID/elements[?type=T][&unique=1][&hidefp=1][&correlation=C]` |
//! | `scancorrelations`, `scancorrelationsexport` | `GET /api/scans/ID/correlations[?format=csv|tsv|xlsx|json]` |
//! | `sf.py -C` | `POST /api/scans/ID/correlate` |
//! | `correlationrules` | `GET /api/correlationrules` |
//! | `scanlog`, `scanerrors` | `GET /api/scans/ID/log[?level=ERROR]` |
//! | `scanviz` | `GET /api/scans/ID/graph` |
//! | `scaneventresultexport`, `scanviz?gexf=1` | `GET /api/scans/ID/export?format=csv|tsv|xlsx|json|gexf|html[&type=T]` |
//! | `scaneventresultexportmulti`, `scanexportjsonmulti` | `GET /api/scans/export?ids=A,B[&format=json|csv|tsv|xlsx][&type=T]` |
//! | (none: Spiderfoot cannot compare scans) | `GET /api/scans/compare?ids=EARLIER,LATER[&format=json|csv|tsv|xlsx]` |
//! | (none: Spiderfoot cannot keep an alert history) | `GET /api/scans/alerts` |
//! | (none: Spiderfoot cannot alert on scans) | `GET /api/scans/alert?ids=EARLIER,LATER[&min_risk=HIGH\|MEDIUM\|LOW\|INFO][&values=1]` |
//! | `search` (one scan, or every scan here) | `GET /api/scans/search?value=V[&type=T][&ids=A,B][&hidefp=1]` |
//! | `stopscan`, `scandelete`, `rerunscan` | `POST /api/scans/ID/stop|delete|rerun` |
//! | `resultsetfp` | `POST /api/scans/ID/fp?ids=A,B&fp=1|0` |
//! | `eventtypes` | `GET /api/eventtypes` |
//! | `opts` (status only) | `GET /api/settings` |

use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

/// A saved multi-export can materialize several scan records. Admit only one
/// process-wide to prevent concurrent exports multiplying peak memory on phones.
static MULTI_EXPORT_ACTIVE: AtomicBool = AtomicBool::new(false);

/// The one multi-export a flag admits: while it is held, a second export, on any thread, is
/// refused with 503. Released when dropped, on every return and during unwinding.
struct MultiExportPermit(&'static AtomicBool);

impl MultiExportPermit {
    fn try_acquire(active: &'static AtomicBool) -> Option<Self> {
        active
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .ok()
            .map(|_| Self(active))
    }
}

impl Drop for MultiExportPermit {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

use serde_json::{Value, json};

use crate::analysis::analyze_snapshot;
use crate::api_leg::Api;
use crate::correlator::rule_catalog;
use crate::entity_reality;
use crate::evidence_register;
use crate::module::reachable_modules;
use crate::pipeline::{PipelineLimits, snapshot_from_entities};
use crate::scan_alert::{self, Policy};
use crate::scan_compare;
use crate::scan_export;
use crate::scan_route::ScanKind;
use crate::scan_search;
use crate::scan_service::{MAX_RUNNING, ScanRequest, ScanService, ServiceError, plan};
use crate::scan_store::{LogLevel, Risk, ScanOptions, ScanRecord, ScanResults, ScanStatus};
use crate::sf_correlate::{Rule, RuleError};
use crate::sf_elements::{self, DataElement};
use crate::sf_types;
use crate::source_outcome::{SourceExecutionOutcome, SourceOutcomeKind};
use crate::value_syntax::form_pairs;

/// Whether a key slot (an environment name such as `HUNTSMAN_SHODAN_KEY`) holds a key. Installed
/// by the binary, which owns the environment; it never sees or returns the value.
pub type SlotCheck = Arc<dyn Fn(&str) -> bool + Send + Sync>;

/// The most scans one multi-scan export reads.
pub const MAX_EXPORT_SCANS: usize = 50;

/// One answer for the server to write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiResponse {
    pub status: u16,
    pub content_type: &'static str,
    /// The bytes to send: UTF-8 text for every answer but an Excel export.
    pub body: Vec<u8>,
    /// For an export: the file name for `Content-Disposition: attachment`.
    pub filename: Option<String>,
}

impl ApiResponse {
    /// The body as text; only an Excel export is not text.
    #[must_use]
    pub fn text(&self) -> Cow<'_, str> {
        String::from_utf8_lossy(&self.body)
    }

    fn export(export: scan_export::Export) -> Self {
        Self {
            status: 200,
            content_type: export.content_type,
            body: export.body,
            filename: Some(export.filename),
        }
    }
}

const JSON: &str = "application/json; charset=utf-8";

/// Count recorded provider invocations, not distinct providers or possible sources.
/// A skipped keyed source and a request Huntsman's guard refused before sending are not
/// attempted requests, and neither is a confirmed empty result. These totals describe execution
/// coverage, never discovery completeness.
fn source_execution_summary(outcomes: &[SourceExecutionOutcome]) -> Value {
    let mut success = 0_usize;
    let mut valid_zero = 0_usize;
    let mut inconsistent_accepted_count = 0_usize;
    let mut not_configured = 0_usize;
    let mut refused_before_sending = 0_usize;
    let mut unresolved = 0_usize;
    for outcome in outcomes {
        let kind = outcome.kind;
        if kind == SourceOutcomeKind::Success && outcome.is_accepted() {
            success += 1;
        } else if kind == SourceOutcomeKind::ValidZero && outcome.is_accepted() {
            valid_zero += 1;
        } else if kind.is_accepted() {
            inconsistent_accepted_count += 1;
            unresolved += 1;
        } else if kind.is_not_configured() {
            not_configured += 1;
        } else if kind.is_refused_before_sending() {
            refused_before_sending += 1;
        } else {
            unresolved += 1;
        }
    }
    json!({
        "unit": "source_execution",
        "total": outcomes.len(),
        "attempted": success + valid_zero + unresolved,
        "accepted": success + valid_zero,
        "success": success,
        "valid_zero": valid_zero,
        "inconsistent_accepted_count": inconsistent_accepted_count,
        "not_configured": not_configured,
        "refused_before_sending": refused_before_sending,
        "unresolved": unresolved,
        "all_recorded_sources_accepted": !outcomes.is_empty()
            && not_configured == 0
            && refused_before_sending == 0
            && unresolved == 0,
    })
}

/// Keep the raw recorded verdict for audit and separately flag contradictory counts.
fn source_execution_row(outcome: &SourceExecutionOutcome) -> Value {
    json!({
        "module": outcome.module,
        "outcome": outcome.kind,
        "outcome_count_conflict": outcome.kind.is_accepted() && !outcome.is_accepted(),
        "observed_at_unix": outcome.observed_at_unix,
        "found": outcome.found,
        "http_status": outcome.http_status,
        "retry_after_secs": outcome.retry_after_secs,
        "detail": outcome.detail,
    })
}

fn ok(status: u16, value: &Value) -> ApiResponse {
    ApiResponse {
        status,
        content_type: JSON,
        body: format!("{value}\n").into_bytes(),
        filename: None,
    }
}

fn error(status: u16, message: &str) -> ApiResponse {
    ok(status, &json!({ "error": message }))
}

fn service_error(failure: &ServiceError) -> ApiResponse {
    error(failure.status(), &failure.to_string())
}

/// The keyed sources' slots, from each source's own [`Api`] constant: every indicator source's,
/// then the keyed legs the `ip`, `domain` and `phone` lookups run beside them, plus the sources
/// that read their key elsewhere.
fn key_slots() -> Vec<(&'static str, Vec<&'static str>)> {
    let legs: [&Api; 7] = [
        &crate::abn_lookup::API,
        &crate::abuseipdb::API,
        &crate::certspotter::API,
        &crate::exa::API,
        &crate::greynoise::API,
        &crate::numverify::API,
        &crate::virustotal::API,
    ];
    let mut slots: Vec<(&'static str, Vec<&'static str>)> = crate::indicator_legs::SOURCES
        .iter()
        .map(|source| source.api)
        .chain(legs)
        .filter_map(|api| api.key.map(|key| (api.source, vec![key.slot])))
        .collect();
    slots.extend([
        (
            "hibp",
            vec![
                crate::environment::HUNTSMAN_HIBP_KEY_ENV,
                crate::environment::HIBP_API_KEY_ENV,
            ],
        ),
        ("seeknow", vec![crate::seeknow::KEY_SLOT]),
        ("oathnet", vec![crate::oathnet::KEY_SLOT]),
        ("dehashed", vec![crate::dehashed::client::API_KEY_ENV]),
        ("stolen_tax", vec![crate::stolen_tax::KEY_SLOT]),
        ("github_user", vec![crate::environment::GITHUB_TOKEN_ENV]),
        (
            "wigle",
            vec![
                crate::environment::WIGLE_USER_ENV,
                crate::environment::WIGLE_TOKEN_ENV,
            ],
        ),
    ]);
    slots
}

/// Whether a module whose key slots are `slots` is set up: every slot it needs holds a key, an
/// alias standing in for its slot (`WiGLE` needs both of its slots; HIBP's one slot may be set
/// through `HIBP_API_KEY`, which is not needed beside it). **Pure.**
fn slots_set(slots: &[&str], set: impl Fn(&str) -> bool) -> bool {
    let fallbacks = crate::provider_credentials::SLOT_FALLBACKS;
    slots
        .iter()
        .filter(|slot| !fallbacks.iter().any(|(_, alias)| alias == *slot))
        .all(|slot| {
            set(slot)
                || fallbacks
                    .iter()
                    .any(|(fallback, alias)| fallback == slot && set(alias))
        })
}

/// A request's query parameters; the last of a repeated name wins.
struct Params(Vec<(String, String)>);

impl Params {
    fn get(&self, key: &str) -> Option<&str> {
        self.0
            .iter()
            .rev()
            .find(|(name, _)| name == key)
            .map(|(_, value)| value.as_str())
    }
}

/// Starts and reads saved scans for the embedded server.
pub struct ScanApi {
    service: Arc<ScanService>,
    slots: Option<SlotCheck>,
    /// Settings the binary adds to the page's Global Settings, after the store's own.
    globals: Vec<Value>,
    /// Admission slots for memory-intensive embedded-server scan responses. Shared across
    /// cloned HTTP routes and released when response construction has completed.
    web_request_slots: Arc<AtomicUsize>,
    /// Whether a multi-export holds its permit: [`MULTI_EXPORT_ACTIVE`], one for the process.
    multi_export: &'static AtomicBool,
}

impl ScanApi {
    #[must_use]
    pub fn new(service: Arc<ScanService>, slots: Option<SlotCheck>) -> Self {
        Self {
            service,
            slots,
            globals: Vec::new(),
            web_request_slots: Arc::new(AtomicUsize::new(0)),
            multi_export: &MULTI_EXPORT_ACTIVE,
        }
    }

    /// This API with a multi-export permit of its own, as each unit test's: the tests of one
    /// binary run in parallel, and an export one of them runs must not refuse another's.
    #[cfg(test)]
    #[must_use]
    fn with_own_multi_export(mut self) -> Self {
        self.multi_export = Box::leak(Box::new(AtomicBool::new(false)));
        self
    }

    /// Adds one entry to the Settings page's Global Settings: `key` names it in the API, the page
    /// shows `description` as its label and `value` beside it. For what only the binary knows,
    /// such as how `serve` was configured.
    #[must_use]
    pub fn with_global(mut self, key: &str, description: &str, value: impl Into<Value>) -> Self {
        self.globals.push(json!({
            "key": key,
            "description": description,
            "value": value.into(),
        }));
        self
    }

    #[must_use]
    pub fn service(&self) -> &Arc<ScanService> {
        &self.service
    }

    /// The shared admission counter for expensive embedded HTTP scan responses.
    /// The HTTP boundary owns the policy and the RAII permit, not this scan API.
    pub(crate) fn web_request_slots(&self) -> &Arc<AtomicUsize> {
        &self.web_request_slots
    }

    /// Whether `path` is one [`Self::handle`] answers.
    #[must_use]
    pub fn handles(path: &str) -> bool {
        path == "/api/scans"
            || path.starts_with("/api/scans/")
            || path == "/api/eventtypes"
            || path == "/api/correlationrules"
            || path == "/api/settings"
    }

    /// Answer one request. `method` is `GET`, `HEAD` or `POST`; `query` is the raw query string
    /// without the `?`.
    #[must_use]
    pub fn handle(&self, method: &str, path: &str, query: &str) -> ApiResponse {
        let Some(params) = form_pairs(query) else {
            return error(400, "query is not valid percent-encoded UTF-8");
        };
        let read = matches!(method, "GET" | "HEAD");
        let write = method == "POST";
        if !read && !write {
            return error(405, "use GET to read and POST to change");
        }
        let param = Params(params);
        let segments: Vec<&str> = path
            .trim_start_matches("/api/")
            .split('/')
            .filter(|segment| !segment.is_empty())
            .collect();
        match (segments.as_slice(), write) {
            (["eventtypes"], false) => event_types(),
            (["correlationrules"], false) => self.correlation_rules(),
            (["settings"], false) => self.settings(),
            (["scans"], false) => self.list(),
            (["scans"], true) => self.start(&param),
            (["scans", "export"], false) => self.export_many(&param),
            (["scans", "compare"], false) => self.compare(&param),
            (["scans", "alert"], false) => self.alert(&param),
            (["scans", "alerts"], false) => self.alerts(),
            (["scans", "search"], false) => self.search(&param),
            (["scans", id], false) => self.status(id),
            (["scans", id, "summary"], false) => self.summary(id),
            (["scans", id, "analyze"], false) => self.analyze(id),
            (["scans", id, "evidence"], false) => self.evidence(id, &param),
            (["scans", id, "matrix"], false) => self.matrix(id, &param),
            (["scans", id, "reality"], false) => self.reality(id, param.get("uid")),
            (["scans", _, "reality"], true) => error(405, "entity reality is read-only"),
            (["scans", id, "elements"], false) => self.elements(id, &param),
            (["scans", id, "correlations"], false) => self.correlations(id, param.get("format")),
            (["scans", id, "correlate"], true) => match self.service.correlate(id) {
                Ok(correlations) => ok(200, &json!(correlations)),
                Err(failure) => service_error(&failure),
            },
            (["scans", id, "log"], false) => self.log(id, param.get("level")),
            (["scans", id, "graph"], false) => self.graph(id),
            (["scans", id, "export"], false) => self.export(id, &param),
            (["scans", id, "stop"], true) => match self.service.stop(id) {
                Ok(record) => ok(202, &json!(record)),
                Err(failure) => service_error(&failure),
            },
            (["scans", id, "delete"], true) => match self.service.delete(id) {
                Ok(()) => ok(200, &json!({ "deleted": id })),
                Err(failure) => service_error(&failure),
            },
            (["scans", id, "rerun"], true) => match self.service.rerun(id) {
                Ok(record) => ok(202, &json!(record)),
                Err(failure) => service_error(&failure),
            },
            (["scans", id, "fp"], true) => self.set_fp(id, &param),
            (_, true) if route_exists(&segments, false) => error(405, "this path is read with GET"),
            (_, false) if route_exists(&segments, true) => {
                error(405, "this path changes a scan; use POST")
            }
            _ => error(404, "no such scan API path"),
        }
    }

    fn settings(&self) -> ApiResponse {
        let slots = key_slots();
        let modules: Vec<Value> = reachable_modules()
            .iter()
            .map(|module| {
                // HIBP's account search reads HIBP's key, WiGLE's Bluetooth search WiGLE's.
                let keyed_as = crate::module::module_of(module.name);
                let key_env: Vec<&str> = slots
                    .iter()
                    .find(|(source, _)| *source == keyed_as)
                    .map(|(_, slots)| slots.clone())
                    .unwrap_or_default();
                let configured = match &self.slots {
                    Some(check) if !key_env.is_empty() => {
                        Value::Bool(slots_set(&key_env, |slot| check(slot)))
                    }
                    _ => Value::Null,
                };
                json!({
                    "name": module.name,
                    "category": module.category,
                    "access": module.access,
                    "network": module.network,
                    "command": module.command,
                    "description": module.description,
                    // The same TA0043 mapping used by operational source selection.
                    // Metadata is an acquisition opportunity, never proof of a finding.
                    "attack_techniques": module.attack_techniques,
                    "key_env": key_env,
                    "configured": configured,
                    "lookups": crate::lookup_modules::lookups_asking(module.name),
                    // The lookups that run an offline module over the target itself, so the
                    // page can say so instead of "no scan lookup asks it".
                    "offline_in": crate::lookup_modules::lookups_running_offline(module.name),
                    "spiderfoot": crate::module::spiderfoot_names(module.name),
                })
            })
            .collect();
        let mut global = json!([
                    {
                        "key": "scan_dir",
                        "description": "where saved scans are kept",
                        "value": self.service.store().dir().display().to_string(),
                    },
                    {
                        "key": "max_running_scans",
                        "description": "scans that run at once; more wait as STARTING",
                        "value": MAX_RUNNING,
                    },
                    {
                        "key": "egress",
                        "description": "where lookups may connect",
                        "value": "public addresses only",
                    },
                    {
                        "key": "keys",
                        "description": "each source reads its key from the environment variable its key_env names; this page shows only whether each is set, never a value",
                        "value": "environment",
                    },
        ]);
        if let Some(list) = global.as_array_mut() {
            list.extend(self.globals.iter().cloned());
        }
        ok(
            200,
            &json!({
                "modules": modules,
                "global": global,
            }),
        )
    }

    fn list(&self) -> ApiResponse {
        match self.service.records() {
            Ok(records) => ok(200, &json!(records)),
            Err(failure) => service_error(&failure),
        }
    }

    fn start(&self, param: &Params) -> ApiResponse {
        let list = |key: &str| -> Vec<String> {
            param
                .get(key)
                .unwrap_or_default()
                .split(',')
                .map(str::trim)
                .filter(|item| !item.is_empty())
                .map(str::to_owned)
                .collect()
        };
        let depth = match param
            .get("depth")
            .map(str::trim)
            .filter(|depth| !depth.is_empty())
        {
            None => 0,
            Some(depth) => match depth.parse::<u32>() {
                Ok(depth) => depth,
                Err(_) => return error(400, "depth is a whole number of hops, 0 or more"),
            },
        };
        let request = ScanRequest {
            target: param.get("target").unwrap_or_default().to_owned(),
            name: param.get("name").map(str::to_owned),
            kind: param.get("kind").map(str::to_owned),
            options: ScanOptions {
                usecase: param.get("usecase").unwrap_or("all").to_owned(),
                modules: list("modules"),
                types: list("types"),
                depth,
            },
        };
        match self.service.start(&request) {
            Ok(record) => ok(202, &json!(record)),
            Err(failure) => service_error(&failure),
        }
    }

    fn record(&self, id: &str) -> Result<ScanRecord, ApiResponse> {
        self.service
            .record(id)
            .map_err(|failure| service_error(&failure))
    }

    fn results(&self, id: &str) -> Result<(ScanRecord, Option<ScanResults>), ApiResponse> {
        let record = self.record(id)?;
        let results = self
            .service
            .store()
            .results(id)
            .map_err(|failure| service_error(&failure.into()))?;
        Ok((record, results))
    }

    /// Derive a raw or JSON evidence register from an existing completed scan.
    /// A baseline yields a delta, including observation-only updates and removals.
    fn evidence(&self, id: &str, params: &Params) -> ApiResponse {
        let format = params.get("format").unwrap_or("raw");
        if !matches!(format, "raw" | "json") {
            return error(400, "evidence format must be raw or json");
        }
        let (record, results) = match self.results(id) {
            Ok(found) => found,
            Err(response) => return response,
        };
        if record.status.is_active() {
            return error(409, "evidence register requires a stopped scan");
        }
        let Some(saved) = results else {
            return error(409, "scan has no saved results");
        };
        let previous = if let Some(baseline) = params.get("baseline") {
            let (old_record, old_results) = match self.results(baseline) {
                Ok(found) => found,
                Err(response) => return response,
            };
            if old_record.status.is_active() {
                return error(409, "baseline scan is active");
            }
            if record.target != old_record.target || record.kind != old_record.kind {
                return error(
                    409,
                    "baseline and current scans must have the same target and kind",
                );
            }
            let Some(old_saved) = old_results else {
                return error(409, "baseline scan has no saved results");
            };
            Some((old_record, old_saved))
        } else {
            None
        };
        let report = match evidence_register::compile(
            &record,
            &saved,
            previous.as_ref().map(|(prior, results)| (prior, results)),
        ) {
            Ok(report) => report,
            Err(reason) => return error(413, &reason),
        };
        let (body, content_type, extension) = if format == "json" {
            match serde_json::to_vec_pretty(&report) {
                Ok(body) => (body, JSON, "json"),
                Err(failure) => return error(500, &failure.to_string()),
            }
        } else {
            match evidence_register::raw_text(&report) {
                Ok(body) => (body.into_bytes(), "text/plain; charset=utf-8", "txt"),
                Err(reason) => return error(413, &reason),
            }
        };
        if body.len() > evidence_register::MAX_RENDER_BYTES {
            return error(
                413,
                "evidence output exceeds bounded export size; no output truncated",
            );
        }
        ApiResponse {
            status: 200,
            content_type,
            body,
            filename: Some(format!("{}-evidence.{extension}", record.id)),
        }
    }

    /// A read-only source-by-finding matrix over the saved evidence elements.
    fn matrix(&self, id: &str, params: &Params) -> ApiResponse {
        let format = params.get("format").unwrap_or("json");
        if !matches!(format, "raw" | "json") {
            return error(400, "matrix format must be raw or json");
        }
        let (record, results) = match self.results(id) {
            Ok(found) => found,
            Err(response) => return response,
        };
        if record.status.is_active() {
            return error(409, "matrix requires a stopped scan");
        }
        let Some(saved) = results else {
            return error(409, "scan has no saved results");
        };
        let report = match evidence_register::compile_matrix(&record, &saved) {
            Ok(report) => report,
            Err(reason) => return error(413, &reason),
        };
        let (body, content_type, extension) = if format == "json" {
            match serde_json::to_vec_pretty(&report) {
                Ok(body) => (body, JSON, "json"),
                Err(failure) => return error(500, &failure.to_string()),
            }
        } else {
            match evidence_register::matrix_raw_text(&report) {
                Ok(body) => (body.into_bytes(), "text/plain; charset=utf-8", "txt"),
                Err(reason) => return error(413, &reason),
            }
        };
        if body.len() > evidence_register::MAX_RENDER_BYTES {
            return error(413, "matrix export exceeds 8 MiB; nothing truncated");
        }
        ApiResponse {
            status: 200,
            content_type,
            body,
            filename: Some(format!("{}-matrix.{extension}", record.id)),
        }
    }

    /// Run the shared deterministic analysis over saved entities, without network requests or
    /// modifications to the original scan. Provider coverage and upstream independence cannot
    /// be reconstructed from merged entities, so the response makes both limitations explicit.
    fn analyze(&self, id: &str) -> ApiResponse {
        let (record, results) = match self.results(id) {
            Ok(found) => found,
            Err(response) => return response,
        };
        if record.status.is_active() {
            return error(409, "scan is active; analyze it after its worker stops");
        }
        let Some(results) = results else {
            return error(409, "scan has no saved results to analyze");
        };

        let limits = PipelineLimits::default();
        let count = results.entities.len().min(limits.max_entities);
        let flagged_elements = results.elements.iter().filter(|element| element.fp).count();
        // SpiderFoot flags describe individual evidence elements and all their descendants.
        // The merged entities below no longer expose a lossless element-to-evidence index.
        // Analyzing them despite any flags would re-introduce the discredited claims into
        // graph links, pivots and correlations. Refuse instead of inventing a filter.
        if flagged_elements != 0 {
            return error(
                409,
                "scan contains false-positive elements; saved-entity analysis cannot safely exclude their evidence",
            );
        }
        let mut snapshot = snapshot_from_entities(&results.entities[..count], id, &limits);
        snapshot.truncated |= count < results.entities.len();
        let report = analyze_snapshot(&snapshot);

        ok(
            200,
            &json!({
                "scan": {
                    "id": record.id,
                    "target": record.target,
                    "status": record.status,
                },
                "source": "saved_scan_entities",
                "limitations": {
                    "original_evidence": "retained_in_saved_results",
                    "provider_coverage": "not_reconstructed",
                    "evidence_ancestry": "not_reconstructed",
                    "false_positive_annotations": "none_present",
                    "scan_complete": record.status == ScanStatus::Finished,
                    "truncated": snapshot.truncated,
                },
                "counts": {
                    "saved_entities": results.entities.len(),
                    "analyzed_entities": snapshot.entities.len(),
                    "derived_relations": snapshot.relations.len(),
                    "source_outcomes": results.outcomes.len(),
                    "flagged_elements": flagged_elements,
                },
                "report": report,
            }),
        )
    }

    /// Attribute recorded assertions to sources without converting them into verified truth.
    /// The saved evidence is read without network requests or store modification.
    fn reality(&self, id: &str, uid: Option<&str>) -> ApiResponse {
        let Some(uid) = uid.filter(|uid| !uid.trim().is_empty()) else {
            return error(400, "reality requires an entity uid");
        };
        let (record, results) = match self.results(id) {
            Ok(found) => found,
            Err(response) => return response,
        };
        if record.status.is_active() {
            return error(409, "scan is active; assess it after its worker stops");
        }
        let Some(results) = results else {
            return error(409, "scan has no saved results to assess");
        };
        // An element-level false positive cannot be safely projected to merged entity
        // evidence. Refuse the report rather than silently laundering flagged sources.
        if results.elements.iter().any(|element| element.fp) {
            return error(
                409,
                "scan contains false-positive elements; entity evidence cannot be safely filtered",
            );
        }
        let Some(entity) = results.entities.iter().find(|entity| entity.uid == uid) else {
            return error(404, "entity uid is not present in the saved scan");
        };
        ok(
            200,
            &json!({
                "scan": {
                    "id": record.id,
                    "status": record.status,
                    "complete": record.status == ScanStatus::Finished,
                },
                "entity": entity_reality::assess(entity),
                "source": "saved_entity_evidence",
                "provider_coverage": "not_reconstructed",
                "independent_source_proof": "not_reconstructed",
                "source_authenticity": "not_established",
            }),
        )
    }

    fn status(&self, id: &str) -> ApiResponse {
        let (record, results) = match self.results(id) {
            Ok(found) => found,
            Err(response) => return response,
        };
        let sources: Vec<Value> = results
            .as_ref()
            .map(|results| results.outcomes.iter().map(source_execution_row).collect())
            .unwrap_or_default();
        let uncertainty_register = crate::scan_uncertainty::derive(&record, results.as_ref());
        let mut value = json!(record);
        value["sources"] = Value::Array(sources);
        value["uncertainty_register"] = json!(uncertainty_register);
        value["people_source_coverage"] =
            json!(crate::scan_coverage::derive(&record, results.as_ref()));
        value["source_execution_summary"] = results.as_ref().map_or(Value::Null, |saved| {
            source_execution_summary(&saved.outcomes)
        });
        value["termination"] = json!(results.as_ref().and_then(|results| results.termination));
        value["lineage"] = json!(
            results
                .as_ref()
                .map(|results| results.lineage.as_slice())
                .unwrap_or_default()
        );
        value["report"] = results.map_or(Value::Null, |results| Value::String(results.text));
        // What the runner does with each New Scan option, so the page never shows a dead control.
        value["honoured"] = json!({
            "usecase": true,
            "types": true,
            "modules": true,
            "depth": true,
        });
        ok(200, &value)
    }

    fn summary(&self, id: &str) -> ApiResponse {
        match self.results(id) {
            Ok((_, results)) => {
                let elements = results.map(|results| results.elements).unwrap_or_default();
                ok(200, &json!(sf_elements::summary(&elements)))
            }
            Err(response) => response,
        }
    }

    fn elements(&self, id: &str, param: &Params) -> ApiResponse {
        let results = match self.results(id) {
            Ok((_, results)) => results,
            Err(response) => return response,
        };
        let Some(results) = results else {
            return ok(200, &json!([]));
        };
        let flag = |key: &str| {
            param
                .get(key)
                .is_some_and(|value| matches!(value, "1" | "true"))
        };
        let mut chosen: Vec<&DataElement> = results
            .elements
            .iter()
            .filter(|element| element.kind != "ROOT")
            .collect();
        if let Some(kind) = param
            .get("type")
            .filter(|kind| !kind.is_empty() && *kind != "ALL")
        {
            chosen.retain(|element| element.kind.eq_ignore_ascii_case(kind));
        }
        if flag("hidefp") {
            chosen.retain(|element| !element.fp);
        }
        if let Some(correlation) = param.get("correlation") {
            let Some(found) = results
                .correlations
                .iter()
                .find(|item| item.id == correlation)
            else {
                return error(404, "no such correlation in this scan");
            };
            let wanted: BTreeSet<&str> = found.elements.iter().map(String::as_str).collect();
            chosen.retain(|element| wanted.contains(element.id.as_str()));
        }
        if flag("unique") {
            let mut seen = BTreeSet::new();
            chosen.retain(|element| seen.insert((element.kind.as_str(), element.data.as_str())));
        }
        ok(200, &Value::Array(element_rows(&results, chosen)))
    }

    /// `GET /api/scans/compare?ids=EARLIER,LATER`: what the later scan found that the earlier did
    /// not, what it no longer finds, the change in each data type and the correlations each has
    /// that the other lacks ([`scan_compare`]). JSON by default; `csv`, `tsv` and `xlsx` are the
    /// added and removed elements as a file. A scan with no results yet compares as empty.
    /// Spiderfoot's `search`, over the scans `ids` names or every saved scan: each matching
    /// element as `/elements` gives it, with the scan it belongs to.
    fn search(&self, param: &Params) -> ApiResponse {
        let value = param.get("value").unwrap_or_default();
        let kind = param
            .get("type")
            .filter(|kind| !kind.is_empty() && *kind != "ALL");
        if value.trim().is_empty() && kind.is_none() {
            return error(400, "search needs a value, a type or both");
        }
        let query = match scan_search::Query::parse(value) {
            Ok(query) => query,
            Err(failure) => return error(400, &failure.to_string()),
        };
        let ids: Vec<&str> = param
            .get("ids")
            .unwrap_or_default()
            .split(',')
            .map(str::trim)
            .filter(|id| !id.is_empty())
            .collect();
        let records = if ids.is_empty() {
            match self.service.store().list() {
                Ok(records) => records,
                Err(failure) => return service_error(&failure.into()),
            }
        } else {
            let mut records = Vec::with_capacity(ids.len());
            for id in ids {
                match self.record(id) {
                    Ok(record) => records.push(record),
                    Err(response) => return response,
                }
            }
            records
        };
        let hide_fp = matches!(param.get("hidefp"), Some("1" | "true"));
        let mut rows = Vec::new();
        for record in records {
            let results = match self.service.store().results(&record.id) {
                Ok(Some(results)) => results,
                Ok(None) => continue,
                Err(failure) => return service_error(&failure.into()),
            };
            let mut hits = scan_search::hits(&results, &query, kind);
            if hide_fp {
                hits.retain(|element| !element.fp);
            }
            for mut row in element_rows(&results, hits) {
                row["scan_id"] = Value::String(record.id.clone());
                row["scan_name"] = Value::String(record.name.clone());
                row["scan_target"] = Value::String(record.target.clone());
                rows.push(row);
            }
        }
        ok(200, &Value::Array(rows))
    }

    /// `GET /api/scans/alert?ids=EARLIER,LATER[&min_risk=HIGH|MEDIUM|LOW|INFO][&values=1]`: whether
    /// the later scan raises an alert over the earlier one, the decision `scans alert` makes
    /// ([`scan_alert`]). Read-only and offline; scans of different targets are refused.
    /// `GET /api/scans/alerts`: every decision `scans alert` and `scans watch` made, raised or not,
    /// oldest first, from the history kept beside the scans ([`scan_alert`]). Empty until one is
    /// made.
    fn alerts(&self) -> ApiResponse {
        let path = self.service.store().dir().join(scan_alert::HISTORY_FILE);
        match scan_alert::read_history(&path) {
            Ok(entries) => ok(200, &Value::Array(entries)),
            Err(failure) => error(500, &failure.to_string()),
        }
    }

    /// `GET /api/scans/alert?ids=EARLIER,LATER[&min_risk=HIGH|MEDIUM|LOW|INFO][&values=1]`: whether
    /// the later scan raises an alert over the earlier one, the decision `scans alert` makes
    /// ([`scan_alert`]). Read-only and offline; scans of different targets are refused.
    fn alert(&self, param: &Params) -> ApiResponse {
        let ids: Vec<&str> = param
            .get("ids")
            .unwrap_or_default()
            .split(',')
            .map(str::trim)
            .filter(|id| !id.is_empty())
            .collect();
        let &[earlier, later] = ids.as_slice() else {
            return error(400, "alert takes two scan ids: ids=EARLIER,LATER");
        };
        let min_risk = match param.get("min_risk").filter(|text| !text.is_empty()) {
            None => Risk::High,
            Some(text) => match scan_alert::parse_min_risk(text) {
                Some(risk) => risk,
                None => return error(400, "min_risk takes HIGH, MEDIUM, LOW or INFO"),
            },
        };
        let policy = Policy {
            min_risk,
            new_values: matches!(param.get("values"), Some("1" | "true")),
        };
        let mut scans = Vec::with_capacity(2);
        for id in [earlier, later] {
            match self.results(id) {
                Ok((record, results)) => {
                    let results = results.unwrap_or_else(|| empty_results(&record));
                    scans.push((record, results));
                }
                Err(response) => return response,
            }
        }
        let [(base, base_results), (other, other_results)] = [&scans[0], &scans[1]];
        if base.target != other.target {
            return error(
                400,
                "alert: the two scans have different targets, so no change between them is an alert",
            );
        }
        let decision =
            scan_alert::assess(&scan_compare::compare(base_results, other_results), policy);
        ok(
            200,
            &json!({ "earlier": earlier, "later": later, "alert": decision }),
        )
    }

    fn compare(&self, param: &Params) -> ApiResponse {
        let ids: Vec<&str> = param
            .get("ids")
            .unwrap_or_default()
            .split(',')
            .map(str::trim)
            .filter(|id| !id.is_empty())
            .collect();
        let &[earlier, later] = ids.as_slice() else {
            return error(400, "compare takes two scan ids: ids=EARLIER,LATER");
        };
        let mut scans = Vec::with_capacity(2);
        for id in [earlier, later] {
            match self.results(id) {
                Ok((record, results)) => {
                    let results = results.unwrap_or_else(|| empty_results(&record));
                    scans.push((record, results));
                }
                Err(response) => return response,
            }
        }
        let [(base, base_results), (other, other_results)] = [&scans[0], &scans[1]];
        let comparison = scan_compare::compare(base_results, other_results);
        let format = param.get("format").filter(|format| !format.is_empty());
        if let Some(format) = format.filter(|format| !format.eq_ignore_ascii_case("json")) {
            return match scan_compare::render(
                [(base, base_results), (other, other_results)],
                &comparison,
                format,
            ) {
                Ok(export) => ApiResponse::export(export),
                Err(message) => error(400, &message),
            };
        }
        let earlier_execution = source_execution_summary(&base_results.outcomes);
        let later_execution = source_execution_summary(&other_results.outcomes);
        let changed_modules = scan_compare::changed_source_modules(base_results, other_results);
        let source_execution_changed = !changed_modules.is_empty();
        let value = json!({
            "base": base,
            "other": other,
            "unchanged": comparison.unchanged(),
            "source_execution": {
                "earlier": earlier_execution,
                "later": later_execution,
                "changed_modules": changed_modules,
            },
            "source_execution_changed": source_execution_changed,
            "types": comparison.types,
            "added": element_rows(other_results, comparison.added.iter().copied()),
            "removed": element_rows(base_results, comparison.removed.iter().copied()),
            "correlations": {
                "added": comparison.correlations_added,
                "removed": comparison.correlations_removed,
            },
        });
        if format.is_none() {
            return ok(200, &value);
        }
        // Asked for as a file: the same answer, under the comparison's file name.
        ApiResponse::export(scan_export::Export {
            body: value.to_string().into_bytes(),
            content_type: "application/json; charset=utf-8",
            filename: format!("{}-vs-{}-Huntsman.json", base.id, other.id),
        })
    }

    fn correlations(&self, id: &str, format: Option<&str>) -> ApiResponse {
        let (record, results) = match self.results(id) {
            Ok(found) => found,
            Err(response) => return response,
        };
        let results = results.unwrap_or_else(|| empty_results(&record));
        let Some(format) = format.filter(|format| !format.is_empty()) else {
            return ok(200, &json!(results.correlations));
        };
        match scan_export::render_correlations(&record, &results, format) {
            Ok(export) => ApiResponse::export(export),
            Err(message) => error(400, &message),
        }
    }

    fn correlation_rules(&self) -> ApiResponse {
        ok(
            200,
            &correlation_rules(self.service.rules(), self.service.rule_errors()),
        )
    }

    fn log(&self, id: &str, level: Option<&str>) -> ApiResponse {
        let wanted = match level.map(str::to_ascii_uppercase).as_deref() {
            None | Some("" | "ALL") => None,
            Some("INFO") => Some(LogLevel::Info),
            Some("WARNING") => Some(LogLevel::Warning),
            Some("ERROR") => Some(LogLevel::Error),
            Some(_) => return error(400, "level is INFO, WARNING or ERROR"),
        };
        match self.service.store().log(id) {
            Ok(entries) => ok(
                200,
                &json!(
                    entries
                        .into_iter()
                        .filter(|entry| wanted.is_none_or(|level| entry.level == level))
                        .collect::<Vec<_>>()
                ),
            ),
            Err(failure) => service_error(&failure.into()),
        }
    }

    fn graph(&self, id: &str) -> ApiResponse {
        let results = match self.results(id) {
            Ok((_, results)) => results,
            Err(response) => return response,
        };
        let elements = results.map(|results| results.elements).unwrap_or_default();
        let nodes: Vec<Value> = elements
            .iter()
            .map(|element| {
                json!({
                    "id": element.id,
                    "type": element.kind,
                    "data": element.data,
                    "module": element.module,
                    "fp": element.fp,
                })
            })
            .collect();
        let edges: Vec<Value> = elements
            .iter()
            .filter_map(|element| {
                element
                    .source
                    .as_ref()
                    .map(|source| json!({ "source": source, "target": element.id }))
            })
            .collect();
        ok(200, &json!({ "nodes": nodes, "edges": edges }))
    }

    fn export(&self, id: &str, param: &Params) -> ApiResponse {
        let limit = u64::try_from(PipelineLimits::default().max_export_bytes).unwrap_or(u64::MAX);
        self.export_with_budget(id, param, limit)
    }

    fn export_with_budget(&self, id: &str, param: &Params, max_bytes: u64) -> ApiResponse {
        // Refuse unsupported output formats before loading or deserializing evidence.
        let format = param.get("format").unwrap_or("csv");
        let normalized = format.trim().to_ascii_lowercase();
        if normalized != "excel" && !scan_export::FORMATS.contains(&normalized.as_str()) {
            return error(400, "unsupported single-scan export format");
        }
        let record = match self.record(id) {
            Ok(record) => record,
            Err(response) => return response,
        };
        // The general results() loader permits a much larger saved scan. Exports
        // must acquire their smaller I/O budget before allocating parsed records.
        let (results, _) = match self.service.store().results_with_byte_budget(id, max_bytes) {
            Ok(found) => found,
            Err(crate::scan_store::StoreError::Invalid(message)) => {
                return error(413, &message);
            }
            Err(failure) => return service_error(&failure.into()),
        };
        let results = results.unwrap_or_else(|| empty_results(&record));
        match scan_export::render(
            &record,
            &results,
            format,
            param.get("type").filter(|kind| !kind.is_empty()),
        ) {
            Ok(export) if u64::try_from(export.body.len()).unwrap_or(u64::MAX) > max_bytes => {
                // The legacy single-scan renderer still constructs its output
                // before this check. Input admission is bounded above; streaming
                // output serializers are a separate follow-up.
                error(413, "export output budget exceeded")
            }
            Ok(export) => ApiResponse::export(export),
            Err(message) => error(400, &message),
        }
    }

    fn export_many(&self, param: &Params) -> ApiResponse {
        let limit = u64::try_from(PipelineLimits::default().max_export_bytes).unwrap_or(u64::MAX);
        self.export_many_with_budget(param, limit)
    }

    fn export_many_with_budget(&self, param: &Params, max_bytes: u64) -> ApiResponse {
        // Reject unsupported formats before reading or deserializing saved evidence.
        // Preserve SpiderFoot's `excel` alias for XLSX.
        let format = param.get("format").unwrap_or("json");
        let normalized = format.trim().to_ascii_lowercase();
        let normalized = if normalized == "excel" {
            "xlsx"
        } else {
            normalized.as_str()
        };
        if !scan_export::MANY_FORMATS.contains(&normalized) {
            return error(400, "unsupported multi-scan export format");
        }
        let ids: Vec<&str> = param
            .get("ids")
            .unwrap_or_default()
            .split(',')
            .map(str::trim)
            .filter(|id| !id.is_empty())
            .collect();
        if ids.is_empty() {
            return error(400, "export needs ids, comma separated");
        }
        if ids.len() > MAX_EXPORT_SCANS {
            return error(
                400,
                &format!("export takes at most {MAX_EXPORT_SCANS} scans"),
            );
        }
        // Validate the request before acquiring the process-wide export permit.
        // RAII releases on every return and during unwinding.
        let Some(_permit) = MultiExportPermit::try_acquire(self.multi_export) else {
            return error(503, "another multi-scan export is already running");
        };
        // Reserve only the bounded number of scan slots, avoiding incremental
        // vector growth while evidence is loaded under the aggregate budget.
        let mut scans = Vec::with_capacity(ids.len());
        let mut remaining = max_bytes;
        for id in ids {
            let record = match self.record(id) {
                Ok(record) => record,
                Err(response) => return response,
            };
            let (results, charged) =
                match self.service.store().results_with_byte_budget(id, remaining) {
                    Ok(found) => found,
                    Err(crate::scan_store::StoreError::Invalid(message)) => {
                        return error(413, &message);
                    }
                    Err(failure) => return service_error(&failure.into()),
                };
            remaining = remaining.saturating_sub(charged);
            let results = results.unwrap_or_else(|| empty_results(&record));
            scans.push((record, results));
        }
        let pairs: Vec<(&ScanRecord, &ScanResults)> = scans
            .iter()
            .map(|(record, results)| (record, results))
            .collect();
        let kind = param.get("type").filter(|kind| !kind.is_empty());
        if format.trim().eq_ignore_ascii_case("json") {
            return match scan_export::render_many_json_bounded(
                &pairs,
                kind,
                usize::try_from(max_bytes).unwrap_or(usize::MAX),
            ) {
                Ok(Ok(export)) => ApiResponse::export(export),
                Ok(Err(_)) => error(413, "export output budget exceeded"),
                Err(message) => error(400, &message),
            };
        }
        if matches!(format.trim().to_ascii_lowercase().as_str(), "csv" | "tsv") {
            return match scan_export::render_many_text_bounded(
                &pairs,
                format,
                kind,
                usize::try_from(max_bytes).unwrap_or(usize::MAX),
            ) {
                Ok(Ok(export)) => ApiResponse::export(export),
                Ok(Err(_)) => error(413, "export output budget exceeded"),
                Err(message) => error(400, &message),
            };
        }
        // Preflight a conservative upper bound before constructing XLSX XML
        // and ZIP buffers. The saved-result input budget was enforced above.
        match scan_export::render_many_xlsx_bounded(
            &pairs,
            kind,
            usize::try_from(max_bytes).unwrap_or(usize::MAX),
        ) {
            Ok(Ok(export)) => ApiResponse::export(export),
            Ok(Err(_)) => error(413, "export output budget exceeded"),
            Err(message) => error(400, &message),
        }
    }

    fn set_fp(&self, id: &str, param: &Params) -> ApiResponse {
        let flag = match param.get("fp") {
            Some("1" | "true") => true,
            Some("0" | "false") => false,
            _ => return error(400, "fp is 1 or 0"),
        };
        let ids: BTreeSet<&str> = param
            .get("ids")
            .unwrap_or_default()
            .split(',')
            .map(str::trim)
            .filter(|id| !id.is_empty())
            .collect();
        if ids.is_empty() {
            return error(400, "fp needs ids, comma separated");
        }
        let (record, results) = match self.results(id) {
            Ok(found) => found,
            Err(response) => return response,
        };
        if record.status.is_active() || record.status == ScanStatus::Created {
            return error(409, "a scan's results can be flagged once it has finished");
        }
        let Some(mut results) = results else {
            return error(404, "this scan saved no results");
        };
        let named = results
            .elements
            .iter()
            .filter(|element| ids.contains(element.id.as_str()) && element.kind != "ROOT")
            .count();
        if named != ids.len() {
            return error(404, "an id names no element of this scan");
        }
        let affected = with_descendants(&results.elements, &ids);
        if !flag {
            if let Some(blocked) = unflag_blocked(&results.elements, &ids, &affected) {
                return error(
                    409,
                    &format!(
                        "element {blocked} was found from an element that is still a false \
                         positive: unset that one, which unsets everything found from it"
                    ),
                );
            }
        }
        let affected: BTreeSet<String> = affected.into_iter().map(str::to_owned).collect();
        let mut changed = Vec::new();
        for element in &mut results.elements {
            if affected.contains(&element.id) && element.kind != "ROOT" {
                element.fp = flag;
                changed.push(element.id.clone());
            }
        }
        match self.service.store().save_results(&results) {
            Ok(()) => ok(200, &json!({ "fp": flag, "ids": changed })),
            Err(failure) => service_error(&failure.into()),
        }
    }
}

/// The elements `ids` name and every element found from them, at any depth: what Spiderfoot's
/// `resultsetfp` flags or unflags, since whatever a false positive led to is no finding either.
fn with_descendants<'a>(elements: &'a [DataElement], ids: &BTreeSet<&str>) -> BTreeSet<&'a str> {
    let mut children: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for element in elements {
        if let Some(source) = element.source.as_deref() {
            children.entry(source).or_default().push(&element.id);
        }
    }
    let mut affected = BTreeSet::new();
    let mut queue: Vec<&str> = elements
        .iter()
        .map(|element| element.id.as_str())
        .filter(|id| ids.contains(id))
        .collect();
    while let Some(id) = queue.pop() {
        if affected.insert(id) {
            queue.extend(children.get(id).into_iter().flatten().copied());
        }
    }
    affected
}

/// The first element of `ids` whose source is a false positive this change leaves flagged, as
/// Spiderfoot refuses to unflag an element under a flagged parent. Unflagging the parent in the
/// same request unflags the child with it, so that is allowed.
fn unflag_blocked<'a>(
    elements: &[DataElement],
    ids: &BTreeSet<&'a str>,
    affected: &BTreeSet<&str>,
) -> Option<&'a str> {
    let flagged: BTreeSet<&str> = elements
        .iter()
        .filter(|element| element.fp)
        .map(|element| element.id.as_str())
        .collect();
    elements
        .iter()
        .filter(|element| ids.contains(element.id.as_str()))
        .find(|element| {
            element
                .source
                .as_deref()
                .is_some_and(|source| flagged.contains(source) && !affected.contains(source))
        })
        .and_then(|element| ids.get(element.id.as_str()).copied())
}

/// Spiderfoot's `correlationrules` (id, name, descr, risk) for every rule a scan runs:
/// Huntsman's own, then `rules`, each with where it came from and, for those, the rule as
/// written (`logic`).
/// After them, each rule that did not load (see [`sf_correlate::with_dir`]): a row whose `origin`
/// is `not loaded`, whose `id` and `name` are the file, whose `descr` and `error` are the reason,
/// with no risk and no logic, so the Settings panel and `scans rules --json` show a broken rule
/// where its results would have been instead of leaving it to the service's log.
#[must_use]
pub fn correlation_rules(rules: &[Rule], errors: &[RuleError]) -> Value {
    let mut rows: Vec<Value> = rule_catalog()
        .into_iter()
        .map(|rule| {
            json!({
                "id": rule.id,
                "name": rule.name.replace('_', " "),
                "descr": rule.description,
                "risk": Risk::of(rule.severity).as_str(),
                "origin": "huntsman",
                "logic": "",
            })
        })
        .collect();
    rows.extend(rules.iter().map(|rule| {
        json!({
            "id": rule.id,
            "name": rule.name,
            "descr": rule.description,
            "risk": rule.risk.as_str(),
            "origin": rule.origin,
            "logic": rule.yaml,
        })
    }));
    rows.extend(errors.iter().map(|failure| {
        json!({
            "id": failure.rule,
            "name": failure.rule,
            "descr": failure.reason,
            "risk": "",
            "origin": "not loaded",
            "logic": "",
            "error": failure.reason,
        })
    }));
    Value::Array(rows)
}

/// Whether a path is answered under `POST` (`write`) or `GET`: the other method gets 405, not 404.
fn route_exists(segments: &[&str], write: bool) -> bool {
    if write {
        matches!(
            segments,
            ["scans"] | ["scans", _, "stop" | "delete" | "rerun" | "fp" | "correlate"]
        )
    } else {
        matches!(
            segments,
            ["eventtypes" | "correlationrules" | "settings" | "scans"]
                | ["scans", _]
                | [
                    "scans",
                    _,
                    "summary"
                        | "analyze"
                        | "evidence"
                        | "matrix"
                        | "elements"
                        | "correlations"
                        | "log"
                        | "graph"
                        | "export"
                ]
        )
    }
}

fn event_types() -> ApiResponse {
    let types: Vec<Value> = sf_types::all()
        .map(|kind| {
            json!({
                "type": kind.code,
                "description": kind.description,
                "category": kind.category.as_str(),
                "raw": kind.raw,
            })
        })
        .collect();
    ok(200, &Value::Array(types))
}

/// The lookup New Scan of `element` runs, which the page offers it only with: the one its type
/// names ([`crate::sf_compat::pivot_kind`]) when that lookup takes the value, else the one the
/// value's own form names (a breach record's `username` that is an address runs the e-mail lookup,
/// a host name that is an IP address the IP lookup), but never a people search of a value only
/// because nothing else takes it. `None` when no lookup takes the value as what it is. **Pure.**
fn pivot_kind(element: &DataElement) -> Option<ScanKind> {
    let typed = crate::sf_compat::pivot_kind(&element.kind)?;
    let takes = |kind: ScanKind| plan(&element.data, Some(kind.command())).is_ok();
    if takes(typed) {
        return Some(typed);
    }
    let named = crate::scan_route::infer_kind(&element.data);
    (named != ScanKind::People && takes(named)).then_some(named)
}

/// Elements as `/elements` answers them: each as saved, with its type's description, the lookup
/// New Scan of it runs (`scan_kind`, [`pivot_kind`]; null when none takes its value) and the data
/// of the element it was found from in `results`. An element whose source was not saved (a scan a
/// `types` filter trimmed before the ancestry was kept) says so with `source_missing`, rather than
/// passing an empty source off as the root.
fn element_rows<'a>(
    results: &ScanResults,
    chosen: impl IntoIterator<Item = &'a DataElement>,
) -> Vec<Value> {
    let sources = scan_compare::source_data(results);
    chosen
        .into_iter()
        .map(|element| {
            let source_data = element
                .source
                .as_deref()
                .map(|source| sources.get(source).copied());
            let mut row = json!(element);
            row["description"] = Value::String(sf_types::describe(&element.kind).to_owned());
            // The page opens New Scan of a value with this lookup, and offers it only with one;
            // detection would read a bare handle as a domain, an AS or a name.
            row["scan_kind"] = pivot_kind(element)
                .map_or(Value::Null, |kind| Value::String(kind.command().to_owned()));
            row["source_data"] = Value::String(source_data.flatten().unwrap_or("").to_owned());
            if source_data == Some(None) {
                row["source_missing"] = Value::Bool(true);
            }
            row
        })
        .collect()
}

fn empty_results(record: &ScanRecord) -> ScanResults {
    ScanResults {
        format_version: crate::scan_store::FORMAT_VERSION,
        scan_id: record.id.clone(),
        text: String::new(),
        entities: Vec::new(),
        outcomes: Vec::new(),
        elements: Vec::new(),
        correlations: Vec::new(),
        lineage: Vec::new(),
        termination: None,
    }
}

#[cfg(test)]
mod tests;
