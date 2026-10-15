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
//! | `scaneventresults`, `scaneventresultsunique` | `GET /api/scans/ID/elements[?type=T][&unique=1][&hidefp=1][&correlation=C]` |
//! | `scancorrelations`, `scancorrelationsexport` | `GET /api/scans/ID/correlations[?format=csv|tsv|xlsx|json]` |
//! | `sf.py -C` | `POST /api/scans/ID/correlate` |
//! | `correlationrules` | `GET /api/correlationrules` |
//! | `scanlog`, `scanerrors` | `GET /api/scans/ID/log[?level=ERROR]` |
//! | `scanviz` | `GET /api/scans/ID/graph` |
//! | `scaneventresultexport`, `scanviz?gexf=1` | `GET /api/scans/ID/export?format=csv|tsv|xlsx|json|gexf[&type=T]` |
//! | `scaneventresultexportmulti`, `scanexportjsonmulti` | `GET /api/scans/export?ids=A,B[&format=json|csv|tsv|xlsx][&type=T]` |
//! | `stopscan`, `scandelete`, `rerunscan` | `POST /api/scans/ID/stop|delete|rerun` |
//! | `resultsetfp` | `POST /api/scans/ID/fp?ids=A,B&fp=1|0` |
//! | `eventtypes` | `GET /api/eventtypes` |
//! | `opts` (status only) | `GET /api/settings` |

use std::borrow::Cow;
use std::collections::BTreeSet;
use std::sync::Arc;

use serde_json::{Value, json};

use crate::api_leg::Api;
use crate::correlator::rule_catalog;
use crate::module::reachable_modules;
use crate::scan_export;
use crate::scan_service::{MAX_RUNNING, ScanRequest, ScanService, ServiceError};
use crate::scan_store::{LogLevel, Risk, ScanOptions, ScanRecord, ScanResults, ScanStatus};
use crate::sf_correlate::Rule;
use crate::sf_elements::{self, DataElement};
use crate::sf_types;
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

/// The keyed sources' slots, from each source's own [`Api`] constant, plus the sources that
/// read their key elsewhere.
fn key_slots() -> Vec<(&'static str, Vec<&'static str>)> {
    let apis: [&Api; 24] = [
        &crate::abuseipdb::API,
        &crate::greynoise::API,
        &crate::hackertarget::API,
        &crate::hunter::API,
        &crate::internetdb::API,
        &crate::ipinfo::API,
        &crate::ipqs::API,
        &crate::kickbox::API,
        &crate::leakix::API,
        &crate::netlas::API,
        &crate::numverify::API,
        &crate::otx::API,
        &crate::pulsedive::API,
        &crate::ripestat::API,
        &crate::robtex::API,
        &crate::securitytrails::API,
        &crate::shodan::API,
        &crate::stopforumspam::API,
        &crate::threatfox::API,
        &crate::urlhaus::API,
        &crate::urlscan::API,
        &crate::virustotal::API,
        &crate::whoxy::API,
        &crate::xposedornot::API,
    ];
    let mut slots: Vec<(&'static str, Vec<&'static str>)> = apis
        .iter()
        .map(|api| {
            (
                api.source,
                api.key.map(|key| key.slot).into_iter().collect(),
            )
        })
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
}

impl ScanApi {
    #[must_use]
    pub fn new(service: Arc<ScanService>, slots: Option<SlotCheck>) -> Self {
        Self { service, slots }
    }

    #[must_use]
    pub fn service(&self) -> &Arc<ScanService> {
        &self.service
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
            (["scans", id], false) => self.status(id),
            (["scans", id, "summary"], false) => self.summary(id),
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
                let key_env: Vec<&str> = slots
                    .iter()
                    .find(|(source, _)| *source == module.name)
                    .map(|(_, slots)| slots.clone())
                    .unwrap_or_default();
                let configured = match &self.slots {
                    Some(check) if !key_env.is_empty() => {
                        Value::Bool(key_env.iter().any(|slot| check(slot)))
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
                    "key_env": key_env,
                    "configured": configured,
                })
            })
            .collect();
        ok(
            200,
            &json!({
                "modules": modules,
                "global": [
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
                ],
            }),
        )
    }

    fn list(&self) -> ApiResponse {
        match self.service.store().list() {
            Ok(records) => ok(200, &json!(records)),
            Err(failure) => service_error(&failure.into()),
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
            .store()
            .get(id)
            .map_err(|failure| service_error(&failure.into()))
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

    fn status(&self, id: &str) -> ApiResponse {
        let (record, results) = match self.results(id) {
            Ok(found) => found,
            Err(response) => return response,
        };
        let sources: Vec<Value> = results
            .as_ref()
            .map(|results| {
                results
                    .outcomes
                    .iter()
                    .map(|outcome| {
                        json!({
                            "module": outcome.module,
                            "outcome": outcome.kind,
                            "found": outcome.found,
                            "http_status": outcome.http_status,
                            "retry_after_secs": outcome.retry_after_secs,
                            "detail": outcome.detail,
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();
        let mut value = json!(record);
        value["sources"] = Value::Array(sources);
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
            "usecase": "passive skips the keyed breach lookup of every email; the other use cases run every source of each lookup",
            "types": true,
            "modules": record.options.modules.is_empty(),
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
        let rows: Vec<Value> = chosen
            .into_iter()
            .map(|element| {
                let source_data = element
                    .source
                    .as_deref()
                    .and_then(|source| results.elements.iter().find(|item| item.id == source))
                    .map_or("", |source| source.data.as_str());
                let mut row = json!(element);
                row["description"] = Value::String(sf_types::describe(&element.kind).to_owned());
                row["source_data"] = Value::String(source_data.to_owned());
                row
            })
            .collect();
        ok(200, &Value::Array(rows))
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
        ok(200, &correlation_rules(self.service.rules()))
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
        let (record, results) = match self.results(id) {
            Ok(found) => found,
            Err(response) => return response,
        };
        let results = results.unwrap_or_else(|| empty_results(&record));
        match scan_export::render(
            &record,
            &results,
            param.get("format").unwrap_or("csv"),
            param.get("type").filter(|kind| !kind.is_empty()),
        ) {
            Ok(export) => ApiResponse::export(export),
            Err(message) => error(400, &message),
        }
    }

    fn export_many(&self, param: &Params) -> ApiResponse {
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
        let mut scans = Vec::new();
        for id in ids {
            match self.results(id) {
                Ok((record, results)) => {
                    let results = results.unwrap_or_else(|| empty_results(&record));
                    scans.push((record, results));
                }
                Err(response) => return response,
            }
        }
        let pairs: Vec<(&ScanRecord, &ScanResults)> = scans
            .iter()
            .map(|(record, results)| (record, results))
            .collect();
        match scan_export::render_many(
            &pairs,
            param.get("format").unwrap_or("json"),
            param.get("type").filter(|kind| !kind.is_empty()),
        ) {
            Ok(export) => ApiResponse::export(export),
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
        let mut changed = Vec::new();
        for element in &mut results.elements {
            if ids.contains(element.id.as_str()) && element.kind != "ROOT" {
                element.fp = flag;
                changed.push(element.id.clone());
            }
        }
        if changed.len() != ids.len() {
            return error(404, "an id names no element of this scan");
        }
        match self.service.store().save_results(&results) {
            Ok(()) => ok(200, &json!({ "fp": flag, "ids": changed })),
            Err(failure) => service_error(&failure.into()),
        }
    }
}

/// Spiderfoot's `correlationrules` (id, name, descr, risk) for every rule a scan runs:
/// Huntsman's own, then `rules`, each with where it came from and, for those, the rule as
/// written (`logic`).
#[must_use]
pub fn correlation_rules(rules: &[Rule]) -> Value {
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
                    "summary" | "elements" | "correlations" | "log" | "graph" | "export"
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
mod tests {
    use super::*;
    use crate::entity::{Entity, EntityKind, Evidence, EvidenceProvenance};
    use crate::scan_route::ScanKind;
    use crate::scan_service::LookupOutput;
    use crate::scan_store::ScanStore;
    use crate::source_outcome::SourceExecutionOutcome;
    use std::path::PathBuf;

    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("hse-scan-api-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    fn api(tag: &str) -> (ScanApi, PathBuf) {
        let dir = scratch(tag);
        let lookup = Arc::new(|_kind: ScanKind, selector: &str| {
            let evidence = Evidence::new(EvidenceProvenance::for_scan("internetdb", "s"), "ports")
                .with_attr("ports", "22,443")
                .with_attr("vulns", "CVE-2021-44228,CVE-2014-0160");
            Ok(LookupOutput {
                text: "report".into(),
                entities: vec![
                    Entity::builder(EntityKind::IpAddress, selector, 0.9, "s")
                        .evidence(evidence)
                        .build(),
                ],
                outcomes: vec![SourceExecutionOutcome::success("internetdb", 1, 1)],
            })
        });
        let service = ScanService::new(ScanStore::open(&dir).unwrap(), lookup);
        let slots: SlotCheck = Arc::new(|slot: &str| slot == crate::environment::SHODAN_KEY_ENV);
        (ScanApi::new(service, Some(slots)), dir)
    }

    fn body(response: &ApiResponse) -> Value {
        serde_json::from_slice(&response.body).unwrap()
    }

    fn finished(api: &ScanApi) -> String {
        api.service()
            .run(&ScanRequest {
                target: "1.1.1.1".into(),
                ..ScanRequest::default()
            })
            .unwrap()
            .id
    }

    #[test]
    fn correlation_rules_are_listed_rerun_and_exported() {
        let (api, dir) = api("correlate");
        assert!(ScanApi::handles("/api/correlationrules"));
        let rules = body(&api.handle("GET", "/api/correlationrules", ""));
        let rules = rules.as_array().unwrap();
        assert_eq!(rules.len(), rule_catalog().len() + 37);
        assert_eq!(rules[0]["origin"], "huntsman");
        assert!(
            rules
                .iter()
                .all(|rule| !rule["descr"].as_str().unwrap().is_empty())
        );
        let database = rules
            .iter()
            .find(|rule| rule["id"] == "database_exposed")
            .unwrap();
        assert_eq!(database["risk"], "HIGH");
        assert_eq!(database["origin"], "spiderfoot");
        assert!(
            database["logic"]
                .as_str()
                .unwrap()
                .starts_with("id: database_exposed\n")
        );
        let id = finished(&api);
        let saved = body(&api.handle("GET", &format!("/api/scans/{id}/correlations"), ""));
        let titles: Vec<&str> = saved
            .as_array()
            .unwrap()
            .iter()
            .map(|correlation| correlation["title"].as_str().unwrap())
            .collect();
        assert!(
            titles.contains(&"Multiple medium/low vulnerabilities found on 1.1.1.1"),
            "{titles:?}"
        );
        let rerun = api.handle("POST", &format!("/api/scans/{id}/correlate"), "");
        assert_eq!(rerun.status, 200, "{}", rerun.text());
        assert_eq!(body(&rerun), saved);
        let csv = api.handle(
            "GET",
            &format!("/api/scans/{id}/correlations"),
            "format=csv",
        );
        assert_eq!(csv.status, 200);
        assert!(
            csv.text()
                .starts_with("Rule Name,Correlation,Risk,Description,Rule,Origin,Elements\r\n")
        );
        assert_eq!(csv.text().matches("\r\n").count(), titles.len() + 1);
        assert!(
            csv.filename
                .unwrap()
                .ends_with("-Huntsman-correlations.csv")
        );
        let refused =
            |method: &str, path: &str, query: &str| api.handle(method, path, query).status;
        assert_eq!(
            refused(
                "GET",
                &format!("/api/scans/{id}/correlations"),
                "format=gexf"
            ),
            400
        );
        assert_eq!(
            refused("GET", &format!("/api/scans/{id}/correlate"), ""),
            405
        );
        assert_eq!(refused("POST", "/api/correlationrules", ""), 405);
        assert_eq!(refused("POST", "/api/scans/nope/correlate", ""), 404);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_scan_started_with_a_depth_keeps_it_and_a_bad_depth_is_refused() {
        let (api, dir) = api("depth");
        let bad = api.handle("POST", "/api/scans", "target=1.1.1.1&depth=deep");
        assert_eq!(bad.status, 400, "{}", bad.body);
        let started = api.handle("POST", "/api/scans", "target=1.1.1.1&depth=2");
        assert_eq!(started.status, 202, "{}", started.body);
        assert_eq!(body(&started)["options"]["depth"], 2);
        let id = body(&started)["id"].as_str().unwrap().to_owned();
        for _ in 0..200 {
            if !api.service().store().get(&id).unwrap().status.is_active() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(25));
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_started_scan_is_listed_and_finishes() {
        let (api, dir) = api("start");
        let started = api.handle(
            "POST",
            "/api/scans",
            "target=1.1.1.1&name=resolver&usecase=footprint",
        );
        assert_eq!(started.status, 202, "{}", started.text());
        let id = body(&started)["id"].as_str().unwrap().to_owned();
        let mut status = String::new();
        for _ in 0..200 {
            status = body(&api.handle("GET", &format!("/api/scans/{id}"), ""))["status"]
                .as_str()
                .unwrap()
                .to_owned();
            if status == "FINISHED" {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(25));
        }
        assert_eq!(status, "FINISHED");
        let list = body(&api.handle("GET", "/api/scans", ""));
        assert_eq!(list[0]["id"], id);
        assert_eq!(list[0]["name"], "resolver");
        assert_eq!(list[0]["options"]["usecase"], "footprint");
        let row = body(&api.handle("GET", &format!("/api/scans/{id}"), ""));
        assert_eq!(row["sources"][0]["module"], "internetdb");
        assert_eq!(row["report"], "report");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn summary_elements_graph_and_log_read_the_saved_scan() {
        let (api, dir) = api("read");
        let id = finished(&api);
        let summary = body(&api.handle("GET", &format!("/api/scans/{id}/summary"), ""));
        let ports = summary
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["type"] == "TCP_PORT_OPEN")
            .unwrap();
        assert_eq!(
            (ports["total"].as_u64(), ports["unique"].as_u64()),
            (Some(2), Some(2))
        );
        let elements = body(&api.handle(
            "GET",
            &format!("/api/scans/{id}/elements"),
            "type=VULNERABILITY_GENERAL",
        ));
        assert_eq!(elements[0]["data"], "CVE-2021-44228");
        assert_eq!(elements[0]["source_data"], "1.1.1.1");
        assert_eq!(elements[0]["description"], "Vulnerability - General");
        let all = body(&api.handle("GET", &format!("/api/scans/{id}/elements"), ""));
        let target = all
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["type"] == "IP_ADDRESS")
            .unwrap();
        assert_eq!(
            target["raw"][0]["evidence"]["attributes"]["ports"],
            "22,443"
        );
        let graph = body(&api.handle("GET", &format!("/api/scans/{id}/graph"), ""));
        assert_eq!(
            graph["edges"].as_array().unwrap().len() + 1,
            graph["nodes"].as_array().unwrap().len()
        );
        let errors = body(&api.handle("GET", &format!("/api/scans/{id}/log"), "level=error"));
        assert_eq!(errors, json!([]));
        assert_eq!(
            api.handle("GET", &format!("/api/scans/{id}/log"), "level=loud")
                .status,
            400
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn false_positive_flags_persist_and_filter() {
        let (api, dir) = api("fp");
        let id = finished(&api);
        let all = body(&api.handle(
            "GET",
            &format!("/api/scans/{id}/elements"),
            "type=TCP_PORT_OPEN",
        ));
        let first = all[0]["id"].as_str().unwrap().to_owned();
        let set = api.handle(
            "POST",
            &format!("/api/scans/{id}/fp"),
            &format!("ids={first}&fp=1"),
        );
        assert_eq!(set.status, 200, "{}", set.text());
        let shown = body(&api.handle(
            "GET",
            &format!("/api/scans/{id}/elements"),
            "type=TCP_PORT_OPEN&hidefp=1",
        ));
        assert_eq!(shown.as_array().unwrap().len(), 1);
        assert_eq!(
            api.handle(
                "POST",
                &format!("/api/scans/{id}/fp"),
                "ids=ffffffffffffffff&fp=1"
            )
            .status,
            404
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn exports_carry_a_file_name_and_spiderfoots_layout() {
        let (api, dir) = api("export");
        let id = finished(&api);
        let csv = api.handle("GET", &format!("/api/scans/{id}/export"), "format=csv");
        assert_eq!(csv.status, 200);
        assert!(
            csv.text()
                .starts_with("Updated,Type,Module,Source,F/P,Data\r\n")
        );
        assert_eq!(csv.filename.as_deref(), Some("1.1.1.1-Huntsman.csv"));
        let book = api.handle("GET", &format!("/api/scans/{id}/export"), "format=xlsx");
        assert_eq!(book.status, 200);
        assert_eq!(book.content_type, crate::xlsx::CONTENT_TYPE);
        assert_eq!(book.filename.as_deref(), Some("1.1.1.1-Huntsman.xlsx"));
        assert!(book.body.starts_with(b"PK\x03\x04"));
        assert!(crate::xlsx::tests::sheet_names(&book.body).contains(&"TCP_PORT_OPEN".to_owned()));
        let many = api.handle("GET", "/api/scans/export", &format!("ids={id},{id}"));
        assert_eq!(many.status, 200);
        assert!(body(&many).as_array().unwrap().len() > 2);
        let many = api.handle(
            "GET",
            "/api/scans/export",
            &format!("ids={id},{id}&format=csv&type=TCP_PORT_OPEN"),
        );
        assert_eq!(many.filename.as_deref(), Some("Huntsman.csv"));
        assert!(
            many.text()
                .starts_with("Scan Name,Updated,Type,Module,Source,F/P,Data\r\n")
        );
        let book = api.handle(
            "GET",
            "/api/scans/export",
            &format!("ids={id}&format=excel"),
        );
        assert_eq!(book.filename.as_deref(), Some("1.1.1.1-Huntsman.xlsx"));
        let correlations = api.handle(
            "GET",
            &format!("/api/scans/{id}/correlations"),
            "format=xlsx",
        );
        assert_eq!(correlations.status, 200);
        assert_eq!(correlations.content_type, crate::xlsx::CONTENT_TYPE);
        assert_eq!(
            api.handle("GET", &format!("/api/scans/{id}/export"), "format=pdf")
                .status,
            400
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn stop_delete_and_rerun_follow_the_scan_state() {
        let (api, dir) = api("lifecycle");
        let id = finished(&api);
        assert_eq!(
            api.handle("POST", &format!("/api/scans/{id}/stop"), "")
                .status,
            409
        );
        let rerun = api.handle("POST", &format!("/api/scans/{id}/rerun"), "");
        assert_eq!(rerun.status, 202);
        assert_ne!(body(&rerun)["id"], id);
        assert_eq!(
            api.handle("POST", &format!("/api/scans/{id}/delete"), "")
                .status,
            200
        );
        assert_eq!(
            api.handle("GET", &format!("/api/scans/{id}"), "").status,
            404
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn methods_paths_and_bad_input_get_their_status() {
        let (api, dir) = api("errors");
        assert_eq!(api.handle("DELETE", "/api/scans", "").status, 405);
        assert_eq!(
            api.handle("GET", "/api/scans/0123456789abcdef/stop", "")
                .status,
            405
        );
        assert_eq!(
            api.handle("POST", "/api/scans/0123456789abcdef/summary", "")
                .status,
            405
        );
        assert_eq!(api.handle("GET", "/api/scans/../../etc", "").status, 404);
        assert_eq!(
            api.handle("GET", "/api/scans/0123456789abcdef", "").status,
            404
        );
        assert_eq!(
            api.handle("GET", "/api/scans/0123456789abcdef/nope", "")
                .status,
            404
        );
        assert_eq!(api.handle("POST", "/api/scans", "").status, 400);
        assert_eq!(api.handle("POST", "/api/scans", "target=%zz").status, 400);
        assert_eq!(
            api.handle("POST", "/api/scans", "target=x.com&usecase=all-out")
                .status,
            400
        );
        assert!(ScanApi::handles("/api/scans/abc/log"));
        assert!(ScanApi::handles("/api/eventtypes"));
        assert!(!ScanApi::handles("/api/scansx"));
        assert!(!ScanApi::handles("/api/lookup"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn event_types_and_settings_describe_the_catalogue_and_key_status_without_values() {
        let (api, dir) = api("settings");
        let types = body(&api.handle("GET", "/api/eventtypes", ""));
        assert_eq!(types.as_array().unwrap().len(), sf_types::all().count());
        assert_eq!(types[0]["type"], "ROOT");
        let settings = body(&api.handle("GET", "/api/settings", ""));
        let shodan = settings["modules"]
            .as_array()
            .unwrap()
            .iter()
            .find(|module| module["name"] == "shodan")
            .unwrap();
        assert_eq!(shodan["key_env"][0], crate::environment::SHODAN_KEY_ENV);
        assert_eq!(shodan["configured"], true);
        let robtex = settings["modules"]
            .as_array()
            .unwrap()
            .iter()
            .find(|module| module["name"] == "robtex")
            .unwrap();
        assert_eq!(robtex["key_env"], json!([]));
        assert_eq!(robtex["configured"], Value::Null);
        assert!(settings["global"].as_array().unwrap().len() >= 3);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
