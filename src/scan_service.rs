//! Running saved scans: Spiderfoot's scan lifecycle over Huntsman's lookups.
//!
//! [`ScanService::start`] saves a `CREATED` scan and runs it on its own thread: `STARTING` while it
//! waits for one of [`MAX_RUNNING`] places, `RUNNING` while its lookups run, then `FINISHED`,
//! `ABORTED` (stopped) or `ERROR-FAILED` (nothing could run). Each lookup's source outcomes go to
//! the scan's log; its entities become data elements and correlations, saved with the scan.
//! [`ScanService::stop`] asks a scan to stop: a lookup already running finishes (a blocking
//! request cannot be interrupted), its results are kept, and no further lookup starts.
//!
//! The service performs no I/O of its own beyond the store: the binary installs the
//! [`ScanLookup`] that runs one lookup, exactly as `scan` and `/api/lookup` run it, so a saved scan
//! reaches every source those reach, keyed sources included whenever their key is configured.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::correlator::evaluate_rules;
use crate::entity::Entity;
use crate::graph_exec::{
    ExecutionPolicy, GraphDefinition, GraphExecutor, HandlerRegistry, TaskContext, TaskFailure,
    TaskOutput, TaskRole, TaskSpec, TaskState, ValueSchema, VerificationRecord, VerificationState,
};
use crate::lookup_modules;
use crate::module_selection::Selection;
use crate::recursion::{
    self, PivotEdge, RecursionPolicy, RecursionReport, SelectorCollector, Step,
    Target as CrawlTarget,
};
use crate::scan_route::{
    NetworkSelector, ScanKind, canonical_selector, explicit_people_is_name, infer_kind,
    inferred_people_is_name, parse_kind,
};
use crate::scan_store::{
    FORMAT_VERSION, LogEntry, LogLevel, Risk, RiskCounts, ScanCorrelation, ScanOptions, ScanRecord,
    ScanResults, ScanStatus, ScanStore, StoreError, new_id,
};
use crate::sf_correlate::{self, Rule, RuleError};
use crate::sf_elements::{self, DataElement, Target};
use crate::sf_types;
use crate::source_outcome::{SourceExecutionOutcome, SourceOutcomeKind};
use crate::termination::TerminationReason;

/// Scans that run at once; more wait as `STARTING`. A phone runs two lookups' worth of requests
/// comfortably, and each lookup already fans out to its sources.
pub const MAX_RUNNING: usize = 2;
/// Maximum number of scan threads, including workers waiting for an execution slot.
/// Bound admission before spawning each 8 MiB-stack thread on memory-constrained devices.
const MAX_SCAN_WORKERS: usize = 8;
/// Total concurrent lookup calls per scan service, across sequential and graph scan waves.
/// This limits phone resource pressure without disabling parallelism within a scan.
const MAX_ACTIVE_LOOKUPS: usize = 2;
/// The longest target, in bytes.
pub const MAX_TARGET_BYTES: usize = 512;
/// The longest scan name, in bytes.
pub const MAX_NAME_BYTES: usize = 200;
/// The longest a [`ScanService::wait`] sleeps before it reads the scan's row again, so a scan
/// whose end it was not told of, as when its thread could not start, is seen soon all the same.
const WAIT_SLICE: Duration = Duration::from_millis(250);
/// The use cases Spiderfoot offers.
pub const USE_CASES: [&str; 4] = ["all", "footprint", "investigate", "passive"];

/// What one lookup found.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct LookupOutput {
    pub text: String,
    pub entities: Vec<Entity>,
    pub outcomes: Vec<SourceExecutionOutcome>,
}

/// Runs one lookup of a kind for a canonical selector, asking only the modules the selection
/// runs. Installed by the binary, which owns transports and keys. The error is a message safe to
/// log.
pub type ScanLookup =
    Arc<dyn Fn(ScanKind, &str, &Selection) -> Result<LookupOutput, String> + Send + Sync>;

/// Why a scan could not be started, stopped, rerun or deleted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServiceError {
    /// The request itself is wrong: an empty or unusable target, an unknown option.
    BadRequest(String),
    NotFound(String),
    /// The scan is in the wrong state for this: deleting a running scan, stopping a finished one.
    Conflict(String),
    /// The store failed.
    Store(String),
}

impl From<StoreError> for ServiceError {
    fn from(error: StoreError) -> Self {
        match error {
            StoreError::NotFound(id) => Self::NotFound(format!("no scan {id}")),
            StoreError::Invalid(message) => Self::BadRequest(message),
            error @ StoreError::Capacity(_) => Self::Conflict(error.to_string()),
            StoreError::Io(message) => Self::Store(message),
        }
    }
}

impl ServiceError {
    /// The HTTP status the scan API answers with.
    #[must_use]
    pub const fn status(&self) -> u16 {
        match self {
            Self::BadRequest(_) => 400,
            Self::NotFound(_) => 404,
            Self::Conflict(_) => 409,
            Self::Store(_) => 500,
        }
    }
}

impl std::fmt::Display for ServiceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadRequest(message)
            | Self::NotFound(message)
            | Self::Conflict(message)
            | Self::Store(message) => f.write_str(message),
        }
    }
}

/// A scan to start, as New Scan submits it.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ScanRequest {
    pub target: String,
    /// Defaults to the target.
    pub name: Option<String>,
    /// A lookup kind (`domain`, `email`, ...) or `auto`, the default.
    pub kind: Option<String>,
    pub options: ScanOptions,
}

/// The lookups a scan runs, its target's Spiderfoot type and canonical form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanPlan {
    pub kind: ScanKind,
    pub target: String,
    pub target_type: &'static str,
}

/// Route a target the way `/api/lookup` routes a selector.
///
/// # Errors
/// [`ServiceError::BadRequest`] for an empty, over-long or unusable target or an unknown kind.
pub fn plan(target: &str, kind: Option<&str>) -> Result<ScanPlan, ServiceError> {
    let target = target.trim();
    if target.is_empty() {
        return Err(ServiceError::BadRequest("a scan needs a target".into()));
    }
    if target.len() > MAX_TARGET_BYTES {
        return Err(ServiceError::BadRequest(format!(
            "the target is longer than {MAX_TARGET_BYTES} bytes"
        )));
    }
    let selector = vec![target.to_owned()];
    let kind = match kind.map(str::trim).filter(|kind| !kind.is_empty()) {
        None | Some("auto") => {
            let kind = infer_kind(target);
            if kind == ScanKind::People && !inferred_people_is_name(&selector) {
                return Err(ServiceError::BadRequest(
                    "not a name, phone, email, handle, domain, IP address, address block, AS number, BSSID or LAT,LON; choose a kind to scan it anyway".into(),
                ));
            }
            kind
        }
        Some(word) => {
            let kind = parse_kind(&word.to_ascii_lowercase())
                .map_err(|_| ServiceError::BadRequest(format!("unknown scan kind {word}")))?;
            if kind == ScanKind::People && !explicit_people_is_name(&selector) {
                return Err(ServiceError::BadRequest(
                    "a people scan needs two alphabetic tokens".into(),
                ));
            }
            kind
        }
    };
    let canonical = canonical_selector(kind, target).ok_or_else(|| {
        ServiceError::BadRequest(format!(
            "the target is not valid for a {} scan",
            kind.command()
        ))
    })?;
    let target_type = target_type(kind, &canonical);
    Ok(ScanPlan {
        kind,
        target: canonical,
        target_type,
    })
}

/// The Spiderfoot type of a canonical target of `kind`.
#[must_use]
pub fn target_type(kind: ScanKind, canonical: &str) -> &'static str {
    match kind {
        ScanKind::People => "HUMAN_NAME",
        ScanKind::Email | ScanKind::Exposure => "EMAILADDR",
        ScanKind::Username => "USERNAME",
        ScanKind::Phone => "PHONE_NUMBER",
        ScanKind::Domain => "INTERNET_NAME",
        ScanKind::Ip if canonical.contains(':') => "IPV6_ADDRESS",
        ScanKind::Ip => "IP_ADDRESS",
        ScanKind::Netblock if canonical.contains(':') => "NETBLOCKV6_OWNER",
        ScanKind::Netblock => "NETBLOCK_OWNER",
        ScanKind::Asn => "BGP_AS_OWNER",
        ScanKind::Network => match NetworkSelector::parse(canonical) {
            Some(NetworkSelector::Bssid(_)) => "HSE_MAC_ADDRESS",
            Some(NetworkSelector::Area { .. }) => "PHYSICAL_COORDINATES",
            _ => "HSE_WIFI_SSID",
        },
    }
}

/// The breach sources the `exposure` lookup runs. An email scan runs `exposure` after `email`
/// unless the `email` lookup already ran one of them, so a keyed breach source is never skipped
/// and never asked twice.
const EXPOSURE_SOURCES: [&str; 4] = ["hibp", "stolen_tax", "oathnet", "dehashed"];

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
        })
}

fn now_nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_nanos())
}

fn validate_options(options: &ScanOptions) -> Result<ScanOptions, ServiceError> {
    let usecase = if options.usecase.trim().is_empty() {
        "all".to_owned()
    } else {
        options.usecase.trim().to_ascii_lowercase()
    };
    if !USE_CASES.contains(&usecase.as_str()) {
        return Err(ServiceError::BadRequest(format!(
            "unknown use case {usecase}; choose all, footprint, investigate or passive"
        )));
    }
    let mut types = Vec::new();
    for code in &options.types {
        let kind = sf_types::find(code)
            .ok_or_else(|| ServiceError::BadRequest(format!("unknown data type {code}")))?;
        types.push(kind.code.to_owned());
    }
    let mut modules: Vec<String> = Vec::new();
    for module in &options.modules {
        let module = module.trim().to_ascii_lowercase();
        if !module.is_empty() && !modules.contains(&module) {
            modules.push(module);
        }
    }
    crate::module::selection(&modules).map_err(ServiceError::BadRequest)?;
    Ok(ScanOptions {
        usecase,
        modules,
        types,
        depth: options.depth,
    })
}

/// The modules a scan with `options` asks: the ones it chose, else every one.
fn chosen(options: &ScanOptions) -> Result<Selection, ServiceError> {
    crate::module::selection(&options.modules).map_err(ServiceError::BadRequest)
}

/// Shared, cancellation-aware admission for all lookups started by this service.
#[derive(Default)]
struct LookupAdmission {
    active: Mutex<usize>,
    freed: Condvar,
}

struct LookupPermit {
    admission: Arc<LookupAdmission>,
}

impl Drop for LookupPermit {
    fn drop(&mut self) {
        let mut active = self
            .admission
            .active
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        *active -= 1;
        self.admission.freed.notify_one();
    }
}

impl LookupAdmission {
    fn acquire(self: &Arc<Self>, should_abort: impl Fn() -> bool) -> Option<LookupPermit> {
        let mut active = self.active.lock().unwrap_or_else(PoisonError::into_inner);
        loop {
            if should_abort() {
                return None;
            }
            if *active < MAX_ACTIVE_LOOKUPS {
                *active += 1;
                return Some(LookupPermit {
                    admission: Arc::clone(self),
                });
            }
            active = self
                .freed
                .wait_timeout(active, Duration::from_millis(25))
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
    }
}

/// Whether a sequential lookup ran, failed, or never acquired a slot before scan cancellation.
enum LookupDispatch {
    Completed(usize),
    Missing,
    Cancelled,
}

struct State {
    running: usize,
    aborts: BTreeSet<String>,
    graph_cancellations: BTreeMap<String, Arc<AtomicBool>>,
}

/// What following a scan's findings produced beside the findings themselves.
struct Crawl {
    lineage: Vec<PivotEdge>,
    termination: TerminationReason,
}

/// The crawl's lookups: each one logged and run through the installed lookup asking only the
/// chosen modules, a stop honoured before the next, a lookup that asks none of them skipped, and
/// an email's breach lookup skipped when its email lookup already ran a breach source, so a keyed
/// breach source is never skipped and never asked twice.
struct ScanCollector<'a> {
    service: &'a ScanService,
    id: &'a str,
    chosen: &'a Selection,
    text: String,
    ran: usize,
    errors: usize,
    breach_checked: BTreeSet<String>,
}

/// Reject graph inputs with missing or mistyped scan target identifiers.
fn lookup_input_schema() -> ValueSchema {
    ValueSchema::Object {
        required: BTreeMap::from([
            ("kind".into(), ValueSchema::String),
            ("selector".into(), ValueSchema::String),
        ]),
        allow_additional: false,
    }
}

/// Verify the lookup envelope before reducing it into scan results. Element payloads are
/// subsequently validated by serde when decoded as `LookupOutput`.
fn lookup_output_schema() -> ValueSchema {
    ValueSchema::Object {
        required: BTreeMap::from([
            ("text".into(), ValueSchema::String),
            (
                "entities".into(),
                ValueSchema::Array {
                    items: Box::new(ValueSchema::Any),
                },
            ),
            (
                "outcomes".into(),
                ValueSchema::Array {
                    items: Box::new(ValueSchema::Any),
                },
            ),
        ]),
        allow_additional: false,
    }
}

/// Preserve failures in durable scan results, not just ephemeral logs and counters.
/// A scheduler or transport error is not a validated zero-result lookup.
fn failed_lookup_step(
    target: &CrawlTarget,
    module: &str,
    kind: SourceOutcomeKind,
    detail: &str,
) -> Step {
    Step {
        entities: Vec::new(),
        outcomes: vec![SourceExecutionOutcome::failed(
            module,
            now_ms() / 1_000,
            kind,
            None,
            format!(
                "{} lookup on {}: {detail}",
                target.kind.command(),
                target.selector
            ),
        )],
    }
}

impl ScanCollector<'_> {
    /// Reduce a completed lookup identically for sequential and graph dispatch.
    /// This does not modify source error counts, which depend on how the lookup ran.
    fn finish_lookup(&mut self, target: &CrawlTarget, found: LookupOutput) -> Step {
        if target.kind == ScanKind::Email
            && found
                .outcomes
                .iter()
                .any(|outcome| EXPOSURE_SOURCES.contains(&outcome.module.as_str()))
        {
            if let Some(selector) = canonical_selector(ScanKind::Exposure, &target.selector) {
                self.breach_checked.insert(selector);
            }
        }
        if !found.text.is_empty() {
            if !self.text.is_empty() {
                self.text.push('\n');
            }
            self.text.push_str(&found.text);
        }
        Step {
            entities: found.entities,
            outcomes: found.outcomes,
        }
    }

    /// Record a graph adapter failure once and preserve the outcome in durable scan results.
    fn graph_failure(
        &mut self,
        target: &CrawlTarget,
        component: &str,
        kind: SourceOutcomeKind,
        detail: &str,
    ) -> Step {
        self.errors = self.errors.saturating_add(1);
        self.service
            .log(self.id, component, LogLevel::Error, detail);
        failed_lookup_step(target, "graph_exec", kind, detail)
    }

    /// Account for a completed graph lookup before applying the shared result reduction.
    fn finish_graph_lookup(&mut self, target: &CrawlTarget, found: LookupOutput) -> Step {
        self.ran = self.ran.saturating_add(1);
        for outcome in &found.outcomes {
            let accepted = outcome.kind.is_accepted();
            self.errors = self.errors.saturating_add(usize::from(!accepted));
            self.service.log(
                self.id,
                &outcome.module,
                if accepted {
                    LogLevel::Info
                } else {
                    LogLevel::Error
                },
                outcome_line(outcome),
            );
        }
        self.finish_lookup(target, found)
    }
    /// Reduce a graph task record independently of scheduling and lookup admission.
    /// Cancellation requested by the scan is not a provider error.
    fn reduce_graph_record(
        &mut self,
        target: &CrawlTarget,
        task_id: &str,
        record: &crate::graph_exec::TaskRecord,
    ) -> Step {
        if record.state == TaskState::Cancelled && self.service.aborted(self.id) {
            self.service.log(
                self.id,
                "graph_exec",
                LogLevel::Info,
                format!("graph task {task_id} cancelled by scan stop"),
            );
            return Step {
                entities: Vec::new(),
                outcomes: Vec::new(),
            };
        }
        if record.state != TaskState::Succeeded {
            return self.graph_failure(
                target,
                target.kind.command(),
                SourceOutcomeKind::Inconclusive,
                &format!(
                    "graph task {task_id} ended as {:?}: {}",
                    record.state,
                    record.error.as_deref().unwrap_or("no failure detail")
                ),
            );
        }
        let decoded = record
            .output
            .as_ref()
            .ok_or_else(|| "successful graph task has no output".to_owned())
            .and_then(|output| {
                serde_json::from_value::<LookupOutput>(output.value.clone())
                    .map_err(|error| format!("malformed lookup output: {error}"))
            });
        match decoded {
            Ok(found) => self.finish_graph_lookup(target, found),
            Err(error) => self.graph_failure(
                target,
                "graph_exec",
                SourceOutcomeKind::SchemaDrift,
                &format!("task {task_id}: {error}"),
            ),
        }
    }
}

impl SelectorCollector for ScanCollector<'_> {
    fn collect(&mut self, target: &CrawlTarget) -> Step {
        let skip = Step {
            entities: Vec::new(),
            outcomes: Vec::new(),
        };
        if target.kind == ScanKind::Exposure && self.breach_checked.contains(&target.selector) {
            return skip;
        }
        if !lookup_modules::asks_any(target.kind, self.chosen) {
            self.service.log(
                self.id,
                "huntsman",
                LogLevel::Info,
                format!(
                    "no chosen module looks up {}, so {} was not looked up",
                    target.kind.command(),
                    target.selector
                ),
            );
            return skip;
        }
        let mut found = LookupOutput::default();
        match self.service.lookup_into(
            self.id,
            (target.kind, &target.selector, self.chosen),
            &mut found,
        ) {
            LookupDispatch::Completed(failed) => {
                self.ran += 1;
                self.errors += failed;
            }
            // lookup_into retained its exact error in found.outcomes.
            LookupDispatch::Missing => self.errors += 1,
            LookupDispatch::Cancelled => {}
        }
        self.finish_lookup(target, found)
    }

    fn may_batch(&self, selected: &[CrawlTarget], next: &CrawlTarget) -> bool {
        let needs_sequential = |target: &CrawlTarget| {
            (target.kind == ScanKind::Exposure && self.breach_checked.contains(&target.selector))
                || !lookup_modules::asks_any(target.kind, self.chosen)
        };
        if needs_sequential(next) || selected.iter().any(needs_sequential) {
            return false;
        }
        !selected.iter().any(|target| {
            target.selector == next.selector
                && ((target.kind == ScanKind::Email && next.kind == ScanKind::Exposure)
                    || (target.kind == ScanKind::Exposure && next.kind == ScanKind::Email))
        })
    }

    // The graph adapter intentionally keeps task construction, execution and ordered accounting
    // together so failures cannot bypass scan-level error reporting.
    #[allow(clippy::too_many_lines)]
    fn collect_batch(&mut self, targets: &[CrawlTarget]) -> Vec<Step> {
        // Keep legacy ordering when a batch contains a paired email/exposure lookup, a skipped
        // module selection, or an already-covered exposure. These cases have stateful semantics.
        let has_email_exposure_pair = targets.iter().any(|email| {
            email.kind == ScanKind::Email
                && targets.iter().any(|exposure| {
                    exposure.kind == ScanKind::Exposure && exposure.selector == email.selector
                })
        });
        let has_stateful_or_skipped_target = targets.iter().any(|target| {
            (target.kind == ScanKind::Exposure && self.breach_checked.contains(&target.selector))
                || !lookup_modules::asks_any(target.kind, self.chosen)
        });
        if targets.len() < 2 || has_email_exposure_pair || has_stateful_or_skipped_target {
            return targets.iter().map(|target| self.collect(target)).collect();
        }

        let run_number = self.service.sequence.fetch_add(1, Ordering::Relaxed);
        let definition = GraphDefinition {
            run_id: format!("scan-{}-{run_number}", self.id),
            tasks: targets
                .iter()
                .enumerate()
                .map(|(index, target)| TaskSpec {
                    id: format!("lookup-{index:04}"),
                    objective: format!(
                        "run {} lookup for the selected scan target",
                        target.kind.command()
                    ),
                    role: TaskRole::Producer,
                    input: json!({
                        "kind": target.kind.command(),
                        "selector": target.selector.clone(),
                    }),
                    input_schema: lookup_input_schema(),
                    output_schema: lookup_output_schema(),
                    dependencies: Vec::new(),
                    exclusive_resources: Vec::new(),
                    rate_limit: None,
                    idempotency_key: None,
                    requires_idempotency: false,
                    timeout_ms: 15 * 60 * 1000,
                    max_retries: 0,
                    resource_units: 1,
                })
                .collect(),
        };
        let cancellation = self.service.graph_cancellation(self.id);
        let mut handlers = HandlerRegistry::new();
        for (index, target) in targets.iter().enumerate() {
            let task_id = format!("lookup-{index:04}");
            let lookup = Arc::clone(&self.service.lookup);
            let admission = Arc::clone(&self.service.admission);
            let cancellation_for_task = Arc::clone(&cancellation);
            let chosen = self.chosen.clone();
            let kind = target.kind;
            let selector = target.selector.clone();
            handlers.insert(
                task_id,
                Arc::new(
                    move |context: TaskContext| -> Result<TaskOutput, TaskFailure> {
                        context.check_deadline()?;
                        let _permit = admission
                            .acquire(|| {
                                cancellation_for_task.load(Ordering::Acquire)
                                    || context.remaining().is_zero()
                            })
                            .ok_or_else(|| {
                                TaskFailure::permanent(
                                    "scan cancelled or task deadline reached before lookup admission",
                                )
                            })?;
                        context.check_deadline()?;
                        let output =
                            lookup(kind, &selector, &chosen).map_err(TaskFailure::permanent)?;
                        let value = serde_json::to_value(output).map_err(|error| {
                            TaskFailure::permanent(format!(
                                "lookup output serialization failed: {error}"
                            ))
                        })?;
                        Ok(TaskOutput {
                            value,
                            evidence: Vec::new(),
                            verification: VerificationRecord {
                                state: VerificationState::Unresolved,
                                producer_id: context.task_id,
                                reviewer_id: "independent-review-pending".into(),
                                basis: "raw lookup output; source claims remain unverified".into(),
                                evidence_refs: Vec::new(),
                            },
                        })
                    },
                ),
            );
        }

        let policy = ExecutionPolicy {
            max_concurrency: 2,
            max_total_resource_units: u64::try_from(targets.len()).unwrap_or(u64::MAX),
            max_output_bytes: 2 * 1024 * 1024,
            run_timeout_ms: 15 * 60 * 1000,
        };
        let report = match GraphExecutor::new(policy).execute(&definition, &handlers, &cancellation)
        {
            Ok(report) => report,
            Err(error) => {
                self.service.log(
                    self.id,
                    "graph_exec",
                    LogLevel::Error,
                    format!("lookup batch rejected by graph executor: {error}"),
                );
                self.errors = self.errors.saturating_add(targets.len());
                return targets
                    .iter()
                    .map(|target| {
                        failed_lookup_step(
                            target,
                            "graph_exec",
                            SourceOutcomeKind::Inconclusive,
                            &format!("lookup batch rejected by graph executor: {error}"),
                        )
                    })
                    .collect();
            }
        };

        let summary = report.summary();
        self.service.log(
            self.id,
            "graph_exec",
            LogLevel::Info,
            format!(
                "lookup wave run {}: {} tasks, {} succeeded, {} failed, {} ms",
                definition.run_id,
                summary.total_tasks,
                summary.succeeded,
                summary.failed + summary.timed_out + summary.blocked,
                summary.wall_clock_ms.unwrap_or_default()
            ),
        );
        targets
            .iter()
            .enumerate()
            .map(|(index, target)| {
                let task_id = format!("lookup-{index:04}");
                let Some(record) = report.tasks.get(&task_id) else {
                    return self.graph_failure(
                        target,
                        "graph_exec",
                        SourceOutcomeKind::Inconclusive,
                        &format!("graph executor omitted task record {task_id}"),
                    );
                };
                self.reduce_graph_record(target, &task_id, record)
            })
            .collect()
    }

    fn on_batch_contract_error(&mut self, violations: usize) {
        self.errors = self.errors.saturating_add(violations);
        self.service.log(
            self.id,
            "recursion",
            LogLevel::Error,
            format!(
                "recursive collector returned {violations} missing or unsolicited batch results"
            ),
        );
    }

    fn cancelled(&self) -> bool {
        self.service.aborted(self.id)
    }
}

/// Releases a reserved scan-thread slot even if the worker panics or spawning fails.
struct ScanWorkerPermit(Arc<AtomicUsize>);

impl Drop for ScanWorkerPermit {
    fn drop(&mut self) {
        let prior = self.0.fetch_sub(1, Ordering::AcqRel);
        debug_assert!(prior > 0, "scan worker permit was released twice");
    }
}

/// Starts, stops, reruns and deletes saved scans over one store.
pub struct ScanService {
    store: ScanStore,
    lookup: ScanLookup,
    rules: Vec<Rule>,
    rule_errors: Vec<RuleError>,
    state: Mutex<State>,
    freed: Condvar,
    admission: Arc<LookupAdmission>,
    worker_slots: Arc<AtomicUsize>,
    sequence: AtomicU64,
}

impl ScanService {
    /// A service over `store` whose scans run Spiderfoot's shipped correlation rules beside
    /// Huntsman's own. Run [`ScanStore::recover`] before the first scan starts.
    #[must_use]
    pub fn new(store: ScanStore, lookup: ScanLookup) -> Arc<Self> {
        Self::with_rules(store, lookup, sf_correlate::shipped().to_vec(), Vec::new())
    }

    /// A service whose scans run `rules` (see [`sf_correlate::with_dir`]) beside Huntsman's own.
    /// `rule_errors` are the rule files that could not be read: each scan logs them, so a broken
    /// rule is seen where its results would have been.
    #[must_use]
    pub fn with_rules(
        store: ScanStore,
        lookup: ScanLookup,
        rules: Vec<Rule>,
        rule_errors: Vec<RuleError>,
    ) -> Arc<Self> {
        Arc::new(Self {
            store,
            lookup,
            rules,
            rule_errors,
            state: Mutex::new(State {
                running: 0,
                aborts: BTreeSet::new(),
                graph_cancellations: BTreeMap::new(),
            }),
            freed: Condvar::new(),
            admission: Arc::new(LookupAdmission::default()),
            worker_slots: Arc::new(AtomicUsize::new(0)),
            sequence: AtomicU64::new(0),
        })
    }

    #[must_use]
    pub fn store(&self) -> &ScanStore {
        &self.store
    }

    /// The Spiderfoot-format rules each scan runs.
    #[must_use]
    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }

    /// The rule files that could not be read.
    #[must_use]
    pub fn rule_errors(&self) -> &[RuleError] {
        &self.rule_errors
    }

    /// Every correlation over a scan's entities and elements: Huntsman's rules, then the
    /// Spiderfoot-format ones, with the count at each risk.
    fn correlate_all(
        &self,
        id: &str,
        entities: &[Entity],
        elements: &[DataElement],
    ) -> (Vec<ScanCorrelation>, RiskCounts) {
        for failure in &self.rule_errors {
            self.log(id, "huntsman", LogLevel::Warning, failure.to_string());
        }
        let mut correlations: Vec<ScanCorrelation> = evaluate_rules(entities, &[], id)
            .iter()
            .map(|correlation| ScanCorrelation::from_rule(correlation, elements))
            .collect();
        correlations.extend(
            sf_correlate::run(&self.rules, elements)
                .into_iter()
                .map(ScanCorrelation::from_finding),
        );
        let mut risks = RiskCounts::default();
        for correlation in &correlations {
            match correlation.risk {
                Risk::High => risks.high += 1,
                Risk::Medium => risks.medium += 1,
                Risk::Low => risks.low += 1,
                Risk::Info => risks.info += 1,
            }
        }
        self.log(
            id,
            "huntsman",
            LogLevel::Info,
            format!(
                "{} correlations from {} rules: high={} medium={} low={} info={}",
                correlations.len(),
                crate::correlator::rule_catalog().len() + self.rules.len(),
                risks.high,
                risks.medium,
                risks.low,
                risks.info
            ),
        );
        (correlations, risks)
    }

    /// Run every rule again over a finished scan's saved results, as `sf.py -C` does: after
    /// flagging false positives or adding a rule. Returns the scan's new correlations.
    ///
    /// # Errors
    /// [`ServiceError::NotFound`] for no such scan or no saved results,
    /// [`ServiceError::Conflict`] while it runs.
    pub fn correlate(&self, id: &str) -> Result<Vec<ScanCorrelation>, ServiceError> {
        let mut record = self.store.get(id)?;
        if record.status.is_active() {
            return Err(ServiceError::Conflict(format!(
                "scan {id} is {}; correlate it when it ends",
                record.status.as_str()
            )));
        }
        let Some(mut results) = self.store.results(id)? else {
            return Err(ServiceError::NotFound(format!(
                "scan {id} has no saved results"
            )));
        };
        let (correlations, risks) = self.correlate_all(id, &results.entities, &results.elements);
        results.correlations.clone_from(&correlations);
        self.store.save_results(&results)?;
        record.correlations = risks;
        self.store.update(&record)?;
        Ok(correlations)
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn log(&self, id: &str, component: &str, level: LogLevel, message: impl Into<String>) {
        // A log the store cannot write must not stop the scan; the row still records the outcome.
        let _ = self.store.append_log(
            id,
            &LogEntry {
                time: now_ms(),
                component: component.to_owned(),
                level,
                message: message.into(),
            },
        );
    }

    /// Save a `CREATED` scan for `request`.
    fn create(&self, request: &ScanRequest) -> Result<(ScanRecord, ScanPlan), ServiceError> {
        let plan = plan(&request.target, request.kind.as_deref())?;
        let options = validate_options(&request.options)?;
        if !lookup_modules::asks_any(plan.kind, &chosen(&options)?) {
            return Err(ServiceError::BadRequest(format!(
                "none of the chosen modules ({}) looks up the target: the {} lookup asks {}",
                options.modules.join(", "),
                plan.kind.command(),
                lookup_modules::modules(plan.kind).join(", ")
            )));
        }
        let name = request
            .name
            .as_deref()
            .map(str::trim)
            .filter(|name| !name.is_empty())
            .unwrap_or(&plan.target)
            .to_owned();
        if name.len() > MAX_NAME_BYTES {
            return Err(ServiceError::BadRequest(format!(
                "the scan name is longer than {MAX_NAME_BYTES} bytes"
            )));
        }
        let record = ScanRecord {
            format_version: FORMAT_VERSION,
            id: new_id(
                &plan.target,
                now_nanos(),
                self.sequence.fetch_add(1, Ordering::Relaxed),
            ),
            name,
            target: plan.target.clone(),
            target_type: plan.target_type.to_owned(),
            kind: plan.kind.command().to_owned(),
            options,
            status: ScanStatus::Created,
            created: now_ms(),
            started: None,
            ended: None,
            elements: 0,
            unique: 0,
            correlations: RiskCounts::default(),
            errors: 0,
            modules_run: Vec::new(),
            owner: Some(std::process::id()),
        };
        self.store.create(&record)?;
        self.log(
            &record.id,
            "huntsman",
            LogLevel::Info,
            format!(
                "scan created: {} target {} routed to the {} lookup",
                record.target_type, record.target, record.kind
            ),
        );
        Ok((record, plan))
    }

    /// Reserve a scan thread before persisting a row or allocating its stack.
    /// This also limits scans queued behind the two active execution slots.
    fn reserve_worker(&self) -> Result<ScanWorkerPermit, ServiceError> {
        let mut live = self.worker_slots.load(Ordering::Acquire);
        loop {
            if live >= MAX_SCAN_WORKERS {
                return Err(ServiceError::Conflict(format!(
                    "scan worker capacity reached ({MAX_SCAN_WORKERS}); retry after a scan finishes"
                )));
            }
            match self.worker_slots.compare_exchange_weak(
                live,
                live + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(observed) => live = observed,
            }
        }
        Ok(ScanWorkerPermit(Arc::clone(&self.worker_slots)))
    }

    /// Start a scan on its own thread and return its `CREATED` row at once.
    ///
    /// # Errors
    /// [`ServiceError::BadRequest`] for an unusable target or option;
    /// [`ServiceError::Conflict`] when scan worker capacity is exhausted; or
    /// [`ServiceError::Store`] when it cannot be saved or its thread cannot start.
    pub fn start(self: &Arc<Self>, request: &ScanRequest) -> Result<ScanRecord, ServiceError> {
        let permit = self.reserve_worker()?;
        let (record, plan) = self.create(request)?;
        let service = Arc::clone(self);
        let id = record.id.clone();
        let spawned = thread::Builder::new()
            .name("scan".into())
            .stack_size(8 * 1024 * 1024)
            .spawn(move || {
                let _permit = permit;
                if let Err(error) = service.execute(&id, &plan) {
                    // The detached worker cannot return an error to start(); preserve
                    // it in the scan log when the scan storage remains writable.
                    service.log(
                        &id,
                        "huntsman",
                        LogLevel::Error,
                        format!("scan worker failed: {error}"),
                    );
                }
            });
        if let Err(error) = spawned {
            let mut failed = record;
            failed.status = ScanStatus::ErrorFailed;
            failed.ended = Some(now_ms());
            self.store.update(&failed)?;
            self.log(
                &failed.id,
                "huntsman",
                LogLevel::Error,
                format!("could not start the scan: {error}"),
            );
            return Err(ServiceError::Store(format!(
                "could not start the scan: {error}"
            )));
        }
        Ok(record)
    }

    /// Start a scan of `request`, or join the scan of the same target, lookup and options that
    /// this process is still waiting to run or running: `serve`'s `/api/lookup`, so a page
    /// reloaded mid-lookup waits on the lookup already under way instead of starting another.
    /// Two requests at once start one scan between them.
    ///
    /// # Errors
    /// As [`Self::start`].
    pub fn start_or_join(
        self: &Arc<Self>,
        request: &ScanRequest,
    ) -> Result<ScanRecord, ServiceError> {
        let plan = plan(&request.target, request.kind.as_deref())?;
        let options = validate_options(&request.options)?;
        let me = Some(std::process::id());
        // Held from the search to the start, so a second request finds the first one's scan.
        let _joining = self.state();
        let running = self.store.list()?.into_iter().find(|record| {
            record.status.is_active()
                && record.owner == me
                && record.target == plan.target
                && record.kind == plan.kind.command()
                && record.options == options
        });
        match running {
            Some(record) => Ok(record),
            None => self.start(request),
        }
    }

    /// Wait until scan `id` ends or `until` passes, and return its row as it then stands.
    ///
    /// # Errors
    /// [`ServiceError::NotFound`] when there is no such scan; [`ServiceError::Store`] when its
    /// row cannot be read.
    pub fn wait(&self, id: &str, until: Instant) -> Result<ScanRecord, ServiceError> {
        loop {
            // A scan saves its final status before it takes this lock to give up its place and
            // notify `freed`, so a row read under the lock cannot miss that notice.
            let state = self.state();
            let record = self.store.get(id)?;
            let now = Instant::now();
            if !record.status.is_active() || now >= until {
                return Ok(record);
            }
            let _ = self
                .freed
                .wait_timeout(state, (until - now).min(WAIT_SLICE))
                .unwrap_or_else(PoisonError::into_inner);
        }
    }

    /// Run a scan on this thread and return its final row: the `scans run` command.
    ///
    /// # Errors
    /// As [`Self::start`].
    pub fn run(&self, request: &ScanRequest) -> Result<ScanRecord, ServiceError> {
        let (record, plan) = self.create(request)?;
        self.execute(&record.id, &plan)?;
        Ok(self.store.get(&record.id)?)
    }

    fn aborted(&self, id: &str) -> bool {
        self.state().aborts.contains(id)
    }

    /// Reuse one cancellation signal across all graph waves of the same scan.
    /// Registration under the state lock cannot miss a stop requested beforehand.
    fn graph_cancellation(&self, id: &str) -> Arc<AtomicBool> {
        let mut state = self.state();
        let already_stopped = state.aborts.contains(id);
        Arc::clone(
            state
                .graph_cancellations
                .entry(id.to_owned())
                .or_insert_with(|| Arc::new(AtomicBool::new(already_stopped))),
        )
    }

    fn set_status(&self, id: &str, status: ScanStatus, at: Option<u64>) -> Result<(), ServiceError> {
        // The state lock also serializes stop requests and the scan row's final counters.
        // A detached read/modify/write could resurrect RUNNING after ABORT-REQUESTED, or
        // overwrite the operator's stop with FINISHED.
        let state = self.state();
        let mut record = self.store.get(id)?;
        if !record.status.is_active() {
            return Ok(());
        }
            if matches!(status, ScanStatus::Starting | ScanStatus::Running)
                && (record.status == ScanStatus::AbortRequested || state.aborts.contains(id))
            {
                return Ok(());
            }
            let status = if status == ScanStatus::Finished && state.aborts.contains(id) {
                ScanStatus::Aborted
            } else {
                status
            };
            record.status = status;
            match status {
                ScanStatus::Running => record.started = at,
                ScanStatus::Aborted | ScanStatus::Finished | ScanStatus::ErrorFailed => {
                    record.ended = at;
                }
                _ => {}
            }
            self.store.update(&record)?;
        Ok(())
    }

    /// The worker: wait for a place, run the lookups, save what they found.
    fn execute(&self, id: &str, plan: &ScanPlan) -> Result<(), ServiceError> {
        // A scan whose status cannot be saved must not dispatch source requests.
        self.set_status(id, ScanStatus::Starting, None)?;
        {
            let mut state = self.state();
            while state.running >= MAX_RUNNING && !state.aborts.contains(id) {
                state = self
                    .freed
                    .wait(state)
                    .unwrap_or_else(PoisonError::into_inner);
            }
            state.running += 1;
        }
        let outcome = catch_unwind(AssertUnwindSafe(|| self.collect(id, plan)));
        {
            let mut state = self.state();
            state.running -= 1;
            state.aborts.remove(id);
            state.graph_cancellations.remove(id);
        }
        self.freed.notify_all();
        match outcome {
            Ok(result) => result,
            Err(_) => {
                self.log(
                    id,
                    "huntsman",
                    LogLevel::Error,
                    "the scan failed unexpectedly; what it saved is kept",
                );
                self.set_status(id, ScanStatus::ErrorFailed, Some(now_ms()))
            }
        }
    }

    fn collect(&self, id: &str, plan: &ScanPlan) -> Result<(), ServiceError> {
        if self.aborted(id) {
            self.log(id, "huntsman", LogLevel::Info, "stopped before it started");
            self.set_status(id, ScanStatus::Aborted, Some(now_ms()))?;
            return Ok(());
        }
        // Persist RUNNING before admitting network requests.
        self.set_status(id, ScanStatus::Running, Some(now_ms()))?;
        let options = match self.store.get(id) {
            Ok(record) => record.options,
            Err(error) => {
                // Never turn a missing or corrupt persisted scan into a lookup with
                // default modules: those are not the operator's selected options.
                // run/wait propagate the persisted row read error to the API boundary;
                // the log and terminal status are best-effort if storage is damaged.
                self.log(
                    id,
                    "huntsman",
                    LogLevel::Error,
                    format!("cannot load persisted scan options: {error}"),
                );
                self.set_status(id, ScanStatus::ErrorFailed, Some(now_ms()))?;
                return Err(error.into());
            }
        };
        let chosen = match chosen(&options) {
            Ok(chosen) => chosen,
            Err(error) => {
                self.log(id, "huntsman", LogLevel::Error, error.to_string());
                self.set_status(id, ScanStatus::ErrorFailed, Some(now_ms()))?;
                return Ok(());
            }
        };
        let passive = options.usecase == "passive";
        let mut targets = vec![CrawlTarget {
            kind: plan.kind,
            selector: plan.target.clone(),
        }];
        if plan.kind == ScanKind::Email && !passive {
            if let Some(selector) = canonical_selector(ScanKind::Exposure, &plan.target) {
                targets.push(CrawlTarget {
                    kind: ScanKind::Exposure,
                    selector,
                });
            }
        }
        let policy = RecursionPolicy {
            max_generations: options.depth,
            expose_emails: !passive,
            ..RecursionPolicy::default()
        };
        let mut collector = ScanCollector {
            service: self,
            id,
            chosen: &chosen,
            text: String::new(),
            ran: 0,
            errors: 0,
            breach_checked: BTreeSet::new(),
        };
        let report = recursion::run_targets(targets, &policy, &mut collector);
        let (ran, errors) = (collector.ran, collector.errors);
        self.log_crawl(id, &options, &report);
        let found = LookupOutput {
            text: collector.text,
            entities: report.entities,
            outcomes: report.outcomes,
        };
        let crawl = Crawl {
            lineage: report.edges,
            termination: report.termination,
        };
        let saved = self.save(id, plan, &options, found, errors, crawl);
        let status = if self.aborted(id) {
            ScanStatus::Aborted
        } else if ran == 0 {
            ScanStatus::ErrorFailed
        } else {
            ScanStatus::Finished
        };
        if let Err(error) = saved {
            self.log(
                id,
                "huntsman",
                LogLevel::Error,
                format!("could not save the results: {error}"),
            );
            self.set_status(id, ScanStatus::ErrorFailed, Some(now_ms()))?;
            return Ok(());
        }
        self.log(
            id,
            "huntsman",
            LogLevel::Info,
            format!("scan {}", status.as_str()),
        );
        self.set_status(id, status, Some(now_ms()))
    }

    /// How far the scan followed what it found, and why it stopped there.
    fn log_crawl(&self, id: &str, options: &ScanOptions, report: &RecursionReport) {
        let reason = serde_json::to_value(report.termination)
            .ok()
            .and_then(|value| value.as_str().map(str::to_owned))
            .unwrap_or_default();
        let detail = match report.termination {
            TerminationReason::Cancelled => {
                "stop requested; the lookups still queued did not run".to_owned()
            }
            TerminationReason::MaxDepth if options.depth == 0 => {
                "depth 0 follows nothing it finds; a deeper scan would look up its findings in turn"
                    .to_owned()
            }
            TerminationReason::MaxDepth => format!(
                "depth {} reached; a deeper scan would look up more of its findings",
                options.depth
            ),
            TerminationReason::ResourceLimit => {
                "the lookup or entity budget ran out with findings left to follow".to_owned()
            }
            _ => "nothing new was left to look up".to_owned(),
        };
        self.log(
            id,
            "huntsman",
            LogLevel::Info,
            format!(
                "{} lookups over {} generations found {} entities; stopped ({reason}): {detail}",
                report.dispatches,
                report.generations.len(),
                report.entities.len()
            ),
        );
    }

    /// Run one lookup, log each source's outcome, and add what it found to `found`. Returns how
    /// many of its sources failed, or `None` when the lookup gave no report at all.
    fn lookup_into(
        &self,
        id: &str,
        (kind, target, chosen): (ScanKind, &str, &Selection),
        found: &mut LookupOutput,
    ) -> LookupDispatch {
        let cancelled = self.graph_cancellation(id);
        let Some(_permit) = self.admission.acquire(|| cancelled.load(Ordering::Acquire)) else {
            self.log(
                id,
                "huntsman",
                LogLevel::Info,
                format!(
                    "{} lookup on {target} cancelled before admission",
                    kind.command()
                ),
            );
            return LookupDispatch::Cancelled;
        };
        if cancelled.load(Ordering::Acquire) {
            return LookupDispatch::Cancelled;
        }
        self.log(
            id,
            "huntsman",
            LogLevel::Info,
            format!("running the {} lookup on {target}", kind.command()),
        );
        match (self.lookup)(kind, target, chosen) {
            Ok(output) => {
                let mut failed = 0;
                for outcome in &output.outcomes {
                    let accepted = outcome.kind.is_accepted();
                    failed += usize::from(!accepted);
                    let level = if accepted {
                        LogLevel::Info
                    } else {
                        LogLevel::Error
                    };
                    self.log(id, &outcome.module, level, outcome_line(outcome));
                }
                if !found.text.is_empty() && !output.text.is_empty() {
                    found.text.push('\n');
                }
                found.text.push_str(&output.text);
                found.entities.extend(output.entities);
                found.outcomes.extend(output.outcomes);
                LookupDispatch::Completed(failed)
            }
            Err(message) => {
                self.log(
                    id,
                    kind.command(),
                    LogLevel::Error,
                    format!("the {} lookup gave no report: {message}", kind.command()),
                );
                found.outcomes.push(SourceExecutionOutcome::inconclusive(
                    "scan_lookup",
                    now_ms() / 1_000,
                    format!("{} lookup on {target}: {message}", kind.command()),
                ));
                LookupDispatch::Missing
            }
        }
    }

    fn save(
        &self,
        id: &str,
        plan: &ScanPlan,
        options: &ScanOptions,
        found: LookupOutput,
        errors: usize,
        crawl: Crawl,
    ) -> Result<(), ServiceError> {
        let now = now_ms();
        let target = Target {
            value: &plan.target,
            kind: plan.target_type,
        };
        let mut elements = sf_elements::elements_with_lineage(
            target,
            &found.entities,
            &sf_elements::lineage(&crawl.lineage),
            now / 1000,
        );
        if !options.types.is_empty() {
            let keep: BTreeSet<&str> = options.types.iter().map(String::as_str).collect();
            elements.retain(|element| {
                element.kind == "ROOT"
                    || element.kind == plan.target_type
                    || keep.contains(element.kind.as_str())
            });
        }
        let (correlations, risks) = self.correlate_all(id, &found.entities, &elements);
        let modules_run: Vec<String> = found
            .outcomes
            .iter()
            .map(|outcome| outcome.module.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let shown: Vec<_> = elements
            .iter()
            .filter(|element| element.kind != "ROOT")
            .collect();
        let unique = shown
            .iter()
            .map(|element| (element.kind.as_str(), element.data.as_str()))
            .collect::<BTreeSet<_>>()
            .len();
        let total = shown.len();
        self.store.save_results(&ScanResults {
            format_version: FORMAT_VERSION,
            scan_id: id.to_owned(),
            text: found.text,
            entities: found.entities,
            outcomes: found.outcomes,
            elements,
            correlations,
            lineage: crawl.lineage,
            termination: Some(crawl.termination),
        })?;
        // A stop and a result-count update must not write stale copies of the same row.
        let _state = self.state();
        let mut record = self.store.get(id)?;
        record.elements = total;
        record.unique = unique;
        record.correlations = risks;
        record.errors = errors;
        record.modules_run = modules_run;
        self.store.update(&record)?;
        Ok(())
    }

    /// Ask a running or waiting scan to stop.
    ///
    /// # Errors
    /// [`ServiceError::NotFound`] for no such scan, [`ServiceError::Conflict`] when it is not
    /// running.
    pub fn stop(&self, id: &str) -> Result<ScanRecord, ServiceError> {
        // Hold the same lock as worker status transitions and save's row update.
        // Otherwise a stop could read RUNNING and replace a newly FINISHED row.
        let mut state = self.state();
        let mut record = self.store.get(id)?;
        if !record.status.is_active() {
            return Err(ServiceError::Conflict(format!(
                "scan {id} is {}, not running",
                record.status.as_str()
            )));
        }
        state.aborts.insert(id.to_owned());
        if let Some(cancelled) = state.graph_cancellations.get(id) {
            cancelled.store(true, Ordering::Release);
        }
        // Wake blocked workers even if persisting the request fails.
        self.freed.notify_all();
        self.admission.freed.notify_all();
        if record.status != ScanStatus::AbortRequested {
            record.status = ScanStatus::AbortRequested;
            self.store.update(&record)?;
            self.log(id, "huntsman", LogLevel::Info, "stop requested");
        }
        Ok(record)
    }

    /// Delete a scan that is not running.
    ///
    /// # Errors
    /// [`ServiceError::NotFound`] for no such scan, [`ServiceError::Conflict`] while it runs.
    pub fn delete(&self, id: &str) -> Result<(), ServiceError> {
        let record = self.store.get(id).or_else(|error| match error {
            // An unreadable row can still be deleted.
            StoreError::Io(_) => Ok(ScanRecord {
                status: ScanStatus::ErrorFailed,
                ..placeholder(id)
            }),
            other => Err(other),
        })?;
        if record.status.is_active() {
            return Err(ServiceError::Conflict(format!(
                "scan {id} is {}; stop it before deleting it",
                record.status.as_str()
            )));
        }
        Ok(self.store.delete(id)?)
    }

    /// Start a new scan with a finished scan's target, kind, name and options.
    ///
    /// # Errors
    /// As [`Self::start`], and [`ServiceError::NotFound`] for no such scan.
    pub fn rerun(self: &Arc<Self>, id: &str) -> Result<ScanRecord, ServiceError> {
        self.start(&self.rerun_request(id)?)
    }

    /// The request that runs scan `id` again: its target, name, lookup and options.
    ///
    /// # Errors
    /// [`ServiceError::NotFound`] when there is no such scan.
    pub fn rerun_request(&self, id: &str) -> Result<ScanRequest, ServiceError> {
        let record = self.store.get(id)?;
        Ok(ScanRequest {
            target: record.target,
            name: Some(record.name),
            kind: Some(record.kind),
            options: record.options,
        })
    }
}

fn placeholder(id: &str) -> ScanRecord {
    ScanRecord {
        format_version: FORMAT_VERSION,
        id: id.to_owned(),
        name: String::new(),
        target: String::new(),
        target_type: String::new(),
        kind: String::new(),
        options: ScanOptions::default(),
        status: ScanStatus::ErrorFailed,
        created: 0,
        started: None,
        ended: None,
        elements: 0,
        unique: 0,
        correlations: RiskCounts::default(),
        errors: 0,
        modules_run: Vec::new(),
        owner: None,
    }
}

/// One source outcome as a log line: what happened, how many it found, and the provider's own
/// words, whole.
fn outcome_line(outcome: &SourceExecutionOutcome) -> String {
    let mut parts: BTreeMap<&str, String> = BTreeMap::new();
    if let Some(status) = outcome.http_status {
        parts.insert("http", status.to_string());
    }
    if let Some(found) = outcome.found {
        parts.insert("found", found.to_string());
    }
    if let Some(retry) = outcome.retry_after_secs {
        parts.insert("retry_after_s", retry.to_string());
    }
    let mut line = serde_json::to_value(outcome.kind)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_else(|| format!("{:?}", outcome.kind));
    for (key, value) in parts {
        let _ = write!(line, " {key}={value}");
    }
    if let Some(detail) = &outcome.detail {
        line.push_str(": ");
        line.push_str(detail);
    }
    line
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entity::{EntityKind, Evidence, EvidenceProvenance};
    use crate::source_outcome::SourceOutcomeKind;
    use std::path::PathBuf;
    use std::sync::mpsc;
    use std::time::Duration;

    #[test]
    fn full_scan_store_is_a_conflict_not_a_bad_request() {
        let error = ServiceError::from(StoreError::Capacity(crate::scan_store::MAX_SCANS));
        assert_eq!(error.status(), 409);
        assert!(matches!(error, ServiceError::Conflict(_)));
    }

    fn scratch(tag: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("hse-scan-service-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    fn found(kind: ScanKind, selector: &str) -> LookupOutput {
        let evidence = Evidence::new(EvidenceProvenance::for_scan("internetdb", "s"), "ports")
            .with_attr("ports", "22,443");
        LookupOutput {
            text: format!("{} {selector}\n", kind.command()),
            entities: vec![
                Entity::builder(EntityKind::IpAddress, selector, 0.9, "s")
                    .evidence(evidence)
                    .build(),
            ],
            outcomes: vec![
                SourceExecutionOutcome::success("internetdb", 1, 1),
                SourceExecutionOutcome::valid_zero("greynoise", 1),
            ],
        }
    }

    fn with_lookup(tag: &str, lookup: ScanLookup) -> (Arc<ScanService>, PathBuf) {
        let dir = scratch(tag);
        (
            ScanService::new(ScanStore::open(&dir).unwrap(), lookup),
            dir,
        )
    }

    #[test]
    fn missing_or_corrupt_scan_configuration_never_dispatches_default_lookups() {
        let calls = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&calls);
        let (service, dir) = with_lookup(
            "missing-scan-options",
            Arc::new(move |_, _, _| {
                observed.fetch_add(1, Ordering::SeqCst);
                Ok(LookupOutput::default())
            }),
        );
        for corrupt in [false, true] {
            let request = ScanRequest {
                target: "example.org".into(),
                kind: Some("domain".into()),
                options: ScanOptions {
                    modules: vec!["crtsh".into()],
                    ..ScanOptions::default()
                },
                ..ScanRequest::default()
            };
            let (record, plan) = service.create(&request).unwrap();
            let row = dir.join(&record.id).join("scan.json");
            if corrupt {
                std::fs::write(&row, b"not json").unwrap();
            } else {
                std::fs::remove_file(&row).unwrap();
            }
            assert!(service.collect(&record.id, &plan).is_err());
            assert_eq!(
                calls.load(Ordering::SeqCst),
                0,
                "unreadable scan options must never result in network calls"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn scan_status_persistence_errors_prevent_lookup_dispatch() {
        let calls = Arc::new(AtomicUsize::new(0));
        let seen = Arc::clone(&calls);
        let (service, dir) = with_lookup(
            "status-persistence",
            Arc::new(move |_, _, _| {
                seen.fetch_add(1, Ordering::SeqCst);
                Ok(LookupOutput::default())
            }),
        );
        let (record, plan) = service
            .create(&ScanRequest {
                target: "example.org".into(),
                kind: Some("domain".into()),
                ..ScanRequest::default()
            })
            .unwrap();

        let row = dir.join(&record.id).join("scan.json");
        std::fs::remove_file(&row).unwrap();
        assert!(matches!(
            service.execute(&record.id, &plan),
            Err(ServiceError::NotFound(_))
        ));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(service.state().running, 0);

        std::fs::write(&row, b"not json").unwrap();
        assert!(matches!(
            service.execute(&record.id, &plan),
            Err(ServiceError::Store(_))
        ));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(service.state().running, 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn scan_thread_admission_rejects_overload_without_creating_a_row() {
        let (service, dir) = with_lookup(
            "bounded-scan-workers",
            Arc::new(|_, _, _| Ok(LookupOutput::default())),
        );
        let permits: Vec<_> = (0..MAX_SCAN_WORKERS)
            .map(|_| service.reserve_worker().unwrap())
            .collect();
        assert_eq!(
            service.worker_slots.load(Ordering::Acquire),
            MAX_SCAN_WORKERS
        );
        let rejected = service.start(&ScanRequest {
            target: "example.com".into(),
            ..ScanRequest::default()
        });
        assert!(matches!(rejected, Err(ServiceError::Conflict(_))));
        assert!(service.store().list().unwrap().is_empty());

        drop(permits);
        assert_eq!(service.worker_slots.load(Ordering::Acquire), 0);
        let started = service
            .start(&ScanRequest {
                target: "example.com".into(),
                ..ScanRequest::default()
            })
            .unwrap();
        let finished = service
            .wait(&started.id, Instant::now() + Duration::from_secs(10))
            .unwrap();
        assert!(!finished.status.is_active());
        for _ in 0..200 {
            if service.worker_slots.load(Ordering::Acquire) == 0 {
                break;
            }
            thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(service.worker_slots.load(Ordering::Acquire), 0);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn spiderfoot_rules_correlate_a_scan_and_again_after_a_false_positive() {
        let dir = scratch("rules");
        let rule = Rule::parse(
            "open_port",
            "id: open_port\nversion: 1\nmeta:\n  name: Open port\n  description: Any open port.\n  risk: MEDIUM\ncollections:\n  - collect:\n      - method: exact\n        field: type\n        value: TCP_PORT_OPEN\naggregation:\n  field: data\nheadline: \"Open port: {data}\"\n",
            "mine.yaml",
        )
        .unwrap();
        let broken = RuleError {
            rule: "broken".into(),
            reason: "not a mapping".into(),
        };
        let service = ScanService::with_rules(
            ScanStore::open(&dir).unwrap(),
            Arc::new(|kind: ScanKind, selector: &str, _: &Selection| Ok(found(kind, selector))),
            vec![rule],
            vec![broken],
        );
        let record = service
            .run(&ScanRequest {
                target: "1.1.1.1".into(),
                ..ScanRequest::default()
            })
            .unwrap();
        let mine = |correlations: &[ScanCorrelation]| -> Vec<String> {
            correlations
                .iter()
                .filter(|correlation| correlation.origin == "mine.yaml")
                .map(|correlation| correlation.title.clone())
                .collect()
        };
        let mut results = service.store().results(&record.id).unwrap().unwrap();
        assert_eq!(
            mine(&results.correlations),
            ["Open port: 1.1.1.1:22", "Open port: 1.1.1.1:443"]
        );
        let medium = |correlations: &[ScanCorrelation]| {
            correlations
                .iter()
                .filter(|correlation| correlation.risk == Risk::Medium)
                .count()
        };
        assert_eq!(record.correlations.medium, medium(&results.correlations));
        let log = service.store().log(&record.id).unwrap();
        assert!(log.iter().any(|entry| entry.level == LogLevel::Warning
            && entry.message == "correlation rule broken: not a mapping"));
        for element in &mut results.elements {
            element.fp |= element.data == "1.1.1.1:22";
        }
        service.store().save_results(&results).unwrap();
        let again = service.correlate(&record.id).unwrap();
        assert_eq!(mine(&again), ["Open port: 1.1.1.1:443"]);
        let saved = service.store().results(&record.id).unwrap().unwrap();
        assert_eq!(saved.correlations, again);
        assert_eq!(
            service.store().get(&record.id).unwrap().correlations.medium,
            medium(&again)
        );
        assert!(matches!(
            service.correlate("nope"),
            Err(ServiceError::NotFound(_))
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_scan_asks_only_the_modules_chosen_and_skips_lookups_that_ask_none() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let seen = Arc::clone(&calls);
        let (service, dir) = with_lookup(
            "modules",
            Arc::new(move |kind: ScanKind, selector: &str, chosen: &Selection| {
                let asked: Vec<&str> = ["crtsh", "spamhaus", "shodan"]
                    .into_iter()
                    .filter(|module| chosen.runs(module))
                    .collect();
                seen.lock().unwrap().push(format!(
                    "{} {selector} asks {}",
                    kind.command(),
                    asked.join(",")
                ));
                let address = Entity::builder(EntityKind::IpAddress, "8.8.8.8", 0.9, "s")
                    .evidence(Evidence::new(
                        EvidenceProvenance::for_scan("crtsh", "s"),
                        "found",
                    ))
                    .build();
                Ok(LookupOutput {
                    text: format!("{} {selector}\n", kind.command()),
                    entities: vec![address],
                    outcomes: vec![SourceExecutionOutcome::success("crtsh", 1, 1)],
                })
            }),
        );
        let scan = |target: &str, modules: &[&str]| {
            service.run(&ScanRequest {
                target: target.into(),
                options: ScanOptions {
                    modules: modules.iter().map(|module| (*module).to_owned()).collect(),
                    depth: 1,
                    ..ScanOptions::default()
                },
                ..ScanRequest::default()
            })
        };
        // Only crt.sh: the domain's lookup asks it alone, and no chosen module looks up the
        // address it found, so that lookup is skipped, not failed.
        let record = scan("example.org", &[" CRTSH "]).unwrap();
        assert_eq!(record.status, ScanStatus::Finished);
        assert_eq!(record.options.modules, ["crtsh"]);
        assert_eq!(record.errors, 0);
        assert_eq!(*calls.lock().unwrap(), ["domain example.org asks crtsh"]);
        let log = service.store().log(&record.id).unwrap();
        assert!(log.iter().any(|entry| entry.level == LogLevel::Info
            && entry.message == "no chosen module looks up ip, so 8.8.8.8 was not looked up"));
        // A Spiderfoot name chooses the module doing its work, which also looks up addresses.
        calls.lock().unwrap().clear();
        let record = scan("example.org", &["SFP_SPAMHAUS"]).unwrap();
        assert_eq!(record.options.modules, ["sfp_spamhaus"]);
        assert_eq!(
            *calls.lock().unwrap(),
            [
                "domain example.org asks spamhaus",
                "ip 8.8.8.8 asks spamhaus"
            ]
        );
        // A name no module answers to, and a target none of the chosen modules looks up, are
        // refused before the scan is saved.
        let unknown = scan("example.org", &["crtsh", "sfp_spider"]).unwrap_err();
        assert!(
            matches!(&unknown, ServiceError::BadRequest(why) if why.starts_with("no module is named sfp_spider;")),
            "{unknown:?}"
        );
        let elsewhere = scan("1.1.1.1", &["crtsh"]).unwrap_err();
        assert!(
            matches!(&elsewhere, ServiceError::BadRequest(why) if why.starts_with("none of the chosen modules (crtsh) looks up the target: the ip lookup asks dnsresolve, rdap,")),
            "{elsewhere:?}"
        );
        assert_eq!(service.store().list().unwrap().len(), 2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_deeper_scan_looks_up_what_it_finds_and_links_each_element_to_its_finder() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let seen = Arc::clone(&calls);
        let (service, dir) = with_lookup(
            "depth",
            Arc::new(move |kind: ScanKind, selector: &str, _: &Selection| {
                seen.lock()
                    .unwrap()
                    .push(format!("{} {selector}", kind.command()));
                let entity = |kind: EntityKind, value: &str, source: &str| {
                    Entity::builder(kind, value, 0.9, "s")
                        .evidence(Evidence::new(
                            EvidenceProvenance::for_scan(source, "s"),
                            "found",
                        ))
                        .build()
                };
                Ok(match kind {
                    ScanKind::Domain => LookupOutput {
                        text: format!("domain {selector}\n"),
                        entities: vec![entity(EntityKind::IpAddress, "8.8.8.8", "dns")],
                        outcomes: vec![SourceExecutionOutcome::success("dns", 1, 1)],
                    },
                    ScanKind::Ip => {
                        let mut output = found(kind, selector);
                        output.entities.push(entity(
                            EntityKind::Domain,
                            "cohost.example.net",
                            "hackertarget",
                        ));
                        output
                    }
                    _ => LookupOutput::default(),
                })
            }),
        );
        let record = service
            .run(&ScanRequest {
                target: "example.org".into(),
                options: ScanOptions {
                    depth: 1,
                    ..ScanOptions::default()
                },
                ..ScanRequest::default()
            })
            .unwrap();
        assert_eq!(record.status, ScanStatus::Finished);
        assert_eq!(record.options.depth, 1);
        // The co-hosted domain would be the third hop's lookup; depth 1 stops before it.
        assert_eq!(*calls.lock().unwrap(), ["domain example.org", "ip 8.8.8.8"]);
        let results = service.store().results(&record.id).unwrap().unwrap();
        assert_eq!(results.termination, Some(TerminationReason::MaxDepth));
        assert_eq!(results.text, "domain example.org\n\nip 8.8.8.8\n");
        assert!(
            results
                .lineage
                .iter()
                .any(|edge| edge.from_selector == "8.8.8.8"
                    && edge.to_value == "cohost.example.net"
                    && edge.generation == 1)
        );
        let element = |data: &str| {
            results
                .elements
                .iter()
                .find(|element| element.data == data && element.kind != "ROOT")
                .unwrap()
        };
        let target = element("example.org");
        let address = element("8.8.8.8");
        assert_eq!(address.source.as_deref(), Some(target.id.as_str()));
        // Found by the address's lookup, so the address's element is its source.
        assert_eq!(
            element("cohost.example.net").source.as_deref(),
            Some(address.id.as_str())
        );
        // A port hangs off the address element its own record made.
        let port_source = element("8.8.8.8:22").source.clone().unwrap();
        assert!(
            results
                .elements
                .iter()
                .any(|element| element.id == port_source
                    && element.data == "8.8.8.8"
                    && element.module == "internetdb")
        );
        let log = service.store().log(&record.id).unwrap();
        assert!(log.iter().any(|entry| entry.message
            == "2 lookups over 2 generations found 2 entities; stopped (max_depth): depth 1 reached; a deeper scan would look up more of its findings"));
        let rerun = service.rerun_request(&record.id).unwrap();
        assert_eq!(rerun.options.depth, 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_run_saves_elements_counts_log_and_finishes() {
        let (service, dir) = with_lookup(
            "run",
            Arc::new(|kind: ScanKind, selector: &str, _: &Selection| Ok(found(kind, selector))),
        );
        let record = service
            .run(&ScanRequest {
                target: " 1.1.1.1 ".into(),
                ..ScanRequest::default()
            })
            .unwrap();
        assert_eq!(record.status, ScanStatus::Finished);
        assert_eq!(record.kind, "ip");
        assert_eq!(record.target_type, "IP_ADDRESS");
        assert_eq!(record.name, "1.1.1.1");
        assert_eq!(record.options.usecase, "all");
        assert_eq!(record.modules_run, ["greynoise", "internetdb"]);
        assert!(record.started.is_some() && record.ended.is_some());
        let results = service.store().results(&record.id).unwrap().unwrap();
        let ports: Vec<&str> = results
            .elements
            .iter()
            .filter(|element| element.kind == "TCP_PORT_OPEN")
            .map(|element| element.data.as_str())
            .collect();
        assert_eq!(ports, ["1.1.1.1:22", "1.1.1.1:443"]);
        assert_eq!(record.elements, results.elements.len() - 1);
        let log = service.store().log(&record.id).unwrap();
        assert!(
            log.iter()
                .any(|entry| entry.component == "greynoise"
                    && entry.message.starts_with("valid_zero"))
        );
        assert!(log.last().unwrap().message.contains("FINISHED"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_email_scan_runs_the_breach_lookup_unless_the_email_lookup_ran_a_breach_source() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let seen = Arc::clone(&calls);
        let (service, dir) = with_lookup(
            "email",
            Arc::new(move |kind: ScanKind, _selector: &str, _: &Selection| {
                seen.lock().unwrap().push(kind.command());
                Ok(LookupOutput::default())
            }),
        );
        service
            .run(&ScanRequest {
                target: "jane@example.org".into(),
                ..ScanRequest::default()
            })
            .unwrap();
        assert_eq!(*calls.lock().unwrap(), ["email", "exposure"]);
        calls.lock().unwrap().clear();
        let (service2, dir2) = with_lookup(
            "email2",
            Arc::new({
                let seen = Arc::clone(&calls);
                move |kind: ScanKind, _selector: &str, _: &Selection| {
                    seen.lock().unwrap().push(kind.command());
                    Ok(LookupOutput {
                        outcomes: vec![SourceExecutionOutcome::valid_zero("hibp", 1)],
                        ..LookupOutput::default()
                    })
                }
            }),
        );
        service2
            .run(&ScanRequest {
                target: "jane@example.org".into(),
                ..ScanRequest::default()
            })
            .unwrap();
        assert_eq!(*calls.lock().unwrap(), ["email"]);
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&dir2);
    }

    #[test]
    fn a_lookup_that_cannot_run_fails_the_scan_with_the_reason_logged() {
        let (service, dir) = with_lookup(
            "fail",
            Arc::new(|_kind: ScanKind, _selector: &str, _: &Selection| {
                Err("egress refused".to_owned())
            }),
        );
        let record = service
            .run(&ScanRequest {
                target: "example.com".into(),
                ..ScanRequest::default()
            })
            .unwrap();
        assert_eq!(record.status, ScanStatus::ErrorFailed);
        assert_eq!(record.errors, 1);
        let log = service.store().log(&record.id).unwrap();
        assert!(log.iter().any(
            |entry| entry.level == LogLevel::Error && entry.message.contains("egress refused")
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn bad_targets_kinds_and_options_are_refused_before_anything_is_saved() {
        let (service, dir) = with_lookup(
            "bad",
            Arc::new(|kind: ScanKind, selector: &str, _: &Selection| Ok(found(kind, selector))),
        );
        for request in [
            ScanRequest::default(),
            ScanRequest {
                target: "example.com".into(),
                kind: Some("nope".into()),
                ..ScanRequest::default()
            },
            ScanRequest {
                target: "example.com".into(),
                options: ScanOptions {
                    usecase: "everything".into(),
                    ..ScanOptions::default()
                },
                ..ScanRequest::default()
            },
            ScanRequest {
                target: "example.com".into(),
                options: ScanOptions {
                    types: vec!["NOT_A_TYPE".into()],
                    ..ScanOptions::default()
                },
                ..ScanRequest::default()
            },
        ] {
            assert!(
                matches!(service.run(&request), Err(ServiceError::BadRequest(_))),
                "{request:?}"
            );
        }
        assert!(service.store().list().unwrap().is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn requested_types_keep_only_those_elements_and_the_target() {
        let (service, dir) = with_lookup(
            "types",
            Arc::new(|kind: ScanKind, selector: &str, _: &Selection| Ok(found(kind, selector))),
        );
        let record = service
            .run(&ScanRequest {
                target: "1.1.1.1".into(),
                options: ScanOptions {
                    types: vec!["tcp_port_open".into()],
                    ..ScanOptions::default()
                },
                ..ScanRequest::default()
            })
            .unwrap();
        assert_eq!(record.options.types, ["TCP_PORT_OPEN"]);
        let results = service.store().results(&record.id).unwrap().unwrap();
        let kinds: BTreeSet<&str> = results
            .elements
            .iter()
            .map(|element| element.kind.as_str())
            .collect();
        assert_eq!(
            kinds,
            BTreeSet::from(["IP_ADDRESS", "ROOT", "TCP_PORT_OPEN"])
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn cancellation_is_monotonic_across_worker_start_and_finish() {
        let (service, dir) = with_lookup(
            "monotonic-status",
            Arc::new(|_: ScanKind, _: &str, _: &Selection| Ok(LookupOutput::default())),
        );
        let (created, _) = service
            .create(&ScanRequest {
                target: "1.1.1.1".into(),
                ..ScanRequest::default()
            })
            .unwrap();
        let stop = service.stop(&created.id).unwrap();
        assert_eq!(stop.status, ScanStatus::AbortRequested);

        // The queued worker may observe the stop after starting. Neither transition
        // may erase the operator's cancellation request or invent a start time.
        service.set_status(&created.id, ScanStatus::Starting, None).unwrap();
        service.set_status(&created.id, ScanStatus::Running, Some(123)).unwrap();
        let row = service.store().get(&created.id).unwrap();
        assert_eq!(row.status, ScanStatus::AbortRequested);
        assert!(row.started.is_none());

        // A worker that chose FINISHED just before stop() acquired the state lock
        // must still commit ABORTED when it eventually updates its row.
        service.set_status(&created.id, ScanStatus::Finished, Some(456)).unwrap();
        let row = service.store().get(&created.id).unwrap();
        assert_eq!(row.status, ScanStatus::Aborted);
        assert_eq!(row.ended, Some(456));
        service.set_status(&created.id, ScanStatus::Running, Some(789)).unwrap();
        assert_eq!(
            service.store().get(&created.id).unwrap().status,
            ScanStatus::Aborted,
            "a completed scan must never be resurrected by a late worker transition"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_stop_while_running_aborts_after_the_lookup_and_keeps_its_results() {
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let release_rx = Mutex::new(release_rx);
        let entered_tx = Mutex::new(entered_tx);
        let (service, dir) = with_lookup(
            "stop",
            Arc::new(move |kind: ScanKind, selector: &str, _: &Selection| {
                entered_tx.lock().unwrap().send(()).unwrap();
                release_rx.lock().unwrap().recv().unwrap();
                Ok(found(kind, selector))
            }),
        );
        let record = service
            .start(&ScanRequest {
                target: "jane@example.org".into(),
                ..ScanRequest::default()
            })
            .unwrap();
        assert_eq!(record.status, ScanStatus::Created);
        entered_rx.recv_timeout(Duration::from_secs(10)).unwrap();
        assert_eq!(
            service.store().get(&record.id).unwrap().status,
            ScanStatus::Running
        );
        assert!(matches!(
            service.delete(&record.id),
            Err(ServiceError::Conflict(_))
        ));
        let stopping = service.stop(&record.id).unwrap();
        assert_eq!(stopping.status, ScanStatus::AbortRequested);
        release_tx.send(()).unwrap();
        let mut status = ScanStatus::AbortRequested;
        for _ in 0..200 {
            status = service.store().get(&record.id).unwrap().status;
            if !status.is_active() {
                break;
            }
            thread::sleep(Duration::from_millis(25));
        }
        assert_eq!(status, ScanStatus::Aborted);
        // The email lookup's results are kept; the breach lookup never started.
        let results = service.store().results(&record.id).unwrap().unwrap();
        assert!(!results.entities.is_empty());
        assert_eq!(results.termination, Some(TerminationReason::Cancelled));
        let log = service.store().log(&record.id).unwrap();
        assert!(log.iter().any(|entry| entry.message.contains(
            "stopped (cancelled): stop requested; the lookups still queued did not run"
        )));
        assert!(
            !log.iter()
                .any(|entry| entry.message.contains("running the exposure"))
        );
        assert!(matches!(
            service.stop(&record.id),
            Err(ServiceError::Conflict(_))
        ));
        service.delete(&record.id).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn stopping_active_graph_batch_signals_cancellation_and_retains_results() {
        let (entered_tx, entered_rx) = mpsc::channel::<String>();
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let entered_tx = Mutex::new(entered_tx);
        let release_rx = Mutex::new(release_rx);
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let observed_calls = Arc::clone(&calls);
        let (service, dir) = with_lookup(
            "stop-graph-batch",
            Arc::new(move |kind: ScanKind, selector: &str, _: &Selection| {
                if kind == ScanKind::Domain {
                    let evidence = Evidence::new(
                        EvidenceProvenance::for_scan("test", "seed"),
                        "discovered address",
                    );
                    return Ok(LookupOutput {
                        entities: ["1.1.1.1", "8.8.8.8", "9.9.9.9"]
                            .into_iter()
                            .map(|ip| {
                                Entity::builder(EntityKind::IpAddress, ip, 0.95, "test")
                                    .evidence(evidence.clone())
                                    .build()
                            })
                            .collect(),
                        ..LookupOutput::default()
                    });
                }
                observed_calls.fetch_add(1, Ordering::SeqCst);
                entered_tx
                    .lock()
                    .unwrap()
                    .send(selector.to_owned())
                    .unwrap();
                release_rx.lock().unwrap().recv().unwrap();
                Ok(LookupOutput {
                    text: format!("completed-{selector}"),
                    ..LookupOutput::default()
                })
            }),
        );
        let record = service
            .start(&ScanRequest {
                target: "example.org".into(),
                kind: Some("domain".into()),
                options: ScanOptions {
                    depth: 1,
                    ..ScanOptions::default()
                },
                ..ScanRequest::default()
            })
            .unwrap();
        let first = entered_rx.recv_timeout(Duration::from_secs(10)).unwrap();
        let second = entered_rx.recv_timeout(Duration::from_secs(10)).unwrap();
        assert_ne!(first, second);
        let cancellation = {
            let state = service.state();
            Arc::clone(
                state
                    .graph_cancellations
                    .get(&record.id)
                    .expect("running graph must register cancellation"),
            )
        };
        assert!(!cancellation.load(Ordering::Acquire));
        service.stop(&record.id).unwrap();
        assert!(cancellation.load(Ordering::Acquire));
        release_tx.send(()).unwrap();
        release_tx.send(()).unwrap();
        let finished = service
            .wait(&record.id, Instant::now() + Duration::from_secs(10))
            .unwrap();
        assert_eq!(finished.status, ScanStatus::Aborted);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        let results = service.store().results(&record.id).unwrap().unwrap();
        assert!(results.text.contains(&format!("completed-{first}")));
        assert!(results.text.contains(&format!("completed-{second}")));
        assert_eq!(results.termination, Some(TerminationReason::Cancelled));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_rerun_is_a_new_scan_with_the_same_target_and_options() {
        let (service, dir) = with_lookup(
            "rerun",
            Arc::new(|kind: ScanKind, selector: &str, _: &Selection| Ok(found(kind, selector))),
        );
        let first = service
            .run(&ScanRequest {
                target: "1.1.1.1".into(),
                name: Some("office".into()),
                kind: Some("ip".into()),
                options: ScanOptions {
                    usecase: "footprint".into(),
                    ..ScanOptions::default()
                },
            })
            .unwrap();
        let second = service.rerun(&first.id).unwrap();
        assert_ne!(second.id, first.id);
        assert_eq!(
            (
                second.name.as_str(),
                second.target.as_str(),
                second.kind.as_str()
            ),
            ("office", "1.1.1.1", "ip")
        );
        assert_eq!(second.options, first.options);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_panicking_lookup_fails_the_scan_and_frees_its_place() {
        let (service, dir) = with_lookup(
            "panic",
            Arc::new(
                |_kind: ScanKind, _selector: &str, _: &Selection| -> Result<LookupOutput, String> {
                    panic!("lookup bug")
                },
            ),
        );
        for _ in 0..=MAX_RUNNING {
            let record = service
                .run(&ScanRequest {
                    target: "example.com".into(),
                    ..ScanRequest::default()
                })
                .unwrap();
            assert_eq!(record.status, ScanStatus::ErrorFailed);
        }
        assert_eq!(service.state().running, 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn graph_scan_envelopes_reject_missing_or_wrongly_typed_fields() {
        assert!(lookup_input_schema().accepts(&json!({
            "kind": "email", "selector": "jane@example.org"
        })));
        assert!(!lookup_input_schema().accepts(&json!({
            "kind": 42, "selector": "jane@example.org"
        })));
        assert!(
            lookup_output_schema().accepts(&serde_json::to_value(LookupOutput::default()).unwrap())
        );
        assert!(!lookup_output_schema().accepts(&json!({
            "text": "", "entities": []
        })));
        assert!(!lookup_output_schema().accepts(&json!({
            "text": "", "entities": {}, "outcomes": []
        })));
    }

    #[test]
    fn graph_batch_admission_separates_dependent_and_independent_targets() {
        let (service, dir) = with_lookup(
            "batch-admission",
            Arc::new(|_, _, _| Ok(LookupOutput::default())),
        );
        let selection = chosen(&ScanOptions::default()).unwrap();
        let collector = ScanCollector {
            service: &service,
            id: "batch-admission",
            chosen: &selection,
            text: String::new(),
            ran: 0,
            errors: 0,
            breach_checked: BTreeSet::new(),
        };
        let email = CrawlTarget {
            kind: ScanKind::Email,
            selector: "jane@example.org".into(),
        };
        let exposure = CrawlTarget {
            kind: ScanKind::Exposure,
            selector: email.selector.clone(),
        };
        assert!(!collector.may_batch(&[email], &exposure));
        let first_ip = CrawlTarget {
            kind: ScanKind::Ip,
            selector: "1.1.1.1".into(),
        };
        let next_ip = CrawlTarget {
            kind: ScanKind::Ip,
            selector: "8.8.8.8".into(),
        };
        assert!(collector.may_batch(&[first_ip], &next_ip));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn sequential_lookup_error_persists_an_inconclusive_outcome() {
        let (service, dir) = with_lookup(
            "persist-sequential-failure",
            Arc::new(|_, _, _| Err("synthetic source outage".into())),
        );
        let record = service
            .run(&ScanRequest {
                target: "1.1.1.1".into(),
                kind: Some("ip".into()),
                ..ScanRequest::default()
            })
            .unwrap();
        assert_eq!(record.status, ScanStatus::ErrorFailed);
        assert_eq!(record.errors, 1);
        let results = service.store().results(&record.id).unwrap().unwrap();
        assert!(results.entities.is_empty());
        assert_eq!(results.outcomes.len(), 1);
        assert_eq!(results.outcomes[0].module, "scan_lookup");
        assert_eq!(results.outcomes[0].kind, SourceOutcomeKind::Inconclusive);
        assert!(results.outcomes[0].found.is_none());
        let diagnostic = results.outcomes[0].detail.as_deref().unwrap();
        assert!(diagnostic.contains("synthetic source outage"));
        assert!(
            results.outcomes[0]
                .detail
                .as_deref()
                .unwrap()
                .contains("ip lookup on 1.1.1.1")
        );
        let log = service.store().log(&record.id).unwrap();
        assert!(
            log.iter()
                .any(|entry| entry.message.contains("synthetic source outage"))
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn graph_lookup_error_persists_alongside_a_valid_zero_result() {
        let (service, dir) = with_lookup(
            "persist-graph-failure",
            Arc::new(|kind: ScanKind, selector: &str, _: &Selection| {
                if kind == ScanKind::Domain {
                    let evidence = Evidence::new(
                        EvidenceProvenance::for_scan("test", "seed"),
                        "discovered address",
                    );
                    return Ok(LookupOutput {
                        entities: ["1.1.1.1", "8.8.8.8"]
                            .into_iter()
                            .map(|ip| {
                                Entity::builder(EntityKind::IpAddress, ip, 0.95, "test")
                                    .evidence(evidence.clone())
                                    .build()
                            })
                            .collect(),
                        ..LookupOutput::default()
                    });
                }
                if selector == "1.1.1.1" {
                    return Err("synthetic provider failure".into());
                }
                Ok(LookupOutput {
                    outcomes: vec![SourceExecutionOutcome::valid_zero("fixture", 42)],
                    ..LookupOutput::default()
                })
            }),
        );
        let record = service
            .run(&ScanRequest {
                target: "example.org".into(),
                kind: Some("domain".into()),
                options: ScanOptions {
                    depth: 1,
                    ..ScanOptions::default()
                },
                ..ScanRequest::default()
            })
            .unwrap();
        assert_eq!(record.status, ScanStatus::Finished);
        assert_eq!(record.errors, 1);
        let results = service.store().results(&record.id).unwrap().unwrap();
        assert_eq!(results.outcomes.len(), 2);
        let failure = results
            .outcomes
            .iter()
            .find(|outcome| outcome.module == "graph_exec")
            .unwrap();
        assert_eq!(failure.kind, SourceOutcomeKind::Inconclusive);
        assert!(failure.found.is_none());
        assert!(failure.detail.as_deref().unwrap().contains("1.1.1.1"));
        assert!(
            failure
                .detail
                .as_deref()
                .unwrap()
                .contains("synthetic provider failure")
        );
        let zero = results
            .outcomes
            .iter()
            .find(|outcome| outcome.module == "fixture")
            .unwrap();
        assert_eq!(zero.kind, SourceOutcomeKind::ValidZero);
        assert_eq!(zero.found, Some(0));
        assert!(record.modules_run.contains(&"graph_exec".to_owned()));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn graph_schema_failure_is_not_misreported_as_empty_success() {
        let target = CrawlTarget {
            kind: ScanKind::Ip,
            selector: "1.1.1.1".into(),
        };
        let failure = failed_lookup_step(
            &target,
            "graph_exec",
            SourceOutcomeKind::SchemaDrift,
            "task lookup-0000: missing output envelope",
        );
        assert!(failure.entities.is_empty());
        assert_eq!(failure.outcomes.len(), 1);
        assert_eq!(failure.outcomes[0].kind, SourceOutcomeKind::SchemaDrift);
        assert!(failure.outcomes[0].found.is_none());
        assert!(!failure.outcomes[0].kind.is_accepted());
    }

    #[test]
    fn independent_recursive_lookups_use_bounded_graph_concurrency() {
        use std::sync::atomic::AtomicUsize;

        let active = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let (service, dir) = with_lookup(
            "graph-concurrency",
            Arc::new({
                let active = Arc::clone(&active);
                let peak = Arc::clone(&peak);
                move |kind: ScanKind, selector: &str, _: &Selection| {
                    if kind == ScanKind::Domain {
                        let evidence = Evidence::new(
                            EvidenceProvenance::for_scan("test", "seed"),
                            "discovered address",
                        );
                        return Ok(LookupOutput {
                            entities: ["1.1.1.1", "8.8.8.8"]
                                .into_iter()
                                .map(|ip| {
                                    Entity::builder(EntityKind::IpAddress, ip, 0.95, "test")
                                        .evidence(evidence.clone())
                                        .build()
                                })
                                .collect(),
                            ..LookupOutput::default()
                        });
                    }
                    let current = active.fetch_add(1, Ordering::SeqCst) + 1;
                    peak.fetch_max(current, Ordering::SeqCst);
                    thread::sleep(Duration::from_millis(100));
                    active.fetch_sub(1, Ordering::SeqCst);
                    Ok(LookupOutput {
                        text: format!("{} {selector}", kind.command()),
                        ..LookupOutput::default()
                    })
                }
            }),
        );
        let record = service
            .run(&ScanRequest {
                target: "example.org".into(),
                kind: Some("domain".into()),
                options: ScanOptions {
                    depth: 1,
                    ..ScanOptions::default()
                },
                ..ScanRequest::default()
            })
            .unwrap();
        assert_eq!(record.status, ScanStatus::Finished);
        assert_eq!(peak.load(Ordering::SeqCst), 2);
        let log = service.store().log(&record.id).unwrap();
        assert!(log.iter().any(|entry| entry.component == "graph_exec"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn graph_reducer_distinguishes_stop_from_actual_task_failure() {
        let (service, dir) = with_lookup(
            "graph-cancel-reduction",
            Arc::new(|_: ScanKind, _: &str, _: &Selection| Ok(LookupOutput::default())),
        );
        let (record, _) = service
            .create(&ScanRequest {
                target: "example.org".into(),
                ..ScanRequest::default()
            })
            .unwrap();
        let selection = chosen(&ScanOptions::default()).unwrap();
        let target = CrawlTarget {
            kind: ScanKind::Ip,
            selector: "1.1.1.1".into(),
        };
        let mut collector = ScanCollector {
            service: &service,
            id: &record.id,
            chosen: &selection,
            text: String::new(),
            ran: 0,
            errors: 0,
            breach_checked: BTreeSet::new(),
        };
        service.state().aborts.insert(record.id.clone());
        let cancelled = crate::graph_exec::TaskRecord {
            state: TaskState::Cancelled,
            error: Some("scan cancelled before dispatch".into()),
            ..crate::graph_exec::TaskRecord::default()
        };
        let stopped = collector.reduce_graph_record(&target, "lookup-0000", &cancelled);
        assert!(stopped.entities.is_empty());
        assert!(stopped.outcomes.is_empty());
        assert_eq!(collector.errors, 0);
        assert_eq!(collector.ran, 0);
        let log = service.store().log(&record.id).unwrap();
        assert!(
            log.iter()
                .any(|entry| entry.message.contains("cancelled by scan stop"))
        );

        service.state().aborts.remove(&record.id);
        let failed = crate::graph_exec::TaskRecord {
            state: TaskState::Failed,
            error: Some("synthetic execution failure".into()),
            ..crate::graph_exec::TaskRecord::default()
        };
        let outcome = collector.reduce_graph_record(&target, "lookup-0001", &failed);
        assert_eq!(collector.errors, 1);
        assert_eq!(outcome.outcomes.len(), 1);
        assert_eq!(outcome.outcomes[0].kind, SourceOutcomeKind::Inconclusive);
        assert!(
            outcome.outcomes[0]
                .detail
                .as_deref()
                .unwrap()
                .contains("synthetic execution failure")
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn concurrent_scans_share_lookup_capacity_without_disabling_graph_parallelism() {
        use std::sync::atomic::AtomicUsize;

        let active = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let calls = Arc::new(AtomicUsize::new(0));
        let (service, dir) = with_lookup(
            "shared-lookup-capacity",
            Arc::new({
                let active = Arc::clone(&active);
                let peak = Arc::clone(&peak);
                let calls = Arc::clone(&calls);
                move |kind: ScanKind, selector: &str, _: &Selection| {
                    if kind == ScanKind::Domain {
                        let evidence = Evidence::new(
                            EvidenceProvenance::for_scan("test", "seed"),
                            "discovered address",
                        );
                        return Ok(LookupOutput {
                            entities: ["1.1.1.1", "8.8.8.8"]
                                .into_iter()
                                .map(|ip| {
                                    Entity::builder(EntityKind::IpAddress, ip, 0.95, "test")
                                        .evidence(evidence.clone())
                                        .build()
                                })
                                .collect(),
                            ..LookupOutput::default()
                        });
                    }
                    let inside = active.fetch_add(1, Ordering::SeqCst) + 1;
                    peak.fetch_max(inside, Ordering::SeqCst);
                    calls.fetch_add(1, Ordering::SeqCst);
                    thread::sleep(Duration::from_millis(80));
                    active.fetch_sub(1, Ordering::SeqCst);
                    Ok(LookupOutput {
                        text: format!("completed-{selector}"),
                        ..LookupOutput::default()
                    })
                }
            }),
        );
        let request = |target: &str| ScanRequest {
            target: target.into(),
            kind: Some("domain".into()),
            options: ScanOptions {
                depth: 1,
                ..ScanOptions::default()
            },
            ..ScanRequest::default()
        };
        let first = service.start(&request("first.example.org")).unwrap();
        let second = service.start(&request("second.example.org")).unwrap();
        for id in [&first.id, &second.id] {
            let record = service
                .wait(id, Instant::now() + Duration::from_secs(15))
                .unwrap();
            assert_eq!(record.status, ScanStatus::Finished);
        }
        assert_eq!(calls.load(Ordering::SeqCst), 4);
        assert!(peak.load(Ordering::SeqCst) <= MAX_ACTIVE_LOOKUPS);
        assert_eq!(active.load(Ordering::SeqCst), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn targets_route_to_kinds_and_spiderfoot_types() {
        for (target, kind, kind_word, sf_type) in [
            ("example.com", None, "domain", "INTERNET_NAME"),
            ("1.1.1.1", None, "ip", "IP_ADDRESS"),
            ("2606:4700:4700::1111", None, "ip", "IPV6_ADDRESS"),
            ("jane@example.org", None, "email", "EMAILADDR"),
            ("+61412345678", None, "phone", "PHONE_NUMBER"),
            ("Jane Citizen", None, "people", "HUMAN_NAME"),
            (
                "jane@example.org",
                Some("exposure"),
                "exposure",
                "EMAILADDR",
            ),
            ("00:11:22:33:44:55", None, "network", "HSE_MAC_ADDRESS"),
        ] {
            let planned = plan(target, kind).unwrap_or_else(|error| panic!("{target}: {error}"));
            assert_eq!(planned.kind.command(), kind_word, "{target}");
            assert_eq!(planned.target_type, sf_type, "{target}");
        }
        assert!(plan("x".repeat(MAX_TARGET_BYTES + 1).as_str(), None).is_err());
        let _ = SourceOutcomeKind::Success;
    }
}
