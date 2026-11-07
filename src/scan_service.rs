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
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::clock;
use crate::correlator::evaluate_rules;
use crate::entity::{Entity, merge_by_uid};
use crate::graph_exec::{
    ExecutionPolicy, GraphDefinition, GraphExecutor, HandlerRegistry, TaskContext, TaskFailure,
    TaskOutput, TaskRole, TaskSpec, TaskState, ValueSchema, VerificationRecord, VerificationState,
};
use crate::lookup_modules;
use crate::module_selection::Selection;
use crate::recursion::{
    self, CrawlProgress, PivotEdge, RecursionPolicy, RecursionReport, SelectorCollector, Step,
    Target as CrawlTarget,
};
use crate::scan_route::{
    ScanKind, canonical_selector, explicit_people_is_name, infer_kind, inferred_people_is_name,
    parse_kind,
};
use crate::scan_store::{
    FORMAT_VERSION, LogEntry, LogLevel, Risk, RiskCounts, ScanCorrelation, ScanOptions, ScanRecord,
    ScanResults, ScanStatus, ScanStore, StoreError, new_id,
};
use crate::serve_events::{Event, EventHub};
use crate::sf_compat::target_type;
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
/// The `kind` of a scan kept from `/api/inspect`: the command that read the file, not a lookup the
/// service can run again, since the file's bytes are not kept with the scan.
pub const INSPECT_KIND: &str = "inspect";

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
            if word.eq_ignore_ascii_case(INSPECT_KIND) {
                return Err(ServiceError::BadRequest(
                    "an inspected file is kept as a scan but its bytes are not; inspect the file again to read it anew".into(),
                ));
            }
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
    let named = crate::module::selection(&options.modules).map_err(ServiceError::BadRequest)?;
    Ok(crate::module::use_case_selection(&options.usecase, &named))
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
    // Volatile failures let wait/run report a row that could not be persisted.
    status_failures: BTreeMap<String, String>,
    // Separate from status errors: a successful row update cannot restore lost log entries.
    log_failures: BTreeMap<String, String>,
}

/// What following a scan's findings produced beside the findings themselves.
struct Crawl {
    lineage: Vec<PivotEdge>,
    /// Why the crawl stopped; `None` while it is still running, so a checkpoint saved mid-crawl
    /// never claims a stop reason.
    termination: Option<TerminationReason>,
}

/// The crawl's lookups: each one logged and run through the installed lookup asking only the
/// chosen modules, a stop honoured before the next, a lookup that asks none of them skipped, and
/// an email's breach lookup skipped when its email lookup already ran a breach source, so a keyed
/// breach source is never skipped and never asked twice.
struct ScanCollector<'a> {
    service: &'a ScanService,
    id: &'a str,
    plan: &'a ScanPlan,
    options: &'a ScanOptions,
    chosen: &'a Selection,
    text: String,
    ran: usize,
    errors: usize,
    breach: lookup_modules::BreachPasses,
    /// How many entities and source outcomes the last checkpoint saved, so a wave that added
    /// nothing writes nothing.
    checkpointed: (usize, usize),
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
            clock::unix_now_millis() / 1_000,
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

impl<'a> ScanCollector<'a> {
    /// A collector for scan `id` with nothing found yet.
    fn new(
        service: &'a ScanService,
        id: &'a str,
        plan: &'a ScanPlan,
        options: &'a ScanOptions,
        chosen: &'a Selection,
    ) -> Self {
        Self {
            service,
            id,
            plan,
            options,
            chosen,
            text: String::new(),
            ran: 0,
            errors: 0,
            breach: lookup_modules::BreachPasses::default(),
            checkpointed: (0, 0),
        }
    }
}

impl ScanCollector<'_> {
    /// Reduce a completed lookup identically for sequential and graph dispatch.
    /// This does not modify source error counts, which depend on how the lookup ran.
    fn finish_lookup(&mut self, target: &CrawlTarget, found: LookupOutput) -> Step {
        self.breach
            .record(target.kind, &target.selector, &found.outcomes);
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
            self.errors = self
                .errors
                .saturating_add(usize::from(is_error_outcome(outcome)));
            self.service.log(
                self.id,
                &outcome.module,
                outcome_log_level(outcome),
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
        if self.breach.covered(target.kind, &target.selector) {
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

    /// Save what the crawl has found so far. A process that dies before the crawl ends (Android
    /// stopping Termux, the phone's memory killer, a swiped-away session) then leaves a scan that
    /// shows its findings, not an empty `ABORTED` row, and the Scans list counts elements while
    /// the scan runs. A wave that added nothing is not written. A checkpoint that cannot be saved
    /// is logged and the crawl goes on: the final save decides the scan's outcome.
    fn progressed(&mut self, progress: &CrawlProgress<'_>) {
        let seen = (progress.entities.len(), progress.outcomes.len());
        if seen == self.checkpointed {
            return;
        }
        let mut entities = progress.entities.to_vec();
        merge_by_uid(&mut entities);
        let found = LookupOutput {
            text: self.text.clone(),
            entities,
            outcomes: progress.outcomes.to_vec(),
        };
        let crawl = Crawl {
            lineage: progress.edges.to_vec(),
            termination: None,
        };
        if let Err(error) = self.service.save(
            self.id,
            Target {
                value: &self.plan.target,
                kind: self.plan.target_type,
            },
            self.options,
            found,
            self.errors,
            crawl,
        ) {
            self.service.log(
                self.id,
                "huntsman",
                LogLevel::Warning,
                format!(
                    "could not save what the scan has found so far, after {} lookups in generation {}: {error}",
                    progress.dispatches, progress.generation
                ),
            );
        } else {
            // Advance only after both the result and scan row are persisted.
            // Otherwise a transient I/O error would make an identical wave
            // appear checkpointed and suppress its retry.
            self.checkpointed = seen;
        }
    }

    fn may_batch(&self, selected: &[CrawlTarget], next: &CrawlTarget) -> bool {
        let needs_sequential = |target: &CrawlTarget| {
            self.breach.covered(target.kind, &target.selector)
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
            self.breach.covered(target.kind, &target.selector)
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
        // A stop may cancel the graph record after a lookup has returned a real failure.
        let lookup_failures = Arc::new(Mutex::new(BTreeMap::new()));
        let mut handlers = HandlerRegistry::new();
        for (index, target) in targets.iter().enumerate() {
            let task_id = format!("lookup-{index:04}");
            let lookup = Arc::clone(&self.service.lookup);
            let admission = Arc::clone(&self.service.admission);
            let cancellation_for_task = Arc::clone(&cancellation);
            let lookup_failures_for_task = Arc::clone(&lookup_failures);
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
                        let output = lookup(kind, &selector, &chosen).map_err(|error| {
                            let _ = lookup_failures_for_task
                                .lock()
                                .unwrap_or_else(PoisonError::into_inner)
                                .insert(context.task_id.clone(), error.clone());
                            TaskFailure::permanent(error)
                        })?;
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
                let lookup_error = lookup_failures
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .remove(&task_id);
                if let Some(error) = lookup_error.filter(|_| record.state == TaskState::Cancelled) {
                    let mut failed = record.clone();
                    failed.state = TaskState::Failed;
                    failed.error = Some(error);
                    return self.reduce_graph_record(target, &task_id, &failed);
                }
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
    // Per-instance ownership is distinct from PID. Kept outside state so start_or_join
    // can register a scan while holding the state lock without re-locking it.
    owned_scans: Mutex<BTreeSet<String>>,
    freed: Condvar,
    admission: Arc<LookupAdmission>,
    worker_slots: Arc<AtomicUsize>,
    sequence: AtomicU64,
    /// Every committed scan-status change is published here, so `serve` can stream it to the Web
    /// UI. Always present; publishing with no subscriber is a cheap no-op.
    events: Arc<EventHub>,
}

impl ScanService {
    /// A service over `store` whose scans run Spiderfoot's shipped correlation rules beside
    /// Huntsman's own. Run [`ScanStore::recover`] before the first scan starts.
    #[must_use]
    pub fn new(store: ScanStore, lookup: ScanLookup) -> Arc<Self> {
        Self::with_rules(store, lookup, sf_correlate::shipped().to_vec(), Vec::new())
    }

    /// The hub every committed scan-status change is published to, for `serve`'s event stream.
    #[must_use]
    pub fn events(&self) -> &Arc<EventHub> {
        &self.events
    }

    /// A service whose scans run `rules` (see [`sf_correlate::with_dir`]) beside Huntsman's own.
    /// `rule_errors` are what [`sf_correlate::with_dir`] reports: a rule file that could not be
    /// read or loaded, a rules path that could not be listed, or files past its limit. Each scan
    /// logs them, so a broken rule is seen where its results would have been.
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
                status_failures: BTreeMap::new(),
                log_failures: BTreeMap::new(),
            }),
            owned_scans: Mutex::new(BTreeSet::new()),
            freed: Condvar::new(),
            admission: Arc::new(LookupAdmission::default()),
            worker_slots: Arc::new(AtomicUsize::new(0)),
            sequence: AtomicU64::new(0),
            events: Arc::new(EventHub::new()),
        })
    }

    /// The saved row for `id`, reconciled with its owner's liveness: a scan whose owning process
    /// is gone reads `ABORTED`, saved and logged so, rather than `RUNNING` for ever.
    ///
    /// # Errors
    /// [`ServiceError::NotFound`] for an unknown id; a store failure as [`ServiceError::Store`].
    pub fn record(&self, id: &str) -> Result<ScanRecord, ServiceError> {
        let mut record = self.store.get(id)?;
        self.store
            .reconcile(&mut record, clock::unix_now_millis())?;
        Ok(record)
    }

    /// Every saved row, each reconciled as [`Self::record`] does.
    ///
    /// # Errors
    /// A store failure as [`ServiceError::Store`].
    pub fn records(&self) -> Result<Vec<ScanRecord>, ServiceError> {
        let now = clock::unix_now_millis();
        let mut records = self.store.list()?;
        for record in &mut records {
            self.store.reconcile(record, now)?;
        }
        Ok(records)
    }

    pub fn store(&self) -> &ScanStore {
        &self.store
    }

    /// The Spiderfoot-format rules each scan runs.
    #[must_use]
    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }

    /// What [`sf_correlate::with_dir`] reported: a rule file that could not be read or loaded, a
    /// rules path that could not be listed, or files past its limit.
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

    fn owned(&self) -> MutexGuard<'_, BTreeSet<String>> {
        self.owned_scans
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    fn log(&self, id: &str, component: &str, level: LogLevel, message: impl Into<String>) {
        // Preserve the persistence failure for run/wait without printing from library code.
        // The worker continues; a later successful status write cannot clear missing evidence.
        if let Err(error) = self.store.append_log(
            id,
            &LogEntry {
                time: clock::unix_now_millis(),
                component: component.to_owned(),
                level,
                message: message.into(),
            },
        ) {
            self.state()
                .log_failures
                .entry(id.to_owned())
                .or_insert_with(|| format!("scan {id}: unable to persist log entry: {error}"));
            self.freed.notify_all();
        }
    }

    /// Save a `CREATED` scan for `request`.
    fn create(&self, request: &ScanRequest) -> Result<(ScanRecord, ScanPlan), ServiceError> {
        let plan = plan(&request.target, request.kind.as_deref())?;
        let options = validate_options(&request.options)?;
        if !lookup_modules::asks_any(plan.kind, &chosen(&options)?) {
            let asks = lookup_modules::modules(plan.kind).join(", ");
            let why = if options.modules.is_empty() {
                format!(
                    "the {} use case runs none of the modules the {} lookup asks ({asks}); choose \
                     all or another use case",
                    options.usecase,
                    plan.kind.command()
                )
            } else {
                format!(
                    "none of the chosen modules ({}) looks up the target: the {} lookup asks {asks}",
                    options.modules.join(", "),
                    plan.kind.command()
                )
            };
            return Err(ServiceError::BadRequest(why));
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
        let (owner, owner_started) = crate::scan_store::this_process();
        let record = ScanRecord {
            format_version: FORMAT_VERSION,
            id: new_id(
                &plan.target,
                clock::unix_now_nanos(),
                self.sequence.fetch_add(1, Ordering::Relaxed),
            ),
            name,
            target: plan.target.clone(),
            target_type: plan.target_type.to_owned(),
            kind: plan.kind.command().to_owned(),
            options,
            status: ScanStatus::Created,
            created: clock::unix_now_millis(),
            started: None,
            ended: None,
            elements: 0,
            unique: 0,
            correlations: RiskCounts::default(),
            errors: 0,
            modules_run: Vec::new(),
            owner: Some(owner),
            owner_started,
        };
        // Register before saving the CREATED row: an identical request that finds the saved row
        // joins it instead of starting a second scan, and an immediate stop can be delivered
        // even if the worker thread has not yet entered execute().
        self.owned().insert(record.id.clone());
        if let Err(error) = self.store.create(&record) {
            self.owned().remove(&record.id);
            return Err(error.into());
        }
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
                service.execute(&id, &plan);
            });
        if let Err(error) = spawned {
            self.owned().remove(&record.id);
            let mut failed = record;
            failed.status = ScanStatus::ErrorFailed;
            failed.ended = Some(clock::unix_now_millis());
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
    /// this service is still waiting to run or running: `serve`'s `/api/lookup`, so a page
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
        let state = self.state();
        let records = self.store.list()?;
        // Only a scan this service still runs, and whose last status it could save, can be
        // joined: a joiner of any other active row would wait on a worker that never comes, or
        // be handed the error of a status the row could not record.
        let running = {
            let owned = self.owned();
            records.into_iter().find(|record| {
                record.status.is_active()
                    && record.owner == me
                    && owned.contains(&record.id)
                    && !state.status_failures.contains_key(&record.id)
                    && record.target == plan.target
                    && record.kind == plan.kind.command()
                    && record.options == options
            })
        };
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
            if let Some(error) = state
                .status_failures
                .get(id)
                .or_else(|| state.log_failures.get(id))
            {
                return Err(ServiceError::Store(error.clone()));
            }
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
        self.execute(&record.id, &plan);
        let state = self.state();
        if let Some(error) = state
            .status_failures
            .get(&record.id)
            .or_else(|| state.log_failures.get(&record.id))
        {
            return Err(ServiceError::Store(error.clone()));
        }
        drop(state);
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

    fn set_status(
        &self,
        id: &str,
        status: ScanStatus,
        at: Option<u64>,
    ) -> Result<(), ServiceError> {
        self.set_status_with(id, status, at, |record| self.store.update(record))
    }

    /// A testable persistence boundary: errors remain observable even when the
    /// underlying scan row cannot store the failure itself.
    fn set_status_with(
        &self,
        id: &str,
        status: ScanStatus,
        at: Option<u64>,
        persist: impl FnOnce(&ScanRecord) -> Result<(), StoreError>,
    ) -> Result<(), ServiceError> {
        // Keep the state lock over read/modify/write so a stop cannot be overwritten.
        let mut state = self.state();
        let mut wrote_row = false;
        let mut committed: Option<ScanStatus> = None;
        let result: Result<(), StoreError> = (|| {
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
            persist(&record)?;
            wrote_row = true;
            committed = Some(status);
            Ok(())
        })();
        if let Err(error) = &result {
            state
                .status_failures
                .entry(id.to_owned())
                .or_insert_with(|| error.to_string());
            self.freed.notify_all();
        } else if wrote_row {
            // Only a committed transition can clear an earlier storage error.
            // An ignored transition (terminal row or pending abort) is not recovery.
            state.status_failures.remove(id);
        }
        // Published after the state lock is released, so a slow subscriber never holds it. The id
        // is the scan's, not a target; the status is a non-sensitive enum.
        drop(state);
        if let Some(status) = committed {
            self.events.publish(Event::Scan {
                id: id.to_owned(),
                status: status.as_str().to_owned(),
                at: clock::unix_now_millis(),
            });
        }
        result.map_err(ServiceError::from)
    }

    /// The worker: wait for a place, run the lookups, save what they found.
    fn execute(&self, id: &str, plan: &ScanPlan) {
        if self.set_status(id, ScanStatus::Starting, None).is_err() {
            self.release(id, false);
            return;
        }
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
        if outcome.is_err() {
            self.log(
                id,
                "huntsman",
                LogLevel::Error,
                "the scan failed unexpectedly; what it saved is kept",
            );
        }
        self.release(id, true);
    }

    /// The worker's last step: give up its place among the running scans when it `held_place`,
    /// then scan `id`. A row the worker leaves active, because a status could not be saved or the
    /// lookups panicked, is marked `ERROR_FAILED` before the scan is given up: no worker remains
    /// to finish it, and an active row can be neither stopped nor deleted and holds back
    /// continuous rescans of its target until the next start.
    fn release(&self, id: &str, held_place: bool) {
        if held_place {
            self.state().running -= 1;
        }
        if self
            .store
            .get(id)
            .is_ok_and(|record| record.status.is_active())
        {
            let ended =
                self.set_status(id, ScanStatus::ErrorFailed, Some(clock::unix_now_millis()));
            self.log(
                id,
                "huntsman",
                LogLevel::Error,
                if ended.is_ok() {
                    "the scan ended without recording an outcome; marked ERROR_FAILED"
                } else {
                    "the scan ended without recording an outcome and could not be marked ERROR_FAILED"
                },
            );
        }
        {
            let mut state = self.state();
            state.aborts.remove(id);
            state.graph_cancellations.remove(id);
            // Under the state lock, so a stop or a join sees the scan either still owned or ended.
            self.owned().remove(id);
        }
        self.freed.notify_all();
    }

    fn collect(&self, id: &str, plan: &ScanPlan) {
        if self.aborted(id) {
            self.log(id, "huntsman", LogLevel::Info, "stopped before it started");
            let _ = self.set_status(id, ScanStatus::Aborted, Some(clock::unix_now_millis()));
            return;
        }
        if self
            .set_status(id, ScanStatus::Running, Some(clock::unix_now_millis()))
            .is_err()
        {
            return;
        }
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
                let _ =
                    self.set_status(id, ScanStatus::ErrorFailed, Some(clock::unix_now_millis()));
                return;
            }
        };
        let chosen = match chosen(&options) {
            Ok(chosen) => chosen,
            Err(error) => {
                self.log(id, "huntsman", LogLevel::Error, error.to_string());
                let _ =
                    self.set_status(id, ScanStatus::ErrorFailed, Some(clock::unix_now_millis()));
                return;
            }
        };
        // An email's breach pass runs when the scan's modules ask a breach source, the one rule
        // every lookup's own breach legs follow: a passive scan asks none.
        let exposes = lookup_modules::asks_any(ScanKind::Exposure, &chosen);
        let mut targets = vec![CrawlTarget {
            kind: plan.kind,
            selector: plan.target.clone(),
        }];
        if plan.kind == ScanKind::Email && exposes {
            if let Some(selector) = canonical_selector(ScanKind::Exposure, &plan.target) {
                targets.push(CrawlTarget {
                    kind: ScanKind::Exposure,
                    selector,
                });
            }
        }
        let policy = RecursionPolicy {
            max_generations: options.depth,
            expose_emails: exposes,
            ..RecursionPolicy::default()
        };
        let mut collector = ScanCollector::new(self, id, plan, &options, &chosen);
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
            termination: Some(report.termination),
        };
        let saved = self.save(
            id,
            Target {
                value: &plan.target,
                kind: plan.target_type,
            },
            &options,
            found,
            errors,
            crawl,
        );
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
            let _ = self.set_status(id, ScanStatus::ErrorFailed, Some(clock::unix_now_millis()));
            return;
        }
        self.log(
            id,
            "huntsman",
            LogLevel::Info,
            format!("scan {}", status.as_str()),
        );
        let _ = self.set_status(id, status, Some(clock::unix_now_millis()));
    }

    /// How far the scan followed what it found, and why it stopped there.
    fn log_crawl(&self, id: &str, options: &ScanOptions, report: &RecursionReport) {
        let reason = report.termination.as_str();
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
                    failed += usize::from(is_error_outcome(outcome));
                    self.log(
                        id,
                        &outcome.module,
                        outcome_log_level(outcome),
                        outcome_line(outcome),
                    );
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
                    clock::unix_now_millis() / 1_000,
                    format!("{} lookup on {target}: {message}", kind.command()),
                ));
                LookupDispatch::Missing
            }
        }
    }

    /// Save `found` as scan `id`'s results and bring its row's counts up to date. With a stop
    /// reason in `crawl` this is the crawl's final save, and the correlation rules are evaluated;
    /// without one it is a checkpoint of a crawl still running, written so a killed process keeps
    /// what it had found, and correlations wait for the end so the rules run once, not once per
    /// wave.
    fn save(
        &self,
        id: &str,
        target: Target<'_>,
        options: &ScanOptions,
        found: LookupOutput,
        errors: usize,
        crawl: Crawl,
    ) -> Result<(), ServiceError> {
        let mut found = found;
        stamp_scan_id(&mut found.entities, id);
        let now = clock::unix_now_millis();
        let mut elements = sf_elements::elements_with_lineage(
            target,
            &found.entities,
            &sf_elements::lineage(&crawl.lineage),
            now / 1000,
        );
        if !options.types.is_empty() {
            let keep: BTreeSet<&str> = options.types.iter().map(String::as_str).collect();
            // A kept element keeps the chain it was found through, whatever those elements' types:
            // Spiderfoot's type filter never removes an event's source chain, and a parent dropped
            // here would leave the Source Data Element, the graph edge and the discovery path
            // dangling, with nothing to recover them from later.
            let by_id: std::collections::HashMap<&str, &sf_elements::DataElement> = elements
                .iter()
                .map(|element| (element.id.as_str(), element))
                .collect();
            let mut retained = std::collections::HashSet::new();
            for element in &elements {
                if element.kind != "ROOT"
                    && element.kind != target.kind
                    && !keep.contains(element.kind.as_str())
                {
                    continue;
                }
                let mut cursor = Some(element);
                while let Some(found) = cursor {
                    if !retained.insert(found.id.clone()) {
                        break;
                    }
                    cursor = found
                        .source
                        .as_deref()
                        .and_then(|source| by_id.get(source).copied());
                }
            }
            elements.retain(|element| retained.contains(&element.id));
        }
        let (correlations, risks) = if crawl.termination.is_some() {
            let (correlations, risks) = self.correlate_all(id, &found.entities, &elements);
            (correlations, Some(risks))
        } else {
            (Vec::new(), None)
        };
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
            termination: crawl.termination,
        })?;
        // A stop and a result-count update must not write stale copies of the same row.
        let _state = self.state();
        let mut record = self.store.get(id)?;
        record.elements = total;
        record.unique = unique;
        if let Some(risks) = risks {
            record.correlations = risks;
        }
        record.errors = errors;
        record.modules_run = modules_run;
        self.store.update(&record)?;
        Ok(())
    }

    /// Keep a report made outside the service's lookups as a `FINISHED` scan of `target`: the
    /// reading of a file uploaded to `/api/inspect`, whose bytes the server does not keep, so the
    /// scan is the one place its findings and their provenance outlive the answer. `target_type`
    /// is the target's Spiderfoot type and `kind` the command that made the report, which a re-run
    /// is refused by. The row is written `RUNNING` before the results and `FINISHED` after them,
    /// so a failure between leaves an `ERROR_FAILED` row with the reason in its log, never a scan
    /// that claims results it has not got.
    ///
    /// # Errors
    /// [`ServiceError::BadRequest`] for an empty or over-long target; [`ServiceError::Store`] when
    /// the store is full or cannot be written.
    pub fn keep(
        &self,
        target: &str,
        target_type: &str,
        kind: &str,
        found: LookupOutput,
    ) -> Result<ScanRecord, ServiceError> {
        let target = target.trim();
        if target.is_empty() {
            return Err(ServiceError::BadRequest(
                "a kept report needs a target".into(),
            ));
        }
        if target.len() > MAX_TARGET_BYTES {
            return Err(ServiceError::BadRequest(format!(
                "the target is longer than {MAX_TARGET_BYTES} bytes"
            )));
        }
        let now = clock::unix_now_millis();
        let (owner, owner_started) = crate::scan_store::this_process();
        let record = ScanRecord {
            format_version: FORMAT_VERSION,
            id: new_id(
                target,
                clock::unix_now_nanos(),
                self.sequence.fetch_add(1, Ordering::Relaxed),
            ),
            name: target.to_owned(),
            target: target.to_owned(),
            target_type: target_type.to_owned(),
            kind: kind.to_owned(),
            options: ScanOptions::default(),
            status: ScanStatus::Running,
            created: now,
            started: Some(now),
            ended: None,
            elements: 0,
            unique: 0,
            correlations: RiskCounts::default(),
            errors: 0,
            modules_run: Vec::new(),
            owner: Some(owner),
            owner_started,
        };
        self.store.create(&record)?;
        let id = record.id.clone();
        self.log(
            &id,
            "huntsman",
            LogLevel::Info,
            format!(
                "scan created: {target_type} target {target} kept from the {kind} command's report"
            ),
        );
        let errors = found
            .outcomes
            .iter()
            .filter(|outcome| is_error_outcome(outcome))
            .count();
        let (entities, outcomes) = (found.entities.len(), found.outcomes.len());
        let crawl = Crawl {
            lineage: Vec::new(),
            termination: Some(TerminationReason::FixedPoint),
        };
        let kept = self.save(
            &id,
            Target {
                value: target,
                kind: target_type,
            },
            &record.options,
            found,
            errors,
            crawl,
        );
        if let Err(error) = kept {
            self.log(
                &id,
                "huntsman",
                LogLevel::Error,
                format!("could not save the results: {error}"),
            );
            let _ = self.set_status(&id, ScanStatus::ErrorFailed, Some(clock::unix_now_millis()));
            return Err(error);
        }
        self.set_status(&id, ScanStatus::Finished, Some(clock::unix_now_millis()))?;
        self.log(
            &id,
            "huntsman",
            LogLevel::Info,
            format!("scan finished: {entities} entities and {outcomes} source outcomes kept"),
        );
        Ok(self.store.get(&id)?)
    }

    /// Ask a running or waiting scan to stop.
    ///
    /// # Errors
    /// [`ServiceError::NotFound`] for no such scan, [`ServiceError::Conflict`] when it is not
    /// running or is not owned by this service instance.
    pub fn stop(&self, id: &str) -> Result<ScanRecord, ServiceError> {
        // Hold the same lock as worker status transitions and save's row update.
        // Otherwise a stop could read RUNNING and replace a newly FINISHED row.
        let mut state = self.state();
        let mut record = self.store.get(id)?;
        // A scan whose process is gone has nothing left to signal: marking it ABORTED is the stop.
        if self
            .store
            .reconcile(&mut record, clock::unix_now_millis())?
        {
            return Ok(record);
        }
        if !record.status.is_active() {
            return Err(ServiceError::Conflict(format!(
                "scan {id} is {}, not running",
                record.status.as_str()
            )));
        }
        // Only this process can signal its workers; a row update cannot stop a foreign worker.
        if record.owner != Some(std::process::id()) {
            return Err(ServiceError::Conflict(format!(
                "scan {id} is not owned by this process; stop it in its owning process"
            )));
        }
        // Same PID is insufficient: separate ScanService instances do not share
        // an abort set, graph cancellation signals, or execution slots.
        if !self.owned().contains(id) {
            return Err(ServiceError::Conflict(format!(
                "scan {id} is not owned by this service instance; stop it through its owning service"
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
        let mut record = self.store.get(id).or_else(|error| match error {
            // A scan this service still runs keeps its directory however unreadable its row: its
            // worker still writes there, and deleting it would lose what the scan finds.
            StoreError::Io(reason) if self.owned().contains(id) => {
                Err(ServiceError::Conflict(format!(
                    "scan {id} is still running and its row cannot be read ({reason}); \
                     delete it once it ends"
                )))
            }
            // An unreadable row can still be deleted.
            StoreError::Io(_) => Ok(ScanRecord {
                status: ScanStatus::ErrorFailed,
                ..placeholder(id)
            }),
            other => Err(other.into()),
        })?;
        // A scan whose process is gone is settled first, so it can be deleted like any ended scan.
        self.store
            .reconcile(&mut record, clock::unix_now_millis())?;
        if record.status.is_active() {
            return Err(ServiceError::Conflict(format!(
                "scan {id} is {}; stop it before deleting it",
                record.status.as_str()
            )));
        }
        self.store.delete(id)?;
        let mut state = self.state();
        self.owned().remove(id);
        state.status_failures.remove(id);
        state.log_failures.remove(id);
        Ok(())
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
        owner_started: None,
    }
}

/// Whether a source outcome is an error of the scan. An answer is not, and neither is a keyed
/// source skipped for want of its key: nothing failed, and the skip is still logged in full.
fn is_error_outcome(outcome: &SourceExecutionOutcome) -> bool {
    !outcome.is_accepted() && !outcome.kind.is_not_configured()
}

/// The level one source outcome is logged at: an error only when it is an error of the scan.
fn outcome_log_level(outcome: &SourceExecutionOutcome) -> LogLevel {
    if is_error_outcome(outcome) {
        LogLevel::Error
    } else {
        LogLevel::Info
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
    if outcome.kind.is_accepted() && !outcome.is_accepted() {
        parts.insert("outcome_count_conflict", "true".to_owned());
    }
    let mut line = outcome.kind.as_str().to_owned();
    for (key, value) in parts {
        let _ = write!(line, " {key}={value}");
    }
    if let Some(detail) = &outcome.detail {
        line.push_str(": ");
        line.push_str(detail);
    }
    line
}

/// Every observation saved under scan `id` is this scan's. Each lookup front-end mints a private
/// id for the entities it builds, which names no saved scan, so a raw record read on the page or
/// in an export led nowhere. The saved scan's id replaces it on every entity, on every evidence
/// record's provenance and on every observation a merge kept, and a kept observation that then
/// differs from the record's own in nothing is dropped, as [`crate::entity::merge_by_uid`] would
/// have dropped it.
pub(crate) fn stamp_scan_id(entities: &mut [Entity], id: &str) {
    for entity in entities {
        id.clone_into(&mut entity.scan_id);
        for evidence in &mut entity.evidence {
            evidence.provenance.scan_id = Some(id.to_owned());
            let mut kept = vec![evidence.provenance.clone()];
            evidence.merged_provenance.retain_mut(|observation| {
                observation.scan_id = Some(id.to_owned());
                if kept.contains(observation) {
                    false
                } else {
                    kept.push(observation.clone());
                    true
                }
            });
        }
    }
}

#[cfg(test)]
mod tests;
