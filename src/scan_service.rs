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
use std::sync::atomic::{AtomicU64, Ordering};
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
use crate::source_outcome::SourceExecutionOutcome;
use crate::termination::TerminationReason;

/// Scans that run at once; more wait as `STARTING`. A phone runs two lookups' worth of requests
/// comfortably, and each lookup already fans out to its sources.
pub const MAX_RUNNING: usize = 2;
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

struct State {
    running: usize,
    aborts: BTreeSet<String>,
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
            Some(failed) => {
                self.ran += 1;
                self.errors += failed;
            }
            None => self.errors += 1,
        }
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
                    input_schema: ValueSchema::Any,
                    output_schema: ValueSchema::Any,
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
        let mut handlers = HandlerRegistry::new();
        for (index, target) in targets.iter().enumerate() {
            let task_id = format!("lookup-{index:04}");
            let lookup = Arc::clone(&self.service.lookup);
            let chosen = self.chosen.clone();
            let kind = target.kind;
            let selector = target.selector.clone();
            handlers.insert(
                task_id,
                Arc::new(
                    move |context: TaskContext| -> Result<TaskOutput, TaskFailure> {
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
        let cancellation = Arc::new(std::sync::atomic::AtomicBool::new(false));
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
                    .map(|_| Step {
                        entities: Vec::new(),
                        outcomes: Vec::new(),
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
                    self.errors = self.errors.saturating_add(1);
                    self.service.log(
                        self.id,
                        "graph_exec",
                        LogLevel::Error,
                        format!("graph executor omitted task record {task_id}"),
                    );
                    return Step {
                        entities: Vec::new(),
                        outcomes: Vec::new(),
                    };
                };
                if record.state != TaskState::Succeeded {
                    self.errors = self.errors.saturating_add(1);
                    self.service.log(
                        self.id,
                        target.kind.command(),
                        LogLevel::Error,
                        format!(
                            "graph task {task_id} ended as {:?}: {}",
                            record.state,
                            record.error.as_deref().unwrap_or("no failure detail")
                        ),
                    );
                    return Step {
                        entities: Vec::new(),
                        outcomes: Vec::new(),
                    };
                }
                let decoded = record
                    .output
                    .as_ref()
                    .ok_or_else(|| "successful graph task has no output".to_owned())
                    .and_then(|output| {
                        serde_json::from_value::<LookupOutput>(output.value.clone())
                            .map_err(|error| format!("malformed lookup output: {error}"))
                    });
                let found = match decoded {
                    Ok(found) => found,
                    Err(error) => {
                        self.errors = self.errors.saturating_add(1);
                        self.service.log(
                            self.id,
                            "graph_exec",
                            LogLevel::Error,
                            format!("task {task_id}: {error}"),
                        );
                        return Step {
                            entities: Vec::new(),
                            outcomes: Vec::new(),
                        };
                    }
                };
                let failed_sources = found
                    .outcomes
                    .iter()
                    .filter(|outcome| !outcome.kind.is_accepted())
                    .count();
                self.ran = self.ran.saturating_add(1);
                self.errors = self.errors.saturating_add(failed_sources);
                for outcome in &found.outcomes {
                    let accepted = outcome.kind.is_accepted();
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
                if target.kind == ScanKind::Email
                    && found
                        .outcomes
                        .iter()
                        .any(|outcome| EXPOSURE_SOURCES.contains(&outcome.module.as_str()))
                {
                    if let Some(selector) = canonical_selector(ScanKind::Exposure, &target.selector)
                    {
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
            })
            .collect()
    }

    fn cancelled(&self) -> bool {
        self.service.aborted(self.id)
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
            }),
            freed: Condvar::new(),
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

    /// Start a scan on its own thread and return its `CREATED` row at once.
    ///
    /// # Errors
    /// [`ServiceError::BadRequest`] for an unusable target or option; [`ServiceError::Store`]
    /// when it cannot be saved or its thread cannot start.
    pub fn start(self: &Arc<Self>, request: &ScanRequest) -> Result<ScanRecord, ServiceError> {
        let (record, plan) = self.create(request)?;
        let service = Arc::clone(self);
        let id = record.id.clone();
        let spawned = thread::Builder::new()
            .name("scan".into())
            .stack_size(8 * 1024 * 1024)
            .spawn(move || service.execute(&id, &plan));
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
        self.execute(&record.id, &plan);
        Ok(self.store.get(&record.id)?)
    }

    fn aborted(&self, id: &str) -> bool {
        self.state().aborts.contains(id)
    }

    fn set_status(&self, id: &str, status: ScanStatus, at: Option<u64>) {
        if let Ok(mut record) = self.store.get(id) {
            // A stop asked for while starting stays visible until the worker honours it.
            if record.status == ScanStatus::AbortRequested && status == ScanStatus::Running {
                return;
            }
            record.status = status;
            match status {
                ScanStatus::Running => record.started = at,
                ScanStatus::Aborted | ScanStatus::Finished | ScanStatus::ErrorFailed => {
                    record.ended = at;
                }
                _ => {}
            }
            let _ = self.store.update(&record);
        }
    }

    /// The worker: wait for a place, run the lookups, save what they found.
    fn execute(&self, id: &str, plan: &ScanPlan) {
        self.set_status(id, ScanStatus::Starting, None);
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
        }
        self.freed.notify_all();
        if outcome.is_err() {
            self.log(
                id,
                "huntsman",
                LogLevel::Error,
                "the scan failed unexpectedly; what it saved is kept",
            );
            self.set_status(id, ScanStatus::ErrorFailed, Some(now_ms()));
        }
    }

    fn collect(&self, id: &str, plan: &ScanPlan) {
        if self.aborted(id) {
            self.log(id, "huntsman", LogLevel::Info, "stopped before it started");
            self.set_status(id, ScanStatus::Aborted, Some(now_ms()));
            return;
        }
        self.set_status(id, ScanStatus::Running, Some(now_ms()));
        let options = self
            .store
            .get(id)
            .map(|record| record.options)
            .unwrap_or_default();
        let chosen = match chosen(&options) {
            Ok(chosen) => chosen,
            Err(error) => {
                self.log(id, "huntsman", LogLevel::Error, error.to_string());
                self.set_status(id, ScanStatus::ErrorFailed, Some(now_ms()));
                return;
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
            self.set_status(id, ScanStatus::ErrorFailed, Some(now_ms()));
            return;
        }
        self.log(
            id,
            "huntsman",
            LogLevel::Info,
            format!("scan {}", status.as_str()),
        );
        self.set_status(id, status, Some(now_ms()));
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
    ) -> Option<usize> {
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
                Some(failed)
            }
            Err(message) => {
                self.log(
                    id,
                    kind.command(),
                    LogLevel::Error,
                    format!("the {} lookup gave no report: {message}", kind.command()),
                );
                None
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
        let mut record = self.store.get(id)?;
        if !record.status.is_active() {
            return Err(ServiceError::Conflict(format!(
                "scan {id} is {}, not running",
                record.status.as_str()
            )));
        }
        self.state().aborts.insert(id.to_owned());
        self.freed.notify_all();
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
