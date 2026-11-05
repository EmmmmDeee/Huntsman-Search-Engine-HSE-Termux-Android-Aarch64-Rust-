//! Evidence-gated, resource-bounded task DAG execution.
//!
//! This engine is deliberately separate from the existing lookup and scan APIs. It validates a
//! complete graph before dispatch, schedules independent ready tasks concurrently, serializes
//! state deterministically, preserves failures as first-class outcomes, and supports checkpoint
//! resume only against the exact same graph definition. Handlers receive cooperative cancellation
//! and deadline signals; Rust cannot safely pre-empt an arbitrary synchronous handler that ignores
//! them, so handlers doing blocking I/O must also use bounded transport timeouts.

use std::collections::{BTreeMap, BTreeSet};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use crate::clock;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

const MAX_ID_BYTES: usize = 128;
const MAX_TASKS: usize = 4096;
const MAX_DEPENDENCIES_PER_TASK: usize = 1024;
const MAX_RESOURCES_PER_TASK: usize = 64;
const MAX_TASK_INPUT_BYTES: usize = 1024 * 1024;
const MAX_DEPENDENCY_OUTPUT_BYTES: usize = 4 * 1024 * 1024;
const MAX_RUN_OUTPUT_BYTES: usize = 12 * 1024 * 1024;
const MAX_CONCURRENCY: usize = 4;
const MAX_OBJECTIVE_BYTES: usize = 4096;
const MAX_SCHEMA_DEPTH: usize = 64;
const MAX_CHECKPOINT_BYTES: usize = 16 * 1024 * 1024;
const MAX_RETRIES: u8 = 8;
const MAX_TIMEOUT_MS: u64 = 24 * 60 * 60 * 1000;

/// A small deterministic JSON schema subset for task boundaries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ValueSchema {
    Any,
    Null,
    Boolean,
    Number,
    String,
    Array {
        items: Box<ValueSchema>,
    },
    Object {
        #[serde(default)]
        required: BTreeMap<String, ValueSchema>,
        #[serde(default = "default_true")]
        allow_additional: bool,
    },
}

const fn default_true() -> bool {
    true
}

impl ValueSchema {
    /// Validate a JSON value against this bounded schema.
    #[must_use]
    pub fn accepts(&self, value: &Value) -> bool {
        self.accepts_at(value, 0)
    }

    fn accepts_at(&self, value: &Value, depth: usize) -> bool {
        if depth > MAX_SCHEMA_DEPTH {
            return false;
        }
        match self {
            Self::Any => true,
            Self::Null => value.is_null(),
            Self::Boolean => value.is_boolean(),
            Self::Number => value.is_number(),
            Self::String => value.is_string(),
            Self::Array { items } => value
                .as_array()
                .is_some_and(|values| values.iter().all(|item| items.accepts_at(item, depth + 1))),
            Self::Object {
                required,
                allow_additional,
            } => {
                let Some(object) = value.as_object() else {
                    return false;
                };
                if !allow_additional && object.keys().any(|key| !required.contains_key(key)) {
                    return false;
                }
                required.iter().all(|(key, schema)| {
                    object
                        .get(key)
                        .is_some_and(|item| schema.accepts_at(item, depth + 1))
                })
            }
        }
    }
}

/// Minimum spacing between starts for tasks in one rate-limit group.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RateLimit {
    pub key: String,
    pub min_interval_ms: u64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskRole {
    #[default]
    Producer,
    Verifier,
}

/// Static task definition. Function handlers are registered separately and are never serialized.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TaskSpec {
    pub id: String,
    pub objective: String,
    #[serde(default)]
    pub role: TaskRole,
    pub input: Value,
    pub input_schema: ValueSchema,
    pub output_schema: ValueSchema,
    #[serde(default)]
    pub dependencies: Vec<String>,
    #[serde(default)]
    pub exclusive_resources: Vec<String>,
    /// Optional shared start-rate limit for an external provider or resource.
    #[serde(default)]
    pub rate_limit: Option<RateLimit>,
    /// Logical-operation key. Duplicate keys in one graph are rejected.
    #[serde(default)]
    pub idempotency_key: Option<String>,
    /// Require handlers to forward the stable key to side-effecting external operations.
    #[serde(default)]
    pub requires_idempotency: bool,
    /// Cooperative per-attempt deadline.
    pub timeout_ms: u64,
    /// Number of retries after the initial attempt; capped by `MAX_RETRIES`.
    #[serde(default)]
    pub max_retries: u8,
    /// Cumulative budget units charged once for each attempted task, not each retry.
    #[serde(default = "one_unit")]
    pub resource_units: u64,
}

const fn one_unit() -> u64 {
    1
}

/// Execution graph. The task vector's input order does not affect execution order.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GraphDefinition {
    pub run_id: String,
    pub tasks: Vec<TaskSpec>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskState {
    Pending,
    Running,
    Succeeded,
    Failed,
    TimedOut,
    Cancelled,
    Blocked,
}

impl TaskState {
    const fn terminal(&self) -> bool {
        matches!(
            self,
            Self::Succeeded | Self::Failed | Self::TimedOut | Self::Cancelled | Self::Blocked
        )
    }

    const fn successful(&self) -> bool {
        matches!(self, Self::Succeeded)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationState {
    Verified,
    Hypothesis,
    Unsupported,
    Unresolved,
}

/// Explicit provenance and independent review record for a task result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationRecord {
    pub state: VerificationState,
    pub producer_id: String,
    pub reviewer_id: String,
    pub basis: String,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
}

/// Evidence locator retained with its source and capture provenance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceReference {
    pub id: String,
    pub source_id: String,
    pub locator: String,
    pub provenance: String,
    pub observed_at_unix: u64,
    #[serde(default)]
    pub content_sha256: Option<String>,
}

/// A successful result. JSON null and empty containers are valid successful values.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TaskOutput {
    pub value: Value,
    #[serde(default)]
    pub evidence: Vec<EvidenceReference>,
    pub verification: VerificationRecord,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskFailure {
    pub message: String,
    pub retryable: bool,
}

impl TaskFailure {
    #[must_use]
    pub fn permanent(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            retryable: false,
        }
    }

    #[must_use]
    pub fn transient(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            retryable: true,
        }
    }
}

/// Read-only task inputs plus cooperative deadline/cancellation checks.
#[derive(Clone)]
pub struct TaskContext {
    pub task_id: String,
    pub input: Value,
    pub dependency_outputs: BTreeMap<String, TaskOutput>,
    pub attempt: u8,
    /// Stable key handlers should forward to idempotent external operations.
    pub idempotency_key: Option<String>,
    deadline: Instant,
    cancelled: Arc<AtomicBool>,
}

impl TaskContext {
    /// Check cancellation and deadline before starting expensive or blocking work.
    pub fn check_deadline(&self) -> Result<(), TaskFailure> {
        if self.cancelled.load(Ordering::Acquire) {
            return Err(TaskFailure::permanent("run cancelled"));
        }
        if Instant::now() >= self.deadline {
            return Err(TaskFailure::permanent("task deadline exceeded"));
        }
        Ok(())
    }

    #[must_use]
    pub fn remaining(&self) -> Duration {
        self.deadline.saturating_duration_since(Instant::now())
    }
}

pub type TaskHandler =
    Arc<dyn Fn(TaskContext) -> Result<TaskOutput, TaskFailure> + Send + Sync + 'static>;
pub type HandlerRegistry = BTreeMap<String, TaskHandler>;
/// Callback used to persist a validated checkpoint after each completed wave.
pub type CheckpointSink<'sink> = dyn Fn(&ExecutionCheckpoint) -> Result<(), String> + 'sink;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionPolicy {
    pub max_concurrency: usize,
    pub max_total_resource_units: u64,
    pub max_output_bytes: usize,
    pub run_timeout_ms: u64,
}

impl Default for ExecutionPolicy {
    fn default() -> Self {
        Self {
            max_concurrency: 2,
            max_total_resource_units: 512,
            max_output_bytes: 2 * 1024 * 1024,
            run_timeout_ms: 15 * 60 * 1000,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunTermination {
    Completed,
    Failed,
    Cancelled,
    TimedOut,
    ResourceLimit,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TaskRecord {
    pub state: TaskState,
    pub attempts: u8,
    pub started_at_unix: Option<u64>,
    pub finished_at_unix: Option<u64>,
    pub duration_ms: Option<u64>,
    pub output: Option<TaskOutput>,
    pub error: Option<String>,
    /// Whether the last failure was explicitly declared retryable by its handler.
    #[serde(default)]
    pub retryable: bool,
}

impl Default for TaskRecord {
    fn default() -> Self {
        Self {
            state: TaskState::Pending,
            attempts: 0,
            started_at_unix: None,
            finished_at_unix: None,
            duration_ms: None,
            output: None,
            error: None,
            retryable: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RunReport {
    pub run_id: String,
    pub graph_fingerprint: String,
    pub policy_fingerprint: String,
    pub started_at_unix: u64,
    pub finished_at_unix: Option<u64>,
    pub duration_ms: Option<u64>,
    pub termination: Option<RunTermination>,
    pub consumed_resource_units: u64,
    /// Last provider starts in UTC milliseconds, persisted across interrupted runs.
    /// Missing in older checkpoints; recovered conservatively from completed task timestamps.
    #[serde(default)]
    pub rate_limit_last_start_unix_ms: BTreeMap<String, u64>,
    pub tasks: BTreeMap<String, TaskRecord>,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunSummary {
    pub total_tasks: usize,
    pub succeeded: usize,
    pub failed: usize,
    pub timed_out: usize,
    pub cancelled: usize,
    pub blocked: usize,
    pub pending_or_running: usize,
    pub retry_attempts: usize,
    pub evidence_references: usize,
    pub verified_results: usize,
    pub wall_clock_ms: Option<u64>,
    pub consumed_resource_units: u64,
}

impl RunReport {
    /// Derive deterministic accounting from the persisted task records.
    #[must_use]
    pub fn summary(&self) -> RunSummary {
        let mut summary = RunSummary {
            total_tasks: self.tasks.len(),
            wall_clock_ms: self.duration_ms,
            consumed_resource_units: self.consumed_resource_units,
            ..RunSummary::default()
        };
        for record in self.tasks.values() {
            match &record.state {
                TaskState::Succeeded => summary.succeeded += 1,
                TaskState::Failed => summary.failed += 1,
                TaskState::TimedOut => summary.timed_out += 1,
                TaskState::Cancelled => summary.cancelled += 1,
                TaskState::Blocked => summary.blocked += 1,
                TaskState::Pending | TaskState::Running => summary.pending_or_running += 1,
            }
            summary.retry_attempts += usize::from(record.attempts.saturating_sub(1));
            if let Some(output) = &record.output {
                summary.evidence_references += output.evidence.len();
                if output.verification.state == VerificationState::Verified {
                    summary.verified_results += 1;
                }
            }
        }
        summary
    }
}

/// Compare a measured sequential baseline with one graph-execution report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionComparison {
    pub sequential_wall_clock_ms: u64,
    pub graph_wall_clock_ms: u64,
    /// Speedup ratio multiplied by 1,000; 1,000 means equal duration, 2,000 means 2x.
    pub speedup_ratio_milli: Option<u64>,
    pub task_count: usize,
    pub graph_summary: RunSummary,
}

impl ExecutionComparison {
    /// Build a comparison from an externally measured sequential duration and graph report.
    #[must_use]
    pub fn from_measured_sequential_baseline(
        sequential_wall_clock_ms: u64,
        graph_report: &RunReport,
    ) -> Self {
        let graph_wall_clock_ms = graph_report.duration_ms.unwrap_or_default();
        Self {
            sequential_wall_clock_ms,
            graph_wall_clock_ms,
            speedup_ratio_milli: (graph_wall_clock_ms > 0)
                .then(|| sequential_wall_clock_ms.saturating_mul(1_000) / graph_wall_clock_ms),
            task_count: graph_report.tasks.len(),
            graph_summary: graph_report.summary(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExecutionCheckpoint {
    pub format_version: u32,
    pub graph_fingerprint: String,
    pub report: RunReport,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum GraphError {
    #[error("invalid graph: {0}")]
    Invalid(String),
    #[error("handler is missing for task {0}")]
    MissingHandler(String),
    #[error("checkpoint does not match graph or run id")]
    CheckpointMismatch,
    #[error("checkpoint is malformed or exceeds the size limit: {0}")]
    Checkpoint(String),
}

/// Validated graph and deterministic topological order.
#[derive(Debug, Clone)]
pub struct ValidatedGraph {
    pub topological_order: Vec<String>,
    by_id: BTreeMap<String, TaskSpec>,
    fingerprint: String,
    // Accept checkpoints emitted before graph task order was canonicalized.
    legacy_fingerprint: String,
}

impl GraphDefinition {
    /// Validate every task contract, dependency, idempotency key and cycle before dispatch.
    #[allow(clippy::too_many_lines)]
    pub fn validate(&self) -> Result<ValidatedGraph, GraphError> {
        if !valid_token(&self.run_id) {
            return Err(GraphError::Invalid("run_id is empty or invalid".into()));
        }
        if self.tasks.is_empty() {
            return Err(GraphError::Invalid("graph contains no tasks".into()));
        }
        if self.tasks.len() > MAX_TASKS {
            return Err(GraphError::Invalid("graph exceeds task limit".into()));
        }
        let mut by_id = BTreeMap::new();
        let mut idempotency = BTreeSet::new();
        let mut rate_limits = BTreeMap::<String, u64>::new();
        let mut total_task_bytes = 0_usize;
        for task in &self.tasks {
            if !valid_token(&task.id) {
                return Err(GraphError::Invalid(format!("invalid task id: {}", task.id)));
            }
            if task.role == TaskRole::Verifier && task.dependencies.is_empty() {
                return Err(GraphError::Invalid(format!(
                    "verifier task {} must depend on the claim-producing task",
                    task.id
                )));
            }
            if task.objective.trim().is_empty() || task.objective.len() > MAX_OBJECTIVE_BYTES {
                return Err(GraphError::Invalid(format!(
                    "invalid objective for {}",
                    task.id
                )));
            }
            if task.timeout_ms == 0 || task.timeout_ms > MAX_TIMEOUT_MS {
                return Err(GraphError::Invalid(format!(
                    "invalid timeout for {}",
                    task.id
                )));
            }
            if task.max_retries > MAX_RETRIES {
                return Err(GraphError::Invalid(format!(
                    "retry limit exceeded for {}",
                    task.id
                )));
            }
            if task.resource_units == 0 {
                return Err(GraphError::Invalid(format!(
                    "zero resource cost for {}",
                    task.id
                )));
            }
            let input_bytes = serde_json::to_vec(&task.input).map_err(|error| {
                GraphError::Invalid(format!("cannot encode input for {}: {error}", task.id))
            })?;
            if input_bytes.len() > MAX_TASK_INPUT_BYTES {
                return Err(GraphError::Invalid(format!(
                    "input exceeds size limit for {}",
                    task.id
                )));
            }
            if task.dependencies.len() > MAX_DEPENDENCIES_PER_TASK
                || task.exclusive_resources.len() > MAX_RESOURCES_PER_TASK
            {
                return Err(GraphError::Invalid(format!(
                    "dependency or resource limit exceeded for {}",
                    task.id
                )));
            }
            if !task.input_schema.accepts(&task.input) {
                return Err(GraphError::Invalid(format!(
                    "input schema mismatch for {}",
                    task.id
                )));
            }
            let mut deps = BTreeSet::new();
            for dependency in &task.dependencies {
                if !valid_token(dependency) {
                    return Err(GraphError::Invalid(format!(
                        "invalid dependency identifier on {}",
                        task.id
                    )));
                }
                if dependency == &task.id {
                    return Err(GraphError::Invalid(format!("self dependency: {}", task.id)));
                }
                if !deps.insert(dependency) {
                    return Err(GraphError::Invalid(format!(
                        "duplicate dependency {dependency} on {}",
                        task.id
                    )));
                }
            }
            if let Some(limit) = &task.rate_limit {
                if !valid_token(&limit.key)
                    || limit.min_interval_ms == 0
                    || limit.min_interval_ms > MAX_TIMEOUT_MS
                {
                    return Err(GraphError::Invalid(format!(
                        "invalid rate limit for {}",
                        task.id
                    )));
                }
                if rate_limits
                    .insert(limit.key.clone(), limit.min_interval_ms)
                    .is_some_and(|existing| existing != limit.min_interval_ms)
                {
                    return Err(GraphError::Invalid(format!(
                        "inconsistent interval for rate-limit group {}",
                        limit.key
                    )));
                }
            }
            let mut resources = BTreeSet::new();
            for resource in &task.exclusive_resources {
                if !valid_token(resource) || !resources.insert(resource) {
                    return Err(GraphError::Invalid(format!(
                        "invalid or duplicate resource on {}",
                        task.id
                    )));
                }
            }
            if task.requires_idempotency && task.idempotency_key.is_none() {
                return Err(GraphError::Invalid(format!(
                    "task {} requires an idempotency key",
                    task.id
                )));
            }
            if let Some(key) = &task.idempotency_key {
                if !valid_token(key) || !idempotency.insert(key.clone()) {
                    return Err(GraphError::Invalid(format!(
                        "invalid or duplicate idempotency key on {}",
                        task.id
                    )));
                }
            }
            let task_bytes = serde_json::to_vec(task).map_err(|error| {
                GraphError::Invalid(format!("cannot encode task {}: {error}", task.id))
            })?;
            total_task_bytes = total_task_bytes.saturating_add(task_bytes.len());
            if total_task_bytes > MAX_CHECKPOINT_BYTES {
                return Err(GraphError::Invalid(
                    "graph exceeds serialized size limit".into(),
                ));
            }
            if by_id.insert(task.id.clone(), task.clone()).is_some() {
                return Err(GraphError::Invalid(format!(
                    "duplicate task id: {}",
                    task.id
                )));
            }
        }
        for task in &self.tasks {
            for dependency in &task.dependencies {
                if !by_id.contains_key(dependency) {
                    return Err(GraphError::Invalid(format!(
                        "task {} depends on missing task {}",
                        task.id, dependency
                    )));
                }
            }
        }

        let mut indegree: BTreeMap<String, usize> = by_id
            .iter()
            .map(|(id, task)| (id.clone(), task.dependencies.len()))
            .collect();
        let mut dependents: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for task in by_id.values() {
            for dependency in &task.dependencies {
                dependents
                    .entry(dependency.clone())
                    .or_default()
                    .push(task.id.clone());
            }
        }
        for values in dependents.values_mut() {
            values.sort();
        }
        let mut ready: BTreeSet<String> = indegree
            .iter()
            .filter(|(_, degree)| **degree == 0)
            .map(|(id, _)| id.clone())
            .collect();
        let mut order = Vec::with_capacity(by_id.len());
        while let Some(id) = ready.pop_first() {
            order.push(id.clone());
            if let Some(children) = dependents.get(&id) {
                for child in children {
                    let degree = indegree.get_mut(child).ok_or_else(|| {
                        GraphError::Invalid("internal indegree inconsistency".into())
                    })?;
                    *degree -= 1;
                    if *degree == 0 {
                        ready.insert(child.clone());
                    }
                }
            }
        }
        if order.len() != by_id.len() {
            return Err(GraphError::Invalid("dependency cycle detected".into()));
        }
        let legacy_encoded = serde_json::to_vec(self)
            .map_err(|error| GraphError::Invalid(format!("cannot fingerprint graph: {error}")))?;
        if legacy_encoded.len() > MAX_CHECKPOINT_BYTES {
            return Err(GraphError::Invalid(
                "graph definition exceeds size limit".into(),
            ));
        }
        let legacy_fingerprint = crate::sha256::hex32(&crate::sha256::sha256(&legacy_encoded));
        // Task declaration order is not part of the graph's execution semantics.
        // Canonicalize for stable fingerprints and order-independent checkpoint resume.
        let canonical = GraphDefinition {
            run_id: self.run_id.clone(),
            tasks: by_id.values().cloned().collect(),
        };
        let encoded = serde_json::to_vec(&canonical)
            .map_err(|error| GraphError::Invalid(format!("cannot fingerprint graph: {error}")))?;
        if encoded.len() > MAX_CHECKPOINT_BYTES {
            return Err(GraphError::Invalid(
                "canonical graph exceeds size limit".into(),
            ));
        }
        let fingerprint = crate::sha256::hex32(&crate::sha256::sha256(&encoded));
        Ok(ValidatedGraph {
            topological_order: order,
            by_id,
            fingerprint,
            legacy_fingerprint,
        })
    }
}

/// Wait for admission without losing responsiveness to cancellation or the run deadline.
/// Bounded sleep slices avoid a full provider interval of cancellation latency.
fn wait_until_or_cancel(until: Instant, cancelled: &AtomicBool, deadline: Instant) {
    loop {
        if cancelled.load(Ordering::Acquire) {
            break;
        }
        let now = Instant::now();
        let remaining = until
            .saturating_duration_since(now)
            .min(deadline.saturating_duration_since(now));
        if remaining.is_zero() {
            break;
        }
        thread::sleep(remaining.min(Duration::from_millis(25)));
    }
}

fn valid_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_ID_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':'))
}

fn derive_termination(records: &BTreeMap<String, TaskRecord>) -> RunTermination {
    if records
        .values()
        .any(|record| record.state == TaskState::TimedOut)
    {
        RunTermination::TimedOut
    } else if records
        .values()
        .any(|record| record.state == TaskState::Cancelled)
    {
        RunTermination::Cancelled
    } else if records
        .values()
        .any(|record| matches!(&record.state, TaskState::Failed | TaskState::Blocked))
    {
        RunTermination::Failed
    } else {
        RunTermination::Completed
    }
}

/// Approximate an actual monotonic attempt start on the wall clock for durable checkpoints.
/// The in-process scheduler continues to use monotonic Instants for precise spacing.
fn attempt_start_unix_ms(started: Instant) -> u64 {
    let age = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    clock::unix_now_millis().saturating_sub(age)
}

/// The scheduler uses monotonic time; checkpoints retain portable wall-clock timestamps.
#[derive(Default)]
struct RateStartHistory {
    monotonic: BTreeMap<String, Instant>,
    persisted: BTreeMap<String, u64>,
}

/// Rehydrate provider spacing from a checkpoint. Legacy checkpoints lack millisecond-level
/// starts; their task completion time is a conservative lower bound for the next safe start.
fn restored_rate_history(
    graph: &ValidatedGraph,
    checkpoint: Option<&ExecutionCheckpoint>,
) -> Result<RateStartHistory, GraphError> {
    let Some(checkpoint) = checkpoint else {
        return Ok(RateStartHistory::default());
    };
    let intervals: BTreeMap<String, u64> = graph
        .by_id
        .values()
        .filter_map(|spec| spec.rate_limit.as_ref())
        .map(|limit| (limit.key.clone(), limit.min_interval_ms))
        .collect();
    let mut persisted = checkpoint.report.rate_limit_last_start_unix_ms.clone();
    if persisted
        .iter()
        .any(|(key, start)| !intervals.contains_key(key) || *start == 0)
    {
        return Err(GraphError::CheckpointMismatch);
    }
    let now = clock::unix_now_millis();
    let explicitly_persisted: BTreeSet<String> = persisted.keys().cloned().collect();
    for (id, spec) in &graph.by_id {
        let Some(limit) = &spec.rate_limit else {
            continue;
        };
        let Some(record) = checkpoint.report.tasks.get(id) else {
            continue;
        };
        // Version-one checkpoints emitted before the timestamp field existed still resume.
        // Use the finish time (rounded up to the next second) instead of a potentially stale
        // first-attempt start, since the handler may have retried the same provider.
        if record.attempts > 0 && !explicitly_persisted.contains(&limit.key) {
            let completed_ms = record.finished_at_unix.map_or(now, |seconds| {
                seconds.saturating_mul(1_000).saturating_add(999)
            });
            persisted
                .entry(limit.key.clone())
                .and_modify(|previous| *previous = (*previous).max(completed_ms))
                .or_insert(completed_ms);
        }
    }
    let instant_now = Instant::now();
    let monotonic = persisted
        .iter()
        .filter_map(|(key, start)| {
            let elapsed_ms = now.saturating_sub(*start);
            let interval = intervals[key];
            (elapsed_ms < interval).then(|| {
                let restored = instant_now
                    .checked_sub(Duration::from_millis(elapsed_ms))
                    .unwrap_or(instant_now);
                (key.clone(), restored)
            })
        })
        .collect();
    Ok(RateStartHistory {
        monotonic,
        persisted,
    })
}

fn validate_output(spec: &TaskSpec, output: &TaskOutput, max_bytes: usize) -> Result<(), String> {
    if !spec.output_schema.accepts(&output.value) {
        return Err(format!("output schema mismatch for {}", spec.id));
    }
    let encoded = serde_json::to_vec(output)
        .map_err(|error| format!("output serialization failed: {error}"))?;
    if encoded.len() > max_bytes {
        return Err(format!(
            "output for {} exceeds {} bytes",
            spec.id, max_bytes
        ));
    }
    let mut evidence_ids = BTreeSet::new();
    for evidence in &output.evidence {
        if !valid_token(&evidence.id)
            || evidence.source_id.trim().is_empty()
            || evidence.locator.trim().is_empty()
            || evidence.provenance.trim().is_empty()
            || !evidence_ids.insert(evidence.id.clone())
        {
            return Err(format!(
                "invalid or duplicate evidence reference for {}",
                spec.id
            ));
        }
        if let Some(hash) = &evidence.content_sha256 {
            if hash.len() != 64 || !hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                return Err(format!("invalid evidence hash for {}", spec.id));
            }
        }
    }
    let verification = &output.verification;
    if verification.producer_id.trim().is_empty()
        || verification.reviewer_id.trim().is_empty()
        || verification.basis.trim().is_empty()
    {
        return Err(format!("missing verification provenance for {}", spec.id));
    }
    if verification
        .evidence_refs
        .iter()
        .any(|reference| !evidence_ids.contains(reference))
    {
        return Err(format!(
            "verification references unknown evidence for {}",
            spec.id
        ));
    }
    if verification.state == VerificationState::Verified {
        if spec.role != TaskRole::Verifier
            || verification.reviewer_id != spec.id
            || verification.producer_id == verification.reviewer_id
            || !spec.dependencies.contains(&verification.producer_id)
        {
            return Err(format!(
                "verified result lacks a separate dependent verifier task for {}",
                spec.id
            ));
        }
        if verification.evidence_refs.is_empty() {
            return Err(format!(
                "verified result lacks linked evidence for {}",
                spec.id
            ));
        }
    }
    if verification
        .evidence_refs
        .iter()
        .collect::<BTreeSet<_>>()
        .len()
        != verification.evidence_refs.len()
    {
        return Err(format!(
            "duplicate verification evidence reference for {}",
            spec.id
        ));
    }
    Ok(())
}

/// A verifier must cite at least one exact evidence record from the claimed producer.
/// Independent new evidence may accompany it, but cannot replace traceability to the
/// producer's underlying observation. This tests lineage, not the truth of a claim.
fn validate_verification_lineage(
    spec: &TaskSpec,
    output: &TaskOutput,
    producer: Option<&TaskOutput>,
) -> Result<(), String> {
    if output.verification.state != VerificationState::Verified {
        return Ok(());
    }
    let original = producer.ok_or_else(|| format!("missing producer evidence for {}", spec.id))?;
    let matches_producer = output.evidence.iter().any(|reference| {
        output.verification.evidence_refs.contains(&reference.id)
            && original.evidence.contains(reference)
    });
    if !matches_producer {
        return Err(format!(
            "verified task {} lacks matching producer evidence",
            spec.id
        ));
    }
    Ok(())
}

fn validate_output_and_lineage(
    spec: &TaskSpec,
    output: &TaskOutput,
    max_bytes: usize,
    producer: Option<&TaskOutput>,
) -> Result<(), String> {
    validate_output(spec, output, max_bytes)?;
    validate_verification_lineage(spec, output, producer)
}

type CompletedJob = (String, (TaskRecord, Option<Instant>));

#[allow(clippy::too_many_lines)]
fn run_one(
    spec: &TaskSpec,
    handler: &TaskHandler,
    dependency_outputs: &BTreeMap<String, TaskOutput>,
    prior_attempts: u8,
    cancelled: &Arc<AtomicBool>,
    run_deadline: Instant,
    max_output_bytes: usize,
) -> (TaskRecord, Option<Instant>) {
    let start = Instant::now();
    let started_at_unix = clock::unix_now();
    let mut record = TaskRecord {
        state: TaskState::Running,
        started_at_unix: Some(started_at_unix),
        ..TaskRecord::default()
    };
    let max_attempts = spec.max_retries.saturating_add(1);
    let mut last_error = "task did not execute".to_string();
    let mut last_attempt_start: Option<Instant> = None;
    loop {
        if cancelled.load(Ordering::Acquire) {
            record.state = TaskState::Cancelled;
            last_error = "run cancelled".into();
            break;
        }
        if Instant::now() >= run_deadline {
            record.state = TaskState::TimedOut;
            last_error = "run deadline exceeded".into();
            break;
        }
        if prior_attempts.saturating_add(record.attempts) >= max_attempts {
            record.state = TaskState::Failed;
            break;
        }
        // Every invocation (including retries) counts as a provider start. Rate-limit
        // the next attempt from the actual preceding attempt, not the initial wave dispatch.
        if let (Some(limit), Some(previous_start)) = (&spec.rate_limit, last_attempt_start) {
            let eligible_at = previous_start + Duration::from_millis(limit.min_interval_ms);
            wait_until_or_cancel(eligible_at, cancelled, run_deadline);
        }
        // Cancellation or the run deadline may have occurred during rate-limit sleep.
        if cancelled.load(Ordering::Acquire) {
            record.state = TaskState::Cancelled;
            last_error = "run cancelled before retry".into();
            break;
        }
        if Instant::now() >= run_deadline {
            record.state = TaskState::TimedOut;
            last_error = "run deadline exceeded before retry".into();
            break;
        }
        record.attempts = record.attempts.saturating_add(1);
        let attempt = prior_attempts.saturating_add(record.attempts);
        let attempt_started = Instant::now();
        last_attempt_start = Some(attempt_started);
        let deadline = (attempt_started + Duration::from_millis(spec.timeout_ms)).min(run_deadline);
        let context = TaskContext {
            task_id: spec.id.clone(),
            input: spec.input.clone(),
            dependency_outputs: dependency_outputs.clone(),
            attempt,
            idempotency_key: spec.idempotency_key.clone(),
            deadline,
            cancelled: Arc::clone(cancelled),
        };
        // Retry permission belongs to this invocation, not an earlier transient failure.
        record.retryable = false;
        let result = catch_unwind(AssertUnwindSafe(|| handler(context)));
        let elapsed = attempt_started.elapsed();
        // A scan stop forbids further work but must not discard a successful lookup that
        // was already running. Preserve its validated output, including its evidence.
        if cancelled.load(Ordering::Acquire) && !matches!(&result, Ok(Ok(_))) {
            record.state = TaskState::Cancelled;
            last_error = "run cancelled while task was executing".into();
            break;
        }
        if Instant::now() > deadline {
            record.state = TaskState::TimedOut;
            last_error = format!("task {} exceeded its deadline", spec.id);
            break;
        }
        match result {
            Ok(Ok(output)) => match validate_output_and_lineage(
                spec,
                &output,
                max_output_bytes,
                dependency_outputs.get(&output.verification.producer_id),
            ) {
                Ok(()) => {
                    record.state = TaskState::Succeeded;
                    record.output = Some(output);
                    record.error = None;
                    record.retryable = false;
                    break;
                }
                Err(error) => {
                    record.state = TaskState::Failed;
                    last_error = error;
                    break;
                }
            },
            Ok(Err(error)) => {
                last_error = error.message;
                record.retryable = error.retryable;
                if !error.retryable
                    || prior_attempts.saturating_add(record.attempts) >= max_attempts
                {
                    record.state = TaskState::Failed;
                    break;
                }
            }
            Err(_) => {
                last_error = format!("task {} panicked", spec.id);
                record.state = TaskState::Failed;
                break;
            }
        }
        let backoff_ms = 10_u64.saturating_mul(1_u64 << u32::from(record.attempts.min(10)));
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            record.state = TaskState::TimedOut;
            last_error = format!("task {} deadline exceeded before retry", spec.id);
            break;
        }
        let retry_wait = Duration::from_millis(backoff_ms).min(remaining);
        wait_until_or_cancel(Instant::now() + retry_wait, cancelled, deadline);
        if elapsed >= Duration::from_millis(spec.timeout_ms) {
            record.state = TaskState::TimedOut;
            last_error = format!("task {} exceeded its deadline", spec.id);
            break;
        }
    }
    record.finished_at_unix = Some(clock::unix_now());
    record.duration_ms = Some(u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX));
    if !record.state.successful() {
        record.error = Some(last_error);
    }
    (record, last_attempt_start)
}

impl ExecutionCheckpoint {
    #[must_use]
    pub fn from_report(report: RunReport) -> Self {
        Self {
            format_version: 1,
            graph_fingerprint: report.graph_fingerprint.clone(),
            report,
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>, GraphError> {
        let bytes =
            serde_json::to_vec(self).map_err(|error| GraphError::Checkpoint(error.to_string()))?;
        if bytes.len() > MAX_CHECKPOINT_BYTES {
            return Err(GraphError::Checkpoint(
                "checkpoint exceeds size limit".into(),
            ));
        }
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, GraphError> {
        if bytes.len() > MAX_CHECKPOINT_BYTES {
            return Err(GraphError::Checkpoint(
                "checkpoint exceeds size limit".into(),
            ));
        }
        let checkpoint: Self = serde_json::from_slice(bytes)
            .map_err(|error| GraphError::Checkpoint(error.to_string()))?;
        if checkpoint.format_version != 1 {
            return Err(GraphError::Checkpoint(
                "unsupported checkpoint version".into(),
            ));
        }
        if checkpoint.graph_fingerprint != checkpoint.report.graph_fingerprint {
            return Err(GraphError::Checkpoint("fingerprint mismatch".into()));
        }
        Ok(checkpoint)
    }
}

/// Executes validated task graphs with deterministic result reduction.
pub struct GraphExecutor {
    pub policy: ExecutionPolicy,
}

impl GraphExecutor {
    #[must_use]
    pub const fn new(policy: ExecutionPolicy) -> Self {
        Self { policy }
    }

    pub fn execute(
        &self,
        definition: &GraphDefinition,
        handlers: &HandlerRegistry,
        cancelled: &Arc<AtomicBool>,
    ) -> Result<RunReport, GraphError> {
        self.execute_inner(definition, handlers, cancelled, None, None)
    }

    pub fn resume(
        &self,
        definition: &GraphDefinition,
        handlers: &HandlerRegistry,
        cancelled: &Arc<AtomicBool>,
        checkpoint: ExecutionCheckpoint,
    ) -> Result<RunReport, GraphError> {
        self.execute_inner(definition, handlers, cancelled, Some(checkpoint), None)
    }

    /// Execute and checkpoint after each completed scheduling wave.
    ///
    /// The sink should atomically persist the encoded checkpoint. A sink failure stops further
    /// dispatch so the engine does not knowingly continue without its requested recovery record.
    pub fn execute_checkpointed<F>(
        &self,
        definition: &GraphDefinition,
        handlers: &HandlerRegistry,
        cancelled: &Arc<AtomicBool>,
        checkpoint_sink: F,
    ) -> Result<RunReport, GraphError>
    where
        F: Fn(&ExecutionCheckpoint) -> Result<(), String>,
    {
        self.execute_inner(
            definition,
            handlers,
            cancelled,
            None,
            Some(&checkpoint_sink),
        )
    }

    /// Resume from a validated checkpoint and continue checkpointing after each completed wave.
    pub fn resume_checkpointed<F>(
        &self,
        definition: &GraphDefinition,
        handlers: &HandlerRegistry,
        cancelled: &Arc<AtomicBool>,
        checkpoint: ExecutionCheckpoint,
        checkpoint_sink: F,
    ) -> Result<RunReport, GraphError>
    where
        F: Fn(&ExecutionCheckpoint) -> Result<(), String>,
    {
        self.execute_inner(
            definition,
            handlers,
            cancelled,
            Some(checkpoint),
            Some(&checkpoint_sink),
        )
    }

    #[allow(clippy::too_many_lines)]
    fn execute_inner(
        &self,
        definition: &GraphDefinition,
        handlers: &HandlerRegistry,
        cancelled: &Arc<AtomicBool>,
        checkpoint: Option<ExecutionCheckpoint>,
        checkpoint_sink: Option<&CheckpointSink<'_>>,
    ) -> Result<RunReport, GraphError> {
        if self.policy.max_concurrency == 0
            || self.policy.max_concurrency > MAX_CONCURRENCY
            || self.policy.max_total_resource_units == 0
            || self.policy.max_output_bytes == 0
            || self.policy.max_output_bytes > MAX_RUN_OUTPUT_BYTES
            || self.policy.run_timeout_ms == 0
            || self.policy.run_timeout_ms > MAX_TIMEOUT_MS
        {
            return Err(GraphError::Invalid("invalid execution policy".into()));
        }
        let graph = definition.validate()?;
        let policy_bytes = serde_json::to_vec(&self.policy)
            .map_err(|error| GraphError::Invalid(format!("cannot fingerprint policy: {error}")))?;
        let policy_fingerprint = crate::sha256::hex32(&crate::sha256::sha256(&policy_bytes));
        if let Some(checkpoint) = &checkpoint {
            if checkpoint.format_version != 1
                || ![
                    graph.fingerprint.as_str(),
                    graph.legacy_fingerprint.as_str(),
                ]
                .contains(&checkpoint.graph_fingerprint.as_str())
                || checkpoint.report.graph_fingerprint != checkpoint.graph_fingerprint
                || checkpoint.report.policy_fingerprint != policy_fingerprint
                || checkpoint.report.consumed_resource_units > self.policy.max_total_resource_units
                || checkpoint.report.run_id != definition.run_id
            {
                return Err(GraphError::CheckpointMismatch);
            }
            let mut minimum_consumed = 0_u64;
            for (id, record) in &checkpoint.report.tasks {
                let Some(spec) = graph.by_id.get(id) else {
                    return Err(GraphError::CheckpointMismatch);
                };
                if record.attempts > spec.max_retries.saturating_add(1)
                    || (record.state == TaskState::Succeeded && record.attempts == 0)
                {
                    return Err(GraphError::CheckpointMismatch);
                }
                if record.attempts > 0 {
                    minimum_consumed = minimum_consumed
                        .checked_add(spec.resource_units)
                        .ok_or(GraphError::CheckpointMismatch)?;
                }
                if record.state == TaskState::Succeeded {
                    let output = record
                        .output
                        .as_ref()
                        .ok_or(GraphError::CheckpointMismatch)?;
                    validate_output(spec, output, self.policy.max_output_bytes)
                        .map_err(|_| GraphError::CheckpointMismatch)?;
                    validate_verification_lineage(
                        spec,
                        output,
                        checkpoint
                            .report
                            .tasks
                            .get(&output.verification.producer_id)
                            .and_then(|parent| parent.output.as_ref()),
                    )
                    .map_err(|_| GraphError::CheckpointMismatch)?;
                    // A saved success is trustworthy only if every prerequisite is also a
                    // saved success. Otherwise a malformed checkpoint could skip a task whose
                    // dependency failed or was never recorded.
                    for dependency in &spec.dependencies {
                        if !checkpoint
                            .report
                            .tasks
                            .get(dependency)
                            .is_some_and(|saved| saved.state == TaskState::Succeeded)
                        {
                            return Err(GraphError::CheckpointMismatch);
                        }
                    }
                } else if record.output.is_some() {
                    return Err(GraphError::CheckpointMismatch);
                }
            }
            // Zero-attempt tasks may have reserved units, but recorded attempts
            // must never cost more than the checkpoint says was consumed.
            if minimum_consumed > checkpoint.report.consumed_resource_units {
                return Err(GraphError::CheckpointMismatch);
            }
        }
        for id in &graph.topological_order {
            let already_succeeded = checkpoint
                .as_ref()
                .and_then(|saved| saved.report.tasks.get(id))
                .is_some_and(|record| record.state == TaskState::Succeeded);
            if !already_succeeded && !handlers.contains_key(id) {
                return Err(GraphError::MissingHandler(id.clone()));
            }
        }

        let started = Instant::now();
        let started_at_unix = checkpoint
            .as_ref()
            .map_or_else(clock::unix_now, |saved| saved.report.started_at_unix);
        let mut records = BTreeMap::new();
        let mut consumed = checkpoint
            .as_ref()
            .map_or(0, |saved| saved.report.consumed_resource_units);
        for id in &graph.topological_order {
            let prior = checkpoint
                .as_ref()
                .and_then(|saved| saved.report.tasks.get(id));
            let mut record = prior.cloned().unwrap_or_default();
            let spec = &graph.by_id[id];
            let attempts_remain = record.attempts < spec.max_retries.saturating_add(1);
            let can_resume = matches!(&record.state, TaskState::Pending | TaskState::Running)
                || (record.state == TaskState::Failed && record.retryable && attempts_remain);
            if can_resume {
                record.state = TaskState::Pending;
                record.finished_at_unix = None;
                record.duration_ms = None;
                record.output = None;
                record.error = None;
                record.retryable = false;
            }
            records.insert(id.clone(), record);
        }
        let mut retained_output_bytes = 0_usize;
        for record in records.values() {
            if let Some(output) = &record.output {
                let output_bytes = serde_json::to_vec(output)
                    .map_err(|error| GraphError::Checkpoint(error.to_string()))?
                    .len();
                retained_output_bytes = retained_output_bytes.saturating_add(output_bytes);
                if retained_output_bytes > MAX_RUN_OUTPUT_BYTES {
                    return Err(GraphError::CheckpointMismatch);
                }
            }
        }
        let run_deadline = Instant::now() + Duration::from_millis(self.policy.run_timeout_ms);
        let has_pending_work = records
            .values()
            .any(|record| matches!(&record.state, TaskState::Pending | TaskState::Running));
        let prior_termination = checkpoint
            .as_ref()
            .and_then(|saved| saved.report.termination.clone());
        let mut termination = if has_pending_work {
            match prior_termination {
                Some(RunTermination::ResourceLimit) => RunTermination::ResourceLimit,
                Some(RunTermination::TimedOut) => RunTermination::TimedOut,
                Some(RunTermination::Cancelled) => RunTermination::Cancelled,
                _ => RunTermination::Completed,
            }
        } else {
            prior_termination.unwrap_or_else(|| derive_termination(&records))
        };
        let RateStartHistory {
            monotonic: mut last_rate_start,
            persisted: mut persisted_rate_start,
        } = restored_rate_history(&graph, checkpoint.as_ref())?;
        let mut errors = checkpoint.map_or_else(Vec::new, |saved| saved.report.errors);

        loop {
            if records.values().all(|record| record.state.terminal()) {
                break;
            }
            if cancelled.load(Ordering::Acquire) {
                termination = RunTermination::Cancelled;
                for record in records
                    .values_mut()
                    .filter(|record| record.state == TaskState::Pending)
                {
                    record.state = TaskState::Cancelled;
                    record.error = Some("run cancelled before dispatch".into());
                    record.finished_at_unix = Some(clock::unix_now());
                }
                break;
            }
            if Instant::now() >= run_deadline {
                termination = RunTermination::TimedOut;
                for record in records
                    .values_mut()
                    .filter(|record| record.state == TaskState::Pending)
                {
                    record.state = TaskState::TimedOut;
                    record.error = Some("run deadline exceeded before dispatch".into());
                    record.finished_at_unix = Some(clock::unix_now());
                }
                break;
            }

            let mut changed = false;
            for id in &graph.topological_order {
                if records[id].state != TaskState::Pending {
                    continue;
                }
                let failed_dependency = graph.by_id[id].dependencies.iter().find(|dependency| {
                    records[*dependency].state.terminal()
                        && !records[*dependency].state.successful()
                });
                if let Some(dependency) = failed_dependency {
                    let record = records
                        .get_mut(id)
                        .ok_or_else(|| GraphError::Invalid("missing task record".into()))?;
                    record.state = TaskState::Blocked;
                    record.error = Some(format!("dependency {dependency} did not succeed"));
                    record.finished_at_unix = Some(clock::unix_now());
                    errors.push(format!("{id}: blocked by {dependency}"));
                    changed = true;
                }
            }
            if changed {
                continue;
            }

            let mut selected = Vec::<String>::new();
            let mut selected_resources = BTreeSet::new();
            let mut selected_rate_keys = BTreeSet::new();
            let mut rate_wait_until: Option<Instant> = None;
            let mut wave_cost = 0_u64;
            let mut budget_blocked = Vec::new();
            let mut dependency_output_blocked = Vec::new();
            for id in &graph.topological_order {
                if selected.len() >= self.policy.max_concurrency {
                    break;
                }
                if records[id].state != TaskState::Pending {
                    continue;
                }
                let spec = &graph.by_id[id];
                if !spec
                    .dependencies
                    .iter()
                    .all(|dependency| records[dependency].state == TaskState::Succeeded)
                {
                    continue;
                }
                if consumed
                    .checked_add(wave_cost)
                    .and_then(|total| total.checked_add(spec.resource_units))
                    .is_none_or(|total| total > self.policy.max_total_resource_units)
                {
                    budget_blocked.push(id.clone());
                    continue;
                }
                let mut dependency_bytes = 0_usize;
                for dependency in &spec.dependencies {
                    let output = records[dependency].output.as_ref().ok_or_else(|| {
                        GraphError::Invalid(format!(
                            "successful dependency {dependency} has no output"
                        ))
                    })?;
                    let output_bytes = serde_json::to_vec(output)
                        .map_err(|error| GraphError::Invalid(error.to_string()))?
                        .len();
                    dependency_bytes = dependency_bytes.saturating_add(output_bytes);
                    if dependency_bytes > MAX_DEPENDENCY_OUTPUT_BYTES {
                        dependency_output_blocked.push(id.clone());
                        break;
                    }
                }
                if dependency_output_blocked.last() == Some(id) {
                    continue;
                }
                if spec
                    .exclusive_resources
                    .iter()
                    .any(|resource| selected_resources.contains(resource))
                {
                    continue;
                }
                if let Some(limit) = &spec.rate_limit {
                    if selected_rate_keys.contains(&limit.key) {
                        continue;
                    }
                    if let Some(last_start) = last_rate_start.get(&limit.key) {
                        let eligible_at =
                            *last_start + Duration::from_millis(limit.min_interval_ms);
                        if Instant::now() < eligible_at {
                            rate_wait_until = Some(
                                rate_wait_until
                                    .map_or(eligible_at, |current| current.min(eligible_at)),
                            );
                            continue;
                        }
                    }
                    selected_rate_keys.insert(limit.key.clone());
                }
                selected_resources.extend(spec.exclusive_resources.iter().cloned());
                wave_cost = wave_cost.saturating_add(spec.resource_units);
                selected.push(id.clone());
            }
            for id in dependency_output_blocked {
                let record = records
                    .get_mut(&id)
                    .ok_or_else(|| GraphError::Invalid("missing task record".into()))?;
                record.state = TaskState::Blocked;
                record.error = Some("dependency output budget exhausted".into());
                record.finished_at_unix = Some(clock::unix_now());
                errors.push(format!("{id}: dependency output budget exhausted"));
                termination = RunTermination::ResourceLimit;
            }
            for id in budget_blocked {
                let record = records
                    .get_mut(&id)
                    .ok_or_else(|| GraphError::Invalid("missing task record".into()))?;
                record.state = TaskState::Blocked;
                record.error = Some("resource budget exhausted".into());
                record.finished_at_unix = Some(clock::unix_now());
                errors.push(format!("{id}: resource budget exhausted"));
                termination = RunTermination::ResourceLimit;
            }
            if selected.is_empty() {
                if let Some(eligible_at) = rate_wait_until {
                    wait_until_or_cancel(eligible_at, cancelled, run_deadline);
                    continue;
                }
                if records
                    .values()
                    .any(|record| record.state == TaskState::Pending)
                {
                    let pending: Vec<String> = records
                        .iter()
                        .filter(|(_, record)| record.state == TaskState::Pending)
                        .map(|(id, _)| id.clone())
                        .collect();
                    for id in pending {
                        if records[&id].state == TaskState::Pending {
                            let record = records
                                .get_mut(&id)
                                .ok_or_else(|| GraphError::Invalid("missing task record".into()))?;
                            record.state = TaskState::Blocked;
                            record.error = Some("no schedulable dependency frontier".into());
                            record.finished_at_unix = Some(clock::unix_now());
                            errors.push(format!("{id}: no schedulable dependency frontier"));
                        }
                    }
                    if termination == RunTermination::Completed {
                        termination = RunTermination::Failed;
                    }
                }
                break;
            }

            let dispatch_started = Instant::now();
            let dispatch_unix_ms = clock::unix_now_millis();
            for id in &selected {
                if let Some(limit) = &graph.by_id[id].rate_limit {
                    last_rate_start.insert(limit.key.clone(), dispatch_started);
                    persisted_rate_start.insert(limit.key.clone(), dispatch_unix_ms);
                }
            }
            consumed = consumed.saturating_add(wave_cost);
            let mut jobs: Vec<crate::concurrent::Job<'_, CompletedJob>> =
                Vec::with_capacity(selected.len());
            for id in &selected {
                let spec = &graph.by_id[id];
                let handler = handlers
                    .get(id)
                    .cloned()
                    .ok_or_else(|| GraphError::MissingHandler(id.clone()))?;
                let deps = spec
                    .dependencies
                    .iter()
                    .map(|dependency| {
                        let output = records[dependency].output.as_ref().ok_or_else(|| {
                            GraphError::Invalid(format!(
                                "successful dependency {dependency} has no output"
                            ))
                        })?;
                        Ok((dependency.clone(), output.clone()))
                    })
                    .collect::<Result<BTreeMap<_, _>, GraphError>>()?;
                let prior_attempts = records[id].attempts;
                let cancelled = Arc::clone(cancelled);
                let max_output_bytes = self.policy.max_output_bytes;
                let task_id = id.clone();
                jobs.push(Box::new(move || {
                    let result = run_one(
                        spec,
                        &handler,
                        &deps,
                        prior_attempts,
                        &cancelled,
                        run_deadline,
                        max_output_bytes,
                    );
                    (task_id, result)
                }));
            }
            let results = crate::concurrent::all(jobs);
            for (id, (mut record, last_attempt_start)) in results {
                if let (Some(limit), Some(start)) =
                    (&graph.by_id[&id].rate_limit, last_attempt_start)
                {
                    last_rate_start.insert(limit.key.clone(), start);
                    persisted_rate_start.insert(limit.key.clone(), attempt_start_unix_ms(start));
                }
                let previous_attempts = records[&id].attempts;
                record.attempts = previous_attempts.saturating_add(record.attempts);
                if record.state.successful() {
                    let output = record.output.as_ref().ok_or_else(|| {
                        GraphError::Invalid(format!("successful task {id} has no output"))
                    })?;
                    let output_bytes = serde_json::to_vec(output)
                        .map_err(|error| GraphError::Invalid(error.to_string()))?
                        .len();
                    if retained_output_bytes.saturating_add(output_bytes) > MAX_RUN_OUTPUT_BYTES {
                        record.state = TaskState::Failed;
                        record.output = None;
                        record.error = Some("run output budget exhausted".into());
                        record.retryable = false;
                        termination = RunTermination::ResourceLimit;
                    } else {
                        retained_output_bytes = retained_output_bytes.saturating_add(output_bytes);
                    }
                }
                if !record.state.successful() {
                    errors.push(format!(
                        "{id}: {}",
                        record.error.as_deref().unwrap_or("task failed")
                    ));
                    if matches!(&record.state, TaskState::TimedOut) {
                        termination = RunTermination::TimedOut;
                    } else if matches!(&record.state, TaskState::Cancelled) {
                        termination = RunTermination::Cancelled;
                    } else if termination == RunTermination::Completed {
                        termination = RunTermination::Failed;
                    }
                }
                records.insert(id, record);
            }
            if let Some(sink) = checkpoint_sink {
                let snapshot = RunReport {
                    run_id: definition.run_id.clone(),
                    graph_fingerprint: graph.fingerprint.clone(),
                    policy_fingerprint: policy_fingerprint.clone(),
                    started_at_unix,
                    finished_at_unix: None,
                    duration_ms: Some(
                        u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
                    ),
                    termination: Some(termination.clone()),
                    consumed_resource_units: consumed,
                    rate_limit_last_start_unix_ms: persisted_rate_start.clone(),
                    tasks: records.clone(),
                    errors: errors.clone(),
                };
                let checkpoint = ExecutionCheckpoint::from_report(snapshot);
                if let Err(error) = sink(&checkpoint) {
                    errors.push(format!("checkpoint persistence failed: {error}"));
                    for record in records
                        .values_mut()
                        .filter(|record| record.state == TaskState::Pending)
                    {
                        record.state = TaskState::Blocked;
                        record.error = Some("checkpoint persistence failed".into());
                        record.finished_at_unix = Some(clock::unix_now());
                    }
                    termination = RunTermination::Failed;
                    break;
                }
            }
        }

        if termination == RunTermination::Completed {
            termination = derive_termination(&records);
        }
        let duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        let mut report = RunReport {
            run_id: definition.run_id.clone(),
            graph_fingerprint: graph.fingerprint,
            policy_fingerprint,
            started_at_unix,
            finished_at_unix: Some(clock::unix_now()),
            duration_ms: Some(duration_ms),
            termination: Some(termination),
            consumed_resource_units: consumed,
            rate_limit_last_start_unix_ms: persisted_rate_start,
            tasks: records,
            errors,
        };
        if let Some(sink) = checkpoint_sink {
            let checkpoint = ExecutionCheckpoint::from_report(report.clone());
            if let Err(error) = sink(&checkpoint) {
                report
                    .errors
                    .push(format!("final checkpoint persistence failed: {error}"));
                report.termination = Some(RunTermination::Failed);
            }
        }
        Ok(report)
    }
}

#[cfg(test)]
mod tests;
