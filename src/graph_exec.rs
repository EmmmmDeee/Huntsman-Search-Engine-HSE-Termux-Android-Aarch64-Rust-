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
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

const MAX_ID_BYTES: usize = 128;
const MAX_TASKS: usize = 4096;
const MAX_DEPENDENCIES_PER_TASK: usize = 1024;
const MAX_RESOURCES_PER_TASK: usize = 64;
const MAX_INPUT_BYTES: usize = 1024 * 1024;
const MAX_CONCURRENCY: usize = 64;
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
    Array { items: Box<ValueSchema> },
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

/// Static task definition. Function handlers are registered separately and are never serialized.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TaskSpec {
    pub id: String,
    pub objective: String,
    pub input: Value,
    pub input_schema: ValueSchema,
    pub output_schema: ValueSchema,
    #[serde(default)]
    pub dependencies: Vec<String>,
    #[serde(default)]
    pub exclusive_resources: Vec<String>,
    /// Logical-operation key. Duplicate keys in one graph are rejected.
    #[serde(default)]
    pub idempotency_key: Option<String>,
    /// Cooperative per-attempt deadline.
    pub timeout_ms: u64,
    /// Number of retries after the initial attempt; capped by MAX_RETRIES.
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
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }

    #[must_use]
    pub fn remaining(&self) -> Duration {
        self.deadline.saturating_duration_since(Instant::now())
    }
}

pub type TaskHandler =
    Arc<dyn Fn(TaskContext) -> Result<TaskOutput, TaskFailure> + Send + Sync + 'static>;
pub type HandlerRegistry = BTreeMap<String, TaskHandler>;

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
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RunReport {
    pub run_id: String,
    pub graph_fingerprint: String,
    pub started_at_unix: u64,
    pub finished_at_unix: Option<u64>,
    pub duration_ms: Option<u64>,
    pub termination: Option<RunTermination>,
    pub consumed_resource_units: u64,
    pub tasks: BTreeMap<String, TaskRecord>,
    pub errors: Vec<String>,
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
}

impl GraphDefinition {
    /// Validate every task contract, dependency, idempotency key and cycle before dispatch.
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
        for task in &self.tasks {
            if !valid_token(&task.id) {
                return Err(GraphError::Invalid(format!("invalid task id: {}", task.id)));
            }
            if task.objective.trim().is_empty() || task.objective.len() > MAX_OBJECTIVE_BYTES {
                return Err(GraphError::Invalid(format!("invalid objective for {}", task.id)));
            }
            if task.timeout_ms == 0 || task.timeout_ms > MAX_TIMEOUT_MS {
                return Err(GraphError::Invalid(format!("invalid timeout for {}", task.id)));
            }
            if task.max_retries > MAX_RETRIES {
                return Err(GraphError::Invalid(format!("retry limit exceeded for {}", task.id)));
            }
            if task.resource_units == 0 {
                return Err(GraphError::Invalid(format!("zero resource cost for {}", task.id)));
            }
            let input_bytes = serde_json::to_vec(&task.input)
                .map_err(|error| GraphError::Invalid(format!("cannot encode input for {}: {error}", task.id)))?;
            if input_bytes.len() > MAX_INPUT_BYTES {
                return Err(GraphError::Invalid(format!("input exceeds size limit for {}", task.id)));
            }
            if task.dependencies.len() > MAX_DEPENDENCIES_PER_TASK
                || task.exclusive_resources.len() > MAX_RESOURCES_PER_TASK
            {
                return Err(GraphError::Invalid(format!("dependency or resource limit exceeded for {}", task.id)));
            }
            if !task.input_schema.accepts(&task.input) {
                return Err(GraphError::Invalid(format!("input schema mismatch for {}", task.id)));
            }
            let mut deps = BTreeSet::new();
            for dependency in &task.dependencies {
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
            let mut resources = BTreeSet::new();
            for resource in &task.exclusive_resources {
                if !valid_token(resource) || !resources.insert(resource) {
                    return Err(GraphError::Invalid(format!(
                        "invalid or duplicate resource on {}",
                        task.id
                    )));
                }
            }
            if let Some(key) = &task.idempotency_key {
                if !valid_token(key) || !idempotency.insert(key.clone()) {
                    return Err(GraphError::Invalid(format!(
                        "invalid or duplicate idempotency key on {}",
                        task.id
                    )));
                }
            }
            if by_id.insert(task.id.clone(), task.clone()).is_some() {
                return Err(GraphError::Invalid(format!("duplicate task id: {}", task.id)));
            }
        }
        for task in self.tasks.iter() {
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
        let encoded = serde_json::to_vec(self)
            .map_err(|error| GraphError::Invalid(format!("cannot fingerprint graph: {error}")))?;
        if encoded.len() > MAX_CHECKPOINT_BYTES {
            return Err(GraphError::Invalid("graph definition exceeds size limit".into()));
        }
        let fingerprint = crate::sha256::hex32(&crate::sha256::sha256(&encoded));
        Ok(ValidatedGraph {
            topological_order: order,
            by_id,
            fingerprint,
        })
    }
}

fn valid_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_ID_BYTES
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':')
        })
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
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
            return Err(format!("invalid or duplicate evidence reference for {}", spec.id));
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
    if verification.state == VerificationState::Verified {
        if verification.producer_id == verification.reviewer_id {
            return Err(format!("verified result lacks independent reviewer for {}", spec.id));
        }
        if verification.evidence_refs.is_empty()
            || verification
                .evidence_refs
                .iter()
                .any(|reference| !evidence_ids.contains(reference))
        {
            return Err(format!("verified result lacks linked evidence for {}", spec.id));
        }
    }
    if verification
        .evidence_refs
        .iter()
        .collect::<BTreeSet<_>>()
        .len()
        != verification.evidence_refs.len()
    {
        return Err(format!("duplicate verification evidence reference for {}", spec.id));
    }
    Ok(())
}

fn unix_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_millis())
}

fn run_one(
    spec: &TaskSpec,
    handler: &TaskHandler,
    dependency_outputs: BTreeMap<String, TaskOutput>,
    prior_attempts: u8,
    cancelled: Arc<AtomicBool>,
    run_deadline: Instant,
    max_output_bytes: usize,
) -> (TaskRecord, u64) {
    let start = Instant::now();
    let started_at_unix = now_unix();
    let mut record = TaskRecord {
        state: TaskState::Running,
        started_at_unix: Some(started_at_unix),
        ..TaskRecord::default()
    };
    let max_attempts = spec.max_retries.saturating_add(1);
    let mut last_error = "task did not execute".to_string();
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
        record.attempts = record.attempts.saturating_add(1);
        let attempt = prior_attempts.saturating_add(record.attempts);
        let deadline = (Instant::now() + Duration::from_millis(spec.timeout_ms)).min(run_deadline);
        let context = TaskContext {
            task_id: spec.id.clone(),
            input: spec.input.clone(),
            dependency_outputs: dependency_outputs.clone(),
            attempt,
            idempotency_key: spec.idempotency_key.clone(),
            deadline,
            cancelled: Arc::clone(&cancelled),
        };
        let attempt_started = Instant::now();
        let result = catch_unwind(AssertUnwindSafe(|| handler(context)));
        let elapsed = attempt_started.elapsed();
        match result {
            Ok(Ok(output)) => {
                if Instant::now() > deadline {
                    record.state = TaskState::TimedOut;
                    last_error = format!("task {} exceeded its deadline", spec.id);
                    break;
                }
                match validate_output(spec, &output, max_output_bytes) {
                    Ok(()) => {
                        record.state = TaskState::Succeeded;
                        record.output = Some(output);
                        record.error = None;
                        break;
                    }
                    Err(error) => {
                        record.state = TaskState::Failed;
                        last_error = error;
                        break;
                    }
                }
            }
            Ok(Err(error)) => {
                last_error = error.message;
                if !error.retryable || prior_attempts.saturating_add(record.attempts) >= max_attempts {
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
        thread::sleep(Duration::from_millis(backoff_ms).min(remaining));
        if elapsed >= Duration::from_millis(spec.timeout_ms) {
            record.state = TaskState::TimedOut;
            last_error = format!("task {} exceeded its deadline", spec.id);
            break;
        }
    }
    record.finished_at_unix = Some(now_unix());
    record.duration_ms = Some(u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX));
    if !record.state.successful() {
        record.error = Some(last_error);
    }
    (record, spec.resource_units)
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
        let bytes = serde_json::to_vec(self)
            .map_err(|error| GraphError::Checkpoint(error.to_string()))?;
        if bytes.len() > MAX_CHECKPOINT_BYTES {
            return Err(GraphError::Checkpoint("checkpoint exceeds size limit".into()));
        }
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, GraphError> {
        if bytes.len() > MAX_CHECKPOINT_BYTES {
            return Err(GraphError::Checkpoint("checkpoint exceeds size limit".into()));
        }
        let checkpoint: Self = serde_json::from_slice(bytes)
            .map_err(|error| GraphError::Checkpoint(error.to_string()))?;
        if checkpoint.format_version != 1 {
            return Err(GraphError::Checkpoint("unsupported checkpoint version".into()));
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
        cancelled: Arc<AtomicBool>,
    ) -> Result<RunReport, GraphError> {
        self.execute_inner(definition, handlers, cancelled, None)
    }

    pub fn resume(
        &self,
        definition: &GraphDefinition,
        handlers: &HandlerRegistry,
        cancelled: Arc<AtomicBool>,
        checkpoint: ExecutionCheckpoint,
    ) -> Result<RunReport, GraphError> {
        self.execute_inner(definition, handlers, cancelled, Some(checkpoint))
    }

    fn execute_inner(
        &self,
        definition: &GraphDefinition,
        handlers: &HandlerRegistry,
        cancelled: Arc<AtomicBool>,
        checkpoint: Option<ExecutionCheckpoint>,
    ) -> Result<RunReport, GraphError> {
        if self.policy.max_concurrency == 0
            || self.policy.max_concurrency > MAX_CONCURRENCY
            || self.policy.max_total_resource_units == 0
            || self.policy.max_output_bytes == 0
            || self.policy.run_timeout_ms == 0
            || self.policy.run_timeout_ms > MAX_TIMEOUT_MS
        {
            return Err(GraphError::Invalid("invalid execution policy".into()));
        }
        let graph = definition.validate()?;
        if let Some(checkpoint) = &checkpoint {
            if checkpoint.format_version != 1
                || checkpoint.graph_fingerprint != graph.fingerprint
                || checkpoint.report.graph_fingerprint != graph.fingerprint
                || checkpoint.report.run_id != definition.run_id
            {
                return Err(GraphError::CheckpointMismatch);
            }
            for (id, record) in &checkpoint.report.tasks {
                if !graph.by_id.contains_key(id) {
                    return Err(GraphError::CheckpointMismatch);
                }
                if record.state == TaskState::Succeeded {
                    let spec = &graph.by_id[id];
                    let output = record.output.as_ref().ok_or(GraphError::CheckpointMismatch)?;
                    validate_output(spec, output, self.policy.max_output_bytes)
                        .map_err(|_| GraphError::CheckpointMismatch)?;
                }
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
            .map_or_else(now_unix, |saved| saved.report.started_at_unix);
        let mut records = BTreeMap::new();
        let mut consumed = checkpoint
            .as_ref()
            .map_or(0, |saved| saved.report.consumed_resource_units);
        for id in &graph.topological_order {
            let prior = checkpoint.as_ref().and_then(|saved| saved.report.tasks.get(id));
            let mut record = prior.cloned().unwrap_or_default();
            if record.state != TaskState::Succeeded {
                record.state = TaskState::Pending;
                record.finished_at_unix = None;
                record.duration_ms = None;
                record.output = None;
                record.error = None;
            }
            records.insert(id.clone(), record);
        }
        let run_deadline = Instant::now() + Duration::from_millis(self.policy.run_timeout_ms);
        let mut termination = RunTermination::Completed;
        let mut errors = checkpoint.map_or_else(Vec::new, |saved| saved.report.errors);

        loop {
            if records.values().all(|record| record.state.terminal()) {
                break;
            }
            if cancelled.load(Ordering::Acquire) {
                termination = RunTermination::Cancelled;
                for record in records.values_mut().filter(|record| record.state == TaskState::Pending) {
                    record.state = TaskState::Cancelled;
                    record.error = Some("run cancelled before dispatch".into());
                    record.finished_at_unix = Some(now_unix());
                }
                break;
            }
            if Instant::now() >= run_deadline {
                termination = RunTermination::TimedOut;
                for record in records.values_mut().filter(|record| record.state == TaskState::Pending) {
                    record.state = TaskState::TimedOut;
                    record.error = Some("run deadline exceeded before dispatch".into());
                    record.finished_at_unix = Some(now_unix());
                }
                break;
            }

            let mut changed = false;
            for id in &graph.topological_order {
                if records[id].state != TaskState::Pending {
                    continue;
                }
                let failed_dependency = graph.by_id[id].dependencies.iter().find(|dependency| {
                    records[*dependency].state.terminal() && !records[*dependency].state.successful()
                });
                if let Some(dependency) = failed_dependency {
                    let record = records.get_mut(id).ok_or_else(|| {
                        GraphError::Invalid("missing task record".into())
                    })?;
                    record.state = TaskState::Blocked;
                    record.error = Some(format!("dependency {dependency} did not succeed"));
                    record.finished_at_unix = Some(now_unix());
                    errors.push(format!("{id}: blocked by {dependency}"));
                    changed = true;
                }
            }
            if changed {
                continue;
            }

            let mut selected = Vec::<String>::new();
            let mut selected_resources = BTreeSet::new();
            let mut wave_cost = 0_u64;
            let mut budget_blocked = Vec::new();
            for id in &graph.topological_order {
                if selected.len() >= self.policy.max_concurrency {
                    break;
                }
                if records[id].state != TaskState::Pending {
                    continue;
                }
                let spec = &graph.by_id[id];
                if !spec.dependencies.iter().all(|dependency| {
                    records[dependency].state == TaskState::Succeeded
                }) {
                    continue;
                }
                if consumed.saturating_add(wave_cost).saturating_add(spec.resource_units)
                    > self.policy.max_total_resource_units
                {
                    budget_blocked.push(id.clone());
                    continue;
                }
                if spec
                    .exclusive_resources
                    .iter()
                    .any(|resource| selected_resources.contains(resource))
                {
                    continue;
                }
                selected_resources.extend(spec.exclusive_resources.iter().cloned());
                wave_cost = wave_cost.saturating_add(spec.resource_units);
                selected.push(id.clone());
            }
            for id in budget_blocked {
                let record = records.get_mut(&id).ok_or_else(|| {
                    GraphError::Invalid("missing task record".into())
                })?;
                record.state = TaskState::Blocked;
                record.error = Some("resource budget exhausted".into());
                record.finished_at_unix = Some(now_unix());
                errors.push(format!("{id}: resource budget exhausted"));
                termination = RunTermination::ResourceLimit;
            }
            if selected.is_empty() {
                if records.values().any(|record| record.state == TaskState::Pending) {
                    let pending: Vec<String> = records
                        .iter()
                        .filter(|(_, record)| record.state == TaskState::Pending)
                        .map(|(id, _)| id.clone())
                        .collect();
                    for id in pending {
                        if records[&id].state == TaskState::Pending {
                            let record = records.get_mut(&id).ok_or_else(|| {
                                GraphError::Invalid("missing task record".into())
                            })?;
                            record.state = TaskState::Blocked;
                            record.error = Some("no schedulable dependency frontier".into());
                            record.finished_at_unix = Some(now_unix());
                            errors.push(format!("{id}: no schedulable dependency frontier"));
                        }
                    }
                    if termination == RunTermination::Completed {
                        termination = RunTermination::Failed;
                    }
                }
                break;
            }

            consumed = consumed.saturating_add(wave_cost);
            let outputs: BTreeMap<String, TaskOutput> = records
                .iter()
                .filter_map(|(id, record)| {
                    record.output.as_ref().map(|output| (id.clone(), output.clone()))
                })
                .collect();
            let results = thread::scope(|scope| {
                let mut handles = Vec::with_capacity(selected.len());
                for id in &selected {
                    let spec = &graph.by_id[id];
                    let handler = handlers.get(id).cloned().expect("handler checked before dispatch");
                    let deps = spec
                        .dependencies
                        .iter()
                        .filter_map(|dependency| {
                            outputs
                                .get(dependency)
                                .cloned()
                                .map(|output| (dependency.clone(), output))
                        })
                        .collect::<BTreeMap<_, _>>();
                    let prior_attempts = records[id].attempts;
                    let cancelled = Arc::clone(&cancelled);
                    let run_deadline = run_deadline;
                    let max_output_bytes = self.policy.max_output_bytes;
                    handles.push((
                        id.clone(),
                        scope.spawn(move || {
                            run_one(
                                spec,
                                &handler,
                                deps,
                                prior_attempts,
                                cancelled,
                                run_deadline,
                                max_output_bytes,
                            )
                        }),
                    ));
                }
                handles
                    .into_iter()
                    .map(|(id, handle)| {
                        let result = handle.join().unwrap_or_else(|_| {
                            let mut record = TaskRecord::default();
                            record.state = TaskState::Failed;
                            record.error = Some("task worker panicked".into());
                            record.finished_at_unix = Some(now_unix());
                            (record, graph.by_id[&id].resource_units)
                        });
                        (id, result)
                    })
                    .collect::<Vec<_>>()
            });
            for (id, (mut record, _charged)) in results {
                let previous_attempts = records[&id].attempts;
                record.attempts = previous_attempts.saturating_add(record.attempts);
                if !record.state.successful() {
                    errors.push(format!(
                        "{id}: {}",
                        record.error.as_deref().unwrap_or("task failed")
                    ));
                    if matches!(record.state, TaskState::TimedOut) {
                        termination = RunTermination::TimedOut;
                    } else if matches!(record.state, TaskState::Cancelled) {
                        termination = RunTermination::Cancelled;
                    } else if termination == RunTermination::Completed {
                        termination = RunTermination::Failed;
                    }
                }
                records.insert(id, record);
            }
        }

        let duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        Ok(RunReport {
            run_id: definition.run_id.clone(),
            graph_fingerprint: graph.fingerprint,
            started_at_unix,
            finished_at_unix: Some(now_unix()),
            duration_ms: Some(duration_ms),
            termination: Some(termination),
            consumed_resource_units: consumed,
            tasks: records,
            errors,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Barrier, Mutex};

    fn schema_any() -> ValueSchema {
        ValueSchema::Any
    }

    fn spec(id: &str, dependencies: &[&str]) -> TaskSpec {
        TaskSpec {
            id: id.into(),
            objective: format!("execute {id}"),
            input: json!({}),
            input_schema: schema_any(),
            output_schema: schema_any(),
            dependencies: dependencies.iter().map(|value| (*value).to_string()).collect(),
            exclusive_resources: Vec::new(),
            idempotency_key: None,
            timeout_ms: 1_000,
            max_retries: 0,
            resource_units: 1,
        }
    }

    fn output(value: Value, producer: &str) -> TaskOutput {
        TaskOutput {
            value,
            evidence: Vec::new(),
            verification: VerificationRecord {
                state: VerificationState::Unresolved,
                producer_id: producer.into(),
                reviewer_id: "independent-reviewer".into(),
                basis: "result retained pending evidence review".into(),
                evidence_refs: Vec::new(),
            },
        }
    }

    fn handler<F>(f: F) -> TaskHandler
    where
        F: Fn(TaskContext) -> Result<TaskOutput, TaskFailure> + Send + Sync + 'static,
    {
        Arc::new(f)
    }

    fn policy() -> ExecutionPolicy {
        ExecutionPolicy {
            max_concurrency: 4,
            max_total_resource_units: 100,
            max_output_bytes: 1024 * 1024,
            run_timeout_ms: 10_000,
        }
    }

    #[test]
    fn rejects_missing_dependencies_and_cycles_before_dispatch() {
        let missing = GraphDefinition {
            run_id: "run-1".into(),
            tasks: vec![spec("a", &["missing"])],
        };
        assert!(missing.validate().is_err());
        let cycle = GraphDefinition {
            run_id: "run-2".into(),
            tasks: vec![spec("a", &["b"]), spec("b", &["a"])],
        };
        assert!(cycle.validate().unwrap_err().to_string().contains("cycle"));
    }

    #[test]
    fn rejects_duplicate_idempotency_keys_and_invalid_input_schema() {
        let mut a = spec("a", &[]);
        let mut b = spec("b", &[]);
        a.idempotency_key = Some("same-operation".into());
        b.idempotency_key = Some("same-operation".into());
        assert!(GraphDefinition { run_id: "run-3".into(), tasks: vec![a, b] }.validate().is_err());
        let mut bad = spec("bad", &[]);
        bad.input = json!("not an object");
        bad.input_schema = ValueSchema::Object { required: BTreeMap::new(), allow_additional: false };
        assert!(GraphDefinition { run_id: "run-4".into(), tasks: vec![bad] }.validate().is_err());
    }

    #[test]
    fn independent_tasks_overlap_but_outputs_reduce_deterministically() {
        let definition = GraphDefinition {
            run_id: "parallel-run".into(),
            tasks: vec![spec("b", &[]), spec("a", &[])],
        };
        let barrier = Arc::new(Barrier::new(2));
        let mut handlers = HandlerRegistry::new();
        for id in ["a", "b"] {
            let barrier = Arc::clone(&barrier);
            handlers.insert(id.into(), handler(move |_| {
                barrier.wait();
                Ok(output(json!({"task": id}), id))
            }));
        }
        let report = GraphExecutor::new(policy())
            .execute(&definition, &handlers, Arc::new(AtomicBool::new(false)))
            .unwrap();
        assert_eq!(report.tasks["a"].state, TaskState::Succeeded);
        assert_eq!(report.tasks["b"].state, TaskState::Succeeded);
        assert_eq!(report.tasks["a"].output.as_ref().unwrap().value, json!({"task":"a"}));
        assert_eq!(report.tasks["b"].output.as_ref().unwrap().value, json!({"task":"b"}));
    }

    #[test]
    fn dependent_task_receives_only_completed_dependency_output() {
        let definition = GraphDefinition {
            run_id: "dependency-run".into(),
            tasks: vec![spec("child", &["parent"]), spec("parent", &[])],
        };
        let mut handlers = HandlerRegistry::new();
        handlers.insert("parent".into(), handler(|_| Ok(output(json!(7), "parent"))));
        handlers.insert("child".into(), handler(|context| {
            let value = context.dependency_outputs["parent"].value.as_i64().unwrap_or_default();
            Ok(output(json!(value + 1), "child"))
        }));
        let report = GraphExecutor::new(policy())
            .execute(&definition, &handlers, Arc::new(AtomicBool::new(false)))
            .unwrap();
        assert_eq!(report.tasks["child"].output.as_ref().unwrap().value, json!(8));
    }

    #[test]
    fn failed_dependency_blocks_descendants_without_hiding_the_failure() {
        let definition = GraphDefinition {
            run_id: "failure-run".into(),
            tasks: vec![spec("root", &[]), spec("child", &["root"])],
        };
        let mut handlers = HandlerRegistry::new();
        handlers.insert("root".into(), handler(|_| Err(TaskFailure::permanent("fixture failure"))));
        handlers.insert("child".into(), handler(|_| Ok(output(json!(true), "child"))));
        let report = GraphExecutor::new(policy())
            .execute(&definition, &handlers, Arc::new(AtomicBool::new(false)))
            .unwrap();
        assert_eq!(report.tasks["root"].state, TaskState::Failed);
        assert_eq!(report.tasks["child"].state, TaskState::Blocked);
        assert!(report.errors.iter().any(|error| error.contains("fixture failure")));
    }

    #[test]
    fn retries_are_bounded_and_counted() {
        let definition = GraphDefinition {
            run_id: "retry-run".into(),
            tasks: vec![{ let mut value = spec("retry", &[]); value.max_retries = 2; value }],
        };
        let attempts = Arc::new(AtomicUsize::new(0));
        let mut handlers = HandlerRegistry::new();
        let attempts_for_handler = Arc::clone(&attempts);
        handlers.insert("retry".into(), handler(move |_| {
            attempts_for_handler.fetch_add(1, Ordering::SeqCst);
            Err(TaskFailure::transient("retry me"))
        }));
        let report = GraphExecutor::new(policy())
            .execute(&definition, &handlers, Arc::new(AtomicBool::new(false)))
            .unwrap();
        assert_eq!(attempts.load(Ordering::SeqCst), 3);
        assert_eq!(report.tasks["retry"].attempts, 3);
        assert_eq!(report.tasks["retry"].state, TaskState::Failed);
    }

    #[test]
    fn empty_success_is_not_confused_with_failure() {
        let definition = GraphDefinition {
            run_id: "empty-run".into(),
            tasks: vec![spec("empty", &[])],
        };
        let mut handlers = HandlerRegistry::new();
        handlers.insert("empty".into(), handler(|_| Ok(output(json!([]), "empty"))));
        let report = GraphExecutor::new(policy())
            .execute(&definition, &handlers, Arc::new(AtomicBool::new(false)))
            .unwrap();
        assert_eq!(report.tasks["empty"].state, TaskState::Succeeded);
        assert_eq!(report.tasks["empty"].output.as_ref().unwrap().value, json!([]));
    }

    #[test]
    fn verified_claim_requires_distinct_reviewer_and_linked_evidence() {
        let mut value = output(json!({"claim":"x"}), "producer");
        value.verification.state = VerificationState::Verified;
        value.verification.reviewer_id = "producer".into();
        assert!(validate_output(&spec("verify", &[]), &value, 1024).is_err());
        value.verification.reviewer_id = "reviewer".into();
        value.evidence.push(EvidenceReference {
            id: "ev-1".into(),
            source_id: "public-source".into(),
            locator: "https://example.invalid/evidence".into(),
            provenance: "captured fixture".into(),
            observed_at_unix: 1,
            content_sha256: None,
        });
        value.verification.evidence_refs = vec!["ev-1".into()];
        assert!(validate_output(&spec("verify", &[]), &value, 1024).is_ok());
    }

    #[test]
    fn exclusive_resource_serializes_conflicting_tasks() {
        let mut a = spec("a", &[]);
        let mut b = spec("b", &[]);
        a.exclusive_resources = vec!["shared-store".into()];
        b.exclusive_resources = vec!["shared-store".into()];
        let definition = GraphDefinition { run_id: "resource-run".into(), tasks: vec![a, b] };
        let inside = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let lock = Arc::new(Mutex::new(()));
        let mut handlers = HandlerRegistry::new();
        for id in ["a", "b"] {
            let inside = Arc::clone(&inside);
            let peak = Arc::clone(&peak);
            let lock = Arc::clone(&lock);
            handlers.insert(id.into(), handler(move |_| {
                let _guard = lock.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                let current = inside.fetch_add(1, Ordering::SeqCst) + 1;
                peak.fetch_max(current, Ordering::SeqCst);
                thread::sleep(Duration::from_millis(10));
                inside.fetch_sub(1, Ordering::SeqCst);
                Ok(output(json!(true), id))
            }));
        }
        let report = GraphExecutor::new(policy())
            .execute(&definition, &handlers, Arc::new(AtomicBool::new(false)))
            .unwrap();
        assert_eq!(report.tasks["a"].state, TaskState::Succeeded);
        assert_eq!(report.tasks["b"].state, TaskState::Succeeded);
        assert_eq!(peak.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn checkpoint_round_trip_and_resume_preserve_success() {
        let definition = GraphDefinition {
            run_id: "checkpoint-run".into(),
            tasks: vec![spec("done", &[]), spec("later", &[])],
        };
        let calls = Arc::new(AtomicUsize::new(0));
        let mut handlers = HandlerRegistry::new();
        for id in ["done", "later"] {
            let calls = Arc::clone(&calls);
            handlers.insert(id.into(), handler(move |_| {
                calls.fetch_add(1, Ordering::SeqCst);
                Ok(output(json!(id), id))
            }));
        }
        let executor = GraphExecutor::new(policy());
        let first = executor.execute(&definition, &handlers, Arc::new(AtomicBool::new(false))).unwrap();
        let checkpoint = ExecutionCheckpoint::from_report(first.clone());
        let bytes = checkpoint.encode().unwrap();
        let decoded = ExecutionCheckpoint::decode(&bytes).unwrap();
        let resumed = executor.resume(&definition, &handlers, Arc::new(AtomicBool::new(false)), decoded).unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(resumed.tasks["done"].state, TaskState::Succeeded);
        assert_eq!(resumed.tasks["later"].state, TaskState::Succeeded);
    }
}
