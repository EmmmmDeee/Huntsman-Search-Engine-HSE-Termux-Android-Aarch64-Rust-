//! Validated, deterministic task-DAG planning and outcome accounting.
//!
//! This module deliberately separates graph validation/reduction from task-specific I/O.
//! It does not replace the existing ROI scheduler or source execution paths.

use std::collections::{BTreeMap, BTreeSet, btree_map::Entry};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const MAX_TASKS: usize = 10_000;
pub const MAX_ATTEMPTS: u8 = 10;
pub const MAX_TIMEOUT_MS: u64 = 600_000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskSpec {
    pub id: String,
    #[serde(default)]
    pub depends_on: Vec<String>,
    #[serde(default = "default_attempts")]
    pub max_attempts: u8,
    pub timeout_ms: u64,
    #[serde(default)]
    pub required_output_keys: Vec<String>,
}

const fn default_attempts() -> u8 {
    1
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GraphError {
    EmptyGraph,
    TooManyTasks { actual: usize, limit: usize },
    EmptyTaskId,
    DuplicateTaskId(String),
    InvalidAttempts { task: String, attempts: u8 },
    InvalidTimeout { task: String, timeout_ms: u64 },
    DuplicateDependency { task: String, dependency: String },
    MissingDependency { task: String, dependency: String },
    SelfDependency(String),
    Cycle(Vec<String>),
}

impl std::fmt::Display for GraphError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyGraph => f.write_str("workflow graph is empty"),
            Self::TooManyTasks { actual, limit } => {
                write!(f, "workflow has {actual} tasks; limit is {limit}")
            }
            Self::EmptyTaskId => f.write_str("task id must not be empty"),
            Self::DuplicateTaskId(id) => write!(f, "duplicate task id: {id}"),
            Self::InvalidAttempts { task, attempts } => {
                write!(f, "task {task} has invalid max_attempts={attempts}")
            }
            Self::InvalidTimeout { task, timeout_ms } => {
                write!(f, "task {task} has invalid timeout_ms={timeout_ms}")
            }
            Self::DuplicateDependency { task, dependency } => {
                write!(f, "task {task} repeats dependency {dependency}")
            }
            Self::MissingDependency { task, dependency } => {
                write!(f, "task {task} references missing dependency {dependency}")
            }
            Self::SelfDependency(id) => write!(f, "task {id} depends on itself"),
            Self::Cycle(ids) => write!(f, "workflow dependency cycle: {}", ids.join(" -> ")),
        }
    }
}

impl std::error::Error for GraphError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskGraph {
    tasks: BTreeMap<String, TaskSpec>,
    layers: Vec<Vec<String>>,
}

impl TaskGraph {
    /// Validate task contracts and construct stable topological execution layers.
    ///
    /// # Errors
    /// Returns an error for invalid task IDs, dependency references, resource bounds, or cycles.
    #[must_use]
    pub fn validate(specs: Vec<TaskSpec>) -> Result<Self, GraphError> {
        if specs.is_empty() {
            return Err(GraphError::EmptyGraph);
        }
        if specs.len() > MAX_TASKS {
            return Err(GraphError::TooManyTasks {
                actual: specs.len(),
                limit: MAX_TASKS,
            });
        }

        let mut tasks = BTreeMap::new();
        for task in specs {
            if task.id.trim().is_empty() {
                return Err(GraphError::EmptyTaskId);
            }
            if !(1..=MAX_ATTEMPTS).contains(&task.max_attempts) {
                return Err(GraphError::InvalidAttempts {
                    task: task.id,
                    attempts: task.max_attempts,
                });
            }
            if !(1..=MAX_TIMEOUT_MS).contains(&task.timeout_ms) {
                return Err(GraphError::InvalidTimeout {
                    task: task.id,
                    timeout_ms: task.timeout_ms,
                });
            }
            let mut dependencies = BTreeSet::new();
            for dependency in &task.depends_on {
                if !dependencies.insert(dependency) {
                    return Err(GraphError::DuplicateDependency {
                        task: task.id.clone(),
                        dependency: dependency.clone(),
                    });
                }
            }
            match tasks.entry(task.id.clone()) {
                Entry::Vacant(entry) => {
                    entry.insert(task);
                }
                Entry::Occupied(entry) => {
                    return Err(GraphError::DuplicateTaskId(entry.key().clone()));
                }
            }
        }

        for task in tasks.values() {
            for dependency in &task.depends_on {
                if dependency == &task.id {
                    return Err(GraphError::SelfDependency(task.id.clone()));
                }
                if !tasks.contains_key(dependency) {
                    return Err(GraphError::MissingDependency {
                        task: task.id.clone(),
                        dependency: dependency.clone(),
                    });
                }
            }
        }

        let mut remaining: BTreeSet<String> = tasks.keys().cloned().collect();
        let mut completed = BTreeSet::new();
        let mut layers = Vec::new();
        while !remaining.is_empty() {
            let layer: Vec<String> = remaining
                .iter()
                .filter(|id| {
                    tasks[*id]
                        .depends_on
                        .iter()
                        .all(|dependency| completed.contains(dependency))
                })
                .cloned()
                .collect();
            if layer.is_empty() {
                return Err(GraphError::Cycle(remaining.into_iter().collect()));
            }
            for id in &layer {
                remaining.remove(id);
                completed.insert(id.clone());
            }
            layers.push(layer);
        }
        Ok(Self { tasks, layers })
    }

    #[must_use]
    pub fn task(&self, id: &str) -> Option<&TaskSpec> {
        self.tasks.get(id)
    }

    #[must_use]
    pub fn tasks(&self) -> &BTreeMap<String, TaskSpec> {
        &self.tasks
    }

    /// Stable topological layers. Tasks in one layer have no dependencies on each other.
    #[must_use]
    pub fn layers(&self) -> &[Vec<String>] {
        &self.layers
    }

    /// Tasks ready after the supplied successful task IDs, in stable lexical order.
    #[must_use]
    pub fn ready<'a>(
        &'a self,
        succeeded: &BTreeSet<String>,
        running: &BTreeSet<String>,
    ) -> Vec<&'a TaskSpec> {
        self.tasks
            .values()
            .filter(|task| {
                !succeeded.contains(&task.id)
                    && !running.contains(&task.id)
                    && task.depends_on.iter().all(|id| succeeded.contains(id))
            })
            .collect()
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum TaskOutcome {
    Succeeded { output: Value, attempts: u8 },
    Empty { attempts: u8 },
    Failed { error: String, attempts: u8 },
    TimedOut { attempts: u8 },
    Cancelled { attempts: u8 },
    Blocked { dependency: String },
    Missing,
    InvalidOutput { reason: String, attempts: u8 },
}

impl TaskOutcome {
    #[must_use]
    pub const fn is_success(&self) -> bool {
        matches!(self, Self::Succeeded { .. } | Self::Empty { .. })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Accounting {
    pub expected: usize,
    pub returned: usize,
    pub succeeded: usize,
    pub failed: usize,
    pub incomplete: usize,
}

/// Account for every expected task without conflating empty success with failure.
#[must_use]
pub fn account(graph: &TaskGraph, outcomes: &BTreeMap<String, TaskOutcome>) -> Accounting {
    let mut succeeded = 0;
    let mut failed = 0;
    let mut incomplete = 0;
    for id in graph.tasks.keys() {
        match outcomes.get(id) {
            Some(outcome) if outcome.is_success() => succeeded += 1,
            Some(
                TaskOutcome::Missing
                | TaskOutcome::Blocked { .. }
                | TaskOutcome::Cancelled { .. }
                | TaskOutcome::TimedOut { .. },
            )
            | None => incomplete += 1,
            Some(_) => failed += 1,
        }
    }
    Accounting {
        expected: graph.tasks.len(),
        returned: outcomes
            .keys()
            .filter(|id| graph.tasks.contains_key(*id))
            .count(),
        succeeded,
        failed,
        incomplete,
    }
}

/// Validate that a successful output is an object containing every required field.
///
/// # Errors
/// Returns an error when the output is not an object or a required key is absent.
#[must_use]
pub fn validate_output(task: &TaskSpec, output: &Value) -> Result<(), String> {
    let object = output
        .as_object()
        .ok_or_else(|| "output must be a JSON object".to_string())?;
    for key in &task.required_output_keys {
        if !object.contains_key(key) {
            return Err(format!("required output key is missing: {key}"));
        }
    }
    Ok(())
}


/// Cooperative cancellation shared by a workflow and its task executors.
#[derive(Clone, Default)]
pub struct CancellationToken(Arc<AtomicBool>);

impl CancellationToken {
    pub fn cancel(&self) {
        self.0.store(true, Ordering::Release);
    }

    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

/// Deadline and cancellation signal passed to each attempt.
///
/// Executors must propagate `remaining()` into blocking I/O timeouts and check
/// cancellation between operations. Rust cannot forcibly stop an uncooperative thread.
#[derive(Debug, Clone)]
pub struct TaskContext {
    deadline: Instant,
    cancellation: CancellationToken,
}

impl TaskContext {
    #[must_use]
    pub fn deadline(&self) -> Instant {
        self.deadline
    }

    #[must_use]
    pub fn remaining(&self) -> Duration {
        self.deadline.saturating_duration_since(Instant::now())
    }

    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.cancellation.is_cancelled()
    }
}

/// Execute each topological layer with bounded concurrency and bounded retries.
///
/// Task executors must honour the cooperative deadline/cancellation contract in
/// `TaskContext`. A dependency runs only after all its prerequisites succeed.
/// Failed prerequisites produce explicit `Blocked` outcomes.
pub fn execute<F>(
    graph: &TaskGraph,
    max_parallel: usize,
    cancellation: CancellationToken,
    executor: &F,
) -> Result<BTreeMap<String, TaskOutcome>, ExecutionError>
where
    F: Fn(&TaskSpec, &TaskContext) -> Result<Value, String> + Sync + Send,
{
    if max_parallel == 0 {
        return Err(ExecutionError::ZeroConcurrency);
    }

    let mut outcomes = BTreeMap::new();
    for layer in graph.layers() {
        let mut runnable = Vec::new();
        for id in layer {
            let task = graph.task(id).expect("validated graph layer references a task");
            if cancellation.is_cancelled() {
                outcomes.insert(id.clone(), TaskOutcome::Cancelled { attempts: 0 });
                continue;
            }
            if let Some(dependency) = task.depends_on.iter().find(|dependency| {
                outcomes.get(*dependency).is_some_and(|outcome: &TaskOutcome| !outcome.is_success())
            }) {
                outcomes.insert(
                    id.clone(),
                    TaskOutcome::Blocked { dependency: dependency.clone() },
                );
            } else {
                runnable.push(id.clone());
            }
        }

        for batch in runnable.chunks(max_parallel) {
            let jobs = batch.iter().map(|id| {
                let id = id.clone();
                let task = graph.task(&id).expect("validated graph contains task");
                let cancellation = cancellation.clone();
                Box::new(move || {
                    let outcome = execute_one(task, &cancellation, executor);
                    (id, outcome)
                }) as crate::concurrent::Job<'_, (String, TaskOutcome)>
            }).collect();
            for (id, outcome) in crate::concurrent::all(jobs) {
                outcomes.insert(id, outcome);
            }
        }
    }
    Ok(outcomes)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionError {
    ZeroConcurrency,
}

impl std::fmt::Display for ExecutionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ZeroConcurrency => f.write_str("workflow concurrency must be at least one"),
        }
    }
}

impl std::error::Error for ExecutionError {}

fn execute_one<F>(
    task: &TaskSpec,
    cancellation: &CancellationToken,
    executor: &F,
) -> TaskOutcome
where
    F: Fn(&TaskSpec, &TaskContext) -> Result<Value, String> + Sync + Send,
{
    let mut last = TaskOutcome::Failed {
        error: "task did not execute".to_string(),
        attempts: 0,
    };
    for attempt in 1..=task.max_attempts {
        if cancellation.is_cancelled() {
            return TaskOutcome::Cancelled { attempts: attempt - 1 };
        }
        let deadline = Instant::now() + Duration::from_millis(task.timeout_ms);
        let context = TaskContext {
            deadline,
            cancellation: cancellation.clone(),
        };
        let result = catch_unwind(AssertUnwindSafe(|| executor(task, &context)));
        if cancellation.is_cancelled() {
            return TaskOutcome::Cancelled { attempts: attempt };
        }
        if Instant::now() > deadline {
            last = TaskOutcome::TimedOut { attempts: attempt };
            continue;
        }
        match result {
            Ok(Ok(output)) => match validate_output(task, &output) {
                Ok(()) if is_empty_output(&output) => {
                    return TaskOutcome::Empty { attempts: attempt };
                }
                Ok(()) => return TaskOutcome::Succeeded { output, attempts: attempt },
                Err(reason) => last = TaskOutcome::InvalidOutput { reason, attempts: attempt },
            },
            Ok(Err(error)) => last = TaskOutcome::Failed { error, attempts: attempt },
            Err(_) => last = TaskOutcome::Failed {
                error: "task executor panicked".to_string(),
                attempts: attempt,
            },
        }
    }
    last
}

fn is_empty_output(output: &Value) -> bool {
    output.is_null()
        || output.as_array().is_some_and(Vec::is_empty)
        || output.as_object().is_some_and(serde_json::Map::is_empty)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn task(id: &str, dependencies: &[&str]) -> TaskSpec {
        TaskSpec {
            id: id.into(),
            depends_on: dependencies.iter().map(|id| (*id).into()).collect(),
            max_attempts: 2,
            timeout_ms: 1_000,
            required_output_keys: vec![],
        }
    }


    #[test]
    fn executor_runs_independent_tasks_concurrently_with_a_cap() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::thread;
        use std::time::Duration;

        let graph = TaskGraph::validate(vec![task("a", &[]), task("b", &[])]).expect("valid graph");
        let active = AtomicUsize::new(0);
        let peak = AtomicUsize::new(0);
        let executor = |_: &TaskSpec, _: &TaskContext| {
            let now = active.fetch_add(1, Ordering::SeqCst) + 1;
            peak.fetch_max(now, Ordering::SeqCst);
            thread::sleep(Duration::from_millis(30));
            active.fetch_sub(1, Ordering::SeqCst);
            Ok(json!({"ok": true}))
        };
        let outcomes = execute(&graph, 2, CancellationToken::default(), &executor).expect("execute");
        assert_eq!(outcomes.values().filter(|outcome| outcome.is_success()).count(), 2);
        assert_eq!(peak.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn executor_retries_within_the_declared_bound_and_blocks_dependents() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let graph = TaskGraph::validate(vec![task("a", &[]), task("b", &["a"])]).expect("valid graph");
        let calls = AtomicUsize::new(0);
        let executor = |task: &TaskSpec, _: &TaskContext| {
            if task.id == "a" && calls.fetch_add(1, Ordering::SeqCst) == 0 {
                Err("temporary failure".to_string())
            } else if task.id == "b" {
                Ok(json!({"done": true}))
            } else {
                Ok(json!({"done": true}))
            }
        };
        let outcomes = execute(&graph, 2, CancellationToken::default(), &executor).expect("execute");
        assert!(matches!(outcomes.get("a"), Some(TaskOutcome::Succeeded { attempts: 2, .. })));
        assert!(matches!(outcomes.get("b"), Some(TaskOutcome::Succeeded { attempts: 1, .. })));
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn executor_rejects_zero_concurrency_and_reports_invalid_output() {
        let graph = TaskGraph::validate(vec![task("a", &[])]).expect("valid graph");
        let executor = |_: &TaskSpec, _: &TaskContext| Ok(json!("not an object"));
        assert_eq!(
            execute(&graph, 0, CancellationToken::default(), &executor),
            Err(ExecutionError::ZeroConcurrency)
        );
        let outcomes = execute(&graph, 1, CancellationToken::default(), &executor).expect("execute");
        assert!(matches!(outcomes.get("a"), Some(TaskOutcome::InvalidOutput { .. })));
    }

    #[test]
    fn independent_tasks_share_a_layer_and_dependents_follow() {
        let graph = TaskGraph::validate(vec![
            task("merge", &["b", "a"]),
            task("b", &[]),
            task("a", &[]),
        ])
        .expect("valid graph");
        assert_eq!(
            graph.layers(),
            &[
                vec!["a".to_string(), "b".to_string()],
                vec!["merge".to_string()]
            ]
        );
    }

    #[test]
    fn rejects_missing_self_and_cyclic_dependencies() {
        assert!(matches!(
            TaskGraph::validate(vec![task("a", &["absent"])]),
            Err(GraphError::MissingDependency { .. })
        ));
        assert!(matches!(
            TaskGraph::validate(vec![task("a", &["a"])]),
            Err(GraphError::SelfDependency(_))
        ));
        assert!(matches!(
            TaskGraph::validate(vec![task("a", &["b"]), task("b", &["a"])]),
            Err(GraphError::Cycle(_))
        ));
    }

    #[test]
    fn rejects_duplicate_ids_and_invalid_resource_bounds() {
        assert!(matches!(
            TaskGraph::validate(vec![task("a", &[]), task("a", &[])]),
            Err(GraphError::DuplicateTaskId(_))
        ));
        let mut invalid = task("a", &[]);
        invalid.timeout_ms = MAX_TIMEOUT_MS + 1;
        assert!(matches!(
            TaskGraph::validate(vec![invalid]),
            Err(GraphError::InvalidTimeout { .. })
        ));
    }

    #[test]
    fn output_contract_and_missing_work_are_explicit() {
        let mut required = task("a", &[]);
        required.required_output_keys.push("source".into());
        assert!(validate_output(&required, &json!({"source":"https://example.test"})).is_ok());
        assert!(validate_output(&required, &json!({})).is_err());
        let graph = TaskGraph::validate(vec![required, task("b", &[])]).expect("valid graph");
        let outcomes = BTreeMap::from([("a".into(), TaskOutcome::Empty { attempts: 1 })]);
        let tally = account(&graph, &outcomes);
        assert_eq!(
            (
                tally.expected,
                tally.returned,
                tally.succeeded,
                tally.incomplete
            ),
            (2, 1, 1, 1)
        );
    }

    #[test]
    fn ready_tasks_wait_for_successful_dependencies() {
        let graph =
            TaskGraph::validate(vec![task("a", &[]), task("b", &["a"])]).expect("valid graph");
        assert_eq!(
            graph
                .ready(&BTreeSet::new(), &BTreeSet::new())
                .iter()
                .map(|task| task.id.as_str())
                .collect::<Vec<_>>(),
            vec!["a"]
        );
        assert_eq!(
            graph
                .ready(&BTreeSet::from(["a".to_string()]), &BTreeSet::new())
                .iter()
                .map(|task| task.id.as_str())
                .collect::<Vec<_>>(),
            vec!["b"]
        );
    }
}
