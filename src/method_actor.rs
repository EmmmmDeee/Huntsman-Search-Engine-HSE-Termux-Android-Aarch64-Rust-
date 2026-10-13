//! Composable method actors for sequential batch pipelines.
//!
//! A method actor is a processing unit that transforms a batch of strings. Actors are
//! ordered by their declared dependencies and run one after another; each stage sees
//! the previous stage's output.
//!
//! ```
//! use huntsman_recon::method_actor::PipelineBuilder;
//! use huntsman_recon::method_actors::{deduplication_actor, lowercase_normalizer_actor};
//!
//! let pipeline = PipelineBuilder::new()
//!     .add_actor(lowercase_normalizer_actor())
//!     .add_actor(deduplication_actor())
//!     .build()
//!     .expect("pipeline");
//! let run = pipeline
//!     .execute(vec!["A@B.COM".to_string(), "a@b.com".to_string()])
//!     .expect("run");
//! assert_eq!(run.output, vec!["a@b.com".to_string()]);
//! ```

use std::fmt;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

/// Result type for actor operations.
pub type ActorResult<T> = Result<T, ActorError>;

/// Errors that occur during actor processing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActorError {
    /// Input validation failed.
    ValidationError(String),
    /// Processing error with context.
    ProcessingError(String),
    /// Actor configuration is invalid.
    ConfigurationError(String),
    /// Pipeline execution was interrupted.
    ExecutionInterrupted(String),
    /// Batch size exceeded actor limits.
    BatchLimitExceeded { max_size: usize, actual: usize },
    /// Dependency constraint violated.
    DependencyViolation(String),
}

impl fmt::Display for ActorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ActorError::ValidationError(msg) => write!(f, "validation error: {msg}"),
            ActorError::ProcessingError(msg) => write!(f, "processing error: {msg}"),
            ActorError::ConfigurationError(msg) => write!(f, "configuration error: {msg}"),
            ActorError::ExecutionInterrupted(msg) => write!(f, "execution interrupted: {msg}"),
            ActorError::BatchLimitExceeded { max_size, actual } => {
                write!(f, "batch limit exceeded: {actual} > {max_size}")
            }
            ActorError::DependencyViolation(msg) => write!(f, "dependency violation: {msg}"),
        }
    }
}

impl std::error::Error for ActorError {}

/// Metadata about an actor for introspection and planning.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActorMetadata {
    /// Unique identifier for this actor implementation.
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// Version for schema evolution.
    pub version: u32,
    /// Maximum batch size this actor can process.
    pub max_batch_size: usize,
    /// Whether this actor is stateless and reusable.
    pub is_stateless: bool,
    /// Approximate cost in operations per item.
    pub cost_estimate: u32,
    /// List of actor IDs that must run before this one.
    pub dependencies: Vec<String>,
}

impl ActorMetadata {
    /// Create metadata for a new actor.
    pub fn new(id: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            version: 1,
            max_batch_size: 1000,
            is_stateless: true,
            cost_estimate: 10,
            dependencies: Vec::new(),
        }
    }

    /// Set the maximum batch size.
    #[must_use]
    pub fn with_max_batch_size(mut self, size: usize) -> Self {
        self.max_batch_size = size;
        self
    }

    /// Set the cost estimate.
    #[must_use]
    pub fn with_cost_estimate(mut self, cost: u32) -> Self {
        self.cost_estimate = cost;
        self
    }

    /// Add a dependency on another actor.
    #[must_use]
    pub fn with_dependency(mut self, actor_id: impl Into<String>) -> Self {
        self.dependencies.push(actor_id.into());
        self
    }
}

/// A processing step that transforms items in a batch.
///
/// Implementations must be deterministic and reusable. State should be
/// captured in the actor at construction time, not modified during processing.
pub trait MethodActor: Send + Sync {
    /// Get metadata about this actor.
    fn metadata(&self) -> &ActorMetadata;

    /// Validate input before processing.
    fn validate(&self, _items: &[String]) -> ActorResult<()> {
        Ok(())
    }

    /// Process a batch of items.
    ///
    /// Implementations must preserve order and handle each item independently
    /// unless documented otherwise. Failed items should return an error containing
    /// the index and reason.
    fn process(&self, items: Vec<String>) -> ActorResult<Vec<String>>;

    /// Optional: finalize after all batches are processed.
    fn finalize(&self) -> ActorResult<()> {
        Ok(())
    }

    /// Get the version of the actor, for tracking changes in behavior.
    fn version(&self) -> u32 {
        self.metadata().version
    }
}

/// A stateless function-based actor.
pub struct FunctionActor {
    metadata: ActorMetadata,
    process_fn: Arc<dyn Fn(Vec<String>) -> ActorResult<Vec<String>> + Send + Sync>,
}

impl FunctionActor {
    /// Create an actor from a processing function.
    pub fn new(
        metadata: ActorMetadata,
        process_fn: Arc<dyn Fn(Vec<String>) -> ActorResult<Vec<String>> + Send + Sync>,
    ) -> Self {
        Self {
            metadata,
            process_fn,
        }
    }
}

impl MethodActor for FunctionActor {
    fn metadata(&self) -> &ActorMetadata {
        &self.metadata
    }

    fn process(&self, items: Vec<String>) -> ActorResult<Vec<String>> {
        (self.process_fn)(items)
    }
}

/// Configuration for pipeline execution.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PipelineConfig {
    /// When a stage fails, pass its input through unchanged and record the failure
    /// instead of aborting the run.
    pub skip_on_error: bool,
    /// Cap on the items any stage receives; excess items are dropped before the stage.
    pub max_items: Option<usize>,
}

impl PipelineConfig {
    /// Pass a failed stage's input through instead of aborting.
    #[must_use]
    pub fn allow_error_skip(mut self) -> Self {
        self.skip_on_error = true;
        self
    }

    /// Cap the items each stage receives.
    #[must_use]
    pub fn with_max_items(mut self, max: usize) -> Self {
        self.max_items = Some(max);
        self
    }

    /// Validate the configuration.
    pub fn validate(&self) -> ActorResult<()> {
        if self.max_items == Some(0) {
            return Err(ActorError::ConfigurationError(
                "max_items must be > 0".to_string(),
            ));
        }
        Ok(())
    }
}

/// Results from a single stage of pipeline execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StageResult {
    /// The actor that produced this result.
    pub actor_id: String,
    /// Items the stage received.
    pub items_processed: usize,
    /// Items the stage emitted.
    pub items_successful: usize,
    /// Items passed through unprocessed because the stage failed under `skip_on_error`.
    pub items_failed: usize,
    /// The stage's error, when it failed under `skip_on_error`.
    pub error: Option<String>,
    /// Processing time in milliseconds.
    pub duration_ms: u64,
}

/// Execution plan for a pipeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionPlan {
    /// Order of actor execution based on dependencies.
    pub actor_order: Vec<String>,
    /// Whether the plan is optimal.
    pub is_optimal: bool,
    /// Total estimated cost.
    pub estimated_cost: u32,
}

impl ExecutionPlan {
    /// Validate that actor dependencies can be satisfied in order.
    pub fn validate(&self, actors: &[String]) -> ActorResult<()> {
        let mut seen = std::collections::HashSet::new();
        for actor_id in &self.actor_order {
            if !actors.contains(actor_id) {
                return Err(ActorError::DependencyViolation(format!(
                    "actor {actor_id} not found in pipeline"
                )));
            }
            seen.insert(actor_id.clone());
        }
        if seen.len() != actors.len() {
            return Err(ActorError::DependencyViolation(
                "execution plan does not include all actors".to_string(),
            ));
        }
        Ok(())
    }
}

/// Builder for composing actors into a pipeline.
pub struct PipelineBuilder {
    actors: Vec<(String, Arc<dyn MethodActor>)>,
    config: PipelineConfig,
}

impl PipelineBuilder {
    /// Create a new pipeline builder.
    #[must_use]
    pub fn new() -> Self {
        Self {
            actors: Vec::new(),
            config: PipelineConfig::default(),
        }
    }

    /// Add an actor to the pipeline.
    #[must_use]
    pub fn add_actor(mut self, actor: Arc<dyn MethodActor>) -> Self {
        let id = actor.metadata().id.clone();
        self.actors.push((id, actor));
        self
    }

    /// Set pipeline configuration.
    #[must_use]
    pub fn with_config(mut self, config: PipelineConfig) -> Self {
        self.config = config;
        self
    }

    /// Topologically sort actors by dependencies.
    fn topological_sort(actors: &[(String, Arc<dyn MethodActor>)]) -> ActorResult<Vec<usize>> {
        let n = actors.len();
        let mut in_degree = vec![0; n];
        let mut adjacency: Vec<Vec<usize>> = vec![Vec::new(); n];
        let mut id_to_index: std::collections::HashMap<String, usize> =
            std::collections::HashMap::new();

        for (i, (id, _)) in actors.iter().enumerate() {
            id_to_index.insert(id.clone(), i);
        }

        for (i, (_, actor)) in actors.iter().enumerate() {
            for dep_id in &actor.metadata().dependencies {
                if let Some(&dep_idx) = id_to_index.get(dep_id) {
                    adjacency[dep_idx].push(i);
                    in_degree[i] += 1;
                } else {
                    return Err(ActorError::DependencyViolation(format!(
                        "actor {} depends on unknown actor {}",
                        actor.metadata().id,
                        dep_id
                    )));
                }
            }
        }

        let mut queue: Vec<usize> = (0..n).filter(|i| in_degree[*i] == 0).collect();
        let mut order = Vec::new();

        while !queue.is_empty() {
            let node = queue.remove(0);
            order.push(node);

            for &neighbor in &adjacency[node] {
                in_degree[neighbor] -= 1;
                if in_degree[neighbor] == 0 {
                    queue.push(neighbor);
                }
            }
        }

        if order.len() != n {
            return Err(ActorError::DependencyViolation(
                "circular dependency detected in actor pipeline".to_string(),
            ));
        }

        Ok(order)
    }

    /// Build and validate the pipeline.
    pub fn build(self) -> ActorResult<Pipeline> {
        self.config.validate()?;

        if self.actors.is_empty() {
            return Err(ActorError::ConfigurationError(
                "pipeline must have at least one actor".to_string(),
            ));
        }

        let sort_order = Self::topological_sort(&self.actors)?;
        let mut sorted_actors = Vec::new();
        let mut actor_order = Vec::new();
        let mut estimated_cost = 0u32;

        for &idx in &sort_order {
            let (id, actor) = self.actors[idx].clone();
            sorted_actors.push(actor.clone());
            actor_order.push(id);
            estimated_cost = estimated_cost.saturating_add(actor.metadata().cost_estimate);
        }

        let is_optimal = sort_order.iter().enumerate().all(|(i, &idx)| idx == i);
        let plan = ExecutionPlan {
            actor_order,
            is_optimal,
            estimated_cost,
        };

        Ok(Pipeline {
            actors: sorted_actors,
            config: self.config,
            plan,
        })
    }
}

impl Default for PipelineBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// An executable pipeline of method actors.
pub struct Pipeline {
    actors: Vec<Arc<dyn MethodActor>>,
    config: PipelineConfig,
    plan: ExecutionPlan,
}

impl Pipeline {
    /// Get the execution plan for this pipeline.
    #[must_use]
    pub fn plan(&self) -> &ExecutionPlan {
        &self.plan
    }

    /// Get the configuration for this pipeline.
    #[must_use]
    pub fn config(&self) -> &PipelineConfig {
        &self.config
    }

    /// Execute the pipeline with the given input items.
    ///
    /// Actors are executed in the order determined by their dependencies.
    /// See `ExecutionPlan` for the specific ordering and cost estimates.
    pub fn execute(&self, mut items: Vec<String>) -> ActorResult<PipelineExecution> {
        let mut results = Vec::new();
        let start_time = std::time::Instant::now();

        for actor in &self.actors {
            if let Some(max) = self.config.max_items {
                items.truncate(max);
            }

            if items.is_empty() {
                break;
            }

            let stage_start = std::time::Instant::now();
            let metadata = actor.metadata();

            if items.len() > metadata.max_batch_size {
                return Err(ActorError::BatchLimitExceeded {
                    max_size: metadata.max_batch_size,
                    actual: items.len(),
                });
            }

            actor.validate(&items)?;

            let received = items.len();
            let (next, failed, error) = if self.config.skip_on_error {
                match actor.process(items.clone()) {
                    Ok(out) => (out, 0, None),
                    Err(e) => (items, received, Some(e.to_string())),
                }
            } else {
                (actor.process(items)?, 0, None)
            };
            items = next;

            let duration = stage_start.elapsed();
            results.push(StageResult {
                actor_id: metadata.id.clone(),
                items_processed: received,
                items_successful: if error.is_some() { 0 } else { items.len() },
                items_failed: failed,
                error,
                #[allow(clippy::cast_possible_truncation)]
                duration_ms: duration.as_millis() as u64,
            });
        }

        for actor in &self.actors {
            actor.finalize()?;
        }

        let total_duration = start_time.elapsed();
        #[allow(clippy::cast_possible_truncation)]
        let total_ms = total_duration.as_millis() as u64;
        Ok(PipelineExecution {
            output: items,
            stages: results,
            total_duration_ms: total_ms,
        })
    }
}

/// Results from a complete pipeline execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineExecution {
    /// Final output items.
    pub output: Vec<String>,
    /// Result from each stage.
    pub stages: Vec<StageResult>,
    /// Total execution time in milliseconds.
    pub total_duration_ms: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_actor_metadata() {
        let meta = ActorMetadata::new("test", "Test Actor")
            .with_max_batch_size(500)
            .with_cost_estimate(20);
        assert_eq!(meta.id, "test");
        assert_eq!(meta.max_batch_size, 500);
        assert_eq!(meta.cost_estimate, 20);
    }

    #[test]
    fn test_pipeline_config_validation() {
        assert!(
            PipelineConfig::default()
                .with_max_items(0)
                .validate()
                .is_err()
        );
        assert!(
            PipelineConfig::default()
                .with_max_items(1)
                .validate()
                .is_ok()
        );
        assert!(PipelineConfig::default().validate().is_ok());
    }

    #[test]
    fn a_failed_stage_under_skip_passes_its_input_through_and_records_the_failure() {
        let failing = Arc::new(FunctionActor::new(
            ActorMetadata::new("fails", "Fails"),
            Arc::new(|_| Err(ActorError::ProcessingError("boom".to_string()))),
        ));
        let upper = Arc::new(FunctionActor::new(
            ActorMetadata::new("upper", "Upper").with_dependency("fails"),
            Arc::new(|items: Vec<String>| {
                Ok(items.into_iter().map(|s| s.to_uppercase()).collect())
            }),
        ));
        let input = vec!["a".to_string(), "b".to_string()];

        let strict = PipelineBuilder::new()
            .add_actor(failing.clone())
            .add_actor(upper.clone())
            .build()
            .unwrap();
        assert!(strict.execute(input.clone()).is_err());

        let lenient = PipelineBuilder::new()
            .add_actor(failing)
            .add_actor(upper)
            .with_config(PipelineConfig::default().allow_error_skip())
            .build()
            .unwrap();
        let run = lenient.execute(input).unwrap();
        assert_eq!(run.output, vec!["A".to_string(), "B".to_string()]);
        assert_eq!(run.stages[0].items_processed, 2);
        assert_eq!(run.stages[0].items_failed, 2);
        assert_eq!(run.stages[0].items_successful, 0);
        assert_eq!(
            run.stages[0].error.as_deref(),
            Some("processing error: boom")
        );
        assert_eq!(run.stages[1].items_processed, 2);
        assert_eq!(run.stages[1].items_failed, 0);
    }

    #[test]
    fn stage_counts_report_items_received_and_emitted() {
        let keep_first = Arc::new(FunctionActor::new(
            ActorMetadata::new("first", "First").with_max_batch_size(10),
            Arc::new(|items: Vec<String>| Ok(items.into_iter().take(1).collect())),
        ));
        let run = PipelineBuilder::new()
            .add_actor(keep_first)
            .build()
            .unwrap()
            .execute(vec!["x".to_string(), "y".to_string(), "z".to_string()])
            .unwrap();
        assert_eq!(run.stages[0].items_processed, 3);
        assert_eq!(run.stages[0].items_successful, 1);
    }

    #[test]
    fn test_function_actor() {
        let metadata = ActorMetadata::new("uppercase", "Uppercase");
        let actor = FunctionActor::new(
            metadata,
            Arc::new(|items| Ok(items.into_iter().map(|s| s.to_uppercase()).collect())),
        );

        let result = actor
            .process(vec!["hello".to_string(), "world".to_string()])
            .unwrap();
        assert_eq!(result, vec!["HELLO".to_string(), "WORLD".to_string()]);
    }

    #[test]
    fn test_pipeline_builder() {
        let metadata = ActorMetadata::new("test", "Test");
        let actor = Arc::new(FunctionActor::new(metadata, Arc::new(Ok)));

        let pipeline = PipelineBuilder::new().add_actor(actor).build();

        assert!(pipeline.is_ok());
    }

    #[test]
    fn test_pipeline_execution() {
        let metadata = ActorMetadata::new("identity", "Identity");
        let actor = Arc::new(FunctionActor::new(metadata, Arc::new(Ok)));

        let pipeline = PipelineBuilder::new().add_actor(actor).build().unwrap();

        let result = pipeline.execute(vec!["test".to_string()]).unwrap();
        assert_eq!(result.output, vec!["test".to_string()]);
        assert_eq!(result.stages.len(), 1);
    }

    #[test]
    fn test_dependency_ordering() {
        let metadata_a = ActorMetadata::new("a", "Actor A");
        let actor_a = Arc::new(FunctionActor::new(metadata_a, Arc::new(Ok)));

        let metadata_b = ActorMetadata::new("b", "Actor B").with_dependency("a");
        let actor_b = Arc::new(FunctionActor::new(metadata_b, Arc::new(Ok)));

        let metadata_c = ActorMetadata::new("c", "Actor C").with_dependency("b");
        let actor_c = Arc::new(FunctionActor::new(metadata_c, Arc::new(Ok)));

        let pipeline = PipelineBuilder::new()
            .add_actor(actor_c)
            .add_actor(actor_b)
            .add_actor(actor_a)
            .build()
            .unwrap();

        assert_eq!(pipeline.plan().actor_order, vec!["a", "b", "c"]);
        assert!(!pipeline.plan().is_optimal);
    }

    #[test]
    fn test_circular_dependency_detection() {
        let metadata_a = ActorMetadata::new("a", "Actor A").with_dependency("c");
        let actor_a = Arc::new(FunctionActor::new(metadata_a, Arc::new(Ok)));

        let metadata_b = ActorMetadata::new("b", "Actor B").with_dependency("a");
        let actor_b = Arc::new(FunctionActor::new(metadata_b, Arc::new(Ok)));

        let metadata_c = ActorMetadata::new("c", "Actor C").with_dependency("b");
        let actor_c = Arc::new(FunctionActor::new(metadata_c, Arc::new(Ok)));

        let result = PipelineBuilder::new()
            .add_actor(actor_a)
            .add_actor(actor_b)
            .add_actor(actor_c)
            .build();

        assert!(result.is_err());
        match result {
            Err(ActorError::DependencyViolation(msg)) => {
                assert!(msg.contains("circular dependency"));
            }
            _ => panic!("expected circular dependency error"),
        }
    }

    #[test]
    fn test_missing_dependency_detection() {
        let metadata_a = ActorMetadata::new("a", "Actor A").with_dependency("missing");
        let actor_a = Arc::new(FunctionActor::new(metadata_a, Arc::new(Ok)));

        let result = PipelineBuilder::new().add_actor(actor_a).build();

        assert!(result.is_err());
        match result {
            Err(ActorError::DependencyViolation(msg)) => {
                assert!(msg.contains("unknown actor"));
            }
            _ => panic!("expected missing dependency error"),
        }
    }
}
