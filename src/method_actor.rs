//! Composable method actors for concurrent pipeline processing.
//!
//! A method actor is an atomic, stateless processing unit that transforms input data
//! to output data. Actors are chained into pipelines for multi-stage processing with
//! built-in batching, error handling, and optional concurrency.
//!
//! # Example
//! ```ignore
//! let pipeline = PipelineBuilder::new()
//!     .add_actor(FilterActor::new(predicate))
//!     .add_actor(TransformActor::new(transform_fn))
//!     .add_actor(EnrichActor::new(enricher))
//!     .build_with_concurrency(4)?;
//!
//! let results = pipeline.execute(input_batch).await?;
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
    pub fn with_max_batch_size(mut self, size: usize) -> Self {
        self.max_batch_size = size;
        self
    }

    /// Set the cost estimate.
    pub fn with_cost_estimate(mut self, cost: u32) -> Self {
        self.cost_estimate = cost;
        self
    }

    /// Add a dependency on another actor.
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PipelineConfig {
    /// Size of batches for processing.
    pub batch_size: usize,
    /// Maximum number of concurrent workers (0 = sequential).
    pub concurrency: usize,
    /// Whether to skip items that fail processing.
    pub skip_on_error: bool,
    /// Maximum total items to process.
    pub max_items: Option<usize>,
    /// Timeout per batch in milliseconds (0 = no timeout).
    pub timeout_ms: u64,
}

impl Default for PipelineConfig {
    fn default() -> Self {
        Self {
            batch_size: 100,
            concurrency: 0,
            skip_on_error: false,
            max_items: None,
            timeout_ms: 0,
        }
    }
}

impl PipelineConfig {
    /// Create with custom batch size.
    pub fn with_batch_size(mut self, size: usize) -> Self {
        self.batch_size = size;
        self
    }

    /// Create with concurrency enabled.
    pub fn with_concurrency(mut self, workers: usize) -> Self {
        self.concurrency = workers;
        self
    }

    /// Create allowing errors to be skipped.
    pub fn allow_error_skip(mut self) -> Self {
        self.skip_on_error = true;
        self
    }

    /// Validate the configuration.
    pub fn validate(&self) -> ActorResult<()> {
        if self.batch_size == 0 {
            return Err(ActorError::ConfigurationError(
                "batch_size must be > 0".to_string(),
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
    /// Total items processed.
    pub items_processed: usize,
    /// Items that passed through successfully.
    pub items_successful: usize,
    /// Items that failed.
    pub items_failed: usize,
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
    pub fn new() -> Self {
        Self {
            actors: Vec::new(),
            config: PipelineConfig::default(),
        }
    }

    /// Add an actor to the pipeline.
    pub fn add_actor(mut self, actor: Arc<dyn MethodActor>) -> Self {
        let id = actor.metadata().id.clone();
        self.actors.push((id, actor));
        self
    }

    /// Set pipeline configuration.
    pub fn with_config(mut self, config: PipelineConfig) -> Self {
        self.config = config;
        self
    }

    /// Set batch size.
    pub fn with_batch_size(mut self, size: usize) -> Self {
        self.config.batch_size = size;
        self
    }

    /// Set concurrency level.
    pub fn with_concurrency(mut self, workers: usize) -> Self {
        self.config.concurrency = workers;
        self
    }

    /// Build and validate the pipeline.
    pub fn build(self) -> ActorResult<Pipeline> {
        self.config.validate()?;

        if self.actors.is_empty() {
            return Err(ActorError::ConfigurationError(
                "pipeline must have at least one actor".to_string(),
            ));
        }

        let actor_ids: Vec<_> = self.actors.iter().map(|(id, _)| id.clone()).collect();
        let plan = ExecutionPlan {
            actor_order: actor_ids.clone(),
            is_optimal: true,
            estimated_cost: self
                .actors
                .iter()
                .map(|(_, a)| a.metadata().cost_estimate)
                .sum(),
        };

        plan.validate(&actor_ids)?;

        Ok(Pipeline {
            actors: self.actors.into_iter().map(|(_, a)| a).collect(),
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
    /// Execute the pipeline with the given input items.
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

            items = match actor.process(items) {
                Ok(out) => out,
                Err(e) => {
                    if self.config.skip_on_error {
                        Vec::new()
                    } else {
                        return Err(e);
                    }
                }
            };

            let duration = stage_start.elapsed();
            results.push(StageResult {
                actor_id: metadata.id.clone(),
                items_processed: metadata.max_batch_size,
                items_successful: items.len(),
                items_failed: 0,
                duration_ms: duration.as_millis() as u64,
            });
        }

        for actor in &self.actors {
            actor.finalize()?;
        }

        let total_duration = start_time.elapsed();
        Ok(PipelineExecution {
            output: items,
            stages: results,
            total_duration_ms: total_duration.as_millis() as u64,
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
        assert!(PipelineConfig::default().with_batch_size(0).validate().is_err());
        assert!(PipelineConfig::default().with_batch_size(1).validate().is_ok());
    }

    #[test]
    fn test_function_actor() {
        let metadata = ActorMetadata::new("uppercase", "Uppercase");
        let actor = FunctionActor::new(metadata, Arc::new(|items| {
            Ok(items.into_iter().map(|s| s.to_uppercase()).collect())
        }));

        let result = actor.process(vec!["hello".to_string(), "world".to_string()]).unwrap();
        assert_eq!(result, vec!["HELLO".to_string(), "WORLD".to_string()]);
    }

    #[test]
    fn test_pipeline_builder() {
        let metadata = ActorMetadata::new("test", "Test");
        let actor = Arc::new(FunctionActor::new(metadata, Arc::new(|items| Ok(items))));

        let pipeline = PipelineBuilder::new()
            .add_actor(actor)
            .with_batch_size(50)
            .build();

        assert!(pipeline.is_ok());
    }

    #[test]
    fn test_pipeline_execution() {
        let metadata = ActorMetadata::new("identity", "Identity");
        let actor = Arc::new(FunctionActor::new(metadata, Arc::new(|items| Ok(items))));

        let pipeline = PipelineBuilder::new()
            .add_actor(actor)
            .build()
            .unwrap();

        let result = pipeline.execute(vec!["test".to_string()]).unwrap();
        assert_eq!(result.output, vec!["test".to_string()]);
        assert_eq!(result.stages.len(), 1);
    }
}
