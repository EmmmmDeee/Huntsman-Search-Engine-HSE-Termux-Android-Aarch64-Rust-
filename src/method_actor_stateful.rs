//! Stateful method actors with context preservation across batches.
//!
//! Extends the base method actor framework with the ability to maintain state
//! and context across batch boundaries. Useful for operations that require
//! accumulation, learning, or stream-wide decisions.
//!
//! State is preserved across batches but isolated per pipeline execution.

use std::sync::Arc;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

use crate::method_actor::{ActorMetadata, ActorResult, MethodActor};

/// Context data that persists across batch processing.
pub trait ActorContext: Send + Sync {
    /// Called at the start of pipeline execution.
    fn initialize(&mut self) -> ActorResult<()> {
        Ok(())
    }

    /// Called after each batch is processed.
    fn after_batch(&mut self, _batch_num: usize, _items_processed: usize) -> ActorResult<()> {
        Ok(())
    }

    /// Called at the end of pipeline execution.
    fn finalize(&mut self) -> ActorResult<()> {
        Ok(())
    }

    /// Get the current state as a string for debugging.
    fn debug_state(&self) -> String {
        "{}".to_string()
    }
}

/// Simple empty context for stateless actors.
#[derive(Debug, Clone, Default)]
pub struct EmptyContext;

impl ActorContext for EmptyContext {}

/// A generic stateful actor that maintains context across batches.
pub struct StatefulMethodActor<C: ActorContext> {
    metadata: ActorMetadata,
    context: Arc<Mutex<C>>,
    process_fn: Arc<dyn Fn(Vec<String>, &mut C) -> ActorResult<Vec<String>> + Send + Sync>,
}

impl<C: ActorContext + 'static> StatefulMethodActor<C> {
    /// Create a stateful actor.
    pub fn new(
        metadata: ActorMetadata,
        context: C,
        process_fn: Arc<dyn Fn(Vec<String>, &mut C) -> ActorResult<Vec<String>> + Send + Sync>,
    ) -> Self {
        Self {
            metadata,
            context: Arc::new(Mutex::new(context)),
            process_fn,
        }
    }

    /// Get access to the context for introspection.
    pub fn context_debug(&self) -> ActorResult<String> {
        self.context
            .lock()
            .map_err(|_| crate::method_actor::ActorError::ExecutionInterrupted(
                "failed to acquire context lock".to_string(),
            ))
            .map(|ctx| ctx.debug_state())
    }

    /// Initialize the context.
    pub fn initialize_context(&self) -> ActorResult<()> {
        self.context
            .lock()
            .map_err(|_| crate::method_actor::ActorError::ExecutionInterrupted(
                "failed to acquire context lock".to_string(),
            ))?
            .initialize()
    }

    /// Signal end of batch processing.
    pub fn after_batch(&self, batch_num: usize, items: usize) -> ActorResult<()> {
        self.context
            .lock()
            .map_err(|_| crate::method_actor::ActorError::ExecutionInterrupted(
                "failed to acquire context lock".to_string(),
            ))?
            .after_batch(batch_num, items)
    }

    /// Finalize the context.
    pub fn finalize_context(&self) -> ActorResult<()> {
        self.context
            .lock()
            .map_err(|_| crate::method_actor::ActorError::ExecutionInterrupted(
                "failed to acquire context lock".to_string(),
            ))?
            .finalize()
    }
}

impl<C: ActorContext + 'static> MethodActor for StatefulMethodActor<C> {
    fn metadata(&self) -> &ActorMetadata {
        &self.metadata
    }

    fn process(&self, items: Vec<String>) -> ActorResult<Vec<String>> {
        let mut context = self
            .context
            .lock()
            .map_err(|_| crate::method_actor::ActorError::ExecutionInterrupted(
                "failed to acquire context lock".to_string(),
            ))?;
        (self.process_fn)(items, &mut *context)
    }

    fn finalize(&self) -> ActorResult<()> {
        self.finalize_context()
    }
}

/// Context for collecting statistics about processed items.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatisticsContext {
    pub total_items_processed: usize,
    pub total_items_output: usize,
    pub batches_processed: usize,
    pub min_batch_size: usize,
    pub max_batch_size: usize,
}

impl Default for StatisticsContext {
    fn default() -> Self {
        Self {
            total_items_processed: 0,
            total_items_output: 0,
            batches_processed: 0,
            min_batch_size: usize::MAX,
            max_batch_size: 0,
        }
    }
}

impl ActorContext for StatisticsContext {
    fn after_batch(&mut self, _: usize, items_processed: usize) -> ActorResult<()> {
        self.total_items_processed += items_processed;
        self.batches_processed += 1;
        self.min_batch_size = self.min_batch_size.min(items_processed);
        self.max_batch_size = self.max_batch_size.max(items_processed);
        Ok(())
    }

    fn debug_state(&self) -> String {
        format!(
            "{{processed: {}, batches: {}, min: {}, max: {}}}",
            self.total_items_processed, self.batches_processed, self.min_batch_size, self.max_batch_size
        )
    }
}

/// Context for deduplicating items while tracking seen values.
#[derive(Debug, Clone)]
pub struct DeduplicationContextWithTracking {
    seen: Arc<Mutex<std::collections::HashSet<String>>>,
    total_duplicates: usize,
}

impl Default for DeduplicationContextWithTracking {
    fn default() -> Self {
        Self {
            seen: Arc::new(Mutex::new(std::collections::HashSet::new())),
            total_duplicates: 0,
        }
    }
}

impl ActorContext for DeduplicationContextWithTracking {
    fn debug_state(&self) -> String {
        let seen = self.seen.lock().map(|s| s.len()).unwrap_or(0);
        format!("{{seen: {}, duplicates: {}}}", seen, self.total_duplicates)
    }
}

/// Create an actor that collects statistics about processing.
pub fn statistics_tracking_actor() -> Arc<dyn MethodActor> {
    let metadata = ActorMetadata::new("statistics_tracker", "Track Processing Statistics")
        .with_cost_estimate(8);
    let context = StatisticsContext::default();
    Arc::new(StatefulMethodActor::new(
        metadata,
        context,
        Arc::new(|items, ctx: &mut StatisticsContext| {
            ctx.total_items_output += items.len();
            Ok(items)
        }),
    ))
}

/// Create an actor that filters items above a count threshold, tracking occurrences.
pub fn occurrence_filter_actor(threshold: usize) -> Arc<dyn MethodActor> {
    let metadata = ActorMetadata::new("occurrence_filter", "Filter by Occurrence Count")
        .with_cost_estimate(15);

    #[derive(Debug, Clone)]
    struct OccurrenceContext {
        counts: Arc<Mutex<std::collections::HashMap<String, usize>>>,
    }

    impl Default for OccurrenceContext {
        fn default() -> Self {
            Self {
                counts: Arc::new(Mutex::new(std::collections::HashMap::new())),
            }
        }
    }

    impl ActorContext for OccurrenceContext {
        fn debug_state(&self) -> String {
            let counts = self.counts.lock().map(|m| m.len()).unwrap_or(0);
            format!("{{tracked_items: {}}}", counts)
        }
    }

    let context = OccurrenceContext::default();
    Arc::new(StatefulMethodActor::new(
        metadata,
        context,
        Arc::new(move |items, ctx: &mut OccurrenceContext| {
            let mut counts = ctx.counts.lock().unwrap();
            for item in &items {
                *counts.entry(item.clone()).or_insert(0) += 1;
            }
            Ok(items
                .into_iter()
                .filter(|item| counts.get(item).copied().unwrap_or(0) >= threshold)
                .collect())
        }),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_context() {
        let mut ctx = EmptyContext;
        assert!(ctx.initialize().is_ok());
        assert!(ctx.after_batch(1, 10).is_ok());
        assert!(ctx.finalize().is_ok());
    }

    #[test]
    fn test_statistics_context() {
        let mut ctx = StatisticsContext::default();
        ctx.after_batch(1, 10).unwrap();
        ctx.after_batch(2, 20).unwrap();
        ctx.after_batch(3, 5).unwrap();

        assert_eq!(ctx.total_items_processed, 35);
        assert_eq!(ctx.batches_processed, 3);
        assert_eq!(ctx.min_batch_size, 5);
        assert_eq!(ctx.max_batch_size, 20);
    }

    #[test]
    fn test_statistics_tracking_actor() {
        let actor = statistics_tracking_actor();
        let result = actor.process(vec!["a".to_string(), "b".to_string()]).unwrap();
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn test_deduplication_with_tracking() {
        let ctx = DeduplicationContextWithTracking::default();
        assert!(!ctx.debug_state().is_empty());
    }
}
