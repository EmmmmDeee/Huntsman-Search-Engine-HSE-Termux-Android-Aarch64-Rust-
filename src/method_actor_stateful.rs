//! Stateful method actors that keep a context across batches.
//!
//! The actor owns its context and drives the context's lifecycle itself: `initialize`
//! before the first batch, `after_batch` after every batch, and `finalize` when the
//! pipeline finalizes its actors. Context therefore persists for the life of the actor.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};

use serde::{Deserialize, Serialize};

use crate::method_actor::{ActorError, ActorMetadata, ActorResult, MethodActor};

/// Context data that persists across batch processing.
pub trait ActorContext: Send + Sync {
    /// Called once, before the first batch.
    fn initialize(&mut self) -> ActorResult<()> {
        Ok(())
    }

    /// Called after each batch with its zero-based index and the number of items received.
    fn after_batch(&mut self, _batch_num: usize, _items_processed: usize) -> ActorResult<()> {
        Ok(())
    }

    /// Called when the owning pipeline finalizes its actors.
    fn finalize(&mut self) -> ActorResult<()> {
        Ok(())
    }

    /// Current state rendered for debugging.
    fn debug_state(&self) -> String {
        "{}".to_string()
    }
}

/// Context for actors that need no state.
#[derive(Debug, Clone, Default)]
pub struct EmptyContext;

impl ActorContext for EmptyContext {}

/// Processing function that mutates the shared context while transforming a batch.
pub type StatefulProcessFn<C> =
    Arc<dyn Fn(Vec<String>, &mut C) -> ActorResult<Vec<String>> + Send + Sync>;

struct Guarded<C> {
    context: C,
    batches: usize,
}

/// A method actor that owns a context and drives its lifecycle.
pub struct StatefulMethodActor<C: ActorContext> {
    metadata: ActorMetadata,
    state: Mutex<Guarded<C>>,
    process_fn: StatefulProcessFn<C>,
}

impl<C: ActorContext + 'static> StatefulMethodActor<C> {
    /// Create a stateful actor. Its metadata is marked as not stateless.
    pub fn new(mut metadata: ActorMetadata, context: C, process_fn: StatefulProcessFn<C>) -> Self {
        metadata.is_stateless = false;
        Self {
            metadata,
            state: Mutex::new(Guarded {
                context,
                batches: 0,
            }),
            process_fn,
        }
    }

    fn lock(&self) -> ActorResult<MutexGuard<'_, Guarded<C>>> {
        self.state.lock().map_err(|_| {
            ActorError::ExecutionInterrupted("actor context lock poisoned".to_string())
        })
    }

    /// The context's debug rendering.
    pub fn context_debug(&self) -> ActorResult<String> {
        Ok(self.lock()?.context.debug_state())
    }

    /// Number of batches this actor has processed.
    pub fn batches_processed(&self) -> ActorResult<usize> {
        Ok(self.lock()?.batches)
    }
}

impl<C: ActorContext + 'static> MethodActor for StatefulMethodActor<C> {
    fn metadata(&self) -> &ActorMetadata {
        &self.metadata
    }

    fn process(&self, items: Vec<String>) -> ActorResult<Vec<String>> {
        let mut state = self.lock()?;
        let batch = state.batches;
        if batch == 0 {
            state.context.initialize()?;
        }
        let received = items.len();
        let output = (self.process_fn)(items, &mut state.context)?;
        state.context.after_batch(batch, received)?;
        state.batches = batch + 1;
        Ok(output)
    }

    fn finalize(&self) -> ActorResult<()> {
        self.lock()?.context.finalize()
    }
}

/// Context that counts items and batches.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatisticsContext {
    pub total_items_processed: usize,
    pub total_items_output: usize,
    pub batches_processed: usize,
    /// Smallest batch seen; `None` until the first batch.
    pub min_batch_size: Option<usize>,
    pub max_batch_size: usize,
}

impl ActorContext for StatisticsContext {
    fn after_batch(&mut self, _: usize, items_processed: usize) -> ActorResult<()> {
        self.total_items_processed += items_processed;
        self.batches_processed += 1;
        self.min_batch_size = Some(
            self.min_batch_size
                .map_or(items_processed, |min| min.min(items_processed)),
        );
        self.max_batch_size = self.max_batch_size.max(items_processed);
        Ok(())
    }

    fn debug_state(&self) -> String {
        format!(
            "{{processed: {}, output: {}, batches: {}, min: {:?}, max: {}}}",
            self.total_items_processed,
            self.total_items_output,
            self.batches_processed,
            self.min_batch_size,
            self.max_batch_size
        )
    }
}

/// Context that counts how often each item has been seen.
#[derive(Debug, Clone, Default)]
pub struct OccurrenceContext {
    counts: HashMap<String, usize>,
}

impl ActorContext for OccurrenceContext {
    fn debug_state(&self) -> String {
        format!("{{tracked_items: {}}}", self.counts.len())
    }
}

/// Statistics-collecting pass-through actor, kept concrete so callers can read its stats.
#[must_use]
pub fn statistics_tracking_actor() -> Arc<StatefulMethodActor<StatisticsContext>> {
    let metadata = ActorMetadata::new("statistics_tracker", "Track Processing Statistics")
        .with_cost_estimate(8);
    Arc::new(StatefulMethodActor::new(
        metadata,
        StatisticsContext::default(),
        Arc::new(|items, ctx: &mut StatisticsContext| {
            ctx.total_items_output += items.len();
            Ok(items)
        }),
    ))
}

/// Emit an item once it has been seen `threshold` times across all batches so far,
/// and on every later sighting.
#[must_use]
pub fn occurrence_filter_actor(threshold: usize) -> Arc<dyn MethodActor> {
    let metadata = ActorMetadata::new("occurrence_filter", "Filter by Occurrence Count")
        .with_cost_estimate(15);
    Arc::new(StatefulMethodActor::new(
        metadata,
        OccurrenceContext::default(),
        Arc::new(move |items, ctx: &mut OccurrenceContext| {
            let mut out = Vec::new();
            for item in items {
                let seen = ctx.counts.entry(item.clone()).or_insert(0);
                *seen += 1;
                if *seen >= threshold {
                    out.push(item);
                }
            }
            Ok(out)
        }),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::method_actor::PipelineBuilder;

    fn strings(values: &[&str]) -> Vec<String> {
        values.iter().map(|v| (*v).to_string()).collect()
    }

    #[test]
    fn statistics_context_tracks_batches() {
        let mut ctx = StatisticsContext::default();
        ctx.after_batch(0, 10).unwrap();
        ctx.after_batch(1, 20).unwrap();
        ctx.after_batch(2, 5).unwrap();

        assert_eq!(ctx.total_items_processed, 35);
        assert_eq!(ctx.batches_processed, 3);
        assert_eq!(ctx.min_batch_size, Some(5));
        assert_eq!(ctx.max_batch_size, 20);
    }

    #[test]
    fn the_actor_drives_the_context_lifecycle_across_pipeline_runs() {
        let stats = statistics_tracking_actor();
        let pipeline = PipelineBuilder::new()
            .add_actor(stats.clone())
            .build()
            .unwrap();

        pipeline.execute(strings(&["a", "b"])).unwrap();
        pipeline.execute(strings(&["c"])).unwrap();

        assert_eq!(stats.batches_processed().unwrap(), 2);
        assert!(!stats.metadata().is_stateless);
        assert_eq!(
            stats.context_debug().unwrap(),
            "{processed: 3, output: 3, batches: 2, min: Some(1), max: 2}"
        );
    }

    #[test]
    fn occurrence_filter_counts_across_batches_and_within_one() {
        let actor = occurrence_filter_actor(2);
        assert_eq!(
            actor.process(strings(&["a", "b", "a"])).unwrap(),
            strings(&["a"])
        );
        assert_eq!(
            actor.process(strings(&["b", "c"])).unwrap(),
            strings(&["b"])
        );
    }
}
