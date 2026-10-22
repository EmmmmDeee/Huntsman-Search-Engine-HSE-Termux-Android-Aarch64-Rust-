//! Shared bounded-execution limits for collection and pipeline composition.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PipelineLimits {
    pub max_targets: usize,
    pub max_entities: usize,
    pub max_relations: usize,
    pub max_dispatches: usize,
    pub max_response_bytes: usize,
    pub max_cross_scan_frontier: usize,
    pub max_cross_scan_visited: usize,
    pub max_generation: u32,
    pub max_export_bytes: usize,
}

impl Default for PipelineLimits {
    fn default() -> Self {
        Self {
            max_targets: 256,
            max_entities: 4096,
            max_relations: 8192,
            max_dispatches: 512,
            max_response_bytes: crate::http::DEFAULT_MAX_BODY,
            max_cross_scan_frontier: 128,
            max_cross_scan_visited: 512,
            max_generation: 4,
            max_export_bytes: 8 * 1024 * 1024,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_nonzero_and_bounded() {
        let limits = PipelineLimits::default();
        assert!(limits.max_targets > 0);
        assert!(limits.max_entities >= limits.max_targets);
        assert!(limits.max_relations >= limits.max_entities);
        assert!(limits.max_dispatches > 0);
        assert_eq!(limits.max_response_bytes, crate::http::DEFAULT_MAX_BODY);
    }

    /// Limits written while `max_archive_captures` existed still read, the old bound ignored.
    #[test]
    fn limits_written_with_the_archive_bound_still_read() {
        let mut json = serde_json::to_value(PipelineLimits::default()).unwrap();
        // Not the old default, so the field being read again would show.
        json["max_archive_captures"] = 1.into();
        assert_eq!(
            serde_json::from_value::<PipelineLimits>(json).unwrap(),
            PipelineLimits::default()
        );
    }
}
