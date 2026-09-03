//! Crash-safe persistence for intelligence frontier checkpoints.

use std::path::Path;

use crate::core::intelligence::{BoundedFrontier, CheckpointError};

impl BoundedFrontier {
    /// Crash-safe Termux-compatible checkpoint: serialize, fsync a private
    /// sibling temp file, atomically rename, then fsync the parent directory.
    pub fn save_checkpoint(&self, path: &Path) -> Result<(), CheckpointError> {
        let bytes = serde_json::to_vec(self)?;
        crate::util::atomic_file::write(path, &bytes)?;
        Ok(())
    }

    pub fn load_checkpoint(path: &Path) -> Result<Self, CheckpointError> {
        let bytes = std::fs::read(path)?;
        let checkpoint: Self = serde_json::from_slice(&bytes)?;
        if !checkpoint.checkpoint_is_valid() {
            return Err(CheckpointError::InvalidBudget);
        }
        Ok(checkpoint)
    }
}
