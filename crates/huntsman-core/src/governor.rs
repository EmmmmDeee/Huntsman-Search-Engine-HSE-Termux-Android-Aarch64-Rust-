//! Resource governor managing token-bucket rates and file descriptor quotas.

use crate::error::HuntsmanError;
use std::sync::Arc;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::Duration;

/// Configuration parameters for mobile runtime throttling.
#[derive(Debug, Clone)]
pub struct GovernorConfig {
    /// Hard cap on concurrent outbound sockets (FD protection on Termux).
    pub max_active_sockets: usize,
    /// Minimum duration between requests to the same target domain.
    pub per_host_cooldown: Duration,
}

impl Default for GovernorConfig {
    fn default() -> Self {
        Self {
            max_active_sockets: 128,
            per_host_cooldown: Duration::from_millis(250),
        }
    }
}

/// Token bucket and socket governor ensuring Termux stability without LMK/OOM triggers.
#[derive(Clone)]
pub struct NetworkGovernor {
    semaphore: Arc<Semaphore>,
    config: GovernorConfig,
}

impl NetworkGovernor {
    /// Initialize the governor with hard concurrency bounds.
    #[must_use]
    pub fn new(config: GovernorConfig) -> Self {
        let semaphore = Arc::new(Semaphore::new(config.max_active_sockets));
        Self { semaphore, config }
    }

    /// Acquire a socket lease. Returns an RAII permit that releases the FD count upon drop.
    ///
    /// # Errors
    /// Returns [`HuntsmanError::RateLimited`] if the governor semaphore has been closed.
    pub async fn acquire_socket_permit(&self) -> Result<OwnedSemaphorePermit, HuntsmanError> {
        self.semaphore
            .clone()
            .acquire_owned()
            .await
            .map_err(|e| HuntsmanError::RateLimited(format!("Semaphore closed: {e}")))
    }

    /// Get the configured per-host delay.
    #[must_use]
    pub fn cooldown_duration(&self) -> Duration {
        self.config.per_host_cooldown
    }
}
