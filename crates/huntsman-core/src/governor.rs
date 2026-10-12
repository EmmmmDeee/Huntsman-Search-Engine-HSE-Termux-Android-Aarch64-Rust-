//! Resource governor: a hard cap on concurrent sockets and per-host dispatch pacing.
//!
//! A Termux process runs under a small file-descriptor limit, and the public resolvers and
//! targets it interrogates rate-limit, ban or answer `REFUSED` to a source that hammers them.
//! The governor keeps the engine inside both budgets: a semaphore bounds the sockets open at
//! once, and a pacing table spaces the dispatches to any single host by at least the
//! configured cooldown.

use crate::error::HuntsmanError;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::{Duration, Instant};

/// Upper bound on hosts with a live pacing entry. Entries whose cooldown has elapsed pace
/// nothing and are evicted first; only when more hosts than this are paced at the same time
/// are the entries closest to expiry dropped early, so the table never outgrows a few hundred
/// kilobytes however many hosts a scan touches.
const MAX_PACED_HOSTS: usize = 1024;

/// Configuration parameters for mobile runtime throttling.
#[derive(Debug, Clone)]
pub struct GovernorConfig {
    /// Hard cap on concurrent outbound sockets (FD protection on Termux).
    pub max_active_sockets: usize,
    /// Minimum spacing between two dispatches to the same host through
    /// [`NetworkGovernor::acquire_host_permit`]. Zero disables pacing.
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

/// Per-host dispatch schedule: the latest dispatch instant reserved for each host.
///
/// A caller reserves the next slot for its host, at least one cooldown after the previous
/// slot and never in the past, and sleeps until it. Reservations are made under the lock and
/// slept on outside it, so concurrent callers for one host line up at cooldown spacing with
/// no lock held across an await.
#[derive(Debug, Default)]
struct HostPacing {
    reserved: HashMap<String, Instant>,
}

impl HostPacing {
    /// Reserve the next dispatch slot for `host` given the current time and the cooldown.
    fn reserve(&mut self, host: &str, now: Instant, cooldown: Duration) -> Instant {
        // Case-insensitive so `Resolver.Example` and `resolver.example` share one budget.
        let key = host.to_ascii_lowercase();
        if !self.reserved.contains_key(&key) && self.reserved.len() >= MAX_PACED_HOSTS {
            self.make_room(now, cooldown);
        }
        let slot = match self.reserved.get(&key) {
            // A cooldown too large for the clock cannot pace; dispatch now rather than never.
            Some(last) => last.checked_add(cooldown).map_or(now, |next| next.max(now)),
            None => now,
        };
        self.reserved.insert(key, slot);
        slot
    }

    /// Drop entries whose cooldown has elapsed, then, if the table is still full, the entries
    /// whose cooldown ends soonest, until one more host fits.
    fn make_room(&mut self, now: Instant, cooldown: Duration) {
        self.reserved
            .retain(|_, slot| now.saturating_duration_since(*slot) < cooldown);
        let excess = (self.reserved.len() + 1).saturating_sub(MAX_PACED_HOSTS);
        if excess == 0 {
            return;
        }
        let mut soonest: Vec<(Instant, String)> = self
            .reserved
            .iter()
            .map(|(host, slot)| (*slot, host.clone()))
            .collect();
        soonest.sort_unstable();
        for (_, host) in soonest.into_iter().take(excess) {
            self.reserved.remove(&host);
        }
    }
}

/// Socket quota and per-host pacing governor ensuring Termux stability without LMK/OOM
/// triggers or remote rate-limit bans.
#[derive(Clone)]
pub struct NetworkGovernor {
    semaphore: Arc<Semaphore>,
    config: GovernorConfig,
    pacing: Arc<Mutex<HostPacing>>,
}

impl NetworkGovernor {
    /// Initialize the governor with hard concurrency bounds.
    #[must_use]
    pub fn new(config: GovernorConfig) -> Self {
        let semaphore = Arc::new(Semaphore::new(config.max_active_sockets));
        Self {
            semaphore,
            config,
            pacing: Arc::new(Mutex::new(HostPacing::default())),
        }
    }

    /// Acquire a socket lease. Returns an RAII permit that releases the FD count upon drop.
    ///
    /// This applies no per-host pacing; it is for callers that pace elsewhere. A dialogue
    /// with a named host should use [`Self::acquire_host_permit`].
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

    /// Acquire a socket lease for a dialogue with `host`, paced so that consecutive dispatches
    /// to that host are at least [`GovernorConfig::per_host_cooldown`] apart.
    ///
    /// The socket permit is taken first, then the next dispatch slot for `host` is reserved
    /// (one cooldown after the previous slot, or now) and awaited. Concurrent callers for one
    /// host therefore dispatch in reservation order at cooldown spacing, while callers for
    /// different hosts never wait on each other. The permit is held while waiting, so the
    /// socket budget is honoured even when a burst targets a single host. `host` is matched
    /// case-insensitively.
    ///
    /// The pacing table is bounded to 1024 live hosts: entries whose cooldown has elapsed are
    /// evicted first, and only beyond that are the entries closest to expiry dropped early.
    ///
    /// # Errors
    /// Returns [`HuntsmanError::RateLimited`] if the governor semaphore has been closed.
    pub async fn acquire_host_permit(
        &self,
        host: &str,
    ) -> Result<OwnedSemaphorePermit, HuntsmanError> {
        let permit = self.acquire_socket_permit().await?;
        let cooldown = self.config.per_host_cooldown;
        if cooldown.is_zero() {
            return Ok(permit);
        }
        let slot = self
            .pacing
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .reserve(host, Instant::now(), cooldown);
        tokio::time::sleep_until(slot).await;
        Ok(permit)
    }

    /// Get the configured per-host delay.
    #[must_use]
    pub fn cooldown_duration(&self) -> Duration {
        self.config.per_host_cooldown
    }

    /// Number of hosts with a pacing entry, for verifying the table bound.
    #[cfg(test)]
    fn paced_hosts(&self) -> usize {
        self.pacing
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .reserved
            .len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn governor(cooldown: Duration, sockets: usize) -> NetworkGovernor {
        NetworkGovernor::new(GovernorConfig {
            max_active_sockets: sockets,
            per_host_cooldown: cooldown,
        })
    }

    async fn dispatch(governor: &NetworkGovernor, host: &str) -> Instant {
        match governor.acquire_host_permit(host).await {
            Ok(_permit) => Instant::now(),
            Err(err) => panic!("acquire_host_permit({host}) failed: {err}"),
        }
    }

    #[tokio::test(start_paused = true)]
    async fn consecutive_dispatches_to_one_host_are_spaced_by_the_cooldown() {
        let cooldown = Duration::from_millis(250);
        let governor = governor(cooldown, 4);

        let first = dispatch(&governor, "1.1.1.1").await;
        let second = dispatch(&governor, "1.1.1.1").await;
        let third = dispatch(&governor, "1.1.1.1").await;

        assert!(second - first >= cooldown, "{:?}", second - first);
        assert!(third - second >= cooldown, "{:?}", third - second);
    }

    #[tokio::test(start_paused = true)]
    async fn different_hosts_do_not_wait_on_each_other() {
        let governor = governor(Duration::from_millis(250), 4);

        let start = Instant::now();
        dispatch(&governor, "1.1.1.1").await;
        dispatch(&governor, "8.8.8.8").await;
        dispatch(&governor, "9.9.9.9").await;

        assert_eq!(Instant::now() - start, Duration::ZERO);
    }

    #[tokio::test(start_paused = true)]
    async fn a_dispatch_after_the_cooldown_has_already_elapsed_is_immediate() {
        let cooldown = Duration::from_millis(250);
        let governor = governor(cooldown, 4);

        dispatch(&governor, "1.1.1.1").await;
        tokio::time::advance(Duration::from_secs(1)).await;
        let before = Instant::now();
        let dispatched = dispatch(&governor, "1.1.1.1").await;

        assert_eq!(dispatched, before);
    }

    #[tokio::test(start_paused = true)]
    async fn concurrent_callers_for_one_host_serialise_at_cooldown_spacing() {
        let cooldown = Duration::from_millis(250);
        let governor = governor(cooldown, 8);
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();

        let mut tasks = Vec::new();
        for _ in 0..4 {
            let governor = governor.clone();
            let tx = tx.clone();
            tasks.push(tokio::spawn(async move {
                let at = dispatch(&governor, "resolver.example").await;
                if tx.send(at).is_err() {
                    panic!("dispatch channel closed");
                }
            }));
        }
        drop(tx);
        for task in tasks {
            if let Err(err) = task.await {
                panic!("dispatch task failed: {err}");
            }
        }

        let mut times = Vec::new();
        while let Some(at) = rx.recv().await {
            times.push(at);
        }
        times.sort_unstable();
        assert_eq!(times.len(), 4);
        for pair in times.windows(2) {
            assert!(pair[1] - pair[0] >= cooldown, "{:?}", pair[1] - pair[0]);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn host_pacing_is_case_insensitive() {
        let cooldown = Duration::from_millis(250);
        let governor = governor(cooldown, 4);

        let first = dispatch(&governor, "Resolver.Example").await;
        let second = dispatch(&governor, "resolver.example").await;

        assert!(second - first >= cooldown, "{:?}", second - first);
        assert_eq!(governor.paced_hosts(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn a_zero_cooldown_paces_and_tracks_nothing() {
        let governor = governor(Duration::ZERO, 4);

        let start = Instant::now();
        dispatch(&governor, "1.1.1.1").await;
        dispatch(&governor, "1.1.1.1").await;

        assert_eq!(Instant::now() - start, Duration::ZERO);
        assert_eq!(governor.paced_hosts(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn expired_entries_are_evicted_once_the_table_is_full() {
        let cooldown = Duration::from_millis(250);
        let governor = governor(cooldown, 4);

        for i in 0..MAX_PACED_HOSTS {
            dispatch(&governor, &format!("host{i}.example")).await;
        }
        assert_eq!(governor.paced_hosts(), MAX_PACED_HOSTS);

        tokio::time::advance(cooldown).await;
        dispatch(&governor, "one-more.example").await;

        assert_eq!(governor.paced_hosts(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn the_table_never_exceeds_the_bound_even_when_every_entry_is_live() {
        let cooldown = Duration::from_secs(60);
        let governor = governor(cooldown, 4);

        for i in 0..MAX_PACED_HOSTS + 200 {
            dispatch(&governor, &format!("host{i}.example")).await;
        }

        assert_eq!(governor.paced_hosts(), MAX_PACED_HOSTS);
        // The newest reservation survives eviction; an immediate repeat is still paced.
        let before = Instant::now();
        let again = dispatch(&governor, &format!("host{}.example", MAX_PACED_HOSTS + 199)).await;
        assert!(again - before >= cooldown, "{:?}", again - before);
    }

    #[tokio::test(start_paused = true)]
    async fn the_socket_budget_is_held_while_pacing() {
        let cooldown = Duration::from_millis(250);
        let governor = governor(cooldown, 1);

        let _first = match governor.acquire_host_permit("1.1.1.1").await {
            Ok(permit) => permit,
            Err(err) => panic!("first acquire failed: {err}"),
        };
        // The one permit is held, so a second caller cannot even begin to pace.
        let blocked = tokio::time::timeout(
            Duration::from_secs(5),
            governor.acquire_host_permit("8.8.8.8"),
        )
        .await;
        assert!(
            blocked.is_err(),
            "a second socket was granted past the budget"
        );
        assert_eq!(governor.cooldown_duration(), cooldown);
    }
}
