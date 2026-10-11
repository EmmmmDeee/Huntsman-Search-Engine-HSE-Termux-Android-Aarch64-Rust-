//! Retry pacing, per-host circuit breaking, and bounded response caching.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackoffPolicy {
    pub max_attempts: u32,
    pub initial_backoff_ms: u64,
    pub max_backoff_ms: u64,
    pub jitter: bool,
}

impl BackoffPolicy {
    #[must_use]
    pub const fn new(
        max_attempts: u32,
        initial_backoff_ms: u64,
        max_backoff_ms: u64,
        jitter: bool,
    ) -> Self {
        Self {
            max_attempts,
            initial_backoff_ms,
            max_backoff_ms,
            jitter,
        }
    }

    #[must_use]
    pub const fn should_retry(&self, attempt: u32) -> bool {
        attempt + 1 < self.max_attempts
    }

    #[must_use]
    pub const fn base_delay_ms(&self, attempt: u32) -> u64 {
        let shift = if attempt > 31 { 31 } else { attempt };
        let scaled = self.initial_backoff_ms.saturating_mul(1_u64 << shift);
        if scaled > self.max_backoff_ms {
            self.max_backoff_ms
        } else {
            scaled
        }
    }

    #[must_use]
    pub fn delay(&self, attempt: u32) -> Duration {
        let base = self.base_delay_ms(attempt);
        if !self.jitter || base == 0 {
            return Duration::from_millis(base);
        }
        let spread = base / 4;
        let random = pseudo_random_u64(u64::from(attempt));
        let window = spread.saturating_mul(2).saturating_add(1);
        let millis = base.saturating_sub(spread).saturating_add(random % window);
        Duration::from_millis(millis)
    }
}

fn pseudo_random_u64(seed: u64) -> u64 {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let value = COUNTER.fetch_add(0x9e37_79b9_7f4a_7c15, Ordering::Relaxed) ^ seed;
    value.wrapping_mul(0xbf58_476d_1ce4_e5b9).rotate_left(17) ^ 0x94d0_49bb_1331_11eb
}

pub const FAILURE_THRESHOLD: u32 = 5;
pub const COOLDOWN_SECS: u64 = 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BreakerState {
    Closed,
    Open,
    HalfOpen,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Breaker {
    state: BreakerState,
    consecutive_failures: u32,
    retry_at: u64,
}

impl Default for Breaker {
    fn default() -> Self {
        Self {
            state: BreakerState::Closed,
            consecutive_failures: 0,
            retry_at: 0,
        }
    }
}

impl Breaker {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn state(&self) -> BreakerState {
        self.state
    }

    pub fn allow(&mut self, now: u64) -> bool {
        match self.state {
            BreakerState::Closed => true,
            BreakerState::Open | BreakerState::HalfOpen => {
                if now >= self.retry_at {
                    self.enter_half_open(now);
                    true
                } else {
                    false
                }
            }
        }
    }

    fn enter_half_open(&mut self, now: u64) {
        self.state = BreakerState::HalfOpen;
        self.retry_at = now.saturating_add(COOLDOWN_SECS);
    }

    pub fn on_success(&mut self) {
        self.state = BreakerState::Closed;
        self.consecutive_failures = 0;
        self.retry_at = 0;
    }

    pub fn on_failure(&mut self, now: u64) {
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        if self.state == BreakerState::HalfOpen || self.consecutive_failures >= FAILURE_THRESHOLD {
            self.open_from(now);
        }
    }

    pub fn on_rate_limited(&mut self, now: u64, retry_after_secs: u64) {
        self.state = BreakerState::Open;
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        self.retry_at = now.saturating_add(retry_after_secs.max(1));
    }

    fn open_from(&mut self, now: u64) {
        self.state = BreakerState::Open;
        self.retry_at = now.saturating_add(COOLDOWN_SECS);
    }
}

fn registry() -> &'static Mutex<HashMap<String, Breaker>> {
    static REGISTRY: OnceLock<Mutex<HashMap<String, Breaker>>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

#[must_use]
pub fn allow_host(host: &str, now: u64) -> bool {
    let mut guard = registry()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    guard.entry(host.to_string()).or_default().allow(now)
}

pub fn record_success(host: &str) {
    let mut guard = registry()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    guard.entry(host.to_string()).or_default().on_success();
}

pub fn record_failure(host: &str, now: u64) {
    let mut guard = registry()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    guard.entry(host.to_string()).or_default().on_failure(now);
}

pub fn record_rate_limited(host: &str, now: u64, retry_after_secs: u64) {
    let mut guard = registry()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    guard
        .entry(host.to_string())
        .or_default()
        .on_rate_limited(now, retry_after_secs);
}

#[must_use]
pub fn host_state(host: &str) -> Option<BreakerState> {
    let guard = registry()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    guard.get(host).map(Breaker::state)
}

#[must_use]
pub fn host_of(url: &str) -> Option<String> {
    let (_, rest) = url.split_once("://")?;
    let authority = rest.split(['/', '?', '#']).next().unwrap_or(rest);
    if authority.is_empty() {
        return None;
    }
    let authority = authority.rsplit('@').next().unwrap_or(authority);
    let host = if authority.starts_with('[') {
        let end = authority.find(']')?;
        &authority[..=end]
    } else {
        authority.split(':').next().unwrap_or(authority)
    };
    (!host.is_empty()).then(|| host.to_ascii_lowercase())
}

pub struct ResponseCache<T: Clone + Send + 'static> {
    inner: OnceLock<Mutex<HashMap<String, T>>>,
    cap: usize,
}

impl<T: Clone + Send + 'static> ResponseCache<T> {
    #[must_use]
    pub const fn new(cap: usize) -> Self {
        Self {
            inner: OnceLock::new(),
            cap,
        }
    }

    fn lock(&self) -> &Mutex<HashMap<String, T>> {
        self.inner
            .get_or_init(|| Mutex::new(HashMap::with_capacity(256.min(self.cap))))
    }

    pub fn get(&self, key: &str) -> Option<T> {
        self.lock()
            .lock()
            .ok()
            .and_then(|cache| cache.get(key).cloned())
    }

    pub fn put(&self, key: String, value: T) {
        let mut cache = self
            .lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if cache.len() < self.cap || cache.contains_key(&key) {
            cache.insert(key, value);
        }
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    #[must_use]
    pub fn capacity(&self) -> usize {
        self.cap
    }

    pub fn clear_prefix(&self, prefix: &str) {
        self.lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .retain(|key, _| !key.starts_with(prefix));
    }

    pub fn clear(&self) {
        self.lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const T0: u64 = 1_000_000;

    #[test]
    fn backoff_doubles_caps_and_jitters() {
        let policy = BackoffPolicy::new(3, 2_000, 8_000, false);
        assert!(policy.should_retry(0));
        assert!(!policy.should_retry(2));
        assert_eq!(policy.base_delay_ms(0), 2_000);
        assert_eq!(policy.base_delay_ms(10), 8_000);
        assert_eq!(policy.delay(1), Duration::from_secs(4));

        let jittered = BackoffPolicy::new(3, 4_000, 8_000, true);
        let first = jittered.delay(0);
        assert!((0..100).any(|_| jittered.delay(0) != first));
    }

    #[test]
    fn breaker_transitions_and_registry_work() {
        let mut breaker = Breaker::new();
        for _ in 0..FAILURE_THRESHOLD {
            breaker.on_failure(T0);
        }
        assert_eq!(breaker.state(), BreakerState::Open);
        assert!(!breaker.allow(T0));
        assert!(breaker.allow(T0 + COOLDOWN_SECS));
        assert_eq!(breaker.state(), BreakerState::HalfOpen);
        breaker.on_success();
        assert_eq!(breaker.state(), BreakerState::Closed);

        let host = "cb-test.example";
        record_rate_limited(host, T0, 90);
        assert!(!allow_host(host, T0 + 89));
        assert!(allow_host(host, T0 + 90));
        assert_eq!(host_state(host), Some(BreakerState::HalfOpen));
    }

    #[test]
    fn host_parser_and_response_cache_are_stable() {
        assert_eq!(
            host_of("https://Example.COM/path?q=1"),
            Some("example.com".to_string())
        );
        assert_eq!(
            host_of("http://[2001:db8::1]/y"),
            Some("[2001:db8::1]".to_string())
        );
        assert_eq!(host_of("not a url"), None);

        let cache: ResponseCache<u32> = ResponseCache::new(2);
        cache.put("a".into(), 1);
        cache.put("b".into(), 2);
        cache.put("c".into(), 3);
        assert_eq!(cache.len(), 2);
        assert_eq!(cache.get("c"), None);
        cache.put("a".into(), 9);
        assert_eq!(cache.get("a"), Some(9));
        cache.clear_prefix("a");
        assert_eq!(cache.get("a"), None);
    }
}
