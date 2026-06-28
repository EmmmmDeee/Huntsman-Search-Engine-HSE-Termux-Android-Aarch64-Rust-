//! In-memory rotating proxy pool.
//!
//! [`ProxyPool`] is a thread-safe, round-robin holder of validated [`Proxy`]
//! entries that is constructed once per scan and carried on
//! [`crate::core::module::ModuleContext`]. A populated pool lets a module rotate
//! egress paths via [`ProxyPool::next`]; an empty pool (the default) simply
//! yields `None`, so callers fall through to a direct connection.
//!
//! Egress configuration today is operator-driven, not auto-harvested: a fetch
//! consults the `HUNTSMAN_SEARCH_PROXY` list (rotated round-robin in
//! `util::curl::rotating_search_proxy`). No live free-proxy harvesting /
//! validation runs — that network-spawning surface (and its SSRF blast radius on
//! an unprivileged Termux device) was removed rather than carried unwired. To
//! populate the pool from a vetted source, build [`Proxy`] entries and hand them
//! to [`ProxyPool::replace`].

use parking_lot::Mutex;

/// A proxy entry held in a [`ProxyPool`].
///
/// `proto` is `&'static str` (`"http"` / `"socks5"`) so a populated pool can mix
/// schemes; [`Proxy::url`] renders the scheme-qualified URL a fetcher feeds to
/// `curl -x`. `latency_ms` is the measured round-trip a populator records so the
/// pool can be ordered fastest-first before [`ProxyPool::replace`].
#[derive(Debug, Clone)]
pub struct Proxy {
    pub addr: String,
    pub proto: &'static str,
    pub latency_ms: u64,
}

impl Proxy {
    pub fn url(&self) -> String {
        format!("{}://{}", self.proto, self.addr)
    }
}

/// Thread-safe proxy pool with round-robin selection.
pub struct ProxyPool {
    proxies: Mutex<Vec<Proxy>>,
    index: Mutex<usize>,
}

impl Default for ProxyPool {
    fn default() -> Self {
        Self::new()
    }
}

impl ProxyPool {
    pub fn new() -> Self {
        Self {
            proxies: Mutex::new(Vec::new()),
            index: Mutex::new(0),
        }
    }

    pub fn count(&self) -> usize {
        self.proxies.lock().len()
    }

    pub fn next(&self) -> Option<Proxy> {
        let proxies = self.proxies.lock();
        if proxies.is_empty() {
            return None;
        }
        let mut idx = self.index.lock();
        let proxy = proxies[*idx % proxies.len()].clone();
        *idx = idx.wrapping_add(1);
        Some(proxy)
    }

    /// Replace the pool contents and reset rotation to the head. A populator
    /// orders `new` fastest-first (by [`Proxy::latency_ms`]) so [`Self::next`]
    /// hands out the lowest-latency egress first.
    pub fn replace(&self, new: Vec<Proxy>) {
        let mut proxies = self.proxies.lock();
        *proxies = new;
        *self.index.lock() = 0;
    }
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
