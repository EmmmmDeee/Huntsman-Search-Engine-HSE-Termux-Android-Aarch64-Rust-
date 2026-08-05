//! Shared primitives for the parallel HTTP existence-probe modules.
//!
//! The Maigret/Sherlock-style enumerators — [`crate::modules::username_search`]
//! and [`crate::modules::streaming_probe`] — fan a handle out across a static
//! site table with reqwest, each probe bounded by a per-site timeout under a
//! shared semaphore. They had independently grown byte-identical copies of the
//! same plumbing: the [`ProbeResult`] outcome enum, the [`WithSite`] adapter that
//! tags each probe future with its site name + category, the [`inconclusive`]
//! zero-hit disambiguation, and the browser-shaped request headers. This module
//! owns that one copy so the two enumerators — and any third — share it.
//!
//! The confidence tiering a hit earns lives separately in
//! [`crate::util::probe_confidence`]; it is keyed on each module's own
//! detection-rule type, so it stays a thin per-module wrapper over that shared
//! function rather than moving here.

/// Browser-shaped `User-Agent` for the per-site probes.
///
/// Cloudflare / PerimeterX / Akamai-fronted platforms score the tool-shaped
/// default UA (`huntsman-search-engine/x.y.z`) as a bot and 403 it, masking real
/// hits as errors on ~30% of a typical site table. Sending a real Chrome-on-
/// Android UA (matching the `util::curl_client` fingerprint the paid OSINT
/// modules use) restores the hit rate.
pub const BROWSER_UA: &str = crate::util::curl::UA_MOBILE;

/// `Accept` header matching what a browser sends. Some WAFs (notably Akamai Bot
/// Manager) score a bare `accept: */*` as suspicious.
pub const BROWSER_ACCEPT: &str = "text/html,application/xhtml+xml,application/xml;\
    q=0.9,image/avif,image/webp,*/*;q=0.8";

/// Cap on each profile-probe body read, so a hostile site can't OOM the
/// concurrent fan-out. 256 KiB is far more than any existence-marker check needs.
pub const BODY_PROBE_CAP: usize = 256 * 1024;

/// The outcome of one site probe.
///
/// `Found` carries the confidence to stamp on the emitted `Url` (tiered by how
/// rigorously the site's rule corroborated existence — see
/// [`crate::util::probe_confidence`]) and whether a body marker confirmed it
/// (`verified`) versus a bare status code. `NotFound` is a definitive absence;
/// `Error` is inconclusive (blocked / unreachable / timed out) — the two are
/// kept distinct so a mostly-blocked run is not reported as a confirmed absence
/// (see [`inconclusive`]).
pub enum ProbeResult {
    Found {
        url: String,
        /// Confidence to stamp on the emitted `Url`, tiered by detection rigor.
        confidence: f64,
        /// True when corroborated by a body marker (vs. a bare status code).
        verified: bool,
    },
    NotFound,
    Error,
}

/// True when a zero-hit run is *inconclusive* rather than a confirmed absence:
/// nothing was found AND at least half the probes were blocked or unreachable,
/// so most sites never gave a definitive answer. Pure, so the M6 disambiguation
/// policy ("`found == 0` must not conflate 'absent' with 'couldn't tell'") is
/// verifiable without the network.
#[must_use]
pub fn inconclusive(found: usize, errored: usize, total: usize) -> bool {
    found == 0 && total > 0 && errored * 2 >= total
}

/// Pair a probe future's outcome with its site name + category for the consumer
/// loop, without cloning the `&'static str`s into the async block.
///
/// Blanket-implemented for every `Future<Output = ProbeResult>`, so a probe
/// built inline as `async move { … }` gets `.then_with_site(name, cat)` in scope
/// simply by importing this trait.
pub trait WithSite: Sized + std::future::Future<Output = ProbeResult> {
    fn then_with_site(
        self,
        name: &'static str,
        cat: &'static str,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = (&'static str, &'static str, ProbeResult)> + Send>,
    >
    where
        Self: Send + 'static,
    {
        Box::pin(async move {
            let out = self.await;
            (name, cat, out)
        })
    }
}

impl<F> WithSite for F where F: std::future::Future<Output = ProbeResult> + Send + 'static {}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
