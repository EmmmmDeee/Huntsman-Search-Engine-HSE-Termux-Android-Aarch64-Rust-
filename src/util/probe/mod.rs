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
#[derive(Debug, Clone, PartialEq)]
pub enum ProbeResult {
    Found {
        /// The profile URL the site answered for.
        url: String,
        /// Confidence to stamp on the emitted `Url`, tiered by detection rigor.
        confidence: f64,
        /// True when corroborated by a body marker (vs. a bare status code).
        verified: bool,
        /// True when the same site answered *absence* for the control handle
        /// (see [`control_handle`]): its rule tells a held handle from an
        /// unheld one for this client, so this presence is not the site's
        /// answer for everything. False when the control could not be read.
        controlled: bool,
    },
    NotFound,
    Error,
    /// The site answered "present" for the control handle too. Its rule does
    /// not tell a held handle from an unheld one for this client — a
    /// single-page-app shell, a soft 404, a catch-all route, a login wall
    /// served as 200 — so its presence answer for the target is neither a
    /// presence nor an absence: never a profile, never a "not here".
    ///
    /// Observed 2026-09-15 from the project's sandbox: `username_search`
    /// reported 75 profiles for a twelve-character handle nobody holds, 74 of
    /// the same sites for a second such handle, and 78 of the 139 it reported
    /// for `torvalds` were among them — every username scan minted those
    /// "profiles" (two of them body-"verified") for any handle whatsoever.
    Indiscriminate {
        /// The URL the site answered "present" for — never emitted as a profile.
        url: String,
    },
    /// The site answered "present" for the target by status alone, and its
    /// answer for the control handle could not be read: the presence cannot
    /// be judged, so it is neither a profile nor an absence — counted and
    /// named in the summary, never minted. Observed 2026-09-15 from the
    /// project's sandbox by the sweep's known-negative control: Odysee
    /// answers `200` for any handle and NameMC sits behind a Cloudflare
    /// challenge, and a status-only presence whose control read had failed
    /// stood as a `weak-detection` profile for a handle nobody holds — the
    /// residual REQ-PROBE-001 had accepted. A body-verified presence carries
    /// its own evidence and stands without a control, flagged.
    Uncontrolled {
        /// The URL the site answered "present" for — never emitted as a profile.
        url: String,
    },
}

/// The handle every presence claim is judged against: a string no platform
/// holds, drawn once per process — twelve lowercase letters and digits from
/// the process's random hasher keys, opening with a letter so every site's
/// handle rule accepts it. A site that answers "present" for it cannot tell
/// a held handle from an unheld one for this client (see
/// [`ProbeResult::Indiscriminate`]).
pub fn control_handle() -> &'static str {
    static HANDLE: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    HANDLE.get_or_init(|| nonce_handle(0))
}

/// A second handle nobody holds, drawn once per process and never equal to
/// [`control_handle`]: the target the capability sweep's known-negative
/// controls probe a module with. It must differ from the probes' own control
/// handle — a presence probe judges every presence against
/// [`control_handle`], so a target equal to it would be judged indiscriminate
/// by construction and the control would prove nothing.
pub fn sweep_control_handle() -> &'static str {
    static HANDLE: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    HANDLE.get_or_init(|| {
        let mut handle = nonce_handle(1);
        if handle == control_handle() {
            // Distinct by construction, whatever the hasher keys: rotate the
            // opening letter.
            let first = handle.remove(0);
            let next = if first == 'z' {
                'a'
            } else {
                (first as u8 + 1) as char
            };
            handle.insert(0, next);
        }
        handle
    })
}

/// Twelve lowercase letters and digits from the process's random hasher keys,
/// the process id and `salt`, opening with a letter so every site's handle
/// rule accepts it.
fn nonce_handle(salt: u32) -> String {
    use std::hash::{BuildHasher, Hasher};
    let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
    hasher.write_u32(std::process::id());
    hasher.write_u32(salt);
    let mut n = hasher.finish();
    const LETTERS: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
    const ALNUM: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let mut handle = String::with_capacity(12);
    handle.push(LETTERS[(n % 26) as usize] as char);
    n /= 26;
    for _ in 0..11 {
        handle.push(ALNUM[(n % 36) as usize] as char);
        n /= 36;
    }
    handle
}

/// A site's answer for the target, judged against its answer for the control
/// handle on the same site. A presence the site also gave the control handle
/// is [`ProbeResult::Indiscriminate`]; a presence the site denied the control
/// handle stands, `controlled`; a presence whose control could not be read
/// is [`ProbeResult::Uncontrolled`] when it rests on the status alone (it
/// cannot be judged, so it is never a profile) and stands uncontrolled when
/// the body verified it (its own evidence, flagged). Anything but a presence
/// is unchanged — an absence or a refusal needs no control.
#[must_use]
pub fn controlled(target: ProbeResult, control: &ProbeResult) -> ProbeResult {
    match (target, control) {
        (
            ProbeResult::Found { url, .. },
            ProbeResult::Found { .. } | ProbeResult::Indiscriminate { .. },
        ) => ProbeResult::Indiscriminate { url },
        (
            ProbeResult::Found {
                url,
                confidence,
                verified,
                ..
            },
            ProbeResult::NotFound,
        ) => ProbeResult::Found {
            url,
            confidence,
            verified,
            controlled: true,
        },
        (
            ProbeResult::Found {
                url,
                verified: false,
                ..
            },
            ProbeResult::Error,
        ) => ProbeResult::Uncontrolled { url },
        (
            ProbeResult::Found {
                url,
                confidence,
                verified,
                ..
            },
            ProbeResult::Error,
        ) => ProbeResult::Found {
            url,
            confidence,
            verified,
            controlled: false,
        },
        (other, _) => other,
    }
}

/// Judge every presence in `first` against the control handle: for each
/// [`ProbeResult::Found`], `control(site)` names the control URL and yields
/// the probe of it, the answers run concurrently, and [`controlled`] is
/// applied. A control answer is remembered per URL for the process, so a
/// multi-target scan asks each site about the control handle once.
///
/// A control probe that FAILED is not remembered — see the insert below. The
/// cache is still process-lifetime for successful answers, which is correct
/// within one scan and stale across scans in a long-lived `hse serve` process;
/// scoping it to a scan is tracked separately (REQ-PROBE-005).
pub async fn control_presences<S, Fut>(
    first: Vec<(S, ProbeResult)>,
    control: impl Fn(S) -> (String, Fut),
) -> Vec<(S, ProbeResult)>
where
    S: Copy,
    Fut: std::future::Future<Output = ProbeResult>,
{
    static ANSWERS: std::sync::OnceLock<
        std::sync::Mutex<std::collections::HashMap<String, ProbeResult>>,
    > = std::sync::OnceLock::new();
    let answers = ANSWERS.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()));

    let mut pending = Vec::new();
    for (site, result) in &first {
        if !matches!(result, ProbeResult::Found { .. }) {
            continue;
        }
        let (url, probe) = control(*site);
        let remembered = answers.lock().map_or(None, |a| a.get(&url).cloned());
        pending.push(async move {
            let answer = match remembered {
                Some(answer) => answer,
                None => probe.await,
            };
            (url, answer)
        });
    }
    let read: Vec<(String, ProbeResult)> = futures::future::join_all(pending).await;
    if let Ok(mut a) = answers.lock() {
        for (url, answer) in &read {
            // A FAILED control probe is not an answer, so it is not remembered.
            //
            // `controlled()` turns a `Found` judged against an `Error` control
            // into `Uncontrolled`, or into `Found { controlled: false }` — the
            // field's own doc says "False when the control could not be read".
            // Caching that verdict made one transient network error mark every
            // future presence on the site uncontrolled for the life of the
            // process, which under `hse serve` is indefinitely. The site is
            // simply re-asked next time (REQ-PROBE-005).
            //
            // This is the doctrine `core::coverage::ProviderOutcome` states one
            // layer up — PROVIDER FAILURE != ZERO EVIDENCE — applied to the
            // cache that decides whether a presence can be confirmed.
            if matches!(answer, ProbeResult::Error) {
                continue;
            }
            a.insert(url.clone(), answer.clone());
        }
    }
    let mut read = read.into_iter();
    first
        .into_iter()
        .map(|(site, result)| {
            if matches!(result, ProbeResult::Found { .. }) {
                let (_, answer) = read.next().expect("one control answer per presence");
                (site, controlled(result, &answer))
            } else {
                (site, result)
            }
        })
        .collect()
}

/// Classify a response status that did **not** match a site's declared presence
/// code into the outcome it actually supports.
///
/// The probe modules previously had no such step: anything other than
/// `status == want` became [`ProbeResult::NotFound`], so a Cloudflare `403`, a
/// `429` rate-limit and a `503` outage were each recorded as a *definitive*
/// "this handle does not exist on this platform". Those runs then fed
/// `definitive_absent`, and [`inconclusive`] — the guard that exists precisely
/// to stop a blocked sweep being read as a confirmed absence — never saw them.
/// A fully WAF-blocked sweep reported a clean, confident zero.
///
/// The rule, given the site's own equality check has already failed:
///
/// * `404` / `410` — the web's actual absence answers. Definitive.
/// * `2xx` — the origin answered successfully, just not with this site's
///   presence code. Definitive: the platform served us a page about this
///   handle and it was not a profile.
/// * everything else — `401`/`403` (login wall, WAF), `405` (refuses HEAD),
///   `408`/`429` (timeout, throttle), `451`, every `5xx`, any surfacing `3xx`
///   (the client follows redirects, so one reaching here means the SSRF guard
///   declined it) and every `1xx` — established nothing about the handle.
///   Inconclusive.
///
/// **Ordering matters**: this is consulted only *after* `status == want` has
/// failed, so a site whose declared presence signal is itself a `403` or `404`
/// never has that code reinterpreted here.
///
/// Pure, so the policy is verifiable without a network.
#[must_use]
pub fn classify_non_matching_status(status: u16) -> ProbeResult {
    match status {
        404 | 410 => ProbeResult::NotFound,
        200..=299 => ProbeResult::NotFound,
        _ => ProbeResult::Error,
    }
}

/// What a site's 2xx body says about the handle, once the status already
/// matched the site's presence code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PageVerdict {
    /// The body is an anti-bot challenge / WAF block page served with the
    /// presence status — the platform never showed us a page about this
    /// handle. Neither presence nor absence: inconclusive.
    Wall,
    /// The page is the site's own and its marker says the profile exists.
    Present,
    /// The page is the site's own and its marker says the profile does not.
    Absent,
}

/// Read a site's body-marker rule against a 2xx body.
///
/// `needle_means_present` is the rule's polarity: `true` for a
/// `StatusAndBody` site (the profile page carries the marker), `false` for a
/// `StatusAndNotBody` site (every URL 200s and the *missing* profile carries
/// the marker). A wall is judged first, for either polarity: a Cloudflare
/// interstitial served with 200 carries no site marker at all, so under the
/// old needle-only reading it was a **verified presence** on every
/// `StatusAndNotBody` site and a definitive absence on every `StatusAndBody`
/// site — the `social_probe` defect (REQ-SOCIAL-001) in its status-200 form.
/// [`crate::util::html::is_challenge_document`] is the one predicate.
#[must_use]
pub fn classify_page(body: &str, needle: &str, needle_means_present: bool) -> PageVerdict {
    if crate::util::html::is_challenge_document(body) {
        return PageVerdict::Wall;
    }
    if body.contains(needle) == needle_means_present {
        PageVerdict::Present
    } else {
        PageVerdict::Absent
    }
}

/// The zero-hit verdict once the control wave has run. An indiscriminate site
/// is neither an answer nor a failure — its rule tells nothing about any
/// handle for this client — so it leaves the sweep's decision capacity
/// instead of counting as blocked: [`inconclusive`] is judged over the sites
/// that can tell, and a run in which no site could tell is inconclusive.
/// Counting the indiscriminate sites as blocked made a handle nobody holds
/// read "inconclusive: 20/43 platform probes were blocked" on
/// `streaming_probe` (11 indiscriminate + 9 refusals) where 23 sites had
/// answered absent.
#[must_use]
pub fn inconclusive_after_control(
    found: usize,
    errored: usize,
    indiscriminate: usize,
    total: usize,
) -> bool {
    let telling = total.saturating_sub(indiscriminate);
    if found == 0 && total > 0 && telling == 0 {
        return true;
    }
    inconclusive(found, errored, telling)
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
