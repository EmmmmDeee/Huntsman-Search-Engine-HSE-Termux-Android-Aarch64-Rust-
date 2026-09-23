//! Shared concurrent-resolution primitive for `dns_intel`'s two hostname-
//! candidate enumeration passes: the static-dictionary brute force
//! ([`super::brute`]) and the structural permutation sweep ([`super::permute`]).
//! Both reduce to the same shape — "resolve a batch of candidate hostnames,
//! bounded-concurrency, keep only the ones that answer, report deterministically"
//! — so this is the ONE implementation both call (Rule 4: delegate, never
//! duplicate) rather than each hand-rolling its own `JoinSet`/`Semaphore`/sort.

use std::collections::BTreeSet;
use std::sync::Arc;

use tokio::sync::Semaphore;

use super::wildcard::{Wildcard, is_wildcard_noise};
use crate::core::module::{ModuleContext, ModuleResult};
use crate::util::dns::shared_resolver;

/// A resolved hostname candidate: `(host, comma-joined resolved IPs, IP count)`.
pub(super) type ResolvedHost = (String, String, usize);

/// Resolve every `candidates` hostname concurrently (bounded to `max_concurrent`
/// in flight), keep only the ones with at least one A/AAAA record that is NOT
/// indistinguishable from `wildcard_fingerprint`'s catch-all noise (`None` when
/// the caller's zone has no stable catch-all to filter, see
/// [`Wildcard::fingerprint`]; what a wildcard leaves reportable is
/// [`reportable_hits`]'s decision), and return them sorted by
/// hostname for deterministic output regardless of DNS completion order —
/// `join_next()` yields in network-completion order (nondeterministic
/// run-to-run), so this collects first and sorts after, matching the
/// fixed-order resolution every other dns_intel pass produces.
///
/// Also returns how many lookups **failed** — SERVFAIL, REFUSED, a timeout —
/// which, unlike "no such name", establish nothing about the name
/// ([`outcome`]). [`reportable_hits`] declares them.
pub(super) async fn resolve_hosts_concurrently(
    candidates: Vec<String>,
    max_concurrent: usize,
    wildcard_fingerprint: Option<Arc<BTreeSet<String>>>,
    _ctx: &ModuleContext,
) -> (Vec<ResolvedHost>, usize) {
    let resolver = shared_resolver();
    // Clamp the concurrency floor to 1: `Semaphore::new(0)` hands out no permits,
    // so every spawned task would await `acquire_owned()` forever and `join_next()`
    // would never complete — a hang. Callers pass a fixed non-zero constant today,
    // but this is a shared primitive, so guard the invariant here rather than
    // trusting every present and future caller.
    let sem = Arc::new(Semaphore::new(max_concurrent.max(1)));
    let mut set = tokio::task::JoinSet::new();

    for host in candidates {
        let sem = Arc::clone(&sem);
        let fingerprint = wildcard_fingerprint.clone();
        set.spawn(async move {
            let Ok(_permit) = sem.acquire_owned().await else {
                return Outcome::Failed;
            };
            let lookup = resolver.lookup_ip(host.as_str()).await;
            outcome(host, lookup, fingerprint.as_deref())
        });
    }

    let mut outcomes = Vec::new();
    while let Some(joined) = set.join_next().await {
        outcomes.push(joined.ok());
    }
    tally(outcomes)
}

/// The batch's hits, sorted by hostname, and its failed lookups. **Pure.** A
/// task that died (`None`) asked nothing, so it counts as a failure too.
pub(super) fn tally(
    outcomes: impl IntoIterator<Item = Option<Outcome>>,
) -> (Vec<ResolvedHost>, usize) {
    let mut hits: Vec<ResolvedHost> = Vec::new();
    let mut failed = 0usize;
    for o in outcomes {
        match o {
            Some(Outcome::Hit(hit)) => hits.push(hit),
            Some(Outcome::Miss) => {}
            Some(Outcome::Failed) | None => failed += 1,
        }
    }
    hits.sort_unstable_by(|a, b| a.0.cmp(&b.0));
    (hits, failed)
}

/// What one candidate lookup established. **Pure.** The candidate's reading of
/// the three answers the wildcard canaries already tell apart
/// (`wildcard::canary`): a record of its own; none (no such name, or only the
/// catch-all's noise); or a lookup that FAILED. Folding the last into the
/// second is what let a pass whose resolver was failing read as "no
/// subdomains" (REQ-DNSINTEL-003 review round).
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Outcome {
    Hit(ResolvedHost),
    Miss,
    Failed,
}

/// Read one candidate's lookup against the catch-all `fingerprint`. **Pure.**
pub(super) fn outcome(
    host: String,
    lookup: std::result::Result<
        hickory_resolver::lookup_ip::LookupIp,
        hickory_resolver::net::NetError,
    >,
    fingerprint: Option<&BTreeSet<String>>,
) -> Outcome {
    match lookup {
        Ok(found) => {
            let ip_set: BTreeSet<String> = found.iter().map(|ip| ip.to_string()).collect();
            if ip_set.is_empty() || fingerprint.is_some_and(|fp| is_wildcard_noise(&ip_set, fp)) {
                return Outcome::Miss;
            }
            let count = ip_set.len();
            let joined = ip_set.into_iter().collect::<Vec<_>>().join(", ");
            Outcome::Hit((host, joined, count))
        }
        Err(e) if e.is_no_records_found() => Outcome::Miss,
        Err(_) => Outcome::Failed,
    }
}

/// The `hits` a hostname-enumeration pass over `candidates` names under `zone`
/// may report: all of them, or — when `zone`'s wildcard leaves them
/// indistinguishable from its own answer
/// ([`Wildcard::leaves_hits_distinguishable`]) — none, declared on `result`
/// through [`ModuleResult::mark_truncated`] so the withheld pass reads as
/// incomplete rather than as "no subdomains". Shared by the brute-force and
/// permutation passes, which face the same wildcard. Pure.
///
/// A pass whose lookups `failed` (see [`outcome`]) is partial, and one where
/// every candidate failed is no answer at all: either is declared, never read as
/// "no subdomains". The wildcard verdict comes first — it withholds everything.
pub(super) fn reportable_hits(
    zone: &str,
    wildcard: &Wildcard,
    candidates: usize,
    hits: Vec<ResolvedHost>,
    failed: usize,
    result: &mut ModuleResult,
) -> Vec<ResolvedHost> {
    if wildcard.leaves_hits_distinguishable(hits.len(), candidates) {
        if failed > 0 {
            result.mark_truncated(
                hits.len(),
                None,
                &format!(
                    "{failed} of {candidates} candidate lookups under {zone} failing (SERVFAIL, \
                     REFUSED or a timeout), which establish nothing about those names"
                ),
            );
        }
        return hits;
    }
    result.mark_truncated(
        0,
        None,
        &format!(
            "the wildcard DNS record on {zone}, which answers for names that do not exist: {} of \
             {candidates} candidate subdomains resolved and none can be told apart from it",
            hits.len()
        ),
    );
    Vec::new()
}
