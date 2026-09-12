//! Operator-health issue-classification policy — pure decision logic, no I/O
//! and no presentation.
//!
//! [`detect_issues`] turns primitive-only health signals ([`IssueInputs`])
//! into an ordered [`DetectedIssue`] list, and [`KeyPoolSummary`] is the
//! value-free per-service key-pool shape one of those signals is built from.
//! The sibling `system_debug` module gathers the live inputs, calls
//! [`detect_issues`], and renders the verdict as the bundle's headline
//! DETECTED ISSUES section via
//! [`render_system_debug_bundle`](super::system_debug::render_system_debug_bundle).
//!
//! Kept separate from presentation so "what counts as a problem" stays
//! unit-testable off plain literals.

/// A single automatically-detected problem for the bundle's headline DETECTED
/// ISSUES section — what makes the artifact *self*-diagnosing rather than a raw
/// dump. Ordered CRITICAL-first when rendered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DetectedIssue {
    /// [`SEV_CRITICAL`] (a hard failure that stops real work) or
    /// [`SEV_WARNING`] (a degradation worth investigating).
    pub severity: &'static str,
    pub category: &'static str,
    pub detail: String,
}

/// `"CRITICAL"` — a hard failure: a failed core self-test check, or missing
/// `curl` (which silently disables `search_engines`/`social_probe`/`oathnet`).
pub(crate) const SEV_CRITICAL: &str = "CRITICAL";
/// `"WARNING"` — a live degradation (a module/engine/scraper failing streak, a
/// silently-zero-yield source, a stored failed scan) that still leaves the
/// engine running.
pub(crate) const SEV_WARNING: &str = "WARNING";

/// Primitive-only inputs to [`detect_issues`], deliberately free of domain
/// structs so the "what counts as a problem" policy is unit-testable from
/// literals. The renderer does the trivial extraction from the live `Report`
/// and health snapshots.
pub(crate) struct IssueInputs<'a> {
    pub selftest_ok: bool,
    /// `(check name, detail)` for every self-test check that FAILED.
    pub selftest_failures: Vec<(&'a str, &'a str)>,
    pub curl_present: bool,
    /// `(module, consecutive_failures)` — live per-process failure streaks.
    pub unhealthy_modules: Vec<(&'a str, u32)>,
    pub engines_down: Vec<&'a str>,
    pub engines_blocked: Vec<&'a str>,
    /// `(module, consecutive_failures)` — cross-scan persisted hard-failure drift.
    pub scrapers_drifted: Vec<(&'a str, u32)>,
    /// modules whose recent completions all silently returned zero results.
    pub scrapers_yield_drifted: Vec<&'a str>,
    /// count of stored scans whose status is `failed`.
    pub failed_scans: usize,
    /// keyed-provider budgets whose daily/session quota is exhausted right now —
    /// the reason a keyed module returns nothing until the quota resets.
    pub quota_exhausted_providers: Vec<&'a str>,
    /// the self-update error message, if the update lifecycle is in its `Error`
    /// phase (a failed auto-update leaves the binary stale).
    pub update_error: Option<&'a str>,
    /// commits behind upstream (`Some(n>0)` ⇒ a newer build exists) — surfaced
    /// because a stale build may be reproducing already-fixed bugs.
    pub update_commits_behind: Option<u64>,
    /// `(service, total_keys)` for each configured service whose pooled keys are
    /// ALL non-active — its keyed modules return nothing silently.
    pub dead_key_services: Vec<(&'a str, usize)>,
    /// the first `PRAGMA integrity_check` problem row when the on-disk DB is
    /// corrupt (`None` ⇒ healthy `["ok"]`).
    pub db_integrity_issue: Option<&'a str>,
    /// whether the SQLite `-wal` sidecar has grown past the safe bound.
    pub wal_oversized: bool,
}

/// The `-wal` size (bytes) above which the write-ahead log is considered to be
/// running away — checkpointing has stalled and the sidecar is eating device
/// storage. 64 MiB: comfortably above a healthy transient WAL, well below a
/// level that matters on a phone.
///
/// Re-exported from `app::export` (Pass 28) so `app::doctor`'s own WAL check
/// shares this exact threshold instead of an independently-maintained inline
/// copy — the two happened to still agree (both `64 * 1024 * 1024`) when
/// this was found, but nothing had been keeping them that way.
pub(crate) const WAL_RUNAWAY_BYTES: u64 = 64 * 1024 * 1024;

/// Join every health signal into one worst-first problem list. **Pure** (no
/// I/O), so the classification policy is unit-testable off fixtures; a fully
/// healthy engine yields an empty vec (rendered as an explicit "no issues
/// auto-detected"). Deterministic ordering (severity, then category, then
/// detail) so two bundles over identical state produce an identical verdict.
pub(crate) fn detect_issues(inp: &IssueInputs) -> Vec<DetectedIssue> {
    let mut issues: Vec<DetectedIssue> = Vec::new();
    // A failed self-test check is the strongest signal — a fundamental
    // subsystem (registry / dispatch / core math / storage) is broken.
    if !inp.selftest_ok {
        for (name, detail) in &inp.selftest_failures {
            issues.push(DetectedIssue {
                severity: SEV_CRITICAL,
                category: "self-test",
                detail: format!("check `{name}` FAILED: {detail}"),
            });
        }
    }
    if !inp.curl_present {
        issues.push(DetectedIssue {
            severity: SEV_CRITICAL,
            category: "environment",
            detail: "curl is MISSING — search_engines/social_probe/oathnet return \
                     nothing; install with `pkg install curl`"
                .to_string(),
        });
    }
    for (name, streak) in &inp.unhealthy_modules {
        issues.push(DetectedIssue {
            severity: SEV_WARNING,
            category: "module-health",
            detail: format!(
                "module `{name}` has failed its last {streak} dispatch(es) this process"
            ),
        });
    }
    for name in &inp.engines_down {
        issues.push(DetectedIssue {
            severity: SEV_WARNING,
            category: "search-engine",
            detail: format!("search engine `{name}` is DOWN (unreachable)"),
        });
    }
    for name in &inp.engines_blocked {
        issues.push(DetectedIssue {
            severity: SEV_WARNING,
            category: "search-engine",
            detail: format!(
                "search engine `{name}` is BLOCKED (captcha / rate-limit / parser defect)"
            ),
        });
    }
    for (name, streak) in &inp.scrapers_drifted {
        issues.push(DetectedIssue {
            severity: SEV_WARNING,
            category: "scraper-drift",
            detail: format!(
                "source `{name}` has failed its last {streak} completion(s) across scans"
            ),
        });
    }
    for name in &inp.scrapers_yield_drifted {
        issues.push(DetectedIssue {
            severity: SEV_WARNING,
            category: "scraper-yield-drift",
            detail: format!(
                "source `{name}` completes without error but has silently stopped finding anything"
            ),
        });
    }
    if inp.failed_scans > 0 {
        issues.push(DetectedIssue {
            severity: SEV_WARNING,
            category: "scans",
            detail: format!(
                "{} stored scan(s) ended in `failed` — see the RECENT SCANS section for each error",
                inp.failed_scans
            ),
        });
    }
    for name in &inp.quota_exhausted_providers {
        issues.push(DetectedIssue {
            severity: SEV_WARNING,
            category: "provider-quota",
            detail: format!(
                "provider `{name}` quota is exhausted — its keyed modules return nothing until it resets"
            ),
        });
    }
    // A failed self-update leaves the binary stale — surface it loudly.
    if let Some(msg) = inp.update_error {
        issues.push(DetectedIssue {
            severity: SEV_CRITICAL,
            category: "update",
            detail: format!("self-update FAILED — the binary is stale: {msg}"),
        });
    }
    // Running behind upstream: a stale build may be reproducing bugs already
    // fixed in a newer release. Grounded in a real operator debug bundle whose
    // three module errors (`stackoverflow_user` invalid-filter, `bluesky_user`
    // 400-not-found, `see_know` `.icu` DNS) were each already fixed upstream —
    // the bundle just had no way to say "you are on an old build; update".
    if let Some(behind) = inp.update_commits_behind.filter(|n| *n > 0) {
        issues.push(DetectedIssue {
            severity: SEV_WARNING,
            category: "update",
            detail: format!(
                "build is {behind} commit(s) behind upstream — run `hse update`; module errors you are seeing may already be fixed in a newer build"
            ),
        });
    }
    // A configured service whose keys are ALL non-active (exhausted / invalid /
    // rate-limited / revoked) is the largest INVISIBLE failure class: the keyed
    // module returns `Ok(empty)` with no error and no failure streak (e.g.
    // `see_know` short-circuits on `is_key_invalid()`/exhausted budget), so it
    // never reaches the error-based health arms above — the pool is the only
    // place the silent death is visible.
    for (service, total) in &inp.dead_key_services {
        issues.push(DetectedIssue {
            severity: SEV_WARNING,
            category: "key-pool",
            detail: format!(
                "service `{service}`: all {total} pooled key(s) are non-active (exhausted/invalid/rate-limited/revoked) — its keyed modules return nothing silently; top up or rotate (`hse keys`)"
            ),
        });
    }
    // On-disk database corruption — the highest-severity, most-invisible signal:
    // the self-test only checks a throwaway temp DB, so a corrupt real store
    // never shows anywhere else.
    if let Some(issue) = inp.db_integrity_issue {
        issues.push(DetectedIssue {
            severity: SEV_CRITICAL,
            category: "storage",
            detail: format!(
                "database integrity check FAILED: {issue} — back up the DB and consider `hse` re-import; corruption silently loses/garbles stored findings"
            ),
        });
    }
    if inp.wal_oversized {
        issues.push(DetectedIssue {
            severity: SEV_WARNING,
            category: "storage",
            detail:
                "the SQLite -wal sidecar has grown past 64 MiB — checkpointing appears stalled; it will keep eating device storage until the process cleanly closes the DB"
                    .to_string(),
        });
    }
    issues.sort_by(|a, b| {
        severity_rank(a.severity)
            .cmp(&severity_rank(b.severity))
            .then_with(|| a.category.cmp(b.category))
            .then_with(|| a.detail.cmp(&b.detail))
    });
    issues
}

/// CRITICAL sorts before WARNING; any unknown label sorts last.
fn severity_rank(sev: &str) -> u8 {
    match sev {
        SEV_CRITICAL => 0,
        SEV_WARNING => 1,
        _ => 2,
    }
}

/// A value-free per-service key-pool summary the caller hands in (mapped from
/// the api layer's `summarize_pool`), so the renderer stays self-contained and
/// never touches key material. A pool is genuinely dead only when it has
/// neither an ACTIVE nor an UNTESTED key ([`KeyPoolSummary::is_dead`]) — an
/// untested key has simply not been probed yet and may work on first use, so it
/// must NOT count as dead (a real-binary run flagged an untested `shodan` key
/// "ALL DEAD" before this distinction was added).
pub(crate) struct KeyPoolSummary {
    pub service: String,
    pub total: usize,
    pub active: usize,
    pub untested: usize,
    pub rate_limited: usize,
    pub exhausted: usize,
    pub invalid: usize,
    pub revoked: usize,
    /// Mean health across the pool's *tested* keys, or `None` when every key is
    /// still untested (no operational history to grade). Rendered as "n/a"
    /// rather than a fabricated score in that case.
    pub avg_health: Option<f64>,
}

impl KeyPoolSummary {
    /// True iff the pool holds keys but NONE can currently be dispatched and
    /// none remain untested — every key is exhausted / invalid / rate-limited /
    /// revoked, so the service's keyed modules silently return nothing.
    #[must_use]
    pub fn is_dead(&self) -> bool {
        self.total > 0 && self.active == 0 && self.untested == 0
    }
}
