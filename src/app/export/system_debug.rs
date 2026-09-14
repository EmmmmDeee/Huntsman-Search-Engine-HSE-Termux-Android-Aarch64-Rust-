//! System self-diagnosis bundle — the whole engine's health in ONE artifact.
//!
//! The per-scan [`render_debug_bundle`](super::renderers::render_debug_bundle)
//! answers "what happened in THIS scan?". This answers the orthogonal,
//! engine-level question the operator (or Claude Code) actually asks when HSE
//! itself misbehaves: "what is wrong with the install, right now, and where do
//! I look?" — by joining every otherwise-fragmented diagnostic surface (the
//! scattered `/health`, `/selftest`, `/modules/health`, `/engines/health`,
//! `/health/scrapers`, `/logs` endpoints) into one downloadable,
//! self-diagnosing file, led by an auto-computed DETECTED ISSUES verdict.
//!
//! The issue-detection POLICY itself ([`detect_issues`]
//! and friends) lives in the sibling `health_policy` module — this file is
//! presentation only: it gathers the live snapshots, calls that policy, and
//! writes every section of the bundle.

use super::health_policy::{
    DetectedIssue, IssueInputs, KeyPoolSummary, SEV_CRITICAL, WAL_RUNAWAY_BYTES, detect_issues,
};

/// The gathered-off-reactor inputs for [`render_system_debug_bundle`]. The
/// async / store-bound parts (the self-test, the recent-scan list, the
/// cross-scan scraper-outcome events, and the in-memory log ring) are fetched
/// by the caller — the HTTP handler or a CLI command — and handed in; the
/// renderer reads only cheap, synchronous process-global state (version,
/// registry, live health snapshots, source manifest) inline.
pub(crate) struct SystemDebugInputs {
    pub selftest: crate::selftest::Report,
    pub scans: Vec<crate::core::scan::Scan>,
    pub scraper_health: Vec<crate::util::scraper_health::SourceHealth>,
    pub scraper_events_checked: usize,
    pub log_dump: String,
    pub log_lines: usize,
    /// Per-service key-pool health (value-free), for the KEY POOL section and
    /// the silently-dead-pool verdict arm.
    pub key_pool: Vec<KeyPoolSummary>,
    /// `PRAGMA integrity_check` rows for the REAL on-disk store — `["ok"]` when
    /// healthy, one or more problem descriptions when corrupt (the self-test
    /// only round-trips a throwaway temp DB, never the operator's data).
    pub db_integrity: Vec<String>,
    /// Size of the SQLite `-wal` sidecar in bytes, or `None` if not found. A
    /// runaway WAL (checkpointing stalled) is a real on-device disk-footprint
    /// failure mode.
    pub wal_bytes: Option<u64>,
    /// Commits the running binary is behind upstream, or `None` if never
    /// checked / offline. A build that is behind may be hitting bugs already
    /// fixed upstream — the exact situation a real operator debug bundle showed
    /// (three module errors, every one already fixed in a newer build).
    pub update_commits_behind: Option<u64>,
    /// Unix seconds of the last successful upstream check, `0` if never.
    pub update_last_checked: u64,
    /// The update lifecycle phase, stringified — `"idle"`/`"checking"`/
    /// `"applying"`/`"restarting"`, or `"error: <msg>"` preserving the payload.
    pub update_phase: String,
}

/// Render the consolidated **system self-diagnosis bundle**: one artifact that
/// encompasses the whole engine's diagnostic + validation state — a headline
/// auto-computed DETECTED ISSUES verdict, the environment fingerprint, the full
/// self-test (validation), live + cross-scan module / engine / scraper health,
/// the recent-scan index (each failed scan's error inline), the recent verbose
/// log ring, and the source-file manifest — organised so the engine can be
/// repaired from this one file.
///
/// Unlike the per-scan [`render_debug_bundle`](super::renderers::render_debug_bundle),
/// this is a LIVE snapshot: it carries logs and a headline health read that
/// change moment to moment, so it is deliberately NOT byte-deterministic across
/// time (the [`detect_issues`] ordering
/// and every section's internal ordering ARE deterministic, so two bundles
/// taken in the same instant diff cleanly). Secret-free by construction
/// — the environment section prints key NAMES only, never values — but the
/// caller still gates it to loopback because the log ring can contain scan
/// targets / discovered PII.
pub(crate) fn render_system_debug_bundle(inp: &SystemDebugInputs) -> String {
    use std::fmt::Write as _;
    let mut s = String::new();
    let _ = writeln!(
        s,
        "=== HUNTSMAN SYSTEM DEBUG BUNDLE — full engine self-diag ==="
    );
    let _ = writeln!(s, "One file: what's wrong, the proof, and every module.");

    // Live snapshots — cheap synchronous process-global reads.
    let module_health = crate::core::engine::module_health_report();
    let engines = crate::modules::search_engines::health::cached_or_empty();
    use crate::modules::search_engines::health::EngineStatus;
    let engines_down: Vec<&str> = engines
        .engines
        .iter()
        .filter(|h| h.status == EngineStatus::Down)
        .map(|h| h.name)
        .collect();
    let engines_blocked: Vec<&str> = engines
        .engines
        .iter()
        .filter(|h| h.status == EngineStatus::Blocked)
        .map(|h| h.name)
        .collect();
    let curl_present = super::environment::curl_present();
    let failed_scans = inp
        .scans
        .iter()
        .filter(|sc| sc.status.as_str() == "failed")
        .count();
    // Keyed-provider quota budgets (the same snapshots `/stats` serves). WiGLE
    // splits into four independent sub-budgets. A `quota_exhausted` flag is why
    // that provider's keyed modules currently return nothing.
    let provider_budgets: Vec<(&str, crate::util::budget::BudgetSnapshot)> = {
        let w = crate::modules::wigle::budget_snapshot();
        vec![
            ("seeknow", crate::util::see_know::budget_snapshot()),
            ("oathnet", crate::util::oathnet::budget_snapshot()),
            ("wigle:geo", w.geo),
            ("wigle:bssid", w.bssid),
            ("wigle:cell", w.cell),
            ("wigle:bluetooth", w.bluetooth),
        ]
    };
    let quota_exhausted: Vec<&str> = provider_budgets
        .iter()
        .filter(|(_, b)| b.quota_exhausted)
        .map(|(n, _)| *n)
        .collect();

    // ── 0. DETECTED ISSUES — the self-diagnosing verdict, read first ──
    let issues = detect_issues(&IssueInputs {
        selftest_ok: inp.selftest.ok,
        selftest_failures: inp
            .selftest
            .checks
            .iter()
            .filter(|c| c.status == crate::selftest::Status::Fail)
            .map(|c| (c.name.as_str(), c.detail.as_str()))
            .collect(),
        curl_present,
        unhealthy_modules: module_health
            .iter()
            .map(|h| (h.name, h.consecutive_failures))
            .collect(),
        engines_down: engines_down.clone(),
        engines_blocked: engines_blocked.clone(),
        scrapers_drifted: inp
            .scraper_health
            .iter()
            .filter(|h| h.is_drifted())
            .map(|h| (h.module.as_str(), h.consecutive_failures))
            .collect(),
        scrapers_yield_drifted: inp
            .scraper_health
            .iter()
            .filter(|h| h.is_yield_drifted())
            .map(|h| h.module.as_str())
            .collect(),
        failed_scans,
        quota_exhausted_providers: quota_exhausted.clone(),
        // The handler stringifies the update phase as `"error: <msg>"` for the
        // `Error` variant; recover the message for the verdict.
        update_error: inp.update_phase.strip_prefix("error: "),
        update_commits_behind: inp.update_commits_behind,
        dead_key_services: inp
            .key_pool
            .iter()
            .filter(|k| k.is_dead())
            .map(|k| (k.service.as_str(), k.total))
            .collect(),
        // Healthy integrity is exactly `["ok"]`; any other row is a problem.
        db_integrity_issue: inp
            .db_integrity
            .iter()
            .find(|r| r.as_str() != "ok")
            .map(String::as_str),
        wal_oversized: inp.wal_bytes.is_some_and(|b| b > WAL_RUNAWAY_BYTES),
    });
    write_detected_issues(&mut s, &issues);

    // ── 1. Environment fingerprint (build / host / module set / key presence) ──
    // Reuse the `curl_present` already computed for the verdict — one spawn, not two.
    s.push_str(&super::environment::render_environment(curl_present));

    write_update_status(&mut s, inp);
    write_disabled_capabilities(&mut s);
    write_validation(&mut s, &inp.selftest);
    write_module_health(&mut s, &module_health);
    write_search_engine_liveness(&mut s, &engines, &engines_down, &engines_blocked);
    write_scraper_health(&mut s, inp);
    write_key_authentication(&mut s, inp);
    write_provider_quotas(&mut s, &provider_budgets, &quota_exhausted);
    write_key_pool(&mut s, inp);
    write_storage_health(&mut s, inp);
    write_recent_scans(&mut s, inp);
    write_recent_logs(&mut s, inp);
    write_source_files(&mut s);

    s
}

/// ── 0. DETECTED ISSUES — the self-diagnosing verdict, read first. ──
fn write_detected_issues(s: &mut String, issues: &[DetectedIssue]) {
    use std::fmt::Write as _;
    let (crit, warn) = issues.iter().fold((0usize, 0usize), |(c, w), i| {
        if i.severity == SEV_CRITICAL {
            (c + 1, w)
        } else {
            (c, w + 1)
        }
    });
    let _ = writeln!(
        s,
        "\n── DETECTED ISSUES ({crit} critical, {warn} warning) ──"
    );
    if issues.is_empty() {
        let _ = writeln!(
            s,
            "  ✓ no issues auto-detected — self-test OK, no module/engine/scraper drift, \
             no failed scans"
        );
    }
    for i in issues {
        let _ = writeln!(s, "  [{}] {}: {}", i.severity, i.category, i.detail);
    }
}

/// ── 1a. Update / build freshness — is this binary current? ──
fn write_update_status(s: &mut String, inp: &SystemDebugInputs) {
    use std::fmt::Write as _;
    let _ = writeln!(s, "\n── UPDATE STATUS ──");
    let behind = match inp.update_commits_behind {
        Some(0) => "up to date".to_string(),
        Some(n) => format!("{n} commit(s) BEHIND upstream — run `hse update`"),
        None => "unknown (never checked / offline)".to_string(),
    };
    let _ = writeln!(s, "  commits_behind: {behind}");
    let _ = writeln!(s, "  phase         : {}", inp.update_phase);
    let last = if inp.update_last_checked == 0 {
        "never".to_string()
    } else {
        crate::util::timefmt::compact_utc(inp.update_last_checked)
    };
    let _ = writeln!(s, "  last_checked  : {last}");
}

/// ── 1b. Disabled capabilities (operator toggles) — the single most direct
///        answer to "why didn't module/feature X run?" that isn't a bug: an
///        operator turned it off in `~/.huntsman/settings.json`. ──
fn write_disabled_capabilities(s: &mut String) {
    use std::fmt::Write as _;
    let disabled_modules: Vec<&'static str> = {
        let reg = crate::modules::registry();
        let mut v: Vec<&'static str> = reg
            .iter()
            .map(|m| m.name())
            .filter(|n| !crate::util::settings::get_bool(&format!("module.{n}"), true))
            .collect();
        v.sort_unstable();
        v
    };
    let disabled_features: Vec<String> = crate::util::settings::feature_toggles()
        .into_iter()
        .filter(|(_, on)| !on)
        .map(|(k, _)| k)
        .collect();
    // Search-engine toggles too — a disabled engine silently never dispatches,
    // exactly the "why did search find nothing?" question. Keys are already
    // `engine.<name>`; strip the prefix for a clean roster.
    let mut disabled_engines: Vec<String> = crate::modules::search_engines::engine_toggles()
        .into_iter()
        .filter(|(_, on)| !on)
        .map(|(k, _)| k.strip_prefix("engine.").map_or(k.clone(), str::to_string))
        .collect();
    disabled_engines.sort_unstable();
    let _ = writeln!(
        s,
        "\n── DISABLED CAPABILITIES ({} module(s), {} engine(s), {} feature(s) turned OFF) ──",
        disabled_modules.len(),
        disabled_engines.len(),
        disabled_features.len()
    );
    if disabled_modules.is_empty() && disabled_engines.is_empty() && disabled_features.is_empty() {
        let _ = writeln!(
            s,
            "  ✓ nothing disabled — every module, engine, and feature is enabled"
        );
    }
    if !disabled_modules.is_empty() {
        let _ = writeln!(s, "  modules OFF : {}", disabled_modules.join(", "));
    }
    if !disabled_engines.is_empty() {
        let _ = writeln!(s, "  engines OFF : {}", disabled_engines.join(", "));
    }
    if !disabled_features.is_empty() {
        let _ = writeln!(s, "  features OFF: {}", disabled_features.join(", "));
    }
}

/// ── 2. Validation — the full self-test suite (`hse selftest`). ──
fn write_validation(s: &mut String, selftest: &crate::selftest::Report) {
    use std::fmt::Write as _;
    let _ = writeln!(s, "\n── VALIDATION (SELF-TEST) ──");
    let _ = writeln!(s, "  {}", selftest.summary());
    s.push_str(&selftest.render());
    s.push('\n');
}

/// ── 3. Live per-process module health (failure streaks). ──
fn write_module_health(s: &mut String, module_health: &[crate::core::engine::ModuleHealth]) {
    use std::fmt::Write as _;
    let _ = writeln!(
        s,
        "\n── MODULE HEALTH (live, this process — {} with a failure streak) ──",
        module_health.len()
    );
    if module_health.is_empty() {
        let _ = writeln!(
            s,
            "  ✓ no module is currently showing a dispatch-failure streak"
        );
    }
    for h in module_health {
        let last = h
            .last_success_at
            .map_or_else(|| "never this process".to_string(), |t| t.to_string());
        let _ = writeln!(
            s,
            "  {:<28} {} consecutive failure(s) · last success: {}",
            h.name, h.consecutive_failures, last
        );
    }
}

/// ── 4a. Search-engine liveness (latest cached sweep). ──
fn write_search_engine_liveness(
    s: &mut String,
    engines: &crate::modules::search_engines::health::HealthSnapshot,
    engines_down: &[&str],
    engines_blocked: &[&str],
) {
    use std::fmt::Write as _;
    let _ = writeln!(
        s,
        "\n── SEARCH-ENGINE LIVENESS (checked_at={}, {} engines: {} down, {} blocked) ──",
        engines.checked_at,
        engines.engines.len(),
        engines_down.len(),
        engines_blocked.len()
    );
    if engines.engines.is_empty() {
        let _ = writeln!(
            s,
            "  (no sweep cached yet — start `hse serve`/`hse engines` to populate)"
        );
    }
    for h in &engines.engines {
        let _ = writeln!(
            s,
            "  {:<14} {:<8} {:>5} ms · {} result(s) · {}",
            h.name,
            h.status.as_str(),
            h.latency_ms,
            h.results,
            h.detail
        );
    }
}

/// ── 4b. Cross-scan scraper health (persisted drift). ──
fn write_scraper_health(s: &mut String, inp: &SystemDebugInputs) {
    use std::fmt::Write as _;
    let drifted: Vec<_> = inp
        .scraper_health
        .iter()
        .filter(|h| h.is_drifted())
        .collect();
    let yield_drifted: Vec<_> = inp
        .scraper_health
        .iter()
        .filter(|h| h.is_yield_drifted())
        .collect();
    let _ = writeln!(
        s,
        "\n── SCRAPER HEALTH (cross-scan, {} tracked over {} events — {} drifted, {} yield-drifted) ──",
        inp.scraper_health.len(),
        inp.scraper_events_checked,
        drifted.len(),
        yield_drifted.len()
    );
    if drifted.is_empty() && yield_drifted.is_empty() {
        let _ = writeln!(
            s,
            "  ✓ no source is drifting (no hard-failure streaks, no silent zero-yield)"
        );
    }
    for h in &drifted {
        let err = h.last_error.as_deref().unwrap_or("(no message)");
        let _ = writeln!(
            s,
            "  [FAIL-DRIFT] {:<24} {} consecutive failure(s) · last error: {}",
            h.module, h.consecutive_failures, err
        );
    }
    for h in &yield_drifted {
        let _ = writeln!(
            s,
            "  [YIELD-DRIFT] {:<24} {} consecutive zero-yield completion(s)",
            h.module, h.consecutive_zero_yield
        );
    }
}

/// ── 4b′. Key authentication — which keyed sources the upstream is actively
///        REJECTING (auth-shaped errors: 401/403, "invalid API key", "API key
///        not found", …), lifted out of the generic drift errors above so a
///        dead credential is called out explicitly with the exact upstream
///        message and the env var most likely holding it. Grounded in observed
///        responses — never mis-reports a working key like a synthetic probe. ──
fn write_key_authentication(s: &mut String, inp: &SystemDebugInputs) {
    use std::fmt::Write as _;
    let auth_rejected = crate::util::key_health::auth_failing_sources(&inp.scraper_health);
    let _ = writeln!(
        s,
        "\n── KEY AUTHENTICATION ({} source(s) rejected by upstream) ──",
        auth_rejected.len()
    );
    if auth_rejected.is_empty() {
        let _ = writeln!(
            s,
            "  ✓ no keyed source is being rejected for bad credentials"
        );
    }
    for i in &auth_rejected {
        let env = i.likely_env_var.unwrap_or("(unmapped)");
        // Capped for the report line, with the truncation disclosed — the full
        // string stays on the issue and is served whole by the keys API.
        let detail = i.detail_capped(200);
        let _ = writeln!(
            s,
            "  [AUTH-REJECT] {:<20} {env} · {} failure(s) · {detail}",
            i.module, i.consecutive_failures
        );
    }
}

/// ── 4c. Keyed-provider quota budgets (why a keyed module returns nothing). ──
fn write_provider_quotas(
    s: &mut String,
    provider_budgets: &[(&str, crate::util::budget::BudgetSnapshot)],
    quota_exhausted: &[&str],
) {
    use std::fmt::Write as _;
    let _ = writeln!(
        s,
        "\n── PROVIDER QUOTAS ({} exhausted) ──",
        quota_exhausted.len()
    );
    for (name, b) in provider_budgets {
        let flag = if b.quota_exhausted {
            " · EXHAUSTED"
        } else {
            ""
        };
        let _ = writeln!(
            s,
            "  {:<16} scan {}/{} · session {}/{}{}",
            name, b.scan_used, b.scan_cap, b.session_used, b.session_cap, flag
        );
    }
}

/// ── 4d. Key-pool health — value-free per-service status. A service with keys
///        but 0 ACTIVE is a silent top-source death (invisible to the
///        error-based health above). ──
fn write_key_pool(s: &mut String, inp: &SystemDebugInputs) {
    use std::fmt::Write as _;
    let dead_pools = inp.key_pool.iter().filter(|k| k.is_dead()).count();
    let _ = writeln!(
        s,
        "\n── KEY POOL ({} service(s) pooled, {} fully dead) ──",
        inp.key_pool.len(),
        dead_pools
    );
    if inp.key_pool.is_empty() {
        let _ = writeln!(
            s,
            "  (no keys in the pool — free modules still run; keyed modules skip cleanly)"
        );
    }
    for k in &inp.key_pool {
        let dead = if k.is_dead() { "  · ALL DEAD" } else { "" };
        // "n/a" (not a fabricated 0.00) when no key has been exercised yet.
        let health = k
            .avg_health
            .map_or_else(|| "n/a".to_string(), |h| format!("{h:.2}"));
        let _ = writeln!(
            s,
            "  {:<14} {}/{} active · {} untested · {} rate-limited · {} exhausted · {} invalid · {} revoked · health {}{}",
            k.service,
            k.active,
            k.total,
            k.untested,
            k.rate_limited,
            k.exhausted,
            k.invalid,
            k.revoked,
            health,
            dead
        );
    }
}

/// ── 4e. Storage health — the REAL on-disk DB (self-test only checks a
///        throwaway temp DB, so corruption is invisible everywhere else). ──
fn write_storage_health(s: &mut String, inp: &SystemDebugInputs) {
    use std::fmt::Write as _;
    let integrity_ok = inp.db_integrity.iter().all(|r| r == "ok");
    let _ = writeln!(s, "\n── STORAGE HEALTH (real on-disk DB) ──");
    if integrity_ok {
        let _ = writeln!(s, "  integrity: ok");
    } else {
        let _ = writeln!(
            s,
            "  integrity: FAIL — {} issue(s):",
            inp.db_integrity
                .iter()
                .filter(|r| r.as_str() != "ok")
                .count()
        );
        for row in inp.db_integrity.iter().filter(|r| r.as_str() != "ok") {
            let _ = writeln!(s, "    • {row}");
        }
    }
    match inp.wal_bytes {
        Some(b) => {
            let note = if b > WAL_RUNAWAY_BYTES {
                "  · RUNAWAY (checkpointing stalled)"
            } else {
                ""
            };
            let _ = writeln!(s, "  WAL size : {} KiB{note}", b / 1024);
        }
        None => {
            let _ = writeln!(s, "  WAL size : (no -wal sidecar found)");
        }
    }
}

/// ── 5. Recent scans (with each failed scan's error inline). ──
fn write_recent_scans(s: &mut String, inp: &SystemDebugInputs) {
    use std::fmt::Write as _;
    let _ = writeln!(
        s,
        "\n── RECENT SCANS ({}, newest-first; pull /api/v1/scans/<id>/debug.txt for per-scan depth) ──",
        inp.scans.len()
    );
    if inp.scans.is_empty() {
        let _ = writeln!(s, "  (no scans stored yet)");
    }
    for sc in &inp.scans {
        let _ = writeln!(
            s,
            "  {}  {:<9} ents={} run={} err={} timeout={} cached={}  {:?}:{}",
            sc.id,
            sc.status.as_str(),
            sc.entity_count,
            sc.modules_run,
            sc.modules_errored,
            sc.modules_timed_out,
            sc.modules_cached,
            sc.target.kind,
            sc.target.value,
        );
        if let Some(err) = sc.error.as_deref().filter(|e| !e.is_empty()) {
            let _ = writeln!(s, "        error: {err}");
        }
    }
}

/// ── 6. Recent verbose logs (the in-memory TRACE ring). ──
fn write_recent_logs(s: &mut String, inp: &SystemDebugInputs) {
    use std::fmt::Write as _;
    let _ = writeln!(
        s,
        "\n── RECENT LOGS ({} line(s) in the ring buffer) ──",
        inp.log_lines
    );
    if inp.log_dump.trim().is_empty() {
        let _ = writeln!(
            s,
            "  (log ring empty — capture installs with the server; a bare CLI run buffers little)"
        );
    } else {
        s.push_str(&inp.log_dump);
        if !inp.log_dump.ends_with('\n') {
            s.push('\n');
        }
    }
}

/// ── 7. Source-file manifest (build fingerprint — every file the binary carries). ──
fn write_source_files(s: &mut String) {
    use std::fmt::Write as _;
    let _ = writeln!(
        s,
        "\n── SOURCE FILES ({} files, {} LOC) ──",
        crate::source_manifest::SOURCE_FILES.len(),
        crate::source_manifest::SOURCE_TOTAL_LINES,
    );
    for (path, lines) in crate::source_manifest::SOURCE_FILES {
        let _ = writeln!(s, "  {lines:>6}  {path}");
    }
}

#[cfg(test)]
mod tests {
    /// A minimal, fully-populated [`super::SystemDebugInputs`] with empty
    /// collections and a healthy DB — enough to drive
    /// [`super::render_system_debug_bundle`] through every section without
    /// touching the store or the network.
    fn minimal_system_debug_inputs() -> super::SystemDebugInputs {
        super::SystemDebugInputs {
            selftest: crate::selftest::Report {
                ok: true,
                passed: 0,
                warned: 0,
                failed: 0,
                total: 0,
                elapsed_ms: 0,
                version: "test".into(),
                checks: vec![],
            },
            scans: vec![],
            scraper_health: vec![],
            scraper_events_checked: 0,
            log_dump: String::new(),
            log_lines: 0,
            key_pool: vec![],
            db_integrity: vec!["ok".to_string()],
            wal_bytes: None,
            update_commits_behind: Some(0),
            update_last_checked: 0,
            update_phase: "idle".into(),
        }
    }

    /// Characterization guard for the system debug bundle: it is assembled
    /// section by section, and this pins the section set AND their order so the
    /// per-section-helper refactor cannot silently drop, reorder, or duplicate a
    /// section. Substrings (not whole lines) so live counts in the headers don't
    /// make the test brittle.
    #[test]
    fn system_debug_bundle_emits_every_section_in_canonical_order() {
        let out = super::render_system_debug_bundle(&minimal_system_debug_inputs());
        const SECTIONS: &[&str] = &[
            "=== HUNTSMAN SYSTEM DEBUG BUNDLE",
            "── DETECTED ISSUES",
            "── UPDATE STATUS ──",
            "── DISABLED CAPABILITIES",
            "── VALIDATION (SELF-TEST) ──",
            "── MODULE HEALTH",
            "── SEARCH-ENGINE LIVENESS",
            "── SCRAPER HEALTH",
            "── KEY AUTHENTICATION",
            "── PROVIDER QUOTAS",
            "── KEY POOL",
            "── STORAGE HEALTH (real on-disk DB) ──",
            "── RECENT SCANS",
            "── RECENT LOGS",
            "── SOURCE FILES",
        ];
        let mut cursor = 0usize;
        for header in SECTIONS {
            match out[cursor..].find(header) {
                Some(off) => cursor += off + header.len(),
                None => panic!("section {header:?} missing or out of order in:\n{out}"),
            }
        }
    }
}
