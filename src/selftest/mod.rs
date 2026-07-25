//! On-demand + automatic self-validation of every module and core feature.
//!
//! One entry point, [`run`], drives the whole suite. It is wired in three ways:
//!   * **automatically**, `hse selftest` runs it and exits non-zero on any
//!     failure, and `hse serve` runs it once at startup and logs a one-line
//!     summary (so a broken build is obvious the moment the server boots);
//!   * **on demand**, `GET /api/v1/selftest` and the Web UI's "Run self-test"
//!     button trigger the same suite and render the structured report.
//!
//! Every check is self-contained and offline — the real module registry, a
//! throwaway temp database, and synthetic entities — so it is safe to run on a
//! phone, in CI, or against a live server without touching the network or the
//! operator's data.

use std::sync::Arc;
use std::time::Instant;

use serde::Serialize;

use crate::core::{
    StoragePort,
    correlator::Correlator,
    dependency::{ALL_TARGET_KINDS, ModuleGraph, PROBE_VALUE},
    entity::{Entity, EntityKind, Evidence, unix_now},
    scan::{MAX_DEPTH, Scan, Target, optimal_depth},
};
use crate::storage::Store;

/// Outcome of a single check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Pass,
    Warn,
    Fail,
}

impl Status {
    /// ASCII marker (no non-ASCII glyphs — Termux terminal-safe).
    fn marker(self) -> &'static str {
        match self {
            Status::Pass => "[ok]",
            Status::Warn => "[warn]",
            Status::Fail => "[FAIL]",
        }
    }
}

/// One named check with a human-readable detail line.
#[derive(Debug, Clone, Serialize)]
pub struct Check {
    pub name: String,
    pub status: Status,
    pub detail: String,
}

/// Aggregate self-test report — JSON-serialised verbatim by the API.
#[derive(Debug, Clone, Serialize)]
pub struct Report {
    /// True iff no check failed (warnings do not flip this).
    pub ok: bool,
    pub passed: usize,
    pub warned: usize,
    pub failed: usize,
    pub total: usize,
    pub elapsed_ms: u128,
    pub version: String,
    pub checks: Vec<Check>,
}

impl Report {
    fn build(checks: Vec<Check>, started: Instant) -> Self {
        let count = |s: Status| checks.iter().filter(|c| c.status == s).count();
        let failed = count(Status::Fail);
        Self {
            ok: failed == 0,
            passed: count(Status::Pass),
            warned: count(Status::Warn),
            failed,
            total: checks.len(),
            elapsed_ms: started.elapsed().as_millis(),
            version: crate::VERSION.to_string(),
            checks,
        }
    }

    /// One-line summary suitable for a log line or a status bar.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "self-test {}: {}/{} pass, {} warn, {} fail in {} ms",
            if self.ok { "OK" } else { "FAILED" },
            self.passed,
            self.total,
            self.warned,
            self.failed,
            self.elapsed_ms,
        )
    }

    /// Human-readable multi-line render (for `hse selftest`).
    #[must_use]
    pub fn render(&self) -> String {
        let mut out = String::new();
        for c in &self.checks {
            out.push_str(&format!(
                "  {:<7} {:<24} {}\n",
                c.status.marker(),
                c.name,
                c.detail
            ));
        }
        out.push('\n');
        out.push_str(&self.summary());
        out
    }
}

fn check(name: &str, status: Status, detail: impl Into<String>) -> Check {
    Check {
        name: name.into(),
        status,
        detail: detail.into(),
    }
}

/// Run the full self-test suite. Offline and side-effect-free (bar a throwaway
/// temp DB it creates and deletes). Never panics — a check that would panic is
/// caught and reported as a failure.
pub async fn run() -> Report {
    let started = Instant::now();
    let checks = vec![
        check_module_registry(),
        check_dispatch_graph(),
        check_module_reachability(),
        check_consumes_accepts(),
        check_module_probes(),
        check_core_math(),
        check_keys(),
        check_storage_and_correlator().await,
        check_log_capture(),
        check_termux_env().await,
    ];
    Report::build(checks, started)
}

/// Every registered module has a unique, non-empty name and a description.
fn check_module_registry() -> Check {
    let modules = crate::modules::registry();
    if modules.is_empty() {
        return check(
            "modules.registry",
            Status::Fail,
            "registry() returned 0 modules",
        );
    }
    let mut seen = std::collections::BTreeSet::new();
    let mut missing_desc = Vec::new();
    for m in &modules {
        if m.name().trim().is_empty() {
            return check(
                "modules.registry",
                Status::Fail,
                "a module has an empty name",
            );
        }
        if !seen.insert(m.name()) {
            return check(
                "modules.registry",
                Status::Fail,
                format!("duplicate module name: {}", m.name()),
            );
        }
        if m.description().trim().is_empty() {
            missing_desc.push(m.name());
        }
    }
    if !missing_desc.is_empty() {
        return check(
            "modules.registry",
            Status::Fail,
            format!("{} module(s) missing a description", missing_desc.len()),
        );
    }
    check(
        "modules.registry",
        Status::Pass,
        format!(
            "{} modules, all uniquely named and described",
            modules.len()
        ),
    )
}

/// The O(1) dispatch index contains every module that accepts a given kind —
/// the load-bearing wiring invariant (a module missing from its bucket silently
/// never runs for that kind). This is the SUBSET direction, not equality: a
/// module that value-gates `accepts()` (a name needs a space, a URL must be an
/// image / social host) declares the kind via an explicit `consumes()` override,
/// so the index legitimately holds MORE than a generic probe accepts. (Equality
/// here is what masked four modules whose `consumes()` had collapsed to empty.)
fn check_dispatch_graph() -> Check {
    let modules = crate::modules::registry();
    let graph = ModuleGraph::build(&modules);
    for (idx, m) in modules.iter().enumerate() {
        for &kind in ALL_TARGET_KINDS {
            if m.accepts(&Target::new(kind, "graph-probe"))
                && !graph.modules_for(kind).contains(&idx)
            {
                return check(
                    "modules.dispatch_graph",
                    Status::Fail,
                    format!(
                        "{} accepts {kind:?} but is missing from its dispatch bucket",
                        m.name()
                    ),
                );
            }
        }
    }
    check(
        "modules.dispatch_graph",
        Status::Pass,
        "every accepting module is in its kind's dispatch bucket",
    )
}

/// End-to-end wiring: from EVERY realistic seed kind, the transitive
/// producer/consumer closure must reach every registered module — the
/// "100% of modules run during a scan" guarantee. A module accepting a kind that
/// a seed can no longer produce would be named here (dead end-to-end wiring that
/// `check_dispatch_graph`'s single-hop view cannot see).
fn check_module_reachability() -> Check {
    let modules = crate::modules::registry();
    let graph = ModuleGraph::build(&modules);
    match crate::core::dependency::reachability::fully_wired(&graph, &modules) {
        Ok(n) => check(
            "modules.reachability",
            Status::Pass,
            format!("all {n} modules reachable from every realistic seed kind (100% wired)"),
        ),
        Err((seed, dead)) => check(
            "modules.reachability",
            Status::Fail,
            format!(
                "from a {seed:?} seed, {} module(s) can never be dispatched end-to-end: {}",
                dead.len(),
                dead.join(", ")
            ),
        ),
    }
}

/// Every module's declared `consumes()` covers each kind its `accepts()`
/// matches against the canonical probe — else it is never indexed for that
/// kind (a value-gated module must override `consumes()`).
fn check_consumes_accepts() -> Check {
    let modules = crate::modules::registry();
    let mut violations = Vec::new();
    let mut dead = Vec::new();
    for m in &modules {
        let declared = m.consumes();
        // Floor: a module that consumes NOTHING is in no dispatch bucket and can
        // never run. A value-gated accepts() (a name needs a space, a URL must be
        // an image / social host) whose author forgot the consumes() override
        // collapses to exactly this — and the probe-subset check below can't see
        // it (the probe itself fails the gate, so an empty consumes() looks
        // "consistent" with zero probed accepts).
        if declared.is_empty() {
            dead.push(m.name());
        }
        for &kind in ALL_TARGET_KINDS {
            if m.accepts(&Target::new(kind, PROBE_VALUE)) && !declared.contains(&kind) {
                violations.push(format!("{}/{kind:?}", m.name()));
            }
        }
    }
    if !dead.is_empty() {
        return check(
            "modules.consumes_accepts",
            Status::Fail,
            format!(
                "module(s) with empty consumes() — dead at runtime (override \
                 consumes() to declare the value-gated kind): {}",
                dead.join(", ")
            ),
        );
    }
    if violations.is_empty() {
        check(
            "modules.consumes_accepts",
            Status::Pass,
            "every module's consumes() covers its probed accepts()",
        )
    } else {
        check(
            "modules.consumes_accepts",
            Status::Fail,
            format!("consumes()/accepts() divergence: {}", violations.join(", ")),
        )
    }
}

/// Exercise each module's pure metadata accessors across every kind — proves
/// the whole registry can be introspected without a panic.
fn check_module_probes() -> Check {
    let modules = crate::modules::registry();
    let mut probes = 0usize;
    for m in &modules {
        let _ = m.priority();
        let _ = m.cost();
        let _ = m.category();
        let _ = m.is_passive();
        let _ = m.max_timeout_ms();
        let _ = m.termux_timeout_ms();
        let _ = m.produces();
        for &kind in ALL_TARGET_KINDS {
            let _ = m.accepts(&Target::new(kind, "probe-value"));
            probes += 1;
        }
    }
    check(
        "modules.probe",
        Status::Pass,
        format!("{probes} module metadata + accepts() probes, no panic"),
    )
}

/// Core scoring maths hold their invariants: `optimal_depth` stays in range,
/// `c_effective` is corroboration-monotonic and clamped to [0, 1].
fn check_core_math() -> Check {
    for &kind in ALL_TARGET_KINDS {
        for paid in [true, false] {
            let (depth, conf) = optimal_depth(kind, paid);
            if !(1..=MAX_DEPTH).contains(&depth) {
                return check(
                    "core.math",
                    Status::Fail,
                    format!(
                        "optimal_depth({kind:?}, {paid}) depth {depth} out of [1, {MAX_DEPTH}]"
                    ),
                );
            }
            if !(0.0..=1.0).contains(&conf) {
                return check(
                    "core.math",
                    Status::Fail,
                    format!("optimal_depth({kind:?}) min_conf {conf} out of [0, 1]"),
                );
            }
        }
    }
    let mut e = Entity::new(EntityKind::Email, "selftest@example.com", 0.80, "st");
    let base = e.c_effective();
    e.add_evidence(Evidence::new("src-a", "x"));
    e.add_evidence(Evidence::new("src-b", "y"));
    let boosted = e.c_effective();
    if boosted < base || !(0.0..=1.0).contains(&boosted) {
        return check(
            "core.math",
            Status::Fail,
            format!("c_effective non-monotonic or unclamped: base={base:.3} boosted={boosted:.3}"),
        );
    }
    check(
        "core.math",
        Status::Pass,
        "optimal_depth bounded; c_effective corroboration-monotonic in [0, 1]",
    )
}

/// The key store loads without error; report the configured-key count.
fn check_keys() -> Check {
    let keys = crate::secrets::keys::load();
    let path = crate::secrets::keys::env_path();
    check(
        "keys.load",
        Status::Pass,
        format!("{} HUNTSMAN_* key(s) loaded from {path}", keys.len()),
    )
}

/// End-to-end storage + correlator: open a throwaway DB, round-trip a synthetic
/// identity graph, and confirm the correlator fires at least one rule on it.
async fn check_storage_and_correlator() -> Check {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "hse-selftest-{}-{}.db",
        std::process::id(),
        unix_now()
    ));
    let p = path.to_string_lossy().into_owned();
    let _ = std::fs::remove_file(&p);

    let result = (|| -> Result<(usize, usize), String> {
        let store = Arc::new(Store::open(&p).map_err(|e| format!("Store::open: {e}"))?);
        let scan_id = "selftest";
        let scan = Scan::new(
            scan_id,
            Target::new(crate::core::scan::TargetKind::Email, "selftest@example.com"),
        );
        store
            .upsert_scan(&scan)
            .map_err(|e| format!("upsert_scan: {e}"))?;

        let mk = |k, v: &str, srcs: &[&str]| -> Entity {
            let mut x = Entity::new(k, v, 0.85, scan_id);
            for s in srcs {
                x.add_evidence(Evidence::new(*s, "selftest"));
            }
            x
        };
        let ents = [
            mk(
                EntityKind::Email,
                "selftest@example.com",
                &["src-a", "src-b"],
            ),
            mk(EntityKind::Username, "selftester", &["src-a", "src-b"]),
            mk(EntityKind::Phone, "+61400000000", &["src-a"]),
        ];
        for e in &ents {
            store
                .upsert_entity(e)
                .map_err(|e| format!("upsert_entity: {e}"))?;
        }
        let read = store
            .entities_for_scan(scan_id)
            .map_err(|e| format!("entities_for_scan: {e}"))?;
        let fired = Correlator::new(Arc::clone(&store) as Arc<dyn StoragePort>)
            .run(scan_id)
            .map_err(|e| format!("correlator: {e}"))?;
        Ok((read.len(), fired.len()))
    })();

    let _ = std::fs::remove_file(&p);
    let _ = std::fs::remove_file(format!("{p}-wal"));
    let _ = std::fs::remove_file(format!("{p}-shm"));

    match result {
        Err(e) => check("storage.correlator", Status::Fail, e),
        Ok((read, _)) if read < 3 => check(
            "storage.correlator",
            Status::Fail,
            format!("entity round-trip lost rows: persisted 3, read {read}"),
        ),
        Ok((_, 0)) => check(
            "storage.correlator",
            Status::Fail,
            "correlator fired 0 rules on a synthetic identity graph (AU-002 expected)",
        ),
        Ok((read, fired)) => check(
            "storage.correlator",
            Status::Pass,
            format!("DB round-trip {read} entities; correlator fired {fired} rule(s)"),
        ),
    }
}

/// The verbose-log ring buffer is wired: a probe line we emit here is captured
/// (only when a subscriber is installed — i.e. under the real binary, not bare
/// unit tests, where it degrades to a non-fatal warning).
fn check_log_capture() -> Check {
    let before = crate::util::log_capture::line_count();
    tracing::debug!(target: "selftest", "log-capture probe line");
    let after = crate::util::log_capture::line_count();
    if after > before {
        check(
            "logs.capture",
            Status::Pass,
            format!(
                "verbose log ring active ({after} lines buffered, downloadable at /api/v1/logs)"
            ),
        )
    } else {
        check(
            "logs.capture",
            Status::Warn,
            "log ring not growing here (no tracing subscriber installed in this context)",
        )
    }
}

/// Report the runtime environment (Termux + sensor-bridge availability).
async fn check_termux_env() -> Check {
    if crate::is_termux() {
        // Probe via the timeout-bounded, kill-on-drop `termux_cmd` helper (the
        // single chokepoint every other termux-* call already uses) instead of a
        // raw blocking `Command::output()`. The old probe could hang `selftest`
        // forever on a wedged CLI, and its `.is_ok()` reported "present" even on a
        // non-zero exit; `termux_cmd` enforces a hard 1.5s timeout and treats a
        // timeout / spawn-failure / non-zero exit as unavailable.
        let api = crate::util::termux::termux_cmd("termux-info", &["-h"], 1500)
            .await
            .is_some();
        if api {
            check(
                "env.termux",
                Status::Pass,
                "Termux detected; termux-api CLI present",
            )
        } else {
            check(
                "env.termux",
                Status::Warn,
                "Termux detected but termux-api CLI missing — sensor modules will no-op",
            )
        }
    } else {
        check(
            "env.termux",
            Status::Pass,
            "non-Termux host (sensor modules inert)",
        )
    }
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
