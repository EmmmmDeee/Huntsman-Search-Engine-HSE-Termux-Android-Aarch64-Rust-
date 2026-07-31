//! `hse repair` — the single end-to-end recovery command for a Termux
//! aarch64 (no-root) userland install.
//!
//! # Why this exists
//!
//! The recovery capability was previously spread across four things that each
//! did part of the job and none of which reclaimed anything:
//!
//! * `hse doctor` — reports environment/storage/key state, changes nothing.
//! * `hse selftest` — probes module capability, changes nothing.
//! * `hse update` — installs a newer binary, but assumes a healthy layout.
//! * `install.sh` — installs, but is a shell script the binary cannot call
//!   into for a partial repair.
//!
//! So an operator whose install had drifted (a half-written database, a
//! `~/.huntsman` left group-readable by an older release, gigabytes of stale
//! Cargo build cache) had no single action that would put it right. This is
//! that action. It **orchestrates** the existing services rather than
//! reimplementing them — diagnosis stays in `doctor`, verification stays in
//! `selftest`, installation stays in `update`/`install.sh` — and adds the two
//! genuinely missing capabilities: reclaiming regenerable disk, and repairing
//! the on-disk layout.
//!
//! # Execution contract
//!
//! Stages run in dependency order and are **individually fallible**: a stage
//! that fails records why and the run continues, because a failure in one
//! (say, no network for the update check) must not deny the operator the
//! others (reclaiming 3 GB of build cache). Nothing here uses `?` to escape
//! the orchestrator. The process exit code reflects the worst status reached,
//! so a script can still gate on it.
//!
//! # Safety contract
//!
//! This command deletes files, so what it may delete is defined narrowly and
//! by allowlist, never by pattern-matching a directory it happens to find:
//!
//! * **Reclaimable** — only the artefacts `install.sh` itself creates under
//!   `$HOME/.cache/` (the Cargo target directory, downloaded release assets,
//!   the staged prebuilt) plus an in-tree `target/` under the source checkout.
//!   Every one is reproducible from the network or a rebuild.
//! * **Never touched** — everything under `$HOME/.huntsman`. That is the
//!   operator's intelligence data and secrets (scan database, key pool, key
//!   vault, dossiers). The database is compacted in place; it is never
//!   deleted, and a corrupt one is reported with remediation rather than
//!   "repaired" by destroying it.
//! * **Liveness-checked** — the background-server PID file is retained while
//!   that process is alive, so a repair never orphans a running `hse serve`.
//!
//! `--dry-run` reports precisely what would be freed and changes nothing.

use std::path::{Path, PathBuf};

use crate::core::error::Result;

mod reclaim;
pub use reclaim::{ReclaimTarget, Reclaimed, reclaimable_targets};

/// How a single repair stage ended.
///
/// Ordered worst-last so a run's overall verdict is `max()` over its stages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StageStatus {
    /// Ran, found nothing to do — already healthy.
    Ok,
    /// Deliberately not run (a `--no-update`/`--dry-run` style opt-out).
    Skipped,
    /// Ran and actively fixed something.
    Repaired,
    /// Ran, found something the operator should know about, but nothing this
    /// command can or should fix automatically.
    Warn,
    /// Could not complete. The run continues; the exit code reflects it.
    Failed,
}

impl StageStatus {
    /// Stable machine-readable label (matches the serde output).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Skipped => "skipped",
            Self::Repaired => "repaired",
            Self::Warn => "warn",
            Self::Failed => "failed",
        }
    }

    /// Operator-facing marker, aligned so a column of stages reads cleanly.
    #[must_use]
    pub fn marker(self) -> &'static str {
        match self {
            Self::Ok => "  ok  ",
            Self::Skipped => " skip ",
            Self::Repaired => "FIXED ",
            Self::Warn => " warn ",
            Self::Failed => " FAIL ",
        }
    }
}

/// One stage's outcome, carrying its own evidence and remediation so the report
/// is self-contained — the operator never has to re-run a different command to
/// learn what a line meant.
#[derive(Debug, Clone, serde::Serialize)]
pub struct StageReport {
    /// Stable identifier (`environment`, `reclaim`, …) — safe to grep/script on.
    pub id: &'static str,
    /// One-line human title.
    pub title: &'static str,
    pub status: StageStatus,
    /// What was observed, one line per fact.
    pub detail: Vec<String>,
    /// What the operator should do, when this command cannot do it itself.
    pub remediation: Option<String>,
    /// Bytes returned to the filesystem by this stage.
    pub bytes_freed: u64,
}

impl StageReport {
    fn new(id: &'static str, title: &'static str) -> Self {
        Self {
            id,
            title,
            status: StageStatus::Ok,
            detail: Vec::new(),
            remediation: None,
            bytes_freed: 0,
        }
    }

    fn say(&mut self, line: impl Into<String>) -> &mut Self {
        self.detail.push(line.into());
        self
    }

    fn set(&mut self, status: StageStatus) -> &mut Self {
        self.status = status;
        self
    }

    fn fix(&mut self, remediation: impl Into<String>) -> &mut Self {
        self.remediation = Some(remediation.into());
        self
    }
}

/// Knobs for one repair run.
#[derive(Debug, Clone, Copy, Default)]
pub struct RepairOptions {
    /// Report what would change; change nothing.
    pub dry_run: bool,
    /// Also reclaim artefacts that cost real time to regenerate (the Cargo
    /// target directory — a full rebuild is ~15–20 min on aarch64) and rotate
    /// logs. Off by default so the common case is cheap and non-destructive.
    pub deep: bool,
    /// Do not contact the network to check for or install a newer build.
    pub no_update: bool,
}

/// The whole run.
#[derive(Debug, Clone, serde::Serialize)]
pub struct RepairReport {
    pub stages: Vec<StageReport>,
    pub bytes_freed: u64,
    pub dry_run: bool,
}

impl RepairReport {
    /// The run's verdict — the worst status any stage reached.
    #[must_use]
    pub fn verdict(&self) -> StageStatus {
        self.stages
            .iter()
            .map(|s| s.status)
            .max()
            .unwrap_or(StageStatus::Ok)
    }

    /// True when at least one stage could not complete.
    #[must_use]
    pub fn had_failure(&self) -> bool {
        self.verdict() == StageStatus::Failed
    }
}

/// Format a byte count for an operator on a phone, where the interesting range
/// spans a log file and a multi-gigabyte build tree.
#[must_use]
pub fn human_bytes(n: u64) -> String {
    const UNITS: [(u64, &str); 4] = [
        (1024 * 1024 * 1024, "GiB"),
        (1024 * 1024, "MiB"),
        (1024, "KiB"),
        (1, "B"),
    ];
    for (scale, label) in UNITS {
        if n >= scale {
            // One decimal below GiB reads as noise; keep it only where the
            // magnitude makes it meaningful.
            return if scale >= 1024 * 1024 {
                format!("{:.1} {label}", n as f64 / scale as f64)
            } else {
                format!("{} {label}", n / scale)
            };
        }
    }
    "0 B".to_string()
}

/// Run every repair stage in dependency order.
///
/// Never returns `Err`: a stage that fails is recorded as
/// [`StageStatus::Failed`] in the report and the run continues. The caller
/// decides the exit code from [`RepairReport::verdict`].
pub async fn run(opts: RepairOptions) -> RepairReport {
    let mut stages = Vec::new();

    stages.push(stage_environment());
    stages.push(stage_reclaim(opts));
    stages.push(stage_layout(opts));
    stages.push(stage_store(opts));
    stages.push(stage_keys());
    stages.push(stage_update(opts).await);

    let bytes_freed = stages.iter().map(|s| s.bytes_freed).sum();
    RepairReport {
        stages,
        bytes_freed,
        dry_run: opts.dry_run,
    }
}

// ── Stage 1: environment ────────────────────────────────────────────────────

fn stage_environment() -> StageReport {
    let mut r = StageReport::new("environment", "Platform and userland");

    r.say(format!("hse {}", crate::VERSION));
    r.say(format!(
        "arch: {} / os: {}",
        std::env::consts::ARCH,
        std::env::consts::OS
    ));

    if crate::is_termux() {
        r.say("Termux: detected");
    } else {
        r.say("Termux: not detected (repair still applies to this layout)");
    }

    match std::env::var("HOME") {
        Ok(home) if !home.is_empty() && Path::new(&home).is_dir() => {
            r.say(format!("HOME: {home}"));
        }
        Ok(home) => {
            r.set(StageStatus::Failed)
                .say(format!("HOME points at {home:?}, which is not a directory"))
                .fix(
                    "Set HOME to your Termux home (usually \
                     /data/data/com.termux/files/home) and re-run.",
                );
        }
        Err(_) => {
            // Not fatal: `paths::huntsman_dir` falls back to `./.huntsman`. But
            // it means every path this command touches is CWD-relative, which
            // is virtually never what the operator intends.
            r.set(StageStatus::Warn)
                .say("HOME is unset — paths resolve relative to the current directory")
                .fix("Export HOME before running so data resolves under your real home.");
        }
    }

    r
}

// ── Stage 2: reclaim ────────────────────────────────────────────────────────

fn stage_reclaim(opts: RepairOptions) -> StageReport {
    let mut r = StageReport::new("reclaim", "Reclaim regenerable disk");

    let Some(home) = home_dir() else {
        r.set(StageStatus::Skipped)
            .say("no resolvable HOME — nothing to scan");
        return r;
    };

    let targets = reclaimable_targets(&home, install_dir(), opts.deep);
    let present: Vec<&ReclaimTarget> = targets.iter().filter(|t| t.exists()).collect();

    if present.is_empty() {
        r.say("nothing to reclaim — no regenerable artefacts present");
        return r;
    }

    let mut freed = 0u64;
    let mut failed = false;
    for t in present {
        let size = t.size_bytes();
        if opts.dry_run {
            r.say(format!(
                "would free {:>10}  {}  ({})",
                human_bytes(size),
                t.path.display(),
                t.why
            ));
            freed += size;
            continue;
        }
        match t.remove() {
            Ok(Reclaimed::Removed) => {
                freed += size;
                r.say(format!(
                    "freed      {:>10}  {}",
                    human_bytes(size),
                    t.path.display()
                ));
            }
            Ok(Reclaimed::Retained(why)) => {
                r.say(format!(
                    "kept                  {} — {why}",
                    t.path.display()
                ));
            }
            Err(e) => {
                failed = true;
                r.say(format!("could not remove {} — {e}", t.path.display()));
            }
        }
    }

    r.bytes_freed = freed;
    if failed {
        r.set(StageStatus::Failed)
            .fix("Check permissions on the paths above, then re-run `hse repair`.");
    } else if freed > 0 {
        r.set(if opts.dry_run {
            StageStatus::Warn
        } else {
            StageStatus::Repaired
        });
        if opts.dry_run {
            r.fix("Re-run without --dry-run to reclaim the space listed above.");
        }
    }
    if !opts.deep && !opts.dry_run {
        r.say("(--deep also reclaims the Cargo build cache and rotates logs)");
    }
    r
}

// ── Stage 3: layout ─────────────────────────────────────────────────────────

fn stage_layout(opts: RepairOptions) -> StageReport {
    let mut r = StageReport::new("layout", "Data directory and permissions");

    // `huntsman_dir`/`subdir` are themselves the repair: both create the
    // directory 0700 when absent and RE-TIGHTEN a pre-existing one that an
    // older release left group/world-readable. Calling them here is the fix,
    // not merely a check — which is why this stage is a no-op in dry-run.
    if opts.dry_run {
        r.set(StageStatus::Skipped)
            .say("dry-run: would create/re-tighten ~/.huntsman and its subdirectories to 0700");
        return r;
    }

    let base = crate::util::paths::huntsman_dir();
    if !base.is_dir() {
        r.set(StageStatus::Failed)
            .say(format!("could not create {}", base.display()))
            .fix("Check that HOME is writable, then re-run.");
        return r;
    }
    r.say(format!("base: {}", base.display()));

    for sub in ["raw", "dossiers"] {
        let d = crate::util::paths::subdir(sub);
        if d.is_dir() {
            r.say(format!("ok    {}", d.display()));
        } else {
            r.set(StageStatus::Warn)
                .say(format!("missing and could not create {}", d.display()));
        }
    }

    match dir_mode(&base) {
        Some(mode) if mode & 0o077 == 0 => {
            r.say(format!("mode: {mode:04o} (owner-only)"));
        }
        Some(mode) => {
            // `huntsman_dir()` above already attempted the re-tighten, so
            // arriving here means it did not take.
            r.set(StageStatus::Warn)
                .say(format!("mode: {mode:04o} — group/world bits still set"))
                .fix(format!("chmod 700 {}", base.display()));
        }
        None => {
            r.say("mode: not checkable on this platform");
        }
    }

    if r.status == StageStatus::Ok {
        r.say("layout verified");
    }
    r
}

// ── Stage 4: store ──────────────────────────────────────────────────────────

fn stage_store(opts: RepairOptions) -> StageReport {
    let mut r = StageReport::new("store", "Intelligence database");

    let db_path = crate::default_db_path();
    if !Path::new(&db_path).exists() {
        r.say(format!("{db_path} does not exist yet — nothing to repair"))
            .say("it is created on the first scan");
        return r;
    }

    let store = match crate::storage::Store::open(&db_path) {
        Ok(s) => s,
        Err(e) => {
            r.set(StageStatus::Failed)
                .say(format!("cannot open {db_path} — {e}"))
                .fix(
                    "The database is unreadable. It holds your collected intelligence, so \
                     this command will not delete it. Move it aside \
                     (`mv ~/.huntsman/huntsman.db ~/.huntsman/huntsman.db.broken`) to start \
                     a fresh one, keeping the original for recovery.",
                );
            return r;
        }
    };
    r.say("opens cleanly");

    match store.integrity_check() {
        Ok(rows) if rows.iter().all(|x| x == "ok") => r.say("integrity: ok"),
        Ok(rows) => {
            r.set(StageStatus::Warn)
                .say(format!("integrity: {} issue(s) reported", rows.len()));
            for row in rows.iter().take(5) {
                r.say(format!("  {row}"));
            }
            r.fix(
                "SQLite reports corruption. This command will not delete your data. \
                 Export what you can (`hse export --scan-id latest --format json`), then \
                 move the database aside to start fresh.",
            )
        }
        Err(e) => r
            .set(StageStatus::Warn)
            .say(format!("integrity: could not run check — {e}")),
    };

    if opts.dry_run {
        r.say("dry-run: would checkpoint the WAL and VACUUM to reclaim free pages");
        if r.status == StageStatus::Ok {
            r.set(StageStatus::Skipped);
        }
        return r;
    }

    // Checkpoint first: VACUUM cannot rebuild the file while the WAL still
    // holds frames, and truncating the -wal is itself a reclaim.
    let wal = format!("{db_path}-wal");
    let wal_before = file_len(&wal);
    match store.checkpoint_truncate() {
        Ok(()) => {
            let saved = wal_before.saturating_sub(file_len(&wal));
            if saved > 0 {
                r.bytes_freed += saved;
                r.set(StageStatus::Repaired).say(format!(
                    "WAL checkpointed — {} reclaimed",
                    human_bytes(saved)
                ));
            } else {
                r.say("WAL already compact");
            }
        }
        Err(e) => {
            // Busy is the expected, benign case: another hse process holds it.
            r.set(StageStatus::Warn)
                .say(format!("WAL checkpoint skipped — {e}"))
                .fix(
                    "Stop the background server (`hse-bg stop`) and re-run for a full compaction.",
                );
        }
    }

    let db_before = file_len(&db_path);
    match store.vacuum() {
        Ok(()) => {
            let saved = db_before.saturating_sub(file_len(&db_path));
            if saved > 0 {
                r.bytes_freed += saved;
                r.set(StageStatus::Repaired).say(format!(
                    "database compacted — {} reclaimed",
                    human_bytes(saved)
                ));
            } else {
                r.say("database already compact");
            }
        }
        Err(e) => {
            r.set(StageStatus::Warn)
                .say(format!("compaction skipped — {e}"))
                .fix(
                    "Stop the background server (`hse-bg stop`) and re-run for a full compaction.",
                );
        }
    }

    r
}

// ── Stage 5: keys ───────────────────────────────────────────────────────────

fn stage_keys() -> StageReport {
    let mut r = StageReport::new("keys", "Credentials file");

    let path = crate::util::keys::env_path();
    let p = Path::new(&path);
    if !p.exists() {
        r.set(StageStatus::Warn)
            .say(format!("{path} not present"))
            .fix(
                "Keyless modules still run. Add keys with `hse set-key HUNTSMAN_<NAME> <value>`; \
                 `hse doctor` ranks which are worth registering first.",
            );
        return r;
    }
    r.say(format!("present: {path}"));

    match dir_mode(p) {
        Some(mode) if mode & 0o077 == 0 => r.say(format!("mode: {mode:04o} (owner-only)")),
        Some(mode) => r
            .set(StageStatus::Warn)
            .say(format!("mode: {mode:04o} — readable beyond the owner"))
            .fix(format!("chmod 600 {path}")),
        None => r.say("mode: not checkable on this platform"),
    };

    r
}

// ── Stage 6: update ─────────────────────────────────────────────────────────

async fn stage_update(opts: RepairOptions) -> StageReport {
    let mut r = StageReport::new("update", "Build freshness");

    if opts.no_update {
        r.set(StageStatus::Skipped).say("--no-update");
        return r;
    }
    if opts.dry_run {
        r.set(StageStatus::Skipped)
            .say("dry-run: would check for and install a newer build");
        return r;
    }

    let Some(dir) = crate::app::update::find_install_dir() else {
        r.set(StageStatus::Warn)
            .say("source directory not found — this build cannot self-update")
            .fix(format!(
                "Re-run the installer to restore updatability:\n  {}",
                crate::app::update::INSTALL_CMD
            ));
        return r;
    };
    r.say(format!("source: {}", dir.display()));

    match crate::app::update::commits_behind(&dir) {
        Some(0) => {
            r.say("already up to date");
        }
        Some(n) => {
            r.say(format!("{n} commit(s) behind — installing"));
            match crate::app::update::apply_update(None).await {
                Ok(()) => {
                    r.set(StageStatus::Repaired).say("updated");
                }
                Err(e) => {
                    r.set(StageStatus::Failed)
                        .say(format!("update failed — {e}"))
                        .fix(format!(
                            "Re-run the installer, which rebuilds from a clean state:\n  {}",
                            crate::app::update::INSTALL_CMD
                        ));
                }
            }
        }
        None => {
            // Offline is the common case on a phone and is not a fault.
            r.set(StageStatus::Warn)
                .say("could not reach the remote — offline?")
                .fix("Re-run `hse repair` when you have connectivity to pick up newer builds.");
        }
    }

    r
}

// ── Shared helpers ──────────────────────────────────────────────────────────

fn home_dir() -> Option<PathBuf> {
    std::env::var("HOME")
        .ok()
        .filter(|h| !h.is_empty())
        .map(PathBuf::from)
}

/// The source checkout `hse update` builds from, when this build has one.
fn install_dir() -> Option<PathBuf> {
    crate::app::update::find_install_dir()
}

fn file_len(p: impl AsRef<Path>) -> u64 {
    std::fs::metadata(p).map_or(0, |m| m.len())
}

/// The permission bits of `p`, or `None` off Unix.
#[cfg(unix)]
fn dir_mode(p: &Path) -> Option<u32> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(p)
        .ok()
        .map(|m| m.permissions().mode() & 0o7777)
}

#[cfg(not(unix))]
fn dir_mode(_p: &Path) -> Option<u32> {
    None
}

/// Render the report for a terminal.
pub fn print_report(rep: &RepairReport) {
    println!("hse {} — repair", crate::VERSION);
    if rep.dry_run {
        println!("(dry run — nothing was changed)");
    }
    for s in &rep.stages {
        println!("\n[{}] {}", s.status.marker(), s.title);
        for line in &s.detail {
            println!("       {line}");
        }
        if let Some(fix) = &s.remediation {
            for (i, line) in fix.lines().enumerate() {
                println!("       {} {line}", if i == 0 { "→" } else { " " });
            }
        }
    }

    println!();
    if rep.bytes_freed > 0 {
        let verb = if rep.dry_run {
            "reclaimable"
        } else {
            "reclaimed"
        };
        println!("{}: {verb}", human_bytes(rep.bytes_freed));
    }
    println!("verdict: {}", rep.verdict().as_str());
}

/// Map the report onto the process result: only a stage that could not complete
/// is an error, so a `warn` (offline, no keys) still exits 0 for scripting.
pub fn into_result(rep: &RepairReport) -> Result<()> {
    if rep.had_failure() {
        return Err(crate::core::error::Error::Other(
            "repair completed with failures — see the report above".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
