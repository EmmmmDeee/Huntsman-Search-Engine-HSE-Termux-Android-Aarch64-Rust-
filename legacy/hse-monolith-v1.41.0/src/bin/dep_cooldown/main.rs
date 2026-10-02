//! `dep-cooldown` — supply-chain gate: fails when a crates.io dependency in
//! `Cargo.lock` was published more recently than the configured cooldown
//! window, unless explicitly allow-listed in `dep-cooldown.toml`.
//!
//! A freshly published version is exactly the moment a stolen publish token
//! or hijacked maintainer account is most likely to slip a compromised
//! release through unnoticed — RustSec/crates.io typically catch and yank a
//! malicious release within days, not hours, so a cooldown window buys real
//! detection time before an unreviewed version reaches this project. Mirrors
//! `cargo audit`/`cargo deny` in scripts/gate.sh and
//! .github/workflows/audit.yml: advisory-quality, wired only when a manifest
//! changed, never a required check.
//!
//! An ISOLATED crates.io fetch failure is reported but non-fatal by default
//! (`--strict` makes it fatal) — for the same reason: this repo's existing
//! supply-chain gates must not fail an unrelated PR on a transient crates.io
//! outage. A COMPLETE fetch failure (every lookup failed) is always fatal
//! regardless of `--strict`: verifying zero of N dependencies must never
//! report the same "OK" a clean run would — see [`policy::should_fail`].

mod lockfile;
mod policy;
mod registry;

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::Parser;

use huntsman_search_engine::util::http::build_client;
use policy::{DEFAULT_COOLDOWN_DAYS, Violation, find_violations, parse_policy_file, should_fail};

#[derive(Parser)]
#[command(
    name = "dep-cooldown",
    about = "Fail when a Cargo.lock dependency was published inside the cooldown window"
)]
struct Args {
    /// Path to Cargo.lock.
    #[arg(long, default_value = "Cargo.lock")]
    lockfile: PathBuf,

    /// Path to the cooldown policy / allow-list file. Missing is not an
    /// error — it means "no overrides, no exceptions", the same as an empty
    /// file.
    #[arg(long, default_value = "dep-cooldown.toml")]
    policy: PathBuf,

    /// Override the cooldown window in days. Takes precedence over
    /// `dep-cooldown.toml`'s `cooldown_days`, which in turn takes precedence
    /// over [`DEFAULT_COOLDOWN_DAYS`].
    #[arg(long)]
    cooldown_days: Option<u32>,

    /// Treat a crates.io lookup failure as a hard failure (exit 1) instead of
    /// a warning. Off by default so a transient registry outage cannot fail
    /// an unrelated PR — see the module-level doc comment.
    #[arg(long)]
    strict: bool,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let args = Args::parse();
    match run(&args).await {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(e) => {
            eprintln!("dep-cooldown: error: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Runs the check; `Ok(true)` means "gate passes" (no violations, and no
/// fetch error under `--strict`), `Ok(false)` means "gate fails" (a real
/// violation, or a fetch error under `--strict`). Split from `main` so the
/// pass/fail decision is a plain returned bool, not tangled with the process
/// exit code.
async fn run(args: &Args) -> Result<bool, String> {
    let lock_raw = std::fs::read_to_string(&args.lockfile)
        .map_err(|e| format!("reading {}: {e}", args.lockfile.display()))?;
    let packages = lockfile::crates_io_packages(&lock_raw)
        .map_err(|e| format!("parsing {}: {e}", args.lockfile.display()))?;

    let policy_file = load_policy_file(&args.policy)?;
    let cooldown_days = args
        .cooldown_days
        .or(policy_file.cooldown_days)
        .unwrap_or(DEFAULT_COOLDOWN_DAYS);

    println!(
        "dep-cooldown: checking {} crates.io {} against a {cooldown_days}-day cooldown ({} allow-listed)",
        packages.len(),
        if packages.len() == 1 {
            "dependency"
        } else {
            "dependencies"
        },
        policy_file.allow.len(),
    );

    let client = build_client();
    let (resolved, fetch_errors) = registry::fetch_publish_dates(&client, &packages).await;

    let now = time::OffsetDateTime::now_utc();
    let violations = find_violations(now, cooldown_days, &resolved, &policy_file.allow);

    for e in &fetch_errors {
        eprintln!(
            "dep-cooldown: warning: could not verify publish date of {} {}: {}",
            e.name, e.version, e.message
        );
    }

    let total_packages = packages.len();
    let failed = should_fail(&violations, &fetch_errors, total_packages, args.strict);

    if !violations.is_empty() {
        eprintln!(
            "dep-cooldown: {} {} inside the cooldown window:",
            violations.len(),
            if violations.len() == 1 {
                "dependency is"
            } else {
                "dependencies are"
            },
        );
        for v in &violations {
            print_violation(v);
        }
        eprintln!(
            "dep-cooldown: if a version above is a deliberate, reviewed upgrade, add it to {} \
             under [[allow]] with a reason — see the file's own comments for the format.",
            args.policy.display()
        );
    }

    if total_packages > 0 && fetch_errors.len() == total_packages {
        eprintln!(
            "dep-cooldown: every crates.io lookup failed — 0 of {total_packages} dependencies were \
             actually verified. Treating this as a failure regardless of --strict: an unreachable \
             registry must not silently report a clean pass."
        );
    } else if args.strict && !fetch_errors.is_empty() {
        eprintln!(
            "dep-cooldown: --strict set and {} crates.io lookup(s) failed — treating as a gate failure",
            fetch_errors.len()
        );
    }

    if !failed {
        if fetch_errors.is_empty() {
            println!(
                "dep-cooldown: OK — checked all {total_packages} dependencies, none inside the cooldown window"
            );
        } else {
            println!(
                "dep-cooldown: OK — checked {} of {total_packages} dependencies (the rest could not \
                 be verified; see warnings above), none inside the cooldown window",
                resolved.len()
            );
        }
    }

    Ok(!failed)
}

fn print_violation(v: &Violation) {
    if v.days_since_publish < 0 {
        eprintln!(
            "  {} {} — publish timestamp is in the future relative to this check (clock skew or \
             registry anomaly); treated as inside the {}-day cooldown",
            v.name, v.version, v.cooldown_days
        );
    } else {
        eprintln!(
            "  {} {} — published {} day(s) ago, cooldown is {} day(s)",
            v.name, v.version, v.days_since_publish, v.cooldown_days
        );
    }
}

/// Load and parse `path`; a missing file is treated as an empty policy (no
/// override, no allow-list) rather than an error, since a repo with no
/// exceptions and no need to override the default has no reason to carry an
/// empty file.
fn load_policy_file(path: &Path) -> Result<policy::PolicyFile, String> {
    match std::fs::read_to_string(path) {
        Ok(raw) => parse_policy_file(&raw).map_err(|e| format!("parsing {}: {e}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(policy::PolicyFile::default()),
        Err(e) => Err(format!("reading {}: {e}", path.display())),
    }
}

#[cfg(test)]
mod tests {
    include!("main_tests.rs");
}
