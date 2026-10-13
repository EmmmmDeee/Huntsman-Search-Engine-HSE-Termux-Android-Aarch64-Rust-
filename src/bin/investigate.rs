//! Thin executable over the shared investigation runtime.

use std::env;
use std::io::Write;
use std::path::Path;
use std::process::ExitCode;

use huntsman_recon::exit::{EX_DATAERR, EX_NOINPUT, EX_PIPE, EX_SOFTWARE, EX_USAGE};
use huntsman_recon::pipeline::{InvestigationInput, InvestigationMode, PipelineLimits};
use huntsman_recon::planner::PlannerPolicy;
use huntsman_recon::runtime::{investigate_offline, persist_session, session_for_outcome};
use huntsman_recon::session::Session;
use huntsman_recon::stdio_failure::status_for;
use huntsman_recon::store::Store;

const USAGE: &str =
    "usage: investigate [--session-dir DIR] SEED [SEED ...] | investigate --load-session DIR ID";

fn fail(code: u8, message: &str) -> ExitCode {
    eprintln!("{message}");
    ExitCode::from(code)
}

/// A failed print ends the process with the status `stdio_failure` gives it, not a panic.
fn exit_on_output_failure() {
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let Some((status, error)) = status_for(info.payload()) else {
            previous(info);
            return;
        };
        if status != EX_PIPE {
            // Not eprintln!: a second failed print inside the hook would abort the process.
            let _ = writeln!(std::io::stderr(), "output write failed: {error}");
        }
        std::process::exit(i32::from(status));
    }));
}

fn main() -> ExitCode {
    exit_on_output_failure();
    let args = env::args().skip(1).collect::<Vec<_>>();
    if args.len() == 1 && matches!(args[0].as_str(), "-h" | "--help" | "help") {
        println!("{USAGE}");
        println!(
            "Runs the bounded offline Huntsman integration spine; planned external routes are not fetched."
        );
        println!(
            "--session-dir DIR persists the run as a reloadable session; --load-session DIR ID prints a saved one."
        );
        return ExitCode::SUCCESS;
    }
    if args.len() == 1 && matches!(args[0].as_str(), "-V" | "--version") {
        println!("investigate {}", env!("CARGO_PKG_VERSION"));
        return ExitCode::SUCCESS;
    }
    if args.first().is_some_and(|arg| arg == "--load-session") {
        return load_session(&args[1..]);
    }
    run_investigation(args)
}

/// Reload and summarize a session persisted by an earlier `--session-dir` run.
fn load_session(rest: &[String]) -> ExitCode {
    let [dir, id] = rest else {
        return fail(EX_USAGE, "investigate --load-session needs exactly DIR ID");
    };
    match Store::new(dir).load(id) {
        Ok(session) => {
            print_session_summary(&session);
            ExitCode::SUCCESS
        }
        Err(huntsman_recon::error::Error::Store(message)) => fail(EX_NOINPUT, &message),
        Err(error) => fail(EX_DATAERR, &error.to_string()),
    }
}

fn run_investigation(args: Vec<String>) -> ExitCode {
    let (session_dir, seeds) = split_session_dir(args);
    if seeds.is_empty() {
        return fail(EX_USAGE, USAGE);
    }
    let input = InvestigationInput {
        scan_id: "cli".to_string(),
        seeds,
        mode: InvestigationMode::Offline,
    };
    let outcome = match investigate_offline(
        &[],
        &input,
        &PipelineLimits::default(),
        &PlannerPolicy::default(),
        &[],
    ) {
        Ok(outcome) => outcome,
        Err(error) => return fail(EX_SOFTWARE, &format!("investigation failed: {error}")),
    };
    if outcome.normalization.accepted.is_empty() {
        return fail(EX_DATAERR, "no actionable seeds");
    }
    // Save before printing, so a reader that stops early cannot cost the session.
    let saved = session_dir.map(|dir| {
        let session = session_for_outcome(&input, &outcome)
            .map_err(|error| format!("session build failed: {error}"))?;
        persist_session(Path::new(&dir), &session)
            .map(|path| (session.id, path))
            .map_err(|error| format!("session save failed: {error}"))
    });
    println!(
        "accepted={} rejected={} entities={} relations={} planned={} termination={:?} truncated={}",
        outcome.normalization.accepted.len(),
        outcome.normalization.rejected.len(),
        outcome.snapshot.entities.len(),
        outcome.snapshot.relations.len(),
        outcome.plan.selected.len(),
        outcome.report.termination,
        outcome.report.truncated || outcome.artifacts.truncated,
    );
    match saved {
        None => ExitCode::SUCCESS,
        Some(Ok((id, path))) => {
            println!("session={id} saved={}", path.display());
            ExitCode::SUCCESS
        }
        Some(Err(message)) => fail(EX_SOFTWARE, &message),
    }
}

/// Pull an optional `--session-dir DIR` out of the argument list; the rest are seeds.
fn split_session_dir(args: Vec<String>) -> (Option<String>, Vec<String>) {
    let mut dir = None;
    let mut seeds = Vec::with_capacity(args.len());
    let mut it = args.into_iter();
    while let Some(arg) = it.next() {
        if arg == "--session-dir" {
            dir = it.next();
        } else {
            seeds.push(arg);
        }
    }
    (dir, seeds)
}

fn print_session_summary(session: &Session) {
    println!(
        "session={} title={} candidates={} falsifications={} executions={} verifications={} terminated={}",
        session.id,
        session.title,
        session.candidates.len(),
        session.falsifications.len(),
        session.executions.len(),
        session.verifications.len(),
        session.termination.is_some(),
    );
}
