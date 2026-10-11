//! Thin executable over the shared investigation runtime.

use std::env;
use std::process::ExitCode;

use huntsman_recon::exit::{EX_DATAERR, EX_SOFTWARE, EX_USAGE};
use huntsman_recon::pipeline::{InvestigationInput, InvestigationMode, PipelineLimits};
use huntsman_recon::planner::PlannerPolicy;
use huntsman_recon::runtime::investigate_offline;

const USAGE: &str = "usage: investigate SEED [SEED ...]";

fn fail(code: u8, message: &str) -> ExitCode {
    eprintln!("{message}");
    ExitCode::from(code)
}

fn main() -> ExitCode {
    let args = env::args().skip(1).collect::<Vec<_>>();
    if args.len() == 1 && matches!(args[0].as_str(), "-h" | "--help" | "help") {
        println!("{USAGE}");
        println!(
            "Runs the bounded offline Huntsman integration spine; planned external routes are not fetched."
        );
        return ExitCode::SUCCESS;
    }
    if args.len() == 1 && matches!(args[0].as_str(), "-V" | "--version") {
        println!("investigate {}", env!("CARGO_PKG_VERSION"));
        return ExitCode::SUCCESS;
    }
    if args.is_empty() {
        return fail(EX_USAGE, USAGE);
    }
    let input = InvestigationInput {
        scan_id: "cli".to_string(),
        seeds: args,
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
    ExitCode::SUCCESS
}
