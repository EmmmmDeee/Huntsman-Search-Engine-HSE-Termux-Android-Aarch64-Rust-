//! The offline investigation spine: plan an investigation from seeds, and save or reload it as a
//! session. Planned external routes are not fetched.

use std::path::Path;
use std::process::ExitCode;

use crate::cli::fail;
use huntsman_recon::error::Error;
use huntsman_recon::exit::{EX_DATAERR, EX_IOERR, EX_NOINPUT, EX_USAGE};
use huntsman_recon::pipeline::{InvestigationInput, InvestigationMode, PipelineLimits};
use huntsman_recon::planner::PlannerPolicy;
use huntsman_recon::runtime::{investigate_offline, persist_session, session_for_outcome};
use huntsman_recon::session::Session;
use huntsman_recon::store::Store;

const PLAN_USAGE: &str =
    "usage: huntsman-recon plan [--session-dir DIR] SEED [SEED ...] | plan --load-session DIR ID";

pub(in crate::cli) fn plan_cmd(args: &[String]) -> ExitCode {
    if args.first().is_some_and(|arg| arg == "--load-session") {
        return load_session(&args[1..]);
    }
    let (session_dir, seeds) = match split_session_dir(args) {
        Ok(split) => split,
        Err(message) => return fail(EX_USAGE, &format!("{message}\n{PLAN_USAGE}")),
    };
    if seeds.is_empty() {
        return fail(EX_USAGE, PLAN_USAGE);
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
        Err(error) => return fail(EX_DATAERR, &format!("plan failed: {error}")),
    };
    if outcome.normalization.accepted.is_empty() {
        return fail(EX_DATAERR, "no actionable seeds");
    }
    // Save before printing, so a reader that stops early cannot cost the session.
    let saved = session_dir.map(|dir| {
        session_for_outcome(&input, &outcome).and_then(|session| {
            persist_session(Path::new(dir), &session).map(|path| (session.id, path))
        })
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
    // The same statuses as a lookup's `--save`: a failed write is an output error.
    match saved {
        None => ExitCode::SUCCESS,
        Some(Ok((id, path))) => {
            println!("session={id} saved={}", path.display());
            ExitCode::SUCCESS
        }
        Some(Err(Error::Store(message))) => fail(EX_IOERR, &message),
        Some(Err(error)) => fail(EX_DATAERR, &error.to_string()),
    }
}

/// `--session-dir DIR` at most once, and the seeds. Any other option is refused: a mistyped
/// option would otherwise be taken for a seed, rejected, and the run left unsaved.
fn split_session_dir(args: &[String]) -> Result<(Option<&str>, Vec<String>), String> {
    let mut dir = None;
    let mut seeds = Vec::with_capacity(args.len());
    let mut rest = args.iter();
    while let Some(arg) = rest.next() {
        match arg.as_str() {
            "--session-dir" => {
                let Some(value) = rest.next().filter(|value| !value.starts_with("--")) else {
                    return Err("plan --session-dir needs a directory path".to_owned());
                };
                if dir.replace(value.as_str()).is_some() {
                    return Err("plan accepts only one --session-dir".to_owned());
                }
            }
            "--load-session" => {
                return Err("--load-session must be the first plan argument".to_owned());
            }
            option if option.starts_with("--") => {
                return Err(format!("unknown plan option {option}"));
            }
            seed => seeds.push(seed.to_owned()),
        }
    }
    Ok((dir, seeds))
}

/// Reload and summarize a session saved by an earlier `--session-dir` run.
fn load_session(rest: &[String]) -> ExitCode {
    let [dir, id] = rest else {
        return fail(
            EX_USAGE,
            &format!("plan --load-session needs exactly DIR ID\n{PLAN_USAGE}"),
        );
    };
    // A session that cannot be read is unreadable input (66); one that is read but does not
    // parse, which a session an older build wrote can be, is bad data (65), as for a ledger.
    match Store::new(dir).load(id) {
        Ok(session) => {
            print_session_summary(&session);
            ExitCode::SUCCESS
        }
        Err(Error::Store(message)) => fail(EX_NOINPUT, &message),
        Err(error) => fail(EX_DATAERR, &error.to_string()),
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn split(args: &[&str]) -> Result<(Option<String>, Vec<String>), String> {
        let args: Vec<String> = args.iter().map(|arg| (*arg).to_owned()).collect();
        split_session_dir(&args).map(|(dir, seeds)| (dir.map(str::to_owned), seeds))
    }

    #[test]
    fn the_session_directory_is_taken_once_wherever_it_appears() {
        assert_eq!(
            split(&["a@example.com", "--session-dir", "out", "example.com"]),
            Ok((
                Some("out".to_owned()),
                vec!["a@example.com".to_owned(), "example.com".to_owned()]
            ))
        );
        assert_eq!(
            split(&["example.com"]),
            Ok((None, vec!["example.com".to_owned()]))
        );
    }

    #[test]
    fn a_request_to_save_is_never_dropped() {
        for args in [
            &["example.com", "--session-dir"][..],
            &["--session-dir", "--other", "example.com"][..],
            &["--session-dir", "a", "--session-dir", "b", "example.com"][..],
            &["--sesion-dir", "a", "example.com"][..],
            &["example.com", "--load-session", "a", "b"][..],
        ] {
            assert!(split(args).is_err(), "{args:?}");
        }
    }
}
