//! Person-selector lookup adapters.

use std::path::Path;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::cli::fail;
use huntsman_recon::email_cli::{EMAIL_USAGE, EmailArgs, EmailRun};
use huntsman_recon::entity::Entity;
use huntsman_recon::error::Error;
use huntsman_recon::exit::{EX_DATAERR, EX_IOERR, EX_NOPERM, EX_UNAVAILABLE, EX_USAGE};
use huntsman_recon::http::{TransportConfig, UreqTransport};
use huntsman_recon::lookup_save::{self, EMAIL_POLICY, PHONE_POLICY, SavePolicy, USERNAME_POLICY};
use huntsman_recon::people_cli::{self, PEOPLE_USAGE, PeopleArgs, PeopleRun};
use huntsman_recon::phone_cli::{PHONE_USAGE, PhoneArgs, PhoneRun};
use huntsman_recon::source_outcome::SourceExecutionOutcome;
use huntsman_recon::username_cli::{USERNAME_USAGE, UsernameArgs, UsernameRun};

/// Saves the lookup ledger when `--save` was given, then prints its summary. A store failure
/// exits 74 and any other save failure exits 65. Without `--save`, nothing is written or printed.
fn save_if_requested(
    save: Option<&Path>,
    entities: &[Entity],
    outcomes: &[SourceExecutionOutcome],
    policy: SavePolicy,
) -> ExitCode {
    let Some(path) = save else {
        return ExitCode::SUCCESS;
    };
    match lookup_save::save(path, entities, outcomes, policy) {
        Ok(entries) => {
            println!("saved={}", path.display());
            println!("entries={}", entries.len());
            println!(
                "tip={}",
                entries.last().map_or("none", |entry| entry.hash.as_str())
            );
            ExitCode::SUCCESS
        }
        Err(Error::Store(message)) => fail(EX_IOERR, &message),
        Err(error) => fail(EX_DATAERR, &error.to_string()),
    }
}

pub(in crate::cli) fn people_cmd(args: &[String]) -> ExitCode {
    let parsed = match PeopleArgs::parse(args) {
        Ok(p) => p,
        Err(e) => return fail(EX_USAGE, &format!("{e}\n{PEOPLE_USAGE}")),
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let transport = UreqTransport::new(&TransportConfig::default());
    match people_cli::run(&transport, &parsed.name, now) {
        PeopleRun::Printed { text, report } => {
            print!("{text}");
            // An empty people lookup has nothing to save, so it writes no ledger and prints no summary.
            if report.entities.is_empty() && report.outcomes.is_empty() {
                return ExitCode::SUCCESS;
            }
            save_if_requested(
                parsed.save.as_deref(),
                &report.entities,
                &report.outcomes,
                lookup_save::PEOPLE_POLICY,
            )
        }
        PeopleRun::Network(msg) => fail(EX_NOPERM, &msg),
        PeopleRun::Failed(msg) => fail(EX_UNAVAILABLE, &msg),
    }
}

pub(in crate::cli) fn email_cmd(args: &[String]) -> ExitCode {
    let parsed = match EmailArgs::parse(args) {
        Ok(parsed) => parsed,
        Err(err) => {
            let message = err.to_string();
            let code = if message.contains("invalid email address") {
                EX_DATAERR
            } else {
                EX_USAGE
            };
            return fail(code, &format!("{message}\n{EMAIL_USAGE}"));
        }
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs());
    let transport = UreqTransport::new(&TransportConfig::default());
    match huntsman_recon::email_cli::run(&transport, &parsed.email, now) {
        EmailRun::Printed { text, report } => {
            print!("{text}");
            save_if_requested(
                parsed.save.as_deref(),
                &report.entities,
                &report.outcomes,
                EMAIL_POLICY,
            )
        }
        EmailRun::Network(message) => fail(EX_NOPERM, &message),
        EmailRun::Failed(message) => fail(EX_UNAVAILABLE, &message),
    }
}

pub(in crate::cli) fn username_cmd(args: &[String]) -> ExitCode {
    let parsed = match UsernameArgs::parse(args) {
        Ok(parsed) => parsed,
        Err(error) => {
            let message = error.to_string();
            let code = if message.contains("username selector") {
                EX_DATAERR
            } else {
                EX_USAGE
            };
            return fail(code, &format!("{message}\n{USERNAME_USAGE}"));
        }
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs());
    let transport = UreqTransport::new(&TransportConfig::default());
    match huntsman_recon::username_cli::run(&transport, &parsed.username, now) {
        UsernameRun::Printed { text, report } => {
            print!("{text}");
            save_if_requested(
                parsed.save.as_deref(),
                &report.entities,
                &report.outcomes,
                USERNAME_POLICY,
            )
        }
        UsernameRun::Failed(message) => fail(EX_UNAVAILABLE, &message),
    }
}

pub(in crate::cli) fn phone_cmd(args: &[String]) -> ExitCode {
    let parsed = match PhoneArgs::parse(args) {
        Ok(parsed) => parsed,
        Err(error) => {
            let message = error.to_string();
            let code =
                if message.contains("phone must") || message.contains("unknown international") {
                    EX_DATAERR
                } else {
                    EX_USAGE
                };
            return fail(code, &format!("{message}\n{PHONE_USAGE}"));
        }
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs());
    match huntsman_recon::phone_cli::run(&parsed.phone, now) {
        PhoneRun::Printed { text, report } => {
            print!("{text}");
            save_if_requested(
                parsed.save.as_deref(),
                &report.entities,
                &report.outcomes,
                PHONE_POLICY,
            )
        }
        PhoneRun::Failed(message) => fail(EX_DATAERR, &message),
    }
}
