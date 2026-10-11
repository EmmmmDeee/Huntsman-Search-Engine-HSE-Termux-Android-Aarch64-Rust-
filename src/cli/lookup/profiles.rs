//! Person-selector lookup adapters.

use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::cli::{EX_DATAERR, EX_IOERR, EX_NOPERM, EX_UNAVAILABLE, EX_USAGE, fail};
use huntsman_recon::email_cli::{EMAIL_USAGE, EmailArgs, EmailRun};
use huntsman_recon::error::Error;
use huntsman_recon::http::{TransportConfig, UreqTransport};
use huntsman_recon::lookup_save::{self, EMAIL_POLICY, PHONE_POLICY, USERNAME_POLICY};
use huntsman_recon::people_cli::{self, PEOPLE_USAGE, PeopleArgs, PeopleRun};
use huntsman_recon::phone_cli::{PHONE_USAGE, PhoneArgs, PhoneRun};
use huntsman_recon::username_cli::{USERNAME_USAGE, UsernameArgs, UsernameRun};

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
            if let Some(path) = parsed.save {
                if report.entities.is_empty() && report.outcomes.is_empty() {
                    return ExitCode::SUCCESS;
                }
                match lookup_save::save(
                    &path,
                    &report.entities,
                    &report.outcomes,
                    lookup_save::PEOPLE_POLICY,
                ) {
                    Ok(entries) => {
                        println!("saved={}", path.display());
                        println!("entries={}", entries.len());
                        println!("tip={}", entries.last().map_or("none", |e| e.hash.as_str()));
                        ExitCode::SUCCESS
                    }
                    Err(Error::Store(msg)) => fail(EX_IOERR, &msg),
                    Err(e) => fail(EX_DATAERR, &e.to_string()),
                }
            } else {
                ExitCode::SUCCESS
            }
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
            if let Some(path) = parsed.save {
                match lookup_save::save(&path, &report.entities, &report.outcomes, EMAIL_POLICY) {
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
                    Err(err) => fail(EX_DATAERR, &err.to_string()),
                }
            } else {
                ExitCode::SUCCESS
            }
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
            if let Some(path) = parsed.save {
                match lookup_save::save(&path, &report.entities, &report.outcomes, USERNAME_POLICY)
                {
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
            } else {
                ExitCode::SUCCESS
            }
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
            if let Some(path) = parsed.save {
                match lookup_save::save(&path, &report.entities, &report.outcomes, PHONE_POLICY) {
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
            } else {
                ExitCode::SUCCESS
            }
        }
        PhoneRun::Failed(message) => fail(EX_DATAERR, &message),
    }
}
