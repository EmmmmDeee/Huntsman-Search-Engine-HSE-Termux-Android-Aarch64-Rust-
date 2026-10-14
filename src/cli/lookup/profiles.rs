//! Person-selector lookup adapters.
//!
//! [`collect`] is the one execution path per lookup kind. The `people`, `email`, `exposure`,
//! `username` and `phone` commands, `scan`, and the Web UI's `/api/lookup` all run through it,
//! so a kind cannot behave differently depending on where it was asked from.

use std::path::Path;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::cli::fail;
use huntsman_recon::email_cli::{EMAIL_USAGE, EmailArgs, EmailRun};
use huntsman_recon::entity::Entity;
use huntsman_recon::error::Error;
use huntsman_recon::exit::{EX_DATAERR, EX_IOERR, EX_NOPERM, EX_UNAVAILABLE, EX_USAGE};
use huntsman_recon::exposure_cli::{EXPOSURE_USAGE, ExposureArgs, ExposureRun, Sources};
use huntsman_recon::hibp::client::{Auth, HibpClient, HibpConfig};
use huntsman_recon::hibp::key::KeyLoader;
use huntsman_recon::http::{Transport, TransportConfig, UreqTransport};
use huntsman_recon::keys::Keys;
use huntsman_recon::lookup_save::{
    self, DOMAIN_POLICY, EMAIL_POLICY, EXPOSURE_POLICY, PEOPLE_POLICY, PHONE_POLICY, SavePolicy,
    USERNAME_POLICY,
};
use huntsman_recon::oathnet;
use huntsman_recon::people_cli::{self, PEOPLE_USAGE, PeopleArgs, PeopleRun};
use huntsman_recon::phone_cli::{PHONE_USAGE, PhoneArgs, PhoneRun};
use huntsman_recon::scan_route::ScanKind;
use huntsman_recon::source_outcome::SourceExecutionOutcome;
use huntsman_recon::stolen_tax;
use huntsman_recon::username_cli::{USERNAME_USAGE, UsernameArgs, UsernameRun};

/// One finished lookup: the rendered report, what it is made of, and how to save it.
pub(in crate::cli) struct Collected {
    pub text: String,
    pub entities: Vec<Entity>,
    pub outcomes: Vec<SourceExecutionOutcome>,
    pub policy: SavePolicy,
}

/// Why a lookup produced no report. Each variant has one exit status.
#[derive(Debug)]
pub(in crate::cli) enum Refused {
    /// The egress policy or the network stopped every source.
    Network(String),
    /// The sources ran and gave nothing usable.
    Unavailable(String),
    /// The selector could not be used.
    Data(String),
}

impl Refused {
    pub(in crate::cli) const fn exit_status(&self) -> u8 {
        match self {
            Self::Network(_) => EX_NOPERM,
            Self::Unavailable(_) => EX_UNAVAILABLE,
            Self::Data(_) => EX_DATAERR,
        }
    }

    pub(in crate::cli) fn message(&self) -> &str {
        match self {
            Self::Network(m) | Self::Unavailable(m) | Self::Data(m) => m,
        }
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

/// Run one lookup of `kind` for an already-parsed `selector`.
///
/// # Errors
/// [`Refused`] when the lookup produced no report.
pub(in crate::cli) fn collect(kind: ScanKind, selector: &str) -> Result<Collected, Refused> {
    let now = now_unix();
    let done = |text, entities, outcomes, policy| Collected {
        text,
        entities,
        outcomes,
        policy,
    };
    match kind {
        ScanKind::People => {
            let transport = UreqTransport::new(&TransportConfig::default());
            match people_cli::run(&transport, selector, now) {
                PeopleRun::Printed { text, report } => {
                    Ok(done(text, report.entities, report.outcomes, PEOPLE_POLICY))
                }
                PeopleRun::Network(m) => Err(Refused::Network(m)),
                PeopleRun::Failed(m) => Err(Refused::Unavailable(m)),
            }
        }
        ScanKind::Email => {
            let transport = UreqTransport::new(&TransportConfig::default());
            match huntsman_recon::email_cli::run(&transport, selector, now) {
                EmailRun::Printed { text, report } => {
                    Ok(done(text, report.entities, report.outcomes, EMAIL_POLICY))
                }
                EmailRun::Network(m) => Err(Refused::Network(m)),
                EmailRun::Failed(m) => Err(Refused::Unavailable(m)),
            }
        }
        ScanKind::Exposure => {
            let client = KeyLoader::default_chain(None)
                .load()
                .map(|(key, _)| HibpClient::production(Auth::ApiKey(key), HibpConfig::default()));
            // Same rule as `recon stolen-tax`: the stolen.tax and OathNet keys are read from the
            // environment, never the default file.
            let keys = Keys::from_env();
            let transport = UreqTransport::new(&stolen_tax::transport_config());
            let oathnet_transport = UreqTransport::new(&oathnet::transport_config());
            let sources = Sources {
                hibp: client.as_ref(),
                stolen_tax: keys
                    .get(stolen_tax::KEY_SLOT)
                    .is_some()
                    .then_some((&transport as &dyn Transport, &keys)),
                oathnet: keys
                    .get(oathnet::KEY_SLOT)
                    .is_some()
                    .then_some((&oathnet_transport as &dyn Transport, &keys)),
            };
            match huntsman_recon::exposure_cli::run(sources, selector, now) {
                ExposureRun::Printed { text, report } => Ok(done(
                    text,
                    report.entities,
                    report.outcomes,
                    EXPOSURE_POLICY,
                )),
                ExposureRun::Network(m) => Err(Refused::Network(m)),
                ExposureRun::Failed(m) => Err(Refused::Unavailable(m)),
            }
        }
        ScanKind::Username => {
            let transport = UreqTransport::new(&TransportConfig::default());
            let keys = Keys::from_env();
            match huntsman_recon::username_cli::run(&transport, &keys, selector, now) {
                UsernameRun::Printed { text, report } => Ok(done(
                    text,
                    report.entities,
                    report.outcomes,
                    USERNAME_POLICY,
                )),
                UsernameRun::Failed(m) => Err(Refused::Unavailable(m)),
            }
        }
        ScanKind::Phone => match huntsman_recon::phone_cli::run(selector, now) {
            PhoneRun::Printed { text, report } => {
                Ok(done(text, report.entities, report.outcomes, PHONE_POLICY))
            }
            PhoneRun::Failed(m) => Err(Refused::Data(m)),
        },
        ScanKind::Domain => {
            let transport = UreqTransport::new(&TransportConfig::default());
            match huntsman_recon::domain_cli::run(&transport, selector, now) {
                huntsman_recon::domain_cli::DomainRun::Printed { text, report } => {
                    Ok(done(text, report.entities, report.outcomes, DOMAIN_POLICY))
                }
                huntsman_recon::domain_cli::DomainRun::Network(m) => Err(Refused::Network(m)),
                huntsman_recon::domain_cli::DomainRun::Failed(m) => Err(Refused::Unavailable(m)),
            }
        }
    }
}

/// The exit status for a rejected lookup argument. A value the operator supplied that cannot be
/// canonicalised is a data error (65); every other rejection is a usage error (64). The error's
/// variant decides, so no wording of a message, and no echoed option text, can change the status.
fn argument_status(error: &Error) -> u8 {
    match error {
        Error::InvalidValue(_) => EX_DATAERR,
        _ => EX_USAGE,
    }
}

fn usage_failure(error: &Error, usage: &str) -> ExitCode {
    fail(argument_status(error), &format!("{error}\n{usage}"))
}

/// Saves the report when `--save` was given, then prints it. A store failure exits 74 and any
/// other save failure exits 65. Without `--save`, nothing is written. The save comes first so a
/// reader that stops early, which ends the process at the next print, cannot cost the ledger.
fn finish(kind: ScanKind, selector: &str, save: Option<&Path>) -> ExitCode {
    let collected = match collect(kind, selector) {
        Ok(collected) => collected,
        Err(refused) => return fail(refused.exit_status(), refused.message()),
    };
    // An empty lookup (the people skip path) has nothing to save and prints no summary.
    let empty = collected.entities.is_empty() && collected.outcomes.is_empty();
    let saved = save.filter(|_| !empty).map(|path| {
        let entries = lookup_save::save(
            path,
            &collected.entities,
            &collected.outcomes,
            collected.policy,
        );
        (path, entries)
    });
    print!("{}", collected.text);
    let Some((path, entries)) = saved else {
        return ExitCode::SUCCESS;
    };
    match entries {
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
    match PeopleArgs::parse(args) {
        Ok(p) => finish(ScanKind::People, &p.name, p.save.as_deref()),
        Err(e) => fail(EX_USAGE, &format!("{e}\n{PEOPLE_USAGE}")),
    }
}

pub(in crate::cli) fn email_cmd(args: &[String]) -> ExitCode {
    match EmailArgs::parse(args) {
        Ok(p) => finish(ScanKind::Email, &p.email, p.save.as_deref()),
        Err(e) => usage_failure(&e, EMAIL_USAGE),
    }
}

pub(in crate::cli) fn exposure_cmd(args: &[String]) -> ExitCode {
    match ExposureArgs::parse(args) {
        Ok(p) => finish(ScanKind::Exposure, &p.selector, p.save.as_deref()),
        Err(e) => usage_failure(&e, EXPOSURE_USAGE),
    }
}

pub(in crate::cli) fn username_cmd(args: &[String]) -> ExitCode {
    match UsernameArgs::parse(args) {
        Ok(p) => finish(ScanKind::Username, &p.username, p.save.as_deref()),
        Err(e) => usage_failure(&e, USERNAME_USAGE),
    }
}

pub(in crate::cli) fn phone_cmd(args: &[String]) -> ExitCode {
    match PhoneArgs::parse(args) {
        Ok(p) => finish(ScanKind::Phone, &p.phone, p.save.as_deref()),
        Err(e) => usage_failure(&e, PHONE_USAGE),
    }
}

pub(in crate::cli) fn domain_cmd(args: &[String]) -> ExitCode {
    use huntsman_recon::domain_cli::{DOMAIN_USAGE, DomainArgs};
    match DomainArgs::parse(args) {
        Ok(p) => finish(ScanKind::Domain, &p.domain, p.save.as_deref()),
        Err(e) => usage_failure(&e, DOMAIN_USAGE),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_rejected_value_exits_65_and_a_usage_error_exits_64() {
        assert_eq!(
            argument_status(&Error::invalid_value("invalid email address")),
            EX_DATAERR
        );
        assert_eq!(
            argument_status(&Error::invalid("only one --save")),
            EX_USAGE
        );
    }

    #[test]
    fn echoed_option_text_cannot_change_the_status() {
        // Before typed errors, the text of an unknown option could select 65 by substring.
        assert_eq!(
            argument_status(&Error::invalid("unknown option --invalid email address")),
            EX_USAGE
        );
    }
}
