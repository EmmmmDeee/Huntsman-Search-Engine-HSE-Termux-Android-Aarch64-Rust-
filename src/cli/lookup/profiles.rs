//! Person-selector lookup adapters.
//!
//! [`collect`] is the one execution path per lookup kind. The `people`, `email`, `exposure`,
//! `username`, `phone`, `domain` and `network` commands, `scan`, and the Web UI's `/api/lookup` all run through it,
//! so a kind cannot behave differently depending on where it was asked from.

use std::path::Path;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::cli::fail;
use huntsman_recon::api_leg;
use huntsman_recon::dehashed::{self, client::DehashedClient};
use huntsman_recon::email_cli::{EMAIL_USAGE, EmailArgs, EmailRun};
use huntsman_recon::entity::{Entity, EntityKind, merge_by_uid};
use huntsman_recon::error::Error;
use huntsman_recon::exit::{EX_DATAERR, EX_IOERR, EX_NOPERM, EX_UNAVAILABLE, EX_USAGE};
use huntsman_recon::exposure_cli::{EXPOSURE_USAGE, ExposureArgs, ExposureRun, Sources};
use huntsman_recon::hibp::client::{Auth, HibpClient, HibpConfig};
use huntsman_recon::hibp::key::KeyLoader;
use huntsman_recon::http::{Transport, TransportConfig, UreqTransport};
use huntsman_recon::ip_cli::{IP_USAGE, IpArgs, IpRun};
use huntsman_recon::keys::Keys;
use huntsman_recon::lookup_save::{
    self, DOMAIN_POLICY, EMAIL_POLICY, EXPOSURE_POLICY, IP_POLICY, NETWORK_POLICY, PEOPLE_POLICY,
    PHONE_POLICY, SavePolicy, USERNAME_POLICY,
};
use huntsman_recon::network_cli::{NETWORK_USAGE, NetworkArgs, NetworkRun};
use huntsman_recon::oathnet;
use huntsman_recon::people_cli::{self, PEOPLE_USAGE, PeopleArgs, PeopleRun};
use huntsman_recon::phone_cli::{PHONE_USAGE, PhoneArgs, PhoneRun};
use huntsman_recon::scan_route::ScanKind;
use huntsman_recon::sf_compat::SfRefused;
use huntsman_recon::source_outcome::SourceExecutionOutcome;
use huntsman_recon::stolen_tax;
use huntsman_recon::username_cli::{USERNAME_USAGE, UsernameArgs, UsernameRun};
use huntsman_recon::wigle;

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

/// `sf -s` runs the same front-ends, so its refusal takes the same status: each arm becomes the
/// arm of the same name, and [`Refused::exit_status`] stays the one status table.
impl From<SfRefused> for Refused {
    fn from(refused: SfRefused) -> Self {
        match refused {
            SfRefused::Network(m) => Self::Network(m),
            SfRefused::Unavailable(m) => Self::Unavailable(m),
            SfRefused::Data(m) => Self::Data(m),
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
    match kind {
        ScanKind::People => people(selector, now),
        ScanKind::Email => email(selector, now),
        ScanKind::Exposure => exposure(selector, now),
        ScanKind::Username => username(selector, now),
        ScanKind::Phone => phone(selector, now),
        ScanKind::Ip => ip(selector, now),
        ScanKind::Domain => domain(selector, now),
        ScanKind::Network => network(selector, now),
    }
}

/// A finished report of one kind, saved under `policy`.
fn done(
    text: String,
    entities: Vec<Entity>,
    outcomes: Vec<SourceExecutionOutcome>,
    policy: SavePolicy,
) -> Collected {
    Collected {
        text,
        entities,
        outcomes,
        policy,
    }
}

/// The people-search sources for a name, with the `SeekNow` leg when its key is configured.
fn people(selector: &str, now: u64) -> Result<Collected, Refused> {
    let transport = UreqTransport::new(&TransportConfig::default());
    let keys = Keys::from_env();
    match people_cli::run(&transport, selector, now) {
        PeopleRun::Printed { text, report } => {
            let (text, entities, outcomes) = with_seeknow_leg(
                EntityKind::Person,
                selector,
                &keys,
                now,
                text,
                report.entities,
                report.outcomes,
            )?;
            Ok(done(text, entities, outcomes, PEOPLE_POLICY))
        }
        PeopleRun::Network(m) => Err(Refused::Network(m)),
        PeopleRun::Failed(m) => Err(Refused::Unavailable(m)),
    }
}

/// The email sources for an address, with the `SeekNow` leg when its key is configured.
fn email(selector: &str, now: u64) -> Result<Collected, Refused> {
    let keys = Keys::from_env();
    let transport = UreqTransport::new(&api_leg::transport_config());
    match huntsman_recon::email_cli::run_keyed(&transport, &keys, selector, now) {
        EmailRun::Printed { text, report } => {
            let (text, entities, outcomes) = with_seeknow_leg(
                EntityKind::Email,
                selector,
                &keys,
                now,
                text,
                report.entities,
                report.outcomes,
            )?;
            Ok(done(text, entities, outcomes, EMAIL_POLICY))
        }
        EmailRun::Network(m) => Err(Refused::Network(m)),
        EmailRun::Failed(m) => Err(Refused::Unavailable(m)),
    }
}

/// Append a `SeekNow` leg to a lookup's report when `HUNTSMAN_SEEKNOW_KEY` is configured.
///
/// With no key, the leg makes no request and the report is returned unchanged, byte for byte.
/// With the key set, `SeekNow`'s entities are merged into the report by uid, its source outcome
/// is appended, and the report text is re-rendered so the console shows the merged result. A
/// `SeekNow` failure is reported as one outcome row, never an abort of the lookup.
fn with_seeknow_leg(
    kind: EntityKind,
    selector: &str,
    keys: &Keys,
    now: u64,
    text: String,
    entities: Vec<Entity>,
    outcomes: Vec<SourceExecutionOutcome>,
) -> Result<(String, Vec<Entity>, Vec<SourceExecutionOutcome>), Refused> {
    let transport = UreqTransport::new(&TransportConfig::default());
    let Some(leg) = huntsman_recon::seeknow_collector::collect_for_lookup(
        &transport, kind, selector, keys, now,
    ) else {
        return Ok((text, entities, outcomes));
    };
    let mut entities = entities;
    let mut outcomes = outcomes;
    entities.extend(leg.entities);
    merge_by_uid(&mut entities);
    outcomes.extend(leg.outcomes);
    let text = huntsman_recon::lookup_report::render(&entities, &outcomes)
        .map_err(Refused::Unavailable)?;
    Ok((text, entities, outcomes))
}

/// The breach and exposure legs for a selector, each keyed leg built only when its key is configured.
fn exposure(selector: &str, now: u64) -> Result<Collected, Refused> {
    let client = KeyLoader::default_chain(None)
        .load()
        .map(|(key, _)| HibpClient::production(Auth::ApiKey(key), HibpConfig::default()));
    // Same rule as `recon stolen-tax`: the stolen.tax and OathNet keys are read from the
    // environment, never the default file.
    let keys = Keys::from_env();
    let transport = UreqTransport::new(&stolen_tax::transport_config());
    let oathnet_transport = UreqTransport::new(&oathnet::transport_config());
    // DeHashed reuses the opt-in client; its key, like stolen.tax and OathNet, is read
    // from the environment only, never the default keys file.
    let dehashed_client = keys.get(dehashed::client::API_KEY_ENV).map(|secret| {
        let transport = Arc::new(UreqTransport::new(&TransportConfig::default()));
        DehashedClient::new(transport, secret)
    });
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
        dehashed: dehashed_client.as_ref(),
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

/// The username sources for a handle, with the `SeekNow` leg when its key is configured.
fn username(selector: &str, now: u64) -> Result<Collected, Refused> {
    let transport = UreqTransport::new(&TransportConfig::default());
    let keys = Keys::from_env();
    match huntsman_recon::username_cli::run(&transport, &keys, selector, now) {
        UsernameRun::Printed { text, report } => {
            let (text, entities, outcomes) = with_seeknow_leg(
                EntityKind::Username,
                selector,
                &keys,
                now,
                text,
                report.entities,
                report.outcomes,
            )?;
            Ok(done(text, entities, outcomes, USERNAME_POLICY))
        }
        UsernameRun::Failed(m) => Err(Refused::Unavailable(m)),
    }
}

/// The phone sources for a number. Its keyed legs read keys from the environment only; a leg
/// whose key is not set makes no request.
fn phone(selector: &str, now: u64) -> Result<Collected, Refused> {
    let keys = Keys::from_env();
    let transport = UreqTransport::new(&api_leg::transport_config());
    match huntsman_recon::phone_cli::run_keyed(&transport, &keys, selector, now) {
        PhoneRun::Printed { text, report } => {
            Ok(done(text, report.entities, report.outcomes, PHONE_POLICY))
        }
        PhoneRun::Failed(m) => Err(Refused::Data(m)),
    }
}

/// The ip sources for an address. Its keyed legs read keys from the environment only, as the
/// other free-tier legs do.
fn ip(selector: &str, now: u64) -> Result<Collected, Refused> {
    let keys = Keys::from_env();
    let transport = UreqTransport::new(&api_leg::transport_config());
    match huntsman_recon::ip_cli::run(&transport, &keys, selector, now) {
        IpRun::Printed { text, report } => {
            Ok(done(text, report.entities, report.outcomes, IP_POLICY))
        }
        IpRun::Network(m) => Err(Refused::Network(m)),
        IpRun::Failed(m) => Err(Refused::Unavailable(m)),
    }
}

/// The domain sources for a hostname.
fn domain(selector: &str, now: u64) -> Result<Collected, Refused> {
    let keys = Keys::from_env();
    let transport = UreqTransport::new(&TransportConfig::default());
    match huntsman_recon::domain_cli::run(&transport, &keys, selector, now) {
        huntsman_recon::domain_cli::DomainRun::Printed { text, report } => {
            Ok(done(text, report.entities, report.outcomes, DOMAIN_POLICY))
        }
        huntsman_recon::domain_cli::DomainRun::Network(m) => Err(Refused::Network(m)),
        huntsman_recon::domain_cli::DomainRun::Failed(m) => Err(Refused::Unavailable(m)),
    }
}

/// The `WiGLE` network lookup for a BSSID, coordinate or SSID.
fn network(selector: &str, now: u64) -> Result<Collected, Refused> {
    // Like the other keyed legs, the WiGLE credentials are read from the environment,
    // never the default file. Configured, they always run.
    let keys = Keys::from_env();
    let transport = UreqTransport::new(&wigle::transport_config());
    let leg = wigle::configured(&keys).then_some((&transport as &dyn Transport, &keys));
    match huntsman_recon::network_cli::run(leg, selector, now) {
        NetworkRun::Printed { text, report } => {
            Ok(done(text, report.entities, report.outcomes, NETWORK_POLICY))
        }
        NetworkRun::Network(m) => Err(Refused::Network(m)),
        NetworkRun::Failed(m) => Err(Refused::Unavailable(m)),
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
        Ok(p) => finish(ScanKind::Exposure, &p.email, p.save.as_deref()),
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

pub(in crate::cli) fn ip_cmd(args: &[String]) -> ExitCode {
    match IpArgs::parse(args) {
        Ok(p) => finish(ScanKind::Ip, &p.ip, p.save.as_deref()),
        Err(e) => usage_failure(&e, IP_USAGE),
    }
}

pub(in crate::cli) fn network_cmd(args: &[String]) -> ExitCode {
    match NetworkArgs::parse(args) {
        Ok(p) => finish(ScanKind::Network, &p.selector, p.save.as_deref()),
        Err(e) => usage_failure(&e, NETWORK_USAGE),
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
    fn an_sf_refusal_exits_as_the_plain_lookup_would() {
        for (refused, status) in [
            (SfRefused::Network("egress-policy".into()), EX_NOPERM),
            (
                SfRefused::Unavailable("registers down".into()),
                EX_UNAVAILABLE,
            ),
            (SfRefused::Data("bad target".into()), EX_DATAERR),
        ] {
            let message = refused.message().to_owned();
            let mapped = Refused::from(refused);
            assert_eq!(mapped.exit_status(), status, "{message}");
            assert_eq!(mapped.message(), message);
        }
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
