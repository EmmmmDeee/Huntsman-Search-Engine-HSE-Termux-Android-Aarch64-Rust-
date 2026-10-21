//! Person-selector lookup adapters.
//!
//! [`collect`] is the one execution path per lookup kind. The `people`, `email`, `exposure`,
//! `username`, `phone`, `domain`, `ip`, `netblock`, `asn` and `network` commands, `scan`, and the Web UI's `/api/lookup` all run through it,
//! so a kind cannot behave differently depending on where it was asked from.

use std::fmt::Write as _;
use std::path::Path;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::cli::fail;
use huntsman_recon::api_leg;
use huntsman_recon::asn_cli::{ASN_USAGE, AsnArgs, AsnRun};
use huntsman_recon::concurrent;
use huntsman_recon::crypto_cli::{self, CryptoRun};
use huntsman_recon::dehashed::{self, client::DehashedClient};
use huntsman_recon::email_cli::{EMAIL_USAGE, EmailArgs, EmailRun};
use huntsman_recon::entity::{Entity, EntityKind, merge_by_uid};
use huntsman_recon::error::Error;
use huntsman_recon::exit::{EX_DATAERR, EX_IOERR, EX_NOPERM, EX_UNAVAILABLE, EX_USAGE};
use huntsman_recon::exposure_cli::{self, EXPOSURE_USAGE, ExposureArgs, ExposureRun, Sources};
use huntsman_recon::hibp::client::{Auth, HibpClient, HibpConfig};
use huntsman_recon::http::{Transport, TransportConfig, UreqTransport};
use huntsman_recon::ip_cli::{IP_USAGE, IpArgs, IpRun};
use huntsman_recon::keys::Keys;
use huntsman_recon::lookup_save::{
    self, ASN_POLICY, CRYPTO_POLICY, DOMAIN_POLICY, EMAIL_EXPOSURE_POLICY, EMAIL_POLICY,
    EXPOSURE_POLICY, IP_POLICY, NETBLOCK_POLICY, NETWORK_POLICY, PEOPLE_POLICY, PHONE_POLICY,
    SavePolicy, USERNAME_EXPOSURE_POLICY, USERNAME_POLICY,
};
use huntsman_recon::module_selection::{Selected, Selection};
use huntsman_recon::netblock_cli::{NETBLOCK_USAGE, NetblockArgs, NetblockRun};
use huntsman_recon::network_cli::{NETWORK_USAGE, NetworkArgs, NetworkRun};
use huntsman_recon::oathnet;
use huntsman_recon::people_cli::{self, PEOPLE_USAGE, PeopleArgs, PeopleRun};
use huntsman_recon::phone_cli::{PHONE_USAGE, PhoneArgs, PhoneRun};
use huntsman_recon::scan_route::ScanKind;
use huntsman_recon::seeknow_collector::LookupLeg;
use huntsman_recon::source_outcome::SourceExecutionOutcome;
use huntsman_recon::stolen_tax;
use huntsman_recon::textnorm::escape_controls;
use huntsman_recon::threat_feeds::{self, Feeds};
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

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

/// Run one lookup of `kind` for an already-parsed `selector`, asking only the modules `chosen`
/// runs: every transport the lookup sends over carries the choice, so a leg left out sends
/// nothing (see [`Selected`]).
///
/// # Errors
/// [`Refused`] when the lookup produced no report.
pub(in crate::cli) fn collect(
    kind: ScanKind,
    selector: &str,
    chosen: &Selection,
) -> Result<Collected, Refused> {
    let now = now_unix();
    match kind {
        ScanKind::People => people(selector, now, chosen),
        ScanKind::Email => email(selector, now, chosen),
        ScanKind::Exposure => exposure(selector, now, chosen),
        ScanKind::Username => username(selector, now, chosen),
        ScanKind::Phone => phone(selector, now, chosen),
        ScanKind::Ip => ip(selector, now, chosen),
        ScanKind::Netblock => netblock(selector, now, chosen),
        ScanKind::Asn => asn(selector, now, chosen),
        ScanKind::Domain => domain(selector, now, chosen),
        ScanKind::Network => network(selector, now, chosen),
        ScanKind::CryptoAddress => crypto(selector, now, chosen),
    }
}

/// A transport built from `config` that asks only what `chosen` runs.
fn transport(config: &TransportConfig, chosen: &Selection) -> Selected<UreqTransport> {
    Selected::new(UreqTransport::new(config), chosen.clone())
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

/// The people-search sources for a name, with the `SeekNow` leg when its key is configured. Each
/// searches the name on its own, so they run at once, and `SeekNow` folds in after the people
/// sources as it did when it ran after them.
fn people(selector: &str, now: u64, chosen: &Selection) -> Result<Collected, Refused> {
    let keys = crate::cli::credentials::lookup_keys();
    let (run, seeknow) = concurrent::pair(
        || {
            let transport = transport(&TransportConfig::default(), chosen);
            people_cli::run(&transport, selector, now)
        },
        || seeknow_leg(EntityKind::Person, selector, (&keys, chosen), now),
    );
    compose_people(run, seeknow)
}

/// One people lookup from what its two parts returned, folded as [`compose_email`] folds an
/// address's.
fn compose_people(run: PeopleRun, seeknow: Option<LookupLeg>) -> Result<Collected, Refused> {
    let policies = (PEOPLE_POLICY, PEOPLE_POLICY);
    match run {
        PeopleRun::Printed { text, report } => {
            let (text, entities, outcomes) =
                with_seeknow_leg(seeknow, text, report.entities, report.outcomes)?;
            Ok(done(text, entities, outcomes, policies.0))
        }
        PeopleRun::Network(m) => {
            legs_beside("people", Refused::Network(m), seeknow, None, policies)
        }
        PeopleRun::Failed(m) => {
            legs_beside("people", Refused::Unavailable(m), seeknow, None, policies)
        }
    }
}

/// The email sources for an address, with the `SeekNow` leg and the keyed breach legs when their
/// keys are configured. Each searches the address on its own, so the three run at once, and a
/// lookup takes as long as the slowest of them rather than all three in turn.
fn email(selector: &str, now: u64, chosen: &Selection) -> Result<Collected, Refused> {
    let keys = crate::cli::credentials::lookup_keys();
    let (run, (seeknow, exposure)) = concurrent::pair(
        || {
            let transport = transport(&api_leg::transport_config(), chosen);
            huntsman_recon::email_cli::run_keyed(&transport, &keys, selector, now)
        },
        || {
            concurrent::pair(
                || seeknow_leg(EntityKind::Email, selector, (&keys, chosen), now),
                || exposure_legs(selector, (&keys, chosen), now, true),
            )
        },
    );
    compose_email(run, seeknow, exposure)
}

/// One email lookup from what its three parts returned. The legs fold on the address as they
/// always did: the `SeekNow` identity leg first, then the breach and exposure legs onto the
/// combined result. When the address's own sources gave no report, the legs that ran beside them
/// are still reported ([`legs_beside`]).
fn compose_email(
    run: EmailRun,
    seeknow: Option<LookupLeg>,
    exposure: Option<ExposureRun>,
) -> Result<Collected, Refused> {
    let policies = (EMAIL_POLICY, EMAIL_EXPOSURE_POLICY);
    match run {
        EmailRun::Printed { text, report } => {
            let (text, entities, outcomes) =
                with_seeknow_leg(seeknow, text, report.entities, report.outcomes)?;
            Ok(with_exposure(
                exposure,
                done(text, entities, outcomes, policies.0),
                policies.1,
            ))
        }
        EmailRun::Network(m) => {
            legs_beside("email", Refused::Network(m), seeknow, exposure, policies)
        }
        EmailRun::Failed(m) => legs_beside(
            "email",
            Refused::Unavailable(m),
            seeknow,
            exposure,
            policies,
        ),
    }
}

/// A lookup whose own sources gave no report (`refused`), from the legs that ran beside them:
/// the `SeekNow` leg's findings and rows, then the breach and exposure legs folded on, and one
/// line saying why the lookup's own sources gave nothing (`{kind}=unavailable reason=…`). A leg
/// whose key is set and that answered is never dropped because a keyless source failed.
///
/// # Errors
/// `refused` itself when no leg answered; the report renderer's error.
fn legs_beside(
    kind: &str,
    refused: Refused,
    seeknow: Option<LookupLeg>,
    exposure: Option<ExposureRun>,
    (policy, exposure_policy): (SavePolicy, SavePolicy),
) -> Result<Collected, Refused> {
    let answered =
        |outcomes: &[SourceExecutionOutcome]| outcomes.iter().any(|o| o.kind.is_accepted());
    let any = seeknow.as_ref().is_some_and(|leg| answered(&leg.outcomes))
        || matches!(&exposure, Some(ExposureRun::Printed { report, .. }) if answered(&report.outcomes));
    if !any {
        return Err(refused);
    }
    let (text, entities, outcomes) = match seeknow {
        Some(leg) => with_seeknow_leg(Some(leg), String::new(), Vec::new(), Vec::new())?,
        None => (String::new(), Vec::new(), Vec::new()),
    };
    let mut found = with_exposure(
        exposure,
        done(text, entities, outcomes, policy),
        exposure_policy,
    );
    let _ = writeln!(
        found.text,
        "{kind}=unavailable reason={}",
        escape_controls(refused.message())
    );
    Ok(found)
}

/// The `SeekNow` leg for `selector`, or `None` when `HUNTSMAN_SEEKNOW_KEY` is not configured or
/// the lookup does not ask `seeknow`, in which case no request is made.
fn seeknow_leg(
    kind: EntityKind,
    selector: &str,
    (keys, chosen): (&Keys, &Selection),
    now: u64,
) -> Option<LookupLeg> {
    if !chosen.runs(huntsman_recon::seeknow_collector::COLLECTOR_ID) {
        return None;
    }
    let transport = transport(&TransportConfig::default(), chosen);
    huntsman_recon::seeknow_collector::collect_for_lookup(&transport, kind, selector, keys, now)
}

/// Append a `SeekNow` leg to a lookup's report.
///
/// With no leg (no key, or `seeknow` not asked), the report is returned unchanged, byte for byte. With one, `SeekNow`'s
/// entities are merged into the report by uid, its source outcome is appended, and the report
/// text is re-rendered so the console shows the merged result. A `SeekNow` failure is reported
/// as one outcome row, never an abort of the lookup.
fn with_seeknow_leg(
    leg: Option<LookupLeg>,
    text: String,
    entities: Vec<Entity>,
    outcomes: Vec<SourceExecutionOutcome>,
) -> Result<(String, Vec<Entity>, Vec<SourceExecutionOutcome>), Refused> {
    let Some(leg) = leg else {
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
fn exposure(selector: &str, now: u64, chosen: &Selection) -> Result<Collected, Refused> {
    let keys = crate::cli::credentials::lookup_keys();
    match exposure_legs(selector, (&keys, chosen), now, false) {
        Some(ExposureRun::Printed { text, report }) => Ok(done(
            text,
            report.entities,
            report.outcomes,
            EXPOSURE_POLICY,
        )),
        Some(ExposureRun::Network(m)) => Err(Refused::Network(m)),
        Some(ExposureRun::Failed(m)) => Err(Refused::Unavailable(m)),
        None => Err(Refused::Unavailable("no exposure leg ran".into())),
    }
}

/// Run the keyed exposure legs for `selector`, each built only when its key is configured. With
/// `only_if_reachable`, `None` when no configured leg can search `selector`, so a lookup with no
/// keys set sends nothing more and prints what it did before.
fn exposure_legs(
    selector: &str,
    (keys, chosen): (&Keys, &Selection),
    now: u64,
    only_if_reachable: bool,
) -> Option<ExposureRun> {
    let client = crate::cli::credentials::hibp_key_loader(keys)
        .load()
        .map(|(key, _)| HibpClient::production(Auth::ApiKey(key), HibpConfig::default()));
    let transport = UreqTransport::new(&stolen_tax::transport_config());
    let oathnet_transport = UreqTransport::new(&oathnet::transport_config());
    // DeHashed reuses the opt-in client; its key comes from the same lookup keys.
    let dehashed_client = keys.get(dehashed::client::API_KEY_ENV).map(|secret| {
        let transport = Arc::new(UreqTransport::new(&TransportConfig::default()));
        DehashedClient::new(transport, secret)
    });
    let sources = Sources {
        hibp: client.as_ref(),
        stolen_tax: keys
            .get(stolen_tax::KEY_SLOT)
            .is_some()
            .then_some((&transport as &(dyn Transport + Sync), keys)),
        oathnet: keys
            .get(oathnet::KEY_SLOT)
            .is_some()
            .then_some((&oathnet_transport as &(dyn Transport + Sync), keys)),
        dehashed: dehashed_client.as_ref(),
        selection: Some(chosen),
    };
    if only_if_reachable && !sources.reach(selector) {
        return None;
    }
    Some(exposure_cli::run(sources, selector, now))
}

/// An email or username lookup with every configured paid breach leg folded in: a keyed source
/// that can search the selector always runs, never only when `exposure` is asked for by name.
/// `exposure` is what [`exposure_legs`] gave for the selector. The report then saves under
/// `policy`, which names each leg's own module. An exposure run that gave no report leaves the
/// lookup as it was, plus one `exposure=unavailable` line.
fn with_exposure(
    exposure: Option<ExposureRun>,
    mut found: Collected,
    policy: SavePolicy,
) -> Collected {
    let reason = match exposure {
        None => return found,
        Some(ExposureRun::Printed { report, .. }) => {
            match exposure_cli::fold_into(&mut found.entities, &mut found.outcomes, report) {
                Ok(text) => {
                    found.text = text;
                    found.policy = policy;
                    return found;
                }
                Err(m) => m,
            }
        }
        Some(ExposureRun::Network(m) | ExposureRun::Failed(m)) => m,
    };
    found
        .text
        .push_str(&exposure_cli::unavailable_line(&reason));
    found
}

/// The username sources for a handle, with the `SeekNow` leg and the keyed breach legs when their
/// keys are configured. Each searches the handle on its own, so the three run at once.
fn username(selector: &str, now: u64, chosen: &Selection) -> Result<Collected, Refused> {
    let keys = crate::cli::credentials::lookup_keys();
    let (run, (seeknow, exposure)) = concurrent::pair(
        || {
            let transport = transport(&TransportConfig::default(), chosen);
            huntsman_recon::username_cli::run(&transport, &keys, selector, now)
        },
        || {
            concurrent::pair(
                || seeknow_leg(EntityKind::Username, selector, (&keys, chosen), now),
                || exposure_legs(selector, (&keys, chosen), now, true),
            )
        },
    );
    compose_username(run, seeknow, exposure)
}

/// One username lookup from what its three parts returned, folded as [`compose_email`] folds an
/// address's.
fn compose_username(
    run: UsernameRun,
    seeknow: Option<LookupLeg>,
    exposure: Option<ExposureRun>,
) -> Result<Collected, Refused> {
    let policies = (USERNAME_POLICY, USERNAME_EXPOSURE_POLICY);
    match run {
        UsernameRun::Printed { text, report } => {
            let (text, entities, outcomes) =
                with_seeknow_leg(seeknow, text, report.entities, report.outcomes)?;
            Ok(with_exposure(
                exposure,
                done(text, entities, outcomes, policies.0),
                policies.1,
            ))
        }
        UsernameRun::Failed(m) => legs_beside(
            "username",
            Refused::Unavailable(m),
            seeknow,
            exposure,
            policies,
        ),
    }
}

/// The phone sources for a number. Its keyed legs read keys from the default file or the
/// environment, as the other keyed lookups do; a leg whose key is not set makes no request.
fn phone(selector: &str, now: u64, chosen: &Selection) -> Result<Collected, Refused> {
    let keys = crate::cli::credentials::lookup_keys();
    let transport = transport(&api_leg::transport_config(), chosen);
    match huntsman_recon::phone_cli::run_keyed(&transport, &keys, selector, now) {
        PhoneRun::Printed { text, report } => {
            Ok(done(text, report.entities, report.outcomes, PHONE_POLICY))
        }
        PhoneRun::Failed(m) => Err(Refused::Data(m)),
    }
}

/// The threat feeds a lookup reads, downloaded over their own transport and kept in
/// `$HUNTSMAN_HOME/feeds`, else `~/.huntsman/feeds`, so a lookup within a feed's age reads its copy.
fn feeds(chosen: &Selection) -> Feeds {
    Feeds::new(
        Box::new(transport(&threat_feeds::transport_config(), chosen)),
        crate::cli::scans::default_feed_dir(),
    )
}

/// The ip sources for an address. Its keyed legs read keys from the default file or the
/// environment, as the other keyed lookups do.
fn ip(selector: &str, now: u64, chosen: &Selection) -> Result<Collected, Refused> {
    let keys = crate::cli::credentials::lookup_keys();
    let transport = transport(&api_leg::transport_config(), chosen);
    match huntsman_recon::ip_cli::run(&transport, &keys, &feeds(chosen), selector, now) {
        IpRun::Printed { text, report } => {
            Ok(done(text, report.entities, report.outcomes, IP_POLICY))
        }
        IpRun::Network(m) => Err(Refused::Network(m)),
        IpRun::Failed(m) => Err(Refused::Unavailable(m)),
    }
}

/// The address-block sources for a CIDR block.
fn netblock(selector: &str, now: u64, chosen: &Selection) -> Result<Collected, Refused> {
    let transport = transport(&api_leg::transport_config(), chosen);
    match huntsman_recon::netblock_cli::run(&transport, &feeds(chosen), selector, now) {
        NetblockRun::Printed { text, report } => Ok(done(
            text,
            report.entities,
            report.outcomes,
            NETBLOCK_POLICY,
        )),
        NetblockRun::Network(m) => Err(Refused::Network(m)),
        NetblockRun::Failed(m) => Err(Refused::Unavailable(m)),
    }
}

/// The AS sources for an AS number. Its transport reads up to [`huntsman_recon::asn_cli::MAX_BODY`]
/// a call, so the largest networks' prefix lists arrive whole.
fn asn(selector: &str, now: u64, chosen: &Selection) -> Result<Collected, Refused> {
    let transport = transport(
        &TransportConfig {
            max_body: huntsman_recon::asn_cli::MAX_BODY,
            ..api_leg::transport_config()
        },
        chosen,
    );
    match huntsman_recon::asn_cli::run(&transport, selector, now) {
        AsnRun::Printed { text, report } => {
            Ok(done(text, report.entities, report.outcomes, ASN_POLICY))
        }
        AsnRun::Network(m) => Err(Refused::Network(m)),
        AsnRun::Failed(m) => Err(Refused::Unavailable(m)),
    }
}

/// The domain sources for a hostname.
fn domain(selector: &str, now: u64, chosen: &Selection) -> Result<Collected, Refused> {
    let keys = crate::cli::credentials::lookup_keys();
    let transport = transport(&huntsman_recon::domain_cli::transport_config(), chosen);
    match huntsman_recon::domain_cli::run(&transport, &keys, &feeds(chosen), selector, now) {
        huntsman_recon::domain_cli::DomainRun::Printed { text, report } => {
            Ok(done(text, report.entities, report.outcomes, DOMAIN_POLICY))
        }
        huntsman_recon::domain_cli::DomainRun::Network(m) => Err(Refused::Network(m)),
        huntsman_recon::domain_cli::DomainRun::Failed(m) => Err(Refused::Unavailable(m)),
    }
}

/// The `WiGLE` network lookup for a BSSID, coordinate or SSID.
fn network(selector: &str, now: u64, chosen: &Selection) -> Result<Collected, Refused> {
    // Like the other keyed legs, the WiGLE credentials come from the default file or the
    // environment. Configured, they always run; a lookup that does not ask `wigle` sends nothing
    // and leaves no WiGLE row, configured or not.
    let keys = crate::cli::credentials::lookup_keys();
    let transport = transport(&wigle::transport_config(), chosen);
    let leg = (wigle::configured(&keys) || !chosen.is_all())
        .then_some((&transport as &dyn Transport, &keys));
    match huntsman_recon::network_cli::run(leg, selector, now) {
        NetworkRun::Printed { text, report } => {
            Ok(done(text, report.entities, report.outcomes, NETWORK_POLICY))
        }
        NetworkRun::Network(m) => Err(Refused::Network(m)),
        NetworkRun::Failed(m) => Err(Refused::Unavailable(m)),
    }
}

/// The on-chain lookup for one Bitcoin address: its balance and lifetime totals from
/// blockchain.info, keyless like the other passive legs.
fn crypto(selector: &str, now: u64, chosen: &Selection) -> Result<Collected, Refused> {
    let transport = transport(&TransportConfig::default(), chosen);
    match crypto_cli::run(&transport, selector, now) {
        CryptoRun::Printed { text, report } => {
            Ok(done(text, report.entities, report.outcomes, CRYPTO_POLICY))
        }
        CryptoRun::Network(m) => Err(Refused::Network(m)),
        CryptoRun::Failed(m) => Err(Refused::Unavailable(m)),
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
    let collected = match collect(kind, selector, &Selection::all()) {
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

pub(in crate::cli) fn ip_cmd(args: &[String]) -> ExitCode {
    match IpArgs::parse(args) {
        Ok(p) => finish(ScanKind::Ip, &p.ip, p.save.as_deref()),
        Err(e) => usage_failure(&e, IP_USAGE),
    }
}

pub(in crate::cli) fn netblock_cmd(args: &[String]) -> ExitCode {
    match NetblockArgs::parse(args) {
        Ok(p) => finish(ScanKind::Netblock, &p.netblock, p.save.as_deref()),
        Err(e) => usage_failure(&e, NETBLOCK_USAGE),
    }
}

pub(in crate::cli) fn asn_cmd(args: &[String]) -> ExitCode {
    match AsnArgs::parse(args) {
        Ok(p) => finish(ScanKind::Asn, &p.asn, p.save.as_deref()),
        Err(e) => usage_failure(&e, ASN_USAGE),
    }
}

pub(in crate::cli) fn network_cmd(args: &[String]) -> ExitCode {
    match NetworkArgs::parse(args) {
        Ok(p) => finish(ScanKind::Network, &p.selector, p.save.as_deref()),
        Err(e) => usage_failure(&e, NETWORK_USAGE),
    }
}

pub(in crate::cli) fn crypto_cmd(args: &[String]) -> ExitCode {
    use huntsman_recon::crypto_cli::{CRYPTO_USAGE, CryptoArgs};
    match CryptoArgs::parse(args) {
        Ok(p) => finish(ScanKind::CryptoAddress, &p.address, p.save.as_deref()),
        Err(e) => usage_failure(&e, CRYPTO_USAGE),
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

    use huntsman_recon::entity::{Evidence, EvidenceProvenance};
    use huntsman_recon::source_outcome::SourceOutcomeKind;

    const OWN_SOURCES_FAILED: &str = "no source answered for ada@example.com: gravatar: timed out";

    /// A `SeekNow` leg that found one person for the address.
    fn seeknow_found() -> LookupLeg {
        let mut person = Entity::new(EntityKind::Person, "Ada Lovelace", 0.7, "scan");
        person.add_evidence(Evidence::new(
            EvidenceProvenance::new("seeknow"),
            "Person SeekNow lists for the address",
        ));
        LookupLeg {
            entities: vec![person],
            outcomes: vec![SourceExecutionOutcome::success("seeknow", 1, 1)],
        }
    }

    /// A `SeekNow` leg whose request failed.
    fn seeknow_failed() -> LookupLeg {
        LookupLeg {
            entities: Vec::new(),
            outcomes: vec![SourceExecutionOutcome::failed(
                "seeknow",
                1,
                SourceOutcomeKind::ConnectFailure,
                None,
                "no route",
            )],
        }
    }

    fn found_by_seeknow(found: &Collected) {
        assert!(
            found
                .entities
                .iter()
                .any(|e| e.kind == EntityKind::Person && e.raw_value == "Ada Lovelace"),
            "{:#?}",
            found.entities
        );
        assert!(
            found
                .outcomes
                .iter()
                .any(|o| o.module == "seeknow" && o.kind.is_accepted()),
            "{:#?}",
            found.outcomes
        );
    }

    /// A paid leg that answered is reported when every one of the address's own sources failed:
    /// before, the lookup was refused and what the leg found was dropped.
    #[test]
    fn an_email_lookup_keeps_what_a_paid_leg_found_when_its_own_sources_fail() {
        for run in [
            EmailRun::Failed(OWN_SOURCES_FAILED.into()),
            EmailRun::Network(OWN_SOURCES_FAILED.into()),
        ] {
            let found = compose_email(run, Some(seeknow_found()), None)
                .unwrap_or_else(|refused| panic!("refused: {}", refused.message()));
            found_by_seeknow(&found);
            assert!(
                found
                    .text
                    .contains(&format!("email=unavailable reason={OWN_SOURCES_FAILED}\n")),
                "{}",
                found.text
            );
            assert_eq!(found.policy.default_source, EMAIL_POLICY.default_source);
        }
    }

    #[test]
    fn a_username_lookup_keeps_what_a_paid_leg_found_when_its_own_sources_fail() {
        let found = compose_username(
            UsernameRun::Failed("no source answered for ada".into()),
            Some(seeknow_found()),
            None,
        )
        .unwrap_or_else(|refused| panic!("refused: {}", refused.message()));
        found_by_seeknow(&found);
        assert!(
            found
                .text
                .contains("username=unavailable reason=no source answered for ada\n")
        );
    }

    #[test]
    fn a_people_lookup_keeps_what_a_paid_leg_found_when_its_own_sources_fail() {
        for run in [
            PeopleRun::Failed("no source answered for Ada Lovelace".into()),
            PeopleRun::Network("no source answered for Ada Lovelace".into()),
        ] {
            let found = compose_people(run, Some(seeknow_found()))
                .unwrap_or_else(|refused| panic!("refused: {}", refused.message()));
            found_by_seeknow(&found);
            assert!(
                found
                    .text
                    .contains("people=unavailable reason=no source answered for Ada Lovelace\n"),
                "{}",
                found.text
            );
        }
        let refused = compose_people(PeopleRun::Failed("nothing".into()), Some(seeknow_failed()))
            .err()
            .unwrap_or_else(|| panic!("a lookup nothing answered was reported"));
        assert_eq!(refused.exit_status(), EX_UNAVAILABLE);
    }

    /// An exposure leg that answered is reported the same way, saved as an exposure.
    #[test]
    fn an_email_lookup_keeps_what_the_breach_legs_found_when_its_own_sources_fail() {
        let report = exposure_cli::Report {
            outcomes: vec![SourceExecutionOutcome::success("hibp_account", 1, 1)],
            ..exposure_cli::Report::default()
        };
        let exposure = ExposureRun::Printed {
            text: String::new(),
            report,
        };
        let found = compose_email(
            EmailRun::Failed(OWN_SOURCES_FAILED.into()),
            None,
            Some(exposure),
        )
        .unwrap_or_else(|refused| panic!("refused: {}", refused.message()));
        assert!(
            found.outcomes.iter().any(|o| o.module == "hibp_account"),
            "{:#?}",
            found.outcomes
        );
        assert_eq!(
            found.policy.default_source,
            EMAIL_EXPOSURE_POLICY.default_source
        );
    }

    /// With no leg that answered, the lookup is refused as before, with its own reason and status.
    #[test]
    fn a_lookup_no_leg_answered_is_refused_with_its_own_reason() {
        for seeknow in [None, Some(seeknow_failed())] {
            let refused = compose_email(
                EmailRun::Failed(OWN_SOURCES_FAILED.into()),
                seeknow,
                Some(ExposureRun::Failed("no key".into())),
            )
            .err()
            .unwrap_or_else(|| panic!("a lookup nothing answered was reported"));
            assert_eq!(refused.message(), OWN_SOURCES_FAILED);
            assert_eq!(refused.exit_status(), EX_UNAVAILABLE);
        }
        let refused = compose_email(EmailRun::Network(OWN_SOURCES_FAILED.into()), None, None)
            .err()
            .unwrap_or_else(|| panic!("a refused lookup was reported"));
        assert_eq!(refused.exit_status(), EX_NOPERM);
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
