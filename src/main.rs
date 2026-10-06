//! Operable binary. No hardcoded workspace path.
//! `check` fails if a self-labeled technique enters Navigator or STIX.

use std::env;
use std::path::Path;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use huntsman_recon::au_id::{Identifier, classify as classify_id, is_valid_abn};
use huntsman_recon::classifier::classify as classify_indicator;
use huntsman_recon::classify::classify_response;
use huntsman_recon::confidence::{Classification, effective};
use huntsman_recon::credential_origin::{AuthenticationAuthority, OperatorCredentialRef};
use huntsman_recon::crtsh::{self, CrtShError};
use huntsman_recon::dns;
use huntsman_recon::egress::EgressPolicy;
use huntsman_recon::email_cli::{EMAIL_HELP, EMAIL_USAGE, EmailArgs, EmailRun};
use huntsman_recon::email_save;
use huntsman_recon::engineering_command;
use huntsman_recon::entity::{Evidence, EvidenceProvenance};
use huntsman_recon::error::Error;
use huntsman_recon::evidence_ancestry::{
    EvidenceAncestryGraph, EvidenceAncestryNode, EvidenceNodeId,
};
use huntsman_recon::fetch::{Credential, FetchOptions, fetch};
use huntsman_recon::fetch_cli::{FETCH_USAGE, FetchArgs};
use huntsman_recon::fsio::write_atomic;
use huntsman_recon::geohash;
use huntsman_recon::geoint::{haversine_m, parse_latlon};
use huntsman_recon::hibp::cli::{HIBP_USAGE, HibpCommand};
use huntsman_recon::http::{
    Request, TransportConfig, UreqTransport, origin_of, parse_http_uri, redact_url,
};
use huntsman_recon::identity::{PersonRecord, resolve};
use huntsman_recon::identity_resolution::{
    AutoMergePolicy, HoldReason, IdentityResolutionDecision, ResolutionState,
};
use huntsman_recon::keys::{Keys, is_configured_value};
use huntsman_recon::ledger::{Claim, admitted, append, chain_intact, load_chain, save_chain, seal};
use huntsman_recon::lineage::{CandidateOutcome, MergeOutcome, Observation, resolve_with_lineage};
use huntsman_recon::navigator::layer;
use huntsman_recon::people_cli::{self, PEOPLE_HELP, PEOPLE_USAGE, PeopleArgs, PeopleRun};
use huntsman_recon::people_save;
use huntsman_recon::recon::ReconTargetKind;
use huntsman_recon::redact::{coarsen_latlon, scrub_secrets};
use huntsman_recon::search::{Document, load_dir, search, search_response, tokenize};
use huntsman_recon::seeknow_cli::{SEEKNOW_HELP, SEEKNOW_USAGE, SeekNowCliRun};
use huntsman_recon::session::{Candidate, ExecuteRecord, FalsifyRecord, Session, VerifyRecord};
use huntsman_recon::source_outcome::{
    SourceHealthAction, SourceOutcomeKind, classify_fetch, recommended_action,
};
use huntsman_recon::source_registry::routes_for;
use huntsman_recon::stage::{EvidenceLevel, Status};
use huntsman_recon::stix::bundle;
use huntsman_recon::stolen_tax::{self, StolenTaxError};
use huntsman_recon::termination::{FrontierState, TerminationSignals, decide_termination};
use huntsman_recon::textnorm::escape_controls;
use huntsman_recon::username_cli::{USERNAME_HELP, USERNAME_USAGE, UsernameArgs, UsernameRun};
use huntsman_recon::username_save;

const USAGE: &str = "usage: huntsman-recon [check | command | geo LAT,LON LAT,LON | geohash LAT,LON [PRECISION] | coarsen LAT,LON | id TOKEN | search QUERY [DIR] | sources QUERY | people NAME [--save FILE] | email ADDR [--save FILE] | username HANDLE [--save FILE] | classify STATUS BODY | fetch URL [options] | hibp SUBCOMMAND | recon crtsh TARGET|dns TARGET|stolen-tax QUERY [--keys FILE] | seeknow SUBCOMMAND | keys FILE | verify LEDGER]";
const RECON_USAGE: &str = "usage: huntsman-recon recon crtsh TARGET | recon dns TARGET | recon stolen-tax QUERY [--keys FILE]";
const HELP: &str = "\
Huntsman Recon — local search, guarded fetch, and evidence-ledger tools

Usage:
  huntsman-recon <COMMAND> [ARGS]
  huntsman-recon --help
  huntsman-recon --version

Commands:
  check                 Run offline self-acceptance and regenerate var/*.json
  command               Print and validate the executable engineering hierarchy
  geo                   Distance between two LAT,LON coordinates in metres
  geohash               Encode LAT,LON (default precision: 7)
  coarsen               Round LAT,LON to one decimal place
  id                    Classify and validate an Australian ABN, ACN, or BSB
  search                Search the built-in fixture or one local text directory
  sources               Classify an indicator and print curated routes (offline)
  people                Look up a name on keyless ASIC people registers
  email                 Enrich an email and query its public Gravatar profile
  username              Enrich a username through public GitHub and Bluesky profiles
  classify              Classify an HTTP status and response body
  fetch                 Make a guarded HTTP request (network access)
  hibp                  Have I Been Pwned lookups (opt-in; keyed subcommands need a key)
  recon                 One crt.sh, DNS/mail, or stolen.tax lookup (network access)
  seeknow               SeekNow/See-Know lookup (opt-in; needs HUNTSMAN_SEEKNOW_KEY)
  keys                  Validate a private keys file; print slots and fingerprints
  verify                Verify a saved evidence ledger

Run `huntsman-recon <COMMAND> --help` for command details.
Search and sources do not collect remote results. `fetch`, `hibp`, `recon`,
`seeknow`, `people`, `email`, and `username` make HTTP requests; their default
egress policy is public-only.";
const EX_USAGE: u8 = 64;
const EX_DATAERR: u8 = 65;
const EX_NOINPUT: u8 = 66;
const EX_UNAVAILABLE: u8 = 69;
const EX_NOPERM: u8 = 77;
const EX_IOERR: u8 = 74;
const MAX_ARTIFACT_BYTES: u64 = 1_048_576;

fn main() -> ExitCode {
    let argv: Vec<String> = env::args().skip(1).collect();
    if argv.is_empty() {
        return check();
    }
    if matches!(argv[0].as_str(), "help" | "-h" | "--help") {
        println!("{HELP}\n{USAGE}");
        return ExitCode::SUCCESS;
    }
    if matches!(argv[0].as_str(), "-V" | "--version") {
        println!("huntsman-recon {}", env!("CARGO_PKG_VERSION"));
        return ExitCode::SUCCESS;
    }
    if argv.len() == 2 && matches!(argv[1].as_str(), "-h" | "--help") {
        print_command_help(&argv[0]);
        return ExitCode::SUCCESS;
    }
    let mut remaining = argv.into_iter();
    match remaining.next().as_deref() {
        Some("command") => command_cmd(&remaining.collect::<Vec<_>>()),
        Some("geo") => geo(remaining.next(), remaining.next()),
        Some("geohash") => geohash_cmd(remaining.next(), remaining.next().as_deref()),
        Some("coarsen") => coarsen_cmd(remaining.next()),
        Some("id") => id_cmd(remaining.next()),
        Some("search") => search_cmd(remaining.next(), remaining.next()),
        Some("sources") => sources_cmd(remaining.next()),
        Some("people") => people_cmd(&remaining.collect::<Vec<_>>()),
        Some("email") => email_cmd(&remaining.collect::<Vec<_>>()),
        Some("username") => username_cmd(&remaining.collect::<Vec<_>>()),
        Some("classify") => classify(remaining.next(), remaining.next()),
        Some("fetch") => fetch_cmd(&remaining.collect::<Vec<_>>()),
        Some("hibp") => hibp_cmd(&remaining.collect::<Vec<_>>()),
        Some("recon") => recon_cmd(&remaining.collect::<Vec<_>>()),
        Some("seeknow") => seeknow_cmd(&remaining.collect::<Vec<_>>()),
        Some("keys") => keys_cmd(remaining.next()),
        Some("verify") => verify(remaining.next()),
        Some("check") | None => check(),
        Some(other) => fail(EX_USAGE, &format!("unknown command: {other}\n{USAGE}")),
    }
}

fn print_command_help(command: &str) {
    let help = match command {
        "check" => {
            "check\nRun offline self-acceptance and regenerate var/ledger.json, var/navigator.json, and var/stix-bundle.json."
        }
        "command" => {
            "command\nValidate and print the fixed engineering command invariant, four phases, ranks, names, and titles."
        }
        "geo" => {
            "geo LAT,LON LAT,LON\nPrint the great-circle distance between two coordinates in metres."
        }
        "geohash" => {
            "geohash LAT,LON [PRECISION]\nEncode coordinates as a geohash. Precision defaults to 7."
        }
        "coarsen" => {
            "coarsen LAT,LON\nRound coordinates to one decimal place for approximate location sharing."
        }
        "id" => "id TOKEN\nClassify and validate an Australian ABN, ACN, or BSB.",
        "search" => {
            "search QUERY [DIR]\nSearch built-in examples, or .txt/.md files in one directory. Challenge pages and unsafe/oversized inputs are skipped."
        }
        "sources" => {
            "sources QUERY\nClassify an indicator and print curated public/browser search routes. Does not fetch those routes."
        }
        "people" => PEOPLE_HELP,
        "email" => EMAIL_HELP,
        "username" => USERNAME_HELP,
        "classify" => {
            "classify STATUS BODY\nClassify an HTTP response as a result, challenge, or other outcome."
        }
        "fetch" => huntsman_recon::fetch_cli::FETCH_USAGE,
        "hibp" => HIBP_USAGE,
        "recon" => RECON_USAGE,
        "seeknow" => SEEKNOW_HELP,
        "keys" => {
            "keys FILE\nCheck a keys file and print configured slot names and fingerprint prefixes, never secret values."
        }
        "verify" => {
            "verify LEDGER\nVerify a ledger file and print its entry count, admitted count, and tip."
        }
        _ => {
            println!("{HELP}\n{USAGE}");
            return;
        }
    };
    println!("{help}\n  -h, --help  Show this help");
}

fn fail(code: u8, msg: &str) -> ExitCode {
    eprintln!("{msg}");
    ExitCode::from(code)
}

fn command_cmd(args: &[String]) -> ExitCode {
    if !args.is_empty() {
        return fail(EX_USAGE, "usage: huntsman-recon command");
    }
    match engineering_command::render() {
        Ok(rendered) => {
            print!("{rendered}");
            ExitCode::SUCCESS
        }
        Err(message) => fail(EX_DATAERR, message),
    }
}

fn people_cmd(args: &[String]) -> ExitCode {
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
                match people_save::save(&path, &report.entities, &report.outcomes) {
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

fn email_cmd(args: &[String]) -> ExitCode {
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
                match email_save::save(&path, &report.entities, &report.outcomes) {
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

fn username_cmd(args: &[String]) -> ExitCode {
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
                match username_save::save(&path, &report.entities, &report.outcomes) {
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

fn geo(a: Option<String>, b: Option<String>) -> ExitCode {
    let (Some(a), Some(b)) = (a, b) else {
        return fail(EX_USAGE, "usage: huntsman-recon geo LAT,LON LAT,LON");
    };
    let Ok((lat1, lon1)) = parse_latlon(&a) else {
        return fail(EX_DATAERR, &format!("bad coordinate: {a}"));
    };
    let Ok((lat2, lon2)) = parse_latlon(&b) else {
        return fail(EX_DATAERR, &format!("bad coordinate: {b}"));
    };
    println!("{:.0}", haversine_m(lat1, lon1, lat2, lon2));
    ExitCode::SUCCESS
}

fn geohash_cmd(pair: Option<String>, precision: Option<&str>) -> ExitCode {
    let Some(pair) = pair else {
        return fail(
            EX_USAGE,
            "usage: huntsman-recon geohash LAT,LON [PRECISION]",
        );
    };
    let Ok((lat, lon)) = parse_latlon(&pair) else {
        return fail(EX_DATAERR, &format!("bad coordinate: {pair}"));
    };
    let precision = match precision.map(str::parse::<usize>) {
        None => 7,
        Some(Ok(p)) => p,
        Some(Err(_)) => return fail(EX_DATAERR, "bad precision"),
    };
    match geohash::encode(lat, lon, precision) {
        Ok(hash) => {
            println!("{hash}");
            ExitCode::SUCCESS
        }
        Err(e) => fail(EX_DATAERR, &e.to_string()),
    }
}

fn coarsen_cmd(pair: Option<String>) -> ExitCode {
    let Some(pair) = pair else {
        return fail(EX_USAGE, "usage: huntsman-recon coarsen LAT,LON");
    };
    match coarsen_latlon(&pair) {
        Some(coarse) => {
            println!("{coarse}");
            ExitCode::SUCCESS
        }
        None => fail(EX_DATAERR, &format!("bad coordinate: {pair}")),
    }
}

fn id_cmd(token: Option<String>) -> ExitCode {
    let Some(token) = token else {
        return fail(EX_USAGE, "usage: huntsman-recon id TOKEN");
    };
    match classify_id(&token) {
        Ok(Identifier::Abn { bare, acn }) => {
            println!("abn={bare}");
            println!("acn={}", acn.as_deref().unwrap_or("none"));
        }
        Ok(Identifier::Acn { bare }) => println!("acn={bare}"),
        Ok(Identifier::Bsb { bare, institution }) => {
            println!("bsb={bare}");
            println!("institution={}", institution.unwrap_or("unknown"));
        }
        Err(e) => return fail(EX_DATAERR, &e.to_string()),
    }
    ExitCode::SUCCESS
}

fn hibp_cmd(args: &[String]) -> ExitCode {
    ExitCode::from(HibpCommand::production().run(
        args,
        &mut std::io::stdin().lock(),
        &mut std::io::stdout().lock(),
        &mut std::io::stderr().lock(),
    ))
}

fn seeknow_cmd(args: &[String]) -> ExitCode {
    let transport = UreqTransport::new(&TransportConfig::default());
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    match huntsman_recon::seeknow_cli::run(&transport, args, env::var_os("HOME").as_deref(), now) {
        SeekNowCliRun::Usage => fail(EX_USAGE, SEEKNOW_USAGE),
        SeekNowCliRun::Printed(text) => {
            print!("{text}");
            ExitCode::SUCCESS
        }
        SeekNowCliRun::BadData(msg) => fail(EX_DATAERR, &msg),
        SeekNowCliRun::Input(msg) => fail(EX_NOINPUT, &msg),
        SeekNowCliRun::NoPerm(msg) => fail(EX_NOPERM, &msg),
        SeekNowCliRun::Unavailable(msg) => fail(EX_UNAVAILABLE, &msg),
    }
}

fn recon_cmd(args: &[String]) -> ExitCode {
    match args {
        [source, target] if source == "crtsh" => crtsh_cmd(target),
        [source, target] if source == "dns" => dns_cmd(target),
        [source, query] if source == "stolen-tax" => stolen_tax_cmd(query, None),
        [source, query, flag, file] if source == "stolen-tax" && flag == "--keys" => {
            stolen_tax_cmd(query, Some(file))
        }
        _ => fail(EX_USAGE, RECON_USAGE),
    }
}

fn print_entities(entities: &[huntsman_recon::entity::Entity]) {
    for e in entities {
        println!(
            "{}\t{}\t{:.2}\t{}",
            serde_json::to_value(&e.kind)
                .ok()
                .and_then(|v| v.as_str().map(str::to_owned))
                .unwrap_or_default(),
            escape_controls(&e.value),
            e.confidence,
            escape_controls(&e.tags.join(","))
        );
    }
}

fn dns_cmd(target: &str) -> ExitCode {
    let target = target.trim();
    if target.is_empty() {
        return fail(EX_USAGE, RECON_USAGE);
    }
    let transport = UreqTransport::new(&dns::transport_config());
    match dns::lookup_domain(&transport, target) {
        None => fail(EX_DATAERR, &format!("bad domain: {target}")),
        Some(report) => {
            let empty = report.answers.is_empty();
            print!("{}", report.render());
            if empty {
                ExitCode::from(EX_UNAVAILABLE)
            } else {
                ExitCode::SUCCESS
            }
        }
    }
}

fn crtsh_cmd(target: &str) -> ExitCode {
    let target = target.trim();
    if target.is_empty() {
        return fail(EX_USAGE, RECON_USAGE);
    }
    let kind = if target.contains("://") {
        ReconTargetKind::Url
    } else if target.contains('@') {
        ReconTargetKind::Email
    } else {
        ReconTargetKind::Domain
    };
    let transport = UreqTransport::new(&crtsh::transport_config());
    match crtsh::lookup(&transport, kind, target, "cli") {
        Ok(report) => {
            print_entities(&report.entities);
            println!(
                "query={} attempts={} entities={}",
                escape_controls(report.query.as_deref().unwrap_or("none")),
                report.attempts,
                report.entities.len()
            );
            ExitCode::SUCCESS
        }
        Err(e @ CrtShError::Refused(_)) => fail(EX_NOPERM, &e.to_string()),
        Err(e) => fail(EX_UNAVAILABLE, &e.to_string()),
    }
}

fn stolen_tax_cmd(query: &str, keys_file: Option<&String>) -> ExitCode {
    if query.trim().is_empty() {
        return fail(EX_USAGE, RECON_USAGE);
    }
    let keys = match keys_file {
        Some(path) => match Keys::load(Path::new(path)) {
            Ok(keys) => keys,
            Err(e) => return fail(EX_NOINPUT, &e.to_string()),
        },
        None => Keys::from_env(),
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let transport = UreqTransport::new(&stolen_tax::transport_config());
    match stolen_tax::lookup(&transport, &keys, query, "cli", now) {
        Ok(report) => {
            print_entities(&report.entities);
            for failure in &report.failed_paths {
                println!(
                    "failed_path={} reason={}",
                    failure.path,
                    escape_controls(&failure.reason)
                );
            }
            for path in &report.skipped_paths {
                println!(
                    "skipped_path={path} reason=not sent, {}s lookup budget exhausted",
                    stolen_tax::LOOKUP_BUDGET.as_secs()
                );
            }
            if let Some(secret) = keys.get(stolen_tax::KEY_SLOT) {
                println!("credential={}", &secret.fingerprint().as_str()[..12]);
            }
            println!(
                "entities={} partial={}",
                report.entities.len(),
                report.truncation.is_some()
            );
            if let Some(note) = &report.truncation {
                println!("truncation={note}");
            }
            ExitCode::SUCCESS
        }
        Err(e @ StolenTaxError::MissingKey) => fail(EX_NOINPUT, &e.to_string()),
        Err(e @ StolenTaxError::Refused(_)) => fail(EX_NOPERM, &e.to_string()),
        Err(e @ (StolenTaxError::Failed(_) | StolenTaxError::BudgetExhausted { .. })) => {
            fail(EX_UNAVAILABLE, &e.to_string())
        }
    }
}

fn fetch_cmd(args: &[String]) -> ExitCode {
    let parsed = match FetchArgs::parse(args) {
        Ok(p) => p,
        Err(e) => return fail(EX_USAGE, &format!("{e}\n{FETCH_USAGE}")),
    };
    let credential = match build_credential(&parsed) {
        Ok(c) => c,
        Err(e) => return fail(EX_NOINPUT, &e.to_string()),
    };
    let transport = UreqTransport::new(&TransportConfig {
        timeout: parsed.timeout,
        egress: if parsed.allow_private {
            EgressPolicy::Unrestricted
        } else {
            EgressPolicy::PublicOnly
        },
        ..TransportConfig::default()
    });
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let fetched = match fetch(
        &transport,
        Request::get(parsed.url.clone()),
        credential.as_ref(),
        &FetchOptions {
            max_redirects: parsed.max_redirects,
            ..FetchOptions::default()
        },
        "cli",
        now,
    ) {
        Ok(f) => f,
        Err(e) => return fail(EX_NOPERM, &e.to_string()),
    };
    let kind = fetched.outcome.kind;
    println!(
        "status={} outcome={} action={} redirects={} url={}",
        fetched
            .outcome
            .http_status
            .map_or_else(|| "none".into(), |s| s.to_string()),
        serde_json::to_value(kind)
            .ok()
            .and_then(|v| v.as_str().map(str::to_owned))
            .unwrap_or_default(),
        serde_json::to_value(recommended_action(kind))
            .ok()
            .and_then(|v| v.as_str().map(str::to_owned))
            .unwrap_or_default(),
        fetched.redirects,
        fetched.final_url,
    );
    if let Some(detail) = &fetched.outcome.detail {
        println!("detail={detail}");
    }
    if let Some(fp) = &fetched.credential_sent {
        println!("credential={}", &fp.as_str()[..12]);
    }
    match fetched.response {
        Some(response) => {
            if parsed.print_body {
                println!("{}", response.text());
            }
            ExitCode::SUCCESS
        }
        None => ExitCode::from(EX_UNAVAILABLE),
    }
}

fn build_credential(args: &FetchArgs) -> Result<Option<Credential>, Error> {
    let Some((slot, style)) = &args.auth else {
        return Ok(None);
    };
    let resolved = Keys::resolve(args.keys_file.as_deref(), env::var_os("HOME").as_deref())?;
    if let Some(warning) = &resolved.warning {
        eprintln!("{warning}");
    }
    let keys = resolved.keys;
    let secret = keys
        .get(slot)
        .ok_or_else(|| Error::Invalid(format!("credential {slot} is not configured")))?;
    let host = parse_http_uri(&args.url)?
        .host()
        .unwrap_or_default()
        .to_owned();
    let authority = AuthenticationAuthority::operator_approved(OperatorCredentialRef {
        provider_id: host,
        credential_slot: slot.clone(),
        approved_at_unix: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs()),
        approval_provenance: "operator supplied --bearer/--header on the command line".into(),
    })?;
    Ok(Some(Credential::new(authority, secret, style.clone())?))
}

fn keys_cmd(path: Option<String>) -> ExitCode {
    let Some(path) = path else {
        return fail(EX_USAGE, "usage: huntsman-recon keys FILE");
    };
    match Keys::load(Path::new(&path)) {
        Ok(keys) => {
            for slot in keys.slots() {
                if let Some(secret) = keys.get(slot) {
                    println!(
                        "{slot} fingerprint={}",
                        &secret.fingerprint().as_str()[..12]
                    );
                }
            }
            ExitCode::SUCCESS
        }
        Err(e) => fail(EX_NOINPUT, &e.to_string()),
    }
}

fn search_cmd(query: Option<String>, dir: Option<String>) -> ExitCode {
    let Some(query) = query else {
        return fail(EX_USAGE, "usage: huntsman-recon search QUERY [DIR]");
    };
    if tokenize(&query).is_empty() {
        return fail(
            EX_USAGE,
            "query has no searchable term (words need two or more letters or digits)",
        );
    }
    let docs = if let Some(dir) = dir {
        match load_dir(Path::new(&dir)) {
            Ok(loaded) => {
                for skipped in &loaded.skipped {
                    eprintln!("skipped\t{}\t{}", skipped.path, skipped.reason);
                }
                loaded.docs
            }
            Err(e) => return fail(EX_NOINPUT, &e.to_string()),
        }
    } else {
        vec![
            Document {
                id: "brisbane".into(),
                body: "Brisbane port radar sighting".into(),
                source: "fixture".into(),
            },
            Document {
                id: "sydney".into(),
                body: "Sydney harbour note".into(),
                source: "fixture".into(),
            },
        ]
    };
    let hits = search(&docs, &query);
    if hits.is_empty() {
        println!("hits=0");
    }
    for hit in &hits {
        println!("{}\t{}\t{}", hit.score, hit.id, hit.source);
    }
    ExitCode::SUCCESS
}

fn sources_cmd(query: Option<String>) -> ExitCode {
    let Some(query) = query else {
        return fail(EX_USAGE, "usage: huntsman-recon sources QUERY");
    };
    let classified = classify_indicator(&query);
    // Residual and unsupported kinds have no descriptors, so the empty-route check
    // is the gate. A confidence floor here would drop low-confidence but routable
    // kinds such as `@handle` usernames.
    let routes = routes_for(&classified.kind, &classified.value);
    if routes.is_empty() {
        return fail(EX_DATAERR, "no actionable source routes");
    }
    println!(
        "kind={} confidence={:.3} routes={}",
        classified.kind.as_str(),
        classified.confidence,
        routes.len()
    );
    for route in routes {
        println!(
            "source={} execution={} access={} url={}",
            route.source_id,
            route.execution.as_str(),
            route.access.as_str(),
            route.url
        );
    }
    ExitCode::SUCCESS
}

fn classify(status: Option<String>, body: Option<String>) -> ExitCode {
    let (Some(status), Some(body)) = (status, body) else {
        return fail(EX_USAGE, "usage: huntsman-recon classify STATUS BODY");
    };
    let Ok(status) = status.parse::<u16>() else {
        return fail(EX_DATAERR, "bad status");
    };
    let kind = classify_fetch(status, &body);
    println!("{:?}", classify_response(status, &body));
    println!(
        "outcome={}",
        serde_json::to_value(kind)
            .ok()
            .and_then(|v| v.as_str().map(str::to_owned))
            .unwrap_or_default()
    );
    println!(
        "action={}",
        serde_json::to_value(recommended_action(kind))
            .ok()
            .and_then(|v| v.as_str().map(str::to_owned))
            .unwrap_or_default()
    );
    ExitCode::SUCCESS
}

fn verify(path: Option<String>) -> ExitCode {
    let Some(path) = path else {
        return fail(EX_USAGE, "usage: huntsman-recon verify LEDGER");
    };
    match load_chain(Path::new(&path)) {
        Ok(entries) => {
            println!("entries={}", entries.len());
            println!("admitted={}", admitted(&entries).len());
            println!("tip={}", entries.last().map_or("none", |e| e.hash.as_str()));
            ExitCode::SUCCESS
        }
        Err(e) => fail(EX_DATAERR, &e.to_string()),
    }
}

/// Self-acceptance. Each gate has its own exit code; every artifact is regenerated, never left stale.
fn check() -> ExitCode {
    match run_check() {
        Ok(meters) => {
            println!("command_hierarchy=accepted");
            println!("accepted techniques=0");
            println!("brisbane_sydney_m={meters:.0}");
            ExitCode::SUCCESS
        }
        Err((code, msg)) => fail(code, &format!("check failed: {msg}")),
    }
}

type Gate = Result<(), (u8, String)>;

fn gate(code: u8, ok: bool, msg: &str) -> Gate {
    if ok {
        Ok(())
    } else {
        Err((code, msg.to_owned()))
    }
}

fn run_check() -> Result<f64, (u8, String)> {
    engineering_command::validate().map_err(|message| (12, message.to_owned()))?;
    let (blat, blon) = parse_latlon("-27.4698,153.0251").map_err(|e| (2, e.to_string()))?;
    let (slat, slon) = parse_latlon("-33.8688,151.2093").map_err(|e| (2, e.to_string()))?;
    let meters = haversine_m(blat, blon, slat, slon);
    gate(
        2,
        (700_000.0..760_000.0).contains(&meters),
        "brisbane-sydney outside band",
    )?;

    check_offline_gates()?;

    let geo = seal(&Claim {
        claim: format!("brisbane-sydney haversine {meters:.0} m inside band"),
        source: "published city centroids".into(),
        component: "src/geoint.rs".into(),
        technique_id: Some("T1591".into()),
        status: Status::Verified,
        evidence_level: EvidenceLevel::DirectObservation,
        does_not_show: "not T1591 and not a survey".into(),
    });
    let wall = append(
        &geo.hash,
        &Claim {
            claim: "challenge page is not a result".into(),
            source: "src/classify.rs".into(),
            component: "src/classify.rs".into(),
            technique_id: None,
            status: Status::Verified,
            evidence_level: EvidenceLevel::Reproduction,
            does_not_show: "does not bypass the wall".into(),
        },
    );
    let entries = vec![geo, wall];
    gate(9, chain_intact(&entries), "fresh chain not intact")?;

    let nav = layer(&entries);
    gate(
        7,
        nav["techniques"].as_array().is_some_and(Vec::is_empty),
        "self-labeled technique entered Navigator",
    )?;
    let stix = bundle(&entries);
    gate(
        8,
        stix["objects"].as_array().is_some_and(Vec::is_empty),
        "self-labeled technique entered STIX",
    )?;

    let ledger_path = Path::new("var/ledger.json");
    save_chain(ledger_path, &entries).map_err(|e| (9, e.to_string()))?;
    let reloaded = load_chain(ledger_path).map_err(|e| (9, e.to_string()))?;
    gate(9, reloaded == entries, "ledger round-trip mismatch")?;
    let tip = entries.last().map_or("", |e| e.hash.as_str());

    check_session(meters, tip)?;

    for (name, value) in [
        ("var/navigator.json", &nav),
        ("var/stix-bundle.json", &stix),
    ] {
        let body = serde_json::to_vec_pretty(value).map_err(|e| (EX_IOERR, e.to_string()))?;
        write_atomic(Path::new(name), &body, MAX_ARTIFACT_BYTES)
            .map_err(|e| (EX_IOERR, e.to_string()))?;
    }
    Ok(meters)
}

/// Classifier, search, and identity gates. Decided without a network.
fn check_offline_gates() -> Gate {
    gate(
        3,
        !classify_response(200, "<html>just a moment cloudflare</html>").is_result(),
        "challenge scored as result",
    )?;
    gate(
        3,
        !classify_response(429, "challenges.cloudflare.com").is_wall(),
        "429 classified as wall",
    )?;
    gate(
        3,
        search_response(
            200,
            "<html>just a moment cloudflare</html>",
            "brisbane",
            "remote",
        )
        .is_empty(),
        "challenge page produced a hit",
    )?;

    let people = resolve(&[
        PersonRecord {
            id: "a".into(),
            name: "Same".into(),
            emails: vec!["a@ex.com".into()],
            handles: vec![],
        },
        PersonRecord {
            id: "b".into(),
            name: "Same".into(),
            emails: vec!["b@ex.com".into()],
            handles: vec![],
        },
    ]);
    gate(4, people.len() == 2, "shared name merged identities")?;
    check_overlay_gates()?;
    check_rebuilt_gates()?;
    check_network_gates()
}

/// Rebuilt monolith utilities: strict identifiers, geohash round-trip, weak sources
/// do not reach Verified, overlapping secrets leave no fragment.
fn check_rebuilt_gates() -> Gate {
    gate(
        10,
        is_valid_abn("51 824 753 556") && !is_valid_abn("5182 hello 4753556"),
        "ABN grouping not strict",
    )?;
    let hash = geohash::encode(-27.4698, 153.0251, 9).map_err(|e| (10, e.to_string()))?;
    let cell = geohash::decode(&hash).map_err(|e| (10, e.to_string()))?;
    gate(
        10,
        cell.contains(-27.4698, 153.0251),
        "geohash cell misses its point",
    )?;
    gate(
        10,
        Classification::from_effective(effective(0.05, 5)) == Classification::Candidate,
        "weak sources reached a tier",
    )?;
    let scrubbed = scrub_secrets("xxabcdefyy", &["abcd", "cdef"]);
    gate(
        10,
        scrubbed == "xx[redacted]yy",
        "secret fragment survived scrubbing",
    )
}

/// Network layer, decided without a socket: egress refuses the operator's own
/// network, credentials never reach a foreign origin, placeholders are not keys.
fn check_network_gates() -> Gate {
    let refused = [
        "127.0.0.1",
        "10.1.2.3",
        "169.254.169.254",
        "::1",
        "fd00::1",
        "::ffff:192.168.0.1",
    ];
    gate(
        11,
        refused.iter().all(|s| {
            s.parse()
                .is_ok_and(|ip| !EgressPolicy::PublicOnly.permits(ip))
        }) && EgressPolicy::PublicOnly.permits(std::net::IpAddr::from([1, 1, 1, 1])),
        "egress policy admits a private address or refuses a public one",
    )?;
    gate(
        11,
        origin_of("https://a.example/x") != origin_of("https://a.example.evil.test/x")
            && origin_of("https://a.example/x") != origin_of("http://a.example/x"),
        "origins not distinguished",
    )?;
    gate(
        11,
        !is_configured_value("insert_key_here") && is_configured_value("k3y-8f2a91"),
        "credential placeholder accepted as configured",
    )?;
    let with_userinfo = format!("https://{}@a.example/x?{}=v", "user:pw", "api_key");
    gate(
        11,
        redact_url(&with_userinfo) == "https://a.example/x?[redacted]",
        "url redaction leaks userinfo or query",
    )
}

/// Refactor-overlay foundations: a WAF is not an auth failure, mirrors count once,
/// delayed work is not a fixed point.
fn check_overlay_gates() -> Gate {
    let waf = classify_fetch(403, "<html>checking your browser cloudflare</html>");
    gate(
        5,
        waf == SourceOutcomeKind::BotWaf,
        "403 challenge not classified as bot/WAF",
    )?;
    gate(
        5,
        recommended_action(waf) != SourceHealthAction::RequireCredential,
        "WAF demanded credentials",
    )?;

    check_lineage_gate()?;
    check_ancestry_graph_gate()?;

    let delayed = FrontierState {
        delayed_retry_work: 1,
        ..FrontierState::default()
    };
    gate(
        5,
        decide_termination(delayed, TerminationSignals::default()).is_none(),
        "delayed work called a fixed point",
    )?;
    Ok(())
}

/// Gate 5, lineage half: families come from the response fields, not the collector.
/// Two collectors relaying one dump are one family and cannot auto-merge; a dump plus
/// an independent registry can, but only with a present, in-range probability.
/// Every observation and candidate comes back.
fn check_lineage_gate() -> Gate {
    let record = |id: &str, collector: &str, field: &str, value: &str| Observation {
        id: id.into(),
        evidence: Evidence::new(EvidenceProvenance::new(collector), "fixture record")
            .with_attr(field, value),
    };
    let observations = vec![
        record("hibp-1", "hibp", "breach", "Adobe 2013"),
        record("dehashed-1", "dehashed", "dbname", "ADOBE  2013"),
        record("abr-1", "abn_lookup", "registry", "company registry"),
    ];
    let mirrors = IdentityResolutionDecision {
        left_entity_uid: "a".into(),
        right_entity_uid: "b".into(),
        state: ResolutionState::Match,
        probability: Some(0.99),
        supporting: vec!["hibp-1".into(), "dehashed-1".into()],
        contradicting: vec![],
        temporal_conflict: false,
        geographic_conflict: false,
        decided_at_unix: 0,
    };
    let independent = IdentityResolutionDecision {
        supporting: vec!["dehashed-1".into(), "abr-1".into()],
        ..mirrors.clone()
    };
    let unscored = IdentityResolutionDecision {
        probability: None,
        ..independent.clone()
    };
    let nan = IdentityResolutionDecision {
        probability: Some(f64::NAN),
        ..independent.clone()
    };
    let resolution = resolve_with_lineage(
        observations.clone(),
        vec![mirrors, independent, unscored, nan],
        AutoMergePolicy::default(),
    )
    .map_err(|e| (5, e.to_string()))?;
    let [mirrors, independent, unscored, nan] = resolution.candidates.as_slice() else {
        return Err((5, "a merge candidate was dropped".into()));
    };
    gate(
        5,
        mirrors.independent_families.len() == 1 && mirrors.outcome != MergeOutcome::AutoMerge,
        "mirrors manufactured corroboration",
    )?;
    gate(
        5,
        independent.outcome == MergeOutcome::AutoMerge,
        "independent roots refused",
    )?;
    let held_for = |c: &CandidateOutcome, want: fn(&HoldReason) -> bool| matches!(&c.outcome, MergeOutcome::Held { reasons } if reasons.iter().any(want));
    gate(
        5,
        held_for(unscored, |r| *r == HoldReason::ProbabilityMissing)
            && held_for(nan, |r| matches!(r, HoldReason::ProbabilityInvalid { .. })),
        "merge without a valid probability",
    )?;
    gate(
        5,
        resolution
            .observations
            .iter()
            .map(|o| &o.observation)
            .eq(&observations),
        "observation dropped or re-attributed",
    )
}

/// Gate 5, graph half: the hand-built ancestry graph and `allows_automatic_merge`, the
/// exact path `resolve::automatic_clusters` takes in production. Unlike the lineage
/// graph (one root plus relay nodes), it has an explicit parent chain and a root that
/// supports a candidate directly. Two mirrors of one dump are one family; a mirror plus
/// an independent registry root are two.
fn check_ancestry_graph_gate() -> Gate {
    let mut graph = EvidenceAncestryGraph::default();
    let nodes: [(&str, &str, &[&str]); 4] = [
        ("dump", "Adobe 2013", &[]),
        ("mirror-a", "provider-a", &["dump"]),
        ("mirror-b", "provider-b", &["dump"]),
        ("registry", "company registry", &[]),
    ];
    for (id, family, parents) in nodes {
        graph
            .insert(EvidenceAncestryNode {
                id: id.into(),
                source_family: family.into(),
                parents: parents.iter().copied().map(EvidenceNodeId::from).collect(),
                derived: !parents.is_empty(),
            })
            .map_err(|e| (5, e.to_string()))?;
    }
    let mirrors = IdentityResolutionDecision {
        left_entity_uid: "a".into(),
        right_entity_uid: "b".into(),
        state: ResolutionState::Match,
        probability: Some(0.99),
        supporting: vec!["mirror-a".into(), "mirror-b".into()],
        contradicting: vec![],
        temporal_conflict: false,
        geographic_conflict: false,
        decided_at_unix: 0,
    };
    gate(
        5,
        !mirrors.allows_automatic_merge(&graph, AutoMergePolicy::default()),
        "mirrors manufactured corroboration (ancestry graph)",
    )?;
    let independent = IdentityResolutionDecision {
        supporting: vec!["mirror-a".into(), "registry".into()],
        ..mirrors
    };
    gate(
        5,
        independent.allows_automatic_merge(&graph, AutoMergePolicy::default()),
        "independent roots refused (ancestry graph)",
    )
}

/// RCVF recorder gate: full terminate refuses an empty tip and binds to the real one.
fn check_session(meters: f64, tip: &str) -> Gate {
    let mut session = Session::new("check");
    session.apply_recover(
        "local-first core",
        "chain bound to session",
        "network only through the guarded fetch layer",
        "terminate only with tip",
    );
    let recorded = session
        .add_candidate(Candidate {
            statement: "hash chain".into(),
            alternatives: vec!["independent hashes".into()],
            reverse_observation: "reorder undetected".into(),
        })
        .and_then(|()| {
            session.add_falsify(FalsifyRecord {
                attack: "terminate without tip".into(),
                test: "full terminate empty tip".into(),
                result: "refused".into(),
            })
        })
        .and_then(|()| {
            session.add_execute(ExecuteRecord {
                action: "check".into(),
                observed: format!("{meters:.0}"),
                component: "src/geoint.rs".into(),
            })
        })
        .and_then(|()| {
            session.add_verify(VerifyRecord {
                claim: "tip binds the session".into(),
                status: Status::Verified,
                evidence_level: EvidenceLevel::DirectObservation,
                does_not_show: "not a live collection".into(),
            })
        });
    recorded.map_err(|e| (6, e.to_string()))?;
    gate(
        6,
        session
            .terminate("no handset run".into(), false, "")
            .is_err(),
        "terminate accepted empty tip",
    )?;
    session
        .terminate("no handset run".into(), false, tip)
        .map_err(|e| (6, e.to_string()))?;
    gate(6, session.bound_to(tip), "session not bound to tip")?;
    Ok(())
}
