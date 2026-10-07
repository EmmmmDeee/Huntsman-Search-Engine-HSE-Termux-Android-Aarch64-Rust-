//! Operable binary. No hardcoded workspace path.
//! `check` fails if a self-labeled technique enters Navigator or STIX.

mod selfcheck;

use std::env;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use huntsman_recon::au_id::{Identifier, classify as classify_id};
use huntsman_recon::classifier;
use huntsman_recon::classifier::classify as classify_indicator;
use huntsman_recon::classify::classify_response;
use huntsman_recon::confidence::{Classification, effective};
use huntsman_recon::credential_origin::{AuthenticationAuthority, OperatorCredentialRef};
use huntsman_recon::crtsh::{self, CrtShError};
use huntsman_recon::directive_lock;
use huntsman_recon::dns;
use huntsman_recon::egress::EgressPolicy;
use huntsman_recon::email_cli::{EMAIL_HELP, EMAIL_USAGE, EmailArgs, EmailRun};
use huntsman_recon::engineering_command;
use huntsman_recon::entity;
use huntsman_recon::error::Error;
use huntsman_recon::fetch::{Credential, FetchOptions, fetch};
use huntsman_recon::fetch_cli::{FETCH_USAGE, FetchArgs};
use huntsman_recon::fsio::{read_bounded, write_atomic};
use huntsman_recon::geohash;
use huntsman_recon::geoint::{haversine_m, parse_latlon};
use huntsman_recon::hibp::cli::{HIBP_USAGE, HibpCommand};
use huntsman_recon::http::{
    Request, TransportConfig, UreqTransport, origin_of, parse_http_uri, redact_url,
};
use huntsman_recon::identity::{PersonRecord, resolve};
use huntsman_recon::keys::Keys;
use huntsman_recon::ledger::{admitted, load_chain};
use huntsman_recon::lineage::{CandidateOutcome, MergeOutcome, Observation, resolve_with_lineage};
use huntsman_recon::lookup_save::{self, EMAIL_POLICY, PHONE_POLICY, USERNAME_POLICY};
use huntsman_recon::module::reachable_modules;
use huntsman_recon::navigator::layer;
use huntsman_recon::people_cli::{self, PEOPLE_HELP, PEOPLE_USAGE, PeopleArgs, PeopleRun};
use huntsman_recon::phone_cli::{PHONE_HELP, PHONE_USAGE, PhoneArgs, PhoneRun};
use huntsman_recon::provider_credentials;
use huntsman_recon::recon::ReconTargetKind;
use huntsman_recon::redact::coarsen_latlon;
use huntsman_recon::retrieval_artifact::ArtifactId;
use huntsman_recon::scan_batch::parse_seed_list;
use huntsman_recon::scan_route::{ScanKind, infer_kind, parse_kind};
use huntsman_recon::search::{Document, load_dir, search, tokenize};
use huntsman_recon::seeknow_cli::{SEEKNOW_HELP, SEEKNOW_USAGE, SeekNowCliRun};
use huntsman_recon::session::{Candidate, ExecuteRecord, FalsifyRecord, Session, VerifyRecord};
use huntsman_recon::sf_compat::{self, SF_USAGE, SfAction, SfArgs};
use huntsman_recon::source_outcome::{classify_fetch, recommended_action};
use huntsman_recon::source_registry::routes_for;
use huntsman_recon::stage::{EvidenceLevel, Status};
use huntsman_recon::stix::bundle;
use huntsman_recon::stolen_tax::{self, StolenTaxError};
use huntsman_recon::termination::{FrontierState, TerminationSignals, decide_termination};
use huntsman_recon::textnorm::escape_controls;
use huntsman_recon::username_cli::{USERNAME_HELP, USERNAME_USAGE, UsernameArgs, UsernameRun};
use huntsman_recon::web_query;
use huntsman_recon::web_server::{ServeConfig, Server, resolve_serve_bind};

const USAGE: &str = "usage: huntsman-recon [check | command | directive check|sync [ROOT] | geo LAT,LON LAT,LON | geohash LAT,LON [PRECISION] | coarsen LAT,LON | id TOKEN | search QUERY [DIR] | sources QUERY | domain-lifecycle analyze INPUT --as-of TIME [--output FILE] | people NAME [--save FILE] | email ADDR [--save FILE] | username HANDLE [--save FILE] | phone NUMBER [--save FILE] | scan SELECTOR [-k people|email|username|phone] [--save FILE] | scan --input-file FILE [-k people|email|username|phone] | investigate TEXT...|--file FILE | query QUERY... | sf [-M|-T|-V]|-s TARGET [options] | serve [--bind ADDR] | modules [--json] | classify STATUS BODY | fetch URL [options] | hibp SUBCOMMAND | recon crtsh TARGET|dns TARGET|stolen-tax QUERY [--keys FILE] | seeknow SUBCOMMAND | keys FILE | credential-status [--probe] [FILE] | verify LEDGER]";
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
  directive             Verify or repair canonical repository instruction mirrors
  geo                   Distance between two LAT,LON coordinates in metres
  geohash               Encode LAT,LON (default precision: 7)
  coarsen               Round LAT,LON to one decimal place
  id                    Classify and validate an Australian ABN, ACN, or BSB
  search                Search the built-in fixture or one local text directory
  sources               Classify an indicator and print curated routes (offline)
  domain-lifecycle      Compare imported domain observations offline
  people                Look up a name on keyless ASIC people registers
  email                 Enrich an email and query its public Gravatar profile
  username              Enrich a username through public GitHub and Bluesky profiles
  phone                 Canonicalise and classify a phone number offline
  scan                  Route one selector or bounded seed-list into rebuilt lookup front-ends
  investigate           Extract actionable entities from local text or one bounded file
  query                 Query the rebuilt keyless web-search subset
  sf                    SpiderFoot-compatible front end over rebuilt lookup paths
  serve                 Start the embedded Web UI and JSON API
  modules               List only currently reachable rebuilt modules
  classify              Classify an HTTP status and response body
  fetch                 Make a guarded HTTP request (network access)
  hibp                  Have I Been Pwned lookups (opt-in; keyed subcommands need a key)
  recon                 One crt.sh, DNS/mail, or stolen.tax lookup (network access)
  seeknow               SeekNow/See-Know lookup (opt-in; needs HUNTSMAN_SEEKNOW_KEY)
  keys                  Validate a private keys file; print slots and fingerprints
  credential-status     Show provider credential completeness without values
  verify                Verify a saved evidence ledger

Run `huntsman-recon <COMMAND> --help` for command details.
Search and sources do not collect remote results. `fetch`, `hibp`, `recon`,
`seeknow`, `people`, `email`, `username`, `query`, and networked `sf -s` lookups make HTTP requests; `serve` accepts inbound HTTP connections; their default
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
        return selfcheck::check();
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
        Some("directive") => directive_cmd(&remaining.collect::<Vec<_>>()),
        Some("geo") => geo(remaining.next(), remaining.next()),
        Some("geohash") => geohash_cmd(remaining.next(), remaining.next().as_deref()),
        Some("coarsen") => coarsen_cmd(remaining.next()),
        Some("id") => id_cmd(remaining.next()),
        Some("search") => search_cmd(remaining.next(), remaining.next()),
        Some("sources") => sources_cmd(remaining.next()),
        Some("domain-lifecycle") => domain_lifecycle_cmd(&remaining.collect::<Vec<_>>()),
        Some("people") => people_cmd(&remaining.collect::<Vec<_>>()),
        Some("email") => email_cmd(&remaining.collect::<Vec<_>>()),
        Some("username") => username_cmd(&remaining.collect::<Vec<_>>()),
        Some("phone") => phone_cmd(&remaining.collect::<Vec<_>>()),
        Some("scan") => scan_cmd(&remaining.collect::<Vec<_>>()),
        Some("investigate") => investigate_cmd(&remaining.collect::<Vec<_>>()),
        Some("query") => query_cmd(&remaining.collect::<Vec<_>>()),
        Some("sf") => sf_cmd(&remaining.collect::<Vec<_>>()),
        Some("serve") => serve_cmd(&remaining.collect::<Vec<_>>()),
        Some("modules") => modules_cmd(&remaining.collect::<Vec<_>>()),
        Some("classify") => classify(remaining.next(), remaining.next()),
        Some("fetch") => fetch_cmd(&remaining.collect::<Vec<_>>()),
        Some("hibp") => hibp_cmd(&remaining.collect::<Vec<_>>()),
        Some("recon") => recon_cmd(&remaining.collect::<Vec<_>>()),
        Some("seeknow") => seeknow_cmd(&remaining.collect::<Vec<_>>()),
        Some("keys") => keys_cmd(remaining.next()),
        Some("credential-status") => credential_status_cmd(&remaining.collect::<Vec<_>>()),
        Some("verify") => verify(remaining.next()),
        Some("check") | None => selfcheck::check(),
        Some(other) => fail(EX_USAGE, &format!("unknown command: {other}\n{USAGE}")),
    }
}

fn print_command_help(command: &str) {
    let help = match command {
        "check" => {
            "check\nRun offline self-acceptance and regenerate var/ledger.json, var/navigator.json, and var/stix-bundle.json."
        }
        "command" => {
            "command [--json]\nValidate and print the fixed engineering command invariant, phases, roles, execution protocols, and capability owners."
        }
        "directive" => {
            "directive check|sync [ROOT]\nVerify or repair the pinned canonical Huntsman directive. Without ROOT, check auto-discovers a source checkout from the current directory or its parents and otherwise verifies the embedded canonical artifact; sync requires a source checkout."
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
        "domain-lifecycle" => huntsman_recon::domain_lifecycle::USAGE,
        "people" => PEOPLE_HELP,
        "email" => EMAIL_HELP,
        "username" => USERNAME_HELP,
        "phone" => PHONE_HELP,
        "scan" => {
            "scan SELECTOR [-k people|email|username|phone] [--save FILE] | scan --input-file FILE [-k people|email|username|phone]\nRoute one selector or a bounded one-target-per-line file into rebuilt lookup front-ends. Batch input trims lines, ignores blank/# comment lines, de-duplicates exact seeds, attempts every seed, and exits non-zero after the batch if any seed failed. --save is single-selector only."
        }
        "investigate" => {
            "investigate TEXT... | investigate --file FILE\nExtract actionable entities from local text. --file refuses symlinks and files over 1 MiB."
        }
        "query" => {
            "query QUERY...\nQuery the rebuilt keyless Bing, Brave, and Mojeek subset through the shared fetch boundary; provider failures remain independent."
        }
        "sf" => SF_USAGE,
        "serve" => {
            "serve [--bind ADDR]\nStart the embedded read-only Web UI and JSON API. Default: 127.0.0.1:8080. HSE_BIND supplies the default bind; an explicit non-loopback bind requires HSE_AUTH_TOKEN."
        }
        "modules" => {
            "modules [--json]\nList only rebuilt modules that are currently reachable through a huntsman-recon command."
        }
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
        "credential-status" => {
            "credential-status [--probe] [FILE]\nShow provider slot completeness without printing credential values. --probe performs canonical live health checks for configured providers that have a registered probe. FILE uses the existing private keys-file loader; otherwise the normal ~/.huntsman.env/environment resolution is used."
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

fn credential_status_cmd(args: &[String]) -> ExitCode {
    let mut live_probe = false;
    let mut explicit = None;
    for arg in args {
        match arg.as_str() {
            "--probe" if !live_probe => live_probe = true,
            flag if flag.starts_with('-') => {
                return fail(
                    EX_USAGE,
                    "usage: huntsman-recon credential-status [--probe] [FILE]",
                );
            }
            path if explicit.is_none() => explicit = Some(Path::new(path)),
            _ => {
                return fail(
                    EX_USAGE,
                    "usage: huntsman-recon credential-status [--probe] [FILE]",
                );
            }
        }
    }

    let home = env::var_os("HOME");
    match Keys::resolve(explicit, home.as_deref()) {
        Ok(resolved) => {
            if let Some(warning) = resolved.warning {
                eprintln!("{warning}");
            }
            if live_probe {
                let transport = UreqTransport::new(&TransportConfig::default());
                print!(
                    "{}",
                    provider_credentials::render_probed(&resolved.keys, &transport)
                );
            } else {
                print!("{}", provider_credentials::render(&resolved.keys));
            }
            ExitCode::SUCCESS
        }
        Err(error) => fail(EX_NOINPUT, &error.to_string()),
    }
}

fn fail(code: u8, msg: &str) -> ExitCode {
    eprintln!("{msg}");
    ExitCode::from(code)
}

fn command_cmd(args: &[String]) -> ExitCode {
    let json = match args {
        [] => false,
        [flag] if flag == "--json" => true,
        _ => return fail(EX_USAGE, "usage: huntsman-recon command [--json]"),
    };
    let rendered = if json {
        engineering_command::render_json()
    } else {
        engineering_command::render()
    };
    match rendered {
        Ok(rendered) => {
            if json {
                println!("{rendered}");
            } else {
                print!("{rendered}");
            }
            ExitCode::SUCCESS
        }
        Err(message) => fail(EX_DATAERR, message),
    }
}

fn discover_directive_root(explicit: Option<&str>) -> Result<Option<PathBuf>, String> {
    if let Some(root) = explicit {
        return Ok(Some(PathBuf::from(root)));
    }
    let cwd = env::current_dir().map_err(|error| format!("current directory: {error}"))?;
    Ok(cwd
        .ancestors()
        .find(|candidate| candidate.join(directive_lock::CANONICAL).is_file())
        .map(Path::to_path_buf))
}

fn directive_cmd(args: &[String]) -> ExitCode {
    let (action, explicit_root) = match args {
        [action] => (action.as_str(), None),
        [action, root] => (action.as_str(), Some(root.as_str())),
        _ => {
            return fail(
                EX_USAGE,
                "usage: huntsman-recon directive check|sync [ROOT]",
            );
        }
    };

    let root = match discover_directive_root(explicit_root) {
        Ok(root) => root,
        Err(message) => return fail(EX_NOINPUT, &message),
    };

    let (scope, mirrors, result) = match action {
        "check" => match root.as_deref() {
            Some(root) => (
                "repository",
                directive_lock::MIRRORS.len(),
                directive_lock::verify_at(root),
            ),
            None => ("embedded", 0, directive_lock::verify_embedded()),
        },
        "sync" => {
            let Some(root) = root.as_deref() else {
                return fail(
                    EX_NOINPUT,
                    "directive sync requires a source checkout; run it from the repository tree or pass ROOT",
                );
            };
            (
                "repository",
                directive_lock::MIRRORS.len(),
                directive_lock::sync_at(root),
            )
        }
        _ => {
            return fail(
                EX_USAGE,
                "usage: huntsman-recon directive check|sync [ROOT]",
            );
        }
    };

    match result {
        Ok(()) => {
            println!("directive={action}");
            println!("scope={scope}");
            println!("canonical={}", directive_lock::CANONICAL);
            println!("sha256={}", directive_lock::EXPECTED_SHA256);
            println!("mirrors={mirrors}");
            if let Some(root) = root {
                println!("root={}", root.display());
            }
            ExitCode::SUCCESS
        }
        Err(message) => fail(EX_DATAERR, &message),
    }
}

fn domain_lifecycle_cmd(args: &[String]) -> ExitCode {
    use huntsman_recon::domain_lifecycle::{Input, MAX_INPUT_BYTES, USAGE, analyze};

    if args.len() == 2 && args[0] == "analyze" && matches!(args[1].as_str(), "--help" | "-h") {
        println!("{USAGE}");
        return ExitCode::SUCCESS;
    }
    if !matches!(args.len(), 4 | 6)
        || args[0] != "analyze"
        || args[2] != "--as-of"
        || (args.len() == 6 && args[4] != "--output")
    {
        return fail(EX_USAGE, USAGE);
    }

    let Ok(as_of) = args[3].parse::<u64>() else {
        return fail(EX_USAGE, "--as-of requires Unix seconds");
    };
    let bytes = match read_bounded(Path::new(&args[1]), MAX_INPUT_BYTES) {
        Ok(bytes) => bytes,
        Err(error) => return fail(EX_NOINPUT, &error.to_string()),
    };
    let input: Input = match serde_json::from_slice(&bytes) {
        Ok(input) => input,
        Err(error) => return fail(EX_DATAERR, &error.to_string()),
    };
    let mut output = match analyze(input, as_of).and_then(|report| {
        serde_json::to_vec_pretty(&report).map_err(|error| Error::Invalid(error.to_string()))
    }) {
        Ok(output) => output,
        Err(error) => return fail(EX_DATAERR, &error.to_string()),
    };
    output.push(b'\n');

    if args.len() == 6 {
        let input_path = Path::new(&args[1]);
        let output_path = Path::new(&args[5]);
        let same_file = std::fs::canonicalize(input_path)
            .ok()
            .zip(std::fs::canonicalize(output_path).ok())
            .is_some_and(|(input, output)| input == output);
        if same_file || input_path == output_path {
            return fail(EX_USAGE, "output must differ from input");
        }
        if let Err(error) = write_atomic(output_path, &output, 16_777_216) {
            return fail(EX_IOERR, &error.to_string());
        }
    } else if let Err(error) = std::io::Write::write_all(&mut std::io::stdout().lock(), &output) {
        return fail(EX_IOERR, &error.to_string());
    }
    ExitCode::SUCCESS
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

fn phone_cmd(args: &[String]) -> ExitCode {
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

fn scan_cmd(args: &[String]) -> ExitCode {
    let mut kind: Option<&str> = None;
    let mut input_file: Option<&str> = None;
    let mut forwarded = Vec::new();
    let mut index = 0;

    while index < args.len() {
        match args[index].as_str() {
            "-k" | "--kind" => {
                if kind.is_some() {
                    return fail(EX_USAGE, "scan accepts only one -k/--kind");
                }
                let Some(value) = args.get(index + 1) else {
                    return fail(EX_USAGE, "scan -k/--kind needs a value");
                };
                kind = Some(value.as_str());
                index += 2;
            }
            "--input-file" => {
                if input_file.is_some() {
                    return fail(EX_USAGE, "scan accepts only one --input-file");
                }
                let Some(value) = args.get(index + 1) else {
                    return fail(EX_USAGE, "scan --input-file needs a value");
                };
                if value.starts_with("--") {
                    return fail(EX_USAGE, "scan --input-file needs a file path");
                }
                input_file = Some(value.as_str());
                index += 2;
            }
            value => {
                forwarded.push(value.to_owned());
                index += 1;
            }
        }
    }

    if let Some(path) = input_file {
        if !forwarded.is_empty() {
            return fail(
                EX_USAGE,
                "scan --input-file does not accept a positional selector or --save",
            );
        }
        return scan_batch_file(path, kind);
    }

    scan_one(&forwarded, kind)
}

fn scan_batch_file(path: &str, kind: Option<&str>) -> ExitCode {
    let bytes = match read_bounded(Path::new(path), MAX_ARTIFACT_BYTES) {
        Ok(bytes) => bytes,
        Err(Error::Store(message)) => return fail(EX_NOINPUT, &message),
        Err(error) => return fail(EX_DATAERR, &error.to_string()),
    };
    let Ok(body) = String::from_utf8(bytes) else {
        return fail(EX_DATAERR, "scan --input-file is not UTF-8");
    };
    let seeds = match parse_seed_list(&body) {
        Ok(seeds) => seeds,
        Err(error) => return fail(EX_DATAERR, &error.to_string()),
    };

    let total = seeds.len();
    eprintln!("batch: scanning {total} seed(s) from {path}");
    let mut succeeded = 0usize;
    let mut failed = 0usize;
    let mut first_failure = None;

    for (offset, seed) in seeds.iter().enumerate() {
        eprintln!("batch [{}/{}] {}", offset + 1, total, escape_controls(seed));
        let code = scan_one(std::slice::from_ref(seed), kind);
        if code == ExitCode::SUCCESS {
            succeeded += 1;
        } else {
            failed += 1;
            first_failure.get_or_insert(code);
        }
    }

    eprintln!("batch complete: {succeeded} succeeded, {failed} failed, {total} total");
    first_failure.unwrap_or(ExitCode::SUCCESS)
}

fn scan_one(forwarded: &[String], kind: Option<&str>) -> ExitCode {
    let Some(selector) = forwarded.first() else {
        return fail(
            EX_USAGE,
            "usage: huntsman-recon scan SELECTOR [-k people|email|username|phone] [--save FILE] | scan --input-file FILE [-k people|email|username|phone]",
        );
    };
    if selector.starts_with("--") {
        return fail(EX_USAGE, "scan needs SELECTOR before options");
    }

    let route = match kind {
        Some(value) => match parse_kind(value) {
            Ok(kind) => kind,
            Err(other) => return fail(EX_USAGE, &format!("unsupported scan kind: {other}")),
        },
        None => infer_kind(selector),
    };

    eprintln!("scan_route={}", route.command());
    match route {
        ScanKind::Email => email_cmd(forwarded),
        ScanKind::Username => username_cmd(forwarded),
        ScanKind::Phone => phone_cmd(forwarded),
        ScanKind::People => people_cmd(forwarded),
    }
}

fn investigate_cmd(args: &[String]) -> ExitCode {
    if args.is_empty() {
        return fail(
            EX_USAGE,
            "usage: huntsman-recon investigate TEXT... | investigate --file FILE",
        );
    }

    let text = if args.first().is_some_and(|arg| arg == "--file") {
        if args.len() != 2 {
            return fail(EX_USAGE, "investigate --file needs exactly one FILE");
        }
        let path = Path::new(&args[1]);
        let bytes = match read_bounded(path, MAX_ARTIFACT_BYTES) {
            Ok(bytes) => bytes,
            Err(Error::Store(message)) => return fail(EX_NOINPUT, &message),
            Err(error) => return fail(EX_DATAERR, &error.to_string()),
        };
        match String::from_utf8(bytes) {
            Ok(text) => text,
            Err(_) => return fail(EX_DATAERR, "investigate input is not UTF-8"),
        }
    } else {
        if args.iter().any(|arg| arg == "--file") {
            return fail(EX_USAGE, "--file must be the first investigate argument");
        }
        args.join(" ")
    };

    let scan_id = entity::scan_id("investigate", &text);
    let entities = classifier::extract_entities(&text, &scan_id);
    println!("entities={}", entities.len());
    for entity in entities {
        println!(
            "{}\t{}\t{:.2}\t{}",
            entity.kind,
            entity.raw_value,
            entity.confidence,
            entity.tags.join(",")
        );
        for evidence in entity.evidence {
            println!(
                "evidence\t{}\t{}",
                evidence.provenance.source, evidence.summary
            );
        }
    }
    ExitCode::SUCCESS
}

fn query_cmd(args: &[String]) -> ExitCode {
    if args.is_empty() {
        return fail(EX_USAGE, "usage: huntsman-recon query QUERY...");
    }
    let query = args.join(" ");
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs());
    let transport = UreqTransport::new(&TransportConfig::default());

    match web_query::search(&transport, &query, now) {
        Ok(report) => {
            for outcome in &report.outcomes {
                let kind = serde_json::to_value(outcome.kind)
                    .ok()
                    .and_then(|value| value.as_str().map(str::to_owned))
                    .unwrap_or_else(|| "unknown".into());
                println!(
                    "engine={}\toutcome={}\tfound={}",
                    outcome.module,
                    kind,
                    outcome
                        .found
                        .map_or_else(|| "none".to_owned(), |count| count.to_string())
                );
            }
            for hit in &report.hits {
                println!("{}\t{}", hit.engine, hit.url);
            }
            println!("hits={}", report.hits.len());
            if report.hits.is_empty() {
                ExitCode::from(EX_UNAVAILABLE)
            } else {
                ExitCode::SUCCESS
            }
        }
        Err(Error::Invalid(message)) => fail(EX_USAGE, &message),
        Err(Error::Network(message)) => fail(EX_NOPERM, &message),
        Err(error) => fail(EX_UNAVAILABLE, &error.to_string()),
    }
}

fn sf_cmd(args: &[String]) -> ExitCode {
    let parsed = match SfArgs::parse(args) {
        Ok(parsed) => parsed,
        Err(error) => return fail(EX_USAGE, &format!("{error}\n{SF_USAGE}")),
    };
    let action = match sf_compat::action(&parsed) {
        Ok(action) => action,
        Err(error) => return fail(EX_DATAERR, &error.to_string()),
    };
    match action {
        SfAction::Text(body) => {
            print!("{body}");
            ExitCode::SUCCESS
        }
        SfAction::Scan(scan) => {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |duration| duration.as_secs());
            let transport = UreqTransport::new(&TransportConfig::default());
            match sf_compat::run_scan(&transport, &scan, now) {
                Ok(body) => {
                    print!("{body}");
                    ExitCode::SUCCESS
                }
                Err(Error::Network(message)) => fail(EX_UNAVAILABLE, &message),
                Err(Error::Invalid(message)) => fail(EX_DATAERR, &message),
                Err(error) => fail(EX_UNAVAILABLE, &error.to_string()),
            }
        }
    }
}

fn serve_cmd(args: &[String]) -> ExitCode {
    let hse_bind = env::var("HSE_BIND").ok();
    let railway_port = env::var("PORT").ok();
    let railway = [
        "RAILWAY_ENVIRONMENT",
        "RAILWAY_ENVIRONMENT_ID",
        "RAILWAY_PROJECT_ID",
        "RAILWAY_SERVICE_ID",
    ]
    .iter()
    .any(|name| env::var_os(name).is_some());
    let mut bind = match resolve_serve_bind(hse_bind.as_deref(), railway_port.as_deref(), railway) {
        Ok(bind) => bind,
        Err(Error::Invalid(message)) => return fail(EX_DATAERR, &message),
        Err(error) => return fail(EX_UNAVAILABLE, &error.to_string()),
    };
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--bind" => {
                let Some(value) = args.get(index + 1) else {
                    return fail(EX_USAGE, "serve --bind needs ADDR");
                };
                bind.clone_from(value);
                index += 2;
            }
            other => {
                return fail(
                    EX_USAGE,
                    &format!(
                        "unknown serve option: {other}\nusage: huntsman-recon serve [--bind ADDR]"
                    ),
                );
            }
        }
    }

    let token = env::var("HSE_AUTH_TOKEN").ok();
    let config = match ServeConfig::parse(&bind, token) {
        Ok(config) => config,
        Err(Error::Invalid(message)) => return fail(EX_DATAERR, &message),
        Err(error) => return fail(EX_UNAVAILABLE, &error.to_string()),
    };
    let server = match Server::bind(config) {
        Ok(server) => server,
        Err(error) => return fail(EX_UNAVAILABLE, &error.to_string()),
    };
    match server.local_addr() {
        Ok(addr) => println!("serving=http://{addr}/"),
        Err(error) => return fail(EX_UNAVAILABLE, &error.to_string()),
    }
    match server.run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => fail(EX_UNAVAILABLE, &error.to_string()),
    }
}

fn modules_cmd(args: &[String]) -> ExitCode {
    let json = match args {
        [] => false,
        [flag] if flag == "--json" => true,
        _ => return fail(EX_USAGE, "usage: huntsman-recon modules [--json]"),
    };
    let modules = reachable_modules();
    if json {
        match serde_json::to_string_pretty(&serde_json::json!({
            "count": modules.len(),
            "modules": modules,
        })) {
            Ok(body) => {
                println!("{body}");
                ExitCode::SUCCESS
            }
            Err(error) => fail(EX_DATAERR, &format!("json: {error}")),
        }
    } else {
        println!("MODULE\tACCESS\tNETWORK\tCOMMAND\tDESCRIPTION");
        for module in modules {
            println!(
                "{}\t{}\t{}\t{}\t{}",
                module.name,
                module.access,
                if module.network { "yes" } else { "no" },
                module.command,
                module.description
            );
        }
        println!("count={}", modules.len());
        ExitCode::SUCCESS
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
