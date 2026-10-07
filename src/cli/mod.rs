//! CLI composition and dispatch for `huntsman-recon`.
//!
//! This module is deliberately an adapter layer: it parses process arguments,
//! constructs transports/configuration, and delegates to the library. Domain
//! behavior belongs in `huntsman_recon`, not in the binary front controller.

use std::env;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use huntsman_recon::attack_cli::{ATTACK_USAGE, render as render_attack};
use huntsman_recon::au_id::{Identifier, classify as classify_id};
use huntsman_recon::classifier;
use huntsman_recon::classifier::classify as classify_indicator;
use huntsman_recon::classify::classify_response;
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
use huntsman_recon::http::{Request, TransportConfig, UreqTransport, parse_http_uri};
use huntsman_recon::keys::Keys;
use huntsman_recon::ledger::{admitted, load_chain};
use huntsman_recon::lookup_save::{self, EMAIL_POLICY, PHONE_POLICY, USERNAME_POLICY};
use huntsman_recon::module::reachable_modules;
use huntsman_recon::people_cli::{self, PEOPLE_HELP, PEOPLE_USAGE, PeopleArgs, PeopleRun};
use huntsman_recon::phone_cli::{PHONE_HELP, PHONE_USAGE, PhoneArgs, PhoneRun};
use huntsman_recon::provider_credentials;
use huntsman_recon::recon::ReconTargetKind;
use huntsman_recon::redact::coarsen_latlon;
use huntsman_recon::scan_batch::parse_seed_list;
use huntsman_recon::scan_route::{ScanKind, infer_kind, parse_kind};
use huntsman_recon::search::{Document, load_dir, search, tokenize};
use huntsman_recon::seeknow_cli::{SEEKNOW_HELP, SEEKNOW_USAGE, SeekNowCliRun};
use huntsman_recon::sf_compat::{self, SF_USAGE, SfAction, SfArgs};
use huntsman_recon::source_outcome::{classify_fetch, recommended_action};
use huntsman_recon::source_registry::routes_for;
use huntsman_recon::stolen_tax::{self, StolenTaxError};
use huntsman_recon::textnorm::escape_controls;
use huntsman_recon::username_cli::{USERNAME_HELP, USERNAME_USAGE, UsernameArgs, UsernameRun};
use huntsman_recon::web_query;
use huntsman_recon::web_server::{ServeConfig, Server, resolve_serve_bind};

const BUILD_SHA: &str = match option_env!("HUNTSMAN_BUILD_SHA") {
    Some(value) => value,
    None => "unknown",
};

const USAGE: &str = "usage: huntsman-recon [check | diagnostics [--json] | build-sha | command | directive check|sync [ROOT] | geo LAT,LON LAT,LON | geohash LAT,LON [PRECISION] | coarsen LAT,LON | id TOKEN | search QUERY [DIR] | sources QUERY | domain-lifecycle analyze INPUT --as-of TIME [--output FILE] | people NAME [--save FILE] | email ADDR [--save FILE] | username HANDLE [--save FILE] | phone NUMBER [--save FILE] | scan SELECTOR [-k people|email|username|phone] [--save FILE] | scan --input-file FILE [-k people|email|username|phone] | investigate TEXT...|--file FILE | query QUERY... | sf [-M|-T|-V]|-s TARGET [options] | serve [--bind ADDR] | modules [--json] | attack SUBCOMMAND | classify STATUS BODY | fetch URL [options] | hibp SUBCOMMAND | recon crtsh TARGET|dns TARGET|stolen-tax QUERY [--keys FILE] | seeknow SUBCOMMAND | keys FILE | credential-status [--probe] [FILE] | verify LEDGER]";
const RECON_USAGE: &str = "usage: huntsman-recon recon crtsh TARGET | recon dns TARGET | recon stolen-tax QUERY [--keys FILE]";
const HELP: &str = "\
Huntsman Recon — local search, guarded fetch, and evidence-ledger tools

Usage:
  huntsman-recon <COMMAND> [ARGS]
  huntsman-recon --help
  huntsman-recon --version

Commands:
  check                 Run offline self-acceptance and regenerate var/*.json
  diagnostics           Print offline build/runtime/module/provider diagnostics
  build-sha             Print the embedded source commit or unknown
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
  attack                MITRE ATT&CK Reconnaissance posture, coverage, gaps, or Navigator JSON
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
mod help;
mod lookup;
mod meta;
mod network;
mod selfcheck;
mod service;
mod utility;

pub(crate) fn run(argv: Vec<String>) -> ExitCode {
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
        help::print_command_help(&argv[0]);
        return ExitCode::SUCCESS;
    }
    let mut remaining = argv.into_iter();
    match remaining.next().as_deref() {
        Some("diagnostics") => meta::diagnostics_cmd(&remaining.collect::<Vec<_>>()),
        Some("build-sha") => meta::build_sha_cmd(&remaining.collect::<Vec<_>>()),
        Some("command") => meta::command_cmd(&remaining.collect::<Vec<_>>()),
        Some("directive") => meta::directive_cmd(&remaining.collect::<Vec<_>>()),
        Some("geo") => utility::geo(remaining.next(), remaining.next()),
        Some("geohash") => utility::geohash_cmd(remaining.next(), remaining.next().as_deref()),
        Some("coarsen") => utility::coarsen_cmd(remaining.next()),
        Some("id") => utility::id_cmd(remaining.next()),
        Some("search") => lookup::search_cmd(remaining.next(), remaining.next()),
        Some("sources") => lookup::sources_cmd(remaining.next()),
        Some("domain-lifecycle") => meta::domain_lifecycle_cmd(&remaining.collect::<Vec<_>>()),
        Some("people") => lookup::people_cmd(&remaining.collect::<Vec<_>>()),
        Some("email") => lookup::email_cmd(&remaining.collect::<Vec<_>>()),
        Some("username") => lookup::username_cmd(&remaining.collect::<Vec<_>>()),
        Some("phone") => lookup::phone_cmd(&remaining.collect::<Vec<_>>()),
        Some("scan") => lookup::scan_cmd(&remaining.collect::<Vec<_>>()),
        Some("investigate") => lookup::investigate_cmd(&remaining.collect::<Vec<_>>()),
        Some("query") => lookup::query_cmd(&remaining.collect::<Vec<_>>()),
        Some("sf") => lookup::sf_cmd(&remaining.collect::<Vec<_>>()),
        Some("serve") => service::serve_cmd(&remaining.collect::<Vec<_>>()),
        Some("modules") => meta::modules_cmd(&remaining.collect::<Vec<_>>()),
        Some("attack") => meta::attack_cmd(&remaining.collect::<Vec<_>>()),
        Some("classify") => utility::classify(remaining.next(), remaining.next()),
        Some("fetch") => network::fetch_cmd(&remaining.collect::<Vec<_>>()),
        Some("hibp") => network::hibp_cmd(&remaining.collect::<Vec<_>>()),
        Some("recon") => network::recon_cmd(&remaining.collect::<Vec<_>>()),
        Some("seeknow") => network::seeknow_cmd(&remaining.collect::<Vec<_>>()),
        Some("keys") => meta::keys_cmd(remaining.next()),
        Some("credential-status") => meta::credential_status_cmd(&remaining.collect::<Vec<_>>()),
        Some("verify") => meta::verify(remaining.next()),
        Some("check") | None => selfcheck::check(),
        Some(other) => fail(EX_USAGE, &format!("unknown command: {other}\n{USAGE}")),
    }
}

fn fail(code: u8, msg: &str) -> ExitCode {
    eprintln!("{msg}");
    ExitCode::from(code)
}
