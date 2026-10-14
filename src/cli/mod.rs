//! CLI composition and dispatch for `huntsman-recon`.
//!
//! This module is deliberately an adapter layer: it parses process arguments,
//! constructs transports/configuration, and delegates to the library. Domain
//! behavior belongs in `huntsman_recon`, not in the binary front controller.

use std::env;
use std::process::ExitCode;

const USAGE: &str = "usage: huntsman-recon [check | doctor [serve] [--fix] [--json] [--probe] [--bind ADDR] | fix [--json] [--probe] [--bind ADDR] | diagnostics [--json] | build-sha | command | directive check|sync [ROOT] | geo LAT,LON LAT,LON | geohash LAT,LON [PRECISION] | coarsen LAT,LON | id TOKEN... | search QUERY [DIR] | sources QUERY... | domain-lifecycle analyze INPUT --as-of TIME [--output FILE] | people NAME [--save FILE] | email ADDR [--save FILE] | exposure ADDR [--save FILE] | username HANDLE [--save FILE] | phone NUMBER [--save FILE] | domain DOMAIN [--save FILE] | network BSSID|LAT,LON|ssid:NAME [--save FILE] | scan SELECTOR [-k people|email|exposure|username|phone|domain|network] [--save FILE] | scan --input-file FILE [-k people|email|exposure|username|phone|domain|network] [--save-dir DIR] | investigate TEXT...|--file FILE | plan [--session-dir DIR] SEED... | plan --load-session DIR ID | query QUERY... | sf [-M|-T|-V]|-s TARGET [options] | serve [--bind ADDR] | modules [--json] | attack SUBCOMMAND | classify STATUS BODY... | fetch URL [options] | hibp SUBCOMMAND | dehashed SUBCOMMAND | recon crtsh TARGET|dns TARGET|stolen-tax QUERY [--keys FILE] | seeknow SUBCOMMAND | keys FILE | credential-status [--probe] [FILE] | verify LEDGER | correlate ARTIFACT [--history DIR] | run-history record|show [options]]";
const RECON_USAGE: &str = "usage: huntsman-recon recon crtsh TARGET | recon dns TARGET | recon stolen-tax QUERY [--keys FILE]";
const HELP: &str = "\
Huntsman Recon — local search, guarded fetch, and evidence-ledger tools

Usage:
  huntsman-recon <COMMAND> [ARGS]
  huntsman-recon --help
  huntsman-recon --version

Commands:
  check                 Run offline self-acceptance; writes var/*.json here
  doctor                Check the whole install and name the fix for each problem
  fix                   Run doctor and make every repair that can be undone
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
  exposure              Keyed breach evidence for an email (HIBP account, stolen.tax)
  username              Enrich a username through public GitHub and Bluesky profiles
  phone                 Canonicalise and classify a phone number offline
  domain                Certificate-transparency names and DNS records for one domain
  network               WiFi network by BSSID, SSID or LAT,LON (OUI offline, WiGLE keyed)
  scan                  Route one selector or bounded seed-list into rebuilt lookup front-ends
  investigate           Extract actionable entities from local text or one bounded file
  plan                  Plan an offline investigation from seeds; save or reload it as a session
  query                 Query the rebuilt keyless web-search subset
  sf                    SpiderFoot-compatible front end over rebuilt lookup paths
  serve                 Start the embedded Web UI and JSON API
  modules               List only currently reachable rebuilt modules
  attack                MITRE ATT&CK Reconnaissance posture, coverage, gaps, or Navigator JSON
  classify              Classify an HTTP status and response body
  fetch                 Make a guarded HTTP request (network access)
  hibp                  Have I Been Pwned lookups (opt-in; keyed subcommands need a key)
  dehashed              DeHashed exact-match search (opt-in; needs a key and --purpose)
  recon                 One crt.sh, DNS/mail, or stolen.tax lookup (network access)
  seeknow               SeekNow/See-Know lookup (opt-in; needs HUNTSMAN_SEEKNOW_KEY)
  keys                  Validate a private keys file; print slots and fingerprints
  credential-status     Show provider credential completeness without values
  verify                Verify a saved evidence ledger
  correlate             Run the correlation rules over a saved scan artifact, and pivot it across a history of saved scans (offline)
  run-history           Record test-run results and compare each with the earlier runs

Run `huntsman-recon <COMMAND> --help` for command details.
Search and sources do not collect remote results. `fetch`, `hibp`, `recon`,
`seeknow`, `people`, `email`, `exposure`, `username`, `domain`, `network`, `query`, `dehashed`, and networked `sf -s` lookups make HTTP requests; `serve` accepts inbound HTTP connections; their default
egress policy is public-only.";
const MAX_ARTIFACT_BYTES: u64 = 1_048_576;
mod credentials;
mod doctor;
mod help;
mod lookup;
mod meta;
mod network;
mod report;
mod selfcheck;
mod service;
mod utility;

use report::{exit_on_output_failure, fail};

pub(crate) fn run(argv: Vec<String>) -> ExitCode {
    exit_on_output_failure();
    let first = argv.first().map(String::as_str);
    if matches!(first, Some("help" | "-h" | "--help")) {
        println!("{HELP}\n{USAGE}");
        return ExitCode::SUCCESS;
    }
    if matches!(first, Some("-V" | "--version")) {
        println!("huntsman-recon {}", env!("CARGO_PKG_VERSION"));
        return ExitCode::SUCCESS;
    }
    if argv.len() == 2 && matches!(argv[1].as_str(), "-h" | "--help") {
        help::print_command_help(&argv[0]);
        return ExitCode::SUCCESS;
    }
    let mut remaining = argv.into_iter();
    match remaining.next().as_deref() {
        Some("doctor") => doctor::doctor_cmd(&remaining.collect::<Vec<_>>()),
        Some("fix") => doctor::fix_cmd(&remaining.collect::<Vec<_>>()),
        Some("diagnostics") => meta::diagnostics_cmd(&remaining.collect::<Vec<_>>()),
        Some("build-sha") => meta::build_sha_cmd(&remaining.collect::<Vec<_>>()),
        Some("command") => meta::command_cmd(&remaining.collect::<Vec<_>>()),
        Some("directive") => meta::directive_cmd(&remaining.collect::<Vec<_>>()),
        Some("geo") => utility::geo(&remaining.collect::<Vec<_>>()),
        Some("geohash") => utility::geohash_cmd(&remaining.collect::<Vec<_>>()),
        Some("coarsen") => utility::coarsen_cmd(&remaining.collect::<Vec<_>>()),
        Some("id") => utility::id_cmd(&remaining.collect::<Vec<_>>()),
        Some("search") => lookup::search_cmd(&remaining.collect::<Vec<_>>()),
        Some("sources") => lookup::sources_cmd(&remaining.collect::<Vec<_>>()),
        Some("domain-lifecycle") => meta::domain_lifecycle_cmd(&remaining.collect::<Vec<_>>()),
        Some("people") => lookup::people_cmd(&remaining.collect::<Vec<_>>()),
        Some("email") => lookup::email_cmd(&remaining.collect::<Vec<_>>()),
        Some("exposure") => lookup::exposure_cmd(&remaining.collect::<Vec<_>>()),
        Some("username") => lookup::username_cmd(&remaining.collect::<Vec<_>>()),
        Some("phone") => lookup::phone_cmd(&remaining.collect::<Vec<_>>()),
        Some("domain") => lookup::domain_cmd(&remaining.collect::<Vec<_>>()),
        Some("network") => lookup::network_cmd(&remaining.collect::<Vec<_>>()),
        Some("scan") => lookup::scan_cmd(&remaining.collect::<Vec<_>>()),
        Some("investigate") => lookup::investigate_cmd(&remaining.collect::<Vec<_>>()),
        Some("plan") => lookup::plan_cmd(&remaining.collect::<Vec<_>>()),
        Some("query") => lookup::query_cmd(&remaining.collect::<Vec<_>>()),
        Some("sf") => lookup::sf_cmd(&remaining.collect::<Vec<_>>()),
        Some("serve") => service::serve_cmd(&remaining.collect::<Vec<_>>()),
        Some("modules") => meta::modules_cmd(&remaining.collect::<Vec<_>>()),
        Some("attack") => meta::attack_cmd(&remaining.collect::<Vec<_>>()),
        Some("classify") => utility::classify(&remaining.collect::<Vec<_>>()),
        Some("fetch") => network::fetch_cmd(&remaining.collect::<Vec<_>>()),
        Some("hibp") => network::hibp_cmd(&remaining.collect::<Vec<_>>()),
        Some("dehashed") => network::dehashed_cmd(&remaining.collect::<Vec<_>>()),
        Some("recon") => network::recon_cmd(&remaining.collect::<Vec<_>>()),
        Some("seeknow") => network::seeknow_cmd(&remaining.collect::<Vec<_>>()),
        Some("keys") => meta::keys_cmd(&remaining.collect::<Vec<_>>()),
        Some("credential-status") => meta::credential_status_cmd(&remaining.collect::<Vec<_>>()),
        Some("verify") => meta::verify(&remaining.collect::<Vec<_>>()),
        Some("correlate") => meta::correlate_cmd(&remaining.collect::<Vec<_>>()),
        Some("run-history") => meta::run_history_cmd(&remaining.collect::<Vec<_>>()),
        Some("check") => selfcheck::check(&remaining.collect::<Vec<_>>()),
        Some(other) => help::unknown_command(other),
        None => help::no_command(),
    }
}
