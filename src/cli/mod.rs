//! CLI composition and dispatch for `huntsman-recon`.
//!
//! This module is deliberately an adapter layer: it parses process arguments,
//! constructs transports/configuration, and delegates to the library. Domain
//! behavior belongs in `huntsman_recon`, not in the binary front controller.

use std::env;
use std::ffi::OsString;
use std::process::ExitCode;

const USAGE: &str = "usage: huntsman-recon [check | doctor [serve] [--fix] [--json] [--probe] [--bind ADDR] | fix [--json] [--probe] [--bind ADDR] | diagnostics [--json] | build-sha | command | directive check|sync [ROOT] | geo LAT,LON LAT,LON | geohash LAT,LON [PRECISION] | coarsen LAT,LON | id TOKEN... | search QUERY [DIR] | sources QUERY... | domain-lifecycle analyze INPUT --as-of TIME [--output FILE] | people NAME [--save FILE] | email ADDR [--save FILE] | exposure ADDR|HANDLE [--save FILE] | username HANDLE [--save FILE] | phone NUMBER [--save FILE] | domain DOMAIN [--save FILE] | ip ADDRESS [--save FILE] | netblock CIDR [--save FILE] | asn AS-NUMBER [--save FILE] | network BSSID|LAT,LON|ssid:NAME [--save FILE] | crypto BITCOIN-ADDRESS [--save FILE] | itunes KEYWORD | geocode PLACE|LAT,LON | exif IMAGE-FILE | radar wifi|cells [--json] [--file TERMUX_SCAN_JSON] | scan SELECTOR [-k people|email|exposure|username|phone|domain|ip|netblock|asn|network|crypto] [--save FILE] | scan --input-file FILE [-k people|email|exposure|username|phone|domain|ip|netblock|asn|network|crypto] [--save-dir DIR] | investigate TEXT...|--file FILE | plan [--session-dir DIR] SEED... | plan --load-session DIR ID | query [--adaptive] QUERY... | sf [-M|-T|-V]|-s TARGET [options] | scans run|list|show|summary|elements|correlations|log|export|fp|delete|rerun|types [ARGS] | serve [--bind ADDR] [--history DIR] | modules [--json] | attack SUBCOMMAND | classify STATUS BODY... | fetch URL [options] | hibp SUBCOMMAND | dehashed SUBCOMMAND | recon crtsh TARGET|dns TARGET|stolen-tax QUERY [--keys FILE] | seeknow SUBCOMMAND | keys FILE|set SLOT --stdin|remove SLOT | credential-status [--probe] [FILE] | verify LEDGER | correlate ARTIFACT [--history DIR] | run-history record|show [options]]";
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
  exposure              Keyed breach evidence for an email (HIBP account, stolen.tax, OathNet)
  username              Enrich a username through public GitHub and Bluesky profiles
  phone                 Canonicalise and classify a phone number offline, plus a keyed carrier lookup
  domain                Certificate-transparency names and DNS records for one domain, plus keyed reputation and published addresses
  ip                    Open ports, routing, scanner status and keyed reputation for one public IP address
  netblock              Registration, routing and every address's PTR names for one public address block
  asn                   Registration, holder, every announced prefix and BGP neighbour of one public AS
  network               WiFi network by BSSID, SSID or LAT,LON (OUI offline, WiGLE keyed)
  crypto                On-chain balance and lifetime totals for one Bitcoin address (keyless, blockchain.info)
  itunes                Search the Apple App Store for one keyword (keyless, iTunes Search API)
  geocode               Geocode a place, address or lat,lon point (keyless, OpenStreetMap Nominatim)
  exif                  Extract EXIF metadata and GPS coordinates from a local image (keyless, offline)
  radar                 Read rootless Termux:API OS-cached WiFi and cellular observations
  scan                  Route one selector or bounded seed-list into rebuilt lookup front-ends
  investigate           Extract actionable entities from local text or one bounded file
  plan                  Plan an offline investigation from seeds; save or reload it as a session
  query                 Keyless web search; --adaptive adds bounded URL attribution
  sf                    SpiderFoot-compatible sf.py front end over saved scans
  scans                 Run, list, read, export, flag, rerun and delete saved Spiderfoot-style scans
  serve                 Start the embedded Web UI and JSON API
  modules               List only currently reachable rebuilt modules
  attack                MITRE ATT&CK Reconnaissance posture, coverage, gaps, or Navigator JSON
  classify              Classify an HTTP status and response body
  fetch                 Make a guarded HTTP request (network access)
  hibp                  Have I Been Pwned lookups (opt-in; keyed subcommands need a key)
  dehashed              DeHashed exact-match search (opt-in; needs a key and --purpose)
  recon                 One crt.sh, DNS/mail, or stolen.tax lookup (network access)
  seeknow               SeekNow/See-Know lookup (opt-in; needs HUNTSMAN_SEEKNOW_KEY)
  keys                  Inspect a private keys file, or set/remove a slot via private storage
  credential-status     Show provider credential completeness without values
  verify                Verify a saved evidence ledger
  correlate             Run the correlation rules over a saved scan artifact, and pivot it across a history of saved scans (offline)
  run-history           Record test-run results and compare each with the earlier runs

Run `huntsman-recon <COMMAND> --help` for command details.
Search and sources do not collect remote results. `fetch`, `hibp`, `recon`,
`seeknow`, `people`, `email`, `exposure`, `username`, `domain`, `network`, `crypto`, `query`, `dehashed`, networked `sf -s` lookups and `scans run` make HTTP requests; `serve` accepts inbound HTTP connections; their default
egress policy is public-only.";
/// The largest plain file a command reads or writes: a seed list, or a self-check scratch file.
/// A saved artifact has its own ceiling, `scan_artifact::MAX_ARTIFACT_BYTES`.
const MAX_PLAIN_FILE_BYTES: u64 = 1_048_576;
mod continuous;
mod credentials;
mod doctor;
mod help;
mod lookup;
mod meta;
mod network;
mod radar;
mod report;
mod scans;
mod selfcheck;
mod service;
mod utility;

use report::{exit_on_output_failure, fail};

/// Runs the command named by the process arguments (without the program name).
pub(crate) fn run(args: Vec<OsString>) -> ExitCode {
    exit_on_output_failure();
    let mut words = Vec::with_capacity(args.len());
    for (index, arg) in args.into_iter().enumerate() {
        match arg.into_string() {
            Ok(arg) => words.push(arg),
            Err(raw) => return help::argument_not_utf8(index + 1, raw.len()),
        }
    }
    let first = words.first().map(String::as_str);
    if matches!(first, Some("help" | "-h" | "--help")) {
        println!("{HELP}\n{USAGE}");
        return ExitCode::SUCCESS;
    }
    if matches!(first, Some("-V" | "--version")) {
        println!("huntsman-recon {}", env!("CARGO_PKG_VERSION"));
        return ExitCode::SUCCESS;
    }
    if words.len() == 2 && matches!(words[1].as_str(), "-h" | "--help") {
        // A word that is not a command gets the usage error, not the general help: a typo
        // answered with help and exit 0 hides itself.
        return match help::command_help(&words[0]) {
            Some(text) => {
                println!("{text}\n  -h, --help  Show this help");
                ExitCode::SUCCESS
            }
            None => help::unknown_command(&words[0]),
        };
    }
    let mut remaining = words.into_iter();
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
        Some("ip") => lookup::ip_cmd(&remaining.collect::<Vec<_>>()),
        Some("netblock") => lookup::netblock_cmd(&remaining.collect::<Vec<_>>()),
        Some("asn") => lookup::asn_cmd(&remaining.collect::<Vec<_>>()),
        Some("network") => lookup::network_cmd(&remaining.collect::<Vec<_>>()),
        Some("crypto") => lookup::crypto_cmd(&remaining.collect::<Vec<_>>()),
        Some("itunes") => lookup::itunes_cmd(&remaining.collect::<Vec<_>>()),
        Some("geocode") => lookup::geocode_cmd(&remaining.collect::<Vec<_>>()),
        Some("exif") => lookup::exif_cmd(&remaining.collect::<Vec<_>>()),
        Some("radar") => radar::radar_cmd(&remaining.collect::<Vec<_>>()),
        Some("scan") => lookup::scan_cmd(&remaining.collect::<Vec<_>>()),
        Some("investigate") => lookup::investigate_cmd(&remaining.collect::<Vec<_>>()),
        Some("plan") => lookup::plan_cmd(&remaining.collect::<Vec<_>>()),
        Some("query") => lookup::query_cmd(&remaining.collect::<Vec<_>>()),
        Some("sf") => lookup::sf_cmd(&remaining.collect::<Vec<_>>()),
        Some("scans") => scans::scans_cmd(&remaining.collect::<Vec<_>>()),
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
