//! Binary adapter commands. Business logic stays in the library crate.

use std::process::ExitCode;

use super::doctor::DOCTOR_HELP;
use super::{HELP, RECON_USAGE, USAGE, fail};
use huntsman_recon::dehashed::cli::DEHASHED_USAGE;
use huntsman_recon::email_cli::EMAIL_HELP;
use huntsman_recon::exit::EX_USAGE;
use huntsman_recon::exposure_cli::EXPOSURE_HELP;
use huntsman_recon::hibp::cli::HIBP_USAGE;
use huntsman_recon::people_cli::PEOPLE_HELP;
use huntsman_recon::phone_cli::PHONE_HELP;
use huntsman_recon::seeknow_cli::SEEKNOW_HELP;
use huntsman_recon::sf_compat::SF_USAGE;
use huntsman_recon::username_cli::USERNAME_HELP;

/// Usage error for a command word that the dispatcher does not know.
pub(super) fn unknown_command(other: &str) -> ExitCode {
    fail(EX_USAGE, &format!("unknown command: {other}\n{USAGE}"))
}

/// Usage error for no command at all: the help on stderr, and nothing written.
pub(super) fn no_command() -> ExitCode {
    fail(EX_USAGE, &format!("{HELP}\n{USAGE}"))
}

pub(super) fn print_command_help(command: &str) {
    let help = match command {
        "check" => {
            "check\nRun offline self-acceptance and regenerate var/ledger.json, var/navigator.json, and var/stix-bundle.json in the current directory, creating var/ if needed. Run it in an empty directory or a checkout."
        }
        "diagnostics" => {
            "diagnostics [--json]\nPrint offline build provenance, target/runtime context, reachable-module counts, ATT&CK-mapped collector counts, and provider credential completeness without values or network access."
        }
        "doctor" => DOCTOR_HELP,
        "fix" => {
            "fix [--json] [--probe] [--bind ADDR]\nThe same as doctor --fix: run every doctor check, make each repair that can be undone, then check again. It creates ~/.huntsman (mode 700) and an empty ~/.huntsman.env (mode 600) when they are missing, tightens loose permissions, re-runs the install acceptance before recording this binary as installed (the old record is kept as installed-revision.bak-TIME), and removes the Rust build cache only when Cargo tagged it and it is stale or the disk is nearly full. It never deletes a ledger or scan data and never writes or prints a key. Exit 0 when nothing fails afterwards, 78 when something still does."
        }
        "build-sha" => {
            "build-sha\nPrint the source commit embedded at build time, or unknown for builds without provenance metadata."
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
        "id" => {
            "id TOKEN...\nClassify and validate an Australian ABN, ACN, or BSB. The rest of the line is the token, so spaced digits need no quotes."
        }
        "search" => {
            "search QUERY [DIR]\nSearch built-in examples, or .txt/.md files in one directory. Every query term must occur; an email address or domain must occur whole. Short HTML challenge pages and unsafe or oversized inputs are skipped."
        }
        "sources" => {
            "sources QUERY...\nClassify an indicator and print curated public/browser search routes. The rest of the line is the query, so a name needs no quotes. Does not fetch those routes."
        }
        "domain-lifecycle" => huntsman_recon::domain_lifecycle::USAGE,
        "people" => PEOPLE_HELP,
        "email" => EMAIL_HELP,
        "exposure" => EXPOSURE_HELP,
        "username" => USERNAME_HELP,
        "phone" => PHONE_HELP,
        "domain" => {
            "domain DOMAIN [--save FILE]\nLook up one domain: certificate-transparency names from crt.sh and DNS records over DNS-over-HTTPS. --save writes an unverified ledger that verify can reload. Makes network requests."
        }
        "scan" => {
            "scan SELECTOR [-k people|email|exposure|username|phone|domain] [--save FILE] | scan --input-file FILE [-k people|email|exposure|username|phone|domain] [--save-dir DIR]\nRoute one selector or a bounded one-target-per-line file into rebuilt lookup front-ends; a domain routes to domain. Batch input trims lines, ignores blank/# comment lines, de-duplicates exact seeds, attempts every seed, and exits non-zero after the batch if any seed failed. --save is single-selector only; --save-dir DIR writes one ledger per batch seed, numbered by its position."
        }
        "investigate" => {
            "investigate TEXT... | investigate --file FILE\nExtract actionable entities from local text. --file refuses symlinks and files over 1 MiB."
        }
        "plan" => {
            "plan [--session-dir DIR] SEED [SEED ...] | plan --load-session DIR ID\nRun the offline investigation spine on one or more seeds: normalise them into entities and relations, analyse that one state, and plan the external routes without fetching them. --session-dir DIR saves the run as a session, and --load-session DIR ID prints a saved one. Offline."
        }
        "query" => {
            "query QUERY...\nQuery the rebuilt keyless Bing, Brave, and Mojeek subset through the shared fetch boundary; provider failures remain independent."
        }
        "sf" => SF_USAGE,
        "serve" => {
            "serve [--bind ADDR]\nStart the embedded Web UI and JSON API, including GET /api/lookup (needs the X-Huntsman-Lookup: 1 header) and GET /api/analyze?seeds=... (offline multi-hop analysis, one seed per line, no network request). Default: 127.0.0.1:8080. HSE_BIND supplies the default bind; an explicit non-loopback bind requires HSE_AUTH_TOKEN."
        }
        "modules" => {
            "modules [--json]\nList only rebuilt modules that are currently reachable through a huntsman-recon command."
        }
        "attack" => {
            "attack status|coverage|gaps [--json] | attack navigator\nRender current Reconnaissance capability coverage from the reachable module catalogue. Parent techniques are roll-ups, not extra scored capabilities."
        }
        "classify" => {
            "classify STATUS BODY...\nClassify an HTTP response as a result, challenge, or other outcome. The rest of the line is the body."
        }
        "fetch" => huntsman_recon::fetch_cli::FETCH_USAGE,
        "hibp" => HIBP_USAGE,
        "recon" => RECON_USAGE,
        "seeknow" => SEEKNOW_HELP,
        "run-history" => huntsman_recon::run_history::cli::USAGE,
        "dehashed" => DEHASHED_USAGE,
        "keys" => {
            "keys FILE\nCheck a keys file and print configured slot names and fingerprint prefixes, never secret values."
        }
        "credential-status" => {
            "credential-status [--probe] [FILE]\nShow provider slot completeness without printing credential values. --probe performs canonical live health checks for configured providers that have a registered probe. FILE uses the existing private keys-file loader; otherwise the normal ~/.huntsman.env/environment resolution is used."
        }
        "correlate" => {
            "correlate ARTIFACT [--history DIR]\nRead a scan artifact written by dehashed --save-artifact and print its entity and relation counts and each correlation rule that fires. With --history, also pivot it across every saved artifact in DIR: print cross_scan=none|historical|relation|transitive, one bridge line per entity this scan shares with an earlier scan, and one link line per scan reached through those entities. Offline."
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
