//! Binary adapter commands. Business logic stays in the library crate.

use super::{HELP, RECON_USAGE, USAGE};
use huntsman_recon::email_cli::EMAIL_HELP;
use huntsman_recon::hibp::cli::HIBP_USAGE;
use huntsman_recon::people_cli::PEOPLE_HELP;
use huntsman_recon::phone_cli::PHONE_HELP;
use huntsman_recon::seeknow_cli::SEEKNOW_HELP;
use huntsman_recon::sf_compat::SF_USAGE;
use huntsman_recon::username_cli::USERNAME_HELP;

pub(super) fn print_command_help(command: &str) {
    let help = match command {
        "check" => {
            "check\nRun offline self-acceptance and regenerate var/ledger.json, var/navigator.json, and var/stix-bundle.json."
        }
        "diagnostics" => {
            "diagnostics [--json]\nPrint offline build provenance, target/runtime context, reachable-module counts, ATT&CK-mapped collector counts, and provider credential completeness without values or network access."
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
        "attack" => {
            "attack status|coverage|gaps [--json] | attack navigator\nRender current Reconnaissance capability coverage from the reachable module catalogue. Parent techniques are roll-ups, not extra scored capabilities."
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
