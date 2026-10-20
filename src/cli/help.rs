//! Binary adapter commands. Business logic stays in the library crate.

use std::process::ExitCode;

use super::doctor::DOCTOR_HELP;
use super::scans::SCANS_HELP;
use super::{HELP, RECON_USAGE, USAGE, fail};
use huntsman_recon::dehashed::cli::DEHASHED_USAGE;
use huntsman_recon::email_cli::EMAIL_HELP;
use huntsman_recon::exit::EX_USAGE;
use huntsman_recon::exposure_cli::EXPOSURE_HELP;
use huntsman_recon::hibp::cli::HIBP_USAGE;
use huntsman_recon::network_cli::NETWORK_HELP;
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

/// Usage error for an argument that is not UTF-8. The bytes are not echoed: an argument can
/// be a selector, and the CLI never prints one back.
pub(super) fn argument_not_utf8(position: usize, bytes: usize) -> ExitCode {
    fail(
        EX_USAGE,
        &format!(
            "argument {position} is not valid UTF-8 ({bytes} bytes); arguments must be UTF-8 text\n{USAGE}"
        ),
    )
}

/// Separate the sensor help from the command dispatcher to keep it bounded.
fn radar_help() -> &'static str {
    "radar wifi|cell [--json] [--file TERMUX_SCAN_JSON]\nRead Android OS-cached nearby WiFi results through termux-wifi-scaninfo with no root. This does NOT trigger an active scan. Each accepted individual BSSID includes SSID, RSSI, band and cache age when /proc/uptime permits; zero, group/broadcast and Android-redacted placeholder BSSIDs are counted as rejected; age over five minutes is labelled stale. No GPS position or UTC sighting timestamp is inferred. A missing Termux:API installation, disabled location services or an empty OS cache is not evidence that there are no networks. --file replays a supplied Termux-format JSON file without querying hardware and without estimating age from the current host's boot clock; imported file source and freshness are unverified. --json returns structured results.\nradar cell [--json] [--file TERMUX_CELL_JSON]\nRootless termux-telephony-cellinfo acquisition using Android cached GSM/LTE/NR/WCDMA/CDMA cell identities, registered status and available dBm. Empty/permission-limited results are inconclusive, no observation timestamp or handset/tower coordinates are invented. --file replays unverified JSON without querying the phone. No provider key or active radio sweep is needed."
}

/// The help text of a dispatched command, or `None` for a word that is not one.
pub(super) fn command_help(command: &str) -> Option<&'static str> {
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
        "network" => NETWORK_HELP,
        "radar" => radar_help(),
        "domain" => {
            "domain DOMAIN [--save FILE]\nLook up one domain: certificate-transparency names from crt.sh, every certificate Cert Spotter logged for the domain and its subdomains in full (subject, serial, issuer, validity, revocation, names and the PEM; HUNTSMAN_CERTSPOTTER_KEY raises its limit), DNS records over DNS-over-HTTPS, the Spamhaus DBL and SURBL domain blocklists over the system resolver, and whether the filtering resolvers Spiderfoot asks (AdGuard, CleanBrowsing, Cloudflare, Comodo, DNS for Family, OpenDNS, Quad9, Yandex) block it, each after a name it is known to block (DNS-over-HTTPS, or UDP to the filter's own servers for Comodo, Quad9, DNS for Family and Yandex). The domain and every host and address the lookup found are checked against the threat feeds Spiderfoot downloads (abuse.ch Feodo Tracker and URLhaus, AlienVault IP Reputation, blocklist.de, botvrij.eu, CINS Army, CoinBlocker, CyberCrime-Tracker, Emerging Threats, GreenSnow, OpenPhish, PhishTank, Steven Black's hosts, Tor's exit relays, VoIPBL and VXVault), each downloaded once and kept in $HUNTSMAN_HOME/feeds, else ~/.huntsman/feeds, until it is older than Spiderfoot keeps it. Pulsedive threat risk, Netlas scan data, AlienVault OTX threat pulses, urlscan.io public page scans, Robtex passive DNS and HackerTarget hosts under the domain are asked without a key (HUNTSMAN_PULSEDIVE_KEY, HUNTSMAN_NETLAS_KEY, HUNTSMAN_OTX_KEY, HUNTSMAN_URLSCAN_KEY and HUNTSMAN_HACKERTARGET_KEY raise their limits). With HUNTSMAN_VIRUSTOTAL_KEY set it adds VirusTotal engine verdicts, with HUNTSMAN_HUNTER_KEY the addresses Hunter.io found published for the domain, with HUNTSMAN_SHODAN_KEY Shodan DNS records (one query credit), with HUNTSMAN_LEAKIX_KEY LeakIX exposed services and leaks, with HUNTSMAN_THREATFOX_KEY ThreatFox IOCs, with HUNTSMAN_ABUSECH_KEY URLhaus malware URLs, with HUNTSMAN_SECTRAILS_KEY SecurityTrails subdomains, and with HUNTSMAN_WHOXY_KEY the live WHOIS record (one Whoxy credit); a leg whose key is not set makes no request, and a key that is set always runs its leg. --save writes an unverified ledger that verify can reload. Makes network requests."
        }
        "ip" => huntsman_recon::ip_cli::IP_HELP,
        "netblock" => huntsman_recon::netblock_cli::NETBLOCK_HELP,
        "asn" => huntsman_recon::asn_cli::ASN_HELP,
        "scan" => {
            "scan SELECTOR [-k people|email|exposure|username|phone|domain|ip|netblock|asn|network] [--save FILE] | scan --input-file FILE [-k people|email|exposure|username|phone|domain|ip|netblock|asn|network] [--save-dir DIR] | scan --recurse SELECTOR [SELECTOR ...] [--max-generations N] [--expand-floor F] [--json]\nRoute one selector or a bounded one-target-per-line file into rebuilt lookup front-ends; a domain routes to domain, and a BSSID or LAT,LON to network. Batch input trims lines, ignores blank/# comment lines, de-duplicates exact seeds, attempts every seed, and exits non-zero after the batch if any seed failed. --save is single-selector only; --save-dir DIR writes one ledger per batch seed, numbered by its position. --recurse runs a bounded fetch-expand-fetch crawl: each lookup's pivotable findings (e-mail, username, domain, phone, plus a public IP or BSSID) become the next generation's seeds, de-duplicated and capped by the shared limits (default up to 4 hops beyond the seeds, expansion confidence floor 0.5), and it prints the full linkage with the pivot lineage (which lookup found each finding), the correlation findings, by-kind element/relation summary, capability gaps, and graph-pivot ranking the shared analysis engine derives across everything reached, every source outcome, and the termination reason; --json prints that same result as one JSON object instead of the text report. Makes network requests."
        }
        "investigate" => {
            "investigate TEXT... | investigate --file FILE\nExtract actionable entities from local text. --file refuses symlinks and files over 1 MiB."
        }
        "plan" => {
            "plan [--session-dir DIR] SEED [SEED ...] | plan --load-session DIR ID\nRun the offline investigation spine on one or more seeds: normalise them into entities and relations, analyse that one state, and plan the external routes without fetching them. --session-dir DIR saves the run as a session, and --load-session DIR ID prints a saved one. Offline."
        }
        "query" => {
            "query QUERY...\nOptional: query --adaptive QUERY... . Query the rebuilt keyless Bing, Brave, and Mojeek subset. --adaptive emits JSON with up to 3 feedback-directed query rounds, URL attribution by engine, typed outcomes and explicit limits (up to 9 engine executions, 18 HTTP attempts with retries)."
        }
        "sf" => SF_USAGE,
        "scans" => SCANS_HELP,
        "serve" => {
            "serve [--bind ADDR] [--history DIR]\nStart the embedded Web UI and JSON API, including GET /api/lookup (needs the X-Huntsman-Lookup: 1 header; each lookup is kept as a saved scan, listed under Scans and in scans list, and a request waits at most 150 seconds, then answers 504 with the scan, which runs on) and GET /api/analyze?seeds=... (offline multi-hop analysis, one seed per line, no network request). With --history DIR, each analysis also bridges its seeds to the saved scan artifacts in DIR, as correlate --history does, and reports the bridges as cross_scan; a directory that cannot be read, or holds a malformed artifact, stops serve at startup. Default: 127.0.0.1:8080. HSE_BIND supplies the default bind. A loopback bind needs no token; an explicit non-loopback bind requires HSE_AUTH_TOKEN."
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
            "keys FILE | keys set SLOT --stdin | keys remove SLOT\nCheck a private keys file without printing secret values, or atomically store/remove one slot in ~/.huntsman.env. New values must arrive through piped standard input, not argv or an interactive terminal."
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
        _ => return None,
    };
    Some(help)
}
