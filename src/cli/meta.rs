//! Binary adapter commands. Business logic stays in the library crate.

use std::env;
use std::io::{IsTerminal, Read as _};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use super::{fail, terminal_json_pretty};
use huntsman_recon::attack_cli::{ATTACK_USAGE, render as render_attack};
use huntsman_recon::clock;
use huntsman_recon::diagnostics::{self, CredentialResolution, TermuxState};
use huntsman_recon::directive_lock;
use huntsman_recon::engineering_command;
use huntsman_recon::error::Error;
use huntsman_recon::exit::{EX_DATAERR, EX_IOERR, EX_NOINPUT, EX_USAGE};
use huntsman_recon::fsio::{read_bounded, write_atomic};
use huntsman_recon::http::{TransportConfig, UreqTransport};
use huntsman_recon::keys::{self, Keys, MAX_KEY_BYTES};
use huntsman_recon::ledger::{admitted, load_chain};
use huntsman_recon::module::reachable_modules;
use huntsman_recon::provider_credentials;

fn diagnostics_snapshot() -> diagnostics::Diagnostics {
    let home = env::var_os("HOME");
    match Keys::resolve(None, home.as_deref()) {
        Ok(resolved) => {
            let resolution = if resolved.warning.is_some() {
                CredentialResolution::Warning
            } else {
                CredentialResolution::Ok
            };
            diagnostics::snapshot(Some(&resolved.keys), resolution, TermuxState::current())
        }
        Err(_) => diagnostics::snapshot(None, CredentialResolution::Error, TermuxState::current()),
    }
}

pub(super) fn diagnostics_cmd(args: &[String]) -> ExitCode {
    let json = match args {
        [] => false,
        [flag] if flag == "--json" => true,
        _ => return fail(EX_USAGE, "usage: huntsman-recon diagnostics [--json]"),
    };
    let report = diagnostics_snapshot();
    if json {
        match terminal_json_pretty(&report) {
            Ok(body) => println!("{body}"),
            Err(error) => return fail(EX_DATAERR, &format!("json: {error}")),
        }
    } else {
        println!("version={}", report.version);
        println!("build_sha={}", report.build_sha);
        println!("target_os={}", report.target_os);
        println!("target_arch={}", report.target_arch);
        println!("termux={}", report.termux.as_str());
        println!("reachable_modules={}", report.reachable_modules);
        println!("network_modules={}", report.network_modules);
        println!("attack_mapped_modules={}", report.attack_mapped_modules);
        println!("providers_total={}", report.providers_total);
        println!("providers_configured={}", report.providers_configured);
        println!(
            "credential_resolution={}",
            report.credential_resolution.as_str()
        );
        println!("selfcheck_command={}", report.selfcheck_command);
    }
    ExitCode::SUCCESS
}

pub(super) fn build_sha_cmd(args: &[String]) -> ExitCode {
    if !args.is_empty() {
        return fail(EX_USAGE, "usage: huntsman-recon build-sha");
    }
    println!("{}", diagnostics::embedded_build_sha());
    ExitCode::SUCCESS
}

pub(super) fn credential_status_cmd(args: &[String]) -> ExitCode {
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

pub(super) fn command_cmd(args: &[String]) -> ExitCode {
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

pub(super) fn directive_cmd(args: &[String]) -> ExitCode {
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

pub(super) fn domain_lifecycle_cmd(args: &[String]) -> ExitCode {
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

pub(super) fn attack_cmd(args: &[String]) -> ExitCode {
    match render_attack(args) {
        Ok(body) => {
            print!("{body}");
            ExitCode::SUCCESS
        }
        Err(message) if message == ATTACK_USAGE => fail(EX_USAGE, &message),
        Err(message) => fail(EX_DATAERR, &message),
    }
}

pub(super) fn modules_cmd(args: &[String]) -> ExitCode {
    let json = match args {
        [] => false,
        [flag] if flag == "--json" => true,
        _ => return fail(EX_USAGE, "usage: huntsman-recon modules [--json]"),
    };
    let modules = reachable_modules();
    if json {
        match terminal_json_pretty(&serde_json::json!({
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

const KEYS_USAGE: &str =
    "usage: huntsman-recon keys FILE | keys set SLOT --stdin | keys remove SLOT";

/// Store a credential received only through non-terminal standard input. Never accept
/// credential values in argv (shell history/process listings), and never print them.
fn keys_set_stdin(slot: &str) -> ExitCode {
    if !keys::valid_slot(slot) {
        return fail(
            EX_USAGE,
            "invalid key slot name (use uppercase letters, digits and '_')",
        );
    }
    let stdin = std::io::stdin();
    if stdin.is_terminal() {
        return fail(
            EX_USAGE,
            "pipe a credential to standard input; terminal entry is refused",
        );
    }
    // One terminal newline is allowed after a max-length credential; an excess byte
    // makes the operation fail rather than silently truncating the secret.
    let mut bytes = Vec::new();
    if let Err(error) = stdin
        .lock()
        .take(MAX_KEY_BYTES as u64 + 2)
        .read_to_end(&mut bytes)
    {
        return fail(
            EX_IOERR,
            &format!("cannot read credential from stdin: {error}"),
        );
    }
    if bytes.last() == Some(&b'\n') {
        bytes.pop();
        if bytes.last() == Some(&b'\r') {
            bytes.pop();
        }
    }
    if bytes.len() > MAX_KEY_BYTES {
        return fail(EX_DATAERR, "credential exceeds the configured byte limit");
    }
    let Ok(value) = std::str::from_utf8(&bytes) else {
        return fail(EX_DATAERR, "credential input must be UTF-8");
    };
    keys_change(slot, Some(value))
}

fn keys_change(slot: &str, value: Option<&str>) -> ExitCode {
    if !keys::valid_slot(slot) {
        return fail(
            EX_USAGE,
            "invalid key slot name (use uppercase letters, digits and '_')",
        );
    }
    let Some(path) = keys::default_keys_path(env::var_os("HOME").as_deref()) else {
        return fail(
            EX_USAGE,
            "HOME must be an absolute path to manage credentials",
        );
    };
    match keys::store_slot(&path, slot, value) {
        Ok(()) => {
            println!(
                "{slot} {}",
                if value.is_some() { "stored" } else { "removed" }
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            let status = if matches!(error, Error::Invalid(_)) {
                EX_DATAERR
            } else {
                EX_IOERR
            };
            fail(status, &error.to_string())
        }
    }
}

pub(super) fn keys_cmd(args: &[String]) -> ExitCode {
    match args {
        [command, slot, flag] if command == "set" && flag == "--stdin" => keys_set_stdin(slot),
        [command, slot] if command == "remove" => keys_change(slot, None),
        [file] if file != "set" && file != "remove" => match Keys::load(Path::new(file)) {
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
            Err(error) => fail(EX_NOINPUT, &error.to_string()),
        },
        _ => fail(EX_USAGE, KEYS_USAGE),
    }
}

/// A ledger that cannot be read (missing file, IO, size, symlink refusal) is unreadable input
/// (66); a ledger that is read but malformed or whose chain is broken is bad data (65). This
/// matches the README exit-code contract and the other file-reading commands.
fn ledger_error_code(error: &Error) -> u8 {
    match error {
        Error::Store(_) => EX_NOINPUT,
        _ => EX_DATAERR,
    }
}

pub(super) fn verify(args: &[String]) -> ExitCode {
    let [path] = args else {
        return fail(EX_USAGE, "usage: huntsman-recon verify LEDGER");
    };
    match load_chain(Path::new(path)) {
        Ok(entries) => {
            println!("entries={}", entries.len());
            println!("admitted={}", admitted(&entries).len());
            println!("tip={}", entries.last().map_or("none", |e| e.hash.as_str()));
            ExitCode::SUCCESS
        }
        Err(e) => fail(ledger_error_code(&e), &e.to_string()),
    }
}

pub(super) fn run_history_cmd(args: &[String]) -> ExitCode {
    use std::io::Read;
    // Bound the --from-stdin read: every other external input in the crate is
    // capped, and an unbounded read of a huge or endless producer would OOM on
    // the memory-constrained Termux target. 16 MiB holds any real test log.
    const MAX_STDIN_BYTES: u64 = 16 * 1024 * 1024;
    let now_unix = clock::unix_now();

    // `--from-stdin` reads libtest output on stdin and injects the real
    // passed/failed counts, so a persistent host can pipe `cargo test` straight
    // into the regression store. The flag is resolved here, in the binary-only
    // wrapper, because it is the only part that touches the process's stdin;
    // the parser and the record logic it feeds are both unit-tested.
    if args.first().map(String::as_str) == Some("record")
        && args.iter().any(|a| a == "--from-stdin")
    {
        // --from-stdin supplies the counts; explicit --passed/--failed would be
        // silently overridden, so reject the combination instead.
        if args.iter().any(|a| a == "--passed" || a == "--failed") {
            eprintln!("run-history: --from-stdin cannot be combined with --passed/--failed");
            return ExitCode::from(EX_USAGE);
        }
        let mut buffer = String::new();
        if std::io::stdin()
            .lock()
            .take(MAX_STDIN_BYTES + 1)
            .read_to_string(&mut buffer)
            .is_err()
        {
            eprintln!("run-history: could not read test output from stdin");
            return ExitCode::from(EX_IOERR);
        }
        if buffer.len() as u64 > MAX_STDIN_BYTES {
            eprintln!("run-history: test output on stdin exceeds 16 MiB");
            return ExitCode::from(EX_IOERR);
        }
        let Some((passed, failed)) = huntsman_recon::run_history::parse_libtest_summary(&buffer)
        else {
            eprintln!("run-history: no 'test result:' line found in stdin");
            return ExitCode::from(EX_DATAERR);
        };
        let mut rewritten: Vec<String> = args
            .iter()
            .filter(|a| a.as_str() != "--from-stdin")
            .cloned()
            .collect();
        rewritten.push("--passed".to_owned());
        rewritten.push(passed.to_string());
        rewritten.push("--failed".to_owned());
        rewritten.push(failed.to_string());
        return ExitCode::from(huntsman_recon::run_history::cli::run(
            &rewritten,
            now_unix,
            &mut std::io::stdout().lock(),
            &mut std::io::stderr().lock(),
        ));
    }

    ExitCode::from(huntsman_recon::run_history::cli::run(
        args,
        now_unix,
        &mut std::io::stdout().lock(),
        &mut std::io::stderr().lock(),
    ))
}

pub(super) fn correlate_cmd(args: &[String]) -> ExitCode {
    const USAGE: &str = "usage: huntsman-recon correlate ARTIFACT [--history DIR]";
    let (path, history_dir) = match args {
        [path] => (path, None),
        [path, flag, dir] if flag == "--history" => (path, Some(dir)),
        _ => return fail(EX_USAGE, USAGE),
    };
    let artifact = match huntsman_recon::scan_artifact::read(Path::new(path)) {
        Ok(artifact) => artifact,
        Err(e) => return artifact_fail(&e),
    };
    // Load the history before printing anything, so a bad history fails the
    // command without a half-written report on stdout.
    let history = match history_dir {
        Some(dir) => match huntsman_recon::scan_artifact::ArtifactHistory::open(Path::new(dir)) {
            Ok(history) => Some(history),
            Err(e) => return artifact_fail(&e),
        },
        None => None,
    };
    println!(
        "scan_id={} entities={} relations={}",
        huntsman_recon::textnorm::escape_controls(&artifact.scan_id),
        artifact.entities.len(),
        artifact.relations.len()
    );
    let correlations = artifact.correlate();
    println!("correlations={}", correlations.len());
    for c in &correlations {
        println!(
            "rule={} severity={:?} entities={}",
            c.rule_id,
            c.severity,
            c.entity_uids.len()
        );
    }
    if let Some(history) = history {
        match artifact.cross_scan(
            &history,
            huntsman_recon::cross_scan::CrossScanOptions::default(),
        ) {
            Ok(category) => print_cross_scan(history.scan_count(), &category),
            Err(e) => return fail(EX_DATAERR, &format!("correlate: {e}")),
        }
    }
    ExitCode::SUCCESS
}

fn print_cross_scan(
    history_scans: usize,
    category: &huntsman_recon::cross_scan::CrossScanCategory,
) {
    use huntsman_recon::cross_scan::CrossScanCategory;
    use huntsman_recon::textnorm::escape_controls;
    let (label, bridges, links) = match category {
        CrossScanCategory::None => ("none", &[][..], &[][..]),
        CrossScanCategory::Historical { matches } => ("historical", &matches[..], &[][..]),
        CrossScanCategory::Relation { matches } => ("relation", &matches[..], &[][..]),
        CrossScanCategory::Transitive { links } => ("transitive", &[][..], &links[..]),
    };
    println!("history_scans={history_scans} cross_scan={label}");
    for bridge in bridges {
        println!(
            "bridge tier={:?} kind={} uid={} scans={}",
            bridge.tier,
            bridge.entity.kind,
            escape_controls(&bridge.entity.uid),
            escape_controls(&bridge.overlapping_scans.join(","))
        );
    }
    for link in links {
        println!(
            "link depth={} tier={:?} via={} scan={}",
            link.depth,
            link.tier,
            escape_controls(&link.via_entity_uid),
            escape_controls(&link.target_scan_id)
        );
    }
}

fn artifact_fail(e: &huntsman_recon::scan_artifact::ArtifactError) -> ExitCode {
    use huntsman_recon::scan_artifact::ArtifactError;
    // Match the crate's exit-code contract (see ledger_error_code):
    // unreadable input (missing file, IO, a directory) is 66; a file
    // that is read but does not parse or has the wrong version is 65.
    let code = match e {
        ArtifactError::Io(_) => EX_NOINPUT,
        ArtifactError::Malformed(_)
        | ArtifactError::UnsupportedVersion { .. }
        | ArtifactError::Unsupported(_) => EX_DATAERR,
    };
    fail(code, &format!("correlate: {e}"))
}
