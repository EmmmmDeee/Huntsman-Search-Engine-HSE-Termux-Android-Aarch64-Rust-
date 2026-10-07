//! Binary adapter commands. Business logic stays in the library crate.

#[allow(clippy::wildcard_imports)]
use super::*;

fn termux_detected() -> bool {
    env::var_os("TERMUX_VERSION").is_some()
        || env::var_os("PREFIX").is_some_and(|value| {
            value
                .to_string_lossy()
                .contains("/data/data/com.termux/files/usr")
        })
}

fn diagnostics_snapshot() -> diagnostics::Diagnostics {
    let home = env::var_os("HOME");
    match Keys::resolve(None, home.as_deref()) {
        Ok(resolved) => {
            let resolution = if resolved.warning.is_some() {
                CredentialResolution::Warning
            } else {
                CredentialResolution::Ok
            };
            diagnostics::snapshot(Some(&resolved.keys), resolution, termux_detected())
        }
        Err(_) => diagnostics::snapshot(None, CredentialResolution::Error, termux_detected()),
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
        match serde_json::to_string_pretty(&report) {
            Ok(body) => println!("{body}"),
            Err(error) => return fail(EX_DATAERR, &format!("json: {error}")),
        }
    } else {
        println!("version={}", report.version);
        println!("build_sha={}", report.build_sha);
        println!("build_sha_known={}", report.build_sha_known);
        println!("target_os={}", report.target_os);
        println!("target_arch={}", report.target_arch);
        println!("android_target={}", report.android_target);
        println!("termux_detected={}", report.termux_detected);
        println!("reachable_modules={}", report.reachable_modules);
        println!("network_modules={}", report.network_modules);
        println!("attack_mapped_modules={}", report.attack_mapped_modules);
        println!("providers_total={}", report.providers_total);
        println!("providers_configured={}", report.providers_configured);
        println!(
            "credential_resolution={}",
            report.credential_resolution.as_str()
        );
        println!("credential_warning={}", report.credential_warning);
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

pub(super) fn keys_cmd(path: Option<String>) -> ExitCode {
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

pub(super) fn verify(path: Option<String>) -> ExitCode {
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
