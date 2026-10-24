//! `doctor`, `doctor serve` and `fix`: the process boundary for `huntsman_recon::doctor`.
//!
//! This adapter reads the environment, runs the other programs a check needs (`df`, `rustc`, this
//! binary's own `check` and `verify`), probes `serve`, and prints. The checks and repairs
//! themselves live in the library.

use std::env;
use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::time::Duration;

use super::fail;
use huntsman_recon::clock;
use huntsman_recon::diagnostics::{self, TermuxState};
use huntsman_recon::doctor::{self, Context, Host, KeyState, Status};
use huntsman_recon::environment::{
    self, HUNTSMAN_ENV_FILE_ENV, HUNTSMAN_HOME_ENV, SERVE_BIND_ENV, SERVE_TOKEN_ENV,
};
use huntsman_recon::exit::{EX_CONFIG, EX_DATAERR, EX_UNAVAILABLE, EX_USAGE};
use huntsman_recon::http::{TransportConfig, UreqTransport};
use huntsman_recon::keys::Keys;
use huntsman_recon::provider_credentials;
use huntsman_recon::serve_probe::{self, AddrSource, ServeProbe, ServeState};
use huntsman_recon::web_server::DEFAULT_BIND;

pub(super) const DOCTOR_HELP: &str = "doctor [serve] [--fix] [--json] [--probe] [--bind ADDR]
Check everything that decides whether Huntsman works here, and print the exact command that fixes each problem. Checks: binary (huntsman-recon on PATH and which build it is), build_sha, provenance (~/.huntsman/installed-revision matches this binary), state_dir, env_file (~/.huntsman.env exists, is yours, mode 600 and parses; never its values), keys (which providers have a key), ledgers (every ledger in ~/.huntsman and ./var verifies), selfcheck (the install acceptance: check and verify in a fresh directory), serve (a running server answers as Huntsman, its page's policy matches its script, and its offline analysis works; port held by another program), disk, build_cache (Cargo cache size, and stale when rustc changed), termux (PREFIX, PATH, TMPDIR).
  --fix        make every repair that can be undone, then check again (same as `fix`)
  --probe      also test each configured key against its provider; this spends quota
  --json       print the report as JSON
  --bind ADDR  the serve address to probe (default HSE_BIND, else the address huntsman start recorded in ~/.huntsman/serve.bind, else 127.0.0.1:8080)
doctor serve probes only the server: it prints serve=healthy|not_running|foreign|unauthorized|degraded and exits 0 only when healthy, 69 otherwise.
Exit 0 when no check fails (warnings allowed), 78 when one does.";

const PROBE_TIMEOUT: Duration = Duration::from_secs(3);

/// What one run does: report, repair then report, or probe only the server.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Report,
    Fix,
    ServeOnly,
}

struct Options {
    mode: Mode,
    json: bool,
    probe: bool,
    bind: Option<String>,
}

fn usage_error() -> ExitCode {
    fail(
        EX_USAGE,
        "usage: huntsman-recon doctor [serve] [--fix] [--json] [--probe] [--bind ADDR]",
    )
}

fn parse(args: &[String], fix: bool) -> Option<Options> {
    let mut options = Options {
        mode: if fix { Mode::Fix } else { Mode::Report },
        json: false,
        probe: false,
        bind: None,
    };
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "serve" if index == 0 && options.mode == Mode::Report => {
                options.mode = Mode::ServeOnly;
            }
            "--fix" if options.mode == Mode::Report => options.mode = Mode::Fix,
            "--json" if !options.json => options.json = true,
            "--probe" if !options.probe => options.probe = true,
            "--bind" if options.bind.is_none() => {
                index += 1;
                options.bind = Some(args.get(index)?.clone());
            }
            _ => return None,
        }
        index += 1;
    }
    if options.mode == Mode::ServeOnly && options.probe {
        return None;
    }
    Some(options)
}

pub(super) fn doctor_cmd(args: &[String]) -> ExitCode {
    match parse(args, false) {
        Some(options) => run(&options),
        None => usage_error(),
    }
}

pub(super) fn fix_cmd(args: &[String]) -> ExitCode {
    match parse(args, true) {
        Some(options) => run(&options),
        None => fail(
            EX_USAGE,
            "usage: huntsman-recon fix [--json] [--probe] [--bind ADDR]",
        ),
    }
}

/// The serve address and where it came from: `--bind`, else `HSE_BIND`, else the address
/// `huntsman start` recorded in the state directory, else the default. A wildcard bind is probed
/// on loopback, where the server also listens. The error names the setting that is not
/// `HOST:PORT`.
fn serve_addr(bind: Option<&str>, place: &Place) -> Result<(SocketAddr, AddrSource), String> {
    let (text, source) = serve_bind(bind, place);
    let text = text.trim();
    let text = text
        .strip_prefix("localhost:")
        .map_or_else(|| text.to_owned(), |port| format!("127.0.0.1:{port}"));
    let Ok(mut addr) = text.parse::<SocketAddr>() else {
        return Err(match &source {
            AddrSource::Flag => format!("doctor --bind needs HOST:PORT, not {text:?}"),
            AddrSource::Env => format!("{SERVE_BIND_ENV} is {text:?}, not HOST:PORT"),
            AddrSource::File(path) => format!(
                "{} holds {text:?}, not HOST:PORT; huntsman start rewrites it, or remove it",
                path.display()
            ),
            AddrSource::Default => format!("the default bind {text:?} is not HOST:PORT"),
        });
    };
    if addr.ip().is_unspecified() {
        addr.set_ip(if addr.is_ipv4() {
            std::net::Ipv4Addr::LOCALHOST.into()
        } else {
            std::net::Ipv6Addr::LOCALHOST.into()
        });
    }
    Ok((addr, source))
}

/// The bind text and its source, before parsing. The controller's file counts only when it holds
/// a first line; an empty `HSE_BIND` is unset, as `serve` treats it.
fn serve_bind(bind: Option<&str>, place: &Place) -> (String, AddrSource) {
    if let Some(bind) = bind {
        return (bind.to_owned(), AddrSource::Flag);
    }
    if let Some(bind) = env::var(SERVE_BIND_ENV)
        .ok()
        .filter(|value| !value.trim().is_empty())
    {
        return (bind, AddrSource::Env);
    }
    if let Some(path) = place.serve_bind_file() {
        let recorded = fs::read_to_string(&path).ok().and_then(|text| {
            text.lines()
                .next()
                .map(str::trim)
                .filter(|line| !line.is_empty())
                .map(str::to_owned)
        });
        if let Some(bind) = recorded {
            return (bind, AddrSource::File(path));
        }
    }
    (DEFAULT_BIND.to_owned(), AddrSource::Default)
}

fn run(options: &Options) -> ExitCode {
    let place = Place::read();
    let (addr, source) = match serve_addr(options.bind.as_deref(), &place) {
        Ok(found) => found,
        // A bad --bind is a usage error; a bad HSE_BIND or serve.bind is the phone's setup.
        Err(message) => {
            let code = if options.bind.is_some() {
                EX_USAGE
            } else {
                EX_CONFIG
            };
            return fail(code, &message);
        }
    };
    let token = env::var(SERVE_TOKEN_ENV)
        .ok()
        .filter(|token| !token.trim().is_empty());
    let probe = serve_probe::probe(addr, token.as_deref(), PROBE_TIMEOUT, source);
    if options.mode == Mode::ServeOnly {
        return print_serve(&probe, options.json);
    }

    let host = ProcessHost {
        exe: place.current_exe.clone(),
        tmp: place.tmpdir.clone().unwrap_or_else(env::temp_dir),
    };
    // Keys are resolved for each examination: a repair can make the keys file readable, and the
    // report after `fix` must count the keys it now holds. A live probe runs once, after repairs.
    let (report, repairs) = if options.mode == Mode::Fix {
        let repairs = place.with_context(&probe, false, |ctx| {
            let first = doctor::examine(ctx, &host);
            doctor::repair(ctx, &first, &host)
        });
        let report = place.with_context(&probe, options.probe, |ctx| doctor::examine(ctx, &host));
        (report, Some(repairs))
    } else {
        let report = place.with_context(&probe, options.probe, |ctx| doctor::examine(ctx, &host));
        (report, None)
    };
    let build_sha = diagnostics::embedded_build_sha();
    let version = env!("CARGO_PKG_VERSION");

    if options.json {
        let body = serde_json::json!({
            "doctor": report.status(),
            "version": version,
            "build_sha": build_sha,
            "ok": report.count(Status::Ok),
            "warn": report.count(Status::Warn),
            "fail": report.count(Status::Fail),
            "checks": report.checks,
            "repairs": repairs,
        });
        match serde_json::to_string_pretty(&body) {
            Ok(body) => println!("{body}"),
            Err(error) => return fail(EX_DATAERR, &format!("json: {error}")),
        }
    } else {
        if let Some(repairs) = &repairs {
            print!("{}", doctor::render_repairs(repairs));
        }
        print!("{}", doctor::render(&report));
    }
    if report.status() == Status::Fail {
        ExitCode::from(EX_CONFIG)
    } else {
        ExitCode::SUCCESS
    }
}

fn print_serve(probe: &ServeProbe, json: bool) -> ExitCode {
    if json {
        match serde_json::to_string_pretty(probe) {
            Ok(body) => println!("{body}"),
            Err(error) => return fail(EX_DATAERR, &format!("json: {error}")),
        }
    } else {
        println!(
            "serve={} addr={} version={} ms={} bind={}",
            probe.state.as_str(),
            probe.addr,
            probe.version.as_deref().unwrap_or("none"),
            probe.elapsed_ms,
            probe.addr_source
        );
        for problem in &probe.problems {
            println!("problem={problem}");
        }
    }
    if probe.state == ServeState::Healthy {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(EX_UNAVAILABLE)
    }
}

/// Everything `doctor` reads from the process, except the keys.
struct Place {
    home: Option<PathBuf>,
    state_dir_override: Option<PathBuf>,
    env_file_override: Option<PathBuf>,
    prefix: Option<PathBuf>,
    path_dirs: Vec<PathBuf>,
    tmpdir: Option<PathBuf>,
    current_exe: Option<PathBuf>,
    cwd: Option<PathBuf>,
}

impl Place {
    fn read() -> Self {
        Self {
            home: absolute(env::var_os(environment::HOME_ENV)),
            state_dir_override: absolute(env::var_os(HUNTSMAN_HOME_ENV)),
            env_file_override: env::var_os(HUNTSMAN_ENV_FILE_ENV)
                .filter(|value| !value.is_empty())
                .map(PathBuf::from),
            prefix: environment::prefix().map(PathBuf::from),
            path_dirs: env::var_os("PATH")
                .map(|path| env::split_paths(&path).collect())
                .unwrap_or_default(),
            tmpdir: env::var_os("TMPDIR")
                .filter(|value| !value.is_empty())
                .map(PathBuf::from),
            current_exe: env::current_exe().ok(),
            cwd: env::current_dir().ok(),
        }
    }

    /// The controller's record of the service's address, in the state directory.
    fn serve_bind_file(&self) -> Option<PathBuf> {
        doctor::resolve_state_dir(self.home.as_deref(), self.state_dir_override.as_deref())
            .map(|dir| dir.join(doctor::SERVE_BIND_FILE))
    }

    /// Resolve the keys as every command does, probe them live when asked, and run `f` on the
    /// whole context.
    fn with_context<T>(
        &self,
        serve: &ServeProbe,
        probe_keys: bool,
        f: impl FnOnce(&Context<'_>) -> T,
    ) -> T {
        let resolved = Keys::resolve(None, self.home.as_deref().map(Path::as_os_str));
        let probes = match (&resolved, probe_keys) {
            (Ok(resolved), true) => Some(provider_credentials::probe(
                &resolved.keys,
                &UreqTransport::new(&TransportConfig::default()),
            )),
            _ => None,
        };
        let ctx = Context {
            home: self.home.clone(),
            state_dir_override: self.state_dir_override.clone(),
            env_file_override: self.env_file_override.clone(),
            termux: TermuxState::current(),
            prefix: self.prefix.clone(),
            path_dirs: self.path_dirs.clone(),
            tmpdir: self.tmpdir.clone(),
            current_exe: self.current_exe.clone(),
            cwd: self.cwd.clone(),
            build_sha: diagnostics::embedded_build_sha(),
            version: env!("CARGO_PKG_VERSION"),
            keys: match &resolved {
                Ok(resolved) => KeyState::Resolved(&resolved.keys),
                Err(error) => KeyState::Error(error.to_string()),
            },
            probes: probes.as_deref(),
            serve,
        };
        f(&ctx)
    }
}

fn absolute(value: Option<std::ffi::OsString>) -> Option<PathBuf> {
    value.map(PathBuf::from).filter(|path| path.is_absolute())
}

/// The real side effects: other programs, this binary, and the clock.
struct ProcessHost {
    exe: Option<PathBuf>,
    tmp: PathBuf,
}

/// Standard output of a program that exited 0, trimmed.
fn output_of(command: &mut Command) -> Option<String> {
    let out = command
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).trim().to_owned())
}

impl Host for ProcessHost {
    fn free_bytes(&self, path: &Path) -> Option<u64> {
        // POSIX `df -P -k`: the second line's fourth field is the space available, in KiB.
        let out = output_of(Command::new("df").arg("-P").arg("-k").arg(path))?;
        let line = out.lines().nth(1)?;
        let kib: u64 = line.split_whitespace().nth(3)?.parse().ok()?;
        kib.checked_mul(1024)
    }

    fn rustc_version(&self) -> Option<String> {
        output_of(Command::new("rustc").arg("--version")).filter(|out| !out.is_empty())
    }

    fn build_sha_of(&self, exe: &Path) -> Option<String> {
        output_of(Command::new(exe).arg("build-sha"))
    }

    fn acceptance(&self) -> Result<(), String> {
        let exe = self.exe.as_ref().ok_or("this binary's path is unknown")?;
        let nanos = clock::unix_subsec_nanos();
        let dir = self
            .tmp
            .join(format!("huntsman-doctor-{}-{nanos}", std::process::id()));
        fs::create_dir_all(&dir).map_err(|error| format!("scratch directory: {error}"))?;
        let step = |args: &[&str]| -> Result<(), String> {
            let status = Command::new(exe)
                .args(args)
                .current_dir(&dir)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .map_err(|error| format!("{}: {error}", args[0]))?;
            if status.success() {
                Ok(())
            } else {
                Err(format!(
                    "`huntsman-recon {}` exited {}",
                    args.join(" "),
                    status
                        .code()
                        .map_or_else(|| "on a signal".to_owned(), |c| c.to_string())
                ))
            }
        };
        let result = step(&["check"]).and_then(|()| step(&["verify", "var/ledger.json"]));
        let _ = fs::remove_dir_all(&dir);
        result
    }

    fn now_unix(&self) -> u64 {
        clock::unix_now()
    }
}
