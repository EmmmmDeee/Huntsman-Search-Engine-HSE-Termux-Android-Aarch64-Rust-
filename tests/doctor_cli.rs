//! `doctor`, `doctor serve` and `fix` as the phone runs them: the real binary, a scratch `$HOME`,
//! and a real `serve` process for the probe.

use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};

const BIN: &str = env!("CARGO_BIN_EXE_huntsman-recon");

fn scratch(tag: &str) -> PathBuf {
    let dir =
        std::env::temp_dir().join(format!("huntsman-doctor-cli-{tag}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(dir.join("tmp")).unwrap();
    fs::create_dir_all(dir.join("work")).unwrap();
    dir
}

/// Whether an inherited variable is a provider key or other Huntsman setting that would make the
/// caller's shell, not the scratch home, decide what `doctor` counts.
fn inherited_setting(name: &str) -> bool {
    name.starts_with("HUNTSMAN_")
        || ["_KEY", "_TOKEN", "_USER", "_SECRET", "_PASSWORD"]
            .iter()
            .any(|suffix| name.ends_with(suffix))
}

/// The binary with `$HOME` at `home`, its own directory and the system tools on `PATH`, and no
/// serve settings or provider keys inherited from the caller.
fn bin(home: &Path) -> Command {
    let bin_dir = Path::new(BIN).parent().unwrap();
    let path = format!("{}:/usr/bin:/bin", bin_dir.display());
    let mut command = Command::new(BIN);
    command
        .current_dir(home.join("work"))
        .env("HOME", home)
        .env("PATH", path)
        .env("TMPDIR", home.join("tmp"))
        .env_remove("HSE_BIND")
        .env_remove("HSE_AUTH_TOKEN")
        .env_remove("HUNTSMAN_HOME")
        .env_remove("HUNTSMAN_ENV_FILE")
        .env_remove("TERMUX_VERSION")
        .env_remove("PREFIX");
    for (name, _) in std::env::vars_os() {
        if name.to_str().is_some_and(inherited_setting) {
            command.env_remove(&name);
        }
    }
    command
}

fn mode(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    fs::metadata(path).unwrap().permissions().mode() & 0o777
}

fn set_mode(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

fn stdout(out: &Output) -> String {
    String::from_utf8(out.stdout.clone()).unwrap()
}

/// A port nothing listens on.
/// Held for the whole of every test that binds, frees or probes a loopback port. Tests in one
/// binary run in parallel threads, and a port a test frees (`free_port`, a stopped server) can be
/// handed by the kernel to another test's listener at once: a probe then meets the wrong program,
/// a "not running" port is suddenly foreign, or a counted accept is spent by a stranger. Cargo
/// runs test binaries one at a time, so serialising these tests here removes the collision.
fn ports() -> std::sync::MutexGuard<'static, ()> {
    static PORTS: std::sync::Mutex<()> = std::sync::Mutex::new(());
    PORTS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

struct Serve {
    child: Child,
    addr: String,
}

impl Drop for Serve {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn start_serve(home: &Path, bind: &str, token: Option<&str>) -> Serve {
    let mut command = bin(home);
    command
        .args(["serve", "--bind", bind])
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    if let Some(token) = token {
        command.env("HSE_AUTH_TOKEN", token);
    }
    let mut child = command.spawn().unwrap();
    let mut line = String::new();
    BufReader::new(child.stdout.as_mut().unwrap())
        .read_line(&mut line)
        .unwrap();
    let addr = line
        .trim()
        .strip_prefix("serving=http://")
        .and_then(|rest| rest.strip_suffix('/'))
        .unwrap_or_else(|| panic!("serve printed {line:?}"))
        .to_owned();
    Serve { child, addr }
}

#[test]
fn doctor_serve_reports_a_real_server_healthy_and_a_stopped_one_not_running() {
    let _ports = ports();
    let home = scratch("serve");
    let serve = start_serve(&home, "127.0.0.1:0", None);
    let out = bin(&home)
        .args(["doctor", "serve", "--bind", &serve.addr])
        .output()
        .unwrap();
    let text = stdout(&out);
    assert_eq!(out.status.code(), Some(0), "{text}");
    assert!(
        text.starts_with(&format!(
            "serve=healthy addr={} version={} ms=",
            serve.addr,
            env!("CARGO_PKG_VERSION")
        )),
        "{text}"
    );
    assert!(!text.contains("problem="), "{text}");

    // The full report agrees.
    let out = bin(&home)
        .args(["doctor", "--json", "--bind", &serve.addr])
        .output()
        .unwrap();
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let serve_check = report["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|check| check["id"] == "serve")
        .unwrap();
    assert_eq!(serve_check["status"], "ok", "{serve_check}");
    assert!(
        serve_check["message"]
            .as_str()
            .unwrap()
            .contains("page, policy and analysis work"),
        "{serve_check}"
    );

    let addr = serve.addr.clone();
    drop(serve);
    let out = bin(&home)
        .args(["doctor", "serve", "--bind", &addr])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(69));
    assert!(
        stdout(&out).starts_with("serve=not_running "),
        "{}",
        stdout(&out)
    );
    let _ = fs::remove_dir_all(&home);
}

/// `huntsman start` records the port it chose in `~/.huntsman/serve.bind` when 8080 is taken,
/// and the service runs there. `doctor` reads the same file, so it probes the address the phone
/// serves on; `--bind` and `HSE_BIND` still win, and `HUNTSMAN_HOME` moves the file with the
/// state directory.
#[test]
fn doctor_serve_reads_the_address_the_termux_controller_recorded() {
    let _ports = ports();
    let home = scratch("serve-bind");
    let serve = start_serve(&home, "127.0.0.1:0", None);
    let bind_file = home.join(".huntsman").join("serve.bind");
    fs::create_dir_all(bind_file.parent().unwrap()).unwrap();
    fs::write(&bind_file, format!("{}\n", serve.addr)).unwrap();
    let out = bin(&home).args(["doctor", "serve"]).output().unwrap();
    let text = stdout(&out);
    assert_eq!(out.status.code(), Some(0), "{text}");
    assert!(
        text.starts_with(&format!("serve=healthy addr={} ", serve.addr)),
        "{text}"
    );
    assert!(
        text.contains(&format!(" bind={}\n", bind_file.display())),
        "{text}"
    );

    // The JSON names the file too.
    let out = bin(&home)
        .args(["doctor", "serve", "--json"])
        .output()
        .unwrap();
    let probe: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(probe["addr"], serve.addr, "{probe}");
    assert_eq!(
        probe["addr_source"],
        bind_file.display().to_string(),
        "{probe}"
    );

    // HUNTSMAN_HOME moves the state directory, and the file with it.
    let alt = home.join("alt");
    fs::create_dir_all(&alt).unwrap();
    fs::write(alt.join("serve.bind"), format!("{}\n", serve.addr)).unwrap();
    let out = bin(&home)
        .env("HUNTSMAN_HOME", &alt)
        .args(["doctor", "serve"])
        .output()
        .unwrap();
    assert!(
        stdout(&out).contains(&format!(" bind={}\n", alt.join("serve.bind").display())),
        "{}",
        stdout(&out)
    );

    // --bind and HSE_BIND win over the file. Port 1 on loopback refuses, so it is not running.
    let out = bin(&home)
        .args(["doctor", "serve", "--bind", "127.0.0.1:1"])
        .output()
        .unwrap();
    assert!(
        stdout(&out).starts_with("serve=not_running addr=127.0.0.1:1 ")
            && stdout(&out).contains(" bind=--bind\n"),
        "{}",
        stdout(&out)
    );
    let out = bin(&home)
        .env("HSE_BIND", "127.0.0.1:1")
        .args(["doctor", "serve"])
        .output()
        .unwrap();
    assert!(
        stdout(&out).contains(" addr=127.0.0.1:1 ") && stdout(&out).contains(" bind=HSE_BIND\n"),
        "{}",
        stdout(&out)
    );

    // The full report says where the address came from once the server is gone.
    drop(serve);
    let out = bin(&home).args(["doctor", "--json"]).output().unwrap();
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let serve_check = report["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|check| check["id"] == "serve")
        .unwrap();
    assert_eq!(serve_check["status"], "ok", "{serve_check}");
    assert!(
        serve_check["message"]
            .as_str()
            .unwrap()
            .contains(&format!("recorded in {}", bind_file.display())),
        "{serve_check}"
    );

    // A recorded line that is not HOST:PORT is a configuration error naming the file, exit 78.
    fs::write(&bind_file, "nonsense\n").unwrap();
    let out = bin(&home).args(["doctor", "serve"]).output().unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(78), "{err}");
    assert!(
        err.contains(&bind_file.display().to_string()) && err.contains("huntsman start"),
        "{err}"
    );
    assert_eq!(stdout(&out), "");
    let _ = fs::remove_dir_all(&home);
}

/// The phone's service still exports the token an earlier installer wrote. A loopback server
/// started with it needs none, so `doctor serve` finds it healthy from a shell without it.
#[test]
fn doctor_serve_finds_a_loopback_server_started_with_a_token_healthy_without_it() {
    let _ports = ports();
    let home = scratch("loopback-token");
    let serve = start_serve(&home, "127.0.0.1:0", Some("doctor-test-serve-token"));
    let out = bin(&home)
        .args(["doctor", "serve", "--bind", &serve.addr])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", stdout(&out));
    assert!(
        stdout(&out).starts_with("serve=healthy "),
        "{}",
        stdout(&out)
    );
    drop(serve);
    let _ = fs::remove_dir_all(&home);
}

#[test]
fn doctor_serve_needs_the_token_a_public_server_was_started_with() {
    let _ports = ports();
    let home = scratch("token");
    let serve = start_serve(&home, "0.0.0.0:0", Some("doctor-test-serve-token"));
    let out = bin(&home)
        .args(["doctor", "serve", "--bind", &serve.addr])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(69));
    assert!(
        stdout(&out).starts_with("serve=unauthorized "),
        "{}",
        stdout(&out)
    );
    let out = bin(&home)
        .args(["doctor", "serve", "--bind", &serve.addr])
        .env("HSE_AUTH_TOKEN", "doctor-test-serve-token")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", stdout(&out));
    assert!(!stdout(&out).contains("doctor-test-serve-token"));
    drop(serve);
    let _ = fs::remove_dir_all(&home);
}

/// Another program on a port: it answers every connection with a page that is not
/// huntsman-recon's, until dropped. It answers any number of connections, not a counted few, so a
/// stray connection (another test's doctor probing a port number it was handed and released,
/// which the kernel can hand to this listener) cannot leave a later probe facing a closed port.
struct Foreign {
    addr: String,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Foreign {
    fn start() -> Self {
        use std::sync::atomic::Ordering;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stopping = std::sync::Arc::clone(&stop);
        let thread = std::thread::spawn(move || {
            for stream in listener.incoming() {
                if stopping.load(Ordering::SeqCst) {
                    break;
                }
                let Ok(mut stream) = stream else { continue };
                let mut buf = [0_u8; 2048];
                let _ = stream.read(&mut buf);
                let _ = stream.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 5\r\n\r\nother",
                );
            }
        });
        Self {
            addr,
            stop,
            thread: Some(thread),
        }
    }
}

impl Drop for Foreign {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::SeqCst);
        // Wake the blocked accept so the thread sees the flag and ends.
        let _ = std::net::TcpStream::connect(&self.addr);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

#[test]
fn a_port_held_by_another_program_is_foreign_and_fails_doctor() {
    let _ports = ports();
    let home = scratch("foreign");
    let foreign = Foreign::start();
    let addr = foreign.addr.clone();
    let out = bin(&home)
        .args(["doctor", "serve", "--bind", &addr])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(69));
    assert!(
        stdout(&out).starts_with("serve=foreign "),
        "{}",
        stdout(&out)
    );

    // A stray connection, as another test's doctor probing a port number it was handed and
    // released, lands on this listener: it is the same program on the same port.
    drop(std::net::TcpStream::connect(&addr).unwrap());
    let out = bin(&home)
        .args(["doctor", "--bind", &addr])
        .output()
        .unwrap();
    let text = stdout(&out);
    assert_eq!(out.status.code(), Some(78), "{text}");
    assert!(text.contains("fail serve"), "{text}");
    assert!(
        text.contains("fix: huntsman-recon serve --bind 127.0.0.1:8081"),
        "{text}"
    );
    drop(foreign);
    let _ = fs::remove_dir_all(&home);
}

#[test]
fn fix_repairs_a_fresh_home_and_leaves_keys_untouched() {
    let _ports = ports();
    let home = scratch("fix");
    let keys = home.join(".huntsman.env");
    let content = "HUNTSMAN_SHODAN_KEY=doctor-test-secret-value-cli\n";
    fs::write(&keys, content).unwrap();
    set_mode(&keys, 0o644);
    let port = free_port().to_string();
    let bind = format!("127.0.0.1:{port}");

    let before = bin(&home)
        .args(["doctor", "--bind", &bind])
        .output()
        .unwrap();
    let text = stdout(&before);
    assert_eq!(before.status.code(), Some(78), "{text}");
    assert!(text.contains("fail env_file"), "{text}");
    assert!(text.contains("warn state_dir"), "{text}");
    assert!(!text.contains("doctor-test-secret-value-cli"), "{text}");

    let fixed = bin(&home).args(["fix", "--bind", &bind]).output().unwrap();
    let text = stdout(&fixed);
    assert_eq!(fixed.status.code(), Some(0), "{text}");
    assert!(
        text.contains("repaired state_dir: created ~/.huntsman (mode 700)"),
        "{text}"
    );
    assert!(
        text.contains("repaired env_file: set ~/.huntsman.env to mode 600"),
        "{text}"
    );
    assert!(text.contains("ok   env_file"), "{text}");
    assert!(
        text.contains("1 of "),
        "the key in the file is now used: {text}"
    );
    assert_eq!(mode(&home.join(".huntsman")), 0o700);
    assert_eq!(mode(&keys), 0o600);
    assert_eq!(fs::read_to_string(&keys).unwrap(), content);

    // `doctor --fix` is the same command, and a second run has nothing left to repair.
    let again = bin(&home)
        .args(["doctor", "--fix", "--json", "--bind", &bind])
        .output()
        .unwrap();
    let report: serde_json::Value = serde_json::from_slice(&again.stdout).unwrap();
    assert_eq!(again.status.code(), Some(0));
    assert_eq!(report["fail"], 0, "{report}");
    assert!(report["repairs"].as_array().unwrap().is_empty(), "{report}");
    assert!(!String::from_utf8_lossy(&again.stdout).contains("doctor-test-secret-value-cli"));
    let _ = fs::remove_dir_all(&home);
}

#[test]
fn a_broken_ledger_in_the_working_directory_fails_doctor_and_survives_fix() {
    let _ports = ports();
    let home = scratch("ledger");
    let var = home.join("work/var");
    fs::create_dir_all(&var).unwrap();
    fs::write(var.join("ledger.json"), "[{\"prev\":").unwrap();
    let bind = format!("127.0.0.1:{}", free_port());
    let out = bin(&home).args(["fix", "--bind", &bind]).output().unwrap();
    let text = stdout(&out);
    assert_eq!(out.status.code(), Some(78), "{text}");
    assert!(text.contains("fail ledgers"), "{text}");
    assert_eq!(
        fs::read_to_string(var.join("ledger.json")).unwrap(),
        "[{\"prev\":"
    );
    let _ = fs::remove_dir_all(&home);
}

#[test]
fn doctor_refuses_unknown_arguments_with_64() {
    let home = scratch("usage");
    for args in [
        &["doctor", "--bogus"][..],
        &["doctor", "now"],
        &["doctor", "--bind"],
        &["doctor", "serve", "--fix"],
        &["doctor", "--json", "--json"],
        &["fix", "serve"],
        &["fix", "--fix"],
        &["doctor", "--bind", "not-an-address"],
    ] {
        let out = bin(&home).args(args).output().unwrap();
        assert_eq!(out.status.code(), Some(64), "{args:?}");
        assert!(out.stdout.is_empty(), "{args:?}");
    }
    let _ = fs::remove_dir_all(&home);
}

#[test]
fn doctor_and_fix_have_help() {
    let home = scratch("help");
    for command in ["doctor", "fix"] {
        let out = bin(&home).args([command, "--help"]).output().unwrap();
        assert_eq!(out.status.code(), Some(0));
        assert!(
            stdout(&out).starts_with(&format!("{command} [")),
            "{}",
            stdout(&out)
        );
    }
    let _ = fs::remove_dir_all(&home);
}

/// The two continuous-normalisation settings live in `~/.huntsman.env` beside the keys, so
/// `doctor` must not report them as keys no provider reads.
#[test]
fn continuous_settings_in_the_keys_file_are_recognised() {
    let _ports = ports();
    let home = scratch("continuous");
    let keys = home.join(".huntsman.env");
    fs::write(
        &keys,
        "HUNTSMAN_CONTINUOUS_TARGETS=*\nHUNTSMAN_CONTINUOUS_INTERVAL_MINUTES=60\n",
    )
    .unwrap();
    set_mode(&keys, 0o600);
    let bind = format!("127.0.0.1:{}", free_port());
    let out = bin(&home)
        .args(["doctor", "--bind", &bind])
        .output()
        .unwrap();
    let text = stdout(&out);
    assert!(
        text.contains("ok   env_file") && text.contains("2 slots set"),
        "{text}"
    );
    assert!(!text.contains("read by no provider"), "{text}");
    let _ = fs::remove_dir_all(&home);
}

/// A shell without `HUNTSMAN_HOME` resolves `~/.huntsman`, while the web UI service the installer
/// set up keeps its state where the installer chose. `doctor` names the difference and the export
/// that ends it, so the scans the page ran are never reported missing.
#[test]
fn doctor_names_a_state_dir_the_web_ui_service_keeps_elsewhere() {
    let _ports = ports();
    let home = scratch("service-state");
    let prefix = home.join("prefix");
    let service = prefix.join("var/service/huntsman-serve");
    fs::create_dir_all(&service).unwrap();
    fs::create_dir_all(prefix.join("tmp")).unwrap();
    let hunt = home.join("hunt");
    fs::write(
        service.join("run"),
        format!(
            "#!/bin/sh\nexport HUNTSMAN_HOME='{}'\nexec huntsman-recon serve\n",
            hunt.display()
        ),
    )
    .unwrap();
    let bind = format!("127.0.0.1:{}", free_port());
    let doctor = |home_env: Option<&Path>| {
        let mut command = bin(&home);
        command
            .args(["doctor", "--bind", &bind])
            .env("TERMUX_VERSION", "0.118.3")
            .env("PREFIX", &prefix);
        if let Some(dir) = home_env {
            command.env("HUNTSMAN_HOME", dir);
        }
        stdout(&command.output().unwrap())
    };
    let text = doctor(None);
    assert!(text.contains("warn state_dir"), "{text}");
    assert!(
        text.contains(
            "~/.huntsman here, but the web UI service keeps its scans and serve.bind in ~/hunt"
        ),
        "{text}"
    );
    assert!(
        text.contains("export HUNTSMAN_HOME=~/hunt, or run commands through huntsman"),
        "{text}"
    );
    // The export the hint names ends the difference.
    let text = doctor(Some(&hunt));
    assert!(!text.contains("keeps its scans"), "{text}");
    let _ = fs::remove_dir_all(&home);
}
