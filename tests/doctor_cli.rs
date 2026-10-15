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

/// The binary with `$HOME` at `home`, its own directory and the system tools on `PATH`, and no
/// serve settings inherited from the caller.
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

/// The phone's service still exports the token an earlier installer wrote. A loopback server
/// started with it needs none, so `doctor serve` finds it healthy from a shell without it.
#[test]
fn doctor_serve_finds_a_loopback_server_started_with_a_token_healthy_without_it() {
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

#[test]
fn a_port_held_by_another_program_is_foreign_and_fails_doctor() {
    let home = scratch("foreign");
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let server = std::thread::spawn(move || {
        for _ in 0..2 {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buf = [0_u8; 2048];
            let _ = stream.read(&mut buf);
            let _ = stream.write_all(
                b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 5\r\n\r\nother",
            );
        }
    });
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
    server.join().unwrap();
    let _ = fs::remove_dir_all(&home);
}

#[test]
fn fix_repairs_a_fresh_home_and_leaves_keys_untouched() {
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
