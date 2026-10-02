//! `fetch` credential resolution with `$HOME/.huntsman.env`.
//!
//! Every run gets a throwaway `HOME` under the system temp dir and a loopback
//! server; the real home directory and real keys are never read. Values are
//! `TEST_ONLY_VALUE_*` dummies.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::thread;
use std::time::Duration;

const SLOT: &str = "HSE_AUTOLOAD_TEST_KEY";

fn fake_home(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "huntsman-env-autoload-{name}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn write_mode(path: &Path, text: &str, mode: u32) {
    std::fs::write(path, text).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }
    #[cfg(not(unix))]
    let _ = mode;
}

/// Accept one request on loopback, answer 200, return the raw request head.
fn serve_once() -> (u16, thread::JoinHandle<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let handle = thread::spawn(move || {
        let (mut sock, _) = listener.accept().unwrap();
        sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut buf = Vec::new();
        let mut chunk = [0u8; 512];
        while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
            match sock.read(&mut chunk) {
                Ok(0) | Err(_) => break,
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
            }
        }
        let _ =
            sock.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
        String::from_utf8_lossy(&buf).into_owned()
    });
    (port, handle)
}

/// `fetch --bearer SLOT` against `port` with `HOME=home`, the slot removed from
/// the inherited environment unless `env_value` sets it.
fn fetch(home: &Path, port: u16, extra: &[&str], env_value: Option<&str>) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_huntsman-recon"));
    cmd.args([
        "fetch",
        &format!("http://127.0.0.1:{port}/"),
        "--allow-private",
        "--timeout",
        "5",
        "--bearer",
        SLOT,
    ])
    .args(extra)
    .env("HOME", home)
    .env_remove(SLOT);
    if let Some(value) = env_value {
        cmd.env(SLOT, value);
    }
    cmd.output().unwrap()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// A port with nothing listening: a run that wrongly got as far as the network
/// exits 69 instead of the expected 66.
fn closed_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn not_configured(out: &Output) {
    assert_eq!(out.status.code(), Some(66), "{}", stderr(out));
    assert_eq!(out.stdout, [] as [u8; 0]);
    assert_eq!(
        stderr(out),
        format!("invalid input: credential {SLOT} is not configured\n")
    );
}

#[cfg(unix)]
#[test]
fn private_default_file_is_auto_loaded() {
    let home = fake_home("private");
    write_mode(
        &home.join(".huntsman.env"),
        &format!("{SLOT}=TEST_ONLY_VALUE_DEFAULT\n"),
        0o600,
    );
    let (port, server) = serve_once();
    let out = fetch(&home, port, &[], None);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert_eq!(stderr(&out), "");
    let request = server.join().unwrap();
    assert!(
        request.contains("Bearer TEST_ONLY_VALUE_DEFAULT\r\n"),
        "credential from ~/.huntsman.env was not sent"
    );
    std::fs::remove_dir_all(&home).unwrap();
}

#[cfg(unix)]
#[test]
fn readable_default_file_is_refused_with_one_warning() {
    let home = fake_home("loose");
    let path = home.join(".huntsman.env");
    write_mode(&path, &format!("{SLOT}=TEST_ONLY_VALUE_LOOSE\n"), 0o644);
    let out = fetch(&home, closed_port(), &[], None);
    assert_eq!(out.status.code(), Some(66), "{}", stderr(&out));
    let err = stderr(&out);
    let mut lines = err.lines();
    let warning = lines.next().unwrap();
    assert!(warning.starts_with("warning: "), "{err}");
    assert!(warning.contains(&path.display().to_string()), "{err}");
    assert!(warning.contains("chmod 600 ~/.huntsman.env"), "{err}");
    assert_eq!(
        lines.collect::<Vec<_>>(),
        [format!(
            "invalid input: credential {SLOT} is not configured"
        )],
        "nothing was loaded from the refused file"
    );
    std::fs::remove_dir_all(&home).unwrap();
}

#[cfg(unix)]
#[test]
fn warning_never_contains_file_values() {
    let home = fake_home("novalue");
    write_mode(
        &home.join(".huntsman.env"),
        &format!(
            "# TEST_ONLY_VALUE_COMMENT\n{SLOT}=TEST_ONLY_VALUE_SECRET\n\
             export OTHER_TEST_SLOT='TEST_ONLY_VALUE_QUOTED'\n"
        ),
        0o640,
    );
    let out = fetch(&home, closed_port(), &[], None);
    let all = format!("{}{}", stderr(&out), String::from_utf8_lossy(&out.stdout));
    assert!(all.contains("chmod 600"), "{all}");
    assert!(!all.contains("TEST_ONLY_VALUE"), "a file value was printed");
    assert!(
        !all.contains("OTHER_TEST_SLOT"),
        "a file slot name was printed"
    );
    std::fs::remove_dir_all(&home).unwrap();
}

#[test]
fn missing_default_file_is_a_silent_no_op() {
    let home = fake_home("missing");
    not_configured(&fetch(&home, closed_port(), &[], None));
    // The environment still supplies the slot exactly as before.
    let (port, server) = serve_once();
    let out = fetch(&home, port, &[], Some("TEST_ONLY_VALUE_ENV"));
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert_eq!(stderr(&out), "");
    assert!(
        server
            .join()
            .unwrap()
            .contains("Bearer TEST_ONLY_VALUE_ENV\r\n")
    );
    std::fs::remove_dir_all(&home).unwrap();
}

#[cfg(unix)]
#[test]
fn explicit_keys_file_overrides_the_default_file() {
    let home = fake_home("explicit");
    write_mode(
        &home.join(".huntsman.env"),
        &format!("{SLOT}=TEST_ONLY_VALUE_DEFAULT\n"),
        0o600,
    );
    let explicit = home.join("explicit.env");
    write_mode(
        &explicit,
        &format!("{SLOT}=TEST_ONLY_VALUE_EXPLICIT\n"),
        0o600,
    );
    let explicit_arg = explicit.to_str().unwrap();

    let (port, server) = serve_once();
    let out = fetch(&home, port, &["--keys", explicit_arg], None);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    let request = server.join().unwrap();
    assert!(request.contains("Bearer TEST_ONLY_VALUE_EXPLICIT\r\n"));
    assert!(!request.contains("TEST_ONLY_VALUE_DEFAULT"));

    // A --keys file without the slot does not fall back to the default file.
    write_mode(&explicit, "UNRELATED_TEST_SLOT=TEST_ONLY_VALUE_X\n", 0o600);
    not_configured(&fetch(
        &home,
        closed_port(),
        &["--keys", explicit_arg],
        None,
    ));

    // With --keys the default file is not inspected, so a loose one is not reported.
    write_mode(
        &home.join(".huntsman.env"),
        &format!("{SLOT}=TEST_ONLY_VALUE_DEFAULT\n"),
        0o644,
    );
    not_configured(&fetch(
        &home,
        closed_port(),
        &["--keys", explicit_arg],
        None,
    ));
    std::fs::remove_dir_all(&home).unwrap();
}

#[cfg(unix)]
#[test]
fn default_file_wins_over_the_environment_like_keys() {
    let home = fake_home("precedence");
    write_mode(
        &home.join(".huntsman.env"),
        &format!("{SLOT}=TEST_ONLY_VALUE_FILE\n"),
        0o600,
    );
    let (port, server) = serve_once();
    let out = fetch(&home, port, &[], Some("TEST_ONLY_VALUE_ENV"));
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert!(
        server
            .join()
            .unwrap()
            .contains("Bearer TEST_ONLY_VALUE_FILE\r\n")
    );

    // A slot the file lacks still falls back to the environment.
    write_mode(
        &home.join(".huntsman.env"),
        "UNRELATED_TEST_SLOT=TEST_ONLY_VALUE_X\n",
        0o600,
    );
    let (port, server) = serve_once();
    let out = fetch(&home, port, &[], Some("TEST_ONLY_VALUE_ENV"));
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert!(
        server
            .join()
            .unwrap()
            .contains("Bearer TEST_ONLY_VALUE_ENV\r\n")
    );
    std::fs::remove_dir_all(&home).unwrap();
}

#[test]
fn anonymous_fetch_does_not_read_the_default_file() {
    let home = fake_home("anonymous");
    write_mode(
        &home.join(".huntsman.env"),
        &format!("{SLOT}=TEST_ONLY_VALUE_DEFAULT\n"),
        0o644,
    );
    let (port, server) = serve_once();
    let out = Command::new(env!("CARGO_BIN_EXE_huntsman-recon"))
        .args([
            "fetch",
            &format!("http://127.0.0.1:{port}/"),
            "--allow-private",
        ])
        .env("HOME", &home)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert_eq!(stderr(&out), "", "no credential requested, no warning");
    assert!(
        !server
            .join()
            .unwrap()
            .to_ascii_lowercase()
            .contains("authorization")
    );
    std::fs::remove_dir_all(&home).unwrap();
}

#[cfg(unix)]
#[test]
fn symlinked_default_file_is_refused_even_when_the_target_is_private() {
    let home = fake_home("symlink");
    let target = home.join("real.env");
    write_mode(&target, &format!("{SLOT}=TEST_ONLY_VALUE_LINKED\n"), 0o600);
    let path = home.join(".huntsman.env");
    std::os::unix::fs::symlink(&target, &path).unwrap();
    let out = fetch(&home, closed_port(), &[], None);
    assert_eq!(out.status.code(), Some(66), "{}", stderr(&out));
    let err = stderr(&out);
    let mut lines = err.lines();
    let warning = lines.next().unwrap();
    assert!(warning.starts_with("warning: "), "{err}");
    assert!(warning.contains(&path.display().to_string()), "{err}");
    assert!(warning.contains("symlink"), "{err}");
    assert!(!err.contains("TEST_ONLY_VALUE"), "a file value was printed");
    assert_eq!(
        lines.collect::<Vec<_>>(),
        [format!(
            "invalid input: credential {SLOT} is not configured"
        )],
        "nothing was loaded through the symlink"
    );
    std::fs::remove_dir_all(&home).unwrap();
}

/// Content and I/O failures are not refusals: a credentialed fetch stops with exit
/// 66 instead of silently falling back to the environment, and stderr names the
/// problem (path or line number) without any value.
#[cfg(unix)]
#[test]
fn unusable_default_file_fails_closed_even_with_the_slot_in_the_environment() {
    let home = fake_home("failclosed");
    let path = home.join(".huntsman.env");
    let oversized = format!("{SLOT}={}\n", "TEST_ONLY_VALUE_".repeat(5000));
    let cases: [(&[u8], u32, &str); 4] = [
        (
            b"TEST_ONLY_VALUE_NOT_A_PAIR\n",
            0o600,
            "keys line 1: expected NAME=value",
        ),
        (oversized.as_bytes(), 0o600, "exceeds 65536 bytes"),
        (b"HSE_X=TEST_ONLY_VALUE_\xff\n", 0o600, "not utf-8"),
        (b"HSE_X=TEST_ONLY_VALUE_UNOPENABLE\n", 0o200, ""),
    ];
    for (body, mode, expected) in cases {
        std::fs::write(&path, body).unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        }
        if mode == 0o200 && std::fs::File::open(&path).is_ok() {
            continue; // running as root: an owner-unreadable file still opens
        }
        let out = fetch(&home, closed_port(), &[], Some("TEST_ONLY_VALUE_ENV"));
        let err = stderr(&out);
        assert_eq!(out.status.code(), Some(66), "{mode:o}: {err}");
        assert!(err.contains(expected), "{mode:o}: {err}");
        if mode == 0o200 {
            assert!(err.contains(&path.display().to_string()), "{err}");
        }
        assert!(!err.contains("TEST_ONLY_VALUE"), "a value was printed");
        assert!(
            !err.starts_with("warning: "),
            "not a warn-and-continue case"
        );
    }
    std::fs::remove_dir_all(&home).unwrap();
}
