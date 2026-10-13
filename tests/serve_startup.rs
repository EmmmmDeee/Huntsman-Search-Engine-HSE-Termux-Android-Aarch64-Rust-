//! What `serve` says when it starts, or cannot. Its default port is often taken by another server
//! in Termux, Termux has no root for a port below 1024, and Android may stop a server that Termux
//! started once Termux is in the background.

use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Command, Stdio};

use huntsman_recon::exit::EX_UNAVAILABLE;

/// `serve` with `args`, with no inherited bind, token, Railway or Termux setting, plus `envs`.
fn serve(args: &[&str], envs: &[(&str, &str)]) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_huntsman-recon"));
    command.arg("serve").args(args);
    for name in [
        "HSE_BIND",
        "HSE_AUTH_TOKEN",
        "PORT",
        "RAILWAY_ENVIRONMENT",
        "RAILWAY_ENVIRONMENT_ID",
        "RAILWAY_PROJECT_ID",
        "RAILWAY_SERVICE_ID",
        "TERMUX_VERSION",
        "PREFIX",
    ] {
        command.env_remove(name);
    }
    command.envs(envs.iter().copied());
    command
}

#[test]
fn a_taken_port_is_named_with_what_to_pass_instead() {
    let taken = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = taken.local_addr().unwrap();
    let out = serve(&["--bind", &addr.to_string()], &[]).output().unwrap();
    assert_eq!(out.status.code(), Some(i32::from(EX_UNAVAILABLE)));
    assert_eq!(String::from_utf8_lossy(&out.stdout), "");
    assert_eq!(
        String::from_utf8_lossy(&out.stderr),
        format!(
            "serve bind {addr}: another program already listens there; stop it, or pass --bind 127.0.0.1:PORT for another port (port 0 picks a free one)\n"
        )
    );
}

/// Starts `serve` on a free port with `envs`; returns its first stdout line and everything it
/// wrote to stderr before it answered a request.
fn startup(envs: &[(&str, &str)]) -> (String, String) {
    let mut child = serve(&["--bind", "127.0.0.1:0"], envs)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut first = String::new();
    BufReader::new(child.stdout.take().unwrap())
        .read_line(&mut first)
        .unwrap();
    // Any startup note is written before the server takes its first connection, so once a
    // request is answered, stderr holds everything startup will ever write to it.
    let addr = first
        .trim()
        .strip_prefix("serving=http://")
        .and_then(|rest| rest.strip_suffix('/'))
        .unwrap_or_else(|| panic!("no serving= line: {first:?}"))
        .to_owned();
    let mut stream = TcpStream::connect(&addr).unwrap();
    write!(stream, "GET /api/health HTTP/1.1\r\nHost: {addr}\r\n\r\n").unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    child.kill().unwrap();
    child.wait().unwrap();
    let mut stderr = String::new();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut stderr)
        .unwrap();
    (first, stderr)
}

#[test]
fn in_termux_serve_says_how_to_keep_it_running() {
    for envs in [
        &[("TERMUX_VERSION", "0.118.3")][..],
        &[("PREFIX", "/data/data/com.termux/files/usr")][..],
    ] {
        let (first, stderr) = startup(envs);
        assert!(first.starts_with("serving=http://127.0.0.1:"), "{first}");
        assert!(
            stderr.contains("termux-wake-lock")
                && stderr.contains("\"Keep serve running on Android\" in docs/INSTALL.md"),
            "{envs:?}: {stderr}"
        );
    }
}

#[test]
fn elsewhere_serve_prints_only_its_address() {
    let (first, stderr) = startup(&[("PREFIX", "/usr")]);
    assert!(first.starts_with("serving=http://127.0.0.1:"), "{first}");
    assert_eq!(stderr, "");
}

/// `serve` gives its hint exactly where `diagnostics` reports Termux: one rule decides both.
#[test]
fn serve_hints_exactly_where_diagnostics_reports_termux() {
    for (envs, termux) in [
        (&[("TERMUX_VERSION", "0.118.3")][..], true),
        (&[("PREFIX", "/data/data/com.termux/files/usr")][..], true),
        (
            &[("PREFIX", "/data/data/com.termux.nix/files/usr")][..],
            false,
        ),
        (
            &[("PREFIX", "/home/u/data/data/com.termux/files/usr")][..],
            false,
        ),
        (&[("PREFIX", "/usr")][..], false),
        (&[][..], false),
    ] {
        let mut diagnostics = Command::new(env!("CARGO_BIN_EXE_huntsman-recon"));
        diagnostics
            .args(["diagnostics", "--json"])
            .env("HOME", env!("CARGO_TARGET_TMPDIR"))
            .env_remove("TERMUX_VERSION")
            .env_remove("PREFIX")
            .envs(envs.iter().copied());
        let out = diagnostics.output().unwrap();
        assert!(out.status.success(), "{envs:?}");
        let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        let expected = if termux { "detected" } else { "not_detected" };
        assert_eq!(report["termux"], expected, "{envs:?}");
        let (_, stderr) = startup(envs);
        assert_eq!(
            stderr.contains("termux-wake-lock"),
            termux,
            "{envs:?}: {stderr}"
        );
    }
}

#[test]
fn the_install_doc_has_the_section_the_hint_names() {
    let doc = fs::read_to_string(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("docs/INSTALL.md"))
        .unwrap();
    let section = doc
        .split("\n## Keep serve running on Android\n")
        .nth(1)
        .and_then(|rest| rest.split("\n## ").next())
        .expect("docs/INSTALL.md has the section serve points Termux users to");
    for needed in [
        "termux-wake-lock",
        "termux-wake-unlock",
        "--bind 127.0.0.1:0",
        "Disable child process restrictions",
        "termux-open-url http://127.0.0.1:8080/",
    ] {
        assert!(section.contains(needed), "missing {needed:?}");
    }
}
