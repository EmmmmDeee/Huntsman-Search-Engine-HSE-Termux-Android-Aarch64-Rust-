//! What `serve` says when it starts, or cannot. Its default port is often taken by another server
//! in Termux, Termux has no root for a port below 1024, and Android may stop a server that Termux
//! started once Termux is in the background.

use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Command, Stdio};

use huntsman_recon::exit::{EX_DATAERR, EX_UNAVAILABLE};

/// `serve` with `args`, with no inherited bind, token, external host or Termux setting, plus `envs`.
fn serve(args: &[&str], envs: &[(&str, &str)]) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_huntsman-recon"));
    command.arg("serve").args(args);
    for name in [
        "HSE_BIND",
        "HSE_AUTH_TOKEN",
        "PORT",
        "TERMUX_VERSION",
        "PREFIX",
        "HUNTSMAN_CONTINUOUS_TARGETS",
        "HUNTSMAN_CONTINUOUS_INTERVAL_MINUTES",
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

/// Starts `serve` on a free loopback port with `envs`; returns its first stdout line and everything
/// it wrote to stderr before it answered a request.
fn startup(envs: &[(&str, &str)]) -> (String, String) {
    startup_on("127.0.0.1:0", envs)
}

/// [`startup`] on `bind`.
fn startup_on(bind: &str, envs: &[(&str, &str)]) -> (String, String) {
    let (first, stderr, _) = startup_asking(bind, envs, "/api/health", "");
    (first, stderr)
}

/// Starts `serve` on `bind` with `envs` and asks it `GET path` with `headers`; returns its first
/// stdout line, everything it wrote to stderr before it answered, and the answer's body.
fn startup_asking(
    bind: &str,
    envs: &[(&str, &str)],
    path: &str,
    headers: &str,
) -> (String, String, String) {
    let mut child = serve(&["--bind", bind], envs)
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
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: {addr}\r\n{headers}\r\n"
    )
    .unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    let body = response
        .split_once("\r\n\r\n")
        .map(|(_, body)| body.to_owned())
        .unwrap_or_default();
    child.kill().unwrap();
    child.wait().unwrap();
    let mut stderr = String::new();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut stderr)
        .unwrap();
    (first, stderr, body)
}

/// A leftover deployment environment may export `PORT` and a retired provider
/// marker. Neither may reject a valid local bind or control the listener.
/// Only `HSE_BIND` or `--bind` may opt the application into public listening.
#[test]
fn unrelated_port_environment_does_not_override_local_bind() {
    let mut child = serve(
        &["--bind", "127.0.0.1:0"],
        &[
            ("PORT", "not-a-valid-port"),
            ("RAILWAY_ENVIRONMENT", "retired-sentinel"),
        ],
    )
    .stdout(Stdio::piped())
    .stderr(Stdio::null())
    .spawn()
    .expect("start serve with explicit local bind");
    let mut first = String::new();
    BufReader::new(child.stdout.take().unwrap())
        .read_line(&mut first)
        .expect("read bound address");
    let addr = first
        .trim()
        .strip_prefix("serving=http://")
        .and_then(|value| value.strip_suffix('/'))
        .expect("local serve starts despite invalid unrelated port");
    assert!(addr.starts_with("127.0.0.1:"), "{first}");
    let _ = child.kill();
    child.wait().expect("reap local server");
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

/// The phone's service still exports the token an earlier installer wrote. A loopback `serve`
/// needs none, says so, and never prints the value.
#[test]
fn on_loopback_serve_says_the_token_is_not_needed_without_printing_it() {
    let value = "TEST-ONLY-serve-token-7f3a";
    let (first, stderr) = startup(&[("HSE_AUTH_TOKEN", value), ("PREFIX", "/usr")]);
    assert!(first.starts_with("serving=http://127.0.0.1:"), "{first}");
    assert!(
        stderr.contains("a loopback bind needs no token") && !stderr.contains("token field"),
        "{stderr}"
    );
    assert!(
        !stderr.contains(value) && !first.contains(value),
        "{stderr}"
    );
}

/// On a public bind every API call but health needs the token. `serve` says so when it starts,
/// names where the value goes, and never prints the value.
#[test]
fn on_a_public_bind_serve_says_the_page_needs_the_token_without_printing_it() {
    let value = "TEST-ONLY-serve-token-7f3a";
    let (first, stderr) = startup_on(
        "0.0.0.0:0",
        &[("HSE_AUTH_TOKEN", value), ("PREFIX", "/usr")],
    );
    assert!(first.starts_with("serving=http://0.0.0.0:"), "{first}");
    assert!(
        stderr.contains("this public bind needs HSE_AUTH_TOKEN")
            && stderr.contains("token field")
            && stderr.contains("/#token=VALUE"),
        "{stderr}"
    );
    assert!(
        !stderr.contains(value) && !first.contains(value),
        "{stderr}"
    );
}

/// The phone's service reads `~/.huntsman.env`, so continuous normalisation set there starts with
/// `serve` and the Settings page says what it does; set nowhere, the page says it is off and how
/// to turn it on; set wrong, `serve` ends before it binds, naming the setting.
#[test]
fn continuous_normalisation_is_read_from_the_keys_file_and_shown_in_settings() {
    let home = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("serve-continuous-home");
    let _ = fs::remove_dir_all(&home);
    fs::create_dir_all(&home).unwrap();
    let keys = home.join(".huntsman.env");
    fs::write(
        &keys,
        "HUNTSMAN_CONTINUOUS_TARGETS=*\nHUNTSMAN_CONTINUOUS_INTERVAL_MINUTES=60\n",
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&keys, fs::Permissions::from_mode(0o600)).unwrap();
    }
    let home_text = home.to_str().unwrap();
    let continuous = |body: &str| {
        let settings: serde_json::Value = serde_json::from_str(body).unwrap();
        settings["global"]
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| entry["key"] == "continuous")
            .cloned()
            .expect("a continuous global setting")
    };
    let header = "X-Huntsman-Lookup: 1\r\n";

    let (first, stderr, body) = startup_asking(
        "127.0.0.1:0",
        &[("HOME", home_text), ("PREFIX", "/usr")],
        "/api/settings",
        header,
    );
    assert!(first.starts_with("serving=http://127.0.0.1:"), "{first}");
    assert!(
        stderr.contains(
            "continuous: enabled with 0 canonical targets, interval=60 minutes, normalise_all=true"
        ),
        "{stderr}"
    );
    let on = continuous(&body);
    assert_eq!(
        on["description"],
        "continuous normalisation while serve runs"
    );
    assert_eq!(
        on["value"],
        "every 60 minutes: every saved target, re-normalised only"
    );

    let (_, stderr, body) = startup_asking(
        "127.0.0.1:0",
        &[("HOME", env!("CARGO_TARGET_TMPDIR")), ("PREFIX", "/usr")],
        "/api/settings",
        header,
    );
    assert!(!stderr.contains("continuous:"), "{stderr}");
    assert_eq!(
        continuous(&body)["value"],
        "off (set HUNTSMAN_CONTINUOUS_TARGETS in ~/.huntsman.env or the environment)"
    );

    let out = serve(
        &["--bind", "127.0.0.1:0"],
        &[
            ("HOME", env!("CARGO_TARGET_TMPDIR")),
            ("HUNTSMAN_CONTINUOUS_TARGETS", "*"),
            ("HUNTSMAN_CONTINUOUS_INTERVAL_MINUTES", "5"),
        ],
    )
    .output()
    .unwrap();
    assert_eq!(out.status.code(), Some(i32::from(EX_DATAERR)));
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        "",
        "serve must refuse before it announces an address"
    );
    assert_eq!(
        String::from_utf8_lossy(&out.stderr),
        "continuous: HUNTSMAN_CONTINUOUS_INTERVAL_MINUTES must be 60..=10080\n"
    );
    let _ = fs::remove_dir_all(&home);
}
