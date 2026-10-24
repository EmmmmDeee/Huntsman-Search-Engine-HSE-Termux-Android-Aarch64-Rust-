//! `scripts/termux/huntsman`, the command install.sh installs as `$PREFIX/bin/huntsman`, run
//! against a fake `huntsman-recon` and a fake runit `sv`, so each behaviour is checked without a
//! phone.

use std::fmt::Write as _;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

static SEQ: AtomicU64 = AtomicU64::new(0);

/// `doctor serve --bind ADDR` answers the state `FAKE_PORTS` lists for ADDR (`not_running` if none);
/// `scan --save FILE` writes a one-entry ledger with an email in it; `verify` fails on FORGED.
const FAKE_RECON: &str = r#"#!/bin/sh
printf 'recon %s\n' "$*" >> "$LOG"
case "$1" in
  doctor)
    state="$(grep "^$4 " "$FAKE_PORTS" 2>/dev/null | tail -n 1 | cut -d' ' -f2)"
    echo "serve=${state:-not_running} addr=$4 version=0.2.0 ms=1"
    [ "${state:-}" = healthy ]
    ;;
  scan)
    while [ $# -gt 0 ]; do
      if [ "$1" = --save ]; then
        shift
        printf '[{"prev":"00","hash":"abc123","claim":{"claim":"alice@example.com registered","source":"gravatar","technique_id":null,"status":"verified"}}]' > "$1"
      fi
      shift
    done
    ;;
  verify)
    if grep -q FORGED "$2"; then echo "invalid input: ledger chain broken" >&2; exit 65; fi
    echo "entries=1"; echo "tip=abc123"
    ;;
  state-dir) echo "HUNTSMAN_HOME=${HUNTSMAN_HOME:-unset}" ;;
  *) echo "recon passthrough: $*" ;;
esac
"#;

/// runit's `sv`: the service is up or down per `$SV_STATE`; bringing it up marks its bind
/// address healthy, as the real server would be.
const FAKE_SV: &str = r#"#!/bin/sh
printf 'sv %s\n' "$*" >> "$LOG"
case "$1" in
  status)
    if [ "$(cat "$SV_STATE" 2>/dev/null)" = up ]; then echo "run: $2: (pid $$) 3s"; else echo "down: $2: 9s"; fi
    ;;
  up|restart)
    echo up > "$SV_STATE"
    bind="$(head -n 1 "$HUNTSMAN_HOME/serve.bind" 2>/dev/null)"
    echo "${bind:-127.0.0.1:8080} healthy" >> "$FAKE_PORTS"
    ;;
  down) echo down > "$SV_STATE" ;;
esac
"#;

struct Phone {
    dir: PathBuf,
}

impl Phone {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!(
            "huntsman-controller-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&dir);
        for sub in [
            "bin",
            "home/.huntsman",
            "service/huntsman-serve",
            "prefix/tmp",
        ] {
            fs::create_dir_all(dir.join(sub)).unwrap();
        }
        let phone = Self { dir };
        phone.executable("bin/huntsman-recon", FAKE_RECON);
        phone.executable("bin/sv", FAKE_SV);
        phone.executable("bin/service-daemon", "#!/bin/sh\nexit 0\n");
        fs::write(phone.path("service/huntsman-serve/run"), "#!/bin/sh\n").unwrap();
        phone
    }

    fn path(&self, rel: &str) -> PathBuf {
        self.dir.join(rel)
    }

    fn executable(&self, rel: &str, body: &str) {
        fs::write(self.path(rel), body).unwrap();
        fs::set_permissions(self.path(rel), fs::Permissions::from_mode(0o755)).unwrap();
    }

    fn mark(&self, addr: &str, state: &str) {
        let ports = self.path("ports");
        let mut text = fs::read_to_string(&ports).unwrap_or_default();
        writeln!(text, "{addr} {state}").unwrap();
        fs::write(ports, text).unwrap();
    }

    fn run(&self, args: &[&str]) -> Output {
        self.run_with_home(args, Some(&self.path("home/.huntsman")))
    }

    /// [`Self::run`] with `HUNTSMAN_HOME` set to `home`, or left out of the environment.
    fn run_with_home(&self, args: &[&str], home: Option<&Path>) -> Output {
        let path = format!(
            "{}:{}",
            self.path("bin").display(),
            std::env::var("PATH").unwrap_or_default()
        );
        let mut command = Command::new("bash");
        match home {
            Some(home) => command.env("HUNTSMAN_HOME", home),
            None => command.env_remove("HUNTSMAN_HOME"),
        };
        command
            .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/termux/huntsman"))
            .args(args)
            .current_dir(&self.dir)
            .env("PATH", path)
            .env("HOME", self.path("home"))
            .env("PREFIX", self.path("prefix"))
            .env("TMPDIR", self.path("prefix/tmp"))
            .env("SVDIR", self.path("service"))
            .env("HUNTSMAN_START_TIMEOUT", "2")
            .env("LOG", self.path("log"))
            .env("FAKE_PORTS", self.path("ports"))
            .env("SV_STATE", self.path("sv-state"))
            .env_remove("HUNTSMAN_RECON")
            .env_remove("HUNTSMAN_REPORTS")
            .env_remove("CARGO_TARGET_DIR")
            .output()
            .expect("controller runs under bash")
    }

    fn log(&self) -> String {
        fs::read_to_string(self.path("log")).unwrap_or_default()
    }
}

impl Drop for Phone {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

fn text(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

#[test]
fn start_brings_the_service_up_and_waits_until_the_page_works() {
    let phone = Phone::new();
    fs::write(phone.path("service/huntsman-serve/down"), "").unwrap();
    let out = phone.run(&["start"]);
    assert!(out.status.success(), "{}", text(&out));
    assert!(
        text(&out).contains("web UI running: http://127.0.0.1:8080/ (restarts automatically)"),
        "{}",
        text(&out)
    );
    assert!(!phone.path("service/huntsman-serve/down").exists());
    assert!(
        phone
            .log()
            .contains("recon doctor serve --bind 127.0.0.1:8080")
    );

    let out = phone.run(&["status"]);
    assert!(out.status.success(), "{}", text(&out));
    assert!(
        text(&out).contains("web UI: RUNNING (healthy)"),
        "{}",
        text(&out)
    );

    let out = phone.run(&["stop"]);
    assert!(out.status.success(), "{}", text(&out));
    assert!(
        phone.path("service/huntsman-serve/down").exists(),
        "stop survives a reboot"
    );
    let out = phone.run(&["status"]);
    assert!(!out.status.success());
    assert!(text(&out).contains("web UI: STOPPED"), "{}", text(&out));
}

#[test]
fn a_taken_port_moves_the_web_ui_to_the_next_free_one_and_back() {
    let phone = Phone::new();
    phone.mark("127.0.0.1:8080", "foreign");
    let out = phone.run(&["start"]);
    assert!(out.status.success(), "{}", text(&out));
    assert!(
        text(&out).contains("127.0.0.1:8080 is taken by another program; using 127.0.0.1:8081"),
        "{}",
        text(&out)
    );
    assert_eq!(
        fs::read_to_string(phone.path("home/.huntsman/serve.bind")).unwrap(),
        "127.0.0.1:8081\n",
        "the service's run script binds what this file says"
    );

    // Whatever held 8080 is gone: the next start returns to it.
    phone.run(&["stop"]);
    phone.mark("127.0.0.1:8080", "not_running");
    let out = phone.run(&["start"]);
    assert!(out.status.success(), "{}", text(&out));
    assert!(!phone.path("home/.huntsman/serve.bind").exists());
    assert!(
        text(&out).contains("http://127.0.0.1:8080/"),
        "{}",
        text(&out)
    );
}

#[test]
fn start_takes_over_from_a_server_the_old_nohup_controller_left_running() {
    let phone = Phone::new();
    let mut old = Command::new("bash")
        .args(["-c", "exec -a 'huntsman-recon serve' sleep 300"])
        .spawn()
        .unwrap();
    fs::write(
        phone.path("home/.huntsman/daemon.pid"),
        format!("{}\n", old.id()),
    )
    .unwrap();
    fs::write(phone.path("home/.huntsman/daemon.port"), "8080\n").unwrap();

    let out = phone.run(&["start"]);
    assert!(out.status.success(), "{}", text(&out));
    assert!(
        text(&out).contains(&format!(
            "stopped the server the old controller started (pid {})",
            old.id()
        )),
        "{}",
        text(&out)
    );
    assert!(
        old.wait().map(|status| !status.success()).unwrap(),
        "the old server was stopped"
    );
    assert!(!phone.path("home/.huntsman/daemon.pid").exists());
    assert!(!phone.path("home/.huntsman/daemon.port").exists());
}

#[test]
fn a_page_that_never_works_fails_start_with_the_reason() {
    let phone = Phone::new();
    phone.executable(
        "bin/sv",
        "#!/bin/sh\n[ \"$1\" = status ] && echo \"run: $2: (pid 7) 1s\"\nexit 0\n",
    );
    phone.mark("127.0.0.1:8080", "degraded");
    let out = phone.run(&["restart"]);
    assert!(!out.status.success());
    assert!(
        text(&out).contains("web UI not answering at 127.0.0.1:8080 (degraded)"),
        "{}",
        text(&out)
    );
}

#[test]
fn scan_pipe_saves_verifies_and_reports_the_full_ledger() {
    let phone = Phone::new();
    let out = phone.run(&["scan-pipe", "alice@example.com"]);
    assert!(out.status.success(), "{}", text(&out));
    assert!(
        phone.log().contains("recon scan alice@example.com --save "),
        "no kind given, so scan picks it: {}",
        phone.log()
    );
    let reports = phone.path("home/huntsman-reports");
    let mut names: Vec<_> = fs::read_dir(&reports)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    assert_eq!(names.len(), 2, "{names:?}");
    assert!(
        names[0].starts_with("alice@example.com_")
            && Path::new(&names[0])
                .extension()
                .is_some_and(|e| e == "json")
    );
    let md = fs::read_to_string(reports.join(&names[1])).unwrap();
    let ledger = fs::read_to_string(reports.join(&names[0])).unwrap();
    assert!(
        md.contains(&ledger),
        "the report carries the ledger as saved"
    );
    assert!(
        md.contains("alice@example.com registered"),
        "unredacted: {md}"
    );
    assert!(
        md.contains("- Ledger check: verified (entries=1 tip=abc123)"),
        "{md}"
    );

    // A ledger that fails verification is reported as such, and the command fails.
    let forged = reports.join("forged.json");
    fs::write(&forged, ledger.replace("registered", "FORGED")).unwrap();
    let out = phone.run(&["report", forged.to_str().unwrap()]);
    assert!(!out.status.success());
    let md = fs::read_to_string(reports.join("forged.md")).unwrap();
    assert!(
        md.contains("- Ledger check: FAILED: invalid input: ledger chain broken"),
        "{md}"
    );

    let out = phone.run(&["scan-pipe", "example.com", "domain"]);
    assert!(out.status.success(), "{}", text(&out));
    assert!(
        phone
            .log()
            .contains("recon scan example.com -k domain --save ")
    );
}

#[test]
fn scan_pipe_never_replaces_an_earlier_ledger_even_with_the_same_timestamp() {
    let phone = Phone::new();
    // Fix the clock so the old timestamp-only naming scheme demonstrably collides.
    phone.executable("bin/date", "#!/bin/sh\nprintf '20261021_004500\\n'\n");
    let long_target = format!("{}{}", "é".repeat(200), "a".repeat(200));
    for target in [
        "alice@example.com",
        "alice@example.com",
        long_target.as_str(),
    ] {
        let out = phone.run(&["scan-pipe", target]);
        assert!(out.status.success(), "{}", text(&out));
    }

    let reports = phone.path("home/huntsman-reports");
    let permissions = fs::metadata(&reports).unwrap().permissions().mode() & 0o777;
    assert_eq!(permissions, 0o700, "report directory must be private");
    let mut json_paths = Vec::new();
    let mut md_paths = Vec::new();
    for entry in fs::read_dir(&reports).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_string_lossy();
        assert!(name.len() <= 255, "overlong filename: {name}");
        let permissions = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(permissions & 0o077, 0, "{name} must be private");
        match path.extension().and_then(|extension| extension.to_str()) {
            Some("json") => json_paths.push(path),
            Some("md") => md_paths.push(path),
            other => panic!("unexpected report extension: {other:?}"),
        }
    }
    assert_eq!(json_paths.len(), 3, "each invocation gets its own ledger");
    assert_eq!(md_paths.len(), 3, "each ledger gets its own report");

    let duplicates = json_paths
        .iter()
        .filter(|path| {
            path.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("alice@example.com_")
        })
        .count();
    assert_eq!(
        duplicates, 2,
        "identical inputs at one timestamp must not collide"
    );
    for ledger in json_paths {
        let body = fs::read_to_string(&ledger).unwrap();
        assert!(body.contains("alice@example.com registered"), "{ledger:?}");
        let report = fs::read_to_string(ledger.with_extension("md")).unwrap();
        assert!(
            report.contains(&body),
            "the report lost evidence for {ledger:?}"
        );
        assert!(report.contains("Ledger check: verified"), "{report}");
    }
}

/// install.sh writes the state directory it chose into the service's run script. A shell without
/// `HUNTSMAN_HOME` drives the same service: `start` writes serve.bind where the run script reads
/// it, and every command passed on to huntsman-recon reads the scan store the service keeps. An
/// exported `HUNTSMAN_HOME` still wins, as it does for huntsman-recon itself.
#[test]
fn the_state_dir_the_installer_chose_reaches_start_and_every_forwarded_command() {
    let phone = Phone::new();
    let hunt = phone.path("home/hunt");
    fs::write(
        phone.path("service/huntsman-serve/run"),
        format!(
            "#!/bin/sh\nexport HUNTSMAN_HOME='{}'\nexec huntsman-recon serve\n",
            hunt.display()
        ),
    )
    .unwrap();
    phone.mark("127.0.0.1:8080", "foreign");
    let out = phone.run_with_home(&["start"], None);
    assert!(out.status.success(), "{}", text(&out));
    assert_eq!(
        fs::read_to_string(hunt.join("serve.bind")).unwrap(),
        "127.0.0.1:8081\n",
        "serve.bind lands where the service's run script reads it"
    );
    assert!(!phone.path("home/.huntsman/serve.bind").exists());
    let out = phone.run_with_home(&["state-dir"], None);
    assert!(
        text(&out).contains(&format!("HUNTSMAN_HOME={}", hunt.display())),
        "{}",
        text(&out)
    );
    let out = phone.run(&["state-dir"]);
    assert!(
        text(&out).contains(&format!(
            "HUNTSMAN_HOME={}",
            phone.path("home/.huntsman").display()
        )),
        "{}",
        text(&out)
    );
    // A run script from an earlier installer, without the export: ~/.huntsman, as before.
    fs::write(phone.path("service/huntsman-serve/run"), "#!/bin/sh\n").unwrap();
    let out = phone.run_with_home(&["state-dir"], None);
    assert!(
        text(&out).contains(&format!(
            "HUNTSMAN_HOME={}",
            phone.path("home/.huntsman").display()
        )),
        "{}",
        text(&out)
    );
}

#[test]
fn other_commands_go_to_huntsman_recon_unchanged() {
    let phone = Phone::new();
    let out = phone.run(&["email", "alice@example.com", "--save", "x.json"]);
    assert!(out.status.success(), "{}", text(&out));
    assert!(
        text(&out).contains("recon passthrough: email alice@example.com --save x.json"),
        "{}",
        text(&out)
    );
    let out = phone.run(&["help"]);
    assert!(out.status.success());
    for line in [
        "huntsman start | stop | restart | status | logs",
        "huntsman scan-pipe TARGET [KIND]",
    ] {
        assert!(text(&out).contains(line), "{}", text(&out));
    }
}

#[test]
fn the_shortcuts_never_export_keys_and_only_load_in_interactive_shells() {
    let profile = fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/termux/huntsman-profile.sh"),
    )
    .unwrap();
    assert!(
        !profile.contains("huntsman.env\""),
        "huntsman-recon reads the keys file itself"
    );
    assert!(!profile.contains("export "), "{profile}");
    let out = Command::new("bash")
        .args([
            "-c",
            "source \"$0\"; type h >/dev/null 2>&1 && echo loaded || echo skipped",
        ])
        .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/termux/huntsman-profile.sh"))
        .output()
        .unwrap();
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "skipped");
}

/// What an earlier installer wrote to `serve.token` before the web UI stopped asking for one.
const OLD_TOKEN: &str = "5f0c8e4a9b7d6c3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d9e";

/// The page needs no token on the phone (Matt, 2026-10-14: "remove these weird token
/// requirements"), so `open` opens the plain address, even with a token file left behind by an
/// earlier install, and the health check sends nothing.
#[test]
fn open_opens_the_plain_page_and_a_left_over_token_changes_nothing() {
    let phone = Phone::new();
    fs::write(
        phone.path("home/.huntsman/serve.token"),
        format!("{OLD_TOKEN}\n"),
    )
    .unwrap();
    phone.executable(
        "bin/termux-open-url",
        "#!/bin/sh\nprintf 'open %s\\n' \"$1\" >> \"$LOG\"\n",
    );

    let out = phone.run(&["start"]);
    assert!(out.status.success(), "{}", text(&out));
    let out = phone.run(&["status"]);
    assert!(
        text(&out).contains("web UI: RUNNING (healthy)"),
        "{}",
        text(&out)
    );

    let out = phone.run(&["open"]);
    assert!(out.status.success(), "{}", text(&out));
    assert!(
        phone
            .log()
            .lines()
            .any(|line| line == "open http://127.0.0.1:8080/"),
        "{}",
        phone.log()
    );
    assert!(!phone.log().contains("token"), "{}", phone.log());
    assert!(
        text(&out)
            .trim_end()
            .ends_with("opened http://127.0.0.1:8080/"),
        "{}",
        text(&out)
    );
}

#[test]
fn a_port_held_by_a_server_that_asks_for_a_token_counts_as_taken() {
    let phone = Phone::new();
    // A Huntsman server outside runit that wants a token: not this service's server.
    phone.mark("127.0.0.1:8080", "unauthorized");
    let out = phone.run(&["start"]);
    assert!(out.status.success(), "{}", text(&out));
    assert!(
        text(&out).contains("127.0.0.1:8080 is taken by another program; using 127.0.0.1:8081"),
        "{}",
        text(&out)
    );
}

#[test]
fn open_without_termux_api_says_where_the_page_is() {
    let phone = Phone::new();
    let out = phone.run(&["open"]);
    assert!(!out.status.success());
    assert!(
        text(&out).contains("open http://127.0.0.1:8080/ in the browser"),
        "{}",
        text(&out)
    );
    assert!(!text(&out).contains("token"), "{}", text(&out));
}
