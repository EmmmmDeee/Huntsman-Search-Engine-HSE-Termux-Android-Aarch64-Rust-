use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

const DEFAULT_MAIN_REV: &str = "0123456789abcdef0123456789abcdef01234567";
static SCRATCH_SEQ: AtomicU64 = AtomicU64::new(0);

fn scratch() -> PathBuf {
    let seq = SCRATCH_SEQ.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "huntsman-root-installer-{}-{seq}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn write_executable(path: &Path, body: &str) {
    fs::write(path, body).unwrap();
    let mut permissions = fs::metadata(path).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(path, permissions).unwrap();
}

fn install_fake_termux_toolchain(fake_bin: &Path, fake_target_libdir: &Path) {
    fs::create_dir_all(fake_bin).unwrap();
    fs::create_dir_all(fake_target_libdir).unwrap();
    fs::write(fake_target_libdir.join("libstd-test.rlib"), b"fixture").unwrap();

    write_executable(
        &fake_bin.join("uname"),
        "#!/bin/sh\nprintf '%s\\n' aarch64\n",
    );
    write_executable(
        &fake_bin.join("timeout"),
        "#!/bin/sh\nprintf 'timeout %s\\n' \"$*\" >> \"$INSTALL_LOG\"\nexit 0\n",
    );
    write_executable(
        &fake_bin.join("pkg"),
        "#!/bin/sh\nprintf 'pkg %s\\n' \"$*\" >> \"$INSTALL_LOG\"\n",
    );
    write_executable(
        &fake_bin.join("git"),
        r#"#!/bin/sh
printf 'git %s\n' "$*" >> "$INSTALL_LOG"
if [ "$1" = 'ls-remote' ]; then
  printf '%s\t%s\n' "${FAKE_MAIN_REV:-0123456789abcdef0123456789abcdef01234567}" 'refs/heads/main'
  exit 0
fi
exit 2
"#,
    );
    write_executable(
        &fake_bin.join("dpkg-query"),
        "#!/bin/sh\nprintf 'dpkg-query %s\\n' \"$*\" >> \"$INSTALL_LOG\"\nprintf '%s' '1.98.0-1'\n",
    );
    write_executable(
        &fake_bin.join("rustc"),
        r#"#!/bin/sh
case "$1" in
  -vV)
    printf '%s\n' 'rustc 1.98.0 (fixture)' 'binary: rustc' 'commit-hash: fixture' 'commit-date: 2026-10-05' 'host: aarch64-linux-android' 'release: 1.98.0'
    ;;
  --print)
    if [ "${2:-}" = "target-libdir" ]; then
      printf '%s\n' "$FAKE_RUST_TARGET_LIBDIR"
    else
      exit 2
    fi
    ;;
  --version)
    printf '%s\n' 'rustc 1.98.0 (fixture)'
    ;;
  *)
    out=''
    while [ "$#" -gt 0 ]; do
      if [ "$1" = '-o' ]; then
        shift
        out="${1:-}"
        break
      fi
      shift
    done
    [ -n "$out" ] || exit 2
    cat > "$out" <<'PROBE'
#!/bin/sh
printf '%s\n' 'huntsman-rust-toolchain-ok'
PROBE
    chmod +x "$out"
    ;;
esac
"#,
    );
    write_executable(
        &fake_bin.join("cargo"),
        "#!/bin/sh\nprintf 'hibp=%s target=%s cargo %s\\n' \"${HUNTSMAN_HIBP_NO_EMBED:-}\" \"${CARGO_TARGET_DIR:-}\" \"$*\" >> \"$INSTALL_LOG\"\n",
    );
}

fn assert_first_install_contract(calls: &str, temp: &Path, prefix: &Path, rev: &str) {
    assert!(calls.contains("pkg update -y"), "{calls}");
    assert!(
        calls.contains("pkg install -y git rust clang curl coreutils"),
        "{calls}"
    );
    assert!(
        calls.contains("pkg install -y rust rust-std-aarch64-linux-android"),
        "{calls}"
    );
    assert!(
        calls.contains("dpkg-query -W -f=${Version} rust"),
        "{calls}"
    );
    assert!(
        calls.contains("dpkg-query -W -f=${Version} rust-std-aarch64-linux-android"),
        "{calls}"
    );
    assert!(
        calls.contains(
            "cargo install --git https://github.com/EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-.git"
        ),
        "{calls}"
    );
    assert!(calls.contains(&format!("--rev {rev}")), "{calls}");
    assert!(calls.contains("--locked"), "{calls}");
    assert!(
        calls.contains(&format!("--root {}", prefix.display())),
        "{calls}"
    );
    assert!(
        !calls.contains("--force"),
        "repeat installs must not force a rebuild: {calls}"
    );
    assert!(calls.contains("hibp=1"), "{calls}");
    assert!(
        calls.contains(&format!(
            "target={}/.cache/huntsman-recon-target",
            temp.display()
        )),
        "default build cache must persist across installer invocations: {calls}"
    );
    assert!(
        calls.contains(&format!(
            "timeout 30 {}/bin/huntsman-recon check",
            prefix.display()
        )),
        "installer must runtime-check the installed binary: {calls}"
    );
    assert!(
        calls.contains(&format!(
            "timeout 30 {}/bin/huntsman-recon verify var/ledger.json",
            prefix.display()
        )),
        "installer must verify the generated ledger before success: {calls}"
    );
}

fn assert_private_state(temp: &Path, expected_rev: &str) {
    let state_dir = temp.join(".huntsman");
    let env_file = temp.join(".huntsman.env");
    let provenance = state_dir.join("installed-revision");
    assert!(state_dir.is_dir(), "installer must initialize ~/.huntsman");
    assert!(
        env_file.is_file(),
        "installer must initialize ~/.huntsman.env"
    );
    assert_eq!(
        fs::metadata(&env_file).unwrap().permissions().mode() & 0o777,
        0o600,
        "~/.huntsman.env must remain private"
    );
    assert!(
        provenance.is_file(),
        "installer must record accepted revision"
    );
    assert_eq!(
        fs::metadata(&provenance).unwrap().permissions().mode() & 0o777,
        0o600,
        "installed revision provenance must remain private"
    );
    let body = fs::read_to_string(&provenance).unwrap();
    assert!(
        body.contains(&format!("revision={expected_rev}\n")),
        "provenance must bind the accepted revision: {body}"
    );
}

#[test]
fn root_installer_builds_huntsman_recon_and_forwards_an_optional_revision() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let installer = root.join("install.sh");
    assert!(installer.is_file(), "root install.sh must exist");

    let temp = scratch();
    let prefix = PathBuf::from("/data/data/com.termux/files/usr");
    let fake_bin = temp.join("fake-bin");
    let fake_target_libdir = temp.join("rustlib");
    let log = temp.join("install.log");
    let tmpdir = temp.join("tmp");
    fs::create_dir_all(&tmpdir).unwrap();
    install_fake_termux_toolchain(&fake_bin, &fake_target_libdir);

    let existing_path = std::env::var("PATH").unwrap_or_default();
    let path = format!("{}:{existing_path}", fake_bin.display());
    let rev = "b2731d117009a841c302a124f38a808d36f6eac7";
    let output = Command::new("bash")
        .arg(&installer)
        .env("PATH", path)
        .env("PREFIX", &prefix)
        .env("INSTALL_LOG", &log)
        .env("FAKE_RUST_TARGET_LIBDIR", &fake_target_libdir)
        .env("HUNTSMAN_REV", rev)
        .env("HOME", &temp)
        .env("TMPDIR", &tmpdir)
        .env_remove("CARGO_TARGET_DIR")
        .output()
        .expect("root installer must execute under bash");

    assert!(
        output.status.success(),
        "installer failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let calls = fs::read_to_string(&log).expect("fake installer log");
    assert_first_install_contract(&calls, &temp, &prefix, rev);
    assert_private_state(&temp, rev);

    let custom_cache = temp.join("custom-cache");
    let second = Command::new("bash")
        .arg(&installer)
        .env("PATH", format!("{}:{existing_path}", fake_bin.display()))
        .env("PREFIX", &prefix)
        .env("INSTALL_LOG", &log)
        .env("FAKE_RUST_TARGET_LIBDIR", &fake_target_libdir)
        .env("CARGO_TARGET_DIR", &custom_cache)
        .env("HOME", &temp)
        .env("TMPDIR", &tmpdir)
        .output()
        .expect("repeat installer must execute");
    assert!(second.status.success(), "repeat installer failed");
    let calls = fs::read_to_string(&log).unwrap();
    assert!(
        calls.contains(&format!("target={}", custom_cache.display())),
        "caller-selected cache must be preserved: {calls}"
    );
    assert!(
        calls.contains("git ls-remote --exit-code https://github.com/EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-.git refs/heads/main"),
        "moving main must be resolved exactly once before Cargo: {calls}"
    );
    assert!(
        calls.contains(&format!("--rev {DEFAULT_MAIN_REV}")),
        "default installs must pin Cargo to the resolved main revision: {calls}"
    );
    assert_private_state(&temp, DEFAULT_MAIN_REV);

    let _ = fs::remove_dir_all(&temp);
}

#[test]
fn legacy_hse_update_contract_routes_to_legacy_channel_without_building_recon() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let installer = root.join("install.sh");
    let temp = scratch();
    let prefix = PathBuf::from("/data/data/com.termux/files/usr");
    let fake_bin = temp.join("fake-bin");
    let fake_target_libdir = temp.join("rustlib");
    let log = temp.join("install.log");
    let tmpdir = temp.join("tmp");
    fs::create_dir_all(&tmpdir).unwrap();
    install_fake_termux_toolchain(&fake_bin, &fake_target_libdir);

    let compat = temp.join("legacy-channel.sh");
    write_executable(
        &compat,
        "#!/bin/sh\nprintf 'compat ref=%s require=%s\\n' \"${HSE_REF:-unset}\" \"${HSE_REQUIRE_SHA:-unset}\" >> \"$INSTALL_LOG\"\nexit 0\n",
    );

    let existing_path = std::env::var("PATH").unwrap_or_default();
    let output = Command::new("bash")
        .arg(&installer)
        .env("PATH", format!("{}:{existing_path}", fake_bin.display()))
        .env("PREFIX", &prefix)
        .env("INSTALL_LOG", &log)
        .env("FAKE_RUST_TARGET_LIBDIR", &fake_target_libdir)
        .env("HOME", &temp)
        .env("TMPDIR", &tmpdir)
        .env("HSE_REQUIRE_SHA", DEFAULT_MAIN_REV)
        .env("HUNTSMAN_LEGACY_CHANNEL_INSTALLER", &compat)
        .env_remove("HUNTSMAN_REV")
        .output()
        .expect("legacy compatibility route must execute");

    assert!(
        output.status.success(),
        "legacy compatibility route failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let calls = fs::read_to_string(&log).unwrap();
    assert!(
        calls.contains("compat ref=legacy-hse require=unset"),
        "{calls}"
    );
    assert!(
        !calls.contains("cargo install"),
        "must not install recon: {calls}"
    );
    assert!(
        !calls.contains("pkg "),
        "legacy handoff must happen before recon package/toolchain setup: {calls}"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("huntsman-recon was not substituted for hse"),
        "{stdout}"
    );

    let _ = fs::remove_dir_all(&temp);
}

#[test]
fn legacy_hse_parent_without_ref_routes_before_recon_install() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let installer = root.join("install.sh");
    let temp = scratch();
    let prefix = PathBuf::from("/data/data/com.termux/files/usr");
    let fake_bin = temp.join("fake-bin");
    let fake_target_libdir = temp.join("rustlib");
    let log = temp.join("install.log");
    let tmpdir = temp.join("tmp");
    let proc_root = temp.join("proc");
    fs::create_dir_all(&tmpdir).unwrap();
    fs::create_dir_all(proc_root.join("100")).unwrap();
    fs::write(proc_root.join("100/status"), "Name:\thse\nPPid:\t1\n").unwrap();
    fs::write(proc_root.join("100/cmdline"), b"hse\0update\0").unwrap();
    install_fake_termux_toolchain(&fake_bin, &fake_target_libdir);

    let compat = temp.join("legacy-channel.sh");
    write_executable(
        &compat,
        "#!/bin/sh\nprintf 'compat ref=%s require=%s\\n' \"${HSE_REF:-unset}\" \"${HSE_REQUIRE_SHA:-unset}\" >> \"$INSTALL_LOG\"\nexit 0\n",
    );

    let existing_path = std::env::var("PATH").unwrap_or_default();
    let output = Command::new("bash")
        .arg(&installer)
        .env("PATH", format!("{}:{existing_path}", fake_bin.display()))
        .env("PREFIX", &prefix)
        .env("INSTALL_LOG", &log)
        .env("FAKE_RUST_TARGET_LIBDIR", &fake_target_libdir)
        .env("HOME", &temp)
        .env("TMPDIR", &tmpdir)
        .env("HUNTSMAN_PROC_ROOT", &proc_root)
        .env("HUNTSMAN_LEGACY_CALLER", "hse")
        .env("HUNTSMAN_LEGACY_CHANNEL_INSTALLER", &compat)
        .env_remove("HUNTSMAN_REV")
        .env_remove("HSE_REF")
        .env_remove("HSE_REQUIRE_SHA")
        .output()
        .expect("parent hse route must execute");

    assert!(
        output.status.success(),
        "parent hse route failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let calls = fs::read_to_string(&log).unwrap();
    assert!(
        calls.contains("compat ref=legacy-hse require=unset"),
        "{calls}"
    );
    assert!(
        !calls.contains("cargo install"),
        "must not install recon: {calls}"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("huntsman-recon was not substituted for hse"),
        "{stdout}"
    );

    let _ = fs::remove_dir_all(&temp);
}

#[test]
fn legacy_download_is_removed_on_failure_and_on_success() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let installer = root.join("install.sh");
    let temp = scratch();
    let prefix = PathBuf::from("/data/data/com.termux/files/usr");
    let fake_bin = temp.join("fake-bin");
    let fake_target_libdir = temp.join("rustlib");
    let log = temp.join("install.log");
    let tmpdir = temp.join("tmp");
    fs::create_dir_all(&tmpdir).unwrap();
    install_fake_termux_toolchain(&fake_bin, &fake_target_libdir);
    // The fake curl writes FAKE_CURL_BODY to the -o target and exits with FAKE_CURL_STATUS.
    write_executable(
        &fake_bin.join("curl"),
        r#"#!/bin/sh
out=''
while [ $# -gt 0 ]; do
  if [ "$1" = '-o' ]; then shift; out="$1"; fi
  shift
done
printf '%s' "$FAKE_CURL_BODY" > "$out"
exit "${FAKE_CURL_STATUS:-0}"
"#,
    );
    let existing_path = std::env::var("PATH").unwrap_or_default();
    let run = |status: &str, body: &str| {
        Command::new("bash")
            .arg(&installer)
            .env("PATH", format!("{}:{existing_path}", fake_bin.display()))
            .env("PREFIX", &prefix)
            .env("INSTALL_LOG", &log)
            .env("FAKE_RUST_TARGET_LIBDIR", &fake_target_libdir)
            .env("HOME", &temp)
            .env("TMPDIR", &tmpdir)
            .env("HSE_REF", "legacy-hse")
            .env("FAKE_CURL_STATUS", status)
            .env("FAKE_CURL_BODY", body)
            .env_remove("HUNTSMAN_REV")
            .env_remove("HUNTSMAN_LEGACY_CHANNEL_INSTALLER")
            .output()
            .expect("legacy download route must execute")
    };
    let leftovers = || -> Vec<String> {
        fs::read_dir(&tmpdir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|name| name.starts_with("huntsman-legacy-install."))
            .collect()
    };

    // A dropped download must fail the install and leave no partial installer behind.
    let failed = run("22", "partial download");
    assert!(
        !failed.status.success(),
        "a failed download must fail the installer:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&failed.stdout),
        String::from_utf8_lossy(&failed.stderr)
    );
    assert!(
        leftovers().is_empty(),
        "a failed legacy download left a partial installer behind: {:?}",
        leftovers()
    );

    // A completed download runs the handoff and is also removed afterwards.
    let body = "#!/bin/sh\nprintf 'legacy-channel-ok\\n' >> \"$INSTALL_LOG\"\n";
    let succeeded = run("0", body);
    assert!(
        succeeded.status.success(),
        "a completed legacy download must install:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&succeeded.stdout),
        String::from_utf8_lossy(&succeeded.stderr)
    );
    assert!(
        fs::read_to_string(&log)
            .unwrap()
            .contains("legacy-channel-ok")
    );
    assert!(
        leftovers().is_empty(),
        "a completed legacy download left its installer behind: {:?}",
        leftovers()
    );

    let _ = fs::remove_dir_all(&temp);
}

#[test]
fn install_doc_upgrades_termux_by_rerunning_the_installer() {
    let doc = fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/INSTALL.md"))
        .expect("docs/INSTALL.md must exist");
    let termux = doc
        .split("## Termux on Android arm64")
        .nth(1)
        .and_then(|rest| rest.split("\n## ").next())
        .expect("docs/INSTALL.md must keep its Termux section");
    assert!(
        termux.contains("Upgrade by running the same two commands again"),
        "re-running install.sh is the Termux upgrade: it pins main and repeats acceptance"
    );
    assert!(
        !termux.contains("`cargo install` command again"),
        "a bare cargo install skips the installer's --root, acceptance and provenance"
    );
}

#[test]
fn install_doc_uninstall_removes_every_path_the_installer_creates() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let installer = fs::read_to_string(root.join("install.sh")).unwrap();
    let doc = fs::read_to_string(root.join("docs/INSTALL.md")).unwrap();
    let uninstall = doc
        .split("## Uninstall from Termux")
        .nth(1)
        .and_then(|rest| rest.split("\n## ").next())
        .expect("docs/INSTALL.md must have an \"Uninstall from Termux\" section");
    assert!(
        uninstall.contains("cargo uninstall --root \"$PREFIX\" huntsman-recon"),
        "install.sh installs with `cargo install --root \"$PREFIX\"`, so Cargo must uninstall it"
    );
    for var in ["HUNTSMAN_HOME", "HUNTSMAN_ENV_FILE", "CARGO_TARGET_DIR"] {
        let marker = format!("${{{var}:-$HOME/");
        let start = installer
            .find(&marker)
            .unwrap_or_else(|| panic!("install.sh must default {var} under $HOME"))
            + marker.len();
        let end = start + installer[start..].find('}').unwrap();
        let path = format!("~/{}", &installer[start..end]);
        let named = uninstall.match_indices(path.as_str()).any(|(at, _)| {
            !uninstall[at + path.len()..]
                .starts_with(|c: char| c.is_alphanumeric() || matches!(c, '.' | '-' | '_'))
        });
        assert!(
            named,
            "the uninstall steps must remove {path}, which install.sh creates ({var})"
        );
    }
}
