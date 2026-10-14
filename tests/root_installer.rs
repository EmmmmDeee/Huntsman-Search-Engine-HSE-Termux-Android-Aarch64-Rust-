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
        // `build-sha` answers with what the fake cargo embedded, as the real binary would.
        r#"#!/bin/sh
printf 'timeout %s\n' "$*" >> "$INSTALL_LOG"
case "$*" in
  *' build-sha') cat "$INSTALL_LOG.build-sha" 2>/dev/null || printf '%s\n' unknown ;;
esac
exit 0
"#,
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
        r#"#!/bin/sh
printf 'hibp=%s target=%s cargo %s\n' "${HUNTSMAN_HIBP_NO_EMBED:-}" "${CARGO_TARGET_DIR:-}" "$*" >> "$INSTALL_LOG"
printf '%s\n' "${HUNTSMAN_BUILD_SHA:-unknown}" > "$INSTALL_LOG.build-sha"
"#,
    );
    install_fake_github(fake_bin);
}

fn install_fake_github(fake_bin: &Path) {
    // GitHub, offline: a release asset is served from FAKE_RELEASE_DIR/<tag>/<name> and
    // `commits/main~N` answers line N of FAKE_MAIN_HISTORY. Anything else is a 404 (exit 22),
    // so no installer test reaches the network.
    write_executable(
        &fake_bin.join("curl"),
        r#"#!/bin/sh
out=''
url=''
while [ $# -gt 0 ]; do
  case "$1" in
    -o) shift; out="$1" ;;
    https://*) url="$1" ;;
  esac
  shift
done
printf 'curl %s\n' "$url" >> "$INSTALL_LOG"
case "$url" in
  https://github.com/*/releases/download/*)
    src="${FAKE_RELEASE_DIR:-/nonexistent}/${url#*/releases/download/}"
    [ -f "$src" ] || exit 22
    cp "$src" "$out"
    ;;
  https://raw.githubusercontent.com/*/scripts/termux/*)
    [ -n "${FAKE_SCRIPTS_DIR:-}" ] || exit 22
    cp "$FAKE_SCRIPTS_DIR/scripts/termux/${url##*/scripts/termux/}" "$out" || exit 22
    ;;
  https://api.github.com/*/commits/main~*)
    sha="$(sed -n "${url##*main~}p" "${FAKE_MAIN_HISTORY:-/nonexistent}" 2>/dev/null)"
    [ -n "$sha" ] || exit 22
    printf '%s' "$sha"
    ;;
  *) exit 22 ;;
esac
"#,
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
    assert!(
        calls.contains(&format!(
            "timeout 30 {}/bin/huntsman-recon build-sha",
            prefix.display()
        )),
        "installer must check the installed binary's embedded revision: {calls}"
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
fn installer_embeds_the_resolved_revision_and_rebuilds_a_binary_without_it() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let installer = root.join("install.sh");
    let existing_path = std::env::var("PATH").unwrap_or_default();

    // An upper-case pin is embedded in the lower-case form build-sha accepts.
    let temp = scratch();
    let fake_bin = temp.join("fake-bin");
    let fake_target_libdir = temp.join("rustlib");
    let log = temp.join("install.log");
    let tmpdir = temp.join("tmp");
    fs::create_dir_all(&tmpdir).unwrap();
    install_fake_termux_toolchain(&fake_bin, &fake_target_libdir);
    let run = |home: &Path, rev: &str| {
        Command::new("bash")
            .arg(&installer)
            .env("PATH", format!("{}:{existing_path}", fake_bin.display()))
            .env("PREFIX", "/data/data/com.termux/files/usr")
            .env("INSTALL_LOG", &log)
            .env("FAKE_RUST_TARGET_LIBDIR", &fake_target_libdir)
            .env("HUNTSMAN_REV", rev)
            .env("HOME", home)
            .env("TMPDIR", &tmpdir)
            .env_remove("CARGO_TARGET_DIR")
            .env_remove("HUNTSMAN_BUILD_SHA")
            .output()
            .expect("installer must execute")
    };
    let output = run(&temp, "B2731D117009A841C302A124F38A808D36F6EAC7");
    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        fs::read_to_string(log.with_extension("log.build-sha")).unwrap(),
        "b2731d117009a841c302a124f38a808d36f6eac7\n"
    );

    // Cargo reports "already installed" for this revision and keeps a binary
    // built without provenance. The installer rebuilds once with --force.
    write_executable(
        &fake_bin.join("cargo"),
        r#"#!/bin/sh
printf 'cargo %s\n' "$*" >> "$INSTALL_LOG"
case "$*" in
  *--force*) printf '%s\n' "$HUNTSMAN_BUILD_SHA" > "$INSTALL_LOG.build-sha" ;;
  *) printf '%s\n' unknown > "$INSTALL_LOG.build-sha" ;;
esac
"#,
    );
    let home = temp.join("stale-home");
    fs::create_dir_all(&home).unwrap();
    fs::write(&log, "").unwrap();
    let output = run(&home, "b2731d117009a841c302a124f38a808d36f6eac7");
    assert!(
        output.status.success(),
        "a stale binary must be rebuilt, not fail the install: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let calls = fs::read_to_string(&log).unwrap();
    assert_eq!(
        calls.matches("cargo install").count(),
        2,
        "one normal install, then one forced rebuild: {calls}"
    );
    assert!(
        calls
            .lines()
            .filter(|l| l.starts_with("cargo install"))
            .nth(1)
            .is_some_and(|l| l.contains("--force")),
        "the rebuild must pass --force: {calls}"
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains(
            "Installed binary reports build-sha unknown, expected b2731d117009a841c302a124f38a808d36f6eac7; rebuilding."
        )
    );
    assert_private_state(&home, "b2731d117009a841c302a124f38a808d36f6eac7");

    // A build that never embeds the revision fails, even after the forced
    // rebuild, and records no provenance.
    write_executable(
        &fake_bin.join("cargo"),
        "#!/bin/sh\nprintf '%s\\n' unknown > \"$INSTALL_LOG.build-sha\"\n",
    );
    let home = temp.join("no-provenance-home");
    fs::create_dir_all(&home).unwrap();
    let output = run(&home, "b2731d117009a841c302a124f38a808d36f6eac7");
    assert!(
        !output.status.success(),
        "a binary without provenance was accepted"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("installed binary reports build-sha unknown, expected b2731d117009a841c302a124f38a808d36f6eac7"),
        "{stderr}"
    );
    assert!(
        !home.join(".huntsman/installed-revision").exists(),
        "provenance must not be recorded for a rejected binary"
    );

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
    assert!(
        installer.contains("dir=\"$svdir/huntsman-serve\"")
            && uninstall.contains("sv-disable huntsman-serve")
            && uninstall.contains("rm -rf \"$PREFIX/var/service/huntsman-serve\""),
        "the uninstall steps must stop and remove the web UI service install.sh creates"
    );
    for path in [
        "\"$PREFIX/bin/huntsman\"",
        "\"$PREFIX/bin/huntsmanctl\"",
        "\"$PREFIX/etc/profile.d/huntsman.sh\"",
    ] {
        assert!(
            uninstall.contains(path),
            "the uninstall steps must remove {path}, which install.sh creates"
        );
    }
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

const ASSET: &str = "huntsman-recon-aarch64-linux-android";
const BUILT_REV: &str = "b2731d117009a841c302a124f38a808d36f6eac7";

/// Publishes a fake `main-<sha7>` release of `bytes` under `releases`, with a checksum file in
/// `sha256sum` format. `checksum_of` lets a test publish a checksum of other bytes.
fn publish_release(releases: &Path, rev: &str, bytes: &[u8], checksum_of: &[u8]) {
    let dir = releases.join(format!("main-{}", &rev[..7]));
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join(ASSET), bytes).unwrap();
    let sums = scratch();
    fs::write(sums.join(ASSET), checksum_of).unwrap();
    let out = Command::new("sha256sum")
        .arg(ASSET)
        .current_dir(&sums)
        .output()
        .unwrap();
    assert!(out.status.success());
    fs::write(dir.join(format!("{ASSET}.sha256")), out.stdout).unwrap();
    let _ = fs::remove_dir_all(&sums);
}

struct Prebuilt {
    temp: PathBuf,
    fake_bin: PathBuf,
    rustlib: PathBuf,
    log: PathBuf,
    releases: PathBuf,
    root: PathBuf,
}

impl Prebuilt {
    fn new() -> Self {
        let temp = scratch();
        let fake_bin = temp.join("fake-bin");
        let rustlib = temp.join("rustlib");
        install_fake_termux_toolchain(&fake_bin, &rustlib);
        fs::create_dir_all(temp.join("tmp")).unwrap();
        Self {
            log: temp.join("install.log"),
            releases: temp.join("releases"),
            root: temp.join("install-root"),
            fake_bin,
            rustlib,
            temp,
        }
    }

    /// Runs install.sh. `build_sha` is what the downloaded binary answers to `build-sha`.
    fn run(&self, env: &[(&str, &str)], build_sha: &str) -> std::process::Output {
        fs::write(&self.log, "").unwrap();
        fs::write(
            self.log.with_extension("log.build-sha"),
            format!("{build_sha}\n"),
        )
        .unwrap();
        let existing_path = std::env::var("PATH").unwrap_or_default();
        Command::new("bash")
            .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("install.sh"))
            .env(
                "PATH",
                format!("{}:{existing_path}", self.fake_bin.display()),
            )
            .env("PREFIX", "/data/data/com.termux/files/usr")
            .env("HUNTSMAN_INSTALL_ROOT", &self.root)
            .env("INSTALL_LOG", &self.log)
            .env("FAKE_RUST_TARGET_LIBDIR", &self.rustlib)
            .env("FAKE_RELEASE_DIR", &self.releases)
            .env("HOME", &self.temp)
            .env("TMPDIR", self.temp.join("tmp"))
            .env_remove("CARGO_TARGET_DIR")
            .env_remove("HUNTSMAN_BUILD_SHA")
            .env_remove("HUNTSMAN_REV")
            .env_remove("HUNTSMAN_FROM_SOURCE")
            .env_remove("HUNTSMAN_SERVE_SERVICE")
            .env("SVDIR", self.temp.join("service"))
            .env("FAKE_SCRIPTS_DIR", env!("CARGO_MANIFEST_DIR"))
            .env("HUNTSMAN_START_TIMEOUT", "2")
            .envs(env.iter().copied())
            .output()
            .expect("installer must execute")
    }

    fn calls(&self) -> String {
        fs::read_to_string(&self.log).unwrap()
    }

    fn installed(&self) -> PathBuf {
        self.root.join("bin/huntsman-recon")
    }

    fn provenance(&self) -> String {
        fs::read_to_string(self.temp.join(".huntsman/installed-revision")).unwrap_or_default()
    }

    /// Adds termux-services: `sv` and `service-daemon` log their calls; `sv status` answers
    /// `FAKE_SV_STATUS` (default `run: …`; `unsupervised` until `service-daemon start`).
    fn with_runit(self) -> Self {
        write_executable(
            &self.fake_bin.join("sv"),
            r#"#!/bin/sh
printf 'sv %s\n' "$*" >> "$INSTALL_LOG"
[ "$1" = status ] || exit 0
# FAKE_SV_STATUS=unsupervised: no runsv answers until service-daemon has started.
if [ "${FAKE_SV_STATUS:-}" = unsupervised ]; then
  grep -q '^service-daemon start' "$INSTALL_LOG" || exit 1
  FAKE_SV_STATUS=''
fi
printf '%s\n' "${FAKE_SV_STATUS:-run: $2: (pid 42) 3s}"
"#,
        );
        write_executable(
            &self.fake_bin.join("service-daemon"),
            "#!/bin/sh\nprintf 'service-daemon %s SVDIR=%s\\n' \"$*\" \"$SVDIR\" >> \"$INSTALL_LOG\"\n",
        );
        self
    }

    fn service(&self) -> PathBuf {
        self.temp.join("service/huntsman-serve")
    }

    fn tmp_is_clean(&self) -> bool {
        fs::read_dir(self.temp.join("tmp"))
            .unwrap()
            .next()
            .is_none()
    }
}

impl Drop for Prebuilt {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.temp);
    }
}

fn stderr(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn a_published_build_is_installed_without_a_compiler() {
    let t = Prebuilt::new();
    let bytes = b"#!/bin/sh\n# verified release build\n";
    publish_release(&t.releases, BUILT_REV, bytes, bytes);
    let out = t.run(&[("HUNTSMAN_REV", BUILT_REV)], BUILT_REV);
    assert!(out.status.success(), "{}", stderr(&out));

    let calls = t.calls();
    assert!(
        calls.contains("pkg install -y git curl coreutils"),
        "{calls}"
    );
    assert!(
        !calls.contains("rust clang"),
        "no compiler for a published build: {calls}"
    );
    assert!(
        !calls.contains("cargo"),
        "no cargo for a published build: {calls}"
    );
    for step in ["build-sha", "check", "verify var/ledger.json"] {
        assert!(
            calls.contains(&format!("{ASSET} {step}")),
            "the downloaded build runs {step} before it replaces anything: {calls}"
        );
    }
    assert_eq!(fs::read(t.installed()).unwrap(), bytes);
    assert_eq!(
        fs::metadata(t.installed()).unwrap().permissions().mode() & 0o777,
        0o755
    );
    assert_private_state(&t.temp, BUILT_REV);
    assert!(
        t.provenance()
            .contains("installed_from=prebuilt main-b2731d1\n"),
        "{}",
        t.provenance()
    );
    assert!(t.tmp_is_clean(), "the download directory is removed");
    assert!(
        fs::read_dir(t.root.join("bin")).unwrap().all(|entry| !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with('.')),
        "no staging file is left next to the binary"
    );
}

#[test]
fn a_build_that_fails_its_checks_never_replaces_the_binary_or_falls_back() {
    let t = Prebuilt::new();
    fs::create_dir_all(t.root.join("bin")).unwrap();
    fs::write(t.installed(), b"previous").unwrap();

    // Bytes that do not match the published checksum.
    publish_release(&t.releases, BUILT_REV, b"tampered", b"original");
    let out = t.run(&[("HUNTSMAN_REV", BUILT_REV)], BUILT_REV);
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("sha256 mismatch for main-b2731d1; not installing"),
        "{}",
        stderr(&out)
    );

    // Matching bytes built from another commit.
    publish_release(&t.releases, BUILT_REV, b"other", b"other");
    let out = t.run(
        &[("HUNTSMAN_REV", BUILT_REV)],
        "0000000000000000000000000000000000000000",
    );
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains(&format!(
            "build main-b2731d1 reports build-sha 0000000000000000000000000000000000000000, expected {BUILT_REV}"
        )),
        "{}",
        stderr(&out)
    );

    assert!(
        !t.calls().contains("cargo"),
        "a bad build is an error, not a reason to compile: {}",
        t.calls()
    );
    assert_eq!(fs::read(t.installed()).unwrap(), b"previous");
    assert!(
        t.provenance().is_empty(),
        "no provenance for a rejected build"
    );
}

#[test]
fn when_main_has_no_build_yet_the_newest_published_commit_is_installed() {
    let t = Prebuilt::new();
    let older = "1111111111111111111111111111111111111111";
    let history = t.temp.join("history");
    fs::write(
        &history,
        format!("2222222222222222222222222222222222222222\n{older}\n"),
    )
    .unwrap();
    publish_release(&t.releases, older, b"older build", b"older build");
    let out = t.run(&[("FAKE_MAIN_HISTORY", history.to_str().unwrap())], older);
    assert!(out.status.success(), "{}", stderr(&out));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains(
            "main is at 0123456, which has no published build yet; installing main-1111111."
        ),
        "{stdout}"
    );
    assert!(!t.calls().contains("cargo"), "{}", t.calls());
    assert_private_state(&t.temp, older);
}

#[test]
fn a_source_build_runs_only_without_a_published_build_or_on_request() {
    // No build anywhere: the head of main is compiled.
    let t = Prebuilt::new();
    let out = t.run(&[], DEFAULT_MAIN_REV);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(
        String::from_utf8_lossy(&out.stdout)
            .contains("No published build for 0123456; building from source.")
    );
    assert!(
        t.calls().contains(&format!("--rev {DEFAULT_MAIN_REV}")),
        "{}",
        t.calls()
    );
    assert!(
        t.provenance()
            .contains("installed_from=source rustc 1.98.0 (fixture)\n"),
        "{}",
        t.provenance()
    );

    // A build exists, but HUNTSMAN_FROM_SOURCE=1 compiles anyway and never downloads.
    publish_release(&t.releases, BUILT_REV, b"bin", b"bin");
    let out = t.run(
        &[("HUNTSMAN_REV", BUILT_REV), ("HUNTSMAN_FROM_SOURCE", "1")],
        BUILT_REV,
    );
    assert!(out.status.success(), "{}", stderr(&out));
    let calls = t.calls();
    assert!(calls.contains(&format!("--rev {BUILT_REV}")), "{calls}");
    assert!(!calls.contains("releases/download"), "{calls}");
}

fn stdout(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// A release "binary" that logs its arguments and answers `doctor serve` as
/// `FAKE_DOCTOR_SERVE` says: 0 healthy, anything else not running.
const FAKE_RECON: &[u8] = br#"#!/bin/sh
printf 'recon %s\n' "$*" >> "$INSTALL_LOG"
if [ "$1 $2" = 'doctor serve' ]; then
  if [ "${FAKE_DOCTOR_SERVE:-0}" = 0 ]; then echo "serve=healthy addr=$4"; exit 0; fi
  echo "serve=not_running addr=$4"; exit 69
fi
"#;

#[test]
fn the_web_ui_runs_as_a_service_that_restarts_with_each_install() {
    let t = Prebuilt::new().with_runit();
    publish_release(&t.releases, BUILT_REV, FAKE_RECON, FAKE_RECON);
    let out = t.run(&[("HUNTSMAN_REV", BUILT_REV)], BUILT_REV);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(
        t.calls()
            .contains("pkg install -y git curl coreutils termux-services jq"),
        "{}",
        t.calls()
    );

    let dir = t.service();
    let run = fs::read_to_string(dir.join("run")).unwrap();
    assert!(
        run.starts_with("#!/data/data/com.termux/files/usr/bin/sh\n"),
        "{run}"
    );
    assert!(run.contains("termux-wake-lock"), "{run}");
    assert!(
        run.contains(&format!(
            "bind=\"$(head -n 1 '{}' 2>/dev/null)\"",
            t.temp.join(".huntsman/serve.bind").display()
        )),
        "the service binds the address `huntsman start` chose: {run}"
    );
    assert!(
        run.contains(&format!(
            "exec \"{}\" serve ${{bind:+--bind \"$bind\"}} 2>&1",
            t.installed().display()
        )),
        "the service runs the binary this install placed: {run}"
    );
    let finish = fs::read_to_string(dir.join("finish")).unwrap();
    assert!(
        finish.contains("[ \"$1\" = 69 ] && exec sleep 60"),
        "a taken port backs off instead of restarting every second: {finish}"
    );
    for path in ["run", "finish", ""] {
        assert_eq!(
            fs::metadata(dir.join(path)).unwrap().permissions().mode() & 0o777,
            0o700,
            "{path}"
        );
    }
    assert_eq!(
        fs::read_link(dir.join("log/run")).unwrap(),
        Path::new("/data/data/com.termux/files/usr/share/termux-services/svlogger")
    );
    assert!(!dir.join("down").exists(), "on by default");
    let calls = t.calls();
    assert!(
        calls.contains(&format!("sv restart {}", dir.display())),
        "a running service is restarted onto the new binary: {calls}"
    );
    assert!(
        calls.contains("recon doctor serve --bind 127.0.0.1:8080"),
        "the installed binary's own probe decides whether the page works: {calls}"
    );
    assert!(
        stdout(&out).contains("Web UI: running at http://127.0.0.1:8080/ (restarts automatically)"),
        "{}",
        stdout(&out)
    );

    // Not yet supervised: the controller starts runit's daemon for this SVDIR.
    let out = t.run(
        &[
            ("HUNTSMAN_REV", BUILT_REV),
            ("FAKE_SV_STATUS", "unsupervised"),
        ],
        BUILT_REV,
    );
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(
        t.calls().contains(&format!(
            "service-daemon start SVDIR={}",
            t.temp.join("service").display()
        )),
        "{}",
        t.calls()
    );
}

#[test]
fn the_huntsman_command_and_its_shortcuts_come_from_the_same_commit() {
    let t = Prebuilt::new().with_runit();
    publish_release(&t.releases, BUILT_REV, FAKE_RECON, FAKE_RECON);
    let out = t.run(&[("HUNTSMAN_REV", BUILT_REV)], BUILT_REV);
    assert!(out.status.success(), "{}", stderr(&out));
    let repo = Path::new(env!("CARGO_MANIFEST_DIR"));
    let controller = t.root.join("bin/huntsman");
    assert_eq!(
        fs::read(&controller).unwrap(),
        fs::read(repo.join("scripts/termux/huntsman")).unwrap()
    );
    assert_eq!(
        fs::metadata(&controller).unwrap().permissions().mode() & 0o777,
        0o755
    );
    assert_eq!(
        fs::read_link(t.root.join("bin/huntsmanctl")).unwrap(),
        Path::new("huntsman")
    );
    assert_eq!(
        fs::read(t.root.join("etc/profile.d/huntsman.sh")).unwrap(),
        fs::read(repo.join("scripts/termux/huntsman-profile.sh")).unwrap(),
        "the shortcuts load from profile.d, so ~/.bashrc is never rewritten"
    );
    assert!(!t.temp.join(".bashrc").exists());
    assert!(
        t.calls().contains(&format!(
            "curl https://raw.githubusercontent.com/EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-/{BUILT_REV}/scripts/termux/huntsman"
        )),
        "{}",
        t.calls()
    );
    assert!(stdout(&out).contains("Command: huntsman (try: huntsman help)"));

    // A commit without the scripts still installs the binary and the service, and says so.
    let out = t.run(
        &[("HUNTSMAN_REV", BUILT_REV), ("FAKE_SCRIPTS_DIR", "")],
        BUILT_REV,
    );
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(
        stderr(&out).contains(
            "warning: huntsman command could not fetch scripts/termux/huntsman at b2731d1"
        ),
        "{}",
        stderr(&out)
    );
}

#[test]
fn switching_the_web_ui_service_off_survives_a_reinstall() {
    let t = Prebuilt::new().with_runit();
    publish_release(&t.releases, BUILT_REV, FAKE_RECON, FAKE_RECON);
    let rev = ("HUNTSMAN_REV", BUILT_REV);

    let out = t.run(&[rev, ("HUNTSMAN_SERVE_SERVICE", "off")], BUILT_REV);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(t.service().join("down").exists());
    assert!(
        stdout(&out).contains("Web UI: off; start it with: huntsman start"),
        "{}",
        stdout(&out)
    );
    assert!(!t.calls().contains("sv restart"), "{}", t.calls());

    // `huntsman stop` leaves a down file; reinstalling keeps the service off.
    let out = t.run(&[rev], BUILT_REV);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(t.service().join("down").exists());
    assert!(!t.calls().contains("sv restart"), "{}", t.calls());

    let out = t.run(&[rev, ("HUNTSMAN_SERVE_SERVICE", "on")], BUILT_REV);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(!t.service().join("down").exists());
    assert!(t.calls().contains("sv restart"), "{}", t.calls());

    let out = t.run(&[rev, ("HUNTSMAN_SERVE_SERVICE", "yes")], BUILT_REV);
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("HUNTSMAN_SERVE_SERVICE must be on or off"),
        "{}",
        stderr(&out)
    );
}

#[test]
fn a_web_ui_that_does_not_answer_is_reported_without_failing_the_install() {
    let t = Prebuilt::new().with_runit();
    publish_release(&t.releases, BUILT_REV, FAKE_RECON, FAKE_RECON);
    let out = t.run(
        &[("HUNTSMAN_REV", BUILT_REV), ("FAKE_DOCTOR_SERVE", "69")],
        BUILT_REV,
    );
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(
        stderr(&out).contains(
            "warning: web UI service not answering yet; huntsman status and huntsman logs say why"
        ),
        "{}",
        stderr(&out)
    );
    assert!(
        t.installed().is_file(),
        "the accepted binary stays installed"
    );

    // Without termux-services there is nothing to supervise the server; say so.
    let t = Prebuilt::new();
    publish_release(&t.releases, BUILT_REV, FAKE_RECON, FAKE_RECON);
    let out = t.run(&[("HUNTSMAN_REV", BUILT_REV)], BUILT_REV);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(
        stdout(&out).contains("Web UI: not set up: termux-services is not installed"),
        "{}",
        stdout(&out)
    );
}
