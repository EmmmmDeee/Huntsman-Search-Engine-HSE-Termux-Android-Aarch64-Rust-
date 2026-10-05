use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

fn scratch() -> PathBuf {
    let dir = std::env::temp_dir().join(format!("huntsman-root-installer-{}", std::process::id()));
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

#[test]
fn root_installer_builds_huntsman_recon_and_forwards_an_optional_revision() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let installer = root.join("install.sh");
    assert!(installer.is_file(), "root install.sh must exist");

    let temp = scratch();
    let prefix = temp.join("prefix");
    let fake_bin = temp.join("fake-bin");
    let fake_target_libdir = temp.join("rustlib");
    let log = temp.join("install.log");
    fs::create_dir_all(prefix.join("bin")).unwrap();
    fs::create_dir_all(prefix.join("tmp")).unwrap();
    fs::create_dir_all(&fake_bin).unwrap();
    fs::create_dir_all(&fake_target_libdir).unwrap();
    fs::write(fake_target_libdir.join("libstd-test.rlib"), b"fixture").unwrap();

    write_executable(
        &fake_bin.join("pkg"),
        "#!/bin/sh\nprintf 'pkg %s\\n' \"$*\" >> \"$INSTALL_LOG\"\n",
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
    printf '%s\n' 'rustc 1.98.0 (fixture)' 'binary: rustc' 'commit-hash: fixture' 'commit-date: 2026-10-05' 'host: x86_64-unknown-linux-gnu' 'release: 1.98.0'
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
        "#!/bin/sh\nprintf 'hibp=%s cargo %s\\n' \"${HUNTSMAN_HIBP_NO_EMBED:-}\" \"$*\" >> \"$INSTALL_LOG\"\n",
    );

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
        .output()
        .expect("root installer must execute under bash");

    assert!(
        output.status.success(),
        "installer failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let calls = fs::read_to_string(&log).expect("fake installer log");
    assert!(calls.contains("pkg install -y git rust clang"), "{calls}");
    assert!(
        calls.contains("pkg install -y rust rust-std-x86_64-unknown-linux-gnu"),
        "{calls}"
    );
    assert!(calls.contains("dpkg-query -W -f=${Version} rust"), "{calls}");
    assert!(
        calls.contains("dpkg-query -W -f=${Version} rust-std-x86_64-unknown-linux-gnu"),
        "{calls}"
    );
    assert!(calls.contains("hibp=1 cargo install --git https://github.com/EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-.git"), "{calls}");
    assert!(calls.contains(&format!("--rev {rev}")), "{calls}");
    assert!(calls.contains("--locked"), "{calls}");
    assert!(
        calls.contains(&format!("--root {}", prefix.display())),
        "{calls}"
    );
    assert!(calls.contains("--force huntsman-recon"), "{calls}");

    let _ = fs::remove_dir_all(&temp);
}
