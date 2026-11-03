#!/usr/bin/env bash
# Build the canonical Huntsman engine from one pinned main commit on a rootless
# Android AArch64 handset. The embedded web UI is compiled into the same binary.
# No installed binary or operator data is changed until every gate passes.
set -Eeuo pipefail
umask 077
IFS=$'\n\t'

repo="https://github.com/EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-.git"
prefix="${PREFIX:-}"
expected="${HUNTSMAN_EXPECT_SHA:-}"
work=""
lock=""
stage=""
owned_lock=0

die() { printf 'FAIL  %s\n' "$*" >&2; exit 1; }
note() { printf 'INFO  %s\n' "$*"; }
cleanup() {
  if [[ -n "$stage" && -e "$stage" ]]; then rm -f -- "$stage"; fi
  if [[ -n "$work" && -d "$work" ]]; then rm -rf -- "$work"; fi
  if (( owned_lock )); then rmdir -- "$lock" 2>/dev/null || true; fi
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

[[ "$(id -u)" != 0 ]] || die 'refusing to run as root'
case "$(uname -m)" in
  aarch64|arm64) ;;
  *) die 'requires Android AArch64 (not a cross-compile)' ;;
esac
case "$prefix" in
  /data/data/com.termux/files/usr*) ;;
  *) die 'requires the standard rootless Termux PREFIX' ;;
esac
[[ -n "${HOME:-}" && -n "${TMPDIR:-}" ]] || die 'Termux HOME and TMPDIR are required'
[[ -z "$expected" || "$expected" =~ ^[a-fA-F0-9]{40}$ ]] ||
  die 'HUNTSMAN_EXPECT_SHA must be a complete 40-digit commit SHA'
for tool in pkg git curl jq sha256sum timeout mktemp; do
  command -v "$tool" >/dev/null 2>&1 || die "missing required command: $tool"
done

# Only this orchestration script is Bash: every runtime collector, API handler,
# evidence model and web-server component remains in the canonical Rust binary.
pkg install -y rust clang git curl coreutils jq
host="$(rustc -vV | sed -n 's/^host: //p')"
[[ -n "$host" ]] || die 'Rust target triple could not be determined'
pkg install -y rust "rust-std-$host"
compiler_version="$(dpkg-query -W -f='${Version}' rust)"
stdlib_version="$(dpkg-query -W -f='${Version}' "rust-std-$host")"
[[ "$compiler_version" == "$stdlib_version" ]] ||
  die 'Termux rust and rust-std packages are different versions'
for tool in cargo rustfmt clippy-driver; do
  command -v "$tool" >/dev/null 2>&1 || die "missing Rust tool: $tool"
done

cache="${HUNTSMAN_REBUILD_CACHE:-$HOME/.cache/huntsman-rebuild}"
mkdir -p -- "$cache"
chmod 700 -- "$cache"
lock="$cache/.full-rebuild.lock"
mkdir -- "$lock" 2>/dev/null || die "another rebuild may be active ($lock); check before removing a stale lock"
owned_lock=1
work="$(mktemp -d "$TMPDIR/huntsman-rebuild.XXXXXXXX")"
mkdir -p "$work/state"
# An installed standard-library directory is not proof that rustc can link a
# native Android executable. Fail before downloading/building the large crate.
cat > "$work/probe.rs" <<'RS'
fn main() { println!("native-std-ok"); }
RS
rustc "$work/probe.rs" -o "$work/probe" || die 'native Rust standard-library link probe failed'
[[ "$("$work/probe")" == "native-std-ok" ]] || die 'native Rust execution probe failed'
report="$cache/last-acceptance.txt"
server_log="$cache/last-server.log"
note 'Fetching one immutable main snapshot'
git clone --quiet --depth 1 --single-branch --branch main "$repo" "$work/source"
cd "$work/source"
revision="$(git rev-parse HEAD)"
[[ "$revision" =~ ^[a-f0-9]{40}$ ]] || die 'main checkout has no full commit SHA'
if [[ -n "$expected" && "${expected,,}" != "$revision" ]]; then
  die "main moved: expected ${expected,,}, fetched $revision"
fi
[[ "$(git status --porcelain)" == "" ]] || die 'checkout was not clean'
note "Pinned source revision: $revision"
note "Rust host: $host; compiler: $(rustc --version)"

# A single compilation worker avoids parallel rustc processes exhausting phone
# memory. Respect an explicit operator override without silently raising it.
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-1}"
export CARGO_INCREMENTAL=0
# CI uses the same debug-info reductions: do not spend scarce phone storage
# or linker memory on development/test DWARF data for this verification run.
export CARGO_PROFILE_DEV_DEBUG=0
export CARGO_PROFILE_TEST_DEBUG=0
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$cache/target}"
export HUNTSMAN_BUILD_SHA="$revision"
case "$CARGO_BUILD_JOBS" in
  ''|*[!0-9]*) die 'CARGO_BUILD_JOBS must be a positive integer' ;;
esac
(( CARGO_BUILD_JOBS > 0 )) || die 'CARGO_BUILD_JOBS must be positive'
mkdir -p -- "$CARGO_TARGET_DIR"

note 'Gate 1: source formatting'
cargo fmt --all --check
note 'Gate 2: all-target Clippy with warnings denied'
cargo clippy --locked --workspace --all-targets -- -D warnings
note 'Gate 3: complete offline Rust test suite'
cargo test --locked --workspace
note 'Gate 4: locked native release build with embedded web UI'
cargo build --locked --release --bin huntsman-recon
binary="$CARGO_TARGET_DIR/release/huntsman-recon"
[[ -f "$binary" && -x "$binary" ]] || die 'missing native release executable'
actual="$("$binary" build-sha)"
[[ "$actual" == "$revision" ]] ||
  die "build provenance mismatch: binary=$actual source=$revision"
note 'Gate 5: physical Termux HTTP/CLI/web API and persisted-scan acceptance'
HSE_BIN="$binary" \
HUNTSMAN_HOME="$work/state" \
HSE_ACCEPTANCE_REPORT="$report" \
HSE_ACCEPTANCE_SERVER_LOG="$server_log" \
  bash scripts/termux-runtime-acceptance.sh ||
  die "Termux acceptance failed; report: $report; installed binary unchanged"
grep -q '^PASS  ' "$report" || die 'acceptance produced no passing checks'
if ! grep -q 'TERMUX_RUNTIME_ACCEPTANCE' "$report"; then
  die "acceptance did not report the device verdict; installed binary unchanged ($report)"
fi

# A binary can be replaced while an existing service process continues running
# its previous inode. The operator restarts serve after installation.
destination="$prefix/bin/huntsman-recon"
backup="$prefix/bin/.huntsman-recon.previous"
mkdir -p "$prefix/bin"
if [[ -L "$destination" || (-e "$destination" && ! -f "$destination") ]]; then
  die 'refusing to replace a symlink or non-regular installed binary'
fi
if [[ -L "$backup" || (-e "$backup" && ! -f "$backup") ]]; then
  die 'refusing a symlink or non-regular rollback destination'
fi
candidate_sha="$(sha256sum "$binary" | cut -d' ' -f1)"
stage="$(mktemp "$prefix/bin/.huntsman-recon.stage.XXXXXXXX")"
cp -- "$binary" "$stage"
chmod 700 "$stage"
staged_sha="$(sha256sum "$stage" | cut -d' ' -f1)"
[[ "$staged_sha" == "$candidate_sha" ]] || die 'staged binary checksum mismatch'
had_previous=0
if [[ -f "$destination" ]]; then
  old_stage="$(mktemp "$prefix/bin/.huntsman-recon.old.XXXXXXXX")"
  cp -p -- "$destination" "$old_stage"
  mv -f -- "$old_stage" "$backup"
  had_previous=1
fi
mv -f -- "$stage" "$destination"
stage=""
if [[ "$("$destination" build-sha 2>/dev/null || true)" != "$revision" ||
      "$(sha256sum "$destination" | cut -d' ' -f1)" != "$candidate_sha" ]]; then
  if (( had_previous )); then mv -f -- "$backup" "$destination"; else rm -f -- "$destination"; fi
  die 'post-install verification failed; previous executable restored where present'
fi
note "PASS  pinned native binary installed: $destination"
note "PASS  provenance: $revision"
note "PASS  acceptance report: $report"
if (( had_previous )); then note "Rollback binary retained: $backup"; fi
note 'Restart an already-running Huntsman serve process to load the new executable.'
