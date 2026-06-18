#!/usr/bin/env bash
# HSE — install from /storage/emulated/0/Download/HSE.zip
# No root. No GitHub. No token. Works offline from the zip alone.

set -e

ZIP="${HSE_ZIP:-/storage/emulated/0/Download/HSE.zip}"
[ -f "$ZIP" ] || ZIP="$HOME/storage/downloads/HSE.zip"
[ -f "$ZIP" ] || { printf 'ERROR: HSE.zip not found.\nLooked in:\n  /storage/emulated/0/Download/HSE.zip\n  ~/storage/downloads/HSE.zip\nSet HSE_ZIP=/path/to/HSE.zip to override.\n'; exit 1; }

WORK="$HOME/.cache/hse-zip-$$"
DEST="${PREFIX:-/data/data/com.termux/files/usr}/bin/hse"
STAGE="$HOME/.cache/.hse-stage-$$"

trap 'rm -rf "$WORK"; rm -f "$STAGE"' EXIT

printf '\n==> HSE install from %s\n' "$ZIP"
printf '==> Extracting...\n'
mkdir -p "$WORK"
unzip -q -o "$ZIP" -d "$WORK"

# ── 1. Try prebuilt binary ─────────────────────────────────────────────────────
printf '==> Scanning for prebuilt aarch64 binary...\n'
for _name in hse-aarch64-linux-android hse; do
    while IFS= read -r _f; do
        [ -f "$_f" ] || continue
        cp "$_f" "$STAGE" 2>/dev/null && chmod 755 "$STAGE" || continue
        if "$STAGE" --version >/dev/null 2>&1; then
            install -m755 "$STAGE" "$DEST"
            printf '\n==> Installed from prebuilt binary: %s\n' "$DEST"
            "$DEST" --version
            exit 0
        fi
    done < <(find "$WORK" -name "$_name" ! -path "*/target/*" 2>/dev/null)
done
printf '  (no working prebuilt found — will build from source)\n'

# ── 2. Source build fallback ───────────────────────────────────────────────
printf '==> Looking for Cargo.toml...\n'
_ct=$(find "$WORK" -name "Cargo.toml" ! -path "*/target/*" -maxdepth 6 2>/dev/null | head -1)
[ -n "$_ct" ] || { printf 'ERROR: no binary and no Cargo.toml found in %s\n' "$ZIP"; exit 1; }
_src=$(dirname "$_ct")
printf '==> Source root: %s\n' "$_src"

printf '==> Installing build tools (skipped if already present)...\n'
pkg install -y rust clang make pkg-config openssl-tool 2>/dev/null || true
command -v cargo >/dev/null 2>&1 || { printf 'ERROR: cargo not found after pkg install\n'; exit 1; }

printf '==> Building HSE release binary (~4-6 min on Motorola aarch64)...\n'
(cd "$_src" && cargo build --release --locked)

[ -f "$_src/target/release/hse" ] || { printf 'ERROR: build succeeded but binary missing\n'; exit 1; }
install -m755 "$_src/target/release/hse" "$DEST"

printf '\n==> Installed: %s\n' "$DEST"
"$DEST" --version
printf '\n==> Run: hse serve   then open http://127.0.0.1:8080 in Chrome\n'
