#!/usr/bin/env bash
# Create ONE arm64-v8a APK containing two executable pure-Rust binaries.
# Bash is orchestration only. The Android Java Activity is the mandatory host.
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
app="$root/android-app"
target="aarch64-linux-android"
abi="$app/app/src/main/jniLibs/arm64-v8a"

for cmd in cargo rustup gradle readelf unzip; do
  command -v "$cmd" >/dev/null || { echo "missing required tool: $cmd" >&2; exit 1; }
done
rustup target list --installed | grep -Fxq "$target" || {
  echo "Install the compiler target: rustup target add $target" >&2
  exit 1
}
ndk="${ANDROID_NDK_HOME:-${ANDROID_NDK_ROOT:-}}"
if [[ -n "$ndk" ]]; then
  host=linux-x86_64
  [[ "$(uname -s)" == Darwin ]] && host=darwin-x86_64
  ndk_tools="$ndk/toolchains/llvm/prebuilt/$host/bin"
  export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="${CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER:-$ndk_tools/aarch64-linux-android26-clang}"
  # Rust's linker setting does not select the compiler for native dependencies.
  export CC_aarch64_linux_android="${CC_aarch64_linux_android:-$ndk_tools/aarch64-linux-android26-clang}"
  export AR_aarch64_linux_android="${AR_aarch64_linux_android:-$ndk_tools/llvm-ar}"
fi
: "${CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER:?Set Android NDK linker}"
cd "$root"
cargo build --locked --profile dist --target "$target" \
  --bin huntsman-recon --bin huntsman-key-health
mkdir -p "$abi"
for executable in huntsman-recon huntsman-key-health; do
  path="$root/target/$target/dist/$executable"
  [[ -f "$path" ]] || { echo "missing Rust binary: $path" >&2; exit 1; }
  readelf -l "$path" | grep -q '/system/bin/linker64' || {
    echo "refusing non-Android executable: $path" >&2; exit 1;
  }
done
cp "$root/target/$target/dist/huntsman-recon" "$abi/libhuntsman.so"
cp "$root/target/$target/dist/huntsman-key-health" "$abi/libhuntsman_key_health.so"
gradle --project-dir "$app" --no-daemon --console plain :app:assembleDebug
apk="$app/app/build/outputs/apk/debug/app-debug.apk"
unzip -l "$apk" | grep -Eq 'lib/arm64-v8a/libhuntsman.so' || exit 1
unzip -l "$apk" | grep -Eq 'lib/arm64-v8a/libhuntsman_key_health.so' || exit 1
echo "Debug APK generated: $apk"
echo "Physical handset install, Web UI, NFC/BLE and API-key checks remain required."
