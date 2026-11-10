#!/usr/bin/env bash
# Builds one Android APK containing the HUNTSMAN cdylib and embedded web UI.
# Android SDK, NDK, Gradle/JDK and Rust aarch64-linux-android target are required.
set -Eeuo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
: "${ANDROID_HOME:?Set ANDROID_HOME to your installed Android SDK}"
: "${ANDROID_NDK_HOME:?Set ANDROID_NDK_HOME to your installed Android NDK}"
: "${JAVA_HOME:?Set JAVA_HOME to JDK 17 or newer}"
command -v cargo >/dev/null || { echo >&2 'Rust cargo is required'; exit 2; }
command -v gradle >/dev/null || { echo >&2 'Gradle is required'; exit 2; }
ndk_host="linux-x86_64"
case "$(uname -s)-$(uname -m)" in
  Darwin-arm64) ndk_host='darwin-x86_64';;
  Linux-x86_64) ndk_host='linux-x86_64';;
  *) echo >&2 'Unsupported NDK host; set up a supported build machine'; exit 2;;
esac
linker="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/$ndk_host/bin/aarch64-linux-android26-clang"
[[ -x "$linker" ]] || { echo >&2 "NDK linker not found: $linker"; exit 2; }
export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$linker"
rustup target add aarch64-linux-android
cargo build --manifest-path "$root/android/rust/Cargo.toml" --release --target aarch64-linux-android
native="$root/android/rust/target/aarch64-linux-android/release/libhuntsman_android.so"
[[ -s "$native" ]] || { echo >&2 'Rust cdylib was not generated'; exit 1; }
install -D -m 0644 "$native" "$root/android/app/src/main/jniLibs/arm64-v8a/libhuntsman_android.so"
(
  cd "$root/android"
  gradle :app:assembleDebug --no-daemon
)
apk="$root/android/app/build/outputs/apk/debug/app-debug.apk"
[[ -s "$apk" ]] || { echo >&2 'APK not produced'; exit 1; }
echo "DEBUG APK: $apk"
sha256sum "$apk"
echo 'Debug APK is for device acceptance only; production signing, tests and Play policy remain separate gates.'
