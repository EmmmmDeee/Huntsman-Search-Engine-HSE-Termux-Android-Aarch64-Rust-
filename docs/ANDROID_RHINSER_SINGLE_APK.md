# HUNTSMAN × RHINSER — one-APK Android AArch64 runbook

**Source date:** 11 November 2026. **Status: source scaffold implemented; APK build and phone acceptance NOT verified.**

## Single authoritative architecture

- **Core:** canonical Rust crate `huntsman-recon`. Existing evidence ledger, scans, network fetch, graph, OSINT catalogue, Rhinser offline NDEF/APDU/TLV/Bluetooth inspection and Web UI are reused unchanged.
- **Mobile package:** one Android APK, `com.huntsman.recon`, containing `lib/arm64-v8a/libhuntsman.so` (a PIE Rust executable) and `libhuntsman_key_health.so` (separate Rust status watcher). A minimal Java `MainActivity` is the unavoidable Android activity/WebView and process-lifecycle adapter. There is no new C++, Python, Node, Kotlin or runtime LLM.
- **Persistence:** private Android application data directory supplies `HOME`; existing Rust Web UI Settings saves provider keys in the already-supported private credential resolver, and `scans/` remains on-device.
- **Access:** randomized per-launch 256-bit bearer token on a private `127.0.0.1` listener. `HSE_APK_LOOPBACK_AUTH=1` activates a dedicated authenticated Rust server mode. **Standard rootless Termux loopback semantics remain unchanged.** HTTP cleartext is allowed for localhost only, never for remote hosts.
- **Credential status:** `huntsman-key-health` is a pure-Rust second binary writing a mode-0600 atomic `$HOME/.huntsman/api-key-health.json`. Default watch: 1800 seconds while process is alive. Actual secrets remain in existing key stores and are never written into this report.

## Build — supported development host

Requires Android SDK API 36, Android Gradle Plugin 9.0.1, Gradle 9.1+ compatible with that plugin, Java 17, Android NDK with `aarch64-linux-android26-clang`, stable Rust with `aarch64-linux-android` target, and `readelf`/`unzip`. Network access is needed on first dependency download.

```bash
rustup target add aarch64-linux-android
export ANDROID_HOME=/path/to/android-sdk
export ANDROID_NDK_HOME=/path/to/android-sdk/ndk/28.2.13676358
bash android-app/build-apk.sh
```

Expected **output only after successful build**:
`android-app/app/build/outputs/apk/debug/app-debug.apk`.

The build script refuses a non-Bionic executable; both Rust bins must have the Android `/system/bin/linker64` interpreter. Android 10+ cannot execute app-writable home binaries, so the ABI-specific executables are packaged as `lib*.so` and extracted to `nativeLibraryDir`. The original Rust engine is not rewritten.

## Phone-only APK acquisition from GitHub Actions

The source repository now includes `.github/workflows/android-rhinser-apk.yml`.
On a branch pull request it attempts a credential-free ARM64 debug APK build,
runs the new Rust tests, inspects the APK's native libraries and uploads an
artifact named `huntsman-android-aarch64-debug-apk` containing the APK and
`APK_SHA256.txt`. After an **actually successful** run a phone can open
**GitHub → Actions → successful run → Artifacts**, download the APK,
independently compare the SHA-256 digest and install it. This is debug signed,
not a supported release; stable release signing, update/migration testing,
and a physical handset acceptance are separate requirements.

GitHub Actions are still failing before runner allocation, so this workflow
has not produced any downloadable APK. Its existence is not build evidence.

**Not established:** This environment lacks Cargo, Android SDK, Gradle and an Android device. Neither an APK binary, APK signature, installation, WebView navigation nor Android background-process behaviour has passed on a physical AArch64 phone.

## Run and verification gates

1. `cargo fmt --all -- --check`
2. `cargo test --locked --bin huntsman-key-health`
3. `cargo test --locked --test android_apk_contract`
4. `cargo test --locked` and `cargo clippy --all-targets -- -D warnings`.
5. `bash android-app/build-apk.sh` and inspect `unzip -l` for both `arm64-v8a/lib*.so` payloads.
6. Install and launch on **rootless Android AArch64**, verify the private listener replies `auth=token`, the page loads, and API requests without the bearer token are rejected. Confirm ordinary Termux still permits its longstanding token-free loopback behaviour.
7. Check Web UI Settings can save a test-only provider key in the app sandbox; verify the health JSON updates, contains **no key values**, preserves a prior good report after a write failure, and marks authentication/real source use unverified without separate evidence.
8. Compare original RHINSER APK workflows on an authorised device for NFC, BLE, Wi-Fi, case history, persistence, permissions and Web UI. A static source inventory alone is insufficient.

## API keys: maintenance rather than uncontrolled replacement

```bash
cargo run --locked --bin huntsman-key-health -- --watch --interval-seconds 1800
cargo run --locked --bin huntsman-key-health -- --probe
```

Default mode is **offline presence only**: `configured` is not `valid`. `--probe` uses the existing guarded HTTP client and can consume provider API quota. A `valid` response may be structurally valid without establishing authentication (DeHashed is the known example). Thus the report *never* says `authentication_verified` or `source_execution_verified` without independent authoritative evidence. Snapshots expire at `stale_after_unix`.

A key cannot be automatically invented, renewed, copied from someone else's account or guaranteed permanent. Provider-managed rotation can be added **only** after an authorized official rotation API and a tested replacement key are available. Never overwrite an existing working key with an unverified candidate; retain previous key state for rollback. Use existing Rust Settings to supply an authorised replacement.

## RHINSER coverage — current factual limits

The exact three original APKs were recovered and hashed:
- `rhinse-osint.apk`: `e6be6b6bbff2128cf72a34d1a64d25fbaf7c121a0ce803e60e45bdb97f363036`
- `Rhinser.apk`: `6a41162f2cf1d59a8689c01a685cd6cde06752c57a02b7177ef009bed7c9593a`
- `RHINSE-SCAN-DETECT.apk`: `30833ef95b4f504cd4db0919bfc5dc6743590d9e33d25ed424fc1cb1d42d68c4`

Existing Rust: 83-entry unverified OSINT link catalogue; saved cases, notes, leads, favourites, history; schema-bounded offline NDEF/APDU/TLV interpretation; synthetic Bluetooth radio fixtures, Wi-Fi and cell survey processing; source-first evidence and Web UI API. These features are already in the canonical library, not new reimplementations.

**Remaining RHINSER gap:** Android live NFC/BLE scanning/writing/permission callbacks, UI workflows, exact historical app behaviours, and method-by-method differential validation are **not 100% converted or device-tested**. Card emulation/remote-execution functionality present in original packages is not copied into the passive evidence engine. No hidden or stealth remote control is implemented. Android background policy may kill the foreground watcher. The Android
`HealthJobService` schedules **best-effort offline** updates every 30 minutes
through `JobScheduler` with persistence across reboot where the OS permits.
This scheduler is not exact, can be deferred under Doze or battery policies,
and cannot guarantee continuous execution or rotate/recover credentials.

## Roadmap, in dependency order

1. Obtain a passing full Rust suite, Clippy, CodeQL and Android AArch64 cross-build on the exact new branch.
2. Produce and cryptographically verify one APK. Test Android 12/13/14/15/16 where relevant, including Android 16K memory pages.
3. Add minimal Android-platform NFC/BLE user-consented acquisition bridges, preserving interpretation/correlation entirely in Rust. Require runtime permissions, verified capture provenance and non-simulated sensors.
4. Reconcile each original RHINSER class and UI workflow with the parity ledger. Differentiate unavailable/unsafe legacy features from complete working parity.
5. Add resilient foreground-service/JobScheduler maintenance where Android permits; handle reboot/Doze and explicit user controls. Do not promise continuous background execution without device evidence.
6. Consolidate old docs *after* link/backreference and behavioural checks. Do not delete changelog, raw evidence, original APKs, provenance or old integration contracts merely to reduce file count.

## Documentation policy

This page is the current **entrypoint for Android packaging and credential health**. The existing `docs/RHINSER_FUNCTIONAL_PARITY.md`, `docs/RHINSER_NATIVE_CONVERSION.md`, `docs/rhinser_native_coverage.json`, `docs/DEHASHED.md` and `docs/PROVIDER_CREDENTIALS.md` remain source-of-truth ledgers for their detailed contracts. Legacy docs have not been deleted: no proven safe-removal/backlink assessment was completed. The repository's source and raw evidence take precedence over an arbitrary file-count target.

**Version discipline:** Production code and saved evidence must be preserved. This branch is an unmerged, unverified candidate; do not treat the source package as a successful installed APK.
