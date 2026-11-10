# HUNTSMAN × RHINSER — CANONICAL BUILD AND OPERATING MANUAL

**Status:** integrated source candidate, **not** a released or handset-tested APK.
**Canonical repository:** `EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-`
**Integration branch:** `feat/hse-rhinser-android-unified` (draft work; do not equate with `main`).
**Source baseline:** `main` at `9488c3e0b3941ade36f8d05ca5e4565f756f1bd6` (verified during assembly).
**Hardware target:** Android AArch64 / ARM64, no root; target is Android 14+ acceptance.

## 1. WHAT IS ACTUALLY IMPLEMENTED

This candidate composes, without overwriting the existing Rust engine:

- Canonical Rust evidence, HTTP, source, entity graph, correlation and Web UI runtime.
- Existing RHINSER catalogue, local case workspace, NDEF/APDU/BER-TLV parsers, offline BLE capture import, cross-case overlap and read-only schema/evidence mappings.
- Additional bounded pure-Rust DEX application class/method inventory (previous draft PR #1814).
- Optional guarded BreachDirectory source-only lookup (previous draft PR #1813).
- Rust provider credential health register (previous draft PR #1815), with structured status, staleness and source-labelled probe verdicts.
- A single-package Android **source build path**: ARM64 Rust cdylib, minimal Android Activity + WebView and a JobScheduler adapter for best-effort credential checks.

This does **not** mean every original RHINSER method or Android permission callback now works. The original three APKs and forensic method maps remain evidence, not compiled modules or translated executable code.

## 2. FILE OWNERSHIP — DO NOT FORK LOGIC

| Owner | Responsibility |
| --- | --- |
| `src/lib.rs`, `src/*` | All canonical Rust OSINT, evidence, correlation, providers, persistence, NFC and BLE *parsing* |
| `src/cli/*` | Canonical Rust command and full Web UI `serve` wiring reused directly by Android Rust bridge |
| `src/bin/huntsman-key-health.rs` | One Rust key-status implementation used by Termux and Android (no secret copies) |
| `src/environment.rs` | Runtime HOME accessor; one Android-only immutable app-home override |
| `android/rust/src/lib.rs` | Narrow JNI entry points only; links canonical Rust and CLI source |
| `android/app/src/main/java/.../HuntsmanActivity.java` | Android Activity, WebView, lifecycle and JobScheduler only, no OSINT source logic |
| `android/app/src/main/*`, `android/*gradle*` | Mandatory APK manifest/resources/build metadata |
| `scripts/build-android-apk.sh` | Bash build orchestration; no runtime feature logic |

**Unavoidable non-Rust exceptions:** Android application manifest and network-security XML, minimal Java Android framework adapter, Gradle build declarations, the existing HTML/JavaScript Web UI, and Bash orchestration. The operating system supplies Android framework code; no Java OSINT implementation is added.

## 3. OPERATOR INSTALLATION / DEBUG BUILD

**Current deliverable is source, not a tested APK.** Build on a supported Linux x86_64 host or GitHub Actions runner with JDK 17+, Android SDK platform 35, NDK, Rust toolchain with `aarch64-linux-android` target, Gradle and the Android plugin. The user can install the resulting debug-signed **single** `app-debug.apk` directly on an ARM64 Android phone.

```bash
# On a capable build host, after fetching the exact integration branch:
git clone --branch feat/hse-rhinser-android-unified \
  https://github.com/EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-.git huntsman
cd huntsman
export ANDROID_HOME=/absolute/path/to/android-sdk
export ANDROID_NDK_HOME="$ANDROID_HOME/ndk/26.3.11579264"
export JAVA_HOME=/absolute/path/to/jdk17
./scripts/build-android-apk.sh
# Expected, IF the build and regression gates pass:
# android/app/build/outputs/apk/debug/app-debug.apk
```

If Gradle, SDK, NDK, or Rust isn't available, no APK can honestly be produced. Android SDK/NDK host tools generally do not run natively under rootless Termux ARM64, so a hosted build runner may be necessary. The ZIP accompanying this guide deliberately contains *no fabricated or renamed APK*.

The Android component uses a signed APK's native `libhuntsman_android.so`, not an executable staged in a writable app data directory (Android 10+ app-data executable restrictions).

### App startup

1. Tap **HUNTSMAN**. The Activity loads the native ARM64 library and starts the **existing canonical Rust `serve` adapter** on `127.0.0.1:8080`.
2. A background Java readiness probe checks `/api/health` for `name=huntsman-recon` and `status=ok`; only then does WebView load the existing Rust-served UI.
3. The WebView permits local loopback content. External HTTPS links open in the user's browser; file/content URLs and external HTTP are blocked inside the WebView.
4. Android app files are the default credential/evidence HOME. The Rust OSINT provider configuration and Web UI key-storage logic use the same app HOME rather than the inaccessible Termux HOME.
5. The Android JobScheduler requests periodic status refreshes; OS Doze and background restrictions may defer them. The file's `stale_after_unix` reveals missed refreshes.

The APK cannot access Termux app-private paths, inherit Termux:API permissions, or call `termux-wifi-scaninfo` as though running inside Termux. These Android-specific operations require explicit, permissioned platform bridges and physical-device acceptance.

## 4. API CREDENTIALS — EXACT CONTRACT

**Primary owner:** `$HOME/.huntsman.env` under Termux; inside the Android application, `${appFilesDir}/.huntsman.env`. Preserve the canonical key resolver and all optional provider slots. Never embed real keys in source, ZIP files, APK assets or Web UI JavaScript.

**Non-secret monitor output:** `${HOME}/.huntsman/api-key-health.json` (in Android, `${appFilesDir}/.huntsman/api-key-health.json`). Key *presence* is not a working key. Only a supported authenticated provider probe with verdict `valid` justifies `authenticated_probe_success=true` at the observed timestamp. Check `stale_after_unix` before relying on any prior pass.

Termux native monitor:

```bash
huntsman-key-health --watch --interval-seconds 1800 --probe
```

This monitor works **only while its process remains alive**. The Android version schedules best-effort OS jobs, with active API probes disabled by default. Use the Android menu to opt in to authenticated checks; some providers charge for probe requests. Presence-only status always remains possible without touching network quotas. Rejected, rate-limited, unknown, unsupported, stale or unavailable credentials are never promoted to valid.

**Credential renewal:** Not universally automatable. Real rotation requires an official provider refresh/grant mechanism, explicit operator authorization and durable private token storage. Generating, harvesting or guessing functional third-party keys is neither possible nor part of this design. The health file is a **state ledger**, not a copy of the keys themselves.

## 5. RHINSER PARITY — EVIDENCE-BASED STATUS

All original APKs are preserved, individually SHA-256 verified, and excluded from the compiled HUNTSMAN APK:

- `rhinse-osint.apk`: 132 defined app classes, 700 method-name references, 908 ZIP members.
- `Rhinser.apk`: 38 defined app classes, 316 method-name references, 25 ZIP members.
- `RHINSE-SCAN-DETECT.apk`: 12 defined app classes, 35 method-name references, 17 ZIP members.

Total: **182 classes, 1,051 distinct method-name references, 950 resources**. The inventory describes static names, *not* translated, executable Rust method bodies.

| Capability | Current status | Release gate |
| --- | --- | --- |
| Public-source catalogue (83 links) | Implemented directory, not 83 live collectors | Validate source identity and link freshness |
| Case workspace, bookmarks, notes | Implemented local Rust workspace; browser editing partial | Browser persistence and migration tests |
| NDEF/APDU and BER-TLV | Implemented read-only Rust inspection of supplied frames | Android NFC hardware capture and differential tests |
| BLE observations | Offline Rust adapter; Termux-based survey input | Native permissioned BLE radio callback and live-scan evidence receipt |
| Android case/Room UI parity | Partial or missing | Tested migration for every supported table and Activity |
| On-device source attestation | Not implemented | Signed hardware provenance/permissions receipts |
| Original prank/demo scanner | Deterministic simulation-only | Verify labelled simulation fidelity, not sensor evidence |
| EMV/HCE/card writing | Not implemented | Separate approved use case, physical hardware, safety review |
| Remote command listener | Not incorporated | Visible, explicitly authorized diagnostics-only design if ever required |
| Single HUNTSMAN APK | Source build path implemented | SDK build, signed APK inspection, actual ARM64 handset tests |

Non-parity cannot be concealed by renaming or simply packaging the original APK assets. Preserve original raw evidence independently in encrypted/private storage; normalised views must be separately provenance-labelled.

## 6. REGRESSION AND RELEASE GATES

```bash
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --locked
cargo build --profile dist --target aarch64-linux-android
./scripts/build-android-apk.sh
```

Additionally verify original APK static inventory against the Rust parser, exact resource and method totals, provider mock outcomes, no-key/no-send, provider rate limits, source evidence provenance, Web UI API parity, HTML security headers, private key-file permissions, and app HOME override. On the target phone, verify a cold start, an app restart, Web UI navigation, a successful opted-in public source, an empty result, a failed provider, a 30-minute health refresh, a missed-refresh stale state, and Android background/Doze behaviour. Record OS/API level, APK SHA-256, commit SHA, resource use, battery and failure logs.

**Never merge or claim a release if any required gate is absent or failing.** Current GitHub Actions jobs have reported `failure` before executing steps (zero job steps), so they do not establish compiler or runtime defects, and cannot be treated as passes.

## 7. DOCUMENTATION RETENTION / FILE CONSOLIDATION

This is the **single authoritative new guide** for the Android/RHINSER/credential integration. Old documentation and the complete original source tree remain in separately dated, immutable archives; historical source material is not deleted or silently overwritten. The `changelog.d` history (hundreds of files) is not a candidate for irreversible deletion until tests, changelog aggregation, cross-references, license and evidence-policy checks establish that removal is safe.

For a compact distribution, ship the current source checkout, the embedded Web UI and this guide; keep original APKs, old engineering archives, and historical documentation outside the installed APK in versioned provenance archives. File-count reduction must never disable feature discovery, tests, historical evidence, recovery or current user documentation.

## 8. NEXT RELEASE MILESTONES

1. **P0 Build unblock:** recover CI runner allocation (jobs currently report failure with zero steps), compile exact integration head and resolve real compiler errors.
2. **P0 Android packaging:** build/sign one ARM64 APK, inspect native `.so`, run cold start and verify Web UI `GET /api/health` on Android 14.
3. **P0 Secrets:** verify all existing credential slots, opt-in probe semantics, atomic write/recovery, app-home file permissions, quota safeguards and stale receipt display.
4. **P1 Hardware parity:** permissioned Android NFC/BLE scanning with raw-event provenance, source attribution and resilient app-private evidence storage; explicitly verify without root.
5. **P1 RHINSER behaviour:** differential feature-by-feature tests against originals; migrate existing case schema and remaining read-only functions to Rust; report unsupported Android capabilities.
6. **P2 Optimisation:** profile on ARM64 before eliminating files or dependencies; deduplicate implementation only after regression gates pass. Do not equate number of files with runtime speed, heap use or APK size.
7. **P2 Documentation cleanup:** mark stale docs, fix references, snapshot full history, and remove only those independently proven redundant.

**Acceptance criterion:** zero *known* defects in tested, supported paths, with reproducible build and actual Android execution. An unconditional promise of zero future regressions or perfect operation across all phones cannot be substantiated.