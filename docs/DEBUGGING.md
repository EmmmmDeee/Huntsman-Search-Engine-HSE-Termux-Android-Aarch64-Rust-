# Debugging & Diagnosis (Termux aarch64, no root)

HSE is designed so that when something fails on-device — and it will, repeatedly,
while you're getting it dialled in — **diagnosis is one paste away**. Every run
leaves a full, secret-redacted debug trace, and a single command bundles
everything an assistant (Claude Code) needs to root-cause the failure.

Everything here is **100% local and deterministic**: no telemetry, no external
service, no network call in the diagnostic path. Logs are scrubbed of
credentials before they're ever written or shared.

---

## TL;DR — the loop

```
0. Right after install:  hse selftest      # offline, 5-stage health check
1. It broke.
2. Run:   hse doctor --bundle
3. Paste the output (or ~/.huntsman/hse-debug-report.txt) to Claude Code.
4. Apply the fix, re-run. Repeat.
```

**`hse selftest`** is the fast first check on a fresh device: it runs storage,
the image codec, the parsers, a **real offline scan** (`phone_intl`, no
network), and the cross-correlation builders, printing a per-stage `[ok]`/
`[FAIL]` report and exiting non-zero if anything is wrong. It needs no keys and
makes no network calls, so it isolates *install/build* problems (a broken
bundled SQLite or `image` decoder on this aarch64 device) from *scan-time*
problems (network, keys). Paste a failing `selftest` straight to Claude Code.

If the **install** broke (before the binary exists), share
`~/.cache/hse-install.log` instead — `install.sh` writes a self-diagnosing
snapshot (OS/arch/Termux version/paths/toolchain) to the top of it.

---

## Where the logs live

| Log | Path | What |
|-----|------|------|
| Runtime | `$HOME/.huntsman/logs/hse.log` | **Always-on `debug`** trace of every run — module start/done/error, expansion ticks, relation/correlator output, HTTP failures. Size-rotated (`hse.log.1`) past 5 MB. |
| Install | `$HOME/.cache/hse-install.log` | Full `install.sh` transcript incl. the up-front diagnostic snapshot. |
| Bundle | `$HOME/.huntsman/hse-debug-report.txt` | Written by `hse doctor --bundle`. |

The runtime log is captured **regardless of terminal verbosity** — so a failure
on an ordinary run is already recorded; you don't have to reproduce it with a
flag.

## Verbosity

| You want | Do |
|----------|----|
| Clean terminal (default) | *(nothing)* — `info` on stderr; full `debug` still goes to the file + Web UI. |
| Debug on the terminal too | `hse -v <cmd>` |
| Trace (everything) on the terminal | `hse -vv <cmd>` |
| A specific target filter | `RUST_LOG=huntsman_search_engine::core::engine=trace hse <cmd>` |
| Just the media modules | `RUST_LOG=hse::exif_geo=debug,hse::doc_meta=debug hse <cmd>` (they log under the short `hse::<module>` target; the always-on file log captures them at `debug` regardless) |

## Watch it live in the Web UI (SpiderFoot-style)

```
hse serve        # binds 127.0.0.1:8080 (localhost only)
```

Open `http://127.0.0.1:8080` in Chrome/Firefox on the device → **Logs** tab: a
dark, level-coloured, auto-scrolling console streaming the same `debug` trace
live (SSE), with pause / clear / substring-filter. Backed by
`GET /api/v1/logs/stream` (live) and `/api/v1/logs/recent` (on-disk backfill).

## The diagnostic bundle — `hse doctor --bundle`

One **offline, redacted** report (stdout + `~/.huntsman/hse-debug-report.txt`):

- HSE version; OS/arch; `HOME` / `PREFIX` / `SHELL` / `TERMUX_VERSION` / `PATH`.
- Storage health (DB opens?), module counts by cost tier.
- **Key *names* only** that are loaded (values are never printed).
- **Termux:API sensor tools** — which of `termux-location` / `termux-wifi-scaninfo`
  / `termux-telephony-cellinfo` / … resolve on `PATH` (missing ⇒ those sensor
  modules no-op, which is expected and harmless).
- **Image pipeline self-test** — an offline encode→decode→hash round-trip that
  proves the pure-Rust image decoder + DCT perceptual hash actually run on this
  device (the main aarch64 risk from the `image` dependency). Shows
  `ok` or `FAIL — <reason>`.
- **Recent scans** incl. any `Failed` status and its error.
- Redacted tails of the runtime and install logs.

It makes **no network calls and spawns no subprocess** — pure introspection +
local file reads, so it's safe to share and reproducible.

## Common Termux failure modes → what to check

| Symptom | Likely cause | Check / fix |
|---------|--------------|-------------|
| `pkg update` fails | Play Store Termux (abandoned) | Reinstall from **F-Droid**; `install.sh` already refuses the Play Store build. |
| Build OOM / killed | < ~1.5 GB RAM | `install.sh` sets `CARGO_BUILD_JOBS=1`; add swap; close apps. |
| TLS handshake errors | Wrong system clock | Android → Date & time → *Set automatically*. |
| Sensor modules return nothing | `termux-api` package / APK missing | `pkg install termux-api` + install **Termux:API** APK from F-Droid. Bundle shows which tools are missing. They no-op cleanly otherwise. |
| `hse: command not found` | `$PREFIX/bin` not on `PATH` | Restart the shell, or `source ~/.bashrc`. |
| Scans return few/no entities | No keys (free modules only) / network | `hse doctor` shows loaded keys; many modules are free and need none. |
| `image`/`zune`/`png` build error | aarch64 toolchain / RAM during compile | Pure-Rust, no C — usually RAM: `CARGO_BUILD_JOBS=1`, add swap. Confirm the codec runs after build with `hse doctor --bundle` (image-pipeline line). |
| Image module yields nothing | fetch failed / not an image / flat-or-tiny / metadata gated | Run `hse -v scan …` (or read the file log) — `exif_geo` logs the exact reason: `image fetch failed`, `no fingerprint`, `below keep threshold`, or `metadata below emit threshold`. |
| PDF (`doc_meta`) yields nothing | not a real PDF / generic author / gated | `doc_meta` logs `not a PDF (missing %PDF- signature)`, `below emit threshold`, etc. at `debug`. |

## Secret safety

Credentials never reach a log or the bundle: `HUNTSMAN_*=…`, `api_key:…`,
`token=…`, `password=…`, `bearer …` patterns are masked by the logger's
`redact` pass, and the bundle prints key **names** only. Entity UIDs and scan
IDs are deliberately **not** redacted — they're needed for diagnosis. The
runtime log is under your home dir on-device; review a bundle before sharing if
your scan targets themselves are sensitive.

## For the assistant diagnosing a bundle

Start at **recent scans** (any `Failed` + error), then the **runtime log tail**
(grep `ERROR`/`WARN`, module names, `ExpansionStop` reasons), then
**environment** (arch, Termux, `PATH`) and **sensor tools** for off-device
no-ops. Check the **image-pipeline** line — a `FAIL` there means the `image`
decoder didn't build/run on this aarch64 device and every `exif_geo`/pHash
result will be empty. For install failures, the **install log tail** snapshot
pins the toolchain/arch/network cause.

When a module "found 0" and you need to know *why*, grep the runtime log for its
short target — `hse::exif_geo` / `hse::doc_meta` log the precise reason at
`debug` (fetch failure, unsupported/truncated image, confidence-gated, not a
PDF, generic author). The gate decisions carry the actual scores
(`content_conf`, `meta_conf`, `doc_conf`) against the thresholds, so "nothing
emitted" is never a mystery.
