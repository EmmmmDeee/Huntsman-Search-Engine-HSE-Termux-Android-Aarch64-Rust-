# HSE Autonomy — unattended operation on Termux (aarch64, no root)

How to run Huntsman Search Engine as a **set-and-forget** on-device intelligence
appliance: install once, optionally add keys and a watchlist, and let it collect,
correlate, and accumulate findings on a schedule — survives screen-off and device
reboot — reviewed from the phone browser whenever you like. No root, no daemon
manager, no cloud.

Everything here is wired by `install.sh`; this document is the operator's map of
it. The running software is the source of truth — cross-check with `hse --help`,
`hse doctor`, and `hse selftest`.

---

## 1. The autonomy stack

| Layer | Component | What it does | Set up by |
|---|---|---|---|
| Install | `install.sh` | Builds/fetches the `hse` binary, wires everything below | one command |
| Keys | `~/.huntsman.env` | Optional API keys (`HUNTSMAN_*`); ~79% of modules need none | `install.sh` template + `hse set-key` |
| Server | `hse-bg` | Runs `hse serve` under `nohup` + wake-lock (survives screen-off) | `install.sh` (Termux) |
| Collection | `hse-watch` | Sweeps a watchlist on an interval via `hse scan --input-file` | `install.sh` (Termux) |
| Autostart | `~/.termux/boot/hse-autostart` | Starts `hse-bg` + `hse-watch` on device boot | `install.sh` if Termux:Boot present |
| Review | web UI | `http://127.0.0.1:8080` in Chrome/Firefox on the device | `hse serve` / `hse-bg` |

---

## 2. One-command install

```sh
curl -fsSL https://raw.githubusercontent.com/EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-/main/install.sh | bash
```

On Termux this also: links shared storage (for sensor modules), installs
`termux-api`, writes the `~/.huntsman.env` keys template, and installs the
`hse-bg` and `hse-watch` wrappers. If the **Termux:Boot** app is installed, it
also installs a boot script so everything auto-starts on reboot.

Verify: `hse doctor` (environment + live free/key-gated split) and
`hse selftest` (module self-check).

---

## 3. APIs — light up as much or as little as you want

HSE is **keyless-first**: the large majority of modules need no key and work
immediately. Keys only *escalate* specific sources.

- **Autonomous discovery (zero-touch):** `hse provision --env-only --discover`
  scans the process environment for any `HUNTSMAN_*` key you already have —
  exported in a shell rc, injected by CI, or passed inline
  (`HUNTSMAN_SHODAN_KEY=… hse provision --discover`) — and pre-configures it into
  `~/.huntsman.env`, so a key you have anywhere becomes a persisted, active one
  with no manual step. The installer runs exactly this, so a fresh install picks
  up whatever you already have. Idempotent (only writes when something changed;
  prints key names, never values).
- **Where keys live:** `~/.huntsman.env` (created `0600`). Set them manually four
  ways:
  - edit the file directly, or
  - `hse set-key HUNTSMAN_SHODAN_KEY <value>` (single key), or
  - `hse keys add shodan <value>` (multi-key pool with rotation), or
  - the **Settings** page in the web UI (paste from the phone browser).
- **Every recognised provider** — with signup links, free-tier notes, and key
  formats — is documented in [`.env.example`](../.env.example) and
  [`docs/OSINT_API_REFERENCE.md`](OSINT_API_REFERENCE.md) (14 categories,
  ~150 providers). Many have free tiers; HSE never marks up provider pricing.
- **Check what's active:** `hse keys status` (pool health) and `hse doctor`
  (which modules are enabled vs key-gated).

For maximum coverage, add the free-tier keys first (e.g. Shodan, VirusTotal,
AbuseIPDB, GreyNoise, Hunter, Numverify, OpenCellID, WiGLE) — see the reference
for each one's free allowance.

---

## 4. Background server (always-on web UI)

```sh
hse-bg start      # nohup + wake-lock so Android can't kill it screen-off
hse-bg status
hse-bg log        # tail the server log
hse-bg stop       # release the wake-lock
```

Then open `http://127.0.0.1:8080` in the device browser. The server binds
localhost only — no LAN exposure.

---

## 5. Unattended recurring collection (`hse-watch`)

This is the autonomy core: HSE periodically re-scans a **watchlist** of seeds and
accumulates findings in the local store, with a wake-lock held.

1. Add seeds to `~/.huntsman/watchlist.txt` — one per line; blank lines and `#`
   comments ignored. The kind is auto-detected from the value:
   ```
   example.com
   alice@example.com
   8.8.8.8
   +61400000000
   ```
2. Start it:
   ```sh
   hse-watch start        # one sweep per hour by default
   hse-watch status       # seeds + running state
   hse-watch run-once     # one immediate sweep, in the foreground
   hse-watch log          # tail the sweep log
   hse-watch stop
   ```
3. Tune it (environment knobs, read at start):
   - `HSE_WATCH_INTERVAL` — seconds between sweeps (default `3600`).
   - `HSE_WATCHLIST` — watchlist path (default `~/.huntsman/watchlist.txt`).
   - `HSE_WATCH_ARGS` — extra `hse scan` flags, e.g. `--full` for the
     no-compromise preset, or `--free-only` to spend no paid credits.
   ```sh
   HSE_WATCH_INTERVAL=1800 HSE_WATCH_ARGS="--free-only" hse-watch start
   ```

`hse-watch` is **opt-in**: with an empty watchlist it does nothing, so it is safe
to leave enabled (including in the boot script) until you add a seed.

Each sweep runs the same scan for every seed and stores results per `scan_id`;
review or export them later (`hse scan --help`, the web UI, or `hse export`).

---

## 6. Autostart on boot (Termux:Boot)

Install **Termux:Boot** from F-Droid
(<https://f-droid.org/packages/com.termux.boot/>). `install.sh` then writes
`~/.termux/boot/hse-autostart`, which on every device reboot:

```sh
termux-wake-lock
hse-bg start      # web UI back up
hse-watch start   # recurring collection resumes (idle if watchlist empty)
```

To create it after installing the app, just re-run `install.sh`.

---

## 7. Battery & process survival (Android)

Android aggressively kills background processes. For true unattended operation:

- Settings → Apps → **Termux** → Battery → **Unrestricted**.
- Settings → Apps → **Termux** → **Allow background data** (for network modules).
- Keep the wake-lock (`hse-bg` / `hse-watch` acquire it automatically; the
  Termux notification shows it held).

---

## 8. Sensors as autonomous GEOINT (optional)

With the **Termux:API** app + `termux-api` package installed, the device's own
GPS / Wi-Fi / cell / ARP become collection sources (`device_sensors`,
`signal_radar`, `wifi_intel`, `cell_intel`) — no root. Grant shared-storage
access (`termux-setup-storage`, offered during install) so sensor and import
modules can read from external storage.

---

## 9. Reviewing what it found

- **Web UI** (`http://127.0.0.1:8080`): dashboard, per-scan entity graph,
  timeline, correlations, location map, and export.
- **CLI**: `hse scan --help` (list/replay), `hse export`, `hse diff` (what
  changed between scans of the same target).

---

## 10. A frictionless repository

CI is deliberately lean and meaningful — the checks that run are the project's
real quality gates (format, clippy-as-errors, tests, MSRV, and the
aarch64-Termux build), plus advisory-only supply-chain scans (`cargo-audit`,
`cargo-deny`) that never block an unrelated change. The stock **Snyk container**
starter workflow was removed: HSE ships no container image (a Dockerfile would
contradict the single-binary/Termux thesis), so that scan could only ever fail,
and supply-chain coverage is already provided by cargo-audit + cargo-deny.
