# Changelog

All notable changes to this project are documented in this file.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
project versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

While the project is `0.x`, the public API may change at any point — minor
versions can include breaking changes; patch versions are bug-fix-only.

## [Unreleased]

### Fixed (post-v0.8.0 merge — Termux installer + doc polish)

- **`install.sh` aborted on Termux 0.118.x** during the disk-space
  sanity check with `awk: fatal: attempt to access field -2`. `df -m
  $HOME` on Android can emit a row with too few fields, and the
  unconditional `$(NF-2)` becomes a negative field index — fatal under
  `set -euo pipefail`. Reproduced end-to-end on a real device
  (`TERMUX_VERSION=0.118.3`, aarch64, Android SDK 34). The awk script
  now guards `NF >= 4`, the pipeline is wrapped in `{...} || true`,
  and a `DISK_AVAIL_MB -eq 0` branch prints "could not read free disk
  space — skipping check" instead of falsely claiming "Only 0MB free".
  Earlier PR #4 "robust df parsing" fix only handled the *wrap-long-
  filesystem-name* case — this closes the *short-row-on-Android* gap.

### Changed (docs)

- `install.sh` post-install footer now leads with the **Web UI quick
  start** (`hse serve` + `http://127.0.0.1:8080` opened in Chrome) —
  that's the headline use case on Termux. `hse live` joined the CLI
  section.
- `docs/INSTALL.md` "Verifying the install" snippet refreshed
  (0.2.0 → 0.8.0; 5 modules → 13 modules; added a web-UI smoke test).
- `docs/ROADMAP.md` — added the missing v0.5.0 (Live mode) and v0.8.0
  (Parallel module dispatch) entries; both were marked still-planned
  even though they shipped. "After 1.0" + non-goals unchanged.
- `docs/MODULES.md` — catalogue heading bumped v0.6 → v0.8.
- `docs/TROUBLESHOOTING.md` — added the awk-NF-2 failure mode with
  the workaround pointing at the manual install path.

### Fixed (review feedback on PR #8 + PR #9)

Thirteen real findings across `gemini-code-assist` and
`copilot-pull-request-reviewer`; nothing rejected on security/correctness
grounds. Single follow-up commit on the v0.8 branch so PR #9 stays
mergeable from `main`.

#### Security

- **`whois::query` had no read size cap.** `tokio::io::AsyncReadExt::
  read_to_string` was allowed to consume the entire stream — a malicious
  or misconfigured WHOIS server could OOM the engine on Termux. Now
  capped at 64 KiB via `(&mut stream).take(65_536)`. Real WHOIS responses
  are 2–8 KiB.
- **`liveLog()` in `spa.html` used `innerHTML` with unescaped
  event-derived strings.** A crafted `ev.error` / `ev.reason` /
  `ev.target_value` containing `<script>` would XSS the SPA. Refactored
  to build the row via `createElement` + `textContent` (which html-escapes
  by definition).
- **CORS was permissive (`allow_origin(Any)`) on loopback binds.** Any
  website opened in Chrome could XHR to `127.0.0.1:8080/api/v1/scans`
  and read the user's scan history. Now allows only the matching
  `http(s)://<bind>` origins, plus the `localhost`/`127.0.0.1`/`[::1]`
  aliases on the same port for loopback binds. The SPA is same-origin
  so this loses no in-product functionality.

#### Correctness

- **`engine::run` left scans stuck in `Running` on persistence error.**
  If `upsert_entity` or the final `upsert_scan` failed (disk full, db
  locked), the run returned an `Err` without ever marking the scan
  `Failed`, leaving the History tab with an entry that never finishes.
  Now any persist-phase error short-circuits to `Failed` + persisted
  `error` string + emitted `ScanComplete{entity_count:0}` event so
  SSE consumers don't hang.
- **`termux_cmd` left timed-out child processes running.** Tokio's
  `timeout()` cancels the future but doesn't kill the child unless
  `Command::kill_on_drop(true)` is set. Now set, so a hung
  `termux-location` is SIGKILLed when its timeout fires.
- **`cli::cmd_live` matched on JSON substring.** Detected the
  terminator with `s.contains("\"type\":\"live_stop\"")` — fragile
  against any future serialiser change. Now pattern-matches
  `EventKind::LiveStop { .. }` before serialising and threads an
  `is_terminator` bool through the stream.

#### API consistency

- **`modules_list` serialised `ModuleCost` via `format!("{:?}", x).
  to_lowercase()`.** Produced `"keygated"` rather than the established
  serde snake_case `"key_gated"`. Now serialises via `serde_json::
  to_value` so JSON callers see the canonical form.

#### Performance

- **`LiveSession.scan_ids` was a `Vec<String>`.** Every event on the
  shared `EventBus` triggered an O(N) linear scan inside
  `session_owns_scan` (called per event per live SSE subscriber). Now
  a `HashSet<String>` — O(1) per-event. Big win for long-running
  sessions with hundreds of iterations.
- **`whois::find_referral` kept allocating `to_lowercase` strings per
  line** despite the v0.5 commit that introduced the zero-alloc
  `starts_with_ascii_ci` helper for the other parsers. Now uses the
  helper consistently.

#### Memory leaks

- **`LiveInner` retained unused `JoinHandle`s forever.** The `joins`
  map was written to in `start()` but never read from — purely dead
  state that grew with every new live session. Field deleted; tokio
  reaps spawned tasks itself.
- **`cancels` map never pruned terminal sessions.** `mark_completed`
  and `mark_stopped` now remove the entry. `sessions` is left intact
  so `GET /api/v1/live/{id}` keeps returning the completed record.

#### Docs / comments

- **`TargetKind::canonical_str` docstring claimed CLI and API would
  produce "the same scan_id for the same target".** False — `scan_id()`
  mixes `unix_now()` so the id changes every invocation. The actual
  invariant is narrower: both interfaces feed the same canonical kind
  string into the hash. Reworded.
- **`api::handlers::scan_create` carried the same misleading docstring.**
  Same fix.

#### Verification

- `cargo fmt --check` — clean
- `cargo clippy --all-targets -D warnings` — clean (re-stripped one
  `Any` import made unused by the CORS cleanup)
- `cargo test` — **94 pass** (84 lib + 10 integration)
- `shellcheck --severity=warning install.sh` — clean
- Release binary 4.9 MB stripped — unchanged

## [0.8.0] — 2026-05-23

### Added
- **Parallel module dispatch.** `ScanOptions::max_concurrent` has been a
  documented field since v0.1 but was never honoured — the engine ran
  modules sequentially. Now, when `max_concurrent > 0`, the engine spawns
  up to that many module tasks in flight at once via
  `tokio::sync::Semaphore` + `tokio::task::JoinSet`. Wall-time on a
  scan with N accepting modules drops from `sum(module_durations)` to
  roughly `max(module_durations) × ceil(N / max_concurrent)`.
- Default remains `max_concurrent = 0` → sequential, byte-identical to
  v0.1–v0.7. The change is fully opt-in.

### Notes
- The sequential and concurrent paths share all module filter logic
  (allowlist, exclude, free_only, passive_only, accepts) so behaviour
  differs only in scheduling.
- Event ordering: with concurrent dispatch, `ModuleStart` events from
  different modules interleave with each other and with `EntityFound`
  events from faster modules. Each event is self-describing (`type` +
  `module`), so SSE consumers handle this transparently. CLI tracing
  logs will look interleaved — accepted trade-off for the speedup.
- 94 tests pass (84 lib + 10 integration); +3 new integration tests
  cover: concurrent execution is faster than sequential (4 × 200 ms
  modules with max_concurrent=4 complete in < 600 ms instead of > 800 ms);
  semaphore cap is respected (6 modules with max_concurrent=2 never see
  peak in-flight > 2); max_concurrent=0 still uses the sequential path
  (peak in-flight stays exactly 1).
- Release binary stays at 4.8 MB stripped — `JoinSet` / `Semaphore` are
  in the existing tokio feature set, no dependency added.

## [0.7.0] — 2026-05-23

### Added
- **Junction table `entity_observations(entity_uid, scan_id, observed_at)`**
  replaces the v0.2 last-scan-wins semantics that hid entities from
  older scans after a re-scan.
- New store methods:
  - `Store::scan_ids_for_entity(uid)` — every scan that observed this
    entity, most recent first.
  - `Store::observation_count(uid)` — cheap "seen in N scans" aggregate.

### Changed
- `Store::entities_for_scan(scan_id)` now joins through the junction
  table; returns every entity that scan observed regardless of which
  scan currently "owns" the legacy `entities.scan_id` column.
- `Store::upsert_entity` wraps its insert + observation row in a
  transaction so the two stay in lock-step.

### Fixed
- **Re-scanning the same target no longer hides the entity from older
  scans.** Empirically verified end-to-end:
  ```
  hse scan --kind email --value test@example.com (twice, 2s apart)
  scan 138c779a  via_junction=1  via_old_column=0   ← previously broken
  scan f8957375  via_junction=1  via_old_column=1
  observations table: 2 rows, 1 distinct entity
  ```

### Migration
- On `Store::open` a one-time idempotent backfill populates
  `entity_observations` from the existing `entities` table:
  `INSERT OR IGNORE ... SELECT uid, scan_id, observed_at FROM entities`.
  Existing databases gain multi-scan tracking from the moment they
  next see an entity upsert; pre-v0.7 entities keep their single
  recorded observation.

### Notes
- 84 tests pass (77 lib + 7 integration); +4 new junction-table tests
  cover: entity observed by two scans appears in both; `scan_ids_for_entity`
  returns all observers newest-first; entity only in scan A doesn't leak
  into scan B; re-observing the same (uid, scan_id) pair is idempotent.
- Release binary stays at 4.8 MB stripped — no new deps, ~80 lines of
  new code in `store.rs`.

## [0.6.0] — 2026-05-23

### Added
- **Six Termux sensor modules** for on-device GEOINT enrichment. All
  `is_passive() == true`, all `cost() == Free`, all accept any target
  (sensors are environmental — they fire on every scan unless excluded).
  Off-device or with `termux-api` uninstalled, the four `termux-*`
  binary-based modules no-op cleanly (no `module_error` events).
  - `arp_scan` (pri 58) — parses `/proc/net/arp`. No termux-api needed.
    Emits one `IpAddress` + one `MacAddress` per complete ARP row.
    Tagged `local-arp`.
  - `net_interfaces` (pri 55) — reads `/sys/class/net/*/address` and
    `/operstate`. No termux-api needed. Emits one `MacAddress` per
    non-loopback interface. Tagged `local-interface`.
  - `wifi_scan` (pri 65) — calls `termux-wifi-scaninfo`. One
    `MacAddress` per visible AP, evidence carries SSID / frequency /
    RSSI. Tagged `wifi-ap`.
  - `wifi_connect` (pri 70) — calls `termux-wifi-connectioninfo`. The
    connected AP as a `MacAddress` (tagged `wifi-connected`) plus the
    device's local IP on that network as an `IpAddress` (tagged
    `local-wifi`). Filters out the `02:00:00:00:00:00` MAC-restricted
    placeholder and `0.0.0.0` disconnected-state IP.
  - `gps_fix` (pri 68) — calls `termux-location -p network -r once`
    (network provider, fast indoor fix). Emits one `Coordinates`
    entity. Confidence 0.90 for GPS provider, 0.65 for network, tagged
    `geoint` and `provider:<network|gps>`.
  - `cell_survey` (pri 62) — calls `termux-telephony-cellinfo`. One
    `DeviceId` entity per registered cell tower keyed
    `<mcc>-<mnc>-<lac|tac>-<cid>`. Evidence includes radio type
    (lte/gsm/umts/nr), dBm, ASU, level. Handles `mcc`/`mnc` arriving
    as either string or integer (varies by Android version).
- **New helper** `src/util/termux.rs::termux_cmd(cmd, args, timeout_ms)`.
  Returns `Option<Vec<u8>>` — `None` for not-found / non-zero exit /
  timeout, so sensor modules can short-circuit with a single `?`-style
  match. Same helper used by all four `termux-*` modules.

### Changed
- Module count 7 → 13. Default scans on a Termux device with
  `termux-api` installed now pick up environmental WiFi / GPS / cell
  context as enrichment. Off-device, only the file-reading sensors
  (`arp_scan` if `/proc/net/arp` exists, `net_interfaces` if
  `/sys/class/net` exists) contribute.
- Recommended pattern when sensors are unwanted: `hse scan ...
  --exclude arp_scan,net_interfaces,wifi_scan,wifi_connect,gps_fix,cell_survey`
  or use the allowlist `--modules` flag to opt in specifically.

### Notes
- 80 tests pass (73 lib + 7 integration); +18 new sensor-module tests
  cover passive/free flags, accepts() for any target, and parse-fixture
  output for arp_scan, wifi_scan, wifi_connect, gps_fix, cell_survey.
- Release binary 4.7 MB → 4.8 MB stripped (six small modules +
  termux_cmd helper).
- No new external dependencies (`tokio::process::Command` was already
  in the tokio feature set from v0.1).

## [0.5.0] — 2026-05-23

### Added
- **Live mode** (`src/core/live.rs`). Re-run a scan on a fixed interval,
  with the same `ScanOptions` and the same engine path (expansion +
  correlator included). Sessions are tokio tasks tracked in an in-memory
  registry; cancellation is via `Arc<AtomicBool>` — no extra dependency.
- New types: `LiveOptions { interval_secs, iterations }`, `LiveSession`,
  `LiveStatus`, `LiveRequest`, `LiveScanner` (cheap-to-clone `Arc` wrapper).
- New event variants:
  - `LiveStart { live_id, target_kind, target_value, interval_secs }`
  - `LiveTick { live_id, iteration, scan_id }`
  - `LiveStop { live_id, reason }`
- HTTP endpoints:
  - `POST   /api/v1/live` — start a session (returns `live_id`)
  - `GET    /api/v1/live` — list active/completed sessions
  - `GET    /api/v1/live/{id}` — single session record
  - `DELETE /api/v1/live/{id}` — request graceful stop
  - `GET    /api/v1/live/{id}/events` — SSE stream that demultiplexes
    both live-level events and the events of every scan the session has
    spawned, so observers see the full picture per iteration.
- CLI subcommand: `hse live --kind … --value … [--interval N] [--iterations N]
  [--depth N] [--free-only] [--passive-only] [--modules CSV]`. Prints
  events as compact JSON to stdout until Ctrl-C.
- SPA: new **Live** tab (sits between Scan and Entities). Form mirrors the
  HTTP request payload (target + interval + iterations + ScanOptions
  knobs); Start/Stop buttons; iteration counter; rolling event log fed
  by the live SSE stream.

### Fixed (ported from PR #6 v0.4 review)
These fixes originated as review feedback on the v0.4 PR and apply equally
to v0.5 since the live engine reuses the same code paths. Cherry-picked
onto this branch so the v0.5 PR isn't merged with regressions.
- **Severity sort was broken**: `Severity::to_string()` produced
  `"CRITICAL"` but `correlations_for_scan` ORDER BY matched `'critical'`,
  so every row hit `ELSE 4` and sort was a no-op. Added
  `Severity::as_canonical()` returning the lowercase form; storage now
  uses that, keeping the column / serde JSON / SQL ORDER BY in sync.
- **scan_id inconsistency CLI vs API**: API used
  `format!("{:?}", kind).to_lowercase()` ("ipaddress"), CLI used the raw
  user-provided `--kind` value ("ip"). Same target → different scan_ids.
  Added `TargetKind::canonical_str()` returning the snake_case form,
  used by every `scan_id()` caller (including the new live module).
- **CORS permissive on non-loopback bind**: `router(state, bind)` now
  inspects the bind address and applies restrictive CORS when not bound
  to loopback. Two new unit tests cover the detector.
- **alienvault_otx swallowed 429 / 5xx**: now only 404 is treated as
  "no findings"; other non-2xx statuses surface as `module_error` events.
- **whois parser allocated per line per key**: replaced `to_lowercase()`
  with a zero-allocation `eq_ignore_ascii_case` prefix check.
- **SPA `min_expand_confidence` rejected 0**: explicit `Number.isFinite`
  check instead of `|| 0.75` falsy fallback.
- **SPA entity-merge dropped tags**: now union-merges tags by UID.

### Implementation notes
- Each tick spawns a fresh scan via `engine.run()`. Scan IDs are
  generated by the existing `scan_id()` (which mixes `unix_now()` so
  back-to-back ticks get distinct IDs).
- Cancellation polls every 250 ms while sleeping the interval, so a Stop
  request takes at most that long to take effect even on long intervals.
- The SSE handler demultiplexes by `event.scan_id == live_id ||
  scanner.session_owns_scan(live_id, event.scan_id)` — newly-spawned
  scans show up in real time without subscribing per scan.
- Sessions are in-memory only (lost on restart, by design). Persistence
  deferred to v0.7+.
- 62 tests pass (55 lib + 7 integration); +4 new live-module tests,
  +2 new `is_loopback_bind` tests (cherry-picked).
- Release binary stays at 4.7 MB stripped — no new deps.

## [0.4.0] — 2026-05-23

### Added
- **Correlator** (`src/core/correlator.rs`). Rule-based post-scan analysis
  that runs synchronously after every scan completes and emits one
  `Correlation` per firing rule. Rules are pure functions over the
  collected entities; adding a rule is a 10-line append to
  `evaluate_rules`. Initial rule set:
  - `AU-001` Multi-source breach corroboration (Critical) — email in ≥2
    distinct breach sources. Dormant in v0.4 (only `hudsonrock` is a
    breach source so far); activates as v0.5+ adds more.
  - `AU-002` Identity cluster (High) — Email + Username + Phone all
    co-located in the same scan.
  - `AU-003` High cross-source corroboration (Medium) — any entity with
    `corroboration ≥ 3` independent sources reporting the same fact.
  - `AU-010` Infrastructure consensus (Medium) — Domain or IP confirmed
    by ≥3 distinct module sources at the evidence level.
- New `Severity` enum (`Low < Medium < High < Critical`), persisted to
  the `correlations` SQLite table with severity-sorted retrieval.
- `EventKind::CorrelationFound { correlation }` and
  `EventKind::CorrelationsDone { count }` event variants — surfaced via
  SSE so the SPA renders correlations live as they fire.
- `GET /api/v1/scans/{id}/correlations` endpoint.
- SPA: new **Correlate** tab with severity-coloured cards. Correlations
  also live-stream into the scan log during the run.
- CLI: `hse scan` table output now includes a correlations section
  beneath the entities. `--output json` adds a `correlations` field.
- Two new free modules:
  - `alienvault_otx` (Free, no key) — accepts `ip` and `domain`. Queries
    AlienVault OTX for threat-intel pulse count. Adds a third source
    that contributes to `AU-010` consensus.
  - `whois` (Free, no key) — raw whois protocol over TCP port 43 (works
    in Termux with no root). Follows IANA referrals once, parses
    registrar / dates / nameservers / registrant email.

### Changed
- Module registry grew 5 → 7. Default scans now hit OTX and whois
  alongside the existing modules, so AU-010 can plausibly fire on
  popular domains (crtsh + dns_resolver + whois + OTX = 4 sources).
- Schema: added `correlations` table with a `UNIQUE(scan_id, rule_id,
  description)` constraint so re-running the correlator on the same scan
  is idempotent.

### Notes
- 56 tests pass (49 lib + 7 integration); 14 of those are new
  (10 correlator rule tests, 4 new module accepts/cost tests).
- Release binary 4.6 MB → 4.7 MB stripped.
- No new external dependencies — `whois` uses `tokio::net::TcpStream`,
  `alienvault_otx` reuses the existing rustls reqwest client.

## [0.3.0] — 2026-05-23

### Added
- **HTTP server + minimal SPA + Server-Sent Events.** New `hse serve`
  subcommand boots an axum 0.8 server bound to `127.0.0.1:8080` (localhost
  only — no LAN exposure by design). Open `http://127.0.0.1:8080` in
  Chrome / Firefox on the device.
- New CLI flag: `hse serve --bind <HOST:PORT>` (env `HSE_BIND`).
- HTTP API (`/api/v1/...`):
  - `GET /health`, `GET /version`
  - `GET /modules` — full registry with cost / passive flags
  - `POST /scans` — create a scan with full `ScanOptions` body
  - `GET /scans` — recent history (capped at 200)
  - `GET /scans/{id}` — single scan record
  - `GET /scans/{id}/entities` — entities discovered by the scan
  - `GET /scans/{id}/events` — Server-Sent Events stream (live progress)
- New embedded SPA at `src/web/spa.html` — single self-contained file
  (no CDN, no JS frameworks, ~520 lines including inline CSS + JS):
  - Scan tab with full `ScanOptions` form (incl. expansion knobs)
  - Live module-progress log fed by SSE
  - Entities tab with kind filter + value search + sortable columns
  - History tab (clickable to reload past scans)
  - Modules tab listing the registry with priority / cost / passive badges
- `tower_http::cors::CorsLayer::permissive()` (safe because we bind to
  loopback only).
- Graceful shutdown on `SIGINT` / `SIGTERM` via `tokio::signal`.

### Changed
- New dependencies: `axum 0.8`, `tower 0.5`, `tower-http 0.6`,
  `tokio-stream 0.1` (sync feature), `futures 0.3`. All rustls-compatible,
  no native-TLS, no openssl, no C-linked deps.
- Release binary 4.3 MB → 4.6 MB stripped (axum + tower bring ~300 KB).

### Notes
- No new core data-model changes; the existing `ScanOptions` /
  `EventBus` / `ScanEngine` carry the HTTP server with zero refactors.
- SSE stream closes when the client disconnects; no auto-close on
  `ScanComplete` for v0.3 — browser `EventSource` handles teardown
  cleanly when the user navigates away.

### Fixed
- CI: MSRV bumped 1.85 → 1.88 to match the `let_chains` feature actually
  used by the engine. Updated `Cargo.toml` `rust-version`, the dedicated
  CI MSRV job, the installer's `RUST_MIN_VERSION`, and all doc / badge
  references.
- CI: four clippy-deny-warnings findings introduced in the v0.2.0 +
  docs/installer PR.
  - `clippy::large_enum_variant` on `Command::Scan` — annotated with
    `#[allow]` (intentional: the variant is the full `ScanOptions`
    surface as clap-derived flags; boxing each field would obscure the
    one-flag-per-field mapping).
  - `clippy::print_literal` in `cli::cmd_scan` — `"CLASS"` moved into
    the format string.
  - `clippy::unnecessary_sort_by` × 2 — `cli::cmd_modules` and
    `ScanEngine::new` switched to `sort_by_key(|m| Reverse(m.priority()))`.
- CI: `install.sh` shellcheck warnings.
  - SC2154: `trap '...' EXIT` body refactored to a named `on_exit()`
    function so shellcheck sees the `rc` assignment.
  - SC2059: every `printf "${COLOUR}...${NC}\n"` rewritten to
    `printf '%s...%s\n' "$COLOUR" "$NC"`.
  - SC1091: `# shellcheck source=/dev/null` directive on `source
    "$HOME/.cargo/env"`.
- `install.sh`: the system-clock hint was an unrunnable awk command
  (single-quote / double-quote escaping was wrong, and the suggested
  `date -s '$(...)'` quoting would have been treated as literal anyway).
  Replaced with two clearer hints (Android Settings, or manual
  `date -s 'YYYY-MM-DD HH:MM:SS'`).
- `install.sh`: disk-space probe was vulnerable to empty `df` output
  yielding a non-numeric `DISK_AVAIL_MB`. Now validates with a regex
  before the arithmetic comparison.

### Added
- Single-shot installer script (`install.sh`) with full Termux aarch64
  support, dependency installation, retry-with-backoff, clock / disk /
  RAM sanity checks, idempotent re-install, and post-install verification.
- GitHub Actions CI: `cargo fmt`, `cargo check`, `cargo clippy -D warnings`,
  `cargo test`, MSRV check (1.85), and `install.sh` shellcheck.
- Issue templates (bug report, feature request) and PR template enforcing
  the architecture invariants.
- Dual MIT / Apache-2.0 license files (Rust ecosystem standard).
- Documentation tree under `docs/`:
  - `INSTALL.md` — every install path + every known Termux quirk.
  - `USAGE.md` — full CLI reference with examples.
  - `MODULES.md` — module catalogue with cost / target / synergy notes.
  - `ARCHITECTURE.md` — design decisions and invariants.
  - `TROUBLESHOOTING.md` — Termux-specific failure modes and workarounds.
  - `ROADMAP.md` — version-by-version delivery plan.
  - `DESIGN.md` — long-term north-star spec (moved from `CLAUDE.md`).
- `SECURITY.md` (security model + responsible disclosure).
- `CONTRIBUTING.md` (how to add a module, code style, commit format).
- `CODE_OF_CONDUCT.md` (Contributor Covenant 2.1).

### Changed
- `CLAUDE.md` (5,099-line design north-star) moved to `docs/DESIGN.md`.
- `README.md` rewritten to industry-standard format with badges, short
  quick-start, and links into `docs/`.

## [0.2.0] — 2026-05-23

### Added
- **Autonomous expansion engine** (`ScanEngine::run_expansion`). When
  `ScanOptions::depth > 0`, each round picks high-confidence entities
  produced so far, converts them to scan targets via
  `TargetKind::from_entity_kind`, and re-dispatches every accepting module.
  Five free modules now chain automatically into a domain → subdomain →
  IP → geo enumeration without manual command stitching.
- `TargetKind::from_entity_kind()` / `to_entity_kind()` — bidirectional
  mapper with explicit unscannable kinds (Organisation, MacAddress,
  Credential, Password, …).
- `ScanOptions` fields: `min_expand_confidence` (default 0.75 = Verified
  tier), `max_entities`, `max_wall_time_secs`. All serde-defaulted.
- `EventKind::ExpansionTick { depth, queued, visited }` and
  `EventKind::ExpansionStop { reason }` for observers.
- CLI flags on `hse scan`: `--depth`, `--min-expand-confidence`,
  `--max-entities`, `--max-wall-time`.
- Five new integration tests covering expansion depth, threshold filtering,
  budget enforcement, cycle detection.

### Fixed
- `Store::upsert_entity` was preserving the old `scan_id` column on
  conflict, so re-scanning a target left `entities_for_scan(new_sid)`
  returning zero. Last-scan-wins semantics are correct for v0.2; a
  junction table for full multi-scan tracking is deferred to v0.7+.

### Notes
- No new dependencies. No new files. ~120 lines added to `engine.rs`.
- Binary still 4.3 MB stripped.

## [0.1.0] — 2026-05-23

### Added
- Foundation: `core` (entity, error, scan, event, module trait, engine),
  `util` (rustls HTTP, key loading, scan-id), `storage` (SQLite WAL).
- Five free modules — `hudsonrock`, `crtsh`, `dns_resolver`, `ip_geo`,
  `email_to_username`.
- CLI: `scan` / `modules` / `doctor` subcommands surfacing the full
  `ScanOptions` API.
- `#![forbid(unsafe_code)]` and Termux-first defaults
  (`$HOME/.huntsman/huntsman.db`, `WORKER_THREADS = 2`,
  release profile `opt-level=z` + `lto` + `strip` → 4.3 MB binary).
- 31 unit tests + 2 integration smoke tests, all passing.
- Architecture invariants enforced:
  - rustls + bundled-sqlite only (no openssl, no native TLS, no C deps)
  - GREATEST-semantics entity merge
  - SHA-256 deterministic UIDs
  - `C_eff = clamp(C × (1 + 0.15 × ln(corroboration)), 0, 1)`
  - Classification derived, never stored
  - Passwords / credentials never written to evidence

[Unreleased]: https://github.com/EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-/compare/v0.8.0...HEAD
[0.8.0]: https://github.com/EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-/releases/tag/v0.8.0
[0.7.0]: https://github.com/EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-/releases/tag/v0.7.0
[0.6.0]: https://github.com/EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-/releases/tag/v0.6.0
[0.5.0]: https://github.com/EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-/releases/tag/v0.5.0
[0.4.0]: https://github.com/EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-/releases/tag/v0.4.0
[0.3.0]: https://github.com/EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-/releases/tag/v0.3.0
[0.2.0]: https://github.com/EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-/releases/tag/v0.2.0
[0.1.0]: https://github.com/EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-/releases/tag/v0.1.0
