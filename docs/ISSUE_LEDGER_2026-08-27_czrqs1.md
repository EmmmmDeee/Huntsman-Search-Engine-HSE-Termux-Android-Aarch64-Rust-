# Issue Ledger — 2026-08-27 (branch `claude/huntsman-consolidation-czrqs1`)

Format per entry: ID | severity | evidence | root cause | remediation |
disposition | commit.

---

### IL-1 — Leaked SeekNow API credential in git-tracked ledger file
- **Severity**: Critical
- **Evidence**: `.agent/state.json`'s `cycle_23_provenance` narrative quoted
  a `seek-`+48-hex-char bearer token verbatim, committed ~17 days before
  discovery. SHA-256 of the value does not match any of the 11 entries in
  `COMPROMISED_EMBEDDED_DIGESTS` (`src/util/keys/constants.rs`), so it is
  not a known-dead credential and must be treated as potentially live.
- **Root cause**: routine per-cycle record-keeping quoted a mid-turn
  message verbatim without checking its shape against known credential
  patterns; `.gitleaks.toml` had no rule matching SeekNow's `seek-<hex>`
  format, and `tests/architecture.rs`'s `no_provider_credential_is_embedded_in_source`
  is scoped to `src/**/*.rs` only, so `.agent/` was outside every existing
  safeguard.
- **Remediation**: recovery point tagged locally
  (`pre-secret-redaction-huntsman-consolidation-czrqs1`) before any edit;
  value redacted in place with a dated note; `.gitleaks.toml` gained
  `hse-seeknow-key`/`hse-wigle-api-name` rules. Full writeup:
  `docs/CREDENTIAL_AUDIT_2026-08-27_czrqs1.md`.
- **Disposition**: FIXED. Follow-up for the account owner (not performed
  here): rotate the credential at SeekNow; decide on a history-rewrite
  pass (coordinated across this branch and PR #483's, which found and
  fixed the identical leak independently).
- **Commit**: `12125ede1`

### IL-2 — Placeholder API key forwarded as a live credential (3 modules)
- **Severity**: High (correctness + a minor confused-deputy risk against
  the provider — a garbage credential sent as if configured)
- **Evidence**: `opencellid`, `cell_intel`, and `abn_lookup` read their key
  via bare `ctx.key_opt(...)`, bypassing `util::keys::resolve_key`'s
  blank/placeholder filter that every other keyed module goes through.
  `hse provision` writes every template line uncommented into a fresh
  `~/.huntsman.env`, so an unedited slot holds the literal string
  `insert_..._here`.
- **Root cause**: these three modules were written against the raw
  `ModuleContext::key_opt` accessor instead of the shared
  `resolve_key`-filtered path, before or without the placeholder-filter
  convention being consistently applied.
- **Remediation**: wrapped each call site in
  `crate::util::keys::resolve_key(...)`. Regression tests added for
  `opencellid` and `abn_lookup` (construct a `ModuleContext` with the
  placeholder value, assert an empty result). `cell_intel`'s equivalent
  path is not independently end-to-end-testable in this sandbox (a live
  Termux sensor read gates it before the fixed line) — review-verified,
  covered indirectly by `resolve_key_policy`'s own exhaustive unit tests.
- **Disposition**: FIXED for these three; the audit that found this also
  noted "this same `ctx.key_opt()`-without-filter pattern recurs in ~30
  other keyed modules across the codebase" as a **systemic pattern**, not
  unique to these three. Auditing and fixing all ~30 is a larger,
  separate effort flagged as a follow-up (not performed here — would be
  its own batch of one-issue-one-fix-one-test-one-commit work).
- **Commit**: `dae4c8c70`

### IL-3 — Undocumented plaintext credential pair with no placeholder filter
- **Severity**: High (a real password, invisible to every operator-facing
  surface, with no defense against the IL-2 injection class)
- **Evidence**: `HUNTSMAN_SEEKNOW_EMAIL`/`HUNTSMAN_SEEKNOW_PASSWORD` (the
  browser-automation login fallback used when the SeekNow API key is
  absent) existed in `.env.example`, `env_template.txt`, and
  `util::keys::KNOWN_KEYS` — none. Read via raw `std::env::var(...)` with
  only a blank-string filter, no placeholder check.
- **Root cause**: this credential pair was added to the `see_know` module
  outside the standard `ModuleContext`/`ServiceDef` key-pool path (it
  authenticates a browser session, not an HTTP header), so it fell outside
  every mechanism — architecture tests included — that keeps the other
  ~65 keyed providers' documentation in sync.
- **Remediation**: documented in `.env.example` as an optional, never
  auto-provisioned pair (so adding documentation cannot itself introduce
  the IL-2 injection class). `seeknow_email()`/`seeknow_password()`
  refactored into a thin env-reading wrapper plus a pure, unit-tested
  `resolve_credential_slot()` filter, as defense in depth.
- **Disposition**: FIXED (documentation + filter). Not done: registering
  in `KNOWN_KEYS` for Settings-UI surfacing — that grid's UX assumptions
  are built around API-key strings, and a plaintext password may warrant
  different handling (masking, etc.), a design decision left as a
  follow-up rather than bundled into this fix.
- **Commit**: `782faeaab`

### IL-4 — 14 functional `HUNTSMAN_*` vars undocumented anywhere
- **Severity**: Low (discoverability only — every var has a safe default,
  none gate a credential)
- **Evidence**: `HUNTSMAN_INSTALL_DIR`, `_LOG_BUFFER_LINES`,
  `_TIDY_INTERVAL_SECS`, `_ENGINE_HEALTH_SECS`,
  `_AUTO_UPDATE_INTERVAL_SECS`, `_RAW_ARCHIVE(_DIR)`, `_WEBHOOK_URL`,
  `_PROXY`, `_PROXY_FEEDS`, `_DOH_URL`, `_OATHNET_BASE`,
  `_OATHNET_SCAN_CAP`/`_SESSION_CAP`, and the 10
  `_WIGLE_{BSSID,BT,CELL,GEO,SSID}_{SCAN,SESSION}_CAP` knobs — all real,
  wired, read in source — zero mentions in `.env.example` or
  `env_template.txt`.
- **Root cause**: these are tuning/override knobs added alongside their
  owning feature over time, outside the credential-provisioning surfaces
  the architecture tests guard; no test asserts the reverse direction
  (every consumed tuning var ⇒ documented) for non-credential vars, by
  that test's own explicit, deliberate design (documented in its own
  comment, to avoid pressuring deletion of legitimate extra docs).
- **Remediation**: documented all 14 in `.env.example` as commented/
  optional entries, with every default/example value cross-checked
  against source rather than guessed (three of the initially-drafted
  example values were caught and corrected this way — OathNet's session
  cap is a fixed 30 not "dynamic", SeekNow's session cap defaults to
  100000 not ~800, the five WiGLE per-kind caps differ from each other
  rather than sharing one number, and DoH's real default is the literal
  IP `1.1.1.1` not the `cloudflare-dns.com` hostname a first guess would
  reach for).
- **Disposition**: FIXED (documentation only — no code changed).
- **Commit**: `45d43d657`

### IL-5 — `HUNTSMAN_PROXY` flagged as a possibly-dead alias
- **Severity**: Informational (investigation, not a defect)
- **Evidence**: retention audit flagged `HUNTSMAN_PROXY` as "an
  undocumented alias sitting beside the documented
  `HUNTSMAN_SEARCH_PROXY` — likely legacy/dead-code-adjacent."
- **Root cause investigation**: traced every read site. `HUNTSMAN_PROXY`
  is read in exactly one place (`util::netrotate::configured_infra_hosts`)
  — the scan-target exclusion list, NOT the actual outbound-proxy
  configuration (`HUNTSMAN_SEARCH_PROXY` is the only var HSE itself uses
  to route requests). It is a real, distinct, intentional feature: naming
  a proxy HSE doesn't manage (e.g. a system-wide one) so HSE never
  mistakes its own egress path for a scan target.
- **Remediation**: not dead code, so nothing to remove. Clarified with a
  doc comment at the read site and documented the distinction in
  `.env.example` so a future reader doesn't have to re-trace this.
- **Disposition**: FIXED (documentation/comment clarity — confirmed NOT a
  defect after investigation).
- **Commit**: `45d43d657`

### IL-6 — Stale "DeHashed is intentionally absent" comment
- **Severity**: Cosmetic
- **Evidence**: `src/util/service_defs/mod.rs`'s comment claimed DeHashed
  had no `ServiceDef` entry, contradicted by a real `dehashed` entry added
  later in the same file (`probe_parser: None` — pool/dashboard
  integration without a working GET probe, since DeHashed v2 is
  POST-only).
- **Root cause**: the comment predates the later commit that resolved the
  limitation differently; nothing updated it when the resolution landed.
- **Remediation**: corrected the comment and the two other comments that
  pointed at it.
- **Disposition**: FIXED.
- **Commit**: `b281c52e8`

### IL-7 — Redundant explicit rustdoc link target
- **Severity**: Cosmetic (the only `cargo doc` warning found)
- **Evidence**: `src/core/resolve/mod.rs:109`'s
  `` [`canonical_email_mailbox`](crate::util::canonical::canonical_email_mailbox) ``
  triggered rustdoc's default-on `redundant_explicit_links` lint — the
  label already resolves via a local `use` import.
- **Root cause**: an explicit link target was written where the short-form
  label already sufficed.
- **Remediation**: removed the explicit target.
- **Disposition**: FIXED. `cargo doc` now builds with zero warnings.
- **Commit**: `8078ced70`

### IL-8 — Stale `fuzz/Cargo.lock`
- **Severity**: Medium (a `--locked` build of the fuzz crate was broken
  from a clean checkout — a real reproducibility defect, distinct from
  the main crate)
- **Evidence**: `fuzz/Cargo.toml`'s dependencies had grown (transitively,
  via the main crate's own growth — fuzz targets exercise
  `huntsman-search-engine`'s parsers directly) beyond what
  `fuzz/Cargo.lock` recorded. Verified pre-existing, not introduced this
  session: restoring the old lockfile and running `cargo check --locked`
  in `fuzz/` fails outright ("cannot update the lock file because
  --locked was passed").
- **Root cause**: the fuzz crate's lockfile was not regenerated after a
  main-crate dependency change that transitively affected it.
- **Remediation**: regenerated additively (`cargo check` without
  `--locked`, not a full `cargo generate-lockfile` re-resolve, to keep
  the diff to exactly the missing entries). Reverified `--locked` passes.
- **Disposition**: FIXED.
- **Commit**: `b0afe9a81`

### IL-9 — `cargo machete`'s plain run false-positives on 2 renamed-lib crates
- **Severity**: Informational (tooling false positive, not a real defect)
- **Evidence**: re-running the issue census directly (not just via
  `scripts/gate.sh`'s CI-mirroring skip path) after merging `main`, plain
  `cargo machete` flagged `kamadak-exif` and `md-5` as unused dependencies.
  Both are used extensively in non-test source (`src/util/exif.rs`'s
  `exif::Reader`/`exif::Tag`/…, `src/util/gravatar/mod.rs`'s `md5::compute`).
- **Root cause**: both crates publish under a package name that differs
  from their library/import name (`kamadak-exif` → `exif`, `md-5` → `md5`).
  Plain `cargo machete` matches usage by guessing the import name from the
  package name text (hyphens → underscores), so it never recognises
  `exif`/`md5` as satisfying `kamadak-exif`/`md-5`.
- **Remediation**: none needed — `cargo machete --with-metadata` (which
  resolves real crate metadata instead of guessing) reports zero unused
  dependencies, confirming both are genuinely used. Recorded here so a
  future run isn't misled by the plain command's output without re-deriving
  this.
- **Disposition**: NOT A DEFECT — documented false positive, no code change.
- **Commit**: none (documentation only, this ledger).

---

## Won't-fix / deferred (documented, not silently dropped)

- **~30 other keyed modules using the same `ctx.key_opt()`-without-filter
  pattern as IL-2** (per the retention audit's own explicit note). Real,
  but a separate, larger remediation batch — auditing which of the ~30
  actually risk an unedited-template scenario (vs. modules with their own
  independent blank-check) needs its own pass, not a rushed blanket
  change bundled into this ledger.
- **`HUNTSMAN_SEEKNOW_EMAIL`/`_PASSWORD` in `KNOWN_KEYS`** (IL-3) — a UI
  design decision (masking a plaintext password in a grid built for API
  keys), not a mechanical documentation fix.
- **16 other open PRs** (excluding this run's own #485) this branch's
  history substantively addresses. GitHub write access was unavailable for
  most of this session (see the audit report's "Known risks" section) and
  was restored only late in the run, after this ledger's fix commits
  landed; triaging and closing the now-superseded ones with evidence is
  left as a follow-up rather than rushed in the time remaining.
- **`RUSTSEC-2024-0436` (`paste` crate, unmaintained)** — already carries
  a written, still-accurate justification in `deny.toml` predating this
  session; re-verified as still correct (the crate is genuinely
  transitive-only, `--all-features`-only, no adopted replacement
  upstream). No action needed; not re-litigated.
