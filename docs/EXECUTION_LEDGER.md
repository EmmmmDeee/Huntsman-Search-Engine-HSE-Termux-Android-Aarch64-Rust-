# Execution ledger — canonicalisation & assurance programme

The durable checkpoint for the autonomous upgrade programme: what is verified,
what is assumed, what remains, and exactly how to resume. Updated at every
material milestone so interrupted work resumes from the last verified state
without repeating completed work. Every claim here is tied to a commit, a gate
run, a CI head, or a runtime check — `CLAIM ≠ EVIDENCE` applies to this file too.

## 1. Current state (checkpoint)

| Item | Value |
|---|---|
| `main` | `4b7ff547` — squash-merge of PR #594 (BSI 200-4 continuity model + self-update rollback proof + continuity-panel polish) on top of `a2b295da` |
| Programme baseline (before) | `cab1f9b4` (HSE v1.41.0, MSRV 1.98, edition 2024) |
| Working branch | `claude/response-accuracy-legal-u90ja3`, restarted at `4b7ff547` (`origin/main`) after the #594 merge (GitHub auto-deleted the merged head) |
| In-flight unit | ble_radar interruption / partial-persistence recovery proof — two tests in `src/storage/signal_tests.rs`, cited by `core::assurance::continuity` to derive ble_radar UNTESTED → TESTED (all six capabilities then TESTED) |
| Toolchain | rustc 1.98; `scripts/gate.sh --quick` = 16 executed checks (MSRV / aarch64 cross / wasm drift / audit are CI's authority) |

## 2. Verified facts (with evidence)

- Every unit below passed `scripts/gate.sh --quick` (15/15) before its push, and
  every pushed head went CI-green (Check & test, MSRV 1.98, aarch64-linux-android,
  hse-core + wasm-ui, clippy ×2, gitleaks, install.sh).
- Assurance maturity is evidence-derived; the static catalogue claims no A5/A6;
  `hse bsi verify` is PASS (exit 0) on the honest catalogue; `HSE-200-4-BCM` is
  TESTED/A4 from real fault-injection tests (disk-full, crash mid-write).
- ATT&CK Enterprise v17.1 is current; registry-derived TA0043 coverage is 33/44
  with 11 honest gaps (e.g. phishing-for-information, correctly not performed).
- Live drift sweep (this sandbox, `SSL_CERT_FILE` honoured): 121 probed —
  60 alive, 37 empty, 20 unreachable, 4 timed-out, **0 TLS failures**, no canary
  empty ⇒ no wire-format drift. The 20 unreachables are egress artefacts
  (HTTP 403 anti-bot, a 503, timeouts, DNS/connect under the proxy policy).
- Doc drift: 4/4 guarded checks pass. Production `unwrap()`s: none (all 27 grep
  hits were inline `#[cfg(test)]`). `allow(dead_code)`: 5 sites, all justified
  (test-enforced allow-lists, documented policy constants, a contract field).
  Termux/no-root: 0 hardcoded `/tmp`, 0 arch cfgs, no sudo/root paths.
- Restart across process instances: `hse serve` started/stopped twice on loopback
  with all state in the SQLite store; endpoints served identically after restart.

## 3. Assumptions (reversible, evidence-supported)

- "Canonicalise file-by-file" is interpreted as *evidence-driven* canonicalisation
  (user-approved): files already at their strongest state are left untouched.
- Continuity objectives quote only bounds a test asserts; the persistence MTPD
  (3600 s) is a *declared* objective, not a measured one, and is labelled so.
- Sandbox-unreachable providers are treated as environment facts, not drift,
  because none is an *empty* canary and the failure classes are transport-level.

## 4. Prioritised gaps (remaining)

Closed since the last checkpoint: **self-update rollback** (PR #594 —
`hse_verify_or_rollback` + four functional tests; self_update → TESTED) and
**BLE radar interruption / partial-observation persistence** (this unit —
two atomicity/restart tests; ble_radar → TESTED). With both closed, all six
continuity capabilities are TESTED; 0 UNTESTED, 0 OBSERVED.

1. **Providers view** — `hse bsi providers` over existing descriptors, health and
   the drift sweep (view over existing authorities; no new registry).
2. **Detection view** — correlator rules carry `rule_id`/`rule_name` on their
   findings but are plain functions (no per-rule descriptor); assess whether a
   descriptor would duplicate the producer→consumer graph before building.
3. **OBSERVED (A5) evidence** — no runtime recovery/incident record mechanism
   exists; by design nothing claims A5 until one does. This is now the only
   route to lift any continuity capability above TESTED.
4. **External:** wasm-ui/pkg drift check needs the pinned wasm-opt (CI only);
   on-device Termux end-to-end needs hardware not available here.

## 5. Changes and outcomes

| Unit | Commit | Outcome |
|---|---|---|
| Canonical BSI evidence model + `hse assurance` | `c9ae3615` | integrated, CI green |
| Gap severity (Schutzbedarf × criticality × depth) | `755e0315` | integrated, CI green |
| `hse bsi` verb family + real `verify` gate | `fee4d23d` | integrated, CI green |
| `hse attack` views over ATT&CK v17.1 | `c2194e59` | integrated, CI green |
| Image XMP people/creator/caption | `8fd651c1` | integrated, CI green |
| Image IPTC-IIM by-line/caption/place | `0dc24d83` | integrated, CI green |
| Web UI + API parity (assurance, ATT&CK) | `07c33f8a` | integrated, CI green |
| BCM 200-4 fault-injection + `HSE_SQLITE_MAX_PAGES` | `28959146` | integrated, CI green |
| `SSL_CERT_FILE` additive TLS trust (fail-loud) | `8b80588b` | integrated, CI green |
| Squash-merge of the above into `main` | `ab14593f` | merged (user-approved) |
| Continuity model + CLI/API/UI | `4406905d` | integrated (PR #594) |
| Self-update rollback proof (`hse_verify_or_rollback`) + continuity-panel `rpo_label` polish; self_update → TESTED | `6d98f646` | integrated (PR #594) |
| Squash-merge of PR #594 into `main` | `4b7ff547` | merged, CI green (user-approved) |
| ble_radar sweep-interruption recovery (2 tests); ble_radar → TESTED | this commit | gate + runtime verified |

Void after evidence: "retire 27 production unwraps" (all test code);
"dead-code audit" (all sites justified); "Termux hardening" (already clean).

## 6. Validation evidence per layer

static (fmt, clippy `-D warnings`, rustdoc lints, doc coverage) → unit (7 000+
lib tests incl. 29 assurance/continuity, 7 endpoint, 3 storage fault, 4 trust,
15 image-metadata) → architecture ratchets (registry, produced kinds, ATT&CK
map, producer→consumer, env-knob reads, SPA endpoints, README count locks) →
integration (`tests/api.rs`, `tests/architecture.rs`, `tests/smoke.rs`) →
runtime (CLI verbs, API on loopback, served UI) → live network (drift sweep).

## 7. Rollback points

- `git revert ab14593f` reverts the whole programme on `main` in one step
  (squash); `cab1f9b4` is the pre-programme state.
- Each unit is an independent commit on the merged branch history (see §5) for
  finer reverts via `git revert <sha>` on a branch built from those commits.
- Continuity unit: revert its single commit; no schema or data migration.

## 8. Restart instructions (exact)

```bash
git fetch origin main
git checkout -B claude/response-accuracy-legal-u90ja3 origin/main   # or the branch's own head
CARGO_INCREMENTAL=0 scripts/gate.sh --quick                          # 15 checks; ~10–15 min
cargo build --bin hse && ./target/debug/hse bsi verify && ./target/debug/hse bsi continuity
./target/debug/hse serve --bind 127.0.0.1:8080   # then GET /api/v1/assurance, /assurance/verify,
                                                 #          /assurance/continuity, /attack, /attack/navigator
cargo test --test live_drift -- --ignored --nocapture   # network; set SSL_CERT_FILE behind a TLS-inspecting proxy
```

Operational notes: repeated gates accumulate the root crate's test binaries —
`cargo clean -p huntsman-search-engine` reclaims ~17 GiB and keeps compiled
deps; `CARGO_INCREMENTAL=0` avoids incremental churn in low-disk sandboxes.

## 9. Failure classification applied

| Class | Response used |
|---|---|
| Resource exhaustion (ENOSPC mid-gate) | stop, `cargo clean -p`, relaunch; gate free space before launch |
| Deterministic defect (ratchet/clippy failure) | reproduce, root-cause, fix, rerun the affected suite, then the full gate |
| Dependency failure (TLS interception) | root-caused to trust config, fixed at the authority (`SSL_CERT_FILE`), re-measured |
| Invariant violation (branch reset to a stale base) | halted, evidence kept, restored to the verified merge commit with gated checks |
| External blocker (no device / no wasm-opt) | recorded precisely; CI named as authority |
