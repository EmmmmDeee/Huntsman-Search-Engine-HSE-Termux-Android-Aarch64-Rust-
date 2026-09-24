# Maintainer run log

Run state: `.agent/state.json`. Repair queue: `.agent/files.md`. The 42-cycle
ledger that used to live in `state.json` is `.agent/history.json`, content
unchanged. Check its `rejected_candidates` and `verified_negatives_recent`
before selecting a candidate, so a disproven one is not re-proposed.

## Run 2026-09-23

- **Work branch.** `claude/charming-meitner-85h3aj`. The session requires
  this name, so it replaces `agent/<date>`. The branch carries two commits
  published before this run (PR #648: REQ-CI-011, REQ-SSE-001). They cannot
  be rebased without a force-push, so this run builds on them. Its first two
  changes close that PR's review findings.
- **Verification.** `CARGO_INCREMENTAL=0 scripts/gate.sh --quick` (build,
  lint, suite), then the suite twice more with per-test output: `cargo test
  --all --lib --bins --tests --locked --features dep-cooldown` and `cargo test
  --doc --locked`. Runs are compared test by test on the `test <name> ...
  ok|FAILED|ignored` lines, keyed on (test target, test name). The doc-test
  `(line N)` suffix is stripped first, because toolchain 1.98 reports it
  unreliably (CLAUDE.md). The fresh worktree is a `git worktree add --detach`
  of the commit, with `target/`, `hse-core/target/` and `wasm-ui/target/`
  symlinked to the main tree's, so dependencies are not rebuilt. One worktree
  path is reused per run, so the crate's artifacts keep one hash set on disk.
- **Baseline `cf86bded`.**
  - The gate passed (`GATE_EXIT=0`). Six checks were skipped, each with its
    reason printed:
    - wasm-ui/pkg drift, MSRV and the cross-build, because of `--quick`;
    - shellcheck and gitleaks, because they are not installed;
    - cargo-audit, deny, machete and dep-cooldown, because no manifest
      changed.
  - Suite, run twice: 8530 tests (8503 passed, 27 ignored, 0 failed), and
    both runs were identical.
  - Doctests, run twice: 86 (83 passed, 3 ignored), both runs identical.
  - No baseline failures and no flaky tests.
  - An earlier attempt died of disk exhaustion (`No space left on device`,
    `ld … signal 7`), and its results are void.
- **Repair queue.** `.agent/files.md` ranks all 1337 tracked files; its
  header gives the formula. Cursor: #1 `src/core/scan/mod.rs`, not started.

### Change 1: [DEFECT] A live iteration's scan id is in flight before any client learns it (core::live)

- **What.** The live loop mints each iteration's scan id inside
  `CancelRegistryGuard::install` and reads it back through `scan_id()`.
- **Why.** The loop sent the `LiveTick` and recorded the id on the session
  before registering it, so `/scans/{id}/events` (REQ-SSE-001) could 404 a
  running scan.
- **Evidence.** The baseline order restored in full, and `record_scan` alone
  moved above the install, both fail
  `a_live_iteration_never_hands_out_a_scan_id_before_it_is_registered`.
  Moving the announcement above the install does not compile. The fix
  restored passes.

### Change 2: [DEFECT] No test frees a port and then relies on it staying refused (test_server::ClosedPort)

- **What.** `abn_lookup` and `portscan` hold a `ClosedPort` for the whole
  test, as the eight other refused-port tests already do.
- **Why.** `abn_lookup` freed its port with an unnamed temporary, and
  `portscan` guessed its listener's neighbouring port was shut, so a
  parallel test could be handed either port.
- **Evidence.** The kernel reproduction: 5 of 20,000 freed ports answered,
  0 of 20,000 held ones. The new portscan assertion kills a scanner that
  reports a failed connect as open.

### Fresh-worktree verification of the run's three commits

Each commit ran in its own fresh worktree: the gate, then the suite twice.

| commit | gate | suite, both runs | doctests, both runs | against the previous commit |
|---|---|---|---|---|
| state-file split | passed | 8532 tests: 8505 passed, 27 ignored | 86: 83 passed, 3 ignored | the two tests PR #648 added |
| change 1 | passed | 8534 tests: 8507 passed, 27 ignored | 86: 83 passed, 3 ignored | the two new tests |
| change 2 | passed | 8534 tests: 8507 passed, 27 ignored | 86: 83 passed, 3 ignored | none |

No test failed, and no test differed between a commit's two runs. The first
row is compared with the baseline `cf86bded`, and the PR #648 commits sit
between the two.

- **Integrated.** PR #648 was squash-merged into `main` as `e364a28c` once CI
  passed on its head (8 of 8 checks). The merged tree is byte-identical to
  the verified head. The work branch restarts from that commit.

### Change 3: [FEATURE] The console's shell is SpiderFoot 4.0's (REQ-UI-002)

- **What.** The first part of the operator's SpiderFoot 4.0 remake: the
  navbar (New Scan, Scans, Settings, a More menu; Dark Mode and About), the
  footer tip, light by default with SpiderFoot's `theme=dark-theme` switch,
  and the scan list as the landing page.
- **Found on the way.** Ten icons the console emitted drew as solid squares.
  The first runtime check found a cascade bug in the new navbar and a phone
  header that pushed the toggle off-screen. All three are fixed.
- **Review.** An independent review found one blocking defect: from 768px
  to about 1,020px wide the bar wrapped onto two rows and covered every page
  title. It also found six should-fix ones. Each was confirmed on a real page
  and fixed.
- **Evidence.** All three new route tests fail on the baseline, and seven
  mutations are each killed. The runtime check passed 51 of 51, from 1280px
  down to a 320px phone. The build before the review failed 10 of those
  checks. The all-routes sweep was clean.
- **Fresh worktree.** The gate passed, and the suite ran twice: 8537 tests
  (8510 passed, 27 ignored, 0 failed), identical in both runs. Against the
  previous commit, the only differences are the three new tests. Doctests: 86
  twice, identical.

### Change 4: [DEFECT] No console view decides a scan's state from its status alone, and the flag is true across processes (REQ-SCANSTATUS-038)

- **What.** Every view that shows or acts on a scan's state now asks one
  rule, `wasm-ui/src/scan_state.rs`: the scan table, Scan Info, its Log
  tab, Scan Settings, the scan list's tallies and search, Compare, and
  Radar. The status pill had three copies and now has one.
  - The flag the rule reads is `Scan::is_interrupted` in core. Each scan
    records the process running it, so a scan another `hse` process runs is
    not called interrupted while that process lives.
  - Every create path registers a scan before writing its row, so an
    orphaned `pending` scan is flagged too.
- **Why.** A scan whose process died kept showing as running. It offered a
  Stop and an Abort button that answered 404, and its clock kept climbing.
  Scan Info re-fetched it every 8 seconds for as long as the page stayed
  open, and its Log tab held a stream open that would never carry an event.
- **Review.** An independent review of the first draft found four
  should-fix defects and six nits, none blocking. All are fixed. The worst
  was a regression the first draft introduced: a scan `hse scan` was
  running in a terminal read as interrupted. The runner fixes it. Copilot's
  two stale 768px comments on PR #650 are fixed in the same commit.
- **Evidence.**
  - A scan killed mid-run: 3 of 17 browser checks pass before the change,
    and 17 of 17 after.
  - The review's scenarios: 2 of 6 on the first draft, 6 of 6 on the final
    build.
  - An open Log tab across a server restart: the first draft reads `live`,
    the final build reads `interrupted`.
  - Twenty-two mutations are each killed, two of them by the runtime check
    alone.
- **Fresh worktree.** The gate passed, and the suite ran twice: 8550 tests
  (8523 passed, 27 ignored, 0 failed), identical in both runs. Against the
  previous commit, 13 tests are new and one is renamed; nothing else
  differs. Doctests: 86 twice, identical.
- **Open defect recorded.** Stop on a scan another process runs answers 404.
  That was true before this change.

## Run 2026-09-24: the cluster procedure

The operator replaced the maintainer procedure with a cluster-based one. The
state file now also carries `competitors`, `capability_gaps`, `clusters` and
`current_cluster`.

- **Setup.** The recorded work branch exists and `origin/main` has not moved
  past its base, so the run continues on it with no rebase. The baseline for
  this run is the fresh-worktree check of the branch head, run minutes
  before: gate passed, 8550 tests twice with identical results, 0 failures,
  doctests 86 twice. No baseline failures and no flaky tests.
- **What HSE is.** A proprietary, single-binary Rust OSINT/GEOINT/NETINT
  engine, with a CLI (including a SpiderFoot `sf.py`-compatible front end)
  and a loopback web console, for authorised investigators working from an
  Android phone in Termux without root. It is not passive-only. It forbids
  unsafe code and native dependencies, and gates new crates behind a cooldown.
- **Competitors.** SpiderFoot 4.0, Recon-ng, theHarvester, Maigret and OWASP
  Amass. Each was read from its own repository.
- **Capability gaps.** There are 21, two of them dormant: the scan name
  (being wired now), and a standalone SVG of the scan graph that
  `/scans/{id}/snake.svg` renders but nothing links to. The other 19 are
  open. Eight competitor functions were dropped because they break a hard
  constraint: an AI summary, onion fetching, screenshots, external scanners,
  a runtime module marketplace, a Cloudflare bypass, browser cookie jars and
  library embedding.
- **Clusters.** The 1221 code files form 398 directory clusters, scored by
  cheap problem signals (dead-code allowances, TODOs, unsafe, swallowed
  errors, unwraps, casts, and non-Rust lines). The score only orders
  candidates; each cluster is read in full before anything in it changes. The
  scan-name change was already in progress and crosses the wire, so it is
  recorded as two halves, server and console, split where the halves meet at
  the JSON field `options.name`.
- **Current cluster.** Scan name, server half and console half together.

### Change 5: [DEFECT] A scan's name is stored as one visible line and titles the scan everywhere (REQ-SCANNAME-001)

- **What.** `ScanOptions.name`, checked by `checked_for_request` at every
  seam: a scan, a batch item and a live session over the API, and `--name`
  on `hse scan` and `hse live`. Invisible and bidi characters are stripped,
  a tab becomes a space, and a name is trimmed. A line break, another
  control character or a name over 200 characters is refused, and the
  typed `ScanNameError` names the fault and the fix. New Scan's two buttons
  send the name through `buildWizardOptions`. wasm-ui's `scan_label` titles
  a scan by its name, with the target beside it, in the scan table, Scan
  Info, Compare and the Live page. The scan list's search moved into
  wasm-ui as `scanMatches`.
- **Why.** New Scan's Scan Name field was collected and never sent, and the
  API refused a name as an unknown option.
- **Review.** An independent review found no blocking defect and three
  should-fix ones:
  - Compare hid a named scan's target;
  - the batch button dropped the name;
  - invisible, bidi and line-separator characters passed the one-line rule.

  All are fixed, as are the nits, except a top-level `"name"` being
  ignored. Refusing it would change the public API, so it is recorded as an
  open defect.
- **Evidence.**
  - Browser check: 4 of 18 before, 18 of 18 after, then 23 of 23 after the
    review fixes.
  - After a restart on the same database: 12 of 12. The upgrade: 6 of 6.
    The previous build reads this build's database, ignoring the name: 4 of
    4.
  - `hse scan --name` runs end to end.
  - Mutations: 29 of 29 caught, each applied alone.
- **Fresh worktree.** Passed. The gate passed (doc coverage held at 1001).
  The full suite ran twice with identical results: 8559 tests, 8532 passed,
  27 ignored, 0 failed. Doctests: 85 passed, 3 ignored, twice.

### Merge: main (#649) into the branch

- **Why.** PR #649 reached main while this branch was open, touching the
  same scan lifecycle, scan handlers and console views; PR #650 could not
  merge (27 conflicting hunks in 18 files).
- **Resolution.** One status pill (wasm-ui `scan_state::status_pill`) now
  carries both sides' rules, `interrupted` from this branch and `partial`
  from #649; the scan list's search matches what the pill shows; `Scan`
  keeps both new fields (`runner`, `origin`). #649 had given
  REQ-SCANSTATUS-002 to another defect, so this branch's REQ-SCANSTATUS-002
  is now REQ-SCANSTATUS-038 everywhere but the pushed commit message.
- **Found by the gate and fixed.** A broken intra-doc link and two stale
  comments naming a function this branch removed; three #649 status reads
  the branch's lock flagged, none of a stored row (an event's and an import
  reply's final status), now exempted by file and exact read.
- **Evidence.** The gate passed (17 checks; doc coverage 998, three fewer than the
  ceiling). The suite: 8844 tests, 8817 passed, 27 ignored, 0 failed;
  doctests 88 passed, 3 ignored. `wasm-ui/pkg` matches a fresh
  regeneration. In a browser, on the merged build: a SIGKILLed scan in
  every view 17 of 17; scan names 23 of 23, and 12 of 12 after a server
  restart. No server panicked.
- **Fresh worktree.** Passed. The gate passed. The full suite ran twice with
  identical results: 8844 tests, 8817 passed, 27 ignored, 0 failed.
  Doctests: 88 passed, 3 ignored, twice.

### Change 6: [DEFECT] A key pool file that will not load is moved to a free backup name or kept, never destroyed (REQ-KEYPOOL-003)

- **What.** `util::key_pool::persistence`: `claim_backup_name` takes the
  first free name of `key_pool.json.bak`, `.bak.1` … `.bak.999` with
  `create_new`, so a backup never replaces anything. A file that cannot be
  moved aside stays where it is, and the pool that stands in for it
  (`KeyPool::never_saved`) refuses every save with both reasons and the
  remedy. `save_pool_to` is the one write path. `hse keys` prints the
  refusal first, and the console's pool add, rotate and revoke answer 409.
- **Why.** Every unusable pool file went to `.bak`, so a second one
  destroyed the first backup, and a failed rename was ignored, so the next
  save replaced the file that had not moved.
- **Review.** An independent review of the first draft found the name was
  checked, then renamed, which another process could race; it is claimed
  with `create_new` now. Its ID collided with REQ-KEYPOOL-002.
- **Evidence.**
  - Runtime on sandboxed builds: 0 of 10 checks before, 10 of 10 after.
    With one backup name freed by hand, the next command moved the file
    there, and a key added then persisted.
  - Mutations: 11 of 11 caught, the three console handlers by the runtime
    check alone.
- **Fresh worktree.** Passed. The gate passed. The full suite ran twice with
  identical results: 8848 tests, 8821 passed, 27 ignored, 0 failed; the only
  difference from the merge's verified run is the 4 new key-pool tests.
  Doctests: 88 passed, 3 ignored, twice.

### Change 7: [DEFECT] A settings.json that does not parse stops hse with the reason and is never replaced (REQ-SETTINGS-001)

- **What.** `util::settings::load_map` returns `SettingsError::{Read,
  Parse}`; `cli::run` loads the file before anything reads a toggle, and
  every command but `build-sha` and `provision --env-only` stops on a file
  it cannot use. `set_bool` reads the file again under one writer lock,
  writes, then swaps the cache. The toggle PUT answers a refusal with 409;
  `apply_update` and the serve timer (`timer_update`) read the file before
  they act.
- **Why.** A trailing comma read as no overrides, turning three
  kill-switches back on silently, and the next write replaced the file.
- **Review.** Two independent reviews; every finding fixed but one nit,
  recorded with the cross-process residual.
- **Evidence.**
  - Runtime on sandboxed builds: 3 of 19 checks before (the controls), 19
    of 19 after. Each build read the other's settings writes.
  - Mutations: 20 of 20 caught, the `apply_update` guard's by the runtime
    check alone.
- **Fresh worktree.** Passed. The gate passed. The full suite ran twice with
  identical results: 8855 tests, 8828 passed, 27 ignored, 0 failed; the only
  difference from the key-pool run is the 7 new settings tests. Doctests: 88
  passed, 3 ignored, twice.

### Change 8: [DEFECT] An unread image's file path is never mined for findings (REQ-INGEST-001)

- **What.** `cli::ingest` holds an image's OCR error while the image work
  that needs no text runs; if that finds nothing and writes nothing, the
  error is the command's (exit 1, nothing written or stored). A missing
  file says so first; tesseract is spawned without a `which` probe, and
  its own stderr reaches the error (`OcrStart`, `OcrFailed`).
- **Why.** The stand-in sentence carried the file path, which the
  extractor mined into findings, and the command exited 0.
- **Review.** Four more faults on the same path found and fixed.
- **Evidence.**
  - Runtime on sandboxed builds, no tesseract on PATH: 1 of 9 checks
    before (the control), 9 of 9 after, including a GPS-tagged photo that
    yields its fix and nothing from its file name.
  - Mutations: 11 of 11 caught, each applied alone.
- **Fresh worktree.** Passed, on the second run. The gate passed. The full
  suite ran twice with identical results: 8859 tests, 8832 passed, 27
  ignored, 0 failed; against the settings run, 5 tests are new and one
  assertion-free test went with the `which` probe it called. Doctests: 88
  passed, 3 ignored, twice. The first run was launched as a background job
  of a non-interactive shell, which ignores SIGINT, and the reconciler's
  fake radar inherited that and never exited: recorded as an open defect.

## Next

- **REQ-CLI-HINTS-001.** The hint after a stored scan named `hse list`,
  which does not exist. Re-ported onto the merged base (the hint now ends
  the shared `summary_lines`) and reviewed a second time; the review's fixes
  are in. Applied and verified on its own next.
