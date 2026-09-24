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

### Change 4: [DEFECT] No console view decides a scan's state from its status alone, and the flag is true across processes (REQ-SCANSTATUS-002)

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

## Next

- **REQ-SCANNAME-001.** New Scan's "Scan Name" field is never sent, so the
  name is not stored and not shown. In progress, as this run's first change.
- **Then** the highest-scoring cluster, and the open defects this run found:
  the CLI's `hse list` hint names a command that does not exist.
