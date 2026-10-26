# Huntsman implementation handoff

This is the entry point for an agent upgrading the real repository. Read it, the
current `AGENTS.md`, and the generated roadmap before changing code. The queue
records intended work and acceptance criteria; a generated file tree records an
immutable source snapshot. Neither is a claim that the repairs are implemented.

## Refresh the document

From a clean clone with Git 2.43 or newer and Rust 1.87 or newer:

```sh
git rev-parse HEAD
git status --short --untracked-files=all
cargo run --locked -p xtask -- roadmap check
mkdir -p target/implementation-map
cargo run --locked -p xtask -- roadmap markdown > target/implementation-map/HUNTSMAN_IMPLEMENTATION_MAP.md
cargo run --locked -p xtask -- roadmap json > target/implementation-map/HUNTSMAN_IMPLEMENTATION_MAP.json
```

Generation reads the **committed** `docs/implementation/queue.json` and complete
Git tree at the captured HEAD. Make a coherent commit before regenerating edits.
Uncommitted changes are explicitly labelled and excluded. Each output records the
commit, tree object, observation timestamp, dirtiness and verification scope.
Git replacement objects, filesystem-monitor hooks, optional index writes and
lazy object fetching are disabled. Partial clones missing required local blobs
are refused; materialize them explicitly before generation. No environment
credentials, ignored files, symlink targets or remote providers are read. The tool never executes queue command strings.

The existing `completion` workflow publishes both register views as the
`huntsman-adaptive-completion` artifact on PRs, main pushes, manual dispatch and
its daily 06:17 UTC (16:17 Australia/Brisbane) schedule. One workflow owns refresh;
no additional scheduled controller is introduced. Generated files do not rewrite
sources, make commits or implement repairs. Download the exact run/commit artifact.

## One task authority, complementary views

The existing `docs/completion/tasks.json` owns broad capability intent and declared
status. Its `completion print|write|check` CLI and index-based output remain intact.
`docs/implementation/queue.json` adds precise implementation contracts, acceptance
commands and rollback without a second completion-state system. Each detailed task
has `register_tasks` IDs linking it to existing broad contracts. The immutable
roadmap validates that crosswalk and includes every broad definition, even those
without a detailed implementation task. Mappings describe partial coverage, not task equivalence, dependency equivalence
or completion. Execute a detailed repair only after its own `depends_on` entries.
A broad task remains open until its full acceptance criteria and all broad
prerequisites are verified, including physical handset gates. Offline radio or
wiring repairs may precede that final acceptance without completing the broader
task. Avoid duplicate implementation where coverage overlaps; record receipts
against the precise scope they prove. An authored VERIFIED label is not fresh proof.

Missing registered paths are explicit. The existing TikTok task remains visible
as unmapped broad work even though none of the ten detailed tasks claims its full
scope. Its module is present in the committed tree; presence alone does not prove
provider reachability, correct attribution or complete integration. Inspect actual
call paths and never infer a contact association from a handle alone.

## Read in this order

1. `AGENTS.md`: authorised execution, platform and evidence rules.
2. Root `ARCHITECTURE.md`, `Cargo.toml` and `Cargo.lock`: current capabilities,
   boundaries, dependency policy, formats, Rust edition 2024 and MSRV 1.87.
3. `docs/implementation/queue.json`: stable task IDs, evidence, dependencies,
   file operations, integration contracts, checks, completion and rollback.
4. Generated `HUNTSMAN_IMPLEMENTATION_MAP.md` and `.json`: one inventory entry
   per committed path, complete nested tree, inclusion hints, exact duplicates,
   path drift and shared edits. Read the whole files, not a truncated chat excerpt.
5. `src/lib.rs`, `src/cli/mod.rs`, `src/module.rs`, `src/lookup_modules.rs`,
   `src/scan_service.rs`, `src/scan_api.rs`, `src/web_server.rs`,
   `src/web_ui.html`: actual composition and execution paths.
6. `tests/architecture_doc.rs`, `tests/architecture_boundaries.rs`,
   `tests/runtime_reachability.rs`, `xtask/src/gate.rs` and `.github/workflows/ci.yml`:
   the existing verification authorities.

`docs/ARCHITECTURE.md` is an explicitly historical target-architecture discussion.
It must not override the current root map or cause a speculative directory move.
Use the existing modular monolith and xtask; no replacement repository is needed.

## Lexicon and machine contract

| Field or label | Exact meaning |
| --- | --- |
| `scope=committed_tree` | Paths and blob IDs belong to the captured immutable commit. |
| `working_tree_clean=false` | Current edits exist; the report does not inventory them. |
| `entrypoint` | Conventional Cargo source-root path; explicit manifest targets need review. |
| `declared_reachable` | Syntactic declaration/literal inclusion path from a conventional root, across all cfg branches. Compilation and runtime use are not established. |
| `unlinked_candidate` | No inclusion path found by this limited scanner. Investigate cfg, path/include macros, custom targets, generated code, fixtures and public consumers before changing it. |
| `not_assessed` | No supported conclusion. This is the compatibility label for every file. |
| `duplicate_groups` | Equal committed regular-file Git blob identities; review-only. Intentional directives and fixtures must be preserved. Semantic duplication is not assessed. |
| `ready_for_execution` | A root queue task with current target paths; no work or tests have run. |
| `awaits_dependencies` | Earlier task outcomes must be established before implementation. |
| `needs_path_review` | A modify/inspect target disappeared, or a create target now exists. Revalidate the task; do not guess a new path. |
| `shared_edit_paths` | Multiple tasks intend to edit the same file. Serialise those changes or reconcile isolated branches before merging. |
| `verification=not_run` | The generator provides no test, security, device, performance or deployment receipt. |

`schema=huntsman.implementation-queue` contains `tasks`. Each task requires:
`id` (stable lower-case kebab identifier), `priority` (0..3), `title`,
`depends_on` (other IDs), `evidence`, `interfaces`, `files` (path/action),
`acceptance`, `done_when`, and `rollback`. Text-array fields must contain nonblank
strings; each path is repository-relative, with no absolute/traversal components.
Actions are `inspect`, `modify`, or `create`. A task names each path at most once.
Dependencies must be unique, resolvable and acyclic. Among available tasks, lower
priority numbers run first, then lexical IDs; prerequisites always precede dependents.

The optional `register_tasks` array references exact IDs in the existing broad
completion register. Unknown or repeated references are refused.

The detailed schema has no automatic completion flag. Archive successful task decisions
and their receipts in a reviewed change, then remove or revise the corresponding
queue task and dependency edges together. Preserve unresolved evidence and external
blockers. Merely editing a task's text cannot make the generator certify success.

The generator uses existing `syn` and `serde_json` in xtask only. It retains
metadata and inclusion edges, reads blobs through one Git batch process, and parses
one source at a time. Metadata is capped at 16 MiB, source blobs at 2 MiB and the
queue at 1 MiB. Oversize input is refused; it is never silently omitted or truncated.
Inclusion traversal is capped at 100,000 file/module contexts. No phone runtime
dependency, daemon, LLM, paid API or persistent analysis cache is added.

## Implementation sequence and integration rules

Run the ordered queue against the actual checkout. Establish baseline receipts
before altering behaviour. Prioritise aggregate export memory, credential authority
and expensive-request admission. Shared provider pacing follows authority migration.
Reconcile executable wiring and source independence before increasing capability.
Legacy parity closes in individual measured increments. Physical handset acceptance
is an explicit external gate, not something a code-generating agent can fabricate.

For each implementation, trace the existing path:

`collector/parser -> guarded transport -> lookup dispatch -> module selection ->
scan service -> CLI/API -> Web UI -> export/evidence`

Use current symbols and signatures after reading their definitions. Preserve
`SourceExecutionOutcome` distinctions: missing key, timeout, WAF/challenge, failed
authentication, unsupported, successful empty response and confirmed miss are
different outcomes. `source_registry` discovery URLs are leads, not collectors or
independently verified evidence. Keep original observations and lineage immutable.

Before an apparently unwired file is removed or activated, record its declarations,
cfg branches, manifest targets, public exports, test/fixture/asset role and caller
evidence. Run the authoritative architecture/reachability checks. Do not erase
intentional directive mirrors (`AGENTS.md`, `CLAUDE.md`, `CONTRIBUTING.md`,
`GEMINI.md`, `RULE.md`, `HUNTSMAN_CANONICAL_TEAM_DIRECTIVE.md`), embedded data or
golden fixtures simply because their committed contents match.

Default resource choices for new work are bounded workers, bounded queues,
streaming or bounded batch I/O, finite deadlines/retries, checked size arithmetic,
minimal persistence and incremental writes. Reuse `PipelineLimits`, `fsio`, the
existing HTTP client/fetch boundary, provider credential registry, worker permits,
scan service/store and native MITM evaluator. Measure before increasing caches or
parallelism. Do not add an async runtime, mandatory cloud service, root requirement,
second key store or duplicate collection engine for convenience.

Wi-Fi/cell observations can be unavailable, stale or historical. A reused SSID,
new BSSID or security variation is a review indicator, not proof of interception
or attribution. Preserve the native eligibility and uncertainty semantics across
CLI and Web UI. Never claim rootless radio observations resolve an active MITM.

## Receipt and merge protocol

Write a failing behavioural regression test, reproduce the defect, implement the
smallest compatible repair, then run focused tests and the existing full gate.
Use a separate reviewed PR for each coherent improvement; do not accumulate all
queue tasks into one speculative rewrite. Keep operator data and credentials out
of Git. Never invoke lifecycle scripts merely to make an unreviewed main push.

Each external verification receipt should contain these fields as ordinary JSON:

```json
{
  "kind": "host_test",
  "commit": "the actual full tested commit SHA",
  "tree": "the actual full tested tree SHA",
  "working_tree_clean": true,
  "command": "the exact command executed",
  "toolchain": "the observed compiler/tool version",
  "target": "the observed target, with host/device distinction",
  "started_at": "actual ISO-8601 timestamp with timezone",
  "finished_at": "actual ISO-8601 timestamp with timezone",
  "exit_code": 0,
  "log_sha256": "SHA-256 of the retained complete execution log",
  "limitations": []
}
```

The example defines fields; its example zero exit code is not an executed receipt.
Keep test-generated fixtures isolated. Log commands, toolchains, target and source
identity; never secret values. Refresh the handoff after a verified change. Pending
or failed CI, unavailable device access and missing credentials remain explicit.

Before merging, check the exact reviewed PR head, no unresolved material review
findings, full host/MSRV gates and relevant Android/AArch64/browser/security jobs.
Merge through the repository's existing PR flow without bypassing protections or
force-pushing main. Re-read the merged main SHA and post-merge checks. A cross-build
proves build compatibility only. `scripts/termux-runtime-acceptance.sh` must actually
produce `TERMUX_RUNTIME_ACCEPTANCE` on the device for a handset claim; its host
mode deliberately produces `HOST_RUNTIME_ACCEPTANCE` instead.

The immediate next repair in the seeded queue is aggregate scan-export budgeting,
after baseline verification. Do not interpret this handoff's implementation as
completion of that repair. Continue through evidence-backed, finite acceptance
criteria; absolute design completion cannot be established for a changing system.
