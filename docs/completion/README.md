# Huntsman — adaptive repository completion contract

## Mission

Maintain a single, dynamically generated, complete and implementable representation of the
Huntsman Search Engine checkout. Resolve verified integration gaps without losing existing files,
functionality, source provenance, data integrity, CLI/API contracts, web UI accessibility or
Termux Android AArch64 rootless compatibility.

This is a **repository engineering register**, not a second OSINT runtime, a self-modifying AI,
or proof that the software is complete. The implementation remains pure Rust. The register
generator lives in the existing Rust xtask workspace crate and adds **no runtime dependencies**.

## Canonical material

1. **Current Git index** — every tracked path, including non-overlapping and inactive files.
2. **docs/completion/tasks.json** — reviewed work items, declared implementation states,
   evidence, affected paths, exact actions and test/acceptance criteria.
3. **xtask/src/completion.rs** — deterministic renderer, dependency validator and sorted tree.
4. **target/completion/IMPLEMENTATION_REGISTER.md** — generated, ephemeral, complete handoff.
5. **.github/workflows/completion.yml** — regenerates and uploads the report and SHA-256 digest
   on pull requests, pushes to main, manual dispatches and the daily schedule.
6. **AGENTS.md** and existing CI/workflows — authority and quality gates, not replaced here.

The generated report names its actual checked-out HEAD. Because a source-addressed report changes
with every commit, it is deliberately kept in ignored target/ instead of being committed to the
same commit it describes. This prevents a self-referential perpetual-diff loop. The generator and
the reviewed task manifest ARE versioned; generated reports are CI artifacts.

## Execution from an existing checkout

~~~sh
cargo run --locked -p xtask -- completion print
cargo run --locked -p xtask -- completion write
cargo run --locked -p xtask -- completion check
cargo test --locked -p xtask
cargo run --locked -p xtask -- gate full
~~~

The generated artifact is at target/completion/IMPLEMENTATION_REGISTER.md. The GitHub Actions
run named **Adaptive completion register** publishes that file and its SHA-256 checksum.

The generator performs only local reads, Git-index discovery, ordered rendering, validation of
the task graph, and optional writing beneath target/. It must never fetch providers, read API
credentials, modify production source, perform deployments or merge code.

## Lexicography and file preservation

The file tree uses deterministic lexicographic directory and file order with correct terminal
connectors. It includes EVERY path returned by git ls-files -z --cached, not merely source roots.
Repository paths referenced by tasks but absent from the index appear as PROPOSED nodes; they
do not silently become existing files. The report does not follow symlinks or traverse Git-ignored
private directories.

States are deliberately scoped:

| State | Meaning |
|---|---|
| E | File currently present in the Git index; existence only, not a quality claim |
| P | Task references a file not present in the Git index; proposed/non-existing |
| REVIEW | Evidence-gathering needed; not a defect assertion |
| UNWIRED | A documented missing call/registration/data path with reproduction |
| INCOMPATIBLE | Demonstrated conflicting interface, platform or data contracts |
| INCOMPLETE | Demonstrated missing behaviour or verified failing acceptance criterion |
| MISSING | Required file absent from the actual tree, evidence recorded |
| PROPOSED | Candidate implementation, not present/approved functionality |
| BLOCKED | Concrete missing permission, external dependency or unavailable test |
| VERIFIED | Named acceptance tests actually executed and passed against a pinned revision |

Labels are not inferred from filenames or line counts. Populate UNWIRED, INCOMPATIBLE,
INCOMPLETE or VERIFIED only after including reproducible evidence. Multiple independent tasks
may reference the same path. Do not delete non-overlapping or apparently unused files based on
the inventory alone.

## Schema and dependency order

The only accepted task input is docs/completion/tasks.json with schema
huntsman.completion/1, and a list of objects containing:

| Field | Required semantics |
|---|---|
| id | Stable, unique, descriptive identifier |
| priority | P0, P1, P2 or P3; measurable impact within dependency constraints |
| state | One of the reviewed states above |
| path | Safe, relative, specific target file |
| depends_on | Exact IDs of prerequisites; no missing, duplicate or cyclic dependencies |
| objective | Observable target behaviour |
| evidence | Grounded observation or explicitly identified uncertainty |
| implementation | Precise instructions preserving existing contracts |
| verification | Executable tests and measurable acceptance conditions |

All required fields must be nonempty; arbitrary shell commands and credentials must not be
inserted into structured labels. The renderer rejects missing IDs, invalid states, unsafe paths,
unknown dependencies and dependency cycles. It repeatedly selects the highest-priority
dependency-ready task with stable ID tie-breaking.

A dependency is ordering information, NOT an assertion that its acceptance tests have passed.
Before proceeding past a prerequisite, consult its actual evidence and verification results.

## Frontier-LLM execution protocol

1. **GROUND:** Fetch main and record commit identity, tree completeness and dirty state. Load
   AGENTS.md, Cargo.toml, the manifest, the register and the exact affected files.
2. **DISCOVER:** Inspect module declarations, crate usage, CLI dispatch, registry admission,
   HTTP routes, web UI assets, source/credential policies, persistence and test coverage.
3. **CORRELATE:** Map consumers/producers and shared contracts; distinguish absent files,
   unreferenced modules, intentional independence and actually broken execution paths.
4. **PRIORITISE:** Resolve release-blocking correctness/security/integrity concerns first,
   then Android runtime and dependencies, end-to-end wiring, evidence quality and measured
   performance. Preserve the manifest's dependency constraints.
5. **EXECUTE:** Make the smallest reliable Rust repair. Add feature wiring, tests and
   documentation alongside the implementation. Preserve public behaviour and unrelated files.
6. **VERIFY:** Run cargo fmt --check, existing xtask gates, targeted tests, Android cross-build,
   CLI and loopback browser smoke tests where available. Do not substitute QEMU for handset proof.
7. **CORRECT:** Reproduce any failure, localise the root cause and re-run relevant checks.
8. **RECONCILE:** Update tasks.json with real status and test evidence; regenerate the report
   and verify all previous indexed paths still appear.
9. **PROMOTE:** Submit a narrowly reviewable PR; require exact-head checks and merge approval.
   Never bypass protected main or represent an unmerged feature as deployed.
10. **REPEAT:** Re-read the merged tree and newly available evidence. Iterate while a feasible,
    higher-value verified action remains. Report a fixed point or blockers; do not promise
    theoretical perfection or unattended model execution.

## Invariants and acceptance

- Rust workspace unchanged except justified tooling additions; no new production dependencies.
- Termux/Android AArch64 userland, no root, loopback web UI and existing CLI contract retained.
- Bounded CPU, RAM, storage, concurrency, retries, downloads and retained evidence.
- Evidence provenance, original records and negative/unknown distinctions preserved.
- No secret collection, speculative identity attribution, silent permissions changes or
  unsupported source outcome claims.
- All tracked files represented; all absent targets explicitly marked.
- Changes accepted only with exact revision, observed test results and traceable failures.
- Report is read-only; it cannot install, repair or upgrade Huntsman by itself.

The upper bound called "absolute completion in design" is operationally interpreted as:
all registered acceptance criteria proven; no reproducible blocking defects; no unaccounted
file paths or integration contracts; and no remaining justified implementation with positive
expected value under measured constraints. Any untested or unknown requirement remains explicit.
