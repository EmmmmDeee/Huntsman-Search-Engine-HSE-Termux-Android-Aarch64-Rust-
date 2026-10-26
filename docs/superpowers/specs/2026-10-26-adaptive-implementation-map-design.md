# Adaptive implementation map

The operator needs an executable handoff another coding agent can use without
reconstructing Huntsman's architecture or trusting stale file trees. The deliverable
is a Rust command in the existing `xtask`, an editable ordered task queue, a complete
generated file tree, and an implementation guide. This is developer tooling; the
phone binary, Web UI, installed state, and runtime dependencies remain compatible.

## Approach

Use one immutable Git commit as the inventory authority and read its blobs through
one `git cat-file --batch` process. Require Git 2.43 or newer; disable
replacement refs, filesystem-monitor hooks, optional index locks and lazy
fetching for every Git subprocess. Refuse unavailable partial-clone blobs. This prevents uncommitted edits, symlinks, or
files outside the checkout from masquerading as the recorded revision. Report
working-tree dirtiness separately. Group identical committed blobs without
retaining their contents. Keep all file paths unique, including binary assets and
symlinks; do not silently omit paths or delete duplicates.

Alternative: maintain a handwritten tree. It becomes stale after every change.
Alternative: introduce a runtime agent or a second analysis service. It adds phone
overhead and would violate the no-runtime-LLM requirement. The existing build-time
automation is sufficient. The choice is an implementation decision under the
operator's standing instruction to execute without ordinary option questions.

## Contracts

- `cargo run --locked -p xtask -- roadmap json|markdown|check` reads the committed
  `docs/implementation/queue.json`; default output is Markdown.
- A generation is a snapshot of the exact commit, not proof of compatibility,
  execution, unused code, a deployment, or successful tests.
- Parse Rust module declarations and literal `#[path]`/`include!` sites. Walk from
  conventional Cargo roots, over all syntactic cfg branches. Unsupported macros,
  explicit Cargo targets, parse errors, and unlinked Rust files remain review
  candidates; never call them proven dead code. Existing architecture tests and
  compiler/platform receipts remain authoritative.
- Every task supplies a unique stable ID, priority 0..3, dependencies, title,
  evidence, interfaces, file operations, acceptance commands, completion rule,
  and rollback. Validate all fields, repository-relative paths and the dependency
  DAG. Order dependencies first, then priority and ID among available tasks.
- Recompute path drift and task/file conflicts. A missing modify/inspect target or
  existing create target requires review; do not silently retarget or auto-complete.
- Each file appears once in the generated tree. Task links and duplicate groups
  reference that path. `unlinked-candidate` and `compatibility-not-assessed` are
  honest scope labels, not evidence that code should be removed.
- Read-only generation: no build scripts, arbitrary queue commands, key lookups,
  code edits, commits, merges, or external provider requests. Acceptance command
  strings are instructions for the next agent, never executable input here.
- Metadata capture is bounded at 16 MiB, source blobs at 2 MiB, and the queue at
  1 MiB. Parse one source file at a time. Oversize input is refused with a clear
  error, never truncated. The product gains no dependencies or persistent cache.
- Existing CI and the daily read-only controller generate Markdown/JSON artifacts
  for their exact checkout. The guide explains manual regeneration, finite
  acceptance, dependency ordering and external device/credential blockers.

## Acceptance

Real Git fixtures prove inventory completeness, immutable provenance, no source
mutation, duplicate grouping, declaration resolution, unsupported syntax labels,
safe path rendering, DAG ordering and invalid-plan rejection. Run the existing
xtask suite, strict Clippy, repository gate and platform CI. A physical handset
receipt remains external until actually executed on rootless AArch64 Termux.

The task queue is finite and continuously revisable. A passing generator does not
establish that the listed repairs are implemented or that a design is absolutely
complete. New evidence changes priorities; receipts, not optimistic status text,
establish completion.
