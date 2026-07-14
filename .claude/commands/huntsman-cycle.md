---
description: Run one cycle of Huntsman's autonomous improvement loop — idempotent, safe to re-invoke until the backlog is genuinely exhausted.
---

# Huntsman improvement cycle

You are running one cycle of the standing autonomous loop that drives Huntsman
toward `docs/PROBLEM_TREE.md`'s mission: the fastest, most correct, most
reproducible on-device OSINT/GEOINT engine, surpassing SpiderFoot and Maltego,
without ever fabricating a finding. `docs/CONVENTIONS.md` holds the standing
source-tree rules (layering, module-per-file, single-sourced vocabularies,
determinism) this loop's step 2 must honour; step 4 below runs the full
verification gate directly — this command is self-contained, cycle after
cycle, until there is nothing left to do.

This prompt is meant to be **run again and again, unattended, until the
project is finished**. Treat idempotency as the primary correctness property:
running this cycle when real work remains must make genuine, verified
progress; running it when nothing remains must change nothing except to
confirm that. Never invent work to look busy.

## 0. Orient — read the live state, don't assume it

1. `git status` and `git log -5 --oneline`. If the working tree is dirty or
   `HEAD` looks mid-cycle (e.g. code changed but the trees/gate weren't
   updated), **finish and verify that work first** — do not start something
   new on top of an unfinished cycle.
2. Read `docs/PROBLEM_TREE.md` §3 (defects/foundations), §4 (capability
   program), §5 (execution order), §6 (verified sound — do not
   re-investigate), §7 (deferred — do not re-litigate without new evidence).
3. Read `docs/SOLUTION_TREE.md` §2 (solution tree) and §4 (gap analysis —
   the live diff between the two trees).
4. Read the newest few entries of `docs/gap_register.md` (newest at top) to
   see what the *last* cycle actually did and why, so this cycle doesn't
   repeat or contradict it.

## 1. Select exactly ONE unit of work

Smallest, highest-leverage, real. In priority order:

1. An in-progress (`[~]`) node left by a prior cycle — finish it.
2. The highest-priority open (`[ ]`) node per `PROBLEM_TREE` §5's execution
   order (P0 crash/corruption → P1 core guarantees → P2 quality/robustness →
   P3 minor → CAP capability), respecting the doctrine's stated sequencing
   rationale (§1: foundations before features).
3. A concrete coverage gap, unfinished solution, or unjustified solution
   surfaced by `SOLUTION_TREE` §4.
4. If — and only if — both trees show no open or in-progress node: run one
   fresh, code-grounded discovery pass (dead code, unwired constants, dropped
   fields, silently truncated output, `TODO`/`FIXME`/`unimplemented!`, a
   clippy lint the newer CI toolchain would catch, a real scan shape that
   exposes a gap). A finding only becomes work if it is grounded in actual
   code/data you can point to — never a speculative "might be nice."

Pick **one**. This loop advances by many small, honest cycles (see
`docs/SOLUTION_TREE.md` §5 for the established "Cycle N" granularity), not by
one large sweep.

## 2. Do the work

- Real code against real behaviour — no mocks, no fabricated data, no
  invented findings. If evidence is needed to justify a fix, find it in the
  code or a real run (`hse selftest`, `hse audit`, or the command itself —
  `docs/CONVENTIONS.md` §9).
- Hold the architecture doctrine: layering (`cli`/`api` → `core` → `util`;
  `core` never imports `modules` or `storage` directly — see
  `docs/CONVENTIONS.md` §1), one module per file (§2), single-sourced
  vocabularies (§3), normalisation-defines-identity (§4), determinism by
  construction (§5) — sort before any order-sensitive fold, deterministic
  tie-breaks, no `HashMap`-iteration-order leaks into output.
- `#![forbid(unsafe_code)]` is absolute. Never add `unsafe`, never weaken a
  guard in `tests/architecture.rs` to make something pass.
- Every module's ATT&CK mapping (`core::attack`) must stay populated —
  new/changed modules need `attack_techniques()` coverage, not a bypass.
- Add or extend a test that **fails against the unfixed code and passes
  against the fix** (`docs/CONVENTIONS.md` §7) — a regression test for a
  bug, a property test for a class of bug, a fixture-driven test for a data
  gap.

## 3. Record it — same commit, both trees

Per `docs/SOLUTION_TREE.md` §0's same-commit rule:

- Flip the status marker (`[ ]`→`[~]`/`[x]`, or add a new node) in
  `docs/PROBLEM_TREE.md` **and** the paired node in `docs/SOLUTION_TREE.md`.
- Add one dated log line to each tree's maintained log (`PROBLEM_TREE` §8,
  `SOLUTION_TREE` §5), cross-referencing the other ("Paired: `SOLUTION_TREE`
  — same commit."), matching the existing entries' voice: what was wrong/
  built, the concrete evidence, the fix, the test delta, gate status.
- If the gap changed, refresh `SOLUTION_TREE` §4.
- Add one line to `docs/gap_register.md` (newest at top): what / why
  (evidentiary or OSINT-quality value) / test count after the change.
- Add an entry under `CHANGELOG.md`'s `[Unreleased]` section, Keep-a-Changelog
  style.
- If a hand-maintained count changed (module count, rule count, test count
  quoted in prose), update every place it's quoted — `docs/CONVENTIONS.md`
  §6 exists precisely so these can't silently drift.

## 4. Gate it

Run the full verification gate — all four, not a subset:

```
cargo fmt --all -- --check
cargo clippy --all-targets --locked -- -D warnings
RUSTDOCFLAGS="-D rustdoc::broken_intra_doc_links -D rustdoc::bare_urls -D rustdoc::invalid_html_tags" \
  cargo doc --no-deps --document-private-items --locked
cargo test
```

If anything fails, fix it before proceeding — never commit red, never
`--no-verify`, never silence a lint by broadening an `#[allow]` beyond the
one site that needs it. For a behaviour-touching change, also exercise the
real surface (`hse selftest`, `hse audit`, or the changed command) per
`docs/CONVENTIONS.md` §9.

## 5. Ship it

One commit, one logical change, matching this repo's established style —
`type(scope): summary` (see recent `git log` for the live convention: `fix`,
`feat`, `test`, …). Stage only the files this cycle actually touched. Then
push the current branch (`git push -u origin <branch>`; retry transient
network failures with backoff, never force-push). This mirrors
`PROBLEM_TREE.md`'s own standing instruction that every cycle's change ships,
not accumulates unshipped.

## 6. Stop condition — the idempotency contract

Before doing ANY of the above, if step 1 finds:

- no in-progress node,
- no open node in either tree (§3/§4 of `PROBLEM_TREE`, honouring §6 verified-
  sound and §7 deferred as closed, not re-openable without new evidence),
- and a fresh discovery pass turns up no new code-grounded gap,

then the project is at a genuine stopping point. In that case:

1. Make **no** code change and touch no git state.
2. Check the top entry of `docs/gap_register.md`. If it is already a
   "CHECKPOINT — backlog exhausted" entry from this same stopping point,
   do nothing further — this run is a true no-op (this is what makes the
   loop idempotent: re-running it after completion is a no-op, not a repeat
   checkpoint).
3. Otherwise, append exactly one `CHECKPOINT — backlog exhausted` line to
   `docs/gap_register.md`, in the register's existing voice, naming what was
   closed this arc and why what remains (if anything, in §7 Deferred) is
   correctly out of scope — mirroring the precedent already in the register.
   Commit and push only this one log line.
4. Report the stopping point plainly: what "perfectly finished" means right
   now (gate green, both trees' open/in-progress sets empty, §4 gap analysis
   empty, every §7 deferral still justified) and that re-running this command
   will verify rather than repeat that state.

"Perfectly finished" is a real, checkable state under this project's own
living-document contract — not a rhetorical target. Reaching it and saying so
is a correct outcome of this command, not a failure to find more work.

## Hard constraints

- Never fabricate a finding, a mock data source, or a test fixture dressed up
  as real evidence — this is an evidentiary OSINT tool; false positives are
  worse than missing coverage (the doctrine's repeated theme throughout both
  trees).
- Never fabricate or invent PII in fixtures/tests — use only the established
  consented test seed (`Kylo4kylo`) or genuinely synthetic data; never
  handle a real third party's PII casually.
- Never expand scope mid-cycle. If step 1's chosen node turns out to be
  bigger than one focused commit, split it into the next node explicitly
  (mark `[~]`, log what's left) rather than sprawling the current commit.
- Never weaken `tests/architecture.rs`, the clippy lint table in `Cargo.toml`
  `[lints]`, or `#![forbid(unsafe_code)]` to make a change land.
