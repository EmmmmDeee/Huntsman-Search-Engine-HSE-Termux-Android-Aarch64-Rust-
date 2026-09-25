# Operating architecture — Huntsman × Claude Code

How work on HSE is coordinated, executed, checked and accepted. The directive
([`RULE.md`](../RULE.md), [`OPERATIONAL_CONSTITUTION.md`](OPERATIONAL_CONSTITUTION.md))
defines what must be true. This document says which mechanism makes each part
of it happen. For every part it also says whether this repository enforces it,
Claude Code provides it, or only a person or a device can supply it.

The principle: **prose states invariants and objectives; mechanisms enforce
the execution topology.** A rule that exists only as text in a prompt
depends on being read, and a rule that depends on being read eventually
isn't followed. Wherever the repository can turn a rule into a mechanism, it
does, and a test fails if the mechanism stops working.

## 1. The loop

```
OBJECTIVE → COORDINATE → DECOMPOSE → PARALLELISE (isolated) → IMPLEMENT
  → TEST → GATE RECEIPT → FALSIFY → PR + CI (auto-fix until green)
  → ULTRAREVIEW → MERGE → REAL TERMUX ARM64 ACCEPTANCE → ACCEPT / REPAIR
```

Each stage produces a different kind of evidence, and none substitutes for a
later one. Cloud success proves cloud success. It does not prove that HSE
works on Android, in Termux, on aarch64.

## 2. Where each rule lives

| Requirement | Mechanism | Status here |
|---|---|---|
| Global objective, constraints, acceptance policy | Claude Code [Project](https://code.claude.com/docs/en/claude-projects.md) instructions | Native. Set in claude.ai, not in git. |
| Durable lessons across sessions | Project memory; for repository facts, [`CLAUDE.md`](../CLAUDE.md) | Native, plus checked-in `CLAUDE.md`. |
| Repository map, invariants, where a change fits | [`CLAUDE.md`](../CLAUDE.md), [`ROADMAP.md`](ROADMAP.md), [`REQUIREMENTS_LEDGER.md`](REQUIREMENTS_LEDGER.md) | Enforced. `tests/doc_drift.rs` holds the map, ledger and changelog to each other. |
| Bounded completion ("done" is judged by evidence) | [`/goal`](https://code.claude.com/docs/en/goal.md) with a condition the gate can check (§4) | Native. |
| Whole-codebase sweeps, audits, cross-checked research | [Dynamic workflows](https://code.claude.com/docs/en/workflows.md) | Native. The orchestration script is outside HSE, so the Rust-only rule is untouched. |
| Parallel investigation | Cloud sessions / [subagents](https://code.claude.com/docs/en/sub-agents.md) / [agent teams](https://code.claude.com/docs/en/agents.md) | Native. |
| Parallel modification without collisions | [Worktrees](https://code.claude.com/docs/en/worktrees.md), one branch per task | Native. `.claude/agents/hse-falsifier.md` declares `isolation: worktree`. |
| **The tree pushed is the tree that passed the gate** | `scripts/gate.sh` → `scripts/gate-receipt.sh` → `.claude/hooks/pre-push-gate.sh` | **Enforced** (REQ-HARNESS-001, §3). |
| **Independent falsification** | `.claude/agents/hse-falsifier.md`, a separate agent in its own worktree | **Defined and loadable.** A test fails if it stops loading. Using it is a step of the loop. |
| Worker-to-worker evidence | [Cross-session messaging](https://code.claude.com/docs/en/cross-session-messaging.md) | Native. Send evidence to whichever worker or decision it can overturn. |
| High-confidence review before merge | [`/code-review ultra`](https://code.claude.com/docs/en/ultrareview.md) | Native. It attacks reasoning. It does not replace tests. |
| CI as a repair loop | `.github/workflows/*.yml`; PR [auto-fix](https://code.claude.com/docs/en/claude-code-on-the-web.md) | Enforced by CI. `scripts/check_workflows.py` fails if the gate stops covering a PR job. |
| Recurring deterioration detection | Scheduled workflows: `live-drift.yml` (provider wire-format drift, weekly), `audit.yml` (advisories), `fuzz.yml`; [routines](https://code.claude.com/docs/en/routines.md) to act on them | Enforced for detection. A routine that answers a red run with `hse-drift-watcher` is an account setting, not a repository file. |
| Drift repair | `.claude/agents/hse-drift-watcher.md` | Defined and loadable (test-locked). |
| Final platform proof | A real Termux arm64 device (§5) | External. Only the device can supply it. |

## 3. The evidence-gated push (enforced)

`scripts/gate.sh` runs every check CI runs on a pull request.
`scripts/check_workflows.py` fails CI if the gate stops covering one. At its
start the gate reads the git **tree id** of the working tree: the tree that
`git add -A && git commit` would record. When it finishes with no failure,
at least one check executed, and that tree unchanged, it writes a receipt under
`$(git rev-parse --git-common-dir)/hse-gate/<tree>`.

`.claude/hooks/pre-push-gate.sh` is a `PreToolUse` hook on `Bash`, filtered to
git commands. For each `git push` a session issues, it resolves every ref the
push sends (following `cd DIR &&`, `git -C DIR`, refspecs and `src:dst`) and
refuses with exit 2 when a ref's tree has no receipt. The refusal names the
command that fixes it. So:

- a push of code the gate never saw is refused before it leaves the session;
- an amend, a rebase or a file added after the run is a different tree, and
  needs a fresh run;
- a push of a tree that already passed costs one file lookup, not a second
  gate run.

The receipt is a record, not a signature. A person can turn the check off for
their own sessions with `HSE_PUSH_GATE=off` in Claude Code's environment (for
example `env` in `.claude/settings.local.json`). Writing that prefix into the
command does nothing, because the hook never sees the command's environment.
`tests/agent_harness.rs` drives the real scripts in throwaway repositories. It
also fails on any hook event, settings key or subagent file Claude Code would
silently ignore. That is exactly how all three of these mechanisms were dead
before REQ-HARNESS-001.

## 4. A `/goal` condition that can be checked

```
/goal Reach a state where, on a committed tree:
- `scripts/gate.sh` passes and records a receipt for HEAD
  (`scripts/gate-receipt.sh check HEAD` exits 0);
- no test, capability or provider was removed to obtain that;
- every changed behaviour has a test that fails on the previous source;
- `git status` shows only intentional changes;
- the change has a REQUIREMENTS_LEDGER entry and a CHANGELOG line;
- hse-falsifier has reviewed the commit range and nothing it reported
  REFUTED is still open.
```

Each line is judged by a command or an artifact, never by the implementer's
confidence.

## 5. The Termux boundary

The cloud host is x86_64 glibc Linux with a different kernel, filesystem,
network and toolchain. The CI job `ci.yml::aarch64-android` cross-compiles
the library, `hse` and every test for `aarch64-linux-android`, but it runs
none of them. What a person on a real device can run today:

| Layer | Command | Proves |
|---|---|---|
| Checkout | `git fetch && git checkout <sha>`, with `git status` clean | The device runs the commit under review, not local state |
| Build + install | `bash install.sh` | Builds on-device, installs, and verifies the installed binary reports the target revision (`hse build-sha`), or rolls back to the previous binary (`hse_verify_or_rollback`, test-locked) |
| Tests | `cargo test --locked` | The suite on bionic/aarch64 |
| Real execution | `hse-test` (`scripts/standard-test.sh`) | A real keyless scan end to end, in an isolated `HOME` |
| Device interfaces | `scripts/reconcile.sh --device-only`, `hse doctor`, `hse radar` | Termux:API sensors, radar and wake-lock plumbing |
| Diagnosis | `bash scripts/diagnose.sh` | A full device report to paste back into a cloud session |

Cloud → device: `claude --teleport <session>`, or fetch the pushed branch.
Device → cloud: commit and push first, then `claude --cloud "<task>"`. A
cloud session works from repository state only. Uncommitted work on the
device does not exist for it.

## 6. Acceptance

None of these is acceptance on its own: Claude reporting done, a session
stopping, `/goal` passing, a Linux build, cloud tests, green CI, a reviewer
approving, an ultrareview with no findings. Each is a layer of evidence. For
behaviour that depends on the production platform, acceptance is **a real
Termux arm64 run of the exact commit, with reproducible passing evidence**.
