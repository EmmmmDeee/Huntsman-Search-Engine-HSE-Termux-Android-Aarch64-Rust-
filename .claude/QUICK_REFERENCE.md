# Claude Code in HSE — quick reference

Everything here is wired, and `tests/agent_harness.rs` fails if it stops being
wired. The loop it belongs to: [`docs/OPERATING_ARCHITECTURE.md`](../docs/OPERATING_ARCHITECTURE.md).

## Before you push

```bash
scripts/gate.sh --quick      # fmt, check, clippy, rustdoc, tests, lints; skips MSRV + cross-build
scripts/gate.sh              # everything CI runs on a pull request
scripts/gate-receipt.sh check HEAD   # did the gate pass on exactly this commit?
```

The gate writes a receipt for the tree it checked. The `PreToolUse` hook
`.claude/hooks/pre-push-gate.sh` refuses any `git push` whose tree has none.
An amend, a rebase or a new file is a new tree, so run the gate again.
`HSE_PUSH_GATE=off` in Claude Code's own environment turns the hook off (a
person's decision). Writing it as a prefix on the command does nothing.

## Commands (`.claude/commands/`)

| Command | Runs |
|---|---|
| `/ci` | `scripts/gate.sh` (`--quick` for the inner loop) |
| `/drift` | `cargo test --test live_drift -- --ignored --nocapture` (real providers) |
| `/doc-drift` | `cargo test --test doc_drift` (docs against code) |

## Subagents (`.claude/agents/`)

| Agent | Use it for |
|---|---|
| `hse-falsifier` | Independent review of a committed range, in its own worktree: revert checks, mutations, reachability, capability loss, Termux constraints. |
| `hse-drift-watcher` | A canary gone `empty`, a `panicked` parser or a fabrication in the live drift sweep. |

## Hooks (`.claude/settings.json`)

| Event | Script | Does |
|---|---|---|
| `SessionStart` | `.claude/hooks/session-start.sh` | Cloud sessions only: toolchain and deps via `scripts/setup-dev.sh`, crate cache warm |
| `PreToolUse` (Bash, `git *`) | `.claude/hooks/pre-push-gate.sh` | Refuses a push without a gate receipt |

Personal preferences (model, effort, keybindings) belong in your own
`~/.claude/settings.json` or `~/.claude/keybindings.json`, not in this shared
file.
