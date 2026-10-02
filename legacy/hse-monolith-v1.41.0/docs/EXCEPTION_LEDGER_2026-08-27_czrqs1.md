# Exception Ledger — 2026-08-27 (branch `claude/huntsman-consolidation-czrqs1`)

Files/constructs not ported to Rust, or Rust-adjacent constructs not
remediated to the theoretical ideal, with justification — per the
"Rust exclusively, exceptions only where genuinely infeasible" mandate and
the completion criterion "every remaining advisory waived with written
justification."

## Non-Rust files (intentional, pre-existing — not this run's decision to make)

| File(s) | Language | Justification |
|---|---|---|
| `scripts/*.sh`, `install.sh` | POSIX shell | Bootstrap/install/CI-glue scripts that must run *before* any Rust toolchain is guaranteed present (installing the toolchain is one of `install.sh`'s own jobs). Porting the installer to Rust would require a second bootstrap mechanism to run the Rust installer itself — the shell script is the correct tool for "get a Rust toolchain onto a bare Termux/Linux/macOS box," not a workaround. |
| `.github/workflows/*.yml` | YAML (GitHub Actions) | CI configuration format mandated by the CI platform; not source code. |
| `docs/**/*.md`, `README.md` | Markdown | Documentation, not source code. |
| `deny.toml`, `dep-cooldown.toml`, `.gitleaks.toml`, `rust-toolchain.toml`, `Cargo.toml` | TOML | Tool configuration formats mandated by their respective tools (`cargo-deny`, this repo's own `dep-cooldown` binary, `gitleaks`, `rustup`, `cargo`); not application logic. |
| `src/web/js/*.js`, static HTML/CSS under `src/web/` | JavaScript/HTML/CSS | The embedded browser-side SPA for the Web UI. A browser cannot execute Rust directly without a WASM compilation step this codebase does not use; the frontend talks to the Rust backend exclusively over its own HTTP API (`src/api/`). Out of scope for a *backend* Rust migration audit — no server-side logic exists in these files.

None of these were introduced or modified by this run beyond the specific,
narrow fixes recorded in the issue ledger (`.gitleaks.toml`'s two new
detection rules).

## Pre-existing, already-justified waivers (re-verified, not re-litigated)

| Item | Justification | Re-verification performed this run |
|---|---|---|
| `RUSTSEC-2024-0436` (`paste` crate, "unmaintained") | `deny.toml`'s own comment: transitive-only (via `image`'s `exr`/`rav1e` codec deps), reachable only under `--all-features`, no upstream-adopted replacement, removal trigger documented (drop the moment `image`/`exr`/`rav1e` stop depending on it). | Confirmed `cargo tree -i paste` on default features prints nothing (genuinely `--all-features`-only, matching the waiver's claim); confirmed the crate is still absent a viable in-tree replacement. Waiver text is accurate and current — not re-litigated further. |

## Constructs reviewed and confirmed NOT exceptions (no waiver needed)

- **`termux_sensor`'s shell-out to `termux-*` CLI tools**: not a Rust
  exception — it is ordinary `tokio::process::Command` usage from Rust
  code, invoking a platform tool that has no Rust API (Termux's Android
  telephony/sensor bridge is only exposed as a CLI). This is the
  documented "platform-specific calls" risk class from Phase 0's own
  checklist, not a non-Rust file.
- **`fuzz/` sub-crate**: a second `Cargo.toml`/`Cargo.lock`-bearing crate,
  but still 100% Rust (a `cargo-fuzz` harness) — not a workspace exception,
  just a second compilation unit. Its lockfile staleness is recorded as
  IL-8 in the issue ledger (a bug, not an exception), not listed here.
