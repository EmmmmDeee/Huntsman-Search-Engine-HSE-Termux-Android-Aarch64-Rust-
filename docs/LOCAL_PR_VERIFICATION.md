# Exact-head local PR verification for Termux

**Purpose:** Verify a candidate PR commit without invoking GitHub Actions, when Actions jobs cannot start. The result is **local handset evidence**, not a substitute for required GitHub checks or release approval.

The canonical project remains a single Rust binary with the existing verification gate:
`cargo run --locked -p xtask -- gate full`.
This wrapper only pins the source, runs that gate, checks binary build identity, and invokes the existing physical Termux acceptance script.

## On a rootless AArch64 Termux handset

Install the prerequisites if absent:

```sh
pkg install -y git rust clang jq coreutils
```

Download the wrapper from the **pinned commit**, and verify its SHA-256 before executing:

```sh
curl -fLSs -o "$HOME/huntsman-pr-verify.sh" 'https://raw.githubusercontent.com/EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-/72e71289f77dc3a4f7959346180c232457690dbb/scripts/termux-pr-verify.sh'
printf '%s  %s\n' '16da9504bedd8ac4e5b16ee6a3a290847fe81ac62dc1bb9742abc54f10209ee7' "$HOME/huntsman-pr-verify.sh" | sha256sum -c -
bash "$HOME/huntsman-pr-verify.sh" 1842 85cadfc0713ea44a00970b41d6f5f50bec7d0d17
```

The script refuses root, non-AArch64 hosts, nonstandard Termux prefixes, invalid SHA selectors, wrong fetched SHA, binary identity mismatch, a failing Rust gate, a failing device acceptance, or a PR that moved during testing.

Its private `report.json`, `gate.log`, `physical-acceptance.log` and ancillary diagnostics are stored in `${HUNTSMAN_HOME:-$HOME/.huntsman}/local-pr-gates/pr<NUMBER>.<RANDOM>/`; source checkout is removed after execution. A checksum-named build cache is reused across runs of the **same** commit only. A lock prevents simultaneous builds using that cache. If the process is killed without cleanup, inspect the corresponding lock before removing it.

On a small phone the full Rust workspace can still exhaust storage or memory despite `CARGO_BUILD_JOBS=1`. A crash or incomplete check **must never be called a PASS**. The wrapper does not modify the installed binary, push a commit, merge, or trigger paid services.

## Verification completed before publication

- `bash -n` — PASS.
- Five mock scenarios — PASS: success, Rust gate failure, physical acceptance failure, fetched SHA mismatch, and postflight PR-head mismatch.
- Full Rust gate in a real Termux checkout — **NOT RUN**.
- Physical device acceptance — **NOT RUN**.
- Protected GitHub Actions checks — **BLOCKED**, with GitHub's explicit billing-lock annotation.

The script was copied to GitHub with SHA-256 verified against the tested local source. GitHub billing locks must be resolved through account billing or GitHub Support. Do not weaken branch protections or move this code into `main` without required verification.
