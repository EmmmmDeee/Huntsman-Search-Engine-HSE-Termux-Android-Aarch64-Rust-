# Canonical Huntsman

One operator repository. One crate. One installed binary.

- Repository: `EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-`
- Binary: `huntsman-recon`
- Package: `huntsman-recon` 0.2.0, edition 2024, rust-version 1.87
- Runtime dependencies (see authoritative `Cargo.toml`): serde, serde_json, thiserror, ureq, ring, miniz_oxide, crc32fast
- Target: Termux Android `aarch64-linux-android`, no root, no ports below 1024
- Value normaliser: `src/canonical.rs`

One command from a clone of `main`:

```sh
bash scripts/lifecycle.sh
```

That builds the locked binary, runs `huntsman-recon check`, runs lib tests, commits non-secret worktree changes, compares the verified commit with live remote `main`, and only when they differ pushes the exact commit to an idempotent `lifecycle/<full-sha>` review branch. It does **not** push `main` or open/merge a PR: open a PR targeting `main` and wait for its required checks before integration. No `HUNTSMAN_SYNC` flag. An interrupted test run (including exit 137 from SIGKILL or low memory) records a failed state and blocks commit/push; retry after restoring sufficient memory. A failed test must never publish unverified changes.

Each checkout builds in a cache of its own, `~/.cache/huntsman-recon-checkouts/<name>-<checksum of its path>`, or `checkouts/<name>-<checksum>` inside `CARGO_TARGET_DIR` when that is set, so two clones never build, test or push each other's code, and `run` builds before it runs. State is `~/.huntsman/lifecycle-state` (mode 600). The log is `~/.huntsman/lifecycle.log`. Secret-looking paths (`*.env`, `*.pem`, `*.key`, `credentials`, `secret`) are refused. Non-main branches and force-push are refused. Successful review-branch publication records `phase=sync`, `status=pending` rather than falsely claiming integration. A failed push leaves the local commit and a failed state file.

Phone install remains `install.sh` (pins `main` to one SHA, installs `huntsman-recon`, runs offline acceptance).

`hse` is the legacy monolith. It is not a second current engine.

Other copies are not this engine:

- `huntsman-rcvf` is a divergent experiment. Do not install it over this binary.
- `Huntsman-` is not the operator binary.
- `HSE-BLE-API-` is the BLE radar APK. It stays a separate runtime because it is not a Termux crate.
- `huntsman-bse-radar` is the Termux seam to that radar. It is not a second search engine.

SeekNow on this binary is `huntsman-recon seeknow search KIND VALUE --fast-only`. It reads `HUNTSMAN_SEEKNOW_KEY`. It does not read `SEEKNOW_COOKIE`.

No repository was deleted.

## Native full-source rebuild and acceptance (Android AArch64)

For an operator-controlled source rebuild on a **real rootless Termux handset**, use
`bash scripts/termux-full-rebuild.sh` from a clone, or obtain this script from the
canonical GitHub `main` after its PR has merged. The script always fetches a fresh,
shallow `main` snapshot, pins its full commit SHA, verifies the Rust/Termux stdlib
pair, runs rustfmt, warning-free Clippy, the locked complete Rust test suite and
a native release build. It then runs `scripts/termux-runtime-acceptance.sh` on the
candidate **before** atomically installing it at `$PREFIX/bin/huntsman-recon`.
It does not reuse a prebuilt, touch saved investigations, install a runtime LLM,
require root or silently substitute a host acceptance for a phone acceptance.

Optional `HUNTSMAN_EXPECT_SHA=<full 40-character sha>` refuses to rebuild if the
fetched main commit differs from the operator-selected version.
`CARGO_BUILD_JOBS=1` is the default to bound phone compiler concurrency; an
explicit override is respected. `CARGO_TARGET_DIR` and
`HUNTSMAN_REBUILD_CACHE` may be set for persistent local compilation caches.
A failed gate leaves the installed binary unchanged. The prior executable is
retained at `$PREFIX/bin/.huntsman-recon.previous` on a successful replacement;
if post-install verification fails, it is restored. A running `serve` process
must be restarted separately to use the newly installed binary.

The device acceptance validates the existing embedded web UI and several CLI/API
paths with isolated test data. It does **not** establish that every external
provider was live, paid credentials were configured, or radio APIs were granted
by Android. Those checks need explicit independent receipts and are never
implied by a successful source rebuild.
