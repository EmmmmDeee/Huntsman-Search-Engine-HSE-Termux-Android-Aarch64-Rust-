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

## Rebuild and upgrade on Android AArch64

`install.sh` is the one install, upgrade and rebuild path on a Termux handset;
`HUNTSMAN_FROM_SOURCE=1` makes it compile the pinned commit on the phone instead
of installing that commit's published build. There is no second rebuild script.
Every run:

- refuses to run as root, and holds `~/.huntsman/.install.lock` (under
  `HUNTSMAN_HOME` when set), so a second run is refused until it ends;
- pins `main` to one full commit SHA, or takes `HUNTSMAN_REV`, before fetching
  anything;
- for a source build, aligns Termux `rust` with `rust-std-<host>`, builds and
  runs a native probe, and runs one compile job per GiB of available memory;
- checks the candidate before it replaces anything: a published build must match
  its release SHA-256, and Cargo installs a source build into a fresh staging
  directory, never over the installed binary. Either must report the pinned
  commit from `build-sha` and pass offline `check` and ledger verification;
- copies the candidate beside `$PREFIX/bin/huntsman-recon`, re-checks its
  SHA-256 there, keeps the current binary as `$PREFIX/bin/.huntsman-recon.previous`
  and renames the copy into place, then puts the previous binary back if the
  installed one does not report the commit;
- refuses to replace a symlinked binary, refuses to report success while another
  copy on `PATH` shadows the install, and restarts the web UI service, when it is
  on, onto the new binary.

A failed check leaves the installed binary as it was. Real-device acceptance of the
web UI and API stays a separate, explicit step (`scripts/termux-runtime-acceptance.sh`,
see `docs/INSTALL.md`). Neither it nor the installer's offline acceptance shows that
external providers were reachable or keyed.
