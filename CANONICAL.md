# Canonical Huntsman

One operator repository. One crate. One installed binary.

- Repository: `EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-`
- Binary: `huntsman-recon`
- Package: `huntsman-recon` 0.2.0, edition 2024, rust-version 1.87
- Dependencies: serde, serde_json, thiserror, ureq
- Target: Termux Android `aarch64-linux-android`, no root, no ports below 1024
- Identity module: `src/repository_identity.rs`
- Value normaliser: `src/canonical.rs`
- Verified on 2026-10-08: `cargo check --locked` finished on commit 4aff3d7. Full `cargo test` can be SIGKILL under low memory; that is a host limit, not a second engine.

Lifecycle, from a clone:

```sh
bash scripts/lifecycle.sh build
bash scripts/lifecycle.sh run
HUNTSMAN_SYNC=1 bash scripts/lifecycle.sh all
```

`sync` pushes `main` only. A dirty tree is committed only when `HUNTSMAN_SYNC_COMMIT=1`. Failures append to `~/.huntsman/lifecycle.log`.

Phone install remains `install.sh` (pins `main` to one SHA, installs `huntsman-recon`, runs offline acceptance).

`hse` is the legacy monolith. It is not a second current engine.

Other copies are not this engine:

- `huntsman-rcvf` is a divergent experiment. Do not install it over this binary.
- `Huntsman-` is not the operator binary.
- `HSE-BLE-API-` is the BLE radar APK. It stays a separate runtime because it is not a Termux crate.
- `huntsman-bse-radar` is the Termux seam to that radar. It is not a second search engine.

SeekNow on this binary is `huntsman-recon seeknow search KIND VALUE --fast-only`. It reads `HUNTSMAN_SEEKNOW_KEY`. It does not read `SEEKNOW_COOKIE`.

No repository was deleted.
