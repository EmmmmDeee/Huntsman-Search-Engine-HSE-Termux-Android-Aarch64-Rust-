# HUNTSMAN native Rust API-key health register

## Purpose

`src/bin/huntsman-key-health.rs` is a native Rust executable linked to the canonical `huntsman-recon` library. It continuously refreshes a **non-secret JSON status file** while running, using exactly the same credential-slot resolver and provider catalogue as `huntsman-recon credential-status`.

The JSON snapshot is **not a file of API keys**. Real key values remain in the operator-owned `$HOME/.huntsman.env`, provider-specific private files or environment variables. The health report contains provider names, slot names, configuration presence, non-sensitive probe verdicts and timestamps. It does not contain secret values, tokens, credentials, raw API bodies or user-targeted lookup data.

## Run on Termux / host

```sh
cargo run --locked --release --bin huntsman-key-health -- --watch --interval-seconds 1800
# Optional, potentially billable live checks (only via existing guarded provider probes):
cargo run --locked --release --bin huntsman-key-health -- --watch --interval-seconds 3600 --probe
```

Default status location: `$HOME/.huntsman/api-key-health.json` (private JSON file). To refresh once, omit `--watch`. To use a different private directory, pass `--output /absolute/path.json`. Parent directory must have Unix 0700-equivalent permissions. A private atomic file update and exclusive writer lock preserve the previous complete report if refresh fails; writes never mutate the actual secrets file.

## Semantic guarantees

- `configured=true` means only that the canonical key resolver loaded a usable non-placeholder credential *value*. It does **not** prove the key works or was used on an active source.
- `probe=valid` / `authenticated_probe_success=true` is emitted only when the existing provider probe reports an authenticated success. `unsupported`, `unavailable`, `rate_limited`, `indeterminate` and `rejected` are kept distinct.
- `runtime_use_verified=false` is deliberate. Provider subscription validity is not evidence of actual search execution. A future module-level source execution ledger can supply that proof.
- There is **no automatic procurement, key guessing, rotation or renewal**. Each provider controls issuance, revocation and expiry. Automated rotation is possible only for an explicitly connected provider supporting official managed rotation.
- `--probe` is opt-in because provider tests can consume API quota. The same existing single guarded HTTP client, origin guards and service contracts are reused.
- The refresh loop operates only while the process runs; Android power management, crashes and disconnections can stop it. Set up a supported foreground service / process supervisor for restart and verified uptime; this program alone cannot promise perpetual maintenance.

## Acceptance and limitations

```sh
cargo fmt --all -- --check
cargo test --locked --bin huntsman-key-health
cargo clippy --all-targets -- -D warnings
cargo build --locked --release --target aarch64-linux-android --bin huntsman-key-health
```

Verify the JSON file's ownership/mode, no secret leakage, no network request without `--probe`, valid/rejected/rate-limited/unsupported state preservation, an interrupted write leaving the previous file intact, and 30-minute refreshes on a physical Android device. These gates remain unverified until actually executed on the target.