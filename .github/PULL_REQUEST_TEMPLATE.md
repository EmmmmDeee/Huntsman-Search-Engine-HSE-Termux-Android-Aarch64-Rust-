## Summary
<!-- One or two sentences: what does this change and why. -->

## Type of change

- [ ] Bug fix
- [ ] New module
- [ ] Feature addition (new `ScanOptions` field, new event, new CLI flag)
- [ ] Refactor / cleanup
- [ ] Documentation
- [ ] Build / CI

## Test plan

- [ ] `cargo fmt --all -- --check` passes
- [ ] `cargo clippy --all-targets -- -D warnings` passes
- [ ] `cargo test --all` passes
- [ ] Tested on Termux aarch64 (please attach `hse doctor` output if relevant)
- [ ] New tests added for new behaviour

## Architecture invariants

By submitting this PR I confirm the change preserves:

- [ ] `#![forbid(unsafe_code)]`
- [ ] No native-TLS / openssl / C-linked dependencies (rustls + bundled-sqlite only)
- [ ] GREATEST-semantics entity merge (`confidence` / `corroboration` only ever increase)
- [ ] SHA-256 deterministic entity UIDs
- [ ] `C_eff = clamp(C × (1 + 0.15 × ln(corroboration)), 0, 1)` formula
- [ ] Classification is derived, never stored
- [ ] No passwords / credentials in evidence

(If any are intentionally violated, explain why in the summary.)

## Checklist

- [ ] CHANGELOG.md updated (under `[Unreleased]`)
- [ ] Docs updated (`docs/USAGE.md`, `docs/MODULES.md`, README) if behaviour changed
- [ ] No secrets, keys, or PII committed
