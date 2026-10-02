# huntsman-recon

Only current version of the project. Previous trees remain in git history.

Offline Rust core. No network client. No credentials. The ledger is a hash chain in `var/ledger.json`. A full session terminate must name that tip. A verified claim is not an ATT&CK score.

```
cargo test
cargo run -- check
cargo run -- geo -27.4698,153.0251 -33.8688,151.2093
```

See `docs/RECONSTRUCTION_2026-10-02.md`.
