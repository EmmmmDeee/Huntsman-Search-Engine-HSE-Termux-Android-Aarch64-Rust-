Implemented the entity/evidence-core slice directly in the repo build and refactored it onto shared owners instead of adding parallel helpers.

What changed:
- Expanded `src/intelligence.rs` into a claim/evidence/inference/provider ledger while keeping the aggregate report API.
- Replaced the minimal `src/cross_scan.rs` history summary with a bridge-analysis model using the shared repo types and an injected `CrossScanStore` boundary.
- Kept provenance mandatory on evidence through the entity model and preserved secret hygiene by storing provider credential fingerprints only.
- Used the shared HTTP boundary already present in the repo (`crate::http::{Request, Response, Transport}`) and did not introduce duplicate request/response types.
- Removed or folded small redundancies while making the full crate pass `cargo clippy --all-targets --locked -- -D warnings` and `cargo test`.

Files intentionally not edited:
- `src/classify.rs`
- `src/session.rs`
- `src/stage.rs`

Validation:
- `cargo clippy --all-targets --locked -- -D warnings`
- `cargo test`

Cleanup:
- No scratch `wt-*` tree remains in the repository.
