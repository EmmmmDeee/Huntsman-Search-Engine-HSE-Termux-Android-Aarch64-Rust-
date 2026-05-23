# Contributing to Huntsman Search Engine

Thanks for your interest! HSE is a prototype iterating toward a useful tool.
Every contribution — even a typo fix or a one-paragraph design critique —
moves it forward.

## Quick links

- **Bug?** [Open an issue](https://github.com/EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-/issues/new?template=bug_report.md)
- **Idea?** [Feature request](https://github.com/EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-/issues/new?template=feature_request.md)
- **Security bug?** See [SECURITY.md](SECURITY.md) — do not file a public issue
- **Architecture?** [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) and [`docs/DESIGN.md`](docs/DESIGN.md)

## Development setup

```bash
# Clone + build
git clone https://github.com/EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-
cd Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-
cargo build

# Run the full check that CI runs:
cargo fmt --all -- --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --all --locked
```

Rust 1.88+ (edition 2024, let-chains stable) is the minimum supported
version (MSRV). The CI verifies this with a dedicated job.

## Adding a new module

This is a deliberately one-file change. See
[`docs/MODULES.md`](docs/MODULES.md) for the full walkthrough, in short:

1. Create `src/modules/your_module.rs`:

   ```rust
   use async_trait::async_trait;
   use crate::core::{
       entity::{Entity, EntityKind, Evidence},
       error::Result,
       module::{Module, ModuleContext, ModuleCost, ModuleResult},
       scan::{Target, TargetKind},
   };

   pub struct YourModule;

   #[async_trait]
   impl Module for YourModule {
       fn name(&self) -> &'static str { "your_module" }
       fn priority(&self) -> u8 { 50 }
       fn cost(&self) -> ModuleCost { ModuleCost::Free }
       fn accepts(&self, t: &Target) -> bool {
           matches!(t.kind, TargetKind::Domain)
       }
       async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
           // ... your logic ...
           Ok(ModuleResult::new())
       }
   }

   #[cfg(test)]
   mod tests { /* always add at least an accepts() test */ }
   ```

2. Register it in `src/modules/mod.rs`:

   ```rust
   pub mod your_module;
   // in registry():
   Arc::new(your_module::YourModule),
   ```

3. Add docs to [`docs/MODULES.md`](docs/MODULES.md) (one row in the catalog
   plus a short paragraph on what it returns and any quirks).

4. Update `CHANGELOG.md` under `[Unreleased]`.

**That's it.** Nothing else needs to change. The engine discovers the module
through the registry; expansion picks up its output automatically; the CLI
`modules` command lists it; future SPA renders it.

## Architecture invariants (do not break)

These are enforced and the PR template asks you to confirm them:

- `#![forbid(unsafe_code)]`
- No native-TLS, no openssl, no C-linked dependencies. rustls + bundled-sqlite only.
- GREATEST-semantics entity merge — `confidence` and `corroboration` only ever increase.
- SHA-256 deterministic entity UIDs from `(kind, normalised_value)`.
- `C_eff = clamp(confidence × (1 + 0.15 × ln(corroboration)), 0, 1)` — the formula is invariant.
- Classification is derived, never stored.
- **Passwords / hashes / plaintext credentials never appear in evidence.** Modules
  that query breach sources MUST explicitly drop credential fields from the
  API response (see `src/modules/hudsonrock.rs` for the pattern).

If your change must break one of these, say so in the PR summary with the
reason. We will probably push back.

## Code style

- `cargo fmt --all` (default `rustfmt.toml`) — CI fails otherwise.
- `cargo clippy --all-targets -- -D warnings` — CI fails otherwise.
- Names: modules and files are `snake_case`; structs are `UpperCamelCase`;
  enum variants are `UpperCamelCase` (serde renames them to `snake_case`
  in JSON via `#[serde(rename_all = "snake_case")]`).
- No `unwrap()` / `expect()` in module business logic. Use `Error::module(...)`
  with a useful message.
- Comments explain **why**, not **what**. Function names should be obvious.
- No emojis in source code, commits, or PR descriptions unless explicitly
  requested by the user / reviewer.

## Commit messages

We use plain conventional-style summaries. First line ≤ 72 chars,
imperative mood, no scope tag required:

```
v0.2.0: add autonomous expansion engine

Body explains why this matters, what it changes, and any tradeoffs.
References issues with #N where relevant.
```

For bug fixes:
```
fix: scan_id preserved on entity upsert (regressed in 0.2)
```

For docs / build / CI only:
```
docs: clarify --min-expand-confidence default in USAGE
ci: add MSRV check at 1.85
```

## Pull request workflow

1. Fork → branch from `main` (e.g. `feat/wigle-module`).
2. Make your change. Add tests. Update `CHANGELOG.md` under `[Unreleased]`.
3. Push and open a PR. Use the template — it's short.
4. CI must be green. Reviewers may ask for changes; please don't take it personally.
5. PRs are usually squash-merged. The CHANGELOG entry survives.

## Releases

Maintainers cut releases by:

1. Move `[Unreleased]` items in `CHANGELOG.md` under a new dated version.
2. Bump `version` in `Cargo.toml`.
3. `cargo test --all --locked && cargo build --release`.
4. Tag (`git tag vX.Y.Z`) and push (`git push --tags`).
5. Cut a GitHub Release with the CHANGELOG entry as the body.

## Code of conduct

By participating you agree to abide by the
[Code of Conduct](CODE_OF_CONDUCT.md). Be kind. Assume good faith.

## Licence

By contributing you agree your work will be licensed under the dual
[MIT](LICENSE-MIT) / [Apache-2.0](LICENSE-APACHE) terms used by the project.
