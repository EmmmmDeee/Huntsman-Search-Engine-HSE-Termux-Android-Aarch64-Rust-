# Delivery Status

This ZIP is an **exact-base merge-ready refactor delivery for Huntsman commit
`feef60ab48ffe4be599c2ef0f678600cdaffc2aa`**.

It is not represented as a byte-for-byte full clone because the current
execution environment could read the connected GitHub repository but could not
materialize/clone the entire current repository tree into the sandbox.

## What is integrated and apply-ready

`patches/primary/` contains the exact-base active patch sequence:

1. one Rust auto-update policy authority;
2. Rust evidence/source-health/identity/termination/credential/evaluation and
   architectural-invariant foundations;
3. registration in `src/core/mod.rs`;
4. repository-invariant mode in the existing Rust `architecture-audit` binary;
5. approved architecture specs and implementation plan;
6. current-base LeakBase exposure/auth boundary;
7. breach-corpus canonical independence;
8. Termux CI artifact provenance.

`overlay/` contains the complete new/replacement files represented by those
patches so they can also be inspected without applying the series.

## What is deliberately not silently promoted

`patches/revalidation-required/` contains substantive earlier Huntsman work
that remains relevant but was produced against older repository states or has
a parameter that still requires empirical validation. These patches are
preserved as implementation inputs and must be rebased/tested before promotion.

## Verification performed here

- exact current source for the three modified integration files was retrieved
  from connected GitHub at `feef60a`;
- generated patch syntax and application are checked against reconstructed
  exact integration files/new-file paths;
- duplicate placeholders/TODO markers are scanned;
- SHA-256 manifest is generated.

## Verification blocked here

The sandbox does not expose `cargo`, `rustc`, or `rustfmt`, cannot ordinary
`git clone` GitHub, and the connected GitHub write API returns HTTP 403 for
branch/file writes. Therefore this delivery does **not** claim:

- Rust compilation;
- clippy;
- full cargo test success;
- GitHub CI success;
- Android cross-build success;
- real Termux device execution.

Those are mandatory promotion gates, not optional polish.
