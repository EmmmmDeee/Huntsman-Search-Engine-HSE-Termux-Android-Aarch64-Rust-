# Commercial readiness and reusable-asset ledger

This document is a due-diligence index for the current `huntsman-recon` tree.
It deliberately separates demonstrated capability from planned work. It is not
a valuation, revenue claim, customer claim, or statement that the reconstruction
has reached legacy parity.

## Value thesis

Huntsman's transferable engineering value is concentrated in reusable Rust
components and their verification evidence:

| Asset | Current evidence | Reuse surface | Commercial relevance |
| --- | --- | --- | --- |
| Evidence/provenance model | `src/`, `docs/LINEAGE.md`, acceptance and adversarial tests | Rust library + JSON artifacts | auditable data pipelines, record linkage, data-quality systems |
| Guarded HTTP/provider boundary | `fetch`, `http`, typed outcomes, fake-transport tests | Rust library + CLI | API integrations, public-data collectors, monitoring |
| Collector/module model | reachable modules + module contract tests | Rust library + CLI/API | integration and data-collection work |
| Deterministic local processing | search, identifiers, geo, lineage, verification | Rust library + CLI | backend/data tooling without hosted dependencies |
| Embedded API/UI | `serve` and API acceptance paths | HTTP | integration and deployment surface |
| Android aarch64 delivery | CI cross-build + ELF checks + release installer | binary artifact | low-resource/edge deployments |
| Release/acceptance machinery | CI, release workflow, handset acceptance harness | automation | reproducible delivery and regression control |
| Historical implementation corpus | pinned read-only `legacy/` trees + dispositions | reconstruction reference only | reduces rediscovery cost; not current capability |

## Current proof boundary

A capability belongs in the **demonstrated** column only when the current tree
contains executable code and a test, acceptance gate, reproducible artifact, or
other claim-specific receipt. Documentation marked PLANNED is not demonstrated.

The canonical detailed boundary is `ARCHITECTURE.md`. The README's
"Which binary to use" table is authoritative for reconstruction-vs-legacy
availability. `docs/DISPOSITIONS.md` accounts for legacy files; presence in
`legacy/` never means the current binary implements that behavior.

## Buyer/client diligence commands

Run these before relying on the asset:

```sh
cargo fmt --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
cargo run --locked -- check
cargo run --locked -- verify var/ledger.json
cargo run --locked -- modules --json
```

For the target handset, also run:

```sh
bash scripts/termux-runtime-acceptance.sh
```

CI cross-compilation is evidence that the Android aarch64 artifact builds with
the expected ELF target. It is not evidence that a particular handset executed
it; the runtime acceptance harness supplies that separate receipt.

## Commercial-readiness gates

These gates intentionally prevent premature product claims.

| Gate | State | Exit condition |
| --- | --- | --- |
| Current crate builds/tests on MSRV and stable | demonstrated in CI | keep both CI lanes green |
| Android aarch64 artifact | demonstrated in CI | keep cross-build + ELF verification green |
| Current/legacy boundary documented | demonstrated | README + architecture contract tests remain green |
| Stable public API contract | **not declared** | explicitly choose supported library/HTTP surfaces and compatibility policy |
| Stable v1 release | **not declared** | owner approval after API/CLI compatibility gates and release candidate |
| Licensing/commercial distribution policy | **undecided** | owner selects proprietary, dual, or open-source terms; do not infer a license |
| Real-device acceptance for a release | external receipt required | run handset harness against the release candidate |
| Performance/SLO claims | **not demonstrated globally** | reproducible benchmark suite with hardware/dataset context |
| Customer/revenue traction | **not claimed** | external commercial evidence |
| Full legacy parity | **not claimed** | close the explicit CURRENT/PLANNED gaps that define required parity |

## Highest-value engineering sequence

1. Close high-value reconstruction gaps that block one canonical product.
2. Define the smallest stable Rust and HTTP integration surfaces from code that
   is already demonstrated; avoid broad public-API commitments before this.
3. Add reproducible performance/resource benchmarks for those surfaces.
4. Produce a release candidate and run CI plus real-device acceptance.
5. Choose licensing/distribution terms deliberately.
6. Only then declare the compatibility contract and promote a stable release.
7. Productize the same verified primitives into recurring public-data
   monitoring, data-quality, API-integration, and automation work.

This ordering preserves option value: it improves transferability and
due-diligence quality without making irreversible package, licensing, or SemVer
commitments prematurely.

## Claim discipline

Do not derive a sale price from lines of code, test count, module count, or
replacement hours alone. Those are inputs to diligence, not market value.
Do not describe PLANNED architecture as shipped. Do not describe CI
cross-compilation as handset execution. Do not describe historical modules as
current modules. Do not claim recurring revenue, customers, or production SLOs
without external receipts.

When commercial evidence exists, maintain accounting separately for:

- cash revenue and direct cash costs;
- contribution margin;
- skilled labor hours;
- net cash per skilled labor hour;
- reusable asset creation;
- recurring/productizable upside.

Owner labor opportunity cost is useful for economic decisions but must not be
mixed into accounting gross/contribution margin.
