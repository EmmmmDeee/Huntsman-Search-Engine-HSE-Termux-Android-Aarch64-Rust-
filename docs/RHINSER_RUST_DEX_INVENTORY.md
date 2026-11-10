# RHINSER original APKs — native Rust DEX method inventory

This extension uses HUNTSMAN's existing bounded Rust APK reader and reuses its
ZIP central-directory, deflate, CRC, manifest and DEX handling. No Python,
Java runtime, new dependency, root privileges, or external HTTP requests are
required for the inspection.

## Source corpus (immutable originals)

| APK | SHA-256 | APK ZIP members | Defined app classes | Distinct app method-name references |
|---|---|---:|---:|---:|
| `rhinse-osint.apk` | `e6be6b6bbff2128cf72a34d1a64d25fbaf7c121a0ce803e60e45bdb97f363036` | 908 | 132 | 700 |
| `Rhinser.apk` | `6a41162f2cf1d59a8689c01a685cd6cde06752c57a02b7177ef009bed7c9593a` | 25 | 38 | 316 |
| `RHINSE-SCAN-DETECT.apk` | `30833ef95b4f504cd4db0919bfc5dc6743590d9e33d25ed424fc1cb1d42d68c4` | 17 | 12 | 35 |

Totals: 182 application class definitions, 1,051 distinct application method-name
references, 950 ZIP members. Of the 1,051 references, 1,050 are owned by
defined application classes. The single remaining method reference belongs
to an array descriptor `[Lcom/rhinse/osint/data/catalog/CatalogRegion;`
(`clone`); it is NOT a defined application class. The Rust parser
preserves it instead of accidentally dropping it.

The original APK bytes were independently hash-checked in an offline
reconstruction; this does not imply that the committed Rust parser has run
against that corpus in CI.

## Rust owner

- `src/apk_intel/rhinser_dex.rs`: bounds-checked DEX class/owner/name parsing.
- `src/apk_intel.rs`: opt-in for APKs whose manifest package names the
  RHINSER or EMV application family; data appears under
  `analysis.rhinser_method_inventories`.
- No second ZIP/HTTP transport, asynchronous runtime, Python runtime, or LLM.
- New document attributes: `apk_rhinser_defined_class_entries`,
  `apk_rhinser_method_name_pairs`,
  `apk_rhinser_unowned_method_references`.

## What this does **not** establish

- Method references and method names are not method implementations,
  source-level translations or proof of original APK execution.
- Not all original Android GUI, Room schema migration, NFC/BLE hardware
  callbacks, or payment-card operations have a production Rust equivalent.
- Android OS permissions and framework callbacks cannot be provided by a
  rootless Termux command alone; a permissioned Android platform adapter
  would be necessary for live radio access.
- Offline Rust code and historical source archives are intentionally retained
  separately; no automatic overlay or speculative behavioural claims.

## Required verification before merging

```sh
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --locked
cargo build --locked --target aarch64-linux-android
huntsman-recon apk /path/to/rhinse-osint.apk --json
huntsman-recon apk /path/to/Rhinser.apk --json
huntsman-recon apk /path/to/RHINSE-SCAN-DETECT.apk --json
```

Compare each `analysis.rhinser_method_inventories` against the original
static method/resource inventory; test on physical rootless Termux for
Android acceptance. These gates must be reported only when executed.
