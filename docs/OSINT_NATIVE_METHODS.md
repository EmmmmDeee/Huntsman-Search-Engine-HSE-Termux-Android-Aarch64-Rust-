# Native OSINT method equivalents

Independent Huntsman implementations: **no H1DR4 runtime connection**. The source-backed casework model and event-pressure heuristic follow public investigative *methodologies*, not proprietary H1DR4 datasets, models or credentials.

## Available paths

- `huntsman-recon osint case docs/OSINT_CASEWORK.json`: analyze imported source assertions, metadata receipts, event chronology, contradictions and follow-up priority. Values at different times are changes, not contradictions. Declared roots and URL hosts do not prove source independence.
- `huntsman-recon osint area-risk docs/OSINT_AREA_EVENTS.json -26.8,152.9 1000 property`: quantify published point-event pressure over the previous 30 days in a 1 km radius; no claim that zero means safe.
- `huntsman-recon osint area-compare docs/OSINT_AREA_EVENTS.json -26.8,152.9 -27.0,152.0`: same imported source set, equal radius, independently computed scores.
- `huntsman-recon osint x "query"`: public index discovery leads, not a private X/Grok corpus.
- `huntsman-recon osint x-api "query"`: official X recent-search first page, requires independently authorized `HUNTSMAN_X_BEARER_TOKEN`.
- Base account state is provided by `huntsman-recon crypto base:0xADDRESS` (keyless public RPC, canonical owner `src/base_rpc.rs`); this branch adds no separate Base or Alchemy path.
- Ethereum mainnet account state is provided by `huntsman-recon crypto eth:0xADDRESS` (keyless public RPC, canonical owner `src/eth_rpc.rs` over the shared `src/evm_rpc.rs` core); keyless, no indexing service, no separate Infura or Alchemy path.
- Solana mainnet-beta account state is provided by `huntsman-recon crypto sol:ADDRESS` (keyless public RPC, canonical owner `src/solana_rpc.rs`): the batch is gated on the mainnet-beta genesis hash, decodes only the SPL Token and Token-2022 account, mint and multisig layouts into `sol:` control-relation pivots (owner, delegate, close, mint and freeze authorities, multisig signers), and lists only the transactions naming the address that the node still retains, whoever signed them; no indexing service, no Helius or other keyed path.
- `huntsman-recon osint plan SEED...`, `osint local QUERY DIRECTORY`, and `osint lookup KIND SELECTOR`: reuse existing graph, local search and provider connectors.

Web UI: Analysis > Source-backed OSINT methods. APIs `POST /api/osint/case` and `POST /api/osint/area-risk` use existing authorization, origin and body-size controls. The area-risk API JSON includes `as_of_unix`, `events`, `center_lat`, `center_lon`, `radius_m`, `category`.

## Evidence and security boundaries

All source URLs are **input claims** until verified. Receipts hash observation metadata, not remote documents. Declared different roots are not proof of independent sourcing. The area score is a disclosed heuristic (density 45, category 25, last-72-hours 15, severity 15) and is not comparable to any proprietary risk score. No provider credentials are copied from H1DR4; no wallet signing, unauthorized private data access, credential guessing, or unrequested paid lookup occurs.

## Acceptance commands

```sh
cargo fmt --all --check
cargo test --lib osint_casework
cargo test --lib osint_area_risk
cargo test --lib federated_osint
cargo test --all-targets
cargo clippy --all-targets -- -D warnings
```

Tested target: rootless Termux Android AArch64 after passing GitHub CI and device smoke tests. Do not merge if either gate fails.
