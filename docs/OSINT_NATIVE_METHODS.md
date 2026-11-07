# Native OSINT method equivalents

Independent Huntsman casework and area-risk heuristics continue to run **without H1DR4**. An optional, keyless, read-only H1DR4 public API connector now exists separately; its third-party source assertions never count as independent corroboration of these local methods. No proprietary H1DR4 models or credentials are required.

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

## Optional H1DR4 public connector (draft integration)

- `huntsman-recon h1dr4 search "SEARCH TERM" --limit 10 --pages 1 --save local-evidence.json`: keyless, bounded public case search; saves an exclusive private JSON report containing exact upstream UTF-8 payload(s), SHA-256, normalized case lead summaries and pagination caveats. The file must not already exist.
- `huntsman-recon h1dr4 case dossier-CASE-ID --limit 200 --save local-case.json`: public case details with bounded tips. Add `--tip 617` to select one matching normalized tip **without discarding the original upstream payload**. If a tip is absent from a bounded page, absence across the case is not established.
- `huntsman-recon h1dr4 rewards --limit 10`: aggregator references; confirm wanted status, rewards and source freshness independently at the relevant official agency.
- `huntsman-recon h1dr4 onchain-stats`: reads public registry aggregate counts, not wallet-owner identities.

**Limits:** Upstream case-detail `tip_count` can reflect the response limit, not the true case total. A tested H1DR4 case ignored `offset` for tips; pagination is therefore not claimed complete. Every response body is preserved as `original_json` with its digest, even when normalized rows are missing or schema changes. No query ever creates cases, submits tips, pays fees, or uses an LLM. Web UI controls and regular event ingestion are not part of this first connector; this document is not evidence that those future integrations work.

## Evidence and security boundaries

All source URLs are **input claims** until verified. Receipts hash observation metadata, not remote documents. Declared different roots are not proof of independent sourcing. The area score is a disclosed heuristic (density 45, category 25, last-72-hours 15, severity 15) and is not comparable to any proprietary risk score. No provider credentials are copied from H1DR4; no wallet signing, unauthorized private data access, credential guessing, or unrequested paid lookup occurs.

## Acceptance commands

```sh
cargo fmt --all --check
cargo test --lib osint_casework
cargo test --lib osint_area_risk
cargo test --lib federated_osint
cargo test --lib h1dr4
cargo test --all-targets
cargo clippy --all-targets -- -D warnings
```

Tested target: rootless Termux Android AArch64 after passing GitHub CI and device smoke tests. Do not merge if either gate fails.
