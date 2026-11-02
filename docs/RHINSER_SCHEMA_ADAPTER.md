# Rhinser → Huntsman schema: evidence-limited entity preview

This implementation responds to `HSE_RHINSER_SCHEMA_INTEGRATION.md` as an **integration proposal**, not a record of observed payment transactions, Bluetooth owners, breaches, real Android sensor operation, or validated merchants.

## Implemented interfaces

- `src/rhinser_schema.rs`: converts the result of the existing, strictly validated `rhinser_native::inspect_capture_json` into canonical `entity::Entity` records.
- `huntsman-recon osint native --entities CAPTURE.json`: opt-in, offline **preview**. The original `osint native CAPTURE.json` output remains unchanged.
- Only non-identifying **fixture event records** are created (`EntityKind::Other`, not `DeviceId`, `Person`, `PaymentCard` or `MacAddress`).
- Every record is tagged `candidate` and `derived`, capped at `CANDIDATE_CONF` (0.25), and contains `operator_input` evidence with the canonical seed evidence role `seed_not_external_verification`.
- Only structural NFC metadata and coarse Bluetooth classification are copied from the already-redacted inspector. No raw payload, PAN, cardholder, MAC, pairing identifier, physical distance or ownership is generated.
- A hash of the *sanitized inspection report* supplies a reproducible **fixture-event identifier**; equal IDs do not establish unique real-world device identity.
- Every timestamp from the fixture is explicitly a caller claim. Ingestion time is separate.
- The returned `relationships_inferred`, `device_attested` and `radio_access` flags are `false`.

## Unimplemented, and deliberately not implied

The provided document proposes `PaymentCardEntity`, `BluetoothDeviceEntity`, `MerchantEntity`, automatic pairing/owner identification, breach matching, fraud scores, SQL tables and Neo4j graph creation. These are not implemented by this preview. The proposed Rust-like entity blocks and GraphQL syntax cannot be compiled against canonical HSE as written. The SQL uses PostgreSQL-specific constructs whereas this repository's current canonical evidence and scan stores must be examined before any compatible migration.

A cryptogram does not prove card ownership or transaction history; RSSI cannot independently determine precise distance; proximity does not establish ownership. Breach, venue, financial risk and vulnerability claims require **separate attributed evidence** and source-specific verification. The examples in the specification are illustrative values, not source receipts.

## Validation

Run:

```bash
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --locked --test rhinser_schema_compat
cargo test --locked rhinser_schema
huntsman-recon osint native --entities consented-capture.json
```

The tests check real CLI execution, legacy CLI compatibility, candidate status, provenance, exclusion of raw NFC bytes, and consent rejection. Hosted cross-compilation or test fixtures do not certify actual Android hardware capture, runtime attestation or physical rootless Termux operation. The CLI does not persist entities, create relations or trigger network enrichment.
