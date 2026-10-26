# TikTok public-contact discovery

Huntsman collects only explicitly self-published contact candidates from an operator-selected public TikTok profile. It does not recover registration email addresses, guess addresses, bypass login, or follow bio links.

## Integration

- Module ID: `tiktok_public_contact`; it participates in the existing `username HANDLE` CLI and Web UI scan flow.
- One keyless, no-redirect, guarded GET of `https://www.tiktok.com/@HANDLE`; shared Termux network restrictions apply.
- Reuses typed source outcomes, entity provenance, selection and saved scan reporting; no new runtime dependency or schema.
- Publishes a profile URL and username when a matching public bootstrap record exists. Emits email candidates only when literally in the published profile signature. Records one HTTPS bio link without visiting it.

## Limitations and acceptance

Only recognized matching public bootstrap records are parsed: `__UNIVERSAL_DATA_FOR_REHYDRATION__` and legacy `SIGI_STATE`. Layout changes, WAF/bot challenges, non-public account fields, missing responses or HTTP 404 do not establish absence. Published contact addresses are self-asserted; mailbox existence and ownership remain unverified.

Check `cargo fmt --all -- --check`, `cargo clippy --all-targets --locked -- -D warnings`, and `cargo test --locked` before merge. Verify the source appears in `huntsman-recon modules --json` and `/api/modules`, and confirm a username scan records its typed outcome on device. Blocked live access must remain unavailable, not passed.

FIELD PROVENANCE: Source evidence identifies each precise originating profile field; the email's source_field is public_bio_signature and its ownership status remains not_verified.
