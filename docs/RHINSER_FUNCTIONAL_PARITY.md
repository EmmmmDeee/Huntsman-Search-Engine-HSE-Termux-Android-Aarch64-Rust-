# Rhinser functional incorporation: reproducible coverage audit

Source baseline: user-supplied Dropbox `rhinse-osint.apk` SHA-256 `e6be6b6bbff2128cf72a34d1a64d25fbaf7c121a0ce803e60e45bdb97f363036`, `Rhinser.apk` SHA-256 `6a41162f2cf1d59a8689c01a685cd6cde06752c57a02b7177ef009bed7c9593a`, `RHINSE-SCAN-DETECT.apk` SHA-256 `30833ef95b4f504cd4db0919bfc5dc6743590d9e33d25ed424fc1cb1d42d68c4`. No APK executed. Other files in the shared folder are separate third-party applications, not Rhinser components.

This document records **observed APK structures and functional equivalents**, not authorship, licence, runtime traffic or installation compatibility. Each status describes Huntsman, not the Android app.

| APK component | Evidence (static) | Huntsman equivalent | Status / limitation |
| --- | --- | --- | --- |
| Australian OSINT catalogue | `assets/osint_catalog.json`: 11 categories, 83 tools | `osint catalog`, `--find`, `--category`, `--tool`, `--url`; Web UI's Multi-hop Analysis source directory | Implemented in source: searchable finite offline catalogue with local API-backed filtering and user-opened HTTPS links; entries are unverified public links, not 83 live collectors |
| Cases | `CaseDao` / `CaseEntity` | `osint workspace FILE case ID TITLE`; existing `osint case FILE` reviewer | Implemented: local persistence and existing evidence review; no Android UI replication |
| Case notes | `NoteDao` / `NoteEntity` | `osint workspace FILE note CASE TEXT` | Implemented: bounded local notes |
| Evidence | `EvidenceDao` / `EvidenceEntity` | `osint workspace FILE lead CASE ID HTTPS_URL SUMMARY`; existing source-first receipts | Implemented: user-supplied unverified links; external claims not automatically verified |
| Bookmarks and favourites | `BookmarkDao` / `FavoriteDao` | `osint workspace FILE bookmark|favourite TOOL_ID` | Implemented: persistent per-workspace source selections |
| Search history / recently used | `SearchHistoryDao` / `RecentToolDao` | `osint workspace FILE search QUERY`, `recent TOOL_ID` | Implemented: bounded history |
| Settings | `SettingDao` / `SettingEntity` | `osint workspace FILE setting KEY VALUE` | Implemented: local keys/values, no Android settings UI |
| NFC scanning | `NfcScannerActivity`, `NfcManager`, `IsoDepProcessor`, `MifareProcessor` | `osint nfc apdu HEX`; `osint nfc ndef HEX` | Partial: read-only offline frames from the operator; **not** live NFC hardware |
| Host card emulation / card writing | `MyHostApduService`, `CardWriter`, `EmvHceService` | None | Not implemented: needs a separate approved Android NFC companion; no live payment-card emulation |
| Saved NFC captures | `SavedCapturesActivity` | Offline operator-provided NFC bytes and generic case leads | Partial: no NFC capture/recording from handset |
| Bluetooth Find Headphones | `FindHeadphonesActivity` | Existing `radar survey-bluetooth --file ... --json` | Partial: handles offline Network Survey CSV, not active Android LE device discovery |
| Remote console / service | `C2ConsoleActivity`, `C2ListenerService`, `AnemfController` | None | Not implemented: the APK includes a remote task-execution agent; no deployment or stealth task control copied |
| Prank scanner | `RHINSE-SCAN-DETECT/assets/index.html` | None | Not implemented: source JavaScript generates random 'detection' scores; entertainment, not a sensor |
| Standalone EMV utility | `Rhinser.apk` package `com.emv.nfcreader` | Offline read-only APDU classification | Partial: no NFC brute force, payment-card track-writing, or card credential emulation |

## Local HTTP interface

The browser's read-only directory appears under **Multi-hop Analysis**. It lazily retrieves the 83-entry JSON from `/api/rhinser/catalog` through the existing authentication helper, supports local category/text filtering, and opens permitted HTTPS source URLs only after explicit clicks. Listing a link is not collecting or validating evidence. Static JavaScript validation and a browser-logic harness passed; native Android/Termux rendering remains unverified.


- `GET /api/rhinser/catalog` returns exactly the same typed, unverified, bounded directory as `osint catalog --json`.
- Requests inherit the Huntsman server's host, bearer-token and no-cache protections; it is read-only and never fetches remote sites.

## Operational commands

```sh
huntsman-recon osint catalog
huntsman-recon osint catalog --json
huntsman-recon osint catalog --find "unclaimed money"
huntsman-recon osint catalog --category au_professions
huntsman-recon osint catalog --tool t0392
huntsman-recon osint catalog --url t0392

huntsman-recon osint workspace my-casebook.json init
huntsman-recon osint workspace my-casebook.json case case-001 "Research case"
huntsman-recon osint workspace my-casebook.json note case-001 "Check source dates"
huntsman-recon osint workspace my-casebook.json lead case-001 lead-001 https://abr.business.gov.au/ "ABR lead, unverified"
huntsman-recon osint workspace my-casebook.json favourite t0343
huntsman-recon osint workspace my-casebook.json bookmark t0392
huntsman-recon osint workspace my-casebook.json recent t0392
huntsman-recon osint workspace my-casebook.json search "Australian public records"
huntsman-recon osint workspace my-casebook.json setting default_region AU
huntsman-recon osint workspace my-casebook.json show

huntsman-recon osint nfc apdu "00 A4 04 00 02 3F 00"
huntsman-recon osint nfc ndef "D1 01 05 54 02 65 6E 48 69"
```

## Acceptance gates

- Catalogue loads all 83 distinct, HTTPS-only source IDs and is deterministic.
- Query filtering and exact lookup never fetch the network or elevate links into evidence.
- Workspace persists case notes and separate source leads; malformed/oversized JSON and secret-bearing URLs are rejected.
- NFC parsers validate user-provided frames without transmitting, exposing payload data or relying on card hardware.
- `cargo fmt --check`, `cargo clippy`, unit/integration suite and Android ARM64 cross-build must pass before the branch may merge.
- Rootless Termux device execution and Android companion behaviour require **physical-device tests**; passing CI cannot substitute for them.

## Remaining engineering work

1. Verify directory URL freshness independently and identify official live collection APIs for high-priority sources.
2. Complete the case workspace's existing Web UI integration without duplicating ledger, correlation or search architecture. The catalogue now has a read-only browser directory; stored casework is still CLI-only.
3. Build a separately permissioned Android NFC/Bluetooth companion with on-device user consent and explicit read-only scanning, then bridge into Huntsman via bounded local receipts.
4. For remote operations, use a visible, authenticated, opt-in device-health protocol limited to approved diagnostics rather than an unconsented remote-execution agent.
5. Treat the prank application as clearly labelled entertainment if its interface is included.
6. Compare each APK's behaviour against the parity matrix on an authorised test handset; never claim full application parity until every feature passes.

No new external runtime dependency or LLM is introduced.
