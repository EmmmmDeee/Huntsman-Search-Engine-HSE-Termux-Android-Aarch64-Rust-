# Uncertainty register — saved scans

The scan status endpoint `GET /api/scans/{id}` exposes a derived
`uncertainty_register`. The same ordered entries are visible in the scan's
**Summary → Uncertainty register** table and downloadable as JSON.

## What it establishes

- **Source outcome:** Repeated unresolved executions are grouped by
  `(module, outcome)`, retaining execution count and earliest/latest
  `observed_at_unix` values. A confirmed `valid_zero` is **not** uncertainty.
- **Execution state:** An active, aborted or failed scan cannot justify
  pretending the investigation was completed.
- **Termination:** A fixed-point stop does not imply exhaustive external-data
  coverage. Budget/time/depth/cancellation stops retain explicit limitations.
- **Source scope:** At least one entry always records that exhaustive discovery,
  source independence and absence of undiscovered findings are **unverified**.
- **Evidence:** Each item points to a stored artifact, such as
  `results.json#outcomes` or `scan.json#status`. The full original outcomes
  remain in the saved scan. These are provenance pointers, **not** proof that
  an outcome was an authentic upstream response.

Items sort by `priority` (1 first), then category and stable ID. Priority is a
*remediation queue*, not a risk score, confidence estimate or severity verdict.
No automated network requests occur. Every action is a proposed next
verification, not a claim that the action ran.

The view does **not** estimate overall dataset completeness, credential rights,
source trustworthiness, recency of unqueried sources, geolocation certainty, or
proof that two providers are independent. The register reports only evidence
recorded in this one scan; cross-scan provider changes remain available through
`GET /api/scans/compare?ids=EARLIER,LATER`.

## Verification contract

- `recorded_executions` equals the saved outcome count; grouped unresolved
  executions never silently change that count.
- A verified empty response (`valid_zero`) is not grouped with parser-empty
  `inconclusive` or unconfigured/key-denied observations.
- If results are unavailable, coverage is unknown rather than zero.
- A repeated failure does not generate duplicate action rows; its observation
  count and time range persist.
- The implementation is pure Rust, read-only, bounded by the scan's already
  existing saved-result limits and compatible with rootless Termux Android
  AArch64. No new persistent schema, runtime model, API key or paid dependency
  is required.

## Open integration uncertainties (2026-10-23)

| Question | Verified evidence | Current status | Next falsification |
|---|---|---|---|
| Is an operator-owned Exa key configured and usable? | `docs/PROVIDER_CREDENTIALS.md` lists `HUNTSMAN_EXA_KEY` as not recovered | **Unverified on device** | Inspect only key presence and a quota-bounded official API probe, without revealing secrets |
| Does an Exa Lite result represent a live page? | [Exa October 19 changelog](https://exa.ai/docs/changelog) says Lite delivers cached content | **No: cached source content** | Compare discovery timestamp with primary-source fetch when freshness materially matters |
| Is this source failure due to a broken parser or unavailable upstream? | Source outcomes distinguish drift, transport, quota and access | **Depends on the recorded outcome** | Reproduce the response contract with fixtures, then a bounded permitted live probe |
| Does scan termination prove total source coverage? | A fixed point only reflects the admissible local frontier | **No** | Record excluded providers, unavailable credentials, source families and collection timestamps |
| Is the latest released artifact running on the user's Termux device? | CI and GitHub publication are separate from on-device execution | **Unverified until a device-side receipt** | Match `huntsman-recon doctor` and `--version` to a known released commit |

Do not convert these open questions into negative findings or imply that
search-result similarity constitutes independent corroboration.
