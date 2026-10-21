# Continuous evidence normalisation (opt-in)

Huntsman can reconcile configured targets for as long as its serve process remains alive. This Rust thread shares the existing saved-scan store, canonical routing, correlation rules, worker admission and saved-scan analysis endpoint. It does not run a language model or modify source code.

## Configuration

Set HUNTSMAN_CONTINUOUS_TARGETS to a semicolon- or newline-separated list of selectors; for example: example.com;1.1.1.1. Configure HUNTSMAN_CONTINUOUS_INTERVAL_MINUTES=1440 for daily collection. Start the usual huntsman-recon serve command.

If targets are not configured, the controller stays off and does not collect remotely. Set HUNTSMAN_CONTINUOUS_TARGETS='*' to continuously re-normalise the most recent saved scan of every canonical target already present in the scan store, without initiating any new network scans. The wildcard may also accompany specific targets, which alone are eligible for recurring collection; people-name targets are refused. At most 32 explicit canonical targets (8192 config bytes) are accepted. Collection interval may be 60 to 10080 minutes, default 1440. Reconciliation wakes every 60 seconds.

Saved scans are kept unchanged in the existing private scans store. For each terminal scan, the shared /api/scans/ID/analyze path recalculates derived findings and writes a bounded, atomic private JSON report to HUNTSMAN_HOME/normalised, or ~/.huntsman/normalised. The deterministic file name hashes the canonical target plus kind; the report carries the source scan ID and limitations.

A cheap revision detector reads the row and results file metadata (size, nanosecond modification time, and Unix inode when available) each cycle. An unchanged scan ID **does not** imply unchanged evidence. Successful reports now include `normalisation.state=current` and `source_revision_hint`; when analysis refuses revised/flagged evidence, the latest report is atomically replaced with a `normalisation.state=stale` marker. The most recent good report is preserved separately as a sibling `*.previous.json`, with its embedded `normalisation.state` changed to `historical` while retaining its findings, attribution and revision hint; the original saved scan evidence remains unchanged. Historical derived reports are never currently verified conclusions. If evidence changes during analysis, that analysis is discarded. A failed write, deleted scan, timestamp/inode collision, or modification between the final check and write can still limit detection: the hint is not a cryptographic content digest or a transaction, and no claim of instantaneous consistency is made. Detection is bounded by the 60-second reconciliation tick except during the existing 15-minute error retry window. Existing consumers must inspect `normalisation.state` and must not present `*.previous.json` as current evidence.

The passive scan use case and zero recursion depth are used. Other configured provider quotas may still apply. No source failure, failed analysis or missing ancestry is promoted to a verified absence or identity. A refused analysis does not overwrite the last good derived report.

After a new or failed scan, collection waits for the configured interval; admission failures back off at least 15 minutes. Existing active scans are joined, not duplicated. The scheduler never silently deletes old scans. Once the store reaches its 4096-record capacity, that limit remains observable; indefinite fresh collection requires a separately approved archival/retention procedure.

## Lifecycle

READ CONFIG -> CANONICALISE -> READ SCAN STORE -> SELECT LATEST SCAN PER CANONICAL TARGET -> ANALYSE COMPLETED SCANS -> ATOMICALLY SAVE DERIVED REPORT -> CHECK RECENCY AND RETRY WINDOWS -> START OR JOIN DUE SCANS -> SLEEP 60 SECONDS -> REPEAT.

This is an evidence normalisation and refreshing controller, not an unattended software-editing agent. It cannot ensure that providers respond or that the Termux process keeps running. Android may suspend a background Termux server; see docs/INSTALL.md. Service restarts derive cadence from saved scan timestamps.

## Verification

Run cargo fmt --check, cargo run --locked -p xtask -- gate full, huntsman-recon doctor serve and huntsman-recon scans list --json. Compare each normalised report's scan ID with the durable scan store and inspect source outcomes. Before merge, install the exact-head Android aarch64 prebuilt on a no-root Termux handset, exercise the loopback web UI, observe a new normalised report, restart the service and verify the report and source scan provenance persist.
