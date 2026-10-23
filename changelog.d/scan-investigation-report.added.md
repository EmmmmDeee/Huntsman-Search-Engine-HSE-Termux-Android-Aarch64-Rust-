- `scans export ID -f html`, `GET /api/scans/ID/export?format=html` and the scan view's
  Export → Report write a saved scan as an investigation report for a client: one
  self-contained page (no script, nothing fetched, print-ready) with the subject, when and how
  the scan ran and the build it ran on, a summary, each finding grouped by kind and ordered by
  confidence with the evidence behind it (source, time and attributes), the correlations, every
  source consulted with its outcome including those that failed, and how to read it: findings
  are leads to corroborate, never identity verdicts. Every source value is escaped, and a
  finding the analyst flagged as a false positive is left out and counted.
