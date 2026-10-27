- `huntsman-recon scans cycle` runs one cycle of continuous collection in the foreground and
  exits, so Android's scheduler can drive it through `termux-job-scheduler` without a resident
  `serve`, which Android may stop. It reads the same continuous settings, runs every due
  target's scan to its end, then decides and notifies the scan's alert, applies
  `HUNTSMAN_CONTINUOUS_KEEP` and re-normalises before it exits. It reports what it did
  (`--json` for an object) and exits 0, 69 when a due scan could not run, 65 for a wrong
  setting, or 78 when no targets are set. `docs/CONTINUOUS_NORMALISATION.md` gives the
  job-scheduler recipe.
