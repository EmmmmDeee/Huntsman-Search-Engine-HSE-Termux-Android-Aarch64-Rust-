- `run-history` exits with the statuses the README's exit-code line gives a history it cannot
  load, instead of 74, the status for a failed write. `run-history show --file runs.jsonl` on a
  file with a line that is not a run (`{not json}`) now exits 65, bad data, and on a history
  that is a symlink, not a regular file or over 16 MiB it now exits 66, unreadable input.
  `run-history record` exits 66 for such an unreadable history and still writes nothing. A
  malformed history keeps 74 under `record`, so it stays distinct from a regression verdict,
  which exits 65. The message on standard error is unchanged.
