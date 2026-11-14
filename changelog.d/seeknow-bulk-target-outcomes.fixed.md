- SeekNow bulk imports now report per-target provider errors as inconclusive, including when the
  export contains usable rows. The CLI and Web UI still attribute those rows through the normal
  evidence rules. When the export includes the submitted target list, a missing result block is
  reported for each unmatched occurrence, including repeated targets.
