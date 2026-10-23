- `recon stolen-tax` no longer hands the queried identity back as a pivot when a breach row
  spells it differently. For `recon stolen-tax @ada_99` with a breach row holding the username
  `ada_99`, the output carried a `username ada99` row with the evidence "Exposed in breach:
  correlated with @ada_99" next to the breach marker, and counted `entities=2`. The query is now
  compared in the same canonical form the entity is stored in, so a leading `@`, a `.`, `_` or
  `-` in a username, or spaces around the query, no longer make it a new identity: that output
  now has only the breach marker and `entities=1`. When that echoed row was the only thing found
  and a path failed or was not sent, the lookup now reports the failure instead of printing the
  echo as a result. In `exposure`, `email` and `username`, the searched identity no longer
  carries that "correlated with" evidence about itself, and the stolen.tax row's `found` count
  no longer includes it.
