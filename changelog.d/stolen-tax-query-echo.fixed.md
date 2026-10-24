- `recon stolen-tax` no longer hands the queried identity back as a pivot when a breach row
  spells it differently. For `recon stolen-tax @ada_99` with a breach row holding the username
  `ada_99`, the output carried a `username ada99` row next to the breach marker, and counted
  `entities=2`. The query is now compared in the same canonical form the entity is stored in, so
  a leading `@`, a `.`, `_` or `-` in a username, or spaces around the query, no longer make it a
  new identity: that output now has only the breach marker and `entities=1`. In `exposure`,
  `email` and `username`, the searched identity no longer carries the evidence "Exposed in
  breach: correlated with @ada_99" about itself, and the stolen.tax row's `found` count no longer
  includes it.
- A stolen.tax row that matches the query but names no breach or stealer host (an osintcat row
  with no corpus name, or a hudsonrock stealer with no host name but a clear login) mints no
  marker, so the identity it carried was the only sign of the match. When that identity was the
  query exactly as typed, the lookup read as not found (`entities=0`, or exit 69 when a path
  failed or was not sent); spelled differently, it came back as an echo of the query. Such rows
  are now counted: `recon stolen-tax` prints `unnamed_rows=N` before the `entities=` line, and in
  `exposure`, `email` and `username` the stolen.tax row's detail says `N row(s) name no breach or
  stealer host`. A lookup whose only match is such a row is reported as that match, marked
  partial when a path failed or was not sent, instead of as not found.
