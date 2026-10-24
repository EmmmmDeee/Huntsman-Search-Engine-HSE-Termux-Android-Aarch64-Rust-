- An address XposedOrNot lists in a breach is now tagged `breach`, the tag HIBP, OathNet and
  DeHashed hits carry, and is scored as breach exposure. For `email ada@example.com` (or `scan`
  of an address) where XposedOrNot answered `{"breaches":[["Artsy","MyHeritage"]]}`, the address
  was tagged `breached`, which nothing scored, so its exposure row in `scan --recurse`, in
  analysis of a saved ledger and in the web UI's analysis held only `verified:10`. It now also
  holds `breach:20`, and its exposure, lead and profile scores rise to match. Where HIBP, OathNet
  or DeHashed already tagged the same address `breach` in that run, its scores do not change,
  though the tag `breached` no longer appears. A ledger saved before this change keeps `breached`
  and is not rescored.
