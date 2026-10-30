- `people --save` (and `scan NAME -k people --save`) now saves the SeekNow leg's outcomes and
  findings as SeekNow's, from `src/seeknow_collector.rs`. The people save policy renamed every
  source it did not name to `asic_persons`, so on every saved people lookup that ran the SeekNow
  leg its rows entered the ledger as ASIC register rows: its `not_configured` row with no key set,
  and its outcomes and findings with one. People ledgers saved earlier keep those rows. A people source the policy does not name now keeps its own name, as in
  every other save policy. The email and username ledgers name the SeekNow leg's component too.
